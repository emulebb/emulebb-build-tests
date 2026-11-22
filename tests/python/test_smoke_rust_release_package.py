from __future__ import annotations

import json
import stat
import io
import tarfile
import subprocess
import tempfile
from types import SimpleNamespace
from pathlib import Path
from contextlib import contextmanager

import pytest

from emule_test_harness.script_modules import load_script_module


smoke = load_script_module("smoke_rust_release_package", "smoke-rust-release-package.py")


@pytest.mark.parametrize("field", [None, "version", "build", "platform", "channel", "sourceRevision"])
def test_explicit_build_identity_rejects_mismatched_runtime_and_cli(monkeypatch, field):
    expected = {"version": "0.1.0-beta.2", "build": "release", "platform": "x64",
                "channel": "nightly", "sourceRevision": "a" * 40}
    app = {"name": "eMuleBB", "apiVersion": "v1", "lifecycle": {"state": "running"}, **expected}
    if field is not None:
        app[field] = "wrong"
        with pytest.raises(RuntimeError, match="Packaged REST"):
            smoke._app_metadata(app, expected)
    else:
        assert smoke._app_metadata(app, expected)["appSourceRevision"] == "a" * 40
    correct = "emulebb-rust 0.1.0-beta.2 (nightly; x64; " + "a" * 40 + ")"
    monkeypatch.setattr(smoke.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args, 0, correct if field is None else "emulebb-rust wrong"))
    if field is None:
        assert smoke._verify_cli_identity(Path("daemon"), expected) == correct
    else:
        with pytest.raises(RuntimeError, match="Packaged CLI"):
            smoke._verify_cli_identity(Path("daemon"), expected)


@pytest.mark.parametrize("name,kind", [("../outside", tarfile.REGTYPE),
                                      ("emulebb-rust/../../outside", tarfile.REGTYPE),
                                      ("emulebb-rust/link", tarfile.SYMTYPE)])
def test_portable_archive_rejects_escape_paths_and_links(tmp_path, name, kind):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.linkname = "/outside"
        archive.addfile(member)
    stream.seek(0)
    with pytest.raises(RuntimeError, match="unsafe"):
        smoke._extract_portable_stream(stream, tmp_path)


def test_package_manifest_rejects_wrong_revision_dirty_source_and_changed_bytes(tmp_path):
    asset = tmp_path / "package.tar.zst"
    asset.write_bytes(b"synthetic archive")
    sbom = tmp_path / "package.spdx.json"
    sbom.write_text("{}")
    data = {"schema": "emulebb.rust.package/2", "version": "0.1.0-beta.2",
            "sbom": sbom.name, "sbomSha256": smoke.file_sha256(sbom),
            "asset": asset.name, "sha256": smoke.file_sha256(asset), "sourceDirty": False, "target": "x86_64-unknown-linux-musl",
            "source": {"emulebbRust": {"commit": "a" * 40}}}
    manifest = asset.with_name(asset.name + ".manifest.json")
    manifest.write_text(json.dumps(data))
    target = data["target"]
    assert smoke._verify_package_manifest(asset, "a" * 40, data["version"], target) == data
    with pytest.raises(RuntimeError, match="provenance"):
        smoke._verify_package_manifest(asset, "a" * 40, data["version"], "aarch64-unknown-linux-musl")
    with pytest.raises(RuntimeError, match="provenance"):
        smoke._verify_package_manifest(asset, "b" * 40, data["version"], target)
    data["sourceDirty"] = True
    manifest.write_text(json.dumps(data))
    with pytest.raises(RuntimeError, match="provenance"):
        smoke._verify_package_manifest(asset, "a" * 40, data["version"], target)
    data["sourceDirty"] = False
    manifest.write_text(json.dumps(data))
    asset.write_bytes(b"changed archive")
    with pytest.raises(RuntimeError, match="provenance"):
        smoke._verify_package_manifest(asset, "a" * 40, data["version"], target)


def test_temporary_root_does_not_suppress_body_error() -> None:
    with pytest.raises(RuntimeError, match="body failed"):
        with smoke._temporary_root() as temp_root:
            assert temp_root.is_dir()
            raise RuntimeError("body failed")


@pytest.fixture
def ownership_contenders(monkeypatch):
    """Use real benign import inputs while controlling only CLI/REST outcomes."""
    from emule_test_harness.paths import get_workspace_output_root

    # WHY: hosted pytest's default tmp_path can be outside OUTPUT. The real
    # import-fixture owner requires managed scratch even when CLI calls are mocked.
    scratch = get_workspace_output_root() / "tmp/profile-ownership-unit"
    scratch.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.TemporaryDirectory(dir=scratch)
    tmp_path = Path(temporary.name)
    profile = tmp_path / "profile"
    profile.mkdir()
    bootstrap = profile / "emulebb-rust-settings.toml"
    bootstrap.write_text("[rest]\nbind_addr = '127.0.0.1:4711'\n", encoding="utf-8")
    state = {"failure": None, "mutation": None, "calls": 0}

    def offline(command, **kwargs):
        state["calls"] += 1
        if state["mutation"] == "bootstrap":
            bootstrap.write_text("changed bootstrap", encoding="utf-8")
        if state["failure"] == "unrelated":
            return SimpleNamespace(returncode=1, stdout="", stderr="invalid import input")
        return SimpleNamespace(
            returncode=0 if state["failure"] == "success" else 1, stdout="",
            stderr="profile is already in use: fixture; stop its daemon or offline command before retrying",
        )

    def rest(url, **kwargs):
        path = url.removeprefix("http://127.0.0.1:4711")
        changed = state["calls"] > 0
        if path == "/api/v1/settings":
            data = {"effective": {"transfers": {"uploadLimitBytesPerSecond": 2048 if changed and state["mutation"] == "settings" else 1024}}}
            return json.dumps({"data": data, "meta": {"apiVersion": "v1"}}).encode()
        assert path == "/api/v1/library/roots?limit=100"
        return json.dumps({"data": [{"id": "1", "path": "/synthetic/changed", "managed": False}] if changed and state["mutation"] == "roots" else [],
                           "meta": {"apiVersion": "v1", "hasMore": False, "nextCursor": None}}).encode()

    monkeypatch.setattr(smoke.subprocess, "run", offline)
    monkeypatch.setattr(smoke, "_request", rest)
    try:
        yield profile, bootstrap, state, tmp_path
    finally:
        temporary.cleanup()


def test_busy_profile_contenders_require_specific_failure_and_preserve_fixture(ownership_contenders):
    profile, bootstrap, state, tmp_path = ownership_contenders
    before = bootstrap.read_bytes()
    result = smoke._reject_offline_profile_writers(tmp_path / "daemon", profile, "http://127.0.0.1:4711", tmp_path)
    assert len(result) == 4 and all(item["profileBusy"] for item in result)
    assert state["calls"] == 4 and bootstrap.read_bytes() == before
    # The portable input is real and closed, so a busy verdict is not masking an
    # empty or malformed import archive prepared by this fixture.
    from emule_test_harness.profile_exchange import read_exchange_header
    assert read_exchange_header(tmp_path / "ownership-import/hashes.sqlite")["schema"] == "emulebb.profile-exchange.v2"


@pytest.mark.parametrize("failure", ["unrelated", "success"])
def test_offline_cli_error_or_success_cannot_count_as_profile_busy(ownership_contenders, failure):
    profile, _, state, tmp_path = ownership_contenders
    state["failure"] = failure
    with pytest.raises(RuntimeError, match="did not reject the busy profile"):
        smoke._reject_offline_profile_writers(tmp_path / "daemon", profile, "http://127.0.0.1:4711", tmp_path)
    assert state["calls"] == 1


@pytest.mark.parametrize("mutation", ["bootstrap", "settings", "roots"])
def test_busy_profile_rejection_cannot_hide_profile_mutation(ownership_contenders, mutation):
    profile, _, state, tmp_path = ownership_contenders
    state["mutation"] = mutation
    with pytest.raises(RuntimeError, match="denied offline commands changed"):
        smoke._reject_offline_profile_writers(tmp_path / "daemon", profile, "http://127.0.0.1:4711", tmp_path)


def test_api_key_meets_daemon_production_validation() -> None:
    assert len(smoke.API_KEY.encode("utf-8")) >= 32
    assert smoke.API_KEY.isascii()
    assert smoke.API_KEY.isprintable()
    assert not any(character.isspace() for character in smoke.API_KEY)


def test_failure_diagnostics_survive_profile_cleanup(monkeypatch, tmp_path):
    monkeypatch.setattr(smoke, "request_json", lambda *args: {"items": [{"message": "socket failure"}]})
    error = RuntimeError("listener failed")
    log = tmp_path / "daemon.log"
    log.write_text("native error context", encoding="utf-8")
    smoke._attach_failure_diagnostics(error, "seeder", "http://127.0.0.1:4711", log)
    log.unlink()
    assert "socket failure" in error.__notes__[0]
    assert "native error context" in error.__notes__[1]


def test_failure_diagnostics_preserve_original_error_when_sources_unavailable(monkeypatch, tmp_path):
    def unavailable(*args):
        raise RuntimeError("daemon stopped")
    monkeypatch.setattr(smoke, "request_json", unavailable)
    error = RuntimeError("original failure")
    smoke._attach_failure_diagnostics(error, "seeder", "http://127.0.0.1:4711", tmp_path / "missing.log")
    assert str(error) == "original failure"
    assert all("unavailable" in note for note in error.__notes__)


def test_linux_capability_probe_reports_missing_emulated_socket_option(monkeypatch):
    import errno

    class Probe:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def bind(self, address):
            assert address == ("127.0.0.1", 0)
        def setsockopt(self, level, option, index):
            raise OSError(errno.ENOPROTOOPT, "Protocol not available")

    monkeypatch.setattr(smoke.sys, "platform", "linux")
    monkeypatch.setattr(smoke.socket, "socket", lambda *args: Probe())
    monkeypatch.setattr(smoke.socket, "if_nametoindex", lambda name: 1, raising=False)
    with pytest.raises(RuntimeError, match="SO_BINDTOIFINDEX.*Protocol not available") as caught:
        smoke._probe_linux_interface_pinning()
    assert "not passing platform coverage" in str(caught.value)
    assert caught.value.__cause__.errno == errno.ENOPROTOOPT


def test_failed_delivery_retains_download_error_context(monkeypatch, tmp_path):
    def fail(*args, **kwargs):
        raise RuntimeError("delivery timed out")
    monkeypatch.setattr(smoke, "wait_for", fail)
    monkeypatch.setattr(smoke, "_download_page", lambda *args: [{"error": "synthetic publication failure"}])
    with pytest.raises(RuntimeError, match="synthetic publication failure"):
        smoke._wait_for_download_delivery("http://127.0.0.1:4711", "7", "a" * 32,
                                          incoming=tmp_path, expected_size=1, expected_sha256="b" * 64)


def test_write_profile_isolated_before_first_launch(monkeypatch, tmp_path) -> None:
    calls = []

    def fake_write_rust_profile(profile, **kwargs):
        calls.append((profile, kwargs))

    monkeypatch.setattr(smoke.rust_client, "write_rust_profile", fake_write_rust_profile)
    profile = tmp_path / "nested" / "profile"
    rust_repo = tmp_path / "rust"
    incoming = tmp_path / "incoming"

    smoke._write_profile(
        profile,
        rust_repo=rust_repo,
        incoming=incoming,
        rest_port=4711,
        ed2k_port=4662,
        kad_port=4672,
        runtime_server_port=4661,
        p2p_ip="192.0.2.10",
    )

    assert calls == [(profile, {
        "rust_repo": rust_repo, "rest_addr": "127.0.0.1", "rest_port": 4711,
        "api_key": smoke.API_KEY, "server_endpoint": "127.0.0.1:4661",
        "replace_servers": True, "local_only_discovery": True,
        "settings": {
            "storage.incomingDirectory": str(incoming), "network.autoConnect": False,
            "network.kadEnabled": False, "network.p2p.bindIp": "192.0.2.10",
            "network.p2p.tcpPort": 4662, "network.p2p.udpPort": 4672,
            "network.nat.enabled": False, "sharing.scanOnStartup": False,
            "network.connections.connectTimeoutSeconds": 10,
            "network.servers.reconnectIntervalSeconds": 60,
        },
    })]


def test_webui_asset_paths_accepts_rooted_history_routing_assets() -> None:
    html = '<script src="/assets/app.js"></script><link href="/assets/app.css">'

    assert smoke._webui_asset_paths(html) == ["/assets/app.js", "/assets/app.css"]


def test_webui_asset_paths_accepts_relative_assets() -> None:
    html = '<script src="./assets/app.js"></script>'

    assert smoke._webui_asset_paths(html) == ["/assets/app.js"]


def test_transfer_payload_is_deterministic(tmp_path) -> None:
    first = smoke._write_transfer_payload(tmp_path / "first.bin", 79)
    second = smoke._write_transfer_payload(tmp_path / "second.bin", 79)

    assert first["sizeBytes"] == 79
    assert first["sha256"] == second["sha256"]
    assert (tmp_path / "first.bin").read_bytes() == (tmp_path / "second.bin").read_bytes()


@pytest.mark.parametrize("ownership", ["owned", "unowned"])
def test_download_delivery_report_omits_temporary_paths(monkeypatch, tmp_path, ownership) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    delivered = incoming / "payload.bin"
    delivered.write_bytes(b"payload")
    expected_sha256 = smoke.file_sha256(delivered)
    transfer_hash = "00112233445566778899aabbccddeeff"
    requests = []

    def completed_shared_file(_base_url, method, path, _api_key):
        requests.append((method, path))
        if path == "/api/v1/downloads/7":
            return {"id": "7", "hash": transfer_hash, "state": "completed", "payloadVerified": True,
                    "completedAt": 100, "delivery": {"path": str(delivered), "state": "delivered", "ownership": ownership}}
        return {
            "hash": transfer_hash,
            "present": True,
            "sizeBytes": delivered.stat().st_size,
        }

    monkeypatch.setattr(
        smoke,
        "request_json",
        completed_shared_file,
    )
    def locations(_base, method, path, _key):
        requests.append((method, path))
        return {"data": [{"path": str(delivered), "present": True}],
                "meta": {"hasMore": False, "nextCursor": None}}
    monkeypatch.setattr(smoke, "request_document", locations)

    report = smoke._wait_for_download_delivery(
        "http://127.0.0.1:4711",
        "7",
        transfer_hash,
        incoming=incoming,
        expected_size=delivered.stat().st_size,
        expected_sha256=expected_sha256,
    )

    assert report["deliveredPathWithinIncoming"] is True
    assert report["sharedFileRegistered"] is True
    assert report["deliveryOwnership"] == ownership
    assert requests == [("GET", "/api/v1/downloads/7"),
                        ("GET", f"/api/v1/library/files/{transfer_hash}"),
                        ("GET", f"/api/v1/library/files/{transfer_hash}/locations?limit=200")]
    assert str(tmp_path) not in json.dumps(report)


@pytest.mark.parametrize(
    "field,value",
    [("hash", "ff" * 16), ("present", False), ("sizeBytes", 99)],
)
def test_download_delivery_rejects_wrong_or_incomplete_shared_content(
    monkeypatch, tmp_path, field, value,
) -> None:
    delivered = tmp_path / "payload.bin"
    delivered.write_bytes(b"payload")
    transfer_hash = "00112233445566778899aabbccddeeff"
    shared = {
        "hash": transfer_hash,
        "present": True,
        "sizeBytes": 7,
    }
    shared[field] = value
    def response(_base, _method, path, _key):
        if path == "/api/v1/downloads/7":
            return {"id": "7", "hash": transfer_hash, "state": "completed", "payloadVerified": True,
                    "completedAt": 100, "delivery": {"path": str(delivered), "state": "delivered", "ownership": "owned"}}
        return shared
    monkeypatch.setattr(smoke, "request_json", response)
    monkeypatch.setattr(smoke, "request_document", lambda *_args: {
        "data": [{"path": str(delivered), "present": True}],
        "meta": {"hasMore": False, "nextCursor": None},
    })
    monkeypatch.setattr(smoke, "wait_for", lambda probe, **_kwargs: probe())

    assert (
        smoke._wait_for_download_delivery(
            "http://127.0.0.1:4711",
            "7",
            transfer_hash,
            incoming=tmp_path,
            expected_size=7,
            expected_sha256=smoke.file_sha256(delivered),
        )
        is None
    )


def test_download_delivery_rejects_none_ownership_even_with_matching_bytes(monkeypatch, tmp_path) -> None:
    delivered = tmp_path / "payload.bin"
    delivered.write_bytes(b"payload")
    file_hash = "00112233445566778899aabbccddeeff"
    def response(_base, _method, path, _key):
        if path == "/api/v1/downloads/7":
            return {"id": "7", "hash": file_hash, "state": "completed", "payloadVerified": True,
                    "completedAt": 100, "delivery": {"path": str(delivered), "state": "delivered", "ownership": "none"}}
        raise AssertionError("A job without delivery ownership must not reach shared-file proof")
    monkeypatch.setattr(smoke, "request_json", response)
    monkeypatch.setattr(smoke, "wait_for", lambda probe, **_kwargs: probe())
    assert smoke._wait_for_download_delivery("http://127.0.0.1:4711", "7", file_hash,
                                              incoming=tmp_path, expected_size=7,
                                              expected_sha256=smoke.file_sha256(delivered)) is None


def test_linux_appimage_restores_owner_execute_bit(monkeypatch, tmp_path) -> None:
    asset = tmp_path / "package.AppImage"
    asset.write_bytes(b"appimage")
    chmod_calls = []

    def fake_chmod(path, mode):
        chmod_calls.append((path, mode))

    def fake_run(command, *, cwd, **_kwargs):
        assert command == [str(asset), "--appimage-extract"]
        package = cwd / "squashfs-root" / "usr" / "lib" / "emulebb-rust"
        package.mkdir(parents=True)
        (cwd / "squashfs-root" / "AppRun").write_text("launcher", encoding="utf-8")

    monkeypatch.setattr(smoke.os, "chmod", fake_chmod)
    monkeypatch.setattr(smoke.subprocess, "run", fake_run)
    monkeypatch.setattr(smoke, "_smoke_binary", lambda *_args, **_kwargs: {"status": "passed"})
    smoke_root = tmp_path / "smoke"
    smoke_root.mkdir()

    report = smoke._smoke_linux_appimage(
        asset,
        smoke_root,
        rust_repo=tmp_path / "rust",
        render_webui=False,
    )

    assert report == {"status": "passed"}
    assert chmod_calls == [(asset, asset.stat().st_mode | stat.S_IXUSR)]


def partial_details(*, size=12, verified=True, state="stopped", intent="stopped"):
    first = size * 2 // 3
    return {"download": {"id": "7", "hash": "a" * 32, "sizeBytes": size,
                         "completedAt": None, "payloadVerified": False, "intent": intent, "state": state},
            "parts": [{"index": 0, "start": 0, "end": first - 1, "sizeBytes": first, "presentBytes": first if verified else 0,
                       "complete": verified, "corrupted": False},
                      {"index": 1, "start": first, "end": size - 1, "sizeBytes": size - first,
                       "presentBytes": 0,
                       "complete": False, "corrupted": False}]}


def test_partial_checkpoint_accepts_verified_part_zero_and_omits_paths():
    result = smoke._partial_snapshot(partial_details(), download_id="7", expected_hash="a" * 32,
                                     expected_size=12)
    assert result == {"partsTotal": 2, "verifiedPartIndices": [0], "verifiedBytes": 8,
                      "state": "stopped", "intent": "stopped"}


def test_verified_partial_reads_separate_detail_and_parts_resources(monkeypatch):
    paths = []
    detail = partial_details()
    def api(base_url, method, path, key):
        paths.append(path)
        return detail["download"]
    def page(base_url, path):
        paths.append(path)
        return detail["parts"]
    monkeypatch.setattr(smoke, "_download_page", page)
    monkeypatch.setattr(smoke, "request_json", api)
    monkeypatch.setattr(smoke, "wait_for", lambda probe, **kwargs: probe())
    result = smoke._wait_for_verified_partial("http://127.0.0.1:4711", "7", "a" * 32, 12)
    assert result["verifiedPartIndices"] == [0]
    assert paths == ["/api/v1/downloads/7", "/api/v1/downloads/7/parts?limit=200"]


@pytest.mark.parametrize("completed,complete", [(8, False), (7, True), (True, True)])
def test_received_bytes_without_verified_part_are_not_a_checkpoint(completed, complete):
    detail = partial_details()
    detail["parts"][0].update(presentBytes=completed, complete=complete)
    assert smoke._partial_snapshot(detail, download_id="7", expected_hash="a" * 32,
                                   expected_size=12) is None


@pytest.mark.parametrize("fault", ["unverified", "corrupted", "already-complete", "boolean-index", "duplicate-index"])
def test_partial_checkpoint_cannot_be_satisfied_by_invalid_or_nonpartial_state(fault):
    detail = partial_details()
    if fault == "unverified":
        detail["parts"][0]["complete"] = False
    elif fault == "corrupted":
        detail["parts"][0]["corrupted"] = True
    elif fault == "already-complete":
        detail["download"].update(completedAt=100, payloadVerified=True)
    else:
        detail["parts"][0 if fault == "boolean-index" else 1]["index"] = False if fault == "boolean-index" else 0
        with pytest.raises(RuntimeError, match="part geometry"):
            smoke._partial_snapshot(detail, download_id="7", expected_hash="a" * 32,
                                    expected_size=12)
        return
    assert smoke._partial_snapshot(detail, download_id="7", expected_hash="a" * 32,
                                   expected_size=12) is None


@pytest.mark.parametrize("fault", ["truncated-page", "missing-first", "gap", "overlap", "wrong-inclusive-size"])
def test_partial_checkpoint_requires_complete_inclusive_part_geometry(fault):
    detail = partial_details()
    if fault == "truncated-page":
        detail["parts"].pop()
    elif fault == "missing-first":
        detail["parts"].pop(0)
    elif fault == "gap":
        detail["parts"][1].update(start=9, sizeBytes=3)
    elif fault == "overlap":
        detail["parts"][1].update(start=7, sizeBytes=5)
    else:
        detail["parts"][1]["sizeBytes"] += 1
    with pytest.raises(RuntimeError, match="part geometry"):
        smoke._partial_snapshot(detail, download_id="7", expected_hash="a" * 32, expected_size=12)


@pytest.mark.parametrize("document,valid", [({"data": {"ok": True}, "meta": {"apiVersion": "v1"}}, True),
                                            ({"ok": True}, False), ({"data": {}, "meta": {}}, False)])
def test_package_rest_requires_the_current_envelope(monkeypatch, document, valid):
    monkeypatch.setattr(smoke, "_request", lambda *args, **kwargs: json.dumps(document).encode())
    if valid:
        assert smoke.request_json("http://127.0.0.1:4711", "GET", "/api/v1/app", smoke.API_KEY) == {"ok": True}
    else:
        with pytest.raises(RuntimeError, match="v1 data/meta envelope"):
            smoke.request_json("http://127.0.0.1:4711", "GET", "/api/v1/app", smoke.API_KEY)


def test_download_action_requires_exact_successful_207_item(monkeypatch):
    payload = {"data": [{"id": "7", "status": "accepted", "httpStatus": 202}],
               "meta": {"apiVersion": "v1"}}
    calls = []
    def request(url, **kwargs):
        calls.append((url, kwargs))
        return json.dumps(payload).encode()
    monkeypatch.setattr(smoke, "_request", request)
    assert smoke._download_action("http://127.0.0.1:4711", "stop", "7") == "accepted"
    assert calls[0][0].endswith("/api/v1/downloads/stop")
    assert calls[0][1]["expected_statuses"] == (207,)
    assert calls[0][1]["json_body"] == {"ids": ["7"]}
    for item in ({"id": "8", "status": "accepted", "httpStatus": 202},
                 {"id": "7", "status": "failed", "httpStatus": 404,
                  "error": {"code": "NOT_FOUND", "message": "Missing", "details": {}}},
                 {"id": "7", "status": "accepted", "httpStatus": 202, "error": {}},
                 {"id": "7", "status": "unchanged", "httpStatus": 202}):
        payload["data"] = [item]
        with pytest.raises(RuntimeError, match="failed for job 7"):
            smoke._download_action("http://127.0.0.1:4711", "stop", "7")


def test_download_page_requires_settled_bounded_envelope(monkeypatch):
    page = {"data": [{"id": "7"}],
            "meta": {"apiVersion": "v1", "hasMore": False, "nextCursor": None}}
    monkeypatch.setattr(smoke, "_request", lambda *args, **kwargs: json.dumps(page).encode())
    assert smoke._download_page("http://127.0.0.1:4711", "/api/v1/downloads?view=completed") == [{"id": "7"}]
    page["meta"] = {"apiVersion": "v1", "hasMore": True, "nextCursor": "later"}
    with pytest.raises(RuntimeError, match="did not settle"):
        smoke._download_page("http://127.0.0.1:4711", "/api/v1/downloads?view=completed")


@pytest.mark.parametrize("fault", [None, "lost-parts", "lost-setting", "changed-part-count"])
@pytest.mark.parametrize("initial_mode", ["default", "custom"])
def test_packaged_restart_reuses_binary_and_profile_without_recreating_job(monkeypatch, tmp_path, fault, initial_mode):
    binary = tmp_path / "emulebb-rust"
    binary.write_bytes(b"synthetic binary")
    webui = tmp_path / "webui"
    webui.mkdir()
    (webui / "index.html").write_text("SPA")
    processes, starts, operations, closed = [], [], [], []
    initial_limit = 12499968 if initial_mode == "default" else 2000000
    state = {"stopped": False, "limit": initial_limit, "mode": initial_mode,
             "revision": 9007199254740993, "leecherStarts": 0}
    def write_profile(profile, **kwargs):
        profile.mkdir()
        (profile / "emulebb-rust-metadata.db").write_bytes(b"synthetic metadata")
    def start(program, profile, log_path):
        process = SimpleNamespace(returncode=None, ordinal=len(processes) + 1)
        process.poll = lambda: process.returncode
        processes.append(process)
        starts.append((program, profile))
        if profile.name == "leecher-profile":
            state["leecherStarts"] += 1
            if fault == "lost-setting" and state["leecherStarts"] == 2:
                state["limit"] = initial_limit
                state["mode"] = initial_mode
        handle = log_path.open("a")
        return process, handle
    def shutdown(base_url, process):
        closed.append(process.ordinal)
        process.returncode = 0
    def api(base_url, method, path, key, body=None, **kwargs):
        operations.append((method, path, body))
        if path == "/api/v1/downloads" and method == "POST":
            assert kwargs["expected_statuses"] == (201,)
            assert body == {"source": {"type": "ed2k-link", "link": body["source"]["link"]},
                            "intent": "started"}
            return {"id": "7", "hash": "a" * 32}
        if path in {"/api/v1/downloads/7", "/api/v1/downloads/7/parts?limit=200"}:
            details = partial_details(size=smoke.TRANSFER_SIZE_BYTES,
                                   verified=not (fault == "lost-parts" and state["leecherStarts"] == 2),
                                   state="stopped" if state["stopped"] else "downloading",
                                   intent="stopped" if state["stopped"] else "started")
            if fault == "changed-part-count" and state["leecherStarts"] == 2:
                second = details["parts"][1]
                original_end = second["end"]
                second["sizeBytes"] //= 2
                second["end"] = second["start"] + second["sizeBytes"] - 1
                details["parts"].append({**second, "index": 2, "start": second["end"] + 1,
                                         "end": original_end, "sizeBytes": original_end - second["end"]})
            return details["download"] if path == "/api/v1/downloads/7" else details["parts"]
        if path == "/api/v1/snapshot":
            return {"downloads": {"unfinished": 0, "completed": 1}}
        return {"ok": True}
    def request(url, **kwargs):
        if url.endswith("/api/v1/settings"):
            method = kwargs.get("method", "GET")
            body = kwargs.get("json_body")
            operations.append((method, "/api/v1/settings", body))
            if method == "PATCH":
                assert body["expectedRevision"] == str(state["revision"])
                if "set" in body:
                    state["limit"] = body["set"]["transfers"]["downloadLimitBytesPerSecond"]
                    state["mode"] = "custom"
                else:
                    assert body["reset"] == ["transfers.downloadLimitBytesPerSecond"]
                    state["limit"], state["mode"] = 12499968, "default"
                state["revision"] += 1
            return json.dumps({
                "data": {"saved": {"transfers": {"downloadLimitBytesPerSecond": {
                    "mode": state["mode"], "value": state["limit"]}}},
                    "effective": {"transfers": {"downloadLimitBytesPerSecond": state["limit"]}}},
                "meta": {"apiVersion": "v1", "settingsRevision": str(state["revision"])},
            }).encode()
        if url.endswith("/api/v1/downloads/7/parts?limit=200"):
            return json.dumps({"data": api(None, "GET", "/api/v1/downloads/7/parts?limit=200", None),
                               "meta": {"apiVersion": "v1", "hasMore": False, "nextCursor": None}}).encode()
        if url.endswith("/api/v1/downloads/stop") or url.endswith("/api/v1/downloads/start"):
            operation = url.rsplit("/", 1)[-1]
            assert kwargs["expected_statuses"] == (207,)
            assert kwargs["json_body"] == {"ids": ["7"]}
            state["stopped"] = operation == "stop"
            operations.append(("POST", f"/api/v1/downloads/{operation}", kwargs["json_body"]))
            return json.dumps({"data": [{"id": "7", "status": "accepted", "httpStatus": 202}],
                               "meta": {"apiVersion": "v1"}}).encode()
        if "/api/v1/downloads?view=completed" in url:
            return json.dumps({"data": [{"id": "7", "hash": "a" * 32}],
                               "meta": {"apiVersion": "v1", "hasMore": False, "nextCursor": None}}).encode()
        if url.endswith("/"):
            return b'<title>eMuleBB WebUI</title><div id="app"></div><script src="/assets/app.js"></script>'
        if "/assets/" in url:
            return b"bundled asset"
        return json.dumps({"data": {"stats": {"ed2kConnected": False}}, "meta": {"apiVersion": "v1"}}).encode()
    ports = iter(range(10000, 10020))
    monkeypatch.setattr(smoke, "_probe_linux_interface_pinning", lambda: None)
    monkeypatch.setattr(smoke, "_local_p2p_ip", lambda: "192.0.2.10")
    monkeypatch.setattr(smoke, "_available_unique_port", lambda *args, **kwargs: next(ports))
    monkeypatch.setattr(smoke, "_write_profile", write_profile)
    monkeypatch.setattr(smoke, "_start_daemon", start)
    monkeypatch.setattr(smoke, "_graceful_shutdown", shutdown)
    monkeypatch.setattr(smoke, "_wait_for_rest", lambda *args: {"name": "eMuleBB", "apiVersion": "v1", "version": "0.1.0-beta.2",
                                                               "build": "release", "platform": "x64", "lifecycle": {"state": "running"}})
    monkeypatch.setattr(smoke, "request_json", api)
    monkeypatch.setattr(smoke, "_request", request)
    monkeypatch.setattr(smoke.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "--profile"))
    monkeypatch.setattr(smoke, "publish_shared_tree", lambda *args, **kwargs: {"sharedFiles": {"matched": {
        "hash": "a" * 32, "displayName": smoke.TRANSFER_FILE_NAME, "sizeBytes": smoke.TRANSFER_SIZE_BYTES,
        "ed2kLink": "ed2k://|file|Sample.Payload.bin|12582912|" + "a" * 32 + "|/"}}})
    monkeypatch.setattr(smoke, "_wait_for_download_delivery", lambda *args, **kwargs: {
        "id": args[1], "state": "completed", "deliveredSha256": kwargs["expected_sha256"]})
    monkeypatch.setattr(smoke, "_parallel_download_proof", lambda *args, **kwargs: {"status": "passed"})
    if fault:
        with pytest.raises(RuntimeError, match="did not survive|did not preserve"):
            smoke._smoke_binary(binary, webui, tmp_path, rust_repo=tmp_path / "rust", render_webui=False)
    else:
        result = smoke._smoke_binary(binary, webui, tmp_path, rust_repo=tmp_path / "rust", render_webui=False)
        assert result["localDownload"]["gracefulShutdowns"] == 3
        assert result["localDownload"]["jobId"] == "7"
        assert result["localDownload"]["retainedCompletedJob"] is True
        assert result["localDownload"]["partialRestart"]["after"]["verifiedPartIndices"] == [0]
        assert closed == [2, 3, 1] and state["limit"] == initial_limit
        assert state["mode"] == initial_mode
        assert len([op for op in operations if op[:2] == ("PATCH", "/api/v1/settings")]) == 2
    assert len(starts) == 3 and starts[1] == starts[2]
    assert len([item for item in operations if item[:2] == ("POST", "/api/v1/downloads")]) == 1
    assert len([item for item in operations if item[:2] == ("GET", "/api/v1/downloads/7")]) == 3
    assert [item[1] for item in operations if item[1] in ("/api/v1/downloads/stop", "/api/v1/downloads/start")] == (
        ["/api/v1/downloads/stop"] if fault else ["/api/v1/downloads/stop", "/api/v1/downloads/start"]
    )
    assert all(process.poll() == 0 for process in processes)


@pytest.mark.parametrize("fault", [None, "startup", "shutdown"])
def test_parallel_source_ownership_drains_every_started_peer(tmp_path, monkeypatch, fault):
    monkeypatch.setattr(smoke, "PARALLEL_DOWNLOAD_COUNT", 4)
    ports, logs, stopped = iter(range(24000, 24100)), [], []
    monkeypatch.setattr(smoke, "_available_unique_port", lambda *args, **kwargs: next(ports))
    monkeypatch.setattr(smoke, "_write_profile", lambda *args, **kwargs: None)
    monkeypatch.setattr(smoke, "request_json", lambda *args, **kwargs: {})
    def start(*args):
        log = io.StringIO()
        logs.append(log)
        return SimpleNamespace(pid=len(logs)), log
    def ready(url, process, path):
        if fault == "startup" and process.pid == 2:
            raise RuntimeError("seed setup failed")
    def stop(url, process):
        stopped.append(process.pid)
        if fault == "shutdown" and process.pid == 2:
            raise RuntimeError("seed cleanup failed")
    monkeypatch.setattr(smoke, "_start_daemon", start)
    monkeypatch.setattr(smoke, "_wait_for_rest", ready)
    monkeypatch.setattr(smoke, "_shutdown_or_stop", stop)
    def run():
        with smoke._parallel_sources(Path("daemon"), tmp_path, rust_repo=tmp_path, p2p_ip="127.0.0.1",
                                     reserved_ports=set(), first_url="http://127.0.0.1:23000",
                                     first_port=23001, first_process=SimpleNamespace(pid=0)) as sources:
            assert len(sources) == 4
    if fault:
        with pytest.raises(RuntimeError, match="seed setup|seed cleanup"):
            run()
    else:
        run()
    assert stopped == ([2, 1] if fault == "startup" else [3, 2, 1])
    assert all(log.closed for log in logs)


def test_parallel_captures_admission_peak_and_waits_until_every_job_is_complete(tmp_path, monkeypatch):
    from emule_test_harness import rust_shared_library_io
    monkeypatch.setattr(smoke, "PARALLEL_DOWNLOAD_COUNT", 3)
    monkeypatch.setattr(smoke, "PARALLEL_PAYLOAD_BYTES", 1024)
    monkeypatch.setattr(smoke.time, "sleep", lambda *_: None)
    class Sampler:
        def __init__(self, *args):
            self.samples = 0
        def maybe_sample(self, **kwargs):
            self.samples += 1
        def summary(self):
            return {"sampleCount": self.samples}
    monkeypatch.setattr(rust_shared_library_io, "ProcessSampler", Sampler)
    monkeypatch.setattr(smoke, "request_document", lambda *args, **kwargs: {
        "data": {}, "meta": {"apiVersion": "v1", "settingsRevision": "1"}})
    sequence, snapshot_calls, page_calls = [], [], []
    def publish(*args, **kwargs):
        file_hash = f"{len(sequence) + 1:032x}"
        return {"sharedFiles": {"matched": {"hash": file_hash,
            "ed2kLink": f"ed2k://|file|Sample.bin|1024|{file_hash}|/"}}}
    def request(url, method, path, key, body=None, **kwargs):
        if path == "/api/v1/downloads":
            job = {"id": str(len(sequence) + 2), "hash": body["source"]["link"].split("|")[4]}
            sequence.append(job)
            return job
        if path == "/api/v1/snapshot":
            snapshot_calls.append(path)
            return {"downloads": {"unfinished": 0, "completed": 1 if len(snapshot_calls) == 1 else 4}}
        if path == "/api/v1/status":
            # The overlap ends before the final start. Sampling only the
            # completion loop must not manufacture evidence of this peak.
            active = 2 if len(starts) == 2 and not page_calls else 0
            return {"stats": {"downloadResources": {"active": active, "preparing": 0, "waiting": 0,
                "concurrency": {"mode": "fixed", "configuredLimit": 3, "target": 3, "burstActive": 0},
                "residentMemory": {"usedBytes": 1024, "softTargetBytes": 64 * 1024 * 1024,
                                   "limitBytes": 128 * 1024 * 1024}}}}
        raise AssertionError(path)
    def page(*args):
        page_calls.append(True)
        return [{**job, "state": "downloading" if len(page_calls) == 1 else "completed"} for job in sequence]
    starts = []
    def start(url, job_id, attempts):
        starts.append(("start", job_id))
        attempts.append({"id": job_id, "attempt": 1, "status": "accepted", "httpStatus": 202})
    monkeypatch.setattr(smoke, "publish_shared_tree", publish)
    monkeypatch.setattr(smoke, "request_json", request)
    monkeypatch.setattr(smoke, "_download_page", page)
    monkeypatch.setattr(smoke, "_start_parallel_job", start)
    monkeypatch.setattr(smoke, "_wait_for_download_delivery", lambda url, job_id, *args, **kwargs: {"id": job_id})
    result = smoke._parallel_download_jobs(tmp_path, sources=[
        {"url": f"http://127.0.0.1:{port}", "port": port, "process": object()} for port in (24001, 24002, 24003)],
        leecher_base_url="http://127.0.0.1:24000", p2p_ip="127.0.0.1", incoming=tmp_path / "incoming",
        leecher_process=object())
    assert len(page_calls) == 2
    assert result["admissionResourceSamples"] == 4
    assert result["resourceSamples"] == 6
    assert result["sampledPeaks"]["chargedActive"] == 2
    assert starts == [("start", "2"), ("start", "3"), ("start", "4")]
    assert len(result["deliveries"]) == 3 and result["controlRetries"] == 0


@pytest.mark.parametrize("outcome", ["success", "busy-then-success", "exhausted", "storage", "other-503", "wrong-status", "unchanged"])
def test_parallel_start_retries_only_recorded_admission_backpressure(monkeypatch, outcome):
    calls, delays, attempts = [], [], []
    def response(url, method, path, key, body, **kwargs):
        calls.append(body)
        assert method == "POST" and path == "/api/v1/downloads/start"
        assert kwargs["expected_statuses"] == (207,)
        row = {"id": "7", "status": "accepted", "httpStatus": 202}
        if outcome == "exhausted" or (outcome == "busy-then-success" and len(calls) < 3):
            row.update(status="failed", httpStatus=503, error={"code": "DOWNLOAD_UNAVAILABLE"})
        elif outcome == "storage":
            row.update(status="failed", httpStatus=500, error={"code": "DOWNLOAD_FAILED"})
        elif outcome == "other-503":
            row.update(status="failed", httpStatus=503, error={"code": "INTERNAL_SERVER_ERROR"})
        elif outcome == "wrong-status":
            row.update(status="failed", httpStatus=500, error={"code": "DOWNLOAD_UNAVAILABLE"})
        elif outcome == "unchanged":
            row.update(status="unchanged", httpStatus=200)
        return {"data": [row], "meta": {"apiVersion": "v1"}}
    monkeypatch.setattr(smoke, "request_document", response)
    monkeypatch.setattr(smoke.time, "sleep", delays.append)
    if outcome in ("success", "busy-then-success"):
        smoke._start_parallel_job("http://127.0.0.1:24000", "7", attempts)
    else:
        with pytest.raises(RuntimeError, match="did not settle"):
            smoke._start_parallel_job("http://127.0.0.1:24000", "7", attempts)
    expected = 3 if outcome == "busy-then-success" else 5 if outcome == "exhausted" else 1
    assert len(calls) == len(attempts) == expected
    assert all(body == {"ids": ["7"]} for body in calls)
    assert [row["attempt"] for row in attempts] == list(range(1, expected + 1))
    assert delays == [0.25 * 2 ** index for index in range(expected - 1)]
    assert [row["retryDelaySeconds"] for row in attempts[:-1]] == delays


def test_parallel_payload_identity_is_distinct_and_repeatable(tmp_path):
    first = smoke._write_transfer_payload(tmp_path / "a.bin", 4096, identity=b"a")
    second = smoke._write_transfer_payload(tmp_path / "b.bin", 4096, identity=b"b")
    repeated = smoke._write_transfer_payload(tmp_path / "again.bin", 4096, identity=b"a")
    assert first["sha256"] != second["sha256"]
    assert first["sha256"] == repeated["sha256"]
    assert first["sizeBytes"] == second["sizeBytes"] == 4096


@pytest.mark.parametrize("fault", [None, "resident", "limit", "soft-target", "active", "mode", "configured", "counter", "missing"])
def test_parallel_resources_preserve_budget_and_fixed_burst_contract(fault):
    resources = {"active": 20, "preparing": 2, "waiting": 3,
                 "concurrency": {"mode": "fixed", "configuredLimit": 16, "target": 16, "burstActive": 4},
                 "residentMemory": {"usedBytes": 128 * 1024 * 1024,
                                    "softTargetBytes": 64 * 1024 * 1024, "limitBytes": 128 * 1024 * 1024}}
    if fault == "resident":
        resources["residentMemory"]["usedBytes"] += 1
    elif fault == "limit":
        resources["residentMemory"]["limitBytes"] *= 2
    elif fault == "soft-target":
        resources["residentMemory"]["softTargetBytes"] = 0
    elif fault == "active":
        resources["active"] = 21
    elif fault == "mode":
        resources["concurrency"]["mode"] = "automatic"
    elif fault == "configured":
        resources["concurrency"]["configuredLimit"] = 17
    elif fault == "counter":
        resources["preparing"] = True
    elif fault == "missing":
        del resources["residentMemory"]
    peaks = {}
    if fault:
        with pytest.raises(RuntimeError, match="resource contract"):
            smoke._record_download_resources(resources, peaks)
        assert peaks == {}
    else:
        smoke._record_download_resources(resources, peaks)
        resources.update(active=0, preparing=0, waiting=0)
        resources["residentMemory"]["usedBytes"] = 0
        smoke._record_download_resources(resources, peaks)
        assert peaks["active"] == 20 and peaks["preparing"] == 2
        assert peaks["residentBytes"] == 128 * 1024 * 1024
        assert peaks["chargedActive"] == 20


@pytest.mark.parametrize("fault", [None, "wrong-source", "corrupt-sbom", "stem-manifest", "wrong-cpu", "changed-during-smoke",
                                  "dirty-harness-before", "dirty-harness-during", "harness-head-change",
                                  "wrong-runtime-source", "wrong-runtime-channel", "capture-ok",
                                  "capture-tampered", "capture-not-created"])
def test_main_binds_every_native_package_before_launch_and_retains_exact_source_proof(monkeypatch, tmp_path, fault):
    version = "0.1.0-beta.2"
    asset = tmp_path / f"emulebb-rust-v{version}-windows-x64.zip"
    asset.write_bytes(b"synthetic Windows package")
    sbom = tmp_path / "package.spdx.json"
    sbom.write_text("{}")
    manifest = {"schema": "emulebb.rust.package/2", "version": version, "sourceDirty": False,
                "asset": asset.name, "sha256": smoke.file_sha256(asset), "sbom": sbom.name,
                "sbomSha256": smoke.file_sha256(sbom), "source": {"emulebbRust": {"commit": "a" * 40}}}
    manifest_path = asset.with_name(asset.name + ".manifest.json")
    if fault == "wrong-source":
        manifest["source"]["emulebbRust"]["commit"] = "b" * 40
    manifest_path.write_text(json.dumps(manifest))
    if fault == "corrupt-sbom":
        sbom.write_text('{"changed":true}')
    elif fault == "stem-manifest":
        manifest_path.rename(asset.with_suffix(".manifest.json"))
    launches = []
    capture = fault is not None and fault.startswith("capture-")
    def probe(*args, **kwargs):
        assert kwargs["expected_identity"] == {"version": version, "build": "release", "platform": "x64",
                                               "channel": "nightly", "sourceRevision": "a" * 40}
        launches.append(args)
        if fault == "changed-during-smoke":
            asset.write_bytes(b"new package from another operation")
            manifest["sha256"] = smoke.file_sha256(asset)
            manifest_path.write_text(json.dumps(manifest))
        result = {"status": "passed", "appVersion": version, "appBuild": "release",
                "appPlatform": "arm64" if fault == "wrong-cpu" else "x64",
                "appChannel": "candidate" if fault == "wrong-runtime-channel" else "nightly",
                "appSourceRevision": ("b" if fault == "wrong-runtime-source" else "a") * 40}
        if capture:
            image = kwargs["public_capture_path"]
            assert image.parent == report.parent
            if fault != "capture-not-created":
                image.write_bytes(b"synthetic screenshot bytes")
                result["publicWebuiCapture"] = {"file": image.name, "width": 1280, "height": 720,
                                                "view": "Search", "sha256": smoke.file_sha256(image)}
                if fault == "capture-tampered":
                    image.write_bytes(b"different screenshot bytes")
        return result
    @contextmanager
    def temporary(**kwargs):
        root = tmp_path / "run"
        root.mkdir()
        yield root
    report = tmp_path / "smoke.json"
    harness_checks = []
    def harness_source(root, *, label):
        assert root == smoke.REPO_ROOT and label == "Package smoke harness"
        harness_checks.append(root)
        if (fault == "dirty-harness-before" or fault == "dirty-harness-during" and len(harness_checks) == 2):
            raise RuntimeError("Package smoke harness worktree must be clean")
        return SimpleNamespace(revision=("d" if fault == "harness-head-change" and len(harness_checks) == 2 else "c") * 40)
    monkeypatch.setattr(smoke, "require_clean_git_source", harness_source)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(smoke, "_temporary_root", temporary)
    monkeypatch.setattr(smoke, "_smoke_windows", probe)
    if capture:
        from emule_test_harness import paths
        monkeypatch.setattr(paths, "get_workspace_output_root", lambda: tmp_path)
    monkeypatch.setattr(smoke.sys, "argv", ["smoke-rust-release-package.py", "--release-dir", str(tmp_path),
                                           "--release-version", version, "--rust-repo", str(tmp_path),
                                           "--target-os", "windows", "--platform", "x64",
                                           "--expected-source-sha", "a" * 40, "--expected-channel", "nightly",
                                           "--report-path", str(report),
                                           *(["--capture-public-webui", "--render-webui"] if capture else [])])
    if fault not in {None, "capture-ok"}:
        with pytest.raises((RuntimeError, OSError)):
            smoke.main()
        assert not report.exists()
        assert len(launches) == (1 if fault in {"wrong-cpu", "changed-during-smoke", "dirty-harness-during", "harness-head-change",
                                              "wrong-runtime-source", "wrong-runtime-channel", "capture-tampered",
                                              "capture-not-created"} else 0)
    else:
        assert smoke.main() == 0
        result = json.loads(report.read_text())
        assert result["schema"] == "emulebb.rust.package-smoke/3" and result["status"] == "passed"
        assert result["origin"] == "local-development" and result["workflow"] is None
        assert result["sourceSha"] == "a" * 40
        assert result["harnessSha"] == "c" * 40 and len(harness_checks) == 2
        assert result["results"][0]["assetSha256"] == smoke.file_sha256(asset)
        assert result["results"][0]["packageManifestSha256"] == smoke.file_sha256(manifest_path)
        assert ("publicWebuiCapture" in result["results"][0]) == capture


@pytest.mark.parametrize("missing", ["--render-webui", "--expected-channel", "--report-path"])
def test_public_capture_requires_explicit_strict_owner_inputs_before_launch(monkeypatch, tmp_path, missing):
    arguments = ["smoke-rust-release-package.py", "--release-dir", str(tmp_path), "--release-version", "0.1.0-beta.2",
                 "--rust-repo", str(tmp_path), "--target-os", "windows", "--platform", "x64",
                 "--expected-source-sha", "a" * 40, "--capture-public-webui"]
    for option, values in (("--render-webui", []), ("--expected-channel", ["candidate"]),
                           ("--report-path", [str(tmp_path / "report.json")])):
        if option != missing:
            arguments.extend([option, *values])
    monkeypatch.setattr(smoke.sys, "argv", arguments)
    monkeypatch.setattr(smoke, "require_clean_git_source", lambda *args, **kwargs: pytest.fail("owner validation too late"))
    with pytest.raises(SystemExit) as error:
        smoke.main()
    assert error.value.code == 2


def test_public_capture_refuses_a_report_outside_owned_output(monkeypatch, tmp_path):
    from emule_test_harness import paths

    output = tmp_path / "output"
    output.mkdir()
    monkeypatch.setattr(paths, "get_workspace_output_root", lambda: output)
    monkeypatch.setattr(smoke, "require_clean_git_source", lambda *args, **kwargs: SimpleNamespace(revision="c" * 40))
    monkeypatch.setattr(smoke.sys, "argv", ["smoke-rust-release-package.py", "--release-dir", str(tmp_path),
        "--release-version", "0.1.0-beta.2", "--rust-repo", str(tmp_path), "--target-os", "windows", "--platform", "x64",
        "--expected-source-sha", "a" * 40, "--expected-channel", "candidate", "--render-webui", "--capture-public-webui",
        "--report-path", str(tmp_path / "outside.json")])
    with pytest.raises(SystemExit) as error:
        smoke.main()
    assert error.value.code == 2
    assert not (tmp_path / "outside.json").exists()
