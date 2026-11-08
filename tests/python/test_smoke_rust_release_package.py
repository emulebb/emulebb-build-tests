from __future__ import annotations

import json
import stat
import io
import tarfile
import subprocess
from types import SimpleNamespace
from contextlib import contextmanager

import pytest

from emule_test_harness.script_modules import load_script_module


smoke = load_script_module("smoke_rust_release_package", "smoke-rust-release-package.py")


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


def test_failed_delivery_retains_transfer_error_context(monkeypatch, tmp_path):
    def fail(*args, **kwargs):
        raise RuntimeError("delivery timed out")
    monkeypatch.setattr(smoke, "wait_for", fail)
    monkeypatch.setattr(smoke, "request_json", lambda *args: {"items": [{"error": "synthetic publication failure"}]})
    with pytest.raises(RuntimeError, match="synthetic publication failure"):
        smoke._wait_for_transfer_delivery("http://127.0.0.1:4711", "a" * 32,
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

    assert calls == [
        (
            profile,
            {
                "rust_repo": rust_repo,
                "incoming_dir": incoming,
                "rest_addr": "127.0.0.1",
                "rest_port": 4711,
                "api_key": smoke.API_KEY,
                "auto_connect": False,
                "network_kademlia": False,
                "p2p_bind_ip": "192.0.2.10",
                "ed2k_port": 4662,
                "kad_port": 4672,
                "server_endpoint": "127.0.0.1:4661",
                "nat_enabled": False,
                "replace_servers": True,
                "initial_shared_directory_reload": False,
                "local_only_discovery": True,
            },
        )
    ]


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


def test_transfer_delivery_report_omits_temporary_paths(monkeypatch, tmp_path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    delivered = incoming / "payload.bin"
    delivered.write_bytes(b"payload")
    expected_sha256 = smoke.file_sha256(delivered)
    transfer_hash = "00112233445566778899aabbccddeeff"
    requests = []

    def completed_shared_file(_base_url, method, path, _api_key):
        requests.append((method, path))
        return {
            "hash": transfer_hash,
            "complete": True,
            "partFile": False,
            "sizeBytes": delivered.stat().st_size,
            "path": str(delivered),
        }

    monkeypatch.setattr(
        smoke,
        "request_json",
        completed_shared_file,
    )

    report = smoke._wait_for_transfer_delivery(
        "http://127.0.0.1:4711",
        transfer_hash,
        incoming=incoming,
        expected_size=delivered.stat().st_size,
        expected_sha256=expected_sha256,
    )

    assert report["deliveredPathWithinIncoming"] is True
    assert report["sharedFileRegistered"] is True
    assert requests == [("GET", f"/api/v1/shared-files/{transfer_hash}")]
    assert str(tmp_path) not in json.dumps(report)


@pytest.mark.parametrize(
    "field,value",
    [("hash", "ff" * 16), ("complete", False), ("partFile", True), ("sizeBytes", 99)],
)
def test_transfer_delivery_rejects_wrong_or_incomplete_shared_content(
    monkeypatch, tmp_path, field, value,
) -> None:
    delivered = tmp_path / "payload.bin"
    delivered.write_bytes(b"payload")
    transfer_hash = "00112233445566778899aabbccddeeff"
    shared = {
        "hash": transfer_hash,
        "complete": True,
        "partFile": False,
        "sizeBytes": 7,
        "path": str(delivered),
    }
    shared[field] = value
    monkeypatch.setattr(smoke, "request_json", lambda *_args: shared)
    monkeypatch.setattr(smoke, "wait_for", lambda probe, **_kwargs: probe())

    assert (
        smoke._wait_for_transfer_delivery(
            "http://127.0.0.1:4711",
            transfer_hash,
            incoming=tmp_path,
            expected_size=7,
            expected_sha256=smoke.file_sha256(delivered),
        )
        is None
    )


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


def partial_details(*, size=12, verified=True, state="paused", completed=None):
    first = size * 2 // 3
    return {"transfer": {"hash": "a" * 32, "sizeBytes": size, "completedBytes": first if completed is None else completed,
                         "partsTotal": 2, "partsObtained": 1 if verified else 0,
                         "partsProgressText": "#0" if verified else "00", "state": state},
            "parts": [{"index": 0, "size": first, "completedBytes": first if verified else 0,
                       "gapBytes": 0 if verified else first, "complete": verified, "corrupted": False},
                      {"index": 1, "size": size - first, "completedBytes": 0, "gapBytes": size - first,
                       "complete": False, "corrupted": False}]}


def test_partial_checkpoint_accepts_verified_part_zero_and_omits_paths():
    result = smoke._partial_snapshot(partial_details(), transfer_hash="a" * 32, expected_size=12)
    assert result == {"partsTotal": 2, "verifiedPartIndices": [0], "verifiedBytes": 8, "completedBytes": 8, "state": "paused"}


def test_verified_partial_reads_the_details_resource(monkeypatch):
    paths = []
    detail = partial_details()
    def api(base_url, method, path, key):
        paths.append(path)
        return detail if path.endswith("/details") else detail["transfer"]
    monkeypatch.setattr(smoke, "request_json", api)
    monkeypatch.setattr(smoke, "wait_for", lambda probe, **kwargs: probe())
    result = smoke._wait_for_verified_partial("http://127.0.0.1:4711", "a" * 32, 12)
    assert result["verifiedPartIndices"] == [0]
    assert paths == ["/api/v1/transfers/" + "a" * 32 + "/details"]


@pytest.mark.parametrize("markers,count", [("00", 0), ("0#", 1), ("#0", True)])
def test_received_bytes_without_matching_verified_markers_are_not_a_checkpoint(markers, count):
    detail = partial_details()
    detail["transfer"].update(partsProgressText=markers, partsObtained=count)
    assert smoke._partial_snapshot(detail, transfer_hash="a" * 32, expected_size=12) is None


@pytest.mark.parametrize("fault", ["unverified", "corrupted", "zero-progress", "already-complete", "boolean-index", "duplicate-index"])
def test_partial_checkpoint_cannot_be_satisfied_by_invalid_or_nonpartial_state(fault):
    detail = partial_details()
    if fault == "unverified":
        detail["transfer"]["partsObtained"] = 0
    elif fault == "corrupted":
        detail["parts"][0]["corrupted"] = True
    elif fault == "zero-progress":
        detail["transfer"]["completedBytes"] = 0
    elif fault == "already-complete":
        detail["transfer"]["completedBytes"] = 12
    else:
        detail["parts"][0 if fault == "boolean-index" else 1]["index"] = False if fault == "boolean-index" else 0
        with pytest.raises(RuntimeError, match="part geometry"):
            smoke._partial_snapshot(detail, transfer_hash="a" * 32, expected_size=12)
        return
    assert smoke._partial_snapshot(detail, transfer_hash="a" * 32, expected_size=12) is None


@pytest.mark.parametrize("document,valid", [({"data": {"ok": True}, "meta": {"apiVersion": "v1"}}, True),
                                            ({"ok": True}, False), ({"data": {}, "meta": {}}, False)])
def test_package_rest_requires_the_current_envelope(monkeypatch, document, valid):
    monkeypatch.setattr(smoke, "_request", lambda *args, **kwargs: json.dumps(document).encode())
    if valid:
        assert smoke.request_json("http://127.0.0.1:4711", "GET", "/api/v1/app", smoke.API_KEY) == {"ok": True}
    else:
        with pytest.raises(RuntimeError, match="v1 data/meta envelope"):
            smoke.request_json("http://127.0.0.1:4711", "GET", "/api/v1/app", smoke.API_KEY)


@pytest.mark.parametrize("fault", [None, "lost-parts", "lost-setting", "changed-part-count"])
def test_packaged_restart_reuses_binary_and_profile_without_recreating_transfer(monkeypatch, tmp_path, fault):
    binary = tmp_path / "emulebb-rust"
    binary.write_bytes(b"synthetic binary")
    webui = tmp_path / "webui"
    webui.mkdir()
    (webui / "index.html").write_text("SPA")
    processes, starts, operations, closed = [], [], [], []
    state = {"paused": False, "limit": 12207, "leecherStarts": 0}
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
                state["limit"] = 12207
        handle = log_path.open("a")
        return process, handle
    def shutdown(base_url, process):
        closed.append(process.ordinal)
        process.returncode = 0
    def api(base_url, method, path, key, body=None):
        operations.append((method, path, body))
        if path == "/api/v1/app/settings":
            if method == "PATCH":
                state["limit"] = body["core"]["downloadLimitKiBps"]
            return {"core": {"downloadLimitKiBps": state["limit"]}}
        if path == "/api/v1/transfers" and method == "POST":
            return {"accepted": True}
        if path.endswith("/operations/pause"):
            state["paused"] = True
            return {"ok": True}
        if path.endswith("/operations/resume"):
            state["paused"] = False
            return {"ok": True}
        if path == "/api/v1/transfers/" + "a" * 32 + "/details":
            details = partial_details(size=smoke.TRANSFER_SIZE_BYTES,
                                   verified=not (fault == "lost-parts" and state["leecherStarts"] == 2),
                                   state="paused" if state["paused"] else "downloading")
            if fault == "changed-part-count" and state["leecherStarts"] == 2:
                details["parts"][1]["size"] //= 2
                details["parts"][1]["gapBytes"] = details["parts"][1]["size"]
                details["parts"].append({**details["parts"][1], "index": 2})
                details["transfer"].update(partsTotal=3, partsProgressText="#00")
            return details
        if path == "/api/v1/transfers/" + "a" * 32:
            return partial_details(size=smoke.TRANSFER_SIZE_BYTES)["transfer"]
        return {"ok": True}
    def request(url, **kwargs):
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
    monkeypatch.setattr(smoke.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "--profile --p2p-bind-interface"))
    monkeypatch.setattr(smoke, "publish_shared_tree", lambda *args, **kwargs: {"sharedFiles": {"matched": {
        "hash": "a" * 32, "name": smoke.TRANSFER_FILE_NAME, "sizeBytes": smoke.TRANSFER_SIZE_BYTES,
        "ed2kLink": "ed2k://|file|Sample.Payload.bin|12582912|" + "a" * 32 + "|/"}}})
    monkeypatch.setattr(smoke, "_wait_for_transfer_delivery", lambda *args, **kwargs: {"state": "completed", "deliveredSha256": kwargs["expected_sha256"]})
    if fault:
        with pytest.raises(RuntimeError, match="did not survive|did not preserve"):
            smoke._smoke_binary(binary, webui, tmp_path, rust_repo=tmp_path / "rust", render_webui=False)
    else:
        result = smoke._smoke_binary(binary, webui, tmp_path, rust_repo=tmp_path / "rust", render_webui=False)
        assert result["localTransfer"]["gracefulShutdowns"] == 3
        assert result["localTransfer"]["partialRestart"]["after"]["verifiedPartIndices"] == [0]
        assert closed == [2, 3, 1] and state["limit"] == 12207
    assert len(starts) == 3 and starts[1] == starts[2]
    assert len([item for item in operations if item[:2] == ("POST", "/api/v1/transfers")]) == 1
    assert len([item for item in operations if item[:2] == ("GET", "/api/v1/transfers/" + "a" * 32 + "/details")]) == 3
    assert all(process.poll() == 0 for process in processes)


@pytest.mark.parametrize("fault", [None, "wrong-source", "corrupt-sbom", "stem-manifest", "wrong-cpu", "changed-during-smoke",
                                  "dirty-harness-before", "dirty-harness-during", "harness-head-change"])
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
    def probe(*args, **kwargs):
        launches.append(args)
        if fault == "changed-during-smoke":
            asset.write_bytes(b"new package from another operation")
            manifest["sha256"] = smoke.file_sha256(asset)
            manifest_path.write_text(json.dumps(manifest))
        return {"status": "passed", "appVersion": version, "appBuild": "release",
                "appPlatform": "arm64" if fault == "wrong-cpu" else "x64"}
    @contextmanager
    def temporary():
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
    monkeypatch.setattr(smoke.sys, "argv", ["smoke-rust-release-package.py", "--release-dir", str(tmp_path),
                                           "--release-version", version, "--rust-repo", str(tmp_path),
                                           "--target-os", "windows", "--platform", "x64",
                                           "--expected-source-sha", "a" * 40, "--report-path", str(report)])
    if fault:
        with pytest.raises((RuntimeError, OSError)):
            smoke.main()
        assert not report.exists()
        assert len(launches) == (1 if fault in {"wrong-cpu", "changed-during-smoke", "dirty-harness-during", "harness-head-change"} else 0)
    else:
        assert smoke.main() == 0
        result = json.loads(report.read_text())
        assert result["schema"] == "emulebb.rust.package-smoke/3" and result["status"] == "passed"
        assert result["origin"] == "local-development" and result["workflow"] is None
        assert result["sourceSha"] == "a" * 40
        assert result["harnessSha"] == "c" * 40 and len(harness_checks) == 2
        assert result["results"][0]["assetSha256"] == smoke.file_sha256(asset)
        assert result["results"][0]["packageManifestSha256"] == smoke.file_sha256(manifest_path)
