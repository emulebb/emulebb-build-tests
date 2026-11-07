from __future__ import annotations

import json
import stat
import io
import tarfile

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


def test_portable_manifest_rejects_wrong_revision_dirty_source_and_changed_bytes(tmp_path):
    asset = tmp_path / "package.tar.zst"
    asset.write_bytes(b"synthetic archive")
    data = {"asset": asset.name, "sha256": smoke.file_sha256(asset), "sourceDirty": False, "target": "x86_64-unknown-linux-musl",
            "source": {"emulebbRust": {"commit": "a" * 40}}}
    manifest = asset.with_name(asset.name + ".manifest.json")
    manifest.write_text(json.dumps(data))
    target = data["target"]
    assert smoke._verify_portable_manifest(asset, "a" * 40, target) == data
    with pytest.raises(RuntimeError, match="provenance"):
        smoke._verify_portable_manifest(asset, "a" * 40, "aarch64-unknown-linux-musl")
    with pytest.raises(RuntimeError, match="provenance"):
        smoke._verify_portable_manifest(asset, "b" * 40, target)
    data["sourceDirty"] = True
    manifest.write_text(json.dumps(data))
    with pytest.raises(RuntimeError, match="provenance"):
        smoke._verify_portable_manifest(asset, "a" * 40, target)
    data["sourceDirty"] = False
    manifest.write_text(json.dumps(data))
    asset.write_bytes(b"changed archive")
    with pytest.raises(RuntimeError, match="provenance"):
        smoke._verify_portable_manifest(asset, "a" * 40, target)


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
