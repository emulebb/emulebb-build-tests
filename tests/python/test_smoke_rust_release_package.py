from __future__ import annotations

import json
import stat

import pytest

from emule_test_harness.script_modules import load_script_module


smoke = load_script_module("smoke_rust_release_package", "smoke-rust-release-package.py")


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
    monkeypatch.setattr(
        smoke,
        "request_json",
        lambda *_args, **_kwargs: {
            "state": "completed",
            "completedBytes": delivered.stat().st_size,
            "deliveredPath": str(delivered),
        },
    )

    report = smoke._wait_for_transfer_delivery(
        "http://127.0.0.1:4711",
        "00112233445566778899aabbccddeeff",
        incoming=incoming,
        expected_size=delivered.stat().st_size,
        expected_sha256=expected_sha256,
    )

    assert report["deliveredPathWithinIncoming"] is True
    assert str(tmp_path) not in json.dumps(report)


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
