from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness import rust_profile_client_launcher


def test_rest_base_url_uses_x_local_ip_for_wildcard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")

    assert (
        rust_profile_client_launcher.rest_base_url({"rest": {"bindAddr": "0.0.0.0:4731"}})
        == "http://192.0.2.10:4731/api/v1"
    )


def test_rest_base_url_rejects_wildcard_without_x_local_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("X_LOCAL_IP", raising=False)

    with pytest.raises(RuntimeError, match="X_LOCAL_IP"):
        rust_profile_client_launcher.rest_base_url({"rest": {"bindAddr": "0.0.0.0:4731"}})


def test_wait_shared_files_ready_accepts_hashing_backlog(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_api_request(_config, path: str, **_kwargs):
        assert path == "/status"
        return {
            "data": {
                "stats": {"sharedHashingActive": True, "sharedHashingCount": 42},
                "runtimeDiagnostics": {"sharedFileCount": 1234},
            }
        }

    monkeypatch.setattr(rust_profile_client_launcher, "api_request", fake_api_request)

    assert rust_profile_client_launcher.wait_shared_files_ready({}, timeout_seconds=1.0) == (1234, 42, True)


def test_run_dry_run_uses_regular_staged_exe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output_root = tmp_path / "out"
    workspace_root = tmp_path / "workspace"
    cargo_target = output_root / "builds" / "rust" / "target"
    profile = output_root / "soak" / "rust-runtime"
    exe = output_root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"")
    workspace_root.mkdir()
    cargo_target.mkdir(parents=True)
    profile.mkdir(parents=True)
    (profile / "emulebb-rust-settings.toml").write_text(
        '[rest]\nbindAddr = "192.0.2.10:4731"\napiKey = "key"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(cargo_target))

    assert rust_profile_client_launcher.run(["--profile-dir", str(profile), "--dry-run"]) == 0

    output = capsys.readouterr().out
    assert str(exe) in output
    assert "emulebb-rust-diagnostics.exe" not in output
    assert "emulebb-rust-ui.exe" not in output
