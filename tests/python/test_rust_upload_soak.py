from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from emule_test_harness import rust_upload_soak


def configure_workspace_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    workspace_root = tmp_path / "workspace"
    output_root = tmp_path / "out"
    workspace_root.mkdir()
    output_root.mkdir()
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    return workspace_root, output_root


def stage_dummy_rust_tools(output_root: Path) -> tuple[Path, Path]:
    bin_dir = output_root / "tools" / "emulebb-rust" / "bin"
    bin_dir.mkdir(parents=True)
    rust_exe = bin_dir / "emulebb-rust-diagnostics.exe"
    rust_ui_exe = bin_dir / "emulebb-rust-ui.exe"
    rust_exe.write_bytes(b"rust")
    rust_ui_exe.write_bytes(b"ui")
    return rust_exe, rust_ui_exe


def test_utc_run_id_uses_canonical_format() -> None:
    now = rust_upload_soak.datetime(2026, 7, 15, 10, 11, 12, tzinfo=rust_upload_soak.UTC)

    assert rust_upload_soak.utc_run_id(now) == "20260715T101112Z"


def test_parser_defaults_to_staged_rust_tools(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _workspace_root, output_root = configure_workspace_env(monkeypatch, tmp_path)
    rust_exe, rust_ui_exe = stage_dummy_rust_tools(output_root)

    args = rust_upload_soak.build_parser().parse_args(["--lan-bind-addr", "192.0.2.10"])
    rust_upload_soak.validate_args(args)

    assert args.rust_exe == rust_exe
    assert args.rust_ui_exe == rust_ui_exe
    assert args.duration_seconds == rust_upload_soak.DEFAULT_DURATION_SECONDS


def test_validate_args_rejects_unusable_values(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _workspace_root, output_root = configure_workspace_env(monkeypatch, tmp_path)
    stage_dummy_rust_tools(output_root)
    args = rust_upload_soak.build_parser().parse_args(
        ["--lan-bind-addr", "192.0.2.10", "--duration-seconds", "0"]
    )

    with pytest.raises(ValueError, match="duration-seconds"):
        rust_upload_soak.validate_args(args)


def test_write_payload_records_size_and_hash(tmp_path: Path) -> None:
    path = tmp_path / "payload.bin"
    size = len(b"emulebb-rust-local-upload-soak\n") + 7

    result = rust_upload_soak.write_payload(path, size)

    data = path.read_bytes()
    assert len(data) == size
    assert result == {
        "path": str(path),
        "sizeBytes": size,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def test_safe_counter_helpers_tolerate_missing_values() -> None:
    assert rust_upload_soak.safe_int(None) == 0
    assert rust_upload_soak.safe_int("12") == 12
    assert rust_upload_soak.safe_int("bad") == 0
    assert rust_upload_soak.safe_float(None) == 0.0
    assert rust_upload_soak.safe_float("1.5") == 1.5
    assert rust_upload_soak.safe_float("bad") == 0.0
