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


def stage_dummy_rust_tools(output_root: Path) -> Path:
    bin_dir = output_root / "tools" / "emulebb-rust" / "bin"
    bin_dir.mkdir(parents=True)
    rust_exe = bin_dir / "emulebb-rust.exe"
    rust_exe.write_bytes(b"rust")
    return rust_exe


def test_utc_run_id_uses_canonical_format() -> None:
    now = rust_upload_soak.datetime(2026, 7, 15, 10, 11, 12, tzinfo=rust_upload_soak.UTC)

    assert rust_upload_soak.utc_run_id(now) == "20260715T101112Z"


def test_parser_defaults_to_staged_rust_tools(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _workspace_root, output_root = configure_workspace_env(monkeypatch, tmp_path)
    rust_exe = stage_dummy_rust_tools(output_root)

    args = rust_upload_soak.build_parser().parse_args(["--lan-bind-addr", "192.0.2.10"])
    rust_upload_soak.validate_args(args)

    assert args.rust_exe == rust_exe
    assert args.duration_seconds == rust_upload_soak.DEFAULT_DURATION_SECONDS


def test_canonical_ed2k_server_does_not_use_repo_override() -> None:
    assert rust_upload_soak.resolve_ed2k_server_repo_override(None) is None


def test_resolve_ed2k_server_repo_override_prefers_explicit_path(tmp_path: Path) -> None:
    override = tmp_path / "custom-ed2k-server"

    assert rust_upload_soak.resolve_ed2k_server_repo_override(override) == str(override)


def test_validate_args_rejects_unusable_values(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _workspace_root, output_root = configure_workspace_env(monkeypatch, tmp_path)
    stage_dummy_rust_tools(output_root)
    args = rust_upload_soak.build_parser().parse_args(
        ["--lan-bind-addr", "192.0.2.10", "--duration-seconds", "0"]
    )

    with pytest.raises(ValueError, match="duration-seconds"):
        rust_upload_soak.validate_args(args)

    args = rust_upload_soak.build_parser().parse_args(["--lan-bind-addr", "192.0.2.10", "--api-key", "short"])
    with pytest.raises(ValueError, match="api-key"):
        rust_upload_soak.validate_args(args)


def test_write_payload_records_size_and_hash(tmp_path: Path) -> None:
    path = tmp_path / "payload.bin"
    duplicate_path = tmp_path / "payload-again.bin"
    size = 4099

    result = rust_upload_soak.write_payload(path, size)
    duplicate = rust_upload_soak.write_payload(duplicate_path, size)

    data = path.read_bytes()
    duplicate_data = duplicate_path.read_bytes()
    assert len(data) == size
    assert data == duplicate_data
    assert len(set(data[:256])) > 64
    assert result == {
        "path": str(path),
        "sizeBytes": size,
        "sha256": hashlib.sha256(data).hexdigest(),
        "contentKind": "deterministic-randbytes",
    }
    assert duplicate["sha256"] == result["sha256"]


def test_safe_counter_helpers_tolerate_missing_values() -> None:
    assert rust_upload_soak.safe_int(None) == 0
    assert rust_upload_soak.safe_int("12") == 12
    assert rust_upload_soak.safe_int("bad") == 0
    assert rust_upload_soak.safe_float(None) == 0.0
    assert rust_upload_soak.safe_float("1.5") == 1.5
    assert rust_upload_soak.safe_float("bad") == 0.0


def test_find_hash_item_handles_retired_transfer_and_local_share(monkeypatch: pytest.MonkeyPatch) -> None:
    file_hash = "00112233445566778899aabbccddeeff"
    responses = {
        "/api/v1/transfers": {"items": []},
        "/api/v1/shared-files": {"items": [{"hash": file_hash, "path": "C:\\incoming\\payload.bin"}]},
    }
    monkeypatch.setattr(rust_upload_soak, "request_json", lambda _base, _method, path, _key: responses[path])

    assert rust_upload_soak.find_hash_item("http://127.0.0.1", "key", "/api/v1/transfers", file_hash) is None
    assert rust_upload_soak.find_hash_item("http://127.0.0.1", "key", "/api/v1/shared-files", file_hash) == responses["/api/v1/shared-files"]["items"][0]


def test_verify_download_delivery_checks_library_promotion(tmp_path: Path) -> None:
    delivered = tmp_path / "incoming" / "payload.bin"
    payload = rust_upload_soak.write_payload(delivered, 4096)

    result = rust_upload_soak.verify_download_delivery(
        None,
        {"hash": "00112233445566778899aabbccddeeff", "sizeBytes": payload["sizeBytes"], "path": str(delivered)},
        payload,
        require_completion=True,
        require_delivered_path=True,
    )

    assert result["ok"] is True
    assert result["completed"] is True
    assert result["deliveredPathPresent"] is True
    assert result["deliveredFileExists"] is True
    assert result["deliveredFileSizeBytes"] == payload["sizeBytes"]
    assert result["deliveredSha256"] == payload["sha256"]


def test_verify_download_delivery_rejects_incomplete_transfer(tmp_path: Path) -> None:
    payload = rust_upload_soak.write_payload(tmp_path / "payload.bin", 4096)

    with pytest.raises(RuntimeError, match="did not enter the verified library"):
        rust_upload_soak.verify_download_delivery(
            {"state": "downloading", "completedBytes": 1024},
            None,
            payload,
            require_completion=True,
            require_delivered_path=False,
        )


def test_delivered_path_requires_retired_transfer(tmp_path: Path) -> None:
    delivered = tmp_path / "incoming" / "payload.bin"
    payload = rust_upload_soak.write_payload(delivered, 4096)

    with pytest.raises(RuntimeError, match="still has a transfer row"):
        rust_upload_soak.verify_download_delivery(
            {"state": "completed", "completedBytes": 4096},
            {"sizeBytes": 4096, "path": str(delivered)},
            payload,
            require_completion=False,
            require_delivered_path=True,
        )
