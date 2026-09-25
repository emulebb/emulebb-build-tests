from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_module():
    script_path = REPO_ROOT / "scripts" / "rust-linux-direct-smoke.py"
    spec = importlib.util.spec_from_file_location("rust_linux_direct_smoke_under_test", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_inputs(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(json.dumps({"auto_browse": {"direct_bootstrap_transfers": rows}}), encoding="utf-8")


def transfer(name: str, file_hash: str) -> dict[str, object]:
    return {
        "name": name,
        "hash": file_hash,
        "size": 123,
        "sha256": "a" * 64,
    }


def test_safe_transfers_require_requested_types_and_put_pdf_first(tmp_path: Path) -> None:
    module = load_module()
    inputs = tmp_path / "inputs.json"
    write_inputs(
        inputs,
        [
            transfer("distribution.iso", "1" * 32),
            transfer("manual.pdf", "2" * 32),
        ],
    )

    rows = module.load_safe_transfers(inputs, {"iso", "pdf"})

    assert [row["suffix"] for row in rows] == [".pdf", ".iso"]


def test_safe_transfers_fail_before_network_when_required_pdf_is_absent(tmp_path: Path) -> None:
    module = load_module()
    inputs = tmp_path / "inputs.json"
    write_inputs(inputs, [transfer("distribution.iso", "1" * 32)])

    with pytest.raises(RuntimeError, match=r"missing required transfer type\(s\): \.pdf"):
        module.load_safe_transfers(inputs, {"iso", "pdf"})


def test_safe_transfers_reject_paths_and_unapproved_extensions(tmp_path: Path) -> None:
    module = load_module()
    inputs = tmp_path / "inputs.json"
    write_inputs(inputs, [transfer("../payload.exe", "1" * 32)])

    with pytest.raises(RuntimeError, match="verified ISO/PDF"):
        module.load_safe_transfers(inputs)


def test_sha256_file_hashes_completed_payload(tmp_path: Path) -> None:
    module = load_module()
    payload = tmp_path / "manual.pdf"
    payload.write_bytes(b"safe fixture\n")

    assert module.sha256_file(payload) == "aec7add6c399ba7576af4cf2a888838cf159bd90876b431f3de1ba3e032efd90"
