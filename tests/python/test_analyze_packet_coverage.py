from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "analyze-packet-coverage.py"
    spec = importlib.util.spec_from_file_location("analyze_packet_coverage_test_module", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ed2k(flow: str, direction: str, opcode: int, name: str) -> dict[str, object]:
    return {
        "schema": "ed2k_packet_v1",
        "flow": flow,
        "direction": direction,
        "protocol_marker": 0xE3,
        "opcode": opcode,
        "opcode_name": name,
        "payload_len": 0,
        "payload_hex": "",
    }


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows), encoding="utf-8")


def test_build_summary_reports_opcode_and_upload_coverage() -> None:
    module = load_script_module()
    rust = [
        _ed2k("client", "send", 0x01, "OP_HELLO"),
        _ed2k("listener", "send", 0x54, "OP_STARTUPLOADREQ"),
    ]
    mfc = [_ed2k("client", "send", 0x01, "OP_HELLO")]
    kad = [
        {"schema": "udp_packet_v1", "direction": "recv", "opcode_name": "KADEMLIA_REQ"},
        {"schema": "udp_packet_v1", "direction": "recv", "opcode_name": "KADEMLIA_REQ"},
        {"schema": "udp_packet_v1", "direction": "send", "opcode": "0x89"},
    ]

    summary = module.build_summary(rust, mfc, kad)

    assert summary["schema"] == "packet_coverage_summary_v1"
    assert summary["records"] == {"rustEd2k": 2, "mfcEd2k": 1, "rustKadUdp": 3}
    assert summary["ed2kOpcodeCoverage"]["ok"] is False
    assert summary["rustUploadServing"] == [
        {"flow": "listener", "direction": "send", "opcodeName": "OP_STARTUPLOADREQ", "count": 1}
    ]
    assert summary["kadUdpHistogram"][0] == {
        "direction": "recv",
        "opcodeName": "KADEMLIA_REQ",
        "count": 2,
    }


def test_main_writes_json_summary(tmp_path: Path) -> None:
    module = load_script_module()
    rust_dir = tmp_path / "rust"
    rust_dir.mkdir()
    mfc_log = tmp_path / "mfc-packet.log"
    json_output = tmp_path / "coverage" / "summary.json"
    _write_jsonl(
        rust_dir / "emulebb-rust-ed2k-tcp-dump-1.jsonl",
        [_ed2k("client", "recv", 0x01, "OP_HELLO")],
    )
    _write_jsonl(
        rust_dir / "emulebb-rust-kad-udp-dump-1.jsonl",
        [{"schema": "udp_packet_v1", "direction": "send", "opcode_name": "KADEMLIA_REQ"}],
    )
    _write_jsonl(mfc_log, [_ed2k("client", "recv", 0x01, "OP_HELLO")])

    assert module.main(
        [
            "--rust-dump-dir",
            str(rust_dir),
            "--mfc-log",
            str(mfc_log),
            "--json-output",
            str(json_output),
        ]
    ) == 0

    summary = json.loads(json_output.read_text(encoding="utf-8"))
    assert summary["records"] == {"rustEd2k": 1, "mfcEd2k": 1, "rustKadUdp": 1}
    assert summary["ed2kOpcodeCoverage"]["ok"] is True
