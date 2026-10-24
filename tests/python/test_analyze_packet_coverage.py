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


def _diag_envelope(
    *, client: str, sequence: int, family: str, body: dict[str, object]
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "client": client,
        "ts": "2026-10-24T00:00:00.000Z",
        "runId": f"{client}-run",
        "processId": 42,
        "segmentId": 0,
        "seq": sequence,
        "streamSeq": sequence,
        "family": family,
        "event": "packet",
        "severity": "info",
        "keys": {
            "peer": "198.51.100.1:4662",
            "protocolMarker": body["protocolMarker"],
            "opcode": body["opcode"],
        },
        "body": body,
    }


def _ed2k_diag(*, client: str, sequence: int, flow: str, direction: str) -> dict[str, object]:
    return _diag_envelope(
        client=client,
        sequence=sequence,
        family="ed2k_tcp",
        body={
            "direction": direction,
            "flow": flow,
            "transportMode": "plain",
            "obfuscated": False,
            "protocolMarker": 0xE3,
            "protocolName": "ed2k",
            "opcode": 0x01,
            "opcodeName": "OP_HELLO",
            "rawLen": 2,
            "rawHex": "aabb",
            "payloadLen": 2,
            "payloadHex": "aabb",
            "payloadHexTruncated": False,
        },
    )


def _kad_diag(*, sequence: int) -> dict[str, object]:
    return _diag_envelope(
        client="rust",
        sequence=sequence,
        family="kad_udp",
        body={
            "direction": "send",
            "protocolMarker": 0xE4,
            "opcode": 0x21,
            "opcodeName": "KADEMLIA2_REQ",
            "payloadLen": 1,
            "decodedHex": "00",
        },
    )


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
    rust_dir = tmp_path / "rust-diagnostics"
    mfc_dir = tmp_path / "mfc-diagnostics"
    rust_dir.mkdir()
    mfc_dir.mkdir()
    json_output = tmp_path / "coverage" / "summary.json"
    _write_jsonl(
        rust_dir / "emulebb-rust-diag-42-rust-run-000000.jsonl",
        [
            _ed2k_diag(client="rust", sequence=1, flow="client", direction="recv"),
            _kad_diag(sequence=2),
        ],
    )
    _write_jsonl(
        mfc_dir / "emulebb-mfc-diag-42-mfc-run-000000.jsonl",
        [_ed2k_diag(client="mfc", sequence=1, flow="client", direction="recv")],
    )

    assert module.main(
        [
            "--rust-diagnostics-dir",
            str(rust_dir),
            "--mfc-diagnostics-dir",
            str(mfc_dir),
            "--json-output",
            str(json_output),
        ]
    ) == 0

    summary = json.loads(json_output.read_text(encoding="utf-8"))
    assert summary["records"] == {"rustEd2k": 1, "mfcEd2k": 1, "rustKadUdp": 1}
    assert summary["ed2kOpcodeCoverage"]["ok"] is True
