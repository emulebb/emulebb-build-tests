from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from emule_test_harness.diag_event_schema import ED2K_TCP_PACKET_VIEW_SCHEMA

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


def _ed2k(
    flow: str,
    direction: str,
    opcode: int,
    name: str,
    *,
    peer_hash: str | None = "00112233445566778899aabbccddeeff",
    file_hash: str | None = None,
) -> dict[str, object]:
    return {
        "schema": ED2K_TCP_PACKET_VIEW_SCHEMA,
        "flow": flow,
        "direction": direction,
        "protocol_marker": 0xE3,
        "opcode": opcode,
        "opcode_name": name,
        "payload_len": 0,
        "payload_hex": "",
        "peer_hash": peer_hash,
        "file_hash": file_hash,
    }


def _diag_envelope(
    *,
    client: str,
    sequence: int,
    family: str,
    body: dict[str, object],
    event: str = "packet",
    stream_sequence: int = 1,
    keys: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "client": client,
        "ts": "2026-10-24T00:00:00.000Z",
        "runId": f"{client}-run",
        "processId": 42,
        "segmentId": 0,
        "seq": sequence,
        "streamSeq": stream_sequence,
        "family": family,
        "event": event,
        "severity": "info",
        "keys": (
            keys
            if keys is not None
            else {
                "peer": "198.51.100.1:4662",
                "protocolMarker": body["protocolMarker"],
                "opcode": body["opcode"],
            }
        ),
        "body": body,
    }


def _ed2k_diag(*, client: str, sequence: int, flow: str, direction: str) -> dict[str, object]:
    return _diag_envelope(
        client=client,
        sequence=sequence,
        family="ed2k_tcp",
        keys={
            "peer": "198.51.100.1:4662",
            "peerHash": "00112233445566778899aabbccddeeff",
            "protocolMarker": 0xE3,
            "opcode": 0x01,
        },
        body={
            "direction": direction,
            "flow": flow,
            "transportMode": "plaintext",
            "obfuscated": False,
            "protocolMarker": 0xE3,
            "protocolName": "ed2k",
            "opcode": 0x01,
            "opcodeName": "OP_HELLO",
            "rawLen": 8,
            "rawHex": "e30200000001aabb",
            "clearFrameLen": 8,
            "clearFrameHex": "e30200000001aabb",
            "payloadLen": 2,
            "payloadHex": "aabb",
            "payloadHexTruncated": False,
        },
    )


def _kad_diag(*, client: str, sequence: int) -> dict[str, object]:
    return _diag_envelope(
        client=client,
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


def _client_udp_diag(
    *, client: str, sequence: int, event: str, stream_sequence: int
) -> dict[str, object]:
    attempt_id = 1
    body: dict[str, object]
    if event == "packet":
        body = {
            "direction": "send",
            "outcome": "attempted",
            "sendAttemptId": attempt_id,
            "rawHex": "AABB",
            "rawLen": 2,
        }
    else:
        body = {
            "outcome": "send_succeeded",
            "sendAttemptId": attempt_id,
            "deliveryKnown": True,
        }
    return _diag_envelope(
        client=client,
        sequence=sequence,
        family="ed2k_client_udp",
        event=event,
        stream_sequence=stream_sequence,
        keys={"sendAttemptId": attempt_id},
        body=body,
    )


def _kad_event_diag(*, client: str, sequence: int) -> dict[str, object]:
    return _diag_envelope(
        client=client,
        sequence=sequence,
        family="kad_event",
        event="state",
        keys={},
        body={"connected": True, "bootstrapping": False},
    )


def _server_udp_diag(*, client: str, sequence: int) -> dict[str, object]:
    return _diag_envelope(
        client=client,
        sequence=sequence,
        family="ed2k_server_udp",
        event="packet",
        keys={"protocolMarker": 0xE3, "opcode": 0xA2},
        body={
            "direction": "send",
            "outcome": "send_succeeded",
            "protocolMarker": 0xE3,
            "protocolName": "ed2k",
            "opcode": 0xA2,
            "opcodeName": "OP_GLOBSERVSTATREQ",
            "payloadLen": 1,
            "payloadHex": "00",
            "payloadHexTruncated": False,
        },
    )


def _server_connection_diag(
    *,
    client: str,
    sequence: int,
    previous_state: str,
    state: str,
    outcome: str,
) -> dict[str, object]:
    peer = "198.51.100.1:4661"
    return _diag_envelope(
        client=client,
        sequence=sequence,
        family="ed2k_tcp",
        event="connection_state",
        keys={"peer": peer, "flow": "server", "traceId": 1},
        body={
            "flow": "server",
            "phase": "connection",
            "traceKey": f"server:tcp:{peer}",
            "traceId": 1,
            "previousState": previous_state,
            "state": state,
            "outcome": outcome,
            "transportMode": "plaintext",
            "obfuscated": False,
            "error": None,
        },
    )


def _complete_diagnostics(client: str) -> list[dict[str, object]]:
    return [
        _ed2k_diag(client=client, sequence=1, flow="client", direction="recv"),
        _client_udp_diag(client=client, sequence=2, event="packet", stream_sequence=1),
        _client_udp_diag(client=client, sequence=3, event="send_outcome", stream_sequence=2),
        _kad_diag(client=client, sequence=4),
        _kad_event_diag(client=client, sequence=5),
        _server_udp_diag(client=client, sequence=6),
        _server_connection_diag(
            client=client,
            sequence=7,
            previous_state="not_connected",
            state="connecting",
            outcome="attempt_started",
        ),
        _server_connection_diag(
            client=client,
            sequence=8,
            previous_state="connecting",
            state="awaiting_idchange",
            outcome="transport_connected",
        ),
        _server_connection_diag(
            client=client,
            sequence=9,
            previous_state="awaiting_idchange",
            state="connected",
            outcome="login_accepted",
        ),
    ]


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows), encoding="utf-8")


def test_build_summary_reports_opcode_and_upload_coverage() -> None:
    module = load_script_module()
    rust = [
        _ed2k("client", "send", 0x01, "OP_HELLO"),
        _ed2k(
            "listener",
            "send",
            0x54,
            "OP_STARTUPLOADREQ",
            file_hash="ffeeddccbbaa99887766554433221100",
        ),
    ]
    mfc = [_ed2k("client", "send", 0x01, "OP_HELLO")]
    rust_diagnostics = _complete_diagnostics("rust")
    mfc_diagnostics = _complete_diagnostics("mfc")

    summary = module.build_summary(rust, mfc, rust_diagnostics, mfc_diagnostics)

    assert summary["schema"] == "packet_coverage_summary_v2"
    assert summary["records"] == {
        "rustDiagnosticEvents": 9,
        "mfcDiagnosticEvents": 9,
        "rustEd2k": 2,
        "mfcEd2k": 1,
        "rustKadUdp": 1,
        "mfcKadUdp": 1,
        "rustServerUdp": 1,
        "mfcServerUdp": 1,
    }
    assert summary["ed2kOpcodeCoverage"]["ok"] is False
    assert summary["ed2kJoinKeyCoverage"] == {
        "ok": True,
        "rust": {
            "ok": True,
            "packetCount": 2,
            "peerHashPackets": 2,
            "filePacketCount": 1,
            "fileHashPackets": 1,
            "missingFileHashByOpcode": [],
        },
        "mfc": {
            "ok": True,
            "packetCount": 1,
            "peerHashPackets": 1,
            "filePacketCount": 0,
            "fileHashPackets": 0,
            "missingFileHashByOpcode": [],
        },
    }
    assert summary["kadOpcodeCoverage"]["oracleOk"] is True
    assert summary["serverUdpOpcodeCoverage"]["oracleOk"] is True
    assert summary["persistedSoakConformance"]["ok"] is True
    assert summary["rustUploadServing"] == [
        {"flow": "listener", "direction": "send", "opcodeName": "OP_STARTUPLOADREQ", "count": 1}
    ]
    assert summary["kadUdpHistogram"]["rust"] == [
        {
            "direction": "send",
            "opcodeName": "KADEMLIA2_REQ",
            "count": 1,
        }
    ]
    assert summary["kadUdpHistogram"]["mfc"] == [
        {
            "direction": "send",
            "opcodeName": "KADEMLIA2_REQ",
            "count": 1,
        }
    ]


def test_build_summary_rejects_missing_mfc_kad_evidence() -> None:
    module = load_script_module()
    rust_diagnostics = _complete_diagnostics("rust")
    mfc_diagnostics = [
        record
        for record in _complete_diagnostics("mfc")
        if record["family"] not in {"kad_udp", "kad_event"}
    ]

    summary = module.build_summary(
        module.diag_event_diff.ed2k_tcp_packet_views(rust_diagnostics),
        module.diag_event_diff.ed2k_tcp_packet_views(mfc_diagnostics),
        rust_diagnostics,
        mfc_diagnostics,
    )

    assert summary["persistedSoakConformance"]["ok"] is False
    required = {
        row["family"]: row
        for row in summary["persistedSoakConformance"]["familyConformance"][
            "requiredFamilies"
        ]
    }
    assert required["kad_udp"] == {
        "family": "kad_udp",
        "rustPresent": True,
        "mfcPresent": False,
        "ok": False,
    }
    assert required["kad_event"]["ok"] is False


def test_build_summary_rejects_missing_file_join_key() -> None:
    module = load_script_module()
    rust = [_ed2k("listener", "send", 0x46, "OP_SENDINGPART")]
    mfc = [
        _ed2k(
            "listener",
            "send",
            0x46,
            "OP_SENDINGPART",
            file_hash="ffeeddccbbaa99887766554433221100",
        )
    ]

    summary = module.build_summary(
        rust,
        mfc,
        _complete_diagnostics("rust"),
        _complete_diagnostics("mfc"),
    )

    assert summary["ed2kJoinKeyCoverage"]["ok"] is False
    assert summary["ed2kJoinKeyCoverage"]["rust"]["missingFileHashByOpcode"] == [
        {"opcodeName": "OP_SENDINGPART", "count": 1}
    ]


def test_build_summary_rejects_missing_mfc_server_udp_evidence() -> None:
    module = load_script_module()
    rust_diagnostics = _complete_diagnostics("rust")
    mfc_diagnostics = [
        record
        for record in _complete_diagnostics("mfc")
        if record["family"] != "ed2k_server_udp"
    ]

    summary = module.build_summary(
        module.diag_event_diff.ed2k_tcp_packet_views(rust_diagnostics),
        module.diag_event_diff.ed2k_tcp_packet_views(mfc_diagnostics),
        rust_diagnostics,
        mfc_diagnostics,
    )

    assert summary["persistedSoakConformance"]["ok"] is False
    required = {
        row["family"]: row
        for row in summary["persistedSoakConformance"]["familyConformance"][
            "requiredFamilies"
        ]
    }
    assert required["ed2k_server_udp"] == {
        "family": "ed2k_server_udp",
        "rustPresent": True,
        "mfcPresent": False,
        "ok": False,
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
        _complete_diagnostics("rust"),
    )
    _write_jsonl(
        mfc_dir / "emulebb-mfc-diag-42-mfc-run-000000.jsonl",
        _complete_diagnostics("mfc"),
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
    assert summary["records"] == {
        "rustDiagnosticEvents": 9,
        "mfcDiagnosticEvents": 9,
        "rustEd2k": 1,
        "mfcEd2k": 1,
        "rustKadUdp": 1,
        "mfcKadUdp": 1,
        "rustServerUdp": 1,
        "mfcServerUdp": 1,
    }
    assert summary["ed2kOpcodeCoverage"]["ok"] is True
    assert summary["kadOpcodeCoverage"]["oracleOk"] is True
    assert summary["serverUdpOpcodeCoverage"]["oracleOk"] is True
    assert summary["persistedSoakConformance"]["ok"] is True
