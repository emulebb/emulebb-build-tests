from __future__ import annotations

from typing import Any

import pytest

from emule_test_harness import direct_callback_diagnostic_evidence as evidence
from emule_test_harness import direct_callback_probe


REQUESTER_HOST = "192.0.2.10"
REQUESTER_PORT = 24662
REQUESTER_HASH = bytes.fromhex("426486A8CAEC0E20426486A8CAEC6E00")
TARGET_HOST = "192.0.2.20"


def target(client_id: int, tcp_port: int, udp_port: int, byte: int) -> dict[str, object]:
    return {
        "clientId": client_id,
        "tcpPort": tcp_port,
        "udpPort": udp_port,
        "userHash": (bytes([byte]) * 16).hex().upper(),
        "idKind": "low-id",
    }


def result(client: str, row: dict[str, object], source_port: int) -> dict[str, object]:
    raw = direct_callback_probe.encode_direct_callback_request(
        tcp_port=REQUESTER_PORT,
        user_hash=REQUESTER_HASH,
        connect_options=0x01,
    )
    user_hash = bytes.fromhex(str(row["userHash"]))
    hello = (
        b"\x10"
        + user_hash
        + int(row["clientId"]).to_bytes(4, "little")
        + int(row["tcpPort"]).to_bytes(2, "little")
    )
    return {
        "schema": "emulebb.direct-callback-probe/1",
        "status": "completed",
        "targetLabel": client,
        "source": {"host": REQUESTER_HOST, "udpPort": source_port},
        "target": {"host": TARGET_HOST, "udpPort": row["udpPort"]},
        "requester": {
            "tcpPort": REQUESTER_PORT,
            "userHash": REQUESTER_HASH.hex().upper(),
            "clientId": direct_callback_probe.high_id_for_ipv4(REQUESTER_HOST),
            "connectOptions": 0x01,
        },
        "request": {
            "protocol": 0xC5,
            "opcode": 0x95,
            "rawHex": raw.hex().upper(),
            "payloadHex": raw[2:].hex().upper(),
            "sentBytes": len(raw),
            "sentAt": 1000.0,
        },
        "callbackConnection": {
            "userHash": row["userHash"],
            "clientId": row["clientId"],
            "tcpPort": row["tcpPort"],
            "payloadLength": len(hello),
            "payloadHex": hello.hex().upper(),
            "peerHost": TARGET_HOST,
            "peerPort": 50000 + int(row["clientId"]),
            "observedAt": 1000.1,
        },
    }


def packet(seq: int, source_port: int, raw: bytes | None = None) -> dict[str, Any]:
    raw = raw or direct_callback_probe.encode_direct_callback_request(
        tcp_port=REQUESTER_PORT,
        user_hash=REQUESTER_HASH,
        connect_options=0x01,
    )
    return {
        "schema": "diag_event_v2",
        "family": "ed2k_client_udp",
        "event": "packet",
        "seq": seq,
        "keys": {
            "peer": f"{REQUESTER_HOST}:{source_port}",
            "protocolMarker": 0xC5,
            "opcode": 0x95,
        },
        "body": {
            "direction": "recv",
            "outcome": "accepted",
            "stateId": "client_udp.direct_callback",
            "stateLabel": "direct_callback",
            "traceKey": f"client_udp:{REQUESTER_HOST}:{source_port}",
            "flow": "client_udp",
            "phase": "direct_callback_request",
            "transportMode": "plaintext",
            "obfuscated": False,
            "protocolMarker": 0xC5,
            "protocolName": "emule",
            "opcode": 0x95,
            "opcodeName": "OP_DIRECTCALLBACKREQ",
            "rawLen": len(raw),
            "rawHex": raw.hex(),
            "payloadLen": len(raw) - 2,
            "payloadHex": raw[2:].hex(),
            "payloadHexTruncated": False,
            "note": "direct_callback_raised",
        },
    }


def passing_report(
    *,
    rust_records: list[dict[str, Any]] | None = None,
    rust_result: dict[str, object] | None = None,
) -> dict[str, Any]:
    targets = {
        "rust": target(7, 4662, 4672, 0x11),
        "mfc": target(9, 4663, 4673, 0x22),
    }
    results = {
        "rust": rust_result or result("rust", targets["rust"], 31001),
        "mfc": result("mfc", targets["mfc"], 31002),
    }
    return evidence.build_direct_callback_diagnostic_evidence(
        requester_host=REQUESTER_HOST,
        requester_tcp_port=REQUESTER_PORT,
        requester_user_hash=REQUESTER_HASH,
        target_host=TARGET_HOST,
        targets=targets,
        requester_results=results,
        rust_records=rust_records or [packet(10, 31001)],
        mfc_records=[packet(20, 31002)],
    )


@pytest.mark.unit
def test_bilateral_direct_callback_is_claimable() -> None:
    report = passing_report()

    evidence.require_direct_callback_diagnostic_evidence(report)
    assert report["coverageClaims"]["eligibleCoverageIds"] == [
        "lowid.direct-callback"
    ]
    assert report["clients"]["rust"]["wireApplication"]["sequence"] == 10
    assert report["clients"]["mfc"]["wireApplication"]["sequence"] == 20


@pytest.mark.unit
def test_duplicate_receive_is_ambiguous() -> None:
    report = passing_report(
        rust_records=[packet(10, 31001), packet(11, 31001)]
    )

    assert report["ok"] is False
    assert report["clients"]["rust"]["wireApplication"]["packetCount"] == 2


@pytest.mark.unit
def test_receive_must_report_application_dispatch() -> None:
    wrong = packet(10, 31001)
    wrong["body"]["note"] = "direct_callback_disabled"
    report = passing_report(rust_records=[wrong])

    assert report["ok"] is False
    assert "client.rust" in report["failures"]


@pytest.mark.unit
def test_callback_hello_must_match_accepted_lowid_identity() -> None:
    row = target(7, 4662, 4672, 0x11)
    wrong = result("rust", row, 31001)
    wrong["callbackConnection"] = {
        **wrong["callbackConnection"],  # type: ignore[dict-item]
        "userHash": "FF" * 16,
    }
    report = passing_report(rust_result=wrong)

    assert report["ok"] is False
    assert report["clients"]["rust"]["requester"]["ok"] is False


@pytest.mark.unit
def test_stimulus_source_endpoint_must_match_receive_diagnostic() -> None:
    report = passing_report(rust_records=[packet(10, 31999)])

    assert report["ok"] is False
    assert report["clients"]["rust"]["wireApplication"]["packetCount"] == 0
