from __future__ import annotations

import struct

from emule_test_harness import ed2k_wire
from emule_test_harness import server_login_diagnostic_evidence as evidence

ENDPOINT = "127.0.0.1:4661"
RUST_NICKNAME = "cl-emulebb-rust-005"
MFC_NICKNAME = "cl-mfc-oracle-002"
RUST_PORT = 4662
MFC_PORT = 4663


def record(
    client: str,
    seq: int,
    event: str,
    *,
    keys: dict[str, object],
    body: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "client": client,
        "seq": seq,
        "streamSeq": seq,
        "family": "ed2k_tcp",
        "event": event,
        "keys": keys,
        "body": body,
    }


def login_payload(
    *,
    client: str,
    nickname: str,
    tcp_port: int,
    server_flags: int = evidence.REQUIRED_SERVER_FLAGS,
    extra_tags: list[bytes] | None = None,
) -> bytes:
    nickname_bytes = nickname.encode("utf-8")
    tags = [
        bytes([0x80 | ed2k_wire.TAGTYPE_STRING, ed2k_wire.CT_NAME])
        + struct.pack("<H", len(nickname_bytes))
        + nickname_bytes,
        bytes([0x80 | ed2k_wire.TAGTYPE_UINT32, evidence.CT_VERSION])
        + struct.pack("<I", 60),
        bytes([0x80 | ed2k_wire.TAGTYPE_UINT32, ed2k_wire.CT_SERVER_FLAGS])
        + struct.pack("<I", server_flags),
        bytes([0x80 | ed2k_wire.TAGTYPE_UINT32, evidence.CT_UDP_PORTS])
        + struct.pack("<I", 73_728),
    ]
    if client == "rust":
        extension_name = b"offerfiles_v"
        tags.append(
            bytes([ed2k_wire.TAGTYPE_UINT32])
            + struct.pack("<H", len(extension_name))
            + extension_name
            + struct.pack("<I", 1)
        )
    tags.extend(extra_tags or [])
    user_hash = (
        bytes.fromhex("00112233440E66778899AABBCCDD6FEF")
        if client == "rust"
        else bytes.fromhex("FFEEDDCCBB0E99887766554433226F00")
    )
    return (
        user_hash
        + struct.pack("<IH", 0, tcp_port)
        + struct.pack("<I", len(tags))
        + b"".join(tags)
    )


def packet(
    client: str,
    seq: int,
    direction: str,
    opcode: int,
    payload: bytes,
    *,
    outcome: str,
    transport_mode: str,
    send_attempt_id: int | None = None,
) -> dict[str, object]:
    keys: dict[str, object] = {
        "opcode": opcode,
        "peer": ENDPOINT,
        "protocolMarker": ed2k_wire.PROTO_EDONKEY,
    }
    if send_attempt_id is not None:
        keys["sendAttemptId"] = send_attempt_id
    return record(
        client,
        seq,
        "packet",
        keys=keys,
        body={
            "direction": direction,
            "flow": "server",
            "obfuscated": transport_mode == "obfuscated",
            "opcode": opcode,
            "outcome": outcome,
            "payloadHex": payload.hex(),
            "payloadHexTruncated": False,
            "payloadLen": len(payload),
            "protocolMarker": ed2k_wire.PROTO_EDONKEY,
            "sendAttemptId": send_attempt_id,
            "transportMode": transport_mode,
        },
    )


def canonical_records(client: str) -> list[dict[str, object]]:
    nickname = RUST_NICKNAME if client == "rust" else MFC_NICKNAME
    tcp_port = RUST_PORT if client == "rust" else MFC_PORT
    transport = "obfuscated" if client == "rust" else "plaintext"
    login = packet(
        client,
        2,
        "send",
        ed2k_wire.OP_LOGINREQUEST,
        login_payload(client=client, nickname=nickname, tcp_port=tcp_port),
        outcome="attempted" if client == "rust" else "send_succeeded",
        transport_mode=transport,
        send_attempt_id=11 if client == "rust" else None,
    )
    records = [login]
    if client == "rust":
        records.append(
            record(
                client,
                3,
                "send_outcome",
                keys={
                    "opcode": ed2k_wire.OP_LOGINREQUEST,
                    "peer": ENDPOINT,
                    "protocolMarker": ed2k_wire.PROTO_EDONKEY,
                    "sendAttemptId": 11,
                },
                body={
                    "deliveryKnown": True,
                    "direction": "send",
                    "flow": "server",
                    "opcode": ed2k_wire.OP_LOGINREQUEST,
                    "outcome": "send_succeeded",
                    "protocolMarker": ed2k_wire.PROTO_EDONKEY,
                },
            )
        )
    records.extend(
        [
            packet(
                client,
                5,
                "recv",
                ed2k_wire.OP_IDCHANGE,
                struct.pack("<I", 7 if client == "rust" else 8),
                outcome="accepted",
                transport_mode=transport,
            ),
            record(
                client,
                6,
                "connection_state",
                keys={"flow": "server", "peer": ENDPOINT, "traceId": 1},
                body={
                    "flow": "server",
                    "outcome": "login_accepted",
                    "state": "connected",
                    "traceId": 1,
                    "transportMode": transport,
                },
            ),
        ]
    )
    return records


def build(
    *,
    rust_records: list[dict[str, object]] | None = None,
    mfc_records: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return evidence.build_server_login_diagnostic_evidence(
        server_endpoint=ENDPOINT,
        rust_nickname=RUST_NICKNAME,
        rust_tcp_port=RUST_PORT,
        mfc_nickname=MFC_NICKNAME,
        mfc_tcp_port=MFC_PORT,
        rust_records=canonical_records("rust") if rust_records is None else rust_records,
        mfc_records=canonical_records("mfc") if mfc_records is None else mfc_records,
    )


def test_bilateral_stock_core_login_is_claimable() -> None:
    report = build()

    assert report["ok"] is True
    assert report["clients"]["rust"]["extensionTags"] == {"offerfiles_v": 1}
    assert report["clients"]["mfc"]["extensionTags"] == {}
    assert report["clients"]["rust"]["transportObservation"]["login"] == "obfuscated"
    assert report["clients"]["mfc"]["transportObservation"]["login"] == "plaintext"
    assert report["comparison"] == {
        "bothAccepted": True,
        "versionEqual": True,
        "serverFlagsEqual": True,
        "udpPortsTagEqual": True,
        "idKindEqual": True,
        "ok": True,
    }
    assert report["coverageClaims"] == {
        "eligibleCoverageIds": ["server.login.request"],
        "evidenceLayers": list(evidence.EVIDENCE_LAYERS),
    }
    evidence.require_server_login_diagnostic_evidence(report)


def test_missing_mfc_login_is_evidence_incomplete() -> None:
    report = build(mfc_records=[])

    assert report["ok"] is False
    assert "client.mfc" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_shared_server_flags_must_match() -> None:
    mfc_records = canonical_records("mfc")
    mfc_records[0] = packet(
        "mfc",
        2,
        "send",
        ed2k_wire.OP_LOGINREQUEST,
        login_payload(
            client="mfc",
            nickname=MFC_NICKNAME,
            tcp_port=MFC_PORT,
            server_flags=evidence.REQUIRED_SERVER_FLAGS | 0x4000,
        ),
        outcome="send_succeeded",
        transport_mode="plaintext",
    )

    report = build(mfc_records=mfc_records)

    assert report["ok"] is False
    assert report["comparison"]["serverFlagsEqual"] is False


def test_unregistered_extension_tag_is_rejected() -> None:
    extra = bytes([0x80 | ed2k_wire.TAGTYPE_UINT32, 0xEE]) + struct.pack("<I", 1)
    rust_records = canonical_records("rust")
    rust_records[0] = packet(
        "rust",
        2,
        "send",
        ed2k_wire.OP_LOGINREQUEST,
        login_payload(
            client="rust",
            nickname=RUST_NICKNAME,
            tcp_port=RUST_PORT,
            extra_tags=[extra],
        ),
        outcome="attempted",
        transport_mode="obfuscated",
        send_attempt_id=11,
    )

    report = build(rust_records=rust_records)

    assert report["ok"] is False
    assert report["clients"]["rust"]["semanticShape"] is False


def test_duplicate_login_is_not_causally_attributable() -> None:
    rust_records = canonical_records("rust")
    rust_records.insert(0, {**rust_records[0], "seq": 1, "streamSeq": 1})

    report = build(rust_records=rust_records)

    assert report["ok"] is False
    assert report["clients"]["rust"]["packetCount"] == 2


def test_rust_login_requires_linked_send_success() -> None:
    rust_records = canonical_records("rust")
    rust_records.pop(1)

    report = build(rust_records=rust_records)

    assert report["ok"] is False
    assert report["clients"]["rust"]["sendSucceeded"] is False


def test_login_acceptance_must_follow_id_change() -> None:
    mfc_records = canonical_records("mfc")
    mfc_records[-1]["seq"] = 4
    mfc_records[-1]["streamSeq"] = 4

    report = build(mfc_records=mfc_records)

    assert report["ok"] is False
    assert report["clients"]["mfc"]["ok"] is False


def test_expected_profile_identity_must_match_wire() -> None:
    report = evidence.build_server_login_diagnostic_evidence(
        server_endpoint=ENDPOINT,
        rust_nickname="wrong-rust-profile",
        rust_tcp_port=RUST_PORT,
        mfc_nickname=MFC_NICKNAME,
        mfc_tcp_port=MFC_PORT,
        rust_records=canonical_records("rust"),
        mfc_records=canonical_records("mfc"),
    )

    assert report["ok"] is False
    assert report["clients"]["rust"]["semanticShape"] is False
