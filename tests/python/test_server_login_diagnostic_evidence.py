from __future__ import annotations

import copy
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
    server_flags: int = evidence.REQUIRED_STOCK_SERVER_FLAGS,
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
    trace_id: int,
    send_attempt_id: int | None = None,
) -> dict[str, object]:
    keys: dict[str, object] = {
        "opcode": opcode,
        "peer": ENDPOINT,
        "protocolMarker": ed2k_wire.PROTO_EDONKEY,
        "traceId": trace_id,
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
            "traceId": trace_id,
            "transportMode": transport_mode,
        },
    )


def canonical_records(
    client: str, transport_plan: tuple[str, ...] = ("plaintext",)
) -> list[dict[str, object]]:
    nickname = RUST_NICKNAME if client == "rust" else MFC_NICKNAME
    tcp_port = RUST_PORT if client == "rust" else MFC_PORT
    fallback = len(transport_plan) == 2
    failed_trace_id = 1
    final_trace_id = 2
    sequence = 0
    records: list[dict[str, object]] = []

    def next_sequence() -> int:
        nonlocal sequence
        sequence += 1
        return sequence

    def attempt_start(transport_mode: str, trace_id: int) -> dict[str, object]:
        return record(
            client,
            next_sequence(),
            "connection_state",
            keys={"flow": "server", "peer": ENDPOINT, "traceId": trace_id},
            body={
                "flow": "server",
                "outcome": "attempt_started",
                "phase": "connection",
                "state": "connecting",
                "traceId": trace_id,
                "transportMode": transport_mode,
            },
        )

    if fallback:
        records.append(attempt_start("obfuscated", failed_trace_id))
        if client == "mfc":
            records.append(
                packet(
                    client,
                    next_sequence(),
                    "send",
                    ed2k_wire.OP_LOGINREQUEST,
                    login_payload(client=client, nickname=nickname, tcp_port=tcp_port),
                    outcome="send_succeeded",
                    transport_mode="obfuscated",
                    trace_id=failed_trace_id,
                )
            )
        records.extend(
            [
                record(
                    client,
                    next_sequence(),
                    "connection_state",
                    keys={
                        "flow": "server",
                        "peer": ENDPOINT,
                        "traceId": failed_trace_id,
                    },
                    body={
                        "error": "crypt negotiation rejected",
                        "flow": "server",
                        "outcome": "connection_failed",
                        "phase": "connection",
                        "state": "server_dead",
                        "traceId": failed_trace_id,
                        "transportMode": "obfuscated",
                    },
                ),
                record(
                    client,
                    next_sequence(),
                    "transport_fallback",
                    keys={
                        "flow": "server",
                        "peer": ENDPOINT,
                        "traceId": failed_trace_id,
                    },
                    body={
                        "error": "crypt negotiation rejected",
                        "flow": "server",
                        "fromTransportMode": "obfuscated",
                        "outcome": "retrying",
                        "phase": "connection",
                        "toTransportMode": "plaintext",
                        "traceId": failed_trace_id,
                    },
                ),
            ]
        )
    records.append(attempt_start(transport_plan[-1], final_trace_id))
    records.append(
        packet(
            client,
            next_sequence(),
            "send",
            ed2k_wire.OP_LOGINREQUEST,
            login_payload(client=client, nickname=nickname, tcp_port=tcp_port),
            outcome="attempted" if client == "rust" else "send_succeeded",
            transport_mode=transport_plan[-1],
            trace_id=final_trace_id,
            send_attempt_id=11 if client == "rust" else None,
        )
    )
    if client == "rust":
        records.append(
            record(
                client,
                next_sequence(),
                "send_outcome",
                keys={
                    "opcode": ed2k_wire.OP_LOGINREQUEST,
                    "peer": ENDPOINT,
                    "protocolMarker": ed2k_wire.PROTO_EDONKEY,
                    "sendAttemptId": 11,
                    "traceId": final_trace_id,
                },
                body={
                    "deliveryKnown": True,
                    "direction": "send",
                    "flow": "server",
                    "opcode": ed2k_wire.OP_LOGINREQUEST,
                    "outcome": "send_succeeded",
                    "protocolMarker": ed2k_wire.PROTO_EDONKEY,
                    "traceId": final_trace_id,
                    "transportMode": transport_plan[-1],
                },
            )
        )
    records.extend(
        [
            packet(
                client,
                next_sequence(),
                "recv",
                ed2k_wire.OP_IDCHANGE,
                struct.pack("<I", 7 if client == "rust" else 8),
                outcome="accepted",
                transport_mode=transport_plan[-1],
                trace_id=final_trace_id,
            ),
            record(
                client,
                next_sequence(),
                "connection_state",
                keys={"flow": "server", "peer": ENDPOINT, "traceId": final_trace_id},
                body={
                    "flow": "server",
                    "outcome": "login_accepted",
                    "phase": "connection",
                    "state": "connected",
                    "traceId": final_trace_id,
                    "transportMode": transport_plan[-1],
                },
            ),
        ]
    )
    return records


def build(
    *,
    expected_transport_plan: tuple[str, ...] = ("plaintext",),
    rust_records: list[dict[str, object]] | None = None,
    mfc_records: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return evidence.build_server_login_diagnostic_evidence(
        server_endpoint=ENDPOINT,
        rust_nickname=RUST_NICKNAME,
        rust_tcp_port=RUST_PORT,
        mfc_nickname=MFC_NICKNAME,
        mfc_tcp_port=MFC_PORT,
        expected_transport_plan=expected_transport_plan,
        rust_records=(
            canonical_records("rust", expected_transport_plan)
            if rust_records is None
            else rust_records
        ),
        mfc_records=(
            canonical_records("mfc", expected_transport_plan)
            if mfc_records is None
            else mfc_records
        ),
    )


def test_bilateral_plaintext_stock_core_login_and_connection_are_claimable() -> None:
    report = build()

    assert report["ok"] is True
    assert report["clients"]["rust"]["extensionTags"] == {"offerfiles_v": 1}
    assert report["clients"]["mfc"]["extensionTags"] == {}
    assert report["clients"]["rust"]["transportObservation"]["login"] == "plaintext"
    assert report["clients"]["mfc"]["transportObservation"]["login"] == "plaintext"
    assert report["comparison"] == {
        "bothAccepted": True,
        "versionEqual": True,
        "serverFlagsEqual": True,
        "udpPortsTagEqual": True,
        "idKindEqual": True,
        "transportPlanExact": True,
        "traceCorrelationExact": True,
        "fallbackSequenceExact": True,
        "ok": True,
    }
    assert report["coverageClaims"] == {
        "eligibleCoverageIds": ["server.connect.plaintext", "server.login.request"],
        "evidenceLayers": list(evidence.EVIDENCE_LAYERS),
    }
    evidence.require_server_login_diagnostic_evidence(report)


def test_bilateral_required_obfuscated_login_and_connection_are_claimable() -> None:
    report = build(expected_transport_plan=("obfuscated",))

    assert report["ok"] is True
    assert report["expectedTransportPlan"] == ["obfuscated"]
    assert report["clients"]["rust"]["transportPlanExact"] is True
    assert report["clients"]["mfc"]["transportPlanExact"] is True
    assert report["coverageClaims"]["eligibleCoverageIds"] == [
        "server.connect.obfuscated",
        "server.login.request",
    ]


def test_bilateral_preferred_fallback_sequence_is_claimable() -> None:
    plan = ("obfuscated", "plaintext")

    report = build(expected_transport_plan=plan)

    assert report["ok"] is True
    assert report["expectedTransportPlan"] == list(plan)
    for client in ("rust", "mfc"):
        row = report["clients"][client]
        assert row["transportObservation"] == {
            "attempts": ["obfuscated", "plaintext"],
            "login": "plaintext",
            "idChange": "plaintext",
            "accepted": "plaintext",
        }
        assert row["connectionFailureCount"] == 1
        assert row["transportFallbackCount"] == 1
        assert row["connectionFailureSequence"] < row["transportFallbackSequence"]
        assert row["transportFallbackSequence"] < row["loginSequence"]
        assert row["failedTraceId"] != row["finalTraceId"]
        assert {
            row["loginTraceId"],
            row["idChangeTraceId"],
            row["loginAcceptedTraceId"],
        } == {row["finalTraceId"]}
        assert row["fallbackCausal"] is True
        assert row["traceCorrelation"] is True
    assert report["clients"]["rust"]["fallbackTraceId"] == 1
    assert report["clients"]["mfc"]["fallbackTraceId"] == 1
    assert report["clients"]["rust"]["loginPacketCount"] == 1
    assert report["clients"]["rust"]["failedAttemptLoginPacketCount"] == 0
    assert report["clients"]["mfc"]["loginPacketCount"] == 2
    assert report["clients"]["mfc"]["failedAttemptLoginPacketCount"] == 1
    assert report["coverageClaims"]["eligibleCoverageIds"] == [
        "server.connect.fallback",
        "server.login.request",
    ]


def test_mixed_transport_observations_are_evidence_incomplete() -> None:
    report = build(
        expected_transport_plan=("obfuscated",),
        rust_records=canonical_records("rust", ("obfuscated",)),
        mfc_records=canonical_records("mfc", ("plaintext",)),
    )

    assert report["ok"] is False
    assert report["clients"]["mfc"]["transportPlanExact"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_missing_mfc_login_is_evidence_incomplete() -> None:
    report = build(mfc_records=[])

    assert report["ok"] is False
    assert "client.mfc" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_shared_server_flags_must_match() -> None:
    mfc_records = canonical_records("mfc")
    mfc_records[1] = packet(
        "mfc",
        2,
        "send",
        ed2k_wire.OP_LOGINREQUEST,
        login_payload(
            client="mfc",
            nickname=MFC_NICKNAME,
            tcp_port=MFC_PORT,
            server_flags=evidence.REQUIRED_STOCK_SERVER_FLAGS | 0x4000,
        ),
        outcome="send_succeeded",
        transport_mode="plaintext",
        trace_id=2,
    )

    report = build(mfc_records=mfc_records)

    assert report["ok"] is False
    assert report["comparison"]["serverFlagsEqual"] is False


def test_unregistered_extension_tag_is_rejected() -> None:
    extra = bytes([0x80 | ed2k_wire.TAGTYPE_UINT32, 0xEE]) + struct.pack("<I", 1)
    rust_records = canonical_records("rust")
    rust_records[1] = packet(
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
        trace_id=2,
        send_attempt_id=11,
    )

    report = build(rust_records=rust_records)

    assert report["ok"] is False
    assert report["clients"]["rust"]["semanticShape"] is False


def test_duplicate_login_is_not_causally_attributable() -> None:
    rust_records = canonical_records("rust")
    rust_records.insert(1, {**rust_records[1]})

    report = build(rust_records=rust_records)

    assert report["ok"] is False
    assert report["clients"]["rust"]["loginPacketCount"] == 2
    assert report["clients"]["rust"]["finalLoginPacketCount"] == 2


def test_rust_login_requires_linked_send_success() -> None:
    rust_records = canonical_records("rust")
    rust_records.pop(2)

    report = build(rust_records=rust_records)

    assert report["ok"] is False
    assert report["clients"]["rust"]["sendSucceeded"] is False


def test_rust_send_outcome_must_join_final_trace() -> None:
    rust_records = canonical_records("rust")
    rust_records[2]["keys"]["traceId"] = 99
    rust_records[2]["body"]["traceId"] = 99

    report = build(rust_records=rust_records)

    assert report["ok"] is False
    assert report["clients"]["rust"]["sendSucceeded"] is False


def test_rust_send_outcome_must_follow_login() -> None:
    rust_records = canonical_records("rust")
    rust_records[2]["seq"] = rust_records[1]["seq"]
    rust_records[2]["streamSeq"] = rust_records[1]["streamSeq"]

    report = build(rust_records=rust_records)

    assert report["ok"] is False
    assert report["clients"]["rust"]["sendSucceeded"] is False


def test_rust_send_outcome_must_precede_id_change() -> None:
    rust_records = canonical_records("rust")
    rust_records[2]["seq"] = 6
    rust_records[2]["streamSeq"] = 6

    report = build(rust_records=rust_records)

    assert report["ok"] is False
    assert report["clients"]["rust"]["sendSucceeded"] is False


def test_rust_login_requires_exactly_one_send_outcome() -> None:
    rust_records = canonical_records("rust")
    failed_outcome = copy.deepcopy(rust_records[2])
    failed_outcome["seq"] = 4
    failed_outcome["streamSeq"] = 4
    failed_outcome["body"]["outcome"] = "send_failed"
    rust_records.insert(3, failed_outcome)

    report = build(rust_records=rust_records)

    assert report["ok"] is False
    assert report["clients"]["rust"]["sendSucceeded"] is False


def test_login_acceptance_must_follow_id_change() -> None:
    mfc_records = canonical_records("mfc")
    mfc_records[-1]["seq"] = 2
    mfc_records[-1]["streamSeq"] = 2

    report = build(mfc_records=mfc_records)

    assert report["ok"] is False
    assert report["clients"]["mfc"]["ok"] is False


def test_fallback_requires_one_structured_decision_between_attempts() -> None:
    mfc_records = canonical_records("mfc", ("obfuscated", "plaintext"))
    mfc_records.pop(3)

    report = build(
        expected_transport_plan=("obfuscated", "plaintext"),
        mfc_records=mfc_records,
    )

    assert report["ok"] is False
    assert report["clients"]["mfc"]["transportFallbackCount"] == 0
    assert report["clients"]["mfc"]["fallbackCausal"] is False


def test_fallback_requires_both_attempt_start_records() -> None:
    rust_records = canonical_records("rust", ("obfuscated", "plaintext"))
    rust_records.pop(3)

    report = build(
        expected_transport_plan=("obfuscated", "plaintext"),
        rust_records=rust_records,
    )

    assert report["ok"] is False
    assert report["clients"]["rust"]["attemptStartCount"] == 1
    assert report["clients"]["rust"]["attemptPlanExact"] is False


def test_extra_malformed_attempt_start_is_not_ignored() -> None:
    rust_records = canonical_records("rust", ("obfuscated", "plaintext"))
    rust_records.append(
        record(
            "rust",
            99,
            "connection_state",
            keys={"flow": "server", "peer": ENDPOINT, "traceId": 99},
            body={
                "flow": "server",
                "outcome": "attempt_started",
                "phase": "malformed",
                "state": "connecting",
                "traceId": 99,
                "transportMode": "plaintext",
            },
        )
    )

    report = build(
        expected_transport_plan=("obfuscated", "plaintext"),
        rust_records=rust_records,
    )

    assert report["ok"] is False
    assert report["clients"]["rust"]["attemptStartCount"] == 3
    assert report["clients"]["rust"]["attemptPlanExact"] is False


def test_extra_malformed_connection_failure_is_not_ignored() -> None:
    rust_records = canonical_records("rust", ("obfuscated", "plaintext"))
    rust_records.append(
        record(
            "rust",
            99,
            "connection_state",
            keys={"flow": "server", "peer": ENDPOINT, "traceId": 99},
            body={
                "flow": "server",
                "outcome": "connection_failed",
                "phase": "malformed",
                "state": "server_dead",
                "traceId": 99,
                "transportMode": "obfuscated",
            },
        )
    )

    report = build(
        expected_transport_plan=("obfuscated", "plaintext"),
        rust_records=rust_records,
    )

    assert report["ok"] is False
    assert report["clients"]["rust"]["connectionFailureCount"] == 2


def test_extra_malformed_login_acceptance_is_not_ignored() -> None:
    rust_records = canonical_records("rust")
    rust_records.append(
        record(
            "rust",
            99,
            "connection_state",
            keys={"flow": "server", "peer": ENDPOINT, "traceId": 99},
            body={
                "flow": "server",
                "outcome": "login_accepted",
                "phase": "malformed",
                "state": "connected",
                "traceId": 99,
                "transportMode": "plaintext",
            },
        )
    )

    report = build(rust_records=rust_records)

    assert report["ok"] is False
    assert report["clients"]["rust"]["loginAcceptedCount"] == 2


def test_failed_attempt_login_must_join_failed_trace() -> None:
    mfc_records = canonical_records("mfc", ("obfuscated", "plaintext"))
    mfc_records[1]["keys"]["traceId"] = 99
    mfc_records[1]["body"]["traceId"] = 99

    report = build(
        expected_transport_plan=("obfuscated", "plaintext"),
        mfc_records=mfc_records,
    )

    assert report["ok"] is False
    assert report["clients"]["mfc"]["failedAttemptLoginPacketCount"] == 1
    assert report["clients"]["mfc"]["fallbackCausal"] is False


def test_mfc_fallback_requires_failed_attempt_login() -> None:
    mfc_records = canonical_records("mfc", ("obfuscated", "plaintext"))
    mfc_records.pop(1)

    report = build(
        expected_transport_plan=("obfuscated", "plaintext"),
        mfc_records=mfc_records,
    )

    assert report["ok"] is False
    assert report["clients"]["mfc"]["failedAttemptLoginPacketCount"] == 0


def test_mfc_failed_attempt_login_must_succeed_on_socket() -> None:
    mfc_records = canonical_records("mfc", ("obfuscated", "plaintext"))
    mfc_records[1]["body"]["outcome"] = "send_failed"

    report = build(
        expected_transport_plan=("obfuscated", "plaintext"),
        mfc_records=mfc_records,
    )

    assert report["ok"] is False
    assert report["clients"]["mfc"]["failedAttemptLoginOutcome"] == "send_failed"


def test_fallback_requires_distinct_failed_and_final_attempts() -> None:
    mfc_records = canonical_records("mfc", ("obfuscated", "plaintext"))
    for record_value in mfc_records[4:]:
        record_value["keys"]["traceId"] = 1
        record_value["body"]["traceId"] = 1

    report = build(
        expected_transport_plan=("obfuscated", "plaintext"),
        mfc_records=mfc_records,
    )

    assert report["ok"] is False
    assert report["clients"]["mfc"]["failedTraceId"] == 1
    assert report["clients"]["mfc"]["finalTraceId"] == 1
    assert report["clients"]["mfc"]["traceCorrelation"] is False


def test_fallback_decision_must_join_the_failed_attempt_trace() -> None:
    rust_records = canonical_records("rust", ("obfuscated", "plaintext"))
    rust_records[2]["keys"]["traceId"] = 99
    rust_records[2]["body"]["traceId"] = 99

    report = build(
        expected_transport_plan=("obfuscated", "plaintext"),
        rust_records=rust_records,
    )

    assert report["ok"] is False
    assert report["clients"]["rust"]["fallbackTraceId"] == 99
    assert report["clients"]["rust"]["fallbackCausal"] is False


def test_fallback_decision_must_precede_plaintext_login() -> None:
    mfc_records = canonical_records("mfc", ("obfuscated", "plaintext"))
    mfc_records[3]["seq"] = 7
    mfc_records[3]["streamSeq"] = 7

    report = build(
        expected_transport_plan=("obfuscated", "plaintext"),
        mfc_records=mfc_records,
    )

    assert report["ok"] is False
    assert report["clients"]["mfc"]["fallbackCausal"] is False


def test_zero_sequence_cannot_satisfy_login_or_fallback_ordering() -> None:
    rust_records = canonical_records("rust", ("obfuscated", "plaintext"))
    rust_records[0]["seq"] = 0
    rust_records[0]["streamSeq"] = 0

    report = build(
        expected_transport_plan=("obfuscated", "plaintext"),
        rust_records=rust_records,
    )

    assert report["ok"] is False
    assert report["clients"]["rust"]["failedAttemptStartSequence"] is None
    assert report["clients"]["rust"]["attemptPlanExact"] is False
    assert report["clients"]["rust"]["fallbackCausal"] is False


def test_singular_transport_report_rejects_retired_mode_field() -> None:
    report = build()
    report["expectedTransportMode"] = "plaintext"

    try:
        evidence.require_server_login_diagnostic_evidence(report)
    except RuntimeError as exc:
        assert "invalid transport plan" in str(exc)
    else:
        raise AssertionError("retired singular transport field must be rejected")


def test_expected_profile_identity_must_match_wire() -> None:
    report = evidence.build_server_login_diagnostic_evidence(
        server_endpoint=ENDPOINT,
        rust_nickname="wrong-rust-profile",
        rust_tcp_port=RUST_PORT,
        mfc_nickname=MFC_NICKNAME,
        mfc_tcp_port=MFC_PORT,
        expected_transport_plan=("plaintext",),
        rust_records=canonical_records("rust"),
        mfc_records=canonical_records("mfc"),
    )

    assert report["ok"] is False
    assert report["clients"]["rust"]["semanticShape"] is False
