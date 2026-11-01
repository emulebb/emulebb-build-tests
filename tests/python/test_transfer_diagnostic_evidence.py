from __future__ import annotations

import pytest

from emule_test_harness import transfer_diagnostic_evidence as evidence

FILE_HASH = "00112233445566778899aabbccddeeff"
FILE_NAME = "fixture.bin"
FILE_SIZE = 9_728_001
AICH_ROOT = bytes.fromhex("44" * 20)
SOURCE_USER_HASH = "77" * 16


def record(
    client: str,
    seq: int,
    family: str,
    event: str,
    *,
    keys: dict[str, object] | None = None,
    body: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "client": client,
        "seq": seq,
        "streamSeq": seq,
        "family": family,
        "event": event,
        "keys": keys or {},
        "body": body or {},
    }


def packet_body(
    *,
    direction: str,
    outcome: str,
    opcode: int,
    opcode_name: str,
    payload: bytes,
) -> dict[str, object]:
    frame = bytes([0xC5]) + (len(payload) + 1).to_bytes(4, "little") + bytes([opcode]) + payload
    body: dict[str, object] = {
        "direction": direction,
        "outcome": outcome,
        "opcodeName": opcode_name,
        "protocolMarker": 0xC5,
        "opcode": opcode,
        "clearFrameHex": frame.hex(),
        "payloadHex": payload.hex(),
        "payloadHexTruncated": False,
        "payloadLen": len(payload),
        "transportMode": "plaintext",
        "obfuscated": False,
    }
    if direction == "send":
        body["attemptedLen"] = len(frame)
        body["writtenLen"] = len(frame)
    return body


def modern_startup_records() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    file_identifier = (
        b"\x07"
        + bytes.fromhex(FILE_HASH)
        + FILE_SIZE.to_bytes(8, "little")
        + AICH_ROOT
    )
    multipacket_request = file_identifier + b"\x58\x02\x00\x00\x00\x00\x4f"
    encoded_name = FILE_NAME.encode("utf-8")
    multipacket_answer = (
        file_identifier
        + b"\x59"
        + len(encoded_name).to_bytes(2, "little")
        + encoded_name
        + b"\x50\x02\x00\x03"
    )
    hashset_request = file_identifier + b"\x03"
    hashset_answer = (
        file_identifier
        + b"\x03"
        + bytes.fromhex(FILE_HASH)
        + b"\x02\x00"
        + bytes.fromhex("11" * 16 + "22" * 16)
        + AICH_ROOT
        + b"\x02\x00"
        + bytes.fromhex("55" * 20 + "66" * 20)
    )
    pairs = (
        (0xA9, "OP_MULTIPACKET_EXT2", multipacket_request, "rust"),
        (0xB0, "OP_MULTIPACKETANSWER_EXT2", multipacket_answer, "mfc"),
        (0xB1, "OP_HASHSETREQUEST2", hashset_request, "rust"),
        (0xB2, "OP_HASHSETANSWER2", hashset_answer, "mfc"),
    )
    rust: list[dict[str, object]] = []
    mfc: list[dict[str, object]] = []
    for seq, (opcode, opcode_name, payload, sender) in enumerate(pairs, start=2):
        receiver = "mfc" if sender == "rust" else "rust"
        keys = {"fileHash": FILE_HASH, "protocolMarker": 0xC5, "opcode": opcode}
        send = record(
            sender,
            seq,
            "ed2k_tcp",
            "packet",
            keys=keys,
            body=packet_body(
                direction="send",
                outcome="send_succeeded",
                opcode=opcode,
                opcode_name=opcode_name,
                payload=payload,
            ),
        )
        receive = record(
            receiver,
            seq,
            "ed2k_tcp",
            "packet",
            keys=keys,
            body=packet_body(
                direction="recv",
                outcome="accepted",
                opcode=opcode,
                opcode_name=opcode_name,
                payload=payload,
            ),
        )
        (rust if sender == "rust" else mfc).append(send)
        (rust if receiver == "rust" else mfc).append(receive)
    return rust, mfc


def complete_manifest() -> dict[str, object]:
    return {
        "file_hash": FILE_HASH,
        "canonical_name": FILE_NAME,
        "file_size": FILE_SIZE,
        "completed": True,
        "md4_hashset_acquired": True,
        "md4_hashset": ["11" * 16, "22" * 16],
        "aich_hashset_acquired": True,
        "aich_root": AICH_ROOT.hex(),
        "aich_hashset": ["55" * 20, "66" * 20],
        "sources": [
            {
                "ip": "127.0.0.1",
                "tcp_port": 4662,
                "user_hash": SOURCE_USER_HASH,
            }
        ],
    }


def packet_named(records: list[dict[str, object]], opcode_name: str) -> dict[str, object]:
    return next(record for record in records if record["body"].get("opcodeName") == opcode_name)


def replace_packet_payload(record: dict[str, object], payload: bytes) -> None:
    body = record["body"]
    opcode = int(body["opcode"])
    frame = bytes([0xC5]) + (len(payload) + 1).to_bytes(4, "little") + bytes([opcode]) + payload
    body["payloadHex"] = payload.hex()
    body["payloadLen"] = len(payload)
    body["clearFrameHex"] = frame.hex()
    if body["direction"] == "send":
        body["attemptedLen"] = len(frame)
        body["writtenLen"] = len(frame)


def use_hash_only_request_identifiers(
    rust: list[dict[str, object]],
    mfc: list[dict[str, object]],
) -> None:
    full_identifier_len = 1 + 16 + 8 + 20
    hash_only_identifier = b"\x01" + bytes.fromhex(FILE_HASH)
    for opcode_name in ("OP_MULTIPACKET_EXT2", "OP_HASHSETREQUEST2"):
        for records in (rust, mfc):
            record = packet_named(records, opcode_name)
            payload = bytes.fromhex(str(record["body"]["payloadHex"]))
            replace_packet_payload(record, hash_only_identifier + payload[full_identifier_len:])


def complete_records() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    request_frame = {
        "direction": "send",
        "outcome": "send_succeeded",
        "opcodeName": "OP_REQUESTPARTS",
        "protocolMarker": 227,
        "opcode": 71,
        "clearFrameHex": "e31100000047aabb",
        "attemptedLen": 8,
        "writtenLen": 8,
        "transportMode": "plaintext",
        "obfuscated": False,
    }
    payload_frame = {
        "direction": "recv",
        "outcome": "accepted",
        "opcodeName": "OP_SENDINGPART",
        "protocolMarker": 227,
        "opcode": 70,
        "clearFrameHex": "e31100000046ccdd",
        "transportMode": "plaintext",
        "obfuscated": False,
    }
    startup_rust, startup_mfc = modern_startup_records()
    rust = [
        *startup_rust,
        record("rust", 1, "sched", "source_engaged", keys={"fileHash": FILE_HASH}, body={"outcome": "engaged"}),
        record(
            "rust",
            11,
            "ed2k_tcp",
            "packet",
            keys={"fileHash": FILE_HASH, "protocolMarker": 227, "opcode": 71},
            body=request_frame,
        ),
        record(
            "rust",
            12,
            "ed2k_tcp",
            "packet",
            keys={"fileHash": FILE_HASH, "protocolMarker": 227, "opcode": 70},
            body=payload_frame,
        ),
        record(
            "rust",
            13,
            "sched",
            "download_payload_accepted",
            keys={"fileHash": FILE_HASH},
            body={"bytes": 2048},
        ),
        record(
            "rust",
            14,
            "sched",
            "download_task_settled",
            keys={"fileHash": FILE_HASH},
            body={"state": "completed", "willReask": False},
        ),
    ]
    mfc = [
        *startup_mfc,
        record(
            "mfc",
            20,
            "sched",
            "shared_publish_offer_batch",
            body={"fileHashes": [FILE_HASH]},
        ),
        record(
            "mfc",
            21,
            "ed2k_tcp",
            "packet",
            keys={"fileHash": FILE_HASH, "protocolMarker": 227, "opcode": 71},
            body={**request_frame, "direction": "recv", "outcome": "accepted"},
        ),
        record(
            "mfc",
            22,
            "ed2k_tcp",
            "packet",
            keys={"fileHash": FILE_HASH, "protocolMarker": 227, "opcode": 70},
            body={**payload_frame, "direction": "send", "outcome": "send_succeeded"},
        ),
        record(
            "mfc",
            23,
            "sched",
            "upload_slot_opened",
            keys={"fileHash": FILE_HASH},
            body={"outcome": "opened"},
        ),
        record(
            "mfc",
            24,
            "sched",
            "upload_request_outcome",
            keys={"fileHash": FILE_HASH},
            body={"outcomeClass": "served", "servedBytes": 0},
        ),
        record(
            "mfc",
            25,
            "sched",
            "upload_payload_accounting",
            keys={"fileHash": FILE_HASH},
            body={"sentFileBytes": 4096},
        ),
    ]
    return rust, mfc


def test_build_transfer_diagnostic_evidence_requires_complete_causal_chain() -> None:
    rust, mfc = complete_records()

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH.upper(),
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="plaintext",
        expected_payload_encoding="uncompressed",
        rust_manifest=complete_manifest(),
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is True
    assert report["fileHash"] == FILE_HASH
    assert report["failures"] == []
    assert report["expectedTransportMode"] == "plaintext"
    assert report["expectedPayloadEncoding"] == "uncompressed"
    assert report["wireChecks"]["requestTransport"]["ok"] is True
    assert report["wireChecks"]["payloadTransport"]["ok"] is True
    assert report["coverageClaims"] == {
        "eligibleCoverageIds": [
            "peer.startup.aich",
            "peer.startup.multipacket-ext2",
            "queue.admission",
            "transfer.block.uncompressed",
        ],
        "evidenceLayers": [
            "codec-transcript",
            "deterministic-state-machine",
            "local-cross-client",
        ],
    }
    assert report["clients"]["mfc"]["checks"]["uploadPayloadSent"]["sentFileBytes"] == 4096
    evidence.require_transfer_diagnostic_evidence(report)


def test_build_transfer_diagnostic_evidence_claims_hash_only_metadata_recovery() -> None:
    rust, mfc = complete_records()
    use_hash_only_request_identifiers(rust, mfc)

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="plaintext",
        expected_payload_encoding="uncompressed",
        rust_manifest=complete_manifest(),
        rust_records=rust,
        mfc_records=mfc,
        metadata_recovery_required=True,
        expected_source_host="127.0.0.1",
        expected_source_port=4662,
        expected_source_user_hash=SOURCE_USER_HASH,
    )

    assert report["ok"] is True
    assert report["metadataRecovery"]["sourceMatch"] is True
    assert report["coverageClaims"]["eligibleCoverageIds"] == [
        "peer.startup.aich",
        "peer.startup.metadata-recovery",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "transfer.block.uncompressed",
    ]


def test_build_transfer_diagnostic_evidence_rejects_metadata_recovery_source_drift() -> None:
    rust, mfc = complete_records()
    use_hash_only_request_identifiers(rust, mfc)

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="plaintext",
        expected_payload_encoding="uncompressed",
        rust_manifest=complete_manifest(),
        rust_records=rust,
        mfc_records=mfc,
        metadata_recovery_required=True,
        expected_source_host="127.0.0.1",
        expected_source_port=4662,
        expected_source_user_hash="88" * 16,
    )

    assert report["ok"] is False
    assert report["metadataRecovery"]["sourceMatch"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_build_transfer_diagnostic_evidence_rejects_hashless_completion() -> None:
    rust, mfc = complete_records()
    rust[-1]["keys"] = {}

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="plaintext",
        expected_payload_encoding="uncompressed",
        rust_manifest=complete_manifest(),
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []
    assert "Rust settled the exact download task as completed" in report["failures"]
    with pytest.raises(RuntimeError, match="diagnostics are incomplete"):
        evidence.require_transfer_diagnostic_evidence(report)


def test_build_transfer_diagnostic_evidence_rejects_zero_payload() -> None:
    rust, mfc = complete_records()
    mfc[-1]["body"] = {"sentFileBytes": 0}

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="plaintext",
        expected_payload_encoding="uncompressed",
        rust_manifest=complete_manifest(),
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is False
    assert "MFC sent payload for the exact file" in report["failures"]


def test_build_transfer_diagnostic_evidence_claims_only_observed_compression_variant() -> None:
    rust, mfc = complete_records()
    for packet in (
        packet_named(rust, "OP_SENDINGPART"),
        packet_named(mfc, "OP_SENDINGPART"),
    ):
        packet["keys"]["opcode"] = 64
        packet["body"]["opcode"] = 64
        packet["body"]["opcodeName"] = "OP_COMPRESSEDPART"
        packet["body"]["clearFrameHex"] = "e31100000040ccdd"

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="plaintext",
        expected_payload_encoding="compressed",
        rust_manifest=complete_manifest(),
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is True
    assert report["coverageClaims"]["eligibleCoverageIds"] == [
        "peer.startup.aich",
        "peer.startup.multipacket-ext2",
        "queue.admission",
        "transfer.block.compressed",
    ]
    assert "transfer.block.invalid-zlib" not in report["coverageClaims"]["eligibleCoverageIds"]
    assert "queue.rank-transition" not in report["coverageClaims"]["eligibleCoverageIds"]
    assert report["wireChecks"]["payloadEncoding"]["ok"] is True


def test_build_transfer_diagnostic_evidence_rejects_unmatched_wire_frame() -> None:
    rust, mfc = complete_records()
    packet_named(mfc, "OP_REQUESTPARTS")["body"]["clearFrameHex"] = "e31100000047ffff"

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="plaintext",
        expected_payload_encoding="uncompressed",
        rust_manifest=complete_manifest(),
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is False
    assert report["wireChecks"]["requestFrames"]["matchedFrameCount"] == 0
    assert "Rust request frames exactly match MFC receive frames" in report["failures"]


def test_build_transfer_diagnostic_evidence_rejects_out_of_order_chain() -> None:
    rust, mfc = complete_records()
    mfc[-1]["seq"] = 19

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="plaintext",
        expected_payload_encoding="uncompressed",
        rust_manifest=complete_manifest(),
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is False
    assert report["ordering"]["mfc"]["ok"] is False


def test_build_transfer_diagnostic_evidence_accepts_bilateral_obfuscated_transport() -> None:
    rust, mfc = complete_records()
    for packet in (
        packet_named(rust, "OP_REQUESTPARTS"),
        packet_named(rust, "OP_SENDINGPART"),
        packet_named(mfc, "OP_REQUESTPARTS"),
        packet_named(mfc, "OP_SENDINGPART"),
    ):
        packet["body"]["transportMode"] = "obfuscated"
        packet["body"]["obfuscated"] = True

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="obfuscated",
        expected_payload_encoding="uncompressed",
        rust_manifest=complete_manifest(),
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is True
    assert report["wireChecks"]["requestTransport"]["expectedObfuscated"] is True
    assert report["wireChecks"]["payloadTransport"]["ok"] is True


def test_build_transfer_diagnostic_evidence_rejects_transport_mismatch() -> None:
    rust, mfc = complete_records()
    rust_payload = packet_named(rust, "OP_SENDINGPART")
    rust_payload["body"]["transportMode"] = "obfuscated"
    rust_payload["body"]["obfuscated"] = True

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="plaintext",
        expected_payload_encoding="uncompressed",
        rust_manifest=complete_manifest(),
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is False
    assert report["wireChecks"]["payloadTransport"]["ok"] is False
    assert "Payload frames used the selected peer transport on both clients" in report["failures"]


def test_build_transfer_diagnostic_evidence_rejects_wrong_payload_encoding() -> None:
    rust, mfc = complete_records()

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="plaintext",
        expected_payload_encoding="compressed",
        rust_manifest=complete_manifest(),
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is False
    assert report["wireChecks"]["payloadEncoding"]["observedOpcodes"] == ["OP_SENDINGPART"]
    assert "Payload frames used only the selected encoding" in report["failures"]


def test_build_transfer_diagnostic_evidence_rejects_startup_filename_drift() -> None:
    rust, mfc = complete_records()
    answer = packet_named(mfc, "OP_MULTIPACKETANSWER_EXT2")
    answer["body"]["payloadHex"] = str(answer["body"]["payloadHex"]).replace(
        FILE_NAME.encode("utf-8").hex(),
        "x".encode("utf-8").hex() * len(FILE_NAME),
    )

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="plaintext",
        expected_payload_encoding="uncompressed",
        rust_manifest=complete_manifest(),
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is False
    assert report["startupChecks"]["multipacketAnswerSemantics"]["ok"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


def test_build_transfer_diagnostic_evidence_rejects_unpersisted_aich_hashset() -> None:
    rust, mfc = complete_records()
    manifest = complete_manifest()
    manifest["aich_hashset_acquired"] = False
    manifest["aich_hashset"] = []

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        expected_file_name=FILE_NAME,
        expected_file_size=FILE_SIZE,
        expected_transport_mode="plaintext",
        expected_payload_encoding="uncompressed",
        rust_manifest=manifest,
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is False
    assert report["startupChecks"]["persistedManifest"]["checks"]["aichAcquired"] is False
    assert report["startupChecks"]["persistedManifest"]["checks"]["aichHashset"] is False
    assert report["coverageClaims"]["eligibleCoverageIds"] == []


@pytest.mark.parametrize("value", ["", "xyz", "0" * 31, "0" * 33])
def test_normalize_ed2k_hash_rejects_invalid_value(value: str) -> None:
    with pytest.raises(ValueError, match="Invalid eD2K hash"):
        evidence.normalize_ed2k_hash(value)
