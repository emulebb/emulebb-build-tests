from __future__ import annotations

import pytest

from emule_test_harness import transfer_diagnostic_evidence as evidence

FILE_HASH = "00112233445566778899aabbccddeeff"


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
    }
    payload_frame = {
        "direction": "recv",
        "outcome": "accepted",
        "opcodeName": "OP_SENDINGPART",
        "protocolMarker": 227,
        "opcode": 70,
        "clearFrameHex": "e31100000046ccdd",
    }
    rust = [
        record("rust", 10, "sched", "source_engaged", keys={"fileHash": FILE_HASH}, body={"outcome": "engaged"}),
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
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is True
    assert report["fileHash"] == FILE_HASH
    assert report["failures"] == []
    assert report["clients"]["mfc"]["checks"]["uploadPayloadSent"]["sentFileBytes"] == 4096
    evidence.require_transfer_diagnostic_evidence(report)


def test_build_transfer_diagnostic_evidence_rejects_hashless_completion() -> None:
    rust, mfc = complete_records()
    rust[-1]["keys"] = {}

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is False
    assert "Rust settled the exact download task as completed" in report["failures"]
    with pytest.raises(RuntimeError, match="diagnostics are incomplete"):
        evidence.require_transfer_diagnostic_evidence(report)


def test_build_transfer_diagnostic_evidence_rejects_zero_payload() -> None:
    rust, mfc = complete_records()
    mfc[-1]["body"] = {"sentFileBytes": 0}

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is False
    assert "MFC sent payload for the exact file" in report["failures"]


def test_build_transfer_diagnostic_evidence_rejects_unmatched_wire_frame() -> None:
    rust, mfc = complete_records()
    mfc[1]["body"]["clearFrameHex"] = "e31100000047ffff"

    report = evidence.build_transfer_diagnostic_evidence(
        file_hash=FILE_HASH,
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
        rust_records=rust,
        mfc_records=mfc,
    )

    assert report["ok"] is False
    assert report["ordering"]["mfc"]["ok"] is False


@pytest.mark.parametrize("value", ["", "xyz", "0" * 31, "0" * 33])
def test_normalize_ed2k_hash_rejects_invalid_value(value: str) -> None:
    with pytest.raises(ValueError, match="Invalid eD2K hash"):
        evidence.normalize_ed2k_hash(value)
