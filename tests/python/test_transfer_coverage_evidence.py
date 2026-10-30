from __future__ import annotations

import json
from pathlib import Path

import pytest

from emule_test_harness import diag_event_runs, transfer_coverage_evidence

pytestmark = pytest.mark.unit


def _record(
    sequence: int,
    *,
    segment_id: int,
    family: str,
    event: str,
    keys: dict[str, object] | None = None,
    body: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "client": "rust",
        "processId": 42,
        "runId": "run-a",
        "segmentId": segment_id,
        "seq": sequence,
        "streamSeq": sequence,
        "family": family,
        "event": event,
        "severity": "info",
        "keys": keys or {},
        "body": body or {},
    }


def _segment(
    tmp_path: Path, segment_id: int, records: list[dict[str, object]]
) -> dict[str, object]:
    path = tmp_path / f"emulebb-rust-diag-42-run-a-{segment_id:06}.jsonl"
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    snapshot = diag_event_runs.load_diag_event_segment_snapshot(path)
    return {
        "segmentId": segment_id,
        "fileName": path.name,
        "source": str(path.resolve()),
        "bytes": snapshot.byte_count,
        "modifiedNs": snapshot.modified_ns,
        "sha256": snapshot.sha256,
        "recordCount": len(snapshot.records),
        "interestingReasons": [],
    }


def _empty() -> dict[str, object]:
    return transfer_coverage_evidence.new_evidence(
        client="rust",
        process_id=42,
        run_id="run-a",
        fixture_hashes=("a" * 32,),
        observed_utc="2026-10-31T00:00:00Z",
    )


def test_advance_retains_exact_bounded_protocol_chain(tmp_path: Path) -> None:
    segment = _segment(
        tmp_path,
        0,
        [
            _record(
                1,
                segment_id=0,
                family="sched",
                event="download_attempt_started",
                keys={"fileHash": "a" * 32},
            ),
            _record(
                2,
                segment_id=0,
                family="sched",
                event="source_engaged",
                keys={"fileHash": "a" * 32, "peer": "192.0.2.1:4662"},
            ),
            _record(
                3,
                segment_id=0,
                family="ed2k_tcp",
                event="packet",
                body={"opcodeName": "OP_QUEUERANKING", "direction": "recv"},
            ),
            _record(
                4,
                segment_id=0,
                family="ed2k_tcp",
                event="state",
                body={"phase": "queued_detached_udp_reask"},
            ),
            _record(
                5,
                segment_id=0,
                family="ed2k_client_udp",
                event="packet",
                keys={"sendAttemptId": 7},
                body={
                    "direction": "send",
                    "outcome": "attempted",
                    "role": "reask_request",
                    "sendAttemptId": 7,
                },
            ),
            _record(
                6,
                segment_id=0,
                family="ed2k_client_udp",
                event="send_outcome",
                keys={"sendAttemptId": 7},
                body={
                    "direction": "send",
                    "outcome": "send_succeeded",
                        "deliveryKnown": True,
                    "role": "reask_request",
                    "sendAttemptId": 7,
                },
            ),
            _record(7, segment_id=0, family="sched", event="reask_sent"),
            _record(8, segment_id=0, family="noise", event="ignored"),
        ],
    )

    evidence = transfer_coverage_evidence.advance_evidence(
        _empty(),
        (segment,),
        observed_utc="2026-10-31T00:01:00Z",
    )

    assert evidence["complete"] is True
    assert evidence["protocolChainComplete"] is True
    assert evidence["source"] == {
        "closedSegmentsScanned": 1,
        "lastClosedSegmentId": 0,
    }
    assert "ignored" not in json.dumps(evidence)
    assert set(evidence["proof"]) == {
        "download_attempt_started",
        "source_engaged",
        "queue_rank",
        "queued_detached_udp_reask",
        "client_udp_attempt",
        "client_udp_terminal",
        "reask_sent",
    }
    assert all(item["segment"]["sha256"] == segment["sha256"] for item in evidence["proof"].values())


def test_attempt_is_replaced_until_a_matching_terminal_is_observed(
    tmp_path: Path,
) -> None:
    first = _segment(
        tmp_path,
        0,
        [
            _record(
                1,
                segment_id=0,
                family="ed2k_client_udp",
                event="packet",
                body={"direction": "send", "role": "reask_request", "sendAttemptId": 7},
            )
        ],
    )
    second = _segment(
        tmp_path,
        1,
        [
            _record(
                2,
                segment_id=1,
                family="ed2k_client_udp",
                event="packet",
                body={
                    "direction": "send",
                    "role": "reask_request",
                    "sendAttemptId": 8,
                },
            ),
            _record(
                3,
                segment_id=1,
                family="ed2k_client_udp",
                event="send_outcome",
                body={
                    "direction": "send",
                    "role": "reask_request",
                    "sendAttemptId": 8,
                    "outcome": "send_succeeded",
                    "deliveryKnown": True,
                },
            ),
        ],
    )

    evidence = transfer_coverage_evidence.advance_evidence(
        _empty(),
        (first, second),
        observed_utc="2026-10-31T00:02:00Z",
    )

    assert evidence["proof"]["client_udp_attempt"]["record"]["body"]["sendAttemptId"] == 8
    assert evidence["proof"]["client_udp_terminal"]["record"]["body"]["sendAttemptId"] == 8
    assert evidence["complete"] is True


def test_failed_send_is_retained_without_completing_target(tmp_path: Path) -> None:
    segment = _segment(
        tmp_path,
        0,
        [
            _record(
                1,
                segment_id=0,
                family="ed2k_client_udp",
                event="packet",
                body={"direction": "send", "role": "reask_request", "sendAttemptId": 7},
            ),
            _record(
                2,
                segment_id=0,
                family="ed2k_client_udp",
                event="send_outcome",
                body={
                    "direction": "send",
                    "role": "reask_request",
                    "sendAttemptId": 7,
                    "outcome": "send_failed",
                    "deliveryKnown": True,
                },
            ),
        ],
    )

    evidence = transfer_coverage_evidence.advance_evidence(
        _empty(),
        (segment,),
        observed_utc="2026-10-31T00:01:00Z",
    )

    assert evidence["coverage"]["client_udp_send_failure"] is True
    assert evidence["coverage"]["client_udp_terminal"] is False
    assert evidence["complete"] is False


def test_fixture_hash_excludes_unrelated_transfer_events(tmp_path: Path) -> None:
    segment = _segment(
        tmp_path,
        0,
        [
            _record(
                1,
                segment_id=0,
                family="sched",
                event="source_engaged",
                keys={"fileHash": "b" * 32},
            )
        ],
    )

    evidence = transfer_coverage_evidence.advance_evidence(
        _empty(),
        (segment,),
        observed_utc="2026-10-31T00:01:00Z",
    )

    assert evidence["proof"] == {}
    assert evidence["source"]["closedSegmentsScanned"] == 1


def test_changed_segment_is_rejected_after_scanner_snapshot(tmp_path: Path) -> None:
    segment = _segment(tmp_path, 0, [_record(1, segment_id=0, family="noise", event="ignored")])
    Path(segment["source"]).write_text(
        json.dumps(_record(2, segment_id=0, family="noise", event="changed")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        transfer_coverage_evidence.TransferCoverageEvidenceError,
        match="changed after indexing",
    ):
        transfer_coverage_evidence.advance_evidence(
            _empty(),
            (segment,),
            observed_utc="2026-10-31T00:01:00Z",
        )


def test_write_and_load_enforce_exact_current_contract(tmp_path: Path) -> None:
    path = tmp_path / "transfer-coverage-evidence.json"

    byte_count = transfer_coverage_evidence.write_evidence(
        path,
        _empty(),
        max_bytes=16_384,
    )
    loaded = transfer_coverage_evidence.load_evidence(path)

    assert byte_count == path.stat().st_size
    assert loaded == _empty()
    assert not path.with_name(f"{path.name}.tmp").exists()


def test_write_fails_instead_of_truncating_exact_records(tmp_path: Path) -> None:
    with pytest.raises(
        transfer_coverage_evidence.TransferCoverageEvidenceError,
        match="exceeds its byte limit",
    ):
        transfer_coverage_evidence.write_evidence(
            tmp_path / "transfer-coverage-evidence.json",
            _empty(),
            max_bytes=10,
        )
