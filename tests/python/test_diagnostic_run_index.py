from __future__ import annotations

import copy

import pytest

from emule_test_harness import diagnostic_run_index
from emule_test_harness.diag_event_runs import DIAGNOSTIC_WRITER_HEALTH_FIELDS


def record(
    sequence: int,
    *,
    segment_id: int = 0,
    family: str = "ed2k_tcp",
    stream_sequence: int | None = None,
    event: str = "packet",
    severity: str = "info",
    outcome: str | None = None,
    opcode: int | None = None,
    marker: int | None = None,
    keys: dict[str, object] | None = None,
) -> dict[str, object]:
    body: dict[str, object] = {}
    if outcome is not None:
        body["outcome"] = outcome
    if opcode is not None:
        body.update(
            {
                "opcode": opcode,
                "protocolMarker": marker if marker is not None else 0xE3,
                "opcodeName": f"OP_{opcode:02X}",
                "direction": "send",
            }
        )
    return {
        "schema": "diag_event_v2",
        "client": "rust",
        "processId": 42,
        "runId": "run-a",
        "segmentId": segment_id,
        "seq": sequence,
        "streamSeq": stream_sequence if stream_sequence is not None else sequence,
        "family": family,
        "event": event,
        "severity": severity,
        "keys": keys or {},
        "body": body,
    }


def writer_health(**updates: object) -> dict[str, object]:
    health: dict[str, object] = {field: 0 for field in DIAGNOSTIC_WRITER_HEALTH_FIELDS}
    health.update(
        {
            "schema": "diag_event_v2",
            "enabled": True,
            "configured": True,
            "initialized": True,
            "runId": "run-a",
            "processId": 42,
            "activeSegmentId": 0,
            "activeFileName": "emulebb-rust-diag-42-run-a-000000.jsonl",
            "retainedSegmentCount": 1,
            "availableBytes": 100,
            "storageAuthorityFaulted": False,
            "writerIoFaulted": False,
            "storageBlockReason": None,
            "storagePolicySatisfied": True,
            "maximumGrowthBytes": 10,
            "maxSegmentBytes": 10,
            "maxSegmentSeconds": 60,
            "retainedSegments": 2,
            "maxTotalBytes": 20,
            "maxRetainedSeconds": 3_600,
            "minimumFreeBytes": 1,
            "initializationFailure": None,
        }
    )
    health.update(updates)
    return health


def test_advance_records_builds_compact_family_opcode_and_outcome_index() -> None:
    index = diagnostic_run_index.new_index(client="rust", process_id=42, run_id="run-a")

    advanced = diagnostic_run_index.advance_records(
        index,
        [
            record(
                10,
                segment_id=3,
                opcode=1,
                outcome="attempted",
                keys={"peer": "198.51.100.2:4662", "peerHash": "00" * 16},
            ),
            record(
                11,
                segment_id=3,
                opcode=1,
                outcome="sent",
                keys={
                    "peer": "198.51.100.2:4662",
                    "peerHash": "00" * 16,
                    "fileHash": "11" * 16,
                },
            ),
            record(
                12,
                segment_id=4,
                family="kad_udp",
                stream_sequence=7,
                event="request_timeout",
                severity="warning",
                outcome="timed_out",
                opcode=2,
                marker=0xE4,
            ),
        ],
    )

    assert index["recordCount"] == 0
    assert advanced.index["recordCount"] == 3
    assert advanced.index["processSequence"] == {
        "first": 10,
        "last": 12,
        "omittedPrefix": 9,
    }
    assert advanced.index["segments"] == {
        "first": 3,
        "last": 4,
        "omittedPrefix": 3,
    }
    ed2k = advanced.index["families"]["ed2k_tcp"]
    assert ed2k["records"] == 2
    assert ed2k["events"] == {"packet": 2}
    assert ed2k["outcomes"] == {"attempted": 1, "sent": 1}
    assert ed2k["keyPresence"] == {
        "fileHash": 1,
        "peer": 2,
        "peerHash": 2,
    }
    assert ed2k["opcodes"]["227:1"] == {
        "protocolMarker": 227,
        "opcode": 1,
        "records": 2,
        "names": ["OP_01"],
        "directions": {"send": 2},
        "events": {"packet": 2},
        "outcomes": {"attempted": 1, "sent": 1},
        "keyPresence": {"fileHash": 1, "peer": 2, "peerHash": 2},
    }
    assert advanced.index["families"]["kad_udp"]["streamSequence"] == {
        "first": 7,
        "last": 7,
        "omittedPrefix": 6,
    }
    assert advanced.interesting_segments == {
        4: (
            "event:request_timeout",
            "outcome:timed_out",
            "severity:warning",
        )
    }


def test_advance_records_continues_existing_process_and_family_sequences() -> None:
    first = diagnostic_run_index.advance_records(
        diagnostic_run_index.new_index(client="rust", process_id=42, run_id="run-a"),
        [record(1)],
    ).index

    second = diagnostic_run_index.advance_records(
        first,
        [record(2, segment_id=1)],
    ).index

    assert second["processSequence"]["last"] == 2
    assert second["segments"]["last"] == 1
    assert second["families"]["ed2k_tcp"]["streamSequence"]["last"] == 2


def test_advance_records_indexes_keys_opcode_without_protocol_marker() -> None:
    event = record(1, family="kad_udp")
    event["keys"] = {"opcode": 2}
    event["body"] = {"direction": "recv"}

    advanced = diagnostic_run_index.advance_records(
        diagnostic_run_index.new_index(client="rust", process_id=42, run_id="run-a"),
        [event],
    )

    assert advanced.index["families"]["kad_udp"]["opcodes"]["null:2"] == {
        "protocolMarker": None,
        "opcode": 2,
        "records": 1,
        "names": [],
        "directions": {"recv": 1},
        "events": {"packet": 1},
        "outcomes": {},
        "keyPresence": {"opcode": 1},
    }


@pytest.mark.parametrize(
    ("records", "message"),
    [
        ([record(1), record(3)], "process sequence"),
        (
            [
                record(1),
                record(2, family="kad_udp", stream_sequence=1),
                record(3, stream_sequence=3),
            ],
            "ed2k_tcp stream sequence",
        ),
        ([record(1), record(2, segment_id=2)], "segment IDs"),
    ],
)
def test_advance_records_rejects_integrity_gaps(
    records: list[dict[str, object]], message: str
) -> None:
    with pytest.raises(diagnostic_run_index.DiagnosticRunIndexError, match=message):
        diagnostic_run_index.advance_records(
            diagnostic_run_index.new_index(
                client="rust", process_id=42, run_id="run-a"
            ),
            records,
        )


def test_advance_records_rejects_foreign_identity_without_mutating_index() -> None:
    index = diagnostic_run_index.new_index(client="rust", process_id=42, run_id="run-a")
    foreign = record(1)
    foreign["runId"] = "run-b"
    original = copy.deepcopy(index)

    with pytest.raises(
        diagnostic_run_index.DiagnosticRunIndexError, match="does not match"
    ):
        diagnostic_run_index.advance_records(index, [foreign])

    assert index == original


def test_advance_writer_health_keeps_first_latest_and_seen_violations() -> None:
    index = diagnostic_run_index.new_index(client="rust", process_id=42, run_id="run-a")
    first = diagnostic_run_index.advance_writer_health(
        index,
        writer_health(recordsWritten=1, bytesWritten=10),
        observed_utc="2026-10-25T10:00:00+00:00",
    )
    second = diagnostic_run_index.advance_writer_health(
        first,
        writer_health(recordsWritten=2, bytesWritten=20, droppedEvents=1),
        observed_utc="2026-10-25T10:01:00+00:00",
    )

    writer = second["writerHealth"]
    assert writer["samples"] == 2
    assert writer["first"]["recordsWritten"] == 1
    assert writer["latest"]["recordsWritten"] == 2
    assert writer["latestObservedUtc"] == "2026-10-25T10:01:00+00:00"
    assert "droppedEvents=1 expected 0" in writer["violationsSeen"]


def test_advance_writer_health_rejects_counter_regression() -> None:
    index = diagnostic_run_index.advance_writer_health(
        diagnostic_run_index.new_index(client="rust", process_id=42, run_id="run-a"),
        writer_health(recordsWritten=2),
        observed_utc="2026-10-25T10:00:00+00:00",
    )

    with pytest.raises(
        diagnostic_run_index.DiagnosticRunIndexError, match="recordsWritten"
    ):
        diagnostic_run_index.advance_writer_health(
            index,
            writer_health(recordsWritten=1),
            observed_utc="2026-10-25T10:01:00+00:00",
        )


def test_advance_writer_health_rejects_active_segment_regression() -> None:
    index = diagnostic_run_index.advance_writer_health(
        diagnostic_run_index.new_index(client="rust", process_id=42, run_id="run-a"),
        writer_health(activeSegmentId=2),
        observed_utc="2026-10-25T10:00:00+00:00",
    )

    with pytest.raises(
        diagnostic_run_index.DiagnosticRunIndexError, match="activeSegmentId"
    ):
        diagnostic_run_index.advance_writer_health(
            index,
            writer_health(activeSegmentId=1),
            observed_utc="2026-10-25T10:01:00+00:00",
        )


def test_advance_writer_health_requires_exact_contract_and_identity() -> None:
    index = diagnostic_run_index.new_index(client="rust", process_id=42, run_id="run-a")
    incomplete = writer_health()
    incomplete.pop("writeErrors")
    with pytest.raises(
        diagnostic_run_index.DiagnosticRunIndexError, match="fields are invalid"
    ):
        diagnostic_run_index.advance_writer_health(
            index, incomplete, observed_utc="2026-10-25T10:00:00+00:00"
        )

    with pytest.raises(diagnostic_run_index.DiagnosticRunIndexError, match="identity"):
        diagnostic_run_index.advance_writer_health(
            index,
            writer_health(runId="run-b"),
            observed_utc="2026-10-25T10:00:00+00:00",
        )
