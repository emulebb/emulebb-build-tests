"""Current diagnostic contract fixtures shared by harness tests."""

from __future__ import annotations


def current_diagnostic_writer_health(
    *,
    client: str = "rust",
    process_id: int = 42,
    run_id: str = "run-a",
    segment_id: int = 0,
    active_file_name: str | None = None,
) -> dict[str, object]:
    """Builds one healthy, exact 41-field ``diag_event_v2`` writer snapshot."""

    prefix = "emulebb-rust" if client == "rust" else "emulebb-mfc"
    return {
        "schema": "diag_event_v2",
        "enabled": True,
        "configured": True,
        "initialized": True,
        "runId": run_id,
        "processId": process_id,
        "activeSegmentId": segment_id,
        "activeFileName": active_file_name
        or f"{prefix}-diag-{process_id}-{run_id}-{segment_id:06}.jsonl",
        "activeSegmentBytes": 10,
        "recordsWritten": 1,
        "bytesWritten": 10,
        "droppedEvents": 0,
        "encodeErrors": 0,
        "writeErrors": 0,
        "rotations": 0,
        "retentionDeletes": 0,
        "retentionDeleteErrors": 0,
        "retentionScanErrors": 0,
        "freeSpaceProbeErrors": 0,
        "retentionPolicyErrors": 0,
        "storagePolicyDrops": 0,
        "storageFaultDrops": 0,
        "retentionLimitDrops": 0,
        "aggregateLimitDrops": 0,
        "minimumFreeSpaceDrops": 0,
        "writerFaultDrops": 0,
        "retainedSegmentCount": 1,
        "retainedBytes": 10,
        "availableBytes": 10_000,
        "storageAuthorityFaulted": False,
        "writerIoFaulted": False,
        "storageBlockReason": None,
        "storagePolicySatisfied": True,
        "maximumGrowthBytes": 100,
        "maxSegmentBytes": 100,
        "maxSegmentSeconds": 60,
        "retainedSegments": 8,
        "maxTotalBytes": 800,
        "maxRetainedSeconds": 3_600,
        "minimumFreeBytes": 500,
        "initializationFailure": None,
    }
