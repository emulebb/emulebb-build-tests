from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path

import pytest

from emule_test_harness import observer_action_evidence, soak_action_diff
from emule_test_harness.diag_event_runs import DiagnosticTraceError

pytestmark = pytest.mark.unit


def _ts(seconds: float) -> datetime:
    return datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc) + timedelta(
        seconds=seconds
    )


def _record(
    *,
    client: str,
    process_id: int,
    run_id: str,
    segment_id: int,
    sequence: int,
    seconds: float,
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "client": client,
        "processId": process_id,
        "runId": run_id,
        "segmentId": segment_id,
        "seq": sequence,
        "streamSeq": sequence,
        "ts": _ts(seconds).isoformat().replace("+00:00", "Z"),
        "family": "sched",
        "event": "tick",
        "severity": "info",
        "keys": {},
        "body": {},
    }


def _write_segment(
    directory: Path,
    *,
    client: str,
    process_id: int,
    run_id: str,
    segment_id: int,
    records: list[dict[str, object]],
    partial_tail: str = "",
) -> Path:
    prefix = "emulebb-rust" if client == "rust" else "emulebb-mfc"
    path = directory / (f"{prefix}-diag-{process_id}-{run_id}-{segment_id:06d}.jsonl")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(json.dumps(record) + "\n" for record in records) + partial_tail
    path.write_text(payload, encoding="utf-8")
    return path


def _source(
    directory: Path,
    *,
    client: str,
    process_id: int = 42,
    run_id: str = "pinned",
) -> observer_action_evidence.PinnedDiagnosticRun:
    directory.mkdir(parents=True, exist_ok=True)
    return observer_action_evidence.PinnedDiagnosticRun(
        client=client,
        directory=directory,
        process_id=process_id,
        run_id=run_id,
    )


def test_pinned_run_rejects_non_path_directory() -> None:
    with pytest.raises(TypeError, match="directory must be a pathlib.Path"):
        observer_action_evidence.PinnedDiagnosticRun(
            client="rust",
            directory="diagnostics",  # type: ignore[arg-type]
            process_id=42,
            run_id="pinned",
        )


def test_capture_uses_exact_pinned_runs_and_retains_provenance(tmp_path: Path) -> None:
    rust_dir = tmp_path / "rust"
    mfc_dir = tmp_path / "mfc"
    rust_first = _write_segment(
        rust_dir,
        client="rust",
        process_id=42,
        run_id="pinned",
        segment_id=3,
        records=[
            _record(
                client="rust",
                process_id=42,
                run_id="pinned",
                segment_id=3,
                sequence=17,
                seconds=-1,
            ),
            _record(
                client="rust",
                process_id=42,
                run_id="pinned",
                segment_id=3,
                sequence=18,
                seconds=5,
            ),
        ],
    )
    rust_second = _write_segment(
        rust_dir,
        client="rust",
        process_id=42,
        run_id="pinned",
        segment_id=4,
        records=[
            _record(
                client="rust",
                process_id=42,
                run_id="pinned",
                segment_id=4,
                sequence=19,
                seconds=20,
            )
        ],
    )
    _write_segment(
        rust_dir,
        client="rust",
        process_id=42,
        run_id="newer",
        segment_id=0,
        records=[
            _record(
                client="rust",
                process_id=42,
                run_id="newer",
                segment_id=0,
                sequence=1,
                seconds=6,
            )
        ],
    )
    mfc_segment = _write_segment(
        mfc_dir,
        client="mfc",
        process_id=84,
        run_id="pinned",
        segment_id=7,
        records=[
            _record(
                client="mfc",
                process_id=84,
                run_id="pinned",
                segment_id=7,
                sequence=9,
                seconds=7,
            )
        ],
    )
    os.utime(rust_first, ns=(10, 10))
    os.utime(rust_second, ns=(20, 20))
    window = soak_action_diff.ActionWindow(start_utc=_ts(0), end_utc=_ts(10))

    evidence = observer_action_evidence.capture_action_diagnostic_evidence(
        window=window,
        rust=_source(rust_dir, client="rust"),
        mfc=_source(mfc_dir, client="mfc", process_id=84),
    )

    assert [record["seq"] for record in evidence.rust.window_records] == [18]
    assert [record["seq"] for record in evidence.mfc.window_records] == [9]
    payload = evidence.report_payload()
    assert payload["status"] == "complete"
    assert payload["window"] == {
        "startUtc": _ts(0).isoformat(),
        "endUtc": _ts(10).isoformat(),
    }
    rust_payload = payload["clients"]["rust"]
    assert rust_payload["identity"] == {"processId": 42, "runId": "pinned"}
    assert rust_payload["recordCount"] == 3
    assert rust_payload["windowRecordCount"] == 1
    assert [segment["segmentId"] for segment in rust_payload["segments"]] == [3, 4]
    assert [segment["windowRecordCount"] for segment in rust_payload["segments"]] == [
        1,
        0,
    ]
    assert rust_payload["segments"][0]["path"] == str(rust_first.resolve())
    assert rust_payload["segments"][0]["modifiedNs"] == rust_first.stat().st_mtime_ns
    assert (
        rust_payload["segments"][0]["sha256"]
        == hashlib.sha256(rust_first.read_bytes()).hexdigest()
    )
    assert payload["clients"]["mfc"]["segments"][0]["path"] == str(
        mfc_segment.resolve()
    )


def test_capture_never_falls_forward_to_a_newer_run(tmp_path: Path) -> None:
    rust_dir = tmp_path / "rust"
    mfc_dir = tmp_path / "mfc"
    _write_segment(
        rust_dir,
        client="rust",
        process_id=42,
        run_id="newer",
        segment_id=0,
        records=[
            _record(
                client="rust",
                process_id=42,
                run_id="newer",
                segment_id=0,
                sequence=1,
                seconds=1,
            )
        ],
    )
    _source(mfc_dir, client="mfc", process_id=84)

    with pytest.raises(DiagnosticTraceError, match="no exact diag_event_v2 rust run"):
        observer_action_evidence.capture_action_diagnostic_evidence(
            window=soak_action_diff.ActionWindow(
                start_utc=_ts(0),
                end_utc=_ts(10),
            ),
            rust=_source(rust_dir, client="rust"),
            mfc=_source(mfc_dir, client="mfc", process_id=84),
        )


def test_capture_rejects_malformed_timestamp_outside_window(tmp_path: Path) -> None:
    rust_dir = tmp_path / "rust"
    mfc_dir = tmp_path / "mfc"
    rust_record = _record(
        client="rust",
        process_id=42,
        run_id="pinned",
        segment_id=0,
        sequence=1,
        seconds=20,
    )
    rust_record["ts"] = "invalid"
    _write_segment(
        rust_dir,
        client="rust",
        process_id=42,
        run_id="pinned",
        segment_id=0,
        records=[rust_record],
    )
    _write_segment(
        mfc_dir,
        client="mfc",
        process_id=84,
        run_id="pinned",
        segment_id=0,
        records=[
            _record(
                client="mfc",
                process_id=84,
                run_id="pinned",
                segment_id=0,
                sequence=1,
                seconds=1,
            )
        ],
    )

    with pytest.raises(soak_action_diff.ActionTraceError, match="field ts"):
        observer_action_evidence.capture_action_diagnostic_evidence(
            window=soak_action_diff.ActionWindow(
                start_utc=_ts(0),
                end_utc=_ts(10),
            ),
            rust=_source(rust_dir, client="rust"),
            mfc=_source(mfc_dir, client="mfc", process_id=84),
        )


def test_capture_marks_ignored_and_unterminated_tails_incomplete(
    tmp_path: Path,
) -> None:
    rust_dir = tmp_path / "rust"
    mfc_dir = tmp_path / "mfc"
    _write_segment(
        rust_dir,
        client="rust",
        process_id=42,
        run_id="pinned",
        segment_id=2,
        records=[
            _record(
                client="rust",
                process_id=42,
                run_id="pinned",
                segment_id=2,
                sequence=1,
                seconds=1,
            )
        ],
        partial_tail="{",
    )
    mfc_segment = _write_segment(
        mfc_dir,
        client="mfc",
        process_id=84,
        run_id="pinned",
        segment_id=3,
        records=[
            _record(
                client="mfc",
                process_id=84,
                run_id="pinned",
                segment_id=3,
                sequence=1,
                seconds=1,
            )
        ],
    )
    mfc_segment.write_text(
        mfc_segment.read_text(encoding="utf-8").rstrip("\n"),
        encoding="utf-8",
    )

    evidence = observer_action_evidence.capture_action_diagnostic_evidence(
        window=soak_action_diff.ActionWindow(start_utc=_ts(0), end_utc=_ts(10)),
        rust=_source(rust_dir, client="rust"),
        mfc=_source(mfc_dir, client="mfc", process_id=84),
    )

    payload = evidence.report_payload()
    assert evidence.complete is False
    assert payload["status"] == "incomplete"
    assert payload["clients"]["rust"]["findings"] == [
        "segment-000002:incomplete-tail-ignored"
    ]
    assert payload["clients"]["rust"]["segments"][0]["incompleteTailIgnored"] is True
    assert payload["clients"]["mfc"]["findings"] == ["segment-000003:unterminated-tail"]
    assert payload["clients"]["mfc"]["segments"][0]["tailTerminated"] is False
