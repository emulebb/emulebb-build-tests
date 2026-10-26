"""Pure exact-run diagnostic evidence capture for one observer action window."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import diag_event_runs, soak_action_diff

ACTION_DIAGNOSTIC_EVIDENCE_SCHEMA = "emulebb-build-tests.action-diagnostic-evidence.v1"
_CLIENTS = ("rust", "mfc")


@dataclass(frozen=True)
class PinnedDiagnosticRun:
    """Manifest-authoritative directory and exact live writer identity."""

    client: str
    directory: Path
    process_id: int
    run_id: str

    def __post_init__(self) -> None:
        if self.client not in _CLIENTS:
            raise ValueError("client must be 'rust' or 'mfc'")
        if not isinstance(self.directory, Path):
            raise TypeError("directory must be a pathlib.Path")
        if self.directory.is_symlink():
            raise RuntimeError(
                f"{self.client} diagnostic directory must not be a symlink: "
                f"{self.directory}"
            )
        directory = self.directory.resolve()
        if not directory.is_dir():
            raise RuntimeError(
                f"{self.client} diagnostic directory is unavailable: {directory}"
            )
        if (
            isinstance(self.process_id, bool)
            or not isinstance(self.process_id, int)
            or self.process_id <= 0
        ):
            raise ValueError("process_id must be a positive integer")
        if not isinstance(self.run_id, str) or not self.run_id:
            raise ValueError("run_id must be a non-empty string")
        object.__setattr__(self, "directory", directory)


@dataclass(frozen=True)
class ClientActionDiagnosticEvidence:
    """One exact client run plus records inside the authoritative action window."""

    source: PinnedDiagnosticRun
    snapshot: diag_event_runs.DiagnosticRunSnapshot
    window_records: tuple[dict[str, Any], ...]
    segment_window_records: tuple[tuple[dict[str, Any], ...], ...]

    @property
    def complete(self) -> bool:
        return not self.findings

    @property
    def findings(self) -> tuple[str, ...]:
        findings: list[str] = []
        for segment in self.snapshot.segments:
            segment_id = _segment_id(segment, client=self.source.client)
            if segment.incomplete_tail_ignored:
                findings.append(f"segment-{segment_id:06d}:incomplete-tail-ignored")
            elif not segment.tail_terminated:
                findings.append(f"segment-{segment_id:06d}:unterminated-tail")
        return tuple(findings)

    def report_payload(self) -> dict[str, Any]:
        segments = []
        for segment, window_records in zip(
            self.snapshot.segments,
            self.segment_window_records,
            strict=True,
        ):
            segments.append(
                {
                    "segmentId": _segment_id(segment, client=self.source.client),
                    "path": str(segment.path),
                    "byteCount": segment.byte_count,
                    "modifiedNs": segment.modified_ns,
                    "sha256": segment.sha256,
                    "recordCount": len(segment.records),
                    "windowRecordCount": len(window_records),
                    "tailTerminated": segment.tail_terminated,
                    "incompleteTailIgnored": segment.incomplete_tail_ignored,
                }
            )
        return {
            "status": "complete" if self.complete else "incomplete",
            "findings": list(self.findings),
            "directory": str(self.source.directory),
            "identity": {
                "processId": self.snapshot.process_id,
                "runId": self.snapshot.run_id,
            },
            "recordCount": len(self.snapshot.records),
            "windowRecordCount": len(self.window_records),
            "segments": segments,
        }


@dataclass(frozen=True)
class ActionDiagnosticEvidence:
    """Exact cross-client diagnostic evidence for one action window."""

    window: soak_action_diff.ActionWindow
    rust: ClientActionDiagnosticEvidence
    mfc: ClientActionDiagnosticEvidence

    @property
    def complete(self) -> bool:
        return self.rust.complete and self.mfc.complete

    def report_payload(self) -> dict[str, Any]:
        return {
            "schema": ACTION_DIAGNOSTIC_EVIDENCE_SCHEMA,
            "status": "complete" if self.complete else "incomplete",
            "window": {
                "startUtc": self.window.start_utc.isoformat(),
                "endUtc": self.window.end_utc.isoformat(),
            },
            "clients": {
                "rust": self.rust.report_payload(),
                "mfc": self.mfc.report_payload(),
            },
        }


def capture_action_diagnostic_evidence(
    *,
    window: soak_action_diff.ActionWindow,
    rust: PinnedDiagnosticRun,
    mfc: PinnedDiagnosticRun,
) -> ActionDiagnosticEvidence:
    """Loads and strictly slices both pinned runs without newest-run fallback."""

    if rust.client != "rust" or mfc.client != "mfc":
        raise ValueError("rust and mfc pinned diagnostic sources are misassigned")
    return ActionDiagnosticEvidence(
        window=window,
        rust=_capture_client(window=window, source=rust),
        mfc=_capture_client(window=window, source=mfc),
    )


def _capture_client(
    *,
    window: soak_action_diff.ActionWindow,
    source: PinnedDiagnosticRun,
) -> ClientActionDiagnosticEvidence:
    snapshot = diag_event_runs.load_exact_diag_run_snapshot(
        source.directory.iterdir(),
        client=source.client,
        process_id=source.process_id,
        run_id=source.run_id,
        allow_incomplete_active_tail=True,
    )
    segment_window_records = tuple(
        tuple(
            soak_action_diff.slice_trace(
                list(segment.records),
                window,
                trace_name=f"{source.client} diagnostic segment {segment.path}",
            )
        )
        for segment in snapshot.segments
    )
    return ClientActionDiagnosticEvidence(
        source=source,
        snapshot=snapshot,
        window_records=tuple(
            record
            for segment_records in segment_window_records
            for record in segment_records
        ),
        segment_window_records=segment_window_records,
    )


def _segment_id(
    segment: diag_event_runs.DiagnosticSegmentSnapshot,
    *,
    client: str,
) -> int:
    identity = diag_event_runs.diag_segment_identity(segment.path, client=client)
    if identity is None:
        raise RuntimeError(
            f"Exact {client} snapshot lost segment identity: {segment.path}"
        )
    return identity[2]
