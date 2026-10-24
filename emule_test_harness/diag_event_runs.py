"""Run-aware discovery and loading for Rust diagnostic event segments."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

RUST_DIAG_SCHEMAS = frozenset({"diag_event_v1", "diag_event_v2"})

_SEGMENT_NAME = re.compile(
    r"^emulebb-rust-diag-(?P<process_id>\d+)-(?P<run_id>.+)-(?P<segment_id>\d{6,})\.jsonl$"
)


def rust_diag_segment_identity(path: Path) -> tuple[int, str, int] | None:
    """Returns ``(process_id, run_id, segment_id)`` for a v2 segment name."""

    match = _SEGMENT_NAME.fullmatch(path.name)
    if match is None:
        return None
    return (
        int(match.group("process_id")),
        match.group("run_id"),
        int(match.group("segment_id")),
    )


def select_latest_rust_diag_run(
    paths: Iterable[Path],
    *,
    process_id: int | None = None,
) -> list[Path]:
    """Selects one newest segmented run, falling back to legacy dump files."""

    files = sorted({path.resolve() for path in paths if path.is_file()})
    grouped: dict[tuple[int, str], list[tuple[int, Path]]] = {}
    for path in files:
        identity = rust_diag_segment_identity(path)
        if identity is None:
            continue
        candidate_process_id, run_id, segment_id = identity
        grouped.setdefault((candidate_process_id, run_id), []).append((segment_id, path))

    eligible = {
        key: segments
        for key, segments in grouped.items()
        if process_id is None or key[0] == process_id
    }
    if not eligible and process_id is not None:
        eligible = grouped
    if eligible:
        _, selected = max(
            eligible.items(),
            key=lambda item: (
                max(path.stat().st_mtime_ns for _, path in item[1]),
                item[0],
            ),
        )
        return [path for _, path in sorted(selected)]

    if process_id is not None:
        exact = [path for path in files if path.name == f"emulebb-rust-diag-{process_id}.jsonl"]
        if exact:
            return exact
    return sorted(files, key=lambda path: (path.stat().st_mtime_ns, path.name))


def load_latest_rust_diag_records(
    paths: Iterable[Path],
    *,
    process_id: int | None = None,
) -> list[dict[str, Any]]:
    """Loads valid records from one selected Rust run in process-sequence order."""

    selected = select_latest_rust_diag_run(paths, process_id=process_id)
    selected_identity = rust_diag_segment_identity(selected[0]) if selected else None
    records: list[dict[str, Any]] = []
    for path in selected:
        for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict) or record.get("schema") not in RUST_DIAG_SCHEMAS:
                continue
            if not isinstance(record.get("seq"), int):
                continue
            if selected_identity is not None:
                selected_process_id, selected_run_id, _ = selected_identity
                if (
                    record.get("schema") != "diag_event_v2"
                    or record.get("processId") != selected_process_id
                    or record.get("runId") != selected_run_id
                ):
                    continue
            records.append(record)
    return sorted(records, key=lambda record: int(record["seq"]))
