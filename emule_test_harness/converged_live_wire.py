"""Pure helpers for the converged eMuleBB live-wire packet-diff orchestrator.

This module holds the side-effect-free logic that the
``scripts/converged-live-wire-diff.py`` orchestrator depends on, so it can be
unit-tested without launching either client, binding hide.me, or touching the
live network:

* :func:`resolve_mfc_diagnostics_exe` resolves the eMuleBB MFC *diagnostics*
  build exe from the canonical output build layout
  (``builds/app/<variant>/<arch>/<configuration>/diagnostics/bin/emulebb-diagnostics.exe``)
  rather than from a hardcoded path;
* :func:`build_search_payload` / :func:`build_shared_directory_patch_payload`
  build the REST request bodies shared by both clients (rust ``/api/v1`` and the
  eMuleBB ``/api/v1`` REST use the same shapes);
* :func:`load_current_diag_capture` selects and validates one segmented
  ``diag_event_v2`` run per client;
* :func:`build_converged_report` aggregates the two diff outputs with explicit
  unified packet evidence into one combined report object.

Both clients emit eD2K TCP packet events in ``diag_event_v2``. The orchestrator
normalizes those events with ``diag_event_diff.ed2k_tcp_packet_views`` before
aligning them with ``packet_trace_diff``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from emule_test_harness import diag_event_runs

# Canonical MFC output build layout dimensions (see WORKSPACE-POLICY build root).
# The packet-diagnostics MFC exe is the `main` variant built with --diagnostics:
# builds/app/main/x64/Release/diagnostics/bin/emulebb-diagnostics.exe (verified).
DEFAULT_MFC_VARIANT = "main"
DEFAULT_MFC_ARCH = "x64"
DEFAULT_MFC_CONFIGURATION = "Release"
# The packet-diagnostics MFC build is staged under the "diagnostics" flavor.
MFC_DIAGNOSTICS_FLAVOR = "diagnostics"
MFC_EXE_NAME = "emulebb-diagnostics.exe"

RUST_DIAG_DUMP_GLOBS = ("emulebb-rust-diag-*.jsonl",)
EMULE_DIAG_DUMP_GLOBS = ("emulebb-mfc-diag-*.jsonl",)
EMULE_DIAG_HEALTH_FILE = "emulebb-mfc-diag-health.json"


@dataclass(frozen=True)
class CurrentDiagCapture:
    """One validated current diagnostic run and its selected segment paths."""

    selected_segments: tuple[Path, ...]
    records: tuple[dict[str, Any], ...]


def mfc_diagnostics_build_dir(
    output_root: Path,
    *,
    variant: str = DEFAULT_MFC_VARIANT,
    arch: str = DEFAULT_MFC_ARCH,
    configuration: str = DEFAULT_MFC_CONFIGURATION,
) -> Path:
    """Returns the diagnostics-flavor MFC ``bin`` directory under the output root.

    Layout: ``<output_root>/builds/app/<variant>/<arch>/<configuration>/diagnostics/bin``.
    """

    return (
        output_root
        / "builds"
        / "app"
        / variant
        / arch
        / configuration
        / MFC_DIAGNOSTICS_FLAVOR
        / "bin"
    )


def resolve_mfc_diagnostics_exe(
    output_root: Path,
    *,
    variant: str = DEFAULT_MFC_VARIANT,
    arch: str = DEFAULT_MFC_ARCH,
    configuration: str = DEFAULT_MFC_CONFIGURATION,
    require_exists: bool = True,
) -> Path:
    """Resolves the eMuleBB MFC diagnostics exe from the output build layout.

    No machine paths are baked in: the build root comes from ``output_root``
    (``EMULEBB_WORKSPACE_OUTPUT_ROOT``) and the variant/arch/configuration are
    parameters. When ``require_exists`` is true a missing exe raises with the
    exact expected path so the operator knows which build to stage.
    """

    exe_path = mfc_diagnostics_build_dir(
        output_root, variant=variant, arch=arch, configuration=configuration
    ) / MFC_EXE_NAME
    if require_exists and not exe_path.is_file():
        raise RuntimeError(
            "eMuleBB MFC diagnostics exe was not found at "
            f"'{exe_path}'. Build the packet-diagnostics flavor "
            "(emule_workspace build app --diagnostics; main/x64/Release/diagnostics) first."
        )
    return exe_path


# The eMuleBB Rust diagnostics build (cargo `packet-diagnostics` feature) is staged
# under a distinct name so it is never confused with the plain release binary (cargo
# emits both as `emulebb-rust.exe`). `emule_workspace build clients --client
# emulebb-rust --diagnostics` writes it next to the cargo output (target-triple
# release dir) and into the staged tools bin; search both, plus the no-triple dir.
RUST_DIAGNOSTICS_EXE_NAME = "emulebb-rust-diagnostics.exe"
# The single canonical location: the build stages exactly one copy here
# (`emule_workspace` `stage_emulebb_rust_runtime`, which clears the dir first).
# The cargo `target/` tree is intermediate build cache and is intentionally NOT
# consulted, so the soak always runs the one exe the VPN split-tunnel whitelists —
# no glob-newest ambiguity across duplicate copies.
RUST_DIAGNOSTICS_EXE_STAGED_PARTS = ("tools", "emulebb-rust", "bin", RUST_DIAGNOSTICS_EXE_NAME)


def resolve_rust_diagnostics_exe(output_root: Path, *, require_exists: bool = True) -> Path:
    """Resolves the single staged eMuleBB Rust diagnostics exe.

    Returns the one canonical staged path. When ``require_exists`` is true and it is
    missing, raises with the exact build command so the operator knows how to
    produce it.
    """

    exe = output_root.joinpath(*RUST_DIAGNOSTICS_EXE_STAGED_PARTS)
    if exe.is_file() or not require_exists:
        return exe
    raise RuntimeError(
        f"eMuleBB Rust diagnostics exe '{RUST_DIAGNOSTICS_EXE_NAME}' was not found at "
        f"'{exe}'. Build it with: python -m emule_workspace build clients "
        "--client emulebb-rust --diagnostics."
    )


# The plain release binary (no `packet-diagnostics` feature, no ed2k_packet_v1 /
# diag_event_v2 dumps) is staged into the same canonical bin dir under its own
# name. Staging clears the dir, so exactly ONE flavor is staged at a time — the
# resolver errors name the build command for the flavor you asked for.
RUST_REGULAR_EXE_NAME = "emulebb-rust.exe"
RUST_REGULAR_EXE_STAGED_PARTS = ("tools", "emulebb-rust", "bin", RUST_REGULAR_EXE_NAME)


def resolve_rust_regular_exe(output_root: Path, *, require_exists: bool = True) -> Path:
    """Resolves the single staged plain-release eMuleBB Rust exe."""

    exe = output_root.joinpath(*RUST_REGULAR_EXE_STAGED_PARTS)
    if exe.is_file() or not require_exists:
        return exe
    raise RuntimeError(
        f"eMuleBB Rust release exe '{RUST_REGULAR_EXE_NAME}' was not found at "
        f"'{exe}'. Build it with: python -m emule_workspace build clients "
        "--client emulebb-rust."
    )


def build_search_payload(term: str) -> dict[str, Any]:
    """Builds the shared ``POST /api/v1/searches`` body used by both clients."""

    if not term or not term.strip():
        raise ValueError("Search term must be a non-empty string.")
    return {"query": term.strip(), "method": "automatic", "type": ""}


def build_shared_directory_patch_payload(seed_dir: Path) -> dict[str, Any]:
    """Builds the shared ``PATCH /api/v1/shared-directories`` body for one seed.

    The same payload shape is accepted by the rust ``/api/v1`` and the eMuleBB
    ``/api/v1`` REST surfaces, so both clients share the identical seed file.
    """

    root = str(seed_dir)
    if not root.endswith(("\\", "/")):
        root += "\\"
    return {"confirmReplaceRoots": True, "roots": [{"path": root}]}


def select_search_terms(terms: list[str], *, max_terms: int) -> list[str]:
    """Selects a GENTLE subset of search terms (be-gentle live discipline)."""

    if max_terms <= 0:
        raise ValueError("max_terms must be greater than zero.")
    cleaned = [term.strip() for term in terms if term and term.strip()]
    if not cleaned:
        raise RuntimeError("No non-empty search terms were provided.")
    return cleaned[:max_terms]


def _first_existing_glob(dump_dir: Path, globs: tuple[str, ...]) -> list[Path]:
    found: list[Path] = []
    for pattern in globs:
        found.extend(sorted(dump_dir.glob(pattern)))
    # Preserve order while de-duplicating overlapping glob matches.
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in found:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def find_diag_traces(
    dump_dir: Path,
    *,
    side: str,
    process_id: int | None = None,
    min_mtime: float | None = None,
) -> list[Path]:
    """Returns ordered diagnostic-event segments for one current client run."""

    if side not in {"rust", "emule"}:
        raise ValueError(f"side must be 'rust' or 'emule', got {side!r}.")
    globs = RUST_DIAG_DUMP_GLOBS if side == "rust" else EMULE_DIAG_DUMP_GLOBS
    client = "rust" if side == "rust" else "mfc"
    candidates = _first_existing_glob(dump_dir, globs)
    if min_mtime is not None:
        candidates = [path for path in candidates if path.stat().st_mtime >= min_mtime]
    return diag_event_runs.select_latest_diag_run(
        candidates, client=client, process_id=process_id
    )


def find_mfc_diag_health(dump_dir: Path) -> Path | None:
    """Returns the MFC writer-health sidecar when present."""

    path = dump_dir / EMULE_DIAG_HEALTH_FILE
    return path if path.is_file() else None


def load_current_diag_capture(
    dump_dir: Path,
    *,
    side: str,
    process_id: int | None = None,
    min_mtime: float | None = None,
    allow_incomplete_active_tail: bool = False,
) -> CurrentDiagCapture:
    """Loads one current run with its segments and validates MFC writer health."""

    segments = find_diag_traces(
        dump_dir, side=side, process_id=process_id, min_mtime=min_mtime
    )
    if not segments:
        raise diag_event_runs.DiagnosticTraceError(
            f"{side} diagnostics did not produce a current diag_event_v2 run in {dump_dir}"
        )
    client = "rust" if side == "rust" else "mfc"
    if side == "emule":
        health = find_mfc_diag_health(dump_dir)
        if health is None:
            raise diag_event_runs.DiagnosticTraceError(
                f"missing MFC diagnostic writer health in {dump_dir}"
            )
        diag_event_runs.load_and_validate_writer_health(
            health, client="mfc", selected_segments=segments
        )
    records = diag_event_runs.load_latest_diag_records(
        segments,
        client=client,
        process_id=process_id,
        allow_incomplete_active_tail=allow_incomplete_active_tail,
    )
    if not records:
        raise diag_event_runs.DiagnosticTraceError(
            f"selected {side} diagnostic run contains no complete events"
        )
    return CurrentDiagCapture(tuple(segments), tuple(records))


def load_current_diag_records(
    dump_dir: Path,
    *,
    side: str,
    process_id: int | None = None,
    min_mtime: float | None = None,
    allow_incomplete_active_tail: bool = False,
) -> list[dict[str, Any]]:
    """Compatibility wrapper returning only one current run's records."""

    capture = load_current_diag_capture(
        dump_dir,
        side=side,
        process_id=process_id,
        min_mtime=min_mtime,
        allow_incomplete_active_tail=allow_incomplete_active_tail,
    )
    return list(capture.records)


def build_converged_report(
    *,
    run_id: str,
    rust_diag_segments: tuple[Path, ...],
    emule_diag_segments: tuple[Path, ...],
    rust_packet_record_count: int,
    emule_packet_record_count: int,
    packet_diff: dict[str, Any],
    diag_diff: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Aggregates both sides into one combined converged-diff report object.

    Packet evidence names the selected ``diag_event_v2`` segments and the count
    of complete eD2K TCP packet records extracted from each run. The top-level
    ``ok`` is true only when both runs supplied packet evidence and both diffs
    converged.
    """

    if rust_packet_record_count < 0 or emule_packet_record_count < 0:
        raise ValueError("packet record counts must be non-negative")
    both_captured = rust_packet_record_count > 0 and emule_packet_record_count > 0

    packet_ok = bool(packet_diff.get("ok"))
    diag_ok = bool(diag_diff.get("ok"))

    report: dict[str, Any] = {
        "scenario": "emulebb.flow.converged.live-wire.hideme.v1",
        "runId": run_id,
        "ok": both_captured and packet_ok and diag_ok,
        "packetEvidence": {
            "source": "diag_event_v2",
            "rust": {
                "selectedSegments": [str(path) for path in rust_diag_segments],
                "extractedRecords": rust_packet_record_count,
                "captured": rust_packet_record_count > 0,
            },
            "emule": {
                "selectedSegments": [str(path) for path in emule_diag_segments],
                "extractedRecords": emule_packet_record_count,
                "captured": emule_packet_record_count > 0,
            },
            "bothCaptured": both_captured,
        },
        "packetDiff": packet_diff,
        "diagDiff": diag_diff,
    }
    if extra:
        report.update(extra)
    return report
