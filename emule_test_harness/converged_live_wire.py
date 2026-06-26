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
* :func:`find_packet_trace` discovers each side's ``ed2k_packet_v1`` JSONL dump;
* :func:`build_converged_report` aggregates the two diff outputs plus the
  packet-dump summaries into one combined report object.

Both clients emit the converged ``ed2k_packet_v1`` packet schema, so the two
captures are aligned with ``emule_test_harness.packet_trace_diff`` and the
broader ``diag_event_v1`` envelope with ``emule_test_harness.diag_event_diff``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# Canonical MFC output build layout dimensions (see WORKSPACE-POLICY build root).
# The packet-diagnostics MFC exe is the `main` variant built with --diagnostics:
# builds/app/main/x64/Release/diagnostics/bin/emulebb-diagnostics.exe (verified).
DEFAULT_MFC_VARIANT = "main"
DEFAULT_MFC_ARCH = "x64"
DEFAULT_MFC_CONFIGURATION = "Release"
# The packet-diagnostics MFC build is staged under the "diagnostics" flavor.
MFC_DIAGNOSTICS_FLAVOR = "diagnostics"
MFC_EXE_NAME = "emulebb-diagnostics.exe"

# Both clients write the converged ed2k_packet_v1 dump. Rust emits per-flow JSONL
# stems under EMULEBB_RUST_LOG_DIR; the MFC diagnostics build writes ONE fixed
# file in its profile log dir (LogArtifactNames::PacketDiagnosticsLogFileName /
# DiagEventV1LogFileName, srchybrid/LogArtifactNames.h).
RUST_PACKET_DUMP_GLOBS = (
    "emulebb-rust-ed2k-*-dump-*.jsonl",
    "emulebb-rust-ed2k-tcp-dump-*.jsonl",
)
EMULE_PACKET_DUMP_GLOBS = ("emulebb-diagnostics-packet.log",)
RUST_DIAG_DUMP_GLOBS = ("emulebb-rust-diag-*.jsonl",)
EMULE_DIAG_DUMP_GLOBS = ("emulebb-diagnostics-diag.log",)


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
RUST_DIAGNOSTICS_EXE_GLOBS = (
    "builds/rust/target/*/release/emulebb-rust-diagnostics.exe",
    "builds/rust/target/release/emulebb-rust-diagnostics.exe",
    "tools/emulebb-rust/bin/emulebb-rust-diagnostics.exe",
)


def resolve_rust_diagnostics_exe(output_root: Path, *, require_exists: bool = True) -> Path:
    """Resolves the eMuleBB Rust diagnostics exe from the output build layout.

    Searches the known staged/build-tree locations for ``emulebb-rust-diagnostics.exe``
    and returns the most recently built match. When ``require_exists`` is true and
    none is found, raises with the exact build command so the operator knows how to
    produce it.
    """

    matches: list[Path] = []
    for pattern in RUST_DIAGNOSTICS_EXE_GLOBS:
        matches.extend(p for p in output_root.glob(pattern) if p.is_file())
    if matches:
        return max(matches, key=lambda p: p.stat().st_mtime)
    if require_exists:
        raise RuntimeError(
            f"eMuleBB Rust diagnostics exe '{RUST_DIAGNOSTICS_EXE_NAME}' was not found under "
            f"'{output_root}'. Build it with: python -m emule_workspace build clients "
            "--client emulebb-rust --diagnostics."
        )
    return output_root / "builds" / "rust" / "target" / "release" / RUST_DIAGNOSTICS_EXE_NAME


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
    return {"confirmReplaceRoots": True, "roots": [root]}


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


def find_packet_trace(dump_dir: Path, *, side: str) -> Path | None:
    """Returns the first ``ed2k_packet_v1`` JSONL dump for one client side.

    ``side`` is ``"rust"`` or ``"emule"``; returns ``None`` when no dump file is
    present (a silently-empty diagnostics build).
    """

    if side == "rust":
        matches = _first_existing_glob(dump_dir, RUST_PACKET_DUMP_GLOBS)
    elif side == "emule":
        matches = _first_existing_glob(dump_dir, EMULE_PACKET_DUMP_GLOBS)
    else:
        raise ValueError(f"side must be 'rust' or 'emule', got {side!r}.")
    return matches[0] if matches else None


def find_diag_trace(dump_dir: Path, *, side: str) -> Path | None:
    """Returns the first ``diag_event_v1`` JSONL dump for one client side."""

    if side == "rust":
        matches = _first_existing_glob(dump_dir, RUST_DIAG_DUMP_GLOBS)
    elif side == "emule":
        matches = _first_existing_glob(dump_dir, EMULE_DIAG_DUMP_GLOBS)
    else:
        raise ValueError(f"side must be 'rust' or 'emule', got {side!r}.")
    return matches[0] if matches else None


def count_jsonl_records(path: Path | None) -> int:
    """Counts non-empty lines in a JSONL dump (0 for a missing/None path)."""

    if path is None or not path.is_file():
        return 0
    return sum(
        1
        for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        if line.strip()
    )


def build_converged_report(
    *,
    run_id: str,
    rust_packet_trace: Path | None,
    emule_packet_trace: Path | None,
    packet_diff: dict[str, Any] | None,
    diag_diff: dict[str, Any] | None,
    rust_packet_summary: dict[str, Any] | None,
    emule_packet_summary: dict[str, Any] | None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Aggregates both sides into one combined converged-diff report object.

    The report records the located traces, the per-(flow, direction)
    ``ed2k_packet_v1`` diff (matches / payload-diffs / only-rust / only-emule),
    the ``diag_event_v1`` family diff, and each side's packet-dump summary. The
    top-level ``ok`` is true only when both traces were captured and both diffs
    converged.
    """

    rust_records = count_jsonl_records(rust_packet_trace)
    emule_records = count_jsonl_records(emule_packet_trace)
    both_captured = rust_records > 0 and emule_records > 0

    packet_ok = bool(packet_diff and packet_diff.get("ok"))
    diag_ok = diag_diff is None or bool(diag_diff.get("ok"))

    report: dict[str, Any] = {
        "scenario": "emulebb.flow.converged.live-wire.hideme.v1",
        "runId": run_id,
        "ok": both_captured and packet_ok and diag_ok,
        "traces": {
            "rust": {
                "path": str(rust_packet_trace) if rust_packet_trace else None,
                "records": rust_records,
                "captured": rust_records > 0,
            },
            "emule": {
                "path": str(emule_packet_trace) if emule_packet_trace else None,
                "records": emule_records,
                "captured": emule_records > 0,
            },
            "bothCaptured": both_captured,
        },
        "packetDiff": packet_diff,
        "diagDiff": diag_diff,
        "packetSummaries": {
            "rust": rust_packet_summary,
            "emule": emule_packet_summary,
        },
    }
    if extra:
        report.update(extra)
    return report
