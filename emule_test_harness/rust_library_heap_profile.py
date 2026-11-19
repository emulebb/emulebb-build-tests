"""Allocation-stack diagnostics using the existing owned watcher replay."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from . import rust_shared_library_io as library
from .build_provenance import require_clean_git_source


def replay_inputs(output: Path, receipt: Path) -> tuple[dict, Path, Path]:
    """Admit a completed owned campaign with one retained initial-phase proof."""
    receipt = receipt.resolve()
    boundary = output / "reports/linux-containers/library"
    if not receipt.is_relative_to(boundary) or receipt.name != "report.json":
        raise RuntimeError("Heap replay requires a managed library receipt")
    source = json.loads(receipt.read_text(encoding="utf-8"))
    run_id = source.get("runId")
    if (source.get("schema") != "emulebb.rust-container-library-io.v1"
            or not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{32}", run_id) is None
            or receipt.parent.name != run_id or source.get("status") not in {"passed", "failed"}
            or source.get("container", {}).get("absent") is not True
            or source.get("volume", {}).get("retained") is not True
            or source["volume"].get("name") != f"emulebb-library-{run_id}"
            or source["volume"].get("labels") != {"emulebb.scope": "shared-library-io", "emulebb.run": run_id}):
        raise RuntimeError("Heap replay source is not an inactive owned allocation")
    reports = list((receipt.parent / "campaign").glob("rust-shared-library-io-*.json"))
    if len(reports) != 1:
        raise RuntimeError("Heap replay requires one original campaign report")
    report = json.loads(reports[0].read_text(encoding="utf-8"))
    if (report.get("schema") != library.REPORT_SCHEMA or not report.get("phases")
            or report["phases"][0].get("acceptance", {}).get("ok") is not True):
        raise RuntimeError("Heap replay source has no accepted initial library phase")
    return source, reports[0], receipt.parent / "native"


def collect_traces(trace_dir: Path, reports: Path) -> list[dict]:
    """Interpret completed heaptrack streams and retain full analysis as files."""
    traces = []
    if not trace_dir.is_dir():
        return traces
    for trace in sorted(trace_dir.iterdir()):
        if not trace.is_file() or trace.stat().st_size == 0:
            continue
        analysis = reports / f"{trace.name}.analysis.txt"
        with analysis.open("w", encoding="utf-8") as stream:
            completed = subprocess.run(["heaptrack_print", "--file", str(trace)],
                stdout=stream, stderr=subprocess.STDOUT, timeout=300, check=False)
        if completed.returncode or analysis.stat().st_size == 0:
            raise RuntimeError(f"Heap trace interpretation failed; inspect {analysis}")
        traces.append({"path": str(trace), "bytes": trace.stat().st_size, "analysis": str(analysis)})
    return traces


def run(args) -> dict:
    """Profile one copied warm baseline and watcher-create phase at 1 GiB."""
    if sys.platform != "linux" or not all(shutil.which(tool) for tool in ("heaptrack", "heaptrack_print")):
        raise RuntimeError("Heap replay requires native Linux and heaptrack tools")
    output = library.get_workspace_output_root().resolve()
    reports = args.report_root.resolve()
    if (not reports.is_relative_to(output / "reports/linux-containers/library-heap")
            or re.fullmatch(r"[0-9a-f]{32}", reports.name) is None):
        raise RuntimeError("Heap reports escaped their diagnostic boundary")
    source, replay_report, native = replay_inputs(output, args.source_receipt)
    if (source.get("sourceRevisions", {}).get("rust") != args.source_sha
            or require_clean_git_source(args.rust_repo, label="heap Rust").revision != args.source_sha):
        raise RuntimeError("Heap replay requires the exact source of its retained failure")
    package = library.load_script_module("heap_portable_package", "smoke-rust-release-package.py")
    manifest = package._verify_package_manifest(args.archive, args.source_sha, args.version, "x86_64-unknown-linux-gnu")
    if source.get("archiveSha256") != manifest["sha256"]:
        raise RuntimeError("Heap replay archive differs from its retained failure")
    before = library.rust_cgroup_budget.sample_budget()
    if (before is None or before["memoryMaxBytes"] != 1024 * 1024 * 1024
            or before["swapMaxBytes"] != 0 or before["cpuQuotaMicros"] != before["cpuPeriodMicros"]):
        raise RuntimeError("Heap replay requires its diagnostic 1 GiB/one-CPU budget")
    reports.mkdir(parents=True, exist_ok=True)
    diagnostic_root = native / "heap-profiles" / reports.name
    trace_dir = diagnostic_root / "trace"
    result = {"schema": "emulebb.rust-library-heap.v1", "status": "running",
        "workloadQualified": False, "sourceSha": args.source_sha, "archiveSha256": manifest["sha256"],
        "sourceReceipt": str(args.source_receipt), "qualificationScope": {"containerLimitsEnforced": False},
        "acceptance": {"ok": False}, "traces": []}
    try:
        executable = library.extract_container_archive(args.archive, diagnostic_root / "runtime")
        scenario = native / "scenario"
        paths = library.HarnessPaths(workspace_root=library.get_required_emule_workspace_root(),
            output_root=output, rust_repo=args.rust_repo, scenario_root=scenario,
            fixture_root=scenario / "fixture/library", manifest_path=scenario / "fixture-manifest.json",
            owner_path=scenario / ".emulebb-rust-shared-library-io-owner.json",
            runs_root=scenario / "runs", reports_root=reports / "campaign", staged_executable=executable)
        original = json.loads(replay_report.read_text(encoding="utf-8"))
        options = library.build_parser().parse_args(["run", "--allow-non-ssd", "--watcher-replay-from", original["runId"],
            "--watcher-timeout-seconds", "3600"])
        report_path, report = library.run_campaign(paths, options, replay_report=replay_report,
            heap_profile_dir=trace_dir, stop_after_watcher_create=True)
        result.update(status=report["status"], campaignReport=str(report_path))
    except BaseException as error:
        result.update(status="failed", error=type(error).__name__)
        raise
    finally:
        try:
            result["traces"] = collect_traces(trace_dir, reports)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            result.update(status="failed", traceError=type(error).__name__)
        if not result["traces"]:
            result.update(status="failed", traceError=result.get("traceError", "missingTrace"))
        library.rust_cgroup_budget.finish_report(result, before)
        library.write_json(reports / "heap-result.json", result)
    return result
