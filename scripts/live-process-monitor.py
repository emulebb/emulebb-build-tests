"""Launches a real-profile eMule process and records long-run CPU/memory evidence."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import cpu_profile, live_process_monitor

import importlib.util


def load_local_module(module_name: str, filename: str):
    """Loads one sibling helper module from a hyphenated script filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")

SUITE_NAME = "live-process-monitor"


def build_parser() -> argparse.ArgumentParser:
    """Builds the live process monitor command-line parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--live-config-file", default=str(REPO_ROOT / "live-process-monitor.local.json"))
    parser.add_argument("--profile-dir")
    parser.add_argument("--base-url")
    parser.add_argument("--api-key")
    parser.add_argument("--duration-seconds", type=float)
    parser.add_argument("--sample-interval-seconds", type=float)
    parser.add_argument("--procdump-path")
    parser.add_argument("--cpu-spike-threshold-one-core", type=float)
    parser.add_argument("--max-spike-dumps", type=int)
    parser.add_argument("--spike-dump-delay-seconds", type=float)
    parser.add_argument("--capture-final-dump", action="store_true")
    parser.add_argument("--skip-spike-dumps", action="store_true")
    parser.add_argument("--cpu-profile", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--cpu-profile-max-file-mb", type=int, default=cpu_profile.DEFAULT_CPU_PROFILE_MAX_FILE_MB)
    parser.add_argument("--cpu-profile-stack", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--cpu-profile-stack-min-hits", type=int, default=10)
    parser.add_argument("--cpu-profile-symbols-required", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--enable-umdh", action="store_true")
    parser.add_argument("--require-umdh", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    return parser


def write_json(path: Path, payload: object) -> None:
    """Writes one stable JSON artifact."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    """Runs the live process monitor and returns a process exit code."""

    args = build_parser().parse_args()
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts or args.keep_running,
    )
    artifacts_dir = paths.source_artifacts_dir
    analysis_dir = artifacts_dir / "analysis"
    diagnostics_dir = artifacts_dir / "diagnostics"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    diagnostics_dir.mkdir(parents=True, exist_ok=True)

    config_path = Path(args.live_config_file).resolve()
    if not config_path.is_file():
        raise RuntimeError(
            f"Missing live monitor config '{config_path}'. Copy live-process-monitor.example.json "
            "to live-process-monitor.local.json and set profileDir."
        )
    config = live_process_monitor.load_config(config_path)
    config = live_process_monitor.merge_config(
        config,
        profile_dir=Path(args.profile_dir).resolve() if args.profile_dir else None,
        base_url=args.base_url.rstrip("/") if args.base_url else None,
        api_key=args.api_key,
        duration_seconds=args.duration_seconds,
        sample_interval_seconds=args.sample_interval_seconds,
        procdump_path=Path(args.procdump_path).resolve() if args.procdump_path else None,
        cpu_spike_threshold_one_core=args.cpu_spike_threshold_one_core,
        max_spike_dumps=args.max_spike_dumps,
        spike_dump_delay_seconds=args.spike_dump_delay_seconds,
    )
    app_exe = config.app_exe or paths.app_exe
    live_process_monitor.validate_config(config, app_exe=app_exe)
    live_process_monitor.validate_capture_mode(
        cpu_profile_enabled=bool(args.cpu_profile),
        enable_umdh=bool(args.enable_umdh),
        capture_final_dump=bool(args.capture_final_dump),
        spike_dumps_enabled=not bool(args.skip_spike_dumps),
        max_spike_dumps=config.max_spike_dumps,
    )

    report: dict[str, object] = {
        "schema": "emule-live-process-monitor-result.v1",
        "status": "running",
        "configuration": args.configuration,
        "app_exe": str(app_exe),
        "profile_dir_configured": True,
        "duration_seconds": config.duration_seconds,
        "sample_interval_seconds": config.sample_interval_seconds,
        "cpu_profile": bool(args.cpu_profile),
        "capture_final_dump": bool(args.capture_final_dump),
        "enable_umdh": bool(args.enable_umdh),
        "artifacts_dir": str(artifacts_dir),
        "checks": {},
        "diagnostics": {},
    }
    write_json(artifacts_dir / "result.json", report)

    tools = {
        "gflags": live_process_monitor.find_tool("gflags.exe", "gflags"),
        "umdh": live_process_monitor.find_tool("umdh.exe", "umdh"),
        "cdb": live_process_monitor.find_tool("cdb.exe", "cdb"),
    }
    cpu_profile_tools = cpu_profile.discover_cpu_profile_tools()
    tools["xperf"] = cpu_profile_tools.xperf
    tools["wpaexporter"] = cpu_profile_tools.wpaexporter
    report["tools"] = tools

    gflags_enabled = False
    cpu_profile_paths = cpu_profile.build_cpu_profile_paths(artifacts_dir)
    cpu_profile_active = False
    cpu_profile_stopped = False
    process: subprocess.Popen[str] | None = None
    process_handle: int | None = None
    metric_rows: list[dict[str, object]] = []
    runtime_counter_rows: list[dict[str, object]] = []
    spike_dumps: list[dict[str, object]] = []
    exit_code = 1

    try:
        if args.enable_umdh:
            if not tools["gflags"] or not tools["umdh"]:
                message = "UMDH requested but gflags or umdh was not found."
                if args.require_umdh:
                    raise RuntimeError(message)
                report["checks"]["umdh_setup"] = {"skipped": True, "reason": message}
            else:
                report["checks"]["gflags_enable_ust"] = live_process_monitor.set_umdh_stack_tracing(
                    str(tools["gflags"]),
                    app_exe,
                    enabled=True,
                    output_path=analysis_dir / "gflags-enable-ust.txt",
                )
                gflags_enabled = True

        cpu_profile_report: dict[str, object] = {
            "enabled": bool(args.cpu_profile),
            "tool": "xperf",
            "profile_paths": {
                "etl": str(cpu_profile_paths.etl_path),
                "detail": str(cpu_profile_paths.detail_path),
                "summary": str(cpu_profile_paths.summary_path),
                "stack": str(cpu_profile_paths.stack_path),
            },
            "max_file_mb": args.cpu_profile_max_file_mb,
            "stack": bool(args.cpu_profile_stack),
            "stack_min_hits": args.cpu_profile_stack_min_hits,
            "symbols_required": bool(args.cpu_profile_symbols_required),
        }
        report["diagnostics"]["cpu_profile"] = cpu_profile_report
        if args.cpu_profile:
            if not cpu_profile_tools.xperf:
                cpu_profile_report["status"] = "skipped"
                cpu_profile_report["reason"] = "xperf was not found"
            else:
                pdb_path = cpu_profile.resolve_app_pdb_path(app_exe)
                if args.cpu_profile_symbols_required and not pdb_path.is_file():
                    raise RuntimeError(f"Required app symbols were not found: {pdb_path}")
                cpu_profile_report["start"] = cpu_profile.start_cpu_profile(
                    tools=cpu_profile_tools,
                    paths=cpu_profile_paths,
                    max_file_mb=args.cpu_profile_max_file_mb,
                    timeout_seconds=30.0,
                )
                cpu_profile_active = cpu_profile_report["start"].get("return_code") == 0
                if not cpu_profile_active:
                    cpu_profile_report["status"] = "failed"

        command = live_process_monitor.build_launch_command(app_exe, config.profile_dir)
        report["launch"] = {"command": command}
        write_json(artifacts_dir / "result.json", report)
        process = subprocess.Popen(command)
        report["pid"] = process.pid
        process_handle = live_process_monitor.open_process(process.pid)

        if args.enable_umdh and tools["umdh"]:
            time.sleep(min(15.0, max(1.0, config.sample_interval_seconds)))
            report["diagnostics"]["umdh_baseline"] = live_process_monitor.capture_umdh_snapshot(
                str(tools["umdh"]),
                process.pid,
                analysis_dir / "umdh-baseline.txt",
            )

        started = time.monotonic()
        deadline = started + config.duration_seconds
        last_sample_monotonic: float | None = None
        last_cpu_seconds: float | None = None
        final_dump: dict[str, object] | None = None

        while time.monotonic() < deadline:
            row = live_process_monitor.sample_process_metrics(
                handle=process_handle,
                started_monotonic=started,
                last_sample_monotonic=last_sample_monotonic,
                last_cpu_seconds=last_cpu_seconds,
            )
            metric_rows.append(row)
            last_sample_monotonic = time.monotonic()
            last_cpu_seconds = float(row["cpu_seconds"])

            counters = live_process_monitor.sample_runtime_counters(config.base_url, config.api_key)
            counters["elapsed_seconds"] = row["elapsed_seconds"]
            runtime_counter_rows.append(counters)

            if int(row["exit_code"]) != live_process_monitor.STILL_ACTIVE:
                report["failure_reason"] = f"process exited early with code {row['exit_code']}"
                break

            if (
                not args.skip_spike_dumps
                and live_process_monitor.should_capture_spike_dump(
                    elapsed_seconds=float(row["elapsed_seconds"]),
                    process_pct_one_core=float(row["process_pct_one_core"]),
                    captured_count=len(spike_dumps),
                    max_spike_dumps=config.max_spike_dumps,
                    cpu_spike_threshold_one_core=config.cpu_spike_threshold_one_core,
                    spike_dump_delay_seconds=config.spike_dump_delay_seconds,
                )
            ):
                dump_path = diagnostics_dir / f"cpu-spike-{len(spike_dumps) + 1:02d}.dmp"
                spike_dumps.append(
                    live_process_monitor.capture_procdump(
                        config.procdump_path,
                        process.pid,
                        dump_path,
                        analysis_dir / f"procdump-cpu-spike-{len(spike_dumps) + 1:02d}.txt",
                    )
                )

            time.sleep(config.sample_interval_seconds)

        if cpu_profile_active:
            cpu_profile_report["stop"] = cpu_profile.stop_cpu_profile(
                tools=cpu_profile_tools,
                paths=cpu_profile_paths,
                timeout_seconds=60.0,
            )
            cpu_profile_stopped = True
            if (
                cpu_profile_report["start"].get("return_code") == 0
                and cpu_profile_report["stop"].get("return_code") == 0
                and cpu_profile_paths.etl_path.is_file()
            ):
                cpu_profile_report["export"] = cpu_profile.export_cpu_profile(
                    tools=cpu_profile_tools,
                    paths=cpu_profile_paths,
                    app_exe=app_exe,
                    timeout_seconds=90.0,
                    include_stack=bool(args.cpu_profile_stack),
                    stack_min_hits=args.cpu_profile_stack_min_hits,
                )
                detail_summary = cpu_profile.parse_xperf_profile_detail_file(cpu_profile_paths.detail_path)
                stack_summary = (
                    cpu_profile.parse_xperf_stack_report_file(cpu_profile_paths.stack_path)
                    if args.cpu_profile_stack
                    else {"available": False, "reason": "stack export disabled"}
                )
                combined_summary = {"detail": detail_summary, "stack": stack_summary}
                cpu_profile_paths.summary_path.write_text(
                    json.dumps(combined_summary, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                cpu_profile_report["summary"] = combined_summary
                cpu_profile_report["status"] = "passed" if detail_summary.get("available") else "failed"
            else:
                cpu_profile_report["status"] = "failed"

        if args.capture_final_dump and process_handle and live_process_monitor.get_process_exit_code(process_handle) == live_process_monitor.STILL_ACTIVE:
            final_dump = live_process_monitor.capture_procdump(
                config.procdump_path,
                process.pid,
                diagnostics_dir / "final-memory.dmp",
                analysis_dir / "procdump-final-memory.txt",
            )
            report["diagnostics"]["final_dump"] = final_dump
            if isinstance(final_dump, dict) and final_dump.get("dump_exists"):
                report["diagnostics"]["cdb_final_dump"] = live_process_monitor.analyze_dump_with_cdb(
                    Path(str(final_dump["dump_path"])),
                    analysis_dir / "cdb-final-memory-summary.txt",
                )

        if args.enable_umdh and tools["umdh"] and process_handle and live_process_monitor.get_process_exit_code(process_handle) == live_process_monitor.STILL_ACTIVE:
            report["diagnostics"]["umdh_final"] = live_process_monitor.capture_umdh_snapshot(
                str(tools["umdh"]),
                process.pid,
                analysis_dir / "umdh-final.txt",
            )
            report["diagnostics"]["umdh_diff"] = live_process_monitor.diff_umdh_snapshots(
                str(tools["umdh"]),
                analysis_dir / "umdh-baseline.txt",
                analysis_dir / "umdh-final.txt",
                analysis_dir / "umdh-diff-baseline-final.txt",
            )

        live_process_monitor.write_metric_csv(analysis_dir / "process-metrics.csv", metric_rows)
        (analysis_dir / "runtime-counters.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in runtime_counter_rows),
            encoding="utf-8",
        )
        report["diagnostics"]["process_metrics_csv"] = str(analysis_dir / "process-metrics.csv")
        report["diagnostics"]["runtime_counters_jsonl"] = str(analysis_dir / "runtime-counters.jsonl")
        report["diagnostics"]["spike_dumps"] = spike_dumps
        report["summary"] = live_process_monitor.summarize_metric_rows(metric_rows)

        if report.get("failure_reason"):
            report["status"] = "failed"
            exit_code = 1
        else:
            report["status"] = "passed"
            exit_code = 0
    finally:
        if cpu_profile_active and not cpu_profile_stopped:
            try:
                report["diagnostics"]["cpu_profile"]["stop"] = cpu_profile.stop_cpu_profile(
                    tools=cpu_profile_tools,
                    paths=cpu_profile_paths,
                    timeout_seconds=60.0,
                )
            except Exception as exc:  # noqa: BLE001 - best-effort cleanup for external ETW session
                report["diagnostics"]["cpu_profile"]["stop_error"] = str(exc)
        if process_handle is not None and process is not None:
            running = live_process_monitor.get_process_exit_code(process_handle) == live_process_monitor.STILL_ACTIVE
            if running and not args.keep_running:
                report["cleanup"] = live_process_monitor.close_process_gracefully(
                    process,
                    process_handle,
                    timeout_seconds=60.0,
                )
            elif running and args.keep_running:
                report["cleanup"] = {"app_closed": False, "kept_running": True, "pid": process.pid}
            live_process_monitor.close_handle(process_handle)
        if gflags_enabled and tools.get("gflags"):
            report["checks"]["gflags_disable_ust"] = live_process_monitor.set_umdh_stack_tracing(
                str(tools["gflags"]),
                app_exe,
                enabled=False,
                output_path=analysis_dir / "gflags-disable-ust.txt",
            )
        write_json(artifacts_dir / "result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
