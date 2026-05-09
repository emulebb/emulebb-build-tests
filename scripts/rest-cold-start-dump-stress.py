"""Runs cold-start REST search/download stress with dump and heap diagnostics."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import live_wire_inputs
from emule_test_harness.live_seed_sources import EMULE_SECURITY_HOME_URL, refresh_seed_files


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


rest_smoke = load_local_module("rest_api_smoke_for_cold_start_dump_stress", "rest-api-smoke.py")
harness_cli_common = rest_smoke.harness_cli_common
live_common = rest_smoke.live_common

SUITE_NAME = "rest-cold-start-dump-stress"
SUITE_INCONCLUSIVE_RETURN_CODE = 2
DIAGNOSTIC_LABELS = ("baseline", "peak", "post_drain")


class DownloadTriggerBudget:
    """Thread-safe per-wave budget for paused live download trigger attempts."""

    def __init__(self, attempts: int) -> None:
        self._remaining = attempts
        self._lock = threading.Lock()

    def claim(self) -> bool:
        """Returns true when the caller should attempt one download trigger."""

        with self._lock:
            if self._remaining <= 0:
                return False
            self._remaining -= 1
            return True


def build_parser() -> argparse.ArgumentParser:
    """Builds the cold-start diagnostic stress CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default="rest-cold-start-dump-stress-key")
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--enable-upnp", action="store_true", default=True)
    parser.add_argument("--p2p-bind-interface-name", default="hide.me")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--network-ready-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--kad-running-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--search-observation-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--seed-download-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument("--live-wire-inputs-file", default=str(live_wire_inputs.get_default_inputs_path(REPO_ROOT)))
    parser.add_argument("--waves", type=int, default=4)
    parser.add_argument("--searches-per-wave", type=int, default=12)
    parser.add_argument("--max-concurrent-searches", type=int, default=8)
    parser.add_argument("--downloads-per-wave", type=int, default=6)
    parser.add_argument("--post-drain-seconds", type=float, default=30.0)
    parser.add_argument("--tool-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--enable-umdh", action="store_true")
    parser.add_argument("--skip-dumps", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validates stress and diagnostic CLI arguments."""

    if args.waves <= 0:
        raise ValueError("waves must be greater than zero.")
    if args.searches_per_wave <= 0:
        raise ValueError("searches per wave must be greater than zero.")
    if args.max_concurrent_searches <= 0:
        raise ValueError("max concurrent searches must be greater than zero.")
    if args.downloads_per_wave < 0:
        raise ValueError("downloads per wave must be zero or greater.")
    if args.post_drain_seconds < 0:
        raise ValueError("post-drain seconds must be zero or greater.")
    if args.tool_timeout_seconds <= 0:
        raise ValueError("tool timeout seconds must be greater than zero.")


def candidate_tool_paths(tool_name: str) -> list[Path]:
    """Returns deterministic fallback locations for Windows diagnostic tools."""

    candidates: list[Path] = []
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(env_name)
        if root:
            candidates.append(Path(root) / "Windows Kits" / "10" / "Debuggers" / "x64" / tool_name)
    program_data = os.environ.get("ProgramData")
    if program_data:
        candidates.append(Path(program_data) / "chocolatey" / "lib" / "sysinternals" / "tools" / tool_name)
        candidates.append(Path(program_data) / "chocolatey" / "bin" / tool_name)
    system_root = os.environ.get("SystemRoot")
    if system_root:
        candidates.append(Path(system_root) / "System32" / tool_name)
    return candidates


def is_known_broken_chocolatey_sysinternals_shim(path: str) -> bool:
    """Returns true for Chocolatey Sysinternals shims whose package payload is missing."""

    program_data = os.environ.get("ProgramData")
    if not program_data:
        return False
    candidate = Path(path)
    shim_dir = Path(program_data) / "chocolatey" / "bin"
    try:
        if candidate.resolve().parent != shim_dir.resolve():
            return False
    except OSError:
        return False
    backing_tool = Path(program_data) / "chocolatey" / "lib" / "sysinternals" / "tools" / candidate.name
    return not backing_tool.is_file()


def find_tool(*names: str) -> str | None:
    """Finds the first available executable from PATH or known Windows tool roots."""

    for name in names:
        for candidate in candidate_tool_paths(name):
            if candidate.is_file():
                if is_known_broken_chocolatey_sysinternals_shim(str(candidate)):
                    continue
                return str(candidate)
        resolved = shutil.which(name)
        if resolved and not is_known_broken_chocolatey_sysinternals_shim(resolved):
            return resolved
    return None


def discover_diagnostic_tools() -> dict[str, str | None]:
    """Discovers Sysinternals and Windows SDK tools used by the diagnostic lane."""

    return {
        "procdump": find_tool("procdump64.exe", "procdump64", "procdump.exe", "procdump"),
        "cdb": find_tool("cdb.exe", "cdb"),
        "handle": find_tool("handle64.exe", "handle64", "handle.exe", "handle"),
        "listdlls": find_tool("listdlls64.exe", "listdlls64", "listdlls.exe", "listdlls"),
        "gflags": find_tool("gflags.exe", "gflags"),
        "umdh": find_tool("umdh.exe", "umdh"),
    }


def run_tool_to_file(
    command: list[str],
    output_path: Path,
    timeout_seconds: float,
    *,
    env: dict[str, str] | None = None,
) -> dict[str, object]:
    """Runs one diagnostic tool and writes stdout/stderr plus metadata to a file."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    command_line = subprocess.list2cmdline(command)
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            env=env,
        )
        duration = round(time.monotonic() - started, 3)
        output_path.write_text(
            "\n".join(
                [
                    f"command: {command_line}",
                    f"return_code: {completed.returncode}",
                    f"duration_seconds: {duration}",
                    "",
                    completed.stdout,
                    completed.stderr,
                ]
            ),
            encoding="utf-8",
        )
        return {
            "command": command,
            "output_path": str(output_path),
            "return_code": completed.returncode,
            "duration_seconds": duration,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        duration = round(time.monotonic() - started, 3)
        output_path.write_text(
            "\n".join(
                [
                    f"command: {command_line}",
                    f"timed_out: true",
                    f"duration_seconds: {duration}",
                    "",
                    str(exc.stdout or ""),
                    str(exc.stderr or ""),
                ]
            ),
            encoding="utf-8",
        )
        return {
            "command": command,
            "output_path": str(output_path),
            "return_code": None,
            "duration_seconds": duration,
            "timed_out": True,
        }


def build_symbol_environment(app_exe: Path, artifacts_dir: Path) -> dict[str, str]:
    """Builds a symbol environment for UMDH/CDB without changing the parent process."""

    env = dict(os.environ)
    symbol_cache = artifacts_dir / "symbols"
    symbol_cache.mkdir(parents=True, exist_ok=True)
    app_symbol_dir = app_exe.parent
    env["_NT_SYMBOL_PATH"] = f"{app_symbol_dir};srv*{symbol_cache}*https://msdl.microsoft.com/download/symbols"
    return env


def set_umdh_stack_tracing(
    gflags_path: str,
    app_exe: Path,
    enabled: bool,
    output_path: Path,
    timeout_seconds: float,
) -> dict[str, object]:
    """Enables or disables UST for the app image with gflags."""

    flag = "+ust" if enabled else "-ust"
    return run_tool_to_file(
        [gflags_path, "/i", app_exe.name, flag],
        output_path,
        timeout_seconds,
    )


def capture_dump_and_analysis(
    *,
    label: str,
    process_id: int,
    tools: dict[str, str | None],
    diagnostics_dir: Path,
    timeout_seconds: float,
    skip_dumps: bool,
    symbol_env: dict[str, str],
) -> dict[str, object]:
    """Captures a full dump and runs CDB summary analysis when available."""

    result: dict[str, object] = {
        "label": label,
        "skipped": bool(skip_dumps),
        "dump": None,
        "cdb": None,
    }
    if skip_dumps:
        return result

    procdump = tools.get("procdump")
    if not procdump:
        result["error"] = "procdump was not found"
        return result

    dump_path = diagnostics_dir / "dumps" / f"{label}.dmp"
    dump_path.parent.mkdir(parents=True, exist_ok=True)
    procdump_log = diagnostics_dir / "analysis" / f"{label}-procdump.txt"
    dump_run = run_tool_to_file(
        [procdump, "-accepteula", "-ma", str(process_id), str(dump_path)],
        procdump_log,
        timeout_seconds,
    )
    dump_run["dump_path"] = str(dump_path)
    dump_run["dump_exists"] = dump_path.is_file()
    result["dump"] = dump_run

    cdb = tools.get("cdb")
    if cdb and dump_path.is_file():
        cdb_log = diagnostics_dir / "analysis" / f"{label}-cdb.txt"
        result["cdb"] = run_tool_to_file(
            [
                cdb,
                "-z",
                str(dump_path),
                "-c",
                ".symfix; .reload; |; lm; ~*k; !handle 0 0; !heap -s; !address -summary; q",
            ],
            cdb_log,
            timeout_seconds,
            env=symbol_env,
        )
    elif not cdb:
        result["cdb"] = {"skipped": True, "reason": "cdb was not found"}
    return result


def redact_sensitive_search_value(value: object) -> object:
    """Redacts exact live search terms from persisted stress artifacts."""

    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            if key == "query":
                redacted["query_present"] = bool(item)
            elif key == "body_text":
                redacted["body_text_redacted"] = True
            else:
                redacted[key] = redact_sensitive_search_value(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive_search_value(item) for item in value]
    return value


def capture_text_snapshot(
    *,
    tool_path: str | None,
    command_suffix: list[str],
    output_path: Path,
    timeout_seconds: float,
    missing_reason: str,
) -> dict[str, object]:
    """Captures a text diagnostic snapshot from one Sysinternals-style tool."""

    if not tool_path:
        return {"skipped": True, "reason": missing_reason}
    return run_tool_to_file([tool_path, *command_suffix], output_path, timeout_seconds)


def capture_umdh_snapshot(
    *,
    label: str,
    process_id: int,
    tools: dict[str, str | None],
    diagnostics_dir: Path,
    timeout_seconds: float,
    symbol_env: dict[str, str],
) -> dict[str, object]:
    """Captures one UMDH snapshot for the current process."""

    umdh = tools.get("umdh")
    if not umdh:
        return {"skipped": True, "reason": "umdh was not found"}
    snapshot_path = diagnostics_dir / "analysis" / f"umdh-{label}.txt"
    run = run_tool_to_file(
        [umdh, f"-p:{process_id}", f"-f:{snapshot_path}"],
        diagnostics_dir / "analysis" / f"umdh-{label}-stdout.txt",
        timeout_seconds,
        env=symbol_env,
    )
    run["snapshot_path"] = str(snapshot_path)
    run["snapshot_exists"] = snapshot_path.is_file()
    return run


def diff_umdh_snapshots(
    *,
    before: Path,
    after: Path,
    diff_name: str,
    tools: dict[str, str | None],
    diagnostics_dir: Path,
    timeout_seconds: float,
    symbol_env: dict[str, str],
) -> dict[str, object]:
    """Runs UMDH diff mode for two completed snapshots."""

    umdh = tools.get("umdh")
    if not umdh:
        return {"skipped": True, "reason": "umdh was not found"}
    if not before.is_file() or not after.is_file():
        return {"skipped": True, "reason": "one or both UMDH snapshots are missing"}
    return run_tool_to_file(
        [umdh, "-d", str(before), str(after)],
        diagnostics_dir / "analysis" / f"umdh-diff-{diff_name}.txt",
        timeout_seconds,
        env=symbol_env,
    )


def collect_diagnostics(
    *,
    label: str,
    process_id: int | None,
    tools: dict[str, str | None],
    diagnostics_dir: Path,
    timeout_seconds: float,
    skip_dumps: bool,
    enable_umdh: bool,
    symbol_env: dict[str, str],
) -> dict[str, object]:
    """Collects resources, dumps, handles, loaded modules, and optional UMDH."""

    result: dict[str, object] = {
        "label": label,
        "process_id": process_id,
        "resources": rest_smoke.get_process_resource_snapshot(process_id),
        "tools": {},
    }
    harness_cli_common.write_json_file(diagnostics_dir / f"resources-{label}.json", result["resources"])
    if process_id is None:
        result["error"] = "process id is unavailable"
        return result

    result["tools"]["dump_analysis"] = capture_dump_and_analysis(
        label=label,
        process_id=process_id,
        tools=tools,
        diagnostics_dir=diagnostics_dir,
        timeout_seconds=timeout_seconds,
        skip_dumps=skip_dumps,
        symbol_env=symbol_env,
    )
    result["tools"]["handle"] = capture_text_snapshot(
        tool_path=tools.get("handle"),
        command_suffix=["-accepteula", "-p", str(process_id), "-a"],
        output_path=diagnostics_dir / "analysis" / f"handle-{label}.txt",
        timeout_seconds=timeout_seconds,
        missing_reason="handle was not found",
    )
    if label == "baseline":
        result["tools"]["listdlls"] = capture_text_snapshot(
            tool_path=tools.get("listdlls"),
            command_suffix=["-accepteula", "-v", str(process_id)],
            output_path=diagnostics_dir / "analysis" / "listdlls.txt",
            timeout_seconds=timeout_seconds,
            missing_reason="listdlls was not found",
        )
    if enable_umdh:
        result["tools"]["umdh"] = capture_umdh_snapshot(
            label=label,
            process_id=process_id,
            tools=tools,
            diagnostics_dir=diagnostics_dir,
            timeout_seconds=timeout_seconds,
            symbol_env=symbol_env,
        )
    return result


def build_wave_search_plan(
    *,
    wave_index: int,
    searches_per_wave: int,
    search_terms: tuple[str, ...],
    network_mode: str,
) -> list[dict[str, object]]:
    """Builds one phased-ramp wave with mixed methods when live networks allow it."""

    if not search_terms:
        raise RuntimeError("Cold-start stress requires at least one live search term.")
    if network_mode == "both":
        method_cycle = (("server", "server"), ("kad", "kad"), ("server", "automatic"))
    elif network_mode == "kad":
        method_cycle = (("kad", "kad"), ("kad", "automatic"))
    else:
        method_cycle = (("server", "server"), ("server", "global"), ("server", "automatic"))
    rows: list[dict[str, object]] = []
    for index in range(searches_per_wave):
        network, method = method_cycle[index % len(method_cycle)]
        term_index = ((wave_index - 1) * searches_per_wave + index) % len(search_terms)
        rows.append(
            {
                "wave": wave_index,
                "ordinal": index + 1,
                "network": network,
                "method": method,
                "query": search_terms[term_index],
                "query_index": term_index,
            }
        )
    return rows


def run_search_task(
    *,
    base_url: str,
    api_key: str,
    plan_row: dict[str, object],
    observation_timeout_seconds: float,
    trigger_budget: DownloadTriggerBudget,
) -> dict[str, object]:
    """Starts one live search, observes it, and optionally triggers a safe paused download."""

    report: dict[str, object] = {
        "wave": plan_row["wave"],
        "ordinal": plan_row["ordinal"],
        "network": plan_row["network"],
        "method": plan_row["method"],
        "query_index": plan_row["query_index"],
    }
    try:
        started = rest_smoke.start_live_search(
            base_url,
            api_key,
            str(plan_row["network"]),
            str(plan_row["query"]),
            forced_method=str(plan_row["method"]),
        )
        report["start"] = redact_sensitive_search_value(started)
        if not bool(started.get("ok")):
            report["ok"] = False
            report["error"] = "search start failed"
            return report
        response = started.get("response")
        assert isinstance(response, dict)
        payload = rest_smoke.require_json_object(response, 200)
        search_id = str(payload["id"])
        report["searchId"] = search_id
        report["activity"] = redact_sensitive_search_value(
            rest_smoke.wait_for_search_observation(
                base_url,
                api_key,
                search_id,
                observation_timeout_seconds,
            )
        )
        if trigger_budget.claim():
            report["download_trigger"] = rest_smoke.trigger_paused_download_from_search_result(
                base_url,
                api_key,
                search_id,
                observation_timeout_seconds,
            )
        report["ok"] = True
    except Exception as exc:
        report["ok"] = False
        report["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
    return report


def run_stress_waves(
    *,
    base_url: str,
    api_key: str,
    process_id: int | None,
    search_terms: tuple[str, ...],
    network_mode: str,
    waves: int,
    searches_per_wave: int,
    max_concurrent_searches: int,
    downloads_per_wave: int,
    observation_timeout_seconds: float,
) -> dict[str, object]:
    """Runs phased live search/download stress while keeping searches active until cleanup."""

    wave_reports: list[dict[str, object]] = []
    all_search_ids: list[str] = []
    completed_download_triggers = 0
    for wave_index in range(1, waves + 1):
        trigger_budget = DownloadTriggerBudget(downloads_per_wave)
        plan = build_wave_search_plan(
            wave_index=wave_index,
            searches_per_wave=searches_per_wave,
            search_terms=search_terms,
            network_mode=network_mode,
        )
        wave_rows: list[dict[str, object]] = []
        with ThreadPoolExecutor(max_workers=max_concurrent_searches) as executor:
            futures = [
                executor.submit(
                    run_search_task,
                    base_url=base_url,
                    api_key=api_key,
                    plan_row=row,
                    observation_timeout_seconds=observation_timeout_seconds,
                    trigger_budget=trigger_budget,
                )
                for row in plan
            ]
            for future in as_completed(futures):
                row = future.result()
                wave_rows.append(row)
                if isinstance(row.get("searchId"), str):
                    all_search_ids.append(str(row["searchId"]))
                trigger = row.get("download_trigger")
                if isinstance(trigger, dict) and bool(trigger.get("ok")):
                    completed_download_triggers += 1

        ready_probe = rest_smoke.http_request(base_url, "/api/v1/app", api_key=api_key)
        wave_reports.append(
            {
                "wave": wave_index,
                "planned_searches": len(plan),
                "completed_searches": sum(1 for row in wave_rows if bool(row.get("ok"))),
                "failed_searches": sum(1 for row in wave_rows if not bool(row.get("ok"))),
                "requested_download_triggers": downloads_per_wave,
                "completed_download_triggers": sum(
                    1
                    for row in wave_rows
                    if isinstance(row.get("download_trigger"), dict) and bool(row["download_trigger"].get("ok"))
                ),
                "rest_ready_probe": rest_smoke.compact_http_result(ready_probe),
                "resource_snapshot": rest_smoke.get_process_resource_snapshot(process_id),
                "searches": sorted(wave_rows, key=lambda row: int(row.get("ordinal", 0))),
            }
        )
        if int(ready_probe["status"]) != 200:
            raise RuntimeError(f"REST readiness probe failed after wave {wave_index}: {ready_probe!r}")

    return {
        "waves": wave_reports,
        "search_ids": all_search_ids,
        "planned_searches": waves * searches_per_wave,
        "completed_searches": sum(wave["completed_searches"] for wave in wave_reports),
        "failed_searches": sum(wave["failed_searches"] for wave in wave_reports),
        "requested_download_triggers": waves * downloads_per_wave,
        "completed_download_triggers": completed_download_triggers,
    }


def cleanup_searches_and_transfers(
    *,
    base_url: str,
    api_key: str,
    search_ids: list[str],
) -> dict[str, object]:
    """Deletes active searches and records safe transfer cleanup state."""

    cleanup: dict[str, object] = {
        "search_ids": search_ids,
    }
    delete_result = rest_smoke.delete_all_searches(base_url, api_key)
    cleanup["delete_all_searches"] = rest_smoke.compact_http_result(delete_result)
    if int(delete_result["status"]) == 200:
        cleanup["post_delete"] = rest_smoke.verify_searches_deleted(base_url, api_key, search_ids)
    clear_result = rest_smoke.clear_completed_transfers(base_url, api_key)
    cleanup["clear_completed_transfers"] = rest_smoke.compact_http_result(clear_result)
    return cleanup


def diagnostics_are_complete(report: dict[str, object], *, skip_dumps: bool) -> bool:
    """Returns true when mandatory dump artifacts exist for the completed labels."""

    if skip_dumps:
        return True
    diagnostics = report.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return False
    for label in DIAGNOSTIC_LABELS:
        entry = diagnostics.get(label)
        if not isinstance(entry, dict):
            return False
        tools = entry.get("tools")
        if not isinstance(tools, dict):
            return False
        dump_analysis = tools.get("dump_analysis")
        if not isinstance(dump_analysis, dict):
            return False
        dump = dump_analysis.get("dump")
        if not isinstance(dump, dict) or not bool(dump.get("dump_exists")):
            return False
    return True


def umdh_diagnostics_are_complete(report: dict[str, object]) -> bool:
    """Returns true when UMDH snapshots and diffs completed without timing out."""

    diagnostics = report.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return False
    for label in DIAGNOSTIC_LABELS:
        entry = diagnostics.get(label)
        if not isinstance(entry, dict):
            return False
        tools = entry.get("tools")
        if not isinstance(tools, dict):
            return False
        umdh = tools.get("umdh")
        if not isinstance(umdh, dict) or bool(umdh.get("timed_out")) or not bool(umdh.get("snapshot_exists")):
            return False
    diffs = diagnostics.get("umdh_diffs")
    if not isinstance(diffs, dict):
        return False
    for diff_name in ("baseline_to_peak", "baseline_to_post_drain"):
        diff = diffs.get(diff_name)
        if not isinstance(diff, dict) or bool(diff.get("timed_out")) or diff.get("return_code") != 0:
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    """Runs the cold-start dump stress suite and returns a process exit code."""

    args = build_parser().parse_args(argv)
    validate_args(args)
    inputs = live_wire_inputs.load_live_wire_inputs(
        live_wire_inputs.resolve_inputs_path(REPO_ROOT, args.live_wire_inputs_file)
    )
    search_terms = inputs.generic_open_terms
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
    diagnostics_dir = artifacts_dir
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    port = rest_smoke.choose_listen_port()
    base_url = f"http://127.0.0.1:{port}"
    tools = discover_diagnostic_tools()
    symbol_env = build_symbol_environment(paths.app_exe, artifacts_dir)
    report: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "suite": SUITE_NAME,
        "status": "failed",
        "base_url": base_url,
        "app_exe": str(paths.app_exe),
        "configuration": args.configuration,
        "artifact_dir": str(paths.run_report_dir),
        "latest_report_dir": str(paths.latest_report_dir),
        "source_artifact_dir": str(paths.source_artifacts_dir),
        "live_seed_source_url": EMULE_SECURITY_HOME_URL,
        "live_wire_inputs_file": str(inputs.path),
        "live_wire_search_terms": live_wire_inputs.summarize_terms(search_terms),
        "diagnostic_tools": tools,
        "settings": {
            "waves": args.waves,
            "searches_per_wave": args.searches_per_wave,
            "max_concurrent_searches": args.max_concurrent_searches,
            "downloads_per_wave": args.downloads_per_wave,
            "post_drain_seconds": args.post_drain_seconds,
            "tool_timeout_seconds": args.tool_timeout_seconds,
            "enable_umdh": bool(args.enable_umdh),
            "skip_dumps": bool(args.skip_dumps),
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
        },
        "checks": {},
        "diagnostics": {},
        "cleanup": {},
    }
    app = None
    process_id: int | None = None
    gflags_enabled = False

    try:
        if args.enable_umdh:
            if not tools.get("gflags") or not tools.get("umdh"):
                raise RuntimeError("UMDH was requested but gflags or umdh was not found.")
            report["checks"]["gflags_enable_ust"] = set_umdh_stack_tracing(
                str(tools["gflags"]),
                paths.app_exe,
                True,
                diagnostics_dir / "analysis" / "gflags-enable-ust.txt",
                args.tool_timeout_seconds,
            )
            gflags_enabled = True

        profile = rest_smoke.prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[])
        seed_refresh = None
        if not args.skip_live_seed_refresh:
            seed_refresh = refresh_seed_files(
                Path(profile["config_dir"]),
                timeout_seconds=args.seed_download_timeout_seconds,
            )
        report["launch_inputs"] = {
            "seed_config_dir": str(seed_config_dir),
            "live_seed_refresh": seed_refresh,
            "profile_base": str(profile["profile_base"]),
            "config_dir": str(profile["config_dir"]),
            "api_key_length": len(args.api_key),
            "bind_addr": args.bind_addr,
            "enable_upnp": True,
        }
        rest_smoke.configure_webserver_profile(
            Path(profile["config_dir"]),
            paths.app_exe,
            args.api_key,
            port,
            args.bind_addr,
        )
        if args.p2p_bind_interface_name:
            rest_smoke.apply_p2p_bind_interface_override(Path(profile["config_dir"]), args.p2p_bind_interface_name)

        app = rest_smoke.launch_app(paths.app_exe, Path(profile["profile_base"]))
        process_id = rest_smoke.get_app_process_id(app)
        report["launched_process_id"] = process_id
        main_window = rest_smoke.wait_for_main_window(app)
        report["main_window_title"] = main_window.window_text()
        ready = rest_smoke.wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        report["checks"]["ready"] = rest_smoke.compact_http_result(ready)

        report["diagnostics"]["baseline"] = collect_diagnostics(
            label="baseline",
            process_id=process_id,
            tools=tools,
            diagnostics_dir=diagnostics_dir,
            timeout_seconds=args.tool_timeout_seconds,
            skip_dumps=args.skip_dumps,
            enable_umdh=args.enable_umdh,
            symbol_env=symbol_env,
        )

        servers = rest_smoke.http_request(base_url, "/api/v1/servers", api_key=args.api_key)
        server_rows = rest_smoke.require_json_array(servers, 200)
        report["checks"]["servers_list"] = {
            "count": len(server_rows),
        }
        try:
            report["checks"]["servers_connect"] = rest_smoke.connect_to_live_server(
                base_url,
                api_key=args.api_key,
                server_rows=server_rows,
                timeout_seconds=args.network_ready_timeout_seconds,
            )
        except rest_smoke.LiveNetworkUnavailableError as exc:
            report["checks"]["servers_connect"] = {
                "ok": False,
                "reason": str(exc),
            }

        kad_connect = rest_smoke.http_request(
            base_url,
            "/api/v1/kad/operations/start",
            method="POST",
            api_key=args.api_key,
            json_body={},
        )
        report["checks"]["kad_connect"] = rest_smoke.compact_http_result(kad_connect)
        if int(kad_connect["status"]) == 200:
            try:
                report["checks"]["kad_running"] = rest_smoke.wait_for_kad_running(
                    base_url,
                    args.api_key,
                    args.kad_running_timeout_seconds,
                )
            except Exception as exc:
                report["checks"]["kad_running"] = {
                    "ok": False,
                    "error": {
                        "type": type(exc).__name__,
                        "message": str(exc),
                    },
                }

        live_network = rest_smoke.wait_for_requested_networks(
            base_url,
            args.api_key,
            args.network_ready_timeout_seconds,
            require_server_connected=False,
            require_kad_connected=False,
        )
        report["checks"]["network_ready"] = live_network
        network_mode = str(live_network["mode"])

        stress = run_stress_waves(
            base_url=base_url,
            api_key=args.api_key,
            process_id=process_id,
            search_terms=search_terms,
            network_mode=network_mode,
            waves=args.waves,
            searches_per_wave=args.searches_per_wave,
            max_concurrent_searches=args.max_concurrent_searches,
            downloads_per_wave=args.downloads_per_wave,
            observation_timeout_seconds=args.search_observation_timeout_seconds,
        )
        report["checks"]["stress"] = stress
        report["diagnostics"]["peak"] = collect_diagnostics(
            label="peak",
            process_id=process_id,
            tools=tools,
            diagnostics_dir=diagnostics_dir,
            timeout_seconds=args.tool_timeout_seconds,
            skip_dumps=args.skip_dumps,
            enable_umdh=args.enable_umdh,
            symbol_env=symbol_env,
        )

        report["cleanup"]["searches_and_transfers"] = cleanup_searches_and_transfers(
            base_url=base_url,
            api_key=args.api_key,
            search_ids=[str(search_id) for search_id in stress["search_ids"]],
        )
        if args.post_drain_seconds:
            time.sleep(args.post_drain_seconds)
        report["diagnostics"]["post_drain"] = collect_diagnostics(
            label="post_drain",
            process_id=process_id,
            tools=tools,
            diagnostics_dir=diagnostics_dir,
            timeout_seconds=args.tool_timeout_seconds,
            skip_dumps=args.skip_dumps,
            enable_umdh=args.enable_umdh,
            symbol_env=symbol_env,
        )

        if args.enable_umdh:
            report["diagnostics"]["umdh_diffs"] = {
                "baseline_to_peak": diff_umdh_snapshots(
                    before=diagnostics_dir / "analysis" / "umdh-baseline.txt",
                    after=diagnostics_dir / "analysis" / "umdh-peak.txt",
                    diff_name="baseline-to-peak",
                    tools=tools,
                    diagnostics_dir=diagnostics_dir,
                    timeout_seconds=args.tool_timeout_seconds,
                    symbol_env=symbol_env,
                ),
                "baseline_to_post_drain": diff_umdh_snapshots(
                    before=diagnostics_dir / "analysis" / "umdh-baseline.txt",
                    after=diagnostics_dir / "analysis" / "umdh-post_drain.txt",
                    diff_name="baseline-to-post_drain",
                    tools=tools,
                    diagnostics_dir=diagnostics_dir,
                    timeout_seconds=args.tool_timeout_seconds,
                    symbol_env=symbol_env,
                ),
            }

        stress_summary = report["checks"]["stress"]
        assert isinstance(stress_summary, dict)
        if int(stress_summary.get("failed_searches", 0)) > 0:
            report["status"] = "failed"
            report["failure_reason"] = "one or more live searches failed"
        elif not diagnostics_are_complete(report, skip_dumps=args.skip_dumps):
            report["status"] = "failed"
            report["failure_reason"] = "required dump diagnostics were not captured"
        elif args.enable_umdh and not umdh_diagnostics_are_complete(report):
            report["status"] = "failed"
            report["failure_reason"] = "required UMDH diagnostics did not complete"
        elif int(stress_summary.get("completed_download_triggers", 0)) < int(stress_summary.get("requested_download_triggers", 0)):
            report["status"] = "inconclusive"
            report["failure_reason"] = "live network did not expose enough safe paused-download candidates"
        else:
            report["status"] = "passed"
    except rest_smoke.LiveNetworkUnavailableError as exc:
        report["status"] = "inconclusive"
        report["failure_reason"] = str(exc)
    except Exception as exc:
        report["status"] = "failed"
        report["failure_reason"] = f"{type(exc).__name__}: {exc}"
        if process_id is not None and "failure" not in report["diagnostics"]:
            report["diagnostics"]["failure"] = collect_diagnostics(
                label="failure",
                process_id=process_id,
                tools=tools,
                diagnostics_dir=diagnostics_dir,
                timeout_seconds=args.tool_timeout_seconds,
                skip_dumps=args.skip_dumps,
                enable_umdh=args.enable_umdh,
                symbol_env=symbol_env,
            )
    finally:
        if app is not None and not args.keep_running:
            try:
                report["cleanup"]["app_shutdown"] = rest_smoke.close_app_cleanly(app)
            except Exception as exc:
                report["cleanup"]["app_shutdown_error"] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
                if report.get("status") == "passed":
                    report["status"] = "failed"
        if gflags_enabled and tools.get("gflags"):
            try:
                report["checks"]["gflags_disable_ust"] = set_umdh_stack_tracing(
                    str(tools["gflags"]),
                    paths.app_exe,
                    False,
                    diagnostics_dir / "analysis" / "gflags-disable-ust.txt",
                    args.tool_timeout_seconds,
                )
            except Exception as exc:
                report["checks"]["gflags_disable_ust_error"] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
        harness_cli_common.write_json_file(artifacts_dir / "result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)

    if report["status"] == "passed":
        return 0
    if report["status"] == "inconclusive":
        return SUITE_INCONCLUSIVE_RETURN_CODE
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
