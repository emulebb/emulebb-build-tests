"""Verifies that the gated eMule crash trigger produces a WER LocalDump."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import time
import urllib.error

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


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


rest_smoke = load_local_module("rest_api_smoke_for_local_dumps_crash_smoke", "rest-api-smoke.py")
rest_cold_start = load_local_module("rest_cold_start_for_local_dumps_crash_smoke", "rest-cold-start-dump-stress.py")
harness_cli_common = rest_smoke.harness_cli_common

SUITE_NAME = "local-dumps-crash-smoke"


def build_parser() -> argparse.ArgumentParser:
    """Builds the command-line parser for the LocalDumps crash smoke suite."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default="local-dumps-crash-test-key")
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--p2p-bind-interface-name", default="hide.me")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--dump-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--request-timeout-seconds", type=float, default=5.0)
    return parser


def wait_for_process_access_violation(process_id: int | None, timeout_seconds: float) -> dict[str, object]:
    """Waits until eMule exits with the Windows access-violation status."""

    deadline = time.monotonic() + timeout_seconds
    last_state: dict[str, object] = rest_smoke.get_process_exit_state(process_id)
    while time.monotonic() <= deadline:
        last_state = rest_smoke.get_process_exit_state(process_id)
        if harness_cli_common.process_exited_with_access_violation(last_state):
            return {
                "ok": True,
                "state": last_state,
            }
        if last_state.get("running") is False and last_state.get("exit_code") != rest_smoke.STILL_ACTIVE:
            return {
                "ok": False,
                "state": last_state,
                "reason": "process exited without access violation",
            }
        time.sleep(0.5)
    return {
        "ok": False,
        "state": last_state,
        "reason": "timed out waiting for access violation exit",
    }


def wait_for_emule_local_dump(local_dumps: dict[str, object], timeout_seconds: float) -> dict[str, object]:
    """Waits for at least one non-empty eMule LocalDump in the configured folder."""

    deadline = time.monotonic() + timeout_seconds
    last_files: dict[str, object] = {"files": []}
    while time.monotonic() <= deadline:
        last_files = harness_cli_common.collect_local_dump_files(local_dumps)
        emule_dumps = [
            row
            for row in harness_cli_common.local_dump_files_for_image(last_files, "emule.exe")
            if int(row.get("size_bytes") or 0) > 0
        ]
        if emule_dumps:
            return {
                "ok": True,
                "local_dump_files": last_files,
                "emule_dumps": emule_dumps,
            }
        time.sleep(1.0)
    return {
        "ok": False,
        "local_dump_files": last_files,
        "emule_dumps": [],
        "reason": "timed out waiting for emule.exe LocalDump",
    }


def trigger_crash(base_url: str, api_key: str, request_timeout_seconds: float) -> dict[str, object]:
    """Calls the gated crash-test endpoint and records the expected disconnect."""

    try:
        result = rest_smoke.http_request(
            base_url,
            "/api/v1/app/operations/crash-test",
            method="POST",
            api_key=api_key,
            json_body={"confirmCrash": True},
            request_timeout_seconds=request_timeout_seconds,
        )
        return {
            "request_completed": True,
            "result": rest_smoke.compact_http_result(result),
        }
    except (OSError, urllib.error.URLError) as exc:
        return {
            "request_completed": False,
            "exception": {
                "type": type(exc).__name__,
                "message": str(exc),
            },
        }


def start_procdump_crash_monitor(process_id: int | None, dump_dir: Path) -> tuple[dict[str, object], subprocess.Popen | None]:
    """Starts ProcDump in crash-monitor mode for the target eMule process."""

    tools = rest_cold_start.discover_diagnostic_tools()
    procdump = tools.get("procdump")
    result: dict[str, object] = {
        "started": False,
        "procdump": procdump,
        "process_id": process_id,
        "dump_dir": str(dump_dir),
    }
    if process_id is None:
        result["error"] = "process id is unavailable"
        return result, None
    if not procdump:
        result["error"] = "procdump was not found"
        return result, None

    dump_dir.mkdir(parents=True, exist_ok=True)
    log_path = dump_dir / "procdump-crash-monitor.txt"
    command = [
        procdump,
        "-accepteula",
        "-ma",
        "-e",
        "1",
        "-o",
        str(process_id),
        str(dump_dir),
    ]
    log_handle = log_path.open("w", encoding="utf-8", errors="replace")
    log_handle.write("command: " + subprocess.list2cmdline(command) + "\n\n")
    log_handle.flush()
    try:
        process = subprocess.Popen(command, stdout=log_handle, stderr=subprocess.STDOUT)
    except OSError as exc:
        log_handle.close()
        result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
        return result, None
    setattr(process, "_emulebb_log_handle", log_handle)
    result.update(
        {
            "started": True,
            "pid": process.pid,
            "log_path": str(log_path),
            "command": command,
        }
    )
    return result, process


def finish_procdump_crash_monitor(process: subprocess.Popen | None, timeout_seconds: float) -> dict[str, object]:
    """Waits for ProcDump to finish and records generated crash dumps."""

    result: dict[str, object] = {
        "started": process is not None,
        "return_code": None,
        "timed_out": False,
    }
    if process is None:
        return result
    try:
        result["return_code"] = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        result["timed_out"] = True
        process.terminate()
        try:
            result["return_code"] = process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            result["return_code"] = process.wait(timeout=5.0)
    finally:
        log_handle = getattr(process, "_emulebb_log_handle", None)
        if log_handle is not None:
            log_handle.close()
    return result


def collect_procdump_crash_dumps(dump_dir: Path) -> dict[str, object]:
    """Returns ProcDump-created eMule dump files from the crash monitor folder."""

    files: list[dict[str, object]] = []
    if dump_dir.is_dir():
        for dump_path in sorted(dump_dir.glob("emule*.dmp"), key=lambda path: path.stat().st_mtime):
            stat = dump_path.stat()
            files.append(
                {
                    "name": dump_path.name,
                    "path": str(dump_path),
                    "size_bytes": stat.st_size,
                    "mtime": round(stat.st_mtime, 3),
                }
            )
    return {
        "dump_folder": str(dump_dir),
        "files": files,
        "count": len(files),
    }


def main(argv: list[str] | None = None) -> int:
    """Runs the LocalDumps crash smoke and returns a process exit code."""

    args = build_parser().parse_args(argv)
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    artifacts_dir = paths.source_artifacts_dir
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    port = rest_smoke.choose_listen_port()
    base_url = f"http://127.0.0.1:{port}"
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
        "local_dumps": paths.local_dumps,
        "settings": {
            "dump_timeout_seconds": args.dump_timeout_seconds,
            "request_timeout_seconds": args.request_timeout_seconds,
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
        },
        "checks": {},
        "cleanup": {},
    }
    app = None
    process_id: int | None = None
    procdump_process: subprocess.Popen | None = None
    procdump_dump_dir = artifacts_dir / "procdump-crash-dumps"

    try:
        if harness_cli_common.windows_error_reporting_is_disabled(paths.local_dumps.get("wer")):
            report["failure_reason"] = "Windows Error Reporting is disabled after LocalDumps setup; WER LocalDumps cannot be captured"
            return 1

        profile = rest_smoke.prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[])
        report["launch_inputs"] = {
            "seed_config_dir": str(seed_config_dir),
            "profile_base": str(profile["profile_base"]),
            "config_dir": str(profile["config_dir"]),
            "api_key_length": len(args.api_key),
            "bind_addr": args.bind_addr,
            "enable_crash_test_endpoint": True,
            "enable_upnp": True,
        }
        rest_smoke.configure_webserver_profile(
            Path(profile["config_dir"]),
            paths.app_exe,
            args.api_key,
            port,
            args.bind_addr,
            enable_crash_test_endpoint=True,
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
        report["checks"]["procdump_monitor"], procdump_process = start_procdump_crash_monitor(process_id, procdump_dump_dir)
        if procdump_process is not None:
            time.sleep(2.0)
        report["checks"]["trigger_crash"] = trigger_crash(base_url, args.api_key, args.request_timeout_seconds)
        report["checks"]["process_exit"] = wait_for_process_access_violation(process_id, args.dump_timeout_seconds)
        report["checks"]["procdump_monitor_finish"] = finish_procdump_crash_monitor(procdump_process, args.dump_timeout_seconds)
        procdump_process = None
        report["checks"]["procdump_dump_files"] = collect_procdump_crash_dumps(procdump_dump_dir)
        report["checks"]["local_dump"] = wait_for_emule_local_dump(paths.local_dumps, args.dump_timeout_seconds)
        dump_count = int(report["checks"]["local_dump"].get("local_dump_files", {}).get("count", 0))
        dump_count += int(report["checks"]["procdump_dump_files"].get("count", 0))
        if report["checks"]["process_exit"].get("ok") and dump_count > 0:
            report["status"] = "passed"
        else:
            report["failure_reason"] = "crash trigger did not produce an access-violation exit and eMule crash dump"
    except Exception as exc:
        report["status"] = "failed"
        report["failure_reason"] = f"{type(exc).__name__}: {exc}"
        if process_id is not None:
            report["failure_process_state"] = rest_smoke.get_process_exit_state(process_id)
    finally:
        if procdump_process is not None:
            report["checks"]["procdump_monitor_finish"] = finish_procdump_crash_monitor(procdump_process, 5.0)
            report["checks"]["procdump_dump_files"] = collect_procdump_crash_dumps(procdump_dump_dir)
        report["local_dump_files"] = harness_cli_common.collect_local_dump_files(paths.local_dumps)
        if app is not None and report.get("status") != "passed":
            state = rest_smoke.get_process_exit_state(process_id)
            if state.get("running"):
                try:
                    report["cleanup"]["app_shutdown"] = rest_smoke.close_app_cleanly(app)
                except Exception as exc:
                    report["cleanup"]["app_shutdown_error"] = {
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
        harness_cli_common.write_json_file(artifacts_dir / "result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)

    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
