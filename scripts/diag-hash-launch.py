"""Launches eMule under diagnostic monitoring for hash-heavy stalls."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.live_profile_seed import validate_seed_config_dir
from emule_test_harness.paths import get_test_artifacts_root, get_test_reports_root, reject_windows_temp_path
from emule_test_harness.workspace_layout import get_default_workspace_root, resolve_workspace_app_root
from emule_test_harness.artifact_names import utc_run_id


def build_parser() -> argparse.ArgumentParser:
    """Builds the hash diagnostic launcher CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-root", type=Path)
    parser.add_argument("--emule-exe", type=Path)
    parser.add_argument("--profile-seed-dir", type=Path)
    parser.add_argument("--profile-root", type=Path)
    parser.add_argument("--report-root", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--cpu-threshold-percent", type=int, default=90)
    parser.add_argument("--cpu-duration-seconds", type=int, default=30)
    return parser


def publish_latest_directory_pointer(target_directory: Path, latest_directory: Path) -> None:
    """Refreshes the stable latest-report directory junction."""

    latest_directory.parent.mkdir(parents=True, exist_ok=True)
    if latest_directory.exists() or latest_directory.is_symlink():
        if latest_directory.is_dir() and not latest_directory.is_symlink():
            shutil.rmtree(latest_directory)
        else:
            latest_directory.unlink()
    completed = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(latest_directory), str(target_directory)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout.strip() or f"Failed to create latest report pointer: {latest_directory}")


def copy_seed_profile(seed_config_directory: Path, profile_base_path: Path) -> None:
    """Copies the deterministic seed config into one isolated profile root."""

    if not seed_config_directory.is_dir():
        raise RuntimeError(f"Seed config directory '{seed_config_directory}' does not exist.")
    validate_seed_config_dir(seed_config_directory)
    config_directory = profile_base_path / "config"
    logs_directory = profile_base_path / "logs"
    config_directory.mkdir(parents=True, exist_ok=True)
    logs_directory.mkdir(parents=True, exist_ok=True)
    for seed_entry in seed_config_directory.iterdir():
        destination = config_directory / seed_entry.name
        if seed_entry.is_dir():
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(seed_entry, destination)
        else:
            shutil.copy2(seed_entry, destination)


def main(argv: list[str] | None = None) -> int:
    """Runs the hash diagnostic launcher."""

    args = build_parser().parse_args(argv)
    test_repo_root = REPO_ROOT.resolve()
    workspace_root = get_default_workspace_root(test_repo_root).resolve()
    app_root = args.app_root.resolve() if args.app_root else resolve_workspace_app_root(
        workspace_root,
        preferred_variant_names=("main", "community"),
    )
    emule_exe = (args.emule_exe or (app_root / "srchybrid" / "x64" / "Debug" / "emulebb.exe")).resolve()
    report_root = (args.report_root or (get_test_reports_root(workspace_root) / "diag-hash-launch")).resolve()
    reject_windows_temp_path(report_root, "report root")
    latest_report_dir = report_root / "latest"
    seed_config_dir = (args.profile_seed_dir or (test_repo_root / "manifests" / "live-profile-seed" / "config")).resolve()

    timestamp = utc_run_id()
    run_dir = report_root / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    profile_root = (args.profile_root or (get_test_artifacts_root(workspace_root) / "diag-hash" / timestamp / "profile-base")).resolve()
    reject_windows_temp_path(profile_root, "profile root")

    print(f"[diag] Report directory: {run_dir}")
    print(f"[diag] App root: {app_root}")
    print(f"[diag] Profile root: {profile_root}")
    if not emule_exe.is_file():
        raise RuntimeError(f"eMule executable not found: {emule_exe}")

    copy_seed_profile(seed_config_dir, profile_root)
    log_dir = profile_root / "logs"
    for log_file in log_dir.glob("*.log"):
        log_file.unlink(missing_ok=True)

    print("[diag] Launching eMule...")
    emule_proc = subprocess.Popen([str(emule_exe), "-ignoreinstances", "-c", str(profile_root)])
    print(f"[diag] eMule PID: {emule_proc.pid}")
    time.sleep(3)

    dump_path = run_dir / "emule-cpu.dmp"
    print(
        "[diag] Starting procdump "
        f"(CPU > {args.cpu_threshold_percent}% for {args.cpu_duration_seconds} s triggers dump)..."
    )
    procdump_proc = subprocess.Popen(
        [
            "procdump",
            "-accepteula",
            "-ma",
            "-c",
            str(args.cpu_threshold_percent),
            "-s",
            str(args.cpu_duration_seconds),
            "-n",
            "1",
            str(emule_proc.pid),
            str(dump_path),
        ],
        stdout=(run_dir / "procdump-stdout.txt").open("w", encoding="utf-8"),
        stderr=(run_dir / "procdump-stderr.txt").open("w", encoding="utf-8"),
    )

    main_log = log_dir / "emulebb.log"
    verbose_log = log_dir / "emulebb-verbose.log"
    deadline = time.monotonic() + args.timeout_seconds
    last_verbose_log_size = 0
    hashing_started = False
    print(f"[diag] Monitoring for {args.timeout_seconds} s (deadline: {datetime.now().strftime('%H:%M:%S')})...")
    print()
    while time.monotonic() < deadline:
        if emule_proc.poll() is not None:
            print(f"[diag] eMule exited with code {emule_proc.returncode}")
            break
        hashing_started = monitor_log(main_log, verbose_log, last_verbose_log_size, hashing_started)
        if verbose_log.is_file():
            last_verbose_log_size = verbose_log.stat().st_size
        time.sleep(2)

    print()
    print("[diag] Collecting results...")
    if procdump_proc.poll() is None:
        print("[diag] Stopping procdump...")
        procdump_proc.terminate()
        try:
            procdump_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            procdump_proc.kill()
    dump_captured = dump_path.is_file()
    print(f"[diag] Dump captured: {dump_captured}")

    try:
        publish_latest_directory_pointer(run_dir, latest_report_dir)
    except Exception as exc:
        print(f"WARNING: Failed to refresh latest report pointer '{latest_report_dir}': {exc}", file=sys.stderr)

    summary_path = run_dir / "diag-hash-launch-summary.json"
    summary = {
        "generated_utc": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "app_exe": str(emule_exe),
        "app_root": str(app_root),
        "workspace_root": str(workspace_root),
        "profile_root": str(profile_root),
        "seed_config_dir": str(seed_config_dir),
        "report_dir": str(run_dir),
        "latest_report_dir": str(latest_report_dir),
        "emule_pid": emule_proc.pid,
        "emule_exited": emule_proc.poll() is not None,
        "emule_exit_code": emule_proc.returncode if emule_proc.poll() is not None else None,
        "hashing_started": hashing_started,
        "dump_captured": dump_captured,
        "dump_path": str(dump_path) if dump_captured else None,
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[diag] Summary written to: {summary_path}")
    if emule_proc.poll() is None:
        print(f"[diag] eMule is still running (PID {emule_proc.pid}).")
        print(f"[diag] To take a manual dump: procdump -accepteula -ma {emule_proc.pid} {run_dir / 'manual.dmp'}")
    return 0


def monitor_log(main_log: Path, verbose_log: Path, last_verbose_log_size: int, hashing_started: bool) -> bool:
    """Prints new hash-related log lines from eMule logs."""

    if main_log.is_file():
        try:
            for line in main_log.read_text(encoding="utf-8", errors="replace").splitlines():
                if "Hashing file:" in line:
                    if not hashing_started:
                        hashing_started = True
                        print("[diag] HASHING STARTED")
                    print(f"  LOG: {line}")
                if re_search_hash_new_files(line):
                    print(f"  LOG: {line}")
        except OSError:
            pass

    if verbose_log.is_file():
        try:
            content = verbose_log.read_text(encoding="utf-8", errors="replace")
            if len(content) > last_verbose_log_size:
                for line in content[last_verbose_log_size:].splitlines():
                    if any(
                        marker in line
                        for marker in ("CreateFromFile checkpoint", "Successfully saved AICH", "raw-hash-complete", "Hashing file")
                    ):
                        print(f"  VERBOSE: {line}")
        except OSError:
            pass
    return hashing_started


def re_search_hash_new_files(line: str) -> bool:
    """Returns whether one log line mentions the legacy new-file hash summary."""

    lowered = line.lower()
    return "hash" in lowered and "new files" in lowered


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
