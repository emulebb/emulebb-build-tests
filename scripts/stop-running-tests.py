from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


TEST_SCRIPT_NAME = "stop-running-tests.py"
TEST_PROCESS_NAMES = {"python.exe", "python", "py.exe", "py"}
TEST_HELPER_PROCESS_NAMES = {
    "amulecmd.exe",
    "amuled.exe",
    "emulebb.exe",
    "emule.exe",
    "goed2k-server.exe",
    "node.exe",
    "xperf.exe",
    "procdump.exe",
    "procdump64.exe",
    "cdb.exe",
}
TEST_RUNNER_MARKERS = (
    "-m emule_workspace test",
    "run-live-e2e-suite.py",
    "\\repos\\emulebb-build-tests\\scripts\\",
    "\\repos\\emulebb-build-tests\\tests\\",
    "pytest",
    "scripts\\godzilla-local-swarm.py",
    "godzilla-local-swarm.py",
)
TEST_HELPER_MARKERS = (
    "\\state\\test-reports\\",
    "\\state\\test-artifacts\\",
    "\\profile-base",
    "\\profile-work",
    "cpu-profile",
    "\\repos\\amutorrent\\server\\server.js",
)


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    parent_pid: int
    name: str
    command_line: str


def default_workspace_root() -> Path:
    return Path(__file__).resolve().parents[3]


def normalize(text: str | Path) -> str:
    return str(text).replace("/", "\\").lower()


def command_mentions_workspace(command_line: str, workspace_root: Path) -> bool:
    return normalize(workspace_root) in normalize(command_line)


def is_self_helper(process: ProcessInfo, current_pid: int) -> bool:
    if process.pid == current_pid:
        return True
    return TEST_SCRIPT_NAME in normalize(process.command_line)


def is_test_runner_process(process: ProcessInfo, workspace_root: Path, current_pid: int) -> bool:
    if is_self_helper(process, current_pid):
        return False
    command = normalize(process.command_line)
    has_workspace_scope = command_mentions_workspace(process.command_line, workspace_root)
    has_godzilla_script = "godzilla-local-swarm.py" in command
    if not has_workspace_scope and not has_godzilla_script:
        return False
    if process.name.lower() not in TEST_PROCESS_NAMES:
        return False
    return any(marker in command for marker in TEST_RUNNER_MARKERS)


def is_orphaned_test_helper_process(process: ProcessInfo, workspace_root: Path, current_pid: int) -> bool:
    if is_self_helper(process, current_pid):
        return False
    command = normalize(process.command_line)
    if not command_mentions_workspace(process.command_line, workspace_root):
        return False
    if process.name.lower() not in TEST_HELPER_PROCESS_NAMES:
        return False
    return any(marker in command for marker in TEST_HELPER_MARKERS)


def build_children_by_parent(processes: list[ProcessInfo]) -> dict[int, list[ProcessInfo]]:
    children: dict[int, list[ProcessInfo]] = {}
    for process in processes:
        children.setdefault(process.parent_pid, []).append(process)
    return children


def collect_descendant_pids(root_pid: int, children_by_parent: dict[int, list[ProcessInfo]]) -> set[int]:
    selected: set[int] = set()
    stack = [root_pid]
    while stack:
        pid = stack.pop()
        for child in children_by_parent.get(pid, []):
            if child.pid in selected:
                continue
            selected.add(child.pid)
            stack.append(child.pid)
    return selected


def select_test_processes(
    processes: list[ProcessInfo],
    workspace_root: Path,
    *,
    current_pid: int | None = None,
) -> tuple[set[int], dict[int, str]]:
    current_pid = os.getpid() if current_pid is None else current_pid
    children_by_parent = build_children_by_parent(processes)
    selected: set[int] = set()
    reasons: dict[int, str] = {}

    for process in processes:
        if is_test_runner_process(process, workspace_root, current_pid):
            selected.add(process.pid)
            reasons[process.pid] = "workspace test runner command line"
            for child_pid in collect_descendant_pids(process.pid, children_by_parent):
                selected.add(child_pid)
                reasons.setdefault(child_pid, f"descendant of workspace test runner {process.pid}")
        elif process.pid not in selected and is_orphaned_test_helper_process(process, workspace_root, current_pid):
            selected.add(process.pid)
            reasons[process.pid] = "orphaned workspace test helper command line"

    selected.discard(current_pid)
    reasons.pop(current_pid, None)
    return selected, reasons


def termination_roots(selected_pids: set[int], processes: list[ProcessInfo]) -> list[int]:
    by_pid = {process.pid: process for process in processes}
    roots = []
    for pid in sorted(selected_pids):
        parent_pid = by_pid.get(pid).parent_pid if pid in by_pid else 0
        if parent_pid not in selected_pids:
            roots.append(pid)
    return roots


def collect_windows_processes() -> list[ProcessInfo]:
    command = (
        "$ErrorActionPreference='Stop'; "
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,ParentProcessId,Name,CommandLine | "
        "ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout or "[]")
    if isinstance(payload, dict):
        payload = [payload]
    return [
        ProcessInfo(
            pid=int(item.get("ProcessId") or 0),
            parent_pid=int(item.get("ParentProcessId") or 0),
            name=str(item.get("Name") or ""),
            command_line=str(item.get("CommandLine") or ""),
        )
        for item in payload
        if item.get("ProcessId")
    ]


def stop_process_tree(root_pid: int) -> dict[str, object]:
    result = subprocess.run(
        ["taskkill", "/PID", str(root_pid), "/T", "/F"],
        capture_output=True,
        text=True,
    )
    return {
        "pid": root_pid,
        "return_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def build_report(
    processes: list[ProcessInfo],
    selected_pids: set[int],
    reasons: dict[int, str],
) -> dict[str, object]:
    selected = [
        {
            "pid": process.pid,
            "parent_pid": process.parent_pid,
            "name": process.name,
            "reason": reasons.get(process.pid, "selected"),
            "command_line": process.command_line,
        }
        for process in sorted(processes, key=lambda item: item.pid)
        if process.pid in selected_pids
    ]
    return {
        "selected_count": len(selected),
        "selected": selected,
        "termination_roots": termination_roots(selected_pids, processes),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Stops eMuleBB workspace test processes selected by process tree and command-line evidence."
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=default_workspace_root(),
        help="Workspace root used to scope process command-line matching.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Only print selected processes; do not stop them.")
    parser.add_argument("--json", action="store_true", help="Print a machine-readable JSON report.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    workspace_root = args.workspace_root.resolve()
    processes = collect_windows_processes()
    selected_pids, reasons = select_test_processes(processes, workspace_root)
    report = build_report(processes, selected_pids, reasons)

    if args.dry_run:
        report["stopped"] = []
    else:
        report["stopped"] = [stop_process_tree(pid) for pid in report["termination_roots"]]

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        action = "Would stop" if args.dry_run else "Stopping"
        print(f"{action} {report['selected_count']} workspace test process(es).")
        for item in report["selected"]:
            print(f"- pid={item['pid']} parent={item['parent_pid']} name={item['name']} reason={item['reason']}")
            print(f"  {item['command_line']}")
        if not args.dry_run:
            for item in report["stopped"]:
                print(f"taskkill root pid={item['pid']} rc={item['return_code']}")
    return 0 if report["selected_count"] == 0 or args.dry_run else max(
        [0, *(int(item["return_code"]) for item in report["stopped"])]
    )


if __name__ == "__main__":
    raise SystemExit(main())
