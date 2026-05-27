"""Windows process helpers for live harness cleanup and adverse tests."""

from __future__ import annotations

import os
import ipaddress
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class WindowsProcessInfo:
    """One current Windows process row returned by WMI."""

    pid: int
    parent_pid: int
    name: str
    command_line: str
    creation_date: str = ""


def process_service():
    """Returns a WMI process service without shelling out to PowerShell."""

    if os.name != "nt":
        raise RuntimeError("Windows process helpers are only available on Windows.")
    import win32com.client  # type: ignore[import-not-found]

    return win32com.client.GetObject("winmgmts:")


def collect_processes() -> list[WindowsProcessInfo]:
    """Returns current Windows process rows through WMI."""

    service = process_service()
    return [
        WindowsProcessInfo(
            pid=int(item.ProcessId),
            parent_pid=int(item.ParentProcessId or 0),
            name=str(item.Name or ""),
            command_line=str(item.CommandLine or ""),
            creation_date=str(getattr(item, "CreationDate", "") or ""),
        )
        for item in service.InstancesOf("Win32_Process")
        if item.ProcessId
    ]


def collect_adapter_ipv4_addresses(interface_name: str = "") -> list[str]:
    """Returns IPv4 addresses from enabled Windows adapters, optionally matching one interface name."""

    service = process_service()
    wanted_name = interface_name.strip().lower()
    wanted_indexes: set[int] = set()
    if wanted_name:
        for adapter in service.ExecQuery("SELECT InterfaceIndex, NetConnectionID, Name, Description FROM Win32_NetworkAdapter"):
            names = {
                str(getattr(adapter, "NetConnectionID", "") or "").strip().lower(),
                str(getattr(adapter, "Name", "") or "").strip().lower(),
                str(getattr(adapter, "Description", "") or "").strip().lower(),
            }
            if wanted_name in names:
                try:
                    wanted_indexes.add(int(adapter.InterfaceIndex))
                except (TypeError, ValueError):
                    continue
        if not wanted_indexes:
            return []

    addresses: set[str] = set()
    for adapter in service.ExecQuery("SELECT InterfaceIndex, IPAddress, IPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True"):
        try:
            interface_index = int(adapter.InterfaceIndex)
        except (TypeError, ValueError):
            continue
        if wanted_indexes and interface_index not in wanted_indexes:
            continue
        for value in adapter.IPAddress or []:
            try:
                addresses.add(str(ipaddress.IPv4Address(str(value))))
            except ipaddress.AddressValueError:
                continue
    return sorted(addresses)


def process_command_line(process_id: int) -> str:
    """Returns the current command line for one process id."""

    for process in collect_processes():
        if process.pid == process_id:
            return process.command_line
    return ""


def process_creation_date(process_id: int) -> str:
    """Returns the current WMI creation date for one process id."""

    for process in collect_processes():
        if process.pid == process_id:
            return process.creation_date
    return ""


def children_by_parent(processes: list[WindowsProcessInfo]) -> dict[int, list[WindowsProcessInfo]]:
    """Indexes process rows by parent pid."""

    children: dict[int, list[WindowsProcessInfo]] = {}
    for process in processes:
        children.setdefault(process.parent_pid, []).append(process)
    return children


def collect_process_tree(process_id: int, processes: list[WindowsProcessInfo] | None = None) -> list[WindowsProcessInfo]:
    """Returns one current process tree rooted at process_id."""

    processes = collect_processes() if processes is None else processes
    by_pid = {process.pid: process for process in processes}
    if process_id not in by_pid:
        return []
    children = children_by_parent(processes)
    selected: set[int] = set()
    stack = [process_id]
    while stack:
        pid = stack.pop()
        if pid in selected:
            continue
        selected.add(pid)
        stack.extend(child.pid for child in children.get(pid, []))
    return [process for process in processes if process.pid in selected]


def remaining_target_pids(targets: list[WindowsProcessInfo]) -> set[int]:
    """Returns pids whose original process instances are still live."""

    target_by_pid = {process.pid: process for process in targets}
    remaining: set[int] = set()
    for process in collect_processes():
        target = target_by_pid.get(process.pid)
        if target is None:
            continue
        if target.creation_date and process.creation_date != target.creation_date:
            continue
        remaining.add(process.pid)
    return remaining


def command_line_contains_markers(command_line: str, markers: list[str] | tuple[str, ...]) -> bool:
    """Returns whether a process command line contains every expected marker."""

    normalized = command_line.lower()
    return all(marker.strip().lower() in normalized for marker in markers if marker.strip())


def terminate_process(process_id: int, exit_code: int = 1, expected_creation_date: str = "") -> dict[str, object]:
    """Terminates one Windows process through WMI."""

    service = process_service()
    matches = list(service.ExecQuery(f"SELECT * FROM Win32_Process WHERE ProcessId = {int(process_id)}"))
    if not matches:
        return {"pid": process_id, "terminated": False, "reason": "process no longer exists"}
    current_creation_date = str(getattr(matches[0], "CreationDate", "") or "")
    if expected_creation_date and current_creation_date != expected_creation_date:
        return {
            "pid": process_id,
            "terminated": False,
            "refused": True,
            "reason": "process creation date changed",
            "expected_creation_date": expected_creation_date,
            "current_creation_date": current_creation_date,
        }
    result = int(matches[0].Terminate(exit_code))
    return {"pid": process_id, "terminated": result == 0, "return_code": result}


def terminate_process_tree(
    process_id: int,
    timeout_seconds: float = 15.0,
    expected_command_line_markers: list[str] | tuple[str, ...] | None = None,
    expected_root_creation_date: str = "",
) -> dict[str, object]:
    """Terminates one current process tree, children first, after optional root verification."""

    targets = collect_process_tree(process_id)
    if not targets:
        return {
            "command": "wmi-terminate",
            "pid": process_id,
            "return_code": 1,
            "targets": [],
            "reason": "root process no longer exists",
        }
    root = next((process for process in targets if process.pid == process_id), None)
    markers = tuple(expected_command_line_markers or ())
    root_creation_mismatch = bool(
        root is not None and expected_root_creation_date and root.creation_date != expected_root_creation_date
    )
    if root is None or root_creation_mismatch or (markers and not command_line_contains_markers(root.command_line, markers)):
        return {
            "command": "wmi-terminate",
            "pid": process_id,
            "return_code": 1,
            "refused": True,
            "reason": "root creation date changed" if root_creation_mismatch else "root command line did not match expected markers",
            "expected_command_line_markers": list(markers),
            "expected_root_creation_date": expected_root_creation_date,
            "root_command_line": root.command_line if root is not None else "",
            "root_creation_date": root.creation_date if root is not None else "",
            "targets": [process.__dict__ for process in targets],
        }
    target_pids = {process.pid for process in targets}
    children = children_by_parent(targets)
    depths: dict[int, int] = {}

    def depth(pid: int) -> int:
        if pid in depths:
            return depths[pid]
        child_depths = [depth(child.pid) for child in children.get(pid, []) if child.pid in target_pids]
        depths[pid] = 1 + max(child_depths, default=0)
        return depths[pid]

    ordered_targets = sorted(targets, key=lambda item: depth(item.pid))
    terminated = [terminate_process(process.pid, expected_creation_date=process.creation_date) for process in ordered_targets]
    deadline = time.monotonic() + timeout_seconds
    remaining = target_pids & remaining_target_pids(targets)
    while remaining and time.monotonic() < deadline:
        remaining = target_pids & remaining_target_pids(targets)
        if remaining:
            time.sleep(0.2)
    return {
        "command": "wmi-terminate",
        "pid": process_id,
        "return_code": 0 if not remaining else 1,
        "targets": [process.__dict__ for process in ordered_targets],
        "terminated": terminated,
        "remaining_pids": sorted(remaining),
    }
