from __future__ import annotations

from emule_test_harness import windows_processes


def test_command_line_contains_all_markers_case_insensitive() -> None:
    assert windows_processes.command_line_contains_markers(
        r"C:\Python313\python.exe C:\tests\godzilla-local-swarm.py --flag",
        ["PYTHON.EXE", "godzilla-local-swarm.py"],
    )
    assert not windows_processes.command_line_contains_markers(
        r"C:\Python313\python.exe C:\tests\other.py",
        ["python.exe", "godzilla-local-swarm.py"],
    )


def test_terminate_process_tree_refuses_unmatched_root_markers(monkeypatch) -> None:
    processes = [
        windows_processes.WindowsProcessInfo(
            pid=10,
            parent_pid=1,
            name="python.exe",
            command_line=r"C:\Python313\python.exe C:\tools\unrelated.py",
        ),
        windows_processes.WindowsProcessInfo(
            pid=11,
            parent_pid=10,
            name="emulebb.exe",
            command_line=r"emulebb.exe -c C:\tools\profile",
        ),
    ]
    terminated: list[int] = []
    monkeypatch.setattr(windows_processes, "collect_process_tree", lambda _pid: processes)
    monkeypatch.setattr(
        windows_processes,
        "terminate_process",
        lambda pid: terminated.append(pid) or {"pid": pid, "terminated": True},
    )

    result = windows_processes.terminate_process_tree(10, expected_command_line_markers=["godzilla-local-swarm.py"])

    assert result["refused"] is True
    assert result["return_code"] == 1
    assert terminated == []
