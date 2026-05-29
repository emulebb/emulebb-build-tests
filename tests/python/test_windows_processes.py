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


def test_terminate_process_tree_refuses_changed_root_creation_date(monkeypatch) -> None:
    processes = [
        windows_processes.WindowsProcessInfo(
            pid=10,
            parent_pid=1,
            name="python.exe",
            command_line=r"C:\Python313\python.exe C:\tests\godzilla-local-swarm.py",
            creation_date="20260527040102.000000+000",
        )
    ]
    terminated: list[int] = []
    monkeypatch.setattr(windows_processes, "collect_process_tree", lambda _pid: processes)
    monkeypatch.setattr(
        windows_processes,
        "terminate_process",
        lambda pid, **_kwargs: terminated.append(pid) or {"pid": pid, "terminated": True},
    )

    result = windows_processes.terminate_process_tree(
        10,
        expected_command_line_markers=["godzilla-local-swarm.py"],
        expected_root_creation_date="20260527040101.000000+000",
    )

    assert result["refused"] is True
    assert result["reason"] == "root creation date changed"
    assert result["return_code"] == 1
    assert terminated == []


def test_terminate_process_tree_verifies_process_instance_before_termination(monkeypatch) -> None:
    processes = [
        windows_processes.WindowsProcessInfo(
            pid=10,
            parent_pid=1,
            name="python.exe",
            command_line=r"C:\Python313\python.exe C:\tests\godzilla-local-swarm.py",
            creation_date="20260527010101.000000+000",
        ),
        windows_processes.WindowsProcessInfo(
            pid=11,
            parent_pid=10,
            name="emulebb.exe",
            command_line=r"emulebb.exe -c C:\tests\profile",
            creation_date="20260527010102.000000+000",
        ),
    ]
    terminated: list[tuple[int, str]] = []

    def terminate(process_id: int, exit_code: int = 1, expected_creation_date: str = "") -> dict[str, object]:
        terminated.append((process_id, expected_creation_date))
        return {"pid": process_id, "terminated": True, "return_code": 0}

    monkeypatch.setattr(windows_processes, "collect_process_tree", lambda _pid: processes)
    monkeypatch.setattr(windows_processes, "collect_processes", lambda: [])
    monkeypatch.setattr(windows_processes, "terminate_process", terminate)

    result = windows_processes.terminate_process_tree(10, expected_command_line_markers=["godzilla-local-swarm.py"])

    assert result["return_code"] == 0
    assert terminated == [
        (11, "20260527010102.000000+000"),
        (10, "20260527010101.000000+000"),
    ]


def test_terminate_process_refuses_reused_pid(monkeypatch) -> None:
    class FakeProcess:
        CreationDate = "20260527010202.000000+000"

        def Terminate(self, _exit_code: int) -> int:
            raise AssertionError("must not terminate a reused pid")

    class FakeService:
        def ExecQuery(self, _query: str):
            return [FakeProcess()]

    monkeypatch.setattr(windows_processes, "process_service", lambda: FakeService())

    result = windows_processes.terminate_process(10, expected_creation_date="20260527010101.000000+000")

    assert result["refused"] is True
    assert result["terminated"] is False
    assert result["reason"] == "process creation date changed"


def test_terminate_process_accepts_wmi_terminate_result_property(monkeypatch) -> None:
    class FakeProcess:
        CreationDate = "20260527010101.000000+000"
        Terminate = 0

    class FakeService:
        def ExecQuery(self, _query: str):
            return [FakeProcess()]

    monkeypatch.setattr(windows_processes, "process_service", lambda: FakeService())

    result = windows_processes.terminate_process(10, expected_creation_date="20260527010101.000000+000")

    assert result == {"pid": 10, "terminated": True, "return_code": 0}


def test_terminate_process_treats_wmi_dispatch_type_error_as_success_when_process_exited(monkeypatch) -> None:
    class FakeProcess:
        CreationDate = "20260527010101.000000+000"

        @property
        def Terminate(self):
            raise TypeError("'int' object is not callable")

    class FakeService:
        def __init__(self) -> None:
            self.calls = 0

        def ExecQuery(self, _query: str):
            self.calls += 1
            return [FakeProcess()] if self.calls == 1 else []

    service = FakeService()
    monkeypatch.setattr(windows_processes, "process_service", lambda: service)

    result = windows_processes.terminate_process(10, expected_creation_date="20260527010101.000000+000")

    assert result == {"pid": 10, "terminated": True, "return_code": 0}


def test_remaining_target_pids_ignores_reused_pid(monkeypatch) -> None:
    target = windows_processes.WindowsProcessInfo(
        pid=10,
        parent_pid=1,
        name="python.exe",
        command_line=r"C:\Python313\python.exe C:\tests\godzilla-local-swarm.py",
        creation_date="20260527030101.000000+000",
    )
    reused = windows_processes.WindowsProcessInfo(
        pid=10,
        parent_pid=1,
        name="python.exe",
        command_line=r"C:\Python313\python.exe C:\tools\unrelated.py",
        creation_date="20260527030102.000000+000",
    )
    monkeypatch.setattr(windows_processes, "collect_processes", lambda: [reused])

    assert windows_processes.remaining_target_pids([target]) == set()
