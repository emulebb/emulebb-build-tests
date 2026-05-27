from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_module():
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "stop-running-tests.py"
    spec = importlib.util.spec_from_file_location("stop_running_tests_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def proc(pid: int, parent: int, name: str, command_line: str):
    module = load_module()
    return module.ProcessInfo(pid=pid, parent_pid=parent, name=name, command_line=command_line)


def test_selects_workspace_test_runner_tree_and_orphaned_helpers() -> None:
    module = load_module()
    workspace_root = Path(r"C:\prj\p2p\eMule\eMulebb-workspace")
    processes = [
        module.ProcessInfo(
            10,
            1,
            "python.exe",
            rf"C:\Python313\python.exe -m emule_workspace test live-e2e --profile release-expanded-quick --workspace {workspace_root}",
        ),
        module.ProcessInfo(
            11,
            10,
            "python.exe",
            rf"C:\Python313\python.exe {workspace_root}\repos\emulebb-build-tests\scripts\run-live-e2e-suite.py",
        ),
        module.ProcessInfo(
            12,
            11,
            "emulebb.exe",
            rf"{workspace_root}\workspaces\workspace\app\emulebb-main\srchybrid\x64\Release\emulebb.exe -ignoreinstances -c {workspace_root}\workspaces\workspace\state\test-reports\run\profile-base",
        ),
        module.ProcessInfo(20, 1, "python.exe", r"C:\Python313\python.exe C:\tools\unrelated.py"),
        module.ProcessInfo(
            30,
            1,
            "emulebb.exe",
            rf"{workspace_root}\workspaces\workspace\app\emulebb-main\srchybrid\x64\Release\emulebb.exe -ignoreinstances -c {workspace_root}\workspaces\workspace\state\test-artifacts\orphan\profile-base",
        ),
        module.ProcessInfo(
            40,
            1,
            "xperf.exe",
            rf"xperf.exe -d {workspace_root}\workspaces\workspace\state\test-reports\run\analysis\cpu-profile.etl",
        ),
    ]

    selected, reasons = module.select_test_processes(processes, workspace_root, current_pid=999)

    assert selected == {10, 11, 12, 30, 40}
    assert reasons[10] == "workspace test runner command line"
    assert reasons[12] == "scoped descendant of workspace test runner 10"
    assert reasons[30] == "orphaned workspace test helper command line"
    assert module.termination_roots(selected, processes) == [10, 30, 40]


def test_selects_godzilla_relative_runner_and_local_swarm_helpers() -> None:
    module = load_module()
    workspace_root = Path(r"C:\prj\p2p\eMule\eMulebb-workspace")
    run_root = workspace_root / "workspaces" / "workspace" / "state" / "test-artifacts" / "godzilla-local-swarm" / "run"
    processes = [
        module.ProcessInfo(
            200,
            1,
            "python.exe",
            r"C:\Python313\python.exe scripts\godzilla-local-swarm.py --visible-ui",
        ),
        module.ProcessInfo(
            201,
            200,
            "goed2k-server.exe",
            rf"{workspace_root}\workspaces\workspace\state\tools\goed2k-server\goed2k-server.exe -config {run_root}\ed2k-server\config.json",
        ),
        module.ProcessInfo(
            202,
            200,
            "amuled.exe",
            rf"{workspace_root}\workspaces\workspace\state\tools\amule\bin\amuled.exe --config-dir={run_root}\clients\cl-amule-004\config",
        ),
        module.ProcessInfo(
            203,
            200,
            "node.exe",
            rf"node {workspace_root}\repos\amutorrent\server\server.js",
        ),
    ]

    selected, reasons = module.select_test_processes(processes, workspace_root, current_pid=999)

    assert selected == {200, 201, 202, 203}
    assert reasons[200] == "workspace test runner command line"
    assert module.termination_roots(selected, processes) == [200]


def test_does_not_select_helper_itself_or_unscoped_python() -> None:
    module = load_module()
    workspace_root = Path(r"C:\prj\p2p\eMule\eMulebb-workspace")
    processes = [
        module.ProcessInfo(
            100,
            1,
            "python.exe",
            rf"C:\Python313\python.exe {workspace_root}\repos\emulebb-build-tests\scripts\stop-running-tests.py",
        ),
        module.ProcessInfo(
            101,
            1,
            "python.exe",
            r"C:\Python313\python.exe -m pytest C:\other-workspace\tests",
        ),
        module.ProcessInfo(
            102,
            1,
            "emulebb.exe",
            rf"{workspace_root}\workspaces\workspace\app\emulebb-main\srchybrid\x64\Release\emulebb.exe -ignoreinstances -c F:\real-profile",
        ),
    ]

    selected, reasons = module.select_test_processes(processes, workspace_root, current_pid=100)

    assert selected == set()
    assert reasons == {}


def test_stop_targets_are_revalidated_against_current_processes(monkeypatch) -> None:
    module = load_module()
    workspace_root = Path(r"C:\prj\p2p\eMule\eMulebb-workspace")
    processes = [
        module.ProcessInfo(
            10,
            1,
            "python.exe",
            rf"C:\Python313\python.exe -m emule_workspace test live-e2e --workspace {workspace_root}",
        ),
        module.ProcessInfo(
            11,
            10,
            "emulebb.exe",
            rf"emulebb.exe -c {workspace_root}\workspaces\workspace\state\test-reports\run\profile-base",
        ),
        module.ProcessInfo(20, 10, "notepad.exe", r"C:\Windows\notepad.exe"),
    ]
    monkeypatch.setattr(module, "collect_windows_processes", lambda: processes)

    targets, reason = module.current_stop_targets(10, workspace_root, current_pid=999)

    assert reason == "workspace test runner command line"
    assert [process.pid for process in targets] == [10, 11]


def test_stop_process_tree_refuses_reused_unscoped_root(monkeypatch) -> None:
    module = load_module()
    workspace_root = Path(r"C:\prj\p2p\eMule\eMulebb-workspace")
    processes = [module.ProcessInfo(10, 1, "python.exe", r"C:\Python313\python.exe C:\tools\unrelated.py")]
    terminated: list[int] = []
    monkeypatch.setattr(module, "collect_windows_processes", lambda: processes)
    monkeypatch.setattr(
        module,
        "terminate_windows_process",
        lambda pid, **_kwargs: terminated.append(pid) or {"pid": pid},
    )

    result = module.stop_process_tree(10, workspace_root=workspace_root, current_pid=999, timeout_seconds=0)

    assert result["refused"] is True
    assert terminated == []


def test_stop_process_tree_verifies_process_instance_before_termination(monkeypatch) -> None:
    module = load_module()
    workspace_root = Path(r"C:\prj\p2p\eMule\eMulebb-workspace")
    processes = [
        module.ProcessInfo(
            10,
            1,
            "python.exe",
            rf"C:\Python313\python.exe -m emule_workspace test live-e2e --workspace {workspace_root}",
            creation_date="20260527020101.000000+000",
        ),
        module.ProcessInfo(
            11,
            10,
            "emulebb.exe",
            rf"emulebb.exe -c {workspace_root}\workspaces\workspace\state\test-reports\run\profile-base",
            creation_date="20260527020102.000000+000",
        ),
    ]
    terminated: list[tuple[int, str]] = []

    def terminate(pid: int, exit_code: int = 1, expected_creation_date: str = "") -> dict[str, object]:
        terminated.append((pid, expected_creation_date))
        return {"pid": pid, "terminated": True, "return_code": 0}

    monkeypatch.setattr(module, "collect_windows_processes", lambda: processes if not terminated else [])
    monkeypatch.setattr(module, "terminate_windows_process", terminate)

    result = module.stop_process_tree(10, workspace_root=workspace_root, current_pid=999, timeout_seconds=0)

    assert result["return_code"] == 0
    assert terminated == [
        (11, "20260527020102.000000+000"),
        (10, "20260527020101.000000+000"),
    ]
    assert result["targets"][0]["creation_date"] == "20260527020102.000000+000"
