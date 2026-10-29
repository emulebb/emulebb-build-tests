from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace


def load_script_module():
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "ed2k-server-readiness-smoke.py"
    spec = importlib.util.spec_from_file_location("ed2k_server_readiness_smoke", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeProcess:
    def __init__(self) -> None:
        self.returncode = None

    def poll(self):
        return self.returncode


def test_readiness_smoke_passes_and_stops_server(monkeypatch, tmp_path: Path) -> None:
    module = load_script_module()
    workspace_root = tmp_path / "workspace"
    server_exe = tmp_path / "output" / "tools" / "ed2k-server"
    artifacts_dir = tmp_path / "output" / "reports" / module.SUITE_NAME / "run"
    server_exe.parent.mkdir(parents=True)
    server_exe.write_bytes(b"linux")
    process = FakeProcess()

    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(module, "allocate_port", lambda **kwargs: 31000 if kwargs.get("udp_offset") else 32000)

    def launch(**kwargs):
        server_dir = kwargs["server_dir"]
        server_dir.mkdir(parents=True)
        (server_dir / "server.pid").write_text("1234\n", encoding="ascii")
        return SimpleNamespace(
            process=process,
            admin_base_url="http://127.0.0.1:32000",
            health={"ok": True},
        )

    monkeypatch.setattr(module.ed2k_server, "launch_ed2k_server", launch)
    monkeypatch.setattr(
        module.ed2k_server,
        "ed2k_server_control",
        lambda *_args: SimpleNamespace(stats=lambda: {"client_count": 0}),
    )
    monkeypatch.setattr(
        module.ed2k_server,
        "stop_process",
        lambda target: setattr(target, "returncode", 0),
    )

    result = module.run_readiness_smoke(
        workspace_root=workspace_root,
        server_exe=server_exe,
        artifacts_dir=artifacts_dir,
        health_timeout_seconds=30.0,
    )

    assert result["status"] == "passed"
    assert result["checks"]["pid"] == 1234
    assert result["checks"]["stats"] == {"client_count": 0}
    assert result["cleanup"] == {"return_code": 0, "stopped": True}


def test_readiness_smoke_records_launch_failure(monkeypatch, tmp_path: Path) -> None:
    module = load_script_module()
    server_exe = tmp_path / "output" / "tools" / "ed2k-server"
    server_exe.parent.mkdir(parents=True)
    server_exe.write_bytes(b"linux")
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(module, "allocate_port", lambda **kwargs: 31000 if kwargs.get("udp_offset") else 32000)
    monkeypatch.setattr(
        module.ed2k_server,
        "launch_ed2k_server",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("readiness failed")),
    )

    result = module.run_readiness_smoke(
        workspace_root=tmp_path / "workspace",
        server_exe=server_exe,
        artifacts_dir=tmp_path / "output" / "reports" / "run",
        health_timeout_seconds=30.0,
    )

    assert result["status"] == "failed"
    assert result["error"] == {"type": "RuntimeError", "message": "readiness failed"}


def test_cleanup_failure_overrides_passed_result(monkeypatch, tmp_path: Path) -> None:
    module = load_script_module()
    server_exe = tmp_path / "output" / "tools" / "ed2k-server"
    artifacts_dir = tmp_path / "output" / "reports" / "run"
    server_exe.parent.mkdir(parents=True)
    server_exe.write_bytes(b"linux")
    process = FakeProcess()
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(module, "allocate_port", lambda **kwargs: 31000 if kwargs.get("udp_offset") else 32000)

    def launch(**kwargs):
        kwargs["server_dir"].mkdir(parents=True)
        (kwargs["server_dir"] / "server.pid").write_text("1234\n", encoding="ascii")
        return SimpleNamespace(process=process, admin_base_url="http://127.0.0.1:32000", health={"ok": True})

    monkeypatch.setattr(module.ed2k_server, "launch_ed2k_server", launch)
    monkeypatch.setattr(module.ed2k_server, "ed2k_server_control", lambda *_args: SimpleNamespace(stats=lambda: {}))
    monkeypatch.setattr(
        module.ed2k_server,
        "stop_process",
        lambda _target: (_ for _ in ()).throw(RuntimeError("cleanup failed")),
    )

    result = module.run_readiness_smoke(
        workspace_root=tmp_path / "workspace",
        server_exe=server_exe,
        artifacts_dir=artifacts_dir,
        health_timeout_seconds=30.0,
    )

    assert result["status"] == "failed"
    assert result["cleanup"] == {"stopped": False, "error": "cleanup failed"}


def test_main_writes_result_under_output_root(monkeypatch, tmp_path: Path) -> None:
    module = load_script_module()
    workspace_root = tmp_path / "workspace"
    output_root = tmp_path / "output"
    server_exe = output_root / "tools" / "ed2k-server"
    server_exe.parent.mkdir(parents=True)
    server_exe.write_bytes(b"linux")
    monkeypatch.setattr(module, "get_required_emule_workspace_root", lambda: workspace_root)
    monkeypatch.setattr(module, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(
        module,
        "run_readiness_smoke",
        lambda **_kwargs: {"suite": module.SUITE_NAME, "status": "passed"},
    )

    exit_code = module.main(
        [
            "--ed2k-server-exe",
            str(server_exe),
            "--artifacts-dir",
            "reports/readiness",
        ]
    )

    result_path = output_root / "reports" / "readiness" / f"{module.SUITE_NAME}-result.json"
    assert exit_code == 0
    assert json.loads(result_path.read_text(encoding="utf-8"))["status"] == "passed"


def test_artifacts_dir_rejects_paths_outside_output_root(tmp_path: Path) -> None:
    module = load_script_module()

    try:
        module.resolve_artifacts_dir(str(tmp_path / "outside"), tmp_path / "output")
    except RuntimeError as exc:
        assert "must stay under EMULEBB_WORKSPACE_OUTPUT_ROOT" in str(exc)
    else:
        raise AssertionError("outside readiness artifacts path was accepted")
