"""Guard the unit/native boundary without running Rust, sockets or daemons."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


pytest_plugins = ["pytester"]
TESTS = Path(__file__).resolve().parent
BIND_CASE = "test_emulebb_rust_server_connect_uses_configured_p2p_bind"
NATIVE_NODES = (
    BIND_CASE,
    "test_emulebb_rust_local_search_download_flow",
    "test_emulebb_rust_shared_dir_behavioral_target[long_path_shared_dir]",
    "test_emulebb_rust_shared_dir_behavioral_target[shared_dir_monitor_e2e]",
)


@pytest.mark.parametrize("native", [False, True])
def test_native_cases_require_explicit_selection(pytester, native: bool) -> None:
    """Collect the actual modules using their maintained default marker policy."""

    args = ["--collect-only", "-q", "-c", str(TESTS.parents[1] / "pyproject.toml"),
            str(TESTS / "test_emulebb_rust_local_client.py"),
            str(TESTS / "test_emulebb_rust_shared_dir_long_path.py")]
    if native:
        args.extend(["-m", "native"])
    result = pytester.runpytest(*args)
    assert result.ret == 0
    collected = [line for line in result.stdout.lines if "::test_" in line]
    assert len(collected) == (4 if native else 2)
    for node in NATIVE_NODES:
        assert any(line.endswith("::" + node) for line in collected) is native
    assert any(line.endswith("::test_local_client_uses_forward_rust_openapi_contract")
               for line in collected) is not native


def load_local_client():
    spec = importlib.util.spec_from_file_location(
        "native_boundary_local_client", TESTS / "test_emulebb_rust_local_client.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("missing", ["executable", "lan"])
def test_native_bind_preconditions_fail_before_any_launch(monkeypatch, tmp_path: Path, missing: str) -> None:
    module = load_local_client()
    executable = tmp_path / "staged-daemon"
    if missing != "executable":
        executable.write_bytes(b"prebuilt")
    monkeypatch.setattr(module, "get_workspace_output_root", lambda: tmp_path)
    monkeypatch.setattr(module.rust_client, "staged_executable", lambda root: executable)
    monkeypatch.delenv("X_LOCAL_IP", raising=False)

    def forbidden(*args, **kwargs):
        pytest.fail("preflight attempted sockets, Cargo or daemon launch")

    monkeypatch.setattr(module, "free_lan_port", forbidden)
    monkeypatch.setattr(module.rust_client, "start_rust_client", forbidden)
    monkeypatch.setattr(module.rust_client, "start_rust_client_executable", forbidden)
    with pytest.raises(pytest.fail.Exception, match="orchestrator-staged|X_LOCAL_IP"):
        getattr(module, BIND_CASE)(tmp_path)


def test_native_bind_uses_only_selected_staged_executable(monkeypatch, tmp_path: Path) -> None:
    module = load_local_client()
    executable = tmp_path / "staged-daemon"
    executable.write_bytes(b"prebuilt")
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")
    monkeypatch.setattr(module, "get_workspace_output_root", lambda: tmp_path)
    monkeypatch.setattr(module.rust_client, "staged_executable", lambda root: executable)
    monkeypatch.setattr(module, "free_lan_port", lambda host: 12345)
    monkeypatch.setattr(module, "write_profile", lambda *args, **kwargs: None)
    calls = []
    process = object()

    def launch(*args):
        calls.append(args)
        return process

    def forbidden(*args, **kwargs):
        pytest.fail("native bind attempted a Cargo fallback")

    class StopBeforeRest(Exception):
        pass

    def stop_before_rest(*args):
        raise StopBeforeRest

    monkeypatch.setattr(module.rust_client, "start_rust_client", forbidden)
    monkeypatch.setattr(module.rust_client, "start_rust_client_executable", launch)
    monkeypatch.setattr(module, "wait_for_rest", stop_before_rest)
    stopped = []
    monkeypatch.setattr(module, "terminate_process", stopped.append)
    with pytest.raises(StopBeforeRest):
        getattr(module, BIND_CASE)(tmp_path)
    assert calls == [(executable, tmp_path / "profile", tmp_path / "emulebb-rust.out")]
    assert stopped == [process]
    observed = json.loads((tmp_path / "native-input.json").read_text(encoding="utf-8"))
    assert observed["executableSha256"] == hashlib.sha256(b"prebuilt").hexdigest()
    assert observed["sourceProvenance"] == "unverified"
