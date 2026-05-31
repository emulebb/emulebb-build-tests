from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


def load_session_module():
    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "amutorrent-interactive-session.py"
    spec = importlib.util.spec_from_file_location("amutorrent_interactive_session_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_amutorrent_environment_points_to_emulebb_rest(tmp_path: Path) -> None:
    session = load_session_module()
    node_path = tmp_path / "node22" / "node.exe"
    base_env = {"PATH": "original-path", "UNCHANGED": "1"}

    env = session.build_amutorrent_environment(
        base_env=base_env,
        amutorrent_port=4001,
        emule_port=47110,
        api_key="test-key",
        instance_id="emulebb-127.0.0.1-47110",
        lan_bind_addr="192.0.2.10",
        node_path=node_path,
        data_dir=tmp_path / "amutorrent-data",
        use_ssl=True,
        extra_ca_cert=str(tmp_path / "webserver-cert.pem"),
    )

    assert env["PORT"] == "4001"
    assert env["lan_bind_address"] == "192.0.2.10"
    assert env["AMUTORRENT_DATA_DIR"] == str(tmp_path / "amutorrent-data")
    assert env["SKIP_SETUP_WIZARD"] == "true"
    assert env["EMULEBB_ENABLED"] == "true"
    assert env["EMULEBB_PORT"] == "47110"
    assert env["EMULEBB_API_KEY"] == "test-key"
    assert env["EMULEBB_USE_SSL"] == "true"
    assert env["EMULEBB_ID"] == "emulebb-127.0.0.1-47110"
    assert env["NODE_EXTRA_CA_CERTS"] == str(tmp_path / "webserver-cert.pem")
    assert env["UNCHANGED"] == "1"
    assert env["PATH"].startswith(str(node_path.parent) + os.pathsep)


def test_write_stop_script_closes_emule_and_stops_amutorrent(tmp_path: Path) -> None:
    session = load_session_module()
    stop_script = tmp_path / "stop-session.cmd"

    session.write_stop_script(stop_script, emule_pid=1234, amutorrent_pid=5678)

    text = stop_script.read_text(encoding="utf-8")
    assert 'call :stop_process "eMuleBB" "1234"' in text
    assert 'call :stop_process "aMuTorrent" "5678"' in text
    assert "taskkill /PID %pid%" in text
    assert "taskkill /PID %pid% /F" in text


def test_parser_defaults_to_local_control_session() -> None:
    session = load_session_module()

    args = session.build_parser().parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert args.configuration == "Debug"
    assert args.live_network is False
    assert args.lan_bind_addr == "192.0.2.10"
