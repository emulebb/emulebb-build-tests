from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest


def load_clean_module():
    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "amutorrent-clean-startup.py"
    spec = importlib.util.spec_from_file_location("amutorrent_clean_startup_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_clean_environment_keeps_wizard_enabled_and_removes_emulebb_env(tmp_path: Path) -> None:
    clean = load_clean_module()
    node_path = tmp_path / "node22" / "node.exe"

    env = clean.build_clean_amutorrent_environment(
        base_env={
            "PATH": "original-path",
            "SKIP_SETUP_WIZARD": "true",
            "EMULEBB_HOST": "127.0.0.1",
            "UNCHANGED": "1",
        },
        amutorrent_port=4002,
        node_path=node_path,
        data_dir=tmp_path / "amutorrent-data",
        extra_ca_cert=str(tmp_path / "webserver-cert.pem"),
    )

    assert env["PORT"] == "4002"
    assert env["AMUTORRENT_DATA_DIR"] == str(tmp_path / "amutorrent-data")
    assert env["WEB_AUTH_ENABLED"] == "false"
    assert "SKIP_SETUP_WIZARD" not in env
    assert "EMULEBB_HOST" not in env
    assert env["NODE_EXTRA_CA_CERTS"] == str(tmp_path / "webserver-cert.pem")
    assert env["UNCHANGED"] == "1"
    assert env["PATH"].startswith(str(node_path.parent) + os.pathsep)


def test_parser_defaults_to_ignored_live_wire_file() -> None:
    clean = load_clean_module()

    args = clean.build_parser().parse_args([])

    assert args.configuration == "Debug"
    assert args.p2p_bind_interface_name == "hide.me"
    assert args.rest_webserver_scheme == "https"
    assert args.live_wire_inputs_file.endswith("live-wire-inputs.local.json")


def test_rest_scheme_defaults_to_https_and_accepts_http() -> None:
    clean = load_clean_module()

    assert clean.normalize_rest_scheme("") == "https"
    assert clean.normalize_rest_scheme("HTTPS") == "https"
    assert clean.normalize_rest_scheme("http") == "http"


def test_live_wire_inputs_path_accepts_workspace_relative_explicit_path(tmp_path: Path, monkeypatch) -> None:
    clean = load_clean_module()
    repo_root = tmp_path / "repos" / "emulebb-build-tests"
    repo_root.mkdir(parents=True)
    workspace_relative = Path("repos") / "emulebb-build-tests" / "live-wire-inputs.local.json"
    inputs_file = tmp_path / workspace_relative
    inputs_file.write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert clean.resolve_clean_live_wire_inputs_path(repo_root, str(workspace_relative)) == inputs_file.resolve()


@pytest.mark.parametrize(
    "row",
    [
        {"fileHash": "abcdef0123456789abcdef0123456789", "fileName": "linux.iso", "fileSize": 1024, "sourceCount": 2},
        {"hash": "abcdef0123456789abcdef0123456789", "name": "linux.iso", "sizeBytes": 1024, "sources": 2},
    ],
)
def test_safe_amutorrent_search_result_accepts_downloadable_rows(row: dict[str, object]) -> None:
    clean = load_clean_module()

    assert clean.is_safe_amutorrent_search_result(row)


def test_safe_amutorrent_search_result_rejects_programs_and_unsourced_rows() -> None:
    clean = load_clean_module()

    assert not clean.is_safe_amutorrent_search_result(
        {"fileHash": "abcdef0123456789abcdef0123456789", "fileName": "setup.exe", "fileSize": 1024, "sourceCount": 2}
    )
    assert not clean.is_safe_amutorrent_search_result(
        {"fileHash": "abcdef0123456789abcdef0123456789", "fileName": "linux.iso", "fileSize": 1024, "sourceCount": 0}
    )


def test_clean_startup_script_does_not_hardcode_runtime_live_terms() -> None:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "amutorrent-clean-startup.py"
    script_text = script_path.read_text(encoding="utf-8")

    assert "live_wire_inputs.load_live_wire_inputs" in script_text
    assert "SKIP_SETUP_WIZARD" in script_text
    assert "require_kad_connected=False" in script_text
    assert '"SKIP_SETUP_WIZARD": "true"' not in script_text
    assert '"linux"' not in script_text
    assert '"ubuntu"' not in script_text
