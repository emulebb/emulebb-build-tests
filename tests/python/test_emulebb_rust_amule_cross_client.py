from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

from emule_test_harness import multi_client


def load_suite_module():
    """Loads the hyphenated Rust/aMule cross-client script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "emulebb-rust-amule-cross-client.py"
    spec = importlib.util.spec_from_file_location("emulebb_rust_amule_cross_client_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_cross_client_script_uses_lan_bind_for_amule_ec_and_port_probes() -> None:
    module = load_suite_module()
    script_text = Path(module.__file__).read_text(encoding="utf-8")

    assert "choose_amule_ports(dtt.choose_distinct_ports(args.lan_bind_addr), args.lan_bind_addr)" in script_text
    assert "ec_address=args.lan_bind_addr" in script_text
    assert "ec_address=\"127.0.0.1\"" not in script_text


def test_cross_client_script_uses_shared_goed2k_launcher_boundary() -> None:
    module = load_suite_module()
    script_text = Path(module.__file__).read_text(encoding="utf-8")

    assert "goed2k.launch_ed2k_server(" in script_text
    assert "goed2k.resolve_ed2k_server_exe(" not in script_text
    assert "goed2k.build_or_skip_ed2k_server_binary(" not in script_text
    assert "goed2k.build_server_config(" not in script_text
    assert "goed2k.start_ed2k_server(" not in script_text


def test_cross_client_uses_configured_lan_and_p2p_addresses(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    rust_repo = tmp_path / "emulebb-rust"
    rust_repo.mkdir()
    (rust_repo / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    server_process = object()
    calls: dict[str, object] = {"stopped": []}
    amule_daemon = tmp_path / "amuled.exe"
    amule_control = tmp_path / "amulecmd.exe"
    amule_daemon.write_text("", encoding="utf-8")
    amule_control.write_text("", encoding="utf-8")

    paths = SimpleNamespace(
        workspace_root=workspace,
        source_artifacts_dir=tmp_path / "artifacts",
        seed_config_dir=tmp_path / "seed",
        app_exe=tmp_path / "emulebb.exe",
    )
    paths.source_artifacts_dir.mkdir()

    monkeypatch.setattr(module.harness_cli_common, "prepare_run_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(module.harness_cli_common, "write_json_file", lambda path, payload: calls.setdefault("report", payload))
    monkeypatch.setattr(module.harness_cli_common, "publish_run_artifacts", lambda _paths: None)
    monkeypatch.setattr(module.harness_cli_common, "publish_latest_report", lambda _paths: None)
    monkeypatch.setattr(module.harness_cli_common, "cleanup_source_artifacts", lambda _paths: None)
    monkeypatch.setattr(module, "resolve_manifest_repo", lambda _workspace, key: rust_repo if key == "emulebb_rust" else tmp_path / key)
    monkeypatch.setattr(
        module.amule_seed,
        "resolve_required_amule",
        lambda _paths, _args: multi_client.ClientAvailability(
            multi_client.CLIENT_IDENTITIES["amule"],
            True,
            amule_daemon,
            "available",
            control_executable=amule_control,
            deterministic_transfer_adapter=True,
        ),
    )
    monkeypatch.setattr(
        module.dtt,
        "choose_distinct_ports",
        lambda lan_bind_addr: {
            "ed2k_tcp": 4661,
            "ed2k_udp": 4665,
            "ed2k_admin": 8080,
            "client1_rest": 4711,
            "client1_tcp": 4662,
            "client1_udp": 4672,
            "client2_tcp": 5662,
            "client2_udp": 5672,
        },
    )
    monkeypatch.setattr(
        module.amule_seed,
        "choose_amule_ports",
        lambda base_ports, lan_bind_addr=None: {
            **base_ports,
            "amule_tcp": 4762,
            "amule_udp": 4772,
            "amule_ec": 4712,
        },
    )
    monkeypatch.setattr(module.rust_emulebb, "choose_extra_port", lambda _lan_bind_addr, used_ports, *, udp=False: max(used_ports) + 1)

    def fake_launch_ed2k_server(**kwargs):
        calls["ed2k_launch"] = kwargs
        return SimpleNamespace(
            process=server_process,
            admin_base_url="http://192.0.2.10:8080",
            build={"skipped": True},
            health={"ok": True},
            config={"listen_address": f"{kwargs['ed2k_address']}:{kwargs['ed2k_port']}"},
        )

    monkeypatch.setattr(module.goed2k, "launch_ed2k_server", fake_launch_ed2k_server)
    monkeypatch.setattr(module.goed2k, "stop_process", lambda process: calls["stopped"].append(process))
    monkeypatch.setattr(module.rust_client, "stop_process_tree", lambda process: calls.setdefault("rust_stop", process))

    def fail_after_goed2k_started(*_args, **_kwargs):
        raise RuntimeError("stop after shared goed2k launch")

    monkeypatch.setattr(module.rust_client, "write_rust_config", fail_after_goed2k_started)

    exit_code = module.main(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--p2p-bind-interface-address",
            "198.51.100.20",
        ]
    )

    assert exit_code == 1
    assert calls["ed2k_launch"]["admin_address"] == "192.0.2.10"
    assert calls["ed2k_launch"]["ed2k_address"] == "198.51.100.20"
    assert calls["stopped"] == [None, server_process]
    assert calls["report"]["current_phase"] == "start_ed2k_server"
    assert calls["report"]["network"]["lan_bind_addr"] == "192.0.2.10"
    assert calls["report"]["network"]["p2p_bind_interface_address"] == "198.51.100.20"
    assert calls["report"]["network"]["server_endpoint"] == "198.51.100.20:4661"
