from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest


def load_suite_module():
    """Loads the hyphenated local Kad swarm script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "local-kad-swarm.py"
    spec = importlib.util.spec_from_file_location("local_kad_swarm_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_local_kad_defaults_are_local_and_bounded() -> None:
    module = load_suite_module()
    args = module.parse_args([])

    assert args.client_count == 3
    assert args.min_contacts_per_client == 1
    assert args.bootstrap_mode == "rest"
    assert args.nodes_dat_fixture_mode == "valid"
    assert args.p2p_bind_interface_name == ""
    assert args.bind_addr == "127.0.0.1"
    assert args.swarm_ready_timeout_seconds == 240.0


def test_validate_args_requires_real_swarm() -> None:
    module = load_suite_module()

    with pytest.raises(ValueError, match="at least 2"):
        module.validate_args(module.parse_args(["--client-count", "1"]))
    with pytest.raises(ValueError, match="may be zero only"):
        module.validate_args(module.parse_args(["--min-contacts-per-client", "0"]))
    with pytest.raises(ValueError, match="lower than client count"):
        module.validate_args(module.parse_args(["--client-count", "3", "--min-contacts-per-client", "3"]))
    with pytest.raises(ValueError, match="requires preseed or both"):
        module.validate_args(module.parse_args(["--nodes-dat-fixture-mode", "stale"]))
    module.validate_args(
        module.parse_args(["--bootstrap-mode", "preseed", "--nodes-dat-fixture-mode", "truncated", "--min-contacts-per-client", "0"])
    )


def test_build_client_specs_uses_stable_emulebb_names() -> None:
    module = load_suite_module()

    specs = module.build_client_specs(3, [(4701, 4801, 4901), (4702, 4802, 4902), (4703, 4803, 4903)])

    assert [spec.profile_id for spec in specs] == ["cl-emulebb-001", "cl-emulebb-002", "cl-emulebb-003"]
    assert [spec.nick for spec in specs] == ["cl-emulebb-001", "cl-emulebb-002", "cl-emulebb-003"]
    assert specs[1].rest_port == 4702
    assert specs[1].tcp_port == 4802
    assert specs[1].udp_port == 4902


def test_build_bootstrap_plan_connects_to_and_from_seed() -> None:
    module = load_suite_module()
    specs = module.build_client_specs(3, [(4701, 4801, 4901), (4702, 4802, 4902), (4703, 4803, 4903)])

    plan = [(source.profile_id, target.profile_id) for source, target in module.build_bootstrap_plan(specs)]

    assert ("cl-emulebb-002", "cl-emulebb-001") in plan
    assert ("cl-emulebb-003", "cl-emulebb-001") in plan
    assert ("cl-emulebb-001", "cl-emulebb-002") in plan
    assert ("cl-emulebb-001", "cl-emulebb-003") in plan


def test_configure_kad_client_profile_is_local_only(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    config_dir = tmp_path / "profile" / "config"
    config_dir.mkdir(parents=True)
    module.live_common.write_utf16_ini_text(
        config_dir / "preferences.ini",
        "[eMule]\nNetworkED2K=1\nNetworkKademlia=0\nFilterBadIPs=1\n[WebServer]\nEnabled=0\n[UPnP]\nEnableUPnP=1\n",
    )
    for name in module.KAD_STATE_FILES:
        (config_dir / name).write_bytes(b"stale")

    monkeypatch.setattr(module.live_common, "apply_webserver_profile", lambda *_args, **_kwargs: None)
    spec = module.KadClientSpec(
        index=1,
        profile_id="cl-emulebb-001",
        nick="cl-emulebb-001",
        tcp_port=4662,
        udp_port=4672,
        rest_port=8080,
    )

    result = module.configure_kad_client_profile(
        config_dir=config_dir,
        app_exe=tmp_path / "app" / "emulebb.exe",
        spec=spec,
        api_key="key",
        rest_bind_addr="127.0.0.1",
        p2p_bind_interface_name="",
        p2p_bind_addr="10.1.2.3",
    )

    text = module.live_common.read_ini_text(config_dir / "preferences.ini")
    assert "NetworkED2K=0" in text
    assert "NetworkKademlia=1" in text
    assert "FilterBadIPs=0" in text
    assert "IPFilterEnabled=0" in text
    assert "BindAddr=10.1.2.3" in text
    assert "EnableUPnP=0" in text
    assert sorted(result["removed_kad_state_files"]) == sorted(module.KAD_STATE_FILES)
    assert not any((config_dir / name).exists() for name in module.KAD_STATE_FILES)


def test_write_nodes_dat_preseeds_local_peer_contacts(tmp_path: Path) -> None:
    module = load_suite_module()
    specs = module.build_client_specs(3, [(4701, 4801, 4901), (4702, 4802, 4902), (4703, 4803, 4903)])
    path = tmp_path / "nodes.dat"

    summary = module.write_nodes_dat(path, owner=specs[0], peers=specs, peer_address="10.1.2.3")

    data = path.read_bytes()
    assert struct.unpack("<III", data[:12]) == (0, 2, 2)
    assert len(data) == 12 + 2 * 34
    assert summary["contact_count"] == 2
    assert summary["fixture_mode"] == "valid"
    first_contact = data[12:46]
    assert first_contact[:16] == module.deterministic_kad_node_id(2)
    stored_ip, udp_port, tcp_port, version, udp_key, udp_key_ip, verified = struct.unpack("<IHHBIIB", first_contact[16:])
    assert stored_ip == module.stored_nodes_dat_ip("10.1.2.3")
    assert udp_port == 4902
    assert tcp_port == 4802
    assert version == module.KADEMLIA_CONTACT_VERSION
    assert udp_key == 0
    assert udp_key_ip == 0
    assert verified == 1


def test_nodes_dat_fixture_modes_cover_stale_and_truncated(tmp_path: Path) -> None:
    module = load_suite_module()
    specs = module.build_client_specs(2, [(4701, 4801, 4901), (4702, 4802, 4902)])
    stale_path = tmp_path / "stale" / "nodes.dat"
    truncated_path = tmp_path / "truncated" / "nodes.dat"

    stale = module.write_nodes_dat_fixture(
        stale_path,
        owner=specs[0],
        peers=specs,
        peer_address="10.1.2.3",
        fixture_mode="stale",
    )
    truncated = module.write_nodes_dat_fixture(
        truncated_path,
        owner=specs[0],
        peers=specs,
        peer_address="10.1.2.3",
        fixture_mode="truncated",
    )

    assert stale["fixture_mode"] == "stale"
    first_contact = stale_path.read_bytes()[12:46]
    _, udp_port, tcp_port, *_ = struct.unpack("<IHHBIIB", first_contact[16:])
    assert udp_port == 5902
    assert tcp_port == 5802
    assert truncated["fixture_mode"] == "truncated"
    assert truncated["contact_count"] == 0
    assert len(truncated_path.read_bytes()) < 25
