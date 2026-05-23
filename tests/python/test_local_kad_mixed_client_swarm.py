from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def load_suite_module():
    """Loads the hyphenated mixed local Kad swarm script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "local-kad-mixed-client-swarm.py"
    spec = importlib.util.spec_from_file_location("local_kad_mixed_client_swarm_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_mixed_kad_defaults_are_local_and_cross_client() -> None:
    module = load_suite_module()
    args = module.parse_args([])

    assert args.bind_addr == "127.0.0.1"
    assert args.p2p_bind_interface_name == ""
    assert args.min_contacts_per_emule_client == 1
    assert args.bootstrap_throttle_seconds == module.DEFAULT_BOOTSTRAP_THROTTLE_SECONDS


def test_mixed_kad_validation_rejects_non_swarm_settings() -> None:
    module = load_suite_module()

    with pytest.raises(ValueError, match="at least 1"):
        module.validate_args(module.parse_args(["--min-contacts-per-emule-client", "0"]))
    with pytest.raises(ValueError, match="zero or greater"):
        module.validate_args(module.parse_args(["--bootstrap-throttle-seconds", "-1"]))


def test_build_participant_specs_uses_stable_client_names() -> None:
    module = load_suite_module()

    specs = module.build_participant_specs(
        [(4701, 4801, 4901), (4702, 4802, 4902)],
        {"tcp": 4804, "udp": 4904, "ec": 4714},
    )

    assert specs["emulebb"].profile_id == "cl-emulebb-001"
    assert specs["harness"].profile_id == "cl-harness-002"
    assert specs["amule"].profile_id == "cl-amule-004"
    assert specs["amule"].rest_port == 0
    assert specs["amule"].udp_port == 4904


def test_explicit_rest_bootstrap_plan_covers_available_targeted_paths() -> None:
    module = load_suite_module()
    specs = module.build_participant_specs(
        [(4701, 4801, 4901), (4702, 4802, 4902)],
        {"tcp": 4804, "udp": 4904, "ec": 4714},
    )

    plan = [(path_id, source.profile_id, target.profile_id) for path_id, source, _target_key, target in module.explicit_rest_bootstrap_plan(specs)]

    assert plan == [
        ("emulebb_to_harness", "cl-emulebb-001", "cl-harness-002"),
        ("emulebb_to_amule", "cl-emulebb-001", "cl-amule-004"),
    ]


def test_preseed_autoconnect_paths_cover_non_rest_clients() -> None:
    module = load_suite_module()
    specs = module.build_participant_specs(
        [(4701, 4801, 4901), (4702, 4802, 4902)],
        {"tcp": 4804, "udp": 4904, "ec": 4714},
    )

    rows = module.preseed_autoconnect_paths(specs)

    assert {(row["source"], row["target"]) for row in rows} == {
        ("cl-harness-002", "cl-emulebb-001"),
        ("cl-harness-002", "cl-amule-004"),
        ("cl-amule-004", "cl-emulebb-001"),
        ("cl-amule-004", "cl-harness-002"),
    }
    assert all("nodes.dat preseed" in str(row["mechanism"]) for row in rows)


def test_read_client_log_text_accepts_utf16_logs(tmp_path: Path) -> None:
    module = load_suite_module()
    log_path = tmp_path / "emulebb.log"
    log_path.write_text("Connecting\nRead 1 contacts from file.\n", encoding="utf-16")

    assert "Read 1 contacts" in module.read_client_log_text(log_path)
