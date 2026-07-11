from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_suite_module():
    """Loads the hyphenated three-client swarm script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "three-client-swarm-transfer.py"
    spec = importlib.util.spec_from_file_location("three_client_swarm_transfer_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_swarm_defaults_to_132_mib_fixture_and_longer_timeout() -> None:
    module = load_suite_module()
    args = module.parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert args.fixture_size_bytes == 132 * 1024 * 1024
    assert args.transfer_completion_timeout_seconds == 1800.0


def test_seed_files_are_distinct_per_client(tmp_path: Path) -> None:
    module = load_suite_module()

    seeds = {
        key: module.create_seed_file(tmp_path, key, module.CLIENT_IDENTITIES[key].profile_id, 4096)
        for key in module.CLIENT_KEYS
    }

    assert {seed.name for seed in seeds.values()} == {
        "seed-from-cl-emulebb-001.bin",
        "seed-from-cl-harness-002.bin",
        "seed-from-cl-amule-004.bin",
    }
    assert len({seed.sha256 for seed in seeds.values()}) == 3
    assert all(seed.path.is_file() and seed.path.stat().st_size == 4096 for seed in seeds.values())


def test_ed2k_link_with_source_adds_local_source_hint() -> None:
    module = load_suite_module()

    link = module.ed2k_link_with_source(
        "ed2k://|file|a.bin|1|0123456789abcdef0123456789abcdef|/",
        source_ip="10.1.2.3",
        source_port=4662,
    )

    assert link == "ed2k://|file|a.bin|1|0123456789abcdef0123456789abcdef|/|sources,10.1.2.3:4662|/"


def test_role_proofs_require_upload_and_download_for_each_client() -> None:
    module = load_suite_module()
    completions = [
        {"source_profile_id": "cl-emulebb-001", "destination_profile_id": "cl-harness-002"},
        {"source_profile_id": "cl-emulebb-001", "destination_profile_id": "cl-amule-004"},
        {"source_profile_id": "cl-harness-002", "destination_profile_id": "cl-emulebb-001"},
        {"source_profile_id": "cl-harness-002", "destination_profile_id": "cl-amule-004"},
        {"source_profile_id": "cl-amule-004", "destination_profile_id": "cl-emulebb-001"},
        {"source_profile_id": "cl-amule-004", "destination_profile_id": "cl-harness-002"},
    ]

    proofs = module.build_role_proofs(completions)

    assert all(row["has_upload_proof"] for row in proofs.values())
    assert all(row["has_download_proof"] for row in proofs.values())
    assert {row["completed_downloads"] for row in proofs.values()} == {2}


def test_three_client_swarm_reuses_shared_goed2k_launcher() -> None:
    module = load_suite_module()
    script_text = Path(module.__file__).read_text(encoding="utf-8")

    assert "goed2k.launch_ed2k_server(" in script_text
    assert "goed2k.start_ed2k_server(" not in script_text
    assert "goed2k.build_ed2k_server_binary(" not in script_text
