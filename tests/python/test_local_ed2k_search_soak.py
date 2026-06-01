from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def load_suite_module():
    """Loads the hyphenated local ED2K soak script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "local-ed2k-search-soak.py"
    spec = importlib.util.spec_from_file_location("local_ed2k_search_soak_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_local_soak_defaults_are_bounded_and_local() -> None:
    module = load_suite_module()
    args = module.parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert args.p2p_bind_interface_name == ""
    assert args.search_waves == 3
    assert args.searches_per_wave == 12
    assert args.max_concurrent_searches == 6
    assert args.synthetic_catalog_files == 240
    assert args.fixture_size_bytes == 132 * 1024 * 1024


def test_synthetic_catalog_records_are_deterministic_and_searchable() -> None:
    module = load_suite_module()

    records = module.build_synthetic_catalog_records(10, source_host="10.1.2.3", source_port=4662)

    assert len(records) == 10
    assert records[0]["name"].startswith("local-soak-linux-")
    assert records[0]["hash"] == module.synthetic_hash("local-soak-linux:0")
    assert records[0]["endpoints"] == [{"host": "10.1.2.3", "port": 4662}]
    assert {row["complete_sources"] for row in records} == {1}
    assert len({row["hash"] for row in records}) == 10


def test_write_catalog_uses_server_schema(tmp_path: Path) -> None:
    module = load_suite_module()
    path = tmp_path / "catalog.json"
    records = module.build_synthetic_catalog_records(2, source_host="10.1.2.3", source_port=4662)

    summary = module.write_catalog(path, records)

    assert summary == {"path": str(path), "file_count": 2}
    assert '"files"' in path.read_text(encoding="utf-8")


def test_search_wave_validation_rejects_zero_counts() -> None:
    module = load_suite_module()

    with pytest.raises(ValueError, match="greater than zero"):
        module.run_search_waves(
            base_url="http://127.0.0.1:1",
            api_key="key",
            waves=0,
            searches_per_wave=1,
            max_concurrent_searches=1,
            timeout_seconds=1.0,
        )
