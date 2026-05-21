from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from emule_test_harness.admin_volume_fixtures import VolumeIdentity


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "shared-cache-volume-identity.py"
    spec = importlib.util.spec_from_file_location("shared_cache_volume_identity_test", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("win32"):
            pytest.skip(f"pywin32 live harness dependency is unavailable: {exc.name}")
        raise
    return module


def volume(root: str, volume_name: str | None, serial_hex: str | None) -> VolumeIdentity:
    return VolumeIdentity(
        root=root,
        volume_name=volume_name,
        serial_hex=serial_hex,
        file_system="NTFS",
        label="EMULEBB_TEST",
        total_bytes=1024,
        free_bytes=512,
    )


def test_identities_match_prefers_volume_name() -> None:
    module = load_script_module()

    assert module.identities_match(volume("X:\\", "\\\\?\\Volume{A}\\", "AAAA"), volume("C:\\mnt", "\\\\?\\Volume{a}\\", "BBBB"))


def test_identities_differ_uses_serial_when_volume_name_unavailable() -> None:
    module = load_script_module()

    assert module.identities_differ(volume("C:\\", None, "AAAA"), volume("X:\\", None, "BBBB")) is True
    assert module.identities_differ(volume("X:\\", None, None), volume("Y:\\", None, None)) is None


def test_write_shared_fixture_builds_expected_tree(tmp_path: Path) -> None:
    module = load_script_module()

    summary = module.write_shared_fixture(tmp_path)

    assert summary["file_count"] == 3
    assert (tmp_path / "shared" / "nested" / "deeper" / "gamma space.txt").is_file()
