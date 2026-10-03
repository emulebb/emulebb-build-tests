from __future__ import annotations

import json
from pathlib import Path

import pytest

from emule_test_harness import rust_shared_library_io as subject


def tiny_spec() -> subject.FixtureSpec:
    return subject.FixtureSpec(
        top_directories=2,
        leaf_directories_per_top=2,
        files_per_leaf=2,
        small_count=4,
        small_size=8,
        medium_count=2,
        medium_size=16,
        large_count=2,
        large_size=32,
    )


@pytest.mark.unit
def test_production_fixture_is_exactly_100k_and_ten_gib_decimal() -> None:
    assert subject.PRODUCTION_SPEC.file_count == 100_000
    assert subject.PRODUCTION_SPEC.total_bytes == 10_485_760_000
    assert len(subject.mutation_indices()) == 1_000
    assert subject.expected_mutation_bytes() == 100 * subject.MIB


@pytest.mark.unit
def test_index_mapping_is_stable_across_tree_and_size_tiers() -> None:
    spec = tiny_spec()
    assert subject.relative_file_for_index(0, spec) == Path(
        "group-000/leaf-000/file-000000.bin"
    )
    assert subject.relative_file_for_index(7, spec) == Path(
        "group-001/leaf-001/file-000007.bin"
    )
    assert [subject.file_size_for_index(index, spec) for index in range(8)] == [
        8,
        8,
        8,
        8,
        16,
        16,
        32,
        32,
    ]


@pytest.mark.unit
def test_prepare_fixture_is_resumable_and_validates_without_deleting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = tiny_spec()
    paths = subject.HarnessPaths(
        workspace_root=tmp_path / "workspace",
        output_root=tmp_path / "output",
        rust_repo=tmp_path / "workspace/repos/emulebb-rust",
        scenario_root=tmp_path / "output/profiles/emulebb-rust-shared-library-io",
        fixture_root=tmp_path
        / "output/profiles/emulebb-rust-shared-library-io/fixture/library",
        manifest_path=tmp_path
        / "output/profiles/emulebb-rust-shared-library-io/fixture-manifest.json",
        owner_path=tmp_path
        / "output/profiles/emulebb-rust-shared-library-io/.emulebb-rust-shared-library-io-owner.json",
        runs_root=tmp_path / "output/profiles/emulebb-rust-shared-library-io/runs",
        reports_root=tmp_path / "output/reports",
        staged_executable=tmp_path / "output/tools/emulebb-rust/bin/emulebb-rust.exe",
    )
    monkeypatch.setattr(
        subject,
        "physical_disk_inventory",
        lambda: [{"diskNumber": 6, "mediaType": "SSD"}],
    )
    monkeypatch.setattr(
        subject,
        "target_disk",
        lambda _paths, _inventory: {
            "diskNumber": 6,
            "mediaType": "SSD",
            "busType": "NVMe",
            "friendlyName": "test",
        },
    )
    first = subject.prepare_fixture(paths, spec=spec)
    second = subject.prepare_fixture(paths, spec=spec)
    assert first["createdCount"] == 8
    assert second["createdCount"] == 0
    assert second["reusedCount"] == 8
    assert subject.validate_fixture(paths.fixture_root, spec)["ok"] is True
    manifest = json.loads(paths.manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "prepared"

    subject.mutate_fixture(paths.fixture_root, spec)
    subject.update_fixture_generation(paths, "mutation-v1")
    resumed = subject.prepare_fixture(paths, spec=spec)
    assert resumed["contentGeneration"] == "mutation-v1"
    restored = subject.restore_fixture_baseline(paths.fixture_root, spec)
    subject.update_fixture_generation(paths, "base-v1")
    assert restored["totalBytes"] == spec.total_bytes
    assert (
        json.loads(paths.manifest_path.read_text(encoding="utf-8"))["contentGeneration"]
        == "base-v1"
    )


@pytest.mark.unit
def test_cleanup_requires_exact_owned_target(tmp_path: Path) -> None:
    scenario = tmp_path / "profiles/emulebb-rust-shared-library-io"
    paths = subject.HarnessPaths(
        workspace_root=tmp_path / "workspace",
        output_root=tmp_path,
        rust_repo=tmp_path / "workspace/repos/emulebb-rust",
        scenario_root=scenario,
        fixture_root=scenario / "fixture/library",
        manifest_path=scenario / "fixture-manifest.json",
        owner_path=scenario / ".emulebb-rust-shared-library-io-owner.json",
        runs_root=scenario / "runs",
        reports_root=tmp_path / "reports",
        staged_executable=tmp_path / "emulebb-rust.exe",
    )
    scenario.mkdir(parents=True)
    subject.write_json(paths.owner_path, {"schema": subject.OWNER_SCHEMA})
    with pytest.raises(RuntimeError, match="confirm"):
        subject.cleanup(paths, confirmed=False)
    result = subject.cleanup(paths, confirmed=True)
    assert result["status"] == "removed"
    assert not scenario.exists()


@pytest.mark.unit
def test_phase_acceptance_checks_serial_io_and_exact_counters() -> None:
    phase = {
        "sharedFilesTotal": 8,
        "maxPerDiskActiveCount": 1,
        "progress": {
            "scannedCount": 8,
            "plannedHashCount": 2,
            "hashedCount": 2,
            "failedHashCount": 0,
            "statFailedCount": 0,
            "skippedFailedCount": 0,
            "skippedIntakeCount": 0,
            "reusedCount": 6,
            "plannedReadBytes": 64,
            "completedReadBytes": 64,
            "diskCount": 1,
            "changedCount": 2,
        },
    }
    result = subject.phase_acceptance(
        phase,
        {
            "sharedFilesTotal": 8,
            "scannedCount": 8,
            "plannedHashCount": 2,
            "hashedCount": 2,
            "reusedCount": 6,
            "plannedReadBytes": 64,
            "diskCount": 1,
            "changedCount": 2,
        },
    )
    assert result["ok"] is True
