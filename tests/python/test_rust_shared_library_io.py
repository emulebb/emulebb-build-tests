from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from emule_test_harness import rust_shared_library_io as subject
from emule_test_harness import rust_shared_library_storage as storage


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


def harness_paths(tmp_path: Path) -> subject.HarnessPaths:
    scenario = tmp_path / "output/profiles/emulebb-rust-shared-library-io"
    return subject.HarnessPaths(
        workspace_root=tmp_path / "workspace",
        output_root=tmp_path / "output",
        rust_repo=tmp_path / "workspace/repos/emulebb-rust",
        scenario_root=scenario,
        fixture_root=scenario / "fixture/library",
        manifest_path=scenario / "fixture-manifest.json",
        owner_path=scenario / ".emulebb-rust-shared-library-io-owner.json",
        runs_root=scenario / "runs",
        reports_root=tmp_path / "output/reports",
        staged_executable=tmp_path / "output/tools/emulebb-rust/bin/emulebb-rust.exe",
    )


@pytest.mark.unit
def test_production_fixture_is_exactly_100k_and_ten_gib_decimal() -> None:
    assert subject.PRODUCTION_SPEC.file_count == 100_000
    assert subject.PRODUCTION_SPEC.total_bytes == 10_485_760_000
    assert len(subject.mutation_indices()) == 1_000
    assert subject.expected_mutation_bytes() == 100 * subject.MIB


@pytest.mark.unit
def test_production_fixture_reserves_exactly_one_long_path_group() -> None:
    first_long = subject.relative_file_for_index(99_000)
    assert len(str(subject.relative_file_for_index(98_999))) < 300
    assert len(str(first_long)) >= 300
    assert len(str(subject.relative_file_for_index(99_999))) >= 300
    assert max(len(part) for part in first_long.parts) <= 60
    assert (
        sum(
            len(str(subject.relative_file_for_index(index))) >= 300
            for index in range(subject.PRODUCTION_SPEC.file_count)
        )
        == 1_000
    )


@pytest.mark.unit
def test_watcher_cohort_is_exactly_one_percent_with_balanced_path_classes() -> None:
    summary = subject.fixture.watcher_cohort_summary()
    paths = [
        subject.fixture.watcher_relative_file(index)
        for index in range(subject.fixture.WATCHER_FILE_COUNT)
    ]
    sizes = [
        subject.fixture.watcher_size_for_index(index)
        for index in range(subject.fixture.WATCHER_FILE_COUNT)
    ]
    assert summary == {
        "fileCount": 1_000,
        "totalBytes": 100 * subject.MIB,
        "normalPathFileCount": 500,
        "longPathFileCount": 500,
    }
    assert sum(size == 16 * 1024 for size in sizes) == 800
    assert sum(size == 256 * 1024 for size in sizes) == 150
    assert sum(size == subject.MIB for size in sizes) == 50
    assert sum(len(str(path)) >= 300 for path in paths) == 500


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
    paths = harness_paths(tmp_path)
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
    subject.update_fixture_generation(paths, "mutation-v2")
    resumed = subject.prepare_fixture(paths, spec=spec)
    assert resumed["contentGeneration"] == "mutation-v2"
    restored = subject.restore_fixture_baseline(paths.fixture_root, spec)
    subject.update_fixture_generation(paths, "base-v2")
    assert restored["totalBytes"] == spec.total_bytes
    assert (
        json.loads(paths.manifest_path.read_text(encoding="utf-8"))["contentGeneration"]
        == "base-v2"
    )


@pytest.mark.unit
def test_cleanup_requires_exact_owned_target(tmp_path: Path) -> None:
    paths = harness_paths(tmp_path)
    paths.scenario_root.mkdir(parents=True)
    subject.write_json(paths.owner_path, {"schema": subject.OWNER_SCHEMA})
    with pytest.raises(RuntimeError, match="confirm"):
        subject.cleanup(paths, confirmed=False)
    result = subject.cleanup(paths, confirmed=True)
    assert result["status"] == "removed"
    assert not paths.scenario_root.exists()


@pytest.mark.unit
def test_v1_fixture_manifest_requires_explicit_cleanup(tmp_path: Path) -> None:
    paths = harness_paths(tmp_path)
    paths.scenario_root.mkdir(parents=True)
    subject.write_json(paths.owner_path, {"schema": subject.OWNER_SCHEMA})
    subject.write_json(
        paths.manifest_path,
        {"schema": "emulebb.rust-shared-library-fixture.v1", "status": "prepared"},
    )
    with pytest.raises(RuntimeError, match="not v2"):
        subject.load_prepared_manifest(paths)


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


@pytest.mark.unit
def test_windows_verbatim_path_handles_drive_unc_and_existing_prefix() -> None:
    assert storage.windows_verbatim_path(r"C:\fixture\library") == (
        r"\\?\C:\fixture\library"
    )
    assert storage.windows_verbatim_path(r"\\server\share\library") == (
        r"\\?\UNC\server\share\library"
    )
    assert storage.windows_verbatim_path(r"\\?\C:\fixture") == r"\\?\C:\fixture"


@pytest.mark.unit
def test_long_path_adapter_reads_walks_and_removes(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    path = (
        root.joinpath(*(f"segment-{index}-" + "x" * 52 for index in range(5)))
        / "file.bin"
    )
    assert storage.absolute_path_length(path) > 260
    subject.fixture.write_payload(path, b"synthetic")
    assert storage.is_file(path)
    assert storage.stat(path).st_size == len(b"synthetic")
    walked = [
        directory / name for directory, _, files in storage.walk(root) for name in files
    ]
    assert walked == [path]
    storage.remove_tree(root)
    assert not storage.is_directory(root)


@pytest.mark.unit
def test_linux_lsblk_parser_maps_children_to_one_physical_disk() -> None:
    rows = storage.parse_linux_lsblk(
        {
            "blockdevices": [
                {
                    "name": "/dev/nvme0n1",
                    "kname": "nvme0n1",
                    "path": "/dev/nvme0n1",
                    "type": "disk",
                    "size": 2_000_000,
                    "model": "Synthetic SSD",
                    "rota": False,
                    "tran": "nvme",
                    "children": [
                        {
                            "name": "/dev/nvme0n1p1",
                            "kname": "nvme0n1p1",
                            "path": "/dev/nvme0n1p1",
                            "type": "part",
                        }
                    ],
                }
            ]
        }
    )
    assert len(rows) == 1
    assert rows[0]["mediaType"] == "SSD"
    assert rows[0]["counterKey"] == "nvme0n1"
    assert "/dev/nvme0n1p1" in rows[0]["devicePaths"]


@pytest.mark.unit
def test_watcher_evidence_is_exact_and_does_not_publish_paths(tmp_path: Path) -> None:
    normal = subject._normalized_path_key(tmp_path / "watch-probe-0000.bin")
    long = subject._normalized_path_key(tmp_path / "watch-probe-0500.bin")
    expected = {
        normal: {"sizeBytes": 16, "pathClass": "normal"},
        long: {"sizeBytes": 32, "pathClass": "long"},
    }
    rows = {
        normal: {
            "hash": "a" * 32,
            "sizeBytes": 16,
            "completed": 1,
            "md4Acquired": 1,
            "aichAcquired": 1,
            "aichRootBytes": 20,
            "sourceMtimeMs": 1,
        },
        long: {
            "hash": "b" * 32,
            "sizeBytes": 32,
            "completed": 1,
            "md4Acquired": 1,
            "aichAcquired": 1,
            "aichRootBytes": 20,
            "sourceMtimeMs": 2,
        },
    }
    evidence, ok = subject._watcher_row_evidence(rows, expected)
    assert ok is True
    assert evidence["normalPathCount"] == 1
    assert evidence["longPathCount"] == 1
    assert str(tmp_path) not in json.dumps(evidence)


@pytest.mark.unit
def test_watcher_rest_sample_uses_canonical_path_field(tmp_path: Path) -> None:
    path = tmp_path / "watch-probe-0000.bin"
    key = subject._normalized_path_key(path)
    rows = {key: {"hash": "a" * 32, "sizeBytes": 16}}
    expected = {key: {"sizeBytes": 16, "pathClass": "normal"}}

    class FakeClient:
        def request(
            self, method: str, route: str, **_kwargs: object
        ) -> dict[str, object]:
            assert method == "GET"
            assert route == f"/shared-files/{'a' * 32}"
            return {"hash": "a" * 32, "sizeBytes": 16, "path": str(path)}

    sample = subject._sample_watcher_rest(FakeClient(), rows, expected)
    assert sample["sampleCount"] == 1
    assert sample["failureCount"] == 0


@pytest.mark.unit
def test_watcher_database_query_returns_only_active_probe_rows(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    database = profile / subject.rust_metadata.RUST_PROFILE_METADATA_FILE
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE known_files (
                id INTEGER PRIMARY KEY, ed2k_hash BLOB, display_name TEXT,
                size_bytes INTEGER, completed INTEGER,
                md4_hashset_acquired INTEGER, aich_hashset_acquired INTEGER,
                aich_root BLOB
            );
            CREATE TABLE local_paths (id INTEGER PRIMARY KEY, display_path TEXT);
            CREATE TABLE shared_file_sources (
                known_file_id INTEGER, path_id INTEGER,
                file_size INTEGER, source_mtime_ms INTEGER
            );
            CREATE TABLE unshared_files (known_file_id INTEGER);
            """
        )
        connection.execute(
            "INSERT INTO known_files VALUES (1, ?, 'watch-probe-0000.bin', 16, 1, 1, 1, ?)",
            (bytes.fromhex("11" * 16), bytes.fromhex("22" * 20)),
        )
        connection.execute(
            "INSERT INTO known_files VALUES (2, ?, 'watch-probe-0001.bin', 16, 1, 1, 1, ?)",
            (bytes.fromhex("33" * 16), bytes.fromhex("44" * 20)),
        )
        connection.execute(
            "INSERT INTO local_paths VALUES (1, ?)", (str(tmp_path / "active"),)
        )
        connection.execute(
            "INSERT INTO local_paths VALUES (2, ?)", (str(tmp_path / "removed"),)
        )
        connection.execute("INSERT INTO shared_file_sources VALUES (1, 1, 16, 123)")
        connection.execute("INSERT INTO shared_file_sources VALUES (2, 2, 16, 124)")
        connection.execute("INSERT INTO unshared_files VALUES (2)")
    rows = subject._watcher_database_rows(profile)
    assert len(rows) == 1
    assert next(iter(rows.values()))["hash"] == "11" * 16


@pytest.mark.unit
def test_storage_snapshot_counts_active_shared_sources_not_transfers(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    database = profile / subject.rust_metadata.RUST_PROFILE_METADATA_FILE
    long_path = str(tmp_path / ("long-segment-" * 30) / "active.bin")
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE known_files (
                id INTEGER PRIMARY KEY, size_bytes INTEGER, completed INTEGER,
                md4_hashset_acquired INTEGER, aich_hashset_acquired INTEGER,
                aich_root BLOB
            );
            CREATE TABLE local_paths (id INTEGER PRIMARY KEY, display_path TEXT);
            CREATE TABLE shared_file_sources (
                known_file_id INTEGER, path_id INTEGER,
                file_size INTEGER, source_mtime_ms INTEGER
            );
            CREATE TABLE unshared_files (known_file_id INTEGER);
            CREATE TABLE transfers (removed_at_ms INTEGER);
            CREATE TABLE shared_file_memberships (removed_at_ms INTEGER);
            CREATE TABLE shared_file_scan_failures (id INTEGER);
            """
        )
        connection.execute(
            "INSERT INTO known_files VALUES (1, 16, 1, 1, 1, ?)",
            (bytes.fromhex("11" * 20),),
        )
        connection.execute(
            "INSERT INTO known_files VALUES (2, 32, 1, 1, 1, ?)",
            (bytes.fromhex("22" * 20),),
        )
        connection.execute("INSERT INTO local_paths VALUES (1, ?)", (long_path,))
        connection.execute(
            "INSERT INTO local_paths VALUES (2, ?)", (str(tmp_path / "hidden.bin"),)
        )
        connection.execute("INSERT INTO shared_file_sources VALUES (1, 1, 16, 123)")
        connection.execute("INSERT INTO shared_file_sources VALUES (2, 2, 32, 124)")
        connection.execute("INSERT INTO unshared_files VALUES (2)")
        connection.execute("INSERT INTO transfers VALUES (NULL)")

    snapshot = subject.profile_storage_snapshot(profile)
    counts = snapshot["rowCounts"]
    assert counts["shareSourceRows"] == 2
    assert counts["activeShareSources"] == 1
    assert counts["activeShareBytes"] == 16
    assert counts["activeLongPathSources"] == 1
    assert counts["invalidActiveShareIntegrity"] == 0
    assert subject.storage_acceptance(
        snapshot,
        expected_active=1,
        expected_bytes=16,
        expected_minimum_long=1,
    ) == {
        "databaseActiveShares": True,
        "databaseActiveBytes": True,
        "databaseHashIntegrity": True,
        "databaseLongPathShares": True,
        "databaseScanFailures": True,
    }


@pytest.mark.unit
def test_watcher_log_summary_reports_empty_logs_without_faking_registration(
    tmp_path: Path,
) -> None:
    empty = tmp_path / "empty.log"
    empty.write_bytes(b"")
    summary = subject.watcher_log_summary([empty])
    assert summary["logByteCount"] == 0
    assert summary["nonEmptyLogCount"] == 0
    assert summary["watcherRegistrations"] == 0


@pytest.mark.unit
def test_storage_target_report_fingerprints_local_roots(tmp_path: Path) -> None:
    target = storage.StorageTarget(
        role="ssdBaseline",
        root=tmp_path / "private-library",
        disk_number=6,
        counter_key="physicaldrive6",
        media_type="SSD",
        bus_type="NVMe",
        friendly_name="Synthetic SSD",
        mount_path=tmp_path,
        expected_file_count=100_000,
        expected_bytes=10_485_760_000,
    )
    report = target.sanitized(subject.path_fingerprint)
    assert str(tmp_path) not in json.dumps(report)
    assert report["expectedFileCount"] == 100_000


@pytest.mark.unit
def test_parser_exposes_independent_watcher_timing() -> None:
    args = subject.build_parser().parse_args(["run"])
    assert args.watcher_timeout_seconds == 600
    assert args.watcher_poll_seconds == 0.5
