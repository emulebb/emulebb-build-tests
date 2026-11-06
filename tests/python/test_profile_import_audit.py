"""Guard the offline import audit against hidden hashing or network startup."""

from __future__ import annotations

import argparse
import json
import sqlite3
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import profile_import_audit, rust_upload_soak
from emule_test_harness.emule_profile_export import PathMapping
from emule_test_harness.profile_import_audit import mount_argument, validate_imported_hashes, validate_reconciliation


@pytest.mark.parametrize("field", ["hashedCount", "completedReadBytes", "activeHashCount", "running"])
def test_audit_rejects_payload_work(field: str) -> None:
    report = {"hashedCount": 0, "completedReadBytes": 0, "activeHashCount": 0, "running": False}
    report[field] = 1
    with pytest.raises(RuntimeError, match="unexpected payload work"):
        validate_reconciliation(report)


def test_pending_hash_work_is_reported_without_being_executed() -> None:
    validate_reconciliation({
        "hashedCount": 0, "completedReadBytes": 0, "activeHashCount": 0,
        "running": False, "plannedHashCount": 12,
    })


def test_container_mount_requires_absolute_explicit_paths() -> None:
    assert mount_argument("/mnt/sample=/data/sample") == ("/mnt/sample", "/data/sample")
    with pytest.raises(argparse.ArgumentTypeError):
        mount_argument("relative=/data/sample")


def test_complete_reuse_rejects_pending_hashing_without_executing_it():
    report={"hashedCount":0,"completedReadBytes":0,"activeHashCount":0,"running":False,"plannedHashCount":1}
    validate_reconciliation(report)
    with pytest.raises(RuntimeError,match="queued for hashing"):
        validate_reconciliation(report,require_complete_reuse=True)


def test_hash_validation_detects_corruption_even_when_row_counts_match(tmp_path: Path) -> None:
    database = tmp_path / "emulebb-rust-metadata.db"
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            CREATE TABLE imported_known_files(id, ed2k_hash, display_name, size_bytes, modified_s, aich_root);
            CREATE TABLE imported_known_file_md4_hashes(imported_known_file_id, part_index, md4_hash);
            CREATE TABLE imported_known_file_aich_hashes(imported_known_file_id, part_index, aich_hash);
        """)
        connection.execute("INSERT INTO imported_known_files VALUES (1, ?, 'Sample.bin', 1024, 1700000000, NULL)",
                           (bytes.fromhex("11" * 16),))
        connection.execute("INSERT INTO imported_known_file_md4_hashes VALUES (1, 0, ?)", (bytes.fromhex("22" * 16),))
    manifest = {"knownFiles": [{
        "fileHash": "11" * 16, "displayName": "Sample.bin", "fileSize": 1024,
        "modifiedS": 1700000000, "aichRoot": None, "md4Hashset": ["22" * 16], "aichHashset": [],
    }]}
    exchange=tmp_path/"exchange.sqlite"
    with sqlite3.connect(exchange) as source:
        source.executescript("CREATE TABLE known_files(id INTEGER PRIMARY KEY,record TEXT,md4 BLOB,aich BLOB); CREATE TABLE recovery_sets(root,size_bytes);")
        record=manifest["knownFiles"][0]
        source.execute("INSERT INTO known_files VALUES(1,?,?,?)",(json.dumps(record),bytes.fromhex("22"*16),b""))
    assert validate_imported_hashes(tmp_path, exchange)["verifiedImportedRecords"] == 1
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE imported_known_file_md4_hashes SET md4_hash = ?", (bytes.fromhex("33" * 16),))
    with pytest.raises(RuntimeError, match="hashset differs"):
        validate_imported_hashes(tmp_path, exchange)


def test_audit_restores_only_its_own_read_only_data_mount(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=1 if "mountpoint" in command else 0)
    monkeypatch.setattr(profile_import_audit.subprocess, "run", run)
    job = SimpleNamespace(path_mappings=(PathMapping(str(tmp_path), "/data/sample"),))
    with ExitStack() as cleanup:
        profile_import_audit.prepare_windows_mounts(
            ["wsl.exe", "-d", "SampleDistro", "--"], job,
            [("/mnt/sample", "/data/sample")], cleanup,
        )
        assert calls[-1][-5:] == ["drvfs", "-o", "ro", tmp_path.as_posix(), "/mnt/sample"]
    assert calls[-1][-2:] == ["umount", "/mnt/sample"]


def test_metadata_output_mount_uses_selected_distribution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="1000\n")
    monkeypatch.setattr(rust_upload_soak.subprocess, "run", run)
    mountpoint = rust_upload_soak.mount_wsl_output_with_metadata("test", tmp_path, distribution="SampleDistro")
    rust_upload_soak.unmount_wsl_output(mountpoint, distribution="SampleDistro")
    assert all(command[:3] == ["wsl.exe", "-d", "SampleDistro"] for command in calls)


def test_snapshot_does_not_create_cross_platform_sqlite_sidecars(tmp_path: Path) -> None:
    with sqlite3.connect(tmp_path / "emulebb-rust-metadata.db") as connection:
        connection.execute("CREATE TABLE sample(value)")
    connection.close()
    snapshot = profile_import_audit.open_profile_snapshot(tmp_path)
    assert snapshot.execute("SELECT count(*) FROM sample").fetchone()[0] == 0
    snapshot.close()
    assert sorted(path.name for path in tmp_path.iterdir()) == ["emulebb-rust-metadata.db"]
    (tmp_path / "emulebb-rust-metadata.db-wal").write_bytes(b"uncheckpointed data")
    with pytest.raises(RuntimeError, match="uncheckpointed WAL"):
        profile_import_audit.open_profile_snapshot(tmp_path)


def test_offline_failure_retains_the_actual_diagnostic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(profile_import_audit.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=1, stderr="sample failure", stdout=""))
    with pytest.raises(RuntimeError, match="sample failure"):
        profile_import_audit.run_json(["sample"], 10)
