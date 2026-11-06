"""Guard the offline import audit against hidden hashing or network startup."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

import pytest

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
    assert validate_imported_hashes(tmp_path, manifest)["verifiedImportedRecords"] == 1
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE imported_known_file_md4_hashes SET md4_hash = ?", (bytes.fromhex("33" * 16),))
    with pytest.raises(RuntimeError, match="hashset differs"):
        validate_imported_hashes(tmp_path, manifest)
