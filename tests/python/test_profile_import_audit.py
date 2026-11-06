"""Guard the offline import audit against hidden hashing or network startup."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import profile_import_audit, rust_upload_soak
from emule_test_harness.emule_profile_export import PathMapping
from emule_test_harness.profile_import_audit import mount_argument, validate_imported_hashes, validate_reconciliation
from emule_test_harness.rust_native_fingerprint import NativeFingerprint, NativeTimestamp, encode_fingerprint


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
            CREATE TABLE known_files(id,ed2k_hash,size_bytes);
            CREATE TABLE verified_local_content(known_file_id,aich_root);
            CREATE TABLE verified_local_md4_hashes(known_file_id,part_index,md4_hash);
            CREATE TABLE verified_local_aich_hashes(known_file_id,part_index,aich_hash);
        """)
        connection.execute("INSERT INTO known_files VALUES (1,?,1024)",(bytes.fromhex("11"*16),))
        connection.execute("INSERT INTO verified_local_content VALUES(1,NULL)")
        connection.execute("INSERT INTO verified_local_md4_hashes VALUES(1,0,?)",(bytes.fromhex("22"*16),))
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
        connection.execute("UPDATE verified_local_md4_hashes SET md4_hash = ?", (bytes.fromhex("33" * 16),))
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


@pytest.fixture
def binding_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Provide two content identities so a wrong binding can keep all row counts."""
    shared = tmp_path / "shared"
    shared.mkdir()
    payload = shared / "Sample.bin"
    payload.write_bytes(b"abc")
    config = tmp_path / "stock"
    config.mkdir()
    (config / "known.met").touch()
    profile = tmp_path / "profile"
    profile.mkdir()
    current = payload.stat()
    seconds, nanos = divmod(current.st_mtime_ns, 1_000_000_000)
    fingerprint = encode_fingerprint(NativeFingerprint(1, b"\0" * 16, 3,
                                    NativeTimestamp(seconds, nanos), None))
    database = profile / "emulebb-rust-metadata.db"
    with sqlite3.connect(database) as db:
        db.executescript("""
            CREATE TABLE local_paths(id,platform,native_path);
            CREATE TABLE local_file_instances(path_id,known_file_id,file_size,verified_fingerprint);
            CREATE TABLE known_files(id,ed2k_hash,size_bytes,aich_root);
            CREATE TABLE verified_local_content(known_file_id,aich_root);
            CREATE TABLE verified_local_md4_hashes(known_file_id,part_index,md4_hash);
            CREATE TABLE verified_local_aich_hashes(known_file_id,part_index,aich_hash);
        """)
        db.execute("INSERT INTO local_paths VALUES(1,'unix',?)", (b"/data/sample/Sample.bin",))
        db.execute("INSERT INTO local_file_instances VALUES(1,1,3,?)", (fingerprint,))
        for i in (1, 2):
            db.execute("INSERT INTO known_files VALUES(?,?,3,?)", (i, bytes([i]) * 16, b"a" * 20))
            db.execute("INSERT INTO verified_local_content VALUES(?,?)", (i, b"a" * 20))
    exchange=tmp_path/"exchange.sqlite"
    with sqlite3.connect(exchange) as db:
        db.execute("CREATE TABLE known_files(id INTEGER PRIMARY KEY,record TEXT,md4 BLOB,aich BLOB)")
        db.execute("INSERT INTO known_files VALUES(1,?,X'',X'')",(json.dumps({"fileHash":"01"*16,"displayName":"Sample.bin","fileSize":3,"modifiedS":seconds,"aichRoot":"61"*20}),))
    monkeypatch.setattr(profile_import_audit.emule_profile_export, "discover_shared_roots",
                        lambda *args: [SimpleNamespace(path=str(shared))])
    job = SimpleNamespace(source_profile=config, output_manifest=exchange, path_mappings=(PathMapping(str(shared), "/data/sample"),))
    return profile, job, database, payload


def test_native_binding_validation_uses_actual_source_metadata(binding_profile) -> None:
    profile, job, _, _ = binding_profile
    result = profile_import_audit.validate_native_bindings(profile, job)
    assert result["verifiedPathBindings"] == 1
    assert result["verifiedRemappedPaths"] == 1


@pytest.mark.parametrize(("mutation", "message"), [
    ("UPDATE local_file_instances SET known_file_id=2", "content identity differs"),
    ("UPDATE verified_local_content SET aich_root=zeroblob(20)", "content identity differs"),
    ("UPDATE known_files SET record=json_set(record,'$.displayName','sample.bin')", "unambiguous stock identity"),
    ("UPDATE known_files SET record=json_set(record,'$.modifiedS',json_extract(record,'$.modifiedS')+1)", "unambiguous stock identity"),
    ("UPDATE known_files SET record=json_set(record,'$.fileSize',4)", "unambiguous stock identity"),
    ("INSERT INTO known_files(record,md4,aich) SELECT json_set(record,'$.fileHash','00000000000000000000000000000000'),md4,aich FROM known_files", "unambiguous stock identity"),
    ("INSERT INTO verified_local_md4_hashes VALUES(1,0,zeroblob(16))", "hashset differs"),
    ("INSERT INTO verified_local_aich_hashes VALUES(1,0,zeroblob(20))", "hashset differs"),
    ("DELETE FROM verified_local_content WHERE known_file_id=1", "without verified hash metadata"),
])
def test_native_binding_validation_rejects_wrong_matches_with_same_counts(binding_profile, mutation, message) -> None:
    profile, job, database, _ = binding_profile
    with sqlite3.connect(job.output_manifest if "record=" in mutation or "record,md4,aich" in mutation else database) as db:
        db.execute(mutation)
    with pytest.raises(RuntimeError, match=message):
        profile_import_audit.validate_native_bindings(profile, job)


def test_native_binding_validation_rejects_changed_file_without_reading_it(binding_profile) -> None:
    profile, job, _, payload = binding_profile
    before = payload.stat()
    os.utime(payload, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
    with pytest.raises(RuntimeError, match="fingerprint differs"):
        profile_import_audit.validate_native_bindings(profile, job)


@pytest.mark.parametrize("path", [b"/data/sample-other/Sample.bin", b"/data/sample/../Sample.bin"])
def test_reverse_path_mapping_enforces_boundaries(path: bytes, tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="mapping|invalid native path"):
        profile_import_audit.source_path_for_binding("unix", path, (PathMapping(str(tmp_path), "/data/sample"),))


def test_stock_comparison_detects_exporter_identity_corruption(binding_profile, monkeypatch: pytest.MonkeyPatch) -> None:
    profile, job, database, payload = binding_profile
    entry = SimpleNamespace(name="Sample.bin", size_bytes=3, modified_s=payload.stat().st_mtime_ns // 1_000_000_000,
                            ed2k_hash="01" * 16, aich_root="61" * 20, md4_hashset=[], aich_hashset=[])
    monkeypatch.setattr(profile_import_audit.mfc_known_met, "iter_known_met", lambda path: iter([entry]))
    assert profile_import_audit.validate_stock_records(profile, job.source_profile, job.output_manifest)["verifiedStockRecords"] == 1
    with sqlite3.connect(job.output_manifest) as db:
        db.execute("UPDATE known_files SET record=json_set(record,'$.fileHash','00000000000000000000000000000000')")
    with pytest.raises(RuntimeError, match="stock record differs"):
        profile_import_audit.validate_stock_records(profile, job.source_profile, job.output_manifest)


@pytest.mark.parametrize("state,rejections,message", [
    ("absent", 0, "do not match"),
    ("absent", 1, None),
    ("valid", 0, None),
    ("valid", 1, "do not match"),
    ("partial", 1, "partial"),
    ("altered", 0, "leaves differ"),
    ("extra", 0, "extra parts"),
    ("orphan", 1, "partial imported leaves"),
])
def test_recovery_rejections_only_allow_wholly_absent_sets(tmp_path, state, rejections, message):
    root, leaves = b"r" * 20, b"h" * 20
    exchange = tmp_path / "exchange.sqlite"
    with sqlite3.connect(exchange) as db:
        db.executescript("CREATE TABLE known_files(id,record,md4,aich); CREATE TABLE recovery_sets(root,size_bytes); CREATE TABLE recovery_parts(root,size_bytes,part_index,leaves);")
        db.execute("INSERT INTO recovery_sets VALUES(?,3)", (root,))
        db.execute("INSERT INTO recovery_parts VALUES(?,3,0,?)", (root, leaves))
    with sqlite3.connect(tmp_path / "emulebb-rust-metadata.db") as db:
        db.executescript("CREATE TABLE known_files(id,size_bytes); CREATE TABLE verified_local_content(known_file_id,aich_root); CREATE TABLE aich_recovery_sets(root,size_bytes); CREATE TABLE aich_recovery_parts(root,size_bytes,part_index,leaves);")
        db.execute("INSERT INTO known_files VALUES(1,3)")
        db.execute("INSERT INTO verified_local_content VALUES(1,?)",(root,))
        if state not in ("absent", "orphan"):
            db.execute("INSERT INTO aich_recovery_sets VALUES(?,3)", (root,))
        if state not in ("absent", "partial"):
            db.execute("INSERT INTO aich_recovery_parts VALUES(?,3,0,?)", (root, b"x" * 20 if state == "altered" else leaves))
        if state == "extra":
            db.execute("INSERT INTO aich_recovery_parts VALUES(?,3,1,?)", (root, leaves))
    if message:
        with pytest.raises(RuntimeError, match=message):
            validate_imported_hashes(tmp_path, exchange, rejected_recovery_sets=rejections)
    else:
        result = validate_imported_hashes(tmp_path, exchange, rejected_recovery_sets=rejections)
        assert result["unavailableRecoverySets"] == rejections
