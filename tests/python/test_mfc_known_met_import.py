from __future__ import annotations

import os
import sqlite3
import struct
from pathlib import Path

from emule_test_harness import mfc_known_met, rust_metadata


def _rust_repo() -> Path:
    return Path(__file__).resolve().parents[2].parent / "emulebb-rust"


def _tag_string(name_id: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return bytes([mfc_known_met.TAGTYPE_STRING]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<H", len(raw)) + raw


def _tag_uint64(name_id: int, value: int) -> bytes:
    return bytes([mfc_known_met.TAGTYPE_UINT64]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<Q", value)


def _tag_blob(name_id: int, value: bytes) -> bytes:
    return bytes([mfc_known_met.TAGTYPE_BLOB]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<I", len(value)) + value


def _known_record(
    *,
    modified_s: int,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    md4_hashset: list[str] | None = None,
    aich_blob: bytes | None = None,
) -> bytes:
    tags = [
        _tag_string(mfc_known_met.FT_FILENAME, name),
        _tag_uint64(mfc_known_met.FT_FILESIZE, size_bytes),
    ]
    if aich_blob is not None:
        tags.append(_tag_blob(mfc_known_met.FT_AICHHASHSET, aich_blob))
    parts = md4_hashset or []
    return (
        struct.pack("<I", modified_s)
        + bytes.fromhex(ed2k_hash)
        + struct.pack("<H", len(parts))
        + b"".join(bytes.fromhex(part) for part in parts)
        + struct.pack("<I", len(tags))
        + b"".join(tags)
    )


def _write_known_met(path: Path, records: list[bytes]) -> None:
    path.write_bytes(
        bytes([mfc_known_met.MET_HEADER_I64TAGS])
        + struct.pack("<I", len(records))
        + b"".join(records)
    )


def test_parse_known_met_reads_identity_and_aich_blob(tmp_path: Path) -> None:
    aich_blob = bytes.fromhex("aa" * 20) + struct.pack("<H", 0)
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=1_700_000_000,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name="Sample File.bin",
                size_bytes=1234,
                aich_blob=aich_blob,
            )
        ],
    )

    entries = mfc_known_met.parse_known_met(known_met)

    assert len(entries) == 1
    assert entries[0].ed2k_hash == "00112233445566778899aabbccddeeff"
    assert entries[0].name == "Sample File.bin"
    assert entries[0].size_bytes == 1234
    assert entries[0].aich_root == "aa" * 20


def test_import_known_met_seeds_share_in_place_manifest(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    payload = shared / "Sample File.bin"
    payload.write_bytes(b"sample")
    modified_s = 1_700_000_000
    os.utime(payload, (modified_s, modified_s))
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=modified_s,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name=payload.name,
                size_bytes=payload.stat().st_size,
            )
        ],
    )
    db_path = tmp_path / "metadata.sqlite"
    rust_metadata.create_metadata_db(_rust_repo(), db_path)

    summary = mfc_known_met.import_mfc_known_met_hashes(
        rust_repo=_rust_repo(),
        metadata_db=db_path,
        known_met=known_met,
        shared_roots=[shared],
    )

    assert summary["importedRecords"] == 1
    manifest = rust_metadata.read_transfer_manifest(db_path, "00112233445566778899aabbccddeeff")
    assert manifest is not None
    assert manifest["completed"] is True
    assert manifest["source_path"] == str(payload)
    assert manifest["source_mtime_ms"] // 1000 == modified_s
    assert manifest["md4_hashset_acquired"] is True
    with sqlite3.connect(db_path) as conn:
        source_row = conn.execute(
            """
            SELECT file_size, source_mtime_ms
            FROM share_in_place_sources
            WHERE source_path = ?
            """,
            (str(payload),),
        ).fetchone()
        piece_rows = conn.execute("SELECT count(*) FROM transfer_pieces").fetchone()[0]
        range_row = conn.execute(
            """
            SELECT start_offset, end_offset, source_kind
            FROM verified_ranges
            """
        ).fetchone()
    assert source_row == (payload.stat().st_size, manifest["source_mtime_ms"])
    assert piece_rows == 0
    assert range_row == (0, payload.stat().st_size, "ed2k_transfer")


def test_import_known_met_skips_ambiguous_path_match(tmp_path: Path) -> None:
    roots = [tmp_path / "one", tmp_path / "two"]
    modified_s = 1_700_000_000
    for root in roots:
        root.mkdir()
        payload = root / "Duplicate.bin"
        payload.write_bytes(b"same")
        os.utime(payload, (modified_s, modified_s))
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=modified_s,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name="Duplicate.bin",
                size_bytes=4,
            )
        ],
    )

    summary = mfc_known_met.import_mfc_known_met_hashes(
        rust_repo=_rust_repo(),
        metadata_db=tmp_path / "metadata.sqlite",
        known_met=known_met,
        shared_roots=roots,
        dry_run=True,
    )

    assert summary["matchedRecords"] == 0
    assert summary["skipped"]["no_unique_path_match"] == 1
    assert summary["skipped"]["no_path_match"] == 0
    assert summary["skipped"]["ambiguous_path_match"] == 1


def test_import_known_met_reports_missing_path_match(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=1_700_000_000,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name="Missing.bin",
                size_bytes=4,
            )
        ],
    )

    summary = mfc_known_met.import_mfc_known_met_hashes(
        rust_repo=_rust_repo(),
        metadata_db=tmp_path / "metadata.sqlite",
        known_met=known_met,
        shared_roots=[shared],
        dry_run=True,
    )

    assert summary["matchedRecords"] == 0
    assert summary["skipped"]["no_unique_path_match"] == 1
    assert summary["skipped"]["no_path_match"] == 1
    assert summary["skipped"]["ambiguous_path_match"] == 0


def test_import_mfc_shared_file_rows_uses_exact_rest_path(tmp_path: Path) -> None:
    root = tmp_path / "share"
    root.mkdir()
    duplicate = tmp_path / "other"
    duplicate.mkdir()
    payload = root / "Duplicate.bin"
    payload.write_bytes(b"same")
    other_payload = duplicate / "Duplicate.bin"
    other_payload.write_bytes(b"same")
    modified_s = 1_700_000_000
    os.utime(payload, (modified_s, modified_s))
    os.utime(other_payload, (modified_s, modified_s))
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=modified_s,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name="Duplicate.bin",
                size_bytes=payload.stat().st_size,
            )
        ],
    )
    db_path = tmp_path / "metadata.sqlite"
    rust_metadata.create_metadata_db(_rust_repo(), db_path)

    summary = mfc_known_met.import_mfc_shared_file_rows_hashes(
        rust_repo=_rust_repo(),
        metadata_db=db_path,
        known_met=known_met,
        shared_file_rows=[
            {
                "hash": "00112233445566778899aabbccddeeff",
                "name": "Duplicate.bin",
                "path": str(payload),
                "sizeBytes": payload.stat().st_size,
                "priority": "auto",
                "autoUploadPriority": True,
                "allTimeTransferred": 123456789,
            }
        ],
        shared_roots=[root],
    )

    assert summary["importedRows"] == 1
    assert summary["skipped"]["path_outside_shared_roots"] == 0
    manifest = rust_metadata.read_transfer_manifest(db_path, "00112233445566778899aabbccddeeff")
    assert manifest is not None
    assert manifest["completed"] is True
    assert manifest["source_path"] == str(payload)
    assert manifest["source_mtime_ms"] // 1000 == modified_s
    assert manifest["upload_priority"] == "normal"
    assert manifest["auto_upload_priority"] is False
    assert manifest["all_time_uploaded_bytes"] == 0
    with sqlite3.connect(db_path) as conn:
        source_row = conn.execute(
            """
            SELECT file_size, source_mtime_ms
            FROM share_in_place_sources
            WHERE source_path = ?
            """,
            (str(payload),),
        ).fetchone()
        piece_rows = conn.execute("SELECT count(*) FROM transfer_pieces").fetchone()[0]
        range_row = conn.execute(
            """
            SELECT start_offset, end_offset, source_kind
            FROM verified_ranges
            """
        ).fetchone()
    assert source_row == (payload.stat().st_size, manifest["source_mtime_ms"])
    assert piece_rows == 0
    assert range_row == (0, payload.stat().st_size, "ed2k_transfer")


def test_import_mfc_shared_file_rows_rejects_outside_shared_roots(tmp_path: Path) -> None:
    root = tmp_path / "share"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    payload = outside / "File.bin"
    payload.write_bytes(b"same")
    modified_s = 1_700_000_000
    os.utime(payload, (modified_s, modified_s))
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=modified_s,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name="File.bin",
                size_bytes=payload.stat().st_size,
            )
        ],
    )

    summary = mfc_known_met.import_mfc_shared_file_rows_hashes(
        rust_repo=_rust_repo(),
        metadata_db=tmp_path / "metadata.sqlite",
        known_met=known_met,
        shared_file_rows=[
            {
                "hash": "00112233445566778899aabbccddeeff",
                "name": "File.bin",
                "path": str(payload),
                "sizeBytes": payload.stat().st_size,
            }
        ],
        shared_roots=[root],
        dry_run=True,
    )

    assert summary["matchedRows"] == 0
    assert summary["skipped"]["path_outside_shared_roots"] == 1


def test_path_root_membership_uses_parent_set_without_prefix_false_positive(tmp_path: Path) -> None:
    root = tmp_path / "share"
    nested = root / "nested"
    sibling_prefix = tmp_path / "share-sibling"
    nested.mkdir(parents=True)
    sibling_prefix.mkdir()

    roots = {mfc_known_met._canonical_existing_root(root)}

    assert mfc_known_met._path_is_under_root_set(nested / "File.bin", roots) is True
    assert mfc_known_met._path_is_under_root_set(sibling_prefix / "File.bin", roots) is False


def test_import_mfc_shared_file_rows_requires_known_met_hashset(tmp_path: Path) -> None:
    root = tmp_path / "share"
    root.mkdir()
    payload = root / "File.bin"
    payload.write_bytes(b"same")
    known_met = tmp_path / "known.met"
    _write_known_met(known_met, [])

    summary = mfc_known_met.import_mfc_shared_file_rows_hashes(
        rust_repo=_rust_repo(),
        metadata_db=tmp_path / "metadata.sqlite",
        known_met=known_met,
        shared_file_rows=[
            {
                "hash": "00112233445566778899aabbccddeeff",
                "name": "File.bin",
                "path": str(payload),
                "sizeBytes": payload.stat().st_size,
            }
        ],
        shared_roots=[root],
        dry_run=True,
    )

    assert summary["matchedRows"] == 0
    assert summary["skipped"]["missing_known_met_entry"] == 1


def test_load_shared_file_rows_json_accepts_rest_envelope(tmp_path: Path) -> None:
    inventory = tmp_path / "shared-files.json"
    inventory.write_text(
        '{"data":{"items":[{"hash":"00112233445566778899aabbccddeeff","path":"C:/x","sizeBytes":1}]}}',
        encoding="utf-8",
    )

    rows = mfc_known_met.load_shared_file_rows_json(inventory)

    assert rows == [{"hash": "00112233445566778899aabbccddeeff", "path": "C:/x", "sizeBytes": 1}]
