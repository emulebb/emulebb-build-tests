from __future__ import annotations

import sqlite3
from pathlib import Path
from emule_test_harness.paths import get_required_emule_workspace_root as _workspace_root_from_environment

import pytest

from emule_test_harness import rust_metadata


def rust_repo() -> Path:
    return _workspace_root_from_environment() / "repos" / "emulebb-rust"


class _TrackedConnection:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self.closed = False

    def __enter__(self) -> _TrackedConnection:
        return self

    def __exit__(self, *args: object) -> bool:
        return self._connection.__exit__(*args)

    def __getattr__(self, name: str) -> object:
        return getattr(self._connection, name)

    def close(self) -> None:
        self.closed = True
        self._connection.close()


@pytest.mark.unit
def test_metadata_writes_close_sqlite_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    with sqlite3.connect(metadata_db) as connection:
        connection.execute(
            "CREATE TABLE settings(section TEXT, key TEXT, value_json TEXT, updated_at_ms INTEGER, "
            "PRIMARY KEY(section, key))"
        )

    original_connect = sqlite3.connect
    tracked: list[_TrackedConnection] = []

    def connect(*args: object, **kwargs: object) -> _TrackedConnection:
        connection = _TrackedConnection(original_connect(*args, **kwargs))
        tracked.append(connection)
        return connection

    monkeypatch.setattr(rust_metadata.sqlite3, "connect", connect)

    rust_metadata.put_setting_json(metadata_db, "network", "enabled", True)

    assert len(tracked) == 1
    assert tracked[0].closed is True


@pytest.mark.unit
def test_seed_indexed_file_persists_explicit_origin_metadata(tmp_path: Path) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)

    rust_metadata.seed_indexed_file(
        metadata_db,
        ed2k_hash="00112233445566778899aabbccddeeff",
        name="Passive Cache Result.bin",
        size_bytes=4096,
        content_type="archive",
        availability_score=2,
        origin="passive_cache",
    )

    with sqlite3.connect(metadata_db) as connection:
        file_origin = connection.execute(
            "SELECT origin, size_bytes, content_type, availability_score "
            "FROM known_file_origins"
        ).fetchone()
        name_origin = connection.execute(
            "SELECT origin FROM file_name_origins"
        ).fetchone()

    assert file_origin == ("passive_cache", 4096, "archive", 2)
    assert name_origin == ("passive_cache",)


@pytest.mark.unit
def test_download_seed_owns_flags_hashsets_and_ranges(tmp_path: Path) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    ed2k_hash = "00112233445566778899aabbccddeeff"
    rust_metadata.seed_transfer_manifest(
        metadata_db, ed2k_hash=ed2k_hash, name="Download.bin",
        size_bytes=8, piece_size=8, completed=True,
        md4_hashset_acquired=True, md4_hashset=["11" * 16],
        aich_hashset_acquired=True, aich_root="22" * 20,
        aich_root_origin="operator_link",
        aich_hashset=["33" * 20],
    )
    manifest = rust_metadata.read_transfer_manifest(metadata_db, ed2k_hash)
    assert manifest is not None
    assert manifest["completed"] is True
    assert manifest["md4_hashset"] == ["11" * 16]
    assert manifest["aich_hashset"] == ["33" * 20]
    assert manifest["aich_root"] == "22" * 20
    assert manifest["aich_root_origin"] == "operator_link"
    assert manifest["aich_trust_generation"] == 1
    assert "source_path" not in manifest
    rust_metadata.require_current_profile_database(rust_repo(), metadata_db)
    with sqlite3.connect(metadata_db) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        assert conn.execute("SELECT count(*) FROM verified_local_content").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM local_file_instances").fetchone() == (0,)
        assert conn.execute("SELECT lower(hex(aich_root)), aich_root_origin FROM known_files").fetchone() == (
            "22" * 20, "operator_link",
        )
        conn.execute("DELETE FROM transfers")
        for table in ("transfer_md4_part_hashes", "transfer_aich_part_hashes", "verified_ranges", "transfer_name_state"):
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM known_files").fetchone() == (1,)
    assert rust_metadata.read_transfer_manifest(metadata_db, ed2k_hash) is None


@pytest.mark.unit
@pytest.mark.parametrize("origin", [None, "local_computed", "network_consensus", "stock_import"])
def test_download_seed_requires_explicit_operator_link_provenance(tmp_path: Path, origin: str | None) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    with pytest.raises(ValueError, match="explicit operator_link"):
        rust_metadata.seed_transfer_manifest(
            metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
            aich_root="22" * 20, aich_root_origin=origin,
        )
    with sqlite3.connect(metadata_db) as conn:
        assert conn.execute("SELECT count(*) FROM known_files").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM transfers").fetchone() == (0,)


@pytest.mark.unit
def test_download_seed_without_root_preserves_no_aich_authority(tmp_path: Path) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    rust_metadata.seed_remembered_source_transfer(
        metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
        source_ip="192.0.2.44", source_tcp_port=4662,
    )
    manifest = rust_metadata.read_transfer_manifest(metadata_db, "11" * 16)
    assert (manifest["aich_root"], manifest["aich_root_origin"], manifest["aich_trust_generation"]) == (None, None, 0)
    with pytest.raises(ValueError, match="require an accepted root"):
        rust_metadata.seed_transfer_manifest(
            metadata_db, ed2k_hash="33" * 16, name="Invalid.bin", size_bytes=8, piece_size=8,
            aich_hashset_acquired=True,
        )
    with sqlite3.connect(metadata_db) as conn:
        assert conn.execute("SELECT count(*) FROM known_files").fetchone() == (1,)


@pytest.mark.unit
@pytest.mark.parametrize("origin", ["local_computed", "stock_import"])
def test_download_seed_inherits_stronger_accepted_identity_without_local_rows(tmp_path: Path, origin: str) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    with sqlite3.connect(metadata_db) as conn:
        conn.execute(
            "INSERT INTO known_files(ed2k_hash,size_bytes,display_name,aich_root,aich_root_origin,"
            "first_seen_at_ms,last_seen_at_ms,updated_at_ms) VALUES (?,8,'Accepted.bin',?,?,0,0,0)",
            (bytes.fromhex("11" * 16), bytes.fromhex("22" * 20), origin),
        )
    rust_metadata.seed_transfer_manifest(
        metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
        aich_root="22" * 20, aich_root_origin="operator_link",
    )
    manifest = rust_metadata.read_transfer_manifest(metadata_db, "11" * 16)
    assert (manifest["aich_root"], manifest["aich_root_origin"], manifest["aich_trust_generation"]) == ("22" * 20, origin, 1)
    with sqlite3.connect(metadata_db) as conn:
        assert conn.execute("SELECT aich_root_origin FROM known_files").fetchone() == (origin,)
        assert conn.execute("SELECT count(*) FROM verified_local_content").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM local_file_instances").fetchone() == (0,)


@pytest.mark.unit
@pytest.mark.parametrize("conflict", ["root", "size"])
def test_download_seed_rejects_accepted_identity_conflicts_before_mutation(tmp_path: Path, conflict: str) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    with sqlite3.connect(metadata_db) as conn:
        conn.execute(
            "INSERT INTO known_files(ed2k_hash,size_bytes,display_name,aich_root,aich_root_origin,"
            "first_seen_at_ms,last_seen_at_ms,updated_at_ms) VALUES (?,8,'Accepted.bin',?,'stock_import',0,0,0)",
            (bytes.fromhex("11" * 16), bytes.fromhex("22" * 20)),
        )
    with pytest.raises(ValueError, match="conflicts with accepted"):
        rust_metadata.seed_transfer_manifest(
            metadata_db, ed2k_hash="11" * 16, name="Changed.bin", size_bytes=9 if conflict == "size" else 8,
            piece_size=8, aich_root="33" * 20 if conflict == "root" else "22" * 20,
            aich_root_origin="operator_link", completed=True,
        )
    with sqlite3.connect(metadata_db) as conn:
        assert conn.execute("SELECT size_bytes,display_name,aich_root_origin FROM known_files").fetchone() == (
            8, "Accepted.bin", "stock_import",
        )
        assert conn.execute("SELECT count(*) FROM transfers").fetchone() == (0,)


@pytest.mark.unit
def test_download_seed_rejects_authority_reseed_without_losing_progress(tmp_path: Path) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    rust_metadata.seed_transfer_manifest(
        metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
        aich_root="22" * 20, aich_root_origin="operator_link", completed=True,
        md4_hashset_acquired=True, md4_hashset=["33" * 16],
    )
    with sqlite3.connect(metadata_db) as conn:
        before = list(conn.iterdump())
    with pytest.raises(ValueError, match="cannot reseed established"):
        rust_metadata.seed_transfer_manifest(
            metadata_db, ed2k_hash="11" * 16, name="Changed.bin", size_bytes=8, piece_size=8,
        )
    with sqlite3.connect(metadata_db) as conn:
        assert list(conn.iterdump()) == before


@pytest.mark.unit
def test_download_manifest_reads_transfer_identity_without_known_identity_fallback(tmp_path: Path) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    rust_metadata.seed_transfer_manifest(
        metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
    )
    with sqlite3.connect(metadata_db) as conn:
        conn.execute(
            "UPDATE known_files SET aich_root=?,aich_root_origin='operator_link'",
            (bytes.fromhex("22" * 20),),
        )
    manifest = rust_metadata.read_transfer_manifest(metadata_db, "11" * 16)
    assert (manifest["aich_root"], manifest["aich_root_origin"], manifest["aich_trust_generation"]) == (None, None, 0)
    with sqlite3.connect(metadata_db) as conn:
        conn.execute(
            "UPDATE transfers SET aich_root=?,aich_root_origin='network_consensus',aich_trust_generation=7",
            (bytes.fromhex("33" * 20),),
        )
    manifest = rust_metadata.read_transfer_manifest(metadata_db, "11" * 16)
    assert (manifest["aich_root"], manifest["aich_root_origin"], manifest["aich_trust_generation"]) == (
        "33" * 20, "network_consensus", 7,
    )


@pytest.mark.unit
@pytest.mark.parametrize("conflict", ["root", "size", "inherited-root"])
def test_download_seed_preserves_completed_history_authority(tmp_path: Path, conflict: str) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    with sqlite3.connect(metadata_db) as conn:
        conn.execute(
            "INSERT INTO download_history(ed2k_hash,size_bytes,display_name,aich_root,"
            "first_completed_at_ms,last_completed_at_ms) VALUES (?,8,'History.bin',?,0,0)",
            (bytes.fromhex("11" * 16), bytes.fromhex("22" * 20)),
        )
        if conflict == "inherited-root":
            conn.execute(
                "INSERT INTO known_files(ed2k_hash,size_bytes,display_name,aich_root,aich_root_origin,"
                "first_seen_at_ms,last_seen_at_ms,updated_at_ms) VALUES (?,8,'Accepted.bin',?,'stock_import',0,0,0)",
                (bytes.fromhex("11" * 16), bytes.fromhex("33" * 20)),
            )
        before = list(conn.iterdump())
    supplied_root = None if conflict == "inherited-root" else ("33" * 20 if conflict == "root" else "22" * 20)
    with pytest.raises(ValueError, match="conflicts with accepted download history"):
        rust_metadata.seed_transfer_manifest(
            metadata_db, ed2k_hash="11" * 16, name="Changed.bin", size_bytes=9 if conflict == "size" else 8,
            piece_size=8, aich_root=supplied_root,
            aich_root_origin="operator_link" if supplied_root is not None else None,
        )
    with sqlite3.connect(metadata_db) as conn:
        assert list(conn.iterdump()) == before


@pytest.mark.unit
def test_download_seed_rolls_back_late_failure_without_losing_md4_progress(tmp_path: Path) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    rust_metadata.seed_transfer_manifest(
        metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
        completed=True, md4_hashset_acquired=True, md4_hashset=["22" * 16],
    )
    with sqlite3.connect(metadata_db) as conn:
        before = list(conn.iterdump())
    with pytest.raises(ValueError, match="fromhex"):
        rust_metadata.seed_transfer_manifest(
            metadata_db, ed2k_hash="11" * 16, name="Changed.bin", size_bytes=8, piece_size=8,
            md4_hashset=["invalid-hash"],
        )
    with sqlite3.connect(metadata_db) as conn:
        assert list(conn.iterdump()) == before
