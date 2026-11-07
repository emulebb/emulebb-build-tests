from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from emule_test_harness import rust_metadata


def rust_repo() -> Path:
    return Path(__file__).resolve().parents[4] / "repos" / "emulebb-rust"


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
        aich_hashset=["33" * 20],
    )
    manifest = rust_metadata.read_transfer_manifest(metadata_db, ed2k_hash)
    assert manifest is not None
    assert manifest["completed"] is True
    assert manifest["md4_hashset"] == ["11" * 16]
    assert manifest["aich_hashset"] == ["33" * 20]
    assert "source_path" not in manifest
    rust_metadata.require_current_profile_database(rust_repo(), metadata_db)
    with sqlite3.connect(metadata_db) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        assert conn.execute("SELECT count(*) FROM verified_local_content").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM local_file_instances").fetchone() == (0,)
        conn.execute("DELETE FROM transfers")
        for table in ("transfer_md4_part_hashes", "transfer_aich_part_hashes", "verified_ranges", "transfer_name_state"):
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM known_files").fetchone() == (1,)
    assert rust_metadata.read_transfer_manifest(metadata_db, ed2k_hash) is None
