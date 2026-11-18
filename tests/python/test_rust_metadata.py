from __future__ import annotations

import sqlite3
from pathlib import Path
from emule_test_harness.workspace_layout import resolve_selected_workspace_repo

import pytest

from emule_test_harness import rust_metadata


def rust_repo() -> Path:
    return resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-rust")


def test_local_discovery_initializes_both_current_schema_domains(tmp_path):
    database = tmp_path / "metadata.db"
    rust_metadata.create_metadata_db(rust_repo(), database)
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT domain, status FROM discovery_initialization ORDER BY domain").fetchall() == [
            ("kad", "pending"), ("servers", "pending")
        ]
    rust_metadata.initialize_local_discovery(rust_repo(), database)
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT domain, status FROM discovery_initialization ORDER BY domain").fetchall() == [
            ("kad", "initialized"), ("servers", "initialized")
        ]


def test_local_discovery_missing_domain_rolls_back_without_repair(tmp_path):
    database = tmp_path / "metadata.db"
    rust_metadata.create_metadata_db(rust_repo(), database)
    with sqlite3.connect(database) as conn:
        conn.execute("DELETE FROM discovery_initialization WHERE domain = 'kad'")
    with pytest.raises(RuntimeError, match="both canonical initialization rows"):
        rust_metadata.initialize_local_discovery(rust_repo(), database)
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT domain, status FROM discovery_initialization").fetchall() == [("servers", "pending")]


def test_local_discovery_missing_database_is_not_created(tmp_path):
    database = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        rust_metadata.initialize_local_discovery(rust_repo(), database)
    assert not database.exists()


def test_discovery_snapshot_reads_current_initialization_and_counts(tmp_path):
    database = tmp_path / "metadata.db"
    rust_metadata.create_metadata_db(rust_repo(), database)
    rust_metadata.seed_server(database, {"host": "127.0.0.1", "port": 24661})
    rust_metadata.replace_kad_bootstrap_endpoints(database, ["127.0.0.1:24672"])
    rust_metadata.initialize_local_discovery(rust_repo(), database)
    snapshot = rust_metadata.read_discovery_snapshot(rust_repo(), database)
    assert snapshot == {
        "servers": {"status": "initialized", "count": 1},
        "kad": {"status": "initialized", "revision": 0, "contactCount": 0, "bootstrapEndpointCount": 1},
    }


def test_discovery_snapshot_missing_database_is_not_created(tmp_path):
    database = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        rust_metadata.read_discovery_snapshot(rust_repo(), database)
    assert not database.exists()


def test_discovery_snapshot_rejects_inconsistent_current_marker_without_writes(tmp_path):
    database = tmp_path / "metadata.db"
    rust_metadata.create_metadata_db(rust_repo(), database)
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE metadata_schema SET schema_version=schema_version+1")
    before = database.read_bytes()
    with pytest.raises(RuntimeError, match="current metadata schema marker"):
        rust_metadata.read_discovery_snapshot(rust_repo(), database)
    assert database.read_bytes() == before


def test_discovery_snapshot_does_not_mix_a_concurrent_initialization(tmp_path, monkeypatch):
    database = tmp_path / "metadata.db"
    rust_metadata.create_metadata_db(rust_repo(), database)
    original_connect = sqlite3.connect
    with original_connect(database) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
    seeded = []

    class SnapshotConnection(_TrackedConnection):
        def execute(self, sql, *args):
            cursor = self._connection.execute(sql, *args)
            if sql.startswith("SELECT schema_id") and not seeded:
                seeded.append(True)
                rust_metadata.seed_server(database, {"host": "127.0.0.1", "port": 24661})
            return cursor

    monkeypatch.setattr(rust_metadata.sqlite3, "connect", lambda *args, **kwargs:
                        SnapshotConnection(original_connect(*args, **kwargs)))
    snapshot = rust_metadata.read_discovery_snapshot(rust_repo(), database)
    assert seeded == [True]
    assert snapshot["servers"] == {"status": "pending", "count": 0}
    with original_connect(database) as connection:
        assert connection.execute("SELECT status FROM discovery_initialization WHERE domain='servers'").fetchone() == ("initialized",)
        assert connection.execute("SELECT count(*) FROM servers").fetchone() == (1,)


def test_local_discovery_wrong_current_marker_does_not_mutate(tmp_path):
    database = tmp_path / "metadata.db"
    rust_metadata.create_metadata_db(rust_repo(), database)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE metadata_schema SET schema_version = schema_version + 1")
    with pytest.raises(RuntimeError, match="current metadata schema marker"):
        rust_metadata.initialize_local_discovery(rust_repo(), database)
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT domain, status FROM discovery_initialization ORDER BY domain").fetchall() == [
            ("kad", "pending"), ("servers", "pending")
        ]


@pytest.mark.parametrize("operation", ["seed", "clear"])
def test_server_fixture_mutation_rolls_back_when_initialization_row_missing(tmp_path, operation):
    database = tmp_path / "metadata.db"
    rust_metadata.create_metadata_db(rust_repo(), database)
    rust_metadata.seed_server(database, {"host": "192.0.2.10", "port": 4661})
    with sqlite3.connect(database) as conn:
        conn.execute("DELETE FROM discovery_initialization WHERE domain = 'servers'")
        before = conn.execute("SELECT address, port FROM servers").fetchall()
    with pytest.raises(RuntimeError, match="canonical initialization row"):
        if operation == "seed":
            rust_metadata.seed_server(database, {"host": "192.0.2.20", "port": 4661})
        else:
            rust_metadata.clear_servers(database)
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT address, port FROM servers").fetchall() == before


def test_failed_server_seed_does_not_complete_initialization(tmp_path):
    database = tmp_path / "metadata.db"
    rust_metadata.create_metadata_db(rust_repo(), database)
    with pytest.raises(sqlite3.IntegrityError):
        rust_metadata.seed_server(database, {
            "host": "192.0.2.10", "port": 4661, "serverPriority": "invalid"
        })
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT status FROM discovery_initialization WHERE domain = 'servers'").fetchone() == ("pending",)
        assert conn.execute("SELECT count(*) FROM servers").fetchone() == (0,)


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
def test_download_seed_owns_job_identity_hashsets_and_ranges(tmp_path: Path) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    ed2k_hash = "00112233445566778899aabbccddeeff"
    job_id = rust_metadata.seed_download_job(
        metadata_db, ed2k_hash=ed2k_hash, name="Download.bin",
        size_bytes=8, piece_size=8, completed=True,
        md4_hashset_acquired=True, md4_hashset=["11" * 16],
        aich_hashset_acquired=True, aich_root="22" * 20,
        aich_root_origin="operator_link", aich_hashset=["33" * 20],
    )
    manifest = rust_metadata.read_download_job_manifest(metadata_db, job_id)
    assert manifest is not None
    assert manifest["job_id"] == job_id and manifest["file_hash"] == ed2k_hash
    assert manifest["completed"] is True
    assert manifest["md4_hashset"] == ["11" * 16]
    assert manifest["aich_hashset"] == ["33" * 20]
    assert (manifest["aich_root"], manifest["aich_root_origin"], manifest["aich_trust_generation"]) == (
        "22" * 20, "operator_link", 1,
    )
    assert (manifest["execution_generation"], manifest["selected_temp_path_id"],
            manifest["storage_path_id"], manifest["storage_directory_marker_id"],
            manifest["terminal_completed_at_s"], manifest["completion_history"]) == (
        0, None, None, None, None, None,
    )
    rust_metadata.require_current_profile_database(rust_repo(), metadata_db)
    with sqlite3.connect(metadata_db) as conn:
        assert conn.execute("SELECT prefix_bytes,present_bytes FROM download_job_pieces WHERE job_id=?", (job_id,)).fetchall() == [(8, 8)]
        assert conn.execute("SELECT checkpointed_bytes FROM download_jobs WHERE id=?", (job_id,)).fetchone() == (8,)
        conn.execute("PRAGMA foreign_keys = ON")
        assert conn.execute("SELECT count(*) FROM verified_local_content").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM local_file_instances").fetchone() == (0,)
        assert conn.execute("SELECT lower(hex(aich_root)), aich_root_origin FROM known_files").fetchone() == (
            "22" * 20, "operator_link",
        )
        assert conn.execute("SELECT latest_download_job_id FROM known_files").fetchone() == (int(job_id),)
        conn.execute("UPDATE known_files SET latest_download_job_id = NULL")
        conn.execute("DELETE FROM download_jobs")
        for table in ("download_job_md4_part_hashes", "download_job_aich_part_hashes",
                      "download_job_verified_ranges", "download_job_pieces"):
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM known_files").fetchone() == (1,)
    assert rust_metadata.read_download_job_manifest(metadata_db, job_id) is None


@pytest.mark.unit
@pytest.mark.parametrize("origin", [None, "local_computed", "network_consensus", "stock_import"])
def test_download_seed_requires_explicit_operator_link_provenance(tmp_path: Path, origin: str | None) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    with pytest.raises(ValueError, match="explicit operator_link"):
        rust_metadata.seed_download_job(
            metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
            aich_root="22" * 20, aich_root_origin=origin,
        )
    with sqlite3.connect(metadata_db) as conn:
        assert conn.execute("SELECT count(*) FROM known_files").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM download_jobs").fetchone() == (0,)


@pytest.mark.unit
def test_download_seed_without_root_preserves_no_aich_authority(tmp_path: Path) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    job_id = rust_metadata.seed_download_job(
        metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
        sources=[{"ip": "192.0.2.44", "tcp_port": 4662}],
    )
    manifest = rust_metadata.read_download_job_manifest(metadata_db, job_id)
    assert (manifest["aich_root"], manifest["aich_root_origin"], manifest["aich_trust_generation"]) == (None, None, 0)
    assert manifest["sources"] == [{"ip": "192.0.2.44", "tcp_port": 4662, "user_hash": None}]
    with pytest.raises(ValueError, match="require an accepted root"):
        rust_metadata.seed_download_job(
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
    job_id = rust_metadata.seed_download_job(
        metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
        aich_root="22" * 20, aich_root_origin="operator_link",
    )
    manifest = rust_metadata.read_download_job_manifest(metadata_db, job_id)
    assert (manifest["aich_root"], manifest["aich_root_origin"], manifest["aich_trust_generation"]) == ("22" * 20, origin, 1)
    with sqlite3.connect(metadata_db) as conn:
        assert conn.execute("SELECT aich_root_origin,display_name FROM known_files").fetchone() == (origin, "Accepted.bin")
        assert conn.execute("SELECT count(*) FROM verified_local_content").fetchone() == (0,)


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
        rust_metadata.seed_download_job(
            metadata_db, ed2k_hash="11" * 16, name="Changed.bin", size_bytes=9 if conflict == "size" else 8,
            piece_size=8, aich_root="33" * 20 if conflict == "root" else "22" * 20,
            aich_root_origin="operator_link", completed=True,
        )
    with sqlite3.connect(metadata_db) as conn:
        assert conn.execute("SELECT size_bytes,display_name,aich_root_origin FROM known_files").fetchone() == (
            8, "Accepted.bin", "stock_import",
        )
        assert conn.execute("SELECT count(*) FROM download_jobs").fetchone() == (0,)


@pytest.mark.unit
def test_download_seed_rejects_active_job_reseed_without_losing_progress(tmp_path: Path) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    first_id = rust_metadata.seed_download_job(
        metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
        aich_root="22" * 20, aich_root_origin="operator_link", completed=True,
        md4_hashset_acquired=True, md4_hashset=["33" * 16],
    )
    with sqlite3.connect(metadata_db) as conn:
        before = list(conn.iterdump())
    with pytest.raises(ValueError, match="cannot reseed established"):
        rust_metadata.seed_download_job(
            metadata_db, ed2k_hash="11" * 16, name="Changed.bin", size_bytes=8, piece_size=8,
        )
    with sqlite3.connect(metadata_db) as conn:
        assert list(conn.iterdump()) == before
    assert rust_metadata.read_download_job_manifest(metadata_db, first_id)["md4_hashset"] == ["33" * 16]


@pytest.mark.unit
def test_download_manifest_reads_job_identity_without_known_identity_fallback(tmp_path: Path) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    job_id = rust_metadata.seed_download_job(
        metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
    )
    with sqlite3.connect(metadata_db) as conn:
        conn.execute(
            "UPDATE known_files SET aich_root=?,aich_root_origin='operator_link'",
            (bytes.fromhex("22" * 20),),
        )
    manifest = rust_metadata.read_download_job_manifest(metadata_db, job_id)
    assert (manifest["aich_root"], manifest["aich_root_origin"], manifest["aich_trust_generation"]) == (None, None, 0)
    with sqlite3.connect(metadata_db) as conn:
        conn.execute(
            "UPDATE download_jobs SET aich_root=?,aich_root_origin='network_consensus',aich_trust_generation=7",
            (bytes.fromhex("33" * 20),),
        )
    manifest = rust_metadata.read_download_job_manifest(metadata_db, job_id)
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
            "first_completed_at_s,last_completed_at_s) VALUES (?,8,'History.bin',?,0,0)",
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
        rust_metadata.seed_download_job(
            metadata_db, ed2k_hash="11" * 16, name="Changed.bin", size_bytes=9 if conflict == "size" else 8,
            piece_size=8, aich_root=supplied_root,
            aich_root_origin="operator_link" if supplied_root is not None else None,
        )
    with sqlite3.connect(metadata_db) as conn:
        assert list(conn.iterdump()) == before


@pytest.mark.unit
def test_download_seed_rolls_back_late_failure_and_does_not_reuse_job_id(tmp_path: Path) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    first_id = rust_metadata.seed_download_job(
        metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
        completed=True, md4_hashset_acquired=True, md4_hashset=["22" * 16],
    )
    with sqlite3.connect(metadata_db) as conn:
        before = list(conn.iterdump())
    with pytest.raises(ValueError, match="fromhex"):
        rust_metadata.seed_download_job(
            metadata_db, ed2k_hash="33" * 16, name="Changed.bin", size_bytes=8, piece_size=8,
            md4_hashset=["invalid-hash"],
        )
    with sqlite3.connect(metadata_db) as conn:
        assert list(conn.iterdump()) == before
        conn.execute("UPDATE known_files SET latest_download_job_id = NULL")
        conn.execute("DELETE FROM download_jobs WHERE id = ?", (int(first_id),))
    second_id = rust_metadata.seed_download_job(
        metadata_db, ed2k_hash="44" * 16, name="New.bin", size_bytes=8, piece_size=8,
    )
    assert int(second_id) > int(first_id)
    assert rust_metadata.read_download_job_manifest(metadata_db, first_id) is None


@pytest.mark.unit
def test_current_profile_preflight_requires_current_job_tables(tmp_path: Path) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    with sqlite3.connect(metadata_db) as conn:
        conn.execute("DROP TABLE download_job_sources")
    with pytest.raises(RuntimeError, match="download_job_sources"):
        rust_metadata.require_current_profile_database(rust_repo(), metadata_db)


@pytest.mark.unit
def test_download_manifest_read_holds_one_snapshot_across_retirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)
    job_id = rust_metadata.seed_download_job(
        metadata_db, ed2k_hash="11" * 16, name="Download.bin", size_bytes=8, piece_size=8,
        md4_hashset_acquired=True, md4_hashset=["22" * 16],
        sources=[{"ip": "192.0.2.44", "tcp_port": 4662}],
    )
    with sqlite3.connect(metadata_db) as conn:
        assert conn.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    real_connect = sqlite3.connect
    retired = False

    class SnapshotConnection(sqlite3.Connection):
        def execute(self, sql, parameters=(), /):
            nonlocal retired
            if "FROM download_job_sources WHERE job_id" in sql and not retired:
                retired = True
                with real_connect(metadata_db) as writer:
                    writer.execute("DELETE FROM download_job_sources WHERE job_id = ?", (int(job_id),))
                    writer.execute("DELETE FROM download_job_md4_part_hashes WHERE job_id = ?", (int(job_id),))
            return super().execute(sql, parameters)

    def connection_with_interleaved_retirement(database, *args, **kwargs):
        if "mode=ro" in str(database):
            kwargs["factory"] = SnapshotConnection
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(rust_metadata.sqlite3, "connect", connection_with_interleaved_retirement)
    manifest = rust_metadata.read_download_job_manifest(metadata_db, job_id)
    assert retired is True
    assert manifest["sources"] == [{"ip": "192.0.2.44", "tcp_port": 4662, "user_hash": None}]
    assert manifest["md4_hashset"] == ["22" * 16]
    with real_connect(metadata_db) as conn:
        assert conn.execute("SELECT count(*) FROM download_job_sources").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM download_job_md4_part_hashes").fetchone() == (0,)


def test_search_observation_fixture_preserves_session_and_global_count_boundaries(tmp_path):
    database = tmp_path / "metadata.db"
    rust_metadata.create_metadata_db(rust_repo(), database)
    fixture = rust_metadata.seed_search_observation_fixture(rust_repo(), database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        counts = connection.execute(
            "SELECT o.observation_count,m.observation_count,o.first_seen_at_s,m.first_seen_at_s "
            "FROM search_result_observations m JOIN content_claim_observations o ON o.id=m.observation_id "
            "WHERE m.session_id=? ORDER BY o.id", (int(fixture["sessionId"]),),
        ).fetchall()
        assert counts == [(3,1,10,20),(1,1,30,30)]
        assert connection.execute("SELECT result_count FROM search_sessions WHERE id=?",(int(fixture["sessionId"]),)).fetchone() == (1,)
