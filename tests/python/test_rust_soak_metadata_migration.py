from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from emule_test_harness import rust_metadata
from emule_test_harness.rust_soak_metadata_migration import (
    build_parser,
    migrate_to_current,
    migrate_v16_to_v17,
    migrate_v18_to_v19,
    migrate_v19_to_v20,
    migrate_v20_to_v21,
    migrate_v21_to_v22,
    migrate_v22_to_v23,
    migrate_v23_to_v24,
)

KNOWN_FILES_MEDIA_COLUMNS_FOR_TEST = (
    "media_artist",
    "media_album",
    "media_title",
    "media_length_seconds",
    "media_bitrate_kbps",
    "media_codec",
    "media_extractor_version",
)

KNOWN_FILES_MEDIA_DDL_LINES = (
    "    media_artist TEXT NOT NULL DEFAULT '',\n",
    "    media_album TEXT NOT NULL DEFAULT '',\n",
    "    media_title TEXT NOT NULL DEFAULT '',\n",
    "    media_length_seconds INTEGER NOT NULL DEFAULT 0 CHECK(media_length_seconds >= 0),\n",
    "    media_bitrate_kbps INTEGER NOT NULL DEFAULT 0 CHECK(media_bitrate_kbps >= 0),\n",
    "    media_codec TEXT NOT NULL DEFAULT '',\n",
    "    media_extractor_version INTEGER NOT NULL DEFAULT 0 CHECK(media_extractor_version >= 0),\n",
)


def schema_without_media_metadata(schema_sql: str) -> str:
    for line in KNOWN_FILES_MEDIA_DDL_LINES:
        schema_sql = schema_sql.replace(line, "")
    return schema_sql


def schema_without_final_rehash_gate(schema_sql: str) -> str:
    schema_sql = schema_sql.replace(
        "CHECK(visible_state IN ('completed', 'completing', 'downloading', 'queued'))",
        "CHECK(visible_state IN ('completed', 'downloading', 'queued'))",
    )
    return schema_sql.replace(
        "    -- Set after all parts verify and cleared only after the authoritative\n"
        "    -- whole-file ED2K MD4 completion rehash succeeds or demotes bad parts.\n"
        "    final_rehash_pending INTEGER NOT NULL DEFAULT 0\n"
        "        CHECK(final_rehash_pending IN (0, 1)),\n",
        "",
    )


def workspace_root() -> Path:
    return Path(__file__).resolve().parents[4]


def rust_repo() -> Path:
    return workspace_root() / "repos" / "emulebb-rust"


def make_v15_db(path: Path) -> None:
    schema_id, _schema_version = rust_metadata._schema_marker(rust_repo())
    with sqlite3.connect(path) as conn:
        conn.executescript(
            schema_without_media_metadata(
                schema_without_final_rehash_gate(
                    rust_metadata._schema_sql(rust_repo())
                )
            )
        )
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, 15, 0)",
            (schema_id,),
        )
        conn.execute(
            "INSERT INTO profile(id, uuid, created_by, created_at_ms, updated_at_ms) VALUES (1, 'profile', 'test', 0, 0)"
        )
        conn.execute(
            "ALTER TABLE shared_directory_roots ADD COLUMN recursive INTEGER NOT NULL DEFAULT 0 CHECK(recursive IN (0, 1))"
        )
        conn.execute(
            """
            INSERT INTO local_paths(
                display_path, native_path, canonical_display_path, normalized_key,
                platform, file_identity_kind, file_identity, size_bytes, mtime_ms,
                last_stat_ms
            )
            VALUES ('C:/share', X'433A2F7368617265', 'C:/share', 'c:/share',
                    'windows', NULL, NULL, NULL, NULL, NULL)
            """
        )
        path_id = conn.execute("SELECT id FROM local_paths").fetchone()[0]
        conn.execute(
            """
            INSERT INTO shared_directory_roots(
                path_id, recursive, monitor_owned, shareable, accessible,
                enabled, last_scan_ms, created_at_ms, deleted_at_ms
            )
            VALUES (?, 1, 0, 1, 1, 1, 123, 0, NULL)
            """,
            (path_id,),
        )
        conn.commit()


def make_v16_db_with_old_priority_check(path: Path) -> None:
    schema_id, _schema_version = rust_metadata._schema_marker(rust_repo())
    old_schema = schema_without_media_metadata(
        schema_without_final_rehash_gate(rust_metadata._schema_sql(rust_repo()))
    ).replace(
        "'auto', 'not-published', 'verylow', 'low', 'normal', 'high', 'release'",
        "'auto', 'verylow', 'low', 'normal', 'high', 'release'",
    )
    with sqlite3.connect(path) as conn:
        conn.executescript(old_schema)
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, 16, 0)",
            (schema_id,),
        )
        conn.execute(
            """
            INSERT INTO known_files(
                ed2k_hash, size_bytes, display_name, upload_priority,
                first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (zeroblob(16), 1, 'sample.bin', 'normal', 0, 0, 0)
            """
        )
        conn.commit()


def assert_known_files_accepts_not_published(db_path: Path) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO known_files(
                ed2k_hash, size_bytes, display_name, upload_priority,
                first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (X'11111111111111111111111111111111', 1, 'hidden.bin', 'not-published', 0, 0, 0)
            """
        )
        conn.commit()


def make_v18_db_without_server_udp_metadata(path: Path) -> None:
    schema_id, _schema_version = rust_metadata._schema_marker(rust_repo())
    old_schema = schema_without_final_rehash_gate(
        rust_metadata._schema_sql(rust_repo())
    )
    for line in (
        "    max_users INTEGER CHECK(max_users IS NULL OR max_users >= 0),\n",
        "    low_id_users INTEGER CHECK(low_id_users IS NULL OR low_id_users >= 0),\n",
        "    obfuscation_udp_port INTEGER CHECK(obfuscation_udp_port IS NULL OR obfuscation_udp_port BETWEEN 1 AND 65535),\n",
        "    udp_key INTEGER CHECK(udp_key IS NULL OR udp_key BETWEEN 1 AND 4294967295),\n",
        "    udp_key_ip INTEGER CHECK(udp_key_ip IS NULL OR udp_key_ip BETWEEN 1 AND 4294967295),\n",
    ):
        old_schema = old_schema.replace(line, "")
    with sqlite3.connect(path) as conn:
        conn.executescript(old_schema)
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, 18, 0)",
            (schema_id,),
        )
        conn.execute(
            "INSERT INTO profile(id, uuid, created_by, created_at_ms, updated_at_ms) VALUES (1, 'profile', 'test', 0, 0)"
        )
        conn.execute(
            """
            INSERT INTO servers(
                address, port, name, first_seen_ms, last_seen_ms
            ) VALUES ('192.0.2.10', 4661, 'legacy server', 0, 0)
            """
        )
        conn.commit()


def make_v19_db_without_source_connect_options(path: Path) -> None:
    schema_id, _schema_version = rust_metadata._schema_marker(rust_repo())
    old_schema = schema_without_final_rehash_gate(
        rust_metadata._schema_sql(rust_repo())
    ).replace(
        "    connect_options INTEGER CHECK(connect_options IS NULL OR connect_options BETWEEN 0 AND 255),\n",
        "",
    )
    old_schema = old_schema.replace("    file_comment TEXT NOT NULL DEFAULT '',\n", "")
    old_schema = old_schema.replace(
        "    file_rating INTEGER NOT NULL DEFAULT 0 CHECK(file_rating BETWEEN 0 AND 255),\n",
        "",
    )
    with sqlite3.connect(path) as conn:
        conn.executescript(old_schema)
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, 19, 0)",
            (schema_id,),
        )
        conn.execute(
            "INSERT INTO known_files(ed2k_hash, size_bytes, display_name, first_seen_ms, last_seen_ms, updated_at_ms) "
            "VALUES (zeroblob(16), 1, 'sample.bin', 0, 0, 0)"
        )
        known_file_id = conn.execute("SELECT id FROM known_files").fetchone()[0]
        conn.execute(
            "INSERT INTO transfers(known_file_id, visible_state, created_at_ms, updated_at_ms) "
            "VALUES (?, 'downloading', 0, 0)",
            (known_file_id,),
        )
        transfer_id = conn.execute("SELECT id FROM transfers").fetchone()[0]
        conn.execute(
            "INSERT INTO transfer_sources(transfer_id, ip, tcp_port, first_seen_ms, last_seen_ms) "
            "VALUES (?, '192.0.2.20', 4662, 0, 0)",
            (transfer_id,),
        )
        conn.commit()


def make_v20_db_without_source_file_descriptions(path: Path) -> None:
    schema_id, _schema_version = rust_metadata._schema_marker(rust_repo())
    old_schema = schema_without_final_rehash_gate(
        rust_metadata._schema_sql(rust_repo())
    ).replace(
        "    file_comment TEXT NOT NULL DEFAULT '',\n", ""
    )
    old_schema = old_schema.replace(
        "    file_rating INTEGER NOT NULL DEFAULT 0 CHECK(file_rating BETWEEN 0 AND 255),\n",
        "",
    )
    with sqlite3.connect(path) as conn:
        conn.executescript(old_schema)
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, 20, 0)",
            (schema_id,),
        )
        conn.execute(
            "INSERT INTO known_files(ed2k_hash, size_bytes, display_name, first_seen_ms, last_seen_ms, updated_at_ms) "
            "VALUES (zeroblob(16), 1, 'sample.bin', 0, 0, 0)"
        )
        known_file_id = conn.execute("SELECT id FROM known_files").fetchone()[0]
        conn.execute(
            "INSERT INTO transfers(known_file_id, visible_state, created_at_ms, updated_at_ms) "
            "VALUES (?, 'downloading', 0, 0)",
            (known_file_id,),
        )
        transfer_id = conn.execute("SELECT id FROM transfers").fetchone()[0]
        conn.execute(
            "INSERT INTO transfer_sources(transfer_id, ip, tcp_port, connect_options, first_seen_ms, last_seen_ms) "
            "VALUES (?, '192.0.2.21', 4662, 7, 0, 0)",
            (transfer_id,),
        )
        conn.commit()


def make_v21_db_without_extended_server_metadata(path: Path) -> None:
    schema_id, _schema_version = rust_metadata._schema_marker(rust_repo())
    old_schema = schema_without_final_rehash_gate(
        rust_metadata._schema_sql(rust_repo())
    )
    old_schema = old_schema.replace("    dynamic_host TEXT NOT NULL DEFAULT '',\n", "")
    old_schema = old_schema.replace("    auxiliary_ports TEXT NOT NULL DEFAULT '',\n", "")
    with sqlite3.connect(path) as conn:
        conn.executescript(old_schema)
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, 21, 0)",
            (schema_id,),
        )
        conn.execute(
            "INSERT INTO servers(address, port, name, first_seen_ms, last_seen_ms) "
            "VALUES ('192.0.2.10', 4661, 'legacy server', 0, 0)"
        )
        conn.commit()


def make_v22_db_without_media_metadata(path: Path) -> None:
    schema_id, _schema_version = rust_metadata._schema_marker(rust_repo())
    old_schema = schema_without_media_metadata(
        schema_without_final_rehash_gate(rust_metadata._schema_sql(rust_repo()))
    )
    with sqlite3.connect(path) as conn:
        conn.executescript(old_schema)
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, 22, 0)",
            (schema_id,),
        )
        conn.execute(
            "INSERT INTO known_files(ed2k_hash, size_bytes, display_name, first_seen_ms, last_seen_ms, updated_at_ms) "
            "VALUES (zeroblob(16), 1, 'sample.mp3', 0, 0, 0)"
        )
        conn.commit()


def make_v23_db_without_final_rehash_gate(path: Path) -> None:
    schema_id, _schema_version = rust_metadata._schema_marker(rust_repo())
    old_schema = schema_without_final_rehash_gate(
        rust_metadata._schema_sql(rust_repo())
    )
    with sqlite3.connect(path) as conn:
        conn.executescript(old_schema)
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, 23, 0)",
            (schema_id,),
        )
        for path_id, display_path in (
            (1, "C:/incoming/delivered.bin"),
            (2, "C:/share/shared.bin"),
        ):
            conn.execute(
                """
                INSERT INTO local_paths(
                    id, display_path, native_path, canonical_display_path,
                    normalized_key, platform
                ) VALUES (?, ?, ?, ?, ?, 'windows')
                """,
                (
                    path_id,
                    display_path,
                    display_path.encode(),
                    display_path,
                    display_path.lower(),
                ),
            )
        rows = (
            (1, "pending.bin", 1, "completed", None, None, None, 50),
            (2, "delivered.bin", 1, "completed", 1, None, None, 50),
            (3, "shared.bin", 1, "completed", None, 2, None, 50),
            (4, "incomplete.bin", 0, "downloading", None, None, None, None),
            (5, "removed.bin", 1, "completed", None, None, 60, 50),
        )
        for row_id, name, completed, state, delivered, source, removed, completed_at in rows:
            conn.execute(
                """
                INSERT INTO known_files(
                    id, ed2k_hash, size_bytes, display_name, completed,
                    first_seen_ms, last_seen_ms, updated_at_ms
                ) VALUES (?, ?, 1, ?, ?, 0, 0, 0)
                """,
                (row_id, bytes([row_id]) * 16, name, completed),
            )
            conn.execute(
                """
                INSERT INTO transfers(
                    id, known_file_id, visible_state, delivered_path_id,
                    source_path_id, created_at_ms, updated_at_ms,
                    completed_at_ms, removed_at_ms
                ) VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?)
                """,
                (
                    row_id,
                    row_id,
                    state,
                    delivered,
                    source,
                    completed_at,
                    removed,
                ),
            )
        conn.commit()


def test_migrates_v15_soak_metadata_to_current_shape(tmp_path: Path) -> None:
    db_path = tmp_path / "emulebb-rust-metadata.db"
    make_v15_db(db_path)
    _schema_id, current_schema_version = rust_metadata._schema_marker(rust_repo())

    result = migrate_to_current(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )

    assert result["action"] == "migrated-to-current"
    assert [step["action"] for step in result["steps"]] == [
        "migrated-v15-to-v16",
        "migrated-v16-to-v17",
        "finalized-v17-to-v18",
        "migrated-v18-to-v19",
        "migrated-v19-to-v20",
        "migrated-v20-to-v21",
        "migrated-v21-to-v22",
        "migrated-v22-to-v23",
        "migrated-v23-to-v24",
    ]
    assert all(Path(str(step["backup"])).is_file() for step in result["steps"])
    with sqlite3.connect(db_path) as conn:
        assert (
            conn.execute("SELECT schema_version FROM metadata_schema").fetchone()[0]
            == current_schema_version
        )
        columns = [
            row[1] for row in conn.execute("PRAGMA table_info(shared_directory_roots)")
        ]
        assert "recursive" not in columns
        assert (
            conn.execute("SELECT count(*) FROM imported_known_files").fetchone()[0] == 0
        )
        assert (
            conn.execute("SELECT count(*) FROM shared_directory_roots").fetchone()[0]
            == 1
        )
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert_known_files_accepts_not_published(db_path)


def test_cli_marks_migration_as_internal_harness_only() -> None:
    description = build_parser().description or ""

    assert "test and soak profiles" in description
    assert "not a supported end-user migration" in description


def test_migrates_v16_known_files_priority_constraint_to_v17(tmp_path: Path) -> None:
    db_path = tmp_path / "emulebb-rust-metadata.db"
    make_v16_db_with_old_priority_check(db_path)

    result = migrate_v16_to_v17(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )

    assert result["action"] == "migrated-v16-to-v17"
    assert Path(str(result["backup"])).is_file()
    with sqlite3.connect(db_path) as conn:
        assert (
            conn.execute("SELECT schema_version FROM metadata_schema").fetchone()[0]
            == 17
        )
        assert conn.execute("SELECT count(*) FROM known_files").fetchone()[0] == 1
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert_known_files_accepts_not_published(db_path)


def test_current_schema_is_noop(tmp_path: Path) -> None:
    db_path = tmp_path / "emulebb-rust-metadata.db"
    rust_metadata.create_metadata_db(rust_repo(), db_path)

    result = migrate_to_current(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )

    assert result["action"] == "noop-current"
    assert result["steps"] == []


def test_migrates_v18_server_udp_metadata_to_v19(tmp_path: Path) -> None:
    db_path = tmp_path / "emulebb-rust-metadata.db"
    make_v18_db_without_server_udp_metadata(db_path)

    result = migrate_v18_to_v19(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )

    assert result["action"] == "migrated-v18-to-v19"
    assert Path(str(result["backup"])).is_file()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT schema_version FROM metadata_schema").fetchone()[0] == 19
        columns = [row[1] for row in conn.execute("PRAGMA table_info(servers)")]
        assert "obfuscation_udp_port" in columns
        assert "udp_key" in columns
        assert "udp_key_ip" in columns
        assert "max_users" in columns
        assert "low_id_users" in columns
        assert conn.execute("SELECT count(*) FROM servers").fetchone()[0] == 1
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_migrates_v19_source_connect_options_to_v20(tmp_path: Path) -> None:
    db_path = tmp_path / "emulebb-rust-metadata.db"
    make_v19_db_without_source_connect_options(db_path)

    result = migrate_v19_to_v20(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )

    assert result["action"] == "migrated-v19-to-v20"
    assert Path(str(result["backup"])).is_file()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT schema_version FROM metadata_schema").fetchone()[0] == 20
        columns = [row[1] for row in conn.execute("PRAGMA table_info(transfer_sources)")]
        assert "connect_options" in columns
        assert conn.execute(
            "SELECT connect_options FROM transfer_sources"
        ).fetchone() == (None,)
        conn.execute("UPDATE transfer_sources SET connect_options = 7")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE transfer_sources SET connect_options = 256")
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_migrates_v20_source_file_descriptions_to_v21(tmp_path: Path) -> None:
    db_path = tmp_path / "emulebb-rust-metadata.db"
    make_v20_db_without_source_file_descriptions(db_path)

    result = migrate_v20_to_v21(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )

    assert result["action"] == "migrated-v20-to-v21"
    assert Path(str(result["backup"])).is_file()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT schema_version FROM metadata_schema").fetchone()[0] == 21
        columns = [row[1] for row in conn.execute("PRAGMA table_info(transfer_sources)")]
        assert "file_comment" in columns
        assert "file_rating" in columns
        assert conn.execute(
            "SELECT file_comment, file_rating FROM transfer_sources"
        ).fetchone() == ("", 0)
        conn.execute(
            "UPDATE transfer_sources SET file_comment = 'useful', file_rating = 255"
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE transfer_sources SET file_rating = 256")
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_migrates_v21_extended_server_metadata_to_v22(tmp_path: Path) -> None:
    db_path = tmp_path / "emulebb-rust-metadata.db"
    make_v21_db_without_extended_server_metadata(db_path)

    result = migrate_v21_to_v22(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )

    assert result["action"] == "migrated-v21-to-v22"
    assert Path(str(result["backup"])).is_file()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT schema_version FROM metadata_schema").fetchone()[0] == 22
        columns = [row[1] for row in conn.execute("PRAGMA table_info(servers)")]
        assert "dynamic_host" in columns
        assert "auxiliary_ports" in columns
        assert conn.execute(
            "SELECT dynamic_host, auxiliary_ports FROM servers"
        ).fetchone() == ("", "")
        conn.execute(
            "UPDATE servers SET dynamic_host = 'server.example', auxiliary_ports = '4662,4663'"
        )
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_migrates_v22_media_metadata_to_v23(tmp_path: Path) -> None:
    db_path = tmp_path / "emulebb-rust-metadata.db"
    make_v22_db_without_media_metadata(db_path)

    result = migrate_v22_to_v23(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )

    assert result["action"] == "migrated-v22-to-v23"
    assert Path(str(result["backup"])).is_file()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT schema_version FROM metadata_schema").fetchone()[0] == 23
        columns = [row[1] for row in conn.execute("PRAGMA table_info(known_files)")]
        assert set(KNOWN_FILES_MEDIA_COLUMNS_FOR_TEST).issubset(columns)
        assert conn.execute(
            "SELECT media_artist, media_album, media_title, media_length_seconds, "
            "media_bitrate_kbps, media_codec, media_extractor_version FROM known_files"
        ).fetchone() == ("", "", "", 0, 0, "", 0)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE known_files SET media_extractor_version = -1")
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_migrates_v23_completion_gate_to_v24(tmp_path: Path) -> None:
    db_path = tmp_path / "emulebb-rust-metadata.db"
    make_v23_db_without_final_rehash_gate(db_path)

    result = migrate_v23_to_v24(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )

    assert result["action"] == "migrated-v23-to-v24"
    assert result["undeliveredDownloadsPendingRehash"] == 1
    backup = Path(str(result["backup"]))
    assert backup.is_file()
    with sqlite3.connect(backup) as conn:
        assert "final_rehash_pending" not in {
            row[1] for row in conn.execute("PRAGMA table_info(transfers)")
        }
        assert conn.execute(
            "SELECT completed FROM known_files WHERE display_name = 'pending.bin'"
        ).fetchone() == (1,)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT schema_version FROM metadata_schema").fetchone()[0] == 24
        rows = {
            name: (completed, state, pending, completed_at)
            for name, completed, state, pending, completed_at in conn.execute(
                """
                SELECT known_files.display_name, known_files.completed,
                       transfers.visible_state, transfers.final_rehash_pending,
                       transfers.completed_at_ms
                FROM known_files
                JOIN transfers ON transfers.known_file_id = known_files.id
                """
            )
        }
        assert rows["pending.bin"] == (0, "completing", 1, None)
        assert rows["delivered.bin"] == (1, "completed", 0, 50)
        assert rows["shared.bin"] == (1, "completed", 0, 50)
        assert rows["incomplete.bin"] == (0, "downloading", 0, None)
        assert rows["removed.bin"] == (1, "completed", 0, 50)
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []

    second = migrate_v23_to_v24(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )
    assert second["action"] == "noop-v24-shape-current"
