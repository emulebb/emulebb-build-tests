"""Helpers to seed the eMuleBB Rust ``metadata.sqlite`` store for harness scenarios.

The Rust client persists its search index and ED2K transfer manifests in a single
SQLite database (``<runtimeDir>/metadata.sqlite``). Harness scenarios that need to
stage prior client state (a previously harvested index entry, or a remembered
download source) seed that database directly before launching the client.

To avoid duplicating the Rust schema in Python, these helpers read the canonical
``schema.sql`` and schema marker straight from the ``emulebb-metadata`` crate, so a
schema change in the client is picked up automatically. Only the small set of seed
``INSERT`` statements is coupled to specific tables.
"""

from __future__ import annotations

import re
import sqlite3
import time
import unicodedata
from pathlib import Path


def _metadata_src_dir(rust_repo: Path) -> Path:
    return rust_repo / "crates" / "emulebb-metadata" / "src"


def _schema_sql(rust_repo: Path) -> str:
    return (_metadata_src_dir(rust_repo) / "schema.sql").read_text(encoding="utf-8")


def _schema_marker(rust_repo: Path) -> tuple[str, int]:
    text = (_metadata_src_dir(rust_repo) / "schema.rs").read_text(encoding="utf-8")
    schema_id = re.search(r'SCHEMA_ID:\s*&str\s*=\s*"([^"]+)"', text)
    schema_version = re.search(r"SCHEMA_VERSION:\s*i64\s*=\s*(\d+)", text)
    if schema_id is None or schema_version is None:
        raise RuntimeError("could not parse SCHEMA_ID/SCHEMA_VERSION from emulebb-metadata schema.rs")
    return schema_id.group(1), int(schema_version.group(1))


def normalize_search_text(value: str) -> str:
    """Mirror ``emulebb_metadata::text::normalize_search_text`` for FTS seed rows."""

    folded = "".join(ch.lower() for ch in unicodedata.normalize("NFKC", value))
    spaced = "".join(ch if ch.isalnum() else " " for ch in folded)
    return " ".join(spaced.split())


def _now_ms() -> int:
    return int(time.time() * 1000)


def create_metadata_db(rust_repo: Path, db_path: Path) -> None:
    """Create ``metadata.sqlite`` with the canonical schema and a matching marker row.

    The Rust ``MetadataStore`` keeps a pre-existing database only when the
    ``metadata_schema`` marker matches its compiled ``SCHEMA_ID``/``SCHEMA_VERSION``;
    otherwise it resets every table. Writing the marker here lets seeded rows survive
    daemon startup.
    """

    db_path.parent.mkdir(parents=True, exist_ok=True)
    schema_id, schema_version = _schema_marker(rust_repo)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_schema_sql(rust_repo))
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, ?, ?)",
            (schema_id, schema_version, _now_ms()),
        )
        conn.commit()


def seed_indexed_file(
    db_path: Path,
    *,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    content_type: str = "archive",
    availability_score: int = 0,
) -> None:
    """Seed a harvested search-index entry (mirrors ``MetadataStore::upsert_indexed_file``)."""

    hash_blob = bytes.fromhex(ed2k_hash)
    normalized = normalize_search_text(name)
    now = _now_ms()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        content_object_id = _upsert_content_object(conn, hash_blob, name, size_bytes, now)
        conn.execute(
            """
            INSERT INTO known_files(
                content_object_id, ed2k_hash, size_bytes, canonical_name,
                content_type, availability_score, first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (content_object_id, hash_blob, size_bytes, name, content_type, availability_score, now, now, now),
        )
        known_file_id = conn.execute(
            "SELECT id FROM known_files WHERE ed2k_hash = ?", (hash_blob,)
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO file_names(known_file_id, name, normalized_name, source_kind, seen_count, first_seen_ms, last_seen_ms)
            VALUES (?, ?, ?, 'index', 1, ?, ?)
            """,
            (known_file_id, name, normalized, now, now),
        )
        conn.commit()


def seed_remembered_source_transfer(
    db_path: Path,
    *,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    piece_size: int,
    source_ip: str,
    source_tcp_port: int,
    source_user_hash: str | None = None,
) -> None:
    """Seed an incomplete transfer with a remembered source (mirrors ``upsert_transfer_manifest``)."""

    hash_blob = bytes.fromhex(ed2k_hash)
    piece_count = (size_bytes + piece_size - 1) // piece_size if size_bytes else 0
    now = _now_ms()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        content_object_id = _upsert_content_object(conn, hash_blob, name, size_bytes, now)
        conn.execute(
            """
            INSERT INTO known_files(
                content_object_id, ed2k_hash, size_bytes, canonical_name,
                part_size, part_count, completed, md4_hashset_acquired,
                aich_hashset_acquired, aich_root, upload_priority,
                auto_upload_priority, comment, rating,
                first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, NULL, 'normal', 0, '', 0, ?, ?, ?)
            """,
            (content_object_id, hash_blob, size_bytes, name, piece_size, piece_count, now, now, now),
        )
        known_file_id = conn.execute(
            "SELECT id FROM known_files WHERE ed2k_hash = ?", (hash_blob,)
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO transfers(
                known_file_id, visible_state, control_state, priority,
                payload_directory, created_at_ms, updated_at_ms
            )
            VALUES (?, 'queued', NULL, 'normal', ?, ?, ?)
            """,
            (known_file_id, ed2k_hash, now, now),
        )
        transfer_id = conn.execute(
            "SELECT id FROM transfers WHERE known_file_id = ?", (known_file_id,)
        ).fetchone()[0]
        for piece_index in range(piece_count):
            conn.execute(
                """
                INSERT INTO transfer_pieces(transfer_id, piece_index, state, bytes_written, updated_at_ms)
                VALUES (?, ?, 'Missing', 0, ?)
                """,
                (transfer_id, piece_index, now),
            )
        conn.execute(
            """
            INSERT INTO transfer_sources(transfer_id, ip, tcp_port, user_hash, first_seen_ms, last_seen_ms)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                transfer_id,
                source_ip,
                source_tcp_port,
                bytes.fromhex(source_user_hash) if source_user_hash else None,
                now,
                now,
            ),
        )
        conn.commit()


def _upsert_content_object(
    conn: sqlite3.Connection,
    hash_blob: bytes,
    name: str,
    size_bytes: int,
    now: int,
) -> int:
    conn.execute(
        """
        INSERT INTO content_objects(
            kind, primary_hash_kind, primary_hash, display_name, size_bytes,
            first_seen_ms, last_seen_ms, updated_at_ms
        )
        VALUES ('ed2k_file', 'ed2k', ?, ?, ?, ?, ?, ?)
        ON CONFLICT(kind, primary_hash_kind, primary_hash) DO UPDATE SET
            display_name = excluded.display_name,
            size_bytes = excluded.size_bytes,
            last_seen_ms = excluded.last_seen_ms,
            updated_at_ms = excluded.updated_at_ms,
            deleted_at_ms = NULL
        """,
        (hash_blob, name, size_bytes, now, now, now),
    )
    return conn.execute(
        "SELECT id FROM content_objects WHERE kind = 'ed2k_file' AND primary_hash_kind = 'ed2k' AND primary_hash = ?",
        (hash_blob,),
    ).fetchone()[0]
