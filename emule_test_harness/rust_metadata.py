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

ED2K_PART_SIZE = 9_728_000


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


def seed_transfer_manifest(
    db_path: Path,
    *,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    piece_size: int,
    completed: bool = False,
    md4_hashset_acquired: bool = False,
    md4_hashset: list[str] | None = None,
    aich_hashset_acquired: bool = False,
    aich_root: str | None = None,
    aich_hashset: list[str] | None = None,
    sources: list[dict] | None = None,
    control_state: str | None = None,
    upload_priority: str = "normal",
    auto_upload_priority: bool = False,
    all_time_uploaded_bytes: int = 0,
    comment: str = "",
    rating: int = 0,
    source_path: str | None = None,
    source_mtime_ms: int | None = None,
) -> None:
    """Seed a full ED2K transfer manifest (mirrors ``MetadataStore::upsert_transfer_manifest``).

    ``sources`` items are dicts with ``ip``, ``tcp_port`` and optional ``user_hash`` (hex).
    ``md4_hashset``/``aich_hashset`` are lists of lowercase hex part hashes.
    """

    md4_hashset = md4_hashset or []
    aich_hashset = aich_hashset or []
    sources = sources or []
    hash_blob = bytes.fromhex(ed2k_hash)
    piece_count = (size_bytes + piece_size - 1) // piece_size if size_bytes and piece_size else 0
    if completed:
        visible_state = "completed"
    elif control_state is not None:
        visible_state = "controlled"
    else:
        visible_state = "queued"
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
                auto_upload_priority, comment, rating, all_time_uploaded_bytes,
                first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ed2k_hash) DO UPDATE SET
                content_object_id = excluded.content_object_id,
                size_bytes = excluded.size_bytes,
                canonical_name = excluded.canonical_name,
                part_size = excluded.part_size,
                part_count = excluded.part_count,
                completed = excluded.completed,
                md4_hashset_acquired = excluded.md4_hashset_acquired,
                aich_hashset_acquired = excluded.aich_hashset_acquired,
                aich_root = excluded.aich_root,
                upload_priority = excluded.upload_priority,
                auto_upload_priority = excluded.auto_upload_priority,
                comment = excluded.comment,
                rating = excluded.rating,
                all_time_uploaded_bytes = excluded.all_time_uploaded_bytes,
                last_seen_ms = excluded.last_seen_ms,
                updated_at_ms = excluded.updated_at_ms
            """,
            (
                content_object_id,
                hash_blob,
                size_bytes,
                name,
                piece_size,
                piece_count,
                1 if completed else 0,
                1 if md4_hashset_acquired else 0,
                1 if aich_hashset_acquired else 0,
                bytes.fromhex(aich_root) if aich_root else None,
                upload_priority,
                1 if auto_upload_priority else 0,
                comment,
                rating,
                all_time_uploaded_bytes,
                now,
                now,
                now,
            ),
        )
        known_file_id = conn.execute(
            "SELECT id FROM known_files WHERE ed2k_hash = ?", (hash_blob,)
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO transfers(
                known_file_id, visible_state, control_state, priority,
                payload_directory, source_path, source_mtime_ms,
                created_at_ms, updated_at_ms, completed_at_ms
            )
            VALUES (?, ?, ?, 'normal', ?, ?, ?, ?, ?, ?)
            ON CONFLICT(known_file_id) DO UPDATE SET
                visible_state = excluded.visible_state,
                control_state = excluded.control_state,
                payload_directory = excluded.payload_directory,
                source_path = excluded.source_path,
                source_mtime_ms = excluded.source_mtime_ms,
                updated_at_ms = excluded.updated_at_ms,
                completed_at_ms = excluded.completed_at_ms,
                removed_at_ms = NULL
            """,
            (
                known_file_id,
                visible_state,
                control_state,
                ed2k_hash,
                source_path,
                source_mtime_ms,
                now,
                now,
                now if completed else None,
            ),
        )
        transfer_id = conn.execute(
            "SELECT id FROM transfers WHERE known_file_id = ?", (known_file_id,)
        ).fetchone()[0]
        if source_path is not None:
            conn.execute(
                """
                INSERT INTO share_in_place_sources(
                    known_file_id, source_path, file_size, source_mtime_ms,
                    created_at_ms, updated_at_ms
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_path) DO UPDATE SET
                    known_file_id = excluded.known_file_id,
                    file_size = excluded.file_size,
                    source_mtime_ms = excluded.source_mtime_ms,
                    updated_at_ms = excluded.updated_at_ms
                """,
                (known_file_id, source_path, size_bytes, source_mtime_ms, now, now),
            )
            conn.execute("DELETE FROM shared_source_failures WHERE source_path = ?", (source_path,))
        conn.execute("DELETE FROM transfer_pieces WHERE transfer_id = ?", (transfer_id,))
        conn.execute("DELETE FROM ed2k_part_hashes WHERE known_file_id = ?", (known_file_id,))
        conn.execute("DELETE FROM aich_part_hashes WHERE known_file_id = ?", (known_file_id,))
        conn.execute("DELETE FROM verified_ranges WHERE known_file_id = ?", (known_file_id,))
        conn.execute("DELETE FROM transfer_sources WHERE transfer_id = ?", (transfer_id,))
        for piece_index in range(piece_count):
            state = "Verified" if completed else "Missing"
            written = expected_piece_length(size_bytes, piece_size, piece_index) if completed else 0
            conn.execute(
                """
                INSERT INTO transfer_pieces(transfer_id, piece_index, state, bytes_written, updated_at_ms)
                VALUES (?, ?, ?, ?, ?)
                """,
                (transfer_id, piece_index, state, written, now),
            )
        for index, part_hash in enumerate(md4_hashset):
            conn.execute(
                "INSERT INTO ed2k_part_hashes(known_file_id, part_index, md4_hash) VALUES (?, ?, ?)",
                (known_file_id, index, bytes.fromhex(part_hash)),
            )
        for index, part_hash in enumerate(aich_hashset):
            conn.execute(
                "INSERT INTO aich_part_hashes(known_file_id, part_index, aich_hash) VALUES (?, ?, ?)",
                (known_file_id, index, bytes.fromhex(part_hash)),
            )
        for source in sources:
            user_hash = source.get("user_hash")
            conn.execute(
                """
                INSERT INTO transfer_sources(transfer_id, ip, tcp_port, user_hash, first_seen_ms, last_seen_ms)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    transfer_id,
                    source["ip"],
                    source["tcp_port"],
                    bytes.fromhex(user_hash) if user_hash else None,
                    now,
                    now,
                ),
            )
        if completed:
            conn.execute(
                """
                INSERT INTO verified_ranges(known_file_id, start_offset, end_offset, source_kind, created_at_ms)
                VALUES (?, 0, ?, 'ed2k_transfer', ?)
                """,
                (known_file_id, size_bytes, now),
            )
        conn.commit()


def seed_share_in_place_manifest(
    db_path: Path,
    *,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    source_path: str,
    source_mtime_ms: int,
    md4_hashset: list[str] | None = None,
    aich_root: str | None = None,
    aich_hashset: list[str] | None = None,
    upload_priority: str = "normal",
    auto_upload_priority: bool = False,
    all_time_uploaded_bytes: int = 0,
) -> None:
    """Seed a completed shared-file manifest that Rust can reload without hashing.

    The row mirrors Rust's local ingest result: completed transfer, verified
    pieces and ranges, original ``source_path``, and source mtime. A later
    shared-directory reload skips hashing only when path, size, and mtime still
    match the scanned file.
    """

    seed_transfer_manifest(
        db_path,
        ed2k_hash=ed2k_hash,
        name=name,
        size_bytes=size_bytes,
        piece_size=ED2K_PART_SIZE,
        completed=True,
        md4_hashset_acquired=True,
        md4_hashset=md4_hashset or [],
        aich_hashset_acquired=aich_root is not None,
        aich_root=aich_root,
        aich_hashset=aich_hashset or [],
        upload_priority=upload_priority,
        auto_upload_priority=auto_upload_priority,
        all_time_uploaded_bytes=all_time_uploaded_bytes,
        source_path=source_path,
        source_mtime_ms=source_mtime_ms,
    )


def seed_share_in_place_manifests(db_path: Path, manifests: list[dict[str, object]]) -> None:
    """Seed many completed share-in-place manifests in one SQLite transaction."""

    now = _now_ms()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        for manifest in manifests:
            _seed_share_in_place_manifest_conn(conn, now=now, **manifest)
        conn.commit()


def _seed_share_in_place_manifest_conn(
    conn: sqlite3.Connection,
    *,
    now: int,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    source_path: str,
    source_mtime_ms: int,
    md4_hashset: list[str] | None = None,
    aich_root: str | None = None,
    aich_hashset: list[str] | None = None,
    upload_priority: str = "normal",
    auto_upload_priority: bool = False,
    all_time_uploaded_bytes: int = 0,
) -> None:
    md4_hashset = md4_hashset or []
    aich_hashset = aich_hashset or []
    hash_blob = bytes.fromhex(ed2k_hash)
    piece_size = ED2K_PART_SIZE
    piece_count = (size_bytes + piece_size - 1) // piece_size if size_bytes and piece_size else 0
    content_object_id = _upsert_content_object(conn, hash_blob, name, size_bytes, now)
    conn.execute(
        """
        INSERT INTO known_files(
            content_object_id, ed2k_hash, size_bytes, canonical_name,
            part_size, part_count, completed, md4_hashset_acquired,
            aich_hashset_acquired, aich_root, upload_priority,
            auto_upload_priority, all_time_uploaded_bytes,
            first_seen_ms, last_seen_ms, updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ed2k_hash) DO UPDATE SET
            content_object_id = excluded.content_object_id,
            size_bytes = excluded.size_bytes,
            canonical_name = excluded.canonical_name,
            part_size = excluded.part_size,
            part_count = excluded.part_count,
            completed = excluded.completed,
            md4_hashset_acquired = excluded.md4_hashset_acquired,
            aich_hashset_acquired = excluded.aich_hashset_acquired,
            aich_root = excluded.aich_root,
            upload_priority = excluded.upload_priority,
            auto_upload_priority = excluded.auto_upload_priority,
            all_time_uploaded_bytes = excluded.all_time_uploaded_bytes,
            last_seen_ms = excluded.last_seen_ms,
            updated_at_ms = excluded.updated_at_ms
        """,
        (
            content_object_id,
            hash_blob,
            size_bytes,
            name,
            piece_size,
            piece_count,
            1 if aich_root is not None else 0,
            bytes.fromhex(aich_root) if aich_root else None,
            upload_priority,
            1 if auto_upload_priority else 0,
            all_time_uploaded_bytes,
            now,
            now,
            now,
        ),
    )
    known_file_id = conn.execute(
        "SELECT id FROM known_files WHERE ed2k_hash = ?", (hash_blob,)
    ).fetchone()[0]
    conn.execute(
        """
        INSERT INTO transfers(
            known_file_id, visible_state, priority, payload_directory,
            source_path, source_mtime_ms, created_at_ms, updated_at_ms, completed_at_ms
        )
        VALUES (?, 'completed', 'normal', ?, ?, ?, ?, ?, ?)
        ON CONFLICT(known_file_id) DO UPDATE SET
            visible_state = excluded.visible_state,
            priority = excluded.priority,
            payload_directory = excluded.payload_directory,
            source_path = excluded.source_path,
            source_mtime_ms = excluded.source_mtime_ms,
            updated_at_ms = excluded.updated_at_ms,
            completed_at_ms = excluded.completed_at_ms,
            removed_at_ms = NULL
        """,
        (known_file_id, ed2k_hash, source_path, source_mtime_ms, now, now, now),
    )
    transfer_id = conn.execute(
        "SELECT id FROM transfers WHERE known_file_id = ?", (known_file_id,)
    ).fetchone()[0]
    conn.execute(
        """
        INSERT INTO share_in_place_sources(
            known_file_id, source_path, file_size, source_mtime_ms,
            created_at_ms, updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_path) DO UPDATE SET
            known_file_id = excluded.known_file_id,
            file_size = excluded.file_size,
            source_mtime_ms = excluded.source_mtime_ms,
            updated_at_ms = excluded.updated_at_ms
        """,
        (known_file_id, source_path, size_bytes, source_mtime_ms, now, now),
    )
    conn.execute("DELETE FROM shared_source_failures WHERE source_path = ?", (source_path,))
    conn.execute("DELETE FROM transfer_pieces WHERE transfer_id = ?", (transfer_id,))
    conn.execute("DELETE FROM ed2k_part_hashes WHERE known_file_id = ?", (known_file_id,))
    conn.execute("DELETE FROM aich_part_hashes WHERE known_file_id = ?", (known_file_id,))
    conn.execute("DELETE FROM verified_ranges WHERE known_file_id = ?", (known_file_id,))
    for piece_index in range(piece_count):
        conn.execute(
            """
            INSERT INTO transfer_pieces(transfer_id, piece_index, state, bytes_written, updated_at_ms)
            VALUES (?, ?, 'Verified', ?, ?)
            """,
            (transfer_id, piece_index, expected_piece_length(size_bytes, piece_size, piece_index), now),
        )
    for index, part_hash in enumerate(md4_hashset):
        conn.execute(
            "INSERT INTO ed2k_part_hashes(known_file_id, part_index, md4_hash) VALUES (?, ?, ?)",
            (known_file_id, index, bytes.fromhex(part_hash)),
        )
    for index, part_hash in enumerate(aich_hashset):
        conn.execute(
            "INSERT INTO aich_part_hashes(known_file_id, part_index, aich_hash) VALUES (?, ?, ?)",
            (known_file_id, index, bytes.fromhex(part_hash)),
        )
    conn.execute(
        """
        INSERT INTO verified_ranges(known_file_id, start_offset, end_offset, source_kind, created_at_ms)
        VALUES (?, 0, ?, 'ed2k_transfer', ?)
        """,
        (known_file_id, size_bytes, now),
    )


def expected_piece_length(file_size: int, piece_size: int, piece_index: int) -> int:
    start = piece_index * piece_size
    return max(0, min(start + piece_size, file_size) - start)


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
    """Seed an incomplete transfer with a single remembered source."""

    seed_transfer_manifest(
        db_path,
        ed2k_hash=ed2k_hash,
        name=name,
        size_bytes=size_bytes,
        piece_size=piece_size,
        sources=[{"ip": source_ip, "tcp_port": source_tcp_port, "user_hash": source_user_hash}],
    )


def read_transfer_manifest(db_path: Path, ed2k_hash: str) -> dict | None:
    """Read a persisted ED2K transfer manifest from ``metadata.sqlite``.

    Mirrors ``MetadataStore::transfer_manifest_by_hash`` and returns the same
    field shape the legacy ``resume-manifest.json`` exposed, so harness checks can
    verify internal hashset/AICH metadata that has no REST surface. Returns
    ``None`` when no known file with that hash exists.
    """

    hash_blob = bytes.fromhex(ed2k_hash)
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT known_files.id, transfers.id, transfers.control_state,
                   known_files.canonical_name, known_files.size_bytes,
                   coalesce(known_files.part_size, 0),
                   known_files.completed, known_files.md4_hashset_acquired,
                   known_files.aich_hashset_acquired,
                   CASE WHEN known_files.aich_root IS NULL THEN NULL
                        ELSE lower(hex(known_files.aich_root)) END,
                   known_files.upload_priority, known_files.comment, known_files.rating,
                   known_files.auto_upload_priority, known_files.all_time_uploaded_bytes,
                   transfers.source_path, transfers.source_mtime_ms
            FROM known_files
            LEFT JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE known_files.ed2k_hash = ?
            """,
            (hash_blob,),
        ).fetchone()
        if row is None:
            return None
        known_file_id = row[0]
        transfer_id = row[1]
        sources = []
        if transfer_id is not None:
            sources = [
                {
                    "ip": src[0],
                    "tcp_port": src[1],
                    "user_hash": src[2],
                }
                for src in conn.execute(
                    """
                    SELECT ip, tcp_port,
                           CASE WHEN user_hash IS NULL THEN NULL ELSE lower(hex(user_hash)) END
                    FROM transfer_sources WHERE transfer_id = ?
                    ORDER BY id
                    """,
                    (transfer_id,),
                )
            ]
        md4_hashset = [
            r[0]
            for r in conn.execute(
                "SELECT lower(hex(md4_hash)) FROM ed2k_part_hashes WHERE known_file_id = ? ORDER BY part_index",
                (known_file_id,),
            )
        ]
        aich_hashset = [
            r[0]
            for r in conn.execute(
                "SELECT lower(hex(aich_hash)) FROM aich_part_hashes WHERE known_file_id = ? ORDER BY part_index",
                (known_file_id,),
            )
        ]
    return {
        "file_hash": ed2k_hash.lower(),
        "control_state": row[2],
        "canonical_name": row[3],
        "file_size": row[4],
        "piece_size": row[5],
        "completed": bool(row[6]),
        "md4_hashset_acquired": bool(row[7]),
        "aich_hashset_acquired": bool(row[8]),
        "aich_root": row[9],
        "upload_priority": row[10],
        "comment": row[11],
        "rating": row[12],
        "auto_upload_priority": bool(row[13]),
        "all_time_uploaded_bytes": row[14],
        "source_path": row[15],
        "source_mtime_ms": row[16],
        "md4_hashset": md4_hashset,
        "aich_hashset": aich_hashset,
        "sources": sources,
    }


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
