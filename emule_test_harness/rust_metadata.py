"""Helpers to seed the eMuleBB Rust profile metadata store for harness scenarios.

The Rust client persists its search index and ED2K transfer manifests in a single
SQLite database (``<profileDir>/emulebb-rust-metadata.db``). Harness scenarios
that need to stage profile settings or prior client state seed that database
directly before launching the client.

To avoid duplicating the Rust schema in Python, these helpers read the canonical
``schema.sql`` and schema marker straight from the ``emulebb-metadata`` crate, so a
schema change in the client is picked up automatically. Only the small set of seed
``INSERT`` statements is coupled to specific tables.
"""

from __future__ import annotations

import re
import json
import os
import sqlite3
import sys
import time
import unicodedata
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any

ED2K_PART_SIZE = 9_728_000
RUST_PROFILE_METADATA_FILE = "emulebb-rust-metadata.db"


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
    """Create ``emulebb-rust-metadata.db`` with the canonical schema and marker row.

    The Rust ``MetadataStore`` keeps a pre-existing database only when the
    ``metadata_schema`` marker matches its compiled ``SCHEMA_ID``/``SCHEMA_VERSION``;
    otherwise startup fails and requires a fresh profile. The marker lets seed rows survive
    daemon startup.
    """

    db_path.parent.mkdir(parents=True, exist_ok=True)
    schema_id, schema_version = _schema_marker(rust_repo)
    now = _now_ms()
    with closing(sqlite3.connect(db_path)) as conn:
        conn.executescript(_schema_sql(rust_repo))
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, ?, ?)",
            (schema_id, schema_version, now),
        )
        conn.execute(
            """
            INSERT INTO profile(id, uuid, created_by, created_at_ms, updated_at_ms)
            VALUES (1, ?, 'emulebb-rust', ?, ?)
            """,
            (str(uuid.uuid4()), now, now),
        )
        conn.commit()


def require_current_profile_database(rust_repo: Path, db_path: Path) -> None:
    """Require a complete database matching the current Rust profile schema."""

    schema_id, schema_version = _schema_marker(rust_repo)
    try:
        with closing(sqlite3.connect(db_path)) as conn:
            marker = conn.execute(
                "SELECT schema_version FROM metadata_schema WHERE schema_id = ?",
                (schema_id,),
            ).fetchone()
            if marker != (schema_version,):
                raise RuntimeError(
                    f"metadata schema marker must be {schema_id}@{schema_version}, got {marker!r}"
                )
            profile_count = conn.execute(
                "SELECT count(*) FROM profile WHERE id = 1"
            ).fetchone()[0]
            if profile_count != 1:
                raise RuntimeError("metadata profile singleton row is missing")
            missing_name_state = conn.execute(
                """
                SELECT count(*)
                FROM transfers
                LEFT JOIN transfer_name_state
                  ON transfer_name_state.transfer_id = transfers.id
                WHERE transfer_name_state.transfer_id IS NULL
                """
            ).fetchone()[0]
            if missing_name_state:
                raise RuntimeError(
                    f"metadata has {missing_name_state} transfer row(s) without transfer_name_state"
                )
    except sqlite3.DatabaseError as exc:
        raise RuntimeError(f"invalid current Rust profile database {db_path}: {exc}") from exc


def _replace_transfer_name_state(conn: sqlite3.Connection, transfer_id: int) -> None:
    conn.execute("DELETE FROM transfer_name_state WHERE transfer_id = ?", (transfer_id,))
    conn.execute(
        """
        INSERT INTO transfer_name_state(
            transfer_id, display_name_pinned, follow_majority_filename
        )
        VALUES (?, 0, 0)
        """,
        (transfer_id,),
    )


def put_setting_json(db_path: Path, section: str, key: str, value: object) -> None:
    """Upsert one Rust profile settings row using the canonical JSON row shape."""

    if not section.strip():
        raise ValueError("settings section must not be empty")
    if not key.strip():
        raise ValueError("settings key must not be empty")
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO settings(section, key, value_json, updated_at_ms)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(section, key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at_ms = excluded.updated_at_ms
            """,
            (section, key, json.dumps(value), _now_ms()),
        )
        conn.commit()


def replace_settings_section(db_path: Path, section: str, values: dict[str, object]) -> None:
    """Replace one Rust settings section with scalar JSON setting rows."""

    if not section.strip():
        raise ValueError("settings section must not be empty")
    now = _now_ms()
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("DELETE FROM settings WHERE section = ?", (section,))
        for key, value in sorted(values.items()):
            if not key.strip():
                raise ValueError("settings key must not be empty")
            conn.execute(
                """
                INSERT INTO settings(section, key, value_json, updated_at_ms)
                VALUES (?, ?, ?, ?)
                """,
                (section, key, json.dumps(value), now),
            )
        conn.commit()


def replace_kad_bootstrap_endpoints(db_path: Path, endpoints: list[str]) -> None:
    """Replace the ordered Rust Kad bootstrap endpoint list."""

    now = _now_ms()
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("DELETE FROM kad_bootstrap_endpoints")
        for position, endpoint in enumerate(endpoints):
            if not endpoint.strip():
                raise ValueError("Kad bootstrap endpoint must not be empty")
            conn.execute(
                """
                INSERT INTO kad_bootstrap_endpoints(position, endpoint, updated_at_ms)
                VALUES (?, ?, ?)
                """,
                (position, endpoint, now),
            )
        conn.commit()


def seed_local_user_hash(db_path: Path, user_hash: bytes) -> None:
    """Seed the Rust ED2K user-hash identity from stock ``preferences.dat`` bytes."""

    if len(user_hash) != 16:
        raise ValueError("ED2K user hash must be exactly 16 bytes")
    normalized = bytearray(user_hash)
    normalized[5] = 0x0E
    normalized[14] = 0x6F
    if _user_hash_is_bad(bytes(normalized)):
        raise ValueError("ED2K user hash must not be an eMule bad hash")
    now = _now_ms()
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO local_identities(
                identity_kind, public_identity, private_secret, created_at_ms, updated_at_ms
            )
            VALUES ('ed2k-user-hash', ?, NULL, ?, ?)
            ON CONFLICT(identity_kind) DO UPDATE SET
                public_identity = excluded.public_identity,
                private_secret = NULL,
                updated_at_ms = excluded.updated_at_ms
            """,
            (bytes(normalized), now, now),
        )
        conn.commit()


def _user_hash_is_bad(user_hash: bytes) -> bool:
    lo = int.from_bytes(user_hash[:8], "little")
    hi = int.from_bytes(user_hash[8:], "little")
    return (lo & 0xFFFF_00FF_FFFF_FFFF) == 0 and (hi & 0xFF00_FFFF_FFFF_FFFF) == 0


def seed_server(db_path: Path, server: dict[str, object]) -> None:
    """Seed one enabled ED2K server row into the Rust SQLite profile."""

    address = str(server.get("host") or server.get("address") or "").strip()
    port = int(server.get("port") or 0)
    if not address or not (1 <= port <= 65535):
        raise ValueError("Rust server seed requires host/address and port.")
    now = _now_ms()
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO servers(
                address, port, name, description, server_priority, static_server,
                enabled, failed_count, ping_ms, users, files, soft_files, hard_files,
                version, obfuscation_tcp_port, udp_flags, first_seen_at_ms, last_seen_at_ms, deleted_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, 0, 0, 0, 0, ?, ?, ?, ?, ?, NULL)
            ON CONFLICT(address, port) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                server_priority = excluded.server_priority,
                static_server = excluded.static_server,
                enabled = excluded.enabled,
                version = excluded.version,
                obfuscation_tcp_port = excluded.obfuscation_tcp_port,
                udp_flags = excluded.udp_flags,
                last_seen_at_ms = excluded.last_seen_at_ms,
                deleted_at_ms = NULL
            """,
            (
                address,
                port,
                str(server.get("name") or ""),
                str(server.get("description") or ""),
                str(server.get("serverPriority") or "normal"),
                1 if bool(server.get("staticServer", True)) else 0,
                1 if bool(server.get("enabled", True)) else 0,
                str(server.get("version") or ""),
                _optional_int(server.get("obfuscationPortTcp") or server.get("obfuscationTcpPort")),
                _optional_int(server.get("udpFlags")),
                now,
                now,
            ),
        )
        conn.commit()


def clear_servers(db_path: Path) -> None:
    """Remove persisted ED2K server rows from a Rust SQLite profile."""

    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("DELETE FROM servers")
        conn.commit()


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    return int(value)


def seed_indexed_file(
    db_path: Path,
    *,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    content_type: str = "archive",
    availability_score: int = 0,
    origin: str,
) -> None:
    """Seed a harvested search-index entry (mirrors ``MetadataStore::upsert_indexed_file``)."""

    if origin not in {"local_share", "transfer", "passive_cache"}:
        raise ValueError("Indexed file origin is invalid.")
    hash_blob = bytes.fromhex(ed2k_hash)
    normalized = normalize_search_text(name)
    now = _now_ms()
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            INSERT INTO known_files(
                ed2k_hash, size_bytes, display_name,
                content_type, availability_score, first_seen_at_ms, last_seen_at_ms, updated_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ed2k_hash) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                display_name = excluded.display_name,
                content_type = excluded.content_type,
                availability_score = max(known_files.availability_score, excluded.availability_score),
                last_seen_at_ms = excluded.last_seen_at_ms,
                updated_at_ms = excluded.updated_at_ms
            """,
            (hash_blob, size_bytes, name, content_type, availability_score, now, now, now),
        )
        known_file_id = conn.execute(
            "SELECT id FROM known_files WHERE ed2k_hash = ?", (hash_blob,)
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO known_file_origins(
                known_file_id, origin, size_bytes, content_type,
                availability_score, first_seen_at_ms, last_seen_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(known_file_id, origin) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                content_type = excluded.content_type,
                availability_score = max(
                    known_file_origins.availability_score,
                    excluded.availability_score
                ),
                last_seen_at_ms = excluded.last_seen_at_ms
            """,
            (
                known_file_id,
                origin,
                size_bytes,
                content_type,
                availability_score,
                now,
                now,
            ),
        )
        conn.execute(
            """
            INSERT INTO file_names(known_file_id, name, normalized_name, seen_count, first_seen_at_ms, last_seen_at_ms)
            VALUES (?, ?, ?, 1, ?, ?)
            ON CONFLICT(known_file_id, normalized_name) DO UPDATE SET
                name = excluded.name,
                seen_count = file_names.seen_count + 1,
                last_seen_at_ms = excluded.last_seen_at_ms
            """,
            (known_file_id, name, normalized, now, now),
        )
        file_name_id = conn.execute(
            "SELECT id FROM file_names WHERE known_file_id = ? AND normalized_name = ?",
            (known_file_id, normalized),
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO file_name_origins(
                file_name_id, origin, first_seen_at_ms, last_seen_at_ms
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(file_name_id, origin) DO UPDATE SET
                last_seen_at_ms = excluded.last_seen_at_ms
            """,
            (file_name_id, origin, now, now),
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
    all_time_upload_requests: int = 0,
    all_time_upload_accepts: int = 0,
    last_upload_request_ms: int = 0,
    comment: str = "",
    rating: int = 0,
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
        visible_state = "queued"
    else:
        visible_state = "queued"
    now = _now_ms()
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            INSERT INTO known_files(
                ed2k_hash, size_bytes, display_name, aich_root, all_time_uploaded_bytes,
                all_time_upload_requests, all_time_upload_accepts, last_upload_requested_at_ms,
                first_seen_at_ms, last_seen_at_ms, updated_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ed2k_hash) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                display_name = excluded.display_name,
                aich_root = excluded.aich_root,
                all_time_uploaded_bytes = excluded.all_time_uploaded_bytes,
                all_time_upload_requests = excluded.all_time_upload_requests,
                all_time_upload_accepts = excluded.all_time_upload_accepts,
                last_upload_requested_at_ms = excluded.last_upload_requested_at_ms,
                last_seen_at_ms = excluded.last_seen_at_ms,
                updated_at_ms = excluded.updated_at_ms
            """,
            (hash_blob, size_bytes, name, bytes.fromhex(aich_root) if aich_root else None,
             all_time_uploaded_bytes, all_time_upload_requests, all_time_upload_accepts,
             last_upload_request_ms, now, now, now),
        )
        known_file_id = conn.execute(
            "SELECT id FROM known_files WHERE ed2k_hash = ?", (hash_blob,)
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO transfers(
                known_file_id, completed, md4_hashset_acquired, aich_hashset_acquired,
                visible_state, control_state, display_name, part_size_bytes, part_count,
                upload_priority, auto_upload_priority, comment, rating,
                delivery_state, delivery_ownership, created_at_ms, updated_at_ms, completed_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'none', ?, ?, ?)
            ON CONFLICT(known_file_id) DO UPDATE SET
                completed = excluded.completed,
                md4_hashset_acquired = excluded.md4_hashset_acquired,
                aich_hashset_acquired = excluded.aich_hashset_acquired,
                visible_state = excluded.visible_state,
                control_state = excluded.control_state,
                display_name = excluded.display_name,
                part_size_bytes = excluded.part_size_bytes,
                part_count = excluded.part_count,
                upload_priority = excluded.upload_priority,
                auto_upload_priority = excluded.auto_upload_priority,
                comment = excluded.comment,
                rating = excluded.rating,
                updated_at_ms = excluded.updated_at_ms,
                completed_at_ms = excluded.completed_at_ms
            """,
            (known_file_id, int(completed), int(md4_hashset_acquired), int(aich_hashset_acquired),
             visible_state, control_state, name, piece_size, piece_count, upload_priority,
             int(auto_upload_priority), comment, rating, now, now, now if completed else None),
        )
        transfer_id = conn.execute(
            "SELECT id FROM transfers WHERE known_file_id = ?", (known_file_id,)
        ).fetchone()[0]
        _replace_transfer_name_state(conn, transfer_id)
        conn.execute("DELETE FROM transfer_pieces WHERE transfer_id = ?", (transfer_id,))
        conn.execute("DELETE FROM transfer_md4_part_hashes WHERE transfer_id = ?", (transfer_id,))
        conn.execute("DELETE FROM transfer_aich_part_hashes WHERE transfer_id = ?", (transfer_id,))
        conn.execute("DELETE FROM verified_ranges WHERE transfer_id = ?", (transfer_id,))
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
                "INSERT INTO transfer_md4_part_hashes(transfer_id, part_index, md4_hash) VALUES (?, ?, ?)",
                (transfer_id, index, bytes.fromhex(part_hash)),
            )
        for index, part_hash in enumerate(aich_hashset):
            conn.execute(
                "INSERT INTO transfer_aich_part_hashes(transfer_id, part_index, aich_hash) VALUES (?, ?, ?)",
                (transfer_id, index, bytes.fromhex(part_hash)),
            )
        for source in sources:
            user_hash = source.get("user_hash")
            conn.execute(
                """
                INSERT INTO transfer_sources(transfer_id, ip, tcp_port, user_hash, first_seen_at_ms, last_seen_at_ms)
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
                INSERT INTO verified_ranges(transfer_id, start_offset, end_offset, created_at_ms)
                VALUES (?, 0, ?, ?)
                """,
                (transfer_id, size_bytes, now),
            )
        conn.commit()



def seed_shared_directory_roots(db_path: Path, roots: list[dict[str, Any]]) -> None:
    """Seed Rust shared-directory roots before daemon startup.

    The daemon validates files and admits memberships during its root scan.
    This helper seeds configuration only; it grants no file serving authority.
    """

    now = _now_ms()
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            "UPDATE shared_directory_roots SET deleted_at_ms = ? WHERE deleted_at_ms IS NULL",
            (now,),
        )
        for root in roots:
            path = str(root.get("path") or "")
            if not path.strip("\\"):
                continue
            path_id = _upsert_local_path(conn, path, now)
            conn.execute(
                """
                INSERT INTO shared_directory_roots(
                    path_id, monitor_owned, shareable, accessible,
                    enabled, created_at_ms, deleted_at_ms
                )
                VALUES (?, ?, ?, ?, 1, ?, NULL)
                ON CONFLICT(path_id) DO UPDATE SET
                    monitor_owned = excluded.monitor_owned,
                    shareable = excluded.shareable,
                    accessible = excluded.accessible,
                    enabled = 1,
                    deleted_at_ms = NULL
                """,
                (
                    path_id,
                    1 if root.get("monitorOwned") else 0,
                    1 if root.get("shareable", True) else 0,
                    1 if root.get("accessible", True) else 0,
                    now,
                ),
            )
        conn.commit()


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
    """Read a persisted ED2K transfer manifest from the Rust profile metadata DB.

    Inspect internal download hashsets and sources without fabricating a local
    shared-file transfer. Return ``None`` when no download exists for the hash.
    """

    hash_blob = bytes.fromhex(ed2k_hash)
    with closing(sqlite3.connect(db_path)) as conn:
        row = conn.execute(
            """
            SELECT known_files.id, transfers.id, transfers.control_state,
                   transfers.display_name, known_files.size_bytes,
                   coalesce(transfers.part_size_bytes, 0),
                   transfers.completed, transfers.md4_hashset_acquired,
                   transfers.aich_hashset_acquired,
                   CASE WHEN known_files.aich_root IS NULL THEN NULL
                        ELSE lower(hex(known_files.aich_root)) END,
                   transfers.upload_priority, transfers.comment, transfers.rating,
                   transfers.auto_upload_priority, known_files.all_time_uploaded_bytes,
                   known_files.all_time_upload_requests,
                   known_files.all_time_upload_accepts,
                   known_files.last_upload_requested_at_ms,
                   transfers.source_fingerprint
            FROM known_files
            JOIN transfers ON transfers.known_file_id = known_files.id
            WHERE known_files.ed2k_hash = ?
            """,
            (hash_blob,),
        ).fetchone()
        if row is None:
            return None
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
                "SELECT lower(hex(md4_hash)) FROM transfer_md4_part_hashes WHERE transfer_id = ? ORDER BY part_index",
                (transfer_id,),
            )
        ]
        aich_hashset = [
            r[0]
            for r in conn.execute(
                "SELECT lower(hex(aich_hash)) FROM transfer_aich_part_hashes WHERE transfer_id = ? ORDER BY part_index",
                (transfer_id,),
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
        "all_time_upload_requests": row[15],
        "all_time_upload_accepts": row[16],
        "last_upload_request_ms": row[17],
        "md4_hashset": md4_hashset,
        "aich_hashset": aich_hashset,
        "sources": sources,
    }


def _upsert_local_path(conn: sqlite3.Connection, display_path: str, now: int) -> int:
    del now
    native_path = _native_path_storage_bytes(display_path)
    search_key = normalize_path_key(display_path)
    platform = current_platform()
    conn.execute(
        """
        INSERT INTO local_paths(
            display_path, native_path, search_key, platform, sort_key, file_name_search_key
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(platform, native_path) DO UPDATE SET
            display_path = excluded.display_path,
            search_key = excluded.search_key,
            sort_key = excluded.sort_key,
            file_name_search_key = excluded.file_name_search_key
        """,
        (display_path, native_path, search_key, platform, display_path.lower(), Path(display_path).name.lower()),
    )
    return conn.execute(
        "SELECT id FROM local_paths WHERE platform = ? AND native_path = ?",
        (platform, native_path),
    ).fetchone()[0]


def _native_path_storage_bytes(display_path: str) -> bytes:
    if current_platform() == "windows":
        return display_path.encode("utf-16-le", errors="surrogatepass")
    return os.fsencode(display_path)


def normalize_path_key(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    if current_platform() == "windows":
        return "".join(ch.lower() for ch in normalized)
    return normalized


def current_platform() -> str:
    if sys.platform == "darwin":
        return "macos"
    if sys.platform == "win32":
        return "windows"
    return "unix"
