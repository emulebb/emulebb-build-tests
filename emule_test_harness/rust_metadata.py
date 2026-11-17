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


def initialize_local_discovery(rust_repo: Path, db_path: Path) -> None:
    """Mark both discovery domains initialized after staging a local fixture.

    Deliberately empty local lists are complete too. Require an existing current
    database and both canonical rows; never create or repair fixture state.
    """
    expected_marker = _schema_marker(rust_repo)
    with closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=rw", uri=True)) as conn:
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            markers = conn.execute("SELECT schema_id, schema_version FROM metadata_schema").fetchall()
            if markers != [expected_marker]:
                raise RuntimeError("local discovery requires the current metadata schema marker")
            changed = conn.execute(
                "UPDATE discovery_initialization SET status = 'initialized' "
                "WHERE domain IN ('servers', 'kad')"
            ).rowcount
            if changed != 2:
                raise RuntimeError("local discovery requires both canonical initialization rows")


def read_discovery_snapshot(rust_repo: Path, db_path: Path) -> dict[str, object]:
    """Read current-schema discovery state/counts coherently without creating files."""
    expected = _schema_marker(rust_repo)
    with closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        with conn:
            conn.execute("BEGIN")
            if conn.execute("SELECT schema_id, schema_version FROM metadata_schema").fetchall() != [expected]:
                raise RuntimeError("discovery snapshot requires the current metadata schema marker")
            states = dict(conn.execute("SELECT domain, status FROM discovery_initialization"))
            if set(states) != {"servers", "kad"} or any(status not in {"pending", "initialized"} for status in states.values()):
                raise RuntimeError("discovery snapshot requires both canonical initialization states")
            revision = conn.execute("SELECT revision FROM kad_routing_revision WHERE id=1").fetchone()
            if revision is None:
                raise RuntimeError("discovery snapshot requires the Kad routing revision singleton")
            return {
                "servers": {"status": states["servers"], "count": conn.execute(
                    "SELECT count(*) FROM servers WHERE deleted_at_ms IS NULL").fetchone()[0]},
                "kad": {"status": states["kad"], "revision": revision[0], "contactCount": conn.execute(
                    "SELECT count(*) FROM kad_routing_contacts").fetchone()[0], "bootstrapEndpointCount": conn.execute(
                    "SELECT count(*) FROM kad_bootstrap_endpoints").fetchone()[0]},
            }


def require_current_profile_database(rust_repo: Path, db_path: Path) -> None:
    """Check the selected marker, profile row, required job tables, and foreign keys.

    The Rust metadata opener remains the authority for full schema semantics.
    """

    schema_id, schema_version = _schema_marker(rust_repo)
    try:
        with closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
            marker = conn.execute("SELECT schema_id, schema_version FROM metadata_schema").fetchall()
            if marker != [(schema_id, schema_version)]:
                raise RuntimeError(
                    f"metadata schema marker must be {schema_id}@{schema_version}, got {marker!r}"
                )
            profile_count = conn.execute(
                "SELECT count(*) FROM profile WHERE id = 1"
            ).fetchone()[0]
            if profile_count != 1:
                raise RuntimeError("metadata profile singleton row is missing")
            for table in (
                "known_files", "download_history", "download_jobs", "download_job_pieces",
                "download_job_md4_part_hashes", "download_job_aich_part_hashes",
                "download_job_verified_ranges", "download_job_sources",
            ):
                conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
            if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise RuntimeError("metadata profile contains broken foreign-key references")
    except sqlite3.DatabaseError as exc:
        raise RuntimeError(f"invalid current Rust profile database {db_path}: {exc}") from exc


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
        _initialize_server_discovery(conn)
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
    """Deliberately empty the server list and prevent first-run repopulation."""

    with closing(sqlite3.connect(db_path)) as conn:
        _initialize_server_discovery(conn)
        conn.execute("DELETE FROM servers")
        conn.commit()


def _initialize_server_discovery(conn: sqlite3.Connection) -> None:
    """Claim fixture-owned server state in the caller's mutation transaction."""
    changed = conn.execute(
        "UPDATE discovery_initialization SET status = 'initialized' WHERE domain = 'servers'"
    ).rowcount
    if changed != 1:
        raise RuntimeError("server fixture requires its canonical initialization row")


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


def seed_download_job(
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
    aich_root_origin: str | None = None,
    aich_hashset: list[str] | None = None,
    sources: list[dict] | None = None,
    upload_priority: str = "normal",
    auto_upload_priority: bool = False,
    all_time_uploaded_bytes: int = 0,
    all_time_upload_requests: int = 0,
    all_time_upload_accepts: int = 0,
    last_upload_requested_at_s: int | None = None,
    comment: str = "",
    rating: int = 0,
) -> str:
    """Seed one fresh, ID-keyed download job without granting filesystem authority.

    A supplied AICH root is an operator-link claim. Existing accepted known-file,
    local-content, and completion-history facts remain authoritative. Completed
    fixture pieces have no delivered path or terminal completion claim.
    """
    hash_blob = bytes.fromhex(ed2k_hash)
    if len(hash_blob) != 16 or size_bytes <= 0 or piece_size <= 0:
        raise ValueError("fixture requires a 16-byte hash and positive size and piece size")
    if (aich_root is None) != (aich_root_origin is None) or aich_root_origin not in (None, "operator_link"):
        raise ValueError("a supplied fixture AICH root requires explicit operator_link origin")
    root_blob = bytes.fromhex(aich_root) if aich_root is not None else None
    if root_blob is not None and len(root_blob) != 20:
        raise ValueError("fixture AICH root must contain 20 bytes")
    md4_hashset = md4_hashset or []
    aich_hashset = aich_hashset or []
    sources = sources or []
    piece_count = (size_bytes + piece_size - 1) // piece_size
    now_ms = _now_ms()
    now_s = now_ms // 1000
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("BEGIN IMMEDIATE")
        history = conn.execute(
            "SELECT size_bytes, aich_root FROM download_history WHERE ed2k_hash = ?", (hash_blob,)
        ).fetchone()
        existing = conn.execute(
            "SELECT id, size_bytes, aich_root, aich_root_origin FROM known_files WHERE ed2k_hash = ?",
            (hash_blob,),
        ).fetchone()
        if existing is not None:
            active = conn.execute(
                """SELECT 1 FROM download_jobs WHERE known_file_id = ?
                   AND removed_at_s IS NULL AND terminal_completed_at_s IS NULL""",
                (existing[0],),
            ).fetchone()
            if active is not None:
                raise ValueError("cannot reseed established download job")
            local = conn.execute(
                "SELECT aich_root FROM verified_local_content WHERE known_file_id = ?", (existing[0],)
            ).fetchone()
            if local is not None and local[0] is not None and local[0] != existing[2]:
                raise ValueError("fixture requires coherent accepted local AICH identity")
            if existing[1] is not None and existing[1] != size_bytes:
                raise ValueError("fixture conflicts with accepted file size")
            if existing[2] is not None:
                if root_blob is not None and root_blob != existing[2]:
                    raise ValueError("fixture conflicts with accepted AICH root")
                root_blob, aich_root_origin = existing[2], existing[3]
        if history is not None and (
            history[0] != size_bytes
            or (history[1] is not None and root_blob is not None and history[1] != root_blob)
        ):
            raise ValueError("fixture conflicts with accepted download history")
        if aich_hashset_acquired and root_blob is None:
            raise ValueError("acquired AICH part hashes require an accepted root")
        if existing is None:
            conn.execute(
                """INSERT INTO known_files(
                   ed2k_hash, display_name, aich_root, aich_root_origin,
                   all_time_uploaded_bytes, all_time_upload_requests, all_time_upload_accepts,
                   last_upload_requested_at_s, first_seen_at_ms, last_seen_at_ms, updated_at_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (hash_blob, name, root_blob, aich_root_origin, all_time_uploaded_bytes,
                 all_time_upload_requests, all_time_upload_accepts, last_upload_requested_at_s,
                 now_ms, now_ms, now_ms),
            )
        known_file_id = conn.execute(
            "SELECT id FROM known_files WHERE ed2k_hash = ?", (hash_blob,)
        ).fetchone()[0]
        job_id = conn.execute(
            """INSERT INTO download_jobs(
               known_file_id, expected_size_bytes, display_name, part_size_bytes, part_count,
               upload_priority, auto_upload_priority, comment, rating, completed,
               md4_hashset_acquired, aich_hashset_acquired, aich_root, aich_root_origin,
               aich_trust_generation, visible_state, delivery_state, created_at_s,
               updated_at_s, completed_at_s)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)""",
            (known_file_id, size_bytes, name, piece_size, piece_count, upload_priority,
             int(auto_upload_priority), comment, rating, int(completed), int(md4_hashset_acquired),
             int(aich_hashset_acquired), root_blob, aich_root_origin,
             1 if root_blob is not None else 0, "completed" if completed else "queued",
             now_s, now_s, now_s if completed else None),
        ).lastrowid
        conn.execute(
            "UPDATE known_files SET latest_download_job_id = ? WHERE id = ?", (job_id, known_file_id)
        )
        for piece_index in range(piece_count):
            present_bytes = expected_piece_length(size_bytes, piece_size, piece_index) if completed else 0
            conn.execute(
                """INSERT INTO download_job_pieces(job_id, piece_index, state, prefix_bytes, present_bytes, updated_at_s)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (job_id, piece_index, "Verified" if completed else "Missing",
                 present_bytes, present_bytes, now_s),
            )
        for index, part_hash in enumerate(md4_hashset):
            conn.execute(
                "INSERT INTO download_job_md4_part_hashes(job_id, part_index, md4_hash) VALUES (?, ?, ?)",
                (job_id, index, bytes.fromhex(part_hash)),
            )
        for index, part_hash in enumerate(aich_hashset):
            conn.execute(
                "INSERT INTO download_job_aich_part_hashes(job_id, part_index, aich_hash) VALUES (?, ?, ?)",
                (job_id, index, bytes.fromhex(part_hash)),
            )
        for source in sources:
            user_hash = source.get("user_hash")
            conn.execute(
                """INSERT INTO download_job_sources(
                   job_id, ip, tcp_port, user_hash, first_seen_at_s, last_seen_at_s)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (job_id, source["ip"], source["tcp_port"],
                 bytes.fromhex(user_hash) if user_hash else None, now_s, now_s),
            )
        if completed:
            conn.execute(
                """INSERT INTO download_job_verified_ranges(job_id, start_offset, end_offset, created_at_s)
                   VALUES (?, 0, ?, ?)""",
                (job_id, size_bytes, now_s),
            )
        conn.commit()
        return str(job_id)


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


def read_download_job_manifest(db_path: Path, job_id: str) -> dict | None:
    """Read the captured job's persisted protocol manifest and identity facts."""
    if (not isinstance(job_id, str) or not job_id.isascii() or not job_id.isdecimal()
            or len(job_id) > 19
            or str(int(job_id)) != job_id or not 0 < int(job_id) <= 9223372036854775807):
        raise ValueError("job ID must be a positive canonical decimal i64 string")
    with closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        # A single snapshot keeps retirement of child rows from mixing with
        # an earlier job/header read during live two-client diagnostics.
        conn.execute("BEGIN")
        row = conn.execute(
            """SELECT jobs.id, lower(hex(known.ed2k_hash)), jobs.display_name,
                      jobs.expected_size_bytes, jobs.part_size_bytes, jobs.completed,
                      jobs.md4_hashset_acquired, jobs.aich_hashset_acquired,
                      CASE WHEN jobs.aich_root IS NULL THEN NULL ELSE lower(hex(jobs.aich_root)) END,
                      jobs.aich_root_origin, jobs.aich_trust_generation,
                      jobs.upload_priority, jobs.comment, jobs.rating, jobs.auto_upload_priority,
                      known.all_time_uploaded_bytes, known.all_time_upload_requests,
                      known.all_time_upload_accepts, known.last_upload_requested_at_s,
                      jobs.execution_generation, jobs.selected_temp_path_id, jobs.storage_path_id,
                      jobs.storage_directory_marker_id, jobs.terminal_completed_at_s,
                      jobs.internal_storage_retired, jobs.visible_state, jobs.intent,
                      jobs.known_file_id
               FROM download_jobs AS jobs
               JOIN known_files AS known ON known.id = jobs.known_file_id
               WHERE jobs.id = ?""",
            (int(job_id),),
        ).fetchone()
        if row is None:
            return None
        sources = [
            {"ip": src[0], "tcp_port": src[1], "user_hash": src[2]}
            for src in conn.execute(
                """SELECT ip, tcp_port,
                          CASE WHEN user_hash IS NULL THEN NULL ELSE lower(hex(user_hash)) END
                   FROM download_job_sources WHERE job_id = ? ORDER BY id""",
                (int(job_id),),
            )
        ]
        md4_hashset = [
            part[0] for part in conn.execute(
                "SELECT lower(hex(md4_hash)) FROM download_job_md4_part_hashes WHERE job_id = ? ORDER BY part_index",
                (int(job_id),),
            )
        ]
        aich_hashset = [
            part[0] for part in conn.execute(
                "SELECT lower(hex(aich_hash)) FROM download_job_aich_part_hashes WHERE job_id = ? ORDER BY part_index",
                (int(job_id),),
            )
        ]
        history = conn.execute(
            """SELECT size_bytes,
                      CASE WHEN aich_root IS NULL THEN NULL ELSE lower(hex(aich_root)) END,
                      first_completed_at_s, last_completed_at_s
               FROM download_history WHERE ed2k_hash = ?""",
            (bytes.fromhex(row[1]),),
        ).fetchone()
        verified = conn.execute(
            """SELECT content.display_name, content.part_size_bytes, content.part_count,
                      CASE WHEN content.aich_root IS NULL THEN NULL ELSE lower(hex(content.aich_root)) END,
                      content.known_file_id
               FROM verified_local_content AS content
               JOIN download_jobs AS jobs ON jobs.known_file_id = content.known_file_id
               WHERE jobs.id = ?""",
            (int(job_id),),
        ).fetchone()
        verified_md4 = [part[0] for part in conn.execute(
            """SELECT lower(hex(parts.md4_hash)) FROM verified_local_md4_hashes AS parts
               JOIN download_jobs AS jobs ON jobs.known_file_id = parts.known_file_id
               WHERE jobs.id = ? ORDER BY parts.part_index""", (int(job_id),)
        )]
        verified_aich = [part[0] for part in conn.execute(
            """SELECT lower(hex(parts.aich_hash)) FROM verified_local_aich_hashes AS parts
               JOIN download_jobs AS jobs ON jobs.known_file_id = parts.known_file_id
               WHERE jobs.id = ? ORDER BY parts.part_index""", (int(job_id),)
        )]
    return {
        "job_id": str(row[0]), "file_hash": row[1], "canonical_name": row[2],
        "file_size": row[3], "piece_size": row[4], "completed": bool(row[5]),
        "md4_hashset_acquired": bool(row[6]), "aich_hashset_acquired": bool(row[7]),
        "aich_root": row[8], "aich_root_origin": row[9], "aich_trust_generation": row[10],
        "upload_priority": row[11], "comment": row[12], "rating": row[13],
        "auto_upload_priority": bool(row[14]), "all_time_uploaded_bytes": row[15],
        "all_time_upload_requests": row[16], "all_time_upload_accepts": row[17],
        "last_upload_requested_at_s": row[18], "execution_generation": row[19],
        "selected_temp_path_id": row[20], "storage_path_id": row[21],
        "storage_directory_marker_id": row[22], "terminal_completed_at_s": row[23],
        "internal_storage_retired": bool(row[24]), "visible_state": row[25], "intent": row[26],
        "known_file_id": row[27],
        "md4_hashset": md4_hashset, "aich_hashset": aich_hashset, "sources": sources,
        "completion_history": None if history is None else {
            "size_bytes": history[0], "aich_root": history[1],
            "first_completed_at_s": history[2], "last_completed_at_s": history[3],
        },
        "verified_local_content": None if verified is None else {
            "display_name": verified[0], "part_size_bytes": verified[1],
            "part_count": verified[2], "aich_root": verified[3],
            "known_file_id": verified[4],
            "md4_hashset": verified_md4, "aich_hashset": verified_aich,
        },
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
