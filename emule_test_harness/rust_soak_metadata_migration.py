"""Internal test/soak profile schema evolution outside the Rust product.

These helpers preserve harness-owned persistent test and soak profiles to speed
engineering validation. They are not a supported end-user migration or recovery
path. The Rust client itself stays current-schema-only and must require end users
with an incompatible schema to create an entirely fresh profile.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
from pathlib import Path

from . import rust_metadata
from .paths import get_required_emule_workspace_root, get_workspace_output_root

FROM_SCHEMA_VERSION = 15
V16_SCHEMA_VERSION = 16
V17_SCHEMA_VERSION = 17
V18_SCHEMA_VERSION = 18
V19_SCHEMA_VERSION = 19
V20_SCHEMA_VERSION = 20
V21_SCHEMA_VERSION = 21
V22_SCHEMA_VERSION = 22
V23_SCHEMA_VERSION = 23
V24_SCHEMA_VERSION = 24
SCHEMA = "emulebb-build-tests.rust-soak-metadata-migration.v1"
SHARED_ROOT_COLUMNS = (
    "id",
    "path_id",
    "monitor_owned",
    "shareable",
    "accessible",
    "enabled",
    "last_scan_ms",
    "created_at_ms",
    "deleted_at_ms",
)
KNOWN_FILES_COLUMNS = (
    "id",
    "ed2k_hash",
    "size_bytes",
    "display_name",
    "content_type",
    "part_size",
    "part_count",
    "completed",
    "md4_hashset_acquired",
    "aich_hashset_acquired",
    "aich_root",
    "upload_priority",
    "auto_upload_priority",
    "comment",
    "rating",
    "availability_score",
    "all_time_uploaded_bytes",
    "all_time_upload_requests",
    "all_time_upload_accepts",
    "last_upload_request_ms",
    "first_seen_ms",
    "last_seen_ms",
    "updated_at_ms",
)


def default_rust_repo() -> Path:
    return get_required_emule_workspace_root() / "repos" / "emulebb-rust"


def default_metadata_db() -> Path:
    return (
        get_workspace_output_root()
        / "soak"
        / "rust-runtime"
        / rust_metadata.RUST_PROFILE_METADATA_FILE
    )


def schema_marker(db_path: Path, schema_id: str) -> int | None:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT schema_version FROM metadata_schema WHERE schema_id = ?",
            (schema_id,),
        ).fetchone()
    return int(row[0]) if row else None


def table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table}")')]


def extract_create_table(schema_sql: str, table: str) -> str:
    start_token = f"CREATE TABLE {table} ("
    start = schema_sql.find(start_token)
    if start < 0:
        raise RuntimeError(f"current Rust schema does not define {table}")
    end = schema_sql.find("\n);", start)
    if end < 0:
        raise RuntimeError(
            f"current Rust schema table definition is truncated for {table}"
        )
    return schema_sql[start : end + 3]


def current_shared_roots_table_sql(rust_repo: Path, table_name: str) -> str:
    ddl = extract_create_table(
        rust_metadata._schema_sql(rust_repo), "shared_directory_roots"
    )
    return ddl.replace(
        "CREATE TABLE shared_directory_roots", f"CREATE TABLE {table_name}", 1
    )


def backup_database(db_path: Path, backup_dir: Path | None, label: str) -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    target_dir = backup_dir or db_path.parent
    target_dir.mkdir(parents=True, exist_ok=True)
    backup_path = target_dir / f"{db_path.stem}.backup-{label}-{stamp}{db_path.suffix}"
    if backup_path.exists():
        raise RuntimeError(f"backup path already exists: {backup_path}")
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as source:
        with sqlite3.connect(backup_path) as backup:
            source.backup(backup)
    return backup_path


def migrate_v15_to_v16(
    *,
    db_path: Path,
    rust_repo: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    db_path = db_path.resolve()
    rust_repo = rust_repo.resolve()
    if not db_path.is_file():
        raise RuntimeError(f"metadata database does not exist: {db_path}")

    schema_id, _current_version = rust_metadata._schema_marker(rust_repo)

    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        before_version = schema_marker(db_path, schema_id)
        if before_version is None:
            raise RuntimeError(f"metadata_schema row is missing for {schema_id}")
        columns = table_columns(conn, "shared_directory_roots")
        row_count = int(
            conn.execute("SELECT count(*) FROM shared_directory_roots").fetchone()[0]
        )

    if before_version >= V16_SCHEMA_VERSION and "recursive" not in columns:
        return {
            "schema": SCHEMA,
            "action": "noop-v16-shape-current",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "schemaVersion": before_version,
            "sharedDirectoryRoots": row_count,
        }
    if before_version != FROM_SCHEMA_VERSION or "recursive" not in columns:
        raise RuntimeError(
            "metadata DB is not the bounded v15 soak profile shape "
            f"(schemaVersion={before_version}, columns={columns})"
        )
    if dry_run:
        return {
            "schema": SCHEMA,
            "action": "would-migrate-v15-to-v16",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "fromSchemaVersion": FROM_SCHEMA_VERSION,
            "toSchemaVersion": V16_SCHEMA_VERSION,
            "sharedDirectoryRoots": row_count,
        }

    backup_path = backup_database(db_path, backup_dir, "v15-to-v16")
    temp_table = "shared_directory_roots_v16_migrating"
    column_csv = ", ".join(SHARED_ROOT_COLUMNS)
    create_temp_sql = current_shared_roots_table_sql(rust_repo, temp_table)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(f"DROP TABLE IF EXISTS {temp_table}")
            conn.execute(create_temp_sql)
            conn.execute(
                f"INSERT INTO {temp_table}({column_csv}) "
                f"SELECT {column_csv} FROM shared_directory_roots"
            )
            conn.execute("DROP TABLE shared_directory_roots")
            conn.execute(f"ALTER TABLE {temp_table} RENAME TO shared_directory_roots")
            conn.execute(
                "UPDATE metadata_schema SET schema_version = ? WHERE schema_id = ?",
                (V16_SCHEMA_VERSION, schema_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.execute("PRAGMA foreign_keys = ON")
        fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_issues:
            raise RuntimeError(
                f"foreign key check failed after migration: {fk_issues[:5]}"
            )
        after_columns = table_columns(conn, "shared_directory_roots")
        after_version = schema_marker(db_path, schema_id)

    return {
        "schema": SCHEMA,
        "action": "migrated-v15-to-v16",
        "metadataDb": str(db_path),
        "backup": str(backup_path),
        "schemaId": schema_id,
        "fromSchemaVersion": before_version,
        "toSchemaVersion": after_version,
        "removedColumn": "shared_directory_roots.recursive",
        "sharedDirectoryRoots": row_count,
        "columns": after_columns,
    }


def current_known_files_table_sql(rust_repo: Path, table_name: str) -> str:
    ddl = extract_create_table(rust_metadata._schema_sql(rust_repo), "known_files")
    return ddl.replace("CREATE TABLE known_files", f"CREATE TABLE {table_name}", 1)


def current_transfers_table_sql(rust_repo: Path, table_name: str) -> str:
    ddl = extract_create_table(rust_metadata._schema_sql(rust_repo), "transfers")
    return ddl.replace("CREATE TABLE transfers", f"CREATE TABLE {table_name}", 1)


def current_imported_known_files_sql(rust_repo: Path) -> str:
    schema_sql = rust_metadata._schema_sql(rust_repo)
    start_token = "CREATE TABLE imported_known_files ("
    end_token = "CREATE TABLE verified_ranges ("
    start = schema_sql.find(start_token)
    end = schema_sql.find(end_token, start)
    if start < 0 or end < 0:
        raise RuntimeError(
            "current Rust schema does not define imported known-file tables"
        )
    return (
        schema_sql[start:end]
        .replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
        .replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ")
    )


def known_files_allows_not_published(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'known_files'"
    ).fetchone()
    return bool(row and "not-published" in str(row[0]))


def migrate_v16_to_v17(
    *,
    db_path: Path,
    rust_repo: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    db_path = db_path.resolve()
    rust_repo = rust_repo.resolve()
    if not db_path.is_file():
        raise RuntimeError(f"metadata database does not exist: {db_path}")

    schema_id, current_version = rust_metadata._schema_marker(rust_repo)
    if current_version < V17_SCHEMA_VERSION:
        raise RuntimeError(
            f"this migration requires Rust schema {V17_SCHEMA_VERSION}+; current schema is {current_version}"
        )

    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        before_version = schema_marker(db_path, schema_id)
        if before_version is None:
            raise RuntimeError(f"metadata_schema row is missing for {schema_id}")
        columns = table_columns(conn, "known_files")
        row_count = int(conn.execute("SELECT count(*) FROM known_files").fetchone()[0])
        already_allows = known_files_allows_not_published(conn)

    if before_version >= V17_SCHEMA_VERSION and already_allows:
        return {
            "schema": SCHEMA,
            "action": "noop-v17-shape-current",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "schemaVersion": before_version,
            "knownFiles": row_count,
        }
    if before_version != V16_SCHEMA_VERSION or columns != list(KNOWN_FILES_COLUMNS):
        raise RuntimeError(
            "metadata DB is not the bounded v16 soak profile shape "
            f"(schemaVersion={before_version}, columns={columns})"
        )
    if dry_run:
        return {
            "schema": SCHEMA,
            "action": "would-migrate-v16-to-v17",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "fromSchemaVersion": V16_SCHEMA_VERSION,
            "toSchemaVersion": V17_SCHEMA_VERSION,
            "knownFiles": row_count,
        }

    backup_path = backup_database(db_path, backup_dir, "v16-to-v17")
    temp_table = "known_files_v17_migrating"
    column_csv = ", ".join(KNOWN_FILES_COLUMNS)
    create_temp_sql = current_known_files_table_sql(rust_repo, temp_table)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(f"DROP TABLE IF EXISTS {temp_table}")
            conn.execute(create_temp_sql)
            conn.execute(
                f"INSERT INTO {temp_table}({column_csv}) "
                f"SELECT {column_csv} FROM known_files"
            )
            conn.execute("DROP TABLE known_files")
            conn.execute(f"ALTER TABLE {temp_table} RENAME TO known_files")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS known_files_hash_idx ON known_files(ed2k_hash)"
            )
            conn.execute(
                "UPDATE metadata_schema SET schema_version = ? WHERE schema_id = ?",
                (V17_SCHEMA_VERSION, schema_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.execute("PRAGMA foreign_keys = ON")
        fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_issues:
            raise RuntimeError(
                f"foreign key check failed after migration: {fk_issues[:5]}"
            )
        after_version = schema_marker(db_path, schema_id)
        after_allows = known_files_allows_not_published(conn)

    return {
        "schema": SCHEMA,
        "action": "migrated-v16-to-v17",
        "metadataDb": str(db_path),
        "backup": str(backup_path),
        "schemaId": schema_id,
        "fromSchemaVersion": before_version,
        "toSchemaVersion": after_version,
        "allowedPriority": "not-published",
        "knownFiles": row_count,
        "knownFilesAllowsNotPublished": after_allows,
    }


SERVER_UDP_METADATA_COLUMNS = (
    "max_users",
    "low_id_users",
    "obfuscation_udp_port",
    "udp_key",
    "udp_key_ip",
)


def migrate_v18_to_v19(
    *,
    db_path: Path,
    rust_repo: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    """Add persisted server UDP key binding and obfuscated-port metadata."""

    db_path = db_path.resolve()
    rust_repo = rust_repo.resolve()
    if not db_path.is_file():
        raise RuntimeError(f"metadata database does not exist: {db_path}")

    schema_id, current_version = rust_metadata._schema_marker(rust_repo)
    if current_version < V19_SCHEMA_VERSION:
        raise RuntimeError(
            f"this migration requires Rust schema {V19_SCHEMA_VERSION}+; current schema is {current_version}"
        )
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        before_version = schema_marker(db_path, schema_id)
        if before_version is None:
            raise RuntimeError(f"metadata_schema row is missing for {schema_id}")
        columns = table_columns(conn, "servers")
        server_count = int(conn.execute("SELECT count(*) FROM servers").fetchone()[0])
    missing = [name for name in SERVER_UDP_METADATA_COLUMNS if name not in columns]

    if before_version >= V19_SCHEMA_VERSION and not missing:
        return {
            "schema": SCHEMA,
            "action": "noop-v19-shape-current",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "schemaVersion": before_version,
            "servers": server_count,
        }
    if before_version != V18_SCHEMA_VERSION:
        raise RuntimeError(
            "metadata DB is not the bounded v18 server shape "
            f"(schemaVersion={before_version}, columns={columns})"
        )
    if dry_run:
        return {
            "schema": SCHEMA,
            "action": "would-migrate-v18-to-v19",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "fromSchemaVersion": V18_SCHEMA_VERSION,
            "toSchemaVersion": V19_SCHEMA_VERSION,
            "addedColumns": missing,
            "servers": server_count,
        }

    backup_path = backup_database(db_path, backup_dir, "v18-to-v19")
    column_ddl = {
        "max_users": "INTEGER CHECK(max_users IS NULL OR max_users >= 0)",
        "low_id_users": "INTEGER CHECK(low_id_users IS NULL OR low_id_users >= 0)",
        "obfuscation_udp_port": (
            "INTEGER CHECK(obfuscation_udp_port IS NULL OR "
            "obfuscation_udp_port BETWEEN 1 AND 65535)"
        ),
        "udp_key": "INTEGER CHECK(udp_key IS NULL OR udp_key BETWEEN 1 AND 4294967295)",
        "udp_key_ip": (
            "INTEGER CHECK(udp_key_ip IS NULL OR udp_key_ip BETWEEN 1 AND 4294967295)"
        ),
    }
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            for column in missing:
                conn.execute(f"ALTER TABLE servers ADD COLUMN {column} {column_ddl[column]}")
            conn.execute(
                "UPDATE metadata_schema SET schema_version = ? WHERE schema_id = ?",
                (V19_SCHEMA_VERSION, schema_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_issues:
            raise RuntimeError(
                f"foreign key check failed after migration: {fk_issues[:5]}"
            )
        after_version = schema_marker(db_path, schema_id)
        after_columns = table_columns(conn, "servers")

    return {
        "schema": SCHEMA,
        "action": "migrated-v18-to-v19",
        "metadataDb": str(db_path),
        "backup": str(backup_path),
        "schemaId": schema_id,
        "fromSchemaVersion": before_version,
        "toSchemaVersion": after_version,
        "addedColumns": missing,
        "columns": after_columns,
        "servers": server_count,
    }


def migrate_v19_to_v20(
    *,
    db_path: Path,
    rust_repo: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    """Add the persisted per-source eMule connect-options byte."""

    db_path = db_path.resolve()
    rust_repo = rust_repo.resolve()
    if not db_path.is_file():
        raise RuntimeError(f"metadata database does not exist: {db_path}")

    schema_id, current_version = rust_metadata._schema_marker(rust_repo)
    if current_version < V20_SCHEMA_VERSION:
        raise RuntimeError(
            f"this migration requires Rust schema {V20_SCHEMA_VERSION}+; current schema is {current_version}"
        )
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        before_version = schema_marker(db_path, schema_id)
        if before_version is None:
            raise RuntimeError(f"metadata_schema row is missing for {schema_id}")
        columns = table_columns(conn, "transfer_sources")
        source_count = int(
            conn.execute("SELECT count(*) FROM transfer_sources").fetchone()[0]
        )
    has_connect_options = "connect_options" in columns

    if before_version >= V20_SCHEMA_VERSION and has_connect_options:
        return {
            "schema": SCHEMA,
            "action": "noop-v20-shape-current",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "schemaVersion": before_version,
            "transferSources": source_count,
        }
    if before_version != V19_SCHEMA_VERSION:
        raise RuntimeError(
            "metadata DB is not the bounded v19 transfer-source shape "
            f"(schemaVersion={before_version}, columns={columns})"
        )
    if dry_run:
        return {
            "schema": SCHEMA,
            "action": "would-migrate-v19-to-v20",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "fromSchemaVersion": V19_SCHEMA_VERSION,
            "toSchemaVersion": V20_SCHEMA_VERSION,
            "addedColumns": (
                [] if has_connect_options else ["transfer_sources.connect_options"]
            ),
            "transferSources": source_count,
        }

    backup_path = backup_database(db_path, backup_dir, "v19-to-v20")
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            if not has_connect_options:
                conn.execute(
                    "ALTER TABLE transfer_sources ADD COLUMN connect_options "
                    "INTEGER CHECK(connect_options IS NULL OR connect_options BETWEEN 0 AND 255)"
                )
            conn.execute(
                "UPDATE metadata_schema SET schema_version = ? WHERE schema_id = ?",
                (V20_SCHEMA_VERSION, schema_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_issues:
            raise RuntimeError(
                f"foreign key check failed after migration: {fk_issues[:5]}"
            )
        after_version = schema_marker(db_path, schema_id)
        after_columns = table_columns(conn, "transfer_sources")

    return {
        "schema": SCHEMA,
        "action": "migrated-v19-to-v20",
        "metadataDb": str(db_path),
        "backup": str(backup_path),
        "schemaId": schema_id,
        "fromSchemaVersion": before_version,
        "toSchemaVersion": after_version,
        "addedColumns": (
            [] if has_connect_options else ["transfer_sources.connect_options"]
        ),
        "columns": after_columns,
        "transferSources": source_count,
    }


def migrate_v20_to_v21(
    *,
    db_path: Path,
    rust_repo: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    """Add durable per-source file comments and ratings."""

    db_path = db_path.resolve()
    rust_repo = rust_repo.resolve()
    if not db_path.is_file():
        raise RuntimeError(f"metadata database does not exist: {db_path}")

    schema_id, current_version = rust_metadata._schema_marker(rust_repo)
    if current_version < V21_SCHEMA_VERSION:
        raise RuntimeError(
            f"this migration requires Rust schema {V21_SCHEMA_VERSION}+; current schema is {current_version}"
        )
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        before_version = schema_marker(db_path, schema_id)
        if before_version is None:
            raise RuntimeError(f"metadata_schema row is missing for {schema_id}")
        columns = table_columns(conn, "transfer_sources")
        source_count = int(
            conn.execute("SELECT count(*) FROM transfer_sources").fetchone()[0]
        )
    missing = [
        column
        for column in ("file_comment", "file_rating")
        if column not in columns
    ]

    if before_version >= V21_SCHEMA_VERSION and not missing:
        return {
            "schema": SCHEMA,
            "action": "noop-v21-shape-current",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "schemaVersion": before_version,
            "transferSources": source_count,
        }
    if before_version != V20_SCHEMA_VERSION:
        raise RuntimeError(
            "metadata DB is not the bounded v20 transfer-source shape "
            f"(schemaVersion={before_version}, columns={columns})"
        )
    added_columns = [f"transfer_sources.{column}" for column in missing]
    if dry_run:
        return {
            "schema": SCHEMA,
            "action": "would-migrate-v20-to-v21",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "fromSchemaVersion": V20_SCHEMA_VERSION,
            "toSchemaVersion": V21_SCHEMA_VERSION,
            "addedColumns": added_columns,
            "transferSources": source_count,
        }

    backup_path = backup_database(db_path, backup_dir, "v20-to-v21")
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            if "file_comment" in missing:
                conn.execute(
                    "ALTER TABLE transfer_sources ADD COLUMN file_comment "
                    "TEXT NOT NULL DEFAULT ''"
                )
            if "file_rating" in missing:
                conn.execute(
                    "ALTER TABLE transfer_sources ADD COLUMN file_rating "
                    "INTEGER NOT NULL DEFAULT 0 CHECK(file_rating BETWEEN 0 AND 255)"
                )
            conn.execute(
                "UPDATE metadata_schema SET schema_version = ? WHERE schema_id = ?",
                (V21_SCHEMA_VERSION, schema_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_issues:
            raise RuntimeError(
                f"foreign key check failed after migration: {fk_issues[:5]}"
            )
        after_version = schema_marker(db_path, schema_id)
        after_columns = table_columns(conn, "transfer_sources")

    return {
        "schema": SCHEMA,
        "action": "migrated-v20-to-v21",
        "metadataDb": str(db_path),
        "backup": str(backup_path),
        "schemaId": schema_id,
        "fromSchemaVersion": before_version,
        "toSchemaVersion": after_version,
        "addedColumns": added_columns,
        "columns": after_columns,
        "transferSources": source_count,
    }


def migrate_v21_to_v22(
    *,
    db_path: Path,
    rust_repo: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    """Add durable dynamic-host and auxiliary-port server metadata."""

    db_path = db_path.resolve()
    rust_repo = rust_repo.resolve()
    if not db_path.is_file():
        raise RuntimeError(f"metadata database does not exist: {db_path}")

    schema_id, current_version = rust_metadata._schema_marker(rust_repo)
    if current_version < V22_SCHEMA_VERSION:
        raise RuntimeError(
            f"this migration requires Rust schema {V22_SCHEMA_VERSION}+; current schema is {current_version}"
        )
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        before_version = schema_marker(db_path, schema_id)
        if before_version is None:
            raise RuntimeError(f"metadata_schema row is missing for {schema_id}")
        columns = table_columns(conn, "servers")
        server_count = int(conn.execute("SELECT count(*) FROM servers").fetchone()[0])
    missing = [
        column
        for column in ("dynamic_host", "auxiliary_ports")
        if column not in columns
    ]

    if before_version >= V22_SCHEMA_VERSION and not missing:
        return {
            "schema": SCHEMA,
            "action": "noop-v22-shape-current",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "schemaVersion": before_version,
            "servers": server_count,
        }
    if before_version != V21_SCHEMA_VERSION:
        raise RuntimeError(
            "metadata DB is not the bounded v21 server-metadata shape "
            f"(schemaVersion={before_version}, columns={columns})"
        )
    added_columns = [f"servers.{column}" for column in missing]
    if dry_run:
        return {
            "schema": SCHEMA,
            "action": "would-migrate-v21-to-v22",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "fromSchemaVersion": V21_SCHEMA_VERSION,
            "toSchemaVersion": V22_SCHEMA_VERSION,
            "addedColumns": added_columns,
            "servers": server_count,
        }

    backup_path = backup_database(db_path, backup_dir, "v21-to-v22")
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            if "dynamic_host" in missing:
                conn.execute(
                    "ALTER TABLE servers ADD COLUMN dynamic_host TEXT NOT NULL DEFAULT ''"
                )
            if "auxiliary_ports" in missing:
                conn.execute(
                    "ALTER TABLE servers ADD COLUMN auxiliary_ports TEXT NOT NULL DEFAULT ''"
                )
            conn.execute(
                "UPDATE metadata_schema SET schema_version = ? WHERE schema_id = ?",
                (V22_SCHEMA_VERSION, schema_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_issues:
            raise RuntimeError(
                f"foreign key check failed after migration: {fk_issues[:5]}"
            )
        after_version = schema_marker(db_path, schema_id)
        after_columns = table_columns(conn, "servers")

    return {
        "schema": SCHEMA,
        "action": "migrated-v21-to-v22",
        "metadataDb": str(db_path),
        "backup": str(backup_path),
        "schemaId": schema_id,
        "fromSchemaVersion": before_version,
        "toSchemaVersion": after_version,
        "addedColumns": added_columns,
        "columns": after_columns,
        "servers": server_count,
    }


KNOWN_FILES_MEDIA_COLUMNS = {
    "media_artist": "TEXT NOT NULL DEFAULT ''",
    "media_album": "TEXT NOT NULL DEFAULT ''",
    "media_title": "TEXT NOT NULL DEFAULT ''",
    "media_length_seconds": (
        "INTEGER NOT NULL DEFAULT 0 CHECK(media_length_seconds >= 0)"
    ),
    "media_bitrate_kbps": (
        "INTEGER NOT NULL DEFAULT 0 CHECK(media_bitrate_kbps >= 0)"
    ),
    "media_codec": "TEXT NOT NULL DEFAULT ''",
    "media_extractor_version": (
        "INTEGER NOT NULL DEFAULT 0 CHECK(media_extractor_version >= 0)"
    ),
}


def migrate_v22_to_v23(
    *,
    db_path: Path,
    rust_repo: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    """Add cached media metadata to the completed-file catalog."""

    db_path = db_path.resolve()
    rust_repo = rust_repo.resolve()
    if not db_path.is_file():
        raise RuntimeError(f"metadata database does not exist: {db_path}")

    schema_id, current_version = rust_metadata._schema_marker(rust_repo)
    if current_version < V23_SCHEMA_VERSION:
        raise RuntimeError(
            f"this migration requires Rust schema {V23_SCHEMA_VERSION}+; current schema is {current_version}"
        )
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        before_version = schema_marker(db_path, schema_id)
        if before_version is None:
            raise RuntimeError(f"metadata_schema row is missing for {schema_id}")
        columns = table_columns(conn, "known_files")
        known_file_count = int(
            conn.execute("SELECT count(*) FROM known_files").fetchone()[0]
        )
    missing = [name for name in KNOWN_FILES_MEDIA_COLUMNS if name not in columns]

    if before_version >= V23_SCHEMA_VERSION and not missing:
        return {
            "schema": SCHEMA,
            "action": "noop-v23-shape-current",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "schemaVersion": before_version,
            "knownFiles": known_file_count,
        }
    if before_version != V22_SCHEMA_VERSION:
        raise RuntimeError(
            "metadata DB is not the bounded v22 known-files shape "
            f"(schemaVersion={before_version}, columns={columns})"
        )
    added_columns = [f"known_files.{column}" for column in missing]
    if dry_run:
        return {
            "schema": SCHEMA,
            "action": "would-migrate-v22-to-v23",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "fromSchemaVersion": V22_SCHEMA_VERSION,
            "toSchemaVersion": V23_SCHEMA_VERSION,
            "addedColumns": added_columns,
            "knownFiles": known_file_count,
        }

    backup_path = backup_database(db_path, backup_dir, "v22-to-v23")
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            for column in missing:
                conn.execute(
                    f"ALTER TABLE known_files ADD COLUMN {column} "
                    f"{KNOWN_FILES_MEDIA_COLUMNS[column]}"
                )
            conn.execute(
                "UPDATE metadata_schema SET schema_version = ? WHERE schema_id = ?",
                (V23_SCHEMA_VERSION, schema_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_issues:
            raise RuntimeError(
                f"foreign key check failed after migration: {fk_issues[:5]}"
            )
        after_version = schema_marker(db_path, schema_id)
        after_columns = table_columns(conn, "known_files")

    return {
        "schema": SCHEMA,
        "action": "migrated-v22-to-v23",
        "metadataDb": str(db_path),
        "backup": str(backup_path),
        "schemaId": schema_id,
        "fromSchemaVersion": before_version,
        "toSchemaVersion": after_version,
        "addedColumns": added_columns,
        "columns": after_columns,
        "knownFiles": known_file_count,
    }


def migrate_v23_to_v24(
    *,
    db_path: Path,
    rust_repo: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    """Install the durable final-rehash gate for undelivered downloads."""

    db_path = db_path.resolve()
    rust_repo = rust_repo.resolve()
    if not db_path.is_file():
        raise RuntimeError(f"metadata database does not exist: {db_path}")

    schema_id, current_version = rust_metadata._schema_marker(rust_repo)
    if current_version < V24_SCHEMA_VERSION:
        raise RuntimeError(
            f"this migration requires Rust schema {V24_SCHEMA_VERSION}+; current schema is {current_version}"
        )
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        before_version = schema_marker(db_path, schema_id)
        if before_version is None:
            raise RuntimeError(f"metadata_schema row is missing for {schema_id}")
        columns = table_columns(conn, "transfers")
        table_sql_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'transfers'"
        ).fetchone()
        table_sql = str(table_sql_row[0]) if table_sql_row else ""
        transfer_count = int(conn.execute("SELECT count(*) FROM transfers").fetchone()[0])
        pending_count = int(
            conn.execute(
                """
                SELECT count(*)
                FROM transfers
                JOIN known_files ON known_files.id = transfers.known_file_id
                WHERE known_files.completed = 1
                  AND transfers.delivered_path_id IS NULL
                  AND transfers.source_path_id IS NULL
                  AND transfers.removed_at_ms IS NULL
                """
            ).fetchone()[0]
        )
    has_gate = "final_rehash_pending" in columns
    allows_completing = "'completing'" in table_sql

    if before_version >= V24_SCHEMA_VERSION and has_gate and allows_completing:
        return {
            "schema": SCHEMA,
            "action": "noop-v24-shape-current",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "schemaVersion": before_version,
            "transfers": transfer_count,
        }
    if before_version != V23_SCHEMA_VERSION or has_gate or allows_completing:
        raise RuntimeError(
            "metadata DB is not the bounded v23 transfer shape "
            f"(schemaVersion={before_version}, columns={columns})"
        )
    if dry_run:
        return {
            "schema": SCHEMA,
            "action": "would-migrate-v23-to-v24",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "fromSchemaVersion": V23_SCHEMA_VERSION,
            "toSchemaVersion": V24_SCHEMA_VERSION,
            "transfers": transfer_count,
            "undeliveredDownloadsPendingRehash": pending_count,
        }

    backup_path = backup_database(db_path, backup_dir, "v23-to-v24")
    temp_table = "transfers_v24_migrating"
    create_temp_sql = current_transfers_table_sql(rust_repo, temp_table)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(f"DROP TABLE IF EXISTS {temp_table}")
            conn.execute(create_temp_sql)
            conn.execute(
                f"""
                INSERT INTO {temp_table}(
                    id, known_file_id, visible_state, final_rehash_pending,
                    control_state, category_id, download_priority, target_path_id,
                    payload_directory, delivered_path_id, source_path_id,
                    source_mtime_ms, created_at_ms, updated_at_ms,
                    completed_at_ms, removed_at_ms
                )
                SELECT
                    transfers.id,
                    transfers.known_file_id,
                    CASE
                        WHEN known_files.completed = 1
                         AND transfers.delivered_path_id IS NULL
                         AND transfers.source_path_id IS NULL
                         AND transfers.removed_at_ms IS NULL
                        THEN 'completing'
                        ELSE transfers.visible_state
                    END,
                    CASE
                        WHEN known_files.completed = 1
                         AND transfers.delivered_path_id IS NULL
                         AND transfers.source_path_id IS NULL
                         AND transfers.removed_at_ms IS NULL
                        THEN 1
                        ELSE 0
                    END,
                    transfers.control_state,
                    transfers.category_id,
                    transfers.download_priority,
                    transfers.target_path_id,
                    transfers.payload_directory,
                    transfers.delivered_path_id,
                    transfers.source_path_id,
                    transfers.source_mtime_ms,
                    transfers.created_at_ms,
                    transfers.updated_at_ms,
                    CASE
                        WHEN known_files.completed = 1
                         AND transfers.delivered_path_id IS NULL
                         AND transfers.source_path_id IS NULL
                         AND transfers.removed_at_ms IS NULL
                        THEN NULL
                        ELSE transfers.completed_at_ms
                    END,
                    transfers.removed_at_ms
                FROM transfers
                JOIN known_files ON known_files.id = transfers.known_file_id
                """
            )
            conn.execute(
                f"""
                UPDATE known_files
                SET completed = 0
                WHERE id IN (
                    SELECT known_file_id
                    FROM {temp_table}
                    WHERE final_rehash_pending = 1
                )
                """
            )
            conn.execute("DROP TABLE transfers")
            conn.execute(f"ALTER TABLE {temp_table} RENAME TO transfers")
            conn.execute(
                "UPDATE metadata_schema SET schema_version = ? WHERE schema_id = ?",
                (V24_SCHEMA_VERSION, schema_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.execute("PRAGMA foreign_keys = ON")
        fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_issues:
            raise RuntimeError(
                f"foreign key check failed after migration: {fk_issues[:5]}"
            )
        after_version = schema_marker(db_path, schema_id)
        after_columns = table_columns(conn, "transfers")

    return {
        "schema": SCHEMA,
        "action": "migrated-v23-to-v24",
        "metadataDb": str(db_path),
        "backup": str(backup_path),
        "schemaId": schema_id,
        "fromSchemaVersion": before_version,
        "toSchemaVersion": after_version,
        "addedColumns": ["transfers.final_rehash_pending"],
        "transfers": transfer_count,
        "undeliveredDownloadsPendingRehash": pending_count,
        "columns": after_columns,
    }


def migrate_to_current(
    *,
    db_path: Path,
    rust_repo: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    db_path = db_path.resolve()
    rust_repo = rust_repo.resolve()
    schema_id, current_version = rust_metadata._schema_marker(rust_repo)
    before_version = schema_marker(db_path, schema_id)
    if before_version is None:
        raise RuntimeError(f"metadata_schema row is missing for {schema_id}")
    original_version = before_version
    steps: list[dict[str, object]] = []

    if before_version == current_version:
        return {
            "schema": SCHEMA,
            "action": "noop-current",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "fromSchemaVersion": original_version,
            "toSchemaVersion": current_version,
            "steps": steps,
        }

    if before_version == FROM_SCHEMA_VERSION:
        result = migrate_v15_to_v16(
            db_path=db_path,
            rust_repo=rust_repo,
            backup_dir=backup_dir,
            dry_run=dry_run,
        )
        steps.append(result)
        if dry_run:
            return {
                "schema": SCHEMA,
                "action": "would-migrate-to-current",
                "metadataDb": str(db_path),
                "schemaId": schema_id,
                "fromSchemaVersion": before_version,
                "toSchemaVersion": current_version,
                "steps": steps,
            }
        before_version = schema_marker(db_path, schema_id)

    if before_version in (V16_SCHEMA_VERSION, V17_SCHEMA_VERSION):
        result = migrate_v16_to_v17(
            db_path=db_path,
            rust_repo=rust_repo,
            backup_dir=backup_dir,
            dry_run=dry_run,
        )
        steps.append(result)
    elif before_version not in (
        V18_SCHEMA_VERSION,
        V19_SCHEMA_VERSION,
        V20_SCHEMA_VERSION,
        V21_SCHEMA_VERSION,
        V22_SCHEMA_VERSION,
        V23_SCHEMA_VERSION,
    ):
        raise RuntimeError(
            f"metadata DB schemaVersion={before_version} cannot be migrated to current {current_version}"
        )

    if not dry_run:
        before_version = schema_marker(db_path, schema_id)
    elif before_version in (V16_SCHEMA_VERSION, V17_SCHEMA_VERSION):
        before_version = V17_SCHEMA_VERSION
    if before_version == V17_SCHEMA_VERSION and current_version >= V18_SCHEMA_VERSION:
        if dry_run:
            steps.append(
                {
                    "schema": SCHEMA,
                    "action": "would-finalize-v17-to-v18",
                    "metadataDb": str(db_path),
                    "schemaId": schema_id,
                    "fromSchemaVersion": V17_SCHEMA_VERSION,
                    "toSchemaVersion": V18_SCHEMA_VERSION,
                }
            )
        else:
            backup_path = backup_database(db_path, backup_dir, "v17-to-v18")
            with sqlite3.connect(db_path) as conn:
                conn.execute("PRAGMA foreign_keys = ON")
                conn.executescript(current_imported_known_files_sql(rust_repo))
                conn.execute(
                    "UPDATE metadata_schema SET schema_version = ? WHERE schema_id = ?",
                    (V18_SCHEMA_VERSION, schema_id),
                )
                conn.commit()
            steps.append(
                {
                    "schema": SCHEMA,
                    "action": "finalized-v17-to-v18",
                    "metadataDb": str(db_path),
                    "backup": str(backup_path),
                    "schemaId": schema_id,
                    "fromSchemaVersion": V17_SCHEMA_VERSION,
                    "toSchemaVersion": V18_SCHEMA_VERSION,
                }
            )

    if not dry_run:
        before_version = schema_marker(db_path, schema_id)
    elif before_version == V17_SCHEMA_VERSION:
        before_version = V18_SCHEMA_VERSION
    if before_version == V18_SCHEMA_VERSION and current_version >= V19_SCHEMA_VERSION:
        steps.append(
            migrate_v18_to_v19(
                db_path=db_path,
                rust_repo=rust_repo,
                backup_dir=backup_dir,
                dry_run=dry_run,
            )
        )

    if not dry_run:
        before_version = schema_marker(db_path, schema_id)
    elif before_version == V18_SCHEMA_VERSION and current_version >= V19_SCHEMA_VERSION:
        before_version = V19_SCHEMA_VERSION
    if before_version == V19_SCHEMA_VERSION and current_version >= V20_SCHEMA_VERSION:
        steps.append(
            migrate_v19_to_v20(
                db_path=db_path,
                rust_repo=rust_repo,
                backup_dir=backup_dir,
                dry_run=dry_run,
            )
        )

    if not dry_run:
        before_version = schema_marker(db_path, schema_id)
    elif before_version == V19_SCHEMA_VERSION and current_version >= V20_SCHEMA_VERSION:
        before_version = V20_SCHEMA_VERSION
    if before_version == V20_SCHEMA_VERSION and current_version >= V21_SCHEMA_VERSION:
        steps.append(
            migrate_v20_to_v21(
                db_path=db_path,
                rust_repo=rust_repo,
                backup_dir=backup_dir,
                dry_run=dry_run,
            )
        )

    if not dry_run:
        before_version = schema_marker(db_path, schema_id)
    elif before_version == V20_SCHEMA_VERSION and current_version >= V21_SCHEMA_VERSION:
        before_version = V21_SCHEMA_VERSION
    if before_version == V21_SCHEMA_VERSION and current_version >= V22_SCHEMA_VERSION:
        steps.append(
            migrate_v21_to_v22(
                db_path=db_path,
                rust_repo=rust_repo,
                backup_dir=backup_dir,
                dry_run=dry_run,
            )
        )

    if not dry_run:
        before_version = schema_marker(db_path, schema_id)
    elif before_version == V21_SCHEMA_VERSION and current_version >= V22_SCHEMA_VERSION:
        before_version = V22_SCHEMA_VERSION
    if before_version == V22_SCHEMA_VERSION and current_version >= V23_SCHEMA_VERSION:
        steps.append(
            migrate_v22_to_v23(
                db_path=db_path,
                rust_repo=rust_repo,
                backup_dir=backup_dir,
                dry_run=dry_run,
            )
        )

    if not dry_run:
        before_version = schema_marker(db_path, schema_id)
    elif before_version == V22_SCHEMA_VERSION and current_version >= V23_SCHEMA_VERSION:
        before_version = V23_SCHEMA_VERSION
    if before_version == V23_SCHEMA_VERSION and current_version >= V24_SCHEMA_VERSION:
        steps.append(
            migrate_v23_to_v24(
                db_path=db_path,
                rust_repo=rust_repo,
                backup_dir=backup_dir,
                dry_run=dry_run,
            )
        )

    final_version = (
        schema_marker(db_path, schema_id) if not dry_run else current_version
    )
    if any(str(step.get("action", "")).startswith("would-") for step in steps):
        action = "would-migrate-to-current"
    elif all(
        step.get("action")
        in (
            "noop-current",
            "noop-v17-shape-current",
            "noop-v19-shape-current",
            "noop-v20-shape-current",
            "noop-v21-shape-current",
            "noop-v22-shape-current",
            "noop-v23-shape-current",
            "noop-v24-shape-current",
        )
        for step in steps
    ):
        action = "noop-current"
    else:
        action = "migrated-to-current"
    return {
        "schema": SCHEMA,
        "action": action,
        "metadataDb": str(db_path),
        "schemaId": schema_id,
        "fromSchemaVersion": original_version,
        "toSchemaVersion": final_version,
        "steps": steps,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata-db", type=Path, default=default_metadata_db())
    parser.add_argument("--rust-repo", type=Path, default=default_rust_repo())
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = migrate_to_current(
        db_path=args.metadata_db,
        rust_repo=args.rust_repo,
        backup_dir=args.backup_dir,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0
