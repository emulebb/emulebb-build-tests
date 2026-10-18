from __future__ import annotations

import sqlite3
import sys
import os
from pathlib import Path

import pytest

from emule_test_harness import rust_metadata


def rust_repo() -> Path:
    return Path(__file__).resolve().parents[4] / "repos" / "emulebb-rust"


@pytest.mark.unit
def test_share_in_place_seed_uses_native_path_and_fingerprint(tmp_path: Path) -> None:
    source = tmp_path / "Sample Résumé 😀.bin"
    source.write_bytes(b"payload")
    metadata_db = tmp_path / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(rust_repo(), metadata_db)

    rust_metadata.seed_share_in_place_manifest(
        metadata_db,
        ed2k_hash="00112233445566778899aabbccddeeff",
        name=source.name,
        size_bytes=source.stat().st_size,
        source_path=str(source),
        source_mtime_ms=source.stat().st_mtime_ns // 1_000_000,
    )

    with sqlite3.connect(metadata_db) as connection:
        row = connection.execute(
            """
            SELECT local_paths.native_path, local_paths.search_key,
                   transfers.visible_state, transfers.delivery_state,
                   transfers.delivery_ownership,
                   length(transfers.source_fingerprint),
                   length(shared_file_sources.source_fingerprint)
            FROM transfers
            JOIN local_paths ON local_paths.id = transfers.source_path_id
            JOIN shared_file_sources
              ON shared_file_sources.known_file_id = transfers.known_file_id
            """
        ).fetchone()

    expected_native_path = (
        str(source).encode("utf-16-le", errors="surrogatepass")
        if sys.platform == "win32"
        else os.fsencode(source)
    )
    assert row[0] == expected_native_path
    assert row[1] == rust_metadata.normalize_path_key(str(source))
    assert row[2:5] == ("completed", "not_applicable", "none")
    assert row[5] > 0
    assert row[6] == row[5]

    manifest = rust_metadata.read_transfer_manifest(
        metadata_db, "00112233445566778899aabbccddeeff"
    )
    assert manifest is not None
    assert manifest["source_path"] == str(source)
    assert manifest["source_mtime_ms"] == source.stat().st_mtime_ns // 1_000_000
