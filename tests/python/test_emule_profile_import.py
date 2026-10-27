from __future__ import annotations

import json
import os
import sqlite3
import struct
from pathlib import Path

import pytest

from emule_test_harness import mfc_known_met, mfc_profile_import, rust_client, rust_metadata


def _rust_repo() -> Path:
    return Path(__file__).resolve().parents[2].parent / "emulebb-rust"


def _tag_string(name_id: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return bytes([mfc_known_met.TAGTYPE_STRING]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<H", len(raw)) + raw


def _tag_uint64(name_id: int, value: int) -> bytes:
    return bytes([mfc_known_met.TAGTYPE_UINT64]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<Q", value)


def _tag_uint32(name_id: int, value: int) -> bytes:
    return bytes([mfc_known_met.TAGTYPE_UINT32]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<I", value)


def _known_record(
    *,
    modified_s: int,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
) -> bytes:
    tags = [
        _tag_string(mfc_known_met.FT_FILENAME, name),
        _tag_uint64(mfc_known_met.FT_FILESIZE, size_bytes),
        _tag_uint32(mfc_known_met.FT_ATTRANSFERRED, 1234),
        _tag_uint32(mfc_known_met.FT_ATREQUESTED, 9),
        _tag_uint32(mfc_known_met.FT_ATACCEPTED, 4),
    ]
    return (
        struct.pack("<I", modified_s)
        + bytes.fromhex(ed2k_hash)
        + struct.pack("<H", 0)
        + struct.pack("<I", len(tags))
        + b"".join(tags)
    )


def _write_known_met(path: Path, records: list[bytes]) -> None:
    path.write_bytes(
        bytes([mfc_known_met.MET_HEADER_I64TAGS])
        + struct.pack("<I", len(records))
        + b"".join(records)
    )


def _server_name_tag(name: str) -> bytes:
    raw = name.encode("ascii")
    return bytes([0x80 | (mfc_known_met.TAGTYPE_STR1 + len(raw) - 1), 0x01]) + raw


def _write_server_met(path: Path) -> None:
    name = _server_name_tag("Local")
    path.write_bytes(
        bytes([mfc_profile_import.SERVER_MET_HEADER])
        + struct.pack("<I", 1)
        + bytes([45, 82, 80, 155])
        + struct.pack("<H", 5687)
        + struct.pack("<I", 1)
        + name
    )


def _write_nodes_dat(path: Path) -> None:
    data = bytearray()
    data.extend(struct.pack("<III", 0, 2, 1))
    data.extend(bytes.fromhex("11" * 16))
    data.extend(struct.pack("<I", int.from_bytes(bytes([1, 2, 3, 4]), "big")))
    data.extend(struct.pack("<HHB", 4672, 4662, 9))
    data.extend(bytes([2]))
    data.extend(struct.pack("<II", 0, 0x11223344))
    path.write_bytes(bytes(data))


def test_import_stock_mfc_profile_creates_fresh_rust_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")
    config = tmp_path / "stock-config"
    shared = tmp_path / "shared"
    rust_profile = tmp_path / "rust-profile"
    config.mkdir()
    shared.mkdir()
    payload = shared / "Shared.bin"
    payload.write_bytes(b"payload")
    modified_s = 1_700_000_000
    os.utime(payload, (modified_s, modified_s))
    (config / "shareddir.dat").write_text(str(shared) + "\r\n", encoding="utf-16")
    _write_known_met(
        config / "known.met",
        [
            _known_record(
                modified_s=modified_s,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name=payload.name,
                size_bytes=payload.stat().st_size,
            )
        ],
    )
    (config / "known2_64.met").write_bytes(bytes([mfc_known_met.KNOWN2_MET_VERSION]))
    _write_server_met(config / "server.met")
    _write_nodes_dat(config / "nodes.dat")
    user_hash = bytes.fromhex("aaaaaaaaaabbccddeeff001122334455")
    (config / "preferences.dat").write_bytes(bytes([mfc_profile_import.PREFERENCES_DAT_VERSION]) + user_hash)

    summary = mfc_profile_import.import_stock_mfc_profile(
        rust_repo=_rust_repo(),
        emule_config_dir=config,
        rust_profile_dir=rust_profile,
        import_user_hash=True,
    )

    assert summary["sharedRoots"] == 1
    assert summary["accessibleSharedRoots"] == 1
    assert summary["servers"] == 1
    assert summary["kadBootstrapEndpoints"] == 1
    assert summary["importedUserHash"] is True
    assert summary["hashes"]["importedKnownRecords"] == 1
    assert summary["hashes"]["manifestImport"]["importedRecords"] == 1
    assert summary["restBaseUrl"] == "http://192.0.2.10:58381/api/v1"
    assert summary["p2pBindIp"] is None
    assert summary["p2pBindInterface"] == "hide.me"
    db_path = rust_profile / rust_metadata.RUST_PROFILE_METADATA_FILE
    settings_path = rust_profile / "emulebb-rust-settings.toml"
    assert settings_path.is_file()
    settings_text = settings_path.read_text(encoding="utf-8")
    assert 'bindAddr = "192.0.2.10:58381"' in settings_text
    assert "127." not in settings_text
    with sqlite3.connect(db_path) as conn:
        roots = conn.execute("SELECT count(*) FROM shared_directory_roots WHERE enabled = 1").fetchone()[0]
        servers = conn.execute("SELECT address, port, name FROM servers").fetchall()
        kad = conn.execute("SELECT endpoint FROM kad_bootstrap_endpoints").fetchall()
        daemon_settings = {
            key: json.loads(value_json)
            for key, value_json in conn.execute("SELECT key, value_json FROM settings WHERE section = 'daemon'")
        }
        identity = conn.execute(
            "SELECT lower(hex(public_identity)) FROM local_identities WHERE identity_kind = 'ed2k-user-hash'"
        ).fetchone()[0]
        imported = conn.execute(
            """
            SELECT lower(hex(ed2k_hash)), display_name, size_bytes, modified_s,
                   all_time_uploaded_bytes, all_time_upload_requests, all_time_upload_accepts
            FROM imported_known_files
            """
        ).fetchall()
        manifests = conn.execute(
            """
            SELECT lower(hex(known_files.ed2k_hash)), known_files.display_name,
                   known_files.size_bytes, local_paths.display_path,
                   transfers.removed_at_ms IS NOT NULL
            FROM transfers
            JOIN known_files ON known_files.id = transfers.known_file_id
            LEFT JOIN local_paths ON local_paths.id = transfers.source_path_id
            """
        ).fetchall()
        profile = conn.execute(
            "SELECT id, created_by FROM profile"
        ).fetchall()
        transfer_name_states = conn.execute(
            """
            SELECT transfer_name_state.display_name_pinned,
                   transfer_name_state.follow_majority_filename
            FROM transfers
            JOIN transfer_name_state
              ON transfer_name_state.transfer_id = transfers.id
            """
        ).fetchall()
    assert roots == 1
    assert servers == [("45.82.80.155", 5687, "Local")]
    assert kad == [("1.2.3.4:4672",)]
    assert daemon_settings.get("p2pBindInterface") == "hide.me"
    assert daemon_settings.get("initialSharedDirectoryReload") is False
    assert "p2pBindIp" not in daemon_settings
    assert identity == "aaaaaaaaaa0eccddeeff001122336f55"
    assert imported == [
        (
            "00112233445566778899aabbccddeeff",
            payload.name,
            payload.stat().st_size,
            modified_s,
            1234,
            9,
            4,
        )
    ]
    assert manifests == [
        (
            "00112233445566778899aabbccddeeff",
            payload.name,
            payload.stat().st_size,
            str(payload),
            1,
        )
    ]
    assert profile == [(1, "emulebb-rust")]
    assert transfer_name_states == [(0, 0)]
    rust_metadata.require_current_profile_database(_rust_repo(), db_path)


def test_upsert_stock_mfc_profile_hashes_reuses_existing_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")
    mfc_profile = tmp_path / "mfc-profile"
    config = mfc_profile / "config"
    shared = tmp_path / "shared"
    rust_profile = tmp_path / "rust-profile"
    config.mkdir(parents=True)
    shared.mkdir()
    payload = shared / "Shared.bin"
    payload.write_bytes(b"payload")
    modified_s = 1_700_000_000
    os.utime(payload, (modified_s, modified_s))
    (config / "shareddir.dat").write_text(str(shared) + "\r\n", encoding="utf-16")
    _write_known_met(
        config / "known.met",
        [
            _known_record(
                modified_s=modified_s,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name=payload.name,
                size_bytes=payload.stat().st_size,
            )
        ],
    )
    mfc_profile_import.import_stock_mfc_profile(
        rust_repo=_rust_repo(),
        emule_config_dir=config,
        rust_profile_dir=rust_profile,
    )
    metadata_db = rust_profile / rust_metadata.RUST_PROFILE_METADATA_FILE
    with sqlite3.connect(metadata_db) as connection:
        connection.execute(
            "UPDATE known_files SET all_time_uploaded_bytes = 987654321"
        )

    summary = mfc_profile_import.upsert_stock_mfc_profile_hashes(
        rust_repo=_rust_repo(),
        mfc_profile_dir=mfc_profile,
        rust_profile_dir=rust_profile,
    )

    assert summary["operation"] == "upsert-hashes"
    assert summary["hashes"]["manifestImport"]["writeMode"] == "refresh-existing"
    assert summary["hashes"]["manifestImport"]["importedSourcePaths"] == 1
    assert summary["hashes"]["manifestImport"]["matchedSourcePaths"] == 1
    assert summary["hashes"]["fingerprintRefresh"]["sharedSourceCount"] == 1
    with sqlite3.connect(metadata_db) as connection:
        uploaded = connection.execute(
            "SELECT all_time_uploaded_bytes FROM known_files"
        ).fetchone()[0]
    assert uploaded == 987654321


def test_import_stock_mfc_profile_requires_rest_lan_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("X_LOCAL_IP", raising=False)
    config = tmp_path / "stock-config"
    rust_profile = tmp_path / "rust-profile"
    config.mkdir()
    (config / "shareddir.dat").write_text("C:\\shared\r\n", encoding="utf-16")
    _write_known_met(config / "known.met", [])

    with pytest.raises(RuntimeError, match="X_LOCAL_IP"):
        mfc_profile_import.import_stock_mfc_profile(
            rust_repo=_rust_repo(),
            emule_config_dir=config,
            rust_profile_dir=rust_profile,
        )


def test_import_stock_mfc_profile_rejects_existing_non_empty_target(tmp_path: Path) -> None:
    config = tmp_path / "stock-config"
    target = tmp_path / "rust-profile"
    config.mkdir()
    target.mkdir()
    (target / "existing.txt").write_text("x", encoding="utf-8")

    with pytest.raises(ValueError, match="new or empty"):
        mfc_profile_import.import_stock_mfc_profile(
            rust_repo=_rust_repo(),
            emule_config_dir=config,
            rust_profile_dir=target,
        )


def test_ensure_persisted_rust_profile_imports_empty_target_transactionally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mfc_profile = tmp_path / "EMULE_BIN"
    config = mfc_profile / "config"
    config.mkdir(parents=True)
    (config / "known.met").write_bytes(b"known")
    (config / "shareddir.dat").write_bytes(b"shared")
    target = tmp_path / "EMULE_RUST_PROFILE_PERSISTED"
    target.mkdir()
    staged_targets: list[Path] = []

    def fake_import(**kwargs: object) -> dict[str, object]:
        staged = Path(str(kwargs["rust_profile_dir"]))
        staged_targets.append(staged)
        (staged / rust_client.RUST_PROFILE_SETTINGS_FILE).write_text("settings", encoding="utf-8")
        rust_metadata.create_metadata_db(
            _rust_repo(),
            staged / rust_metadata.RUST_PROFILE_METADATA_FILE,
        )
        return {
            "schemaVersion": 1,
            "sharedRoots": 3,
            "servers": 2,
            "kadBootstrapEndpoints": 4,
            "importedUserHash": False,
        }

    monkeypatch.setattr(mfc_profile_import, "import_stock_mfc_profile", fake_import)

    result = mfc_profile_import.ensure_persisted_rust_profile(
        rust_repo=_rust_repo(),
        mfc_profile_dir=mfc_profile,
        rust_profile_dir=target,
        rest_addr="127.0.0.1",
    )

    assert result["mode"] == "imported-mfc"
    assert result["imported"] is True
    assert staged_targets and staged_targets[0] != target
    assert not staged_targets[0].exists()
    assert (target / rust_client.RUST_PROFILE_SETTINGS_FILE).is_file()
    assert (target / rust_metadata.RUST_PROFILE_METADATA_FILE).is_file()
    marker = json.loads((target / mfc_profile_import.PERSISTED_PROFILE_IMPORT_MARKER).read_text(encoding="utf-8"))
    assert marker["sourceMfcProfileDir"] == str(mfc_profile.resolve())
    assert marker["sharedRoots"] == 3


def test_ensure_persisted_rust_profile_reuses_valid_nonempty_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "EMULE_RUST_PROFILE_PERSISTED"
    target.mkdir()
    (target / rust_client.RUST_PROFILE_SETTINGS_FILE).write_text("settings", encoding="utf-8")
    rust_metadata.create_metadata_db(
        _rust_repo(),
        target / rust_metadata.RUST_PROFILE_METADATA_FILE,
    )
    monkeypatch.setattr(
        mfc_profile_import,
        "import_stock_mfc_profile",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("existing profile must not be imported")),
    )

    result = mfc_profile_import.ensure_persisted_rust_profile(
        rust_repo=_rust_repo(),
        mfc_profile_dir=None,
        rust_profile_dir=target,
    )

    assert result["mode"] == "reused-persisted"
    assert result["imported"] is False


def test_ensure_persisted_rust_profile_rejects_missing_transfer_name_state(
    tmp_path: Path,
) -> None:
    target = tmp_path / "EMULE_RUST_PROFILE_PERSISTED"
    target.mkdir()
    (target / rust_client.RUST_PROFILE_SETTINGS_FILE).write_text("settings", encoding="utf-8")
    metadata_db = target / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.create_metadata_db(_rust_repo(), metadata_db)
    rust_metadata.seed_transfer_manifest(
        metadata_db,
        ed2k_hash="00112233445566778899aabbccddeeff",
        name="missing-state.bin",
        size_bytes=1,
        piece_size=1,
    )
    with sqlite3.connect(metadata_db) as connection:
        connection.execute("DELETE FROM transfer_name_state")

    with pytest.raises(RuntimeError, match="without transfer_name_state"):
        mfc_profile_import.ensure_persisted_rust_profile(
            rust_repo=_rust_repo(),
            mfc_profile_dir=None,
            rust_profile_dir=target,
        )


def test_ensure_persisted_rust_profile_rejects_invalid_nonempty_target(tmp_path: Path) -> None:
    target = tmp_path / "EMULE_RUST_PROFILE_PERSISTED"
    target.mkdir()
    (target / "unrelated.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(RuntimeError, match="non-empty but invalid"):
        mfc_profile_import.ensure_persisted_rust_profile(
            rust_repo=tmp_path / "emulebb-rust",
            mfc_profile_dir=None,
            rust_profile_dir=target,
        )

    assert (target / "unrelated.txt").read_text(encoding="utf-8") == "keep"


def test_ensure_persisted_rust_profile_preserves_empty_target_after_import_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mfc_profile = tmp_path / "EMULE_BIN"
    config = mfc_profile / "config"
    config.mkdir(parents=True)
    (config / "known.met").write_bytes(b"known")
    (config / "shareddir.dat").write_bytes(b"shared")
    target = tmp_path / "EMULE_RUST_PROFILE_PERSISTED"
    target.mkdir()

    def fail_import(**kwargs: object) -> dict[str, object]:
        staged = Path(str(kwargs["rust_profile_dir"]))
        (staged / "partial.txt").write_text("partial", encoding="utf-8")
        raise RuntimeError("import failed")

    monkeypatch.setattr(mfc_profile_import, "import_stock_mfc_profile", fail_import)

    with pytest.raises(RuntimeError, match="import failed"):
        mfc_profile_import.ensure_persisted_rust_profile(
            rust_repo=tmp_path / "emulebb-rust",
            mfc_profile_dir=mfc_profile,
            rust_profile_dir=target,
        )

    assert target.is_dir()
    assert list(target.iterdir()) == []
    assert not list(tmp_path.glob(".EMULE_RUST_PROFILE_PERSISTED.import-*"))


def test_parse_server_met_rejects_trailing_bytes(tmp_path: Path) -> None:
    server_met = tmp_path / "server.met"
    _write_server_met(server_met)
    server_met.write_bytes(server_met.read_bytes() + b"x")

    with pytest.raises(ValueError, match="trailing bytes"):
        mfc_profile_import.parse_server_met(server_met)


def test_load_recursive_roots_ignores_non_stock_monitored_sidecars(tmp_path: Path) -> None:
    config = tmp_path / "stock-config"
    config.mkdir()
    (config / "shareddir.dat").write_text("C:\\many\\one\r\nC:\\many\\two\r\n", encoding="utf-16")
    (config / "shareddir.monitored.dat").write_text("F:\\SharedRoot\r\n", encoding="utf-16")

    roots = mfc_profile_import._load_recursive_root_entries(config / "shareddir.dat")

    assert roots == [
        {"path": "C:\\many\\one\\", "recursive": True},
        {"path": "C:\\many\\two\\", "recursive": True},
    ]


def test_load_recursive_roots_collapses_fully_listed_directory_tree(tmp_path: Path) -> None:
    config = tmp_path / "stock-config"
    root = tmp_path / "MORE_SHR" / "mp3-albums"
    one = root / "artist-one"
    two = root / "artist-two"
    (one / "disc").mkdir(parents=True)
    two.mkdir(parents=True)
    config.mkdir()
    (config / "shareddir.dat").write_text(
        "\r\n".join(str(path) for path in [one, one / "disc", two]) + "\r\n",
        encoding="utf-16",
    )

    roots = mfc_profile_import._load_recursive_root_entries(config / "shareddir.dat")

    assert roots == [{"path": str(root) + "\\", "recursive": True}]


def test_load_recursive_roots_keeps_exact_dirs_when_tree_cannot_be_proved(tmp_path: Path) -> None:
    config = tmp_path / "stock-config"
    root = tmp_path / "shared"
    one = root / "one"
    missing = root / "missing"
    one.mkdir(parents=True)
    config.mkdir()
    (config / "shareddir.dat").write_text(f"{one}\r\n{missing}\r\n", encoding="utf-16")

    roots = mfc_profile_import._load_recursive_root_entries(config / "shareddir.dat")

    assert roots == [
        {"path": str(one) + "\\", "recursive": True},
        {"path": str(missing) + "\\", "recursive": True},
    ]
