from __future__ import annotations

import json
from pathlib import Path

import pytest

from emule_test_harness import profile_overlay


def test_file_overlay_restores_exact_bytes_and_removes_backup(tmp_path: Path) -> None:
    target = tmp_path / "profile" / "config" / "preferences.ini"
    target.parent.mkdir(parents=True)
    original = b"\xff\xfe[\x00e\x00M\x00u\x00l\x00e\x00]\x00\r\x00\n\x00"
    target.write_bytes(original)
    journal = tmp_path / "output" / "soak" / "transactions" / "mfc-preferences"

    overlay = profile_overlay.begin_file_overlay(target=target, journal_dir=journal)
    target.write_bytes(b"temporary harness preferences")
    result = overlay.restore()

    assert target.read_bytes() == original
    assert result["status"] == "restored"
    assert result["alreadyRestored"] is False
    assert not (journal / profile_overlay.BACKUP_NAME).exists()
    manifest = json.loads((journal / profile_overlay.MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["state"] == "restored"


def test_recover_file_overlay_restores_prior_active_journal(tmp_path: Path) -> None:
    target = tmp_path / "profile" / "preferences.ini"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"original")
    journal = tmp_path / "journal"
    profile_overlay.begin_file_overlay(target=target, journal_dir=journal)
    target.write_bytes(b"stranded overlay")

    result = profile_overlay.recover_file_overlay(target=target, journal_dir=journal)

    assert target.read_bytes() == b"original"
    assert result["recovered"] is True
    assert result["alreadyRestored"] is False


def test_begin_file_overlay_rejects_unrecovered_active_journal(tmp_path: Path) -> None:
    target = tmp_path / "preferences.ini"
    target.write_bytes(b"original")
    journal = tmp_path / "journal"
    profile_overlay.begin_file_overlay(target=target, journal_dir=journal)

    with pytest.raises(RuntimeError, match="must be recovered"):
        profile_overlay.begin_file_overlay(target=target, journal_dir=journal)


def test_file_overlay_removes_file_that_did_not_originally_exist(tmp_path: Path) -> None:
    target = tmp_path / "profile" / "preferences.ini"
    target.parent.mkdir()
    journal = tmp_path / "journal"

    overlay = profile_overlay.begin_file_overlay(target=target, journal_dir=journal)
    target.write_bytes(b"temporary")
    overlay.restore()

    assert not target.exists()


def test_file_overlay_refuses_missing_backup_when_target_is_not_restored(tmp_path: Path) -> None:
    target = tmp_path / "preferences.ini"
    target.write_bytes(b"original")
    journal = tmp_path / "journal"
    overlay = profile_overlay.begin_file_overlay(target=target, journal_dir=journal)
    target.write_bytes(b"temporary")
    overlay.backup_path.unlink()

    with pytest.raises(RuntimeError, match="backup is missing"):
        overlay.restore()

    assert target.read_bytes() == b"temporary"
