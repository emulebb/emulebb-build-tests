"""Durable exact-file overlays for operator-owned live profiles."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "emulebb.profile-file-overlay.v1"
MANIFEST_NAME = "manifest.json"
BACKUP_NAME = "original.bin"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left.resolve())) == os.path.normcase(str(right.resolve()))


def _write_private_bytes(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    _write_private_bytes(temporary, (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    os.replace(temporary, path)


def _read_manifest(journal_dir: Path) -> dict[str, Any] | None:
    path = journal_dir / MANIFEST_NAME
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Invalid profile overlay journal: {path}") from error
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise RuntimeError(f"Unsupported profile overlay journal: {path}")
    return payload


def _atomic_restore(target: Path, payload: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_raw = tempfile.mkstemp(prefix=f".{target.name}.restore-", dir=target.parent)
    temporary = Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


@dataclass(frozen=True)
class FileOverlay:
    """One active durable overlay journal for an exact target file."""

    target: Path
    journal_dir: Path

    @property
    def manifest_path(self) -> Path:
        return self.journal_dir / MANIFEST_NAME

    @property
    def backup_path(self) -> Path:
        return self.journal_dir / BACKUP_NAME

    def restore(self) -> dict[str, Any]:
        """Restore the original target bytes and close the journal."""

        manifest = _read_manifest(self.journal_dir)
        if manifest is None:
            raise RuntimeError(f"Profile overlay journal is missing: {self.manifest_path}")
        journal_target = Path(str(manifest.get("target") or ""))
        if not _same_path(journal_target, self.target):
            raise RuntimeError(
                f"Profile overlay target mismatch: journal={journal_target}, expected={self.target.resolve()}"
            )
        if manifest.get("state") == "restored":
            if self.backup_path.exists():
                self.backup_path.unlink()
            return _restore_summary(manifest, recovered=False, already_restored=True)
        if manifest.get("state") != "active":
            raise RuntimeError(f"Unsupported profile overlay state: {manifest.get('state')!r}")

        original_existed = bool(manifest.get("originalExisted"))
        original_sha256 = str(manifest.get("originalSha256") or "")
        if original_existed:
            if self.backup_path.is_file():
                payload = self.backup_path.read_bytes()
                if _sha256(payload) != original_sha256:
                    raise RuntimeError(f"Profile overlay backup digest mismatch: {self.backup_path}")
                _atomic_restore(self.target, payload)
            elif not self.target.is_file() or _sha256(self.target.read_bytes()) != original_sha256:
                raise RuntimeError(f"Profile overlay backup is missing before restore: {self.backup_path}")
        elif self.target.exists():
            if not self.target.is_file():
                raise RuntimeError(f"Profile overlay target became a non-file: {self.target}")
            self.target.unlink()

        if self.backup_path.exists():
            self.backup_path.unlink()
        manifest = {
            **manifest,
            "state": "restored",
            "restoredAt": _utc_now(),
        }
        _write_json(self.manifest_path, manifest)
        return _restore_summary(manifest, recovered=False, already_restored=False)


def begin_file_overlay(*, target: Path, journal_dir: Path) -> FileOverlay:
    """Snapshot an exact file before a temporary live-profile overlay."""

    target = target.resolve()
    journal_dir = journal_dir.resolve()
    if not target.parent.is_dir():
        raise RuntimeError(f"Profile overlay target parent does not exist: {target.parent}")
    existing = _read_manifest(journal_dir)
    if existing is not None and existing.get("state") == "active":
        raise RuntimeError(f"Active profile overlay must be recovered before reuse: {journal_dir}")

    journal_dir.mkdir(parents=True, exist_ok=True)
    original_existed = target.is_file()
    if target.exists() and not original_existed:
        raise RuntimeError(f"Profile overlay target is not a file: {target}")
    payload = target.read_bytes() if original_existed else b""
    if original_existed:
        _write_private_bytes(journal_dir / BACKUP_NAME, payload)
    elif (journal_dir / BACKUP_NAME).exists():
        (journal_dir / BACKUP_NAME).unlink()
    manifest = {
        "schema": SCHEMA,
        "state": "active",
        "target": str(target),
        "originalExisted": original_existed,
        "originalSha256": _sha256(payload) if original_existed else None,
        "beganAt": _utc_now(),
        "restoredAt": None,
    }
    _write_json(journal_dir / MANIFEST_NAME, manifest)
    return FileOverlay(target=target, journal_dir=journal_dir)


def recover_file_overlay(*, target: Path, journal_dir: Path) -> dict[str, Any]:
    """Recover a prior active overlay, or report that none is active."""

    target = target.resolve()
    journal_dir = journal_dir.resolve()
    manifest = _read_manifest(journal_dir)
    if manifest is None:
        return {"enabled": False, "status": "absent", "target": str(target)}
    overlay = FileOverlay(target=target, journal_dir=journal_dir)
    if manifest.get("state") == "restored":
        return overlay.restore()
    result = overlay.restore()
    return {**result, "recovered": True}


def _restore_summary(
    manifest: dict[str, Any],
    *,
    recovered: bool,
    already_restored: bool,
) -> dict[str, Any]:
    return {
        "enabled": True,
        "status": "restored",
        "target": str(manifest["target"]),
        "originalExisted": bool(manifest["originalExisted"]),
        "originalSha256": manifest.get("originalSha256"),
        "restoredAt": manifest.get("restoredAt"),
        "recovered": recovered,
        "alreadyRestored": already_restored,
    }
