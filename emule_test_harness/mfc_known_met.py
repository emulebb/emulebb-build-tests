"""Import MFC ``known.met`` shared-file hashes into Rust metadata.

``known.met`` does not store source paths, so imports are deliberately
conservative: a record is imported only when a scan of the configured shared
roots finds exactly one file with the same basename, byte size, and whole-second
mtime as the MFC record. The Rust row stores the actual scanned mtime in
milliseconds so the normal share-in-place reload skip can avoid hashing later.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from emule_test_harness import rust_metadata

MET_HEADER = 0x0E
MET_HEADER_I64TAGS = 0x0F
FT_FILENAME = 0x01
FT_FILESIZE = 0x02
FT_AICHHASHSET = 0x35
TAGTYPE_STRING = 0x02
TAGTYPE_UINT32 = 0x03
TAGTYPE_FLOAT32 = 0x04
TAGTYPE_BOOL = 0x05
TAGTYPE_BOOLARRAY = 0x06
TAGTYPE_BLOB = 0x07
TAGTYPE_UINT16 = 0x08
TAGTYPE_UINT8 = 0x09
TAGTYPE_UINT64 = 0x0B
TAGTYPE_STR1 = 0x11
TAGTYPE_STR16 = 0x20


@dataclass(frozen=True)
class KnownMetEntry:
    modified_s: int
    ed2k_hash: str
    md4_hashset: list[str]
    name: str | None
    size_bytes: int | None
    aich_root: str | None
    aich_hashset: list[str]


@dataclass(frozen=True)
class SharedFileCandidate:
    path: Path
    size_bytes: int
    mtime_s: int
    mtime_ms: int


@dataclass(frozen=True)
class MfcSharedFileRow:
    path: Path
    name: str
    ed2k_hash: str
    size_bytes: int
    upload_priority: str
    auto_upload_priority: bool
    all_time_uploaded_bytes: int


class BinaryReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise ValueError("truncated known.met")
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.read(2), "little")

    def u32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.read(8), "little")


def parse_known_met(path: Path) -> list[KnownMetEntry]:
    reader = BinaryReader(path.read_bytes())
    header = reader.u8()
    if header not in {MET_HEADER, MET_HEADER_I64TAGS}:
        raise ValueError(f"unsupported known.met header 0x{header:02x}")
    record_count = reader.u32()
    entries = []
    for _ in range(record_count):
        entries.append(_read_known_met_record(reader))
    if reader.remaining() != 0:
        raise ValueError("known.met has trailing bytes")
    return entries


def import_mfc_known_met_hashes(
    *,
    rust_repo: Path,
    metadata_db: Path,
    known_met: Path,
    shared_roots: list[Path],
    dry_run: bool = False,
) -> dict[str, Any]:
    if not dry_run and not metadata_db.exists():
        rust_metadata.create_metadata_db(rust_repo, metadata_db)

    entries = parse_known_met(known_met)
    candidates = scan_shared_file_candidates(shared_roots)
    by_key: dict[tuple[str, int, int], list[SharedFileCandidate]] = {}
    for candidate in candidates:
        by_key.setdefault(
            (
                candidate.path.name.casefold(),
                candidate.size_bytes,
                candidate.mtime_s,
            ),
            [],
        ).append(candidate)

    reason_counts = {
        "missing_identity": 0,
        "md4_count_mismatch": 0,
        "no_unique_path_match": 0,
        "no_path_match": 0,
        "ambiguous_path_match": 0,
        "aich_count_mismatch": 0,
    }
    imported = 0
    matched = 0
    for entry in entries:
        if entry.name is None or entry.size_bytes is None:
            reason_counts["missing_identity"] += 1
            continue
        if len(entry.md4_hashset) != expected_md4_hash_count(entry.size_bytes):
            reason_counts["md4_count_mismatch"] += 1
            continue
        matches = by_key.get((entry.name.casefold(), entry.size_bytes, entry.modified_s), [])
        if len(matches) == 0:
            reason_counts["no_unique_path_match"] += 1
            reason_counts["no_path_match"] += 1
            continue
        if len(matches) > 1:
            reason_counts["no_unique_path_match"] += 1
            reason_counts["ambiguous_path_match"] += 1
            continue
        if entry.aich_root is not None and len(entry.aich_hashset) != expected_aich_hash_count(entry.size_bytes):
            reason_counts["aich_count_mismatch"] += 1
            continue

        matched += 1
        if not dry_run:
            candidate = matches[0]
            rust_metadata.seed_share_in_place_manifest(
                metadata_db,
                ed2k_hash=entry.ed2k_hash,
                name=entry.name,
                size_bytes=entry.size_bytes,
                source_path=str(candidate.path),
                source_mtime_ms=candidate.mtime_ms,
                md4_hashset=entry.md4_hashset,
                aich_root=entry.aich_root,
                aich_hashset=entry.aich_hashset,
            )
            imported += 1

    return {
        "knownMetRecords": len(entries),
        "sharedFilesScanned": len(candidates),
        "matchedRecords": matched,
        "importedRecords": imported,
        "dryRun": dry_run,
        "skipped": reason_counts,
        "metadataDb": str(metadata_db),
    }


def import_mfc_shared_file_rows_hashes(
    *,
    rust_repo: Path,
    metadata_db: Path,
    known_met: Path,
    shared_file_rows: list[dict[str, Any]],
    shared_roots: list[Path],
    dry_run: bool = False,
) -> dict[str, Any]:
    """Import MFC REST shared-file rows into Rust metadata by exact source path.

    MFC's ``/api/v1/shared-files`` rows expose the full local path and ED2K hash,
    which removes the basename/size/mtime ambiguity inherent in raw
    ``known.met``. We still require the matching ``known.met`` entry so large
    files keep their MD4/AICH part hashsets when Rust skips hashing.
    """

    if not dry_run and not metadata_db.exists():
        rust_metadata.create_metadata_db(rust_repo, metadata_db)

    known_entries = {entry.ed2k_hash: entry for entry in parse_known_met(known_met)}
    roots = [_canonical_existing_root(root) for root in shared_roots if root.is_dir()]
    parsed_rows: list[tuple[MfcSharedFileRow, KnownMetEntry, int]] = []
    reason_counts = {
        "invalid_row": 0,
        "path_outside_shared_roots": 0,
        "path_missing": 0,
        "size_mismatch": 0,
        "missing_known_met_entry": 0,
        "md4_count_mismatch": 0,
        "aich_count_mismatch": 0,
    }
    for row in shared_file_rows:
        parsed = _parse_mfc_shared_file_row(row)
        if parsed is None:
            reason_counts["invalid_row"] += 1
            continue
        if roots and not _path_is_under_roots(parsed.path, roots):
            reason_counts["path_outside_shared_roots"] += 1
            continue
        try:
            stat = parsed.path.stat()
        except OSError:
            reason_counts["path_missing"] += 1
            continue
        if not parsed.path.is_file():
            reason_counts["path_missing"] += 1
            continue
        if stat.st_size != parsed.size_bytes:
            reason_counts["size_mismatch"] += 1
            continue
        entry = known_entries.get(parsed.ed2k_hash)
        if entry is None:
            reason_counts["missing_known_met_entry"] += 1
            continue
        if len(entry.md4_hashset) != expected_md4_hash_count(parsed.size_bytes):
            reason_counts["md4_count_mismatch"] += 1
            continue
        if entry.aich_root is not None and len(entry.aich_hashset) != expected_aich_hash_count(parsed.size_bytes):
            reason_counts["aich_count_mismatch"] += 1
            continue
        parsed_rows.append((parsed, entry, stat.st_mtime_ns // 1_000_000))

    seeded_rows = 0
    updated_existing_rows = 0
    if not dry_run:
        existing = rust_metadata.read_existing_share_in_place_keys(metadata_db)
        metadata_updates: list[dict[str, Any]] = []
        for parsed, entry, source_mtime_ms in parsed_rows:
            existing_key = existing.get(parsed.ed2k_hash)
            if existing_key == (parsed.size_bytes, str(parsed.path), source_mtime_ms):
                metadata_updates.append(_upload_metadata_update(parsed))
                updated_existing_rows += 1
                continue
            rust_metadata.seed_share_in_place_manifest(
                metadata_db,
                ed2k_hash=parsed.ed2k_hash,
                name=parsed.name,
                size_bytes=parsed.size_bytes,
                source_path=str(parsed.path),
                source_mtime_ms=source_mtime_ms,
                md4_hashset=entry.md4_hashset,
                aich_root=entry.aich_root,
                aich_hashset=entry.aich_hashset,
                upload_priority=parsed.upload_priority,
                auto_upload_priority=parsed.auto_upload_priority,
                all_time_uploaded_bytes=parsed.all_time_uploaded_bytes,
            )
            seeded_rows += 1
        rust_metadata.update_known_file_upload_metadata_bulk(metadata_db, metadata_updates)

    return {
        "knownMetRecords": len(known_entries),
        "sharedFileRows": len(shared_file_rows),
        "matchedRows": len(parsed_rows),
        "importedRows": 0 if dry_run else len(parsed_rows),
        "seededRows": 0 if dry_run else seeded_rows,
        "updatedExistingRows": 0 if dry_run else updated_existing_rows,
        "dryRun": dry_run,
        "skipped": reason_counts,
        "metadataDb": str(metadata_db),
    }


def load_shared_file_rows_json(path: Path) -> list[dict[str, Any]]:
    """Load shared-file rows from a REST envelope, ``{"items": [...]}``, or list."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return [row for row in items if isinstance(row, dict)]
    items = payload.get("items")
    if isinstance(items, list):
        return [row for row in items if isinstance(row, dict)]
    return []


def scan_shared_file_candidates(roots: list[Path]) -> list[SharedFileCandidate]:
    candidates: list[SharedFileCandidate] = []
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                path = Path(dirpath) / filename
                try:
                    stat = path.stat()
                except OSError:
                    continue
                if not path.is_file():
                    continue
                candidates.append(
                    SharedFileCandidate(
                        path=path,
                        size_bytes=stat.st_size,
                        mtime_s=int(stat.st_mtime),
                        mtime_ms=stat.st_mtime_ns // 1_000_000,
                    )
                )
    return candidates


def _parse_mfc_shared_file_row(row: dict[str, Any]) -> MfcSharedFileRow | None:
    raw_hash = str(row.get("hash") or row.get("fileHash") or "").strip().lower()
    raw_path = str(row.get("path") or "").strip()
    raw_name = str(row.get("name") or "").strip()
    raw_size = row.get("sizeBytes", row.get("size"))
    raw_priority = str(row.get("priority") or "").strip().lower()
    raw_auto_priority = row.get("autoUploadPriority")
    raw_all_time_transferred = row.get("allTimeTransferred", 0)
    if len(raw_hash) != 32:
        return None
    try:
        bytes.fromhex(raw_hash)
    except ValueError:
        return None
    if not raw_path:
        return None
    try:
        size_bytes = int(raw_size)
    except (TypeError, ValueError):
        return None
    if size_bytes < 0:
        return None
    path = Path(raw_path)
    name = raw_name or path.name
    if not name:
        return None
    return MfcSharedFileRow(
        path=path,
        name=name,
        ed2k_hash=raw_hash,
        size_bytes=size_bytes,
        upload_priority=_parse_mfc_upload_priority(raw_priority),
        auto_upload_priority=_parse_mfc_auto_upload_priority(raw_auto_priority, raw_priority),
        all_time_uploaded_bytes=_parse_non_negative_int(raw_all_time_transferred),
    )


def _upload_metadata_update(row: MfcSharedFileRow) -> dict[str, Any]:
    return {
        "ed2k_hash": row.ed2k_hash,
        "upload_priority": row.upload_priority,
        "auto_upload_priority": row.auto_upload_priority,
        "all_time_uploaded_bytes": row.all_time_uploaded_bytes,
    }


def _parse_mfc_upload_priority(value: str) -> str:
    if value in {"auto", "verylow", "low", "normal", "high", "veryhigh", "release"}:
        return value
    return "normal"


def _parse_mfc_auto_upload_priority(value: object, raw_priority: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        folded = value.strip().casefold()
        if folded in {"1", "true", "yes", "on"}:
            return True
        if folded in {"0", "false", "no", "off"}:
            return False
    return raw_priority == "auto"


def _parse_non_negative_int(value: object) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return max(parsed, 0)


def _canonical_existing_root(path: Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def _path_is_under_roots(path: Path, roots: list[str]) -> bool:
    candidate = os.path.normcase(os.path.abspath(str(path)))
    for root in roots:
        try:
            if os.path.commonpath([candidate, root]) == root:
                return True
        except ValueError:
            continue
    return False


def expected_md4_hash_count(file_size: int) -> int:
    if file_size == 0:
        return 0
    whole_parts = file_size // rust_metadata.ED2K_PART_SIZE
    return whole_parts + int(whole_parts > 0)


def expected_aich_hash_count(file_size: int) -> int:
    if file_size <= rust_metadata.ED2K_PART_SIZE:
        return 0
    return (file_size + rust_metadata.ED2K_PART_SIZE - 1) // rust_metadata.ED2K_PART_SIZE


def _read_known_met_record(reader: BinaryReader) -> KnownMetEntry:
    modified_s = reader.u32()
    ed2k_hash = reader.read(16).hex()
    part_count = reader.u16()
    md4_hashset = [reader.read(16).hex() for _ in range(part_count)]
    tags = [_read_tag(reader) for _ in range(reader.u32())]
    name = _first_tag_value(tags, FT_FILENAME, str)
    size = _first_tag_value(tags, FT_FILESIZE, int)
    aich_blob = _first_tag_value(tags, FT_AICHHASHSET, bytes)
    aich_root, aich_hashset = _parse_aich_hashset_blob(aich_blob) if aich_blob else (None, [])
    return KnownMetEntry(
        modified_s=modified_s,
        ed2k_hash=ed2k_hash,
        md4_hashset=md4_hashset,
        name=name,
        size_bytes=size,
        aich_root=aich_root,
        aich_hashset=aich_hashset,
    )


def _read_tag(reader: BinaryReader) -> tuple[int | str, Any]:
    tag_type = reader.u8()
    if tag_type & 0x80:
        tag_type &= 0x7F
        name: int | str = reader.u8()
    else:
        name_len = reader.u16()
        if name_len == 1:
            name = reader.u8()
        else:
            name = reader.read(name_len).decode("ascii", errors="replace")

    if tag_type == TAGTYPE_STRING:
        return name, _decode_mfc_string(reader.read(reader.u16()))
    if TAGTYPE_STR1 <= tag_type <= TAGTYPE_STR16:
        return name, _decode_mfc_string(reader.read(tag_type - TAGTYPE_STR1 + 1))
    if tag_type == TAGTYPE_UINT32:
        return name, reader.u32()
    if tag_type == TAGTYPE_UINT64:
        return name, reader.u64()
    if tag_type == TAGTYPE_UINT16:
        return name, reader.u16()
    if tag_type == TAGTYPE_UINT8:
        return name, reader.u8()
    if tag_type == TAGTYPE_FLOAT32:
        return name, reader.read(4)
    if tag_type == TAGTYPE_BOOL:
        return name, bool(reader.u8())
    if tag_type == TAGTYPE_BOOLARRAY:
        bit_count = reader.u16()
        return name, reader.read((bit_count // 8) + 1)
    if tag_type == TAGTYPE_BLOB:
        return name, reader.read(reader.u32())
    raise ValueError(f"unsupported known.met tag type 0x{tag_type:02x}")


def _decode_mfc_string(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    for encoding in ("mbcs", "cp1252", "utf-8"):
        try:
            return raw.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def _first_tag_value(tags: list[tuple[int | str, Any]], name_id: int, expected_type: type) -> Any | None:
    for name, value in tags:
        if name == name_id and isinstance(value, expected_type):
            return value
    return None


def _parse_aich_hashset_blob(blob: bytes) -> tuple[str, list[str]]:
    if len(blob) < 22:
        raise ValueError("truncated AICH hashset blob")
    reader = BinaryReader(blob)
    root = reader.read(20).hex()
    part_count = reader.u16()
    expected_len = 20 + 2 + (20 * part_count)
    if len(blob) != expected_len:
        raise ValueError("AICH hashset blob length mismatch")
    return root, [reader.read(20).hex() for _ in range(part_count)]


def summary_json(summary: dict[str, Any]) -> str:
    return json.dumps(summary, indent=2, sort_keys=True)
