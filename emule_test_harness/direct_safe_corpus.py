"""Prepare an operator-local hash allowlist from exact MFC known.met file matches."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import mfc_known_met

ALLOWED_SUFFIXES = frozenset({".pdf", ".iso"})
MAX_CANDIDATE_BYTES = 256 * 1024 * 1024
MAX_PDF_BYTES = 20 * 1024 * 1024
MIN_CANDIDATE_BYTES = 256 * 1024
LINUX_PDF_TERMS = ("linux", "ubuntu", "debian", "gnu", "unix")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _size_bucket(size: int) -> int:
    if size < 10 * 1024 * 1024:
        return 0
    if size < 50 * 1024 * 1024:
        return 1
    return 2


def _matched_candidates_with_activity(
    source_root: Path, known_met: Path,
) -> list[tuple[Path, str, int, tuple[int, int, int, int]]]:
    """Match exact MFC identities and retain activity only for corpus ranking."""

    known_by_key: dict[tuple[str, int, int], dict[str, tuple[int, int, int, int]]] = defaultdict(dict)
    for entry in mfc_known_met.parse_known_met(known_met):
        if entry.name is None or entry.size_bytes is None:
            continue
        if len(entry.md4_hashset) != mfc_known_met.expected_md4_hash_count(entry.size_bytes):
            continue
        known_by_key[(entry.name.casefold(), entry.size_bytes, entry.modified_s)][entry.ed2k_hash.lower()] = (
            int(getattr(entry, "last_upload_request_ms", 0)),
            int(getattr(entry, "all_time_upload_accepts", 0)),
            int(getattr(entry, "all_time_upload_requests", 0)),
            int(getattr(entry, "all_time_uploaded_bytes", 0)),
        )
    matches: list[tuple[Path, str, int, tuple[int, int, int, int]]] = []
    for candidate in mfc_known_met.scan_shared_file_candidates([{"path": str(source_root), "recursive": False}]):
        path = candidate.path
        if path.suffix.lower() not in ALLOWED_SUFFIXES or not MIN_CANDIDATE_BYTES <= candidate.size_bytes <= MAX_CANDIDATE_BYTES:
            continue
        if path.suffix.lower() == ".pdf" and (
            candidate.size_bytes > MAX_PDF_BYTES
            or not any(term in path.name.casefold() for term in LINUX_PDF_TERMS)
        ):
            continue
        hashes = known_by_key.get((path.name.casefold(), candidate.size_bytes, candidate.mtime_s), {})
        if len(hashes) == 1:
            file_hash, activity = next(iter(hashes.items()))
            matches.append((path, file_hash, candidate.size_bytes, activity))
    return matches


def matched_candidates(source_root: Path, known_met: Path) -> list[tuple[Path, str, int]]:
    """Match by MFC's name/size/second-mtime identity, rejecting ambiguities."""

    return [(path, file_hash, size) for path, file_hash, size, _ in _matched_candidates_with_activity(source_root, known_met)]


def prepare_corpus(
    source_root: Path,
    known_met: Path,
    prior_inputs: Path,
    output_path: Path,
    *,
    max_candidates: int = 50,
) -> dict[str, Any]:
    """Write a bounded private allowlist, preserving existing approved rows."""

    if max_candidates < 1 or max_candidates > 50:
        raise ValueError("max_candidates must be in 1..50")
    if not source_root.is_dir() or not known_met.is_file() or not prior_inputs.is_file():
        raise RuntimeError("source root, known.met, and prior operator inputs must exist")
    prior = json.loads(prior_inputs.read_text(encoding="utf-8-sig"))
    prior_rows = prior.get("auto_browse", {}).get("direct_bootstrap_transfers", [])
    if not isinstance(prior_rows, list):
        raise ValueError("prior direct bootstrap transfers must be a list")
    selected: list[dict[str, Any]] = [dict(row) for row in prior_rows if isinstance(row, dict)]
    if len(selected) > max_candidates:
        selected = selected[:max_candidates]
    seen_hashes = {str(row.get("hash") or "").lower() for row in selected}
    seen_names = {str(row.get("name") or "").casefold() for row in selected}
    buckets: dict[int, list[tuple[Path, str, int, tuple[int, int, int, int]]]] = defaultdict(list)
    matches = _matched_candidates_with_activity(source_root, known_met)
    for path, file_hash, size, activity in matches:
        if file_hash not in seen_hashes and path.name.casefold() not in seen_names and "|" not in path.name:
            buckets[_size_bucket(size)].append((path, file_hash, size, activity))
    for bucket in buckets.values():
        # Recent successful uploads are a useful, though not guaranteed, proxy
        # for live public availability; preserve the hash as a stable tie-break.
        bucket.sort(key=lambda row: row[1])
        bucket.sort(key=lambda row: row[3], reverse=True)
    while len(selected) < max_candidates and any(buckets.values()):
        for index in (0, 1, 2):
            if not buckets[index] or len(selected) >= max_candidates:
                continue
            path, file_hash, size, _ = buckets[index].pop(0)
            if file_hash in seen_hashes or path.name.casefold() in seen_names:
                continue
            before = path.stat()
            if before.st_size != size:
                continue
            sha256 = _sha256_file(path)
            after = path.stat()
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                continue
            selected.append({"name": path.name, "hash": file_hash, "size": size, "sha256": sha256})
            seen_hashes.add(file_hash)
            seen_names.add(path.name.casefold())
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps({"auto_browse": {"direct_bootstrap_transfers": selected}}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return {
        "matchedKnownMetCandidates": len(matches),
        "priorApprovedCount": len(prior_rows),
        "allowlistCount": len(selected),
        "pdfCount": sum(str(row.get("name") or "").lower().endswith(".pdf") for row in selected),
        "isoCount": sum(str(row.get("name") or "").lower().endswith(".iso") for row in selected),
        "selectedWithUploadActivity": sum(activity != (0, 0, 0, 0) for _, file_hash, _, activity in matches if file_hash in seen_hashes),
        "output": str(output_path),
    }
