"""External live-wire input contract for operator-owned runtime data."""

from __future__ import annotations

import datetime as _dt
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "emulebb-build-tests.live-wire-inputs.v1"
LEGACY_SCHEMAS = ("emule-build-tests.live-wire-inputs.v1",)
DEFAULT_INPUTS_FILE_NAME = "live-wire-inputs.local.json"
HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
PLACEHOLDER_HASH = "0123456789abcdef0123456789abcdef"


@dataclass(frozen=True)
class LiveWireInputs:
    """Validated operator-owned live-wire runtime inputs."""

    path: Path
    generic_open_terms: tuple[str, ...]
    document_terms: tuple[str, ...]
    radarr_movie_terms: tuple[str, ...]
    sonarr_series_terms: tuple[str, ...]
    video_roots: tuple[Path, ...]
    bootstrap_transfer_hashes: tuple[str, ...]
    direct_bootstrap_transfers: tuple[dict[str, object], ...]
    mfc_profile_dir: Path | None = None


def get_default_inputs_path(repo_root: Path) -> Path:
    """Returns the default ignored local live-wire input file path."""

    return repo_root.resolve() / DEFAULT_INPUTS_FILE_NAME


def resolve_inputs_path(repo_root: Path, raw_path: str | None) -> Path:
    """Resolves a CLI-provided input path or the default local path."""

    if raw_path:
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = repo_root.resolve() / candidate
        return candidate.resolve()
    return get_default_inputs_path(repo_root)


def load_live_wire_inputs(path: Path) -> LiveWireInputs:
    """Loads and validates one live-wire input JSON file."""

    if not path.is_file():
        raise RuntimeError(f"Live-wire inputs file is missing: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Live-wire inputs file is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Live-wire inputs file must contain one JSON object: {path}")
    return parse_live_wire_inputs(payload, path=path)


def load_live_wire_inputs_payload(path: Path) -> dict[str, Any]:
    """Loads one live-wire input JSON object without normalizing its ordering."""

    if not path.is_file():
        raise RuntimeError(f"Live-wire inputs file is missing: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Live-wire inputs file is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Live-wire inputs file must contain one JSON object: {path}")
    return payload


def parse_live_wire_inputs(payload: dict[str, Any], *, path: Path | None = None) -> LiveWireInputs:
    """Validates one live-wire input payload and returns normalized values."""

    if payload.get("schema") not in (SCHEMA, *LEGACY_SCHEMAS):
        raise RuntimeError(f"Live-wire inputs schema must be {SCHEMA!r}.")
    search_terms = require_object(payload, "search_terms")
    auto_browse = require_object(payload, "auto_browse")
    media_corpus = read_optional_object(payload, "media_corpus")
    mfc_profile = read_optional_object(payload, "mfc_profile")
    return LiveWireInputs(
        path=(path or Path(DEFAULT_INPUTS_FILE_NAME)).resolve(),
        generic_open_terms=read_terms(search_terms, "generic_open"),
        document_terms=read_terms(search_terms, "documents"),
        radarr_movie_terms=read_terms(search_terms, "radarr_movies"),
        sonarr_series_terms=read_optional_terms(search_terms, "sonarr_series", fallback_key="radarr_movies"),
        video_roots=read_optional_paths(media_corpus, "video_roots"),
        bootstrap_transfer_hashes=read_hashes(auto_browse, "bootstrap_transfer_hashes"),
        direct_bootstrap_transfers=read_direct_transfers(auto_browse, "direct_bootstrap_transfers"),
        mfc_profile_dir=read_optional_single_path(mfc_profile, "profile_dir"),
    )


def require_object(payload: dict[str, Any], key: str) -> dict[str, Any]:
    """Returns one nested object or raises with a precise input-contract error."""

    value = payload.get(key)
    if not isinstance(value, dict):
        raise RuntimeError(f"Live-wire inputs field {key!r} must be an object.")
    return value


def read_optional_object(payload: dict[str, Any], key: str) -> dict[str, Any]:
    """Returns an optional nested object or raises with a precise input-contract error."""

    value = payload.get(key, {})
    if not isinstance(value, dict):
        raise RuntimeError(f"Live-wire inputs field {key!r} must be an object.")
    return value


def read_terms(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    """Reads one non-empty string-list term field."""

    value = payload.get(key)
    if not isinstance(value, list) or not value:
        raise RuntimeError(f"Live-wire inputs field {key!r} must be a non-empty array.")
    terms: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise RuntimeError(f"Live-wire inputs field {key!r}[{index}] must be a non-empty string.")
        terms.append(item.strip())
    return tuple(terms)


def read_optional_terms(payload: dict[str, Any], key: str, *, fallback_key: str) -> tuple[str, ...]:
    """Reads an optional term field, falling back to an existing required field."""

    if key not in payload:
        return read_terms(payload, fallback_key)
    return read_terms(payload, key)


def read_optional_paths(payload: dict[str, Any], key: str) -> tuple[Path, ...]:
    """Reads an optional string-list path field without exposing the values in reports."""

    value = payload.get(key, [])
    if not isinstance(value, list):
        raise RuntimeError(f"Live-wire inputs field {key!r} must be an array.")
    paths: list[Path] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise RuntimeError(f"Live-wire inputs field {key!r}[{index}] must be a non-empty string.")
        paths.append(Path(item.strip()).expanduser().resolve())
    return tuple(paths)


def read_optional_single_path(payload: dict[str, Any], key: str) -> Path | None:
    """Reads one optional filesystem-path string, or None when the key is absent."""

    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"Live-wire inputs field {key!r} must be a non-empty string.")
    return Path(value.strip()).expanduser()


def read_hashes(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    """Reads one non-empty 32-hex hash array."""

    value = payload.get(key)
    if not isinstance(value, list) or not value:
        raise RuntimeError(f"Live-wire inputs field {key!r} must be a non-empty array.")
    hashes: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not HASH_RE.fullmatch(item.strip()):
            raise RuntimeError(f"Live-wire inputs field {key!r}[{index}] must be a 32-character hex hash.")
        hashes.append(item.strip())
    return tuple(hashes)


def read_direct_transfers(payload: dict[str, Any], key: str) -> tuple[dict[str, object], ...]:
    """Reads direct bootstrap transfer rows with validated real-file metadata."""

    value = payload.get(key)
    if not isinstance(value, list) or not value:
        raise RuntimeError(f"Live-wire inputs field {key!r} must be a non-empty array.")
    transfers: list[dict[str, object]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise RuntimeError(f"Live-wire inputs field {key!r}[{index}] must be an object.")
        transfer_hash = item.get("hash")
        name = item.get("name")
        size = item.get("size")
        method = item.get("method", "direct_ed2k")
        if not isinstance(transfer_hash, str) or not HASH_RE.fullmatch(transfer_hash.strip()):
            raise RuntimeError(f"Live-wire inputs field {key!r}[{index}].hash must be a 32-character hex hash.")
        if not isinstance(name, str) or not name.strip():
            raise RuntimeError(f"Live-wire inputs field {key!r}[{index}].name must be a non-empty string.")
        if not isinstance(size, int) or size <= 0:
            raise RuntimeError(f"Live-wire inputs field {key!r}[{index}].size must be a positive integer.")
        if method != "direct_ed2k":
            raise RuntimeError(f"Live-wire inputs field {key!r}[{index}].method must be 'direct_ed2k'.")
        transfers.append(
            {
                "hash": transfer_hash.strip(),
                "name": name.strip(),
                "size": size,
                "method": method,
            }
        )
    return tuple(transfers)


def build_direct_bootstrap_transfer(result_row: dict[str, Any]) -> dict[str, object]:
    """Builds one direct bootstrap transfer row from a safe live search result."""

    transfer_hash = result_row.get("hash")
    name = result_row.get("name")
    size = result_row.get("sizeBytes", result_row.get("size"))
    if not isinstance(transfer_hash, str) or not HASH_RE.fullmatch(transfer_hash.strip()):
        raise RuntimeError("Live search result hash must be a 32-character hex hash.")
    if not isinstance(name, str) or not name.strip():
        raise RuntimeError("Live search result name must be a non-empty string.")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise RuntimeError("Live search result size must be a positive integer.")
    return {
        "hash": transfer_hash.strip().lower(),
        "name": name.strip(),
        "size": size,
        "method": "direct_ed2k",
    }


def merge_live_wire_bootstrap_result(payload: dict[str, Any], result_row: dict[str, Any]) -> dict[str, object]:
    """Merges one selected live result into the auto-browse bootstrap inputs."""

    parse_live_wire_inputs(payload)
    payload["schema"] = SCHEMA
    auto_browse = require_object(payload, "auto_browse")
    direct_row = build_direct_bootstrap_transfer(result_row)
    transfer_hash = str(direct_row["hash"])

    hashes = read_hashes(auto_browse, "bootstrap_transfer_hashes")
    existing_hashes = [item.strip().lower() for item in hashes if item.strip().lower() != PLACEHOLDER_HASH]
    new_hashes = [transfer_hash]
    new_hashes.extend(item for item in existing_hashes if item != transfer_hash)
    auto_browse["bootstrap_transfer_hashes"] = new_hashes

    direct_transfers = read_direct_transfers(auto_browse, "direct_bootstrap_transfers")
    existing_rows = [
        dict(item)
        for item in direct_transfers
        if str(item.get("hash") or "").strip().lower() not in {PLACEHOLDER_HASH, transfer_hash}
    ]
    auto_browse["direct_bootstrap_transfers"] = [direct_row, *existing_rows]

    parse_live_wire_inputs(payload)
    return {
        "updated": True,
        "hash_present": bool(transfer_hash),
        "bootstrap_hash_count": len(auto_browse["bootstrap_transfer_hashes"]),
        "direct_row_count": len(auto_browse["direct_bootstrap_transfers"]),
    }


def update_live_wire_bootstrap_inputs(path: Path, result_row: dict[str, Any]) -> dict[str, object]:
    """Updates a live-wire inputs file from one selected live search result."""

    payload = load_live_wire_inputs_payload(path)
    summary = merge_live_wire_bootstrap_result(payload, result_row)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return summary


def select_daily(items: tuple[str, ...], *, today: _dt.date | None = None) -> tuple[int, str]:
    """Selects one item deterministically by local date modulo item count."""

    if not items:
        raise RuntimeError("Cannot select from an empty live-wire input list.")
    selected_date = today or _dt.date.today()
    ordinal = int(selected_date.strftime("%Y%m%d"))
    index = ordinal % len(items)
    return index, items[index]


def summarize_terms(items: tuple[str, ...]) -> dict[str, object]:
    """Returns a redacted summary for a runtime term list."""

    return {"count": len(items)}


def summarize_direct_transfers(items: tuple[dict[str, object], ...]) -> dict[str, object]:
    """Returns a redacted summary for direct bootstrap transfer inputs."""

    return {
        "count": len(items),
        "methods": sorted({str(item.get("method") or "") for item in items}),
        "sizes": [int(item["size"]) for item in items],
    }


def summarize_paths(items: tuple[Path, ...]) -> dict[str, object]:
    """Returns a redacted summary for operator-owned local path lists."""

    return {"count": len(items)}


def redact_term_selection(index: int, items: tuple[str, ...], *, source: str) -> dict[str, object]:
    """Reports one selected runtime term without exposing the term itself."""

    return {
        "source": source,
        "count": len(items),
        "selected_index": index,
    }
