"""Foreground resumable MP3 playlist downloader for the eMuleBB MFC REST API."""

from __future__ import annotations

import argparse
import configparser
import datetime as dt
import difflib
import json
import math
import os
import re
import sqlite3
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LIVE_WIRE_INPUTS = REPO_ROOT / "live-wire-inputs.local.json"
DEFAULT_STATE_RELATIVE_PATH = Path("tmp") / "playlist-mp3-download" / "state.sqlite"
DEFAULT_REST_PORT = 4711
DEFAULT_REQUEST_TIMEOUT_SECONDS = 12.0
DEFAULT_SEARCH_TIMEOUT_SECONDS = 75.0
DEFAULT_SEARCH_POLL_SECONDS = 5.0
DEFAULT_SEARCH_LIMIT = 100
DEFAULT_MIN_SOURCES = 1
DEFAULT_MIN_NAME_SCORE = 0.45
DEFAULT_MIN_SIZE_MB = 0.25
DEFAULT_MAX_SIZE_MB = 512.0
DEFAULT_PROGRESS_INTERVAL_SECONDS = 15.0
INVALID_WINDOWS_FILENAME_CHARS = '<>:"/\\|?*'
RESERVED_WINDOWS_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
BAD_FAKE_SEVERITIES = {"high", "critical"}
UNSAFE_DOWNLOAD_SUFFIXES = {
    ".7z",
    ".ace",
    ".bat",
    ".cmd",
    ".com",
    ".exe",
    ".gz",
    ".iso",
    ".msi",
    ".ps1",
    ".rar",
    ".scr",
    ".tar",
    ".vbs",
    ".xz",
    ".zip",
}
NOISE_TOKENS = {
    "mp3",
    "audio",
    "music",
    "official",
    "lyrics",
    "lyric",
    "hq",
    "hd",
    "cbr",
    "vbr",
    "kbps",
}


class StopRequested(Exception):
    """Raised when the operator asks the foreground run to stop."""


@dataclass(frozen=True)
class RuntimeConfig:
    """Resolved non-secret runtime configuration."""

    playlist: Path
    target_root: Path
    preferences: Path
    base_url: str
    category_name: str | None
    state_db: Path


@dataclass(frozen=True)
class Candidate:
    """One ranked search result that is safe enough to add."""

    result: dict[str, Any]
    score: float
    source_count: int
    complete_source_count: int
    similarity: float
    normalized_name: str
    safe_name: str


def log(message: str) -> None:
    """Writes one foreground status line."""

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{stamp}] {message}", flush=True)


def expand_path_text(value: str | None) -> str | None:
    """Expands environment variables and user markers in one optional path."""

    if value is None:
        return None
    text = os.path.expandvars(value.strip())
    if not text:
        return None
    return str(Path(text).expanduser())


def resolve_path(value: str | Path | None, *, base: Path | None = None) -> Path | None:
    """Resolves an optional path without inventing machine-local defaults."""

    if value is None:
        return None
    text = expand_path_text(str(value))
    if text is None:
        return None
    candidate = Path(text)
    if not candidate.is_absolute() and base is not None:
        candidate = base / candidate
    return candidate.resolve()


def require_env(name: str) -> str:
    """Returns a required inherited environment variable."""

    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be set in the inherited environment.")
    return value


def load_json_object(path: Path) -> dict[str, Any]:
    """Loads one JSON object from disk."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"JSON file is invalid: {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"JSON file must contain one object: {path}")
    return payload


def live_wire_object(path: Path | None) -> dict[str, Any]:
    """Returns the optional playlist-specific live-wire configuration object."""

    if path is None or not path.is_file():
        return {}
    payload = load_json_object(path)
    value = payload.get("playlist_mp3_download", {})
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise RuntimeError("live-wire field 'playlist_mp3_download' must be an object.")
    result = dict(value)
    local_package = payload.get("local_package_install", {})
    if isinstance(local_package, dict):
        if "port" not in result and "emulebb_port" in local_package:
            result["port"] = local_package["emulebb_port"]
        if "host" not in result:
            host = first_text(local_package.get("emulebb_lan_bind_address"), local_package.get("lan_bind_address"))
            if host is not None:
                result["host"] = host
    return result


def live_wire_mfc_profile(path: Path | None) -> Path | None:
    """Reads the optional MFC profile directory from live-wire inputs."""

    if path is None or not path.is_file():
        return None
    payload = load_json_object(path)
    value = payload.get("mfc_profile", {})
    if not isinstance(value, dict):
        return None
    return resolve_path(value.get("profile_dir"))


def first_text(*values: object) -> str | None:
    """Returns the first nonblank string among several optional values."""

    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def config_text(config: dict[str, Any], *keys: str) -> str | None:
    """Returns the first nonblank string for several live-wire alias keys."""

    return first_text(*(config.get(key) for key in keys))


def read_text_best_effort(path: Path) -> str:
    """Reads a Windows profile text file across the encodings eMuleBB uses."""

    data = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-16", "utf-16le", "cp1252"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if "\x00" not in text[:200]:
            return text
    return data.decode("utf-8", errors="replace")


def read_preferences(path: Path) -> configparser.ConfigParser:
    """Reads one eMuleBB preferences.ini file."""

    if not path.is_file():
        raise RuntimeError(f"preferences.ini is missing: {path}")
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read_string(read_text_best_effort(path))
    return parser


def get_ini_value(parser: configparser.ConfigParser, section: str, key: str) -> str | None:
    """Reads one INI value using eMuleBB's mixed-case key convention."""

    if not parser.has_section(section):
        return None
    for existing_key, value in parser.items(section):
        if existing_key.casefold() == key.casefold():
            text = value.strip()
            return text or None
    return None


def normalize_base_url(raw: str) -> str:
    """Normalizes a REST base URL to the host root, without the /api/v1 suffix."""

    text = raw.strip().rstrip("/")
    if text.endswith("/api/v1"):
        text = text[: -len("/api/v1")]
    parsed = urllib.parse.urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError(f"REST base URL must include scheme, host, and port: {raw!r}")
    return text


def normalized_windows_path_key(path: Path | str | None) -> str:
    """Returns a stable Windows path comparison key."""

    if path is None:
        return ""
    text = str(path).strip().replace("/", "\\")
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("\\\\?\\"):
        text = text[4:]
    return text.rstrip("\\").casefold()


def parse_port(value: object, fallback: int) -> int:
    """Parses a TCP port value from config or returns the fallback."""

    if value is None:
        return fallback
    try:
        port = int(str(value).strip())
    except ValueError:
        return fallback
    return port if 1 <= port <= 65535 else fallback


def build_base_url(
    *,
    explicit_base_url: str | None,
    explicit_host: str | None,
    explicit_port: int | None,
    live_wire_config: dict[str, Any],
    preferences: configparser.ConfigParser,
) -> str:
    """Builds the REST base URL from explicit, live-wire, INI, and env inputs."""

    configured_base_url = first_text(
        explicit_base_url,
        os.environ.get("EMULEBB_MFC_BASE_URL"),
        live_wire_config.get("base_url"),
    )
    if configured_base_url is not None:
        return normalize_base_url(configured_base_url)

    bind_addr = first_text(
        explicit_host,
        os.environ.get("EMULEBB_MFC_REST_HOST"),
        get_ini_value(preferences, "WebServer", "BindAddr"),
        config_text(live_wire_config, "host", "rest_host"),
    )
    if bind_addr in (None, "0.0.0.0"):
        bind_addr = require_env("X_LOCAL_IP")
    port_candidate: object = first_text(os.environ.get("EMULEBB_MFC_REST_PORT"), get_ini_value(preferences, "WebServer", "Port"))
    if port_candidate is None:
        port_candidate = live_wire_config.get("port")
    port = explicit_port or parse_port(port_candidate, DEFAULT_REST_PORT)
    return normalize_base_url(f"http://{bind_addr}:{port}")


def resolve_runtime_config(args: argparse.Namespace) -> RuntimeConfig:
    """Combines CLI, env, and live-wire settings into a concrete runtime config."""

    require_env("EMULEBB_WORKSPACE_ROOT")
    output_root = Path(require_env("EMULEBB_WORKSPACE_OUTPUT_ROOT")).resolve()
    require_env("CARGO_TARGET_DIR")
    require_env("X_LOCAL_IP")

    live_wire_path = resolve_path(args.live_wire_inputs_file, base=REPO_ROOT)
    if live_wire_path is None:
        live_wire_path = resolve_path(os.environ.get("EMULEBB_LIVE_WIRE_INPUTS"), base=REPO_ROOT)
    if live_wire_path is None:
        live_wire_path = DEFAULT_LIVE_WIRE_INPUTS.resolve()
    live_wire_config = live_wire_object(live_wire_path)

    playlist = resolve_path(
        first_text(
            args.playlist,
            os.environ.get("EMULEBB_MP3_PLAYLIST"),
            config_text(live_wire_config, "playlist", "playlist_path"),
        ),
        base=REPO_ROOT,
    )
    target_root = resolve_path(
        first_text(
            args.target_root,
            os.environ.get("EMULEBB_MP3_TARGET_ROOT"),
            config_text(live_wire_config, "target_root", "target_path", "download_root"),
        ),
        base=REPO_ROOT,
    )

    profile_dir = resolve_path(
        first_text(args.profile_dir, os.environ.get("EMULEBB_MFC_PROFILE_DIR"), config_text(live_wire_config, "profile_dir")),
        base=REPO_ROOT,
    )
    if profile_dir is None:
        profile_dir = live_wire_mfc_profile(live_wire_path)

    preferences = resolve_path(
        first_text(
            args.preferences,
            os.environ.get("EMULEBB_MFC_PREFERENCES"),
            config_text(live_wire_config, "preferences", "preferences_path"),
        ),
        base=REPO_ROOT,
    )
    if preferences is None and profile_dir is not None:
        preferences = (profile_dir / "config" / "preferences.ini").resolve()

    if playlist is None:
        raise RuntimeError("Playlist path is required via --playlist, EMULEBB_MP3_PLAYLIST, or live-wire JSON.")
    if target_root is None:
        raise RuntimeError("Target root is required via --target-root, EMULEBB_MP3_TARGET_ROOT, or live-wire JSON.")
    if preferences is None:
        raise RuntimeError("preferences.ini path is required via --preferences, --profile-dir, env, or live-wire JSON.")
    if not playlist.is_file():
        raise RuntimeError(f"Playlist file is missing: {playlist}")
    if not target_root.is_dir():
        raise RuntimeError(f"Target root is missing or not a directory: {target_root}")

    parsed_preferences = read_preferences(preferences)
    api_key = get_ini_value(parsed_preferences, "WebServer", "ApiKey")
    if not api_key:
        raise RuntimeError("preferences.ini must contain a nonblank [WebServer] ApiKey.")

    state_db = resolve_path(
        first_text(args.state_db, os.environ.get("EMULEBB_MP3_STATE_DB"), live_wire_config.get("state_db")),
        base=REPO_ROOT,
    )
    if state_db is None:
        state_db = (output_root / DEFAULT_STATE_RELATIVE_PATH).resolve()

    category_name = first_text(
        args.category_name,
        os.environ.get("EMULEBB_MP3_CATEGORY_NAME"),
        config_text(live_wire_config, "category_name", "category"),
    )
    base_url = build_base_url(
        explicit_base_url=args.base_url,
        explicit_host=args.host,
        explicit_port=args.port,
        live_wire_config=live_wire_config,
        preferences=parsed_preferences,
    )

    return RuntimeConfig(
        playlist=playlist,
        target_root=target_root,
        preferences=preferences,
        base_url=base_url,
        category_name=category_name,
        state_db=state_db,
    )


def api_key_from_preferences(path: Path) -> str:
    """Loads the REST API key without logging it."""

    parser = read_preferences(path)
    api_key = get_ini_value(parser, "WebServer", "ApiKey")
    if not api_key:
        raise RuntimeError("preferences.ini must contain a nonblank [WebServer] ApiKey.")
    return api_key


def normalize_text(value: str) -> str:
    """Normalizes human-visible MP3/query names for comparisons."""

    text = unicodedata.normalize("NFKC", value)
    text = urllib.parse.unquote(text)
    text = text.casefold()
    text = re.sub(r"\.(mp3)$", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\b\d{2,4}\s*k(?:bps)?\b", " ", text)
    text = re.sub(r"\[[^\]]*\]|\([^)]*\)|\{[^}]*\}", " ", text)
    text = re.sub(r"[_.,;!]+", " ", text)
    text = re.sub(r"[-+]+", " ", text)
    text = re.sub(r"[^0-9a-z]+", " ", text)
    tokens = [token for token in text.split() if token not in NOISE_TOKENS]
    return " ".join(tokens)


def normalize_query(value: str) -> str:
    """Returns the stable dedupe key for one playlist line."""

    text = value.strip()
    if text.startswith("ed2k://|file|"):
        parts = text.split("|")
        if len(parts) > 2:
            text = parts[2]
    return normalize_text(text)


def strip_mp3_suffix(name: str) -> str:
    """Removes any existing .mp3 suffix before safe-name reconstruction."""

    return re.sub(r"\.mp3$", "", name.strip(), flags=re.IGNORECASE)


def safe_mp3_filename(name: str, *, fallback: str) -> str:
    """Returns a Windows-safe normalized .mp3 filename."""

    stem = strip_mp3_suffix(name) or strip_mp3_suffix(fallback) or "download"
    stem = unicodedata.normalize("NFKC", stem)
    stem = "".join(" " if ord(ch) < 32 or ch in INVALID_WINDOWS_FILENAME_CHARS else ch for ch in stem)
    stem = re.sub(r"\s+", " ", stem).strip(" .")
    if not stem:
        stem = "download"
    if stem.upper() in RESERVED_WINDOWS_NAMES:
        stem = f"{stem}_file"
    max_stem_length = 180
    if len(stem) > max_stem_length:
        stem = stem[:max_stem_length].rstrip(" .")
    return f"{stem}.mp3"


def read_playlist(path: Path) -> list[tuple[int, str, str]]:
    """Reads and normalizes playlist rows."""

    rows: list[tuple[int, str, str]] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(read_text_best_effort(path).splitlines(), start=1):
        query = raw_line.strip()
        if not query:
            continue
        key = normalize_query(query)
        if not key or key in seen:
            continue
        seen.add(key)
        rows.append((line_number, query, key))
    if not rows:
        raise RuntimeError(f"Playlist has no usable rows: {path}")
    return rows


def scan_existing_mp3s(target_root: Path) -> dict[str, Path]:
    """Scans existing local MP3 files by normalized stem."""

    existing: dict[str, Path] = {}
    for path in target_root.rglob("*.mp3"):
        if not path.is_file():
            continue
        key = normalize_text(path.stem)
        if key and key not in existing:
            existing[key] = path
    return existing


def connect_state_db(path: Path) -> sqlite3.Connection:
    """Opens and migrates the resumable state database."""

    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS playlist_items (
            query_key TEXT PRIMARY KEY,
            query_text TEXT NOT NULL,
            line_number INTEGER NOT NULL,
            status TEXT NOT NULL,
            selected_hash TEXT,
            selected_name TEXT,
            normalized_name TEXT,
            safe_name TEXT,
            source_count INTEGER,
            complete_source_count INTEGER,
            attempts INTEGER NOT NULL DEFAULT 0,
            reason TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS transfer_hashes (
            hash TEXT PRIMARY KEY,
            query_key TEXT NOT NULL,
            status TEXT NOT NULL,
            name TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def now_text() -> str:
    """Returns a UTC timestamp string for state rows."""

    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def ensure_state_rows(conn: sqlite3.Connection, rows: Iterable[tuple[int, str, str]]) -> None:
    """Seeds the state database with playlist rows without clobbering progress."""

    stamp = now_text()
    for line_number, query, key in rows:
        conn.execute(
            """
            INSERT INTO playlist_items (query_key, query_text, line_number, status, created_at, updated_at)
            VALUES (?, ?, ?, 'pending', ?, ?)
            ON CONFLICT(query_key) DO UPDATE SET
                query_text=excluded.query_text,
                line_number=excluded.line_number,
                updated_at=excluded.updated_at
            """,
            (key, query, line_number, stamp, stamp),
        )
    conn.commit()


def update_item(conn: sqlite3.Connection, query_key: str, status: str, **fields: object) -> None:
    """Updates one playlist item state row."""

    assignments = ["status = ?", "updated_at = ?"]
    values: list[object] = [status, now_text()]
    for key, value in fields.items():
        assignments.append(f"{key} = ?")
        values.append(value)
    values.append(query_key)
    conn.execute(f"UPDATE playlist_items SET {', '.join(assignments)} WHERE query_key = ?", values)
    conn.commit()


def mark_transfer_hash(
    conn: sqlite3.Connection,
    *,
    transfer_hash: str,
    query_key: str,
    status: str,
    name: str | None,
) -> None:
    """Records one known transfer hash for resume-safe dedupe."""

    conn.execute(
        """
        INSERT INTO transfer_hashes (hash, query_key, status, name, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(hash) DO UPDATE SET
            query_key=excluded.query_key,
            status=excluded.status,
            name=excluded.name,
            updated_at=excluded.updated_at
        """,
        (transfer_hash.casefold(), query_key, status, name, now_text()),
    )
    conn.commit()


def state_summary(conn: sqlite3.Connection) -> dict[str, int]:
    """Returns item counts by status."""

    rows = conn.execute("SELECT status, COUNT(*) AS count FROM playlist_items GROUP BY status").fetchall()
    return {str(row["status"]): int(row["count"]) for row in rows}


def pending_items(conn: sqlite3.Connection, *, retry_no_match: bool) -> list[sqlite3.Row]:
    """Returns rows eligible for foreground processing."""

    statuses = ("pending", "error", "searching", "selected", "dry_run_selected")
    if retry_no_match:
        statuses = (*statuses, "no_match", "no_sources", "ambiguous")
    placeholders = ",".join("?" for _ in statuses)
    return list(
        conn.execute(
            f"""
            SELECT * FROM playlist_items
            WHERE status IN ({placeholders})
            ORDER BY line_number
            """,
            statuses,
        )
    )


def request_json(
    base_url: str,
    method: str,
    path: str,
    *,
    api_key: str,
    body: dict[str, object] | None = None,
    timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Runs one REST request and returns the parsed JSON object."""

    payload = None
    headers = {"X-API-Key": api_key, "Connection": "close"}
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/v1/{path.lstrip('/')}",
        data=payload,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            text = response.read().decode("utf-8", errors="replace")
            data = json.loads(text) if text else {}
            if not isinstance(data, dict):
                raise RuntimeError(f"REST response was not a JSON object for {method} {path}.")
            return data
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"REST {method} {path} failed with HTTP {exc.code}: {redact_response_text(text)}") from exc


def redact_response_text(value: str, limit: int = 500) -> str:
    """Bounds REST error text before it reaches foreground logs."""

    text = re.sub(r"(?i)(api[-_ ]?key|password|token)[^,;}\n]*", r"\1=<redacted>", value)
    return text[:limit]


def rest_data(payload: dict[str, Any]) -> Any:
    """Extracts the OpenAPI data envelope when present."""

    if "data" in payload:
        return payload["data"]
    return payload


def rest_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Extracts an items collection from one REST envelope."""

    data = rest_data(payload)
    if isinstance(data, dict):
        items = data.get("items", [])
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def list_categories(base_url: str, api_key: str) -> list[dict[str, Any]]:
    """Reads current eMuleBB download categories."""

    return rest_items(retry_request(base_url, "GET", "categories", api_key=api_key))


def category_name_for_run(config: RuntimeConfig, args: argparse.Namespace) -> str | None:
    """Returns the configured category name or a target-derived one when requested."""

    if config.category_name:
        return config.category_name
    if args.ensure_category_path or args.verify_category_path:
        return config.target_root.name
    return None


def find_category(categories: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    """Finds a category by case-insensitive name."""

    key = name.casefold()
    for category in categories:
        value = category.get("name")
        if isinstance(value, str) and value.casefold() == key:
            return category
    return None


def ensure_category_path(config: RuntimeConfig, api_key: str, args: argparse.Namespace) -> str | None:
    """Verifies, creates, or updates the category path used by new downloads."""

    category_name = category_name_for_run(config, args)
    if category_name is None:
        return None

    categories = list_categories(config.base_url, api_key)
    category = find_category(categories, category_name)
    target_key = normalized_windows_path_key(config.target_root)
    if category is None:
        if args.verify_category_path:
            raise RuntimeError(f"Category {category_name!r} is missing.")
        if args.ensure_category_path and not args.dry_run and not args.preflight_only:
            retry_request(
                config.base_url,
                "POST",
                "categories",
                api_key=api_key,
                body={"name": category_name, "path": str(config.target_root)},
            )
            log(f"created category {category_name!r} for target root")
        elif args.ensure_category_path:
            log(f"would create category {category_name!r} for target root")
        return category_name

    current_path = category.get("path")
    current_key = normalized_windows_path_key(str(current_path) if current_path is not None else None)
    if current_key == target_key:
        log(f"category {category_name!r} already points at target root")
        return category_name

    if args.verify_category_path:
        raise RuntimeError(f"Category {category_name!r} does not point at the target root.")
    if args.ensure_category_path and not args.dry_run and not args.preflight_only:
        category_id = category.get("id")
        if not isinstance(category_id, int) or isinstance(category_id, bool):
            raise RuntimeError(f"Category {category_name!r} has no numeric id.")
        retry_request(
            config.base_url,
            "PATCH",
            f"categories/{category_id}",
            api_key=api_key,
            body={"path": str(config.target_root)},
        )
        log(f"updated category {category_name!r} to target root")
    elif args.ensure_category_path:
        log(f"would update category {category_name!r} to target root")
    return category_name


def retry_request(
    base_url: str,
    method: str,
    path: str,
    *,
    api_key: str,
    body: dict[str, object] | None = None,
    attempts: int = 4,
    delay_seconds: float = 1.0,
) -> dict[str, Any]:
    """Retries transient local REST failures."""

    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return request_json(base_url, method, path, api_key=api_key, body=body)
        except (OSError, TimeoutError, urllib.error.URLError, RuntimeError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            time.sleep(delay_seconds * attempt)
    assert last_error is not None
    raise last_error


def preflight_rest(config: RuntimeConfig, api_key: str) -> None:
    """Checks the REST listener before mutating searches or transfers."""

    retry_request(config.base_url, "GET", "app", api_key=api_key)
    retry_request(config.base_url, "GET", "status", api_key=api_key)


def paged_items(base_url: str, path: str, *, api_key: str, limit: int = 500) -> list[dict[str, Any]]:
    """Reads paginated REST collection items."""

    offset = 0
    items: list[dict[str, Any]] = []
    while True:
        separator = "&" if "?" in path else "?"
        payload = retry_request(base_url, "GET", f"{path}{separator}offset={offset}&limit={limit}", api_key=api_key)
        batch = rest_items(payload)
        items.extend(batch)
        data = rest_data(payload)
        total = data.get("total") if isinstance(data, dict) else None
        if not batch or (isinstance(total, int) and len(items) >= total) or len(batch) < limit:
            break
        offset += len(batch)
    return items


def existing_rest_keys(base_url: str, api_key: str) -> tuple[set[str], set[str]]:
    """Returns normalized names and hashes already known to the REST client."""

    names: set[str] = set()
    hashes: set[str] = set()
    for path in ("transfers", "shared-files"):
        for item in paged_items(base_url, path, api_key=api_key):
            item_hash = str(item.get("hash") or "").strip().casefold()
            if item_hash:
                hashes.add(item_hash)
            name = str(item.get("name") or "").strip()
            if name:
                key = normalize_query(name)
                if key:
                    names.add(key)
    return names, hashes


def search_create_body(query: str, args: argparse.Namespace) -> dict[str, object]:
    """Builds the native REST search request body."""

    body: dict[str, object] = {
        "query": query[:160],
        "method": args.search_method,
        "type": "audio",
        "extension": "mp3",
    }
    min_size = int(args.min_size_mb * 1024 * 1024)
    max_size = int(args.max_size_mb * 1024 * 1024)
    if min_size > 0:
        body["minSizeBytes"] = min_size
    if max_size > 0:
        body["maxSizeBytes"] = max_size
    return body


def response_search_id(payload: dict[str, Any]) -> str:
    """Extracts a search id from the REST response."""

    data = rest_data(payload)
    if isinstance(data, dict):
        for key in ("searchId", "id"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    raise RuntimeError("Search response did not include a search id.")


def result_extension(result: dict[str, Any]) -> str:
    """Returns the candidate file extension."""

    value = str(result.get("extension") or "").strip().casefold()
    if value:
        return value if value.startswith(".") else f".{value}"
    return Path(str(result.get("name") or "")).suffix.casefold()


def int_value(value: object, fallback: int = 0) -> int:
    """Converts JSON numeric fields without accepting booleans as integers."""

    if isinstance(value, bool):
        return fallback
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return fallback


def fake_severity(result: dict[str, Any]) -> str:
    """Returns the candidate fake-file severity."""

    fake = result.get("fakeFile")
    if isinstance(fake, dict):
        return str(fake.get("severity") or "none").casefold()
    return "none"


def candidate_from_result(
    result: dict[str, Any],
    *,
    query_key: str,
    query_text: str,
    min_sources: int,
    min_name_score: float,
    min_size_bytes: int,
    max_size_bytes: int,
) -> Candidate | None:
    """Builds a ranked candidate if a search result is safe enough."""

    name = str(result.get("name") or "").strip()
    if not name:
        return None
    suffix = result_extension(result)
    if suffix != ".mp3":
        return None
    if any(name.casefold().endswith(suffix) for suffix in UNSAFE_DOWNLOAD_SUFFIXES):
        return None
    if bool(result.get("spam")):
        return None
    if fake_severity(result) in BAD_FAKE_SEVERITIES:
        return None
    size = int_value(result.get("sizeBytes"))
    if size < min_size_bytes or (max_size_bytes > 0 and size > max_size_bytes):
        return None
    source_count = max(int_value(result.get("sources")), int_value(result.get("clientCount")), int_value(result.get("serverCount")))
    complete_source_count = int_value(result.get("completeSources"))
    if max(source_count, complete_source_count) < min_sources:
        return None
    normalized_name = normalize_query(name)
    if not normalized_name:
        return None
    similarity = difflib.SequenceMatcher(None, query_key, normalized_name).ratio()
    if similarity < min_name_score and query_key not in normalized_name and normalized_name not in query_key:
        return None
    safe_name = safe_mp3_filename(name, fallback=query_text)
    score = (
        similarity * 100.0
        + math.log1p(max(source_count, complete_source_count)) * 8.0
        + math.log1p(complete_source_count) * 4.0
        - int_value(result.get("rating"), 0)
    )
    return Candidate(
        result=result,
        score=score,
        source_count=source_count,
        complete_source_count=complete_source_count,
        similarity=similarity,
        normalized_name=normalized_name,
        safe_name=safe_name,
    )


def choose_candidate(
    results: list[dict[str, Any]],
    *,
    query_key: str,
    query_text: str,
    args: argparse.Namespace,
    existing_names: set[str],
    existing_hashes: set[str],
) -> Candidate | None:
    """Selects the best source-backed MP3 result for one query."""

    min_size_bytes = int(args.min_size_mb * 1024 * 1024)
    max_size_bytes = int(args.max_size_mb * 1024 * 1024)
    candidates: list[Candidate] = []
    for result in results:
        transfer_hash = str(result.get("hash") or "").strip().casefold()
        if transfer_hash and transfer_hash in existing_hashes:
            continue
        candidate = candidate_from_result(
            result,
            query_key=query_key,
            query_text=query_text,
            min_sources=args.min_sources,
            min_name_score=args.min_name_score,
            min_size_bytes=min_size_bytes,
            max_size_bytes=max_size_bytes,
        )
        if candidate is None:
            continue
        if candidate.normalized_name in existing_names:
            continue
        candidates.append(candidate)
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item.score, item.complete_source_count, item.source_count), reverse=True)
    return candidates[0]


def poll_search_results(
    base_url: str,
    api_key: str,
    search_id: str,
    *,
    timeout_seconds: float,
    poll_seconds: float,
    limit: int,
) -> list[dict[str, Any]]:
    """Polls one search until it accumulates visible results or times out."""

    deadline = time.monotonic() + timeout_seconds
    best_results: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        payload = retry_request(base_url, "GET", f"searches/{search_id}?offset=0&limit={limit}", api_key=api_key)
        results = rest_items(payload)
        if len(results) > len(best_results):
            best_results = results
        time.sleep(poll_seconds)
    return best_results


def delete_search(base_url: str, api_key: str, search_id: str) -> None:
    """Stops one search session best-effort."""

    try:
        retry_request(base_url, "DELETE", f"searches/{search_id}", api_key=api_key, attempts=2)
    except Exception as exc:
        log(f"warning: failed to delete search session {search_id}: {redact_response_text(str(exc))}")


def download_body(config: RuntimeConfig, paused: bool | None) -> dict[str, object] | None:
    """Builds the optional search-result download request body."""

    body: dict[str, object] = {}
    if config.category_name:
        body["categoryName"] = config.category_name
    if paused is not None:
        body["paused"] = paused
    return body or None


def add_download(
    base_url: str,
    api_key: str,
    search_id: str,
    transfer_hash: str,
    *,
    body: dict[str, object] | None,
) -> None:
    """Adds one search result to the download queue."""

    retry_request(
        base_url,
        "POST",
        f"searches/{urllib.parse.quote(search_id)}/results/{transfer_hash}/operations/download",
        api_key=api_key,
        body=body,
    )


def rename_transfer(base_url: str, api_key: str, transfer_hash: str, safe_name: str) -> bool:
    """Renames one queued transfer to the normalized MP3 filename."""

    body = {"name": safe_name}
    for _ in range(5):
        try:
            retry_request(base_url, "PATCH", f"transfers/{transfer_hash}", api_key=api_key, body=body, attempts=2)
            return True
        except Exception:
            time.sleep(1.0)
    return False


def mark_existing_local(conn: sqlite3.Connection, existing_names: set[str]) -> int:
    """Marks playlist rows already present in the target MP3 root."""

    count = 0
    rows = conn.execute(
        """
        SELECT query_key FROM playlist_items
        WHERE status IN ('pending', 'error', 'searching', 'selected', 'dry_run_selected', 'no_match', 'no_sources', 'ambiguous')
        """
    ).fetchall()
    for row in rows:
        key = str(row["query_key"])
        if key in existing_names:
            update_item(conn, key, "skipped_existing_local", reason="normalized local mp3 filename already exists")
            count += 1
    return count


def mark_existing_rest(conn: sqlite3.Connection, existing_names: set[str]) -> int:
    """Marks playlist rows already represented by REST transfers or shared files."""

    count = 0
    rows = conn.execute(
        """
        SELECT query_key FROM playlist_items
        WHERE status IN ('pending', 'error', 'searching', 'selected', 'dry_run_selected')
        """
    ).fetchall()
    for row in rows:
        key = str(row["query_key"])
        if key in existing_names:
            update_item(conn, key, "skipped_existing_rest", reason="normalized REST transfer/shared filename already exists")
            count += 1
    return count


def refresh_completed_from_rest(conn: sqlite3.Connection, rest_names: set[str], rest_hashes: set[str]) -> int:
    """Updates rows whose selected transfer now appears in REST state."""

    count = 0
    rows = conn.execute("SELECT query_key, selected_hash, normalized_name FROM playlist_items WHERE status IN ('added', 'renamed')").fetchall()
    for row in rows:
        selected_hash = str(row["selected_hash"] or "").casefold()
        normalized_name = str(row["normalized_name"] or "")
        if (selected_hash and selected_hash in rest_hashes) or (normalized_name and normalized_name in rest_names):
            count += 1
    return count


def process_one_item(
    conn: sqlite3.Connection,
    config: RuntimeConfig,
    api_key: str,
    item: sqlite3.Row,
    args: argparse.Namespace,
    *,
    existing_names: set[str],
    existing_hashes: set[str],
) -> bool:
    """Searches, selects, and optionally adds one playlist item."""

    query_key = str(item["query_key"])
    query_text = str(item["query_text"])
    update_item(conn, query_key, "searching", attempts=int(item["attempts"]) + 1)
    log(f"searching line {item['line_number']} ({query_key[:80]})")

    search_id: str | None = None
    try:
        search_response = retry_request(config.base_url, "POST", "searches", api_key=api_key, body=search_create_body(query_text, args))
        search_id = response_search_id(search_response)
        results = poll_search_results(
            config.base_url,
            api_key,
            search_id,
            timeout_seconds=args.search_timeout_seconds,
            poll_seconds=args.search_poll_seconds,
            limit=args.search_limit,
        )
        candidate = choose_candidate(
            results,
            query_key=query_key,
            query_text=query_text,
            args=args,
            existing_names=existing_names,
            existing_hashes=existing_hashes,
        )
        if candidate is None:
            with_sources = sum(
                1
                for result in results
                if max(int_value(result.get("sources")), int_value(result.get("completeSources"))) >= args.min_sources
            )
            status = "no_sources" if with_sources == 0 else "no_match"
            update_item(conn, query_key, status, reason=f"visible_results={len(results)} source_backed_results={with_sources}")
            log(f"{status}: line {item['line_number']} visible={len(results)} source_backed={with_sources}")
            return False

        transfer_hash = str(candidate.result.get("hash") or "").strip().casefold()
        if not transfer_hash:
            update_item(conn, query_key, "error", reason="selected candidate did not include a hash")
            return False

        update_item(
            conn,
            query_key,
            "selected",
            selected_hash=transfer_hash,
            selected_name=str(candidate.result.get("name") or ""),
            normalized_name=candidate.normalized_name,
            safe_name=candidate.safe_name,
            source_count=candidate.source_count,
            complete_source_count=candidate.complete_source_count,
            reason=f"score={candidate.score:.2f} similarity={candidate.similarity:.3f}",
        )

        if args.dry_run:
            update_item(conn, query_key, "dry_run_selected", reason="dry-run candidate selected but no download was added")
            log(
                "dry-run selected "
                f"line {item['line_number']} hash={transfer_hash} "
                f"sources={candidate.source_count} complete={candidate.complete_source_count} "
                f"name={candidate.safe_name!r}"
            )
            return False

        add_download(
            config.base_url,
            api_key,
            search_id,
            transfer_hash,
            body=download_body(config, args.paused),
        )
        update_item(conn, query_key, "added", reason="download added through search result route")
        mark_transfer_hash(conn, transfer_hash=transfer_hash, query_key=query_key, status="added", name=candidate.safe_name)
        existing_hashes.add(transfer_hash)
        existing_names.add(candidate.normalized_name)
        log(
            f"added line {item['line_number']} hash={transfer_hash} "
            f"sources={candidate.source_count} complete={candidate.complete_source_count}"
        )

        if args.rename_transfers:
            if rename_transfer(config.base_url, api_key, transfer_hash, candidate.safe_name):
                update_item(conn, query_key, "renamed", reason="download added and renamed")
                mark_transfer_hash(conn, transfer_hash=transfer_hash, query_key=query_key, status="renamed", name=candidate.safe_name)
                log(f"renamed hash={transfer_hash} to {candidate.safe_name!r}")
            else:
                log(f"warning: rename failed for hash={transfer_hash}; transfer remains added")
        return True
    except Exception as exc:
        update_item(conn, query_key, "error", reason=redact_response_text(str(exc)))
        log(f"error line {item['line_number']}: {redact_response_text(str(exc))}")
        return False
    finally:
        if search_id and args.delete_searches:
            delete_search(config.base_url, api_key, search_id)


def print_summary(conn: sqlite3.Connection) -> None:
    """Prints a compact foreground state summary."""

    summary = state_summary(conn)
    parts = " ".join(f"{key}={summary[key]}" for key in sorted(summary))
    log(f"state {parts}")


def watch_transfers(config: RuntimeConfig, api_key: str, conn: sqlite3.Connection, *, interval_seconds: float) -> None:
    """Keeps the process in foreground for operator monitoring."""

    log("watching transfers; press Ctrl+C to stop")
    while True:
        try:
            transfers = paged_items(config.base_url, "transfers", api_key=api_key)
            active = sum(1 for item in transfers if str(item.get("state") or "") in {"downloading", "queued", "paused"})
            completed = sum(1 for item in transfers if str(item.get("state") or "") == "completed")
            total_sources = sum(int_value(item.get("sources")) for item in transfers)
            log(f"transfers active={active} completed_visible={completed} total_sources={total_sources}")
            print_summary(conn)
            time.sleep(interval_seconds)
        except KeyboardInterrupt as exc:
            raise StopRequested from exc


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parses CLI arguments for the foreground operator script."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--playlist", help="Playlist text file. Can also come from EMULEBB_MP3_PLAYLIST or live-wire JSON.")
    parser.add_argument("--target-root", help="Existing/completed MP3 root. Can also come from EMULEBB_MP3_TARGET_ROOT or live-wire JSON.")
    parser.add_argument("--preferences", help="Path to config/preferences.ini. Can also come from EMULEBB_MFC_PREFERENCES.")
    parser.add_argument("--profile-dir", help="MFC profile directory containing config/preferences.ini.")
    parser.add_argument("--base-url", help="REST host root, with or without /api/v1.")
    parser.add_argument("--host", help="REST host override when --base-url is omitted.")
    parser.add_argument("--port", type=int, help="REST port override when --base-url is omitted.")
    parser.add_argument("--category-name", help="Optional eMuleBB category name for added downloads.")
    parser.add_argument("--ensure-category-path", action="store_true", help="Create or update the category path to the target root before adding downloads.")
    parser.add_argument("--verify-category-path", action="store_true", help="Require the category to already point at the target root.")
    parser.add_argument("--state-db", help="SQLite resume-state path. Defaults under EMULEBB_WORKSPACE_OUTPUT_ROOT.")
    parser.add_argument("--live-wire-inputs-file", help="Optional ignored live-wire JSON input path.")
    parser.add_argument("--dry-run", action="store_true", help="Search and select candidates without adding downloads.")
    parser.add_argument("--preflight-only", action="store_true", help="Validate inputs and REST read surfaces without searches or downloads.")
    parser.add_argument("--paused", action=argparse.BooleanOptionalAction, default=False, help="Add selected transfers paused.")
    parser.add_argument("--rename-transfers", action=argparse.BooleanOptionalAction, default=True, help="Normalize selected transfer names through REST PATCH.")
    parser.add_argument("--delete-searches", action=argparse.BooleanOptionalAction, default=True, help="Delete each search session after processing.")
    parser.add_argument("--retry-no-match", action="store_true", help="Retry rows previously marked no_match/no_sources/ambiguous.")
    parser.add_argument("--watch", action="store_true", help="Keep polling transfer summaries after queue processing.")
    parser.add_argument("--max-new-downloads", type=int, default=0, help="Stop after adding this many new downloads; 0 means no explicit cap.")
    parser.add_argument("--min-sources", type=int, default=DEFAULT_MIN_SOURCES, help="Minimum sources or complete sources required.")
    parser.add_argument("--min-name-score", type=float, default=DEFAULT_MIN_NAME_SCORE, help="Minimum normalized name similarity from 0.0 to 1.0.")
    parser.add_argument("--min-size-mb", type=float, default=DEFAULT_MIN_SIZE_MB, help="Minimum MP3 candidate size.")
    parser.add_argument("--max-size-mb", type=float, default=DEFAULT_MAX_SIZE_MB, help="Maximum MP3 candidate size; 0 disables the cap.")
    parser.add_argument("--search-method", choices=("automatic", "server", "global", "kad"), default="automatic")
    parser.add_argument("--search-timeout-seconds", type=float, default=DEFAULT_SEARCH_TIMEOUT_SECONDS)
    parser.add_argument("--search-poll-seconds", type=float, default=DEFAULT_SEARCH_POLL_SECONDS)
    parser.add_argument("--search-limit", type=int, default=DEFAULT_SEARCH_LIMIT)
    parser.add_argument("--progress-interval-seconds", type=float, default=DEFAULT_PROGRESS_INTERVAL_SECONDS)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    """Runs the foreground resumable playlist workflow."""

    args = parse_args(argv)
    config = resolve_runtime_config(args)
    api_key = api_key_from_preferences(config.preferences)
    log(f"playlist={config.playlist}")
    log(f"target_root={config.target_root}")
    log(f"state_db={config.state_db}")
    log(f"base_url={config.base_url}")
    if config.category_name:
        log(f"category_name={config.category_name}")

    rows = read_playlist(config.playlist)
    existing_local = scan_existing_mp3s(config.target_root)
    conn = connect_state_db(config.state_db)
    ensure_state_rows(conn, rows)
    skipped_local = mark_existing_local(conn, set(existing_local))
    log(f"loaded playlist_rows={len(rows)} existing_mp3={len(existing_local)} skipped_local={skipped_local}")

    preflight_rest(config, api_key)
    rest_names, rest_hashes = existing_rest_keys(config.base_url, api_key)
    skipped_rest = mark_existing_rest(conn, rest_names)
    refresh_seen = refresh_completed_from_rest(conn, rest_names, rest_hashes)
    log(f"rest_seen_names={len(rest_names)} rest_seen_hashes={len(rest_hashes)} skipped_rest={skipped_rest} refreshed_seen={refresh_seen}")
    effective_category_name = ensure_category_path(config, api_key, args)
    if effective_category_name and effective_category_name != config.category_name:
        config = RuntimeConfig(
            playlist=config.playlist,
            target_root=config.target_root,
            preferences=config.preferences,
            base_url=config.base_url,
            category_name=effective_category_name,
            state_db=config.state_db,
        )
    print_summary(conn)
    if args.preflight_only:
        log("preflight-only finished before searches or downloads")
        conn.close()
        return 0

    added_count = 0
    last_progress = time.monotonic()
    try:
        known_names = set(existing_local) | rest_names
        known_hashes = set(rest_hashes)
        for item in pending_items(conn, retry_no_match=args.retry_no_match):
            if args.max_new_downloads and added_count >= args.max_new_downloads:
                log(f"stopping because max_new_downloads={args.max_new_downloads} was reached")
                break
            if time.monotonic() - last_progress >= args.progress_interval_seconds:
                print_summary(conn)
                last_progress = time.monotonic()
            added = process_one_item(
                conn,
                config,
                api_key,
                item,
                args,
                existing_names=known_names,
                existing_hashes=known_hashes,
            )
            if added:
                added_count += 1
        print_summary(conn)
        log(f"queue processing finished added={added_count} dry_run={args.dry_run}")
        if args.watch:
            watch_transfers(config, api_key, conn, interval_seconds=args.progress_interval_seconds)
    except (KeyboardInterrupt, StopRequested):
        log("stop requested; state has been flushed")
        print_summary(conn)
        return 130
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
