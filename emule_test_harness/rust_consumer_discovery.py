"""Discover one exact safe PDF candidate from a running Rust daemon."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .rust_consumer_live import DEFAULT_MAX_TRANSFER_BYTES
from .rust_webui_live_proof import profile_settings_api_key

DEFAULT_SERVER_MET_URL = "https://upd.emule-security.org/server.met"


def _api_data(
    base_url: str,
    path: str,
    api_key: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
) -> Any:
    payload = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(
        f"{base_url.rstrip('/')}/api/v1/{path.lstrip('/')}",
        data=payload,
        method=method,
        headers={
            "X-API-Key": api_key,
            **({"Content-Type": "application/json"} if payload is not None else {}),
        },
    )
    with urlopen(request, timeout=20.0) as response:
        value = json.loads(response.read())
    return value.get("data", value) if isinstance(value, dict) else value


def _wait(description: str, timeout_seconds: float, probe) -> Any:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            value = probe()
            if value is not None:
                return value
        except Exception as exc:  # noqa: BLE001 - retry bounded live observations
            last_error = exc
        time.sleep(1.0)
    suffix = f": {type(last_error).__name__}" if last_error is not None else ""
    raise RuntimeError(f"timed out waiting for {description}{suffix}")


def select_pdf_candidate(rows: Any, max_bytes: int) -> dict[str, Any] | None:
    """Select the healthiest exact `.pdf` result inside the strict byte bound."""

    candidates: list[dict[str, Any]] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "")
        file_hash = str(row.get("hash") or "").lower()
        size = row.get("sizeBytes")
        sources = row.get("sources", row.get("availability", 0))
        if (
            Path(name).name != name
            or Path(name).suffix.lower() != ".pdf"
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 < size <= max_bytes
            or len(file_hash) != 32
            or any(ch not in "0123456789abcdef" for ch in file_hash)
            or not isinstance(sources, int)
            or isinstance(sources, bool)
            or sources <= 0
        ):
            continue
        candidates.append(
            {
                "name": name,
                "hash": file_hash,
                "size": size,
                "method": "direct_ed2k",
                "sources": sources,
            }
        )
    if not candidates:
        return None
    return sorted(candidates, key=lambda row: (-int(row["sources"]), int(row["size"])))[0]


def discover_pdf_candidate(
    *,
    base_url: str,
    api_key: str,
    search_term: str,
    max_bytes: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Import/connect as needed, run one filtered search, and return one exact candidate."""

    status = _api_data(base_url, "status", api_key)
    stats = status.get("stats", {}) if isinstance(status, dict) else {}
    if not stats.get("ed2kConnected"):
        _api_data(
            base_url,
            "servers/operations/import-met-url",
            api_key,
            method="POST",
            body={"url": DEFAULT_SERVER_MET_URL},
        )
        _api_data(base_url, "servers/operations/connect", api_key, method="POST", body={})
        _wait(
            "eD2K server connection",
            timeout_seconds,
            lambda: (
                lambda value: value
                if isinstance(value, dict) and value.get("stats", {}).get("ed2kConnected")
                else None
            )(_api_data(base_url, "status", api_key)),
        )

    created = _api_data(
        base_url,
        "searches",
        api_key,
        method="POST",
        body={
            "query": search_term,
            "method": "server",
            "type": "doc",
            "extension": "pdf",
            "maxSizeBytes": max_bytes,
            "minAvailability": 1,
        },
    )
    if not isinstance(created, dict) or created.get("id") is None:
        raise RuntimeError("filtered PDF discovery search was not created")
    search_id = int(created["id"])

    def completed_candidate() -> dict[str, Any] | None:
        page = _api_data(base_url, f"searches/{search_id}?limit=200", api_key)
        if not isinstance(page, dict):
            return None
        status = str(page.get("status") or "")
        if status == "error":
            raise RuntimeError("filtered PDF discovery search failed")
        if status != "complete":
            return None
        return select_pdf_candidate(page.get("items"), max_bytes)

    return _wait("a safe PDF search result", timeout_seconds, completed_candidate)


def write_private_candidate(path: Path, candidate: dict[str, Any]) -> None:
    """Write only the exact trigger allowlist fields to an ignored local input file."""

    payload = {
        "auto_browse": {
            "direct_bootstrap_transfers": [
                {key: candidate[key] for key in ("name", "hash", "size", "method")}
            ]
        }
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-settings", type=Path, required=True)
    parser.add_argument("--output-inputs", type=Path, required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:4711")
    parser.add_argument("--search-term", required=True)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_TRANSFER_BYTES)
    parser.add_argument("--timeout-seconds", type=float, default=240.0)
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    parsed = urlparse(args.base_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("consumer candidate discovery is limited to a loopback Rust REST endpoint")
    if not str(args.search_term).strip():
        raise RuntimeError("consumer candidate discovery requires a non-empty search term")
    if not 0 < int(args.max_bytes) <= DEFAULT_MAX_TRANSFER_BYTES:
        raise RuntimeError("consumer candidate discovery requires a PDF strictly smaller than 5 MiB")
    candidate = discover_pdf_candidate(
        base_url=str(args.base_url),
        api_key=profile_settings_api_key(args.profile_settings.resolve()),
        search_term=str(args.search_term).strip(),
        max_bytes=int(args.max_bytes),
        timeout_seconds=float(args.timeout_seconds),
    )
    write_private_candidate(args.output_inputs.resolve(), candidate)
    print(
        json.dumps(
            {
                "status": "passed",
                "candidateSelected": True,
                "pdfOnly": True,
                "strictLessThan5MiB": True,
                "outputInputs": str(args.output_inputs.resolve()),
            },
            indent=2,
        )
    )
    return 0
