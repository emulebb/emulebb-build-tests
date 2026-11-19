"""Shared native REST constants and bounded collection traversal."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urlencode

REST_CONTRACT_VERSION = "2.0.0"
REST_CONTRACT_VERSION_HEADER = "X-Contract-Version"


def iter_library_roots(fetch_page: Callable[[str], dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Stream ID-ordered root pages using an existing authenticated request owner."""
    cursor: str | None = None
    previous_id = 0
    while True:
        query: dict[str, str | int] = {"limit": 100}
        if cursor is not None:
            query["cursor"] = cursor
        document = fetch_page("/library/roots?" + urlencode(query))
        rows, meta = document.get("data"), document.get("meta")
        if not isinstance(rows, list) or len(rows) > 100 or not isinstance(meta, dict):
            raise RuntimeError("library root collection requires a bounded data page and metadata")
        for row in rows:
            value = row.get("id") if isinstance(row, dict) else None
            if not isinstance(value, str) or not 1 <= len(value) <= 19 or not value.isascii() or not value.isdecimal():
                raise RuntimeError("library root identity is invalid")
            number = int(value)
            if value != str(number) or not previous_id < number <= 9223372036854775807:
                raise RuntimeError("library root page did not advance its immutable identities")
            previous_id = number
            yield row
        more, next_cursor = meta.get("hasMore"), meta.get("nextCursor")
        if more is False and next_cursor is None:
            return
        if more is not True or not rows or not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
            raise RuntimeError("library root continuation did not advance")
        cursor = next_cursor

# Compile-time packet-diagnostics controls are private harness surfaces. They
# are intentionally implemented by diagnostics builds and intentionally absent
# from the public product OpenAPI document.
RUST_PRIVATE_DIAGNOSTICS_ROUTES = frozenset(
    {
        ("POST", "/api/v1/diagnostics/protocol-controls/queued-source-reasks"),
        ("POST", "/api/v1/diagnostics/protocol-fixtures/buddy-relay-eligibility"),
        ("POST", "/api/v1/diagnostics/protocol-fixtures/client-udp-queue-pressure"),
        ("POST", "/api/v1/diagnostics/protocol-fixtures/queued-lowid-sources"),
    }
)
