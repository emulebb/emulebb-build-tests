"""Shared native REST constants and bounded collection traversal."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urlencode

REST_CONTRACT_VERSION = "2.0.0"
REST_CONTRACT_VERSION_HEADER = "X-Contract-Version"


def settings_patch(snapshot: dict[str, Any], *, set_values: dict[str, Any] | None = None,
                   reset: tuple[str, ...] = ()) -> dict[str, Any]:
    """Build one canonical write against the caller's observed settings revision.

    The request owner submits once and exposes conflicts; this helper performs
    no HTTP calls, retries, or conversion of setting names or values.
    """
    meta = snapshot.get("meta")
    revision = meta.get("settingsRevision") if isinstance(meta, dict) else None
    if (not isinstance(revision, str) or not 1 <= len(revision) <= 19
            or not revision.isascii() or not revision.isdecimal()
            or revision != str(int(revision)) or not 1 <= int(revision) <= 9223372036854775807):
        raise RuntimeError("Settings response requires an exact positive decimal-string revision")
    if not set_values and not reset:
        raise ValueError("Settings patch requires a set or reset")
    body: dict[str, Any] = {"expectedRevision": revision}
    if set_values:
        body["set"] = set_values
    if reset:
        body["reset"] = list(reset)
    return body


def restore_settings_patch(snapshot: dict[str, Any], saved_leaves: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Restore captured current leaves, preserving default/custom modes.

    Only the caller-owned dotted keys participate; unrelated saved settings stay
    untouched. Default leaves reset against the installed product defaults.
    """
    values: dict[str, Any] = {}
    reset = []
    for key, leaf in saved_leaves.items():
        if leaf["mode"] == "default":
            reset.append(key)
        elif leaf["mode"] == "custom":
            branch = values
            *groups, name = key.split(".")
            for group in groups:
                branch = branch.setdefault(group, {})
            branch[name] = leaf["value"]
        else:
            raise RuntimeError("Saved settings snapshot has an invalid mode")
    return settings_patch(snapshot, set_values=values, reset=tuple(reset))


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
