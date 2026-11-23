"""Shared native REST constants and bounded collection traversal."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any, Literal
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


def _iter_resource_pages(fetch_page: Callable[[str], dict[str, Any]], path: str,
                         query: dict[str, Any]) -> Iterator[list[dict[str, Any]]]:
    """Traverse current bounded envelopes using the existing request owner."""
    cursor: str | None = None
    while True:
        parameters = dict(query)
        if cursor is not None:
            parameters["cursor"] = cursor
        document = fetch_page(path + "?" + urlencode(parameters))
        rows, meta = (document.get("data"), document.get("meta")) if isinstance(document, dict) else (None, None)
        if (not isinstance(rows, list) or len(rows) > query["limit"] or not isinstance(meta, dict)
                or not {"hasMore", "nextCursor"}.issubset(meta)):
            raise RuntimeError(f"{path} collection requires a bounded data page and metadata")
        yield rows
        more, next_cursor = meta.get("hasMore"), meta.get("nextCursor")
        if more is False and next_cursor is None:
            return
        if more is not True or not rows or not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
            raise RuntimeError(f"{path} continuation did not advance")
        cursor = next_cursor


def _iter_id_resources(fetch_page: Callable[[str], dict[str, Any]], path: str,
                       query: dict[str, Any], *, descending: bool) -> Iterator[dict[str, Any]]:
    """Traverse bounded current resource pages with strict immutable-ID order."""
    previous_id = 9223372036854775808 if descending else 0
    for rows in _iter_resource_pages(fetch_page, path, query):
        for row in rows:
            value = row.get("id") if isinstance(row, dict) else None
            if not isinstance(value, str) or not 1 <= len(value) <= 19 or not value.isascii() or not value.isdecimal():
                raise RuntimeError(f"{path} identity is invalid")
            number = int(value)
            advances = 0 < number < previous_id if descending else previous_id < number <= 9223372036854775807
            if value != str(number) or not advances:
                raise RuntimeError(f"{path} page did not advance its immutable identities")
            previous_id = number
            yield row


def iter_library_roots(fetch_page: Callable[[str], dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Stream ID-ordered root pages using an existing authenticated request owner."""
    return _iter_id_resources(fetch_page, "/library/roots", {"limit": 100}, descending=False)


def iter_downloads(fetch_page: Callable[[str], dict[str, Any]], *,
                   view: Literal["all", "completed", "unfinished"] = "all") -> Iterator[dict[str, Any]]:
    """Stream all retained jobs in native descending-ID order without a total cap."""
    return _iter_id_resources(fetch_page, "/downloads", {"view": view, "limit": 200}, descending=True)


def iter_library_files(fetch_page: Callable[[str], dict[str, Any]], *,
                       view: Literal["present", "shared", "unavailable", "allKnown"] = "present",
                       search: str | None = None, root_id: str | None = None,
                       count_total: bool = False, limit: int = 200,
                       sort: str | None = None, order: Literal["asc", "desc"] = "asc") -> Iterator[dict[str, Any]]:
    """Stream thin canonical library rows without a total-result cap."""
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("library file page limit must be between 1 and 200")
    query: dict[str, Any] = {"view": view, "limit": limit}
    if sort is not None:
        query["sort"] = sort
    if sort is not None or order != "asc":
        query["order"] = order
    if search is not None:
        query["q"] = search
    if root_id is not None:
        query["rootId"] = root_id
    if count_total:
        query["countTotal"] = "true"
    for rows in _iter_resource_pages(fetch_page, "/library/files", query):
        for row in rows:
            value = row.get("hash") if isinstance(row, dict) else None
            if (not isinstance(value, str) or len(value) != 32
                    or any(character not in "0123456789abcdef" for character in value)
                    or not isinstance(row.get("displayName"), str)):
                raise RuntimeError("/library/files identity or displayName is invalid")
            yield row


def iter_library_locations(fetch_page: Callable[[str], dict[str, Any]], file_hash: str) -> Iterator[dict[str, Any]]:
    """Read separate cached copy pages; no path is inferred from a hash row."""
    if len(file_hash) != 32 or any(character not in "0123456789abcdef" for character in file_hash):
        raise ValueError("library locations require a lowercase hexadecimal content hash")
    for rows in _iter_resource_pages(fetch_page, f"/library/files/{file_hash}/locations", {"limit": 200}):
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str) or type(row.get("present")) is not bool:
                raise RuntimeError("library location requires its cached path and presence")
            yield row


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
