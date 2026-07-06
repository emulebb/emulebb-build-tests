"""Scripted, labelled action sets for solo *capture-then-offline-diff* parity runs.

The same action set is executed identically against ONE client at a time (rust
solo, then MFC solo — never simultaneously, which flaps rust off the operator via
the shared HighID ``client_id`` = egress IP; see the ``converged-soak-live`` memo).
Each action emits ``begin``/``end`` markers carrying ``ts_utc`` so the offline diff
can slice the ``[t0, t1]`` diag/packet window per action and correlate the two solo
recordings by ``actionId``.

Downloads use FIXED ed2k hashes taken from the git-ignored live-wire inputs
(``auto_browse.direct_bootstrap_transfers`` → ``LiveWireInputs.direct_bootstrap_transfers``)
so BOTH clients fetch the same files — source-acquisition/transfer behaviour is then
directly comparable, unlike drifting search results. Hashes/paths never live in the
committed code. Search terms are generic and spaced (be-gentle: the operator throttles
on volume — 0-results-for-all is that throttle, not a bug).

Pure helpers (``build_ed2k_link``/``default_action_set``/``execute_action_set``) are
unit-tested; the live REST wiring is isolated in :func:`make_rest_runner`.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import time
import urllib.request
from typing import Any, Callable

MARKER_SCHEMA = "scripted_action_marker_v1"
DEFAULT_SEARCH_METHODS = ("server", "global", "kad")
DEFAULT_SPACING_SECONDS = 15.0

ActionRunner = Callable[["ScriptedAction"], dict[str, Any]]
MarkerWriter = Callable[[dict[str, Any]], None]


@dataclasses.dataclass(frozen=True)
class ScriptedAction:
    """One labelled action. ``id`` is the correlation key across the two solo runs."""

    id: str
    kind: str  # "search" | "download"
    params: dict[str, Any]


def utc_now_iso() -> str:
    """RFC3339 UTC with a ``Z`` suffix, matching the diag/packet ``ts_utc`` format."""

    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def build_ed2k_link(fixture: dict[str, Any]) -> str:
    """``ed2k://|file|<name>|<size>|<hash>|/`` from a direct-transfer fixture row.

    Mirrors the harness link format (auto-browse-live/amule). Raises on a fixture
    missing the fields the REST transfer-add requires.
    """

    file_hash = str(fixture.get("hash") or "").strip().lower()
    name = str(fixture.get("name") or "").strip()
    size = fixture.get("size")
    if len(file_hash) != 32:
        raise ValueError("direct-transfer fixture needs a 32-char ed2k hash")
    if not name:
        raise ValueError("direct-transfer fixture needs a non-empty name")
    if not isinstance(size, int) or size <= 0:
        raise ValueError("direct-transfer fixture needs a positive integer size")
    return f"ed2k://|file|{name}|{size}|{file_hash}|/"


def default_action_set(
    search_terms: list[str],
    download_fixtures: list[dict[str, Any]],
    *,
    methods: tuple[str, ...] = DEFAULT_SEARCH_METHODS,
) -> list[ScriptedAction]:
    """One search per method (over the given terms, round-robin) + one download per
    fixture. Kept small on purpose — the goal is exercising each path once, gently."""

    actions: list[ScriptedAction] = []
    if search_terms:
        for index, method in enumerate(methods):
            term = search_terms[index % len(search_terms)]
            actions.append(
                ScriptedAction(
                    id=f"search-{method}-{term}",
                    kind="search",
                    params={"query": term, "method": method},
                )
            )
    for fixture in download_fixtures:
        file_hash = str(fixture.get("hash") or "").strip().lower()
        actions.append(
            ScriptedAction(
                id=f"download-{file_hash[:8]}",
                kind="download",
                params={
                    "hash": file_hash,
                    "size": fixture.get("size"),
                    "name": fixture.get("name"),
                },
            )
        )
    return actions


def execute_action_set(
    actions: list[ScriptedAction],
    runner: ActionRunner,
    marker_writer: MarkerWriter,
    *,
    spacing_seconds: float = DEFAULT_SPACING_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict[str, Any]]:
    """Run every action in order, emitting begin/end markers around each and pausing
    ``spacing_seconds`` between them (be-gentle). ``runner``/``sleep`` are injected so
    the sequencing + marker contract is testable without a live client."""

    results: list[dict[str, Any]] = []
    for action in actions:
        # Search markers carry the method (server/global/kad) so the offline diff
        # can pick the method-aware coverage gate without parsing the actionId.
        method = action.params.get("method") if action.kind == "search" else None
        extra = {"method": method} if method else {}
        marker_writer(
            {
                "schema": MARKER_SCHEMA,
                "marker": "begin",
                "actionId": action.id,
                "kind": action.kind,
                **extra,
                "ts_utc": utc_now_iso(),
            }
        )
        try:
            outcome = runner(action)
            status = "ok"
        except Exception as exc:  # noqa: BLE001 - one failing action must not abort the set
            outcome = {"error": str(exc)[:200]}
            status = "error"
        marker_writer(
            {
                "schema": MARKER_SCHEMA,
                "marker": "end",
                "actionId": action.id,
                "kind": action.kind,
                **extra,
                "status": status,
                "outcome": outcome,
                "ts_utc": utc_now_iso(),
            }
        )
        results.append({"actionId": action.id, "status": status, "outcome": outcome})
        if action is not actions[-1]:
            sleep(spacing_seconds)
    return results


# ── live REST wiring (isolated from the pure logic above) ─────────────────────────


def _http(base_url: str, api_key: str, path: str, method: str = "GET", body: Any = None, timeout: float = 30.0) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"X-API-Key": api_key}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base_url + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - trusted LAN REST
        return json.loads(response.read())


def _data(payload: Any) -> Any:
    return payload.get("data", payload) if isinstance(payload, dict) else payload


def _items(payload: Any) -> list[dict[str, Any]]:
    data = _data(payload)
    if isinstance(data, list):
        return data
    return list(data.get("items") or []) if isinstance(data, dict) else []


def run_search(base_url: str, api_key: str, query: str, method: str, *, poll_seconds: float = 25.0) -> dict[str, Any]:
    """POST a search then poll to completion (async contract), returning the method,
    the search id, and the count of well-formed result hashes."""

    search_id = str(
        _data(_http(base_url, api_key, "/api/v1/searches", "POST", {"query": query, "method": method, "type": ""})).get("id")
        or ""
    )
    rows: list[dict[str, Any]] = []
    deadline = time.monotonic() + poll_seconds
    while time.monotonic() < deadline:
        page = _http(base_url, api_key, f"/api/v1/searches/{search_id}")
        rows = _items(page) or rows
        if str(_data(page).get("status") or "").lower().startswith("complet"):
            break
        time.sleep(2.0)
    result_count = len([r for r in rows if len(str(r.get("hash") or "")) == 32])
    return {"method": method, "searchId": search_id, "resultCount": result_count}


def run_download(base_url: str, api_key: str, fixture: dict[str, Any]) -> dict[str, Any]:
    """Add a direct transfer by ed2k link (``POST /api/v1/transfers``)."""

    link = build_ed2k_link(fixture)
    _http(base_url, api_key, "/api/v1/transfers", "POST", {"link": link})
    return {"added": True, "hash": str(fixture.get("hash")).lower()}


def make_rest_runner(base_url: str, api_key: str) -> ActionRunner:
    """Binds a live-REST :data:`ActionRunner` for ``execute_action_set``."""

    def _run(action: ScriptedAction) -> dict[str, Any]:
        if action.kind == "search":
            return run_search(base_url, api_key, action.params["query"], action.params["method"])
        if action.kind == "download":
            return run_download(base_url, api_key, action.params)
        raise ValueError(f"unknown scripted action kind: {action.kind!r}")

    return _run
