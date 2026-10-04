"""Server-health evidence helpers shared by Rust live VPN smoke lanes."""

from __future__ import annotations

import re
from typing import Any


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _response_data(payload: dict[str, Any]) -> Any:
    return payload.get("data", payload)


def server_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Returns canonical server rows from list or wrapped REST responses."""

    data = _response_data(payload)
    if isinstance(data, dict):
        rows = data.get("items", data.get("servers", []))
    else:
        rows = data
    if not isinstance(rows, list):
        raise RuntimeError("server response did not contain a row list")
    return [dict(row) for row in rows if isinstance(row, dict)]


def endpoint(row: dict[str, Any]) -> str:
    explicit = str(row.get("endpoint") or "").strip()
    if explicit:
        return explicit.lower()
    address = str(row.get("address") or row.get("ip") or "").strip()
    port = int(row.get("port") or 0)
    if not address or not port:
        raise RuntimeError("server row lacked an endpoint or address/port")
    return f"{address}:{port}".lower()


def health_snapshot(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Captures only stable health fields; names and live statistics are omitted."""

    return {
        endpoint(row): {
            "enabled": bool(row.get("enabled")),
            "failedCount": int(row.get("failedCount") or 0),
            "current": bool(row.get("current")),
        }
        for row in server_rows(payload)
    }


def connected_server_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    snapshot = health_snapshot(payload)
    current = [key for key, row in snapshot.items() if row["current"]]
    if len(current) != 1:
        raise RuntimeError(f"expected one current ED2K server, found {len(current)}")
    selected = current[0]
    return {"endpoint": selected, **snapshot[selected]}


def compare_after_local_failure(
    before_payload: dict[str, Any],
    after_payload: dict[str, Any],
) -> dict[str, Any]:
    """Proves a local/VPN failure did not disable or increment healthy servers."""

    before = health_snapshot(before_payload)
    after = health_snapshot(after_payload)
    failures: list[str] = []
    checked: list[dict[str, Any]] = []
    for key, old in sorted(before.items()):
        if not old["enabled"]:
            continue
        new = after.get(key)
        if new is None:
            failures.append(f"enabled server disappeared: {key}")
            continue
        checked.append(
            {
                "endpoint": key,
                "failedCountBefore": old["failedCount"],
                "failedCountAfter": new["failedCount"],
                "enabledAfter": new["enabled"],
            }
        )
        if not new["enabled"]:
            failures.append(f"enabled server was disabled: {key}")
        if new["failedCount"] != old["failedCount"]:
            failures.append(
                f"failedCount changed for {key}: {old['failedCount']} -> {new['failedCount']}"
            )
    if not checked:
        failures.append("no pre-fault enabled server remained available for comparison")
    return {"passed": not failures, "servers": checked, "failures": failures}


def ignored_failure_log_evidence(logs: str) -> dict[str, Any]:
    """Finds stable classified-failure fields without retaining arbitrary log text."""

    # Docker captures the colored tracing formatter verbatim.  Strip its SGR
    # sequences before matching so styling between a field name and '=' cannot
    # hide otherwise valid structured evidence.
    logs = ANSI_ESCAPE_RE.sub("", logs)
    reasons = sorted(
        set(
            re.findall(
                r"reason[= ]+\"?(dns_resolution|local_bind_interface|timeout_unreachable|"
                r"protocol_rejection|established_disconnect|transport_other)\"?",
                logs,
            )
        )
    )
    ignored = bool(re.search(r'action[= ]+"?ignored"?', logs))
    return {"passed": ignored and bool(reasons), "action": "ignored" if ignored else None, "reasons": reasons}
