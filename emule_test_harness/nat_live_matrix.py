"""Capability-aware live NAT backend matrix shared by Rust smoke lanes."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any


PCP_BACKEND = "pcp_natpmp"
MINIUPNPC_BACKEND = "upnp_miniupnpc"
PCP_PROTOCOLS = {"pcp_v2", "pcp_v1", "nat_pmp_v0"}


def matrix_cases(forced_pcp_server_ip: str = "192.0.2.1") -> tuple[dict[str, Any], ...]:
    """Returns the four required live NAT configurations in execution order."""

    return (
        {
            "name": "default-auto",
            "backendOrder": [],
            "pcpServerIp": None,
            "expectedBackends": [PCP_BACKEND, MINIUPNPC_BACKEND],
            "attemptedBackends": [PCP_BACKEND, MINIUPNPC_BACKEND],
        },
        {
            "name": "pcp-only",
            "backendOrder": [PCP_BACKEND],
            "pcpServerIp": None,
            "expectedBackends": [PCP_BACKEND],
            "attemptedBackends": [PCP_BACKEND],
        },
        {
            "name": "miniupnpc-only",
            "backendOrder": [MINIUPNPC_BACKEND],
            "pcpServerIp": None,
            "expectedBackends": [MINIUPNPC_BACKEND],
            "attemptedBackends": [MINIUPNPC_BACKEND],
        },
        {
            "name": "forced-pcp-failure-miniupnpc-fallback",
            "backendOrder": [PCP_BACKEND, MINIUPNPC_BACKEND],
            "pcpServerIp": forced_pcp_server_ip,
            "expectedBackends": [MINIUPNPC_BACKEND],
            "attemptedBackends": [PCP_BACKEND, MINIUPNPC_BACKEND],
        },
    )


def settings_patch(case: dict[str, Any]) -> dict[str, object]:
    """Builds one restart-required settings update with obfuscation disabled."""

    return {
        "ed2k": {"obfuscationEnabled": False},
        "nat": {
            "enabled": True,
            "requireInitialMapping": False,
            "backendOrder": list(case["backendOrder"]),
            "pcpServerIp": case["pcpServerIp"],
            "discoveryTimeoutSecs": 2,
        },
    }


def _response_data(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data", payload)
    if not isinstance(data, dict):
        raise RuntimeError("REST response data was not an object")
    return data


def evaluate_case(
    case: dict[str, Any],
    status_payload: dict[str, Any],
    *,
    duration_seconds: float,
    daemon_alive: bool,
    maximum_seconds: float,
) -> dict[str, Any]:
    """Classifies supported and cleanly unsupported live-network outcomes."""

    status = _response_data(status_payload)
    mappings = status.get("mappings") or []
    if not isinstance(mappings, list):
        mappings = []
    backend = status.get("backend")
    protocol = status.get("protocol")
    error = str(status.get("lastError") or "")
    result: dict[str, Any] = {
        "name": case["name"],
        "backendOrder": list(case["backendOrder"]),
        "pcpServerIp": case["pcpServerIp"],
        "durationSeconds": round(duration_seconds, 3),
        "daemonAlive": daemon_alive,
        "enabled": bool(status.get("enabled")),
        "gatewayDiscovered": bool(status.get("gatewayDiscovered")),
        "backend": backend,
        "protocol": protocol,
        "mappingCount": len(mappings),
        "lastError": error or None,
    }
    failures: list[str] = []
    if not daemon_alive:
        failures.append("daemon exited during NAT reconciliation")
    if duration_seconds > maximum_seconds:
        failures.append(
            f"case exceeded the {maximum_seconds:g}s bounded-execution limit"
        )
    if not result["enabled"]:
        failures.append("NAT status did not remain enabled")
    if status.get("pcpServerIp") != case["pcpServerIp"]:
        failures.append("status did not report the configured PCP server override")

    supported = (
        result["gatewayDiscovered"]
        and len(mappings) >= 2
        and backend in case["expectedBackends"]
    )
    if supported:
        if backend == PCP_BACKEND and protocol not in PCP_PROTOCOLS:
            failures.append(f"PCP backend reported unexpected protocol {protocol!r}")
        if backend == MINIUPNPC_BACKEND and protocol != "upnp_igd":
            failures.append(f"MiniUPnPc backend reported unexpected protocol {protocol!r}")
        result["capability"] = "supported"
    else:
        missing_attempts = [
            name for name in case["attemptedBackends"] if name not in error
        ]
        if not error:
            failures.append("unsupported result did not retain a diagnostic error")
        elif missing_attempts:
            failures.append(
                "diagnostic did not prove backend attempt(s): " + ", ".join(missing_attempts)
            )
        if backend is not None or mappings:
            failures.append("partial mapping state remained after an unsupported result")
        result["capability"] = "unsupported"

    result["passed"] = not failures
    if failures:
        result["failures"] = failures
    return result


def run_matrix(
    *,
    apply_settings: Callable[[dict[str, object]], dict[str, Any]],
    restart_daemon: Callable[[], None],
    read_nat_status: Callable[[], dict[str, Any]],
    daemon_alive: Callable[[], bool],
    forced_pcp_server_ip: str = "192.0.2.1",
    maximum_case_seconds: float = 60.0,
) -> dict[str, Any]:
    """Runs all four configurations, restarting between restart-required updates."""

    results = []
    for case in matrix_cases(forced_pcp_server_ip):
        started = time.monotonic()
        updated = _response_data(apply_settings(settings_patch(case)))
        ed2k = updated.get("ed2k") or {}
        nat = updated.get("nat") or {}
        if not isinstance(ed2k, dict) or ed2k.get("obfuscationEnabled") is not False:
            raise RuntimeError("settings update did not disable protocol obfuscation")
        if not isinstance(nat, dict) or nat.get("backendOrder") != case["backendOrder"]:
            raise RuntimeError("settings update did not retain the requested NAT backend order")
        if nat.get("pcpServerIp") != case["pcpServerIp"]:
            raise RuntimeError("settings update did not retain the PCP server override")
        restart_daemon()
        status_payload = read_nat_status()
        while (
            _response_data(status_payload).get("lastRefreshUnixSecs") is None
            and daemon_alive()
            and time.monotonic() - started <= maximum_case_seconds
        ):
            time.sleep(0.25)
            status_payload = read_nat_status()
        results.append(
            evaluate_case(
                case,
                status_payload,
                duration_seconds=time.monotonic() - started,
                daemon_alive=daemon_alive(),
                maximum_seconds=maximum_case_seconds,
            )
        )

    return {
        "schema": "emulebb.rust-nat-live-matrix.v1",
        "protocolObfuscationEnabled": False,
        "caseCount": len(results),
        "supportedCount": sum(row["capability"] == "supported" for row in results),
        "unsupportedCount": sum(row["capability"] == "unsupported" for row in results),
        "passed": all(row["passed"] for row in results),
        "cases": results,
    }
