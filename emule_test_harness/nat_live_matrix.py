"""Capability-aware live NAT backend matrix shared by Rust smoke lanes."""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from .rust_rest_contract import settings_patch


PCP_BACKEND = "pcp_natpmp"
MINIUPNPC_BACKEND = "upnp_miniupnpc"
PCP_PROTOCOLS = {"pcp_v2", "pcp_v1", "nat_pmp_v0"}
# Match the established hide.me live-wire lane.  The provider IGD rejects the
# classic eMule ports in some regions, while these fixed high ports remain below
# the Linux/Windows dynamic ranges and are accepted by both NAT-PMP and UPnP.
LIVE_ED2K_PORT = 41662
LIVE_KAD_PORT = 41672


def tunnel_ipv4(address_output: str) -> str:
    match = re.search(r"\binet\s+([0-9.]+)/", address_output)
    if not match:
        raise RuntimeError("tun0 did not expose a parseable IPv4 address")
    return str(ipaddress.IPv4Address(match.group(1)))


def tunnel_gateway(route_output: str, configured_gateway: str | None = None) -> str:
    if configured_gateway:
        return str(ipaddress.IPv4Address(configured_gateway))
    match = re.search(r"\bvia\s+([0-9.]+)", route_output)
    if not match:
        match = re.search(
            r"(?m)^(\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+tun0\s+scope\s+link(?:\s|$)",
            route_output,
        )
    if not match:
        raise RuntimeError("tun0 route table did not expose a PCP/NAT-PMP gateway")
    return str(ipaddress.IPv4Address(match.group(1)))


def igd_ipv4(igd_url_or_ip: str) -> str:
    parsed = urlsplit(igd_url_or_ip)
    candidate = parsed.hostname if parsed.scheme else igd_url_or_ip
    if not candidate:
        raise RuntimeError("IGD URL did not contain a host")
    try:
        return str(ipaddress.IPv4Address(candidate))
    except ipaddress.AddressValueError as exc:
        raise RuntimeError("IGD host must be an explicit IPv4 address") from exc


def matrix_cases(
    forced_pcp_server_ip: str = "192.0.2.1",
    *,
    bind_ip: str | None = None,
    pcp_server_ip: str | None = None,
    igd_ip: str | None = None,
) -> tuple[dict[str, Any], ...]:
    """Returns the four required live NAT configurations in execution order."""

    return (
        {
            "name": "default-auto",
            "backendOrder": None,
            "bindIp": bind_ip,
            "pcpServerIp": pcp_server_ip,
            "igdIp": igd_ip,
            "expectedBackends": [PCP_BACKEND, MINIUPNPC_BACKEND],
            "attemptedBackends": [PCP_BACKEND, MINIUPNPC_BACKEND],
        },
        {
            "name": "pcp-only",
            "backendOrder": ["pcp-natpmp"],
            "bindIp": bind_ip,
            "pcpServerIp": pcp_server_ip,
            "igdIp": igd_ip,
            "expectedBackends": [PCP_BACKEND],
            "attemptedBackends": [PCP_BACKEND],
        },
        {
            "name": "miniupnpc-only",
            "backendOrder": ["upnp"],
            "bindIp": bind_ip,
            "pcpServerIp": None,
            "igdIp": igd_ip,
            "expectedBackends": [MINIUPNPC_BACKEND],
            "attemptedBackends": [MINIUPNPC_BACKEND],
        },
        {
            "name": "forced-pcp-failure-miniupnpc-fallback",
            "backendOrder": ["pcp-natpmp", "upnp"],
            "bindIp": bind_ip,
            "pcpServerIp": forced_pcp_server_ip,
            "igdIp": igd_ip,
            "expectedBackends": [MINIUPNPC_BACKEND],
            "attemptedBackends": [PCP_BACKEND, MINIUPNPC_BACKEND],
        },
    )


def settings_values(case: dict[str, Any]) -> dict[str, Any]:
    """Return current product values for one restart-bound NAT case."""
    nat = {"enabled": True, "requireInitialMapping": False,
           "pcpServerIp": case["pcpServerIp"], "igdIp": case["igdIp"]}
    if case["backendOrder"] is not None:
        nat["backendOrder"] = list(case["backendOrder"])
    return {"security": {"obfuscationEnabled": False}, "network": {
        "p2p": {"bindIp": case["bindIp"], "tcpPort": LIVE_ED2K_PORT, "udpPort": LIVE_KAD_PORT},
        "nat": nat}}


def _response_data(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("REST response requires an object data envelope")
    return data


def _verify_values(actual: dict[str, Any], expected: dict[str, Any], *, saved: bool) -> None:
    """Require each selected current value to be retained or effective."""
    for key, value in expected.items():
        if isinstance(value, dict):
            _verify_values(actual[key], value, saved=saved)
        elif (actual[key]["value"] if saved else actual[key]) != value:
            raise RuntimeError(f"NAT settings did not retain or apply the requested {key}")


def evaluate_case(
    case: dict[str, Any],
    status_payload: dict[str, Any],
    *,
    duration_seconds: float,
    daemon_alive: bool,
    maximum_seconds: float,
    require_supported: bool = False,
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
        "backendOrder": case["backendOrder"],
        "bindIp": case["bindIp"],
        "pcpServerIp": case["pcpServerIp"],
        "igdIp": case["igdIp"],
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
    if status.get("bindIp") != case["bindIp"]:
        failures.append("status did not report the configured NAT bind address")
    if status.get("igdIp") != case["igdIp"]:
        failures.append("status did not report the configured IGD address")

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
        if require_supported:
            failures.append("required live NAT capability was unsupported")
        result["capability"] = "unsupported"

    result["passed"] = not failures
    if failures:
        result["failures"] = failures
    return result


def run_matrix(
    *,
    read_settings: Callable[[], dict[str, Any]],
    apply_settings: Callable[[dict[str, object]], dict[str, Any]],
    restart_daemon: Callable[[], None],
    read_nat_status: Callable[[], dict[str, Any]],
    daemon_alive: Callable[[], bool],
    forced_pcp_server_ip: str = "192.0.2.1",
    bind_ip: str | None = None,
    pcp_server_ip: str | None = None,
    igd_ip: str | None = None,
    require_supported: bool = False,
    maximum_case_seconds: float = 60.0,
) -> dict[str, Any]:
    """Runs all four configurations, restarting between restart-required updates."""

    results = []
    for case in matrix_cases(
        forced_pcp_server_ip,
        bind_ip=bind_ip,
        pcp_server_ip=pcp_server_ip,
        igd_ip=igd_ip,
    ):
        started = time.monotonic()
        values = settings_values(case)
        reset = ("network.nat.backendOrder",) if case["backendOrder"] is None else ()
        updated = _response_data(apply_settings(settings_patch(
            read_settings(), set_values=values, reset=reset)))
        _verify_values(updated["saved"], values, saved=True)
        order = updated["saved"]["network"]["nat"]["backendOrder"]
        if reset and order["mode"] != "default":
            raise RuntimeError("Default NAT case did not reset the backend order")
        if updated["application"]["failed"]:
            raise RuntimeError("NAT settings application failed")
        restart_daemon()
        restarted = _response_data(read_settings())
        _verify_values(restarted["effective"], values, saved=False)
        if restarted["effective"]["network"]["nat"]["backendOrder"] != order["value"]:
            raise RuntimeError("NAT backend order did not apply after restart")
        if restarted["application"]["pendingRestart"] or restarted["application"]["failed"]:
            raise RuntimeError("NAT settings remain unapplied after restart")
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
                require_supported=require_supported,
            )
        )

    return {
        "schema": "emulebb.rust-nat-live-matrix.v2",
        "protocolObfuscationEnabled": False,
        "caseCount": len(results),
        "supportedCount": sum(row["capability"] == "supported" for row in results),
        "unsupportedCount": sum(row["capability"] == "unsupported" for row in results),
        "passed": all(row["passed"] for row in results),
        "cases": results,
    }
