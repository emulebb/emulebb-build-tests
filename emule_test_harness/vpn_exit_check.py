"""VPN exit-IP validation for the converged soak (HTTP + STUN, CIDR allowlist).

Confirms both live clients egress through the hide.me tunnel and nowhere else:
resolve the public exit IPv4 two independent ways from a socket bound to the
tunnel bind IP — a STUN Binding Request and an HTTP IP-echo — and assert both
agree and fall inside the operator's ``allowedPublicIpCidrs``. A mismatch or an
address outside the allowlist means a clearnet leak and must abort the soak.

Stdlib only (``socket`` / ``struct`` / ``ipaddress`` / ``http.client``); the
CIDR-membership and STUN-parse logic are pure and unit-testable without a network.
"""

from __future__ import annotations

import http.client
import ipaddress
import os
import secrets
import socket
import struct
from typing import Any

# Public STUN servers (host, port). Tried in order; the first to answer wins.
DEFAULT_STUN_SERVERS: tuple[tuple[str, int], ...] = (
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
)
# Plain-text IPv4 echo endpoints (host, path). Body must be just the IP.
DEFAULT_HTTP_ECHOES: tuple[tuple[str, str], ...] = (
    ("api.ipify.org", "/"),
    ("ifconfig.me", "/ip"),
    ("checkip.amazonaws.com", "/"),
)

_STUN_MAGIC_COOKIE = 0x2112A442
_STUN_BINDING_REQUEST = 0x0001
_ATTR_MAPPED_ADDRESS = 0x0001
_ATTR_XOR_MAPPED_ADDRESS = 0x0020


def ipv4_in_cidrs(ip: str, cidrs_csv: str) -> bool:
    """Whether ``ip`` (IPv4) is inside any CIDR in the comma-separated list."""

    try:
        addr = ipaddress.IPv4Address(ip.strip())
    except ValueError:
        return False
    for raw in (cidrs_csv or "").split(","):
        token = raw.strip()
        if not token:
            continue
        try:
            if addr in ipaddress.ip_network(token, strict=False):
                return True
        except ValueError:
            continue
    return False


def parse_stun_mapped_address(payload: bytes) -> str | None:
    """Extract the mapped public IPv4 from a STUN Binding Response body."""

    if len(payload) < 20:
        return None
    msg_type, msg_len = struct.unpack(">HH", payload[:4])
    cookie = struct.unpack(">I", payload[4:8])[0]
    # A Binding Response is 0x0101 (success); accept any non-request with the cookie.
    if cookie != _STUN_MAGIC_COOKIE or msg_type == _STUN_BINDING_REQUEST:
        return None
    body = payload[20 : 20 + msg_len]
    offset = 0
    while offset + 4 <= len(body):
        attr_type, attr_len = struct.unpack(">HH", body[offset : offset + 4])
        value = body[offset + 4 : offset + 4 + attr_len]
        offset += 4 + attr_len + (-attr_len % 4)  # attributes are 4-byte padded
        if attr_type == _ATTR_XOR_MAPPED_ADDRESS and len(value) >= 8 and value[1] == 0x01:
            xaddr = struct.unpack(">I", value[4:8])[0] ^ _STUN_MAGIC_COOKIE
            return str(ipaddress.IPv4Address(xaddr))
        if attr_type == _ATTR_MAPPED_ADDRESS and len(value) >= 8 and value[1] == 0x01:
            return str(ipaddress.IPv4Address(value[4:8]))
    return None


def stun_public_ip(
    bind_ip: str,
    *,
    servers: tuple[tuple[str, int], ...] = DEFAULT_STUN_SERVERS,
    timeout: float = 6.0,
) -> str | None:
    """Resolve the public IPv4 via STUN from a UDP socket bound to ``bind_ip``."""

    request = struct.pack(">HHI", _STUN_BINDING_REQUEST, 0, _STUN_MAGIC_COOKIE) + secrets.token_bytes(12)
    for host, port in servers:
        try:
            dest = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.bind((bind_ip, 0))
                sock.sendto(request, dest)
                data, _ = sock.recvfrom(1024)
            ip = parse_stun_mapped_address(data)
            if ip:
                return ip
        except OSError:
            continue
    return None


def http_public_ip(
    bind_ip: str,
    *,
    echoes: tuple[tuple[str, str], ...] = DEFAULT_HTTP_ECHOES,
    timeout: float = 6.0,
) -> str | None:
    """Resolve the public IPv4 via an HTTP IP-echo, source-bound to ``bind_ip``."""

    for host, path in echoes:
        try:
            conn = http.client.HTTPConnection(host, 80, timeout=timeout, source_address=(bind_ip, 0))
            try:
                conn.request("GET", path, headers={"Host": host, "User-Agent": "curl/8"})
                body = conn.getresponse().read().decode("ascii", "ignore").strip()
            finally:
                conn.close()
            candidate = body.split()[0] if body else ""
            ipaddress.IPv4Address(candidate)  # validate
            return candidate
        except (OSError, ValueError, IndexError, http.client.HTTPException):
            continue
    return None


def validate_exit_ip(bind_ip: str, allowed_cidrs: str, *, label: str = "tunnel") -> dict[str, Any]:
    """Validate the public exit IP for ``bind_ip`` via HTTP + STUN against the
    allowlist. Returns a result dict; ``ok`` is True only when both methods
    resolve, agree, and land inside ``allowed_cidrs``. Never raises on a leak —
    the caller decides how to fail so it can record the evidence first."""

    stun_ip = stun_public_ip(bind_ip)
    http_ip = http_public_ip(bind_ip)
    agree = bool(stun_ip and http_ip and stun_ip == http_ip)
    stun_ok = bool(stun_ip and ipv4_in_cidrs(stun_ip, allowed_cidrs))
    http_ok = bool(http_ip and ipv4_in_cidrs(http_ip, allowed_cidrs))
    reasons: list[str] = []
    if stun_ip is None:
        reasons.append("STUN did not resolve a public IP")
    elif not stun_ok:
        reasons.append(f"STUN exit {stun_ip} is outside the hide.me allowlist")
    if http_ip is None:
        reasons.append("HTTP echo did not resolve a public IP")
    elif not http_ok:
        reasons.append(f"HTTP exit {http_ip} is outside the hide.me allowlist")
    if stun_ip and http_ip and not agree:
        reasons.append(f"STUN {stun_ip} != HTTP {http_ip} (inconsistent exit)")
    return {
        "label": label,
        "bindIp": bind_ip,
        "stunIp": stun_ip,
        "httpIp": http_ip,
        "agree": agree,
        "allowedCidrs": allowed_cidrs,
        "ok": bool(stun_ok and http_ok and agree),
        "reasons": reasons,
    }


def rest_reported_public_ip(status: dict[str, Any]) -> str | None:
    """Best-effort extract of a client's REST-reported public/external IPv4
    (rust `/api/v1/status` + `/api/v1/kad`; MFC exposes the same envelope). The
    client's own server-IDCHANGE / STUN result — a per-client cross-check."""

    for container_key in ("kad", "ed2k", "network"):
        container = status.get(container_key)
        if isinstance(container, dict):
            for key in ("publicIp", "externalIp", "publicAddress", "ip"):
                value = container.get(key)
                if isinstance(value, str) and value.strip():
                    try:
                        ipaddress.IPv4Address(value.strip())
                        return value.strip()
                    except ValueError:
                        continue
    for key in ("publicIp", "externalIp"):
        value = status.get(key)
        if isinstance(value, str) and value.strip():
            try:
                ipaddress.IPv4Address(value.strip())
                return value.strip()
            except ValueError:
                continue
    return None


def _looks_like_ci() -> bool:
    return bool(os.environ.get("CI"))
