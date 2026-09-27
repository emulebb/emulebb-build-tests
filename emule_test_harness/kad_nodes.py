"""Kad ``nodes.dat`` download + parse helpers for live-wire harness runs.

This mirrors the binary layout parsed by the Rust client in
``crates/emulebb-kad-dht/src/bootstrap.rs`` so the harness can seed the
daemon's ``[kad] bootstrapNodes`` from a real, current ``nodes.dat`` (the
REST ``import-nodes-url`` endpoint is a stub, and the public mirror serves an
HTML page to non-browser clients).
"""

from __future__ import annotations

import ipaddress
import struct
import urllib.request
from pathlib import Path
from typing import NamedTuple

# Public mirror of the always-current Kad node set.
DEFAULT_NODES_DAT_URL = "https://upd.emule-security.org/nodes.dat"

# A browser-ish User-Agent; the mirror redirects non-browser fetches to an FAQ
# HTML page, which would otherwise parse as zero contacts.
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# Stock record widths: node_id(16) + ip(4) + udp(2) + tcp(2) + version/type(1),
# with v2/normal-v3 adding CKadUDPKey(key + bound public IP) and verified byte.
_ENTRY_BASIC = 25
_ENTRY_EXTENDED = 34
_MAX_CONTACTS = 500_000


class BootstrapContact(NamedTuple):
    """One parsed Kad contact reduced to what bootstrapNodes needs."""

    ip: str
    udp_port: int
    tcp_port: int

    @property
    def endpoint(self) -> str:
        return f"{self.ip}:{self.udp_port}"


def download_nodes_dat(url: str = DEFAULT_NODES_DAT_URL, *, timeout_seconds: float = 30.0) -> bytes:
    """Fetches a ``nodes.dat`` payload from a public mirror."""

    request = urllib.request.Request(url, headers={"User-Agent": _BROWSER_UA})
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return response.read()


def _is_public_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def parse_nodes_dat(data: bytes) -> list[BootstrapContact]:
    """Parses a ``nodes.dat`` payload into public, routable Kad contacts.

    Mirrors the exact stock grammar used by the Rust DHT crate. A non-zero first
    u32 is always the legacy v0 contact count (including 2 and 3). A zero first
    word introduces modern v1/v2/v3 headers. Record widths are selected by the
    declared format and the total payload must match exactly.
    """

    if len(data) < 4:
        return []

    offset = 0
    (first,) = struct.unpack_from("<I", data, offset)
    offset += 4

    if first == 0:
        if len(data) == 4:  # valid empty legacy file
            return []
        if len(data) < 12:
            return []
        (version,) = struct.unpack_from("<I", data, offset)
        offset += 4
        if version == 1:
            entry_size = _ENTRY_BASIC
        elif version == 2:
            entry_size = _ENTRY_EXTENDED
        elif version == 3:
            if len(data) < 16:
                return []
            (edition,) = struct.unpack_from("<I", data, offset)
            offset += 4
            if edition == 0:
                entry_size = _ENTRY_EXTENDED
            elif edition == 1:
                entry_size = _ENTRY_BASIC
            else:
                return []
        else:
            return []
        (count,) = struct.unpack_from("<I", data, offset)
        offset += 4
    else:
        count = first
        entry_size = _ENTRY_BASIC

    if count > _MAX_CONTACTS:
        return []
    if len(data) != offset + count * entry_size:
        return []

    contacts: list[BootstrapContact] = []
    for _ in range(count):
        # ip is 4 bytes at node_id(16); to_be_bytes(le_u32) == raw bytes reversed.
        (ip_le,) = struct.unpack_from("<I", data, offset + 16)
        udp_port, tcp_port = struct.unpack_from("<HH", data, offset + 20)
        offset += entry_size
        if ip_le == 0 or udp_port == 0:
            continue
        ip = ".".join(str(b) for b in struct.pack(">I", ip_le))
        if not _is_public_ipv4(ip):
            continue
        contacts.append(BootstrapContact(ip=ip, udp_port=udp_port, tcp_port=tcp_port))
    return contacts


def fetch_bootstrap_endpoints(
    url: str = DEFAULT_NODES_DAT_URL,
    *,
    limit: int = 40,
    timeout_seconds: float = 30.0,
) -> list[str]:
    """Downloads + parses ``nodes.dat`` and returns up to ``limit`` ``ip:udpPort`` strings."""

    return bootstrap_endpoints_from_nodes_dat(
        download_nodes_dat(url, timeout_seconds=timeout_seconds),
        limit=limit,
    )


def load_bootstrap_endpoints(path: Path, *, limit: int = 40) -> list[str]:
    """Reads a local ``nodes.dat`` and returns up to ``limit`` ``ip:udpPort`` strings."""

    return bootstrap_endpoints_from_nodes_dat(path.read_bytes(), limit=limit)


def bootstrap_endpoints_from_nodes_dat(data: bytes, *, limit: int = 40) -> list[str]:
    """Parses a ``nodes.dat`` payload and returns deduplicated bootstrap endpoints."""

    contacts = parse_nodes_dat(data)
    seen: set[str] = set()
    endpoints: list[str] = []
    for contact in contacts:
        endpoint = contact.endpoint
        if endpoint in seen:
            continue
        seen.add(endpoint)
        endpoints.append(endpoint)
        if len(endpoints) >= limit:
            break
    return endpoints
