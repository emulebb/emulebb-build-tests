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
from typing import NamedTuple

# Public mirror of the always-current Kad node set.
DEFAULT_NODES_DAT_URL = "https://upd.emule-security.org/nodes.dat"

# A browser-ish User-Agent; the mirror redirects non-browser fetches to an FAQ
# HTML page, which would otherwise parse as zero contacts.
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# Smallest valid contact record: node_id(16) + ip(4) + udp(2) + tcp(2) +
# version(1) = 25. Modern records are 34 bytes (adds contact_type + last_seen +
# udp_key); entry size is derived from the payload so both layouts parse.
_ENTRY_BASIC = 25


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

    Mirrors ``parse_nodes_dat`` in the Rust DHT crate: the first u32 is either
    a ``0`` magic prefix (modern, followed by version + count), a bare version
    (2 or 3), or the legacy contact count. The IP is stored little-endian and
    recovered with ``to_be_bytes`` (i.e. the raw 4 bytes reversed).
    """

    if len(data) < 8:
        return []

    offset = 0
    (first,) = struct.unpack_from("<I", data, offset)
    offset += 4

    if first == 0:
        (version,) = struct.unpack_from("<I", data, offset)
        offset += 4
        if version == 3:
            offset += 4  # bootstrap edition
        elif version != 2:
            return []
        (count,) = struct.unpack_from("<I", data, offset)
        offset += 4
    elif first in (2, 3):
        if first == 3:
            offset += 4  # bootstrap edition
        (count,) = struct.unpack_from("<I", data, offset)
        offset += 4
    else:
        count = first

    if count == 0 or count > 500_000:
        return []

    remaining = len(data) - offset
    entry_size = remaining // count
    if entry_size < _ENTRY_BASIC:
        return []

    contacts: list[BootstrapContact] = []
    for _ in range(count):
        if offset + entry_size > len(data):
            break
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

    contacts = parse_nodes_dat(download_nodes_dat(url, timeout_seconds=timeout_seconds))
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
