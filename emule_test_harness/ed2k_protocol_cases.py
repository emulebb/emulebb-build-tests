"""Authoritative deterministic eD2K transport and fixture variants."""

from __future__ import annotations

import hashlib
import random
from dataclasses import asdict, dataclass
from pathlib import Path

PROTOCOL_PADDING_LENGTH = 128
LOW_COMPRESSIBILITY = "low-compressibility"
COMPRESSIBLE = "compressible"
SERVER_UDP_FLAG_EXT_GETSOURCES = 0x0000_0001
SERVER_UDP_FLAG_EXT_GETFILES = 0x0000_0002
SERVER_UDP_FLAG_EXT_GETSOURCES2 = 0x0000_0020
SERVER_UDP_FLAG_LARGEFILES = 0x0000_0100
SERVER_UDP_FLAG_UDPOBFUSCATION = 0x0000_0200
SERVER_UDP_FLAG_TCPOBFUSCATION = 0x0000_0400


@dataclass(frozen=True)
class ProtocolCase:
    """One deterministic eD2K protocol configuration."""

    name: str
    artifact_id: str
    server_protocol_obfuscation: bool
    server_udp: bool
    client_crypt_supported: bool
    client_crypt_requested: bool
    client_crypt_required: bool
    fixture_pattern: str = LOW_COMPRESSIBILITY


PROTOCOL_CASES = (
    ProtocolCase(
        name="plain-server-plain-clients",
        artifact_id="plain",
        server_protocol_obfuscation=False,
        server_udp=True,
        client_crypt_supported=False,
        client_crypt_requested=False,
        client_crypt_required=False,
    ),
    ProtocolCase(
        name="obfuscated-preferred",
        artifact_id="obf-pref",
        server_protocol_obfuscation=True,
        server_udp=True,
        client_crypt_supported=True,
        client_crypt_requested=True,
        client_crypt_required=False,
    ),
    ProtocolCase(
        name="obfuscated-preferred-fallback",
        artifact_id="obf-fallback",
        server_protocol_obfuscation=False,
        server_udp=True,
        client_crypt_supported=True,
        client_crypt_requested=True,
        client_crypt_required=False,
    ),
    ProtocolCase(
        name="obfuscated-required",
        artifact_id="obf-req",
        server_protocol_obfuscation=True,
        server_udp=True,
        client_crypt_supported=True,
        client_crypt_requested=True,
        client_crypt_required=True,
    ),
    ProtocolCase(
        name="obfuscated-required-compressible",
        artifact_id="obf-req-z",
        server_protocol_obfuscation=True,
        server_udp=True,
        client_crypt_supported=True,
        client_crypt_requested=True,
        client_crypt_required=True,
        fixture_pattern=COMPRESSIBLE,
    ),
)
PROTOCOL_CASE_MAP = {case.name: case for case in PROTOCOL_CASES}


def selected_cases(names: list[str] | None) -> list[ProtocolCase]:
    """Returns requested cases in authoritative matrix order."""

    if not names:
        return list(PROTOCOL_CASES)
    wanted = set(names)
    return [case for case in PROTOCOL_CASES if case.name in wanted]


def _bool_pref(value: bool) -> str:
    return "1" if value else "0"


def mfc_preference_updates(case: ProtocolCase) -> tuple[tuple[str, str], ...]:
    """Returns the exact MFC preference updates for one case."""

    return (
        ("CryptLayerSupported", _bool_pref(case.client_crypt_supported)),
        ("CryptLayerRequested", _bool_pref(case.client_crypt_requested)),
        ("CryptLayerRequired", _bool_pref(case.client_crypt_required)),
        ("CryptTCPPaddingLength", str(PROTOCOL_PADDING_LENGTH)),
    )


def mfc_preference_snapshot(case: ProtocolCase) -> dict[str, str]:
    """Returns the report form of the MFC preference updates."""

    return dict(mfc_preference_updates(case))


def expected_peer_transport_mode(case: ProtocolCase) -> str:
    """Returns the transport mode required for the case's peer session."""

    return "obfuscated" if case.client_crypt_supported else "plaintext"


def required_server_transport_plan(case: ProtocolCase) -> tuple[str, ...]:
    """Returns the exact ordered server transports required by one case."""

    if not case.client_crypt_supported:
        return ("plaintext",)
    if case.server_protocol_obfuscation:
        return ("obfuscated",)
    if case.client_crypt_requested and not case.client_crypt_required:
        return ("obfuscated", "plaintext")
    raise ValueError(f"Protocol case {case.name!r} has no successful server transport plan.")


def expected_payload_encoding(case: ProtocolCase) -> str:
    """Returns the exact payload opcode family required for one fixture."""

    return "compressed" if case.fixture_pattern == COMPRESSIBLE else "uncompressed"


def client_connect_options(case: ProtocolCase) -> int:
    """Returns the stock source-hint crypt bits represented by one case."""

    return (
        int(case.client_crypt_supported)
        | (int(case.client_crypt_requested) << 1)
        | (int(case.client_crypt_required) << 2)
    )


def server_udp_flags(case: ProtocolCase) -> int:
    """Returns the stock server capability flags advertised to Rust."""

    flags = (
        SERVER_UDP_FLAG_EXT_GETSOURCES
        | SERVER_UDP_FLAG_EXT_GETFILES
        | SERVER_UDP_FLAG_EXT_GETSOURCES2
        | SERVER_UDP_FLAG_LARGEFILES
    )
    if case.server_protocol_obfuscation:
        flags |= SERVER_UDP_FLAG_TCPOBFUSCATION
    if case.server_protocol_obfuscation and case.server_udp:
        flags |= SERVER_UDP_FLAG_UDPOBFUSCATION
    return flags


def rust_server_entry(case: ProtocolCase, host: str, tcp_port: int) -> dict[str, object]:
    """Builds the deterministic server metadata Rust needs for one case."""

    udp_key = 0x11223344 if case.server_protocol_obfuscation and case.server_udp else 0
    return {
        "host": host,
        "port": tcp_port,
        "name": "emulebb-local-e2e",
        "description": "Workspace deterministic eMuleBB Rust protocol campaign server",
        "udpFlags": server_udp_flags(case),
        "udpKey": udp_key,
        "udpKeyIp": 0,
        "obfuscationPortTcp": tcp_port if case.server_protocol_obfuscation else 0,
        "obfuscationPortUdp": tcp_port + 4 if case.server_protocol_obfuscation and case.server_udp else 0,
    }


def write_fixture(path: Path, size_bytes: int, pattern: str) -> str:
    """Writes deterministic bytes for one protocol case and returns SHA-256."""

    if pattern not in {LOW_COMPRESSIBILITY, COMPRESSIBLE}:
        raise ValueError(f"Unsupported protocol fixture pattern: {pattern!r}")
    if size_bytes <= 0:
        raise ValueError("Fixture size must be greater than zero.")
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    remaining = size_bytes
    rng = random.Random(0xED2B2026)
    compressible_block = (b"emulebb-local-ed2k-compressible-fixture\n" * 2048)[: 64 * 1024]
    with path.open("wb") as handle:
        while remaining > 0:
            chunk_size = min(64 * 1024, remaining)
            if pattern == COMPRESSIBLE:
                chunk = compressible_block[:chunk_size]
            else:
                chunk = bytes(rng.getrandbits(8) for _ in range(chunk_size))
            handle.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def protocol_surface(case: ProtocolCase) -> dict[str, object]:
    """Returns the explicit transport and fixture surface for one case."""

    surface = asdict(case)
    surface["client_data_compression"] = {
        "mode": "stock-auto-negotiated",
        "preference_toggle": False,
        "evidence": (
            "eMule advertises data compression capability during client hello; "
            "the matrix varies fixture compressibility because no stock profile toggle exists."
        ),
    }
    surface["rust_client_crypt"] = {
        "obfuscation_enabled": case.client_crypt_supported,
        "required_preference_supported": False,
        "evidence": (
            "emulebb-rust exposes one ED2K obfuscation boolean, not separate "
            "supported/requested/required preferences."
        ),
    }
    return surface
