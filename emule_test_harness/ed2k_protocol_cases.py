"""Authoritative deterministic eD2K transport and fixture variants."""

from __future__ import annotations

import hashlib
import random
from dataclasses import asdict, dataclass
from pathlib import Path

PROTOCOL_PADDING_LENGTH = 128
LOW_COMPRESSIBILITY = "low-compressibility"
COMPRESSIBLE = "compressible"


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
    return surface
