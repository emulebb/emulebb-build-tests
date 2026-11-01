from __future__ import annotations

import hashlib
from pathlib import Path

from emule_test_harness import ed2k_protocol_cases


def test_default_matrix_covers_plain_obfuscated_udp_and_compression_surfaces() -> None:
    cases = {case.name: case for case in ed2k_protocol_cases.selected_cases(None)}

    assert tuple(cases) == (
        "plain-server-plain-clients",
        "obfuscated-preferred",
        "obfuscated-required",
        "obfuscated-required-compressible",
    )
    assert cases["plain-server-plain-clients"].server_protocol_obfuscation is False
    assert cases["plain-server-plain-clients"].client_crypt_supported is False
    assert cases["obfuscated-preferred"].client_crypt_requested is True
    assert cases["obfuscated-required"].client_crypt_required is True
    assert cases["obfuscated-required-compressible"].artifact_id == "obf-req-z"
    assert all(case.server_udp for case in cases.values())
    assert cases["obfuscated-required-compressible"].fixture_pattern == ed2k_protocol_cases.COMPRESSIBLE


def test_selected_cases_preserves_matrix_order() -> None:
    selected = ed2k_protocol_cases.selected_cases(
        ["obfuscated-required", "plain-server-plain-clients"]
    )

    assert [case.name for case in selected] == ["plain-server-plain-clients", "obfuscated-required"]


def test_protocol_surface_documents_auto_negotiated_compression() -> None:
    case = ed2k_protocol_cases.PROTOCOL_CASE_MAP["obfuscated-required-compressible"]

    surface = ed2k_protocol_cases.protocol_surface(case)

    assert surface["fixture_pattern"] == "compressible"
    assert surface["client_data_compression"]["mode"] == "stock-auto-negotiated"
    assert surface["client_data_compression"]["preference_toggle"] is False


def test_fixture_writer_is_deterministic_for_both_patterns(tmp_path: Path) -> None:
    for pattern in (ed2k_protocol_cases.LOW_COMPRESSIBILITY, ed2k_protocol_cases.COMPRESSIBLE):
        first = tmp_path / pattern / "first.bin"
        second = tmp_path / pattern / "second.bin"

        first_hash = ed2k_protocol_cases.write_fixture(first, 1024 * 1024 + 7, pattern)
        second_hash = ed2k_protocol_cases.write_fixture(second, 1024 * 1024 + 7, pattern)

        assert first.read_bytes() == second.read_bytes()
        assert first_hash == second_hash == hashlib.sha256(first.read_bytes()).hexdigest()


def test_mfc_preferences_are_derived_from_the_same_case() -> None:
    case = ed2k_protocol_cases.PROTOCOL_CASE_MAP["obfuscated-required"]

    assert ed2k_protocol_cases.mfc_preference_snapshot(case) == {
        "CryptLayerSupported": "1",
        "CryptLayerRequested": "1",
        "CryptLayerRequired": "1",
        "CryptTCPPaddingLength": str(ed2k_protocol_cases.PROTOCOL_PADDING_LENGTH),
    }
