from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_suite_module():
    """Loads the hyphenated protocol-combination script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "local-ed2k-protocol-combinations.py"
    spec = importlib.util.spec_from_file_location("local_ed2k_protocol_combinations_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_default_matrix_covers_plain_obfuscated_udp_and_compression_surfaces() -> None:
    module = load_suite_module()

    cases = {case.name: case for case in module.selected_cases(None)}

    assert "plain-server-plain-clients" in cases
    assert cases["plain-server-plain-clients"].server_protocol_obfuscation is False
    assert cases["plain-server-plain-clients"].client_crypt_supported is False
    assert "obfuscated-preferred" in cases
    assert cases["obfuscated-preferred"].client_crypt_requested is True
    assert "obfuscated-required" in cases
    assert cases["obfuscated-required"].client_crypt_required is True
    assert "obfuscated-required-no-server-udp-compressible" in cases
    assert cases["obfuscated-required-no-server-udp-compressible"].artifact_id == "obf-req-no-udp-z"
    assert cases["obfuscated-required-no-server-udp-compressible"].server_udp is False
    assert cases["obfuscated-required-no-server-udp-compressible"].fixture_pattern == "compressible"


def test_selected_cases_preserves_matrix_order() -> None:
    module = load_suite_module()

    selected = module.selected_cases(["obfuscated-required", "plain-server-plain-clients"])

    assert [case.name for case in selected] == ["plain-server-plain-clients", "obfuscated-required"]


def test_protocol_surface_documents_auto_negotiated_compression() -> None:
    module = load_suite_module()

    surface = module.protocol_surface(module.PROTOCOL_CASE_MAP["obfuscated-required-no-server-udp-compressible"])

    assert surface["fixture_pattern"] == "compressible"
    assert surface["client_data_compression"]["mode"] == "stock-auto-negotiated"
    assert surface["client_data_compression"]["preference_toggle"] is False


def test_apply_protocol_preferences_writes_eMule_crypt_keys(tmp_path: Path) -> None:
    module = load_suite_module()
    config_dir = tmp_path / "profile" / "config"
    config_dir.mkdir(parents=True)
    module.live_common.write_utf16_ini_text(config_dir / "preferences.ini", "[eMule]\nNick=test\n")

    written = module.apply_protocol_preferences(config_dir, module.PROTOCOL_CASE_MAP["obfuscated-required"])

    text = module.live_common.read_ini_text(config_dir / "preferences.ini")
    assert written == {
        "CryptLayerSupported": "1",
        "CryptLayerRequested": "1",
        "CryptLayerRequired": "1",
        "CryptTCPPaddingLength": str(module.PROTOCOL_PADDING_LENGTH),
    }
    assert "CryptLayerSupported=1" in text
    assert "CryptLayerRequested=1" in text
    assert "CryptLayerRequired=1" in text


def test_compressible_fixture_writer_is_deterministic(tmp_path: Path) -> None:
    module = load_suite_module()
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"

    first_hash = module.write_protocol_fixture_file(first, 1024 * 1024 + 7, "compressible")
    second_hash = module.write_protocol_fixture_file(second, 1024 * 1024 + 7, "compressible")

    assert first.read_bytes() == second.read_bytes()
    assert first_hash == second_hash == module.dtt.file_sha256(first)
