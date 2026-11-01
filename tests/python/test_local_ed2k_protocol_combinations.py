from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from emule_test_harness import ed2k_protocol_cases


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


def test_apply_protocol_preferences_writes_eMule_crypt_keys(tmp_path: Path) -> None:
    module = load_suite_module()
    config_dir = tmp_path / "profile" / "config"
    config_dir.mkdir(parents=True)
    module.live_common.write_utf16_ini_text(config_dir / "preferences.ini", "[eMule]\nNick=test\n")

    written = module.apply_protocol_preferences(
        config_dir,
        ed2k_protocol_cases.PROTOCOL_CASE_MAP["obfuscated-required"],
    )

    text = module.live_common.read_ini_text(config_dir / "preferences.ini")
    assert written == {
        "CryptLayerSupported": "1",
        "CryptLayerRequested": "1",
        "CryptLayerRequired": "1",
        "CryptTCPPaddingLength": str(ed2k_protocol_cases.PROTOCOL_PADDING_LENGTH),
    }
    assert "CryptLayerSupported=1" in text
    assert "CryptLayerRequested=1" in text
    assert "CryptLayerRequired=1" in text


def test_protocol_cases_reuse_shared_ed2k_harness_launcher() -> None:
    module = load_suite_module()
    script_text = Path(module.__file__).read_text(encoding="utf-8")

    assert "ed2k_harness.prepare_ed2k_server_binary(" in script_text
    assert "ed2k_harness.launch_ed2k_server(" in script_text
    assert "ed2k_address=p2p_address" in script_text
    assert "server_address = ed2k_server.ed2k_host" in script_text
    assert script_text.count("address=server_address") == 2
    assert "network[\"ed2k_server_address\"] = server_address" in script_text
    assert "ed2k_harness.resolve_ed2k_server_exe(" not in script_text
    assert "ed2k_harness.build_ed2k_server_binary(" not in script_text
    assert "ed2k_harness.start_ed2k_server(" not in script_text
    assert "ed2k_harness.build_server_config(" not in script_text
