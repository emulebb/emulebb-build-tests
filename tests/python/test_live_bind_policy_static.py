from __future__ import annotations

import re
from pathlib import Path

from emule_test_harness import live_e2e_suite


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_ROOT = REPO_ROOT / "scripts"
HARNESS_ROOT = REPO_ROOT / "emule_test_harness"

STANDALONE_LIVE_SCRIPT_NETWORK_SCOPES = {
    "amutorrent-clean-startup.py": "vpn",
    "amutorrent-emulebb-ui-live.py": "vpn",
    "amutorrent-interactive-session.py": "vpn",
    "amutorrent-resilience-live.py": "vpn",
    "deterministic-amule-transfer.py": "lan",
    "fake-kad-trust-soak.py": "vpn",
    "radarr-sonarr-emulebb-live.py": "vpn",
    "three-client-swarm-transfer.py": "lan",
}


def python_sources(*roots: Path) -> list[Path]:
    return sorted(path for root in roots for path in root.rglob("*.py"))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_live_harness_rejects_retired_bind_flag_names() -> None:
    retired_patterns = (
        re.compile(r"(?<![\w-])--bind-addr(?![\w-])"),
        re.compile(r"(?<![\w-])--rest-bind-addr(?![\w-])"),
        re.compile(r"(?<![\w-])--web-bind-addr(?![\w-])"),
        re.compile(r"\brest_bind_addr\b"),
        re.compile(r"\bweb_bind_addr\b"),
    )
    offenders: list[str] = []

    for path in python_sources(SCRIPT_ROOT, HARNESS_ROOT):
        text = read_text(path)
        for pattern in retired_patterns:
            if pattern.search(text):
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {pattern.pattern}")

    assert offenders == []


def test_public_vpn_profiles_do_not_write_interface_name_to_bindaddr() -> None:
    offenders: list[str] = []

    for path in python_sources(SCRIPT_ROOT, HARNESS_ROOT):
        text = read_text(path)
        if "BindAddr=hide.me" in text:
            offenders.append(str(path.relative_to(REPO_ROOT)))

    assert offenders == []


def test_suite_scripts_requiring_lan_bind_are_registered_for_lan_forwarding() -> None:
    by_script_name = {spec.script_name: spec for spec in live_e2e_suite.SUITE_SPECS}
    offenders: list[str] = []

    for script_path in sorted(SCRIPT_ROOT.glob("*.py")):
        text = read_text(script_path)
        if '--lan-bind-addr"' not in text and "'--lan-bind-addr'" not in text:
            continue
        spec = by_script_name.get(script_path.name)
        if spec is None:
            continue
        if spec.name not in live_e2e_suite.LAN_BIND_ADDR_SUITE_NAMES:
            offenders.append(f"{spec.name} ({script_path.name})")

    assert offenders == []


def test_lan_bind_argument_is_required_for_live_scripts() -> None:
    offenders: list[str] = []
    pattern = re.compile(
        r"add_argument\(\s*[\"']--lan-bind-addr[\"'](?P<body>.*?)\)",
        re.DOTALL,
    )

    for script_path in sorted(SCRIPT_ROOT.glob("*.py")):
        for match in pattern.finditer(read_text(script_path)):
            body = match.group("body")
            if "required=True" not in body:
                offenders.append(str(script_path.relative_to(REPO_ROOT)))

    assert offenders == []


def test_standalone_p2p_live_scripts_have_network_scope_classification() -> None:
    registered_scripts = {spec.script_name for spec in live_e2e_suite.SUITE_SPECS}
    offenders: list[str] = []

    for script_path in sorted(SCRIPT_ROOT.glob("*.py")):
        text = read_text(script_path)
        if "--p2p-bind-interface-name" not in text or script_path.name in registered_scripts:
            continue
        if STANDALONE_LIVE_SCRIPT_NETWORK_SCOPES.get(script_path.name) not in {"vpn", "lan"}:
            offenders.append(script_path.name)

    assert offenders == []


def test_public_vpn_standalone_scripts_enable_vpn_guard_surface() -> None:
    offenders: list[str] = []

    for script_name, network_scope in sorted(STANDALONE_LIVE_SCRIPT_NETWORK_SCOPES.items()):
        if network_scope != "vpn":
            continue
        text = read_text(SCRIPT_ROOT / script_name)
        if "--vpn-guard-enabled" not in text:
            offenders.append(f"{script_name}: missing --vpn-guard-enabled")
        if "--vpn-guard-allowed-public-ip-cidrs" not in text:
            offenders.append(f"{script_name}: missing --vpn-guard-allowed-public-ip-cidrs")
        if 'default="hide.me"' not in text and "DEFAULT_P2P_BIND_INTERFACE_NAME" not in text:
            offenders.append(f"{script_name}: public VPN default is not hide.me")

    assert offenders == []
