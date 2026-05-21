from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


def load_suite_module():
    """Loads the hyphenated aMuTorrent local ED2K UI script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "amutorrent-local-ed2k-ui-live.py"
    spec = importlib.util.spec_from_file_location("amutorrent_local_ed2k_ui_live_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parser_defaults_use_local_ed2k_and_132_mib_fixture() -> None:
    module = load_suite_module()

    args = module.parse_args([])

    assert args.p2p_bind_interface_name == ""
    assert args.fixture_size_bytes == 132 * 1024 * 1024
    assert args.configuration == "Release"


def test_amutorrent_environment_enables_both_ed2k_clients(tmp_path: Path, monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module, "reject_windows_temp_path", lambda _path, _description: None)
    node_path = Path(r"C:\tools\node\node.exe") if os.name == "nt" else Path("/opt/node/bin/node")

    env = module.build_local_amutorrent_environment(
        base_env={"PATH": "base-path", "UNRELATED": "kept"},
        amutorrent_port=19001,
        node_path=node_path,
        data_dir=tmp_path / "amutorrent-data",
        emulebb_rest_port=19002,
        emulebb_api_key="api-key",
        amule_ec_port=19003,
        amule_password="amule-password",
    )

    assert env["PORT"] == "19001"
    assert env["BIND_ADDRESS"] == "127.0.0.1"
    assert env["AMUTORRENT_DATA_DIR"].endswith("amutorrent-data")
    assert env["WEB_AUTH_ENABLED"] == "false"
    assert env["SKIP_SETUP_WIZARD"] == "true"
    assert env["EMULEBB_ENABLED"] == "true"
    assert env["EMULEBB_HOST"] == "127.0.0.1"
    assert env["EMULEBB_PORT"] == "19002"
    assert env["EMULEBB_API_KEY"] == "api-key"
    assert env["EMULEBB_ID"] == module.CLIENT01.profile_id
    assert env["EMULEBB_NAME"] == module.CLIENT01.profile_id
    assert env["AMULE_ENABLED"] == "true"
    assert env["AMULE_HOST"] == "127.0.0.1"
    assert env["AMULE_PORT"] == "19003"
    assert env["AMULE_PASSWORD"] == "amule-password"
    assert env["AMULE_ID"] == module.CLIENT04.profile_id
    assert env["AMULE_NAME"] == module.CLIENT04.profile_id
    assert env["UNRELATED"] == "kept"


def test_snapshot_wait_is_instance_scoped(monkeypatch) -> None:
    module = load_suite_module()
    calls = []

    def fake_fetch(_page, _path, _method="GET", _body=None):
        calls.append(_path)
        return {
            "status": 200,
            "payload": {
                "data": {
                    "items": [
                        {"hash": "abc123", "instanceId": module.CLIENT01.profile_id, "status": "downloading"},
                        {"hash": "abc123", "instanceId": module.CLIENT04.profile_id, "status": "complete"},
                    ]
                }
            },
        }

    monkeypatch.setattr(module, "fetch_page_json", fake_fetch)

    item = module.wait_for_snapshot_item(
        object(),
        transfer_hash="abc123",
        instance_id=module.CLIENT04.profile_id,
        timeout_seconds=1.0,
    )

    assert item["instanceId"] == module.CLIENT04.profile_id
    assert item["status"] == "complete"
    assert calls == ["/api/v1/data/snapshot"]


def test_ed2k_instance_button_click_uses_stable_instance_hook() -> None:
    module = load_suite_module()

    class FakeButton:
        def __init__(self, page) -> None:
            self.page = page

        @property
        def first(self):
            return self

        def wait_for(self, timeout):
            self.page.timeout = timeout

        def click(self):
            self.page.clicked = True

    class FakePage:
        def __init__(self) -> None:
            self.selectors = []
            self.timeout = None
            self.clicked = False

        def locator(self, selector):
            self.selectors.append(selector)
            return FakeButton(self)

    page = FakePage()

    module.click_ed2k_instance_button(page, module.CLIENT04.profile_id)

    assert page.selectors == [
        (
            '[data-testid="emulebb-add-download-modal"] '
            f'[data-testid="ed2k-instance-{module.CLIENT04.profile_id}"]'
        ),
        (
            '[data-testid="emulebb-add-download-modal"] '
            f'[data-testid="ed2k-instance-{module.CLIENT04.profile_id}"][data-selected="true"]:visible'
        ),
        (
            '[data-testid="emulebb-add-download-modal"]'
            f'[data-selected-ed2k-instance="{module.CLIENT04.profile_id}"]'
        ),
    ]
    assert page.timeout == 15000
    assert page.clicked is True


def test_windows_npm_command_uses_cmd_fallback(monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module.amutorrent_ui.os, "name", "nt")

    command = module.amutorrent_ui.npm_command_for_node(Path("node"))

    assert command == "npm.cmd"
