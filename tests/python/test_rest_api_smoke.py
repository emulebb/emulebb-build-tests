from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import ssl
import subprocess
import time
from types import SimpleNamespace
import urllib.error

import pytest

PRIVATE_NATIVE_ONLY_ROUTES: set[tuple[str, str]] = set()


def load_rest_api_smoke_module():
    """Loads the hyphenated REST smoke script for focused unit tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "rest-api-smoke.py"
    spec = importlib.util.spec_from_file_location("rest_api_smoke_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def section_text(text: str, section: str) -> str:
    start = text.index(f"[{section}]")
    next_section = text.find("\n[", start + 1)
    return text[start:] if next_section == -1 else text[start:next_section]


def test_nat_backend_order_accepts_upnp_first() -> None:
    module = load_rest_api_smoke_module()

    summary = module.assert_upnp_backend_order(
        [
            {"message": "NAT mapping backend mode: Automatic"},
            {"message": "Attempting NAT mapping backend 'UPnP IGD (MiniUPnP)'"},
            {"message": "Trying fallback NAT mapping backend 'PCP/NAT-PMP'"},
            {"message": "Attempting NAT mapping backend 'PCP/NAT-PMP'"},
        ]
    )

    assert summary["backend_names"] == ["UPnP IGD (MiniUPnP)", "PCP/NAT-PMP"]
    assert summary["upnp_first"] is True
    assert summary["pcp_before_upnp"] is False


def test_nat_backend_order_rejects_pcp_first() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(AssertionError, match="Expected first NAT backend"):
        module.assert_upnp_backend_order(
            [
                {"message": "Attempting NAT mapping backend 'PCP/NAT-PMP'"},
                {"message": "Attempting NAT mapping backend 'UPnP IGD (MiniUPnP)'"},
            ]
        )


def test_nat_backend_order_requires_attempts() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(AssertionError, match="No NAT mapping backend attempts"):
        module.assert_upnp_backend_order([{"message": "eMuleBB 0.7.3 x64 ready"}])


def test_nat_backend_order_reports_missing_bind_interface_as_live_network_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 200,
            "json": [
                {
                    "message": (
                        "Networking disabled for this session because the selected "
                        "bind interface is no longer available: hide.me"
                    )
                }
            ],
            "raw_json": {
                "data": [
                    {
                        "message": (
                            "Networking disabled for this session because the selected "
                            "bind interface is no longer available: hide.me"
                        )
                    }
                ],
                "meta": {"apiVersion": "v1"},
            },
        },
    )

    with pytest.raises(module.LiveNetworkUnavailableError, match="hide\\.me"):
        module.wait_for_upnp_backend_order("https://127.0.0.1:1", "api-key", 0.1)


def test_p2p_bind_override_writes_interface_name(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    preferences_path.write_text(
        "[eMule]\nBindAddr=127.0.0.1\nBindInterface=\n",
        encoding="utf-16",
    )

    module.apply_p2p_bind_interface_override(config_dir, "hide.me")

    text = module.live_common.read_ini_text(preferences_path)
    assert "BindInterface=hide.me" in text
    assert "BindAddr=hide.me" not in text
    assert "BindAddr=" in text
    assert "BlockNetworkWhenBindUnavailableAtStartup" not in text
    assert "VpnGuardMode=Off" in text
    assert "127.0.0.1" not in text


def test_p2p_bind_override_can_enable_vpn_guard(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    preferences_path.write_text(
        "[eMule]\nBindAddr=127.0.0.1\nBindInterface=\nBlockNetworkWhenBindUnavailableAtStartup=1\n",
        encoding="utf-16",
    )

    module.apply_p2p_bind_interface_override(config_dir, "hide.me", "8.8.8.8/32")

    text = module.live_common.read_ini_text(preferences_path)
    assert "BindInterface=hide.me" in text
    assert "BlockNetworkWhenBindUnavailableAtStartup" not in text
    assert "VpnGuardMode=Block" in text
    assert "VpnGuardAllowedPublicIpCidrs=8.8.8.8/32" in text


def test_p2p_bind_override_can_enable_vpn_guard_without_cidrs(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    preferences_path.write_text(
        "[eMule]\nBindAddr=127.0.0.1\nBindInterface=\n",
        encoding="utf-16",
    )

    module.apply_p2p_bind_interface_override(config_dir, "hide.me", vpn_guard_enabled=True)

    text = module.live_common.read_ini_text(preferences_path)
    assert "BindInterface=hide.me" in text
    assert "VpnGuardMode=Block" in text
    assert "VpnGuardAllowedPublicIpCidrs=" in text


def test_vpn_guard_scenarios_run_expected_hook_sequences(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    observed: list[str] = []

    def fake_run_hook(_config, name, _context):
        observed.append(name)
        return {"configured": True, "name": name, "returncode": 0}

    monkeypatch.setattr(module.vpn_guard_live, "run_hook", fake_run_hook)

    config = {"commands": {}}
    context = {"app_exe": r"C:\app\emulebb.exe", "p2p_bind_interface_name": "hide.me"}

    module.setup_vpn_guard_scenario(config, "success", context)
    assert observed == ["connect", "checkConnected", "allowlistEmulebb", "checkAllowlisted"]

    observed.clear()
    module.setup_vpn_guard_scenario(config, "not-allowlisted", context)
    assert observed == ["connect", "checkConnected", "removeAllowlistEmulebb", "checkNotAllowlisted"]

    observed.clear()
    module.setup_vpn_guard_scenario(config, "vpn-off", context)
    assert observed == ["removeAllowlistEmulebb", "disconnect", "checkDisconnected"]


def test_vpn_guard_restore_reconnects_and_allowlists(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    observed: list[str] = []

    def fake_run_hook(_config, name, _context):
        observed.append(name)
        return {"configured": True, "name": name, "returncode": 0}

    monkeypatch.setattr(module.vpn_guard_live, "run_hook", fake_run_hook)

    result = module.restore_vpn_guard_scenario({"commands": {}}, "vpn-off", {"p2p_bind_interface_name": "hide.me"})

    assert result["enabled"] is True
    assert observed == ["connect", "checkConnected", "allowlistEmulebb", "checkAllowlisted"]


def test_vpn_guard_startup_block_assertion_accepts_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 200,
            "json": {
                "network": {
                    "vpnGuard": {
                        "enabled": True,
                        "startupBlocked": True,
                        "startupBlockReason": "VPN Guard public IP mismatch",
                    }
                }
            },
            "raw_json": {
                "data": {
                    "network": {
                        "vpnGuard": {
                            "enabled": True,
                            "startupBlocked": True,
                            "startupBlockReason": "VPN Guard public IP mismatch",
                        }
                    }
                },
                "meta": {"apiVersion": "v1"},
            },
        },
    )

    result = module.assert_vpn_guard_startup_blocked("http://192.0.2.10:4711", "api-key")

    assert result["vpnGuard"]["startupBlocked"] is True


def test_vpn_guard_startup_block_assertion_accepts_log_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 200,
            "json": {
                "logs": [
                    {
                        "level": "error",
                        "message": (
                            "VPN Guard blocked P2P startup for this session because "
                            "detected public IPv4 149.88.27.82 is outside allowed CIDRs 8.8.8.8/32."
                        ),
                    }
                ]
            },
            "raw_json": {
                "data": {
                    "logs": [
                        {
                            "level": "error",
                            "message": (
                                "VPN Guard blocked P2P startup for this session because "
                                "detected public IPv4 149.88.27.82 is outside allowed CIDRs 8.8.8.8/32."
                            ),
                        }
                    ]
                },
                "meta": {"apiVersion": "v1"},
            },
        },
    )

    result = module.assert_vpn_guard_startup_blocked("http://192.0.2.10:4711", "api-key")

    assert result["startupBlockMessages"]


def test_network_diagnostics_contract_asserts_status_and_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()

    network = {
        "ports": {"tcp": 4662, "udp": 4672, "serverUdp": 4665},
        "binding": {
            "configuredAddress": "",
            "configuredInterfaceId": "hide.me",
            "configuredInterfaceName": "hide.me",
            "activeConfiguredAddress": "10.8.0.4",
            "activeInterfaceId": "hide.me",
            "activeInterfaceName": "hide.me",
            "activeInterfaceIndex": 11,
            "resolveResult": "resolved",
        },
        "vpnGuard": {
            "enabled": True,
            "mode": "block",
            "allowedPublicIpCidrs": "8.8.8.8/32",
            "startupBlocked": False,
            "startupBlockReason": "",
        },
    }

    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 200,
            "content_type": "application/json",
            "json": {"network": network},
            "raw_json": {"data": {"network": network}, "meta": {"apiVersion": "v1"}},
        },
    )

    result = module.assert_network_diagnostics_contract(
        "http://192.0.2.10:4711",
        "api-key",
        status_payload={"network": network},
    )

    assert result["statusNetwork"]["vpnGuard"]["enabled"] is True
    assert result["snapshotNetwork"]["binding"]["activeInterfaceName"] == "hide.me"


def test_configure_webserver_profile_keeps_crash_endpoint_disabled_by_default(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    preferences_path.write_text("[eMule]\nConfirmExit=1\n[WebServer]\nEnabled=0\n", encoding="utf-16")
    app_exe = tmp_path / "app" / "emulebb-main" / "srchybrid" / "x64" / "Release" / "emulebb.exe"

    module.configure_webserver_profile(config_dir, app_exe, "api-key", 4711, "192.0.2.10")

    text = module.live_common.read_ini_text(preferences_path)
    assert "Enabled=1" in text
    assert "EnableDiagnosticRestEndpoints=0" in text


def test_configure_webserver_profile_can_enable_crash_endpoint(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    preferences_path.write_text("[eMule]\nConfirmExit=1\n[WebServer]\nEnabled=0\n", encoding="utf-16")
    app_exe = tmp_path / "app" / "emulebb-main" / "srchybrid" / "x64" / "Release" / "emulebb.exe"

    module.configure_webserver_profile(
        config_dir,
        app_exe,
        "api-key",
        4711,
        "192.0.2.10",
        enable_crash_test_endpoint=True,
    )

    text = module.live_common.read_ini_text(preferences_path)
    assert "EnableDiagnosticRestEndpoints=1" in text


def test_configure_webserver_profile_can_use_local_rest_only_network(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    preferences_path = config_dir / "preferences.ini"
    preferences_path.write_text(
        "[eMule]\n"
        "Autoconnect=1\n"
        "Reconnect=1\n"
        "NetworkED2K=1\n"
        "NetworkKademlia=1\n"
        "BindAddr=\n"
        "BindInterface=hide.me\n"
        "VpnGuardMode=Block\n"
        "[WebServer]\n"
        "Enabled=0\n"
        "BindAddr=127.0.0.1\n"
        "[UPnP]\n"
        "EnableUPnP=1\n",
        encoding="utf-16",
    )
    (config_dir / "server.met").write_bytes(b"public server seed")
    (config_dir / "nodes.dat").write_bytes(b"public kad seed")
    (config_dir / "addresses.dat").write_text("https://upd.emule-security.org/server.met\n", encoding="utf-16")
    app_exe = tmp_path / "app" / "emulebb-main" / "srchybrid" / "x64" / "Release" / "emulebb.exe"

    module.configure_webserver_profile(
        config_dir,
        app_exe,
        "api-key",
        4711,
        "192.0.2.10",
        live_network=False,
    )

    text = module.live_common.read_ini_text(preferences_path)
    emule_section = section_text(text, "eMule")
    webserver_section = section_text(text, "WebServer")
    upnp_section = section_text(text, "UPnP")
    assert "BindInterface=hide.me" not in emule_section
    assert "BindInterface=" in emule_section
    assert "BindAddr=192.0.2.10" in emule_section
    assert "NetworkED2K=0" in emule_section
    assert "NetworkKademlia=0" in emule_section
    assert "Autoconnect=0" in emule_section
    assert "Reconnect=0" in emule_section
    assert "VpnGuardMode=Off" in emule_section
    assert "EnableUPnP=0" in upnp_section
    assert "BindAddr=192.0.2.10" in webserver_section
    assert not (config_dir / "server.met").exists()
    assert not (config_dir / "nodes.dat").exists()
    addresses_text = module.live_common.read_ini_text(config_dir / "addresses.dat")
    assert "emule-security" not in addresses_text
    assert addresses_text.strip() == "http://192.0.2.254/server.met"


def test_live_server_unavailable_is_inconclusive_exit_code() -> None:
    module = load_rest_api_smoke_module()

    assert module.LIVE_NETWORK_UNAVAILABLE_EXIT_CODE == 2
    with pytest.raises(module.LiveNetworkUnavailableError, match="No server candidates"):
        module.connect_to_live_server("http://127.0.0.1:1", "api-key", [], 1.0)


def test_rest_socket_adversity_base_url_parsing() -> None:
    module = load_rest_api_smoke_module()

    assert module.parse_base_url_endpoint("http://127.0.0.1:4711") == {
        "scheme": "http",
        "host": "127.0.0.1",
        "port": 4711,
    }
    assert module.parse_base_url_endpoint("https://127.0.0.1") == {
        "scheme": "https",
        "host": "127.0.0.1",
        "port": 443,
    }


def test_rest_base_host_uses_explicit_lan_bind_address_for_vpn() -> None:
    module = load_rest_api_smoke_module()

    assert module.rest_base_host_for_lan_bind_addr("10.54.221.82") == "10.54.221.82"
    for candidate in ("", "127.0.0.1", "0.0.0.0", "::"):
        with pytest.raises(ValueError):
            module.rest_base_host_for_lan_bind_addr(candidate)


def test_https_urlopen_context_is_only_used_for_https() -> None:
    module = load_rest_api_smoke_module()

    assert module.build_urlopen_context("http://127.0.0.1:4711") is None
    assert module.build_urlopen_context("https://127.0.0.1:4711") is not None


def test_https_urlopen_context_uses_generated_certificate_trust(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    calls: list[str | None] = []

    def fake_create_default_context(*, cafile=None):
        calls.append(cafile)
        return SimpleNamespace(cafile=cafile)

    monkeypatch.setattr(module.ssl, "create_default_context", fake_create_default_context)
    cert_path = tmp_path / "webserver-cert.pem"
    module.configure_https_trust(str(cert_path))

    context = module.build_urlopen_context("https://127.0.0.1:4711")

    assert context.cafile == str(cert_path)
    assert calls == [str(cert_path)]
    module.configure_https_trust(None)


def test_http_request_retries_transient_rest_socket_abort(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    calls: list[object] = []

    class RetryableSocketError(OSError):
        winerror = 10053

    class FakeResponse:
        status = 200
        headers = {"Content-Type": "application/json; charset=utf-8"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self) -> bytes:
            return b'{"data":{"ok":true},"meta":{"apiVersion":"v1"}}'

    def fake_urlopen(request, **_kwargs):
        calls.append(request)
        if len(calls) == 1:
            raise urllib.error.URLError(RetryableSocketError())
        return FakeResponse()

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.http_request("http://192.0.2.10:4711", "/api/v1/app", api_key="key")

    assert len(calls) == 2
    assert result["status"] == 200
    assert result["json"] == {"ok": True}
    assert calls[0].headers["Connection"] == "close"


def test_http_request_retries_direct_transient_rest_socket_abort(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    calls: list[object] = []

    class RetryableSocketError(OSError):
        winerror = 10053

    class FakeResponse:
        status = 200
        headers = {"Content-Type": "application/json; charset=utf-8"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self) -> bytes:
            return b'{"data":{"ok":true},"meta":{"apiVersion":"v1"}}'

    def fake_urlopen(request, **_kwargs):
        calls.append(request)
        if len(calls) == 1:
            raise RetryableSocketError()
        return FakeResponse()

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.http_request("http://192.0.2.10:4711", "/api/v1/app", api_key="key")

    assert len(calls) == 2
    assert result["status"] == 200


def test_rest_stress_treats_listener_busy_close_as_retryable() -> None:
    module = load_rest_api_smoke_module()

    assert module.is_retryable_rest_stress_exception(RuntimeError("Remote end closed connection without response"))


def test_https_certificate_pair_is_generated_by_emule_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    observed_commands: list[list[str]] = []
    observed_pem_checks: list[tuple[Path, Path]] = []

    def fake_run(command, **kwargs):
        observed_commands.append(list(command))
        cert_path = Path(command[command.index("--cert") + 1])
        key_path = Path(command[command.index("--key") + 1])
        cert_path.write_text("certificate", encoding="utf-8")
        key_path.write_text("key", encoding="utf-8")
        assert kwargs["check"] is False
        assert kwargs["timeout"] == 30.0
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(
        module,
        "require_usable_https_pem_pair",
        lambda cert, key: observed_pem_checks.append((cert, key)),
    )

    material = module.create_https_certificate_pair(Path("emulebb.exe"), tmp_path, hosts=("192.0.2.10",))

    assert material["generator"] == "emule-cli"
    assert Path(material["certificate"]).read_text(encoding="utf-8") == "certificate"
    assert Path(material["key"]).read_text(encoding="utf-8") == "key"
    assert observed_commands == [
        [
            "emulebb.exe",
            "--generate-webserver-cert",
            "--cert",
            str(tmp_path / "https-cert" / "webserver-cert.pem"),
            "--key",
                str(tmp_path / "https-cert" / "webserver-key.pem"),
                "--host",
                "192.0.2.10",
            ]
        ]
    assert observed_pem_checks == [
        (tmp_path / "https-cert" / "webserver-cert.pem", tmp_path / "https-cert" / "webserver-key.pem")
    ]


def write_https_preferences(
    module,
    config_dir: Path,
    *,
    certificate: Path,
    key: Path,
    use_https: str = "1",
    port: int = 4711,
    lan_bind_addr: str = "127.0.0.1",
) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    module.live_common.write_utf16_ini_text(
        config_dir / "preferences.ini",
        "\n".join(
            [
                "[WebServer]",
                f"UseHTTPS={use_https}",
                f"HTTPSCertificate={certificate}",
                f"HTTPSKey={key}",
                f"Port={port}",
                f"BindAddr={lan_bind_addr}",
            ]
        ),
    )


def test_https_pem_readiness_accepts_generated_pair_and_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    cert_path = tmp_path / "webserver-cert.pem"
    key_path = tmp_path / "webserver-key.pem"
    config_dir = tmp_path / "config"
    cert_path.write_text("certificate", encoding="ascii")
    key_path.write_text("key", encoding="ascii")
    write_https_preferences(module, config_dir, certificate=cert_path, key=key_path)
    monkeypatch.setattr(module, "decode_certificate_metadata", lambda _path: {"sha256": "abc123"})
    monkeypatch.setattr(module, "require_usable_https_pem_pair", lambda _cert, _key: None)

    summary = module.verify_https_pem_readiness(
        config_dir=config_dir,
        base_url="https://127.0.0.1:4711",
        certificate_path=str(cert_path),
        key_path=str(key_path),
        lan_bind_addr="127.0.0.1",
    )

    assert summary["ok"] is True
    assert summary["tls_pair_loadable"] is True
    assert summary["trust_anchor_loadable"] is True
    assert summary["certificate"]["size_bytes"] == len("certificate")
    assert summary["certificate_metadata"]["sha256"] == "abc123"
    assert summary["profile"]["observed"]["UseHTTPS"] == "1"


def test_https_pem_readiness_rejects_missing_certificate(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    cert_path = tmp_path / "missing-cert.pem"
    key_path = tmp_path / "webserver-key.pem"
    config_dir = tmp_path / "config"
    key_path.write_text("key", encoding="ascii")
    write_https_preferences(module, config_dir, certificate=cert_path, key=key_path)

    with pytest.raises(RuntimeError, match="certificate PEM is missing"):
        module.verify_https_pem_readiness(
            config_dir=config_dir,
            base_url="https://127.0.0.1:4711",
            certificate_path=str(cert_path),
            key_path=str(key_path),
            lan_bind_addr="127.0.0.1",
        )


def test_https_pem_readiness_rejects_empty_key(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    cert_path = tmp_path / "webserver-cert.pem"
    key_path = tmp_path / "webserver-key.pem"
    config_dir = tmp_path / "config"
    cert_path.write_text("certificate", encoding="ascii")
    key_path.write_text("", encoding="ascii")
    write_https_preferences(module, config_dir, certificate=cert_path, key=key_path)

    with pytest.raises(RuntimeError, match="key PEM is empty"):
        module.verify_https_pem_readiness(
            config_dir=config_dir,
            base_url="https://127.0.0.1:4711",
            certificate_path=str(cert_path),
            key_path=str(key_path),
            lan_bind_addr="127.0.0.1",
        )


def test_https_pem_readiness_rejects_unloadable_pair(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    cert_path = tmp_path / "webserver-cert.pem"
    key_path = tmp_path / "webserver-key.pem"
    config_dir = tmp_path / "config"
    cert_path.write_text("certificate", encoding="ascii")
    key_path.write_text("key", encoding="ascii")
    write_https_preferences(module, config_dir, certificate=cert_path, key=key_path)
    monkeypatch.setattr(module, "decode_certificate_metadata", lambda _path: {"sha256": "abc123"})

    def fail_load(_cert: Path, _key: Path) -> None:
        raise ssl.SSLError("[X509] PEM lib")

    monkeypatch.setattr(module, "require_usable_https_pem_pair", fail_load)

    with pytest.raises(RuntimeError, match="HTTPS PEM pair is not TLS-loadable"):
        module.verify_https_pem_readiness(
            config_dir=config_dir,
            base_url="https://127.0.0.1:4711",
            certificate_path=str(cert_path),
            key_path=str(key_path),
            lan_bind_addr="127.0.0.1",
        )


def test_https_pem_readiness_rejects_profile_config_mismatch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    cert_path = tmp_path / "webserver-cert.pem"
    key_path = tmp_path / "webserver-key.pem"
    config_dir = tmp_path / "config"
    cert_path.write_text("certificate", encoding="ascii")
    key_path.write_text("key", encoding="ascii")
    write_https_preferences(module, config_dir, use_https="0", certificate=cert_path, key=key_path)
    monkeypatch.setattr(module, "decode_certificate_metadata", lambda _path: {"sha256": "abc123"})
    monkeypatch.setattr(module, "require_usable_https_pem_pair", lambda _cert, _key: None)

    with pytest.raises(RuntimeError, match="UseHTTPS"):
        module.verify_https_pem_readiness(
            config_dir=config_dir,
            base_url="https://127.0.0.1:4711",
            certificate_path=str(cert_path),
            key_path=str(key_path),
            lan_bind_addr="127.0.0.1",
        )


def test_rest_ready_timeout_reports_https_pem_context(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()

    def fake_http_request(_base_url, _path, **_kwargs):
        raise module.urllib.error.URLError(ssl.SSLError("[X509] PEM lib"))

    def fake_wait_for(resolve, **_kwargs):
        assert resolve() is None
        raise RuntimeError("Timed out waiting for REST API readiness")

    monkeypatch.setattr(module, "http_request", fake_http_request)
    monkeypatch.setattr(module, "wait_for", fake_wait_for)

    with pytest.raises(RuntimeError, match="HTTPSCertificate"):
        module.wait_for_rest_ready(
            "https://127.0.0.1:4711",
            "api-key",
            1.0,
            readiness_context={
                "profile": {
                    "observed": {
                        "HTTPSCertificate": "webserver-cert.pem",
                        "HTTPSKey": "webserver-key.pem",
                    }
                }
            },
        )


def test_https_certificate_validation_requires_trust_anchor_and_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    request_ca_files: list[object] = []
    ready_calls: list[float] = []

    def fake_http_request(_base_url, _path, **kwargs):
        request_ca_files.append(kwargs.get("tls_ca_file"))
        if kwargs.get("tls_ca_file") is None:
            raise module.urllib.error.URLError(ssl.SSLError("self-signed certificate"))
        return {"status": 200, "content_type": "application/json", "body_text": "{}", "json": {}, "raw_json": {}}

    def fake_wait_for_rest_ready(_base_url, _api_key, timeout_seconds, **_kwargs):
        ready_calls.append(timeout_seconds)
        return {"status": 200, "content_type": "application/json", "body_text": "{}", "json": {}, "raw_json": {}}

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class FakeContext:
        def wrap_socket(self, _sock, *, server_hostname):
            assert server_hostname == "wrong-host.emulebb.invalid"
            raise ssl.SSLError("hostname mismatch")

    monkeypatch.setattr(module, "http_request", fake_http_request)
    monkeypatch.setattr(module, "wait_for_rest_ready", fake_wait_for_rest_ready)
    monkeypatch.setattr(module.socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())
    monkeypatch.setattr(module.ssl, "create_default_context", lambda *, cafile=None: FakeContext())

    summary = module.exercise_https_certificate_validation(
        "https://127.0.0.1:4711",
        "api-key",
        "webserver-cert.pem",
        request_timeout_seconds=1.0,
        post_validation_ready_timeout_seconds=3.0,
    )

    assert summary["ok"] is True
    assert summary["untrusted_rejected"] is True
    assert summary["wrong_host_rejected"] is True
    assert summary["post_validation_ready"]["status"] == 200
    assert request_ca_files == ["webserver-cert.pem", None]
    assert ready_calls == [3.0]


def test_rest_socket_probe_outcome_rejects_timeouts() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(AssertionError, match="timeout_probe"):
        module.require_socket_probe_outcome(
            "timeout_probe",
            {"outcome": "timeout", "status": None},
            allowed_statuses={400},
        )


def test_rest_socket_probe_outcome_accepts_declared_status_or_close() -> None:
    module = load_rest_api_smoke_module()

    module.require_socket_probe_outcome(
        "bad_request_probe",
        {"outcome": "response", "status": 400},
        allowed_statuses={400},
    )
    module.require_socket_probe_outcome(
        "closed_probe",
        {"outcome": "closed", "status": None},
        allowed_statuses={400},
    )


def test_rest_socket_adversity_includes_response_send_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    raw_payloads: list[bytes] = []

    def fake_raw_socket_probe(_host: str, _port: int, payload: bytes, **_kwargs: object) -> dict[str, object]:
        raw_payloads.append(payload)
        return {"outcome": "sent_reset", "status": None, "elapsed_ms": 1.0}

    def fake_http_request(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "status": 400,
            "content_type": "application/json",
            "json": {"error": "INVALID_ARGUMENT"},
            "raw_json": {"error": {"code": "INVALID_ARGUMENT", "message": "bad request"}},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "raw_socket_probe", fake_raw_socket_probe)
    monkeypatch.setattr(module, "http_request", fake_http_request)

    summary = module.exercise_rest_socket_adversity(
        "http://127.0.0.1:4711",
        "api-key",
        budget="smoke",
        request_timeout_seconds=1.0,
    )

    assert "reset_during_response_send" in [probe["scenario"] for probe in summary["probes"]]
    assert "reset_during_error_response_send" in [probe["scenario"] for probe in summary["probes"]]
    assert any(b"GET /api/v1/logs?limit=400 HTTP/1.1" in payload for payload in raw_payloads)
    assert any(b"GET /api/v1/r1-missing-error-reset HTTP/1.1" in payload for payload in raw_payloads)


def test_rest_tls_handshake_adversity_requires_https() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(RuntimeError, match="HTTPS base URL"):
        module.exercise_rest_tls_handshake_adversity(
            "http://127.0.0.1:4711",
            budget="smoke",
            request_timeout_seconds=1.0,
        )


def test_rest_adversity_config_rejects_incompatible_transports() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(ValueError, match="socket adversity"):
        module.validate_rest_adversity_config(webserver_scheme="https", socket_budget="smoke", tls_budget="off")
    with pytest.raises(ValueError, match="TLS handshake adversity"):
        module.validate_rest_adversity_config(webserver_scheme="http", socket_budget="off", tls_budget="smoke")

    module.validate_rest_adversity_config(webserver_scheme="http", socket_budget="smoke", tls_budget="off")
    module.validate_rest_adversity_config(webserver_scheme="https", socket_budget="off", tls_budget="smoke")


def test_rest_tls_handshake_adversity_records_smoke_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    observed: list[dict[str, object]] = []

    def fake_chunk_probe(host: str, port: int, chunks: list[bytes], **kwargs: object) -> dict[str, object]:
        observed.append({"host": host, "port": port, "chunks": chunks, **kwargs})
        return {"outcome": "sent_reset", "status": None, "elapsed_ms": 1.0}

    monkeypatch.setattr(module, "raw_socket_chunk_probe", fake_chunk_probe)

    summary = module.exercise_rest_tls_handshake_adversity(
        "https://127.0.0.1:4711",
        budget="smoke",
        request_timeout_seconds=2.0,
    )

    assert summary["scheme"] == "https"
    assert summary["probe_count"] == 3
    assert [probe["scenario"] for probe in summary["probes"]] == [
        "stalled_tls_connect_close",
        "partial_tls_record_reset",
        "partial_tls_clienthello_reset",
    ]
    assert {entry["host"] for entry in observed} == {"127.0.0.1"}
    assert {entry["port"] for entry in observed} == {4711}


def test_rest_error_path_matrix_summarizes_release_statuses() -> None:
    module = load_rest_api_smoke_module()

    matrix = module.build_rest_error_path_matrix(
        {
            "missing_key": {"status": 401, "content_type": "application/json"},
            "rest_surface": {
                "invalid_method": {"status": 405, "content_type": "application/json"},
                "missing_route": {"status": 404, "content_type": "application/json"},
                "bad_payload": {"status": 400, "content_type": "application/json"},
            },
            "conflict": {"response": {"status": 409, "content_type": "application/json"}},
        }
    )

    assert matrix["status_counts"] == {"400": 1, "401": 1, "404": 1, "405": 1, "409": 1}
    assert matrix["ok"] is True
    assert matrix["covered_release_statuses"] == [400, 401, 404, 405, 409, 500, 503]
    assert matrix["missing_release_statuses"] == []
    assert matrix["live_missing_release_statuses"] == [500, 503]
    assert matrix["seam_backed_release_statuses"] == [500, 503]
    assert matrix["release_statuses"][3]["seam"]["expected_error_code"] == "METHOD_NOT_ALLOWED"
    assert matrix["release_statuses"][4]["seam"]["expected_error_code"] == "INVALID_STATE"
    assert matrix["release_statuses"][5]["seam"]["expected_error_code"] == "EMULE_ERROR"
    assert matrix["release_statuses"][6]["seam"]["expected_error_code"] == "EMULE_UNAVAILABLE"
    assert matrix["error_response_count"] == 5


def test_rest_error_path_matrix_hard_gate_rejects_missing_statuses() -> None:
    module = load_rest_api_smoke_module()

    matrix = module.build_rest_error_path_matrix({"missing_key": {"status": 401, "content_type": "application/json"}})

    assert matrix["ok"] is False
    assert matrix["missing_release_statuses"] == [400, 404]
    with pytest.raises(AssertionError, match="release coverage gaps"):
        module.require_rest_error_path_matrix(matrix)


def test_process_resource_snapshot_diff_ignores_missing_values() -> None:
    module = load_rest_api_smoke_module()

    assert module.diff_process_resource_snapshots(
        {
            "process_id": 123,
            "handles": 10,
            "thread_count": 4,
            "gdi_objects": None,
            "private_bytes": 4096,
        },
        {
            "process_id": 123,
            "handles": 14,
            "thread_count": 5,
            "gdi_objects": 2,
            "private_bytes": 6144,
        },
    ) == {
        "handles": 4,
        "thread_count": 1,
        "gdi_objects": None,
        "private_bytes": 2048,
    }


def test_process_exit_state_handles_missing_process_id() -> None:
    module = load_rest_api_smoke_module()

    assert module.get_process_exit_state(None) == {
        "process_id": None,
        "open_process_ok": False,
        "running": None,
        "exit_code": None,
        "last_error": None,
    }


def test_rest_leak_churn_defaults_include_r1_soak_boundary() -> None:
    module = load_rest_api_smoke_module()

    assert module.REST_LEAK_CHURN_DEFAULT_CYCLES["smoke"] > 0
    assert module.REST_LEAK_CHURN_DEFAULT_CYCLES["soak"] >= 1000


def test_rest_leak_churn_supports_https_cycles(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    calls: list[dict[str, object]] = []

    def fake_chunk_probe(host: str, port: int, chunks: list[bytes], **kwargs: object) -> dict[str, object]:
        calls.append({"host": host, "port": port, "chunks": chunks, **kwargs})
        return {"outcome": "sent_reset", "status": None, "elapsed_ms": 1.0}

    monkeypatch.setattr(module, "raw_socket_chunk_probe", fake_chunk_probe)
    monkeypatch.setattr(
        module,
        "get_process_resource_snapshot",
        lambda _pid: {
            "handles": 10,
            "thread_count": 4,
            "gdi_objects": 1,
            "user_objects": 1,
            "private_bytes": 4096,
            "working_set_bytes": 8192,
        },
    )

    summary = module.exercise_rest_leak_churn(
        "https://127.0.0.1:4711",
        "api-key",
        process_id=123,
        budget="smoke",
        cycles=3,
        request_timeout_seconds=1.0,
    )

    assert summary["scheme"] == "https"
    assert summary["cycles_completed"] == 3
    assert [row["scenario"] for row in summary["sampled_cycles"]] == [
        "stalled_tls_connect_close",
        "partial_tls_record_reset",
        "partial_tls_clienthello_reset",
    ]
    assert len(calls) == 3
    assert summary["resource_observability"]["ok"] is True


def test_rest_leak_churn_resource_thresholds_report_pass_and_failures() -> None:
    module = load_rest_api_smoke_module()

    passing = module.evaluate_rest_leak_churn_resources(
        {"handles": 1, "private_bytes": 1024, "working_set_bytes": None},
        {"handles": 2, "private_bytes": 2048, "working_set_bytes": None},
    )
    assert passing["ok"] is True
    assert passing["violations"] == []

    failing = module.evaluate_rest_leak_churn_resources(
        {"handles": 65, "thread_count": 5, "private_bytes": 1024, "working_set_bytes": None},
        {"handles": 2, "private_bytes": 512 * 1024 * 1024, "working_set_bytes": None},
    )
    assert failing["ok"] is False
    assert {
        (violation["metric"], violation["phase"])
        for violation in failing["violations"]
    } == {
        ("handles", "after_drain"),
        ("thread_count", "after_drain"),
        ("private_bytes", "peak"),
    }


def test_rest_leak_churn_resource_observability_requires_tracked_metrics() -> None:
    module = load_rest_api_smoke_module()

    summary = module.evaluate_rest_leak_churn_resource_observability(
        (
            {"handles": 10, "thread_count": None, "private_bytes": 4096},
            {"handles": 12, "thread_count": None, "private_bytes": 8192},
            {"handles": 11, "thread_count": None, "private_bytes": 4096},
        )
    )

    assert summary["ok"] is False
    assert "handles" in summary["available_metrics"]
    assert "private_bytes" in summary["available_metrics"]
    assert "thread_count" in summary["missing_metrics"]
    assert "working_set_bytes" in summary["missing_metrics"]


def test_rest_leak_churn_fails_when_resource_snapshots_are_unobservable(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "raw_socket_probe",
        lambda *_args, **_kwargs: {"outcome": "sent_reset", "status": None, "elapsed_ms": 1.0},
    )
    monkeypatch.setattr(module, "get_process_resource_snapshot", lambda _pid: {"handles": None})

    with pytest.raises(AssertionError, match="resource snapshots incomplete"):
        module.exercise_rest_leak_churn(
            "http://127.0.0.1:4711",
            "api-key",
            process_id=123,
            budget="smoke",
            cycles=1,
            request_timeout_seconds=1.0,
        )


def test_restart_app_after_churn_records_shutdown_relaunch_and_ready_evidence() -> None:
    module = load_rest_api_smoke_module()
    closed_apps: list[object] = []

    def fake_close(app: object) -> None:
        closed_apps.append(app)

    def fake_launch(app_exe: Path, profile_base: Path) -> str:
        assert app_exe == Path("emulebb.exe")
        assert profile_base == Path("profile")
        return "new-app"

    def fake_pid(app: object) -> int:
        return {"old-app": 111, "new-app": 222}[str(app)]

    def fake_snapshot(process_id: int | None) -> dict[str, int | None]:
        return {
            "process_id": process_id,
            "handles": 20,
            "thread_count": 8,
            "gdi_objects": 1,
            "user_objects": 1,
            "private_bytes": 4096,
            "working_set_bytes": 8192,
        }

    relaunched, summary = module.restart_app_after_churn(
        "old-app",
        app_exe=Path("emulebb.exe"),
        profile_base=Path("profile"),
        base_url="https://127.0.0.1:4711",
        api_key="api-key",
        rest_ready_timeout_seconds=5.0,
        close_func=fake_close,
        launch_func=fake_launch,
        wait_main_window_func=lambda _app: SimpleNamespace(window_text=lambda: "eMule"),
        wait_ready_func=lambda _base_url, _api_key, _timeout: {
            "status": 200,
            "content_type": "application/json",
            "json": {"name": "eMuleBB"},
        },
        get_pid_func=fake_pid,
        snapshot_func=fake_snapshot,
    )

    assert relaunched == "new-app"
    assert closed_apps == ["old-app"]
    assert summary["old_process_id"] == 111
    assert summary["new_process_id"] == 222
    assert summary["same_process_id_reused"] is False
    assert summary["main_window_title"] == "eMule"
    assert summary["ready"] == {
        "status": 200,
        "content_type": "application/json",
        "json": {"name": "eMuleBB"},
    }
    assert summary["snapshots"]["before_shutdown"]["process_id"] == 111
    assert summary["snapshots"]["after_relaunch"]["process_id"] == 222
    assert summary["resource_delta_after_relaunch"] == {
        "handles": 0,
        "thread_count": 0,
        "gdi_objects": 0,
        "user_objects": 0,
        "private_bytes": 0,
        "working_set_bytes": 0,
    }


def test_native_rest_app_identity_uses_public_product_name() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    source = (
        workspace_root
        / "workspaces"
        / "workspace"
        / "app"
        / "emulebb-main"
        / "srchybrid"
        / "WebServerJson.cpp"
    ).read_text(encoding="utf-8")

    app_start = source.index("json BuildAppJson")
    app_block = source[app_start : source.index("json BuildSharedFilesListJson", app_start)]
    assert '{"name", "eMuleBB"}' in app_block
    assert '{"name", "eMule"}' not in app_block

    script = (Path(__file__).resolve().parents[2] / "scripts" / "rest-api-smoke.py").read_text(encoding="utf-8")
    assert 'version["json"]["name"] == "eMuleBB"' in script
    assert 'version["json"]["name"] == "eMule"' not in script


def test_restart_app_after_churn_tolerates_tray_relaunch_window_absence() -> None:
    module = load_rest_api_smoke_module()

    def fake_pid(app: object) -> int:
        return {"old-app": 111, "new-app": 222}[str(app)]

    def fake_snapshot(process_id: int | None) -> dict[str, int | None]:
        return {
            "process_id": process_id,
            "handles": 20,
            "thread_count": 8,
            "gdi_objects": 1,
            "user_objects": 1,
            "private_bytes": 4096,
            "working_set_bytes": 8192,
        }

    def fail_wait_main_window(_app: object, *, timeout: float = 90.0):
        raise RuntimeError("Timed out waiting for eMule main window. Last value: None")

    relaunched, summary = module.restart_app_after_churn(
        "old-app",
        app_exe=Path("emulebb.exe"),
        profile_base=Path("profile"),
        base_url="http://127.0.0.1:4711",
        api_key="api-key",
        rest_ready_timeout_seconds=5.0,
        close_func=lambda _app: None,
        launch_func=lambda _app_exe, _profile_base: "new-app",
        wait_main_window_func=fail_wait_main_window,
        wait_ready_func=lambda _base_url, _api_key, _timeout: {"status": 200},
        get_pid_func=fake_pid,
        snapshot_func=fake_snapshot,
    )

    assert relaunched == "new-app"
    assert summary["main_window_title"] == "not observed (minimized to tray)"
    assert summary["ready"] == {"status": 200, "content_type": None}


def test_max_resource_snapshot_keeps_high_water_marks() -> None:
    module = load_rest_api_smoke_module()

    assert module.max_resource_snapshot(
        {"handles": 10, "private_bytes": None, "working_set_bytes": 500},
        {"handles": 8, "private_bytes": 1000, "working_set_bytes": 700},
    ) == {
        "handles": 10,
        "private_bytes": 1000,
        "working_set_bytes": 700,
    }


def test_live_seed_import_evidence_records_sources_and_outcomes(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    calls: list[dict[str, object]] = []

    def fake_http_request(base_url: str, path: str, **kwargs: object) -> dict[str, object]:
        calls.append({"base_url": base_url, "path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json",
            "raw_json": {"data": {"ok": True, "imported": True}, "meta": {"apiVersion": "v1"}},
            "json": {"ok": True, "imported": True},
            "headers": {},
            "body_text": "",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)
    summary = module.exercise_live_seed_imports(
        "http://127.0.0.1:1",
        "api-key",
        {
            "source_home_url": module.EMULE_SECURITY_HOME_URL,
            "files": [
                {
                    "name": "server_met",
                    "file_name": "server.met",
                    "url": module.EMULE_SECURITY_SERVER_MET_URL,
                    "bytes": 80,
                    "sha256": "s" * 64,
                },
                {
                    "name": "nodes_dat",
                    "file_name": "nodes.dat",
                    "url": module.EMULE_SECURITY_NODES_DAT_URL,
                    "bytes": 96,
                    "sha256": "n" * 64,
                },
            ],
        },
    )

    assert [call["path"] for call in calls] == [
        "/api/v1/servers/operations/import-met-url",
        "/api/v1/kad/operations/import-nodes-url",
    ]
    assert [call["json_body"] for call in calls] == [
        {"url": module.EMULE_SECURITY_SERVER_MET_URL},
        {"url": module.EMULE_SECURITY_NODES_DAT_URL},
    ]
    assert {entry["file_name"]: entry["imported"] for entry in summary["imports"]} == {
        "server.met": True,
        "nodes.dat": True,
    }
    assert {entry["file_name"]: entry["source_bytes"] for entry in summary["imports"]} == {
        "server.met": 80,
        "nodes.dat": 96,
    }


def test_live_seed_import_evidence_rejects_failed_import(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()

    def fake_http_request(_base_url: str, _path: str, **_kwargs: object) -> dict[str, object]:
        return {
            "status": 200,
            "content_type": "application/json",
            "raw_json": {"data": {"ok": False, "imported": False}, "meta": {"apiVersion": "v1"}},
            "json": {"ok": False, "imported": False},
            "headers": {},
            "body_text": "",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)
    with pytest.raises(AssertionError, match="imported"):
        module.exercise_live_seed_imports(
            "http://127.0.0.1:1",
            "api-key",
            {
                "source_home_url": module.EMULE_SECURITY_HOME_URL,
                "files": [
                    {
                        "name": "server_met",
                        "file_name": "server.met",
                        "url": module.EMULE_SECURITY_SERVER_MET_URL,
                        "bytes": 80,
                        "sha256": "s" * 64,
                    },
                    {
                        "name": "nodes_dat",
                        "file_name": "nodes.dat",
                        "url": module.EMULE_SECURITY_NODES_DAT_URL,
                        "bytes": 96,
                        "sha256": "n" * 64,
                    },
                ],
            },
        )


def test_missing_transfer_bulk_result_requires_per_item_error() -> None:
    module = load_rest_api_smoke_module()

    result = module.require_missing_transfer_bulk_result(
        {
            "status": 200,
            "raw_json": {
                "data": {
                    "items": [
                        {
                            "hash": module.REST_SURFACE_MISSING_HASH,
                            "ok": False,
                            "error": "transfer not found",
                        },
                    ],
                },
                "meta": {"apiVersion": "v1"},
            },
            "json": {
                "items": [
                    {
                        "hash": module.REST_SURFACE_MISSING_HASH,
                        "ok": False,
                        "error": "transfer not found",
                    },
                ],
            },
        }
    )

    assert result["hash"] == module.REST_SURFACE_MISSING_HASH


def test_transfer_details_payload_compaction_validates_release_shape() -> None:
    module = load_rest_api_smoke_module()

    compact = module.compact_transfer_details_payload(
        {
            "transfer": {"hash": module.REST_SURFACE_VALID_DOWNLOAD_HASH, "name": "rest-api-smoke.bin"},
            "parts": [
                {
                    "index": 0,
                    "start": 0,
                    "end": 1023,
                    "completedBytes": 0,
                    "gapBytes": 1024,
                    "complete": False,
                    "requested": False,
                    "corrupted": False,
                    "availableSources": 0,
                }
            ],
            "sources": [],
        },
        module.REST_SURFACE_VALID_DOWNLOAD_HASH,
    )

    assert compact["hash"] == module.REST_SURFACE_VALID_DOWNLOAD_HASH
    assert compact["part_count"] == 1
    assert compact["source_count"] == 0
    assert compact["first_part"]["gapBytes"] == 1024


def test_rest_payload_unwraps_success_and_error_envelopes() -> None:
    module = load_rest_api_smoke_module()

    assert module.unwrap_rest_payload(
        {
            "data": {"items": [{"name": "file.bin"}]},
            "meta": {"apiVersion": "v1"},
        }
    ) == {"items": [{"name": "file.bin"}]}
    assert module.unwrap_rest_payload(
        {
            "error": {
                "code": "NOT_FOUND",
                "message": "transfer not found",
            }
        }
    ) == {"error": "NOT_FOUND", "message": "transfer not found"}


def test_openapi_error_envelope_documents_stable_error_codes() -> None:
    openapi_path = Path(__file__).resolve().parents[3] / "emulebb-tooling" / "docs" / "rest" / "REST-API-OPENAPI.yaml"
    text = openapi_path.read_text(encoding="utf-8")
    error_schema = text[text.index("    ErrorEnvelope:\n") : text.index("    AppEnvelope:\n")]

    assert "required: [error]" in error_schema
    assert "required: [code, message, details]" in error_schema
    for code in (
        "INVALID_ARGUMENT",
        "UNAUTHORIZED",
        "METHOD_NOT_ALLOWED",
        "NOT_FOUND",
        "INVALID_STATE",
        "SERVICE_BUSY",
        "EMULE_UNAVAILABLE",
        "EMULE_ERROR",
    ):
        assert f"                - {code}" in error_schema
    assert "details:" in error_schema
    assert "additionalProperties: true" in error_schema


def test_openapi_metadata_tracks_beta_release_contract() -> None:
    openapi_path = Path(__file__).resolve().parents[3] / "emulebb-tooling" / "docs" / "rest" / "REST-API-OPENAPI.yaml"
    text = openapi_path.read_text(encoding="utf-8")

    assert "  version: 0.7.3\n" in text
    assert "Frozen 0.7.3 contract" in text
    assert "1.0.0-pre" not in text


def _collect_open_additional_properties(schema: object, path: tuple[str, ...] = ()) -> dict[tuple[str, ...], object]:
    open_nodes: dict[tuple[str, ...], object] = {}
    if isinstance(schema, dict):
        if schema.get("additionalProperties") is not False and "additionalProperties" in schema:
            open_nodes[path] = schema["additionalProperties"]
        for key, value in schema.items():
            if key != "additionalProperties":
                open_nodes.update(_collect_open_additional_properties(value, path + (str(key),)))
    elif isinstance(schema, list):
        for index, value in enumerate(schema):
            open_nodes.update(_collect_open_additional_properties(value, path + (str(index),)))
    return open_nodes


def test_openapi_public_response_dtos_are_closed_except_explicit_extension_maps() -> None:
    module = load_rest_api_smoke_module()
    document = module.load_openapi_document()

    open_nodes = _collect_open_additional_properties(document)

    assert open_nodes == {
        (
            "components",
            "schemas",
            "ErrorEnvelope",
            "properties",
            "error",
            "properties",
            "details",
        ): True,
        (
            "components",
            "schemas",
            "App",
            "properties",
            "capabilities",
        ): {"type": "boolean"},
    }


def test_openapi_inline_response_data_objects_are_closed() -> None:
    module = load_rest_api_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]
    open_data_objects: list[str] = []

    def visit(schema_name: str, node: object, path: tuple[str, ...] = ()) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if (
                    key == "data"
                    and isinstance(value, dict)
                    and value.get("type") == "object"
                    and not any(keyword in value for keyword in ("$ref", "allOf", "anyOf", "oneOf", "unevaluatedProperties"))
                    and value.get("additionalProperties") is not False
                ):
                    open_data_objects.append("/".join((schema_name, *path, key)))
                visit(schema_name, value, path + (str(key),))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                visit(schema_name, value, path + (str(index),))

    for schema_name, schema in schemas.items():
        if schema_name.endswith("Envelope"):
            visit(schema_name, schema)

    assert open_data_objects == []


def test_openapi_core_public_dtos_reject_undocumented_fields() -> None:
    module = load_rest_api_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]

    for schema_name in (
        "EnvelopeMeta",
        "AppLifecycle",
        "Preferences",
        "Stats",
        "Category",
        "Transfer",
        "TransferPart",
        "TransferSource",
        "SharedFile",
        "SharedDirectory",
        "Upload",
        "SearchResult",
    ):
        assert schemas[schema_name]["additionalProperties"] is False

    assert schemas["SnapshotEnvelope"]["allOf"][1]["properties"]["data"]["additionalProperties"] is False


def test_openapi_search_type_enums_match_rest_tokens() -> None:
    module = load_rest_api_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]
    rest_tokens = ["", "arc", "audio", "iso", "image", "pro", "video", "doc", "emulecollection"]

    for schema_name in ("SearchSession", "Search", "SearchCreateRequest", "SearchResult"):
        assert schemas[schema_name]["properties"]["type"]["enum"] == rest_tokens

    assert "enum" not in schemas["SearchResult"]["properties"]["fileType"]
    assert "not remapped" in schemas["SearchResult"]["properties"]["fileType"]["description"]


def test_openapi_rest_consistency_cleanup_contracts() -> None:
    module = load_rest_api_smoke_module()
    document = module.load_openapi_document()
    schemas = document["components"]["schemas"]

    assert schemas["Category"]["properties"]["priority"] == {"type": "integer", "minimum": 0}
    assert schemas["CategoryCreateRequest"]["properties"]["priority"] == {
        "$ref": "#/components/schemas/CategoryPriorityInput"
    }
    assert schemas["CategoryPatch"]["properties"]["priority"] == {
        "$ref": "#/components/schemas/CategoryPriorityInput"
    }
    assert schemas["CategoryCreateRequest"]["properties"]["path"]["minLength"] == 1
    assert schemas["CategoryPatch"]["properties"]["path"]["minLength"] == 1
    assert schemas["CategoryPriorityInput"]["oneOf"] == [
        {"type": "string", "enum": ["verylow", "low", "normal", "high", "veryhigh"]},
        {"type": "integer", "minimum": 0},
    ]

    assert schemas["TransferPriority"]["enum"] == ["auto", "verylow", "low", "normal", "high", "veryhigh"]
    assert schemas["SharedFilePriority"]["enum"] == ["auto", "verylow", "low", "normal", "high", "release"]
    assert "release" not in schemas["TransferPriority"]["enum"]
    assert "veryhigh" not in schemas["SharedFilePriority"]["enum"]
    assert schemas["Transfer"]["properties"]["priority"] == {"$ref": "#/components/schemas/TransferPriority"}
    assert schemas["TransferPatch"]["properties"]["priority"] == {"$ref": "#/components/schemas/TransferPriority"}
    assert schemas["SharedFile"]["properties"]["priority"] == {"$ref": "#/components/schemas/SharedFilePriority"}
    assert schemas["SharedFilePatch"]["properties"]["priority"] == {"$ref": "#/components/schemas/SharedFilePriority"}

    assert len(schemas["TransferCreateRequest"]["oneOf"]) == 2
    assert schemas["TransferCreateRequest"]["not"] == {"required": ["categoryId", "categoryName"]}
    assert schemas["TransferCreateRequest"]["properties"]["categoryId"]["maximum"] == 4294967295
    assert len(schemas["TransferPatch"]["oneOf"]) == 4
    assert schemas["TransferPatch"]["properties"]["categoryId"]["maximum"] == 4294967295
    assert schemas["Transfer"]["properties"]["categoryId"] == {
        "type": "integer",
        "minimum": 0,
        "maximum": 4294967295,
    }
    assert schemas["SharedFilePatch"]["minProperties"] == 1
    assert schemas["SharedFilePatch"]["dependentRequired"] == {
        "comment": ["rating"],
        "rating": ["comment"],
    }
    assert schemas["SharedFileCreateRequest"]["properties"]["path"]["minLength"] == 1
    assert schemas["SharedDirectoryReplaceRequest"]["properties"]["roots"]["items"] == {
        "$ref": "#/components/schemas/SharedDirectoryRootInput"
    }
    assert schemas["SharedDirectoryRootInput"]["oneOf"] == [
        {"type": "string", "minLength": 1},
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "minLength": 1},
                "recursive": {"type": "boolean"},
            },
        },
    ]
    assert schemas["PreferencesPatch"]["minProperties"] == 1
    assert schemas["ServerPatch"]["minProperties"] == 1
    assert schemas["ServerCreateRequest"]["properties"]["address"]["minLength"] == 1
    assert schemas["ServerCreateRequest"]["properties"]["port"]["minimum"] == 1
    assert schemas["ServerCreateRequest"]["properties"]["port"]["maximum"] == 65535
    assert schemas["UrlImportRequest"]["properties"]["url"]["minLength"] == 1
    assert "format" not in schemas["UrlImportRequest"]["properties"]["url"]
    assert schemas["Ed2kLinkEnvelope"]["allOf"][1]["properties"]["data"]["additionalProperties"] is False
    assert schemas["Ed2kLinkEnvelope"]["allOf"][1]["properties"]["data"]["required"] == ["hash", "link"]
    assert schemas["KadBootstrapRequest"]["required"] == ["address", "port"]
    assert schemas["KadBootstrapRequest"]["properties"]["address"]["minLength"] == 1
    assert schemas["KadBootstrapRequest"]["properties"]["port"]["minimum"] == 1
    assert schemas["KadBootstrapRequest"]["properties"]["port"]["maximum"] == 65535
    assert document["paths"]["/kad/operations/bootstrap"]["post"]["requestBody"]["required"] is True
    assert schemas["Kad"]["properties"]["blockedByVpnGuard"] == {"type": "boolean"}
    assert schemas["Kad"]["properties"]["network"] == {"$ref": "#/components/schemas/NetworkStatus"}
    assert schemas["SearchResultDownloadRequest"]["not"] == {"required": ["categoryId", "categoryName"]}
    assert schemas["SearchResultDownloadRequest"]["properties"]["categoryId"]["maximum"] == 4294967295

    assert schemas["Stats"]["properties"]["sharedHashingActive"] == {"type": "boolean"}
    assert schemas["Stats"]["properties"]["sharedHashingCount"] == {"type": "integer", "minimum": 0}
    assert schemas["App"]["properties"]["lifecycle"] == {"$ref": "#/components/schemas/AppLifecycle"}
    assert schemas["Status"]["properties"]["lifecycle"] == {"$ref": "#/components/schemas/AppLifecycle"}
    assert "connected" not in schemas["Status"]["properties"]
    assert "downloadSpeedKiBps" not in schemas["Status"]["properties"]
    assert "uploadSpeedKiBps" not in schemas["Status"]["properties"]
    assert schemas["AppLifecycle"]["properties"]["state"]["enum"] == ["starting", "running", "shuttingdown", "done"]
    assert schemas["EnvelopeMeta"]["required"] == ["apiVersion"]
    assert schemas["NetworkStatus"]["properties"]["binding"]["properties"]["resolveResult"]["enum"] == [
        "default",
        "resolved",
        "interfacenotfound",
        "interfacenameambiguous",
        "interfacehasnoaddress",
        "addressnotfoundoninterface",
        "addressnotfound",
        "unknown",
    ]
    assert schemas["NetworkStatus"]["properties"]["vpnGuard"]["properties"]["mode"]["enum"] == ["off", "block"]

    category_id_schema_paths: list[str] = []

    def visit_category_id_schemas(node: object, path: tuple[str, ...] = ()) -> None:
        if isinstance(node, dict):
            properties = node.get("properties")
            if isinstance(properties, dict) and "categoryId" in properties:
                category_schema = properties["categoryId"]
                assert isinstance(category_schema, dict)
                category_id_schema_paths.append("/".join((*path, "properties", "categoryId")))
                assert category_schema.get("type") == "integer"
                assert category_schema.get("minimum") == 0
                assert category_schema.get("maximum") == 4294967295
            for key, value in node.items():
                visit_category_id_schemas(value, path + (str(key),))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                visit_category_id_schemas(value, path + (str(index),))

    visit_category_id_schemas(document)
    assert category_id_schema_paths == [
        "components/schemas/Transfer/properties/categoryId",
        "components/schemas/TransferCreateRequest/properties/categoryId",
        "components/schemas/TransferPatch/properties/categoryId",
        "components/schemas/SearchResultDownloadRequest/properties/categoryId",
    ]

    parameters = document["components"]["parameters"]
    assert parameters["CategoryId"]["schema"]["maximum"] == 4294967295
    assert parameters["SearchId"]["schema"] == {"type": "integer", "minimum": 0, "maximum": 4294967295}
    assert parameters["Offset"]["schema"]["maximum"] == 2147483647
    assert parameters["Confirm"]["schema"] == {"type": "boolean", "enum": [True]}
    assert parameters["ServerId"]["schema"]["pattern"].startswith("^[^/]+:")
    assert parameters["ClientId"]["schema"]["pattern"].startswith("^([0-9a-f]{32}|[^/]+:")

    responses = document["components"]["responses"]
    assert document["paths"]["/transfers"]["post"]["responses"]["200"]["$ref"].endswith("/BulkOperationResponse")
    assert "requestBody" not in document["paths"]["/transfers/{hash}"]["delete"]
    assert document["paths"]["/transfers/{hash}/files"]["delete"]["parameters"][0]["$ref"].endswith("/Confirm")
    assert document["paths"]["/transfers/{hash}/files"]["delete"]["responses"]["200"]["$ref"].endswith("/BulkOperationResponse")
    assert document["paths"]["/transfers/{hash}/operations/pause"]["post"]["responses"]["200"]["$ref"].endswith("/BulkOperationResponse")
    assert document["paths"]["/transfers/{hash}/operations/resume"]["post"]["responses"]["200"]["$ref"].endswith("/BulkOperationResponse")
    assert document["paths"]["/transfers/{hash}/operations/stop"]["post"]["responses"]["200"]["$ref"].endswith("/BulkOperationResponse")
    assert document["paths"]["/shared-files"]["post"]["responses"]["200"]["$ref"].endswith("/SharedFileCreateResponse")
    assert "requestBody" not in document["paths"]["/shared-files/{hash}"]["delete"]
    assert document["paths"]["/shared-files/{hash}/file"]["delete"]["parameters"][0]["$ref"].endswith("/Confirm")
    assert document["paths"]["/shared-files/{hash}/file"]["delete"]["responses"]["200"]["$ref"].endswith("/SharedFileDeleteResponse")
    assert "requestBody" not in document["paths"]["/searches"]["delete"]
    assert document["paths"]["/searches"]["delete"]["parameters"][0]["$ref"].endswith("/Confirm")
    assert document["paths"]["/searches/{searchId}/results/{hash}/operations/download"]["post"]["responses"]["200"]["$ref"].endswith("/SearchResultDownloadResponse")
    assert document["paths"]["/transfers/{hash}/sources/{clientId}/operations/browse"]["post"]["responses"]["200"]["$ref"].endswith("/TransferSourceBrowseResponse")
    assert document["paths"]["/servers/{serverId}/operations/connect"]["post"]["responses"]["200"]["$ref"].endswith("/ServerStatusResponse")
    assert document["paths"]["/servers/operations/import-met-url"]["post"]["responses"]["200"]["$ref"].endswith("/UrlImportResponse")
    assert document["paths"]["/kad/operations/import-nodes-url"]["post"]["responses"]["200"]["$ref"].endswith("/UrlImportResponse")
    assert document["paths"]["/uploads/{clientId}/operations/remove"]["post"]["responses"]["200"]["$ref"].endswith("/UploadRemoveResponse")
    assert document["paths"]["/upload-queue/{clientId}/operations/remove"]["post"]["responses"]["200"]["$ref"].endswith("/UploadRemoveResponse")
    for response_name in (
        "PeerBanResponse",
        "SearchResultDownloadResponse",
        "SharedFileCreateResponse",
        "TransferSourceBrowseResponse",
        "UploadRemoveResponse",
        "UrlImportResponse",
    ):
        assert response_name in responses

    assert schemas["ErrorEnvelope"]["properties"]["error"]["required"] == ["code", "message", "details"]
    expected_error_statuses = {"400", "401", "404", "405", "409", "500", "503"}
    for path_item in document["paths"].values():
        for method, operation in path_item.items():
            if method == "parameters":
                continue
            if method == "delete":
                assert "requestBody" not in operation
            assert expected_error_statuses <= set(operation["responses"])
            for status in expected_error_statuses:
                # 405 carries the Allow header via a dedicated response component.
                expected_ref = "/MethodNotAllowedResponse" if status == "405" else "/ErrorResponse"
                assert operation["responses"][status]["$ref"].endswith(expected_ref)
            assert operation["responses"]["default"]["$ref"].endswith("/ErrorResponse")

    source_properties = schemas["TransferSource"]["properties"]
    assert "state" not in source_properties
    assert source_properties["downloadState"]["enum"] == [
        "downloading",
        "onqueue",
        "connected",
        "connecting",
        "waitcallback",
        "waitcallbackkad",
        "reqhashset",
        "noneededparts",
        "toomanyconns",
        "toomanyconnskad",
        "lowtolowip",
        "banned",
        "error",
        "none",
        "remotequeuefull",
        "unknown",
    ]


def test_openapi_response_dtos_expose_runtime_required_fields() -> None:
    module = load_rest_api_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]

    expected_required_fields = {
        "App": ["name", "version", "apiVersion", "lifecycle", "capabilities"],
        "AppLifecycle": [
            "state",
            "startupComplete",
            "coreReady",
            "sharedFilesReady",
            "acceptingRest",
            "acceptingMutations",
            "shutdownInProgress",
        ],
        "Status": ["lifecycle", "stats", "servers", "kad", "network", "sharedStartupCache", "runtimeDiagnostics"],
        "Stats": [
            "connected",
            "downloadSpeedKiBps",
            "uploadSpeedKiBps",
            "sessionDownloadedBytes",
            "sessionUploadedBytes",
            "activeUploads",
            "waitingUploads",
            "downloadCount",
            "ed2kConnected",
            "ed2kHighId",
            "kadRunning",
            "kadConnected",
            "kadFirewalled",
        ],
        "TransferSource": [
            "clientId",
            "userName",
            "userHash",
            "address",
            "port",
            "downloadState",
            "clientSoftware",
            "downloadSpeedKiBps",
            "availableParts",
            "partCount",
            "serverIp",
            "serverPort",
            "lowId",
            "queueRank",
            "viewSharedFiles",
            "sharedFilesRequestPending",
        ],
        "SharedFile": [
            "hash",
            "name",
            "path",
            "directory",
            "sizeBytes",
            "priority",
            "autoUploadPriority",
            "requests",
            "acceptedRequests",
            "transferredBytes",
            "allTimeRequests",
            "allTimeAccepts",
            "allTimeTransferred",
            "partCount",
            "partFile",
            "complete",
            "comment",
            "rating",
            "hasComment",
            "userRating",
            "publishedEd2k",
            "sharedByRule",
        ],
        "Upload": [
            "clientId",
            "userName",
            "userHash",
            "clientSoftware",
            "clientMod",
            "uploadState",
            "uploadSpeedKiBps",
            "uploadedBytes",
            "queueSessionUploaded",
            "payloadBuffered",
            "waitTimeMs",
            "waitStartedTick",
            "score",
            "address",
            "port",
            "serverIp",
            "serverPort",
            "lowId",
            "friendSlot",
            "uploading",
            "waitingQueue",
            "requestedFileHash",
            "requestedFileName",
            "requestedFileSizeBytes",
            "requestedPartsObtained",
            "requestedPartsTotal",
            "requestedPartsProgressText",
        ],
        "Server": [
            "address",
            "port",
            "name",
            "priority",
            "static",
            "connected",
            "connecting",
            "current",
            "description",
            "dynIp",
            "failedCount",
            "hardFiles",
            "ip",
            "ping",
            "softFiles",
            "version",
            "users",
            "files",
        ],
        "ServerStatus": ["connected", "connecting", "currentServer", "lowId", "serverCount"],
        "Kad": [
            "running",
            "connected",
            "firewalled",
            "bootstrapping",
            "bootstrapProgress",
            "contactCount",
            "lanMode",
            "users",
            "files",
        ],
        "RuntimeDiagnostics": [
            "processId",
            "knownFileCount",
            "sharedFileCount",
            "sharedHashingCount",
            "downloadFileCount",
            "activeUploads",
            "waitingUploads",
            "geolocation",
        ],
        "GeolocationRuntimeDiagnostics": [
            "enabled",
            "databaseLoaded",
            "databaseBytes",
            "indexBytes",
            "nodeCount",
            "recordSize",
            "lookupCacheCount",
            "decodedNodeCacheCount",
            "refreshQueued",
        ],
    }

    for schema_name, required_fields in expected_required_fields.items():
        assert schemas[schema_name]["required"] == required_fields

    assert "fileHash" not in schemas["Upload"]["required"]
    assert "fileName" not in schemas["Upload"]["required"]
    assert "active" not in schemas["ServerStatus"]["required"]
    assert "nodes" not in schemas["Kad"]["required"]


def test_openapi_response_numeric_bounds_match_runtime_domains() -> None:
    module = load_rest_api_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]

    minimum_zero_fields = {
        "Stats": [
            "downloadSpeedKiBps",
            "uploadSpeedKiBps",
            "sessionDownloadedBytes",
            "sessionUploadedBytes",
            "totalDownloadedBytes",
            "totalUploadedBytes",
            "activeDownloads",
            "activeUploads",
            "waitingUploads",
            "downloadCount",
        ],
        "Transfer": [
            "sizeBytes",
            "completedBytes",
            "downloadSpeedKiBps",
            "uploadSpeedKiBps",
            "partsObtained",
            "partsTotal",
            "partsAvailable",
        ],
        "TransferSource": ["downloadSpeedKiBps", "availableParts", "partCount", "queueRank"],
        "SharedFile": [
            "sizeBytes",
            "allTimeRequests",
            "allTimeAccepts",
            "allTimeTransferred",
            "partCount",
            "userRating",
            "requests",
            "acceptedRequests",
            "transferredBytes",
        ],
        "Upload": [
            "uploadSpeedKiBps",
            "uploadedBytes",
            "queueSessionUploaded",
            "payloadBuffered",
            "waitTimeMs",
            "waitStartedTick",
            "score",
            "requestedFileSizeBytes",
            "requestedPartsObtained",
            "requestedPartsTotal",
        ],
        "UploadScoreBreakdown": ["baseScore", "effectiveScore", "lowRatioBonus", "lowIdDivisor", "cooldownRemainingMs"],
        "Server": ["failedCount", "hardFiles", "ping", "softFiles", "users", "files"],
        "Kad": ["nodes", "users", "files", "bootstrapProgress", "indexedSources", "indexedKeywords"],
        "SearchResult": ["sizeBytes", "sources", "completeSources", "clientCount", "serverCount", "kadPublishInfo", "rating"],
    }

    for schema_name, field_names in minimum_zero_fields.items():
        for field_name in field_names:
            assert schemas[schema_name]["properties"][field_name]["minimum"] == 0

    bounded_port_fields = {
        "TransferSource": ["port", "serverPort"],
        "Upload": ["port", "serverPort"],
        "SearchResult": ["clientPort", "serverPort"],
        "Friend": ["port"],
    }
    for schema_name, field_names in bounded_port_fields.items():
        for field_name in field_names:
            assert schemas[schema_name]["properties"][field_name]["minimum"] == 0
            assert schemas[schema_name]["properties"][field_name]["maximum"] == 65535

    assert schemas["Server"]["properties"]["port"] == {"type": "integer", "minimum": 1, "maximum": 65535}
    assert "enum" not in schemas["SearchResult"]["properties"]["fileType"]


def test_rest_vocabulary_source_and_openapi_stay_in_sync() -> None:
    module = load_rest_api_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]
    workspace_root = Path(__file__).resolve().parents[4]
    app_source = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"
    json_source = (app_source / "WebServerJson.cpp").read_text(encoding="utf-8")
    surface_source = (app_source / "WebApiSurfaceSeams.h").read_text(encoding="utf-8")
    command_source = (app_source / "WebApiCommandSeams.h").read_text(encoding="utf-8")
    json_seams = (app_source / "WebServerJsonSeams.h").read_text(encoding="utf-8")
    arr_seams = (app_source / "WebServerArrCompatSeams.h").read_text(encoding="utf-8")

    search_methods = ["automatic", "server", "global", "kad"]
    search_types = ["", "arc", "audio", "iso", "image", "pro", "video", "doc", "emulecollection"]
    assert schemas["SearchCreateRequest"]["properties"]["method"]["enum"] == search_methods
    assert schemas["SearchCreateRequest"]["properties"]["type"]["enum"] == search_types

    for token in search_methods:
        assert token in json_seams
    for token in search_types:
        assert token in json_seams

    assert schemas["TransferState"]["enum"] == [
        "downloading",
        "paused",
        "queued",
        "checking",
        "completing",
        "completed",
        "error",
        "missingfiles",
    ]
    for token in schemas["TransferState"]["enum"]:
        assert f'_T("{token}")' in json_source or token in command_source

    assert schemas["TransferPriority"]["enum"] == ["auto", "verylow", "low", "normal", "high", "veryhigh"]
    assert schemas["SharedFilePriority"]["enum"] == ["auto", "verylow", "low", "normal", "high", "release"]
    for token in ("uploading", "queued", "connecting", "banned", "idle"):
        assert f'return "{token}";' in surface_source
    for token in schemas["TransferSource"]["properties"]["downloadState"]["enum"]:
        assert f'return "{token}";' in surface_source

    assert 'name: includeScoreBreakdown' in module.OPENAPI_CONTRACT_PATH.read_text(encoding="utf-8")
    assert '{"GET", "/upload-queue", "", "offset,limit,includeScoreBreakdown"}' in json_seams
    assert 'TryParseBooleanQueryValue(it->second, "includeScoreBreakdown"' in json_seams
    assert "CopyUploadQueueQueryParams(query, rRoute.params)" in json_seams
    assert 'const bool bIncludeScoreBreakdown = rParams.value("includeScoreBreakdown", false);' in json_source
    assert "BuildUploadsListJson(bWaitingQueue, uLimit, uOffset, &uTotal, bIncludeScoreBreakdown)" in json_source

    assert arr_seams.index('methods.push_back("global")') < arr_seams.index('methods.push_back("kad")')
    assert 'return "video";' in arr_seams


def test_native_transfer_operation_responses_use_stable_bulk_items() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    source_path = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid" / "WebServerJson.cpp"
    source = source_path.read_text(encoding="utf-8")

    assert 'return json{{"items", json::array({result})}};' in source
    assert "json singleResource;" not in source
    assert 'return json{{"items", results}};' in source


def test_transfer_add_response_uses_stable_bulk_items() -> None:
    module = load_rest_api_smoke_module()
    expected_hash = "abcdef0123456789fedcba9876543210"

    item = {"hash": expected_hash, "name": "rest-api-unicode.bin", "ok": True}
    result = {
        "status": 200,
        "content_type": "application/json; charset=utf-8",
        "json": {"items": [item]},
        "raw_json": {"data": {"items": [item]}, "meta": {"apiVersion": "v1"}},
    }

    assert module.require_transfer_add_result(result, expected_hash) == item


def test_require_json_object_reports_compact_response_on_status_mismatch() -> None:
    module = load_rest_api_smoke_module()
    result = {
        "status": 409,
        "content_type": "application/json; charset=utf-8",
        "json": {"error": "INVALID_STATE", "message": "transfer could not be queued"},
        "raw_json": {
            "error": {
                "code": "INVALID_STATE",
                "message": "transfer could not be queued",
                "details": {},
            }
        },
    }

    with pytest.raises(AssertionError) as raised:
        module.require_json_object(result, 200)

    message = str(raised.value)
    assert "INVALID_STATE" in message
    assert "transfer could not be queued" in message


def test_transfer_operation_response_uses_stable_bulk_items() -> None:
    module = load_rest_api_smoke_module()
    expected_hash = "fedcba98765432100123456789abcdef"

    item = {"hash": expected_hash, "ok": True}
    result = {
        "status": 200,
        "content_type": "application/json; charset=utf-8",
        "json": {"items": [item]},
        "raw_json": {"data": {"items": [item]}, "meta": {"apiVersion": "v1"}},
    }

    assert module.require_transfer_operation_result(result, expected_hash) == {
        "hash": expected_hash,
        "ok": True,
        "state": None,
        "stopped": None,
    }


def test_arr_adapter_http_step_records_transport_failure(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    smoke = {"ok": True}

    def fail_request(*_args, **_kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(module, "http_request", fail_request)

    with pytest.raises(module.ArrAdapterSmokeFailure) as raised:
        module.record_arr_adapter_http_request(
            smoke,
            family="torznab",
            step="search",
            base_url="http://127.0.0.1:4711",
            path="/indexer/emulebb/api?t=search&q=linux",
            api_key="test-key",
        )

    assert raised.value.check_result is smoke
    assert smoke["ok"] is False
    assert smoke["failed_step"] == {
        "family": "torznab",
        "step": "search",
        "path": "/indexer/emulebb/api?t=search&q=linux",
    }
    assert smoke["torznab"]["search"]["transport_error"] == {
        "type": "TimeoutError",
        "message": "timed out",
    }


def test_peer_add_friend_never_returns_ok_for_friend_response() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    source_path = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid" / "WebServerJson.cpp"
    source = source_path.read_text(encoding="utf-8")

    assert 'pFriend != NULL ? BuildFriendJson(*pFriend) : json{{"ok", true}}' not in source
    assert 'rError.strMessage = _T("friend was added but could not be resolved");' in source


def test_rest_smoke_uses_v1_upload_remove_operation_route() -> None:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "rest-api-smoke.py"
    source = script_path.read_text(encoding="utf-8")

    assert '"/api/v1/uploads/unknown/operations/remove"' in source
    assert '"/api/v1/uploads/unknown",\n        method="DELETE"' not in source


def test_rest_search_type_docs_reject_alias_and_remap_language() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    rest_docs_dir = workspace_root / "repos" / "emulebb-tooling" / "docs" / "rest"
    docs = "\n".join(
        (rest_docs_dir / name).read_text(encoding="utf-8")
        for name in ("REST-API-CONTRACT.md", "REST-API-ADAPTERS.md", "REST-API-PARITY-INVENTORY.md")
    )
    normalized_docs = re.sub(r"\s+", " ", docs)

    assert "No aliases, alternate casing, or request-time type remapping are accepted." in normalized_docs
    assert "`SearchResult.fileType` remains row metadata" in normalized_docs
    assert "adapter-side result filter" in normalized_docs
    assert "family-to-search-type mapping still resolves to REST tokens" in normalized_docs

    for forbidden in ("`Video`", "`cdimage`", "normalized to", "normalizes to"):
        assert forbidden not in docs


def test_rest_contract_docs_define_adapter_subset_and_legacy_compile_only_boundary() -> None:
    module = load_rest_api_smoke_module()
    workspace_root = Path(__file__).resolve().parents[4]
    rest_docs_dir = workspace_root / "repos" / "emulebb-tooling" / "docs" / "rest"
    adapter_doc = (rest_docs_dir / "REST-API-ADAPTERS.md").read_text(encoding="utf-8")
    contract_doc = (rest_docs_dir / "REST-API-CONTRACT.md").read_text(encoding="utf-8")
    parity_doc = (rest_docs_dir / "REST-API-PARITY-INVENTORY.md").read_text(encoding="utf-8")

    adapter_doc_lower = adapter_doc.lower()
    qbit_routes = [route for route in module.ADAPTER_CONTRACT_ROUTES if route["family"] == "qbit"]
    assert len(qbit_routes) == 19
    for route in qbit_routes:
        method = str(route["method"]).lower()
        path = str(route["path"])
        assert f"| `{method.lower()}` | `{path}` |" in adapter_doc_lower

    normalized_adapter_doc = re.sub(r"\s+", " ", adapter_doc_lower)
    assert "not a full qbittorrent web api clone" in normalized_adapter_doc
    assert "paths are matched case-insensitively" in normalized_adapter_doc
    assert "adapter_contract_routes" in normalized_adapter_doc

    for required_text in (
        "/indexer/emulebb/api",
        "webapiversion",
        "createcategory",
        "setcategory",
        "setforcestart",
        "https://github.com/qbittorrent/qbittorrent/wiki/webui-api-%28qbittorrent-4.1%29",
        "https://torznab.github.io/spec-1.3-draft/",
        "save_path",
        "content_path",
        "setsharelimits",
        "`t`",
        "`apikey`",
        "`season`",
        "`ep`",
        "`year`",
        "deprecated",
        "compile-only",
    ):
        assert required_text in adapter_doc_lower

    contract_doc_lower = contract_doc.lower()
    assert "rest-api-adapters.md" in contract_doc_lower
    assert "deprecated" in contract_doc_lower
    assert "legacy template-based webserver" in contract_doc_lower
    assert "compile preservation" in contract_doc_lower

    parity_doc_lower = parity_doc.lower()
    assert "migrated action inventory" in parity_doc_lower
    assert "not a functional parity promise" in parity_doc_lower
    assert "compile-only" in parity_doc_lower
    assert "legacy action" not in parity_doc_lower


def test_adapter_contract_registry_matches_sources_and_public_shapes() -> None:
    module = load_rest_api_smoke_module()

    summary = module.assert_adapter_contract_routes_match_sources()
    assert summary["ok"], summary

    routes = {
        (route["method"], route["path"]): route
        for route in module.ADAPTER_CONTRACT_ROUTES
    }
    assert summary["qbit_route_count"] == 19
    assert routes[("GET", "/api/v2/app/webapiversion")]["authRequired"] is False
    assert routes[("GET", "/api/v2/app/preferences")]["responseKind"] == "json"
    assert routes[("POST", "/api/v2/torrents/add")]["requiredFormFields"] == ("urls",)
    assert routes[("POST", "/api/v2/torrents/delete")]["requiredFormFields"] == ("hashes",)
    assert routes[("GET", "/api/v2/torrents/properties")]["requiredQueryFields"] == ("hash",)

    torznab = routes[("GET", "/indexer/emulebb/api")]
    assert torznab["responseKind"] == "xml"
    assert torznab["authMode"] == "api-key-query-or-header"
    assert torznab["acceptedTypes"] == ("caps", "movie", "search", "tvsearch")
    assert torznab["queryFields"] == ("cat", "ep", "limit", "offset", "q", "season", "t", "year")


def test_rest_stress_adapter_operations_match_adapter_contract_registry() -> None:
    module = load_rest_api_smoke_module()

    summary = module.assert_rest_stress_adapter_operations_match_contract()
    assert summary["ok"], summary


def test_rest_error_response_requires_json_not_html() -> None:
    module = load_rest_api_smoke_module()
    error_result = {
        "status": 404,
        "content_type": "application/json; charset=utf-8",
        "body_text": '{"error":{"code":"NOT_FOUND","message":"transfer not found","details":{}}}',
        "raw_json": {
            "error": {
                "code": "NOT_FOUND",
                "message": "transfer not found",
                "details": {},
            },
        },
        "json": {
            "error": "NOT_FOUND",
            "message": "transfer not found",
            "details": {},
        },
    }

    assert module.is_native_rest_json_response(error_result) is True
    assert module.response_matches_kind(error_result, "native-json") is True
    assert module.response_matches_kind(error_result, "json") is True
    assert module.require_error_response(error_result, 404, "NOT_FOUND")["error"] == "NOT_FOUND"

    method_not_allowed = {
        **error_result,
        "status": 405,
        "body_text": (
            '{"error":{"code":"METHOD_NOT_ALLOWED",'
            '"message":"HTTP method is not allowed for this API route","details":{}}}'
        ),
        "raw_json": {
            "error": {
                "code": "METHOD_NOT_ALLOWED",
                "message": "HTTP method is not allowed for this API route",
                "details": {},
            },
        },
        "json": {
            "error": "METHOD_NOT_ALLOWED",
            "message": "HTTP method is not allowed for this API route",
            "details": {},
        },
    }
    assert module.require_error_response(method_not_allowed, 405, "METHOD_NOT_ALLOWED")["error"] == "METHOD_NOT_ALLOWED"

    html_content_type = {**error_result, "content_type": "text/html; charset=utf-8"}
    assert module.is_native_rest_json_response(html_content_type) is False
    assert module.response_matches_kind({**html_content_type, "body_text": "<html></html>"}, "native-json") is False
    with pytest.raises(AssertionError):
        module.require_error_response(html_content_type, 404, "NOT_FOUND")

    html_body = {**error_result, "body_text": "<html><body>login</body></html>"}
    with pytest.raises(AssertionError):
        module.require_error_response(html_body, 404, "NOT_FOUND")
def test_missing_transfer_bulk_result_rejects_success_rows() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(AssertionError):
        module.require_missing_transfer_bulk_result(
            {
                "status": 200,
                "raw_json": {
                    "data": {
                        "items": [
                            {
                                "hash": module.REST_SURFACE_MISSING_HASH,
                                "ok": True,
                            },
                        ],
                    },
                    "meta": {"apiVersion": "v1"},
                },
                "json": {
                    "items": [
                        {
                            "hash": module.REST_SURFACE_MISSING_HASH,
                            "ok": True,
                        },
                    ],
                },
            }
        )


def test_rest_contract_registry_matches_openapi() -> None:
    module = load_rest_api_smoke_module()

    summary = module.assert_contract_routes_match_openapi()

    assert summary["ok"] is True
    assert summary["operation_count"] == summary["openapi_route_count"]
    assert summary["duplicate_operation_ids"] == []
    assert summary["missing_from_registry"] == []
    assert summary["missing_from_openapi"] == []
    assert summary["unknown_execution_models"] == []


def test_rest_preference_contract_matches_openapi_and_native_sources() -> None:
    module = load_rest_api_smoke_module()

    summary = module.assert_preference_contract_matches_sources()

    assert summary["ok"], summary
    assert "downloadAutoBroadbandIo" in summary["openapi_preferences"]
    assert "downloadAutoBroadbandIo" in summary["openapi_patch"]
    assert "downloadAutoBroadbandIo" in summary["native_response"]
    assert "downloadAutoBroadbandIo" in summary["native_mutable"]
    assert "uploadSlotElasticPercent" in summary["openapi_preferences"]
    assert "uploadSlotElasticPercent" in summary["openapi_patch"]
    assert "uploadSlotElasticPercent" in summary["native_response"]
    assert "uploadSlotElasticPercent" in summary["native_mutable"]
    assert "autoBroadbandIo" not in summary["openapi_preferences"]
    assert "autoBroadbandIo" not in summary["openapi_patch"]


def _csv_fields(value: str) -> set[str]:
    return {field for field in value.split(",") if field}


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _component_ref_name(line: str, kind: str) -> str | None:
    match = re.search(rf"#/components/{kind}/([A-Za-z0-9_]+)", line)
    return match.group(1) if match else None


def _native_route_token_value(token: str, workspace_root: Path) -> str:
    token = token.strip()
    if token.startswith('"') and token.endswith('"'):
        return token[1:-1]
    if token == "WebApiSurfaceSeams::kMutablePreferenceFieldListCsv":
        surface_header = (
            workspace_root
            / "workspaces"
            / "workspace"
            / "app"
            / "emulebb-main"
            / "srchybrid"
            / "WebApiSurfaceSeams.h"
        ).read_text(encoding="utf-8")
        csv_block = re.search(
            r"kMutablePreferenceFieldListCsv\s*=\s*(?P<body>.*?);",
            surface_header,
            flags=re.S,
        )
        assert csv_block is not None
        return "".join(re.findall(r'"([^"]*)"', csv_block.group("body")))
    raise AssertionError(f"unsupported native route field token: {token}")


def _native_route_contracts() -> dict[tuple[str, str], dict[str, set[str]]]:
    workspace_root = Path(__file__).resolve().parents[4]
    route_header = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid" / "WebServerJsonSeams.h"
    # Scope the scan to the GetApiRouteSpecs() table so unrelated brace-enclosed
    # string arrays elsewhere in the header (for example method-name lists) are
    # not misread as route specs.
    header_text = route_header.read_text(encoding="utf-8")
    block_start = header_text.index("GetApiRouteSpecs()")
    block_end = header_text.index("return specs;", block_start)
    route_specs = re.findall(
        r'\{\s*"([A-Z]+)"\s*,\s*"([^"]+)"\s*,\s*("[^"]*"|WebApiSurfaceSeams::kMutablePreferenceFieldListCsv)\s*,\s*("[^"]*")(?:\s*,\s*([^}]+?))?\s*\}',
        header_text[block_start:block_end],
    )

    return {
        (method, path): {
            "body": _csv_fields(_native_route_token_value(body_fields, workspace_root)),
            "query": _csv_fields(_native_route_token_value(query_fields, workspace_root)),
            "execution": {"direct"} if "kRestRouteExecutionDirect" in execution_model else {"ui-thread"},
        }
        for method, path, body_fields, query_fields, execution_model in route_specs
    }


def _openapi_component_parameters(lines: list[str]) -> dict[str, dict[str, str | None]]:
    parameters: dict[str, dict[str, str | None]] = {}
    in_components = False
    in_parameters = False
    current_name: str | None = None
    current_block: list[str] = []

    def commit() -> None:
        if current_name is None:
            return
        name = None
        location = None
        for line in current_block:
            stripped = line.strip()
            if stripped.startswith("name:"):
                name = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("in:"):
                location = stripped.split(":", 1)[1].strip()
        parameters[current_name] = {"name": name, "in": location}

    for line in lines:
        if line == "components:":
            in_components = True
            continue
        if not in_components:
            continue
        if line.startswith("  parameters:"):
            in_parameters = True
            continue
        if in_parameters and line.startswith("  ") and not line.startswith("    ") and not line.startswith("  parameters:"):
            commit()
            break
        if not in_parameters:
            continue
        match = re.match(r"    ([A-Za-z0-9_]+):\s*$", line)
        if match:
            commit()
            current_name = match.group(1)
            current_block = []
        elif current_name is not None:
            current_block.append(line)
    return parameters


def _openapi_schema_properties(lines: list[str]) -> dict[str, set[str]]:
    schemas: dict[str, set[str]] = {}
    in_components = False
    in_schemas = False
    current_name: str | None = None
    in_properties = False
    properties: set[str] = set()

    def commit() -> None:
        if current_name is not None:
            schemas[current_name] = set(properties)

    for line in lines:
        if line == "components:":
            in_components = True
            continue
        if not in_components:
            continue
        if line.startswith("  schemas:"):
            in_schemas = True
            continue
        if not in_schemas:
            continue
        schema_match = re.match(r"    ([A-Za-z0-9_]+):\s*$", line)
        if schema_match:
            commit()
            current_name = schema_match.group(1)
            in_properties = False
            properties = set()
            continue
        if current_name is None:
            continue
        if line.startswith("      properties:"):
            in_properties = True
            continue
        if in_properties:
            prop_match = re.match(r"        ([A-Za-z0-9_]+):\s*$", line)
            if prop_match:
                properties.add(prop_match.group(1))
            elif line and _indent(line) <= 6:
                in_properties = False
    commit()
    return schemas


def _openapi_operation_contracts(openapi_path: Path) -> dict[tuple[str, str], dict[str, set[str]]]:
    lines = openapi_path.read_text(encoding="utf-8").splitlines()
    component_parameters = _openapi_component_parameters(lines)
    schema_properties = _openapi_schema_properties(lines)
    operations: dict[tuple[str, str], dict[str, set[str]]] = {}
    current_path: str | None = None
    current_method: str | None = None
    block: list[str] = []

    def parse_operation_block() -> dict[str, set[str]]:
        body_fields: set[str] = set()
        query_fields: set[str] = set()
        in_parameters = False
        in_request_body = False
        for index, line in enumerate(block):
            stripped = line.strip()
            if _indent(line) == 6 and stripped == "parameters:":
                in_parameters = True
                in_request_body = False
                continue
            if _indent(line) == 6 and stripped == "requestBody:":
                in_request_body = True
                in_parameters = False
                continue
            if _indent(line) <= 6 and stripped not in {"parameters:", "requestBody:"}:
                in_parameters = False
                in_request_body = False
            if in_parameters:
                parameter_ref = _component_ref_name(line, "parameters")
                if parameter_ref is not None:
                    parameter = component_parameters[parameter_ref]
                    if parameter["in"] == "query":
                        query_fields.add(str(parameter["name"]))
                direct_name = re.match(r"        - name: (.+)$", line)
                if direct_name:
                    location = None
                    for nested in block[index + 1 :]:
                        if re.match(r"        - ", nested) or _indent(nested) <= 6:
                            break
                        if nested.strip().startswith("in:"):
                            location = nested.strip().split(":", 1)[1].strip()
                    if location == "query":
                        query_fields.add(direct_name.group(1).strip())
            if in_request_body:
                schema_ref = _component_ref_name(line, "schemas")
                if schema_ref is not None:
                    body_fields.update(schema_properties.get(schema_ref, set()))
        return {"body": body_fields, "query": query_fields}

    def commit() -> None:
        if current_path is not None and current_method is not None:
            operations[(current_method, current_path)] = parse_operation_block()

    for line in lines:
        if line.startswith("components:"):
            commit()
            break
        path_match = re.match(r"  (/[^:]+):\s*$", line)
        if path_match:
            commit()
            current_path = path_match.group(1)
            current_method = None
            block = []
            continue
        method_match = re.match(r"    (get|post|patch|delete):\s*$", line)
        if method_match:
            commit()
            current_method = method_match.group(1).upper()
            block = []
            continue
        if current_method is not None:
            block.append(line)
    return operations


def test_native_route_specs_match_openapi_methods_paths_and_fields() -> None:
    module = load_rest_api_smoke_module()
    native_contracts = {
        route_key: {
            "body": contract["body"],
            "query": contract["query"],
        }
        for route_key, contract in _native_route_contracts().items()
        if route_key not in PRIVATE_NATIVE_ONLY_ROUTES
    }
    openapi_contracts = _openapi_operation_contracts(module.OPENAPI_CONTRACT_PATH)

    assert native_contracts == openapi_contracts


def test_rest_v1_paging_surface_is_intentionally_narrow() -> None:
    contracts = _openapi_operation_contracts(load_rest_api_smoke_module().OPENAPI_CONTRACT_PATH)

    assert contracts[("GET", "/shared-files")]["query"] == {"limit", "offset"}
    assert contracts[("GET", "/upload-queue")]["query"] == {"includeScoreBreakdown", "limit", "offset"}
    assert contracts[("GET", "/logs")]["query"] == {"limit"}
    assert contracts[("GET", "/snapshot")]["query"] == {"limit"}

    unpaged_routes = {
        ("GET", "/categories"),
        ("GET", "/transfers/{hash}/sources"),
        ("GET", "/transfers/{hash}/sources/{clientId}"),
        ("GET", "/shared-files/{hash}/comments"),
        ("GET", "/uploads"),
        ("GET", "/uploads/{clientId}"),
        ("GET", "/upload-queue/{clientId}"),
        ("GET", "/servers"),
        ("GET", "/friends"),
        ("GET", "/searches"),
    }
    for route_key in unpaged_routes:
        assert "limit" not in contracts[route_key]["query"]
        assert "offset" not in contracts[route_key]["query"]


def test_native_route_execution_model_inventory_matches_dispatch_boundary() -> None:
    module = load_rest_api_smoke_module()
    native_contracts = _native_route_contracts()
    direct_routes = sorted(
        route_key for route_key, contract in native_contracts.items() if contract["execution"] == {"direct"}
    )
    ui_thread_routes = sorted(
        route_key for route_key, contract in native_contracts.items() if contract["execution"] == {"ui-thread"}
    )
    routes_by_operation = {route["operationId"]: route for route in module.REST_CONTRACT_ROUTES}

    assert direct_routes == [("GET", "/app")]
    assert len(direct_routes) + len(ui_thread_routes) == len(native_contracts)
    assert routes_by_operation["getApp"]["executionModel"] == "direct"
    assert routes_by_operation["getPreferences"]["executionModel"] == "ui-thread"
    assert routes_by_operation["shutdownApp"]["executionModel"] == "ui-thread"
    assert all(route["executionModel"] in {"direct", "ui-thread"} for route in module.REST_CONTRACT_ROUTES)


def test_destructive_native_routes_require_explicit_confirmation_or_intent() -> None:
    native_contracts = _native_route_contracts()
    required_body_fields = {
        ("POST", "/app/shutdown"): {"confirmShutdown"},
        ("POST", "/diagnostics/dumps"): {"confirmDump"},
        ("POST", "/transfers/operations/clear-completed"): {"confirmClearCompleted"},
        ("PATCH", "/shared-directories"): {"confirmReplaceRoots"},
        ("POST", "/logs/operations/clear"): {"confirmClearLogs"},
        ("POST", "/diagnostics/crash-tests"): {"confirmCrash"},
    }
    required_query_fields = {
        ("DELETE", "/transfers/{hash}/files"): {"confirm"},
        ("DELETE", "/shared-files/{hash}/file"): {"confirm"},
        ("DELETE", "/searches"): {"confirm"},
    }
    id_targeted_delete_routes = {
        ("DELETE", "/categories/{categoryId}"),
        ("DELETE", "/transfers/{hash}"),
        ("DELETE", "/shared-files/{hash}"),
        ("DELETE", "/servers/{serverId}"),
        ("DELETE", "/searches/{searchId}"),
        ("DELETE", "/friends/{userHash}"),
    }

    for route_key, required_fields in required_body_fields.items():
        assert required_fields <= native_contracts[route_key]["body"]

    for route_key, required_fields in required_query_fields.items():
        assert required_fields <= native_contracts[route_key]["query"]
        assert native_contracts[route_key]["body"] == set()

    for route_key in id_targeted_delete_routes:
        assert route_key in native_contracts
        assert native_contracts[route_key]["body"] == set()

    audited_delete_routes = {
        route_key for route_key in required_query_fields
    } | id_targeted_delete_routes
    delete_routes = {route_key for route_key in native_contracts if route_key[0] == "DELETE"}
    assert delete_routes == audited_delete_routes


def test_completed_transfer_delete_preserves_shared_file_registration() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    source = (
        workspace_root
        / "workspaces"
        / "workspace"
        / "app"
        / "emulebb-main"
        / "srchybrid"
        / "WebServerJson.cpp"
    ).read_text(encoding="utf-8")
    completed_delete_branch = source[
        source.index("if (pPartFile->GetStatus() == PS_COMPLETE)") : source.index(
            "} else if (!bDeleteFiles)",
            source.index("if (pPartFile->GetStatus() == PS_COMPLETE)"),
        )
    ]
    row_only_branch = completed_delete_branch[
        completed_delete_branch.index("if (!bDeleteFiles)") : completed_delete_branch.index("SShellDeleteFileResult deleteResult;")
    ]

    assert "GetDownloadList()->RemoveFile(pPartFile)" in row_only_branch
    assert "theApp.sharedfiles->RemoveFile" not in row_only_branch


def test_openapi_contract_routes_are_the_live_completeness_source() -> None:
    module = load_rest_api_smoke_module()

    routes_by_operation = {route["operationId"]: route for route in module.REST_CONTRACT_ROUTES}

    assert routes_by_operation["getApp"]["path"] == "/api/v1/app"
    assert routes_by_operation["getApp"]["safety"] == "safe"
    assert routes_by_operation["getApp"]["successResponseStatuses"] == ["200"]
    assert routes_by_operation["getApp"]["successResponseRefs"] == ["AppResponse"]
    assert routes_by_operation["getApp"]["responseEnvelope"] == "AppResponse"
    assert routes_by_operation["getSnapshot"]["path"] == "/api/v1/snapshot?limit=7"
    assert routes_by_operation["getTransfer"]["path"] == f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}"
    assert routes_by_operation["getTransfer"]["responseEnvelope"] == "TransferResponse"
    assert routes_by_operation["getTransferDetails"]["path"] == f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/details"
    assert routes_by_operation["getTransferDetails"]["responseEnvelope"] == "TransferDetailsResponse"
    assert routes_by_operation["removeUploadClient"]["method"] == "POST"
    assert routes_by_operation["removeUploadClient"]["path"] == (
        f"/api/v1/uploads/{module.REST_SURFACE_MISSING_HASH}/operations/remove"
    )
    assert routes_by_operation["downloadSearchResult"]["path"] == (
        f"/api/v1/searches/123/results/{module.REST_SURFACE_MISSING_HASH}/operations/download"
    )
    assert routes_by_operation["shutdownApp"]["safe"] is False
    assert routes_by_operation["shutdownApp"]["safety"] == "unsafe"
    assert routes_by_operation["shutdownApp"]["successResponseStatuses"] == ["200"]
    assert routes_by_operation["shutdownApp"]["responseEnvelope"] == "OkAcceptedResponse"
    assert routes_by_operation["captureDiagnosticDump"]["safe"] is False
    assert routes_by_operation["captureDiagnosticDump"]["safety"] == "unsafe"
    assert routes_by_operation["captureDiagnosticDump"]["responseEnvelope"] == "DiagnosticDumpResponse"
    assert routes_by_operation["triggerDiagnosticCrashTest"]["safe"] is False
    assert routes_by_operation["triggerDiagnosticCrashTest"]["safety"] == "unsafe"
    assert routes_by_operation["triggerDiagnosticCrashTest"]["responseEnvelope"] == "OkAcceptedResponse"
    assert all(len(route["successResponseRefs"]) == 1 for route in module.REST_CONTRACT_ROUTES)
    assert all(route["responseEnvelope"] == route["successResponseRefs"][0] for route in module.REST_CONTRACT_ROUTES)


def test_openapi_response_schema_validation_rejects_extra_fields(tmp_path: Path) -> None:
    module = load_rest_api_smoke_module()
    openapi_path = tmp_path / "openapi.yaml"
    openapi_path.write_text(
        """
openapi: 3.1.0
components:
  responses:
    StrictResponse:
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/StrictEnvelope"
  schemas:
    StrictEnvelope:
      type: object
      additionalProperties: false
      required: [data]
      properties:
        data:
          type: object
          additionalProperties: false
          required: [ok]
          properties:
            ok:
              type: boolean
""",
        encoding="utf-8",
    )

    module.validate_openapi_response_payload("StrictResponse", {"data": {"ok": True}}, openapi_path)
    with pytest.raises(module.jsonschema.ValidationError):
        module.validate_openapi_response_payload("StrictResponse", {"data": {"ok": True, "extra": 1}}, openapi_path)


def test_openapi_custom_success_response_samples_match_contract() -> None:
    module = load_rest_api_smoke_module()
    meta = {"apiVersion": "v1"}
    network = {
        "ports": {"tcp": 4662, "udp": 4672, "serverUdp": 4672},
        "binding": {
            "configuredAddress": "",
            "configuredInterfaceId": "",
            "configuredInterfaceName": "hide.me",
            "activeConfiguredAddress": "",
            "activeInterfaceId": "",
            "activeInterfaceName": "hide.me",
            "activeInterfaceIndex": 12,
            "resolveResult": "resolved",
        },
        "vpnGuard": {
            "enabled": True,
            "mode": "block",
            "allowedPublicIpCidrs": "",
            "startupBlocked": True,
            "startupBlockReason": "VPN Guard blocked P2P startup",
        },
    }
    samples = {
        "BulkOperationResponse": {"data": {"items": [{"ok": True, "hash": "0" * 32}], "total": 1}, "meta": meta},
        "PeerBanResponse": {"data": {"ok": True, "banned": True}, "meta": meta},
        "UploadRemoveResponse": {"data": {"ok": True, "removed": "queue"}, "meta": meta},
        "UrlImportResponse": {"data": {"ok": True, "imported": True}, "meta": meta},
        "SharedFileCreateResponse": {
            "data": {"ok": True, "path": "C:/incoming/example.dat", "alreadyShared": False, "queued": True, "file": None},
            "meta": meta,
        },
        "SharedFileDeleteResponse": {
            "data": {"ok": True, "deletedFiles": False, "path": "C:/incoming/example.dat", "hash": "0" * 32},
            "meta": meta,
        },
        "TransferSourceBrowseResponse": {"data": {"ok": True, "alreadyPending": False, "searchId": "12"}, "meta": meta},
        "SearchResultDownloadResponse": {"data": {"ok": True, "searchId": "12", "hash": "0" * 32}, "meta": meta},
        "Ed2kLinkResponse": {"data": {"hash": "0" * 32, "link": "ed2k://|file|example.dat|1|hash|/"}, "meta": meta},
        "KadResponse": {
            "data": {
                "running": False,
                "connected": False,
                "firewalled": None,
                "bootstrapping": False,
                "bootstrapProgress": 0,
                "contactCount": None,
                "lanMode": False,
                "users": None,
                "files": None,
                "operationQueued": False,
                "blockedByVpnGuard": True,
                "network": network,
            },
            "meta": meta,
        },
    }

    for response_name, payload in samples.items():
        module.validate_openapi_response_payload(response_name, payload)


def test_openapi_custom_success_responses_reject_generic_ok_fallbacks() -> None:
    module = load_rest_api_smoke_module()

    for response_name in (
        "FriendResponse",
        "PeerBanResponse",
        "UploadRemoveResponse",
        "UrlImportResponse",
        "SharedFileCreateResponse",
        "SharedFileDeleteResponse",
        "TransferSourceBrowseResponse",
        "SearchResultDownloadResponse",
        "Ed2kLinkResponse",
    ):
        with pytest.raises(module.jsonschema.ValidationError):
            module.validate_openapi_response_payload(response_name, {"data": {"ok": True}, "meta": {"apiVersion": "v1"}})


def test_openapi_error_code_enum_covers_native_rest_codes() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    app_source = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"
    openapi_text = (workspace_root / "repos" / "emulebb-tooling" / "docs" / "rest" / "REST-API-OPENAPI.yaml").read_text(
        encoding="utf-8"
    )
    native_text = (app_source / "WebServerJson.cpp").read_text(encoding="utf-8")
    native_text += (app_source / "WebServerJsonSeams.h").read_text(encoding="utf-8")

    enum_match = re.search(
        r"code:\n\s+type: string\n(?:.|\n)*?enum:\n(?P<values>(?:\s+- [A-Z_]+\n)+)",
        openapi_text,
    )
    assert enum_match is not None
    documented_codes = set(re.findall(r"- ([A-Z_]+)", enum_match.group("values")))
    native_codes = set(re.findall(r'(?:strCode\s*=\s*|strErrorCode\s*=\s*|rCode == )"([A-Z_]+)"', native_text))

    assert native_codes <= documented_codes


def test_openapi_response_dtos_require_core_implementation_fields() -> None:
    module = load_rest_api_smoke_module()
    document = module.yaml.safe_load(module.OPENAPI_CONTRACT_PATH.read_text(encoding="utf-8"))
    schemas = document["components"]["schemas"]

    snapshot_data = schemas["SnapshotEnvelope"]["allOf"][1]["properties"]["data"]
    transfer_details_data = schemas["TransferDetailsEnvelope"]["allOf"][1]["properties"]["data"]
    search_result = schemas["SearchResult"]

    assert set(snapshot_data["required"]) == {
        "app",
        "status",
        "transfers",
        "sharedFiles",
        "uploads",
        "uploadQueue",
        "servers",
            "kad",
            "network",
            "logs",
        }
    assert set(transfer_details_data["required"]) == {"transfer", "parts", "sources"}
    assert {
        "searchId",
        "method",
        "type",
        "hash",
        "name",
        "sizeBytes",
        "sources",
        "completeSources",
        "fileType",
        "complete",
        "knownType",
        "directory",
        "clientIp",
        "clientPort",
        "serverIp",
        "serverPort",
        "clientCount",
        "serverCount",
        "kadPublishInfo",
        "rating",
        "hasComment",
        "spam",
        "evidence",
    } <= set(search_result["required"])


def test_qbit_compat_torrent_list_uses_native_transfer_command() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    source_path = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid" / "WebServerQBitCompat.cpp"
    source = source_path.read_text(encoding="utf-8")

    assert 'BuildInternalCommand("qbit/transfers/info"' in source
    assert "theApp.downloadqueue" not in source
    assert "CPartFile" not in source


def test_arr_compat_uses_shared_native_validation_and_search_commands() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    app_source = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"
    tooling_docs = workspace_root / "repos" / "emulebb-tooling" / "docs" / "rest"
    source = (app_source / "WebServerArrCompat.cpp").read_text(encoding="utf-8")
    seams = (app_source / "WebServerArrCompatSeams.h").read_text(encoding="utf-8")
    adapter_docs = (tooling_docs / "REST-API-ADAPTERS.md").read_text(encoding="utf-8")
    parity_docs = (tooling_docs / "REST-API-PARITY-INVENTORY.md").read_text(encoding="utf-8")

    assert 'BuildInternalCommand("search/start"' in source
    assert 'BuildInternalCommand("search/results"' in source
    assert 'BuildInternalCommand("search/delete"' in source
    assert '"method", rMethod' in source
    assert '"type", rSearchType' in source
    assert 'BuildInternalCommand("status/get"' in source
    assert "BuildAvailableNativeSearchMethods(request.eFamily)" in source
    assert "BuildCacheKey(request, nativeSearchMethods)" in source
    assert "RunNativeSearches(request, nativeSearchMethods)" in source
    assert "BuildErrorXml" in source
    assert '<error code=\\"' in source
    assert source.index("BuildCacheKey(request, nativeSearchMethods)") < source.index("if (request.uOffset > 0)")
    assert source.index("if (TryGetCachedResults(strCacheKey, results))") < source.index("if (request.uOffset > 0)")
    assert "BuildNativeSearchMethodNames(eFamily)" in source
    assert "BuildRestSearchTypeNames(rRequest.eFamily)" in source
    assert "WebServerJsonSeams::TryValidateRequestPathEscapes" in seams
    assert "WebServerJsonSeams::TryParseQueryString" in seams
    assert "WebServerJsonSeams::TryNormalizeSearchText" in seams
    assert "WebServerJsonSeams::TryParseUnsignedDecimalValue" in seams
    assert "WebServerJsonSeams::TryValidatePublicFileNameText" in seams
    assert "WebServerJsonSeams::NormalizeAsciiWhitespace" in seams
    assert seams.index('methods.push_back("global")') < seams.index('methods.push_back("kad")')
    assert "BuildAvailableNativeSearchMethodNames" in seams
    assert "BuildNativeSearchMethodsCacheToken" in seams
    assert 'normalized.find("offset")' in seams
    assert 'normalized.find("limit")' in seams
    assert "IsConnectedNetworkSearchMethod" in seams
    assert 'return "video";' in seams
    assert "REST `video` searches" in adapter_docs
    assert "adapter-side result filter" in adapter_docs
    assert "`offset`, `limit`" in adapter_docs
    assert "page only a cached first-page result set" in adapter_docs
    assert "Unknown Torznab/Newznab extension query parameters are ignored" in adapter_docs
    assert '<error code="HTTP_STATUS" description="..."/>' in adapter_docs
    assert "REST `video` searches" in parity_docs


def test_native_search_resources_echo_selected_type() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    source_path = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid" / "WebServerJson.cpp"
    source = source_path.read_text(encoding="utf-8")

    rest_type_formatter = "WebServerJsonSeams::GetRestSearchFileTypeName(StdUtf8FromCString(rFileType))"
    native_type_assignment = (
        "pSearchParams->strFileType = CStringFromStdUtf8("
        "WebServerJsonSeams::GetNativeSearchFileTypeName(request.strFileType));"
    )
    assert rest_type_formatter in source
    assert native_type_assignment in source

    assert "GetSearchTypeName(pSearchParams->strFileType)" in source
    assert "GetSearchTypeName(rSearchParams.strFileType)" in source


def test_qbit_compat_uses_shared_native_validation_and_bridge_commands() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    app_source = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"
    source = (app_source / "WebServerQBitCompat.cpp").read_text(encoding="utf-8")
    seams = (app_source / "WebServerQBitCompatSeams.h").read_text(encoding="utf-8")

    assert "WebServerJson::BuildInternalCommand" in source
    assert 'BuildInternalCommand("transfers/add"' in source
    assert 'ExecuteHashBulkCommand("transfers/delete"' in source
    assert 'BuildInternalCommand("transfers/set_category"' in source
    assert 'BuildInternalCommand("transfers/get"' in source
    assert "WebServerJsonSeams::TryValidateRequestPathEscapes" in seams
    assert "WebServerJsonSeams::TryParseQueryString" in seams
    assert "WebServerJsonSeams::TryParseUrlEncodedFields" in seams
    assert "WebServerJsonSeams::TryNormalizeCategoryNameText" in seams
    assert "TryValidateAddRequestUrl" in seams
    assert "x.emulebb-ed2k" in seams
    assert "eMuleBB BTIH magnet does not match its eD2K hash" in seams
    assert "only eD2K URLs are supported" in seams


def test_qbit_adapter_smoke_add_uses_native_ed2k_url() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    script_path = workspace_root / "repos" / "emulebb-build-tests" / "scripts" / "rest-api-smoke.py"
    source = script_path.read_text(encoding="utf-8")
    qbit_add_block = source[
        source.index("qbit_add_form = urllib.parse.urlencode") : source.index(
            "qbit_add_valid = record_arr_adapter_http_request"
        )
    ]

    assert (
        '"urls": f"ed2k://|file|qbit-rest-smoke.bin|1024|{REST_SURFACE_QBIT_DOWNLOAD_HASH}|/"'
        in qbit_add_block
    )
    assert "magnet:?xt=urn:btih:" not in qbit_add_block


def test_native_transfer_add_reports_queue_rejection_as_failure() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    source_path = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid" / "WebServerJson.cpp"
    source = source_path.read_text(encoding="utf-8")
    transfer_add_block = source[source.index('if (strCommand == "transfers/add")') : source.index("auto handleTransferBulkMutation")]

    assert "theApp.downloadqueue->AddFileLinkToDownload(*pFileLink" in transfer_add_block
    assert "theApp.downloadqueue->GetFileByID(pFileLink->GetHashKey()) == NULL" in transfer_add_block
    assert 'rLinkErrorCode = "INVALID_STATE";' in transfer_add_block
    assert "no temp/incoming volume placement satisfies the protected disk-space thresholds" in transfer_add_block
    assert 'added["ok"] = false;' in transfer_add_block
    assert 'added["code"] = static_cast<LPCSTR>(strLinkErrorCode);' in transfer_add_block
    assert "rError.strCode = !strLinkErrorCode.IsEmpty() ? strLinkErrorCode" in transfer_add_block


def test_qbit_compat_documents_hash_mutation_cap() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    seams = (
        workspace_root
        / "workspaces"
        / "workspace"
        / "app"
        / "emulebb-main"
        / "srchybrid"
        / "WebServerQBitCompatSeams.h"
    ).read_text(encoding="utf-8")
    adapter_docs = (
        workspace_root / "repos" / "emulebb-tooling" / "docs" / "rest" / "REST-API-ADAPTERS.md"
    ).read_text(encoding="utf-8")

    assert "kMaxHashMutationCount = 100" in seams
    assert "one to 100 pipe-delimited 32-character eD2K hashes" in adapter_docs
    assert "The `hashes=all` value is intentionally" in adapter_docs
    assert "not supported by the Arr adapter" in adapter_docs


def test_rest_contract_registry_covers_release_families() -> None:
    module = load_rest_api_smoke_module()

    families = {route["family"] for route in module.REST_CONTRACT_ROUTES}

    assert families == {
        "app",
        "categories",
        "diagnostics",
        "friends",
        "kad",
        "logs",
        "searches",
        "servers",
        "shared",
        "shared-directories",
        "status",
        "transfers",
        "uploads",
    }
    assert any(route["operationId"] == "shutdownApp" and route["safe"] is False for route in module.REST_CONTRACT_ROUTES)
    assert any(route["operationId"] == "captureDiagnosticDump" and route["safe"] is False for route in module.REST_CONTRACT_ROUTES)
    assert any(route["operationId"] == "triggerDiagnosticCrashTest" and route["safe"] is False for route in module.REST_CONTRACT_ROUTES)


def test_rest_contract_summary_counts_outcomes_and_methods() -> None:
    module = load_rest_api_smoke_module()

    summary = module.build_contract_coverage_summary(
        [
            {
                "name": "getApp",
                "operationId": "getApp",
                "family": "app",
                "method": "GET",
                "path": "/api/v1/app",
                "safe": True,
                "safety": "safe",
                "responseEnvelope": "AppResponse",
                "executionModel": "direct",
                "skipped": False,
                "ok": True,
                "outcome": "success",
            },
            {
                "name": "getTransfer",
                "operationId": "getTransfer",
                "family": "transfers",
                "method": "GET",
                "path": f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}",
                "safe": True,
                "safety": "safe",
                "responseEnvelope": "TransferResponse",
                "executionModel": "ui-thread",
                "skipped": False,
                "ok": True,
                "outcome": "expected_error",
            },
            {
                "name": "shutdownApp",
                "operationId": "shutdownApp",
                "family": "app",
                "method": "POST",
                "path": "/api/v1/app/shutdown",
                "safe": False,
                "safety": "unsafe",
                "responseEnvelope": "OkAcceptedResponse",
                "executionModel": "ui-thread",
                "skipped": True,
                "ok": True,
                "outcome": "skipped_unsafe",
            },
        ],
        "contract",
    )

    assert summary["safe_route_count"] == 2
    assert summary["unsafe_route_count"] == 1
    assert summary["exercised_route_count"] == 2
    assert summary["success_count"] == 1
    assert summary["expected_error_count"] == 1
    assert summary["method_counts"] == {"GET": 2, "POST": 1}
    assert summary["response_envelope_counts"] == {"AppResponse": 1, "TransferResponse": 1, "OkAcceptedResponse": 1}
    assert summary["safety_counts"] == {"safe": 2, "unsafe": 1}
    assert summary["execution_model_counts"] == {"direct": 1, "ui-thread": 2}
    assert summary["outcome_counts"]["skipped_unsafe"] == 1


def test_live_search_plan_covers_release_query_corpus() -> None:
    module = load_rest_api_smoke_module()

    search_terms = ("linux", "ubuntu", "fedora", "freebsd", "debian", "emule")
    server_count = len(search_terms)
    kad_count = len(search_terms)
    plan = module.build_search_plan(server_count, kad_count, search_terms)

    assert [row["query"] for row in plan[:server_count]] == list(search_terms)
    assert [row["query_index"] for row in plan[:server_count]] == list(range(server_count))
    assert [row["network"] for row in plan[:server_count]] == ["server"] * server_count
    assert [row["query"] for row in plan[server_count:]] == list(search_terms)
    assert [row["query_index"] for row in plan[server_count:]] == list(range(kad_count))
    assert [row["network"] for row in plan[server_count:]] == ["kad"] * kad_count
    assert all("query" not in row for row in module.summarize_search_plan(plan))


def test_live_search_start_uses_broad_file_type_for_release_terms(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"id": "42"},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.start_live_search("http://127.0.0.1:1", "key", "server", "fedora", forced_method="server")

    assert result["ok"] is True
    assert requests[0]["path"] == "/api/v1/searches"
    assert requests[0]["json_body"] == {
        "query": "fedora",
        "method": "server",
        "type": "",
    }


def test_delete_all_searches_uses_confirmation_payload(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"ok": True},
            "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.delete_all_searches("http://127.0.0.1:1", "key")

    assert result["status"] == 200
    assert requests == [
        {
            "path": "/api/v1/searches?confirm=true",
            "method": "DELETE",
            "api_key": "key",
        }
    ]


def test_verify_searches_deleted_requires_each_search_to_404(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[str] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append(path)
        return {
            "status": 404,
            "content_type": "application/json; charset=utf-8",
            "json": {"error": "NOT_FOUND", "message": "search not found"},
            "raw_json": {
                "error": {
                    "code": "NOT_FOUND",
                    "message": "search not found",
                    "details": {},
                }
            },
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.verify_searches_deleted("http://127.0.0.1:1", "key", ["42", "43"])

    assert result["checked"] == 2
    assert requests == ["/api/v1/searches/42", "/api/v1/searches/43"]


def test_clear_completed_transfers_uses_confirmation_payload(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"ok": True},
            "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.clear_completed_transfers("http://127.0.0.1:1", "key")

    assert result["status"] == 200
    assert requests == [
        {
            "path": "/api/v1/transfers/operations/clear-completed",
            "method": "POST",
            "api_key": "key",
            "json_body": {"confirmClearCompleted": True},
        }
    ]


def test_clear_logs_uses_confirmation_payload(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"ok": True},
            "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.clear_logs("http://127.0.0.1:1", "key")

    assert result["status"] == 200
    assert requests == [
        {
            "path": "/api/v1/logs/operations/clear",
            "method": "POST",
            "api_key": "key",
            "json_body": {"confirmClearLogs": True},
        }
    ]


def test_extract_triggered_transfer_hashes_uses_live_transfer_response() -> None:
    module = load_rest_api_smoke_module()

    cycles = [
        {
            "download_trigger": {
                "ok": True,
                "transfer": {
                    "json": {
                        "hash": "0123456789abcdef0123456789abcdef",
                    },
                },
            },
        },
        {
            "download_trigger": {
                "ok": True,
                "transfer": {
                    "json": {
                        "hash": "0123456789ABCDEF0123456789ABCDEF",
                    },
                },
            },
        },
        {"download_trigger": {"ok": False}},
    ]

    assert module.extract_triggered_transfer_hashes(cycles) == ["0123456789abcdef0123456789abcdef"]


def test_verify_transfers_still_exist_requires_hash_match(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[str] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append(path)
        transfer_hash = path.rsplit("/", 1)[-1]
        return {
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "json": {"hash": transfer_hash},
            "raw_json": {
                "data": {"hash": transfer_hash},
                "meta": {"apiVersion": "v1"},
            },
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.verify_transfers_still_exist(
        "http://127.0.0.1:1",
        "key",
        ["0123456789abcdef0123456789abcdef"],
    )

    assert result["checked"] == 1
    assert requests == ["/api/v1/transfers/0123456789abcdef0123456789abcdef"]


def test_live_download_candidate_filter_rejects_unsafe_rows() -> None:
    module = load_rest_api_smoke_module()

    safe = {
        "hash": "0123456789abcdef0123456789abcdef",
        "name": "linux.iso",
        "sizeBytes": 1024,
        "fileType": "Iso",
        "sources": module.MIN_SAFE_LIVE_DOWNLOAD_SOURCES,
        "completeSources": 0,
    }

    assert module.is_safe_live_download_result(safe) is True
    assert module.is_safe_live_download_result({**safe, "name": "setup.exe"}) is False
    assert module.is_safe_live_download_result({**safe, "name": "installer.msi"}) is False
    assert module.is_safe_live_download_result({**safe, "name": "clip.mp4"}) is False
    assert module.is_safe_live_download_result({**safe, "name": "bundle.rar", "fileType": "Arc"}) is False
    assert module.is_safe_live_download_result({**safe, "fileType": "Pro"}) is False
    assert module.is_safe_live_download_result({**safe, "name": "linux xxx sample.iso"}) is False
    assert module.is_safe_live_download_result({**safe, "hash": "0123456789ABCDEF0123456789ABCDEF"}) is False
    assert module.is_safe_live_download_result({**safe, "sizeBytes": 0}) is False
    assert module.is_safe_live_download_result({**safe, "sizeBytes": module.MAX_SAFE_LIVE_DOWNLOAD_BYTES + 1}) is False
    assert module.is_safe_live_download_result({**safe, "sources": module.MIN_SAFE_LIVE_DOWNLOAD_SOURCES - 1}) is False


def test_live_download_trigger_posts_paused_download(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    requests: list[dict[str, object]] = []

    def fake_http_request(_base_url, path, **kwargs):
        requests.append({"path": path, **kwargs})
        if path.endswith("/operations/download"):
            return {
                "status": 200,
                "content_type": "application/json",
                "json": {"ok": True},
                "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}},
                "body_text": "{}",
            }
        if path == "/api/v1/transfers/0123456789abcdef0123456789abcdef":
            return {
                "status": 200,
                "content_type": "application/json",
                "json": {
                    "hash": "0123456789abcdef0123456789abcdef",
                    "name": "linux.iso",
                    "sizeBytes": 1024,
                    "complete": False,
                },
                "raw_json": {
                    "data": {
                        "hash": "0123456789abcdef0123456789abcdef",
                        "name": "linux.iso",
                        "sizeBytes": 1024,
                        "complete": False,
                    },
                    "meta": {"apiVersion": "v1"},
                },
                "body_text": "{}",
            }
        return {
            "status": 200,
            "content_type": "application/json",
            "json": {
                "id": "42",
                "query": "linux",
                "method": "kad",
                "type": "iso",
                "status": "running",
                "items": [
                    {
                        "method": "kad",
                        "type": "iso",
                        "hash": "0123456789abcdef0123456789abcdef",
                        "name": "linux.iso",
                        "sizeBytes": 1024,
                        "fileType": "Iso",
                        "sources": 2,
                        "completeSources": 0,
                    }
                ],
                "total": 1,
                "offset": 0,
                "limit": 100,
            },
            "raw_json": {
                "data": {
                    "id": "42",
                    "query": "linux",
                    "method": "kad",
                    "type": "iso",
                    "status": "running",
                    "items": [
                        {
                            "method": "kad",
                            "type": "iso",
                            "hash": "0123456789abcdef0123456789abcdef",
                            "name": "linux.iso",
                            "sizeBytes": 1024,
                            "fileType": "Iso",
                            "sources": 2,
                            "completeSources": 0,
                        }
                    ],
                    "total": 1,
                    "offset": 0,
                    "limit": 100,
                },
                "meta": {"apiVersion": "v1"},
            },
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.trigger_paused_download_from_search_result("http://127.0.0.1:1", "key", "42", 1.0)

    assert result["ok"] is True
    assert requests[-2]["path"] == "/api/v1/searches/42/results/0123456789abcdef0123456789abcdef/operations/download"
    assert requests[-2]["json_body"] == {"paused": True, "categoryId": 0}
    assert requests[-1]["path"] == "/api/v1/transfers/0123456789abcdef0123456789abcdef"
    assert result["transfer"]["status"] == 200


def test_triggered_transfer_wait_rejects_hash_mismatch(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    def fake_http_request(_base_url, _path, **_kwargs):
        return {
            "status": 200,
            "content_type": "application/json",
            "json": {"hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "raw_json": {
                "data": {"hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                "meta": {"apiVersion": "v1"},
            },
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    with pytest.raises(AssertionError, match="hash mismatch"):
        module.wait_for_triggered_transfer(
            "http://127.0.0.1:1",
            "key",
            "0123456789abcdef0123456789abcdef",
            1.0,
        )


def test_live_download_trigger_timeout_without_candidate_is_nonfatal(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    def fake_http_request(_base_url, _path, **_kwargs):
        return {
            "status": 200,
            "content_type": "application/json",
            "json": {
                "id": "42",
                "query": "linux",
                "method": "kad",
                "type": "",
                "status": "running",
                "items": [],
                "total": 0,
                "offset": 0,
                "limit": 100,
            },
            "raw_json": {
                "data": {
                    "id": "42",
                    "query": "linux",
                    "method": "kad",
                    "type": "",
                    "status": "running",
                    "items": [],
                    "total": 0,
                    "offset": 0,
                    "limit": 100,
                },
                "meta": {"apiVersion": "v1"},
            },
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.trigger_paused_download_from_search_result("http://127.0.0.1:1", "key", "42", 0.01)

    assert result["ok"] is False
    assert result["reason"] == "timed out without a safe download candidate"
    assert result["observations"]


def test_rest_stress_config_rejects_invalid_values() -> None:
    module = load_rest_api_smoke_module()

    with pytest.raises(ValueError, match="duration"):
        module.validate_rest_stress_config(
            budget="smoke",
            duration_seconds=0,
            concurrency=1,
            max_failures=0,
            request_timeout_seconds=1,
        )
    with pytest.raises(ValueError, match="concurrency"):
        module.validate_rest_stress_config(
            budget="smoke",
            duration_seconds=1,
            concurrency=0,
            max_failures=0,
            request_timeout_seconds=1,
        )


def test_rest_stress_operations_include_safe_mutation_routes() -> None:
    module = load_rest_api_smoke_module()

    operations = module.build_rest_stress_operations("smoke")
    method_path_pairs = {(operation["method"], operation["path"]) for operation in operations}
    operations_by_pair = {(operation["method"], operation["path"]): operation for operation in operations}

    assert ("GET", "/api/v1/status") in method_path_pairs
    assert ("GET", "/api/v1/shared-directories") in method_path_pairs
    assert operations_by_pair[("GET", "/api/v1/status")]["expected_statuses"] == (200,)
    assert ("PATCH", "/api/v1/app/preferences") in method_path_pairs
    assert ("POST", "/api/v1/transfers") in method_path_pairs
    assert ("POST", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/operations/pause") in method_path_pairs
    transfer_files_delete_path = f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/files?confirm=false"
    assert ("DELETE", transfer_files_delete_path) in method_path_pairs
    assert operations_by_pair[("DELETE", transfer_files_delete_path)][
        "expected_statuses"
    ] == (400,)
    assert operations_by_pair[("DELETE", transfer_files_delete_path)][
        "scenario"
    ] == "transfer_file_delete_requires_confirm"
    assert ("POST", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/sources/{module.REST_SURFACE_MISSING_HASH}/operations/browse") in method_path_pairs
    assert operations_by_pair[
        ("POST", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/sources/{module.REST_SURFACE_MISSING_HASH}/operations/browse")
    ]["json_body"] == {}
    assert operations_by_pair[("POST", "/api/v1/logs/operations/clear")]["json_body"] == {"confirmClearLogs": True}
    assert ("POST", "/api/v1/kad/operations/recheck-firewall") in method_path_pairs
    assert ("POST", "/api/v1/searches") in method_path_pairs
    assert ("DELETE", "/api/v1/searches/123") in method_path_pairs


def test_shutdown_is_excluded_from_broad_stress_mutation_loops() -> None:
    module = load_rest_api_smoke_module()

    audit = module.assert_shutdown_excluded_from_broad_mutation_loops()

    assert audit["ok"] is True
    assert "/api/v1/app/shutdown" in audit["excluded_paths"]
    assert "/api/v1/diagnostics/dumps" in audit["excluded_paths"]
    assert "/api/v1/diagnostics/crash-tests" in audit["excluded_paths"]
    assert set(audit["stress_budgets"]) == {"smoke", "soak"}
    for budget in ("smoke", "soak"):
        operations = module.build_rest_stress_operations(budget)
        assert all(operation["path"] != "/api/v1/app/shutdown" for operation in operations)
        assert all(operation["path"] != "/api/v1/diagnostics/dumps" for operation in operations)
        assert all(operation["path"] != "/api/v1/diagnostics/crash-tests" for operation in operations)
        assert audit["stress_budgets"][budget]["unsafe_path_match_count"] == 0
        assert audit["stress_budgets"][budget]["operation_count"] == len(operations)
    routes_by_operation = {route["operationId"]: route for route in audit["contract_routes"]}
    assert set(routes_by_operation) == {"captureDiagnosticDump", "shutdownApp", "triggerDiagnosticCrashTest"}
    assert routes_by_operation["shutdownApp"]["path"] == "/api/v1/app/shutdown"
    assert routes_by_operation["shutdownApp"]["safe"] is False
    assert routes_by_operation["shutdownApp"]["safety"] == "unsafe"
    assert routes_by_operation["captureDiagnosticDump"]["path"] == "/api/v1/diagnostics/dumps"
    assert routes_by_operation["captureDiagnosticDump"]["safe"] is False
    assert routes_by_operation["captureDiagnosticDump"]["safety"] == "unsafe"
    assert routes_by_operation["triggerDiagnosticCrashTest"]["path"] == "/api/v1/diagnostics/crash-tests"
    assert routes_by_operation["triggerDiagnosticCrashTest"]["safe"] is False
    assert routes_by_operation["triggerDiagnosticCrashTest"]["safety"] == "unsafe"


def test_rest_stress_operations_include_expected_error_edges() -> None:
    module = load_rest_api_smoke_module()

    operations = module.build_rest_stress_operations("smoke")
    operations_by_pair = {(operation["method"], operation["path"]): operation for operation in operations}

    assert operations_by_pair[("GET", "/api/v1/logs?limit=%2x")]["scenario"] == "malformed_percent_escape"
    assert operations_by_pair[("GET", "/api/v1/logs?limit=%2x")]["expected_statuses"] == (400,)
    assert operations_by_pair[("GET", "/api/v1/logs%2x?limit=10")]["scenario"] == "malformed_route_escape"
    assert operations_by_pair[("GET", "/api/v1/logs?limit=10&limit=20")]["scenario"] == "duplicate_query_parameter"
    assert operations_by_pair[("get", "/api/v1/app")]["scenario"] == "lowercase_method_rejected"
    assert operations_by_pair[("get", "/api/v1/app")]["expected_statuses"] == (400,)
    assert operations_by_pair[
        ("GET", "/api/v1/transfers/0123456789ABCDEF0123456789ABCDEF")
    ]["scenario"] == "uppercase_hash_rejected"
    assert operations_by_pair[
        ("GET", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/details")
    ]["scenario"] == "missing_transfer_details_rejected"
    assert operations_by_pair[
        ("GET", f"/api/v1/transfers/{module.REST_SURFACE_MISSING_HASH}/details")
    ]["expected_statuses"] == (404,)
    assert operations_by_pair[("POST", "/api/v1/transfers")]["expected_statuses"] == (400,)
    assert any(
        operation["scenario"] == "conflicting_category_fields"
        and operation["expected_statuses"] == (400,)
        for operation in operations
    )
    assert any(
        operation["scenario"] == "unicode_query_length_rejected"
        and operation["expected_statuses"] == (400,)
        and "λ" in operation["json_body"]["query"]
        for operation in operations
    )
    assert any(
        operation["scenario"] == "long_unicode_shared_file_path_rejected"
        and operation["expected_statuses"] == (400,)
        and "λ" in operation["json_body"]["path"]
        and "例" in operation["json_body"]["path"]
        and "\\" not in operation["json_body"]["path"]
        for operation in operations
    )


def test_rest_stress_operations_include_adapter_traffic_without_legacy_html() -> None:
    module = load_rest_api_smoke_module()

    operations = module.build_rest_stress_operations("smoke")
    operations_by_pair = {(operation["method"], operation["path"]): operation for operation in operations}

    assert operations_by_pair[("GET", "/indexer/emulebb/api?t=caps")]["response_kind"] == "xml"
    assert operations_by_pair[("GET", "/indexer/emulebb/api?t=caps&t=search")]["expected_statuses"] == (400,)
    assert operations_by_pair[("GET", "/indexer/emulebb/api?t=caps&apikey=wrong-key")]["expected_statuses"] == (401,)
    assert operations_by_pair[
        ("GET", "/indexer/emulebb/api?t=search&season=abc&q=linux&apikey={api_key}")
    ]["api_key"] is False
    assert operations_by_pair[
        ("GET", "/indexer/emulebb/api?t=search&cat=abc&q=linux&apikey={api_key}")
    ]["expected_statuses"] == (400,)
    assert operations_by_pair[("GET", "/api/v2/app/webapiVersion")]["response_kind"] == "text"
    assert any(
        operation["method"] == "GET"
        and operation["path"] == "/api/v2/torrents/categories"
        and operation["scenario"] == "qbit_categories"
        and operation["extra_headers"] == {"Cookie": "{qbit_session_cookie}"}
        for operation in operations
    )
    assert any(
        operation["method"] == "GET"
        and operation["path"] == "/api/v2/torrents/categories"
        and operation["scenario"] == "qbit_wrong_cookie_rejected"
        and operation["expected_statuses"] == (403,)
        and operation["extra_headers"] == {"Cookie": "SID=wrong"}
        for operation in operations
    )
    assert any(
        operation["method"] == "POST"
        and operation["path"] == "/api/v2/auth/login"
        and operation["scenario"] == "qbit_bad_login_rejected"
        and operation["raw_body"] == "username=emule&password=wrong-key"
        and operation["expected_statuses"] == (200,)
        and operation["expected_body_contains"] == "Fails."
        for operation in operations
    )
    assert operations_by_pair[
        ("GET", f"/api/v2/torrents/properties?hash={module.REST_SURFACE_MISSING_HASH}")
    ]["expected_statuses"] == (404,)
    assert operations_by_pair[("POST", "/api/v2/torrents/pause")]["raw_body"] == f"hashes={module.REST_SURFACE_MISSING_HASH}"
    assert any(
        operation["method"] == "POST"
        and operation["path"] == "/api/v2/torrents/delete"
        and operation["scenario"] == "qbit_missing_hash_delete"
        and operation["raw_body"] == f"hashes={module.REST_SURFACE_MISSING_HASH}&deleteFiles=false"
        and operation["expected_statuses"] == (200,)
        for operation in operations
    )
    assert any(
        operation["method"] == "POST"
        and operation["path"] == "/api/v2/torrents/delete"
        and operation["scenario"] == "qbit_bad_delete_boolean_rejected"
        and operation["raw_body"] == f"hashes={module.REST_SURFACE_MISSING_HASH}&deleteFiles=wat"
        and operation["expected_statuses"] == (400,)
        for operation in operations
    )
    assert any(
        operation["method"] == "POST"
        and operation["path"] == "/api/v2/torrents/setForceStart"
        and operation["scenario"] == "qbit_bad_force_start_boolean_rejected"
        and operation["raw_body"] == f"hashes={module.REST_SURFACE_MISSING_HASH}&value=wat"
        and operation["expected_statuses"] == (400,)
        for operation in operations
    )
    assert ("GET", "/") not in operations_by_pair
    assert all(operation.get("family") != "legacy-html" for operation in operations)
    assert all(operation.get("response_kind") != "html" for operation in operations)


def test_rest_stress_summary_is_bounded_and_deterministic() -> None:
    module = load_rest_api_smoke_module()

    summary = module.summarize_rest_stress_results(
        [
            {
                "path": "/ok",
                "status": 200,
                "ok": True,
                "duration_ms": 1.0,
                "scenario": "read",
                "content_type": "application/json; charset=utf-8",
                "native_rest_json": True,
            },
            {
                "path": "/missing",
                "status": 404,
                "ok": True,
                "duration_ms": 4.0,
                "scenario": "safe_mutation",
                "content_type": "application/json; charset=utf-8",
                "native_rest_json": True,
            },
            {
                "path": "/boom",
                "status": "exception",
                "ok": False,
                "duration_ms": 9.0,
                "error": "timeout",
                "scenario": "read",
                "content_type": "application/xml",
                "native_rest_json": False,
            },
        ],
        budget="smoke",
        duration_seconds=30.0,
        concurrency=4,
        max_failures=1,
    )

    assert summary["ok"] is True
    assert summary["budget"] == "smoke"
    assert summary["requests_completed"] == 3
    assert summary["status_counts"] == {"200": 1, "404": 1, "exception": 1}
    assert summary["method_counts"] == {"UNKNOWN": 3}
    assert summary["scenario_counts"] == {"read": 2, "safe_mutation": 1}
    assert summary["content_type_counts"] == {"application/json; charset=utf-8": 2, "application/xml": 1}
    assert summary["error_counts"] == {"timeout": 1}
    assert summary["timeout_count"] == 1
    assert summary["native_rest_non_json_count"] == 1
    assert summary["retry_attempt_count"] == 0
    assert summary["retried_success_count"] == 0
    assert summary["retried_failure_count"] == 0
    assert summary["operation_coverage"] is None
    assert summary["latency_ms"]["max"] == 9.0
    assert len(summary["failures_sample"]) == 1
    assert "path" not in summary["failures_sample"][0]
    assert summary["failures_sample"][0]["operation_key"] == "UNKNOWN /boom [read]"
    assert [row["duration_ms"] for row in summary["slowest_requests_sample"]] == [9.0, 4.0, 1.0]
    assert [row["operation_key"] for row in summary["slowest_requests_sample"]] == [
        "UNKNOWN /boom [read]",
        "UNKNOWN /missing [safe_mutation]",
        "UNKNOWN /ok [read]",
    ]


def test_rest_stress_summary_reports_operation_coverage_starvation() -> None:
    module = load_rest_api_smoke_module()

    operations = [
        {"method": "GET", "path": "/api/v1/server", "scenario": "read"},
        {"method": "GET", "path": "/api/v1/transfers", "scenario": "read"},
        {"method": "POST", "path": "/api/v1/searches", "scenario": "safe_mutation"},
    ]
    summary = module.summarize_rest_stress_results(
        [
            {
                "operation_key": module.rest_stress_operation_key(operations[0]),
                "method": "GET",
                "path": "/api/v1/server",
                "status": 200,
                "ok": True,
                "scenario": "read",
            },
            {
                "operation_key": module.rest_stress_operation_key(operations[0]),
                "method": "GET",
                "path": "/api/v1/server",
                "status": 200,
                "ok": True,
                "scenario": "read",
            },
            {
                "operation_key": module.rest_stress_operation_key(operations[1]),
                "method": "GET",
                "path": "/api/v1/transfers",
                "status": 200,
                "ok": True,
                "scenario": "read",
            },
        ],
        budget="smoke",
        duration_seconds=30.0,
        concurrency=4,
        max_failures=0,
        operations=operations,
    )

    assert summary["ok"] is False
    assert summary["failure_count"] == 0
    assert summary["operation_coverage"] == {
        "expected_operation_count": 3,
        "observed_operation_count": 2,
        "missed_operation_count": 1,
        "missed_operations_sample": ["POST /api/v1/searches [safe_mutation]"],
        "unexpected_operation_count": 0,
        "min_observed_per_operation": 0,
        "max_observed_per_operation": 2,
        "full_cycle_reached": True,
        "ok": False,
    }


def test_rest_stress_summary_does_not_fail_coverage_before_full_cycle() -> None:
    module = load_rest_api_smoke_module()

    operations = [
        {"method": "GET", "path": "/api/v1/server", "scenario": "read"},
        {"method": "GET", "path": "/api/v1/transfers", "scenario": "read"},
    ]
    summary = module.summarize_rest_stress_results(
        [
            {
                "operation_key": module.rest_stress_operation_key(operations[0]),
                "method": "GET",
                "path": "/api/v1/server",
                "status": 200,
                "ok": True,
                "scenario": "read",
            },
        ],
        budget="smoke",
        duration_seconds=0.1,
        concurrency=1,
        max_failures=0,
        operations=operations,
    )

    assert summary["ok"] is True
    assert summary["operation_coverage"]["full_cycle_reached"] is False
    assert summary["operation_coverage"]["missed_operation_count"] == 1


def test_rest_stress_retry_classification_is_limited_to_transient_resets() -> None:
    module = load_rest_api_smoke_module()

    assert module.is_retryable_rest_stress_exception(
        RuntimeError("<urlopen error [WinError 10054] An existing connection was forcibly closed by the remote host>")
    )
    assert module.is_retryable_rest_stress_exception(
        RuntimeError("[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol")
    )
    assert not module.is_retryable_rest_stress_exception(
        RuntimeError("<urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>")
    )
    assert not module.is_retryable_rest_stress_exception(TimeoutError("timed out"))
    assert module.is_retryable_rest_stress_response(
        {
            "status": 503,
            "content_type": "text/plain; charset=utf-8",
            "body_text": "eMuleBB web API is busy\n",
        }
    )
    assert not module.is_retryable_rest_stress_response(
        {
            "status": 503,
            "content_type": "application/json; charset=utf-8",
            "body_text": '{"error":"EMULE_UNAVAILABLE"}',
        }
    )


def test_rest_stress_caps_inflight_workers_to_accepted_client_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()
    active_workers = 0
    peak_workers = 0

    monkeypatch.setattr(
        module,
        "build_rest_stress_operations",
        lambda _budget: [
            {
                "method": "GET",
                "path": "/api/v1/app",
                "family": "app",
                "scenario": "read",
                "expected_statuses": (200,),
                "response_kind": "text",
            }
        ],
    )

    def fake_http_request(*_args, **_kwargs):
        nonlocal active_workers, peak_workers
        active_workers += 1
        peak_workers = max(peak_workers, active_workers)
        try:
            time.sleep(0.01)
            return {"status": 200, "content_type": "text/plain", "body_text": "ok", "json": None, "raw_json": None}
        finally:
            active_workers -= 1

    monkeypatch.setattr(module, "http_request", fake_http_request)

    summary = module.exercise_rest_stress(
        "https://127.0.0.1:4711",
        "api-key",
        budget="smoke",
        duration_seconds=0.04,
        concurrency=4,
        max_failures=0,
        request_timeout_seconds=1.0,
    )

    assert summary["requested_concurrency"] == 4
    assert summary["effective_concurrency"] == module.REST_STRESS_ACCEPTED_CLIENT_THREAD_LIMIT
    assert peak_workers == module.REST_STRESS_ACCEPTED_CLIENT_THREAD_LIMIT


def test_rest_stress_response_error_classification_is_specific() -> None:
    module = load_rest_api_smoke_module()

    assert module.classify_rest_stress_response_error(
        expected_match=True,
        response_kind_match=True,
        body_match=True,
        native_rest_json=True,
    ) is None
    assert module.classify_rest_stress_response_error(
        expected_match=False,
        response_kind_match=False,
        body_match=False,
        native_rest_json=False,
    ) == "status mismatch"
    assert module.classify_rest_stress_response_error(
        expected_match=True,
        response_kind_match=False,
        body_match=False,
        native_rest_json=False,
    ) == "response kind mismatch"
    assert module.classify_rest_stress_response_error(
        expected_match=True,
        response_kind_match=True,
        body_match=False,
        native_rest_json=False,
    ) == "response body mismatch"
    assert module.classify_rest_stress_response_error(
        expected_match=True,
        response_kind_match=True,
        body_match=True,
        native_rest_json=False,
    ) == "native REST JSON mismatch"


def test_rest_stress_summary_reports_retry_recovery() -> None:
    module = load_rest_api_smoke_module()

    summary = module.summarize_rest_stress_results(
        [
            {"status": 200, "ok": True, "duration_ms": 2.0, "retry_count": 1},
            {"status": "exception", "ok": False, "duration_ms": 3.0, "retry_count": 2, "error": "reset"},
        ],
        budget="soak",
        duration_seconds=30.0,
        concurrency=64,
        max_failures=1,
    )

    assert summary["ok"] is True
    assert summary["retry_attempt_count"] == 3
    assert summary["retried_success_count"] == 1
    assert summary["retried_failure_count"] == 1


def test_rest_stress_https_resource_gate_reports_snapshots(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        module,
        "build_rest_stress_operations",
        lambda _budget: [
            {
                "method": "GET",
                "path": "/api/v1/app",
                "family": "native-rest",
                "scenario": "read",
                "expected_statuses": (200,),
                "response_kind": "text",
            }
        ],
    )
    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {"status": 200, "content_type": "text/plain", "body_text": "ok", "json": None, "raw_json": None},
    )
    monkeypatch.setattr(
        module,
        "get_process_resource_snapshot",
        lambda _pid: {
            "handles": 10,
            "thread_count": 4,
            "gdi_objects": 1,
            "user_objects": 1,
            "private_bytes": 4096,
            "working_set_bytes": 8192,
        },
    )

    summary = module.exercise_rest_stress(
        "https://127.0.0.1:4711",
        "api-key",
        budget="smoke",
        duration_seconds=0.02,
        concurrency=1,
        max_failures=0,
        request_timeout_seconds=1.0,
        process_id=123,
        resource_gate_enabled=True,
    )

    assert summary["ok"] is True
    assert summary["resource_gate_enabled"] is True
    assert summary["resource_observability"]["ok"] is True
    assert summary["resource_thresholds"]["ok"] is True
    assert set(summary["resource_snapshots"]) == {"before", "peak", "after_drain"}


def test_rest_stress_resource_gate_fails_threshold_violations(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        module,
        "build_rest_stress_operations",
        lambda _budget: [
            {
                "method": "GET",
                "path": "/api/v1/app",
                "family": "native-rest",
                "scenario": "read",
                "expected_statuses": (200,),
                "response_kind": "text",
            }
        ],
    )
    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {"status": 200, "content_type": "text/plain", "body_text": "ok", "json": None, "raw_json": None},
    )
    snapshot_calls = 0

    def fake_snapshot(_pid):
        nonlocal snapshot_calls
        snapshot_calls += 1
        if snapshot_calls == 1:
            return {
                "handles": 10,
                "thread_count": 4,
                "gdi_objects": 1,
                "user_objects": 1,
                "private_bytes": 4096,
                "working_set_bytes": 8192,
            }
        return {
            "handles": 10,
            "thread_count": 4,
            "gdi_objects": 1,
            "user_objects": 1,
            "private_bytes": 512 * 1024 * 1024,
            "working_set_bytes": 512 * 1024 * 1024,
        }

    monkeypatch.setattr(module, "get_process_resource_snapshot", fake_snapshot)

    with pytest.raises(AssertionError, match="REST stress resource thresholds exceeded"):
        module.exercise_rest_stress(
            "https://127.0.0.1:4711",
            "api-key",
            budget="smoke",
            duration_seconds=0.01,
            concurrency=1,
            max_failures=0,
            request_timeout_seconds=1.0,
            process_id=123,
            resource_gate_enabled=True,
        )


def test_server_connect_transport_loss_is_runtime_failure_signal() -> None:
    module = load_rest_api_smoke_module()

    assert module.did_rest_listener_disappear(
        [
            {"connected": False},
            {"transport_error": {"message": "<urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>"}},
        ]
    )
    assert not module.did_rest_listener_disappear([{"connected": False, "connecting": False}])


def test_close_app_cleanly_with_timing_records_shutdown_duration() -> None:
    module = load_rest_api_smoke_module()
    closed: list[object] = []

    result = module.close_app_cleanly_with_timing("app", close_func=closed.append)

    assert closed == ["app"]
    assert result["app_closed"] is True
    assert isinstance(result["shutdown_duration_ms"], float)
    assert result["shutdown_duration_ms"] >= 0.0


def test_rest_contract_completeness_skips_shutdown(monkeypatch) -> None:
    module = load_rest_api_smoke_module()
    observed_paths: list[tuple[str, str]] = []

    def fake_http_request(_base_url, path, *, method="GET", **_kwargs):
        observed_paths.append((method, path))
        return {
            "status": 200,
            "content_type": "application/json",
            "json": {"ok": True},
            "raw_json": {"data": {"ok": True}, "meta": {"apiVersion": "v1"}},
            "body_text": "{}",
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)
    monkeypatch.setattr(module, "validate_openapi_response_payload", lambda *_args, **_kwargs: None)

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is True
    assert ("POST", "/api/v1/app/shutdown") not in observed_paths
    assert ("POST", "/api/v1/diagnostics/dumps") not in observed_paths
    assert ("POST", "/api/v1/diagnostics/crash-tests") not in observed_paths
    assert any(route["operationId"] == "shutdownApp" and route["skipped"] for route in summary["routes"])
    assert any(route["operationId"] == "captureDiagnosticDump" and route["skipped"] for route in summary["routes"])
    assert any(route["operationId"] == "triggerDiagnosticCrashTest" and route["skipped"] for route in summary["routes"])


def test_rest_contract_completeness_rejects_undeclared_4xx(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "REST_CONTRACT_ROUTES",
        (
            {
                "name": "getApp",
                "operationId": "getApp",
                "family": "app",
                "method": "GET",
                "path": "/api/v1/app",
                "safe": True,
                "safety": "safe",
                "hasRequestBody": False,
                "requestBodyRequired": False,
                "successResponseStatuses": ["200"],
                "successResponseRefs": ["AppResponse"],
                "responseEnvelope": "AppResponse",
            },
        ),
    )
    monkeypatch.setattr(module, "assert_contract_routes_match_openapi", lambda: {"ok": True})
    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 400,
            "content_type": "application/json",
            "json": {"error": "INVALID_ARGUMENT", "message": "bad request"},
            "raw_json": {"error": {"code": "INVALID_ARGUMENT", "message": "bad request", "details": {}}},
            "body_text": "{}",
        },
    )

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is False
    assert summary["failed_routes"] == ["getApp"]
    assert summary["routes"][0]["outcome"] == "unexpected_error"
    assert summary["routes"][0]["expectedResponseStatuses"] == [200]


def test_rest_contract_completeness_accepts_declared_negative_probe(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "REST_CONTRACT_ROUTES",
        (
            {
                "name": "createSearch",
                "operationId": "createSearch",
                "family": "searches",
                "method": "POST",
                "path": "/api/v1/searches",
                "safe": True,
                "safety": "safe",
                "hasRequestBody": True,
                "requestBodyRequired": True,
                "successResponseStatuses": ["200"],
                "successResponseRefs": ["SearchResponse"],
                "responseEnvelope": "SearchResponse",
            },
        ),
    )
    monkeypatch.setattr(module, "assert_contract_routes_match_openapi", lambda: {"ok": True})
    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 400,
            "content_type": "application/json",
            "json": {"error": "INVALID_ARGUMENT", "message": "query is required"},
            "raw_json": {"error": {"code": "INVALID_ARGUMENT", "message": "query is required", "details": {}}},
            "body_text": "{}",
        },
    )

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is True
    assert summary["expected_error_count"] == 1
    assert summary["failed_routes"] == []
    assert summary["routes"][0]["outcome"] == "expected_error"
    assert summary["routes"][0]["expectedResponseStatuses"] == [200, 400]


def test_rest_contract_completeness_accepts_category_create_negative_probe(monkeypatch) -> None:
    module = load_rest_api_smoke_module()

    monkeypatch.setattr(
        module,
        "REST_CONTRACT_ROUTES",
        (
            {
                "name": "createCategory",
                "operationId": "createCategory",
                "family": "categories",
                "method": "POST",
                "path": "/api/v1/categories",
                "safe": True,
                "safety": "safe",
                "hasRequestBody": True,
                "requestBodyRequired": True,
                "successResponseStatuses": ["200"],
                "successResponseRefs": ["CategoryResponse"],
                "responseEnvelope": "CategoryResponse",
            },
        ),
    )
    monkeypatch.setattr(module, "assert_contract_routes_match_openapi", lambda: {"ok": True})
    monkeypatch.setattr(
        module,
        "http_request",
        lambda *_args, **_kwargs: {
            "status": 400,
            "content_type": "application/json",
            "json": {"error": "INVALID_ARGUMENT", "message": "name is required"},
            "raw_json": {"error": {"code": "INVALID_ARGUMENT", "message": "name is required", "details": {}}},
            "body_text": "{}",
        },
    )

    summary = module.exercise_rest_contract_completeness("http://127.0.0.1:1", "key", "contract")

    assert summary["ok"] is True
    assert summary["expected_error_count"] == 1
    assert summary["routes"][0]["operationId"] == "createCategory"
    assert summary["routes"][0]["expectedResponseStatuses"] == [200, 400]
