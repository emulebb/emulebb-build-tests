from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import urllib.request


def load_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "smoke-rust-openvpn.py"
    spec = importlib.util.spec_from_file_location("rust_openvpn_smoke_under_test", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_run_search_reads_canonical_items_and_total(monkeypatch) -> None:
    module = load_module()
    requests: list[tuple[str, str, dict[str, object] | None]] = []

    def request_json(
        url: str,
        _key: str,
        *,
        method: str = "GET",
        payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        requests.append((url, method, payload))
        if method == "POST":
            return {"data": {"id": "7"}}
        if method == "DELETE":
            return {"data": {}}
        return {
            "data": {
                "status": "complete",
                "items": [{"hash": "a" * 32}, {"hash": "b" * 32}],
                "total": 5,
            }
        }

    monkeypatch.setattr(module, "request_json", request_json)
    result = module.run_search(
        "http://127.0.0.1:14712/api/v1",
        "secret",
        method="server",
        query="ubuntu",
        timeout_seconds=60,
    )

    assert result["maximumResultCount"] == 5
    assert result["finalStatus"] == "complete"
    assert result["samples"][-1]["resultCount"] == 5
    assert result["samples"][-1]["pageItemCount"] == 2
    assert [row[1] for row in requests] == ["POST", "GET", "DELETE"]


def test_openvpn_compose_allows_an_explicit_empty_interface_binding() -> None:
    compose = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "rust-openvpn"
        / "compose.yaml"
    ).read_text(encoding="utf-8")

    assert "${EMULEBB_TEST_P2P_INTERFACE-tun0}" in compose
    assert "${EMULEBB_TEST_RUST_LOG-info}" in compose
    assert "${EMULEBB_TEST_RUST_IMAGE-ghcr.io/emulebb/emulebb-rust:0.1.0-beta.1}" in compose


def test_openvpn_smoke_exposes_controlled_tunnel_delay() -> None:
    script = (
        Path(__file__).resolve().parents[2] / "scripts" / "smoke-rust-openvpn.py"
    ).read_text(encoding="utf-8")

    assert '"--tunnel-egress-delay-ms"' in script
    assert '"netem"' in script


def test_openvpn_smoke_includes_tunnel_failure_accounting_and_recovery() -> None:
    script = (
        Path(__file__).resolve().parents[2] / "scripts" / "smoke-rust-openvpn.py"
    ).read_text(encoding="utf-8")

    assert '"stop", "--timeout", "10", "openvpn"' in script
    assert '"start", "openvpn"' in script
    assert '"restart", "emulebb-rust"' in script
    assert "rustRestartedForNamespaceRecovery" in script
    assert "compare_after_local_failure" in script
    assert "offTunnelPacketCount" in script


def test_reachability_treats_connection_reset_as_not_ready(monkeypatch) -> None:
    module = load_module()

    def reset(*_args, **_kwargs):
        raise ConnectionResetError(104, "reset")

    monkeypatch.setattr(urllib.request, "urlopen", reset)

    assert module.url_is_reachable("http://127.0.0.1:14712/status", "key") is False
