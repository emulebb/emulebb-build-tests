from __future__ import annotations

import copy
from pathlib import Path

import pytest

from emule_test_harness import nat_live_matrix, rust_metadata
from emule_test_harness.workspace_layout import resolve_selected_workspace_repo


def test_vpn_address_gateway_and_igd_match_port_forward_helper_semantics() -> None:
    assert (
        nat_live_matrix.tunnel_ipv4(
            "7: tun0 inet 10.46.56.2/24 scope global tun0\n"
        )
        == "10.46.56.2"
    )
    assert (
        nat_live_matrix.tunnel_gateway(
            "10.46.56.0/24 dev tun0 scope link src 10.46.56.2\n"
            "10.46.56.1 dev tun0 scope link\n"
        )
        == "10.46.56.1"
    )
    assert (
        nat_live_matrix.tunnel_gateway("default via 10.8.0.1 dev tun0\n")
        == "10.8.0.1"
    )
    assert nat_live_matrix.igd_ipv4("http://10.255.255.250:1900/gateDesc.xml") == (
        "10.255.255.250"
    )


def status(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "enabled": True,
        "gatewayDiscovered": False,
        "backend": None,
        "protocol": None,
        "bindIp": None,
        "pcpServerIp": None,
        "igdIp": None,
        "mappings": [],
        "lastError": None,
    }
    value.update(overrides)
    return {"data": value}


def test_matrix_cases_cover_default_isolated_and_forced_fallback() -> None:
    cases = nat_live_matrix.matrix_cases()

    assert [case["name"] for case in cases] == [
        "default-auto",
        "pcp-only",
        "miniupnpc-only",
        "forced-pcp-failure-miniupnpc-fallback",
    ]
    assert cases[0]["backendOrder"] is None
    assert cases[-1]["pcpServerIp"] == "192.0.2.1"
    values = nat_live_matrix.settings_values(cases[0])
    assert values["security"] == {"obfuscationEnabled": False}
    assert values["network"]["p2p"] == {"bindIp": None, "tcpPort": 41662, "udpPort": 41672}


def test_vpn_matrix_pins_tunnel_gateway_and_explicit_igd() -> None:
    cases = nat_live_matrix.matrix_cases(
        bind_ip="10.8.0.2", pcp_server_ip="10.8.0.1", igd_ip="10.8.0.1"
    )

    assert cases[0]["pcpServerIp"] == "10.8.0.1"
    assert cases[1]["pcpServerIp"] == "10.8.0.1"
    assert cases[2]["pcpServerIp"] is None
    assert all(case["bindIp"] == "10.8.0.2" for case in cases)
    assert all(case["igdIp"] == "10.8.0.1" for case in cases)
    assert nat_live_matrix.settings_values(cases[1])["network"]["nat"] == {
        "enabled": True, "requireInitialMapping": False, "backendOrder": ["pcp-natpmp"],
        "pcpServerIp": "10.8.0.1", "igdIp": "10.8.0.1",
    }


def test_supported_pcp_result_requires_a_negotiated_protocol() -> None:
    case = nat_live_matrix.matrix_cases()[1]
    result = nat_live_matrix.evaluate_case(
        case,
        status(
            gatewayDiscovered=True,
            backend="pcp_natpmp",
            protocol="pcp_v2",
            mappings=[{}, {}],
        ),
        duration_seconds=1.0,
        daemon_alive=True,
        maximum_seconds=60.0,
    )

    assert result["passed"] is True
    assert result["capability"] == "supported"


def test_clean_unsupported_default_proves_both_attempts() -> None:
    case = nat_live_matrix.matrix_cases()[0]
    result = nat_live_matrix.evaluate_case(
        case,
        status(
            lastError=(
                "NAT reconcile failed after 2 backends: pcp_natpmp: timed out; "
                "upnp_miniupnpc: no gateway"
            )
        ),
        duration_seconds=3.0,
        daemon_alive=True,
        maximum_seconds=60.0,
    )

    assert result["passed"] is True
    assert result["capability"] == "unsupported"


def test_unsupported_result_fails_when_fallback_attempt_is_missing() -> None:
    case = nat_live_matrix.matrix_cases()[-1]
    result = nat_live_matrix.evaluate_case(
        case,
        status(pcpServerIp="192.0.2.1", lastError="pcp_natpmp: timed out"),
        duration_seconds=3.0,
        daemon_alive=True,
        maximum_seconds=60.0,
    )

    assert result["passed"] is False
    assert "upnp_miniupnpc" in result["failures"][0]


def test_required_vpn_capability_rejects_clean_unsupported_result() -> None:
    case = nat_live_matrix.matrix_cases()[1]
    result = nat_live_matrix.evaluate_case(
        case,
        status(lastError="pcp_natpmp: unavailable"),
        duration_seconds=3.0,
        daemon_alive=True,
        maximum_seconds=60.0,
        require_supported=True,
    )

    assert result["capability"] == "unsupported"
    assert result["passed"] is False
    assert "required live NAT capability was unsupported" in result["failures"]


@pytest.mark.parametrize("fault", [None, "conflict", "lost-effective", "unapplied"])
def test_matrix_checks_revision_and_effective_settings_before_nat(monkeypatch, fault):
    from emule_test_harness.rust_openapi_responses import (
        load_openapi_document, openapi_schema_component, validate_openapi_schema,
    )
    repo = Path(__file__).resolve().parents[2]
    rust = resolve_selected_workspace_repo(repo, "emulebb-rust")
    tooling = resolve_selected_workspace_repo(repo, "emulebb-tooling")
    document = load_openapi_document(tooling / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml")
    schema = openapi_schema_component(document, "SettingsPatch")
    defaults = rust_metadata.saved_settings_defaults(rust)
    saved = copy.deepcopy(defaults)
    def resolve(branch):
        return branch["value"] if set(branch) == {"mode", "value"} else {k: resolve(v) for k, v in branch.items()}
    effective = resolve(saved)
    cases = nat_live_matrix.matrix_cases()
    current = -1
    reads, writes = [0, 0, 0, 0], []
    revision = 9007199254740993
    def read_settings():
        return {"data": {"saved": copy.deepcopy(saved), "effective": copy.deepcopy(effective),
                         "application": {"failed": [], "pendingRestart": ["network.nat.enabled"]
                                         if fault == "unapplied" and current >= 0 else []}},
                "meta": {"settingsRevision": str(revision)}}
    def apply_settings(payload):
        nonlocal revision
        writes.append(payload)
        validate_openapi_schema(document, schema, payload)
        assert payload["expectedRevision"] == str(revision)
        if fault == "conflict":
            raise RuntimeError("SETTINGS_CONFLICT")
        def apply(branch, values):
            for key, value in values.items():
                if isinstance(value, dict):
                    apply(branch[key], value)
                else:
                    branch[key] = {"mode": "custom", "value": value}
        apply(saved, payload["set"])
        if "reset" in payload:
            assert payload["reset"] == ["network.nat.backendOrder"]
            saved["network"]["nat"]["backendOrder"] = copy.deepcopy(defaults["network"]["nat"]["backendOrder"])
        revision += 1
        return read_settings()
    def restart_daemon():
        nonlocal current, effective
        current += 1
        effective = resolve(saved)
        if fault == "lost-effective":
            effective["network"]["p2p"]["tcpPort"] = 1
    def read_nat_status():
        reads[current] += 1
        case = cases[current]
        if reads[current] == 1:
            return status(pcpServerIp=case["pcpServerIp"])
        attempts = "; ".join(f"{backend}: unavailable" for backend in case["attemptedBackends"])
        return status(pcpServerIp=case["pcpServerIp"], lastRefreshUnixSecs=1, lastError=attempts)
    monkeypatch.setattr(nat_live_matrix.time, "sleep", lambda _seconds: None)
    kwargs = dict(read_settings=read_settings, apply_settings=apply_settings, restart_daemon=restart_daemon,
                  read_nat_status=read_nat_status, daemon_alive=lambda: True)
    if fault:
        with pytest.raises(RuntimeError, match="SETTINGS_CONFLICT|did not retain or apply|remain unapplied"):
            nat_live_matrix.run_matrix(**kwargs)
        assert len(writes) == 1 and reads == [0, 0, 0, 0]
    else:
        result = nat_live_matrix.run_matrix(**kwargs)
        assert result["passed"] is True and reads == [2, 2, 2, 2]
        assert len(writes) == 4
        assert writes[0]["reset"] == ["network.nat.backendOrder"]
        assert writes[-1]["set"]["network"]["nat"]["backendOrder"] == ["pcp-natpmp", "upnp"]
