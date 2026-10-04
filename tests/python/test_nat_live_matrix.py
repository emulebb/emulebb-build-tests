from __future__ import annotations

from emule_test_harness import nat_live_matrix


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
    assert cases[0]["backendOrder"] == []
    assert cases[-1]["pcpServerIp"] == "192.0.2.1"
    assert nat_live_matrix.settings_patch(cases[0])["ed2k"] == {
        "obfuscationEnabled": False
    }


def test_vpn_matrix_pins_tunnel_gateway_and_explicit_igd() -> None:
    cases = nat_live_matrix.matrix_cases(
        bind_ip="10.8.0.2", pcp_server_ip="10.8.0.1", igd_ip="10.8.0.1"
    )

    assert cases[0]["pcpServerIp"] == "10.8.0.1"
    assert cases[1]["pcpServerIp"] == "10.8.0.1"
    assert cases[2]["pcpServerIp"] is None
    assert all(case["bindIp"] == "10.8.0.2" for case in cases)
    assert all(case["igdIp"] == "10.8.0.1" for case in cases)
    assert nat_live_matrix.settings_patch(cases[1])["nat"] == {
        "enabled": True,
        "requireInitialMapping": False,
        "backendOrder": ["pcp_natpmp"],
        "bindIp": "10.8.0.2",
        "pcpServerIp": "10.8.0.1",
        "igdIp": "10.8.0.1",
        "leaseDurationSecs": 86400,
        "discoveryTimeoutSecs": 15,
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


def test_run_matrix_waits_for_each_initial_reconcile(monkeypatch) -> None:
    cases = nat_live_matrix.matrix_cases()
    current = -1
    reads = [0, 0, 0, 0]
    latest_patch: dict[str, object] = {}

    def apply_settings(payload: dict[str, object]) -> dict[str, object]:
        latest_patch.clear()
        latest_patch.update(payload)
        return {"data": payload}

    def restart_daemon() -> None:
        nonlocal current
        current += 1

    def read_nat_status() -> dict[str, object]:
        reads[current] += 1
        case = cases[current]
        if reads[current] == 1:
            return status(pcpServerIp=case["pcpServerIp"])
        attempts = "; ".join(
            f"{backend}: unavailable" for backend in case["attemptedBackends"]
        )
        return status(
            pcpServerIp=case["pcpServerIp"],
            lastRefreshUnixSecs=1,
            lastError=attempts,
        )

    monkeypatch.setattr(nat_live_matrix.time, "sleep", lambda _seconds: None)
    result = nat_live_matrix.run_matrix(
        apply_settings=apply_settings,
        restart_daemon=restart_daemon,
        read_nat_status=read_nat_status,
        daemon_alive=lambda: True,
    )

    assert result["passed"] is True
    assert reads == [2, 2, 2, 2]
    assert latest_patch["ed2k"] == {"obfuscationEnabled": False}
