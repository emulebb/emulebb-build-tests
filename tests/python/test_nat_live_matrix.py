from __future__ import annotations

from emule_test_harness import nat_live_matrix


def status(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "enabled": True,
        "gatewayDiscovered": False,
        "backend": None,
        "protocol": None,
        "pcpServerIp": None,
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
