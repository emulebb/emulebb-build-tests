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
