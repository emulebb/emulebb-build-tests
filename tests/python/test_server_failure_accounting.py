from __future__ import annotations

from emule_test_harness import server_failure_accounting


def payload(*rows):
    return {"data": {"items": list(rows)}}


def test_connected_snapshot_accepts_endpoint_and_address_shapes() -> None:
    assert server_failure_accounting.connected_server_snapshot(
        payload({"endpoint": "EXAMPLE.test:4661", "enabled": True, "current": True})
    )["endpoint"] == "example.test:4661"
    assert server_failure_accounting.health_snapshot(
        payload({"address": "203.0.113.8", "port": 4661, "enabled": True})
    )["203.0.113.8:4661"]["failedCount"] == 0


def test_local_failure_comparison_rejects_disable_or_count_change() -> None:
    before = payload({"endpoint": "203.0.113.8:4661", "enabled": True, "failedCount": 0})
    healthy = payload({"endpoint": "203.0.113.8:4661", "enabled": True, "failedCount": 0})
    disabled = payload({"endpoint": "203.0.113.8:4661", "enabled": False, "failedCount": 1})

    assert server_failure_accounting.compare_after_local_failure(before, healthy)["passed"]
    result = server_failure_accounting.compare_after_local_failure(before, disabled)
    assert not result["passed"]
    assert len(result["failures"]) == 2


def test_log_evidence_requires_ignored_action_and_classified_reason() -> None:
    result = server_failure_accounting.ignored_failure_log_evidence(
        'ignored ED2K failure phase="socket_setup" reason="local_bind_interface" action="ignored"'
    )
    assert result == {
        "passed": True,
        "action": "ignored",
        "reasons": ["local_bind_interface"],
    }
    assert not server_failure_accounting.ignored_failure_log_evidence("connection failed")["passed"]


def test_log_evidence_ignores_tracing_ansi_field_styling() -> None:
    result = server_failure_accounting.ignored_failure_log_evidence(
        "reason\x1b[0m\x1b[2m=\x1b[0mlocal_bind_interface "
        "action\x1b[0m\x1b[2m=\x1b[0m\"ignored\""
    )

    assert result == {
        "passed": True,
        "action": "ignored",
        "reasons": ["local_bind_interface"],
    }
