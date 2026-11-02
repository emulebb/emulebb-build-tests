from __future__ import annotations

import pytest

from emule_test_harness import lan_ip_pool


@pytest.mark.unit
def test_default_candidates_follow_the_existing_interface_subnet(monkeypatch) -> None:
    monkeypatch.setattr(lan_ip_pool, "resolve_interface_index", lambda _address: 7)
    pool = lan_ip_pool.LanIpPool("192.168.1.210", first_octet4=211, last_octet4=213)

    assert pool._candidates() == ["192.168.1.211", "192.168.1.212", "192.168.1.213"]


@pytest.mark.unit
def test_candidate_network_can_be_independent_of_interface_address(monkeypatch) -> None:
    monkeypatch.setattr(lan_ip_pool, "resolve_interface_index", lambda _address: 28)
    pool = lan_ip_pool.LanIpPool(
        "172.17.128.1",
        prefix_length=32,
        candidate_network="192.0.2.0/24",
        first_octet4=241,
        last_octet4=243,
    )

    assert pool._candidates() == ["192.0.2.241", "192.0.2.242", "192.0.2.243"]
