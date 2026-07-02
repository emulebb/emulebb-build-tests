from __future__ import annotations

from emule_test_harness import soak_launch


def test_rust_stats_connected_requires_ed2k() -> None:
    assert soak_launch.rust_stats_connected({"ed2kConnected": True}, require_kad=False) is True
    assert soak_launch.rust_stats_connected({"ed2kConnected": False}, require_kad=False) is False
    assert soak_launch.rust_stats_connected({}, require_kad=False) is False


def test_rust_stats_connected_kad_gate_only_when_required() -> None:
    ed2k_only = {"ed2kConnected": True, "kadConnected": False}
    # Bring-up gate is ED2K-only, so Kad-not-connected still counts as connected.
    assert soak_launch.rust_stats_connected(ed2k_only, require_kad=False) is True
    # Restart controller gate additionally requires Kad.
    assert soak_launch.rust_stats_connected(ed2k_only, require_kad=True) is False
    assert soak_launch.rust_stats_connected(
        {"ed2kConnected": True, "kadConnected": True}, require_kad=True
    ) is True
