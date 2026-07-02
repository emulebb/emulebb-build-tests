from __future__ import annotations

from emule_test_harness import soak_launch


def test_rust_stats_connected_requires_ed2k() -> None:
    assert soak_launch.rust_stats_connected({"ed2kConnected": True}, require_kad=False) is True
    assert soak_launch.rust_stats_connected({"ed2kConnected": False}, require_kad=False) is False
    assert soak_launch.rust_stats_connected({}, require_kad=False) is False


def test_api_items_tolerates_envelope_shapes() -> None:
    assert soak_launch.api_items([{"a": 1}]) == [{"a": 1}]
    assert soak_launch.api_items({"items": [1, 2]}) == [1, 2]
    assert soak_launch.api_items({"data": {"items": [3]}}) == [3]
    assert soak_launch.api_items({"data": [4, 5]}) == [4, 5]
    # data container is tried before the top-level payload.
    assert soak_launch.api_items({"data": {"servers": [9]}, "servers": [1]}, "servers") == [9]
    # named key at the top level when there is no data wrapper.
    assert soak_launch.api_items({"transfers": [7]}, "transfers") == [7]
    assert soak_launch.api_items({"nope": []}, "servers") == []


def test_api_items_require_dict_filters_non_objects() -> None:
    assert soak_launch.api_items({"items": [{"x": 1}, "junk", 3]}, require_dict=True) == [{"x": 1}]
    assert soak_launch.api_items([{"x": 1}, 2], require_dict=True) == [{"x": 1}]
    assert soak_launch.api_items({"items": [{"x": 1}, "junk"]}) == [{"x": 1}, "junk"]


def test_rust_stats_connected_kad_gate_only_when_required() -> None:
    ed2k_only = {"ed2kConnected": True, "kadConnected": False}
    # Bring-up gate is ED2K-only, so Kad-not-connected still counts as connected.
    assert soak_launch.rust_stats_connected(ed2k_only, require_kad=False) is True
    # Restart controller gate additionally requires Kad.
    assert soak_launch.rust_stats_connected(ed2k_only, require_kad=True) is False
    assert soak_launch.rust_stats_connected(
        {"ed2kConnected": True, "kadConnected": True}, require_kad=True
    ) is True
