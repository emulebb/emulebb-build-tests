from __future__ import annotations

from pathlib import Path

import pytest

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


def test_rust_bringup_does_not_force_second_server_connect() -> None:
    source = Path(soak_launch.__file__).read_text(encoding="utf-8")

    assert "rust server reconnect after share import" not in source


def test_bring_up_rust_cleans_process_on_connection_timeout(tmp_path: Path, monkeypatch) -> None:
    class FakeRustMod:
        @staticmethod
        def get_stats(_base_url: str) -> dict[str, object]:
            return {"ed2kConnected": False}

        @staticmethod
        def import_server_met(_base_url: str, _server_met_url: str) -> None:
            return None

        @staticmethod
        def share_directories(_base_url: str, _shared_roots: list[object]) -> None:
            return None

    class FakeProcess:
        pid = 4242

    fake_process = FakeProcess()
    launched: dict[str, object] = {}
    stopped: list[object] = []

    def fake_start(_exe_path: Path, _profile_dir: Path, handle) -> FakeProcess:
        launched["handle"] = handle
        return fake_process

    def fake_wait_until(description: str, *_args):
        if description == "rust ED2K connected":
            raise RuntimeError("Timed out waiting for rust ED2K connected")
        return {"ready": True}

    monkeypatch.setattr(soak_launch, "write_rust_profile", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(soak_launch, "start_rust_client_executable_with_output", fake_start)
    monkeypatch.setattr(soak_launch, "wait_until", fake_wait_until)
    monkeypatch.setattr(soak_launch, "patch_upload_limit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(soak_launch, "retry_http_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(soak_launch, "connect_operator_server", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(soak_launch, "stop_process_tree", lambda process: stopped.append(process))

    with pytest.raises(RuntimeError, match="rust ED2K connected"):
        soak_launch.bring_up_rust(
            rust_mod=FakeRustMod(),
            exe_path=tmp_path / "emulebb-rust-diagnostics.exe",
            bind_ip="10.0.0.2",
            rest_addr="192.0.2.10",
            rest_port=4731,
            profile_dir=tmp_path / "profile",
            packet_dump_dir=tmp_path / "profile" / "packet-dump",
            incoming_dir=tmp_path / "profile" / "incoming",
            bootstrap_nodes=[],
            shared_roots=[],
            server_met_url="",
            server_endpoint=soak_launch.OPERATOR_SERVER,
            obfuscation=True,
            timeouts={"rest": 1.0, "connect": 1.0},
        )

    assert stopped == [fake_process]
    assert launched["handle"].closed is True
