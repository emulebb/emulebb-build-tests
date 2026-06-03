from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness import windows_vm_local_ed2k


def test_preferences_text_configures_local_ed2k_without_kad_or_interface_bind(tmp_path: Path) -> None:
    text = windows_vm_local_ed2k.preferences_text(
        target="win11",
        incoming_dir=tmp_path / "incoming",
        temp_dir=tmp_path / "temp",
        tcp_port=4762,
        udp_port=4772,
        bind_addr="169.254.83.248",
        rest_port=4711,
        api_key="key",
    )

    assert "Nick=win11-vm" in text
    assert "NetworkED2K=1" in text
    assert "NetworkKademlia=0" in text
    assert text.count("BindAddr=169.254.83.248") == 2
    assert "BindAddr=127.0.0.1" not in text
    assert "BindInterface=\n" in text
    assert "Port=4762" in text
    assert "UDPPort=4772" in text
    assert "ApiKey=key" in text


def test_write_deterministic_file_is_repeatable(tmp_path: Path) -> None:
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"

    first_hash = windows_vm_local_ed2k.write_deterministic_file(first, size=4097, seed=11)
    second_hash = windows_vm_local_ed2k.write_deterministic_file(second, size=4097, seed=11)

    assert first.read_bytes() == second.read_bytes()
    assert first_hash == second_hash
    assert first.stat().st_size == 4097


def test_ed2k_link_with_source_adds_standard_source_hint() -> None:
    link = "ed2k://|file|sample.bin|1|00112233445566778899AABBCCDDEEFF|/"

    annotated = windows_vm_local_ed2k.ed2k_link_with_source(link, source_ip="169.254.95.14", source_port=4762)

    assert annotated == "ed2k://|file|sample.bin|1|00112233445566778899AABBCCDDEEFF|/|sources,169.254.95.14:4762|/"
    assert windows_vm_local_ed2k.ed2k_link_with_source(annotated, source_ip="169.254.95.14", source_port=4762) == annotated


def test_api_rows_accepts_raw_and_wrapped_shapes() -> None:
    assert windows_vm_local_ed2k.api_rows([{"address": "127.0.0.1"}, "bad"], "servers") == [
        {"address": "127.0.0.1"}
    ]
    assert windows_vm_local_ed2k.api_rows({"servers": [{"address": "127.0.0.1"}]}, "servers") == [
        {"address": "127.0.0.1"}
    ]
    assert windows_vm_local_ed2k.api_rows({"data": {"sharedFiles": [{"name": "sample.bin"}]}}, "sharedFiles") == [
        {"name": "sample.bin"}
    ]
    assert windows_vm_local_ed2k.api_rows({"data": {"items": [{"address": "169.254.1.10"}]}}, "servers") == [
        {"address": "169.254.1.10"}
    ]


def test_connect_server_tolerates_reset_before_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    status_calls = 0

    def fake_http_json(base_url: str, path: str, **kwargs: object) -> object:
        nonlocal status_calls
        calls.append((str(kwargs.get("method", "GET")), path))
        if path == "/api/v1/servers":
            return {"data": {"items": [{"address": "169.254.1.10", "port": 4661}]}}
        if path == "/api/v1/status":
            status_calls += 1
            return {"data": {"servers": {"connected": False, "connecting": status_calls > 1}}}
        if path.endswith("/operations/connect"):
            raise ConnectionResetError("reset")
        return {}

    monkeypatch.setattr(windows_vm_local_ed2k, "http_json", fake_http_json)
    args = type(
        "Args",
        (),
        {
            "base_url": "http://127.0.0.1:4711",
            "api_key": "key",
            "server_address": "169.254.1.10",
            "server_port": 4661,
        },
    )()

    assert windows_vm_local_ed2k.command_add_connect_server(args) == 0
    assert ("POST", "/api/v1/servers/169.254.1.10:4661/operations/connect") in calls


def test_wait_server_connected_uses_status_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_http_json(base_url: str, path: str, **kwargs: object) -> object:
        calls.append(path)
        return {"data": {"servers": {"connected": True}}}

    monkeypatch.setattr(windows_vm_local_ed2k, "http_json", fake_http_json)
    args = type(
        "Args",
        (),
        {
            "base_url": "http://127.0.0.1:4711",
            "api_key": "key",
            "timeout_seconds": 1.0,
        },
    )()

    assert windows_vm_local_ed2k.command_wait_server_connected(args) == 0
    assert calls == ["/api/v1/status"]
