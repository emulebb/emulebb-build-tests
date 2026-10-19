from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness import rust_ed2k
from emule_test_harness.ed2k_server import UnsupportedEd2kServerCapability


@pytest.mark.unit
def test_build_server_config_writes_private_minimal_toml(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"

    config = rust_ed2k.build_server_config(
        path,
        ed2k_port=4661,
        admin_port=8080,
        listen_address="0.0.0.0",
        advertised_address="172.20.0.2",
        protocol_obfuscation=False,
    )

    text = path.read_text(encoding="utf-8")
    assert config["server"]["public"] is False
    assert config["admin"] == {"enabled": True, "port": 8080, "bind": "127.0.0.1", "tls": "off"}
    assert 'this_ip = "172.20.0.2"' in text
    assert 'listen_ip = "0.0.0.0"' in text
    assert "support_crypt = false" in text
    assert "password" not in text
    assert text.endswith("\n")


@pytest.mark.unit
def test_build_server_config_requires_explicit_addresses(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="listen_address"):
        rust_ed2k.build_server_config(
            tmp_path / "config.toml",
            ed2k_port=4661,
            admin_port=8080,
            listen_address="",
            advertised_address="172.20.0.2",
        )


@pytest.mark.unit
def test_rust_control_normalizes_stats_and_clients(monkeypatch) -> None:
    payloads = {
        "/api/stats": {"bytes_in": 12},
        "/api/clients": [{"nick": "aMule", "ip": "192.0.2.10"}, "ignored"],
    }
    monkeypatch.setattr(
        rust_ed2k,
        "admin_request",
        lambda _base, path, **_kwargs: payloads[path],
    )
    control = rust_ed2k.RustEd2kServerControl("http://127.0.0.1:8080")

    assert control.stats() == {"ok": True, "data": {"bytes_in": 12}}
    assert control.list_clients() == [
        {"nick": "aMule", "ip": "192.0.2.10", "client_name": "aMule"}
    ]


@pytest.mark.unit
def test_rust_control_reports_missing_observation_capabilities() -> None:
    control = rust_ed2k.RustEd2kServerControl("http://127.0.0.1:8080")

    with pytest.raises(UnsupportedEd2kServerCapability, match="file lookup"):
        control.get_file("00112233445566778899aabbccddeeff")
    with pytest.raises(UnsupportedEd2kServerCapability, match="file listing"):
        control.list_files()
    with pytest.raises(UnsupportedEd2kServerCapability, match="audit API"):
        control.audit()
