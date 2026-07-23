from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from emule_test_harness import goed2k


@pytest.mark.unit
def test_build_server_config_enables_packet_trace(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    trace_path = tmp_path / "packets.trace.jsonl"
    config = goed2k.build_server_config(
        config_path,
        ed2k_port=4751,
        admin_port=4752,
        catalog_path=tmp_path / "catalog.json",
        token="token",
        admin_address="192.0.2.10",
        ed2k_address="192.0.2.10",
        packet_trace=True,
        packet_trace_path=trace_path,
    )

    assert config["packet_trace"] is True
    assert config["packet_trace_path"] == str(trace_path)
    written = json.loads(config_path.read_text(encoding="utf-8"))
    assert written["packet_trace"] is True
    assert written["packet_trace_path"] == str(trace_path)


@pytest.mark.unit
def test_build_server_config_omits_trace_path_when_disabled(tmp_path: Path) -> None:
    config = goed2k.build_server_config(
        tmp_path / "config.json",
        ed2k_port=4751,
        admin_port=4752,
        catalog_path=tmp_path / "catalog.json",
        token="token",
        admin_address="192.0.2.10",
        ed2k_address="192.0.2.10",
    )

    assert config["packet_trace"] is False
    assert "packet_trace_path" not in config


@pytest.mark.unit
def test_build_server_met_encodes_single_entry() -> None:
    met = goed2k.build_server_met("192.168.1.210", 4751, "goed2k-live")

    assert met[0] == 0x0E  # MET header
    assert met[1:5] == struct.pack("<I", 1)  # server count
    assert met[5:9] == bytes([192, 168, 1, 210])  # IPv4 octets in order
    assert met[9:11] == struct.pack("<H", 4751)  # port little-endian
    assert met[11:15] == struct.pack("<I", 1)  # tag count
    assert met[15] == 0x82  # string tag | special-name flag
    assert met[16] == 0x01  # ST_SERVERNAME
    name_len = struct.unpack_from("<H", met, 17)[0]
    assert met[19 : 19 + name_len] == b"goed2k-live"


@pytest.mark.unit
def test_build_server_met_rejects_non_ipv4() -> None:
    with pytest.raises(ValueError):
        goed2k.build_server_met("2001:db8::1", 4751, "goed2k-live")
