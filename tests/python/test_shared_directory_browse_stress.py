from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path


def load_suite_module():
    """Loads the hyphenated shared-directory browse stress script."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "shared-directory-browse-stress.py"
    spec = importlib.util.spec_from_file_location("shared_directory_browse_stress_for_tests", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_packet_uses_ed2k_tcp_header() -> None:
    module = load_suite_module()

    packet = module.build_packet(module.OP_ASKSHAREDFILESDIR, b"abc")

    assert packet[:5] == struct.pack("<BI", module.ED2K_PROTOCOL, 4)
    assert packet[5] == module.OP_ASKSHAREDFILESDIR
    assert packet[6:] == b"abc"


def test_ed2k_string_roundtrip() -> None:
    module = load_suite_module()

    encoded = module.encode_ed2k_string("Dir_001")
    decoded, offset = module.decode_ed2k_string(encoded + b"tail", 0)

    assert decoded == "Dir_001"
    assert offset == len(encoded)


def test_read_packet_accepts_emule_protocol_frame() -> None:
    module = load_suite_module()

    class FakeSocket:
        def __init__(self) -> None:
            self.payload = bytearray(struct.pack("<BI", module.EMULE_PROTOCOL, 2) + bytes([0x01, 0x02]))

        def recv(self, size: int) -> bytes:
            chunk = self.payload[:size]
            del self.payload[:size]
            return bytes(chunk)

    assert module.read_packet(FakeSocket()) == (0x01, b"\x02")


def test_request_directory_files_decodes_response(monkeypatch) -> None:
    module = load_suite_module()
    sent_packets: list[bytes] = []

    class FakeSocket:
        def sendall(self, payload: bytes) -> None:
            sent_packets.append(payload)

    payload = module.encode_ed2k_string("Folder_1") + struct.pack("<I", 12) + b"file-data"
    monkeypatch.setattr(module, "wait_for_opcode", lambda _sock, _opcode, *, timeout_seconds: payload)

    result = module.request_directory_files(FakeSocket(), "Folder_1", timeout_seconds=1.0)

    protocol, size = struct.unpack("<BI", sent_packets[0][:5])
    assert protocol == module.ED2K_PROTOCOL
    assert size == len(sent_packets[0]) - 5
    assert sent_packets[0][5] == module.OP_ASKSHAREDFILESDIR
    requested_directory, offset = module.decode_ed2k_string(sent_packets[0][6:], 0)
    assert requested_directory == "Folder_1"
    assert offset == len(sent_packets[0]) - 6
    assert result["mode"] == "directory"
    assert result["directory"] == "Folder_1"
    assert result["file_count"] == 12
    assert result["payload_bytes"] == len(payload)


def test_request_full_shared_files_decodes_response(monkeypatch) -> None:
    module = load_suite_module()
    sent_packets: list[bytes] = []

    class FakeSocket:
        def sendall(self, payload: bytes) -> None:
            sent_packets.append(payload)

    payload = struct.pack("<I", 42) + b"file-data"
    monkeypatch.setattr(module, "wait_for_opcode", lambda _sock, _opcode, *, timeout_seconds: payload)

    result = module.request_full_shared_files(FakeSocket(), timeout_seconds=1.0)

    protocol, size = struct.unpack("<BI", sent_packets[0][:5])
    assert protocol == module.ED2K_PROTOCOL
    assert size == 1
    assert sent_packets[0][5] == module.OP_ASKSHAREDFILES
    assert result["mode"] == "full-list"
    assert result["file_count"] == 42


def test_build_request_plan_supports_other_full_and_mixed_modes() -> None:
    module = load_suite_module()

    assert module.build_request_plan(["Dir_1"], 0, 3, "other") == [module.OP_OTHER_SHARED_FILES] * 3
    assert module.build_request_plan(["Dir_1"], 0, 2, "full-list") == ["", ""]
    mixed = module.build_request_plan(["Dir_1", "Dir_2"], 0, 8, "mixed")

    assert len(mixed) == 8
    assert module.OP_OTHER_SHARED_FILES in mixed
    assert "" in mixed
    assert {"Dir_1", "Dir_2"}.intersection(mixed)


def test_assert_thresholds_reports_latency_and_cpu_failures() -> None:
    module = load_suite_module()

    failures = module.assert_thresholds(
        {
            "latency_ms": {"avg": 80.0, "p95": 200.0},
            "max_avg_ms": 50.0,
            "max_p95_ms": 150.0,
        },
        {"process_pct_one_core": 70.0, "max_one_core_percent": 35.0},
    )

    assert failures == [
        "avg latency 80.0ms exceeded 50.0ms",
        "p95 latency 200.0ms exceeded 150.0ms",
        "CPU 70.0% of one core exceeded 35.0%",
    ]


def test_get_rest_shared_file_count_uses_v1_total(monkeypatch) -> None:
    module = load_suite_module()

    def fake_http_request(_base_url: str, _path: str, *, api_key: str, request_timeout_seconds: float):
        return {"status": 200, "json": {"data": {"items": [], "total": 640}}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    assert module.get_rest_shared_file_count("http://192.0.2.10:1", "key") == 640


def test_build_fixture_selects_browse_stress_subtree(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    calls = []

    def fake_ensure_fixture(root, *, include_browse_stress=False, include_browse_stress_smoke=False, **_kwargs):
        calls.append(
            {
                "root": root,
                "include_browse_stress": include_browse_stress,
                "include_browse_stress_smoke": include_browse_stress_smoke,
            }
        )
        key = "shared_directory_browse_stress" if include_browse_stress else "shared_directory_browse_stress_smoke"
        return {"subtrees": {key: {"root": str(tmp_path / key), "expected_visible_file_count": 1}}}

    monkeypatch.setattr(module.generated_fixture, "ensure_fixture", fake_ensure_fixture)

    result = module.build_fixture(tmp_path / "shared", "full")

    assert result["subtree_key"] == "shared_directory_browse_stress"
    assert calls == [
        {
            "root": tmp_path / "shared",
            "include_browse_stress": True,
            "include_browse_stress_smoke": False,
        }
    ]
