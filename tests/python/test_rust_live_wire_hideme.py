from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

from tests.python.diagnostic_fixtures import ed2k_tcp_clear_frame


def load_live_wire_module():
    script_path = (
        Path(__file__).resolve().parents[2] / "scripts" / "rust-live-wire-hideme.py"
    )
    spec = importlib.util.spec_from_file_location("rust_live_wire_hideme", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ed2k_tcp_packet_event(
    *,
    opcode: int,
    payload: bytes,
    direction: str,
    process_id: int = 42,
    run_id: str = "active",
) -> dict[str, object]:
    clear_frame = ed2k_tcp_clear_frame(0xE3, opcode, payload)
    return {
        "schema": "diag_event_v2",
        "client": "rust",
        "runId": run_id,
        "processId": process_id,
        "segmentId": 0,
        "seq": 1,
        "streamSeq": 1,
        "ts": "2026-10-24T12:00:00.000Z",
        "family": "ed2k_tcp",
        "event": "packet",
        "severity": "info",
        "keys": {
            "peer": "192.0.2.20:4662",
            "protocolMarker": 0xE3,
            "opcode": opcode,
        },
        "body": {
            "flow": "peer",
            "direction": direction,
            "transportMode": "plaintext",
            "obfuscated": False,
            "protocolMarker": 0xE3,
            "protocolName": "ed2k",
            "opcode": opcode,
            "opcodeName": f"OP_{opcode:02X}",
            "rawLen": len(clear_frame),
            "rawHex": clear_frame.hex(),
            "clearFrameLen": len(clear_frame),
            "clearFrameHex": clear_frame.hex(),
            "payloadLen": len(payload),
            "payloadHex": payload.hex(),
            "payloadHexTruncated": False,
        },
    }


def client_udp_packet_event(
    *, opcode_name: str, direction: str, transport_mode: str = "obfuscated"
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "client": "rust",
        "runId": "active",
        "processId": 42,
        "segmentId": 0,
        "seq": 2,
        "streamSeq": 2,
        "ts": "2026-10-24T12:00:01.000Z",
        "family": "ed2k_client_udp",
        "event": "packet",
        "severity": "info",
        "keys": {"peer": "192.0.2.20:4672"},
        "body": {
            "direction": direction,
            "transportMode": transport_mode,
            "opcodeName": opcode_name,
            "rawLen": 2,
            "rawHex": "aabb",
        },
    }


def test_udp_reask_protocol_log_counts_outbound_reasks_only(tmp_path: Path) -> None:
    module = load_live_wire_module()
    log_path = tmp_path / "daemon.out"
    log_path.write_text(
        "\n".join(
            [
                "ed2k udp reask loop started",
                "ed2k udp reask: PKT-IN <- 192.0.2.20:4672 (51 bytes) hex=abcd",
                "ed2k udp reask: routed reply from 192.0.2.21:4672",
                "ed2k udp reask: PKT-OUT reask ping -> 192.0.2.22:4672 (35 bytes) hex=abcd",
                "ed2k udp reask: reask to 192.0.2.22:4672 timed out: RetryUdp",
                "ed2k udp reask: PKT-OUT reask ping -> 192.0.2.23:4672 (35 bytes) hex=abcd",
                "Kad source accepted",
            ]
        ),
        encoding="utf-8",
    )

    counts = module.count_log_matches(log_path, ("udp reask", "Kad source"))

    assert counts == {"udp reask": 2, "Kad source": 1}


def test_p2p_bound_to_uses_python_socket_inventory(monkeypatch) -> None:
    module = load_live_wire_module()

    def fake_listening_socket_addresses(protocol: str) -> list[tuple[str, int]]:
        if protocol == "tcp":
            return [("192.0.2.10", module.ED2K_PORT)]
        if protocol == "udp":
            return [("192.0.2.10", module.KAD_PORT)]
        raise AssertionError(f"unexpected protocol {protocol}")

    monkeypatch.setattr(
        module, "_listening_socket_addresses", fake_listening_socket_addresses
    )

    assert module.p2p_bound_to("192.0.2.10")
    assert not module.p2p_bound_to("192.0.2.11")


def test_shared_root_normalization_uses_current_rust_shape() -> None:
    module = load_live_wire_module()

    assert module._normalize_shared_root_entry({"path": r"C:\Tree", "recursive": True}) == "C:\\Tree\\"
    assert module._normalize_shared_root_entry(r"D:\Flat") == "D:\\Flat\\"


def test_resolve_rust_live_wire_exe_uses_plain_release_by_default(tmp_path: Path) -> None:
    module = load_live_wire_module()
    exe = tmp_path / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"plain")

    resolved = module.resolve_rust_live_wire_exe(tmp_path, require_packet_diagnostics=False)

    assert resolved == exe


def test_resolve_rust_live_wire_exe_uses_diagnostics_when_required(tmp_path: Path) -> None:
    module = load_live_wire_module()
    plain = tmp_path / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
    diagnostics = tmp_path / "tools" / "emulebb-rust" / "bin" / "emulebb-rust-diagnostics.exe"
    diagnostics.parent.mkdir(parents=True)
    plain.write_bytes(b"plain")
    diagnostics.write_bytes(b"diagnostics")

    resolved = module.resolve_rust_live_wire_exe(tmp_path, require_packet_diagnostics=True)

    assert resolved == diagnostics


def test_source_exchange_summary_counts_embedded_sx2_requests() -> None:
    module = load_live_wire_module()
    request_filename_ext_info = bytes([1, 0, 0, 0, 0])
    answer_sources2_payload = (
        bytes([4])
        + bytes(range(16))
        + (2).to_bytes(2, "little")
        + (bytes([192, 0, 2, 1]) + (4662).to_bytes(2, "little") + bytes(23))
        + (bytes([192, 0, 2, 2]) + (4663).to_bytes(2, "little") + bytes(23))
    )
    multipacket_ext_payload = (
        bytes(range(16))
        + (12345).to_bytes(8, "little")
        + bytes([module.OP_REQUESTFILENAME])
        + request_filename_ext_info
        + bytes([module.OP_REQUESTSOURCES2, 4, 0, 0])
        + bytes([module.OP_AICHFILEHASHREQ])
    )
    events = [
        ed2k_tcp_packet_event(
            opcode=module.OP_MULTIPACKET_EXT,
            payload=multipacket_ext_payload,
            direction="send",
        ),
        ed2k_tcp_packet_event(
            opcode=module.OP_ANSWERSOURCES2,
            payload=answer_sources2_payload,
            direction="recv",
        ),
    ]

    summary = module.summarize_source_exchange_packets(
        module.diag_event_diff.ed2k_tcp_packet_views(events)
    )

    assert summary["requestSources2Sent"] == 1
    assert summary["embeddedRequestSources2Sent"] == 1
    assert summary["standaloneRequestSources2Sent"] == 0
    assert summary["answerSources2Received"] == 1
    assert summary["answerSources2SourceCount"] == 2
    assert summary["emptyAnswerSources2Received"] == 0


def test_source_exchange_summary_counts_ext2_embedded_sx2_requests() -> None:
    module = load_live_wire_module()
    request_filename_ext_info = bytes([1, 0, 0, 0, 0])
    file_identifier = bytes([0x03]) + bytes(range(16)) + (54321).to_bytes(8, "little")
    multipacket_ext2_payload = (
        file_identifier
        + bytes([module.OP_REQUESTFILENAME])
        + request_filename_ext_info
        + bytes([module.OP_REQUESTSOURCES2, 4, 0, 0])
    )
    packets = module.diag_event_diff.ed2k_tcp_packet_views(
        [
            ed2k_tcp_packet_event(
                opcode=module.OP_MULTIPACKET_EXT2,
                payload=multipacket_ext2_payload,
                direction="send",
            )
        ]
    )

    summary = module.summarize_source_exchange_packets(packets)

    assert summary["requestSources2Sent"] == 1
    assert summary["embeddedRequestSources2Sent"] == 1


def test_source_exchange_summary_counts_empty_sx2_answers() -> None:
    module = load_live_wire_module()
    answer_sources2_payload = bytes([4]) + bytes(range(16)) + (0).to_bytes(2, "little")
    packets = module.diag_event_diff.ed2k_tcp_packet_views(
        [
            ed2k_tcp_packet_event(
                opcode=module.OP_ANSWERSOURCES2,
                payload=answer_sources2_payload,
                direction="recv",
            )
        ]
    )

    summary = module.summarize_source_exchange_packets(packets)

    assert summary["answerSources2Received"] == 1
    assert summary["answerSources2SourceCount"] == 0
    assert summary["emptyAnswerSources2Received"] == 1


def test_peer_packet_diagnostics_use_selected_unified_run_not_legacy_dump(
    tmp_path: Path,
) -> None:
    module = load_live_wire_module()
    legacy = tmp_path / "emulebb-rust-ed2k-tcp-dump-legacy.jsonl"
    legacy.write_text(
        json.dumps(
            {
                "direction": "send",
                "opcode": module.OP_REQUESTSOURCES2,
                "payload_hex": "",
            }
        ),
        encoding="utf-8",
    )
    stale = tmp_path / "emulebb-rust-diag-42-stale-000000.jsonl"
    active = tmp_path / "emulebb-rust-diag-42-active-000000.jsonl"
    stale.write_text(
        json.dumps(
            ed2k_tcp_packet_event(
                opcode=module.OP_REQUESTSOURCES2,
                payload=b"",
                direction="send",
                run_id="stale",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    active.write_text(
        json.dumps(
            ed2k_tcp_packet_event(
                opcode=module.OP_ANSWERSOURCES2,
                payload=bytes([4]) + bytes(range(16)) + (0).to_bytes(2, "little"),
                direction="recv",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    os.utime(stale, (1_000_000_000, 1_000_000_000))
    os.utime(active, (2_000_000_000, 2_000_000_000))

    segments, records, packets = module.load_peer_packet_diagnostics(
        tmp_path,
        process_id=42,
    )

    assert segments == [active.resolve()]
    assert len(records) == 1
    assert [packet["opcode"] for packet in packets] == [module.OP_ANSWERSOURCES2]
    summary = module.summarize_source_exchange_packets(packets)
    assert summary["requestSources2Sent"] == 0
    assert summary["answerSources2Received"] == 1


def test_client_udp_summary_uses_unified_packet_events_only() -> None:
    module = load_live_wire_module()
    records = [
        client_udp_packet_event(opcode_name="OP_REASKFILEPING", direction="send"),
        client_udp_packet_event(opcode_name="OP_REASKACK", direction="recv"),
        {**client_udp_packet_event(opcode_name="OP_QUEUEFULL", direction="recv"), "event": "state"},
        ed2k_tcp_packet_event(opcode=0x01, payload=b"", direction="send"),
    ]

    summary = module.summarize_client_udp_packets(records)

    assert summary["records"] == 2
    assert summary["captured"] is True
    assert summary["reaskFilePingSent"] == 1
    assert summary["reaskAckObserved"] == 1
    assert summary["queueFullObserved"] == 0
    assert summary["transportModes"] == {"obfuscated": 2}


def test_run_downloads_returns_after_first_completion(monkeypatch) -> None:
    module = load_live_wire_module()
    hashes = ["00112233445566778899aabbccddeeff", "ffeeddccbbaa99887766554433221100"]
    ids = {hashes[0]: "7", hashes[1]: "8"}
    def create(label, *_args, **kwargs):
        assert label == "download"
        assert kwargs["body"] == {"intent": "started", "category": None}
        file_hash = _args[2].split("/")[-3]
        return {"data": {"id": ids[file_hash], "hash": file_hash}}
    detail_calls = []
    def detail(_base, _key, job_id, *, expected_hash):
        detail_calls.append(job_id)
        assert ids[expected_hash] == job_id
        return {"id": job_id, "hash": expected_hash, "sizeBytes": 10,
                "state": "completed" if job_id == "7" else "downloading",
                "payloadVerified": job_id == "7", "progress": 1 if job_id == "7" else 0,
                "delivery": {"state": "delivered" if job_id == "7" else "pending"}}
    monkeypatch.setattr(module, "retry_http_json", create)
    monkeypatch.setattr(module, "download_detail", detail)
    monkeypatch.setattr(module, "download_part_totals", lambda *_args: {"verifiedBytes": 0})
    monkeypatch.setattr(module, "_source_count_lower_bound", lambda *_args: 1)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    result = module.run_downloads("http://192.0.2.10:4731", [
        {"hash": hashes[0], "sizeBytes": 10, "_searchId": "1"},
        {"hash": hashes[1], "sizeBytes": 10, "_searchId": "1"},
    ], 60, max_concurrent=2)
    assert result["completed"] is True and result["completedCount"] == 1
    assert detail_calls == ["7", "8"]


def test_download_completion_does_not_infer_payload_verification_from_bytes(monkeypatch):
    module = load_live_wire_module()
    monkeypatch.setattr(module, "retry_http_json", lambda *_args, **_kwargs: {"data": {"id": "7", "hash": "a" * 32}})
    observations = []
    def detail(_base, _key, job_id, *, expected_hash):
        observations.append(job_id)
        done = len(observations) == 2
        return {"id": job_id, "hash": expected_hash, "sizeBytes": 1000, "progress": 1,
                "state": "completed" if done else "verifying", "payloadVerified": done,
                "delivery": {"state": "delivered" if done else "pending"}}
    source_counts = iter([1, 2])
    monkeypatch.setattr(module, "download_detail", detail)
    monkeypatch.setattr(module, "download_part_totals", lambda *_args: {"verifiedBytes": 1000})
    monkeypatch.setattr(module, "_source_count_lower_bound", lambda *_args: next(source_counts))
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    result = module.run_downloads("http://192.0.2.10", [{"hash": "a" * 32, "sizeBytes": 1000, "_searchId": "1"}], 60, max_concurrent=1)
    assert observations == ["7", "7"]
    assert result["sourceGrowthObserved"] is True
    assert result["sourceExchangeObserved"] is False


def test_all_failed_creations_do_not_poll_global_history(monkeypatch):
    module = load_live_wire_module()
    def fail(*_args, **_kwargs):
        raise RuntimeError("admission unavailable")
    monkeypatch.setattr(module, "retry_http_json", fail)
    monkeypatch.setattr(module, "download_detail", lambda *_args, **_kwargs: pytest.fail("no captured job"))
    result = module.run_downloads("http://192.0.2.10", [{"hash": "a" * 32, "sizeBytes": 1, "_searchId": "1"}], 60, max_concurrent=1)
    assert result["started"] == 0 and result["completed"] is False


def test_source_observation_is_one_bounded_window(monkeypatch):
    module = load_live_wire_module()
    calls = []
    def read(_base, method, path, _key):
        calls.append((method, path))
        return {"data": [{}] * 200, "meta": {"hasMore": True, "nextCursor": "another-page"}}
    monkeypatch.setattr(module, "request_json", read)
    assert module._source_count_lower_bound("http://192.0.2.10", "7") == 201
    assert calls == [("GET", "/api/v1/downloads/7/sources?limit=200")]


def test_hold_soak_reads_fixed_counts_instead_of_download_history(monkeypatch):
    module = load_live_wire_module()
    clock = [0.0]
    monkeypatch.setattr(module.time, "time", lambda: clock[0])
    monkeypatch.setattr(module.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(module, "get_stats", lambda _base: {"ed2kConnected": True, "activeUploads": 2})
    monkeypatch.setattr(module, "get_kad", lambda _base: {"connected": True, "contactCount": 3})
    calls = []
    def read(label, attempts, base, path, **kwargs):
        calls.append(path)
        return {"data": {"downloads": {"unfinished": 1000, "completed": 100000}}}
    monkeypatch.setattr(module, "retry_http_json", read)
    result = module.hold_soak("http://192.0.2.10", 1)
    assert calls == ["/api/v1/snapshot?limit=1"]
    assert result["snapshots"][0]["downloadCount"] == 101000
    assert result["snapshots"][0]["activeUploads"] == 2



def test_candidate_filter_uses_current_search_display_name_and_size():
    module = load_live_wire_module()
    row = {"displayName": "Sample Manual.txt", "hash": "a" * 32,
           "sizeBytes": min(4096, module.MAX_DOWNLOAD_BYTES), "sources": module.MIN_DOWNLOAD_SOURCES}
    assert module.safe_download_rejection_reason(row) is None
    assert module.safe_download_rejection_reason({**row, "displayName": "setup.exe"}) == "unsafeNameToken"
