from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path


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
    raw = bytes([0xE3, opcode]) + payload
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
            "rawLen": len(raw),
            "rawHex": raw.hex(),
            "payloadLen": len(payload),
            "payloadHex": payload.hex(),
            "payloadHexTruncated": False,
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


def test_run_downloads_returns_after_first_completion(monkeypatch) -> None:
    module = load_live_wire_module()
    transfer_hashes = [
        "00112233445566778899aabbccddeeff",
        "ffeeddccbbaa99887766554433221100",
    ]

    def fake_retry_http_json(label, *_args, **_kwargs):
        assert label in {"download", "resume", "transfers"}
        if label == "transfers":
            fake_retry_http_json.transfer_calls += 1
            assert fake_retry_http_json.transfer_calls == 1
            return {
                "transfers": [
                    {
                        "hash": transfer_hashes[0],
                        "completedBytes": 10,
                        "sizeBytes": 10,
                        "sources": 1,
                        "state": "completed",
                    },
                    {
                        "hash": transfer_hashes[1],
                        "completedBytes": 0,
                        "sizeBytes": 10,
                        "sources": 1,
                        "state": "downloading",
                    },
                ]
            }
        return {"ok": True}

    fake_retry_http_json.transfer_calls = 0
    monkeypatch.setattr(module, "retry_http_json", fake_retry_http_json)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    result = module.run_downloads(
        "http://192.0.2.10:4731",
        [
            {"hash": transfer_hashes[0], "sources": 1, "sizeBytes": 10, "_searchId": "1"},
            {"hash": transfer_hashes[1], "sources": 1, "sizeBytes": 10, "_searchId": "1"},
        ],
        60,
        max_concurrent=2,
    )

    assert result["completed"] is True
    assert result["completedCount"] == 1
    assert fake_retry_http_json.transfer_calls == 1
