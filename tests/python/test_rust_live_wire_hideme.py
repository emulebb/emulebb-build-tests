from __future__ import annotations

import importlib.util
import json
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


def test_source_exchange_summary_counts_embedded_sx2_requests(tmp_path: Path) -> None:
    module = load_live_wire_module()
    dump_path = tmp_path / "emulebb-rust-ed2k-tcp-dump-test.jsonl"
    request_filename_ext_info = bytes([1, 0, 0, 0, 0])
    multipacket_ext_payload = (
        bytes(range(16))
        + (12345).to_bytes(8, "little")
        + bytes([module.OP_REQUESTFILENAME])
        + request_filename_ext_info
        + bytes([module.OP_REQUESTSOURCES2, 4, 0, 0])
        + bytes([module.OP_AICHFILEHASHREQ])
    )
    records = [
        {
            "direction": "send",
            "opcode": module.OP_MULTIPACKET_EXT,
            "payload_hex": multipacket_ext_payload.hex(),
        },
        {
            "direction": "recv",
            "opcode": module.OP_ANSWERSOURCES2,
            "payload_hex": "",
        },
    ]
    dump_path.write_text("\n".join(json.dumps(row) for row in records), encoding="utf-8")

    summary = module.summarize_source_exchange_packets(tmp_path)

    assert summary["requestSources2Sent"] == 1
    assert summary["embeddedRequestSources2Sent"] == 1
    assert summary["standaloneRequestSources2Sent"] == 0
    assert summary["answerSources2Received"] == 1


def test_source_exchange_summary_counts_ext2_embedded_sx2_requests(tmp_path: Path) -> None:
    module = load_live_wire_module()
    dump_path = tmp_path / "emulebb-rust-ed2k-tcp-dump-test.jsonl"
    request_filename_ext_info = bytes([1, 0, 0, 0, 0])
    file_identifier = bytes([0x03]) + bytes(range(16)) + (54321).to_bytes(8, "little")
    multipacket_ext2_payload = (
        file_identifier
        + bytes([module.OP_REQUESTFILENAME])
        + request_filename_ext_info
        + bytes([module.OP_REQUESTSOURCES2, 4, 0, 0])
    )
    dump_path.write_text(
        json.dumps(
            {
                "direction": "send",
                "opcode": module.OP_MULTIPACKET_EXT2,
                "payload_hex": multipacket_ext2_payload.hex(),
            }
        ),
        encoding="utf-8",
    )

    summary = module.summarize_source_exchange_packets(tmp_path)

    assert summary["requestSources2Sent"] == 1
    assert summary["embeddedRequestSources2Sent"] == 1


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
