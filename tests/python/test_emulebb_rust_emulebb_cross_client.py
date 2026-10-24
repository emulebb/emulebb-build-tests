from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness.diag_event_runs import DiagnosticTraceError

from emule_test_harness import rust_metadata


def _rust_repo() -> Path:
    return Path(__file__).resolve().parents[3] / "emulebb-rust"


def load_suite_module():
    """Loads the hyphenated Rust/eMuleBB cross-client script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "emulebb-rust-emulebb-cross-client.py"
    spec = importlib.util.spec_from_file_location("emulebb_rust_emulebb_cross_client_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_wait_for_rust_ed2k_connected_reads_canonical_status_stats(monkeypatch) -> None:
    module = load_suite_module()

    monkeypatch.setattr(
        module,
        "request_json",
        lambda *_args, **_kwargs: {"stats": {"ed2kConnected": True}},
    )
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())

    status = module.wait_for_rust_ed2k_connected("http://192.0.2.10:4711", "key", 1.0)

    assert status["stats"]["ed2kConnected"] is True


def test_wait_for_rust_search_result_reads_unwrapped_search_payload(monkeypatch) -> None:
    module = load_suite_module()

    expected_hash = "00112233445566778899aabbccddeeff"
    monkeypatch.setattr(
        module,
        "request_json",
        lambda *_args, **_kwargs: {
            "id": "search-1",
            "status": "complete",
            "items": [{"hash": expected_hash.upper(), "name": "fixture.bin"}],
        },
    )
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())

    result = module.wait_for_rust_search_result(
        "http://192.0.2.10:4711",
        "key",
        query="fixture",
        transfer_hash=expected_hash,
        timeout_seconds=1.0,
    )

    assert result["search"]["id"] == "search-1"
    assert result["result"]["name"] == "fixture.bin"


def test_disconnect_mfc_servers_accepts_successful_rest_response(monkeypatch) -> None:
    module = load_suite_module()
    calls: list[tuple[str, str, dict[str, object]]] = []

    def fake_http_request(_base_url, path, *, method, json_body, **_kwargs):
        calls.append((method, path, json_body))
        return {
            "status": 200,
            "content_type": "application/json",
            "json": {"serverCount": 1},
            "raw_json": {"data": {"serverCount": 1}, "meta": {"apiVersion": "v1"}},
        }

    monkeypatch.setattr(module.dtt.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(
        module.dtt.rest_smoke,
        "compact_http_result",
        lambda result: {"status": result["status"]},
    )

    result = module.disconnect_mfc_servers(
        "http://192.0.2.10:4711",
        "key",
    )

    assert result["status"] == 200
    assert calls == [
        (
            "POST",
            "/api/v1/servers/operations/disconnect",
            {},
        )
    ]


def test_cross_client_script_uses_shared_ed2k_harness_launcher_boundary() -> None:
    module = load_suite_module()
    script_text = Path(module.__file__).read_text(encoding="utf-8")

    assert "ed2k_harness.launch_ed2k_server(" in script_text
    assert "ed2k_harness.resolve_ed2k_server_exe(" not in script_text
    assert "ed2k_harness.build_or_skip_ed2k_server_binary(" not in script_text
    assert "ed2k_harness.build_server_config(" not in script_text
    assert "ed2k_harness.start_ed2k_server(" not in script_text


def test_cross_client_disables_rust_kad_by_default() -> None:
    module = load_suite_module()

    args = module.parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert args.rust_kad_enabled is False


def test_cross_client_source_lifecycle_arguments_are_opt_in() -> None:
    module = load_suite_module()

    defaults = module.parse_args(["--lan-bind-addr", "192.0.2.10"])
    enabled = module.parse_args(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--verify-source-lifecycle",
            "--verify-same-session-republish",
            "--verify-reflected-self-source",
            "--diagnostics",
            "--fixture-size-bytes",
            "19456000",
            "--rust-upload-limit-kibps",
            "512",
            "--source-withdraw-timeout-seconds",
            "45",
        ]
    )

    assert defaults.verify_source_lifecycle is False
    assert defaults.verify_same_session_republish is False
    assert defaults.verify_reflected_self_source is False
    assert defaults.verify_completed_download_release is False
    assert defaults.source_withdraw_timeout_seconds == 30.0
    assert enabled.verify_source_lifecycle is True
    assert enabled.verify_same_session_republish is True
    assert enabled.verify_reflected_self_source is True
    assert enabled.source_withdraw_timeout_seconds == 45.0


def test_completed_download_release_requires_diagnostics() -> None:
    module = load_suite_module()
    args = module.parse_args(
        ["--lan-bind-addr", "192.0.2.10", "--verify-completed-download-release"]
    )

    with pytest.raises(ValueError, match="requires --diagnostics"):
        module.validate_optional_soak_args(args)


def test_reflected_self_source_requires_diagnostics() -> None:
    module = load_suite_module()
    args = module.parse_args(
        ["--lan-bind-addr", "192.0.2.10", "--verify-reflected-self-source"]
    )

    with pytest.raises(ValueError, match="requires --diagnostics"):
        module.validate_optional_soak_args(args)


def test_reflected_self_source_requires_partial_transfer_window() -> None:
    module = load_suite_module()
    too_small = module.parse_args(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--diagnostics",
            "--verify-reflected-self-source",
            "--rust-upload-limit-kibps",
            "512",
        ]
    )
    unbounded = module.parse_args(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--diagnostics",
            "--verify-reflected-self-source",
            "--fixture-size-bytes",
            "19456000",
        ]
    )

    with pytest.raises(ValueError, match="above one ED2K part"):
        module.validate_optional_soak_args(too_small)
    with pytest.raises(ValueError, match="requires --rust-upload-limit-kibps"):
        module.validate_optional_soak_args(unbounded)


def test_wait_for_reflected_self_source_uses_only_post_cursor_packets(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    trace = tmp_path / "emule-packets.jsonl"
    old_record = {"schema": "ed2k_packet_v1", "event_seq": 10}
    new_records = [
        {"schema": "ed2k_packet_v1", "event_seq": 11},
        {"schema": "ed2k_packet_v1", "event_seq": 12},
    ]
    loads = iter([[old_record], [old_record, *new_records]])
    observed: list[list[dict[str, object]]] = []

    monkeypatch.setattr(
        module.converged_live_wire,
        "find_packet_trace",
        lambda *_args, **_kwargs: trace,
    )
    monkeypatch.setattr(module.packet_trace_diff, "load_trace", lambda _path: next(loads))
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())
    monkeypatch.setattr(
        module.packet_trace_diff,
        "reflected_self_source_evidence",
        lambda records, **_kwargs: observed.append(records)
        or {
            "requester_offer_seen": True,
            "request_seen": True,
            "reply_seen": True,
            "matching_reply_count": 1,
            "returned_source_count": 1,
            "expected_publisher_present": True,
            "requester_present": False,
        },
    )

    cursor = module.capture_mfc_packet_cursor(tmp_path, 1.0)
    evidence = module.wait_for_reflected_self_source_evidence(
        tmp_path,
        cursor,
        transfer_hash="AA" * 16,
        requester_port=4662,
        expected_publisher_port=5662,
        timeout_seconds=1.0,
    )

    assert observed == [new_records]
    assert evidence == {
        "requester_offer_seen": True,
        "request_seen": True,
        "reply_seen": True,
        "matching_reply_count": 1,
        "returned_source_count": 1,
        "expected_publisher_present": True,
        "requester_present": False,
    }


def test_recycle_rust_publisher_proves_withdrawal_and_republication(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    calls: list[tuple[object, ...]] = []
    old_process = SimpleNamespace(wait=lambda timeout: calls.append(("wait", timeout)) or 0)
    new_process = object()
    transfer_hash = "ab" * 16

    class FakeControl:
        shared_file_calls = 0

        def wait_for_client_shared_files(self, nick, minimum, timeout):
            self.shared_file_calls += 1
            calls.append(("shared_files", self.shared_file_calls, nick, minimum, timeout))
            return {
                "client_name": nick,
                "ip": "172.17.128.1",
                "shared_files": 1,
            }

        def wait_for_file(self, file_hash, timeout):
            calls.append(("file", file_hash, timeout))
            return {"hash": file_hash, "sources": 1}

        def wait_for_file_endpoint(self, file_hash, host, port, timeout, description):
            calls.append(("endpoint", file_hash, host, port, timeout, description))
            return {"hash": file_hash, "endpoints": [{"host": host, "port": port}]}

        def wait_for_client_absent(self, nick, timeout):
            calls.append(("client_absent", nick, timeout))
            return {"absent": True}

        def wait_for_file_endpoint_absent(self, file_hash, host, port, timeout):
            calls.append(("endpoint_absent", file_hash, host, port, timeout))
            return {"absent": True}

    monkeypatch.setattr(
        module,
        "request_json",
        lambda base_url, method, path, api_key, body=None: calls.append(
            ("request", base_url, method, path, api_key, body)
        )
        or {"accepted": True},
    )
    monkeypatch.setattr(
        module.rust_client,
        "start_rust_client_executable_append",
        lambda executable, profile, output: calls.append(("launch", executable, profile, output)) or new_process,
    )
    monkeypatch.setattr(
        module,
        "wait_for_rust_rest",
        lambda base_url, process, output, api_key, timeout: calls.append(("rest", process, timeout))
        or {"ready": True},
    )
    monkeypatch.setattr(
        module,
        "wait_for_rust_ed2k_connected",
        lambda base_url, api_key, timeout: calls.append(("connected", timeout))
        or {"stats": {"ed2kConnected": True}},
    )

    relaunched, report = module.recycle_rust_publisher(
        process=old_process,
        executable=tmp_path / "emulebb-rust.exe",
        profile_dir=tmp_path / "profile",
        output_path=tmp_path / "rust.out",
        base_url="http://192.0.2.10:4711",
        api_key="key",
        client_nick="cl-emulebb-rust-005",
        transfer_hash=transfer_hash,
        endpoint_port=4662,
        server_control=FakeControl(),
        rest_ready_timeout_seconds=10.0,
        connect_timeout_seconds=20.0,
        withdraw_timeout_seconds=30.0,
        publish_timeout_seconds=40.0,
    )

    assert relaunched is new_process
    assert report["required_by_adapter"] is False
    assert report["withdrawn"]["client"]["absent"] is True
    assert report["republished"]["file"]["sources"] == 1
    assert [call[0] for call in calls] == [
        "shared_files",
        "file",
        "endpoint",
        "request",
        "wait",
        "client_absent",
        "endpoint_absent",
        "launch",
        "rest",
        "request",
        "connected",
        "shared_files",
        "file",
        "endpoint",
    ]


def test_rust_offer_batch_evidence_counts_only_nonempty_catalog_offers(tmp_path: Path) -> None:
    module = load_suite_module()
    logs = tmp_path / "logs"
    logs.mkdir()
    rows = [
        {
            "timestamp": "2026-10-20T12:00:00Z",
            "fields": {
                "message": "refreshed ED2K shared catalog advertisement",
                "entries_sent": 1,
                "total_entries": 1,
                "published_entries": 1,
                "pending_entries": 0,
                "wrapped": True,
                "skipped_duplicate_batch": False,
            },
        },
        {
            "timestamp": "2026-10-20T12:01:00Z",
            "fields": {
                "message": "refreshed ED2K shared catalog advertisement",
                "entries_sent": 0,
                "total_entries": 1,
            },
        },
    ]
    (logs / "emulebb-rust.test.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\nnot-json\n",
        encoding="utf-8",
    )

    evidence = module.rust_offer_batch_evidence(tmp_path)

    assert evidence["count"] == 1
    assert evidence["latest"]["entries_sent"] == 1
    assert evidence["latest"]["skipped_duplicate_batch"] is False


def test_wait_for_rust_published_entry_count_reads_current_session(monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(
        module,
        "request_json",
        lambda *_args, **_kwargs: {
            "servers": {
                "currentServer": {
                    "offerFilesPublishedEntries": 1,
                    "offerFilesPendingEntries": 0,
                    "offerFilesMode": "legacy",
                }
            }
        },
    )

    result = module.wait_for_rust_published_entry_count(
        "http://192.0.2.10:4711",
        "key",
        1,
        1.0,
    )

    assert result == {"published_entries": 1, "pending_entries": 0, "mode": "legacy"}


def test_same_session_republish_reoffers_without_duplicate_source(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    calls: list[tuple[object, ...]] = []
    clients = iter(
        [
            {"client_name": "cl-emulebb-rust-005", "ip": "172.17.128.1", "connected_seconds": 10},
            {"client_name": "cl-emulebb-rust-005", "ip": "172.17.128.1", "connected_seconds": 12},
        ]
    )
    transfer_hash = "ab" * 16

    class FakeControl:
        def wait_for_client_shared_files(self, nick, minimum, timeout):
            calls.append(("client", nick, minimum, timeout))
            return next(clients)

        def get_file(self, file_hash):
            calls.append(("file", file_hash))
            return {
                "hash": file_hash,
                "sources": 1,
                "complete_sources": 1,
                "endpoints": [{"host": "172.17.128.1", "port": 4662, "complete": True}],
            }

    monkeypatch.setattr(
        module,
        "request_json",
        lambda _base_url, method, path, _api_key, body=None: calls.append(("request", method, path, body))
        or {"ok": True},
    )
    monkeypatch.setattr(
        module,
        "wait_for_rust_shared_file_absent",
        lambda *_args, **_kwargs: {"absent": True},
    )
    monkeypatch.setattr(
        module,
        "wait_for_rust_shared_file",
        lambda *_args, **_kwargs: {"count": 1, "matched": {"name": "fixture.bin"}},
    )
    offers = iter([{"count": 1, "latest": {"entries_sent": 1}}, {"count": 2, "latest": {"entries_sent": 1}}])
    monkeypatch.setattr(module, "wait_for_rust_offer_batch", lambda *_args, **_kwargs: next(offers))
    publish_states = iter(
        [
            {"published_entries": 1},
            {"published_entries": 0},
            {"published_entries": 1},
        ]
    )
    monkeypatch.setattr(
        module,
        "wait_for_rust_published_entry_count",
        lambda *_args, **_kwargs: next(publish_states),
    )

    result = module.verify_rust_same_session_republish(
        profile_dir=tmp_path / "profile",
        base_url="http://192.0.2.10:4711",
        api_key="key",
        shared_root=tmp_path / "shared",
        file_name="fixture.bin",
        transfer_hash=transfer_hash,
        client_nick="cl-emulebb-rust-005",
        endpoint_port=4662,
        server_control=FakeControl(),
        timeout_seconds=30.0,
    )

    assert result["same_session"] is True
    assert result["source_count"] == 1
    assert result["republished"]["offer"]["count"] == 2
    assert [call[0] for call in calls] == [
        "client",
        "file",
        "request",
        "request",
        "file",
        "request",
        "request",
        "file",
        "client",
    ]


def test_choose_extra_port_uses_bounded_harness_range_allocator(monkeypatch) -> None:
    module = load_suite_module()
    used_ports = {21000, 21001}
    observed: dict[str, object] = {}

    def fake_choose(lan_bind_addr: str, used: set[int], *, udp: bool = False) -> int:
        observed.update(lan_bind_addr=lan_bind_addr, used=set(used), udp=udp)
        return 21002

    monkeypatch.setattr(module.dtt, "choose_available_local_port", fake_choose)

    assert module.choose_extra_port("192.0.2.10", used_ports, udp=True) == 21002
    assert observed == {
        "lan_bind_addr": "192.0.2.10",
        "used": {21000, 21001},
        "udp": True,
    }
    assert used_ports == {21000, 21001, 21002}


def test_local_kad_diagnostics_audit_rejects_nonlocal_contacts(tmp_path: Path) -> None:
    module = load_suite_module()
    rust_dir = tmp_path / "rust"
    mfc_dir = tmp_path / "mfc"
    rust_dir.mkdir()
    mfc_dir.mkdir()
    peers = {"rust": "10.1.2.3:4000", "emule": "10.1.2.3:4001"}

    def current_packets(_directory, *, side, process_id):
        assert process_id in {41, 42}
        return [{"keys": {"peer": peers[side]}}]

    module.current_kad_packet_records = current_packets
    assert module.audit_local_kad_diagnostics(
        rust_dir,
        mfc_dir,
        expected_ip="10.1.2.3",
        rust_process_id=41,
        mfc_process_id=42,
    ) == {
        "rustPackets": 1, "mfcPackets": 1,
    }

    peers["rust"] = "8.8.8.8:4000"
    with pytest.raises(RuntimeError, match="nonlocal peer"):
        module.audit_local_kad_diagnostics(
            rust_dir,
            mfc_dir,
            expected_ip="10.1.2.3",
            rust_process_id=41,
            mfc_process_id=42,
        )
    peers["rust"] = "10.1.2.3:4000"
    peers["emule"] = "8.8.8.8:4001"
    with pytest.raises(RuntimeError, match="nonlocal peer"):
        module.audit_local_kad_diagnostics(
            rust_dir,
            mfc_dir,
            expected_ip="10.1.2.3",
            rust_process_id=41,
            mfc_process_id=42,
        )


def test_local_kad_exchange_requires_decoded_two_way_bootstrap(tmp_path: Path) -> None:
    module = load_suite_module()
    pairs = [
        ("send", "KADEMLIA2_BOOTSTRAP_REQ"),
        ("recv", "KADEMLIA2_BOOTSTRAP_REQ"),
        ("send", "KADEMLIA2_BOOTSTRAP_RES"),
    ]
    records = [
        {"body": {"direction": direction, "opcodeName": opcode}}
        for direction, opcode in pairs
    ]
    module.current_kad_packet_records = lambda *_args, **_kwargs: list(records)
    assert module.local_kad_exchange_evidence(tmp_path, process_id=41) is None
    records.append(
        {"body": {"direction": "recv", "opcodeName": "KADEMLIA2_BOOTSTRAP_RES"}}
    )
    assert module.local_kad_exchange_evidence(tmp_path, process_id=41) == {
        f"{direction}:{opcode}": 1 for direction, opcode in pairs + [("recv", "KADEMLIA2_BOOTSTRAP_RES")]
    }


def test_cross_client_shared_root_uses_current_object_contract(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    calls = []
    monkeypatch.setattr(module, "request_json", lambda *args, **kwargs: calls.append((args, kwargs)) or {})
    monkeypatch.setattr(module, "wait_for_rust_shared_file", lambda *_args, **_kwargs: {"name": "fixture.bin"})

    module.publish_rust_shared_tree(
        "http://192.0.2.10:4711", "key", root=tmp_path, file_name="fixture.bin", timeout_seconds=1.0,
    )

    assert calls[0][0][4]["roots"] == [{"path": str(tmp_path)}]


def test_cross_client_diagnostics_require_both_unified_peer_streams(tmp_path: Path) -> None:
    module = load_suite_module()
    rust = tmp_path / "rust"
    mfc = tmp_path / "mfc"
    rust.mkdir()
    mfc.mkdir()

    with pytest.raises(DiagnosticTraceError, match="rust diagnostics"):
        module.require_diagnostics(rust, mfc, kad_required=False)


def test_cross_client_diagnostics_require_client_udp_family_on_both_sides(
    monkeypatch,
    tmp_path: Path,
) -> None:
    module = load_suite_module()
    def diag_records(_directory, *, side):
        family = "ed2k_client_udp" if side == "rust" else "sched"
        return [
            {
                "schema": "diag_event_v2",
                "client": side,
                "ts": "2026-10-24T00:00:00.000Z",
                "family": "ed2k_tcp",
                "event": "packet",
                "keys": {
                    "peer": "192.0.2.1:4662",
                    "protocolMarker": 0xE3,
                    "opcode": 0x01,
                },
                "body": {
                    "direction": "recv",
                    "flow": "listener",
                    "transportMode": "plaintext",
                    "obfuscated": False,
                    "protocolMarker": 0xE3,
                    "protocolName": "ed2k",
                    "opcode": 0x01,
                    "opcodeName": "OP_HELLO",
                    "rawLen": 6,
                    "rawHex": "e30100000001",
                    "payloadLen": 0,
                    "payloadHex": "",
                    "payloadHexTruncated": False,
                },
            },
            {
                "schema": "diag_event_v2",
                "family": family,
                "event": "packet" if family == "ed2k_client_udp" else "source_count",
                "keys": {},
                "body": {
                    "direction": "recv",
                    "outcome": "accepted",
                    "rawHex": "c590",
                }
                if family == "ed2k_client_udp"
                else {"sourceCount": 1},
            }
        ]

    monkeypatch.setattr(
        module.converged_live_wire,
        "load_current_diag_records",
        diag_records,
    )

    with pytest.raises(RuntimeError, match="required-family"):
        module.require_diagnostics(tmp_path / "rust", tmp_path / "mfc", kad_required=False)


def test_cross_client_diagnostics_load_all_segments_and_mfc_health(tmp_path: Path) -> None:
    module = load_suite_module()
    rust = tmp_path / "rust"
    mfc = tmp_path / "mfc"
    rust.mkdir()
    mfc.mkdir()
    for client, directory, process_id, run_id in (
        ("rust", rust, 41, "rust-run"),
        ("mfc", mfc, 42, "mfc-run"),
    ):
        for segment_id in (0, 1):
            path = directory / (
                f"emulebb-{client}-diag-{process_id}-{run_id}-{segment_id:06}.jsonl"
            )
            attempt_id = 11 if client == "rust" else 21
            body = {
                "direction": "send",
                "sendAttemptId": attempt_id,
                "role": "reask_request",
                "opcode": 0x90,
            }
            event = "packet" if segment_id == 0 else "send_outcome"
            if event == "packet":
                body.update({"outcome": "attempted", "rawHex": "c590", "rawLen": 2})
            else:
                body.update({"outcome": "send_succeeded", "deliveryKnown": True})
            records = [
                {
                        "schema": "diag_event_v2",
                        "client": client,
                        "processId": process_id,
                        "runId": run_id,
                        "segmentId": segment_id,
                        "seq": segment_id + 1,
                        "streamSeq": segment_id + 1,
                        "family": "ed2k_client_udp",
                        "event": event,
                        "keys": {
                            "peer": "192.0.2.1:4672",
                            "protocolMarker": 0xC5,
                            "opcode": 0x90,
                            "sendAttemptId": attempt_id,
                        },
                        "body": body,
                }
            ]
            if segment_id == 0:
                records.append(
                    {
                        "schema": "diag_event_v2",
                        "client": client,
                        "processId": process_id,
                        "runId": run_id,
                        "segmentId": segment_id,
                        "seq": 2,
                        "streamSeq": 1,
                        "family": "ed2k_tcp",
                        "event": "packet",
                        "ts": "2026-10-24T00:00:00.000Z",
                        "keys": {
                            "peer": "192.0.2.1:4662",
                            "protocolMarker": 0xE3,
                            "opcode": 0x01,
                        },
                        "body": {
                            "direction": "recv",
                            "flow": "listener",
                            "transportMode": "plaintext",
                            "obfuscated": False,
                            "protocolMarker": 0xE3,
                            "protocolName": "ed2k",
                            "opcode": 0x01,
                            "opcodeName": "OP_HELLO",
                            "rawLen": 6,
                            "rawHex": "e30100000001",
                            "payloadLen": 0,
                            "payloadHex": "",
                            "payloadHexTruncated": False,
                        },
                    }
                )
            if segment_id == 1:
                records[0]["seq"] = 3
            path.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )

    active_mfc = mfc / "emulebb-mfc-diag-42-mfc-run-000001.jsonl"
    (mfc / "emulebb-mfc-diag-health.json").write_text(
        json.dumps(
            {
                "schema": "diag_event_v2",
                "enabled": True,
                "configured": True,
                "initialized": True,
                "runId": "mfc-run",
                "processId": 42,
                "activeSegmentId": 1,
                "activeFileName": active_mfc.name,
                "droppedEvents": 0,
                "encodeErrors": 0,
                "writeErrors": 0,
                "retentionDeleteErrors": 0,
                "initializationFailure": None,
            }
        ),
        encoding="utf-8",
    )
    (mfc / "emulebb-verbose.log").write_text("Connected\n", encoding="utf-8")

    assert module.require_diagnostics(rust, mfc, kad_required=False) == {
        "rust": {
            "packetRecords": 1,
            "eventRecords": 3,
            "clientUdp": {
                "records": 2,
                "packets": 1,
                "sendAttempts": 1,
                "sendTerminals": 1,
                "outcomes": {"send_succeeded": 1},
            },
        },
        "emule": {
            "packetRecords": 1,
            "eventRecords": 3,
            "clientUdp": {
                "records": 2,
                "packets": 1,
                "sendAttempts": 1,
                "sendTerminals": 1,
                "outcomes": {"send_succeeded": 1},
            },
        },
        "mfcSecureIdent": {"failureLines": 0},
    }


def _download_lifecycle_events(
    transfer_hash: str,
    peer: str,
    *,
    first_seq: int,
) -> list[dict[str, object]]:
    def event(seq: int, name: str, body: dict[str, object]) -> dict[str, object]:
        return {
            "schema": "diag_event_v2",
            "family": "sched",
            "seq": seq,
            "event": name,
            "keys": {"fileHash": transfer_hash, "peer": peer},
            "body": body,
        }

    return [
        event(first_seq, "source_engaged", {"outcome": "engaged"}),
        event(
            first_seq + 1,
            "source_conn_budget",
            {"outcome": "admit", "activeConnections": 1, "connectionCap": 1},
        ),
        event(first_seq + 2, "source_dropped", {"outcome": "dropped"}),
        event(
            first_seq + 3,
            "download_task_settled",
            {"state": "completed", "willReask": False},
        ),
    ]


def test_download_connection_reuse_requires_second_admission_after_settlement() -> None:
    module = load_suite_module()
    first_hash = "00112233445566778899aabbccddeeff"
    second_hash = "ffeeddccbbaa99887766554433221100"
    peer = "192.0.2.20:4662"
    records = [
        *_download_lifecycle_events(first_hash, peer, first_seq=10),
        *_download_lifecycle_events(second_hash, peer, first_seq=20),
    ]

    evidence = module.download_connection_reuse_evidence(records, first_hash, second_hash)

    assert evidence is not None
    assert evidence["connectionCap"] == 1
    assert evidence["samePeer"] is True
    assert evidence["first"]["taskSettled"]["seq"] == 13
    assert evidence["second"]["connectionAdmitted"]["seq"] == 21


def test_download_connection_reuse_rejects_pre_settlement_second_admission() -> None:
    module = load_suite_module()
    first_hash = "00112233445566778899aabbccddeeff"
    second_hash = "ffeeddccbbaa99887766554433221100"
    peer = "192.0.2.20:4662"
    records = [
        *_download_lifecycle_events(second_hash, peer, first_seq=10),
        *_download_lifecycle_events(first_hash, peer, first_seq=20),
    ]

    assert module.download_connection_reuse_evidence(records, first_hash, second_hash) is None


def test_load_rust_diag_records_rejects_legacy_unsegmented_input(tmp_path: Path) -> None:
    module = load_suite_module()
    trace = tmp_path / "emulebb-rust-diag-123.jsonl"
    trace.write_text(
        "not-json\n"
        + json.dumps({"schema": "diag_event_v1", "seq": 2, "family": "sched"})
        + "\n"
        + json.dumps({"schema": "other", "seq": 1})
        + "\n"
        + json.dumps({"schema": "diag_event_v1", "seq": 1, "family": "sched"})
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="no diag_event_v2"):
        module.load_rust_diag_records(tmp_path)


def test_load_rust_diag_records_uses_only_the_latest_v2_run(tmp_path: Path) -> None:
    module = load_suite_module()
    stale = tmp_path / "emulebb-rust-diag-41-stale-000000.jsonl"
    stale.write_text(
        json.dumps(
            {
                "schema": "diag_event_v2",
                "client": "rust",
                "runId": "stale",
                "processId": 41,
                "segmentId": 0,
                "seq": 99,
                "streamSeq": 99,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    active = tmp_path / "emulebb-rust-diag-42-active-000000.jsonl"
    active.write_text(
        json.dumps(
            {
                "schema": "diag_event_v2",
                "client": "rust",
                "runId": "active",
                "processId": 42,
                "segmentId": 0,
                "seq": 1,
                "streamSeq": 1,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    os.utime(stale, ns=(1, 1))
    os.utime(active, ns=(2, 2))

    records = module.load_rust_diag_records(tmp_path)
    assert [(record["runId"], record["seq"]) for record in records] == [("active", 1)]


def test_cross_client_rejects_mfc_secure_ident_failure(tmp_path: Path) -> None:
    module = load_suite_module()
    log = tmp_path / "emulebb-verbose.log"
    log.write_text("Connected to local peer\n", encoding="utf-8")
    assert module.require_mfc_secure_ident_clean(log) == {"failureLines": 0}
    log.write_text("Error: Unknown exception in CClientCreditsList::VerifyIdent\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="rejected Rust secure identification"):
        module.require_mfc_secure_ident_clean(log)


def test_cross_client_fixture_names_are_unicode() -> None:
    module = load_suite_module()

    assert "Unicode-\u00e9-\u6f22" in module.rust_to_emulebb_fixture_name()
    assert "Unicode-\u00e9-\u6f22" in module.rust_shared_tree_fixture_name()
    assert "Unicode-\u00e9-\u6f22" in module.emulebb_to_rust_fixture_name()
    assert "Unicode-\u00e9-\u6f22" in module.emulebb_to_rust_reuse_fixture_name()
    assert not module.rust_to_emulebb_fixture_name().isascii()
    assert not module.rust_shared_tree_fixture_name().isascii()
    assert not module.emulebb_to_rust_fixture_name().isascii()
    assert not module.emulebb_to_rust_reuse_fixture_name().isascii()


def test_cross_client_validate_optional_soak_args_accepts_upload_limits() -> None:
    module = load_suite_module()
    args = SimpleNamespace(
        rust_upload_limit_kibps=64,
        emulebb_upload_limit_kibps=64,
    )

    module.validate_optional_soak_args(args)


def test_cross_client_validate_optional_soak_args_rejects_bad_upload_limit() -> None:
    module = load_suite_module()
    args = SimpleNamespace(
        rust_upload_limit_kibps=0,
        emulebb_upload_limit_kibps=None,
    )

    with pytest.raises(ValueError, match="rust-upload-limit-kibps"):
        module.validate_optional_soak_args(args)


def test_decoded_ed2k_link_name_handles_url_escaped_unicode() -> None:
    module = load_suite_module()

    name = module.decoded_ed2k_link_name({"name": "emulebb-to-emulebb-rust-Unicode-%C3%A9-%E6%BC%A2.bin"})

    assert name == "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin"


def test_completed_incoming_path_uses_decoded_unicode_name(tmp_path: Path) -> None:
    module = load_suite_module()

    path = module.completed_incoming_path(
        tmp_path, {"name": "emulebb-rust-shared-tree-Unicode-%C3%A9-%E6%BC%A2.bin"}
    )

    assert path == tmp_path / "emulebb-rust-shared-tree-Unicode-\u00e9-\u6f22.bin"
    with pytest.raises(ValueError, match="safe local filename"):
        module.completed_incoming_path(tmp_path, {"name": "..%2Fescape.bin"})


def test_cross_client_requirements_accept_unicode_and_manifest_metadata() -> None:
    module = load_suite_module()
    shared_tree_name = "emulebb-rust-shared-tree-Unicode-\u00e9-\u6f22.bin"

    requirements = module.require_cross_client_requirements(
        {
            "fixture": {"name": "emulebb-rust-to-emulebb-Unicode-\u00e9-\u6f22.bin"},
            "emulebb_fixture": {"name": "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin"},
            "rust_shared_tree": {"name": shared_tree_name, "recursive": True},
            "checks": {
                "rust_shared_tree_publish": {
                    "sharedFiles": {
                        "matched": {
                            "name": shared_tree_name,
                            "ed2kLink": "ed2k://|file|fixture.bin|1|00112233445566778899aabbccddeeff|/",
                        }
                    }
                },
                "rust_emulebb_manifest_metadata": {
                    "canonicalName": "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin",
                    "sourceUserHashCount": 1,
                    "expectedHashsetCount": 2,
                    "md4HashsetAcquired": True,
                    "md4HashsetCount": 2,
                    "aichHashsetAcquired": True,
                    "aichHashsetCount": 2,
                }
            },
        }
    )

    assert requirements["bidirectionalTransfers"] is True
    assert requirements["unicodeFixtureNames"] is True
    assert requirements["recursiveSharedTreeUpload"] is True
    assert requirements["rustPersistedSourceUserHash"] is True
    assert requirements["rustPersistedMd4Hashset"] is True
    assert requirements["rustPersistedAichHashset"] is True


def test_cross_client_requirements_accept_single_part_empty_hashsets() -> None:
    module = load_suite_module()
    shared_tree_name = "emulebb-rust-shared-tree-Unicode-\u00e9-\u6f22.bin"

    requirements = module.require_cross_client_requirements(
        {
            "fixture": {"name": "emulebb-rust-to-emulebb-Unicode-\u00e9-\u6f22.bin"},
            "emulebb_fixture": {"name": "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin"},
            "rust_shared_tree": {"name": shared_tree_name, "recursive": True},
            "checks": {
                "rust_shared_tree_publish": {"sharedFiles": {"matched": {"name": shared_tree_name}}},
                "rust_emulebb_manifest_metadata": {
                    "canonicalName": "emulebb-to-emulebb-rust-Unicode-\u00e9-\u6f22.bin",
                    "sourceUserHashCount": 1,
                    "expectedHashsetCount": 0,
                    "md4HashsetAcquired": True,
                    "md4HashsetCount": 0,
                    "aichHashsetAcquired": True,
                    "aichHashsetCount": 0,
                },
            },
        }
    )

    assert requirements["rustPersistedMd4Hashset"] is True
    assert requirements["rustPersistedAichHashset"] is True


def test_cross_client_requirements_reject_ascii_fixture_names() -> None:
    module = load_suite_module()

    try:
        module.require_cross_client_requirements(
            {
                "fixture": {"name": "emulebb-rust-to-emulebb.bin"},
                "emulebb_fixture": {"name": "emulebb-to-emulebb-rust.bin"},
                "rust_shared_tree": {"name": "emulebb-rust-shared-tree.bin", "recursive": True},
                "checks": {
                    "rust_shared_tree_publish": {
                        "sharedFiles": {
                            "matched": {
                                "name": "emulebb-rust-shared-tree.bin",
                                "ed2kLink": "ed2k://|file|fixture.bin|1|00112233445566778899aabbccddeeff|/",
                            }
                        }
                    },
                    "rust_emulebb_manifest_metadata": {
                        "canonicalName": "emulebb-to-emulebb-rust.bin",
                        "sourceUserHashCount": 1,
                        "expectedHashsetCount": 2,
                        "md4HashsetAcquired": True,
                        "md4HashsetCount": 2,
                        "aichHashsetAcquired": True,
                        "aichHashsetCount": 2,
                    }
                },
            }
        )
    except RuntimeError as exc:
        assert "Unicode" in str(exc)
    else:
        raise AssertionError("ASCII cross-client fixture names were accepted")


def test_write_rust_shared_tree_fixture_uses_nested_recursive_fixture(tmp_path: Path) -> None:
    module = load_suite_module()

    fixture = module.write_rust_shared_tree_fixture(tmp_path / "shared-tree", 4097)

    assert fixture["recursive"] is True
    assert fixture["unicode_name"] is True
    assert Path(fixture["path"]).is_file()
    assert Path(fixture["path"]).parent == tmp_path / "shared-tree" / "alpha" / "beta"
    assert fixture["name"] == module.rust_shared_tree_fixture_name()
    assert fixture["size"] == 4097
    assert len(str(fixture["sha256"])) == 64


def test_materialize_local_profile_seed_adds_run_server_met(tmp_path: Path) -> None:
    module = load_suite_module()
    seed = tmp_path / "seed"
    seed.mkdir()
    for name in module.MFC_PROFILE_SEED_FILES:
        (seed / name).write_bytes(name.encode("ascii"))

    output = module.materialize_local_profile_seed(
        seed,
        tmp_path / "generated-seed",
        server_address="192.0.2.44",
        server_port=4711,
        server_name="local-cross-client",
    )

    for name in module.MFC_PROFILE_SEED_FILES:
        assert (output / name).read_bytes() == name.encode("ascii")
    server_met = output / "server.met"
    assert server_met.is_file()
    assert b"local-cross-client" in server_met.read_bytes()


def test_publish_rust_shared_tree_configures_current_root_and_returns_link(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    calls: list[tuple[str, str, object]] = []

    def fake_request_json(_base_url, method, path, _api_key, body=None):
        calls.append((method, path, body))
        if path == "/api/v1/shared-directories":
                return {"roots": body["roots"], "items": []}
        if path == "/api/v1/shared-directories/operations/reload":
            return {"ok": True}
        if path == "/api/v1/shared-files":
            return {
                "items": [
                    {
                        "name": "Nested.bin",
                        "ed2kLink": "ed2k://|file|Nested.bin|1|00112233445566778899aabbccddeeff|/",
                    }
                ]
            }
        if path == "/api/v1/status":
            return {"stats": {"sharedHashingCount": 0}}
        raise AssertionError(path)

    monkeypatch.setattr(module, "request_json", fake_request_json)

    result = module.publish_rust_shared_tree(
        "http://192.0.2.10:4711",
        "key",
        root=tmp_path / "shared-tree",
        file_name="Nested.bin",
        timeout_seconds=1.0,
    )

    assert calls[0] == (
        "PATCH",
        "/api/v1/shared-directories",
        {"roots": [{"path": str(tmp_path / "shared-tree")}], "confirmReplaceRoots": True},
    )
    assert calls[1] == ("POST", "/api/v1/shared-directories/operations/reload", None)
    assert calls[2] == ("GET", "/api/v1/shared-files", None)
    assert calls[3] == ("GET", "/api/v1/status", None)
    assert result["sharedFiles"]["matched"]["name"] == "Nested.bin"


def test_rust_emulebb_manifest_metadata_requires_md4_aich_and_source_identity(tmp_path: Path) -> None:
    module = load_suite_module()
    transfer_hash = "00112233445566778899aabbccddeeff"
    metadata_db = tmp_path / "emulebb-rust-metadata.db"
    rust_metadata.create_metadata_db(_rust_repo(), metadata_db)
    rust_metadata.seed_transfer_manifest(
        metadata_db,
        ed2k_hash=transfer_hash,
        name="emulebb-to-emulebb-rust.bin",
        size_bytes=module.ED2K_PART_SIZE_BYTES + 1,
        piece_size=module.ED2K_PART_SIZE_BYTES,
        md4_hashset_acquired=True,
        md4_hashset=[
            "0123456789abcdef0123456789abcdef",
            "fedcba9876543210fedcba9876543210",
        ],
        aich_hashset_acquired=True,
        aich_root="59ba286e4c4b8f0019c9fd89806d7212b37c82d6",
        aich_hashset=[
            "044c4a5f2af419cc2b6b06f69f5e3bd655ec6edb",
            "06fd075b8705ae9189470c69a70e2d5d5593ca09",
        ],
        sources=[{"ip": "192.0.2.44", "tcp_port": 4662, "user_hash": "31719b50f40e503c1d533d9af3ef6fb8"}],
    )

    metadata = module.require_rust_download_manifest_metadata(
        tmp_path,
        transfer_hash=transfer_hash,
        expected_name="emulebb-to-emulebb-rust.bin",
        expected_size=module.ED2K_PART_SIZE_BYTES + 1,
        require_aich_hashset=True,
    )

    assert metadata["expectedPartCount"] == 2
    assert metadata["expectedHashsetCount"] == 2
    assert metadata["md4HashsetCount"] == 2
    assert metadata["aichHashsetAcquired"] is True
    assert metadata["aichHashsetCount"] == 2
    assert metadata["sourceUserHashCount"] == 1


def test_rust_emulebb_manifest_metadata_rejects_missing_required_aich(tmp_path: Path) -> None:
    module = load_suite_module()
    transfer_hash = "00112233445566778899aabbccddeeff"
    metadata_db = tmp_path / "emulebb-rust-metadata.db"
    rust_metadata.create_metadata_db(_rust_repo(), metadata_db)
    rust_metadata.seed_transfer_manifest(
        metadata_db,
        ed2k_hash=transfer_hash,
        name="emulebb-to-emulebb-rust.bin",
        size_bytes=module.ED2K_PART_SIZE_BYTES,
        piece_size=module.ED2K_PART_SIZE_BYTES,
        md4_hashset_acquired=True,
        md4_hashset=[],
        aich_hashset_acquired=False,
        aich_hashset=[],
        sources=[{"ip": "192.0.2.44", "tcp_port": 4662, "user_hash": "31719b50f40e503c1d533d9af3ef6fb8"}],
    )

    with pytest.raises(RuntimeError, match="AICH hashset"):
        module.require_rust_download_manifest_metadata(
            tmp_path,
            transfer_hash=transfer_hash,
            expected_name="emulebb-to-emulebb-rust.bin",
            expected_size=module.ED2K_PART_SIZE_BYTES,
            require_aich_hashset=True,
        )


def test_rust_emulebb_manifest_metadata_accepts_empty_single_part_hashsets(tmp_path: Path) -> None:
    module = load_suite_module()
    transfer_hash = "00112233445566778899aabbccddeeff"
    metadata_db = tmp_path / "emulebb-rust-metadata.db"
    rust_metadata.create_metadata_db(_rust_repo(), metadata_db)
    rust_metadata.seed_transfer_manifest(
        metadata_db,
        ed2k_hash=transfer_hash,
        name="emulebb-to-emulebb-rust.bin",
        size_bytes=module.ED2K_PART_SIZE_BYTES,
        piece_size=module.ED2K_PART_SIZE_BYTES,
        md4_hashset_acquired=True,
        md4_hashset=[],
        aich_hashset_acquired=True,
        aich_root="59ba286e4c4b8f0019c9fd89806d7212b37c82d6",
        aich_hashset=[],
        sources=[{"ip": "192.0.2.44", "tcp_port": 4662, "user_hash": "31719b50f40e503c1d533d9af3ef6fb8"}],
    )

    metadata = module.require_rust_download_manifest_metadata(
        tmp_path,
        transfer_hash=transfer_hash,
        expected_name="emulebb-to-emulebb-rust.bin",
        expected_size=module.ED2K_PART_SIZE_BYTES,
        require_aich_hashset=True,
    )

    assert metadata["expectedPartCount"] == 1
    assert metadata["expectedHashsetCount"] == 0
    assert metadata["md4HashsetAcquired"] is True
    assert metadata["md4HashsetCount"] == 0
    assert metadata["aichHashsetAcquired"] is True
    assert metadata["aichHashsetCount"] == 0


def test_cross_client_uses_shared_ed2k_harness_launcher_and_stops_it_on_failure(
    monkeypatch, tmp_path: Path
) -> None:
    module = load_suite_module()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    rust_repo = tmp_path / "emulebb-rust"
    rust_repo.mkdir()
    (rust_repo / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    server_process = object()
    calls: dict[str, object] = {"stopped": []}

    paths = SimpleNamespace(
        workspace_root=workspace,
        source_artifacts_dir=tmp_path / "artifacts",
        seed_config_dir=tmp_path / "seed",
        app_exe=tmp_path / "emulebb.exe",
    )
    paths.source_artifacts_dir.mkdir()
    monkeypatch.setattr(module.harness_cli_common, "prepare_run_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(module.harness_cli_common, "write_json_file", lambda path, payload: calls.setdefault("report", payload))
    monkeypatch.setattr(module.harness_cli_common, "publish_run_artifacts", lambda _paths: None)
    monkeypatch.setattr(module.harness_cli_common, "publish_latest_report", lambda _paths: None)
    monkeypatch.setattr(module.harness_cli_common, "cleanup_source_artifacts", lambda _paths: None)
    monkeypatch.setattr(module, "resolve_manifest_repo", lambda _workspace, key: rust_repo if key == "emulebb_rust" else tmp_path / key)
    monkeypatch.setattr(
        module.dtt,
        "choose_distinct_ports",
        lambda lan_bind_addr: {
            "ed2k_tcp": 4661,
            "ed2k_udp": 4665,
            "ed2k_admin": 8080,
            "client1_rest": 4711,
            "client1_tcp": 4662,
            "client1_udp": 4672,
            "client2_tcp": 5662,
            "client2_udp": 5672,
        },
    )
    monkeypatch.setattr(module, "choose_extra_port", lambda _lan_bind_addr, used_ports, *, udp=False: max(used_ports) + 1)

    def fake_launch_ed2k_server(**kwargs):
        calls["ed2k_launch"] = kwargs
        return SimpleNamespace(
            process=server_process,
            admin_base_url="http://192.0.2.10:8080",
            ed2k_host="172.17.142.32",
            ed2k_port=4661,
            build={"skipped": True},
            health={"ok": True},
            config={"listen_address": f"{kwargs['ed2k_address']}:{kwargs['ed2k_port']}"},
        )

    monkeypatch.setattr(module.ed2k_harness, "launch_ed2k_server", fake_launch_ed2k_server)
    monkeypatch.setattr(module.ed2k_harness, "resolve_route_bind_ip", lambda _host, _port: "172.17.128.1")
    monkeypatch.setattr(module.ed2k_harness, "stop_process", lambda process: calls["stopped"].append(process))
    monkeypatch.setattr(module.rust_client, "stop_process_tree", lambda process: calls.setdefault("rust_stop", process))
    monkeypatch.setattr(module.dtt, "discover_interface_ipv4", lambda _name: "192.0.2.10")

    def fail_after_ed2k_server_started(*_args, **kwargs):
        calls["rust_profile"] = kwargs
        raise RuntimeError("stop after shared ED2K harness launch")

    monkeypatch.setattr(module.rust_client, "write_rust_profile", fail_after_ed2k_server_started)

    exit_code = module.main(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--p2p-bind-interface-address",
            "198.51.100.20",
        ]
    )

    assert exit_code == 1
    assert calls["ed2k_launch"]["admin_address"] == "192.0.2.10"
    assert calls["ed2k_launch"]["ed2k_address"] == "198.51.100.20"
    assert calls["stopped"] == [server_process]
    assert calls["report"]["current_phase"] == "start_ed2k_server"
    assert calls["report"]["network"]["lan_bind_addr"] == "192.0.2.10"
    assert calls["report"]["network"]["p2p_bind_interface_address"] == "198.51.100.20"
    assert calls["report"]["network"]["server_endpoint"] == "172.17.142.32:4661"
    assert calls["rust_profile"]["p2p_bind_ip"] == "172.17.128.1"
    assert calls["rust_profile"]["ed2k_nickname"] == module.CLIENT_RUST.nick
