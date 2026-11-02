from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from tests.python.diagnostic_fixtures import current_diagnostic_writer_health


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "emulebb-rust-reask-cross-client.py"
FILE_HASH = "44556677889900112233aabbccddeeff"
SOURCE_TCP_ENDPOINT = "127.0.0.10:4662"
SOURCE_UDP_ENDPOINT = "127.0.0.10:4672"
SOURCE_USER_HASH = "11223344556677889900aabbccddeeff"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "emulebb_rust_reask_cross_client_test", SCRIPT
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_mfc_run(log_dir: Path) -> None:
    for segment_id, waiting_sessions in ((0, 1), (1, 3)):
        segment = log_dir / f"emulebb-mfc-diag-42-active-{segment_id:06}.jsonl"
        segment.write_text(
            json.dumps(
                {
                    "schema": "diag_event_v2",
                    "client": "mfc",
                    "processId": 42,
                    "runId": "active",
                    "segmentId": segment_id,
                    "seq": segment_id + 1,
                    "streamSeq": segment_id + 1,
                    "event": "capacity_snapshot",
                    "body": {
                        "effectiveSlotCap": 2,
                        "activeSlots": 2,
                        "waitingSessions": waiting_sessions,
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
    active = log_dir / "emulebb-mfc-diag-42-active-000001.jsonl"
    (log_dir / "emulebb-mfc-diag-health.json").write_text(
        json.dumps(
            current_diagnostic_writer_health(
                client="mfc",
                run_id="active",
                segment_id=1,
                active_file_name=active.name,
            )
        ),
        encoding="utf-8",
    )


def _registration_record() -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "family": "sched",
        "event": "udp_reask_source_registered",
        "keys": {
            "fileHash": FILE_HASH,
            "peer": SOURCE_TCP_ENDPOINT,
            "peerHash": SOURCE_USER_HASH,
        },
        "body": {
            "outcome": "accepted",
            "sourceUdpEndpoint": SOURCE_UDP_ENDPOINT,
            "sourceUdpVersion": 4,
            "lowId": False,
            "buddyEndpoint": None,
            "buddyId": None,
        },
    }


def _applied_record() -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "family": "sched",
        "event": "udp_reask_reply_applied",
        "keys": {
            "fileHash": FILE_HASH,
            "peer": SOURCE_TCP_ENDPOINT,
            "peerHash": SOURCE_USER_HASH,
        },
        "body": {
            "outcome": "applied",
            "sourceUdpVersion": 4,
            "requestPendingAfter": False,
        },
    }


def test_capacity_precondition_reads_health_validated_segments(tmp_path: Path) -> None:
    module = _load_module()
    _write_mfc_run(tmp_path)

    assert (
        module.wait_for_upload_capacity(tmp_path, active_slots=2, timeout=0.1)[
            "waitingSessions"
        ]
        == 3
    )


def test_capacity_records_reject_missing_writer_health(tmp_path: Path) -> None:
    module = _load_module()
    _write_mfc_run(tmp_path)
    (tmp_path / "emulebb-mfc-diag-health.json").unlink()

    with pytest.raises(ValueError, match="missing MFC diagnostic writer health"):
        module._mfc_capacity_snapshots(tmp_path)


def test_rust_capacity_requires_one_exact_opened_production_slot(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "current_diag_records",
        lambda *_args, **_kwargs: [
            {
                "schema": "diag_event_v2",
                "family": "sched",
                "event": "capacity_snapshot",
                "seq": 1,
                "body": {
                    "baseSlots": 1,
                    "elasticSlots": 0,
                    "effectiveSlotCap": 1,
                    "activeSlots": 1,
                    "waitingSessions": 0,
                },
            },
            {
                "schema": "diag_event_v2",
                "family": "sched",
                "event": "upload_slot_opened",
                "seq": 2,
                "keys": {
                    "fileHash": FILE_HASH,
                    "peer": SOURCE_TCP_ENDPOINT,
                },
                "body": {"outcome": "opened"},
            },
        ],
    )

    assert module.wait_for_rust_occupied_upload_slot(
        Path("unused"),
        file_hash=FILE_HASH,
        peer_endpoint=SOURCE_TCP_ENDPOINT,
        timeout=0.1,
    )["slotOpenedSequence"] == 2


def test_server_publication_uses_exact_named_client(monkeypatch) -> None:
    module = _load_module()

    class FakeControl:
        def wait_for_client_shared_files(self, nickname, minimum, timeout):
            assert (nickname, minimum, timeout) == ("rust-responder", 1, 1.0)
            return {
                "client_name": nickname,
                "ip": "192.0.2.241",
                "high_id": True,
                "shared_files": 1,
            }

    monkeypatch.setattr(
        module.ed2k_harness,
        "ed2k_server_control",
        lambda base_url, secret: FakeControl(),
    )

    assert module.wait_for_server_client_publication(
        "http://server.test",
        "secret",
        "rust-responder",
        1.0,
    ) == {
        "clientName": "rust-responder",
        "address": "192.0.2.241",
        "highId": True,
        "sharedFiles": 1,
    }


def test_server_publication_rejects_fragment_match(monkeypatch) -> None:
    module = _load_module()

    class FakeControl:
        def wait_for_client_shared_files(self, *_args):
            return {"client_name": "rust-responder-other", "shared_files": 1}

    monkeypatch.setattr(
        module.ed2k_harness,
        "ed2k_server_control",
        lambda base_url, secret: FakeControl(),
    )

    with pytest.raises(RuntimeError, match="expected 'rust-responder'"):
        module.wait_for_server_client_publication(
            "http://server.test",
            "secret",
            "rust-responder",
            1.0,
        )


def test_server_client_precondition_rejects_low_id() -> None:
    module = _load_module()

    with pytest.raises(RuntimeError, match="observed 'rust-requester' as LowID"):
        module.require_server_high_id_client(
            {
                "client_name": "rust-requester",
                "ip": "172.17.128.213",
                "high_id": False,
                "shared_files": 0,
            },
            nickname="rust-requester",
        )


def test_exact_direct_v4_registration_builds_control_identity() -> None:
    module = _load_module()

    identity = module.find_udp_reask_registration(
        [_registration_record()],
        file_hash=FILE_HASH.upper(),
        source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
        source_udp_endpoint=SOURCE_UDP_ENDPOINT,
    )

    assert identity == {
        "fileHash": FILE_HASH,
        "sourceTcpEndpoint": SOURCE_TCP_ENDPOINT,
        "sourceUdpEndpoint": SOURCE_UDP_ENDPOINT,
        "sourceUserHash": SOURCE_USER_HASH,
        "sourceUdpVersion": 4,
    }
    assert module.queued_source_reask_request(
        file_hash=FILE_HASH,
        source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
        source_udp_endpoint=SOURCE_UDP_ENDPOINT,
        source_user_hash=SOURCE_USER_HASH,
    ) == {
        "fileHash": FILE_HASH,
        "sourceIp": "127.0.0.10",
        "sourceTcpPort": 4662,
        "sourceUdpPort": 4672,
        "sourceUserHash": SOURCE_USER_HASH,
        "sourceUdpVersion": 4,
    }


def test_registration_rejects_duplicate_exact_identity() -> None:
    module = _load_module()

    with pytest.raises(RuntimeError, match="multiple exact direct V4"):
        module.find_udp_reask_registration(
            [_registration_record(), _registration_record()],
            file_hash=FILE_HASH,
            source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
            source_udp_endpoint=SOURCE_UDP_ENDPOINT,
        )


def test_mfc_queue_identity_requires_exact_onqueue_highid_source() -> None:
    module = _load_module()
    rows = {
        "data": {
            "items": [
                {
                    "address": "127.0.0.11",
                    "port": 4662,
                    "userHash": "ffeeddccbbaa00998877665544332211",
                    "downloadState": "onqueue",
                    "tcpConnected": False,
                    "lowId": False,
                    "queueRank": 1,
                },
                {
                    "address": "127.0.0.10",
                    "port": 4662,
                    "userHash": SOURCE_USER_HASH,
                    "downloadState": "onqueue",
                    "tcpConnected": False,
                    "lowId": False,
                    "queueRank": 1,
                },
            ]
        }
    }

    assert module.find_mfc_queued_source(
        rows, source_ip="127.0.0.10", source_tcp_port=4662
    ) == {
        "sourceIp": "127.0.0.10",
        "sourceTcpPort": 4662,
        "sourceUserHash": SOURCE_USER_HASH,
        "queueRank": 1,
    }

    rows["data"]["items"][1]["downloadState"] = "connected"
    assert (
        module.find_mfc_queued_source(
            rows, source_ip="127.0.0.10", source_tcp_port=4662
        )
        is None
    )

    rows["data"]["items"][1]["downloadState"] = "onqueue"
    rows["data"]["items"][1]["tcpConnected"] = True
    assert (
        module.find_mfc_queued_source(
            rows, source_ip="127.0.0.10", source_tcp_port=4662
        )
        is None
    )


def test_upload_waiter_identity_requires_exact_requester_and_file() -> None:
    module = _load_module()
    rows = {
        "data": {
            "items": [
                {
                    "clientId": "wrong-port",
                    "address": "127.0.0.20",
                    "port": 4663,
                    "requestedFileHash": FILE_HASH,
                    "waitingQueue": True,
                },
                {
                    "clientId": "exact-waiter",
                    "address": "127.0.0.20",
                    "port": 4662,
                    "requestedFileHash": FILE_HASH.upper(),
                    "waitingQueue": True,
                },
            ]
        }
    }

    assert module.find_upload_waiter(
        rows,
        file_hash=FILE_HASH,
        requester_tcp_endpoint="127.0.0.20:4662",
    ) == {
        "clientId": "exact-waiter",
        "address": "127.0.0.20",
        "requestedFileHash": FILE_HASH,
        "waitingQueue": True,
    }


def test_upload_waiter_removal_requires_confirmed_absence(monkeypatch) -> None:
    module = _load_module()
    calls: list[str] = []

    def retry(_base_url, path, **_kwargs):
        calls.append(path)
        return {
            "status": 200,
            "raw_json": {"data": {"ok": True, "removed": "queue"}},
        }

    monkeypatch.setattr(module.dtt, "retry_rest_request", retry)
    monkeypatch.setattr(
        module.cc,
        "request_json",
        lambda *_args, **_kwargs: {"data": {"items": []}},
    )
    waiter = {
        "clientId": "127.0.0.20:4662",
        "address": "127.0.0.20",
        "requestedFileHash": FILE_HASH,
        "waitingQueue": True,
    }

    assert module.remove_upload_waiter(
        "http://responder.test",
        "secret",
        waiter=waiter,
        file_hash=FILE_HASH,
        requester_tcp_endpoint="127.0.0.20:4662",
        timeout=0.1,
    ) == {
        "waiter": waiter,
        "response": {
            "status": 200,
            "json": {"ok": True, "removed": "queue"},
        },
        "verifiedAbsent": True,
    }
    assert calls == [
        "/api/v1/upload-queue/127.0.0.20%3A4662/operations/remove"
    ]


def test_queue_pressure_receipt_uses_exact_requester_udp_endpoint(monkeypatch) -> None:
    module = _load_module()
    request = module.queue_pressure_request(
        file_hash=FILE_HASH.upper(),
        requester_udp_endpoint="127.0.0.20:4672",
    )
    payload = {
        "accepted": True,
        "fixtureId": 7,
        "fileHash": FILE_HASH,
        "sourceEndpoint": "127.0.0.20:4672",
        "actualWaitingUserCount": 0,
        "effectiveWaitingUserCount": 1951,
        "queueSize": 2000,
        "expiresAfterMillis": 30000,
        "state": "client-udp-queue-pressure-armed",
    }
    monkeypatch.setattr(
        module.dtt,
        "retry_rest_request",
        lambda *_args, **_kwargs: {
            "status": 200,
            "raw_json": {"data": payload},
        },
    )

    assert request == {
        "fileHash": FILE_HASH,
        "sourceIp": "127.0.0.20",
        "sourceUdpPort": 4672,
    }
    assert module.arm_queue_pressure(
        "http://responder.test",
        "secret",
        request,
    ) == {
        "request": request,
        "response": {"status": 200, "json": payload},
    }


def test_control_receipt_unwraps_only_the_api_data_envelope() -> None:
    module = _load_module()
    request = module.queued_source_reask_request(
        file_hash=FILE_HASH,
        source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
        source_udp_endpoint=SOURCE_UDP_ENDPOINT,
        source_user_hash=SOURCE_USER_HASH,
    )
    response_payload = {
        "accepted": True,
        "fileHash": FILE_HASH,
        "sourceEndpoint": SOURCE_UDP_ENDPOINT,
        "sourceTcpPort": 4662,
        "sourceUserHash": SOURCE_USER_HASH,
        "sourceUdpVersion": 4,
        "state": "queued-source-reask-pending",
    }

    assert module.queued_source_reask_receipt(
        request,
        {"status": 200, "raw_json": {"data": response_payload, "meta": {}}},
    ) == {
        "request": request,
        "response": {"status": 200, "json": response_payload},
    }


def test_exact_v4_application_is_required_once() -> None:
    module = _load_module()

    assert (
        module.find_udp_reask_applied(
            [_applied_record()],
            file_hash=FILE_HASH,
            source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
            source_user_hash=SOURCE_USER_HASH,
        )
        == _applied_record()
    )

    with pytest.raises(RuntimeError, match="multiple exact V4"):
        module.find_udp_reask_applied(
            [_applied_record(), _applied_record()],
            file_hash=FILE_HASH,
            source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
            source_user_hash=SOURCE_USER_HASH,
        )


def test_runner_loads_the_accepted_stock_client_udp_record() -> None:
    module = _load_module()

    record = module.load_stock_client_udp_record()

    assert record["recordId"] == "stock.client-udp.corpus"
    assert record["payloadDigest"] == (
        "sha256:89468db8e028268f21598216f5949ae11c2b1c3e1370b151d3d7136e8fda812b"
    )
