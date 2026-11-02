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


def test_capacity_oracle_reads_all_health_validated_segments(tmp_path: Path) -> None:
    module = _load_module()
    _write_mfc_run(tmp_path)

    assert module.max_waiting_sessions(tmp_path) == 3


def test_capacity_oracle_rejects_missing_writer_health(tmp_path: Path) -> None:
    module = _load_module()
    _write_mfc_run(tmp_path)
    (tmp_path / "emulebb-mfc-diag-health.json").unlink()

    with pytest.raises(ValueError, match="missing MFC diagnostic writer health"):
        module.max_waiting_sessions(tmp_path)


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
                    "lowId": False,
                    "queueRank": 1,
                },
                {
                    "address": "127.0.0.10",
                    "port": 4662,
                    "userHash": SOURCE_USER_HASH,
                    "downloadState": "onqueue",
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
