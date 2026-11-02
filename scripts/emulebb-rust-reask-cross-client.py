"""Prove one bilateral direct client-UDP reask scenario locally.

The canonical campaign runs both production directions against one deterministic
fixture and one upstream-clean local eD2K server:

* Rust requester -> MFC responder, with MFC's two real upload slots occupied;
* MFC requester -> Rust responder, with Rust's one real upload slot occupied.

Each requester must queue and detach naturally. The harness then wakes exactly
that already queued source once through the diagnostics-only scheduler control.
For clear or encrypted transport, both clients must record the corresponding
per-source crypt decision before the ordinary scheduler emits the exact request
and ACK frames.
For queue-full, the exact requester is removed from the responder's real upload
queue before one exact, expiring queue-pressure prerequisite is armed. The
ordinary scheduler and production packet path remain responsible for the
request, response, and state transition.

For file-not-found, the harness withdraws the fixture from the responder's
production shared catalog after the requester has registered the real queued
source. MFC uses a reversible file move; Rust clears the ephemeral profile's
configured shared roots so its live Windows file handle is not disturbed. The
production shared catalog must prove the exact hash absent before the ordinary
scheduler sends one reask. A moved fixture is restored only after the responder
stops.

The verdict comes only from complete ``diag_event_v2`` causal evidence, exact
wire bytes, the accepted stock corpus, and matching applied state. Process exit,
daemon log strings, elapsed time, and public traffic are never verdicts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import ed2k_server as ed2k_harness  # noqa: E402
from emule_test_harness import build_provenance  # noqa: E402
from emule_test_harness import client_udp_diagnostic_evidence as udp_evidence  # noqa: E402
from emule_test_harness import converged_live_wire  # noqa: E402
from emule_test_harness import rust_client  # noqa: E402
from emule_test_harness import rust_ed2k  # noqa: E402
from emule_test_harness import soak_build_refresh  # noqa: E402
from emule_test_harness.paths import get_workspace_output_root  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES, resolve_manifest_repo  # noqa: E402
from emule_test_harness.script_modules import load_script_module  # noqa: E402

cc = load_script_module(
    "emulebb_rust_emulebb_cross_client_for_reask",
    "emulebb-rust-emulebb-cross-client.py",
)
dtt = cc.dtt
live_common = cc.live_common
harness_cli_common = cc.harness_cli_common

SUITE_NAME = "emulebb-rust-reask-cross-client"
API_KEY = "emulebb-rust-reask-cross-client-key"
QUEUED_SOURCE_REASK_PATH = "/api/v1/diagnostics/protocol-controls/queued-source-reasks"
QUEUE_PRESSURE_PATH = "/api/v1/diagnostics/protocol-fixtures/client-udp-queue-pressure"
SHARED_DIRECTORIES_PATH = "/api/v1/shared-directories"
MFC_SHARED_FILES_PATH = "/api/v1/shared-files?offset=0&limit=100"
MFC_SHARED_RELOAD_PATH = "/api/v1/shared-files/operations/reload"
RUST_SHARED_FILES_PATH = "/api/v1/shared-files"
RUST_SHARED_RELOAD_PATH = "/api/v1/shared-directories/operations/reload"
STOCK_CLIENT_UDP_RECORD_ID = "stock.client-udp.corpus"
PROTOCOL_CATALOG_PATH = REPO_ROOT / "manifests" / "protocol-parity-catalog.json"
CLIENT_EMULEBB = CLIENT_IDENTITIES["emulebb"]
# eMuleBB enforces a minimum of two upload slots. Disable elastic headroom.
EMULEBB_MAX_UPLOAD_KIB = 4
# Trace the reask + transfer paths so the detach / reask / ack are observable.
RUST_LOG = (
    "info,emulebb_ed2k=info,emulebb_core=info"
    ",emulebb_ed2k::ed2k_tcp=debug,emulebb_ed2k::ed2k_transfer=debug"
    ",emulebb_ed2k::ed2k_client_udp=trace"
)

SCENARIO_COVERAGE_IDS = {
    "v4": udp_evidence.COVERAGE_ID,
    "clear": udp_evidence.CLEAR_COVERAGE_ID,
    "encrypted": udp_evidence.ENCRYPTED_COVERAGE_ID,
    "queue-full": udp_evidence.QUEUE_FULL_COVERAGE_ID,
    "file-not-found": udp_evidence.FILE_NOT_FOUND_COVERAGE_ID,
}
SCENARIO_CAMPAIGN_SCHEMAS = {
    "v4": "emulebb-build-tests.client-udp-v4-campaign.v1",
    "clear": "emulebb-build-tests.client-udp-clear-campaign.v1",
    "encrypted": "emulebb-build-tests.client-udp-encrypted-campaign.v1",
    "queue-full": "emulebb-build-tests.client-udp-queue-full-campaign.v1",
    "file-not-found": ("emulebb-build-tests.client-udp-file-not-found-campaign.v1"),
}
SCENARIO_REPLY_OPCODES = {
    "v4": udp_evidence.OP_REASKACK,
    "clear": udp_evidence.OP_REASKACK,
    "encrypted": udp_evidence.OP_REASKACK,
    "queue-full": udp_evidence.OP_QUEUEFULL,
    "file-not-found": udp_evidence.OP_FILENOTFOUND,
}
SCENARIO_EVIDENCE_BUILDERS = {
    "v4": udp_evidence.build_client_udp_v4_diagnostic_evidence,
    "clear": udp_evidence.build_client_udp_clear_diagnostic_evidence,
    "encrypted": udp_evidence.build_client_udp_encrypted_diagnostic_evidence,
    "queue-full": udp_evidence.build_client_udp_queue_full_diagnostic_evidence,
    "file-not-found": (
        udp_evidence.build_client_udp_file_not_found_diagnostic_evidence
    ),
}
SCENARIO_EVIDENCE_REQUIREMENTS = {
    "v4": udp_evidence.require_client_udp_v4_diagnostic_evidence,
    "clear": udp_evidence.require_client_udp_clear_diagnostic_evidence,
    "encrypted": udp_evidence.require_client_udp_encrypted_diagnostic_evidence,
    "queue-full": udp_evidence.require_client_udp_queue_full_diagnostic_evidence,
    "file-not-found": (
        udp_evidence.require_client_udp_file_not_found_diagnostic_evidence
    ),
}
SCENARIO_OBFUSCATION = {
    scenario: scenario == "encrypted" for scenario in SCENARIO_COVERAGE_IDS
}
SCENARIO_RAW_EVIDENCE_SCHEMAS = {
    "clear": udp_evidence.CLEAR_RAW_EVIDENCE_SCHEMA,
    "encrypted": udp_evidence.ENCRYPTED_RAW_EVIDENCE_SCHEMA,
}


def build_ack_raw_evidence(
    *,
    scenario: str,
    file_hash: str,
    part_count: int,
    transitions: list[udp_evidence.ClientUdpV4Transition],
) -> dict[str, object]:
    """Serialize complete ACK reducer inputs for independent receipt validation."""

    try:
        schema = SCENARIO_RAW_EVIDENCE_SCHEMAS[scenario]
    except KeyError as exc:
        raise ValueError(
            f"scenario has no raw ACK evidence schema: {scenario!r}"
        ) from exc

    return {
        "schema": schema,
        "scenario": scenario,
        "fileHash": _canonical_hash(file_hash, field="file_hash"),
        "partCount": part_count,
        "transitions": [
            {
                "requester": transition.requester,
                "responder": transition.responder,
                "sourceTcpEndpoint": transition.source_tcp_endpoint,
                "sourceUdpEndpoint": transition.source_udp_endpoint,
                "sourceUserHash": transition.source_user_hash.hex(),
                "requesterUdpEndpoint": transition.requester_udp_endpoint,
                "controlReceipt": transition.control_receipt,
                "requesterRecords": list(transition.requester_records),
                "responderRecords": list(transition.responder_records),
            }
            for transition in transitions
        ],
    }


@dataclass(frozen=True)
class RustRuntime:
    nickname: str
    base_url: str
    process: object
    output_path: Path
    profile_dir: Path
    tcp_endpoint: str
    udp_endpoint: str
    diagnostics_dir: Path | None
    executable: Path


@dataclass(frozen=True)
class AuthoritativeBuilds:
    """Exact canonical binaries and causal build receipts for one campaign."""

    rust_repo: Path
    rust_exe: Path
    server_exe: Path
    report: dict[str, object]


def _api_data(payload: object) -> object:
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def _api_items(payload: object) -> list[dict[str, object]]:
    data = _api_data(payload)
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict) and isinstance(data.get("items"), list):
        rows = data["items"]
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


def _canonical_hash(value: object, *, field: str) -> str:
    normalized = str(value or "").lower()
    if len(normalized) != 32 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise RuntimeError(f"{field} must be a 32-character hexadecimal value")
    return normalized


def _split_endpoint(value: object, *, field: str) -> tuple[str, int]:
    endpoint = str(value or "")
    host, separator, raw_port = endpoint.rpartition(":")
    if not separator or not host:
        raise RuntimeError(f"{field} must be an IPv4 host:port endpoint")
    try:
        port = int(raw_port)
    except ValueError as error:
        raise RuntimeError(f"{field} must contain a numeric port") from error
    if not 1 <= port <= 65535:
        raise RuntimeError(f"{field} port must be in the range 1..65535")
    return host, port


def wait_for_server_client_publication(
    admin_base_url: str,
    api_key: str,
    nickname: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Require one exact upstream-admin client identity with a published file."""

    row = ed2k_harness.ed2k_server_control(
        admin_base_url,
        api_key,
    ).wait_for_client_shared_files(nickname, 1, timeout_seconds)
    return require_server_high_id_client(row, nickname=nickname)


def wait_for_server_high_id_client(
    admin_base_url: str,
    api_key: str,
    nickname: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Require one exact server-observed HighID client identity."""

    row = ed2k_harness.ed2k_server_control(
        admin_base_url,
        api_key,
    ).wait_for_client(nickname, timeout_seconds)
    return require_server_high_id_client(row, nickname=nickname)


def require_server_high_id_client(
    row: dict[str, object], *, nickname: str
) -> dict[str, object]:
    """Normalize an exact upstream-admin HighID observation."""

    observed_nickname = str(row.get("client_name") or "")
    if observed_nickname != nickname:
        raise RuntimeError(
            f"Server resolved client {observed_nickname!r}; expected {nickname!r}"
        )
    if not bool(row.get("high_id")):
        raise RuntimeError(f"Server observed {nickname!r} as LowID")
    return {
        "clientName": observed_nickname,
        "address": str(row.get("ip") or ""),
        "highId": bool(row.get("high_id")),
        "sharedFiles": int(row.get("shared_files") or 0),
    }


def find_udp_reask_registration(
    records: list[dict[str, Any]],
    *,
    file_hash: str,
    source_tcp_endpoint: str,
    source_udp_endpoint: str,
) -> dict[str, object] | None:
    """Resolve one exact naturally registered direct V4 queued source."""

    normalized_file_hash = _canonical_hash(file_hash, field="file_hash")
    matches: list[dict[str, Any]] = []
    for record in records:
        keys = record.get("keys") if isinstance(record.get("keys"), dict) else {}
        body = record.get("body") if isinstance(record.get("body"), dict) else {}
        if (
            record.get("schema") == udp_evidence.DIAGNOSTIC_SCHEMA
            and record.get("family") == "sched"
            and record.get("event") == "udp_reask_source_registered"
            and str(keys.get("fileHash") or "").lower() == normalized_file_hash
            and str(keys.get("peer") or "").lower() == source_tcp_endpoint.lower()
            and body.get("outcome") == "accepted"
            and body.get("sourceUdpEndpoint") == source_udp_endpoint
            and body.get("sourceUdpVersion") == 4
            and body.get("lowId") is False
            and body.get("buddyEndpoint") is None
            and body.get("buddyId") is None
        ):
            matches.append(record)
    if len(matches) > 1:
        raise RuntimeError(
            "multiple exact direct V4 source registrations were recorded"
        )
    if not matches:
        return None
    keys = matches[0]["keys"]
    return {
        "fileHash": normalized_file_hash,
        "sourceTcpEndpoint": source_tcp_endpoint,
        "sourceUdpEndpoint": source_udp_endpoint,
        "sourceUserHash": _canonical_hash(
            keys.get("peerHash"), field="source peerHash"
        ),
        "sourceUdpVersion": 4,
    }


def find_mfc_queued_source(
    payload: object,
    *,
    source_ip: str,
    source_tcp_port: int,
) -> dict[str, object] | None:
    """Resolve one exact disconnected HighID source in MFC's production queue."""

    matches = [
        row
        for row in _api_items(payload)
        if str(row.get("address") or "").lower() == source_ip.lower()
        and row.get("port") == source_tcp_port
        and row.get("downloadState") == "onqueue"
        and row.get("tcpConnected") is False
        and row.get("lowId") is False
        and isinstance(row.get("queueRank"), int)
        and not isinstance(row.get("queueRank"), bool)
        and int(row["queueRank"]) > 0
    ]
    if len(matches) > 1:
        raise RuntimeError(
            "multiple exact MFC queued sources matched the Rust uploader"
        )
    if not matches:
        return None
    source = matches[0]
    return {
        "sourceIp": source_ip,
        "sourceTcpPort": source_tcp_port,
        "sourceUserHash": _canonical_hash(
            source.get("userHash"), field="MFC source userHash"
        ),
        "queueRank": int(source["queueRank"]),
    }


def find_upload_waiter(
    payload: object,
    *,
    file_hash: str,
    requester_tcp_endpoint: str,
) -> dict[str, object] | None:
    """Resolve one exact requester in a responder's production upload queue."""

    normalized_hash = _canonical_hash(file_hash, field="upload waiter file hash")
    requester_host, requester_port = _split_endpoint(
        requester_tcp_endpoint,
        field="requester_tcp_endpoint",
    )
    matches = [
        row
        for row in _api_items(payload)
        if str(row.get("address") or "").casefold() == requester_host.casefold()
        and row.get("port") == requester_port
        and str(row.get("requestedFileHash") or "").casefold() == normalized_hash
        and row.get("waitingQueue") is True
        and isinstance(row.get("clientId"), str)
        and bool(str(row["clientId"]).strip())
    ]
    if len(matches) > 1:
        raise RuntimeError("multiple exact upload waiters matched the requester")
    if not matches:
        return None
    waiter = matches[0]
    return {
        "clientId": waiter["clientId"],
        "address": requester_host,
        "requestedFileHash": normalized_hash,
        "waitingQueue": True,
    }


def wait_for_upload_waiter(
    base_url: str,
    api_key: str,
    *,
    file_hash: str,
    requester_tcp_endpoint: str,
    timeout: float,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        payload = cc.request_json(
            base_url,
            "GET",
            "/api/v1/upload-queue",
            api_key,
        )
        waiter = find_upload_waiter(
            payload,
            file_hash=file_hash,
            requester_tcp_endpoint=requester_tcp_endpoint,
        )
        if waiter is not None:
            return waiter
        time.sleep(1.0)
    raise RuntimeError("responder never exposed the exact requester upload waiter")


def wait_for_upload_waiter_absent(
    base_url: str,
    api_key: str,
    *,
    file_hash: str,
    requester_tcp_endpoint: str,
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        payload = cc.request_json(
            base_url,
            "GET",
            "/api/v1/upload-queue",
            api_key,
        )
        waiter = find_upload_waiter(
            payload,
            file_hash=file_hash,
            requester_tcp_endpoint=requester_tcp_endpoint,
        )
        if waiter is None:
            return
        time.sleep(0.25)
    raise RuntimeError("exact requester remained in the responder upload queue")


def remove_upload_waiter(
    base_url: str,
    api_key: str,
    *,
    waiter: dict[str, object],
    file_hash: str,
    requester_tcp_endpoint: str,
    timeout: float,
) -> dict[str, object]:
    client_id = str(waiter.get("clientId") or "")
    if not client_id:
        raise RuntimeError("upload waiter clientId is missing")
    response = dtt.retry_rest_request(
        base_url,
        f"/api/v1/upload-queue/{quote(client_id, safe='')}/operations/remove",
        method="POST",
        api_key=api_key,
        timeout_seconds=30.0,
    )
    payload = _api_data(response.get("raw_json"))
    receipt = {
        "waiter": waiter,
        "response": {
            "status": int(response.get("status") or 0),
            "json": payload if isinstance(payload, dict) else None,
        },
        "verifiedAbsent": False,
    }
    if receipt["response"] != {
        "status": 200,
        "json": {"ok": True, "removed": "queue"},
    }:
        raise RuntimeError(
            "exact upload waiter removal failed: "
            f"{dtt.rest_smoke.compact_http_result(response)!r}"
        )
    wait_for_upload_waiter_absent(
        base_url,
        api_key,
        file_hash=file_hash,
        requester_tcp_endpoint=requester_tcp_endpoint,
        timeout=timeout,
    )
    receipt["verifiedAbsent"] = True
    return receipt


def queue_pressure_request(
    *,
    file_hash: str,
    requester_udp_endpoint: str,
) -> dict[str, object]:
    requester_host, requester_port = _split_endpoint(
        requester_udp_endpoint,
        field="requester_udp_endpoint",
    )
    return {
        "fileHash": _canonical_hash(file_hash, field="file_hash"),
        "sourceIp": requester_host,
        "sourceUdpPort": requester_port,
    }


def arm_queue_pressure(
    base_url: str,
    api_key: str,
    request: dict[str, object],
) -> dict[str, object]:
    response = dtt.retry_rest_request(
        base_url,
        QUEUE_PRESSURE_PATH,
        method="POST",
        api_key=api_key,
        json_body=request,
        timeout_seconds=30.0,
    )
    payload = _api_data(response.get("raw_json"))
    receipt = {
        "request": request,
        "response": {
            "status": int(response.get("status") or 0),
            "json": payload if isinstance(payload, dict) else None,
        },
    }
    if receipt["response"]["status"] != 200:
        raise RuntimeError(
            "exact client-UDP queue pressure prerequisite failed: "
            f"{dtt.rest_smoke.compact_http_result(response)!r}"
        )
    return receipt


def queued_source_reask_request(
    *,
    file_hash: str,
    source_tcp_endpoint: str,
    source_udp_endpoint: str,
    source_user_hash: str,
) -> dict[str, object]:
    tcp_host, tcp_port = _split_endpoint(
        source_tcp_endpoint, field="source_tcp_endpoint"
    )
    udp_host, udp_port = _split_endpoint(
        source_udp_endpoint, field="source_udp_endpoint"
    )
    if tcp_host.lower() != udp_host.lower():
        raise RuntimeError(
            "queued source TCP and UDP endpoints must use the same address"
        )
    return {
        "fileHash": _canonical_hash(file_hash, field="file_hash"),
        "sourceIp": tcp_host,
        "sourceTcpPort": tcp_port,
        "sourceUdpPort": udp_port,
        "sourceUserHash": _canonical_hash(source_user_hash, field="source_user_hash"),
        "sourceUdpVersion": 4,
    }


def queued_source_reask_receipt(
    request: dict[str, object],
    response: dict[str, object],
) -> dict[str, object]:
    raw_json = response.get("raw_json")
    payload = _api_data(raw_json)
    return {
        "request": request,
        "response": {
            "status": int(response.get("status") or 0),
            "json": payload if isinstance(payload, dict) else None,
        },
    }


def find_udp_reask_applied(
    records: list[dict[str, Any]],
    *,
    file_hash: str,
    source_tcp_endpoint: str,
    source_user_hash: str,
    reply_opcode: int,
) -> dict[str, Any] | None:
    normalized_file_hash = _canonical_hash(file_hash, field="file_hash")
    normalized_user_hash = _canonical_hash(source_user_hash, field="source_user_hash")
    matches: list[dict[str, Any]] = []
    for record in records:
        keys = record.get("keys") if isinstance(record.get("keys"), dict) else {}
        body = record.get("body") if isinstance(record.get("body"), dict) else {}
        if (
            record.get("schema") == udp_evidence.DIAGNOSTIC_SCHEMA
            and record.get("family") == "sched"
            and record.get("event") == "udp_reask_reply_applied"
            and str(keys.get("fileHash") or "").lower() == normalized_file_hash
            and str(keys.get("peer") or "").lower() == source_tcp_endpoint.lower()
            and str(keys.get("peerHash") or "").lower() == normalized_user_hash
            and body.get("outcome") == "applied"
            and body.get("replyOpcode") == reply_opcode
            and body.get("sourceUdpVersion") == 4
            and body.get("requestPendingAfter") is False
        ):
            matches.append(record)
    if len(matches) > 1:
        raise RuntimeError("multiple exact client-UDP application events were recorded")
    return matches[0] if matches else None


def find_file_not_found_completion(
    records: list[dict[str, Any]],
    *,
    file_hash: str,
    source_tcp_endpoint: str,
    source_user_hash: str,
) -> dict[str, dict[str, Any]] | None:
    """Resolve one ordered FNF application, dead-list, and source drop."""

    normalized_file_hash = _canonical_hash(file_hash, field="file_hash")
    normalized_user_hash = _canonical_hash(
        source_user_hash,
        field="source_user_hash",
    )

    def identity(record: dict[str, Any]) -> bool:
        keys = record.get("keys") if isinstance(record.get("keys"), dict) else {}
        return bool(
            record.get("schema") == udp_evidence.DIAGNOSTIC_SCHEMA
            and record.get("family") == "sched"
            and str(keys.get("fileHash") or "").casefold() == normalized_file_hash
            and str(keys.get("peer") or "").casefold() == source_tcp_endpoint.casefold()
            and str(keys.get("peerHash") or "").casefold() == normalized_user_hash
        )

    applied = find_udp_reask_applied(
        records,
        file_hash=normalized_file_hash,
        source_tcp_endpoint=source_tcp_endpoint,
        source_user_hash=normalized_user_hash,
        reply_opcode=udp_evidence.OP_FILENOTFOUND,
    )
    dead_listed = [
        record
        for record in records
        if identity(record)
        and record.get("event") == "source_dead_listed"
        and record.get("body")
        == {
            "outcome": "dead_listed",
            "reason": "udp_fnf",
            "blockSecs": 2700,
        }
    ]
    dropped = [
        record
        for record in records
        if identity(record)
        and record.get("event") == "source_dropped"
        and record.get("body") == {"outcome": "dropped"}
    ]
    swapped = [
        record
        for record in records
        if identity(record) and record.get("event") == "source_swapped"
    ]
    if swapped:
        raise RuntimeError("file-not-found source was swapped instead of dropped")
    if len(dead_listed) > 1 or len(dropped) > 1:
        raise RuntimeError(
            "multiple exact file-not-found terminal events were recorded"
        )
    if applied is None or not dead_listed or not dropped:
        return None
    sequences = [
        applied.get("seq"),
        dead_listed[0].get("seq"),
        dropped[0].get("seq"),
    ]
    if not all(
        isinstance(sequence, int) and not isinstance(sequence, bool) and sequence > 0
        for sequence in sequences
    ) or not (sequences[0] < sequences[1] < sequences[2]):
        raise RuntimeError("file-not-found terminal events were not causally ordered")
    return {
        "applied": applied,
        "deadListed": dead_listed[0],
        "dropped": dropped[0],
    }


def load_stock_client_udp_record(
    path: Path = PROTOCOL_CATALOG_PATH,
) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    records = payload.get("records") if isinstance(payload, dict) else None
    matches = [
        record
        for record in records or []
        if isinstance(record, dict)
        and record.get("recordId") == STOCK_CLIENT_UDP_RECORD_ID
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"protocol catalog must contain exactly one {STOCK_CLIENT_UDP_RECORD_ID!r} record"
        )
    return matches[0]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=sorted(SCENARIO_COVERAGE_IDS),
        required=True,
    )
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--p2p-bind-interface-name", default="")
    parser.add_argument("--p2p-bind-interface-address")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--reask-observe-timeout-seconds", type=float, default=180.0)
    # Large enough that the slow eMuleBB slot stays busy for a few reask ticks.
    parser.add_argument("--fixture-size-bytes", type=int, default=8 * 1024 * 1024)
    return parser.parse_args(argv)


def prepare_authoritative_builds(paths) -> AuthoritativeBuilds:
    """Clean-build every campaign executable from clean, unchanged sources."""

    workspace_root = paths.workspace_root
    build_repo = resolve_manifest_repo(workspace_root, "build")
    rust_repo = resolve_manifest_repo(workspace_root, "emulebb_rust")
    server_repo = resolve_manifest_repo(workspace_root, "ed2k_server")
    runner_state = build_provenance.require_clean_git_source(
        REPO_ROOT,
        label="client-UDP campaign runner",
    )
    rust_build = build_provenance.run_canonical_source_build(
        soak_build_refresh.diagnostics_build_command("rust", clean=True),
        build_repo=build_repo,
        source_repo=rust_repo,
        label="Rust diagnostics",
    )
    mfc_build = build_provenance.run_canonical_source_build(
        soak_build_refresh.diagnostics_build_command("mfc", clean=True),
        build_repo=build_repo,
        source_repo=paths.app_root,
        label="MFC diagnostics oracle",
    )
    server_build = build_provenance.run_canonical_source_build(
        rust_ed2k.server_build_command(clean=True),
        build_repo=build_repo,
        source_repo=server_repo,
        label="ed2k-server dependency",
        timeout_seconds=900.0,
    )

    rust_exe = converged_live_wire.resolve_rust_diagnostics_exe(
        get_workspace_output_root()
    )
    mfc_exe = paths.app_exe.resolve()
    server_exe = rust_ed2k.resolve_server_exe(None)
    for label, executable in (
        ("Rust diagnostics", rust_exe),
        ("MFC diagnostics oracle", mfc_exe),
        ("ed2k-server dependency", server_exe),
    ):
        if not executable.is_file():
            raise RuntimeError(f"{label} clean build did not stage {executable}.")

    return AuthoritativeBuilds(
        rust_repo=rust_repo,
        rust_exe=rust_exe,
        server_exe=server_exe,
        report={
            "runner": {
                "sourceRevision": runner_state.revision,
                "sourceClean": runner_state.clean,
            },
            "rustDiagnostics": {
                "path": str(rust_exe),
                "sha256": dtt.file_sha256(rust_exe),
                "build": rust_build,
            },
            "mfcDiagnostics": {
                "path": str(mfc_exe),
                "sha256": dtt.file_sha256(mfc_exe),
                "build": mfc_build,
            },
            "ed2kServer": {
                "path": str(server_exe),
                "sha256": dtt.file_sha256(server_exe),
                "build": server_build,
            },
        },
    )


def start_rust(
    *,
    repo,
    paths,
    lan_bind_addr,
    api_key,
    p2p_address,
    server_endpoint,
    used_ports,
    label,
    enable_reask,
    obfuscation_enabled,
    upload_limit_kibps=None,
    base_upload_slots=None,
    upload_slot_elastic_percent=None,
    shared_dir=None,
) -> RustRuntime:
    """Launch one staged Rust client with an isolated deterministic profile."""

    nickname = f"client-udp-v4-{label}"
    rest_port = cc.choose_extra_port(lan_bind_addr, used_ports)
    ed2k_port = cc.choose_extra_port(lan_bind_addr, used_ports)
    kad_port = cc.choose_extra_port(lan_bind_addr, used_ports, udp=True)
    profile = paths.source_artifacts_dir / f"rust-{label}-profile"
    rust_client.write_rust_profile(
        profile,
        rust_repo=repo,
        rest_addr=lan_bind_addr,
        rest_port=rest_port,
        api_key=api_key,
        p2p_bind_ip=p2p_address,
        ed2k_port=ed2k_port,
        ed2k_nickname=nickname,
        kad_port=kad_port,
        server_endpoint=server_endpoint,
        enable_udp_reask=enable_reask,
        # The hairpin server reports each client's actual TEST-NET bind address,
        # so this selects the production clear or user-hash-keyed UDP path.
        obfuscation_enabled=obfuscation_enabled,
        local_only_discovery=True,
        upload_limit_kibps=upload_limit_kibps,
        base_upload_slots=base_upload_slots,
        upload_slot_elastic_percent=upload_slot_elastic_percent,
    )
    out_path = paths.source_artifacts_dir / f"rust-{label}.out"
    executable = converged_live_wire.resolve_rust_diagnostics_exe(
        get_workspace_output_root()
    )
    packet_dir = paths.source_artifacts_dir / f"rust-{label}-packet-dump"
    packet_dir.mkdir(parents=True, exist_ok=True)
    previous_rust_log = os.environ.get("RUST_LOG")
    previous_diagnostic_dir = os.environ.get("EMULEBB_RUST_LOG_DIR")
    try:
        os.environ["RUST_LOG"] = RUST_LOG
        os.environ["EMULEBB_RUST_LOG_DIR"] = str(packet_dir)
        process = rust_client.start_rust_client_executable(
            executable, profile, out_path
        )
    finally:
        if previous_rust_log is None:
            os.environ.pop("RUST_LOG", None)
        else:
            os.environ["RUST_LOG"] = previous_rust_log
        if previous_diagnostic_dir is None:
            os.environ.pop("EMULEBB_RUST_LOG_DIR", None)
        else:
            os.environ["EMULEBB_RUST_LOG_DIR"] = previous_diagnostic_dir
    base_url = f"http://{lan_bind_addr}:{rest_port}"
    try:
        cc.wait_for_rust_rest(base_url, process, out_path, api_key, 60.0)
        if shared_dir is not None:
            cc.request_json(
                base_url,
                "PATCH",
                "/api/v1/shared-directories",
                api_key,
                {
                    "roots": [{"path": str(Path(shared_dir).resolve())}],
                    "confirmReplaceRoots": True,
                },
            )
            cc.request_json(
                base_url,
                "POST",
                "/api/v1/shared-directories/operations/reload",
                api_key,
            )
        cc.request_json(base_url, "POST", "/api/v1/servers/operations/connect", api_key)
        cc.wait_for_rust_ed2k_connected(base_url, api_key, 120.0)
    except Exception:
        rust_client.stop_process_tree(process)
        raise
    return RustRuntime(
        nickname=nickname,
        base_url=base_url,
        process=process,
        output_path=out_path,
        profile_dir=profile,
        tcp_endpoint=f"{p2p_address}:{ed2k_port}",
        udp_endpoint=f"{p2p_address}:{kad_port}",
        diagnostics_dir=packet_dir,
        executable=executable,
    )


def rust_shared_file_link(base_url, api_key, *, file_name, timeout):
    """Wait for one Rust shared-file link and return its normalized hash and link."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = cc.request_json(base_url, "GET", "/api/v1/shared-files", api_key)
        data = _api_data(response)
        if isinstance(data, dict):
            rows = data.get("sharedFiles")
            if not isinstance(rows, list):
                rows = data.get("items")
        else:
            rows = None
        for row in rows or []:
            if isinstance(row, dict) and row.get("name") == file_name:
                file_hash = _canonical_hash(row.get("hash"), field="Rust shared hash")
                link_response = cc.request_json(
                    base_url,
                    "GET",
                    f"/api/v1/shared-files/{file_hash}/ed2k-link",
                    api_key,
                )
                link_payload = _api_data(link_response)
                if not isinstance(link_payload, dict) or not link_payload.get("link"):
                    raise RuntimeError("Rust shared-file link response is incomplete")
                return file_hash, str(link_payload["link"])
        time.sleep(2.0)
    raise RuntimeError(f"Rust never published shared file {file_name!r}")


def find_shared_file_by_hash(
    payload: object,
    *,
    file_hash: str,
) -> dict[str, object] | None:
    """Resolve one exact shared-catalog row by ED2K hash."""

    normalized_hash = _canonical_hash(file_hash, field="shared file hash")
    matches = [
        row
        for row in _api_items(payload)
        if str(row.get("hash") or "").casefold() == normalized_hash
    ]
    if len(matches) > 1:
        raise RuntimeError("shared catalog exposed the exact hash more than once")
    return matches[0] if matches else None


def wait_for_shared_file_presence(
    base_url: str,
    api_key: str,
    *,
    file_hash: str,
    present: bool,
    shared_files_path: str,
    timeout: float,
) -> dict[str, object] | None:
    """Wait for the production shared catalog to contain or omit one hash."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        payload = cc.request_json(
            base_url,
            "GET",
            shared_files_path,
            api_key,
        )
        row = find_shared_file_by_hash(payload, file_hash=file_hash)
        if (row is not None) is present:
            return row
        time.sleep(0.25)
    state = "present" if present else "absent"
    raise RuntimeError(f"shared catalog never proved exact hash {state}")


def reload_shared_catalog(
    base_url: str,
    api_key: str,
    *,
    reload_path: str,
) -> dict[str, object]:
    """Invoke one client's production shared-catalog reload operation."""

    response = dtt.retry_rest_request(
        base_url,
        reload_path,
        method="POST",
        api_key=api_key,
        json_body={},
        timeout_seconds=30.0,
    )
    status = int(response.get("status") or 0)
    payload = _api_data(response.get("raw_json"))
    receipt = {
        "status": status,
        "json": payload if isinstance(payload, dict) else None,
    }
    if status != 200:
        raise RuntimeError(
            "shared-catalog reload failed: "
            f"{dtt.rest_smoke.compact_http_result(response)!r}"
        )
    return receipt


def clear_shared_roots(
    base_url: str,
    api_key: str,
) -> dict[str, object]:
    """Replace an ephemeral responder profile's shared roots with none."""

    request = {"roots": [], "confirmReplaceRoots": True}
    response = dtt.retry_rest_request(
        base_url,
        SHARED_DIRECTORIES_PATH,
        method="PATCH",
        api_key=api_key,
        json_body=request,
        timeout_seconds=30.0,
    )
    status = int(response.get("status") or 0)
    payload = _api_data(response.get("raw_json"))
    receipt = {
        "request": request,
        "response": {
            "status": status,
            "json": payload if isinstance(payload, dict) else None,
        },
    }
    if status != 200:
        raise RuntimeError(
            "shared-root replacement failed: "
            f"{dtt.rest_smoke.compact_http_result(response)!r}"
        )
    return receipt


def restore_shared_fixture(shared_path: Path, withdrawn_path: Path) -> None:
    """Restore one harness-owned fixture without overwriting another file."""

    if shared_path.exists():
        if withdrawn_path.exists():
            raise RuntimeError(
                "both shared and withdrawn fixture paths exist; refusing overwrite"
            )
        return
    if not withdrawn_path.is_file():
        raise RuntimeError("withdrawn fixture is missing and cannot be restored")
    shared_path.parent.mkdir(parents=True, exist_ok=True)
    withdrawn_path.replace(shared_path)


def withdraw_shared_fixture(
    base_url: str,
    api_key: str,
    *,
    fixture_path: Path,
    file_hash: str,
    reload_path: str,
    shared_files_path: str,
    timeout: float,
) -> tuple[dict[str, object], Path]:
    """Withdraw one real fixture and prove its exact catalog hash disappeared."""

    wait_for_shared_file_presence(
        base_url,
        api_key,
        file_hash=file_hash,
        present=True,
        shared_files_path=shared_files_path,
        timeout=timeout,
    )
    shared_path = fixture_path.resolve()
    shared_root = shared_path.parent
    withdrawn_path = (shared_root.parent / "withdrawn" / shared_path.name).resolve()
    if withdrawn_path.is_relative_to(shared_root):
        raise RuntimeError("withdrawn fixture path remained inside the shared root")
    if withdrawn_path.exists():
        raise RuntimeError("withdrawn fixture target already exists")
    withdrawn_path.parent.mkdir(parents=True, exist_ok=True)
    shared_path.replace(withdrawn_path)
    try:
        reload_response = reload_shared_catalog(
            base_url,
            api_key,
            reload_path=reload_path,
        )
        wait_for_shared_file_presence(
            base_url,
            api_key,
            file_hash=file_hash,
            present=False,
            shared_files_path=shared_files_path,
            timeout=timeout,
        )
    except Exception:
        restore_shared_fixture(shared_path, withdrawn_path)
        raise
    return (
        {
            "fileHash": _canonical_hash(file_hash, field="file_hash"),
            "method": "file-move",
            "fixturePath": str(shared_path),
            "movedToPath": str(withdrawn_path),
            "presentBefore": True,
            "reloadResponse": reload_response,
            "absentAfter": True,
        },
        withdrawn_path,
    )


def withdraw_rust_shared_root(
    base_url: str,
    api_key: str,
    *,
    fixture_path: Path,
    file_hash: str,
    timeout: float,
) -> dict[str, object]:
    """Withdraw one Rust fixture by clearing its ephemeral production roots."""

    wait_for_shared_file_presence(
        base_url,
        api_key,
        file_hash=file_hash,
        present=True,
        shared_files_path=RUST_SHARED_FILES_PATH,
        timeout=timeout,
    )
    shared_directories = clear_shared_roots(base_url, api_key)
    reload_response = reload_shared_catalog(
        base_url,
        api_key,
        reload_path=RUST_SHARED_RELOAD_PATH,
    )
    wait_for_shared_file_presence(
        base_url,
        api_key,
        file_hash=file_hash,
        present=False,
        shared_files_path=RUST_SHARED_FILES_PATH,
        timeout=timeout,
    )
    return {
        "fileHash": _canonical_hash(file_hash, field="file_hash"),
        "method": "shared-roots-cleared",
        "fixturePath": str(fixture_path.resolve()),
        "sharedDirectories": shared_directories,
        "presentBefore": True,
        "reloadResponse": reload_response,
        "absentAfter": True,
    }


def find_transfer_source(
    payload: object,
    *,
    source_tcp_endpoint: str,
    source_user_hash: str,
) -> dict[str, object] | None:
    """Resolve one exact transfer source identity from a REST source list."""

    host, port = _split_endpoint(
        source_tcp_endpoint,
        field="source_tcp_endpoint",
    )
    normalized_hash = _canonical_hash(
        source_user_hash,
        field="source_user_hash",
    )
    matches = [
        row
        for row in _api_items(payload)
        if str(row.get("address") or "").casefold() == host.casefold()
        and row.get("port") == port
        and str(row.get("userHash") or "").casefold() == normalized_hash
    ]
    if len(matches) > 1:
        raise RuntimeError("transfer source list exposed the exact source twice")
    return matches[0] if matches else None


def wait_for_transfer_source_absent(
    base_url: str,
    api_key: str,
    *,
    file_hash: str,
    source_tcp_endpoint: str,
    source_user_hash: str,
    timeout: float,
) -> dict[str, object]:
    """Require the requester REST model to omit one exact dropped source."""

    normalized_file_hash = _canonical_hash(file_hash, field="file_hash")
    normalized_user_hash = _canonical_hash(
        source_user_hash,
        field="source_user_hash",
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        payload = cc.request_json(
            base_url,
            "GET",
            f"/api/v1/transfers/{normalized_file_hash}/sources",
            api_key,
        )
        source = find_transfer_source(
            payload,
            source_tcp_endpoint=source_tcp_endpoint,
            source_user_hash=normalized_user_hash,
        )
        if source is None:
            return {
                "fileHash": normalized_file_hash,
                "sourceTcpEndpoint": source_tcp_endpoint,
                "sourceUserHash": normalized_user_hash,
                "verifiedAbsent": True,
            }
        time.sleep(0.25)
    raise RuntimeError("requester retained the exact file-not-found source")


def _mfc_capacity_snapshots(log_dir: Path) -> list[dict]:
    return [
        event
        for event in converged_live_wire.load_current_diag_records(
            log_dir, side="emule", allow_incomplete_active_tail=True
        )
        if event.get("event") == "capacity_snapshot"
    ]


def wait_for_upload_capacity(
    log_dir: Path, *, active_slots: int, timeout: float
) -> dict:
    """Require a fresh diagnostics snapshot proving the test's queue precondition."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            snapshots = _mfc_capacity_snapshots(log_dir)
        except ValueError:
            snapshots = []
        for event in reversed(snapshots):
            body = event.get("body", {})
            if body.get("effectiveSlotCap") != active_slots:
                raise RuntimeError(
                    f"MFC effective upload cap is not {active_slots}: {body}"
                )
            if body.get("activeSlots", 0) >= active_slots:
                return body
            break
        time.sleep(1.0)
    raise RuntimeError(f"MFC never reached {active_slots} occupied upload slots")


def wait_for_rust_occupied_upload_slot(
    log_dir: Path,
    *,
    file_hash: str,
    peer_endpoint: str,
    timeout: float,
) -> dict[str, object]:
    """Require a fixed one-slot policy and one exact real admitted uploader."""

    normalized_hash = _canonical_hash(file_hash, field="occupied-slot file hash")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            records = current_diag_records(log_dir, side="rust")
        except ValueError:
            records = []
        snapshots = [
            record
            for record in records
            if record.get("family") == "sched"
            and record.get("event") == "capacity_snapshot"
            and isinstance(record.get("body"), dict)
        ]
        policy = snapshots[-1] if snapshots else None
        if policy is not None:
            body = policy["body"]
            if body.get("baseSlots") != 1:
                raise RuntimeError(f"Rust base upload slot count is not 1: {body}")
            if body.get("elasticSlots") != 0 or body.get("effectiveSlotCap") != 1:
                raise RuntimeError(f"Rust upload slot cap is not fixed: {body}")
            opened = [
                record
                for record in records
                if record.get("schema") == udp_evidence.DIAGNOSTIC_SCHEMA
                and record.get("family") == "sched"
                and record.get("event") == "upload_slot_opened"
                and isinstance(record.get("keys"), dict)
                and isinstance(record.get("body"), dict)
                and str(record["keys"].get("fileHash") or "").lower() == normalized_hash
                and record["keys"].get("peer") == peer_endpoint
                and record["body"].get("outcome") == "opened"
                and int(record.get("seq") or 0) > int(policy.get("seq") or 0)
            ]
            if len(opened) > 1:
                raise RuntimeError(
                    f"Rust recorded multiple exact upload-slot openings: {opened!r}"
                )
            if opened:
                return {
                    "policy": dict(body),
                    "slotOpenedSequence": opened[0].get("seq"),
                    "fileHash": normalized_hash,
                    "peer": peer_endpoint,
                }
        time.sleep(1.0)
    raise RuntimeError(
        "Rust never opened its fixed production slot for the exact occupier"
    )


def current_diag_records(log_dir: Path, *, side: str) -> list[dict[str, Any]]:
    return converged_live_wire.load_current_diag_records(
        log_dir,
        side=side,
        allow_incomplete_active_tail=True,
    )


def wait_for_udp_reask_registration(
    log_dir: Path,
    *,
    side: str,
    file_hash: str,
    source_tcp_endpoint: str,
    source_udp_endpoint: str,
    timeout: float,
    process: object | None = None,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"{side} requester exited before source registration")
        try:
            records = current_diag_records(log_dir, side=side)
        except ValueError:
            records = []
        registration = find_udp_reask_registration(
            records,
            file_hash=file_hash,
            source_tcp_endpoint=source_tcp_endpoint,
            source_udp_endpoint=source_udp_endpoint,
        )
        if registration is not None:
            return registration
        time.sleep(1.0)
    raise RuntimeError(f"{side} requester never registered the exact direct V4 source")


def wait_for_mfc_queued_source(
    base_url: str,
    api_key: str,
    *,
    file_hash: str,
    source_ip: str,
    source_tcp_port: int,
    timeout: float,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        payload = cc.request_json(
            base_url,
            "GET",
            f"/api/v1/transfers/{file_hash}/sources",
            api_key,
        )
        source = find_mfc_queued_source(
            payload,
            source_ip=source_ip,
            source_tcp_port=source_tcp_port,
        )
        if source is not None:
            return source
        time.sleep(1.0)
    raise RuntimeError(
        "MFC requester never reached the exact disconnected HighID queue state"
    )


def trigger_queued_source_reask(
    base_url: str,
    api_key: str,
    request: dict[str, object],
) -> dict[str, object]:
    response = dtt.retry_rest_request(
        base_url,
        QUEUED_SOURCE_REASK_PATH,
        method="POST",
        api_key=api_key,
        json_body=request,
        timeout_seconds=30.0,
    )
    receipt = queued_source_reask_receipt(request, response)
    if receipt["response"]["status"] != 200:
        raise RuntimeError(
            "exact queued-source reask control failed without retry: "
            f"{dtt.rest_smoke.compact_http_result(response)!r}"
        )
    return receipt


def wait_for_udp_reask_applied(
    log_dir: Path,
    *,
    side: str,
    file_hash: str,
    source_tcp_endpoint: str,
    source_user_hash: str,
    reply_opcode: int,
    timeout: float,
    process: object | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"{side} requester exited before applying the V4 reply")
        try:
            records = current_diag_records(log_dir, side=side)
        except ValueError:
            records = []
        applied = find_udp_reask_applied(
            records,
            file_hash=file_hash,
            source_tcp_endpoint=source_tcp_endpoint,
            source_user_hash=source_user_hash,
            reply_opcode=reply_opcode,
        )
        if applied is not None:
            return applied, records
        time.sleep(1.0)
    raise RuntimeError(
        f"{side} requester never applied client-UDP opcode {reply_opcode:#04x}"
    )


def wait_for_file_not_found_completion(
    log_dir: Path,
    *,
    side: str,
    file_hash: str,
    source_tcp_endpoint: str,
    source_user_hash: str,
    timeout: float,
    process: object | None = None,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Wait for the complete ordered requester-side FNF state transition."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(
                f"{side} requester exited before completing file-not-found"
            )
        try:
            records = current_diag_records(log_dir, side=side)
        except ValueError:
            records = []
        completion = find_file_not_found_completion(
            records,
            file_hash=file_hash,
            source_tcp_endpoint=source_tcp_endpoint,
            source_user_hash=source_user_hash,
        )
        if completion is not None:
            return completion, records
        time.sleep(0.25)
    raise RuntimeError(f"{side} requester never completed file-not-found handling")


def start_mfc(
    *,
    args: argparse.Namespace,
    paths,
    profile_seed_dir: Path,
    artifact_label: str,
    p2p_address: str,
    server_address: str,
    ports: dict[str, int],
    obfuscation_enabled: bool,
    saturate_upload_queue: bool = False,
) -> dict[str, object]:
    profile_root = paths.source_artifacts_dir / artifact_label
    profile = live_common.prepare_scenario_profile(
        profile_seed_dir,
        profile_root,
        [],
        CLIENT_EMULEBB.profile_id,
    )
    config_dir = Path(profile["config_dir"])
    dtt.configure_client_profile(
        config_dir=config_dir,
        app_exe=paths.app_exe,
        nick=CLIENT_EMULEBB.nick,
        tcp_port=ports["client1_tcp"],
        udp_port=ports["client1_udp"],
        ed2k_enabled=True,
        autoconnect=False,
        rest_api_key=args.api_key,
        rest_port=ports["client1_rest"],
        lan_bind_addr=args.lan_bind_addr,
        enable_diagnostic_rest_endpoints=True,
        p2p_bind_interface_name=args.p2p_bind_interface_name,
        p2p_bind_addr=p2p_address,
        crypt_layer_supported=obfuscation_enabled,
        crypt_layer_requested=obfuscation_enabled,
        crypt_layer_required=False,
    )
    if saturate_upload_queue:
        # MFC clamps the slot count to its production minimum of two. Remove
        # elastic headroom and slow the fixture before the process reads the
        # profile so two occupiers deterministically hold both slots.
        live_common.apply_section_preferences(
            config_dir,
            "UploadPolicy",
            (("MaxUploadClientsAllowed", "2"), ("UploadSlotElasticPercent", "0")),
        )
        live_common.apply_emule_preferences(
            config_dir,
            (("MaxUpload", str(EMULEBB_MAX_UPLOAD_KIB)),),
        )
    dtt.write_server_met(
        config_dir / "server.met",
        address=server_address,
        port=ports["ed2k_tcp"],
        name="client-udp-local",
    )
    app = live_common.launch_app(
        paths.app_exe,
        Path(profile["profile_base"]),
        minimized_to_tray=True,
    )
    base_url = f"http://{args.lan_bind_addr}:{ports['client1_rest']}"
    try:
        dtt.rest_smoke.wait_for_rest_ready(
            base_url,
            args.api_key,
            args.rest_ready_timeout_seconds,
        )
        dtt.add_and_connect_server(
            base_url,
            args.api_key,
            address=server_address,
            port=ports["ed2k_tcp"],
            timeout_seconds=args.server_connect_timeout_seconds,
        )
    except Exception:
        live_common.close_app_cleanly(app)
        raise
    return {
        "app": app,
        "baseUrl": base_url,
        "profile": profile,
        "configDir": config_dir,
        "diagnosticsDir": Path(profile["profile_base"]) / "logs",
        "tcpEndpoint": f"{p2p_address}:{ports['client1_tcp']}",
        "udpEndpoint": f"{p2p_address}:{ports['client1_udp']}",
    }


def stop_mfc(runtime: dict[str, object] | None) -> None:
    if runtime is None:
        return
    try:
        live_common.close_app_cleanly(runtime["app"])
    except Exception:  # noqa: BLE001
        pass


def run_rust_requester_phase(
    *,
    args: argparse.Namespace,
    scenario: str,
    paths,
    profile_seed_dir: Path,
    rust_repo: Path,
    mfc_responder_ip: str,
    server_address: str,
    peer_ips: list[str],
    ports: dict[str, int],
    used_ports: set[int],
    server_endpoint: str,
    admin_base_url: str,
    fixture_path: Path,
) -> tuple[
    udp_evidence.ClientUdpV4Transition
    | udp_evidence.ClientUdpQueueFullTransition
    | udp_evidence.ClientUdpFileNotFoundTransition,
    dict[str, object],
]:
    mfc = None
    rust_clients: list[RustRuntime] = []
    withdrawn_fixture_path = None
    try:
        obfuscation_enabled = SCENARIO_OBFUSCATION[scenario]
        mfc = start_mfc(
            args=args,
            paths=paths,
            profile_seed_dir=profile_seed_dir,
            artifact_label="phase-rust-requester",
            p2p_address=mfc_responder_ip,
            server_address=server_address,
            ports=ports,
            obfuscation_enabled=obfuscation_enabled,
            saturate_upload_queue=True,
        )
        dtt.add_emule_shared_file(mfc["baseUrl"], args.api_key, fixture_path)
        dtt.reload_emule_shared_files(mfc["baseUrl"], args.api_key)
        shared = dtt.wait_for_emule_shared_file_link(
            mfc["baseUrl"],
            args.api_key,
            file_name=fixture_path.name,
            timeout_seconds=args.link_export_timeout_seconds,
        )
        link = str(shared["link"])
        file_hash = _canonical_hash(
            dtt.parse_ed2k_file_link(link)["hash"],
            field="MFC shared hash",
        )
        publication = wait_for_server_client_publication(
            admin_base_url,
            args.api_key,
            CLIENT_EMULEBB.nick,
            args.server_publish_timeout_seconds,
        )

        occupiers = [
            start_rust(
                repo=rust_repo,
                paths=paths,
                lan_bind_addr=args.lan_bind_addr,
                api_key=args.api_key,
                p2p_address=peer_ips[index],
                server_endpoint=server_endpoint,
                used_ports=used_ports,
                label=f"{scenario}-occupier-{index + 1}",
                enable_reask=False,
                obfuscation_enabled=obfuscation_enabled,
            )
            for index in range(2)
        ]
        rust_clients.extend(occupiers)
        requester = start_rust(
            repo=rust_repo,
            paths=paths,
            lan_bind_addr=args.lan_bind_addr,
            api_key=args.api_key,
            p2p_address=peer_ips[2],
            server_endpoint=server_endpoint,
            used_ports=used_ports,
            label=f"{scenario}-rust-requester",
            enable_reask=True,
            obfuscation_enabled=obfuscation_enabled,
        )
        rust_clients.append(requester)
        rust_high_id_clients = [
            wait_for_server_high_id_client(
                admin_base_url,
                args.api_key,
                runtime.nickname,
                args.server_connect_timeout_seconds,
            )
            for runtime in rust_clients
        ]
        for occupier in occupiers:
            cc.request_json(
                occupier.base_url,
                "POST",
                "/api/v1/transfers",
                args.api_key,
                {"link": link, "paused": False},
            )
        capacity = wait_for_upload_capacity(
            mfc["diagnosticsDir"],
            active_slots=2,
            timeout=args.reask_observe_timeout_seconds,
        )
        cc.request_json(
            requester.base_url,
            "POST",
            "/api/v1/transfers",
            args.api_key,
            {"link": link, "paused": False},
        )
        registration = wait_for_udp_reask_registration(
            requester.diagnostics_dir,
            side="rust",
            file_hash=file_hash,
            source_tcp_endpoint=mfc["tcpEndpoint"],
            source_udp_endpoint=mfc["udpEndpoint"],
            timeout=args.reask_observe_timeout_seconds,
            process=requester.process,
        )
        waiter_removal_receipt = None
        queue_pressure_receipt = None
        shared_withdrawal_receipt = None
        source_absence_receipt = None
        if scenario == "queue-full":
            waiter = wait_for_upload_waiter(
                mfc["baseUrl"],
                args.api_key,
                file_hash=file_hash,
                requester_tcp_endpoint=requester.tcp_endpoint,
                timeout=args.reask_observe_timeout_seconds,
            )
            waiter_removal_receipt = remove_upload_waiter(
                mfc["baseUrl"],
                args.api_key,
                waiter=waiter,
                file_hash=file_hash,
                requester_tcp_endpoint=requester.tcp_endpoint,
                timeout=args.reask_observe_timeout_seconds,
            )
            pressure_request = queue_pressure_request(
                file_hash=file_hash,
                requester_udp_endpoint=requester.udp_endpoint,
            )
            queue_pressure_receipt = arm_queue_pressure(
                mfc["baseUrl"],
                args.api_key,
                pressure_request,
            )
        elif scenario == "file-not-found":
            (
                shared_withdrawal_receipt,
                withdrawn_fixture_path,
            ) = withdraw_shared_fixture(
                mfc["baseUrl"],
                args.api_key,
                fixture_path=fixture_path,
                file_hash=file_hash,
                reload_path=MFC_SHARED_RELOAD_PATH,
                shared_files_path=MFC_SHARED_FILES_PATH,
                timeout=args.reask_observe_timeout_seconds,
            )
        control_request = queued_source_reask_request(
            file_hash=file_hash,
            source_tcp_endpoint=registration["sourceTcpEndpoint"],
            source_udp_endpoint=registration["sourceUdpEndpoint"],
            source_user_hash=registration["sourceUserHash"],
        )
        control_receipt = trigger_queued_source_reask(
            requester.base_url,
            args.api_key,
            control_request,
        )
        if scenario == "file-not-found":
            completion, requester_records = wait_for_file_not_found_completion(
                requester.diagnostics_dir,
                side="rust",
                file_hash=file_hash,
                source_tcp_endpoint=mfc["tcpEndpoint"],
                source_user_hash=registration["sourceUserHash"],
                timeout=args.reask_observe_timeout_seconds,
                process=requester.process,
            )
            applied = completion["applied"]
            source_absence_receipt = wait_for_transfer_source_absent(
                requester.base_url,
                args.api_key,
                file_hash=file_hash,
                source_tcp_endpoint=mfc["tcpEndpoint"],
                source_user_hash=registration["sourceUserHash"],
                timeout=args.reask_observe_timeout_seconds,
            )
        else:
            applied, requester_records = wait_for_udp_reask_applied(
                requester.diagnostics_dir,
                side="rust",
                file_hash=file_hash,
                source_tcp_endpoint=mfc["tcpEndpoint"],
                source_user_hash=registration["sourceUserHash"],
                reply_opcode=SCENARIO_REPLY_OPCODES[scenario],
                timeout=args.reask_observe_timeout_seconds,
                process=requester.process,
            )
        responder_records = current_diag_records(mfc["diagnosticsDir"], side="emule")
        transition_arguments = {
            "requester": "rust",
            "responder": "mfc",
            "source_tcp_endpoint": mfc["tcpEndpoint"],
            "source_udp_endpoint": mfc["udpEndpoint"],
            "source_user_hash": bytes.fromhex(registration["sourceUserHash"]),
            "requester_udp_endpoint": requester.udp_endpoint,
            "control_receipt": control_receipt,
            "requester_records": requester_records,
            "responder_records": responder_records,
        }
        if scenario == "queue-full":
            transition = udp_evidence.ClientUdpQueueFullTransition(
                **transition_arguments,
                waiter_removal_receipt=waiter_removal_receipt,
                queue_pressure_receipt=queue_pressure_receipt,
            )
        elif scenario == "file-not-found":
            transition = udp_evidence.ClientUdpFileNotFoundTransition(
                **transition_arguments,
                shared_withdrawal_receipt=shared_withdrawal_receipt,
                source_absence_receipt=source_absence_receipt,
            )
        else:
            transition = udp_evidence.ClientUdpV4Transition(**transition_arguments)
        check = {
            "fileHash": file_hash,
            "publication": publication,
            "rustHighIdClients": rust_high_id_clients,
            "capacity": capacity,
            "registration": registration,
            "control": control_receipt,
            "applicationSequence": applied.get("seq"),
        }
        if scenario == "queue-full":
            check["waiterRemoval"] = waiter_removal_receipt
            check["queuePressure"] = queue_pressure_receipt
        elif scenario == "file-not-found":
            check["sharedWithdrawal"] = shared_withdrawal_receipt
            check["sourceAbsence"] = source_absence_receipt
            check["deadListedSequence"] = completion["deadListed"].get("seq")
            check["droppedSequence"] = completion["dropped"].get("seq")
        return (
            transition,
            check,
        )
    finally:
        stop_mfc(mfc)
        for runtime in rust_clients:
            rust_client.stop_process_tree(runtime.process)
        if withdrawn_fixture_path is not None:
            restore_shared_fixture(fixture_path.resolve(), withdrawn_fixture_path)


def run_mfc_requester_phase(
    *,
    args: argparse.Namespace,
    scenario: str,
    paths,
    profile_seed_dir: Path,
    rust_repo: Path,
    uploader_ip: str,
    occupier_ip: str,
    p2p_address: str,
    server_address: str,
    ports: dict[str, int],
    used_ports: set[int],
    server_endpoint: str,
    admin_base_url: str,
    fixture_path: Path,
    expected_file_hash: str,
) -> tuple[
    udp_evidence.ClientUdpV4Transition
    | udp_evidence.ClientUdpQueueFullTransition
    | udp_evidence.ClientUdpFileNotFoundTransition,
    dict[str, object],
]:
    mfc = None
    uploader = None
    occupier = None
    withdrawn_fixture_path = None
    try:
        obfuscation_enabled = SCENARIO_OBFUSCATION[scenario]
        uploader = start_rust(
            repo=rust_repo,
            paths=paths,
            lan_bind_addr=args.lan_bind_addr,
            api_key=args.api_key,
            p2p_address=uploader_ip,
            server_endpoint=server_endpoint,
            used_ports=used_ports,
            label=f"{scenario}-rust-responder",
            enable_reask=True,
            obfuscation_enabled=obfuscation_enabled,
            upload_limit_kibps=4,
            base_upload_slots=1,
            upload_slot_elastic_percent=0,
            shared_dir=fixture_path.parent,
        )
        file_hash, link = rust_shared_file_link(
            uploader.base_url,
            args.api_key,
            file_name=fixture_path.name,
            timeout=args.link_export_timeout_seconds,
        )
        if file_hash != expected_file_hash:
            raise RuntimeError(
                f"Rust responder fixture hash {file_hash} does not match MFC {expected_file_hash}"
            )
        uploader_host, uploader_tcp_port = _split_endpoint(
            uploader.tcp_endpoint,
            field="Rust uploader TCP endpoint",
        )
        publication = wait_for_server_client_publication(
            admin_base_url,
            args.api_key,
            uploader.nickname,
            args.server_publish_timeout_seconds,
        )

        occupier = start_rust(
            repo=rust_repo,
            paths=paths,
            lan_bind_addr=args.lan_bind_addr,
            api_key=args.api_key,
            p2p_address=occupier_ip,
            server_endpoint=server_endpoint,
            used_ports=used_ports,
            label=f"{scenario}-responder-occupier",
            enable_reask=False,
            obfuscation_enabled=obfuscation_enabled,
        )
        occupier_high_id_client = wait_for_server_high_id_client(
            admin_base_url,
            args.api_key,
            occupier.nickname,
            args.server_connect_timeout_seconds,
        )
        cc.request_json(
            occupier.base_url,
            "POST",
            "/api/v1/transfers",
            args.api_key,
            {"link": link, "paused": False},
        )
        occupied_slot = wait_for_rust_occupied_upload_slot(
            uploader.diagnostics_dir,
            file_hash=file_hash,
            peer_endpoint=occupier.tcp_endpoint,
            timeout=args.reask_observe_timeout_seconds,
        )

        mfc = start_mfc(
            args=args,
            paths=paths,
            profile_seed_dir=profile_seed_dir,
            artifact_label="phase-mfc-requester",
            p2p_address=p2p_address,
            server_address=server_address,
            ports=ports,
            obfuscation_enabled=obfuscation_enabled,
        )
        mfc_high_id_client = wait_for_server_high_id_client(
            admin_base_url,
            args.api_key,
            CLIENT_EMULEBB.nick,
            args.server_connect_timeout_seconds,
        )
        dtt.add_transfer(mfc["baseUrl"], args.api_key, link, file_hash)
        source = wait_for_mfc_queued_source(
            mfc["baseUrl"],
            args.api_key,
            file_hash=file_hash,
            source_ip=uploader_host,
            source_tcp_port=uploader_tcp_port,
            timeout=args.reask_observe_timeout_seconds,
        )
        waiter_removal_receipt = None
        queue_pressure_receipt = None
        shared_withdrawal_receipt = None
        source_absence_receipt = None
        if scenario == "queue-full":
            waiter = wait_for_upload_waiter(
                uploader.base_url,
                args.api_key,
                file_hash=file_hash,
                requester_tcp_endpoint=mfc["tcpEndpoint"],
                timeout=args.reask_observe_timeout_seconds,
            )
            waiter_removal_receipt = remove_upload_waiter(
                uploader.base_url,
                args.api_key,
                waiter=waiter,
                file_hash=file_hash,
                requester_tcp_endpoint=mfc["tcpEndpoint"],
                timeout=args.reask_observe_timeout_seconds,
            )
            pressure_request = queue_pressure_request(
                file_hash=file_hash,
                requester_udp_endpoint=mfc["udpEndpoint"],
            )
            queue_pressure_receipt = arm_queue_pressure(
                uploader.base_url,
                args.api_key,
                pressure_request,
            )
        elif scenario == "file-not-found":
            shared_withdrawal_receipt = withdraw_rust_shared_root(
                uploader.base_url,
                args.api_key,
                fixture_path=fixture_path,
                file_hash=file_hash,
                timeout=args.reask_observe_timeout_seconds,
            )
        control_request = queued_source_reask_request(
            file_hash=file_hash,
            source_tcp_endpoint=uploader.tcp_endpoint,
            source_udp_endpoint=uploader.udp_endpoint,
            source_user_hash=source["sourceUserHash"],
        )
        control_receipt = trigger_queued_source_reask(
            mfc["baseUrl"],
            args.api_key,
            control_request,
        )
        if scenario == "file-not-found":
            completion, requester_records = wait_for_file_not_found_completion(
                mfc["diagnosticsDir"],
                side="emule",
                file_hash=file_hash,
                source_tcp_endpoint=uploader.tcp_endpoint,
                source_user_hash=source["sourceUserHash"],
                timeout=args.reask_observe_timeout_seconds,
            )
            applied = completion["applied"]
            source_absence_receipt = wait_for_transfer_source_absent(
                mfc["baseUrl"],
                args.api_key,
                file_hash=file_hash,
                source_tcp_endpoint=uploader.tcp_endpoint,
                source_user_hash=source["sourceUserHash"],
                timeout=args.reask_observe_timeout_seconds,
            )
        else:
            applied, requester_records = wait_for_udp_reask_applied(
                mfc["diagnosticsDir"],
                side="emule",
                file_hash=file_hash,
                source_tcp_endpoint=uploader.tcp_endpoint,
                source_user_hash=source["sourceUserHash"],
                reply_opcode=SCENARIO_REPLY_OPCODES[scenario],
                timeout=args.reask_observe_timeout_seconds,
            )
        responder_records = current_diag_records(
            uploader.diagnostics_dir,
            side="rust",
        )
        transition_arguments = {
            "requester": "mfc",
            "responder": "rust",
            "source_tcp_endpoint": uploader.tcp_endpoint,
            "source_udp_endpoint": uploader.udp_endpoint,
            "source_user_hash": bytes.fromhex(source["sourceUserHash"]),
            "requester_udp_endpoint": mfc["udpEndpoint"],
            "control_receipt": control_receipt,
            "requester_records": requester_records,
            "responder_records": responder_records,
        }
        if scenario == "queue-full":
            transition = udp_evidence.ClientUdpQueueFullTransition(
                **transition_arguments,
                waiter_removal_receipt=waiter_removal_receipt,
                queue_pressure_receipt=queue_pressure_receipt,
            )
        elif scenario == "file-not-found":
            transition = udp_evidence.ClientUdpFileNotFoundTransition(
                **transition_arguments,
                shared_withdrawal_receipt=shared_withdrawal_receipt,
                source_absence_receipt=source_absence_receipt,
            )
        else:
            transition = udp_evidence.ClientUdpV4Transition(**transition_arguments)
        check = {
            "fileHash": file_hash,
            "publication": publication,
            "occupierHighIdClient": occupier_high_id_client,
            "occupiedSlot": occupied_slot,
            "mfcHighIdClient": mfc_high_id_client,
            "queueSource": source,
            "control": control_receipt,
            "applicationSequence": applied.get("seq"),
        }
        if scenario == "queue-full":
            check["waiterRemoval"] = waiter_removal_receipt
            check["queuePressure"] = queue_pressure_receipt
        elif scenario == "file-not-found":
            check["sharedWithdrawal"] = shared_withdrawal_receipt
            check["sourceAbsence"] = source_absence_receipt
            check["deadListedSequence"] = completion["deadListed"].get("seq")
            check["droppedSequence"] = completion["dropped"].get("seq")
        return (
            transition,
            check,
        )
    finally:
        stop_mfc(mfc)
        if occupier is not None:
            rust_client.stop_process_tree(occupier.process)
        if uploader is not None:
            rust_client.stop_process_tree(uploader.process)
        if withdrawn_fixture_path is not None:
            restore_shared_fixture(fixture_path.resolve(), withdrawn_fixture_path)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.fixture_size_bytes <= 0:
        raise ValueError("--fixture-size-bytes must be greater than zero")
    app_exe = str(
        converged_live_wire.resolve_mfc_diagnostics_exe(
            get_workspace_output_root(),
            configuration="Release",
        )
    )
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration="Release",
        workspace_root=None,
        app_root=None,
        app_exe=app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    profile_seed_dir = (
        Path(args.profile_seed_dir).resolve()
        if args.profile_seed_dir
        else paths.seed_config_dir
    )
    coverage_id = SCENARIO_COVERAGE_IDS[args.scenario]
    campaign_schema = SCENARIO_CAMPAIGN_SCHEMAS[args.scenario]
    report: dict[str, object] = {
        "schema": campaign_schema,
        "suite": SUITE_NAME,
        "scenario": args.scenario,
        "coverageId": coverage_id,
        "status": "running",
        "checks": {},
    }
    server_process = None
    high_id_pool = None
    try:
        if args.p2p_bind_interface_name or args.p2p_bind_interface_address:
            raise ValueError(
                f"{coverage_id} owns its deterministic HighID route; "
                "do not pass a P2P bind override"
            )
        builds = prepare_authoritative_builds(paths)
        report["builds"] = builds.report
        (
            high_id_pool,
            high_id_address,
            _windows_route_address,
        ) = dtt.provision_relayed_reask_high_id_address()
        peer_ips = high_id_pool.acquire(3)
        ports = dtt.choose_distinct_ports(args.lan_bind_addr)
        used_ports = set(ports.values())
        ed2k_server = ed2k_harness.launch_ed2k_server(
            workspace_root=paths.workspace_root,
            server_dir=paths.source_artifacts_dir / "ed2k-server",
            ed2k_port=ports["ed2k_tcp"],
            admin_port=ports["ed2k_admin"],
            token=args.api_key,
            admin_address=args.lan_bind_addr,
            ed2k_address=high_id_address,
            exe_override=str(builds.server_exe),
            advertised_address_override=high_id_address,
            hairpin_lan_clients=True,
        )
        server_process = ed2k_server.process
        server_address = ed2k_server.ed2k_host
        server_endpoint = f"{server_address}:{ed2k_server.ed2k_port}"
        report["network"] = {
            "controlAddress": args.lan_bind_addr,
            "serverAddress": server_address,
            "mfcResponderAddress": high_id_address,
            "rustPeerAddresses": peer_ips,
            "transportMode": (
                "obfuscated" if SCENARIO_OBFUSCATION[args.scenario] else "plaintext"
            ),
            "publicTraffic": False,
        }
        if ed2k_server.server_exe.resolve() != builds.server_exe:
            raise RuntimeError(
                "ed2k-server launch did not use the clean-built executable"
            )

        fixture_path = (
            paths.source_artifacts_dir / "fixture" / f"client-udp-{args.scenario}.bin"
        )
        dtt.write_fixture_file(
            fixture_path,
            args.fixture_size_bytes,
            seed=0x5EA5C0DE,
        )
        part_count = max(
            1,
            (args.fixture_size_bytes + cc.ED2K_PART_SIZE_BYTES - 1)
            // cc.ED2K_PART_SIZE_BYTES,
        )
        report["fixture"] = {
            "path": str(fixture_path),
            "sizeBytes": args.fixture_size_bytes,
            "partCount": part_count,
        }

        report["currentPhase"] = "rust-requester-mfc-responder"
        rust_transition, rust_check = run_rust_requester_phase(
            args=args,
            scenario=args.scenario,
            paths=paths,
            profile_seed_dir=profile_seed_dir,
            rust_repo=builds.rust_repo,
            mfc_responder_ip=high_id_address,
            server_address=server_address,
            peer_ips=peer_ips,
            ports=ports,
            used_ports=used_ports,
            server_endpoint=server_endpoint,
            admin_base_url=ed2k_server.admin_base_url,
            fixture_path=fixture_path,
        )
        report["checks"]["rustRequesterMfcResponder"] = rust_check

        report["currentPhase"] = "mfc-requester-rust-responder"
        mfc_transition, mfc_check = run_mfc_requester_phase(
            args=args,
            scenario=args.scenario,
            paths=paths,
            profile_seed_dir=profile_seed_dir,
            rust_repo=builds.rust_repo,
            uploader_ip=high_id_address,
            occupier_ip=peer_ips[0],
            p2p_address=peer_ips[1],
            server_address=server_address,
            ports=ports,
            used_ports=used_ports,
            server_endpoint=server_endpoint,
            admin_base_url=ed2k_server.admin_base_url,
            fixture_path=fixture_path,
            expected_file_hash=rust_check["fileHash"],
        )
        report["checks"]["mfcRequesterRustResponder"] = mfc_check

        report["currentPhase"] = "causal-evidence"
        transitions = [rust_transition, mfc_transition]
        if args.scenario in SCENARIO_RAW_EVIDENCE_SCHEMAS:
            raw_evidence_path = (
                paths.source_artifacts_dir
                / f"client-udp-{args.scenario}-raw-evidence.json"
            )
            harness_cli_common.write_json_file(
                raw_evidence_path,
                build_ack_raw_evidence(
                    scenario=args.scenario,
                    file_hash=rust_check["fileHash"],
                    part_count=part_count,
                    transitions=transitions,
                ),
            )
            report["rawEvidence"] = {
                "path": str(raw_evidence_path),
                "sizeBytes": raw_evidence_path.stat().st_size,
                "sha256": dtt.file_sha256(raw_evidence_path),
            }
        evidence_builder = SCENARIO_EVIDENCE_BUILDERS[args.scenario]
        evidence = evidence_builder(
            file_hash=bytes.fromhex(rust_check["fileHash"]),
            part_count=part_count,
            stock_record=load_stock_client_udp_record(),
            transitions=transitions,
        )
        report["evidence"] = evidence
        SCENARIO_EVIDENCE_REQUIREMENTS[args.scenario](evidence)
        runner_after = build_provenance.require_clean_git_source(
            REPO_ROOT,
            label="client-UDP campaign runner",
        )
        if runner_after.revision != report["builds"]["runner"]["sourceRevision"]:
            raise RuntimeError(
                "client-UDP campaign runner revision changed during the run"
            )
        report["currentPhase"] = "complete"
        report["status"] = "passed"
        return 0
    except Exception as exc:  # noqa: BLE001
        report["status"] = "failed"
        report["error"] = {
            "type": type(exc).__name__,
            "message": str(exc) or repr(exc),
        }
        return 1
    finally:
        ed2k_harness.stop_process(server_process)
        if high_id_pool is not None:
            high_id_pool.release()
        report["finishedAt"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        harness_cli_common.write_json_file(
            paths.source_artifacts_dir / "emulebb-rust-reask-cross-client-result.json",
            report,
        )
        print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
