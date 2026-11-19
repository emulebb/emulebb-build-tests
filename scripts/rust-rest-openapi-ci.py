"""Launch a local Rust daemon and gate its live responses against OpenAPI.

This is the CI-owned counterpart to ``check-rust-rest-openapi-responses.py``.
It creates a fresh external profile with networking disabled for response/SSE
conformance, then exercises real friend controls and Kad persistence with
separate loopback-only peers. Every daemon is stopped and evidence is retained.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import rust_client, rust_local_ed2k, rust_metadata, rust_rest_conformance  # noqa: E402
from emule_test_harness.ed2k_file_observer import Ed2kFilePeerObserver  # noqa: E402
from emule_test_harness.paths import get_required_emule_workspace_root, get_workspace_output_root  # noqa: E402
from emule_test_harness.vm_guest_profiles import http_json, wait_until  # noqa: E402
from emule_test_harness.script_modules import load_script_module  # noqa: E402
from emule_test_harness.rust_openapi_responses import (  # noqa: E402
    load_openapi_document, openapi_operation_response, response_json_schema, validate_openapi_schema,
)

API_KEY = "rust-rest-openapi-ci-secret-0001"
REST_ADDR = "127.0.0.1"
FRIEND_PEER_BUDGET_SECONDS = 180.0
KAD_IMPORT_BUDGET_SECONDS = 90.0
CATEGORY_BUDGET_SECONDS = 120.0
LISTENER_RECEIPT_FILE = ".emulebb-rest-listener.json"
FRIEND_FAULT_TRIGGERS = tuple(f"harness_friend_failure_{operation}" for operation in ("insert", "update", "delete"))


def verify_listener_receipt(profile: Path, base_url: str) -> dict[str, object]:
    """Match the owned profile's actual listener to its unauthenticated probe."""
    receipt = json.loads((profile / LISTENER_RECEIPT_FILE).read_text(encoding="utf-8"))
    expected = urllib.parse.urlsplit(base_url)
    if (not isinstance(receipt, dict)
            or receipt.get("probeHost") != expected.hostname
            or type(receipt.get("probePort")) is not int
            or receipt["probePort"] != expected.port
            or not isinstance(receipt.get("instanceId"), str)
            or re.fullmatch(r"[0-9a-f]{32}", receipt["instanceId"]) is None):
        raise RuntimeError("Listener receipt does not identify the actual fixture endpoint")
    request = urllib.request.Request(base_url + "/healthz")
    with urllib.request.urlopen(request, timeout=2.0) as response:
        if response.status != 204 or response.headers.get("X-Emulebb-Instance") != receipt["instanceId"]:
            raise RuntimeError("Listener receipt is stale or health endpoint is not ready")
    return {"status": "passed", "configuredPort": receipt["probePort"], "instanceMatched": True}


def require_download_id(row: dict[str, Any], *, hash_value: str) -> str:
    """Keep the allocated job identity separate from the protocol content hash."""
    job_id = row.get("id")
    if (not isinstance(job_id, str) or not re.fullmatch(r"[1-9][0-9]{0,18}", job_id)
            or int(job_id) > 9223372036854775807 or row.get("hash") != hash_value):
        raise RuntimeError(f"Download admission returned invalid job identity: {row}")
    return job_id


def require_download_action_result(response: dict[str, Any], job_id: str) -> str:
    """An admitted one-job action succeeds only when its exact item succeeds."""
    payload = response.get("raw_json")
    items = payload.get("data") if isinstance(payload, dict) else None
    if (response.get("status") != 207 or not isinstance(items, list) or len(items) != 1
            or not isinstance(items[0], dict) or items[0].get("id") != job_id
            or items[0].get("status") not in ("accepted", "unchanged")
            or items[0].get("httpStatus") not in (200, 202) or "error" in items[0]
            or (items[0]["status"] == "unchanged" and items[0]["httpStatus"] != 200)):
        raise RuntimeError(f"Download action did not succeed for job {job_id}: {response}")
    return items[0]["status"]


def kad_node_id_display(wire_hex: str) -> str:
    """Match NodeId Display: four little-endian CUInt128 words, in word order."""
    return "".join(f"{word:08x}" for word in struct.unpack("<4I", bytes.fromhex(wire_hex)))


def kad_contact_display_ids(snapshot: dict) -> list[str]:
    """Translate SQLite wire identities before comparing REST contact membership."""
    return sorted(kad_node_id_display(row[0]) for row in snapshot["contacts"])


def kad_database_snapshot(rust_repo: Path, database: Path) -> dict[str, object]:
    """Capture current-schema identity and routing evidence from one read-only transaction."""
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
        with connection:
            connection.execute("BEGIN")
            if connection.execute("SELECT schema_id,schema_version FROM metadata_schema").fetchall() != [rust_metadata._schema_marker(rust_repo)]:
                raise RuntimeError("Kad evidence requires the selected current metadata schema")
            identity = connection.execute(
                "SELECT lower(hex(public_identity)) FROM local_identities WHERE identity_kind='kad-node-id'"
            ).fetchone()
            return {
                "identity": identity[0] if identity else None,
                "initialization": connection.execute(
                    "SELECT status FROM discovery_initialization WHERE domain='kad'").fetchone()[0],
                "revision": connection.execute("SELECT revision FROM kad_routing_revision WHERE id=1").fetchone()[0],
                "contacts": [[value.hex() if isinstance(value, bytes) else value for value in row]
                             for row in connection.execute("SELECT * FROM kad_routing_contacts ORDER BY node_id")],
            }


def kad_import_fault(database: Path, *, enabled: bool) -> None:
    """Make the owned routing transaction abort at its real revision update."""
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=rw", uri=True)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            if enabled:
                connection.execute("CREATE TRIGGER harness_kad_revision_failure BEFORE UPDATE ON kad_routing_revision "
                                   "BEGIN SELECT RAISE(ABORT, 'harness Kad revision failure'); END")
            else:
                connection.execute("DROP TRIGGER IF EXISTS harness_kad_revision_failure")


def prove_kad_import(*, request, rust_repo: Path, database: Path, url: str,
                     expected_node_id_wire_hex: str, document: dict) -> dict[str, object]:
    """Prove actual SQL failure rolls back the import before a successful retry."""
    route = "/kad/operations/import-nodes-url"
    before = kad_database_snapshot(rust_repo, database)
    cache_before = request("GET", "/api/v1/kad/nodes")["json"]["data"]
    try:
        kad_import_fault(database, enabled=True)
        response = request("POST", f"/api/v1{route}", expected=500, body={"url": url})
        payload = response["json"]
        if payload.get("error", {}).get("code") != "PERSISTENCE_FAILED":
            raise RuntimeError("Kad revision fault did not return PERSISTENCE_FAILED")
        schema = response_json_schema(openapi_operation_response(document, "POST", route, 500), route)
        validate_openapi_schema(document, schema, payload)
        if kad_database_snapshot(rust_repo, database) != before:
            raise RuntimeError("Failed Kad import changed durable identity/routing state")
        if request("GET", "/api/v1/kad/nodes")["json"]["data"] != cache_before:
            raise RuntimeError("Failed Kad import changed the live contact collection")
    finally:
        kad_import_fault(database, enabled=False)
    response = request("POST", f"/api/v1{route}", body={"url": url})
    schema = response_json_schema(openapi_operation_response(document, "POST", route, 200), route)
    validate_openapi_schema(document, schema, response["json"])
    if response["json"]["data"].get("imported") is not True:
        raise RuntimeError("Kad import retry did not import its local input")
    after = kad_database_snapshot(rust_repo, database)
    ids = [row[0] for row in after["contacts"]]
    cache = request("GET", "/api/v1/kad/nodes")["json"]["data"]
    if (ids != [expected_node_id_wire_hex] or after["initialization"] != "initialized"
            or after["revision"] <= before["revision"]
            or sorted(row["nodeId"] for row in cache["items"]) != kad_contact_display_ids(after)):
        raise RuntimeError("Kad import retry lacks one coherent unique durable/live contact")
    return {"route": route, "failure": {"status": 500, "code": "PERSISTENCE_FAILED",
            "routingSnapshotUnchanged": True, "liveContactsUnchanged": True},
            "retry": "passed", "nodeIdWireHex": expected_node_id_wire_hex,
            "nodeIdDisplay": kad_node_id_display(expected_node_id_wire_hex),
            "before": before, "after": after}


def run_kad_persistence_phase(*, executable: Path, rust_repo: Path, root: Path,
                              openapi_contract: Path) -> dict[str, object]:
    """Import, roll back, retry and reopen one local-only Kad profile."""
    from emule_test_harness.local_kad_peer import LocalKadPeer

    package = load_script_module("package_helpers_for_kad_contract", "smoke-rust-release-package.py")
    smoke = rust_rest_conformance.load_rest_smoke_module(openapi_contract)
    document = load_openapi_document(openapi_contract)
    report: dict[str, Any] = {"status": "failed", "networkMode": "loopback-direct-local-only",
                              "budgetSeconds": KAD_IMPORT_BUDGET_SECONDS}
    deadline = time.monotonic() + KAD_IMPORT_BUDGET_SECONDS
    root.mkdir(parents=True, exist_ok=False)
    profile = root / "profile"
    database = profile / rust_metadata.RUST_PROFILE_METADATA_FILE
    process = handle = fixture = None
    base_url = ""

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise RuntimeError("Kad persistence phase exceeded its runtime budget")
        return value

    def request(method, path, *, expected=200, body=None):
        response = smoke.http_request(base_url, path, method=method, api_key=API_KEY, json_body=body,
                                      request_timeout_seconds=min(5.0, remaining()))
        if response["status"] != expected:
            raise RuntimeError(f"Kad phase {method} {path} expected {expected}: {response}")
        return {"status": response["status"], "json": response["raw_json"]}

    def ready():
        if process.poll() is not None:
            raise RuntimeError("Kad persistence daemon exited before readiness")
        return request("GET", "/api/v1/status")

    try:
        fixture = LocalKadPeer(REST_ADDR, {REST_ADDR})
        fixture.start()
        ports: set[int] = set()
        rest_port = package._available_unique_port(ports)
        base_url = f"http://127.0.0.1:{rest_port}"
        rust_client.write_rust_profile(
            profile,
            rust_repo=rust_repo,
            rest_addr=REST_ADDR,
            rest_port=rest_port,
            api_key=API_KEY,
            server_endpoint=f'127.0.0.1:{package._available_unique_port(ports)}',
            local_only_discovery=True,
            local_kad_seed=rust_client.kad_nodes.BootstrapContact(REST_ADDR, fixture.udp_port, fixture.tcp_port),
            settings={
                'network.kadEnabled': True,
                'network.p2p.bindIp': REST_ADDR,
                'network.p2p.tcpPort': package._available_unique_port(ports),
                'network.p2p.udpPort': package._available_unique_port(ports, socket_type=socket.SOCK_DGRAM),
                'network.nat.enabled': False,
                'security.obfuscationEnabled': False,
                'sharing.scanOnStartup': False,
                'network.connections.connectTimeoutSeconds': 10,
                'network.servers.reconnectIntervalSeconds': 60,
            },
        )
        process, handle = package._start_daemon(executable, profile, root / "daemon.log")
        wait_until("Kad persistence REST readiness", remaining(), ready)
        request("POST", "/api/v1/kad/operations/stop")
        if request("GET", "/api/v1/kad")["json"]["data"]["running"]:
            raise RuntimeError("Kad import rollback proof requires a stopped runtime")
        # The existing runtime is created through server connect; the only
        # configured server and Kad bootstrap endpoint are loopback fixtures.
        request("POST", "/api/v1/servers/operations/connect")
        request("POST", "/api/v1/kad/operations/start")
        request("POST", "/api/v1/kad/operations/bootstrap",
                body={"address": REST_ADDR, "port": fixture.udp_port})

        def connected_local_peer():
            status = request("GET", "/api/v1/kad")["json"]["data"]
            evidence = fixture.evidence()
            return evidence if status.get("running") and int(evidence.get("routingReplies", 0)) > 0 else None

        report["localPeer"] = wait_until("real loopback Kad routing reply", remaining(), connected_local_peer)
        report["localPeer"]["nodeIdWireHex"] = fixture.node_id.hex()
        report["localPeer"]["nodeIdDisplay"] = kad_node_id_display(fixture.node_id.hex())
        request("POST", "/api/v1/kad/operations/stop")
        if not kad_database_snapshot(rust_repo, database)["identity"]:
            raise RuntimeError("Kad fault baseline requires its established runtime identity")
        report["import"] = prove_kad_import(
            request=request, rust_repo=rust_repo, database=database, url=fixture.nodes_url,
            expected_node_id_wire_hex=fixture.node_id.hex(), document=document)
        settled = kad_database_snapshot(rust_repo, database)
        if not settled["identity"] or not settled["contacts"]:
            raise RuntimeError("Kad stop did not retain its durable identity and local contact")
        request("POST", "/api/v1/app/shutdown", body={"confirmShutdown": True})
        process.wait(timeout=min(20.0, remaining()))
        if process.returncode != 0:
            raise RuntimeError("Kad persistence daemon did not stop gracefully")
        handle.close()
        handle = None
        reopened = kad_database_snapshot(rust_repo, database)
        if (reopened["identity"] != settled["identity"] or reopened["initialization"] != settled["initialization"]
                or [row[:4] for row in reopened["contacts"]] != [row[:4] for row in settled["contacts"]]):
            raise RuntimeError("Kad durable identity/contact membership changed after graceful daemon exit")
        process, handle = package._start_daemon(executable, profile, root / "restart.log")
        wait_until("restarted Kad persistence REST readiness", remaining(), ready)
        restarted = kad_database_snapshot(rust_repo, database)
        if restarted != reopened:
            raise RuntimeError("Same-profile restart changed durable Kad identity or contacts")
        request("POST", "/api/v1/servers/operations/connect")
        request("POST", "/api/v1/kad/operations/stop")
        cached_ids = [row["nodeId"] for row in request("GET", "/api/v1/kad/nodes")["json"]["data"]["items"]]
        if sorted(cached_ids) != kad_contact_display_ids(reopened):
            raise RuntimeError("Same-profile restart did not retain Kad identity and contacts")
        if (profile / "nodes.dat").exists():
            raise RuntimeError("Kad runtime created a profile cache file outside SQLite")
        report["reopen"] = {"identityStable": True, "contactsStable": True, "afterRestart": restarted}
        report["status"] = "passed"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        try:
            if database.is_file():
                kad_import_fault(database, enabled=False)
        except Exception as error:
            report["status"] = "failed"
            report["faultCleanupError"] = str(error)
        try:
            if process is not None and process.poll() is None:
                http_json(base_url, "/api/v1/app/shutdown", api_key=API_KEY, method="POST",
                          body={"confirmShutdown": True}, timeout_seconds=5.0)
                process.wait(timeout=20.0)
            if process is not None and process.poll() != 0:
                raise RuntimeError("Kad persistence daemon did not stop gracefully")
            report["teardown"] = "graceful"
        except Exception as error:
            report["status"] = "failed"
            report["teardown"] = f"forced: {error}"
            if process is not None:
                rust_client.stop_process_tree(process)
        finally:
            if handle is not None:
                handle.close()
            if fixture is not None:
                try:
                    fixture.close()
                except Exception as error:
                    report["status"] = "failed"
                    report["fixtureCleanupError"] = str(error)
        write_report(root / "report.json", report)
    if report["status"] != "passed":
        raise RuntimeError(f"Kad persistence proof failed; evidence: {root / 'report.json'}")
    return report


def run_category_persistence_phase(*, executable: Path, rust_repo: Path, root: Path,
                                   openapi_contract: Path) -> dict[str, object]:
    """Prove category assignment, job identity and complete sharing across restart."""
    package = load_script_module("package_helpers_for_category_contract", "smoke-rust-release-package.py")
    smoke = rust_rest_conformance.load_rest_smoke_module(openapi_contract)
    document = load_openapi_document(openapi_contract)
    root.mkdir(parents=True, exist_ok=False)
    profile = root / "profile"
    incoming = profile / "incoming"
    temp_override = profile / "category-temp"
    destination = profile / "category-destination"
    independent_root = profile / "independent-shared-root"
    for directory in (incoming, temp_override, destination, independent_root):
        directory.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"status": "failed", "networkMode": "loopback-direct-local-only",
                              "budgetSeconds": CATEGORY_BUDGET_SECONDS}
    deadline = time.monotonic() + CATEGORY_BUDGET_SECONDS
    process = handle = None
    port = choose_loopback_port()
    base_url = f"http://{REST_ADDR}:{port}"
    database = profile / rust_metadata.RUST_PROFILE_METADATA_FILE

    def remaining() -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise RuntimeError("Category persistence phase exceeded its runtime budget")
        return value

    def request(method: str, path: str, *, body: dict[str, Any] | None = None) -> Any:
        if method == "PATCH" and path.startswith("/api/v1/downloads/"):
            response = smoke.http_request(base_url, path, method=method, api_key=package.API_KEY,
                                          json_body=body, request_timeout_seconds=min(5.0, remaining()))
            if response["status"] != 204:
                raise RuntimeError(f"Download metadata patch expected 204: {response}")
            return None
        return http_json(base_url, path, api_key=package.API_KEY, method=method, body=body,
                         timeout_seconds=min(5.0, remaining()))["data"]

    def ready() -> object:
        if process is not None and process.poll() is not None:
            raise RuntimeError("Category persistence daemon exited before readiness")
        return request("GET", "/api/v1/status")

    def categories() -> list[dict[str, Any]]:
        return request("GET", "/api/v1/categories")["items"]

    def shared_files() -> dict[str, Any]:
        return request("GET", "/api/v1/shared-files")

    def shared_file_or_none(hash_value: str) -> dict[str, Any] | None:
        try:
            return request("GET", f"/api/v1/shared-files/{hash_value}")
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise

    def reload_settled() -> object | None:
        directories = request("GET", "/api/v1/library/scan")
        progress = directories.get("reloadProgress")
        if (isinstance(progress, dict) and progress.get("running") is False
                and progress.get("pending") is False and directories.get("hashingCount") == 0):
            return progress
        return None

    def require_category(row: dict[str, Any], *, name: str,
                         temp_dir: str | None, destination_dir: str | None,
                         comment: str) -> None:
        expected = {"name": name, "tempDir": temp_dir,
                    "destinationDir": destination_dir, "comment": comment}
        if row != expected:
            raise RuntimeError(f"Category contract differs: expected {expected}, got {row}")

    def validated_read(path: str, contract_path: str) -> dict[str, Any]:
        payload = http_json(base_url, path, api_key=package.API_KEY,
                            timeout_seconds=min(5.0, remaining()))
        schema = response_json_schema(openapi_operation_response(document, "GET", contract_path, 200),
                                      f"GET {contract_path} 200")
        validate_openapi_schema(document, schema, payload)
        return payload

    def library_request(method: str, path: str, contract_path: str, status: int,
                    body: dict[str, Any] | None = None) -> Any:
        response = smoke.http_request(base_url, path, method=method, api_key=package.API_KEY,
                                      json_body=body, request_timeout_seconds=min(5.0, remaining()))
        if response["status"] != status:
            raise RuntimeError(f"Library contract expected HTTP {status}: {response}")
        if status == 204:
            if response.get("body_text") != "" or response.get("raw_json") is not None:
                raise RuntimeError("No-content library operation returned a body")
            return None
        payload = response["raw_json"]
        schema = response_json_schema(openapi_operation_response(document, method, contract_path, status),
                                      f"{method} {contract_path} {status}")
        validate_openapi_schema(document, schema, payload)
        return payload["data"]

    def sharing(enabled: bool, selected: list[str], expected: list[str]) -> None:
        rows = library_request("POST", "/api/v1/library/files/sharing", "/library/files/sharing", 207,
                               {"enabled": enabled, "hashes": selected})
        if [row["hash"] for row in rows] != selected or [row["status"] for row in rows] != expected:
            raise RuntimeError(f"Ordered sharing outcomes differ: {rows}")

    def sharing_flags(selected: list[str]) -> list[bool | None]:
        with closing(sqlite3.connect(database)) as connection:
            return [None if (row := connection.execute(
                "SELECT sharing_enabled FROM known_files WHERE ed2k_hash=?", (bytes.fromhex(value),)).fetchone()) is None
                else bool(row[0]) for value in selected]

    def upload_counts(hash_value: str) -> tuple[int, int]:
        with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            row = connection.execute(
                "SELECT all_time_upload_requests,all_time_upload_accepts FROM known_files WHERE ed2k_hash=?",
                (bytes.fromhex(hash_value),),
            ).fetchone()
        if row is None:
            raise RuntimeError("Upload accounting lost the known library hash")
        return int(row[0]), int(row[1])

    def live_upload_counts(hash_value: str) -> tuple[int, int]:
        row = shared_file_or_none(hash_value)
        if row is None:
            raise RuntimeError("Live upload accounting lost the physical library entry")
        return int(row["allTimeRequests"]), int(row["allTimeAccepts"])

    def upload_timestamps(hash_value: str) -> tuple[int | None, int | None]:
        with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            row = connection.execute(
                "SELECT last_upload_requested_at_s,last_uploaded_at_s FROM known_files WHERE ed2k_hash=?",
                (bytes.fromhex(hash_value),),
            ).fetchone()
        if row is None:
            raise RuntimeError("Upload timestamps lost the known library hash")
        return row[0], row[1]

    def require_upload_checkpoint(hash_value: str, expected: tuple[int, int]) -> tuple[int, int]:
        def settled() -> tuple[int, int] | None:
            current = upload_counts(hash_value)
            return current if current == expected else None
        return wait_until("upload accounting checkpoint", remaining(), settled)

    def require_file_tags(hash_value: str, names: list[str]) -> None:
        rows = library_request("GET", f"/api/v1/library/files/{hash_value}/tags",
                           "/library/files/{hash}/tags", 200)
        if rows != [{"name": name} for name in names]:
            raise RuntimeError(f"Durable library tag membership differs: {rows}")

    def download(job_id: str) -> dict[str, Any]:
        return request("GET", f"/api/v1/downloads/{job_id}")

    def assignments() -> list[object]:
        return [download(job_id).get("category") for job_id in job_ids]

    def add_download(hash_value: str, name: str, *, category: str | None = None) -> str:
        body: dict[str, Any] = {"source": {"type": "content", "hash": hash_value,
                                         "name": name, "sizeBytes": 4096}, "intent": "stopped"}
        if category is not None:
            body["category"] = category
        result = smoke.http_request(base_url, "/api/v1/downloads", method="POST", api_key=package.API_KEY,
                                    json_body=body, request_timeout_seconds=min(5.0, remaining()))
        if result["status"] != 201:
            raise RuntimeError(f"Fresh download admission expected 201: {result}")
        row = result["raw_json"]["data"]
        job_id = require_download_id(row, hash_value=hash_value)
        if (row.get("name"), row.get("category"), row.get("sizeBytes"), row.get("intent")) != (
                name, category.title() if category is not None else None, 4096, "stopped"):
            raise RuntimeError(f"Download admission changed requested fields: {row}")
        return job_id

    def download_action(operation: str, job_id: str) -> str:
        result = smoke.http_request(base_url, f"/api/v1/downloads/{operation}", method="POST",
                                    api_key=package.API_KEY, json_body={"ids": [job_id]},
                                    request_timeout_seconds=min(5.0, remaining()))
        return require_download_action_result(result, job_id)

    def download_page(path: str) -> list[dict[str, Any]]:
        result = http_json(base_url, path, api_key=package.API_KEY,
                           timeout_seconds=min(5.0, remaining()))
        rows, meta = result.get("data"), result.get("meta")
        if (not isinstance(rows, list) or not isinstance(meta, dict)
                or meta.get("hasMore") is not False or meta.get("nextCursor") is not None):
            raise RuntimeError(f"Small download page did not settle: {result}")
        return rows

    def durable_jobs() -> list[tuple[Any, ...]]:
        with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            if connection.execute("SELECT schema_id,schema_version FROM metadata_schema").fetchall() != [
                    rust_metadata._schema_marker(rust_repo)]:
                raise RuntimeError("Download evidence requires the selected current metadata schema")
            return connection.execute(
                "SELECT j.id,lower(hex(k.ed2k_hash)),c.name,j.intent,"
                "temp.display_path,storage.display_path,j.storage_directory_marker_id,"
                "j.storage_directory_identity FROM download_jobs j "
                "JOIN known_files k ON k.id=j.known_file_id "
                "LEFT JOIN categories c ON c.id=j.category_id "
                "LEFT JOIN local_paths temp ON temp.id=j.selected_temp_path_id "
                "LEFT JOIN local_paths storage ON storage.id=j.storage_path_id "
                "WHERE j.removed_at_s IS NULL ORDER BY j.id"
            ).fetchall()

    hashes = ("00112233445566778899aabbccddeeff", "102132435465768798a9babcbddceeff",
              "2031425364758697a8b9cadbecfd0e1f")
    job_ids: list[str] = []
    try:
        ports = {port}
        server_port = package._available_unique_port(ports)
        tcp_port = package._available_unique_port(ports)
        udp_port = package._available_unique_port(ports, socket_type=socket.SOCK_DGRAM)
        package._write_profile(
            profile, rust_repo=rust_repo, incoming=incoming, rest_port=port,
            ed2k_port=tcp_port, kad_port=udp_port, runtime_server_port=server_port,
            p2p_ip=REST_ADDR,
        )
        search_fixture = rust_metadata.seed_search_observation_fixture(rust_repo, database)
        process, handle = package._start_daemon(executable, profile, root / "daemon.log")
        wait_until("category REST readiness", remaining(), ready)
        session_path = f"/api/v1/searches/{search_fixture['sessionId']}"
        session_metadata = validated_read(session_path, "/searches/{searchId}")
        if session_metadata["data"]["resultCount"] != 1 or session_metadata["data"]["status"] != "completed":
            raise RuntimeError("Search metadata lost retained result cardinality or terminal state")
        summaries = validated_read(session_path + "/results?limit=1&sort=sources&order=desc", "/searches/{searchId}/results")
        if summaries["data"][0]["id"] != search_fixture["resultId"] or summaries["data"][0]["displayName"] != "Beta.bin":
            raise RuntimeError("Sorted result summary lost its permanent claim identity or selected name")
        selected = validated_read(session_path + "/results/" + search_fixture["resultId"], "/searches/{searchId}/results/{resultId}")
        if selected["data"] != summaries["data"][0]:
            raise RuntimeError("Selected and paged result summaries disagree")
        observation_path = f"/api/v1/searches/{search_fixture['sessionId']}/results/{search_fixture['resultId']}/observations"
        observation_contract = "/searches/{searchId}/results/{resultId}/observations"
        first_observations = validated_read(observation_path + "?limit=1", observation_contract)
        if (first_observations["data"][0]["rawName"] != "Alpha.bin"
                or first_observations["data"][0]["observationCount"] != 1
                or first_observations["data"][0]["firstSeenAt"] != 20
                or first_observations["data"][0]["completeSources"] is not None):
            raise RuntimeError("Observation page mixed global occurrences or invented reported values")
        observation_cursor = first_observations["meta"]["nextCursor"]
        if not first_observations["meta"]["hasMore"] or not observation_cursor:
            raise RuntimeError("Observation first page omitted its bounded continuation")
        second_observations = validated_read(observation_path + "?limit=1&cursor=" + observation_cursor, observation_contract)
        if (second_observations["data"][0]["rawName"] != "Beta.bin"
                or second_observations["meta"]["hasMore"]
                or second_observations["meta"]["nextCursor"] is not None):
            raise RuntimeError("Observation continuation repeated or lost session provenance")
        report["searchObservations"] = {"status":"passed", "pages":2, "rows":2, "sessionLocalCounts":True}
        capture = smoke.http_request(base_url, "/api/v1/diagnostics/bundles", method="POST",
                                     api_key=package.API_KEY, json_body={"confirmCapture": True, "maxBytes": 4194304},
                                     request_timeout_seconds=min(5.0, remaining()))
        if capture["status"] != 200:
            raise RuntimeError(f"Diagnostic capture expected HTTP 200: {capture['status']}")
        bundle = capture["raw_json"]
        bundle_schema = response_json_schema(openapi_operation_response(document, "POST", "/diagnostics/bundles", 200),
                                             "diagnostic capture")
        validate_openapi_schema(document, bundle_schema, bundle)
        snapshot = next(item for item in bundle["operationalSnapshots"]["searches"]["items"]
                        if item["session"]["id"] == search_fixture["sessionId"])
        if snapshot["session"] != session_metadata["data"] or snapshot["results"]["items"] != summaries["data"]:
            raise RuntimeError("Diagnostic search snapshot disagrees with canonical metadata/results")
        report["searchDiagnosticCapture"] = {"status": "passed", "canonicalSummaries": True,
                                             "bundleSchema": bundle["schema"]}

        # WHY: allocation is owned by the bounded network scheduler. Start its
        # loopback-only runtime before asking this fixture to prove storage;
        # a fully disabled profile records intent without running that worker.
        request("POST", "/api/v1/servers/operations/connect")
        if categories():
            raise RuntimeError("Fresh profile exposed a synthetic category")

        first = request("POST", "/api/v1/categories", body={
            "name": "Alpha", "tempDir": str(temp_override),
            "destinationDir": str(destination), "comment": "First category",
        })
        require_category(first, name="Alpha",
                         temp_dir=str(temp_override), destination_dir=str(destination),
                         comment="First category")
        second = request("POST", "/api/v1/categories", body={"name": "Second-2", "comment": "Keep"})
        require_category(second, name="Second-2",
                         temp_dir=None, destination_dir=None, comment="Keep")
        require_category(request("GET", "/api/v1/categories/alpha"), name="Alpha",
                         temp_dir=str(temp_override), destination_dir=str(destination),
                         comment="First category")
        try:
            request("POST", "/api/v1/categories", body={"name": "ALPHA"})
        except urllib.error.HTTPError as error:
            payload = json.load(error)
            if error.code != 409 or payload.get("error", {}).get("code") != "CATEGORY_NAME_CONFLICT":
                raise RuntimeError(f"Category name collision returned {error.code}: {payload}") from error
        else:
            raise RuntimeError("ASCII case-insensitive duplicate category name was accepted")
        for invalid_name in (" Alpha", "Alpha Beta", "Alpha.Beta", "Alpha_Beta", "-Alpha", "é", "Alpha\n", "A" * 65):
            try:
                request("POST", "/api/v1/categories", body={"name": invalid_name})
            except urllib.error.HTTPError as error:
                if error.code != 400:
                    raise RuntimeError(f"Invalid category name returned HTTP {error.code}") from error
            else:
                raise RuntimeError(f"Invalid category name was accepted: {invalid_name!r}")

        patched = request("PATCH", "/api/v1/categories/ALPHA", body={"comment": "Edited"})
        require_category(patched, name="Alpha",
                         temp_dir=str(temp_override), destination_dir=str(destination),
                         comment="Edited")
        patched = request("PATCH", "/api/v1/categories/alpha", body={"tempDir": None})
        require_category(patched, name="Alpha",
                         temp_dir=None, destination_dir=str(destination), comment="Edited")
        patched = request("PATCH", "/api/v1/categories/Alpha", body={"tempDir": str(temp_override)})
        require_category(patched, name="Alpha",
                         temp_dir=str(temp_override), destination_dir=str(destination), comment="Edited")

        job_ids.append(add_download(hashes[0], "Alpha.bin", category="alpha"))
        job_ids.append(add_download(hashes[1], "Beta.bin", category="second-2"))
        job_ids.append(add_download(hashes[2], "Gamma.bin"))
        if len(set(job_ids)) != 3 or list(map(int, job_ids)) != sorted(map(int, job_ids)):
            raise RuntimeError("Distinct downloads did not receive ordered job IDs")
        if assignments() != ["Alpha", "Second-2", None]:
            raise RuntimeError("Download category assignment differs before deletion")
        filtered = download_page("/api/v1/downloads?view=all&category=ALPHA")
        if [row["id"] for row in filtered] != [job_ids[0]] or filtered[0]["hash"] != hashes[0]:
            raise RuntimeError("Case-insensitive category filter did not select the assigned job")
        all_rows = download_page("/api/v1/downloads?view=all&limit=3")
        if [row["id"] for row in all_rows] != list(reversed(job_ids)):
            raise RuntimeError("Thin download page did not retain descending job identity")
        counts = request("GET", "/api/v1/snapshot")["downloads"]
        if counts != {"unfinished": 3, "completed": 0}:
            raise RuntimeError(f"Download snapshot counts differ: {counts}")
        first_page = validated_read("/api/v1/downloads?view=all&limit=1", "/downloads")
        if ([row["id"] for row in first_page["data"]] != [job_ids[2]]
                or first_page["meta"]["hasMore"] is not True or not first_page["meta"]["nextCursor"]):
            raise RuntimeError("First bounded download page did not expose its continuation")
        query = urllib.parse.urlencode({"view": "all", "limit": 1,
                                        "cursor": first_page["meta"]["nextCursor"]})
        second_page = validated_read(f"/api/v1/downloads?{query}", "/downloads")
        if [row["id"] for row in second_page["data"]] != [job_ids[1]]:
            raise RuntimeError("Download cursor repeated or skipped the next job")
        validated_read(f"/api/v1/downloads/{job_ids[0]}", "/downloads/{id}")
        for resource in ("parts", "sources", "comments"):
            payload = validated_read(f"/api/v1/downloads/{job_ids[0]}/{resource}",
                                     f"/downloads/{{id}}/{resource}")
            expected = [{"index": 0, "start": 0, "end": 4095, "sizeBytes": 4096,
                         "presentBytes": 0, "complete": False, "corrupted": False}] if resource == "parts" else []
            if payload["data"] != expected:
                raise RuntimeError(f"Stopped unallocated download returned unexpected {resource}: {payload}")
        report["downloadReadContracts"] = {"detail": "passed", "cursor": "passed",
                                           "parts": "passed", "sources": "passed", "comments": "passed"}
        if download_action("start", job_ids[0]) != "accepted":
            raise RuntimeError("Stopped download was not started")
        def allocated_storage() -> tuple[Any, ...] | None:
            row = durable_jobs()[0]
            return row if row[5] is not None and row[6] is not None and row[7] is not None else None

        started_row = wait_until("download storage allocation", remaining(), allocated_storage)
        marker = started_row[6]
        storage_path = Path(started_row[5])
        if (str(uuid.UUID(marker)) != marker or started_row[4] != str(temp_override)
                or storage_path.parent.resolve() != temp_override.resolve()
                or storage_path.name != f"{job_ids[0]}-{marker}" or not storage_path.is_dir()):
            raise RuntimeError(f"Download did not persist its allocated UUID storage path: {started_row[:7]}")
        if download_action("stop", job_ids[0]) != "accepted":
            raise RuntimeError("Started download was not stopped")
        request("PATCH", f"/api/v1/downloads/{job_ids[2]}", body={"category": "ALPHA"})
        if assignments() != ["Alpha", "Second-2", "Alpha"]:
            raise RuntimeError("Download category patch did not return canonical saved spelling")
        request("PATCH", f"/api/v1/downloads/{job_ids[2]}", body={"category": None})
        if assignments() != ["Alpha", "Second-2", None]:
            raise RuntimeError("Null download category patch did not clear assignment")

        category_only = destination / "CategoryOnly.txt"
        category_only_bytes = b"category-only complete share\n"
        duplicate_name = "DuplicateCopy.txt"
        duplicate_bytes = b"same complete content in two eligible roots\n"
        category_copy = destination / duplicate_name
        independent_copy = independent_root / duplicate_name
        category_only.write_bytes(category_only_bytes)
        category_copy.write_bytes(duplicate_bytes)
        independent_copy.write_bytes(duplicate_bytes)
        request("POST", "/api/v1/library/scan")
        wait_until("category root reload", remaining(), reload_settled)

        def category_shares_ready() -> tuple[dict[str, Any], dict[str, Any]] | None:
            rows = shared_files()
            try:
                only = rust_local_ed2k.require_shared_file_item(rows, category_only.name)
                duplicate = rust_local_ed2k.require_shared_file_item(rows, duplicate_name)
            except RuntimeError:
                return None
            if all(row.get("complete") is True and row.get("partFile") is False
                   for row in (only, duplicate)):
                return only, duplicate
            return None

        only_row, duplicate_row = wait_until("category complete shares", remaining(), category_shares_ready)
        only_hash, duplicate_hash = only_row["hash"], duplicate_row["hash"]
        if only_hash == duplicate_hash or Path(duplicate_row["path"]).resolve() != category_copy.resolve():
            raise RuntimeError("Category root did not own the initial complete shares")
        library_request("POST", "/api/v1/library/tags", "/library/tags", 201, {"name": "Rotate"})
        library_request("GET", "/api/v1/library/tags/rotate", "/library/tags/{tagName}", 200)
        if library_request("GET", "/api/v1/library/tags", "/library/tags", 200) != [{"name": "Rotate"}]:
            raise RuntimeError("Created tag did not appear in the name collection")
        missing_hash = "ff" * 16
        tag_hashes = [only_hash, missing_hash, duplicate_hash]
        outcomes = library_request("POST", "/api/v1/library/files/tags/add", "/library/files/tags/add", 207,
                               {"tag": "rotate", "hashes": tag_hashes})
        if ([row["hash"] for row in outcomes] != tag_hashes
                or [row["status"] for row in outcomes] != ["accepted", "failed", "accepted"]
                or outcomes[1]["httpStatus"] != 404):
            raise RuntimeError(f"Ordered per-hash tag outcomes differ: {outcomes}")
        require_file_tags(only_hash, ["Rotate"])
        require_file_tags(duplicate_hash, ["Rotate"])
        library_request("POST", "/api/v1/library/roots", "/library/roots", 201,
                        {"path": str(independent_root), "watchEnabled": False})
        request("POST", "/api/v1/library/scan")
        wait_until("independent root reload", remaining(), reload_settled)
        if independent_copy.read_bytes() != duplicate_bytes:
            raise RuntimeError("Independent complete copy changed before category deletion")

        # Both physical copies are eligible here. Keep one connection and its
        # cached complete reader across REST rotation; a fresh request must fail.
        counts_before = upload_counts(duplicate_hash)
        timestamps_before = upload_timestamps(duplicate_hash)
        if timestamps_before != (None, None):
            raise RuntimeError("A never-uploaded fixture fabricated an upload timestamp")
        upload_started_at = int(time.time())
        peer = Ed2kFilePeerObserver(REST_ADDR, tcp_port, min(5.0, remaining()))
        with peer:
            if not peer.filename_available(duplicate_hash) or not peer.start_upload(duplicate_hash):
                raise RuntimeError("Enabled complete content was not admitted to the local peer")
            if peer.request_range(duplicate_hash, 0, 10) != duplicate_bytes[:10]:
                raise RuntimeError("Local peer received different verified bytes")
            if peer.request_range(duplicate_hash, 10, 20) != duplicate_bytes[10:20]:
                raise RuntimeError("Second request in one upload stint returned different bytes")
            if (counts := live_upload_counts(duplicate_hash)) != (counts_before[0] + 2, counts_before[1] + 1):
                raise RuntimeError("Multiple payload requests did not count as one accepted upload stint")
            sharing(False, [duplicate_hash], ["accepted"])
            if peer.request_range(duplicate_hash, 20, 30) is not None:
                raise RuntimeError("Disabled hash reused a complete reader on the established connection")
            if (counts := live_upload_counts(duplicate_hash)) != (counts_before[0] + 3, counts_before[1] + 1):
                raise RuntimeError("Refused demand changed the accepted-stint count")
            sharing(True, [duplicate_hash], ["accepted"])
            if not peer.start_upload(duplicate_hash) or peer.request_range(duplicate_hash, 30, 40) != duplicate_bytes[30:40]:
                raise RuntimeError("Re-enabled content did not resume the established peer")
            if (counts := live_upload_counts(duplicate_hash)) != (counts_before[0] + 4, counts_before[1] + 1):
                raise RuntimeError("Re-enable duplicated acceptance within the same upload stint")
            sharing_wire = list(peer.transcript)
        require_upload_checkpoint(duplicate_hash, (counts_before[0] + 4, counts_before[1] + 1))
        first_timestamps = upload_timestamps(duplicate_hash)
        if not all(value is not None and upload_started_at <= value <= int(time.time()) for value in first_timestamps):
            raise RuntimeError("Upload request/actual-upload timestamps are not Unix seconds")

        request("DELETE", "/api/v1/categories/ALPHA")
        if assignments() != [None, "Second-2", None]:
            raise RuntimeError("Category deletion did not clear only matching assignments")

        def category_share_withdrawal() -> dict[str, Any] | None:
            survivor = shared_file_or_none(duplicate_hash)
            if (shared_file_or_none(only_hash) is None and survivor is not None
                    and survivor.get("complete") is True and survivor.get("partFile") is False
                    and Path(survivor["path"]).resolve() == independent_copy.resolve()
                    and shared_files().get("total") == 1):
                return survivor
            return None

        wait_until("category share withdrawal and independent copy", remaining(), category_share_withdrawal)
        if (category_only.read_bytes(), category_copy.read_bytes(), independent_copy.read_bytes()) != (
            category_only_bytes, duplicate_bytes, duplicate_bytes
        ):
            raise RuntimeError("Category deletion changed complete-share files")
        require_file_tags(only_hash, ["Rotate"])
        require_file_tags(duplicate_hash, ["Rotate"])
        selected_sharing = [only_hash, missing_hash, duplicate_hash]
        sharing(False, selected_sharing, ["accepted", "failed", "accepted"])
        sharing(False, selected_sharing, ["unchanged", "failed", "unchanged"])
        if sharing_flags(selected_sharing) != [False, None, False]:
            raise RuntimeError("Sharing mutations changed unknown or durable hash policy unexpectedly")
        # A refused-only connection owns no upload session. Its demand must
        # reach SQLite through final drain even without a session-release flush.
        with Ed2kFilePeerObserver(REST_ADDR, tcp_port, min(5.0, remaining())) as refused_peer:
            if refused_peer.request_range(duplicate_hash, 0, 10) is not None:
                raise RuntimeError("Disabled content admitted refused-only shutdown fixture")
        if live_upload_counts(duplicate_hash) != (counts_before[0] + 5, counts_before[1] + 1):
            raise RuntimeError("Refused-only demand was absent from live accounting")
        request("POST", "/api/v1/app/shutdown", body={"confirmShutdown": True})
        process.wait(timeout=min(20.0, remaining()))
        if process.returncode != 0:
            raise RuntimeError("Category persistence daemon did not stop gracefully")
        handle.close()
        handle = None
        process, handle = package._start_daemon(executable, profile, root / "restart.log")
        wait_until("restarted category REST readiness", remaining(), ready)
        if upload_counts(duplicate_hash) != (counts_before[0] + 5, counts_before[1] + 1):
            raise RuntimeError("Clean shutdown did not persist refused-only demand")
        request("POST", "/api/v1/servers/operations/connect")
        request("POST", "/api/v1/library/scan")
        wait_until("restarted category root reload", remaining(), reload_settled)
        surviving = categories()
        if len(surviving) != 1:
            raise RuntimeError("Surviving category membership changed on profile reopen")
        require_category(surviving[0], name="Second-2",
                         temp_dir=None, destination_dir=None, comment="Keep")
        if assignments() != [None, "Second-2", None]:
            raise RuntimeError("Download assignments changed on profile reopen")
        rows = durable_jobs()
        if ([(str(row[0]), row[1], row[2]) for row in rows]
                != list(zip(job_ids, hashes, (None, "Second-2", None)))
                or rows[0][4:8] != started_row[4:8]):
            raise RuntimeError("Job identity, selective category clearing or storage changed on reopen")
        recreated = request("POST", "/api/v1/categories", body={"name": "ALPHA"})
        require_category(recreated, name="ALPHA", temp_dir=None, destination_dir=None, comment="")
        if assignments() != [None, "Second-2", None]:
            raise RuntimeError("Reusing a deleted name changed transfer assignments")
        if sharing_flags(selected_sharing) != [False, None, False]:
            raise RuntimeError("Sharing policy changed across profile reopen or hydration")
        unavailable_counts_before = upload_counts(only_hash)
        peer = Ed2kFilePeerObserver(REST_ADDR, tcp_port, min(5.0, remaining()))
        with peer:
            # This retained hash has no copy under a current root after reopen.
            # Demand must still checkpoint without fabricating serving authority.
            if peer.request_range(only_hash, 0, 10) is not None:
                raise RuntimeError("Unavailable content gained payload authority from demand")
            if peer.filename_available(duplicate_hash) or peer.request_range(duplicate_hash, 0, 10) is not None:
                raise RuntimeError("Restarted disabled hash accepted a new peer request")
            if upload_timestamps(duplicate_hash)[1] != first_timestamps[1]:
                raise RuntimeError("A refused post-restart request changed last actual upload time")
            sharing(True, [only_hash, duplicate_hash], ["accepted", "accepted"])
            if not peer.filename_available(duplicate_hash) or not peer.start_upload(duplicate_hash):
                raise RuntimeError("Re-enabled hash was not visible to the new peer")
            if peer.request_range(duplicate_hash, 0, 10) != duplicate_bytes[:10]:
                raise RuntimeError("Re-enabled restarted hash returned different bytes")
            sharing_wire.extend(peer.transcript)
        counts_after = require_upload_checkpoint(duplicate_hash, (counts_before[0] + 7, counts_before[1] + 2))
        require_upload_checkpoint(only_hash, (unavailable_counts_before[0] + 1, unavailable_counts_before[1]))
        final_timestamps = upload_timestamps(duplicate_hash)
        if not all(value is not None and first_timestamps[index] <= value <= int(time.time()) for index, value in enumerate(final_timestamps)):
            raise RuntimeError("Upload timestamps did not persist and advance across reopen")
        report["uploadTimestamps"] = {"before": list(timestamps_before), "firstCheckpoint": list(first_timestamps),
            "afterRestart": list(final_timestamps), "unixSeconds": True, "refusedRequestRetainsLastUpload": True}
        report["uploadAccounting"] = {"before": list(counts_before), "after": list(counts_after),
            "multiplePacketsOneAcceptedStint": True, "refusedDemandCounted": True,
            "reEnableKeepsSameStint": True, "newSessionAfterRestart": True}
        report["uploadAccounting"]["refusedOnlyDemandFlushedOnShutdown"] = True
        report["uploadAccounting"]["unavailableHashDemandCheckpointed"] = True
        report["librarySharing"] = {"orderedMixedOutcomes": True, "idempotentWrites": True,
            "hashPolicyAcrossCopies": True, "tagsAndFilesPreserved": True, "unknownHashNotCreated": True,
            "persistedAcrossReopen": True, "cachedReaderRefusedOnNewRequest": True,
            "restartHydrationRefusedNewRequest": True, "reEnabledRequestsSucceeded": True,
            "wireTranscript": sharing_wire}
        wait_until("restarted independent complete share", remaining(), category_share_withdrawal)
        if (category_only.read_bytes(), category_copy.read_bytes(), independent_copy.read_bytes()) != (
            category_only_bytes, duplicate_bytes, duplicate_bytes
        ):
            raise RuntimeError("Category restart changed complete-share files")
        require_file_tags(only_hash, ["Rotate"])
        require_file_tags(duplicate_hash, ["Rotate"])
        for expected in ("accepted", "unchanged"):
            removed = library_request("POST", "/api/v1/library/files/tags/remove", "/library/files/tags/remove", 207,
                                  {"tag": "ROTATE", "hashes": [only_hash]})
            if removed[0]["status"] != expected:
                raise RuntimeError(f"Tag removal idempotence differs: {removed}")
        require_file_tags(only_hash, [])
        library_request("DELETE", "/api/v1/library/tags/rotate", "/library/tags/{tagName}", 204)
        require_file_tags(duplicate_hash, [])
        library_request("POST", "/api/v1/library/tags", "/library/tags", 201, {"name": "ROTATE"})
        require_file_tags(duplicate_hash, [])
        report["libraryTags"] = {"orderedMixedOutcomes": True, "unavailableContentRetained": True,
                                 "persistedAcrossReopen": True, "idempotentRemoval": True,
                                 "deletionClearedAssignments": True, "recreatedNameHasNoAssignments": True}
        report["categoryNames"] = {"deleted": "Alpha", "survivor": "Second-2", "recreated": "ALPHA"}
        report["assignmentsAfterReopen"] = [None, "Second-2", None]
        report["downloadIds"] = job_ids
        report["storage"] = {"jobId": job_ids[0], "path": str(storage_path), "markerId": marker,
                             "persistedAcrossReopen": True}
        report["sharing"] = {"withdrawnHash": only_hash, "survivingHash": duplicate_hash,
                             "categoryOnlyWithdrawn": True, "independentCompleteCopyRetained": True,
                             "fixtureBytesUnchanged": True}
        report["status"] = "passed"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
        if "peer" in locals():
            report["sharingWireFailure"] = list(peer.transcript)
        try:
            fields = ("id", "hash", "category", "intent", "temp", "storage", "marker")
            report["durableJobs"] = [{**dict(zip(fields, row[:7])), "storageIdentityCaptured": row[7] is not None}
                                     for row in durable_jobs()]
        except Exception as evidence_error:
            report["durableJobsError"] = f"{type(evidence_error).__name__}: {evidence_error}"
    finally:
        try:
            if process is not None and process.poll() is None:
                http_json(base_url, "/api/v1/app/shutdown", api_key=package.API_KEY, method="POST",
                          body={"confirmShutdown": True}, timeout_seconds=5.0)
                process.wait(timeout=20.0)
            if process is not None and process.poll() != 0:
                raise RuntimeError("Category persistence daemon did not stop gracefully")
            report["teardown"] = "graceful"
        except Exception as error:
            report["status"] = "failed"
            report["teardown"] = f"forced: {error}"
            if process is not None:
                rust_client.stop_process_tree(process)
        finally:
            if handle is not None:
                handle.close()
        write_report(root / "report.json", report)
    if report["status"] != "passed":
        raise RuntimeError(f"Category persistence proof failed; evidence: {root / 'report.json'}")
    return report


def friend_database_rows(database: Path) -> list[tuple]:
    """Reopen the disposable database read-only for independent durable evidence."""
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
        return connection.execute(
            "SELECT lower(hex(user_hash)), name, last_address, last_port, first_seen_at_ms, "
            "last_seen_at_ms, deleted_at_ms, id FROM friends ORDER BY user_hash"
        ).fetchall()


def friend_write_fault(database: Path, *, enabled: bool) -> None:
    """Install/remove deterministic SQLite statement failures in an owned fixture."""
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=rw", uri=True)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            for operation, name in zip(("INSERT", "UPDATE", "DELETE"), FRIEND_FAULT_TRIGGERS, strict=True):
                if enabled:
                    # WHY: persistent triggers are visible to daemon connections;
                    # TEMP triggers on this separate fixture connection are not.
                    connection.execute(f"CREATE TRIGGER {name} BEFORE {operation} ON friends "
                                       "BEGIN SELECT RAISE(ABORT, 'harness friend write failure'); END")
                else:
                    connection.execute(f"DROP TRIGGER IF EXISTS {name}")


def prove_friend_frontdoor(*, request, database: Path, prefix: str, route_template: str,
                           ready, user_hash: str, document: dict) -> dict[str, object]:
    """Exercise actual peer friend controls through failure, consistency and retry."""
    result: dict[str, object] = {"route": route_template, "failures": []}
    for operation in ("add-friend", "remove-friend"):
        ready()
        cache_before = request("GET", "/api/v1/friends")["json"]["data"]
        durable_before = friend_database_rows(database)
        try:
            friend_write_fault(database, enabled=True)
            response = request("POST", f"{prefix}/operations/{operation}", expected=500)
            payload = response["json"]
            if payload.get("error", {}).get("code") != "PERSISTENCE_FAILED":
                raise RuntimeError(f"Friend persistence failure returned the wrong code: {response}")
            schema = response_json_schema(openapi_operation_response(
                document, "POST", f"{route_template}/operations/{operation}", 500), operation)
            validate_openapi_schema(document, schema, payload)
            if request("GET", "/api/v1/friends")["json"]["data"] != cache_before:
                raise RuntimeError("Failed friend mutation changed the HTTP friend cache")
            if friend_database_rows(database) != durable_before:
                raise RuntimeError("Failed friend mutation changed reopened durable friend state")
            result["failures"].append({"operation": operation, "status": 500, "code": "PERSISTENCE_FAILED",
                                       "cacheUnchanged": True, "reopenedDatabaseUnchanged": True})
        finally:
            friend_write_fault(database, enabled=False)
        ready()
        response = request("POST", f"{prefix}/operations/{operation}")
        schema = response_json_schema(openapi_operation_response(
            document, "POST", f"{route_template}/operations/{operation}", 200), operation)
        validate_openapi_schema(document, schema, response["json"])
        # Successful retry must change both authorities, not merely return 200.
        if request("GET", "/api/v1/friends")["json"]["data"] == cache_before:
            raise RuntimeError("Successful friend retry did not publish the HTTP cache")
        if friend_database_rows(database) == durable_before:
            raise RuntimeError("Successful friend retry did not change durable state")
        cache_after = request("GET", "/api/v1/friends")["json"]["data"]
        visible = any(row["userHash"].lower() == user_hash.lower() for row in cache_after["items"])
        durable = any(row[0] == user_hash.lower() and row[6] is None for row in friend_database_rows(database))
        if visible != (operation == "add-friend") or durable != visible:
            raise RuntimeError("Successful friend retry disagreed with current cache/durable membership")
    result["retryAddAndRemove"] = "passed"
    return result


def run_friend_peer_phase(*, executable: Path, rust_repo: Path, root: Path,
                          openapi_contract: Path) -> dict[str, object]:
    """Prove six populated peer-control frontdoors using local-only disposable peers."""
    package = load_script_module("package_helpers_for_friend_contract", "smoke-rust-release-package.py")
    from emule_test_harness import rust_local_ed2k

    smoke = rust_rest_conformance.load_rest_smoke_module(openapi_contract)
    document = load_openapi_document(openapi_contract)
    deadline = time.monotonic() + FRIEND_PEER_BUDGET_SECONDS
    report: dict[str, Any] = {"status": "failed", "networkMode": "loopback-direct-local-only",
                              "budgetSeconds": FRIEND_PEER_BUDGET_SECONDS, "frontdoors": [], "teardown": []}
    peers: list[dict[str, Any]] = []
    root.mkdir(parents=True, exist_ok=False)
    ports: set[int] = set()

    def remaining() -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise RuntimeError("Local friend-peer phase exceeded its runtime budget")
        return value

    def request(peer, method, path, *, expected=200, body=None):
        result = smoke.http_request(peer["base"], path, method=method, api_key=package.API_KEY,
                                    json_body=body, request_timeout_seconds=min(5.0, remaining()))
        if result["status"] != expected:
            raise RuntimeError(f"Local friend-peer {method} {path} expected {expected}: {result}")
        return {"status": result["status"], "json": result["raw_json"]}

    def data(peer, method, path, body=None):
        value = request(peer, method, path, body=body)["json"]
        return value["data"]

    def poll(label, callback):
        return wait_until(label, remaining(), callback)

    try:
        unused_server_port = package._available_unique_port(ports)
        for role in ("seeder", "leecher-one", "leecher-two"):
            profile = root / role
            peer = {"profile": profile, "database": profile / rust_metadata.RUST_PROFILE_METADATA_FILE,
                    "rest": package._available_unique_port(ports), "tcp": package._available_unique_port(ports),
                    "udp": package._available_unique_port(ports, socket_type=socket.SOCK_DGRAM)}
            peer["base"] = f"http://127.0.0.1:{peer['rest']}"
            package._write_profile(profile, rust_repo=rust_repo, incoming=profile / "incoming", rest_port=peer["rest"],
                                   ed2k_port=peer["tcp"], kad_port=peer["udp"], runtime_server_port=unused_server_port,
                                   p2p_ip=REST_ADDR)
            peer["userHash"] = hashlib.sha256(f"local-friend-contract-{role}".encode("ascii")).digest()[:16]
            rust_metadata.seed_local_user_hash(peer["database"], peer["userHash"])
            if role == "seeder":
                # Start above JSON's exact-integer range before any session exists.
                # The HTTP contract must preserve these IDs as decimal strings.
                with closing(sqlite3.connect(peer["database"])) as connection:
                    connection.execute("INSERT INTO sqlite_sequence(name,seq) VALUES('search_sessions',?)",
                                       (9_007_199_254_740_992,))
                    connection.commit()
                rust_metadata.seed_indexed_file(peer["database"], ed2k_hash="99" * 16,
                    name="Synthetic.Identity.Proof.bin", size_bytes=4096, origin="passive_cache")
                rust_metadata.edit_app_settings(rust_repo, peer["database"], {
                    "network.autoConnect": False, "network.kadEnabled": False,
                    "transfers.uploadLimitBytesPerSecond": 8192,
                    "transfers.upload.baseSlots": 1, "transfers.upload.elasticPercent": 0,
                })
            peers.append(peer)
            peer["process"], peer["log"] = package._start_daemon(executable, profile, root / f"{role}.log")

            def ready(peer=peer):
                if peer["process"].poll() is not None:
                    raise RuntimeError("Local friend peer exited before readiness")
                return request(peer, "GET", "/api/v1/status")

            poll(f"{role} REST readiness", ready)
            request(peer, "POST", "/api/v1/servers/operations/connect")
        seeder = peers[0]
        first_search = request(seeder, "POST", "/api/v1/searches",
                               body={"query": "Synthetic identity proof", "method": "server"}, expected=201)
        search_id = first_search["json"]["data"]["id"]
        if search_id != "9007199254740993":
            raise RuntimeError("Search identity was not an exact SQLite-allocated decimal string")
        schema = response_json_schema(openapi_operation_response(document, "POST", "/searches", 201), "search create")
        validate_openapi_schema(document, schema, first_search["json"])
        live_search = data(seeder, "GET", f"/api/v1/searches/{search_id}")
        if live_search["id"] != search_id:
            raise RuntimeError("Full-width search identity did not roundtrip through its resource path")
        live_results = request(seeder, "GET", f"/api/v1/searches/{search_id}/results")["json"]
        if live_search["resultCount"] != 0 or live_results["data"] != []:
            raise RuntimeError("Live search included results without a network observation")
        result_schema = response_json_schema(openapi_operation_response(document, "GET", "/searches/{searchId}/results", 200), "search results")
        validate_openapi_schema(document, result_schema, live_results)
        with closing(sqlite3.connect(seeder["database"].resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            if connection.execute("SELECT count(*) FROM known_files WHERE ed2k_hash=?", (bytes.fromhex("99" * 16),)).fetchone()[0] != 1:
                raise RuntimeError("Live-search proof lost its matching indexed fixture")
            if connection.execute("SELECT count(*) FROM content_claims").fetchone()[0] != 0:
                raise RuntimeError("Live-search lookup fabricated a permanent network claim")
        stopped = request(seeder, "POST", f"/api/v1/searches/{search_id}/stop", expected=204)
        if stopped["json"] is not None:
            raise RuntimeError("Search stop returned a body")
        request(seeder, "POST", f"/api/v1/searches/{search_id}/stop", expected=204)
        stopped_session = data(seeder, "GET", f"/api/v1/searches/{search_id}")
        if stopped_session["status"] != "stopped" or stopped_session["resultCount"] != 0:
            raise RuntimeError("Search stop failed to preserve frozen session metadata")
        second_search_response = request(seeder, "POST", "/api/v1/searches",
            body={"parentSearchId":search_id,"query":"Edited synthetic criteria","method":"server"},expected=201)["json"]
        validate_openapi_schema(document, schema, second_search_response)
        second_search=second_search_response["data"]
        if (second_search["id"] != "9007199254740994" or second_search["parentSearchId"] != search_id
                or second_search["query"] != "Edited synthetic criteria" or second_search["resultCount"] != 0):
            raise RuntimeError("Linked creation lost exact identity, supplied criteria or independent membership")
        request(seeder, "DELETE", f"/api/v1/searches/{search_id}")
        request(seeder, "GET", f"/api/v1/searches/{search_id}", expected=404)
        child_response=request(seeder,"GET",f"/api/v1/searches/{second_search['id']}")["json"]
        child_schema=response_json_schema(openapi_operation_response(document,"GET","/searches/{searchId}",200),"linked session metadata")
        validate_openapi_schema(document,child_schema,child_response)
        if child_response["data"]["parentSearchId"] is not None or child_response["data"]["query"] != "Edited synthetic criteria":
            raise RuntimeError("Parent deletion failed to preserve and unlink its child")
        request(seeder,"POST","/api/v1/searches",expected=404,
                body={"parentSearchId":search_id,"query":"Missing parent proof","method":"server"})
        request(seeder,"POST",f"/api/v1/searches/{second_search['id']}/stop",expected=204)
        request(seeder, "DELETE", f"/api/v1/searches/{second_search['id']}")
        third_search=request(seeder,"POST","/api/v1/searches",expected=201,
                             body={"query":"Identity nonreuse proof","method":"server"})["json"]["data"]
        if third_search["id"] != "9007199254740995":
            raise RuntimeError("Deletion reused an ID or missing-parent creation consumed an ID")
        request(seeder,"DELETE",f"/api/v1/searches/{third_search['id']}")
        report["searchIdentityPhase"] = {"status": "passed", "stringIds": True,
                                         "beyondJavaScriptSafeInteger": True, "deletedIdNotReused": True,
                                         "networkResultsOnly": True, "indexLookupCreatesNoClaim": True, "stopPreservedSession": True, "linkedCriteria": True, "parentDeletionPreservedChild": True, "missingParentNotAllocated": True}
        transfers = data(seeder, "GET", "/api/v1/settings")["effective"]["transfers"]
        upload = transfers["upload"]
        if (upload["baseSlots"], upload["elasticPercent"], transfers["uploadLimitBytesPerSecond"]) != (1, 0, 8192):
            raise RuntimeError("Local seeder did not admit the required single-slot upload policy")
        report["seederPolicy"] = {"baseSlots": upload["baseSlots"], "elasticPercent": upload["elasticPercent"],
                                  "uploadLimitBytesPerSecond": transfers["uploadLimitBytesPerSecond"]}
        payload = package._write_transfer_payload(root / "shared" / "Synthetic.Friend.Control.bin")
        shared = rust_local_ed2k.publish_shared_tree(
            seeder["base"], package.API_KEY, root=Path(payload["path"]).parent,
            file_name=payload["name"], timeout_seconds=min(60.0, remaining()))
        content = shared["sharedFiles"]["matched"]
        file_hash = content["hash"]
        link = rust_local_ed2k.ed2k_link_with_source(content["ed2kLink"], REST_ADDR, seeder["tcp"])
        for peer in peers[1:]:
            admitted = request(peer, "POST", "/api/v1/downloads", expected=201, body={
                "source": {"type": "ed2k-link", "link": link}, "intent": "started",
            })["json"]["data"]
            peer["downloadId"] = require_download_id(admitted, hash_value=file_hash)

        def populated():
            active = data(seeder, "GET", "/api/v1/uploads")["items"]
            queued = data(seeder, "GET", "/api/v1/upload-queue")["items"]
            def valid(row):
                return row.get("id") and row.get("userHash") and row.get("requestedFileHash") == file_hash
            active = next((row for row in active if valid(row) and row.get("uploading")), None)
            queued = next((row for row in queued if valid(row) and row.get("waitingQueue")), None)
            if active and queued:
                if active["userHash"] == queued["userHash"]:
                    raise RuntimeError("Local upload peers must have distinct user identities")
                return active, queued
            return None

        active, queued = poll("one active and one waiting local upload", populated)
        report["readiness"] = {"active": active["id"], "queued": queued["id"], "fileHash": file_hash}
        for collection, row in (("uploads", active), ("upload-queue", queued)):
            prefix = f"/api/v1/{collection}/{row['id']}"
            def ready(prefix=prefix, row=row):
                observed = data(seeder, "GET", prefix)
                if observed.get("userHash") != row["userHash"]:
                    raise RuntimeError("Local upload identity changed during friend control proof")
            report["frontdoors"].append(prove_friend_frontdoor(
                request=lambda method, path, **kwargs: request(seeder, method, path, **kwargs),
                database=seeder["database"], prefix=prefix,
                route_template=f"/{collection}/{{id}}", ready=ready,
                user_hash=row["userHash"], document=document))
        leecher = peers[1]
        source_path = f"/api/v1/downloads/{leecher['downloadId']}/sources"
        source = poll("real local transfer source identity", lambda: next((row for row in data(
            leecher, "GET", source_path) if row.get("clientId") and row.get("userHash")), None))
        source_prefix = f"{source_path}/{source['clientId']}"
        def source_ready():
            observed = data(leecher, "GET", source_prefix)
            if observed.get("userHash") != source["userHash"]:
                raise RuntimeError("Local transfer-source identity changed during proof")
        report["frontdoors"].append(prove_friend_frontdoor(
            request=lambda method, path, **kwargs: request(leecher, method, path, **kwargs),
            database=leecher["database"], prefix=source_prefix,
            route_template="/downloads/{id}/sources/{clientId}", ready=source_ready,
            user_hash=source["userHash"], document=document))
        report["requiredRoutes"] = 6
        report["provenRoutes"] = sum(len(frontdoor["failures"]) for frontdoor in report["frontdoors"])
        if report["provenRoutes"] != report["requiredRoutes"]:
            raise RuntimeError("Local friend frontdoor evidence is incomplete")
        report["status"] = "passed"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        for peer in reversed(peers):
            process = peer.get("process")
            try:
                friend_write_fault(peer["database"], enabled=False)
            except Exception as error:
                report["status"] = "failed"
                report["teardown"].append(str(error))
            finally:
                try:
                    package._shutdown_or_stop(peer["base"], process)
                    if process is not None and process.poll() != 0:
                        raise RuntimeError("Local friend peer did not stop gracefully")
                except Exception as error:
                    report["status"] = "failed"
                    report["teardown"].append(str(error))
                finally:
                    if peer.get("log"):
                        peer["log"].close()
            if peer["database"].is_file():
                try:
                    rows = friend_database_rows(peer["database"])
                    with closing(sqlite3.connect(peer["database"].resolve().as_uri() + "?mode=ro", uri=True)) as connection:
                        integrity = connection.execute("PRAGMA quick_check").fetchone()
                        triggers = connection.execute(
                            "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'harness_friend_failure_%'"
                        ).fetchall()
                    if integrity != ("ok",) or triggers or (process is not None and process.poll() is None):
                        raise RuntimeError("Local friend fixture teardown or database integrity was incomplete")
                    report.setdefault("finalDatabases", []).append({"profile": peer["profile"].name,
                        "friendRows": rows, "reopenedAfterShutdown": True, "integrity": "ok", "faultTriggersRemoved": True})
                except Exception as error:
                    report["status"] = "failed"
                    report["teardown"].append(str(error))
        write_report(root / "report.json", report)
    if report["status"] != "passed":
        raise RuntimeError(f"Local friend-peer proof failed; evidence: {root / 'report.json'}")
    return report


def run_settings_cli_phase(executable: Path, profile: Path) -> dict[str, object]:
    """Use the packaged offline command and inspect only its canonical row."""
    def command(*args: str, succeeds: bool = True, selected_profile: bool = True) -> str:
        argv = [str(executable)]
        if selected_profile:
            argv.extend(["--profile", str(profile)])
        argv.extend(["settings", *args])
        result = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", timeout=20)
        if (result.returncode == 0) != succeeds:
            raise RuntimeError(f"Offline settings command outcome differs: {result.stderr}")
        if succeeds:
            return result.stdout.rstrip("\r\n")
        return result.stderr

    def snapshot() -> tuple[int, str]:
        database = profile / rust_metadata.RUST_PROFILE_METADATA_FILE
        with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            row = connection.execute("SELECT revision,document_json FROM app_settings WHERE id=1").fetchone()
        if row is None:
            raise RuntimeError("Offline command did not initialize the typed settings row")
        return int(row[0]), str(row[1])

    if "--profile is required" not in command("get", "network.ed2kEnabled", succeeds=False, selected_profile=False):
        raise RuntimeError("Offline settings did not require an explicit profile")
    if command("get", "network.ed2kEnabled") != "true" or snapshot()[0] != 1:
        raise RuntimeError("Fresh offline settings did not resolve the compiled default at revision 1")
    if command("set", "network.nickname", "Sample") != "":
        raise RuntimeError("Successful settings set emitted unexpected stdout")
    if command("get", "network.nickname") != "Sample":
        raise RuntimeError("Settings get did not emit the single plain-text value")
    if command("set", "network.nickname", "Sample") != "" or snapshot()[0] != 3:
        raise RuntimeError("Explicit unchanged settings set did not advance its revision")
    backends = '["upnp","pcp-natpmp"]'
    if command("set", "network.nat.backendOrder", backends) != "" or command("get", "network.nat.backendOrder") != backends:
        raise RuntimeError("Offline list values did not use one inline JSON argument")
    if command("reset", "network.nickname") != "" or command("get", "network.nickname") != "eMule":
        raise RuntimeError("Offline reset did not select the compiled default")
    before = snapshot()
    if before[0] != 5:
        raise RuntimeError("Offline command revisions include unexpected read-time writes")
    if "network.ed2kEnabled" not in command("set", "network.ed2kEnabled", "invalid", succeeds=False):
        raise RuntimeError("Offline syntax failure did not identify the canonical setting")
    if "network.hostnameLookup.dnsServers" not in command("set", "network.hostnameLookup.enabled", "true", succeeds=False):
        raise RuntimeError("Offline validation did not report its canonical dependent field")
    if snapshot() != before:
        raise RuntimeError("Invalid offline settings changed the document or revision")
    saved = json.loads(before[1])
    if saved["network"]["nickname"]["mode"] != "default" or saved["network"]["nat"]["backendOrder"]["mode"] != "custom":
        raise RuntimeError("Offline edits lost saved default/custom modes")
    # A typed stored combination can become invalid after resolving defaults.
    # Reads must not repair it, while an explicit reset may restore validity.
    saved["network"]["hostnameLookup"]["enabled"] = {"mode": "custom", "value": True}
    saved["network"]["hostnameLookup"]["dnsServers"] = {"mode": "default", "value": ["192.0.2.1:53"]}
    with closing(sqlite3.connect(profile / rust_metadata.RUST_PROFILE_METADATA_FILE)) as connection:
        with connection:
            connection.execute("UPDATE app_settings SET document_json=? WHERE id=1", (json.dumps(saved),))
    unresolved = snapshot()
    command("get", "network.hostnameLookup.enabled", succeeds=False)
    if snapshot() != unresolved:
        raise RuntimeError("Offline read repaired invalid resolved settings")
    if command("reset", "network.hostnameLookup.enabled") != "" or command("get", "network.hostnameLookup.enabled") != "false" or snapshot()[0] != 6:
        raise RuntimeError("An explicit offline reset could not restore valid settings")
    return {"status": "passed", "revision": snapshot()[0], "plainSingleKeyOutput": True,
            "inlineJsonLists": True, "invalidWritesPreserved": True, "explicitProfileRequired": True,
            "canonicalFieldDiagnostics": True, "explicitDefaultResolutionRecovery": True}


def run_retained_download_scale_phase(*, executable: Path, rust_repo: Path, root: Path,
                                      openapi_contract: Path) -> dict[str, object]:
    """Browse 100k retained jobs and reopen them through the packaged daemon.

    Reuse the existing profile, launch, shutdown and schema helpers. This is
    metadata-scale evidence, not the combined physical-library/container gate.
    """
    root.mkdir(parents=True, exist_ok=False)
    profile = root / "profile"
    port = choose_loopback_port()
    base_url = f"http://{REST_ADDR}:{port}"
    package = load_script_module("package_helpers_for_retained_scale", "smoke-rust-release-package.py")
    api_key = package.API_KEY
    process = handle = None
    report: dict[str, Any] = {"status": "failed", "fixture": "metadata-only",
                              "physicalLibraryQualified": False, "memoryLimitQualified": False}
    try:
        rust_client.write_rust_profile(
            profile,
            rust_repo=rust_repo,
            rest_addr=REST_ADDR,
            rest_port=port,
            api_key=api_key,
            local_only_discovery=True,
            settings={
                'storage.incomingDirectory': str(profile / 'incoming'),
                'network.nat.enabled': False,
                'sharing.scanOnStartup': False,
                'security.vpnGuard.mode': 'off',
            },
        )
        database = profile / rust_metadata.RUST_PROFILE_METADATA_FILE
        rust_metadata.edit_app_settings(rust_repo, database, {
            "network.autoConnect": False, "network.servers.autoReconnect": False,
            "network.ed2kEnabled": False, "network.kadEnabled": False,
        })
        fixture = rust_metadata.seed_retained_download_scale(database)
        report["fixtureCounts"] = fixture
        document = load_openapi_document(openapi_contract)
        schema = response_json_schema(openapi_operation_response(document, "GET", "/downloads", 200), "/downloads")
        process, handle = package._start_daemon(executable, profile, root / "daemon.log")

        def ready():
            if process.poll() is not None:
                raise RuntimeError(f"Retained-scale daemon exited: {process.returncode}")
            try:
                return http_json(base_url, "/api/v1/status", api_key=api_key, timeout_seconds=2.0)
            except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError):
                return None

        wait_until("retained-scale REST readiness", 120.0, ready)
        report["listener"] = verify_listener_receipt(profile, base_url)
        expected_counts = {"activeDownloads": fixture["queued"],
                           "downloadCount": fixture["jobs"]}
        stats = ready()["data"]["stats"]
        report["dashboardCounts"] = {key: stats[key] for key in expected_counts}
        if {key: stats[key] for key in expected_counts} != expected_counts:
            raise RuntimeError("Retained-scale dashboard counts differ from the seeded jobs")
        report["views"] = rust_rest_conformance.prove_retained_download_pages(
            lambda path: http_json(base_url, "/api/v1" + path, api_key=api_key, timeout_seconds=30.0),
            fixture, validate_first_page=lambda payload: validate_openapi_schema(document, schema, payload),
        )
        package._graceful_shutdown(base_url, process)
        handle.close()
        handle = None
        if (profile / LISTENER_RECEIPT_FILE).exists():
            raise RuntimeError("Retained-scale listener receipt survived shutdown")
        process, handle = package._start_daemon(executable, profile, root / "restart.log")
        wait_until("reopened retained-scale REST readiness", 120.0, ready)
        stats = ready()["data"]["stats"]
        if {key: stats[key] for key in expected_counts} != expected_counts:
            raise RuntimeError("Retained job counts changed across clean restart")
        report["restartCountsPreserved"] = True
        report["status"] = "passed"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        try:
            if process is not None and process.poll() is None:
                package._graceful_shutdown(base_url, process)
            if process is not None and process.returncode != 0:
                raise RuntimeError(f"Retained-scale daemon exited {process.returncode}")
            report["teardown"] = "graceful" if process is not None else "not-started"
        except Exception as error:
            report.update(status="failed", teardown=f"forced: {error}")
            if process is not None:
                rust_client.stop_process_tree(process)
        finally:
            if handle is not None:
                handle.close()
        write_report(root / "report.json", report)
    if report["status"] != "passed":
        raise RuntimeError(f"Retained download scale proof failed; evidence: {root / 'report.json'}")
    return report


def staged_executable(output_root: Path) -> Path:
    """Returns the orchestrator-staged regular daemon for this host OS."""

    return rust_client.staged_executable(output_root)


def choose_loopback_port() -> int:
    """Reserves an ephemeral loopback port long enough to select its number."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((REST_ADDR, 0))
        return int(listener.getsockname()[1])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_revision(rust_repo: Path) -> str:
    """Returns the CI revision, falling back to the checked-out Rust HEAD."""

    ci_revision = os.environ.get("GITHUB_SHA", "").strip()
    if ci_revision:
        return ci_revision
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=rust_repo,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def run_campaign(*, ready_timeout_seconds: float = 60.0, rust_repo: Path | None = None,
                 openapi_contract: Path | None = None,
                 registered_stage: bool = False) -> tuple[dict[str, Any], Path]:
    workspace_root = get_required_emule_workspace_root()
    output_root = get_workspace_output_root()
    rust_repo = (rust_repo or workspace_root / "repos" / "emulebb-rust").resolve()
    if openapi_contract is not None:
        openapi_contract = openapi_contract.resolve()
        if not openapi_contract.is_file():
            raise RuntimeError("Selected OpenAPI contract must be an existing file")
    for selected in (rust_repo, openapi_contract):
        if selected is not None and not any(selected.resolve().is_relative_to(workspace_root / boundary)
                                             for boundary in ("repos", "workspaces")):
            raise RuntimeError("Selected REST sources must remain inside workspace source boundaries")
    identity = rust_client.verified_runtime_stage(rust_repo, output_root) if registered_stage else None
    executable = Path(identity["executable"]) if identity else staged_executable(output_root)
    if not rust_repo.is_dir():
        raise RuntimeError(f"emulebb-rust source is missing: {rust_repo}")
    if not executable.is_file():
        raise RuntimeError(f"staged emulebb-rust daemon is missing: {executable}")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_root = output_root / "reports" / "rust-rest-openapi-ci" / run_id
    profile_dir = output_root / "profiles" / "rust-rest-openapi-ci" / run_id
    contract_shared_root = profile_dir / "contract-shared-root"
    report_path = run_root / "report.json"
    daemon_log = run_root / "daemon.log"
    port = choose_loopback_port()
    base_url = f"http://{REST_ADDR}:{port}"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo,
        rest_addr=REST_ADDR,
        rest_port=port,
        api_key=API_KEY,
        local_only_discovery=True,
        settings={
            'storage.incomingDirectory': str(profile_dir / 'incoming'),
            'network.nat.enabled': False,
            'sharing.scanOnStartup': False,
            'security.vpnGuard.mode': 'off',
        },
    )
    metadata_path = profile_dir / rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_metadata.edit_app_settings(rust_repo, metadata_path, {
        "network.autoConnect": False, "network.servers.autoReconnect": False,
        "network.ed2kEnabled": False, "network.kadEnabled": False,
    })

    report: dict[str, Any] = {
        "schema": "emulebb.rust-rest-openapi-ci.v1",
        "runId": run_id,
        "status": "failed",
        "networkMode": "local-disabled",
        "restLoopback": True,
        "sourceRevision": source_revision(rust_repo),
        "sourcePath": str(rust_repo),
        "openapiContract": str(openapi_contract or rust_rest_conformance.RUST_OPENAPI_CONTRACT_PATH),
        "executableSha256": sha256_file(executable),
    }
    if identity:
        report["sourceRevision"] = identity["source"]["revision"]
        report["runtimeStageReceipt"] = identity["receipt"]
        report["runtimeStageTarget"] = identity["target"]
        report["workstream"] = identity["workstream"]
    run_root.mkdir(parents=True, exist_ok=True)
    handle = daemon_log.open("w", encoding="utf-8", newline="\n")
    process = None
    try:
        report["settingsCliPhase"] = run_settings_cli_phase(executable, profile_dir / "settings-cli-proof")
        process = rust_client.spawn_rust_daemon(executable, profile_dir, output_handle=handle)

        def rest_ready() -> object | None:
            if process is not None and process.poll() is not None:
                raise RuntimeError(f"Rust daemon exited before REST readiness (code {process.returncode}).")
            try:
                return http_json(base_url, "/api/v1/status", api_key=API_KEY, timeout_seconds=2.0)
            except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError):
                return None

        wait_until("Rust REST ready", ready_timeout_seconds, rest_ready)
        report["listenerReceiptPhase"] = verify_listener_receipt(profile_dir, base_url)
        refused = subprocess.run(
            [str(executable), "--profile", str(profile_dir), "settings", "get", "network.ed2kEnabled"],
            capture_output=True, text=True, encoding="utf-8", timeout=20,
        )
        if refused.returncode == 0 or "profile is already in use" not in refused.stderr:
            raise RuntimeError("Offline settings command bypassed the running daemon's profile lease")
        report["settingsCliPhase"]["runningProfileRefused"] = True
        previous_contract_shared_root = os.environ.get("EMULEBB_REST_CONTRACT_SHARED_ROOT")
        os.environ["EMULEBB_REST_CONTRACT_SHARED_ROOT"] = str(contract_shared_root)
        try:
            report["conformance"] = rust_rest_conformance.run_response_conformance(
                base_url,
                API_KEY,
                budget="contract",
                **({"openapi_path": openapi_contract} if openapi_contract else {}),
            )
        finally:
            if previous_contract_shared_root is None:
                os.environ.pop("EMULEBB_REST_CONTRACT_SHARED_ROOT", None)
            else:
                os.environ["EMULEBB_REST_CONTRACT_SHARED_ROOT"] = previous_contract_shared_root
        report["friendPeerPhase"] = run_friend_peer_phase(
            executable=executable, rust_repo=rust_repo, root=profile_dir / "friend-peer-phase",
            openapi_contract=openapi_contract or rust_rest_conformance.RUST_OPENAPI_CONTRACT_PATH,
        )
        report["kadPersistencePhase"] = run_kad_persistence_phase(
            executable=executable, rust_repo=rust_repo, root=profile_dir / "kad-persistence-phase",
            openapi_contract=openapi_contract or rust_rest_conformance.RUST_OPENAPI_CONTRACT_PATH,
        )
        report["categoryPersistencePhase"] = run_category_persistence_phase(
            executable=executable, rust_repo=rust_repo, root=profile_dir / "category-persistence-phase",
            openapi_contract=openapi_contract or rust_rest_conformance.RUST_OPENAPI_CONTRACT_PATH,
        )
        report["retainedDownloadScalePhase"] = run_retained_download_scale_phase(
            executable=executable, rust_repo=rust_repo, root=profile_dir / "retained-download-scale-phase",
            openapi_contract=openapi_contract or rust_rest_conformance.RUST_OPENAPI_CONTRACT_PATH,
        )
        report["status"] = "passed"
    except rust_rest_conformance.RestConformanceError as exc:
        report["conformance"] = exc.summary
        report["error"] = "live REST/OpenAPI response conformance failed"
    except Exception as exc:  # noqa: BLE001 - retain CI launch failures in the report
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if process is not None and process.poll() is None:
            try:
                http_json(
                    base_url,
                    "/api/v1/app/shutdown",
                    api_key=API_KEY,
                    method="POST",
                    body={"confirmShutdown": True},
                    timeout_seconds=5.0,
                )
                process.wait(timeout=20.0)
                report["teardown"] = "graceful"
                if (profile_dir / LISTENER_RECEIPT_FILE).exists():
                    report["status"] = "failed"
                    report["error"] = "REST listener receipt survived graceful daemon shutdown"
                elif "listenerReceiptPhase" in report:
                    report["listenerReceiptPhase"]["removedOnShutdown"] = True
            except Exception as exc:  # noqa: BLE001 - teardown evidence must survive
                report["teardown"] = f"forced: {type(exc).__name__}: {exc}"
                rust_client.stop_process_tree(process)
        elif process is not None:
            report["teardown"] = f"already-exited: {process.returncode}"
        else:
            report["teardown"] = "not-started"
        handle.close()
        write_report(report_path, report)
    return report, report_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--rust-repo", type=Path)
    parser.add_argument("--openapi-contract", type=Path)
    parser.add_argument("--registered-stage", action="store_true")
    args = parser.parse_args(argv)
    if args.ready_timeout_seconds <= 0:
        raise ValueError("--ready-timeout-seconds must be positive.")
    selected = {}
    if args.rust_repo:
        selected["rust_repo"] = args.rust_repo
    if args.openapi_contract:
        selected["openapi_contract"] = args.openapi_contract
    if args.registered_stage:
        selected["registered_stage"] = True
    report, report_path = run_campaign(ready_timeout_seconds=args.ready_timeout_seconds, **selected)
    print(json.dumps({"report": str(report_path), "status": report["status"], "teardown": report["teardown"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
