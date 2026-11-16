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
FRIEND_FAULT_TRIGGERS = tuple(f"harness_friend_failure_{operation}" for operation in ("insert", "update", "delete"))


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
            profile, rust_repo=rust_repo, rest_addr=REST_ADDR, rest_port=rest_port, api_key=API_KEY,
            network_kademlia=True, p2p_bind_ip=REST_ADDR,
            ed2k_port=package._available_unique_port(ports),
            kad_port=package._available_unique_port(ports, socket_type=socket.SOCK_DGRAM),
            server_endpoint=f"127.0.0.1:{package._available_unique_port(ports)}",
            local_only_discovery=True, local_kad_seed=rust_client.kad_nodes.BootstrapContact(
                REST_ADDR, fixture.udp_port, fixture.tcp_port),
            kad_bootstrap_min_routing_contacts=1, nat_enabled=False,
            obfuscation_enabled=False, initial_shared_directory_reload=False,
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


def run_category_persistence_phase(*, executable: Path, rust_repo: Path, root: Path) -> dict[str, object]:
    """Prove category assignment, job identity and complete sharing across restart."""
    package = load_script_module("package_helpers_for_category_contract", "smoke-rust-release-package.py")
    smoke = rust_rest_conformance.load_rest_smoke_module()
    root.mkdir(parents=True, exist_ok=False)
    profile = root / "profile"
    incoming = profile / "incoming"
    temp_override = profile / "category-temp"
    destination = profile / "category-destination"
    independent_root = profile / "independent-shared-root"
    for directory in (incoming, temp_override, destination, independent_root):
        directory.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"status": "failed", "networkMode": "local-disabled",
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
        return http_json(base_url, path, api_key=API_KEY, method=method, body=body,
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
        directories = request("GET", "/api/v1/shared-directories")
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

    def download(job_id: str) -> dict[str, Any]:
        return request("GET", f"/api/v1/downloads/{job_id}")

    def assignments() -> list[object]:
        return [download(job_id).get("category") for job_id in job_ids]

    def add_download(hash_value: str, name: str, *, category: str | None = None) -> str:
        body: dict[str, Any] = {"source": {"type": "content", "hash": hash_value,
                                         "name": name, "sizeBytes": 4096}, "intent": "stopped"}
        if category is not None:
            body["category"] = category
        result = smoke.http_request(base_url, "/api/v1/downloads", method="POST", api_key=API_KEY,
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
                                    api_key=API_KEY, json_body={"ids": [job_id]},
                                    request_timeout_seconds=min(5.0, remaining()))
        return require_download_action_result(result, job_id)

    def download_page(path: str) -> list[dict[str, Any]]:
        result = http_json(base_url, path, api_key=API_KEY,
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
        rust_client.write_rust_profile(
            profile, rust_repo=rust_repo, incoming_dir=incoming, rest_addr=REST_ADDR,
            rest_port=port, api_key=API_KEY, nat_enabled=False,
            initial_shared_directory_reload=False, local_only_discovery=True,
            vpn_guard_mode="off",
        )
        for section, settings in rust_client.rust_network_settings_patch(
            auto_connect=False, reconnect_enabled=False, network_ed2k=False,
            network_kademlia=False,
        ).items():
            rust_metadata.replace_settings_section(database, section, settings)
        process, handle = package._start_daemon(executable, profile, root / "daemon.log")
        wait_until("category REST readiness", remaining(), ready)
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
        request("POST", "/api/v1/shared-directories/operations/reload")
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
        request("PATCH", "/api/v1/shared-directories", body={
            "roots": [{"path": str(independent_root)}], "confirmReplaceRoots": True,
        })
        request("POST", "/api/v1/shared-directories/operations/reload")
        wait_until("independent root reload", remaining(), reload_settled)
        if independent_copy.read_bytes() != duplicate_bytes:
            raise RuntimeError("Independent complete copy changed before category deletion")

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
        request("POST", "/api/v1/app/shutdown", body={"confirmShutdown": True})
        process.wait(timeout=min(20.0, remaining()))
        if process.returncode != 0:
            raise RuntimeError("Category persistence daemon did not stop gracefully")
        handle.close()
        handle = None
        process, handle = package._start_daemon(executable, profile, root / "restart.log")
        wait_until("restarted category REST readiness", remaining(), ready)
        request("POST", "/api/v1/shared-directories/operations/reload")
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
        wait_until("restarted independent complete share", remaining(), category_share_withdrawal)
        if (category_only.read_bytes(), category_copy.read_bytes(), independent_copy.read_bytes()) != (
            category_only_bytes, duplicate_bytes, duplicate_bytes
        ):
            raise RuntimeError("Category restart changed complete-share files")
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
    finally:
        try:
            if process is not None and process.poll() is None:
                http_json(base_url, "/api/v1/app/shutdown", api_key=API_KEY, method="POST",
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
                rust_metadata.replace_settings_section(peer["database"], "core", {
                    "autoConnect": False, "networkKademlia": False, "uploadLimitKiBps": 8,
                    "baseUploadSlots": 1, "uploadSlotElasticPercent": 0,
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
        core = data(seeder, "GET", "/api/v1/app/settings")["core"]
        if (core.get("baseUploadSlots"), core.get("uploadSlotElasticPercent"), core.get("uploadLimitKiBps")) != (1, 0, 8):
            raise RuntimeError("Local seeder did not admit the required single-slot upload policy")
        report["seederPolicy"] = {key: core[key] for key in
                                  ("baseUploadSlots", "uploadSlotElasticPercent", "uploadLimitKiBps")}
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
                return row.get("clientId") and row.get("userHash") and row.get("requestedFileHash") == file_hash
            active = next((row for row in active if valid(row) and row.get("uploading")), None)
            queued = next((row for row in queued if valid(row) and row.get("waitingQueue")), None)
            if active and queued:
                if active["userHash"] == queued["userHash"]:
                    raise RuntimeError("Local upload peers must have distinct user identities")
                return active, queued
            return None

        active, queued = poll("one active and one waiting local upload", populated)
        report["readiness"] = {"active": active["clientId"], "queued": queued["clientId"], "fileHash": file_hash}
        for collection, row in (("uploads", active), ("upload-queue", queued)):
            prefix = f"/api/v1/{collection}/{row['clientId']}"
            def ready(prefix=prefix, row=row):
                observed = data(seeder, "GET", prefix)
                if observed.get("userHash") != row["userHash"]:
                    raise RuntimeError("Local upload identity changed during friend control proof")
            report["frontdoors"].append(prove_friend_frontdoor(
                request=lambda method, path, **kwargs: request(seeder, method, path, **kwargs),
                database=seeder["database"], prefix=prefix,
                route_template=f"/{collection}/{{clientId}}", ready=ready,
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
        incoming_dir=profile_dir / "incoming",
        rest_addr=REST_ADDR,
        rest_port=port,
        api_key=API_KEY,
        nat_enabled=False,
        initial_shared_directory_reload=False,
        local_only_discovery=True,
        vpn_guard_mode="off",
    )
    metadata_path = profile_dir / rust_metadata.RUST_PROFILE_METADATA_FILE
    for section, settings in rust_client.rust_network_settings_patch(
        auto_connect=False,
        reconnect_enabled=False,
        network_ed2k=False,
        network_kademlia=False,
    ).items():
        rust_metadata.replace_settings_section(metadata_path, section, settings)

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
        process = rust_client.spawn_rust_daemon(executable, profile_dir, output_handle=handle)

        def rest_ready() -> object | None:
            if process is not None and process.poll() is not None:
                raise RuntimeError(f"Rust daemon exited before REST readiness (code {process.returncode}).")
            try:
                return http_json(base_url, "/api/v1/status", api_key=API_KEY, timeout_seconds=2.0)
            except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError):
                return None

        wait_until("Rust REST ready", ready_timeout_seconds, rest_ready)
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
