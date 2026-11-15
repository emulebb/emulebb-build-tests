"""Launch a local Rust daemon and gate its live responses against OpenAPI.

This is the CI-owned counterpart to ``check-rust-rest-openapi-responses.py``.
It creates a fresh external profile with networking disabled for response/SSE
conformance, then exercises real friend controls with separate loopback-only
peers. Every daemon is stopped and machine-readable evidence is retained.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import rust_client, rust_metadata, rust_rest_conformance  # noqa: E402
from emule_test_harness.paths import get_required_emule_workspace_root, get_workspace_output_root  # noqa: E402
from emule_test_harness.vm_guest_profiles import http_json, wait_until  # noqa: E402
from emule_test_harness.script_modules import load_script_module  # noqa: E402
from emule_test_harness.rust_openapi_responses import (  # noqa: E402
    load_openapi_document, openapi_operation_response, response_json_schema, validate_openapi_schema,
)

API_KEY = "rust-rest-openapi-ci-secret-0001"
REST_ADDR = "127.0.0.1"
FRIEND_PEER_BUDGET_SECONDS = 180.0
FRIEND_FAULT_TRIGGERS = tuple(f"harness_friend_failure_{operation}" for operation in ("insert", "update", "delete"))


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
            request(peer, "POST", "/api/v1/transfers", body={"link": link, "paused": False})

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
        source_path = f"/api/v1/transfers/{file_hash}/sources"
        source = poll("real local transfer source identity", lambda: next((row for row in data(
            leecher, "GET", source_path)["items"] if row.get("clientId") and row.get("userHash")), None))
        source_prefix = f"{source_path}/{source['clientId']}"
        def source_ready():
            observed = data(leecher, "GET", source_prefix)
            if observed.get("userHash") != source["userHash"]:
                raise RuntimeError("Local transfer-source identity changed during proof")
        report["frontdoors"].append(prove_friend_frontdoor(
            request=lambda method, path, **kwargs: request(leecher, method, path, **kwargs),
            database=leecher["database"], prefix=source_prefix,
            route_template="/transfers/{hash}/sources/{clientId}", ready=source_ready,
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
