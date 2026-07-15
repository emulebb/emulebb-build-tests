from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

import pytest

from emule_test_harness import goed2k
from emule_test_harness import rust_client
from emule_test_harness import rust_metadata
from emule_test_harness.script_modules import load_script_module


API_KEY = "test-api-key"
SEED_HASH = "00112233445566778899aabbccddeeff"
SERVER_SEARCH_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
SERVER_SEARCH_NAME = "Rust.Live.Search.Fixture.bin"
ED2K_PART_SIZE = 9_728_000
SERVICE_PORT_START = int(os.environ.get("EMULEBB_RUST_TEST_PORT_START", "30000"))
SERVICE_PORT_END = int(os.environ.get("EMULEBB_RUST_TEST_PORT_END", "45000"))
_ALLOCATED_PORTS: set[int] = set()


dtt = load_script_module("deterministic_two_client_transfer_for_rust_tests", "deterministic-two-client-transfer.py")
rest_smoke = load_script_module("rest_api_smoke_for_rust_tests", "rest-api-smoke.py")


def workspace_root() -> Path:
    return Path(__file__).resolve().parents[4]


def active_workspace_root() -> Path:
    return workspace_root() / "workspaces" / "workspace"


def free_lan_port(host: str) -> int:
    return free_lan_port_not(host, set())


def free_lan_port_not(host: str, forbidden: set[int]) -> int:
    blocked = set(forbidden) | _ALLOCATED_PORTS
    for port in range(SERVICE_PORT_START, SERVICE_PORT_END):
        if port in blocked:
            continue
        if _lan_port_available(host, port):
            forbidden.add(port)
            _ALLOCATED_PORTS.add(port)
            return port
    raise RuntimeError(f"could not find a free LAN port outside {sorted(forbidden)}")


def _lan_port_available(host: str, port: int) -> bool:
    """Returns whether a deterministic LAN service port can bind TCP and UDP."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                tcp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            tcp.bind((host, port))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                udp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            udp.bind((host, port))
    except OSError:
        return False
    return True


def rust_metadata_path(profile_dir: Path) -> Path:
    return profile_dir / rust_client.RUST_PROFILE_METADATA_FILE


def write_profile(
    profile_dir: Path,
    lan_host: str,
    port: int,
    *,
    ed2k_server_endpoint: str | None = None,
    ed2k_listen_port: int | None = None,
    kad_listen_port: int | None = None,
    kad_bootstrap_nodes: list[str] | None = None,
    kad_bootstrap_min_routing_contacts: int = 10,
) -> None:
    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=workspace_root() / "repos" / "emulebb-rust",
        rest_addr=lan_host,
        rest_port=port,
        api_key=API_KEY,
        p2p_bind_ip=lan_host if ed2k_server_endpoint is not None else None,
        ed2k_port=ed2k_listen_port,
        kad_port=kad_listen_port,
        server_endpoint=ed2k_server_endpoint,
        kad_bootstrap_nodes=kad_bootstrap_nodes,
        kad_bootstrap_min_routing_contacts=kad_bootstrap_min_routing_contacts,
    )


def write_remembered_source_manifest(
    profile_dir: Path,
    file_hash: str,
    name: str,
    size_bytes: int,
    source_host: str,
    source_port: int,
) -> None:
    repo = workspace_root() / "repos" / "emulebb-rust"
    metadata_path = rust_metadata_path(profile_dir)
    if not metadata_path.exists():
        rust_metadata.create_metadata_db(repo, metadata_path)
    rust_metadata.seed_remembered_source_transfer(
        metadata_path,
        ed2k_hash=file_hash,
        name=name,
        size_bytes=size_bytes,
        piece_size=ED2K_PART_SIZE,
        source_ip=source_host,
        source_tcp_port=source_port,
    )


def write_rust_peer_exchange_report(report: dict[str, object]) -> None:
    """Writes optional structured Rust peer-exchange evidence for matrix runs."""

    report_path = os.environ.get("EMULEBB_RUST_PEER_EXCHANGE_REPORT")
    if not report_path:
        return
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def seed_index(repo: Path, metadata_path: Path) -> None:
    rust_metadata.create_metadata_db(repo, metadata_path)
    rust_metadata.seed_indexed_file(
        metadata_path,
        ed2k_hash=SEED_HASH,
        name="Scenario.File.bin",
        size_bytes=4096,
        content_type="archive",
        availability_score=2,
    )


def test_rust_peer_exchange_report_writer_uses_env_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report_path = tmp_path / "reports" / "rust-peer.json"
    monkeypatch.setenv("EMULEBB_RUST_PEER_EXCHANGE_REPORT", str(report_path))

    write_rust_peer_exchange_report({"status": "passed", "checks": {"bidirectionalRustTransfers": True}})

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report == {"status": "passed", "checks": {"bidirectionalRustTransfers": True}}


def request_json(
    base_url: str,
    method: str,
    path: str,
    body: dict[str, object] | None = None,
    *,
    timeout: float = 5,
) -> dict[str, object]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}{path}",
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def poll_search(
    base_url: str,
    search_id: str,
    *,
    want: int = 1,
    attempts: int = 40,
    interval: float = 0.25,
) -> dict[str, object]:
    """Polls a search (async eMuleBB search/start -> poll search/results) until it
    has at least `want` items under the canonical "items" key, returning the page."""
    page: dict[str, object] = {"items": []}
    for _ in range(attempts):
        page = request_json(
            base_url, "GET", f"/api/v1/searches/{search_id}?limit=200&offset=0"
        )["data"]
        if len(page.get("items", [])) >= want or page.get("status") == "complete":
            if page.get("items"):
                return page
        time.sleep(interval)
    return page


def request_json_status(
    base_url: str,
    method: str,
    path: str,
    body: dict[str, object] | None = None,
    *,
    timeout: float = 5,
) -> tuple[int, dict[str, object]]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}{path}",
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def process_output(output_path: Path) -> str:
    return output_path.read_text(encoding="utf-8", errors="replace") if output_path.exists() else ""


def wait_for_rest(base_url: str, process: subprocess.Popen[str], output_path: Path) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                f"emulebb-rust exited early with code {process.returncode}\n{process_output(output_path)}"
            )
        try:
            request_json(base_url, "GET", "/api/v1/app")
            return
        except urllib.error.URLError:
            time.sleep(0.2)
    if process.poll() is not None:
        raise AssertionError(
            f"emulebb-rust exited before REST became ready with code {process.returncode}\n{process_output(output_path)}"
        )
    raise AssertionError(f"emulebb-rust REST API did not become ready\n{process_output(output_path)}")


def wait_for_condition(description: str, deadline_seconds: float, probe: Callable[[], object]) -> object:
    deadline = time.monotonic() + deadline_seconds
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            result = probe()
            if result:
                return result
        except (AssertionError, OSError, urllib.error.URLError) as exc:
            last_error = exc
        time.sleep(0.2)
    detail = f": {last_error}" if last_error is not None else ""
    raise AssertionError(f"Timed out waiting for {description}{detail}")


def terminate_process(process: subprocess.Popen[str]) -> None:
    rust_client.stop_process_tree(process, timeout_seconds=5)


@pytest.mark.native
def test_emulebb_rust_local_search_download_flow(tmp_path: Path) -> None:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not available")
    repo = workspace_root() / "repos" / "emulebb-rust"
    if not repo.is_dir():
        pytest.skip("emulebb-rust repo is not available")
    lan_host = os.environ.get("X_LOCAL_IP")
    if not lan_host:
        pytest.skip("X_LOCAL_IP is required for LAN-bound harness control traffic")

    profile_dir = tmp_path / "profile"
    output_path = tmp_path / "emulebb-rust.out"
    shared_root = tmp_path / "shared-root"
    nested_shared_root = shared_root / "nested"
    shared_top_file = shared_root / "Rust.Shared.Root.bin"
    shared_nested_file = nested_shared_root / "Rust.Shared.Nested.bin"
    nested_shared_root.mkdir(parents=True)
    shared_top_file.write_bytes(b"emulebb-rust shared root fixture")
    shared_nested_file.write_bytes(b"emulebb-rust nested shared root fixture")
    port = free_lan_port(lan_host)
    write_profile(profile_dir, lan_host, port)
    seed_index(repo, rust_metadata_path(profile_dir))

    process = rust_client.start_rust_client(repo, profile_dir, output_path)
    try:
        base_url = f"http://{lan_host}:{port}"
        wait_for_rest(base_url, process, output_path)

        rest_contract = rest_smoke.exercise_rest_contract_completeness(base_url, API_KEY, "contract")
        assert rest_contract["ok"], json.dumps(
            [
                {
                    "operationId": route["operationId"],
                    "method": route["method"],
                    "path": route["path"],
                    "status": route.get("status"),
                    "outcome": route.get("outcome"),
                    "error": route.get("error"),
                }
                for route in rest_contract["routes"]
                if not route.get("ok") and not route.get("skipped")
            ],
            indent=2,
        )
        assert rest_contract["openapi"]["ok"], rest_contract["openapi"]

        app = request_json(base_url, "GET", "/api/v1/app")
        assert app["data"]["name"] == "eMuleBB Rust"
        assert "rest.emulebb.v1" in app["data"]["capabilities"]
        settings = request_json(base_url, "GET", "/api/v1/app/settings")["data"]
        assert settings["core"]["uploadLimitKiBps"] > 0
        updated_settings = request_json(
            base_url,
            "PATCH",
            "/api/v1/app/settings",
            {
                "core": {
                    "uploadLimitKiBps": 2048,
                    "uploadClientDataRate": 64,
                    "queueSize": 3000,
                    "networkEd2k": False,
                },
            },
        )["data"]
        assert updated_settings["core"]["uploadLimitKiBps"] == 2048
        assert updated_settings["core"]["uploadClientDataRate"] == 64
        assert updated_settings["core"]["queueSize"] == 3000
        assert updated_settings["core"]["networkEd2k"] is False
        empty_settings_status, _ = request_json_status(
            base_url,
            "PATCH",
            "/api/v1/app/settings",
            {},
        )
        assert empty_settings_status == 400
        categories = request_json(base_url, "GET", "/api/v1/categories")["data"]["items"]
        assert categories[0]["id"] == 0
        created_category = request_json(
            base_url,
            "POST",
            "/api/v1/categories",
            {
                "name": " Harness Media ",
                "path": str(shared_root),
                "comment": "daemon category",
                "color": 255,
                "priority": "high",
            },
        )["data"]
        assert created_category["id"] == 1
        assert created_category["name"] == "Harness Media"
        assert created_category["priority"] == 2
        updated_category = request_json(
            base_url,
            "PATCH",
            "/api/v1/categories/1",
            {"name": "Harness Archive", "path": None, "color": None, "priority": "verylow"},
        )["data"]
        assert updated_category["name"] == "Harness Archive"
        assert updated_category["path"] is None
        assert updated_category["priority"] == 4
        default_delete_status, _ = request_json_status(
            base_url,
            "DELETE",
            "/api/v1/categories/0",
        )
        assert default_delete_status == 400
        deleted_category = request_json(base_url, "DELETE", "/api/v1/categories/1")["data"]
        assert deleted_category["ok"] is True
        missing_category_status, _ = request_json_status(base_url, "GET", "/api/v1/categories/1")
        assert missing_category_status == 404
        friends = request_json(base_url, "GET", "/api/v1/friends")["data"]["items"]
        assert friends == []
        friend_hash = "00112233445566778899aabbccddeeff"
        created_friend = request_json(
            base_url,
            "POST",
            "/api/v1/friends",
            {"userHash": friend_hash, "name": "Harness Peer"},
        )["data"]
        assert created_friend["userHash"] == friend_hash
        assert created_friend["name"] == "Harness Peer"
        assert created_friend["lastSeen"] is None
        assert created_friend["address"] is None
        assert created_friend["port"] == 0
        duplicate_friend = request_json(
            base_url,
            "POST",
            "/api/v1/friends",
            {"userHash": friend_hash, "name": "Ignored Rename"},
        )["data"]
        assert duplicate_friend["name"] == "Harness Peer"
        invalid_friend_status, invalid_friend_error = request_json_status(
            base_url,
            "POST",
            "/api/v1/friends",
            {"userHash": friend_hash.upper()},
        )
        assert invalid_friend_status == 400
        assert "userHash" in invalid_friend_error["error"]["message"]
        deleted_friend = request_json(base_url, "DELETE", f"/api/v1/friends/{friend_hash}")["data"]
        assert deleted_friend["ok"] is True
        missing_friend_status, _ = request_json_status(
            base_url,
            "DELETE",
            f"/api/v1/friends/{friend_hash}",
        )
        assert missing_friend_status == 404
        assert request_json(base_url, "GET", "/api/v1/uploads")["data"]["items"] == []
        upload_queue = request_json(base_url, "GET", "/api/v1/upload-queue")["data"]
        assert upload_queue["items"] == []
        assert {"total", "offset", "limit"} <= upload_queue.keys()
        missing_upload_status, missing_upload_error = request_json_status(
            base_url,
            "GET",
            "/api/v1/upload-queue/unknown",
        )
        assert missing_upload_status == 404
        assert missing_upload_error["error"]["code"] == "NOT_FOUND"
        missing_confirm_status, missing_confirm_error = request_json_status(
            base_url,
            "PATCH",
            "/api/v1/shared-directories",
            {"roots": [str(shared_root)], "confirmReplaceRoots": False},
        )
        assert missing_confirm_status == 400
        assert "confirmReplaceRoots" in json.dumps(missing_confirm_error)
        shared_directories = request_json(
            base_url,
            "PATCH",
            "/api/v1/shared-directories",
            {"roots": [{"path": str(shared_root), "recursive": True}], "confirmReplaceRoots": True},
        )["data"]
        assert shared_directories["roots"][0]["recursive"] is True
        assert shared_directories["roots"][0]["accessible"] is True
        listed_directories = request_json(base_url, "GET", "/api/v1/shared-directories")["data"]
        assert listed_directories["roots"][0]["path"] == shared_directories["roots"][0]["path"]
        reload_result = request_json(
            base_url,
            "POST",
            "/api/v1/shared-directories/operations/reload",
            timeout=30,
        )["data"]
        assert reload_result["ok"] is True
        assert "count" not in reload_result
        shared_files_reload_result = request_json(
            base_url,
            "POST",
            "/api/v1/shared-files/operations/reload",
            timeout=30,
        )["data"]
        assert shared_files_reload_result["ok"] is True
        shared_files = request_json(base_url, "GET", "/api/v1/shared-files")["data"]["items"]
        shared_file_names = {row["name"] for row in shared_files}
        assert {shared_top_file.name, shared_nested_file.name} <= shared_file_names
        top_shared_file = next(row for row in shared_files if row["name"] == shared_top_file.name)
        nested_shared_file = next(row for row in shared_files if row["name"] == shared_nested_file.name)
        transfer_rows_before_clear = request_json(base_url, "GET", "/api/v1/transfers")["data"]["items"]
        assert any(
            row["hash"] == top_shared_file["hash"] and row["state"] == "completed"
            for row in transfer_rows_before_clear
        )
        denied_clear_completed_status, denied_clear_completed_error = request_json_status(
            base_url,
            "POST",
            "/api/v1/transfers/operations/clear-completed",
            {"confirmClearCompleted": False},
        )
        assert denied_clear_completed_status == 400
        assert "confirmClearCompleted" in denied_clear_completed_error["error"]["message"]
        cleared_completed = request_json(
            base_url,
            "POST",
            "/api/v1/transfers/operations/clear-completed",
            {"confirmClearCompleted": True},
        )["data"]
        assert cleared_completed["ok"] is True
        transfer_rows_after_clear = request_json(base_url, "GET", "/api/v1/transfers")["data"]["items"]
        assert not any(row["hash"] == top_shared_file["hash"] for row in transfer_rows_after_clear)
        comments = request_json(
            base_url,
            "GET",
            f"/api/v1/shared-files/{top_shared_file['hash']}/comments",
        )["data"]
        assert comments["items"] == []
        empty_shared_patch_status, empty_shared_patch_error = request_json_status(
            base_url,
            "PATCH",
            f"/api/v1/shared-files/{top_shared_file['hash']}",
            {},
        )
        assert empty_shared_patch_status == 400
        assert "shared-file PATCH" in empty_shared_patch_error["error"]["message"]
        rating_only_status, rating_only_error = request_json_status(
            base_url,
            "PATCH",
            f"/api/v1/shared-files/{top_shared_file['hash']}",
            {"rating": 5},
        )
        assert rating_only_status == 400
        assert "comment" in rating_only_error["error"]["message"]
        updated_shared_file = request_json(
            base_url,
            "PATCH",
            f"/api/v1/shared-files/{top_shared_file['hash']}",
            {"priority": "release", "comment": "Harness share comment", "rating": 4},
        )["data"]
        assert updated_shared_file["priority"] == "release"
        assert updated_shared_file["autoUploadPriority"] is False
        assert updated_shared_file["comment"] == "Harness share comment"
        assert updated_shared_file["rating"] == 4
        assert updated_shared_file["hasComment"] is True
        assert updated_shared_file["userRating"] == 4
        comments = request_json(
            base_url,
            "GET",
            f"/api/v1/shared-files/{top_shared_file['hash']}/comments",
        )["data"]
        assert comments["items"] == [
            {
                "source": "local",
                "userName": None,
                "fileName": top_shared_file["name"],
                "comment": "Harness share comment",
                "rating": 4,
            }
        ]
        persisted_shared_file = request_json(
            base_url,
            "GET",
            f"/api/v1/shared-files/{top_shared_file['hash']}",
        )["data"]
        assert persisted_shared_file["priority"] == "release"
        assert persisted_shared_file["comment"] == "Harness share comment"
        assert persisted_shared_file["rating"] == 4
        unshared = request_json(
            base_url,
            "DELETE",
            f"/api/v1/shared-files/{top_shared_file['hash']}",
        )["data"]
        assert unshared["ok"] is True
        assert unshared["deletedFiles"] is False
        unshared_status, _ = request_json_status(
            base_url,
            "GET",
            f"/api/v1/shared-files/{top_shared_file['hash']}",
        )
        assert unshared_status == 404
        delete_without_confirm_status, _ = request_json_status(
            base_url,
            "DELETE",
            f"/api/v1/shared-files/{nested_shared_file['hash']}/file",
        )
        assert delete_without_confirm_status == 400
        deleted_shared_file = request_json(
            base_url,
            "DELETE",
            f"/api/v1/shared-files/{nested_shared_file['hash']}/file?confirm=true",
        )["data"]
        assert deleted_shared_file["ok"] is True
        assert deleted_shared_file["deletedFiles"] is True
        snapshot = request_json(base_url, "GET", "/api/v1/snapshot?limit=1")["data"]
        assert snapshot["app"]["name"] == "eMuleBB Rust"
        assert snapshot["status"]["lifecycle"]["state"] == "running"
        assert len(snapshot["transfers"]) <= 1
        assert len(snapshot["sharedFiles"]) <= 1
        assert len(snapshot["uploads"]) <= 1
        assert len(snapshot["uploadQueue"]) <= 1
        assert "ports" in snapshot["network"]
        assert "binding" in snapshot["network"]
        assert "vpnGuard" in snapshot["network"]
        kad_status = request_json(base_url, "GET", "/api/v1/kad")["data"]
        assert kad_status["running"] is False
        assert kad_status["connected"] is False
        assert kad_status["bootstrapping"] is False
        assert kad_status["bootstrapProgress"] == 0
        import_empty_status, import_empty_error = request_json_status(
            base_url,
            "POST",
            "/api/v1/kad/operations/import-nodes-url",
            {"url": " "},
        )
        assert import_empty_status == 400
        assert "url" in import_empty_error["error"]["message"]
        # An unreachable/invalid URL import now fails explicitly with EMULE_ERROR
        # (master URL-import contract), not an in-band {ok:false}.
        import_fail_status, import_fail_error = request_json_status(
            base_url,
            "POST",
            "/api/v1/kad/operations/import-nodes-url",
            {"url": f"http://{lan_host}:{port}/nodes.dat"},
        )
        assert import_fail_status == 500
        assert import_fail_error["error"]["code"] == "EMULE_ERROR"
        bad_bootstrap_status, bad_bootstrap_error = request_json_status(
            base_url,
            "POST",
            "/api/v1/kad/operations/bootstrap",
            {"address": "", "port": 4662},
        )
        assert bad_bootstrap_status == 400
        assert "address" in bad_bootstrap_error["error"]["message"]
        bootstrapped_kad = request_json(
            base_url,
            "POST",
            "/api/v1/kad/operations/bootstrap",
            {"address": lan_host, "port": 4662},
        )["data"]
        assert bootstrapped_kad["running"] is True
        assert bootstrapped_kad["connected"] is True
        assert bootstrapped_kad["firewalled"] is False
        assert bootstrapped_kad["contactCount"] == 0
        recheck_kad = request_json(
            base_url,
            "POST",
            "/api/v1/kad/operations/recheck-firewall",
        )["data"]
        assert recheck_kad["operationQueued"] is True
        assert recheck_kad["alreadyRunning"] is False
        stopped_kad = request_json(base_url, "POST", "/api/v1/kad/operations/stop")["data"]
        assert stopped_kad["running"] is False
        assert stopped_kad["connected"] is False
        logs = request_json(base_url, "GET", "/api/v1/logs")["data"]["items"]
        assert isinstance(logs, list)
        for entry in logs:
            assert set(entry) >= {"timestamp", "level", "message", "debug"}
        denied_log_clear_status, denied_log_clear_error = request_json_status(
            base_url,
            "POST",
            "/api/v1/logs/operations/clear",
            {"confirmClearLogs": False},
        )
        assert denied_log_clear_status == 400
        assert "confirmClearLogs" in denied_log_clear_error["error"]["message"]
        cleared_logs = request_json(
            base_url,
            "POST",
            "/api/v1/logs/operations/clear",
            {"confirmClearLogs": True},
        )["data"]
        assert cleared_logs["ok"] is True
        logs_after_clear = request_json(base_url, "GET", "/api/v1/logs")["data"]["items"]
        assert logs_after_clear == []

        search = request_json(
            base_url,
            "POST",
            "/api/v1/searches",
            {"query": "scenario file", "method": "automatic", "type": ""},
        )["data"]
        # search/start returns an empty first page (status running); poll for results.
        assert search["status"] == "running"
        paged_search = poll_search(base_url, search["id"], want=1)
        assert paged_search["id"] == search["id"]
        assert len(paged_search["items"]) == 1
        assert paged_search["items"][0]["hash"] == SEED_HASH

        search_id = search["id"]
        download = request_json(
            base_url,
            "POST",
            f"/api/v1/searches/{search_id}/results/{SEED_HASH}/operations/download",
            {"paused": True},
        )["data"]
        assert download == {"ok": True, "searchId": search_id, "hash": SEED_HASH}
        transfer = request_json(base_url, "GET", f"/api/v1/transfers/{SEED_HASH}")["data"]
        assert transfer["hash"] == SEED_HASH
        assert transfer["state"] == "paused"
        # Master-aligned transfer fields: KiBps speeds, the separate stopped flag,
        # and the live source/part counters (0 here with no live peers).
        assert transfer["stopped"] is False
        assert "downloadSpeedBytesPerSec" not in transfer
        assert isinstance(transfer["downloadSpeedKiBps"], (int, float))
        assert isinstance(transfer["uploadSpeedKiBps"], (int, float))
        assert transfer["sourcesTransferring"] == 0
        assert transfer["partsAvailable"] == 0
        # Transfer details: {transfer, parts, sources}. The parts array carries
        # real per-part geometry/progress derived from the resume manifest.
        details = request_json(base_url, "GET", f"/api/v1/transfers/{SEED_HASH}/details")["data"]
        assert details["transfer"]["hash"] == SEED_HASH
        assert isinstance(details["sources"], list)
        assert isinstance(details["parts"], list)
        assert len(details["parts"]) == transfer["partsTotal"]
        part_fields = {
            "index", "start", "end", "size", "completedBytes", "gapBytes",
            "complete", "requested", "corrupted", "availableSources",
        }
        for index, part in enumerate(details["parts"]):
            assert set(part) == part_fields
            assert part["index"] == index
            assert part["end"] >= part["start"]
            assert part["size"] == part["end"] - part["start"] + 1
            assert part["completedBytes"] + part["gapBytes"] == part["size"]
            assert part["complete"] == (part["gapBytes"] == 0)
        details_missing_status, _ = request_json_status(
            base_url, "GET", "/api/v1/transfers/ffffffffffffffffffffffffffffffff/details"
        )
        assert details_missing_status == 404
        multi_family_patch_status, multi_family_patch_error = request_json_status(
            base_url,
            "PATCH",
            f"/api/v1/transfers/{SEED_HASH}",
            {"priority": "high", "name": "Rejected.bin"},
        )
        assert multi_family_patch_status == 400
        assert "one mutation family" in multi_family_patch_error["error"]["message"]
        priority_transfer = request_json(
            base_url,
            "PATCH",
            f"/api/v1/transfers/{SEED_HASH}",
            {"priority": "veryhigh"},
        )["data"]
        assert priority_transfer["priority"] == "veryhigh"
        download_category = request_json(
            base_url,
            "POST",
            "/api/v1/categories",
            {"name": "Harness Downloads"},
        )["data"]
        categorized_transfer = request_json(
            base_url,
            "PATCH",
            f"/api/v1/transfers/{SEED_HASH}",
            {"categoryName": "harness downloads"},
        )["data"]
        assert categorized_transfer["categoryId"] == download_category["id"]
        assert categorized_transfer["categoryName"] == "Harness Downloads"
        renamed_transfer = request_json(
            base_url,
            "PATCH",
            f"/api/v1/transfers/{SEED_HASH}",
            {"name": " Scenario Renamed.bin "},
        )["data"]
        assert renamed_transfer["name"] == "Scenario Renamed.bin"
        assert renamed_transfer["priority"] == "veryhigh"
        assert renamed_transfer["categoryId"] == download_category["id"]

        transfers = request_json(base_url, "GET", "/api/v1/transfers")["data"]["items"]
        assert any(row["hash"] == SEED_HASH and row["state"] == "paused" for row in transfers)

        # Persistence proof: restart the daemon and confirm the paused control
        # state and renamed canonical name reload from emulebb-rust-metadata.db.
        terminate_process(process)
        process = rust_client.start_rust_client_append(repo, profile_dir, output_path)
        wait_for_rest(base_url, process, output_path)
        reloaded_transfer = request_json(base_url, "GET", f"/api/v1/transfers/{SEED_HASH}")["data"]
        assert reloaded_transfer["state"] == "paused"
        assert reloaded_transfer["name"] == "Scenario Renamed.bin"

        delete_row_status, delete_row_error = request_json_status(
            base_url,
            "DELETE",
            f"/api/v1/transfers/{SEED_HASH}",
        )
        assert delete_row_status == 400
        assert "only completed transfers can be removed without deleting files" in json.dumps(delete_row_error)

        delete_result = request_json(
            base_url,
            "DELETE",
            f"/api/v1/transfers/{SEED_HASH}/files?confirm=true",
        )["data"]
        assert delete_result["items"][0]["ok"] is True
        assert delete_result["items"][0]["hash"] == SEED_HASH
        assert not (profile_dir / "transfers" / SEED_HASH).exists()
        denied_search_clear_status, denied_search_clear_error = request_json_status(
            base_url,
            "DELETE",
            "/api/v1/searches",
        )
        assert denied_search_clear_status == 400
        assert "confirm" in denied_search_clear_error["error"]["message"]
        cleared_searches = request_json(base_url, "DELETE", "/api/v1/searches?confirm=true")["data"]
        assert cleared_searches["ok"] is True
        searches_after_clear = request_json(base_url, "GET", "/api/v1/searches")["data"]["items"]
        assert searches_after_clear == []
    finally:
        terminate_process(process)


@pytest.mark.native
def test_emulebb_rust_server_connect_uses_configured_p2p_bind(tmp_path: Path) -> None:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not available")
    repo = workspace_root() / "repos" / "emulebb-rust"
    if not repo.is_dir():
        pytest.skip("emulebb-rust repo is not available")
    lan_host = os.environ.get("X_LOCAL_IP")
    if not lan_host:
        pytest.skip("X_LOCAL_IP is required for LAN-bound harness control traffic")

    profile_dir = tmp_path / "profile"
    output_path = tmp_path / "emulebb-rust.out"
    port = free_lan_port(lan_host)
    ed2k_port = free_lan_port(lan_host)
    kad_port = free_lan_port(lan_host)
    write_profile(
        profile_dir,
        lan_host,
        port,
        ed2k_server_endpoint="192.0.2.20:4661",
        ed2k_listen_port=ed2k_port,
        kad_listen_port=kad_port,
    )

    process = rust_client.start_rust_client(repo, profile_dir, output_path)
    try:
        base_url = f"http://{lan_host}:{port}"
        wait_for_rest(base_url, process, output_path)

        servers = request_json(base_url, "GET", "/api/v1/servers")["data"]["items"]
        assert [(server["address"], server["port"]) for server in servers] == [("192.0.2.20", 4661)]
        configured_server = request_json(base_url, "GET", "/api/v1/servers/192.0.2.20:4661")["data"]
        assert configured_server["address"] == "192.0.2.20"
        assert configured_server["port"] == 4661

        created_server = request_json(
            base_url,
            "POST",
            "/api/v1/servers",
            {
                "address": "192.0.2.21",
                "port": 4661,
                "name": "dynamic",
                "priority": "low",
                "static": False,
            },
        )["data"]
        assert created_server["address"] == "192.0.2.21"
        assert created_server["port"] == 4661
        assert created_server["priority"] == "low"
        updated_server = request_json(
            base_url,
            "PATCH",
            "/api/v1/servers/192.0.2.21:4661",
            {"name": "dynamic-updated", "priority": "high", "static": True},
        )["data"]
        assert updated_server["name"] == "dynamic-updated"
        assert updated_server["priority"] == "high"
        assert updated_server["static"] is True
        deleted_server = request_json(base_url, "DELETE", "/api/v1/servers/192.0.2.21:4661")["data"]
        assert deleted_server["address"] == "192.0.2.21"
        assert deleted_server["port"] == 4661
        missing_server_status, missing_server_error = request_json_status(
            base_url,
            "GET",
            "/api/v1/servers/192.0.2.21:4661",
        )
        assert missing_server_status == 404
        assert missing_server_error["error"]["code"] == "NOT_FOUND"
        import_empty_status, import_empty_error = request_json_status(
            base_url,
            "POST",
            "/api/v1/servers/operations/import-met-url",
            {"url": " "},
        )
        assert import_empty_status == 400
        assert "url" in import_empty_error["error"]["message"]
        # Unreachable/invalid URL import fails explicitly with EMULE_ERROR.
        import_met_fail_status, import_met_fail_error = request_json_status(
            base_url,
            "POST",
            "/api/v1/servers/operations/import-met-url",
            {"url": f"http://{lan_host}:{port}/server.met"},
        )
        assert import_met_fail_status == 500
        assert import_met_fail_error["error"]["code"] == "EMULE_ERROR"

        connected = request_json(base_url, "POST", "/api/v1/servers/operations/connect")["data"]
        assert connected["serverCount"] == 1
        assert connected["connected"] is False

        status = request_json(base_url, "GET", "/api/v1/status")["data"]
        assert status["servers"]["serverCount"] == 1

        disconnected = request_json(base_url, "POST", "/api/v1/servers/operations/disconnect")["data"]
        assert disconnected["serverCount"] == 1
        assert disconnected["connected"] is False
    finally:
        terminate_process(process)


@pytest.mark.native
def test_emulebb_rust_searches_local_goed2k_server_catalog(tmp_path: Path) -> None:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not available")
    ed2k_server_exe = goed2k.env_ed2k_server_exe_override()
    if shutil.which("go") is None and ed2k_server_exe is None:
        pytest.skip("go is not available")
    rust_repo = workspace_root() / "repos" / "emulebb-rust"
    server_repo = workspace_root() / "repos" / "goed2k-server"
    if not rust_repo.is_dir() or (ed2k_server_exe is None and not server_repo.is_dir()):
        pytest.skip("emulebb-rust or goed2k-server repo is not available")
    lan_host = os.environ.get("X_LOCAL_IP")
    if not lan_host:
        pytest.skip("X_LOCAL_IP is required for LAN-bound harness control traffic")

    server_root = tmp_path / "goed2k"
    server_root.mkdir()
    server_port = dtt.choose_tcp_port_with_udp_offset(lan_host)
    _ALLOCATED_PORTS.update({server_port, server_port + 4})
    admin_port = free_lan_port(lan_host)
    forbidden_ports = {server_port, admin_port, server_port + 4}
    rust_ed2k_port = free_lan_port_not(lan_host, forbidden_ports)
    rust_kad_port = free_lan_port_not(lan_host, forbidden_ports)
    admin_token = "goed2k-test-token"
    ed2k_server = goed2k.launch_ed2k_server(
        workspace_root=active_workspace_root(),
        server_dir=server_root,
        ed2k_port=server_port,
        admin_port=admin_port,
        token=admin_token,
        admin_address=lan_host,
        ed2k_address=lan_host,
        exe_override=ed2k_server_exe,
        catalog_files=[
            goed2k.catalog_file(
                file_hash=SERVER_SEARCH_HASH,
                name=SERVER_SEARCH_NAME,
                size=4096,
                endpoints=[{"host": lan_host, "port": rust_ed2k_port}],
            )
        ],
    )
    server_process = ed2k_server.process

    rust_profile_dir = tmp_path / "profile"
    rust_output_path = tmp_path / "emulebb-rust.out"
    rust_port = free_lan_port(lan_host)
    write_profile(
        rust_profile_dir,
        lan_host,
        rust_port,
        ed2k_server_endpoint=f"{lan_host}:{server_port}",
        ed2k_listen_port=rust_ed2k_port,
        kad_listen_port=rust_kad_port,
    )

    rust_process = rust_client.start_rust_client(rust_repo, rust_profile_dir, rust_output_path)

    try:
        admin_base_url = ed2k_server.admin_base_url
        base_url = f"http://{lan_host}:{rust_port}"
        wait_for_rest(base_url, rust_process, rust_output_path)

        connect = request_json(base_url, "POST", "/api/v1/servers/operations/connect")["data"]
        assert connect["serverCount"] == 1

        wait_for_condition(
            "emulebb-rust ED2K server connection",
            30,
            lambda: request_json(base_url, "GET", "/api/v1/status")["data"]["stats"]["ed2kConnected"],
        )

        search = request_json(
            base_url,
            "POST",
            "/api/v1/searches",
            {"query": "Rust.Live.Search.Fixture", "method": "server", "type": ""},
        )["data"]
        results = poll_search(base_url, search["id"])["items"]
        assert any(result["hash"] == SERVER_SEARCH_HASH and result["name"] == SERVER_SEARCH_NAME for result in results)
        stats = goed2k.admin_request(admin_base_url, admin_token, "/api/stats")["data"]
        assert int(stats["search_requests"]) >= 1
    finally:
        terminate_process(rust_process)
        goed2k.stop_process(server_process)
        goed2k.stop_server_processes()


@pytest.mark.native
def test_emulebb_rust_peers_exchange_files_via_local_goed2k_sources(tmp_path: Path) -> None:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not available")
    ed2k_server_exe = goed2k.env_ed2k_server_exe_override()
    if shutil.which("go") is None and ed2k_server_exe is None:
        pytest.skip("go is not available")
    rust_repo = workspace_root() / "repos" / "emulebb-rust"
    server_repo = workspace_root() / "repos" / "goed2k-server"
    if not rust_repo.is_dir() or (ed2k_server_exe is None and not server_repo.is_dir()):
        pytest.skip("emulebb-rust or goed2k-server repo is not available")
    lan_host = os.environ.get("X_LOCAL_IP")
    if not lan_host:
        pytest.skip("X_LOCAL_IP is required for LAN-bound harness control traffic")

    payload_path = tmp_path / "Rust.Peer.Download.Fixture.bin"
    payload = (b"emulebb-rust-ed2k-download-fixture\n" * 256) + b"tail"
    payload_path.write_bytes(payload)
    unicode_payload_path = tmp_path / "Rust.Peer.Unicode-\u00e9-\u6f22.Fixture.bin"
    unicode_payload = (b"emulebb-rust-ed2k-unicode-download-fixture\n" * 257) + b"tail"
    unicode_payload_path.write_bytes(unicode_payload)
    hash_only_payload_path = tmp_path / "Rust.Peer.Hash.Only.Metadata.Fixture.bin"
    hash_only_payload = (b"emulebb-rust-ed2k-hash-only-metadata-fixture\n" * 255) + b"tail"
    hash_only_payload_path.write_bytes(hash_only_payload)
    reverse_payload_path = tmp_path / "Rust.Peer.Reverse.Download.Fixture.bin"
    reverse_payload = (b"emulebb-rust-ed2k-reverse-download-fixture\n" * 256) + b"tail"
    reverse_payload_path.write_bytes(reverse_payload)

    server_root = tmp_path / "goed2k"
    server_root.mkdir()
    server_port = dtt.choose_tcp_port_with_udp_offset(lan_host)
    _ALLOCATED_PORTS.update({server_port, server_port + 4})
    admin_port = free_lan_port(lan_host)
    forbidden_ports = {server_port, admin_port, server_port + 4}
    admin_token = "goed2k-test-token"
    ed2k_server = goed2k.launch_ed2k_server(
        workspace_root=active_workspace_root(),
        server_dir=server_root,
        ed2k_port=server_port,
        admin_port=admin_port,
        token=admin_token,
        admin_address=lan_host,
        ed2k_address=lan_host,
        exe_override=ed2k_server_exe,
    )
    server_process = ed2k_server.process

    seeder_profile_dir = tmp_path / "seeder-profile"
    seeder_output_path = tmp_path / "seeder.out"
    seeder_rest_port = free_lan_port_not(lan_host, forbidden_ports)
    seeder_ed2k_port = free_lan_port_not(lan_host, forbidden_ports)
    seeder_kad_port = free_lan_port_not(lan_host, forbidden_ports)

    leecher_profile_dir = tmp_path / "leecher-profile"
    leecher_output_path = tmp_path / "leecher.out"
    leecher_rest_port = free_lan_port_not(lan_host, forbidden_ports)
    leecher_ed2k_port = free_lan_port_not(lan_host, forbidden_ports)
    leecher_kad_port = free_lan_port_not(lan_host, forbidden_ports)
    kad_bootstrap_min_contacts = 1
    write_profile(
        seeder_profile_dir,
        lan_host,
        seeder_rest_port,
        ed2k_server_endpoint=f"{lan_host}:{server_port}",
        ed2k_listen_port=seeder_ed2k_port,
        kad_listen_port=seeder_kad_port,
        kad_bootstrap_nodes=[f"{lan_host}:{leecher_kad_port}"],
        kad_bootstrap_min_routing_contacts=kad_bootstrap_min_contacts,
    )
    write_profile(
        leecher_profile_dir,
        lan_host,
        leecher_rest_port,
        ed2k_server_endpoint=f"{lan_host}:{server_port}",
        ed2k_listen_port=leecher_ed2k_port,
        kad_listen_port=leecher_kad_port,
        kad_bootstrap_nodes=[f"{lan_host}:{seeder_kad_port}"],
        kad_bootstrap_min_routing_contacts=kad_bootstrap_min_contacts,
    )

    remembered_profile_dir = tmp_path / "remembered-leecher-profile"
    remembered_output_path = tmp_path / "remembered-leecher.out"
    remembered_rest_port = free_lan_port_not(lan_host, forbidden_ports)
    remembered_ed2k_port = free_lan_port_not(lan_host, forbidden_ports)
    remembered_kad_port = free_lan_port_not(lan_host, forbidden_ports)
    dead_server_port = free_lan_port_not(lan_host, forbidden_ports)
    write_profile(
        remembered_profile_dir,
        lan_host,
        remembered_rest_port,
        ed2k_server_endpoint=f"{lan_host}:{dead_server_port}",
        ed2k_listen_port=remembered_ed2k_port,
        kad_listen_port=remembered_kad_port,
        kad_bootstrap_nodes=[f"{lan_host}:{seeder_kad_port}"],
        kad_bootstrap_min_routing_contacts=kad_bootstrap_min_contacts,
    )
    with sqlite3.connect(rust_metadata_path(seeder_profile_dir)) as conn:
        seeder_bootstrap = conn.execute("SELECT endpoint FROM kad_bootstrap_endpoints").fetchone()[0]
        seeder_min_contacts = json.loads(
            conn.execute(
                "SELECT value_json FROM settings WHERE section = 'kad' AND key = 'bootstrapMinRoutingContacts'"
            ).fetchone()[0]
        )
    with sqlite3.connect(rust_metadata_path(leecher_profile_dir)) as conn:
        leecher_bootstrap = conn.execute("SELECT endpoint FROM kad_bootstrap_endpoints").fetchone()[0]
        leecher_min_contacts = json.loads(
            conn.execute(
                "SELECT value_json FROM settings WHERE section = 'kad' AND key = 'bootstrapMinRoutingContacts'"
            ).fetchone()[0]
        )
    assert seeder_bootstrap == f"{lan_host}:{leecher_kad_port}"
    assert leecher_bootstrap == f"{lan_host}:{seeder_kad_port}"
    assert seeder_min_contacts == 1
    assert leecher_min_contacts == 1

    seeder_process = rust_client.start_rust_client(rust_repo, seeder_profile_dir, seeder_output_path)
    leecher_process = rust_client.start_rust_client(rust_repo, leecher_profile_dir, leecher_output_path)

    remembered_leecher_process: subprocess.Popen[str] | None = None
    try:
        admin_base_url = ed2k_server.admin_base_url

        seeder_base_url = f"http://{lan_host}:{seeder_rest_port}"
        wait_for_rest(seeder_base_url, seeder_process, seeder_output_path)
        request_json(seeder_base_url, "POST", "/api/v1/servers/operations/connect")["data"]
        wait_for_condition(
            "seeder ED2K server connection",
            30,
            lambda: request_json(seeder_base_url, "GET", "/api/v1/status")["data"]["stats"]["ed2kConnected"],
        )
        share = request_json(
            seeder_base_url,
            "POST",
            "/api/v1/shared-files",
            {"path": str(payload_path)},
            timeout=30,
        )["data"]
        assert share["ok"] is True
        assert share["queued"] is False
        assert share["file"]["name"] == payload_path.name
        assert int(share["file"]["sizeBytes"]) == len(payload)
        share_file = share["file"]
        unicode_share = request_json(
            seeder_base_url,
            "POST",
            "/api/v1/shared-files",
            {"path": str(unicode_payload_path)},
            timeout=30,
        )["data"]
        assert unicode_share["ok"] is True
        assert unicode_share["queued"] is False
        assert unicode_share["file"]["name"] == unicode_payload_path.name
        assert int(unicode_share["file"]["sizeBytes"]) == len(unicode_payload)
        unicode_share_file = unicode_share["file"]
        hash_only_share = request_json(
            seeder_base_url,
            "POST",
            "/api/v1/shared-files",
            {"path": str(hash_only_payload_path)},
            timeout=30,
        )["data"]
        assert hash_only_share["ok"] is True
        assert hash_only_share["queued"] is False
        assert hash_only_share["file"]["name"] == hash_only_payload_path.name
        assert int(hash_only_share["file"]["sizeBytes"]) == len(hash_only_payload)
        hash_only_share_file = hash_only_share["file"]

        listed_shares = request_json(seeder_base_url, "GET", "/api/v1/shared-files")["data"]["items"]
        assert any(file["hash"] == share_file["hash"] for file in listed_shares)
        assert any(file["hash"] == unicode_share_file["hash"] for file in listed_shares)
        assert any(file["hash"] == hash_only_share_file["hash"] for file in listed_shares)
        share_link = request_json(
            seeder_base_url,
            "GET",
            f"/api/v1/shared-files/{share_file['hash']}/ed2k-link",
        )["data"]
        assert share_link["hash"] == share_file["hash"]
        assert share_link["link"] == share_file["ed2kLink"]

        published = goed2k.wait_for_server_file_endpoint(
            admin_base_url,
            admin_token,
            str(share_file["hash"]),
            lan_host,
            seeder_ed2k_port,
            30,
            "goed2k dynamic file published by Rust OP_OFFERFILES",
        )
        assert published["name"] == payload_path.name
        unicode_published = goed2k.wait_for_server_file_endpoint(
            admin_base_url,
            admin_token,
            str(unicode_share_file["hash"]),
            lan_host,
            seeder_ed2k_port,
            30,
            "goed2k Unicode file published by Rust OP_OFFERFILES",
        )
        assert unicode_published["name"] == unicode_payload_path.name
        hash_only_published = goed2k.wait_for_server_file_endpoint(
            admin_base_url,
            admin_token,
            str(hash_only_share_file["hash"]),
            lan_host,
            seeder_ed2k_port,
            30,
            "goed2k hash-only metadata file published by Rust OP_OFFERFILES",
        )
        assert hash_only_published["name"] == hash_only_payload_path.name

        write_remembered_source_manifest(
            remembered_profile_dir,
            str(share_file["hash"]).lower(),
            payload_path.name,
            len(payload),
            lan_host,
            seeder_ed2k_port,
        )
        remembered_leecher_process = rust_client.start_rust_client(
            rust_repo,
            remembered_profile_dir,
            remembered_output_path,
        )
        remembered_base_url = f"http://{lan_host}:{remembered_rest_port}"
        wait_for_rest(remembered_base_url, remembered_leecher_process, remembered_output_path)
        remembered_transfers = request_json(remembered_base_url, "GET", "/api/v1/transfers")["data"]["items"]
        assert any(transfer["hash"] == str(share_file["hash"]).lower() for transfer in remembered_transfers)
        remembered_resume = request_json(
            remembered_base_url,
            "POST",
            f"/api/v1/transfers/{share_file['hash']}/operations/resume",
            timeout=45,
        )["data"]
        assert remembered_resume["items"][0]["ok"] is True
        remembered_transfer = request_json(remembered_base_url, "GET", f"/api/v1/transfers/{share_file['hash']}")["data"]
        if remembered_transfer["state"] != "completed":
            remembered_transfer = wait_for_condition(
                "remembered-source leecher transfer completion",
                90,
                lambda: request_json(remembered_base_url, "GET", f"/api/v1/transfers/{share_file['hash']}")["data"]
                if request_json(remembered_base_url, "GET", f"/api/v1/transfers/{share_file['hash']}")["data"]["state"] == "completed"
                else None,
            )
        assert remembered_transfer["state"] == "completed"
        assert int(remembered_transfer["completedBytes"]) == len(payload)
        remembered_payload = remembered_profile_dir / "transfers" / str(share_file["hash"]).lower() / "pieces.bin"
        assert remembered_payload.read_bytes() == payload

        leecher_base_url = f"http://{lan_host}:{leecher_rest_port}"
        wait_for_rest(leecher_base_url, leecher_process, leecher_output_path)
        request_json(leecher_base_url, "POST", "/api/v1/servers/operations/connect")["data"]
        wait_for_condition(
            "leecher ED2K server connection",
            30,
            lambda: request_json(leecher_base_url, "GET", "/api/v1/status")["data"]["stats"]["ed2kConnected"],
        )
        hash_only_hash = str(hash_only_share_file["hash"]).lower()
        hash_only_link = f"ed2k://|file|{hash_only_hash}|0|{hash_only_hash}|/"
        hash_only_create = request_json(
            leecher_base_url,
            "POST",
            "/api/v1/transfers",
            {"link": hash_only_link, "paused": False},
            timeout=30,
        )["data"]
        assert hash_only_create["items"][0]["ok"] is True
        assert hash_only_create["items"][0]["hash"] == hash_only_hash

        search = request_json(
            leecher_base_url,
            "POST",
            "/api/v1/searches",
            {"query": "Rust.Peer.Download.Fixture", "method": "server", "type": ""},
            timeout=30,
        )["data"]
        search_items = poll_search(leecher_base_url, search["id"])["items"]
        result = next(result for result in search_items if result["hash"] == share_file["hash"])
        download = request_json(
            leecher_base_url,
            "POST",
            f"/api/v1/searches/{search['id']}/results/{result['hash']}/operations/download",
        )["data"]
        assert download == {"ok": True, "searchId": search["id"], "hash": result["hash"]}
        unicode_search = request_json(
            leecher_base_url,
            "POST",
            "/api/v1/searches",
            {"query": "Rust.Peer.Unicode-\u00e9-\u6f22", "method": "server", "type": ""},
            timeout=30,
        )["data"]
        unicode_items = poll_search(leecher_base_url, unicode_search["id"])["items"]
        unicode_result = next(
            result
            for result in unicode_items
            if result["hash"] == unicode_share_file["hash"]
        )
        assert unicode_result["name"] == unicode_payload_path.name
        unicode_download = request_json(
            leecher_base_url,
            "POST",
            f"/api/v1/searches/{unicode_search['id']}/results/{unicode_result['hash']}/operations/download",
        )["data"]
        assert unicode_download == {
            "ok": True,
            "searchId": unicode_search["id"],
            "hash": unicode_result["hash"],
        }
        queued_downloads = request_json(leecher_base_url, "GET", "/api/v1/transfers")["data"]["items"]
        queued_hashes = {transfer["hash"] for transfer in queued_downloads}
        assert {result["hash"], unicode_result["hash"]} <= queued_hashes
        resume = request_json(
            leecher_base_url,
            "POST",
            f"/api/v1/transfers/{result['hash']}/operations/resume",
            timeout=30,
        )["data"]
        assert resume["items"][0]["ok"] is True
        unicode_resume = request_json(
            leecher_base_url,
            "POST",
            f"/api/v1/transfers/{unicode_result['hash']}/operations/resume",
            timeout=30,
        )["data"]
        assert unicode_resume["items"][0]["ok"] is True
        hash_only_resume = request_json(
            leecher_base_url,
            "POST",
            f"/api/v1/transfers/{hash_only_hash}/operations/resume",
            timeout=30,
        )["data"]
        assert hash_only_resume["items"][0]["ok"] is True
        transfer = request_json(leecher_base_url, "GET", f"/api/v1/transfers/{result['hash']}")["data"]
        if transfer["state"] != "completed":
            transfer = wait_for_condition(
                "leecher transfer completion",
                90,
                lambda: request_json(leecher_base_url, "GET", f"/api/v1/transfers/{result['hash']}")["data"]
                if request_json(leecher_base_url, "GET", f"/api/v1/transfers/{result['hash']}")["data"]["state"] == "completed"
                else None,
            )
        assert transfer["state"] == "completed"
        assert int(transfer["completedBytes"]) == len(payload)
        assert float(transfer["progress"]) == pytest.approx(1.0)
        unicode_transfer = request_json(
            leecher_base_url,
            "GET",
            f"/api/v1/transfers/{unicode_result['hash']}",
        )["data"]
        if unicode_transfer["state"] != "completed":
            unicode_transfer = wait_for_condition(
                "Unicode leecher transfer completion",
                90,
                lambda: request_json(
                    leecher_base_url,
                    "GET",
                    f"/api/v1/transfers/{unicode_result['hash']}",
                )["data"]
                if request_json(
                    leecher_base_url,
                    "GET",
                    f"/api/v1/transfers/{unicode_result['hash']}",
                )["data"]["state"]
                == "completed"
                else None,
            )
        assert unicode_transfer["name"] == unicode_payload_path.name
        assert unicode_transfer["state"] == "completed"
        assert int(unicode_transfer["completedBytes"]) == len(unicode_payload)
        assert float(unicode_transfer["progress"]) == pytest.approx(1.0)
        hash_only_transfer = request_json(leecher_base_url, "GET", f"/api/v1/transfers/{hash_only_hash}")["data"]
        if hash_only_transfer["state"] != "completed":
            hash_only_transfer = wait_for_condition(
                "hash-only metadata leecher transfer completion",
                90,
                lambda: request_json(leecher_base_url, "GET", f"/api/v1/transfers/{hash_only_hash}")["data"]
                if request_json(leecher_base_url, "GET", f"/api/v1/transfers/{hash_only_hash}")["data"]["state"] == "completed"
                else None,
            )
        assert hash_only_transfer["name"] == hash_only_payload_path.name
        assert hash_only_transfer["state"] == "completed"
        assert int(hash_only_transfer["sizeBytes"]) == len(hash_only_payload)
        assert int(hash_only_transfer["completedBytes"]) == len(hash_only_payload)
        assert float(hash_only_transfer["progress"]) == pytest.approx(1.0)
        sources = request_json(
            leecher_base_url,
            "GET",
            f"/api/v1/transfers/{result['hash']}/sources",
        )["data"]["items"]
        assert any(
            source["address"] == lan_host
            and int(source["port"]) == seeder_ed2k_port
            for source in sources
        )
        downloaded_payload = leecher_profile_dir / "transfers" / str(result["hash"]) / "pieces.bin"
        assert downloaded_payload.read_bytes() == payload
        downloaded_unicode_payload = (
            leecher_profile_dir / "transfers" / str(unicode_result["hash"]) / "pieces.bin"
        )
        assert downloaded_unicode_payload.read_bytes() == unicode_payload
        downloaded_hash_only_payload = leecher_profile_dir / "transfers" / hash_only_hash / "pieces.bin"
        assert downloaded_hash_only_payload.read_bytes() == hash_only_payload

        reverse_share = request_json(
            leecher_base_url,
            "POST",
            "/api/v1/shared-files",
            {"path": str(reverse_payload_path)},
            timeout=30,
        )["data"]
        assert reverse_share["ok"] is True
        assert reverse_share["queued"] is False
        assert reverse_share["file"]["name"] == reverse_payload_path.name
        assert int(reverse_share["file"]["sizeBytes"]) == len(reverse_payload)
        reverse_share_file = reverse_share["file"]

        reverse_published = goed2k.wait_for_server_file_endpoint(
            admin_base_url,
            admin_token,
            str(reverse_share_file["hash"]),
            lan_host,
            leecher_ed2k_port,
            30,
            "goed2k reverse dynamic file published by Rust OP_OFFERFILES",
        )
        assert reverse_published["name"] == reverse_payload_path.name

        reverse_search = request_json(
            seeder_base_url,
            "POST",
            "/api/v1/searches",
            {"query": "Rust.Peer.Reverse.Download.Fixture", "method": "server", "type": ""},
            timeout=30,
        )["data"]
        reverse_items = poll_search(seeder_base_url, reverse_search["id"])["items"]
        reverse_result = next(
            result
            for result in reverse_items
            if result["hash"] == reverse_share_file["hash"]
        )
        reverse_download = request_json(
            seeder_base_url,
            "POST",
            f"/api/v1/searches/{reverse_search['id']}/results/{reverse_result['hash']}/operations/download",
        )["data"]
        assert reverse_download == {
            "ok": True,
            "searchId": reverse_search["id"],
            "hash": reverse_result["hash"],
        }
        reverse_resume = request_json(
            seeder_base_url,
            "POST",
            f"/api/v1/transfers/{reverse_result['hash']}/operations/resume",
            timeout=30,
        )["data"]
        assert reverse_resume["items"][0]["ok"] is True
        reverse_transfer = request_json(seeder_base_url, "GET", f"/api/v1/transfers/{reverse_result['hash']}")["data"]
        if reverse_transfer["state"] != "completed":
            reverse_transfer = wait_for_condition(
                "reverse seeder transfer completion",
                90,
                lambda: request_json(seeder_base_url, "GET", f"/api/v1/transfers/{reverse_result['hash']}")["data"]
                if request_json(seeder_base_url, "GET", f"/api/v1/transfers/{reverse_result['hash']}")["data"]["state"] == "completed"
                else None,
            )
        assert reverse_transfer["state"] == "completed"
        assert int(reverse_transfer["completedBytes"]) == len(reverse_payload)
        assert float(reverse_transfer["progress"]) == pytest.approx(1.0)
        reverse_sources = request_json(
            seeder_base_url,
            "GET",
            f"/api/v1/transfers/{reverse_result['hash']}/sources",
        )["data"]["items"]
        assert any(
            source["address"] == lan_host
            and int(source["port"]) == leecher_ed2k_port
            for source in reverse_sources
        )
        reverse_downloaded_payload = seeder_profile_dir / "transfers" / str(reverse_result["hash"]) / "pieces.bin"
        assert reverse_downloaded_payload.read_bytes() == reverse_payload

        terminate_process(leecher_process)
        leecher_process = rust_client.start_rust_client_append(
            rust_repo,
            leecher_profile_dir,
            leecher_output_path,
        )
        wait_for_rest(leecher_base_url, leecher_process, leecher_output_path)
        persisted_sources = request_json(
            leecher_base_url,
            "GET",
            f"/api/v1/transfers/{result['hash']}/sources",
        )["data"]["items"]
        persisted_endpoint = f"{lan_host}:{seeder_ed2k_port}"
        assert any(
            source["address"] == lan_host and int(source["port"]) == seeder_ed2k_port
            for source in persisted_sources
        )
        persisted_source = next(
            source
            for source in persisted_sources
            if source["address"] == lan_host and int(source["port"]) == seeder_ed2k_port
        )
        if persisted_source.get("userHash"):
            assert persisted_source["clientId"] == persisted_source["userHash"]
        else:
            assert persisted_source["clientId"] == persisted_endpoint
        assert int(persisted_source["port"]) == seeder_ed2k_port
        single_source = request_json(
            leecher_base_url,
            "GET",
            f"/api/v1/transfers/{result['hash']}/sources/{persisted_source['clientId']}",
        )["data"]
        assert single_source["clientId"] == persisted_source["clientId"]
        assert single_source["address"] == lan_host
        browse_status, browse_error = request_json_status(
            leecher_base_url,
            "POST",
            f"/api/v1/transfers/{result['hash']}/sources/{persisted_source['clientId']}/operations/browse",
        )
        assert browse_status == 400
        assert "shared-file browsing" in browse_error["error"]["message"]
        banned_source = request_json(
            leecher_base_url,
            "POST",
            f"/api/v1/transfers/{result['hash']}/sources/{persisted_source['clientId']}/operations/ban",
        )["data"]
        assert banned_source == {"ok": True, "banned": True}
        source_after_ban = request_json(
            leecher_base_url,
            "GET",
            f"/api/v1/transfers/{result['hash']}/sources/{persisted_source['clientId']}",
        )["data"]
        assert source_after_ban["downloadState"] == "banned"
        unbanned_source = request_json(
            leecher_base_url,
            "POST",
            f"/api/v1/transfers/{result['hash']}/sources/{persisted_source['clientId']}/operations/unban",
        )["data"]
        assert unbanned_source == {"ok": True, "banned": False}
        release_status, release_error = request_json_status(
            leecher_base_url,
            "POST",
            f"/api/v1/transfers/{result['hash']}/sources/{persisted_source['clientId']}/operations/release-slot",
        )
        assert release_status == 400
        assert "upload slot" in release_error["error"]["message"]
        removed_source = request_json(
            leecher_base_url,
            "POST",
            f"/api/v1/transfers/{result['hash']}/sources/{persisted_source['clientId']}/operations/remove",
        )["data"]
        assert removed_source["ok"] is True
        sources_after_remove = request_json(
            leecher_base_url,
            "GET",
            f"/api/v1/transfers/{result['hash']}/sources",
        )["data"]["items"]
        assert not any(source["clientId"] == persisted_source["clientId"] for source in sources_after_remove)

        delete_row = request_json(
            leecher_base_url,
            "DELETE",
            f"/api/v1/transfers/{result['hash']}",
        )["data"]
        assert delete_row["items"][0]["ok"] is True
        assert delete_row["items"][0]["hash"] == result["hash"]
        assert downloaded_payload.read_bytes() == payload
        delete_read_status, _ = request_json_status(
            leecher_base_url,
            "GET",
            f"/api/v1/transfers/{result['hash']}",
        )
        assert delete_read_status == 404
        remaining_transfers = request_json(leecher_base_url, "GET", "/api/v1/transfers")["data"]["items"]
        assert not any(transfer["hash"] == result["hash"] for transfer in remaining_transfers)
        write_rust_peer_exchange_report(
            {
                "schema": "emulebb-rust.peer-exchange-result.v1",
                "status": "passed",
                "checks": {
                    "serverDynamicOfferFiles": True,
                    "rememberedSourceResumeWithoutServer": True,
                    "multiTransferCount": 3,
                    "unicodeFilenameTransfer": True,
                    "hashOnlyMetadataRecovery": True,
                    "bidirectionalRustTransfers": True,
                    "sourcePersistenceAfterRestart": True,
                    "sourceControlOperations": True,
                    "destructiveTransferDelete": True,
                },
                "transfers": {
                    "primary": {
                        "hash": str(result["hash"]).lower(),
                        "name": transfer["name"],
                        "sizeBytes": int(transfer["sizeBytes"]),
                    },
                    "unicode": {
                        "hash": str(unicode_result["hash"]).lower(),
                        "name": unicode_transfer["name"],
                        "sizeBytes": int(unicode_transfer["sizeBytes"]),
                    },
                    "hashOnly": {
                        "hash": hash_only_hash,
                        "hashOnlyLink": hash_only_link,
                        "name": hash_only_transfer["name"],
                        "sizeBytes": int(hash_only_transfer["sizeBytes"]),
                    },
                    "reverse": {
                        "hash": str(reverse_result["hash"]).lower(),
                        "name": reverse_transfer["name"],
                        "sizeBytes": int(reverse_transfer["sizeBytes"]),
                    },
                },
                "sources": {
                    "persistedEndpoint": persisted_endpoint,
                    "persistedClientId": persisted_source["clientId"],
                    "reverseEndpoint": f"{lan_host}:{leecher_ed2k_port}",
                },
            }
        )
    finally:
        if remembered_leecher_process is not None:
            terminate_process(remembered_leecher_process)
        terminate_process(leecher_process)
        terminate_process(seeder_process)
        goed2k.stop_process(server_process)
        goed2k.stop_server_processes()
