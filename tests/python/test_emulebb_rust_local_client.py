from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

from emule_test_harness import rust_client
from emule_test_harness import rust_metadata
from emule_test_harness.script_modules import load_script_module


API_KEY = "0123456789abcdef0123456789abcdef"
SEED_HASH = "00112233445566778899aabbccddeeff"
SERVER_SEARCH_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
SERVER_SEARCH_NAME = "Rust.Live.Search.Fixture.bin"
ED2K_PART_SIZE = 9_728_000
SERVICE_PORT_START = int(os.environ.get("EMULEBB_RUST_TEST_PORT_START", "30000"))
SERVICE_PORT_END = int(os.environ.get("EMULEBB_RUST_TEST_PORT_END", "45000"))
_ALLOCATED_PORTS: set[int] = set()


dtt = load_script_module("deterministic_two_client_transfer_for_rust_tests", "deterministic-two-client-transfer.py")


def load_rust_rest_smoke_module() -> ModuleType:
    """Loads the shared smoke runner against the forward Rust OpenAPI contract."""

    contract_env = "EMULEBB_REST_OPENAPI_CONTRACT_PATH"
    previous_contract = os.environ.get(contract_env)
    rust_contract = (
        Path(__file__).resolve().parents[4]
        / "repos"
        / "emulebb-tooling"
        / "docs"
        / "products"
        / "emulebb-rust"
        / "api"
        / "REST-API-OPENAPI.yaml"
    )
    os.environ[contract_env] = str(rust_contract)
    try:
        return load_script_module("rest_api_smoke_for_rust_tests", "rest-api-smoke.py")
    finally:
        if previous_contract is None:
            os.environ.pop(contract_env, None)
        else:
            os.environ[contract_env] = previous_contract


rest_smoke = load_rust_rest_smoke_module()


def test_local_client_uses_forward_rust_openapi_contract() -> None:
    expected = (
        workspace_root()
        / "repos"
        / "emulebb-tooling"
        / "docs"
        / "products"
        / "emulebb-rust"
        / "api"
        / "REST-API-OPENAPI.yaml"
    )
    assert rest_smoke.OPENAPI_CONTRACT_PATH == expected


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
    if not metadata_path.exists():
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


def configure_shared_directory(
    base_url: str,
    root: Path,
    expected_names: set[str],
) -> dict[str, dict[str, object]]:
    """Shares one root through the canonical Rust directory mutation surface."""

    request_json(
        base_url,
        "PATCH",
        "/api/v1/shared-directories",
        {"roots": [{"path": str(root)}], "confirmReplaceRoots": True},
        timeout=30,
    )
    request_json(
        base_url,
        "POST",
        "/api/v1/shared-directories/operations/reload",
        timeout=30,
    )

    def probe() -> dict[str, dict[str, object]] | None:
        items = request_json(base_url, "GET", "/api/v1/shared-files", timeout=30)["data"]["items"]
        by_name = {str(item["name"]): item for item in items}
        return by_name if expected_names <= by_name.keys() else None

    return wait_for_condition(
        f"shared files under {root}",
        30,
        probe,
    )


def terminate_process(process: subprocess.Popen[str]) -> None:
    rust_client.stop_process_tree(process, timeout_seconds=5)
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
        assert app["data"]["name"] == "eMuleBB"
        assert app["data"]["capabilities"]["transfers"] is True
        assert "rest.emulebb.v1" not in app["data"]["capabilities"]
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
            "/api/v1/upload-queue/00000000000000000000000000000000",
        )
        assert missing_upload_status == 404
        assert missing_upload_error["error"]["code"] == "NOT_FOUND"
        missing_confirm_status, missing_confirm_error = request_json_status(
            base_url,
            "PATCH",
            "/api/v1/shared-directories",
            {"roots": [{"path": str(shared_root)}], "confirmReplaceRoots": False},
        )
        assert missing_confirm_status == 400
        assert "confirmReplaceRoots" in json.dumps(missing_confirm_error)
        shared_directories = request_json(
            base_url,
            "PATCH",
            "/api/v1/shared-directories",
            {"roots": [{"path": str(shared_root)}], "confirmReplaceRoots": True},
        )["data"]
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
        shared_files = request_json(base_url, "GET", "/api/v1/shared-files")["data"]["items"]
        shared_file_names = {row["name"] for row in shared_files}
        assert {shared_top_file.name, shared_nested_file.name} <= shared_file_names
        top_shared_file = next(row for row in shared_files if row["name"] == shared_top_file.name)
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
        assert shared_top_file.is_file()
        assert shared_nested_file.is_file()
        snapshot = request_json(base_url, "GET", "/api/v1/snapshot?limit=1")["data"]
        assert snapshot["app"]["name"] == "eMuleBB"
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
        assert bootstrapped_kad["connected"] is False
        assert bootstrapped_kad["firewallState"] == "unknown"
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
            {"priority": "high", "displayName": "Rejected.bin"},
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
            {"displayName": " Scenario Renamed.bin "},
        )["data"]
        assert renamed_transfer["displayName"] == "Scenario Renamed.bin"
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
        assert reloaded_transfer["displayName"] == "Scenario Renamed.bin"

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
        assert deleted_server["enabled"] is False
        disabled_server = request_json(base_url, "GET", "/api/v1/servers/192.0.2.21:4661")["data"]
        assert disabled_server["address"] == "192.0.2.21"
        assert disabled_server["port"] == 4661
        assert disabled_server["enabled"] is False
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
        assert connected["serverCount"] == 2
        assert connected["connected"] is False

        status = request_json(base_url, "GET", "/api/v1/status")["data"]
        assert status["servers"]["serverCount"] == 2

        disconnect_status, disconnect_payload = request_json_status(
            base_url,
            "POST",
            "/api/v1/servers/operations/disconnect",
        )
        assert disconnect_status == 200, disconnect_payload
        disconnected = disconnect_payload["data"]
        assert disconnected["serverCount"] == 2
        assert disconnected["connected"] is False
    finally:
        terminate_process(process)
