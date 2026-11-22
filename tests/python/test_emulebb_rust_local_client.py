from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from emule_test_harness.paths import get_required_emule_workspace_root as _workspace_root_from_environment
from emule_test_harness.paths import get_workspace_output_root
from types import ModuleType

import pytest

from emule_test_harness import rust_client
from emule_test_harness import rust_rest_conformance
from emule_test_harness.workspace_layout import resolve_selected_workspace_repo
from emule_test_harness.rust_local_ed2k import require_download_id, require_download_batch, publish_shared_tree
from emule_test_harness.rust_rest_contract import iter_library_files, settings_patch
from emule_test_harness.local_kad_peer import LocalKadPeer
from emule_test_harness.kad_nodes import BootstrapContact
from emule_test_harness.script_modules import load_script_module


API_KEY = "0123456789abcdef0123456789abcdef"
SEED_HASH = "00112233445566778899aabbccddeeff"
SERVICE_PORT_START = int(os.environ.get("EMULEBB_RUST_TEST_PORT_START", "30000"))
SERVICE_PORT_END = int(os.environ.get("EMULEBB_RUST_TEST_PORT_END", "45000"))
_ALLOCATED_PORTS: set[int] = set()


dtt = load_script_module("deterministic_two_client_transfer_for_rust_tests", "deterministic-two-client-transfer.py")


def load_rust_rest_smoke_module() -> ModuleType:
    """Loads the shared smoke runner against the forward Rust OpenAPI contract."""

    rust_contract = (resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-tooling")
                     / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml")
    return rust_rest_conformance.load_rest_smoke_module(rust_contract)


rest_smoke = load_rust_rest_smoke_module()


def test_local_client_uses_forward_rust_openapi_contract() -> None:
    expected = (resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-tooling")
                / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml")
    assert rest_smoke.OPENAPI_CONTRACT_PATH == expected


def workspace_root() -> Path:
    return _workspace_root_from_environment()


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


def write_profile(
    profile_dir: Path,
    lan_host: str,
    port: int,
    *,
    ed2k_server_endpoint: str | None = None,
    ed2k_listen_port: int | None = None,
    kad_listen_port: int | None = None,
    kad_bootstrap_nodes: list[str] | None = None,
    local_kad_seed: BootstrapContact | None = None,
) -> None:
    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=resolve_selected_workspace_repo(Path(__file__).parents[2], 'emulebb-rust'),
        rest_addr=lan_host,
        rest_port=port,
        api_key=API_KEY,
        server_endpoint=ed2k_server_endpoint,
        kad_bootstrap_nodes=kad_bootstrap_nodes,
        local_only_discovery=True,
        local_kad_seed=local_kad_seed,
        settings={
            'network.p2p.bindIp': lan_host if ed2k_server_endpoint is not None else None,
            **({'network.p2p.tcpPort': ed2k_listen_port} if ed2k_listen_port is not None else {}),
            **({'network.p2p.udpPort': kad_listen_port} if kad_listen_port is not None else {}),
            'network.kadEnabled': True,
            # LocalKadPeer is an explicit plaintext wire fixture.
            **({'security.obfuscationEnabled': False} if local_kad_seed is not None else {}),
            'network.connections.connectTimeoutSeconds': 10,
            'network.servers.reconnectIntervalSeconds': 60,
        },
    )


def write_rust_peer_exchange_report(report: dict[str, object]) -> None:
    """Writes optional structured Rust peer-exchange evidence for matrix runs."""

    report_path = os.environ.get("EMULEBB_RUST_PEER_EXCHANGE_REPORT")
    if not report_path:
        return
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
    try:
        with opener.open(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise AssertionError(f"{method} {path} returned HTTP {error.code}: {detail}") from error


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
            payload = response.read().decode("utf-8")
            return response.status, json.loads(payload) if payload else {}
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


@pytest.fixture
def local_kad_peer() -> Iterator[LocalKadPeer]:
    """Declare and close the isolated peer used by the native profile."""
    lan_host = os.environ.get("X_LOCAL_IP")
    if not lan_host:
        pytest.fail("X_LOCAL_IP is required for the explicitly selected native Kad case")
    peer = LocalKadPeer(lan_host, {lan_host})
    peer.start()
    try:
        yield peer
    finally:
        peer.close()


@pytest.mark.native
def test_emulebb_rust_local_search_download_flow(tmp_path: Path, local_kad_peer: LocalKadPeer) -> None:
    repo = resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-rust")
    stage = rust_client.verified_runtime_stage(repo, get_workspace_output_root())
    executable = Path(stage["executable"])
    (tmp_path / "stage-input.json").write_text(json.dumps({
        "stage": stage, "harnessSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
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
    write_profile(
        profile_dir,
        lan_host,
        port,
        ed2k_server_endpoint=f"{lan_host}:{free_lan_port(lan_host)}",
        ed2k_listen_port=free_lan_port(lan_host),
        kad_listen_port=free_lan_port(lan_host),
        local_kad_seed=BootstrapContact(lan_host, local_kad_peer.udp_port, local_kad_peer.tcp_port),
    )

    process = rust_client.start_rust_client_executable(executable, profile_dir, output_path)
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
        assert app["data"]["capabilities"]["downloads"] is True
        settings = request_json(base_url, "GET", "/api/v1/settings")
        assert settings["data"]["effective"]["transfers"]["uploadLimitBytesPerSecond"] > 0
        updated_settings = request_json(base_url, "PATCH", "/api/v1/settings", settings_patch(
            settings, set_values={"transfers": {"uploadLimitBytesPerSecond": 2097152, "maxSourcesPerFile": 500}},
        ))
        assert updated_settings["data"]["saved"]["transfers"]["uploadLimitBytesPerSecond"] == {"mode": "custom", "value": 2097152}
        assert updated_settings["data"]["saved"]["transfers"]["maxSourcesPerFile"]["value"] == 500
        empty_settings_status, _ = request_json_status(base_url, "PATCH", "/api/v1/settings", {
            "expectedRevision": updated_settings["meta"]["settingsRevision"], "set": {},
        })
        assert empty_settings_status == 400
        categories = request_json(base_url, "GET", "/api/v1/categories")["data"]["items"]
        assert categories == []
        created_category = request_json(base_url, "POST", "/api/v1/categories", {
            "name": "Harness-Media", "destinationDir": str(tmp_path / "category-output"), "comment": "daemon category",
        })["data"]
        assert created_category["name"] == "Harness-Media"
        updated_category = request_json(base_url, "PATCH", "/api/v1/categories/harness-media", {
            "destinationDir": None, "comment": "updated category",
        })["data"]
        assert updated_category["name"] == "Harness-Media"
        assert updated_category["destinationDir"] is None
        assert updated_category["comment"] == "updated category"
        assert request_json(base_url, "DELETE", "/api/v1/categories/Harness-Media")["data"]["ok"] is True
        assert request_json_status(base_url, "GET", "/api/v1/categories/Harness-Media")[0] == 404
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
        assert request_json(base_url, "GET", "/api/v1/uploads")["data"] == []
        upload_queue = request_json(base_url, "GET", "/api/v1/upload-queue?countTotal=true")
        assert upload_queue["data"] == []
        assert upload_queue["meta"]["total"] == 0
        assert upload_queue["meta"]["hasMore"] is False
        assert upload_queue["meta"]["nextCursor"] is None
        missing_upload_status, missing_upload_error = request_json_status(
            base_url,
            "GET",
            "/api/v1/upload-queue/12345678-1234-4234-8234-123456789abc",
        )
        assert missing_upload_status == 404
        assert missing_upload_error["error"]["code"] == "NOT_FOUND"
        published = publish_shared_tree(base_url, API_KEY, root=shared_root, file_name=shared_top_file.name)
        root_id = published["directories"]["id"]
        root = request_json(base_url, "GET", f"/api/v1/library/roots/{root_id}")["data"]
        assert root["accessible"] is True and root["watchEnabled"] is False
        assert Path(root["path"]).samefile(shared_root)
        roots = request_json(base_url, "GET", "/api/v1/library/roots")["data"]
        assert any(row["id"] == root_id for row in roots)
        overlap_status, _ = request_json_status(base_url, "POST", "/api/v1/library/roots", {"path": str(nested_shared_root)})
        assert overlap_status == 409
        shared_files = list(iter_library_files(
            lambda path: request_json(base_url, "GET", "/api/v1" + path), view="shared", root_id=root_id,
        ))
        assert {shared_top_file.name, shared_nested_file.name} <= {row["displayName"] for row in shared_files}
        top_shared_file = published["sharedFiles"]["matched"]
        file_resource = f"/api/v1/library/files/{top_shared_file['hash']}"
        for invalid in ({}, {"rating": 5}):
            invalid_status, _ = request_json_status(base_url, "PATCH", file_resource, invalid)
            assert invalid_status == 400
        edit_status, edit_body = request_json_status(base_url, "PATCH", file_resource, {
            "uploadPriority": "release", "comment": "Harness share comment", "rating": 4,
        })
        assert edit_status == 204 and edit_body == {}
        persisted_shared_file = request_json(base_url, "GET", file_resource)["data"]
        assert persisted_shared_file["uploadPriority"] == "release"
        assert persisted_shared_file["comment"] == "Harness share comment"
        assert persisted_shared_file["rating"] == 4
        assert shared_top_file.is_file()
        assert shared_nested_file.is_file()
        snapshot = request_json(base_url, "GET", "/api/v1/snapshot?limit=1")["data"]
        assert snapshot["app"]["name"] == "eMuleBB"
        assert snapshot["status"]["lifecycle"]["state"] == "running"
        assert snapshot["downloads"] == {"unfinished": 0, "completed": 0}
        assert snapshot["status"]["runtimeDiagnostics"]["sharedFileCount"] >= 2
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
        # The shared runtime is created explicitly through local server connect.
        request_json(base_url, "POST", "/api/v1/servers/operations/connect", timeout=30)
        bootstrapped_kad = request_json(base_url, "POST", "/api/v1/kad/operations/bootstrap", {
            "address": lan_host, "port": local_kad_peer.udp_port,
        }, timeout=30)["data"]
        assert bootstrapped_kad["running"] is True
        def observed_local_kad():
            status = request_json(base_url, "GET", "/api/v1/kad")["data"]
            evidence = local_kad_peer.evidence()
            if not (status["running"] and status["contactCount"] >= 1 and evidence.get("routingReplies", 0) > 0):
                raise AssertionError(json.dumps({"kad": status, "peer": evidence}, sort_keys=True))
            return status
        observed_kad = wait_for_condition("the declared local Kad peer exchange", 30, observed_local_kad)
        # One real peer proves routing exchange, not the ten-contact readiness threshold.
        assert observed_kad["connected"] is False and observed_kad["bootstrapping"] is True
        recheck_kad = request_json(
            base_url,
            "POST",
            "/api/v1/kad/operations/recheck-firewall",
        )["data"]
        assert recheck_kad["operationQueued"] is True
        assert isinstance(recheck_kad["alreadyRunning"], bool)
        stopped_kad = request_json(base_url, "POST", "/api/v1/kad/operations/stop")["data"]
        assert stopped_kad["running"] is False
        assert stopped_kad["connected"] is False
        request_json(base_url, "POST", "/api/v1/servers/operations/disconnect")
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

        settings = request_json(base_url, "GET", "/api/v1/settings")
        restored_settings = request_json(base_url, "PATCH", "/api/v1/settings", settings_patch(
            settings, reset=("transfers.uploadLimitBytesPerSecond", "transfers.maxSourcesPerFile"),
        ))
        assert restored_settings["data"]["saved"]["transfers"]["uploadLimitBytesPerSecond"]["mode"] == "default"

        search = request_json(
            base_url,
            "POST",
            "/api/v1/searches",
            {"query": "scenario file", "method": "automatic"},
        )["data"]
        assert search["status"] == "queued"
        search_resource = f"/api/v1/searches/{search['id']}"
        header = request_json(base_url, "GET", search_resource)["data"]
        assert header["id"] == search["id"] and header["resultCount"] == 0
        results = request_json(base_url, "GET", search_resource + "/results?limit=100")
        assert results["data"] == [] and results["meta"]["hasMore"] is False
        assert request_json_status(base_url, "POST", search_resource + "/stop")[0] == 204
        assert request_json(base_url, "GET", search_resource)["data"]["status"] == "stopped"

        admission = request_json(base_url, "POST", "/api/v1/downloads", {
            "source": {"type": "content", "hash": SEED_HASH, "name": "Scenario.File.bin",
                       "sizeBytes": 4096}, "intent": "stopped",
        })["data"]
        download_id = require_download_id(admission, expected_hash=SEED_HASH)
        resource = f"/api/v1/downloads/{download_id}"
        download = request_json(base_url, "GET", resource)["data"]
        assert download["id"] == download_id and download["hash"] == SEED_HASH
        assert download["state"] == "stopped" and download["intent"] == "stopped"
        assert download["payloadVerified"] is False
        parts = request_json(base_url, "GET", resource + "/parts?limit=200")
        assert parts["meta"]["hasMore"] is False
        assert len(parts["data"]) == 1
        part = parts["data"][0]
        assert part == {"index": 0, "start": 0, "end": 4095, "sizeBytes": 4096,
                        "presentBytes": 0, "complete": False, "corrupted": False}
        for collection in ("sources", "comments"):
            page = request_json(base_url, "GET", resource + f"/{collection}?limit=200")
            assert page["data"] == [] and page["meta"]["hasMore"] is False
        assert request_json_status(base_url, "GET", "/api/v1/downloads/9223372036854775807")[0] == 404
        request_json(base_url, "POST", "/api/v1/categories", {"name": "Harness-Downloads"})
        patch_status, _ = request_json_status(base_url, "PATCH", resource, {
            "name": "Scenario Renamed.bin", "category": "harness-downloads",
        })
        assert patch_status == 204
        updated = request_json(base_url, "GET", resource)["data"]
        assert updated["name"] == "Scenario Renamed.bin" and updated["category"] == "Harness-Downloads"
        jobs = request_json(base_url, "GET", "/api/v1/downloads?limit=100")
        assert any(row["id"] == download_id and row["state"] == "stopped" for row in jobs["data"])

        # Restart must preserve the same job identity, intent and presentation.
        terminate_process(process)
        process = rust_client.start_rust_client_executable_append(executable, profile_dir, output_path)
        wait_for_rest(base_url, process, output_path)
        reloaded = request_json(base_url, "GET", resource)["data"]
        assert reloaded["id"] == download_id and reloaded["state"] == "stopped"
        assert reloaded["name"] == "Scenario Renamed.bin" and reloaded["category"] == "Harness-Downloads"
        for action in ("start", "stop"):
            reply = request_json(base_url, "POST", f"/api/v1/downloads/{action}", {"ids": [download_id]})
            require_download_batch(reply, download_id)
        removed = request_json(base_url, "POST", "/api/v1/downloads/remove", {
            "ids": [download_id], "deleteData": False,
        })
        require_download_batch(removed, download_id)
        assert request_json_status(base_url, "GET", resource)[0] == 404
        assert shared_top_file.read_bytes() == b"emulebb-rust shared root fixture"
        assert shared_nested_file.read_bytes() == b"emulebb-rust nested shared root fixture"
        denied_search_clear_status, denied_search_clear_error = request_json_status(
            base_url,
            "DELETE",
            "/api/v1/searches",
        )
        assert denied_search_clear_status == 400
        assert "confirm" in denied_search_clear_error["error"]["message"]
        cleared_searches = request_json(base_url, "DELETE", "/api/v1/searches?confirm=true")["data"]
        assert cleared_searches["ok"] is True
        searches_after_clear = request_json(base_url, "GET", "/api/v1/searches")["data"]
        assert searches_after_clear == []
    finally:
        terminate_process(process)


@pytest.mark.native
def test_emulebb_rust_server_connect_uses_configured_p2p_bind(tmp_path: Path) -> None:
    repo = resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-rust")
    stage = rust_client.verified_runtime_stage(repo, get_workspace_output_root())
    executable = Path(stage["executable"])
    lan_host = os.environ.get("X_LOCAL_IP")
    if not lan_host:
        pytest.fail("X_LOCAL_IP is required for the explicitly selected native server-bind case")
    (tmp_path / "native-input.json").write_text(json.dumps({
        "stage": stage, "harnessSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": "REST server operations with configured P2P bind; not observed socket-source-IP proof",
    }, indent=2) + "\n", encoding="utf-8", newline="\n")

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

    process = rust_client.start_rust_client_executable(executable, profile_dir, output_path)
    try:
        base_url = f"http://{lan_host}:{port}"
        wait_for_rest(base_url, process, output_path)

        servers = request_json(base_url, "GET", "/api/v1/servers")["data"]
        assert [(server["address"], server["port"]) for server in servers] == [("192.0.2.20", 4661)]
        configured_server = request_json(base_url, "GET", f"/api/v1/servers/{servers[0]['id']}")["data"]
        assert configured_server["address"] == "192.0.2.20" and configured_server["port"] == 4661
        identity = request_json(base_url, "POST", "/api/v1/servers", {
            "address": "192.0.2.21", "port": 4661, "priority": "low", "static": False,
        })["data"]["id"]
        resource = f"/api/v1/servers/{identity}"
        created_server = request_json(base_url, "GET", resource)["data"]
        assert created_server["address"] == "192.0.2.21" and created_server["priority"] == "low"
        assert request_json_status(base_url, "PATCH", resource, {"priority": "high", "static": True, "enabled": False})[0] == 204
        disabled_server = request_json(base_url, "GET", resource)["data"]
        assert disabled_server["priority"] == "high" and disabled_server["static"] is True
        assert disabled_server["enabled"] is False
        assert request_json_status(base_url, "DELETE", resource)[0] == 204
        assert request_json_status(base_url, "GET", resource)[0] == 404
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

        disconnect_status, disconnect_payload = request_json_status(
            base_url,
            "POST",
            "/api/v1/servers/operations/disconnect",
        )
        assert disconnect_status == 200, disconnect_payload
        disconnected = disconnect_payload["data"]
        assert disconnected["serverCount"] == 1
        assert disconnected["connected"] is False
    finally:
        terminate_process(process)
