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


API_KEY = "test-api-key"
SEED_HASH = "00112233445566778899aabbccddeeff"
SERVER_SEARCH_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
SERVER_SEARCH_NAME = "Rust.Live.Search.Fixture.bin"


def workspace_root() -> Path:
    return Path(__file__).resolve().parents[4]


def free_lan_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def free_lan_port_not(host: str, forbidden: set[int]) -> int:
    for _ in range(100):
        port = free_lan_port(host)
        if port not in forbidden:
            forbidden.add(port)
            return port
    raise RuntimeError(f"could not find a free LAN port outside {sorted(forbidden)}")


def free_goed2k_server_port(host: str) -> int:
    for _ in range(100):
        port = free_lan_port(host)
        if port <= 65531:
            return port
    raise RuntimeError("could not find a free goed2k server port with UDP offset room")


def write_config(
    path: Path,
    runtime_dir: Path,
    lan_host: str,
    port: int,
    *,
    ed2k_server_endpoint: str | None = None,
    ed2k_listen_port: int | None = None,
    kad_listen_port: int | None = None,
) -> None:
    lines = [
        f'runtimeDir = "{runtime_dir.as_posix()}"',
    ]
    if ed2k_server_endpoint is not None:
        if ed2k_listen_port is None or kad_listen_port is None:
            raise ValueError("ED2K configs require ed2k_listen_port and kad_listen_port")
        lines.extend(
            [
                f'p2pBindIp = "{lan_host}"',
                "",
            ]
        )
    lines.extend(
        [
            "[rest]",
            f'bindAddr = "{lan_host}:{port}"',
            f'apiKey = "{API_KEY}"',
            "",
        ]
    )
    if ed2k_server_endpoint is not None:
        lines.extend(
            [
                "[kad]",
                f"listenPort = {kad_listen_port}",
                "",
                "[ed2k]",
                f"listenPort = {ed2k_listen_port}",
                f'serverEndpoints = ["{ed2k_server_endpoint}"]',
                "connectTimeoutSecs = 1",
                "reconnectIntervalSecs = 60",
                "",
            ]
        )
    path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


def seed_index(index_path: Path) -> None:
    index_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(index_path) as conn:
        conn.executescript(
            """
            CREATE TABLE files (
                id INTEGER PRIMARY KEY,
                ed2k_hash BLOB NOT NULL UNIQUE,
                size_bytes INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                availability_score INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER NOT NULL DEFAULT (unixepoch()),
                last_seen INTEGER NOT NULL DEFAULT (unixepoch())
            );

            CREATE TABLE file_names (
                id INTEGER PRIMARY KEY,
                file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                normalized_name TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 1,
                first_seen INTEGER NOT NULL DEFAULT (unixepoch()),
                last_seen INTEGER NOT NULL DEFAULT (unixepoch()),
                UNIQUE(file_id, normalized_name)
            );

            CREATE VIRTUAL TABLE file_name_fts USING fts5(
                name,
                normalized_name,
                content='file_names',
                content_rowid='id',
                tokenize = 'unicode61 remove_diacritics 2 tokenchars ''.-_'''
            );

            CREATE TRIGGER file_names_ai AFTER INSERT ON file_names BEGIN
                INSERT INTO file_name_fts(rowid, name, normalized_name)
                VALUES (new.id, new.name, new.normalized_name);
            END;
            """
        )
        conn.execute(
            """
            INSERT INTO files(ed2k_hash, size_bytes, content_type, availability_score)
            VALUES (x'00112233445566778899aabbccddeeff', 4096, 'archive', 2)
            """
        )
        conn.execute(
            """
            INSERT INTO file_names(file_id, name, normalized_name)
            VALUES (1, 'Scenario.File.bin', 'scenario file bin')
            """
        )


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


def admin_json(base_url: str, path: str, token: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"{base_url}{path}",
        headers={"X-Admin-Token": token},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


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


def wait_for_goed2k_admin(base_url: str, token: str, process: subprocess.Popen[str], output_path: Path) -> None:
    def probe() -> bool:
        if process.poll() is not None:
            raise AssertionError(f"goed2k-server exited early with code {process.returncode}\n{process_output(output_path)}")
        payload = admin_json(base_url, "/api/stats", token)
        return bool(payload.get("ok"))

    wait_for_condition("goed2k-server admin API", 30, probe)


def write_goed2k_catalog(path: Path, source_host: str, source_port: int) -> None:
    path.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "hash": SERVER_SEARCH_HASH.upper(),
                        "name": SERVER_SEARCH_NAME,
                        "size": 4096,
                        "file_type": "Archive",
                        "extension": "bin",
                        "sources": 1,
                        "complete_sources": 1,
                        "endpoints": [{"host": source_host, "port": source_port}],
                    }
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def write_empty_goed2k_catalog(path: Path) -> None:
    path.write_text('{"files":[]}\n', encoding="utf-8")


def write_goed2k_config(
    path: Path,
    *,
    listen_host: str,
    listen_port: int,
    admin_port: int,
    token: str,
    catalog_path: Path,
) -> None:
    path.write_text(
        json.dumps(
            {
                "listen_address": f"{listen_host}:{listen_port}",
                "admin_listen_address": f"{listen_host}:{admin_port}",
                "admin_token": token,
                "server_name": "emulebb-rust-local-ed2k",
                "server_description": "eMuleBB Rust local ED2K test server",
                "storage_backend": "json",
                "catalog_path": str(catalog_path),
                "search_batch_size": 20,
                "server_udp": True,
                "udp_port_offset": 4,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def test_emulebb_rust_local_search_download_flow(tmp_path: Path) -> None:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not available")
    repo = workspace_root() / "repos" / "emulebb-rust"
    if not repo.is_dir():
        pytest.skip("emulebb-rust repo is not available")
    lan_host = os.environ.get("X_LOCAL_IP")
    if not lan_host:
        pytest.skip("X_LOCAL_IP is required for LAN-bound harness control traffic")

    runtime_dir = tmp_path / "runtime"
    config_path = tmp_path / "emulebb-rust.toml"
    output_path = tmp_path / "emulebb-rust.out"
    port = free_lan_port(lan_host)
    write_config(config_path, runtime_dir, lan_host, port)
    seed_index(runtime_dir / "index.sqlite")

    with output_path.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(
            [
                "cargo",
                "run",
                "-p",
                "emulebb-daemon",
                "--bin",
                "emulebb-rust",
                "--",
                "--config",
                str(config_path),
            ],
            cwd=repo,
            stdout=output,
            stderr=subprocess.STDOUT,
            text=True,
        )
    try:
        base_url = f"http://{lan_host}:{port}"
        wait_for_rest(base_url, process, output_path)

        app = request_json(base_url, "GET", "/api/v1/app")
        assert app["data"]["name"] == "eMuleBB Rust"
        assert "rest.emulebb.v1" in app["data"]["capabilities"]

        search = request_json(
            base_url,
            "POST",
            "/api/v1/searches",
            {"query": "scenario file", "method": "automatic", "type": ""},
        )["data"]
        assert search["status"] == "completed"
        assert search["results"][0]["hash"] == SEED_HASH

        search_id = search["id"]
        transfer = request_json(
            base_url,
            "POST",
            f"/api/v1/searches/{search_id}/results/{SEED_HASH}/operations/download",
        )["data"]
        assert transfer["hash"] == SEED_HASH
        assert transfer["state"] == "queued"

        transfers = request_json(base_url, "GET", "/api/v1/transfers")["data"]["items"]
        assert [row["hash"] for row in transfers] == [SEED_HASH]
        assert (runtime_dir / "transfers" / SEED_HASH / "resume-manifest.json").is_file()
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

    runtime_dir = tmp_path / "runtime"
    config_path = tmp_path / "emulebb-rust.toml"
    output_path = tmp_path / "emulebb-rust.out"
    port = free_lan_port(lan_host)
    ed2k_port = free_lan_port(lan_host)
    kad_port = free_lan_port(lan_host)
    write_config(
        config_path,
        runtime_dir,
        lan_host,
        port,
        ed2k_server_endpoint="192.0.2.20:4661",
        ed2k_listen_port=ed2k_port,
        kad_listen_port=kad_port,
    )

    with output_path.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(
            [
                "cargo",
                "run",
                "-p",
                "emulebb-daemon",
                "--bin",
                "emulebb-rust",
                "--",
                "--config",
                str(config_path),
            ],
            cwd=repo,
            stdout=output,
            stderr=subprocess.STDOUT,
            text=True,
        )
    try:
        base_url = f"http://{lan_host}:{port}"
        wait_for_rest(base_url, process, output_path)

        servers = request_json(base_url, "GET", "/api/v1/servers")["data"]["items"]
        assert [server["endpoint"] for server in servers] == ["192.0.2.20:4661"]

        connected = request_json(base_url, "POST", "/api/v1/servers/operations/connect")["data"]
        assert connected["running"] is True
        assert connected["connected"] is False

        status = request_json(base_url, "GET", "/api/v1/status")["data"]
        assert status["ed2k"]["running"] is True

        disconnected = request_json(base_url, "POST", "/api/v1/servers/operations/disconnect")["data"]
        assert disconnected["running"] is False
        assert disconnected["connected"] is False
    finally:
        terminate_process(process)


def test_emulebb_rust_searches_local_goed2k_server_catalog(tmp_path: Path) -> None:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not available")
    if shutil.which("go") is None:
        pytest.skip("go is not available")
    rust_repo = workspace_root() / "repos" / "emulebb-rust"
    server_repo = workspace_root() / "repos" / "goed2k-server"
    if not rust_repo.is_dir() or not server_repo.is_dir():
        pytest.skip("emulebb-rust or goed2k-server repo is not available")
    lan_host = os.environ.get("X_LOCAL_IP")
    if not lan_host:
        pytest.skip("X_LOCAL_IP is required for LAN-bound harness control traffic")

    server_root = tmp_path / "goed2k"
    server_root.mkdir()
    server_port = free_goed2k_server_port(lan_host)
    admin_port = free_lan_port(lan_host)
    forbidden_ports = {server_port, admin_port, server_port + 4}
    rust_ed2k_port = free_lan_port_not(lan_host, forbidden_ports)
    rust_kad_port = free_lan_port_not(lan_host, forbidden_ports)
    admin_token = "goed2k-test-token"
    catalog_path = server_root / "catalog.json"
    server_config_path = server_root / "config.json"
    server_output_path = tmp_path / "goed2k-server.out"
    write_goed2k_catalog(catalog_path, lan_host, rust_ed2k_port)
    write_goed2k_config(
        server_config_path,
        listen_host=lan_host,
        listen_port=server_port,
        admin_port=admin_port,
        token=admin_token,
        catalog_path=catalog_path,
    )

    with server_output_path.open("w", encoding="utf-8") as server_output:
        server_process = subprocess.Popen(
            ["go", "run", "./cmd/goed2k-server", "-config", str(server_config_path)],
            cwd=server_repo,
            stdout=server_output,
            stderr=subprocess.STDOUT,
            text=True,
        )

    rust_runtime_dir = tmp_path / "runtime"
    rust_config_path = tmp_path / "emulebb-rust.toml"
    rust_output_path = tmp_path / "emulebb-rust.out"
    rust_port = free_lan_port(lan_host)
    write_config(
        rust_config_path,
        rust_runtime_dir,
        lan_host,
        rust_port,
        ed2k_server_endpoint=f"{lan_host}:{server_port}",
        ed2k_listen_port=rust_ed2k_port,
        kad_listen_port=rust_kad_port,
    )

    with rust_output_path.open("w", encoding="utf-8") as rust_output:
        rust_process = subprocess.Popen(
            [
                "cargo",
                "run",
                "-p",
                "emulebb-daemon",
                "--bin",
                "emulebb-rust",
                "--",
                "--config",
                str(rust_config_path),
            ],
            cwd=rust_repo,
            stdout=rust_output,
            stderr=subprocess.STDOUT,
            text=True,
        )

    try:
        wait_for_goed2k_admin(f"http://{lan_host}:{admin_port}", admin_token, server_process, server_output_path)
        base_url = f"http://{lan_host}:{rust_port}"
        wait_for_rest(base_url, rust_process, rust_output_path)

        connect = request_json(base_url, "POST", "/api/v1/servers/operations/connect")["data"]
        assert connect["running"] is True

        wait_for_condition(
            "emulebb-rust ED2K server connection",
            30,
            lambda: request_json(base_url, "GET", "/api/v1/status")["data"]["ed2k"]["connected"],
        )

        search = request_json(
            base_url,
            "POST",
            "/api/v1/searches",
            {"query": "Rust.Live.Search.Fixture", "method": "server", "type": ""},
        )["data"]
        results = search["results"]
        assert any(result["hash"] == SERVER_SEARCH_HASH and result["name"] == SERVER_SEARCH_NAME for result in results)
        stats = admin_json(f"http://{lan_host}:{admin_port}", "/api/stats", admin_token)["data"]
        assert int(stats["search_requests"]) >= 1
    finally:
        terminate_process(rust_process)
        terminate_process(server_process)


def test_emulebb_rust_downloads_from_local_rust_peer_via_goed2k_sources(tmp_path: Path) -> None:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not available")
    if shutil.which("go") is None:
        pytest.skip("go is not available")
    rust_repo = workspace_root() / "repos" / "emulebb-rust"
    server_repo = workspace_root() / "repos" / "goed2k-server"
    if not rust_repo.is_dir() or not server_repo.is_dir():
        pytest.skip("emulebb-rust or goed2k-server repo is not available")
    lan_host = os.environ.get("X_LOCAL_IP")
    if not lan_host:
        pytest.skip("X_LOCAL_IP is required for LAN-bound harness control traffic")

    payload_path = tmp_path / "Rust.Peer.Download.Fixture.bin"
    payload = (b"emulebb-rust-ed2k-download-fixture\n" * 256) + b"tail"
    payload_path.write_bytes(payload)

    server_root = tmp_path / "goed2k"
    server_root.mkdir()
    server_port = free_goed2k_server_port(lan_host)
    admin_port = free_lan_port(lan_host)
    forbidden_ports = {server_port, admin_port, server_port + 4}
    admin_token = "goed2k-test-token"
    catalog_path = server_root / "catalog.json"
    server_config_path = server_root / "config.json"
    server_output_path = tmp_path / "goed2k-server.out"
    write_empty_goed2k_catalog(catalog_path)
    write_goed2k_config(
        server_config_path,
        listen_host=lan_host,
        listen_port=server_port,
        admin_port=admin_port,
        token=admin_token,
        catalog_path=catalog_path,
    )

    with server_output_path.open("w", encoding="utf-8") as server_output:
        server_process = subprocess.Popen(
            ["go", "run", "./cmd/goed2k-server", "-config", str(server_config_path)],
            cwd=server_repo,
            stdout=server_output,
            stderr=subprocess.STDOUT,
            text=True,
        )

    seeder_runtime_dir = tmp_path / "seeder-runtime"
    seeder_config_path = tmp_path / "seeder.toml"
    seeder_output_path = tmp_path / "seeder.out"
    seeder_rest_port = free_lan_port_not(lan_host, forbidden_ports)
    seeder_ed2k_port = free_lan_port_not(lan_host, forbidden_ports)
    seeder_kad_port = free_lan_port_not(lan_host, forbidden_ports)
    write_config(
        seeder_config_path,
        seeder_runtime_dir,
        lan_host,
        seeder_rest_port,
        ed2k_server_endpoint=f"{lan_host}:{server_port}",
        ed2k_listen_port=seeder_ed2k_port,
        kad_listen_port=seeder_kad_port,
    )

    leecher_runtime_dir = tmp_path / "leecher-runtime"
    leecher_config_path = tmp_path / "leecher.toml"
    leecher_output_path = tmp_path / "leecher.out"
    leecher_rest_port = free_lan_port_not(lan_host, forbidden_ports)
    leecher_ed2k_port = free_lan_port_not(lan_host, forbidden_ports)
    leecher_kad_port = free_lan_port_not(lan_host, forbidden_ports)
    write_config(
        leecher_config_path,
        leecher_runtime_dir,
        lan_host,
        leecher_rest_port,
        ed2k_server_endpoint=f"{lan_host}:{server_port}",
        ed2k_listen_port=leecher_ed2k_port,
        kad_listen_port=leecher_kad_port,
    )

    with seeder_output_path.open("w", encoding="utf-8") as seeder_output:
        seeder_process = subprocess.Popen(
            [
                "cargo",
                "run",
                "-p",
                "emulebb-daemon",
                "--bin",
                "emulebb-rust",
                "--",
                "--config",
                str(seeder_config_path),
            ],
            cwd=rust_repo,
            stdout=seeder_output,
            stderr=subprocess.STDOUT,
            text=True,
        )
    with leecher_output_path.open("w", encoding="utf-8") as leecher_output:
        leecher_process = subprocess.Popen(
            [
                "cargo",
                "run",
                "-p",
                "emulebb-daemon",
                "--bin",
                "emulebb-rust",
                "--",
                "--config",
                str(leecher_config_path),
            ],
            cwd=rust_repo,
            stdout=leecher_output,
            stderr=subprocess.STDOUT,
            text=True,
        )

    try:
        admin_base_url = f"http://{lan_host}:{admin_port}"
        wait_for_goed2k_admin(admin_base_url, admin_token, server_process, server_output_path)

        seeder_base_url = f"http://{lan_host}:{seeder_rest_port}"
        wait_for_rest(seeder_base_url, seeder_process, seeder_output_path)
        request_json(seeder_base_url, "POST", "/api/v1/servers/operations/connect")["data"]
        wait_for_condition(
            "seeder ED2K server connection",
            30,
            lambda: request_json(seeder_base_url, "GET", "/api/v1/status")["data"]["ed2k"]["connected"],
        )
        share = request_json(
            seeder_base_url,
            "POST",
            "/api/v1/shares",
            {"path": str(payload_path), "name": payload_path.name},
            timeout=30,
        )["data"]
        assert share["name"] == payload_path.name
        assert int(share["sizeBytes"]) == len(payload)

        def server_has_dynamic_share() -> object:
            files = admin_json(admin_base_url, f"/api/files?search={share['hash']}", admin_token)["data"]
            for file in files:
                if file["hash"].lower() == str(share["hash"]).lower() and file["endpoints"]:
                    assert file["endpoints"][0]["host"] == lan_host
                    assert int(file["endpoints"][0]["port"]) == seeder_ed2k_port
                    return file
            return None

        published = wait_for_condition(
            "goed2k dynamic file published by Rust OP_OFFERFILES",
            30,
            server_has_dynamic_share,
        )
        assert published["name"] == payload_path.name

        leecher_base_url = f"http://{lan_host}:{leecher_rest_port}"
        wait_for_rest(leecher_base_url, leecher_process, leecher_output_path)
        request_json(leecher_base_url, "POST", "/api/v1/servers/operations/connect")["data"]
        wait_for_condition(
            "leecher ED2K server connection",
            30,
            lambda: request_json(leecher_base_url, "GET", "/api/v1/status")["data"]["ed2k"]["connected"],
        )

        search = request_json(
            leecher_base_url,
            "POST",
            "/api/v1/searches",
            {"query": "Rust.Peer.Download.Fixture", "method": "server", "type": ""},
            timeout=30,
        )["data"]
        result = next(result for result in search["results"] if result["hash"] == share["hash"])
        request_json(
            leecher_base_url,
            "POST",
            f"/api/v1/searches/{search['id']}/results/{result['hash']}/operations/download",
        )["data"]
        transfer = request_json(
            leecher_base_url,
            "POST",
            f"/api/v1/transfers/{result['hash']}/operations/resume",
            timeout=30,
        )["data"]
        if transfer["state"] != "completed":
            transfer = wait_for_condition(
                "leecher transfer completion",
                30,
                lambda: request_json(leecher_base_url, "GET", f"/api/v1/transfers/{result['hash']}")["data"]
                if request_json(leecher_base_url, "GET", f"/api/v1/transfers/{result['hash']}")["data"]["state"] == "completed"
                else None,
            )
        assert transfer["state"] == "completed"
        assert int(transfer["completedBytes"]) == len(payload)
        assert float(transfer["progress"]) == pytest.approx(1.0)
        sources = request_json(
            leecher_base_url,
            "GET",
            f"/api/v1/transfers/{result['hash']}/sources",
        )["data"]["items"]
        assert any(
            source["ip"] == lan_host
            and int(source["tcpPort"]) == seeder_ed2k_port
            and source["endpoint"] == f"{lan_host}:{seeder_ed2k_port}"
            for source in sources
        )
        downloaded_payload = leecher_runtime_dir / "transfers" / str(result["hash"]) / "pieces.bin"
        assert downloaded_payload.read_bytes() == payload

        terminate_process(leecher_process)
        with leecher_output_path.open("a", encoding="utf-8") as leecher_output:
            leecher_process = subprocess.Popen(
                [
                    "cargo",
                    "run",
                    "-p",
                    "emulebb-daemon",
                    "--bin",
                    "emulebb-rust",
                    "--",
                    "--config",
                    str(leecher_config_path),
                ],
                cwd=rust_repo,
                stdout=leecher_output,
                stderr=subprocess.STDOUT,
                text=True,
            )
        wait_for_rest(leecher_base_url, leecher_process, leecher_output_path)
        persisted_sources = request_json(
            leecher_base_url,
            "GET",
            f"/api/v1/transfers/{result['hash']}/sources",
        )["data"]["items"]
        assert any(
            source["endpoint"] == f"{lan_host}:{seeder_ed2k_port}"
            for source in persisted_sources
        )
    finally:
        terminate_process(leecher_process)
        terminate_process(seeder_process)
        terminate_process(server_process)
