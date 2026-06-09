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
from pathlib import Path

import pytest


API_KEY = "test-api-key"
SEED_HASH = "00112233445566778899aabbccddeeff"


def workspace_root() -> Path:
    return Path(__file__).resolve().parents[4]


def free_lan_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def write_config(
    path: Path,
    runtime_dir: Path,
    lan_host: str,
    port: int,
    *,
    ed2k_server_endpoint: str | None = None,
) -> None:
    lines = [
        f'runtimeDir = "{runtime_dir.as_posix()}"',
    ]
    if ed2k_server_endpoint is not None:
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
                "[ed2k]",
                "listenPort = 41001",
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


def request_json(base_url: str, method: str, path: str, body: dict[str, object] | None = None) -> dict[str, object]:
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
    write_config(
        config_path,
        runtime_dir,
        lan_host,
        port,
        ed2k_server_endpoint="192.0.2.20:4661",
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
