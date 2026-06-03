"""Python guest runner for visible Windows VM local ED2K transfer tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

try:
    from emule_test_harness.vm_guest_profiles import (
        api_data,
        api_rows,
        emit,
        http_json,
        local_ed2k_preferences_text as preferences_text,
        repair_firewall,
        retry_http_json as _retry_http_json,
        run,
        start_visible_app,
        wait_until,
        write_preferences_ini,
    )
except ModuleNotFoundError:
    from vm_guest_profiles import (
        api_data,
        api_rows,
        emit,
        http_json,
        local_ed2k_preferences_text as preferences_text,
        repair_firewall,
        retry_http_json as _retry_http_json,
        run,
        start_visible_app,
        wait_until,
        write_preferences_ini,
    )


def status_servers(payload: Any) -> dict[str, Any]:
    """Returns the server status object from /api/v1/status."""

    data = api_data(payload)
    if not isinstance(data, dict):
        return {}
    servers = data.get("servers")
    return servers if isinstance(servers, dict) else {}


def matching_server_row(rows: list[dict[str, Any]], address: str, port: int) -> dict[str, Any] | None:
    """Finds a REST server row by endpoint."""

    for row in rows:
        if str(row.get("address")) == address and int(row.get("port", 0)) == port:
            return row
    return None


def read_server_status(base_url: str, api_key: str) -> dict[str, Any]:
    """Reads the server status snapshot with transient REST retry."""

    return status_servers(
        retry_http_json(
            "server status",
            3,
            base_url,
            "/api/v1/status",
            api_key=api_key,
        )
    )


def retry_http_json(description: str, attempts: int, base_url: str, path: str, **kwargs: Any) -> Any:
    """Retries REST through the runner-level request function for tests and live guest use."""

    return _retry_http_json(description, attempts, base_url, path, request_func=http_json, **kwargs)


def guest_ipv4() -> str:
    """Returns a non-loopback IPv4 address for VM-to-VM traffic."""

    candidates: set[str] = set()
    for host in {socket.gethostname(), socket.getfqdn(), ""}:
        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(host, None, socket.AF_INET):
                if family == socket.AF_INET and sockaddr:
                    candidates.add(str(sockaddr[0]))
        except OSError:
            continue
    usable = sorted(address for address in candidates if not address.startswith("127.") and address != "0.0.0.0")
    if not usable:
        raise RuntimeError("No non-loopback IPv4 address is available in the guest.")
    return usable[0]


def write_deterministic_file(path: Path, *, size: int, seed: int) -> str:
    """Creates one deterministic fixture and returns its SHA-256."""

    path.parent.mkdir(parents=True, exist_ok=True)
    block = bytes((index + seed) % 251 for index in range(1024 * 1024))
    remaining = size
    with path.open("wb") as handle:
        while remaining:
            chunk = block[: min(len(block), remaining)]
            handle.write(chunk)
            remaining -= len(chunk)
    return sha256_file(path)


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def ed2k_link_with_source(link: str, *, source_ip: str, source_port: int) -> str:
    """Adds a deterministic local source hint to an ED2K file link."""

    if not source_ip or source_port <= 0 or "|sources," in link:
        return link
    if not link.endswith("|/"):
        raise ValueError(f"Unsupported ED2K file link terminator: {link!r}")
    return f"{link}|sources,{source_ip}:{source_port}|/"


def goed2k_server_config(*, listen_ip: str, catalog_path: Path, admin_token: str) -> dict[str, Any]:
    """Builds the deterministic ED2K server config for VM-to-VM campaign traffic."""

    if listen_ip.startswith("127.") or listen_ip == "0.0.0.0":
        raise ValueError(f"goed2k-server listen_ip must be a guest LAN address: {listen_ip}")
    return {
        "listen_address": f"{listen_ip}:4661",
        "admin_listen_address": f"{listen_ip}:8080",
        "admin_token": admin_token,
        "server_name": "emulebb-vm-local-ed2k",
        "server_description": "eMuleBB VM local ED2K transfer server",
        "catalog_path": str(catalog_path),
        "server_udp": True,
        "udp_port_offset": 4,
    }


def goed2k_admin_stats_url(config: dict[str, Any]) -> str:
    """Returns the configured goed2k admin stats URL."""

    address = str(config.get("admin_listen_address", "")).strip()
    if not address:
        raise ValueError("goed2k-server config is missing admin_listen_address.")
    return f"http://{address}/api/stats"


def netsh_delete_rule(name: str) -> None:
    subprocess.run(
        ["netsh.exe", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def netsh_allow_program(name: str, program_path: Path, protocol: str) -> None:
    netsh_delete_rule(name)
    run(
        [
            "netsh.exe",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={name}",
            "dir=in",
            "action=allow",
            f"program={program_path}",
            f"protocol={protocol}",
            "profile=any",
        ],
        timeout_seconds=30.0,
    )


def command_prepare_client(args: argparse.Namespace) -> int:
    root = Path(args.root)
    artifacts = root / "artifacts"
    expanded = root / "expanded"
    profile = root / "profile"
    config_dir = profile / "config"
    incoming = profile / "incoming"
    temp = profile / "temp"
    shared = profile / "shared"
    for directory in (artifacts, config_dir, incoming, temp, shared):
        directory.mkdir(parents=True, exist_ok=True)
    if expanded.exists():
        shutil.rmtree(expanded)
    with zipfile.ZipFile(args.package_zip) as archive:
        archive.extractall(expanded)

    app_root = expanded / "eMuleBB"
    exe = app_root / "emulebb.exe"
    if not exe.is_file():
        raise RuntimeError(f"Package did not contain eMuleBB\\emulebb.exe: {args.package_zip}")

    ip_address = guest_ipv4()
    sample_name = f"{args.target}-sample.bin"
    sample_path = shared / sample_name
    sample_sha256 = write_deterministic_file(
        sample_path,
        size=args.fixture_size_bytes,
        seed=10 if args.target == "win10" else 11,
    )
    write_preferences_ini(
        config_dir,
        preferences_text(
            target=args.target,
            incoming_dir=incoming,
            temp_dir=temp,
            tcp_port=args.tcp_port,
            udp_port=args.udp_port,
            bind_addr=ip_address,
            rest_port=args.rest_port,
            api_key=args.api_key,
        ),
    )

    repair_result = repair_firewall(
        app_root / "scripts" / "Repair-Firewall.ps1",
        exe,
        artifacts / "firewall-repair.json",
    )

    if args.server_exe:
        server_root = root / "ed2k-server"
        server_root.mkdir(parents=True, exist_ok=True)
        catalog_path = server_root / "catalog.json"
        catalog_path.write_text('{"files":[]}\n', encoding="utf-8")
        (server_root / "config.json").write_text(
            json.dumps(goed2k_server_config(listen_ip=ip_address, catalog_path=catalog_path, admin_token=args.admin_token), indent=2)
            + "\n",
            encoding="utf-8",
        )
        netsh_allow_program("eMuleBB VM Lab ED2K Server TCP", Path(args.server_exe), "TCP")
        netsh_allow_program("eMuleBB VM Lab ED2K Server UDP", Path(args.server_exe), "UDP")

    start_visible_app(
        exe,
        profile,
        task_name=f"eMuleBB VM Local ED2K {args.target}",
        username=args.username,
        password=args.password,
    )
    result = {
        "schema": "emulebb.windows-vm-local-ed2k-target.v1",
        "target": args.target,
        "status": "prepared",
        "guest": {"computerName": socket.gethostname(), "ipv4": ip_address},
        "appExe": str(exe),
        "profile": str(profile),
        "configDir": str(config_dir),
        "incomingDir": str(incoming),
        "tempDir": str(temp),
        "sharedDir": str(shared),
        "sample": {
            "name": sample_name,
            "path": str(sample_path),
            "size": args.fixture_size_bytes,
            "sha256": sample_sha256,
        },
        "restBaseUrl": f"http://{ip_address}:{args.rest_port}",
        "checks": [{"name": "firewall-repair", "status": "passed", "details": repair_result}],
        "errors": [],
        "artifactsDir": str(artifacts),
    }
    (root / "target-result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return emit(result)


def command_start_server(args: argparse.Namespace) -> int:
    root = Path(args.root)
    server_exe = root / "goed2k-server.exe"
    config_path = root / "ed2k-server" / "config.json"
    artifacts = root / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    stdout = (artifacts / "goed2k-server.log").open("w", encoding="utf-8")
    process = subprocess.Popen(
        [str(server_exe), "-config", str(config_path)],
        stdout=stdout,
        stderr=subprocess.STDOUT,
        cwd=str(root),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )

    def ready():
        request = urllib.request.Request(
            goed2k_admin_stats_url(config),
            headers={"X-Admin-Token": args.admin_token},
        )
        with urllib.request.urlopen(request, timeout=5.0) as response:
            return response.status == 200

    wait_until("goed2k-server admin API", 30.0, ready)
    return emit(
        {
            "name": "goed2k-server-ready",
            "status": "passed",
            "pid": process.pid,
            "listenAddress": config.get("listen_address", ""),
            "adminListenAddress": config.get("admin_listen_address", ""),
            "port": 4661,
        }
    )


def command_wait_rest(args: argparse.Namespace) -> int:
    result = wait_until(
        "eMuleBB REST API",
        args.timeout_seconds,
        lambda: http_json(args.base_url, "/api/v1/status", api_key=args.api_key),
    )
    return emit({"name": "rest-ready", "status": "passed", "details": result})


def command_add_connect_server(args: argparse.Namespace) -> int:
    server = {"address": args.server_address, "port": args.server_port, "name": "emulebb-vm-local-ed2k", "connect": False}
    rows = api_rows(http_json(args.base_url, "/api/v1/servers", api_key=args.api_key), "servers")
    if matching_server_row(rows, args.server_address, args.server_port) is None:
        http_json(args.base_url, "/api/v1/servers", api_key=args.api_key, method="POST", body=server)

    row = wait_until(
        "local ED2K server row",
        30.0,
        lambda: matching_server_row(
            api_rows(http_json(args.base_url, "/api/v1/servers", api_key=args.api_key), "servers"),
            args.server_address,
            args.server_port,
        ),
    )

    attempts: list[dict[str, Any]] = []
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        status = read_server_status(args.base_url, args.api_key)
        if status.get("connected") or status.get("connecting"):
            return emit(
                {
                    "name": "server-connect",
                    "status": "passed",
                    "details": {"server": row, "attempts": attempts, "serverStatus": status},
                }
            )
        attempt: dict[str, Any] = {"ordinal": len(attempts) + 1}
        try:
            attempt["response"] = http_json(
                args.base_url,
                f"/api/v1/servers/{args.server_address}:{args.server_port}/operations/connect",
                api_key=args.api_key,
                method="POST",
                body={},
            )
        except (ConnectionResetError, OSError, TimeoutError, urllib.error.URLError) as exc:
            attempt["warning"] = f"connect request reset before response: {exc}"
        attempts.append(attempt)
        status = read_server_status(args.base_url, args.api_key)
        if status.get("connected") or status.get("connecting"):
            return emit(
                {
                    "name": "server-connect",
                    "status": "passed",
                    "details": {"server": row, "attempts": attempts, "serverStatus": status},
                }
            )
        time.sleep(1.0)
    raise RuntimeError(
        "Timed out starting ED2K server connection: "
        + json.dumps(
            {
                "server": row,
                "attempts": attempts[-5:],
                "serverStatus": read_server_status(args.base_url, args.api_key),
            },
            sort_keys=True,
        )
    )


def command_wait_server_connected(args: argparse.Namespace) -> int:
    result = wait_until(
        "ED2K server connection",
        args.timeout_seconds,
        lambda: status_servers(http_json(args.base_url, "/api/v1/status", api_key=args.api_key)).get("connected"),
    )
    return emit({"name": "server-connected", "status": "passed", "details": {"connected": bool(result)}})


def command_shared_link(args: argparse.Namespace) -> int:
    retry_http_json(
        "shared directory add",
        3,
        args.base_url,
        "/api/v1/shared-files",
        api_key=args.api_key,
        method="POST",
        body={"path": args.path},
    )
    retry_http_json(
        "shared directory reload",
        3,
        args.base_url,
        "/api/v1/shared-files/operations/reload",
        api_key=args.api_key,
        method="POST",
        body={},
    )

    def resolve():
        rows = api_rows(
            retry_http_json(
                "shared files list",
                3,
                args.base_url,
                "/api/v1/shared-files",
                api_key=args.api_key,
            ),
            "sharedFiles",
            "shared_files",
        )
        for row in rows:
            if row.get("name") == args.name and row.get("hash"):
                link_payload = retry_http_json(
                    "shared ED2K link",
                    3,
                    args.base_url,
                    f"/api/v1/shared-files/{row['hash']}/ed2k-link",
                    api_key=args.api_key,
                )
                link_data = api_data(link_payload)
                link = link_data.get("link", "") if isinstance(link_data, dict) else ""
                if link.startswith("ed2k://|file|"):
                    return {"name": "shared-ed2k-link", "status": "passed", "hash": row["hash"], "link": link}
        return None

    return emit(wait_until(f"shared ED2K link for {args.name}", args.timeout_seconds, resolve))


def command_wait_shared_stable(args: argparse.Namespace) -> int:
    """Waits for shared-file hashing to settle before downloads use the source."""

    def resolve():
        status = api_data(
            retry_http_json(
                "shared status",
                3,
                args.base_url,
                "/api/v1/status",
                api_key=args.api_key,
            )
        )
        if not isinstance(status, dict):
            return None
        diagnostics = status.get("runtimeDiagnostics")
        startup_cache = status.get("sharedStartupCache")
        if not isinstance(diagnostics, dict) or not isinstance(startup_cache, dict):
            return None
        if int(diagnostics.get("sharedHashingCount") or 0) != 0:
            return None
        if int(startup_cache.get("hashingCount") or 0) != 0:
            return None
        if bool(startup_cache.get("deferredHashingActive")):
            return None
        if int(diagnostics.get("sharedFileCount") or 0) < 1:
            return None
        return {"diagnostics": diagnostics, "sharedStartupCache": startup_cache}

    result = wait_until("shared files stable", args.timeout_seconds, resolve)
    time.sleep(args.settle_seconds)
    return emit({"name": "shared-stable", "status": "passed", "details": result, "settleSeconds": args.settle_seconds})


def command_add_transfer(args: argparse.Namespace) -> int:
    link = ed2k_link_with_source(args.link, source_ip=args.source_address, source_port=args.source_port)
    result = http_json(
        args.base_url,
        "/api/v1/transfers",
        api_key=args.api_key,
        method="POST",
        body={"link": link, "paused": False, "categoryId": 0},
    )
    return emit({"name": "transfer-add", "status": "passed", "details": result, "sourceAnnotated": link != args.link})


def command_wait_completed(args: argparse.Namespace) -> int:
    path = Path(args.incoming_dir) / args.name

    def resolve():
        if path.is_file() and path.stat().st_size == args.size:
            digest = sha256_file(path)
            if digest == args.sha256:
                return {"name": "transfer-complete", "status": "passed", "path": str(path), "sha256": digest}
        return None

    return emit(wait_until(f"completed file {args.name}", args.timeout_seconds, resolve))


def command_stop_runtime(_: argparse.Namespace) -> int:
    for image in ("emulebb.exe", "goed2k-server.exe"):
        subprocess.run(["taskkill.exe", "/IM", image, "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return emit({"name": "stop-runtime", "status": "passed"})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare-client")
    prepare.add_argument("--root", required=True)
    prepare.add_argument("--target", required=True, choices=("win10", "win11"))
    prepare.add_argument("--package-zip", required=True)
    prepare.add_argument("--username", required=True)
    prepare.add_argument("--password", required=True)
    prepare.add_argument("--tcp-port", required=True, type=int)
    prepare.add_argument("--udp-port", required=True, type=int)
    prepare.add_argument("--rest-port", required=True, type=int)
    prepare.add_argument("--api-key", required=True)
    prepare.add_argument("--fixture-size-bytes", required=True, type=int)
    prepare.add_argument("--server-exe", default="")
    prepare.add_argument("--admin-token", default="")
    prepare.set_defaults(func=command_prepare_client)

    start_server = subparsers.add_parser("start-server")
    start_server.add_argument("--root", required=True)
    start_server.add_argument("--admin-token", required=True)
    start_server.set_defaults(func=command_start_server)

    wait_rest = subparsers.add_parser("wait-rest")
    wait_rest.add_argument("--base-url", required=True)
    wait_rest.add_argument("--api-key", required=True)
    wait_rest.add_argument("--timeout-seconds", type=float, default=90.0)
    wait_rest.set_defaults(func=command_wait_rest)

    add_server = subparsers.add_parser("add-connect-server")
    add_server.add_argument("--base-url", required=True)
    add_server.add_argument("--api-key", required=True)
    add_server.add_argument("--server-address", required=True)
    add_server.add_argument("--server-port", required=True, type=int)
    add_server.set_defaults(func=command_add_connect_server)

    wait_server = subparsers.add_parser("wait-server-connected")
    wait_server.add_argument("--base-url", required=True)
    wait_server.add_argument("--api-key", required=True)
    wait_server.add_argument("--timeout-seconds", type=float, default=90.0)
    wait_server.set_defaults(func=command_wait_server_connected)

    shared_link = subparsers.add_parser("shared-link")
    shared_link.add_argument("--base-url", required=True)
    shared_link.add_argument("--api-key", required=True)
    shared_link.add_argument("--name", required=True)
    shared_link.add_argument("--path", required=True)
    shared_link.add_argument("--timeout-seconds", type=float, default=120.0)
    shared_link.set_defaults(func=command_shared_link)

    shared_stable = subparsers.add_parser("wait-shared-stable")
    shared_stable.add_argument("--base-url", required=True)
    shared_stable.add_argument("--api-key", required=True)
    shared_stable.add_argument("--timeout-seconds", type=float, default=120.0)
    shared_stable.add_argument("--settle-seconds", type=float, default=10.0)
    shared_stable.set_defaults(func=command_wait_shared_stable)

    add_transfer = subparsers.add_parser("add-transfer")
    add_transfer.add_argument("--base-url", required=True)
    add_transfer.add_argument("--api-key", required=True)
    add_transfer.add_argument("--link", required=True)
    add_transfer.add_argument("--source-address", default="")
    add_transfer.add_argument("--source-port", default=0, type=int)
    add_transfer.set_defaults(func=command_add_transfer)

    completed = subparsers.add_parser("wait-completed")
    completed.add_argument("--incoming-dir", required=True)
    completed.add_argument("--name", required=True)
    completed.add_argument("--size", required=True, type=int)
    completed.add_argument("--sha256", required=True)
    completed.add_argument("--timeout-seconds", type=float, default=300.0)
    completed.set_defaults(func=command_wait_completed)

    stop = subparsers.add_parser("stop-runtime")
    stop.set_defaults(func=command_stop_runtime)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
