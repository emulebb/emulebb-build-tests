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


def emit(payload: dict[str, Any]) -> int:
    """Writes one JSON object for the host shim."""

    print(json.dumps(payload, sort_keys=True))
    return 0


def run(command: list[str], *, timeout_seconds: float = 60.0) -> None:
    """Runs one command and raises with useful output on failure."""

    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"{command[0]} failed with exit code {completed.returncode}: {detail}")


def api_rows(payload: Any, *candidate_keys: str) -> list[dict[str, Any]]:
    """Returns REST rows from either a raw list or a wrapped API object."""

    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = None
        for key in candidate_keys:
            value = payload.get(key)
            if isinstance(value, list):
                rows = value
                break
        if rows is None and isinstance(payload.get("data"), list):
            rows = payload["data"]
        elif rows is None and isinstance(payload.get("data"), dict):
            data = payload["data"]
            for key in candidate_keys:
                value = data.get(key)
                if isinstance(value, list):
                    rows = value
                    break
        if rows is None:
            rows = []
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


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


def preferences_text(
    *,
    target: str,
    incoming_dir: Path,
    temp_dir: Path,
    tcp_port: int,
    udp_port: int,
    bind_addr: str,
    rest_port: int,
    api_key: str,
) -> str:
    """Builds the eMuleBB profile used by the local VM transfer test."""

    return "\n".join(
        [
            "[eMule]",
            f"Nick={target}-vm",
            "ConfirmExit=0",
            f"IncomingDir={incoming_dir}",
            f"TempDir={temp_dir}",
            f"Port={tcp_port}",
            f"UDPPort={udp_port}",
            "ServerUDPPort=65535",
            f"BindAddr={bind_addr}",
            "BindInterface=",
            "BlockNetworkWhenBindUnavailableAtStartup=1",
            "NetworkED2K=1",
            "NetworkKademlia=0",
            "Autoconnect=0",
            "Reconnect=0",
            "SafeServerConnect=0",
            "FilterBadIPs=0",
            "AllowLocalHostIP=1",
            "GeoLocationLookupEnabled=0",
            "IPFilterEnabled=0",
            "SaveLogToDisk=1",
            "SaveDebugToDisk=1",
            "Verbose=1",
            "FullVerbose=1",
            "[WebServer]",
            "Enabled=1",
            f"ApiKey={api_key}",
            f"Port={rest_port}",
            "BindAddr=127.0.0.1",
            "UseHTTPS=0",
            "[UPnP]",
            "EnableUPnP=0",
            "",
        ]
    )


def repair_firewall(script_path: Path, program_path: Path, result_path: Path) -> dict[str, Any]:
    """Runs the packaged firewall repair script and returns its result JSON."""

    run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
            "-ProgramPath",
            str(program_path),
            "-ResultPath",
            str(result_path),
        ],
        timeout_seconds=60.0,
    )
    return json.loads(result_path.read_text(encoding="utf-8-sig"))


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


def start_visible_app(exe_path: Path, profile_dir: Path, *, task_name: str, username: str, password: str) -> None:
    """Starts eMuleBB in the interactive user session through Task Scheduler."""

    subprocess.run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    command = f'"{exe_path}" -ignoreinstances -c "{profile_dir}"'
    start_time = time.strftime("%H:%M", time.localtime(time.time() + 60))
    run(
        [
            "schtasks.exe",
            "/Create",
            "/TN",
            task_name,
            "/SC",
            "ONCE",
            "/ST",
            start_time,
            "/TR",
            command,
            "/RU",
            username,
            "/RP",
            password,
            "/RL",
            "HIGHEST",
            "/IT",
            "/F",
        ],
        timeout_seconds=30.0,
    )
    run(["schtasks.exe", "/Run", "/TN", task_name], timeout_seconds=30.0)


def http_json(
    base_url: str,
    path: str,
    *,
    api_key: str,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout_seconds: float = 30.0,
) -> Any:
    data = None
    headers = {"X-API-Key": api_key}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read()
    return json.loads(raw.decode("utf-8-sig")) if raw else {}


def wait_until(description: str, timeout_seconds: float, callback):
    deadline = time.monotonic() + timeout_seconds
    last_error: str | None = None
    while time.monotonic() < deadline:
        try:
            result = callback()
            if result:
                return result
        except (OSError, TimeoutError, urllib.error.URLError, RuntimeError) as exc:
            last_error = str(exc)
        time.sleep(1.0)
    suffix = f": {last_error}" if last_error else ""
    raise RuntimeError(f"Timed out waiting for {description}{suffix}")


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
    (config_dir / "preferences.ini").write_text(
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
        encoding="utf-16",
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
            json.dumps(
                {
                    "listen_address": "0.0.0.0:4661",
                    "admin_listen_address": "127.0.0.1:8080",
                    "admin_token": args.admin_token,
                    "server_name": "emulebb-vm-local-ed2k",
                    "server_description": "eMuleBB VM local ED2K transfer server",
                    "catalog_path": str(catalog_path),
                    "server_udp": True,
                    "udp_port_offset": 4,
                },
                indent=2,
            )
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
        "restBaseUrl": f"http://127.0.0.1:{args.rest_port}",
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
            "http://127.0.0.1:8080/api/stats",
            headers={"X-Admin-Token": args.admin_token},
        )
        with urllib.request.urlopen(request, timeout=5.0) as response:
            return response.status == 200

    wait_until("goed2k-server admin API", 30.0, ready)
    return emit({"name": "goed2k-server-ready", "status": "passed", "pid": process.pid, "port": 4661})


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
    if not any(str(row.get("address")) == args.server_address and int(row.get("port", 0)) == args.server_port for row in rows):
        http_json(args.base_url, "/api/v1/servers", api_key=args.api_key, method="POST", body=server)
    try:
        connected = http_json(
            args.base_url,
            f"/api/v1/servers/{args.server_address}:{args.server_port}/operations/connect",
            api_key=args.api_key,
            method="POST",
            body={},
        )
    except (ConnectionResetError, OSError, TimeoutError, urllib.error.URLError) as exc:
        connected = {"warning": f"connect request reset before response: {exc}"}
    return emit({"name": "server-connect", "status": "passed", "details": connected})


def command_wait_server_connected(args: argparse.Namespace) -> int:
    result = wait_until(
        "ED2K server connection",
        args.timeout_seconds,
        lambda: http_json(args.base_url, "/api/v1/servers/status", api_key=args.api_key).get("connected"),
    )
    return emit({"name": "server-connected", "status": "passed", "details": {"connected": bool(result)}})


def command_shared_link(args: argparse.Namespace) -> int:
    http_json(args.base_url, "/api/v1/shared-files", api_key=args.api_key, method="POST", body={"path": args.path})
    http_json(args.base_url, "/api/v1/shared-files/operations/reload", api_key=args.api_key, method="POST", body={})

    def resolve():
        rows = api_rows(http_json(args.base_url, "/api/v1/shared-files", api_key=args.api_key), "sharedFiles", "shared_files")
        for row in rows:
            if row.get("name") == args.name and row.get("hash"):
                link_payload = http_json(args.base_url, f"/api/v1/shared-files/{row['hash']}/ed2k-link", api_key=args.api_key)
                link = link_payload.get("link", "")
                if link.startswith("ed2k://|file|"):
                    return {"name": "shared-ed2k-link", "status": "passed", "hash": row["hash"], "link": link}
        return None

    return emit(wait_until(f"shared ED2K link for {args.name}", args.timeout_seconds, resolve))


def command_add_transfer(args: argparse.Namespace) -> int:
    result = http_json(
        args.base_url,
        "/api/v1/transfers",
        api_key=args.api_key,
        method="POST",
        body={"link": args.link, "paused": False, "categoryId": 0},
    )
    return emit({"name": "transfer-add", "status": "passed", "details": result})


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

    add_transfer = subparsers.add_parser("add-transfer")
    add_transfer.add_argument("--base-url", required=True)
    add_transfer.add_argument("--api-key", required=True)
    add_transfer.add_argument("--link", required=True)
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
