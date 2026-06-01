"""Python guest runner for visible Windows VM hide.me live-wire tests."""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

SERVER_MET_URL = "https://upd.emule-security.org/server.met"
SAFE_QUERIES = ("linux", "ubuntu", "debian", "fedora")
MIN_SAFE_SOURCES = 2
MAX_SAFE_BYTES = 256 * 1024 * 1024
try:
    from emule_test_harness.vm_guest_profiles import (
        DEFAULT_HIDEME_VPN_GUARD_ALLOWED_PUBLIC_IP_CIDRS,
        api_data,
        api_rows,
        emit,
        hideme_live_preferences_text as preferences_text,
        repair_firewall,
        retry_http_json,
        start_visible_app,
        wait_until,
        write_preferences_ini,
    )
except ModuleNotFoundError:
    from vm_guest_profiles import (
        DEFAULT_HIDEME_VPN_GUARD_ALLOWED_PUBLIC_IP_CIDRS,
        api_data,
        api_rows,
        emit,
        hideme_live_preferences_text as preferences_text,
        repair_firewall,
        retry_http_json,
        start_visible_app,
        wait_until,
        write_preferences_ini,
    )


def vpn_adapters() -> list[dict[str, str]]:
    script = (
        "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status | "
        "ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    payload = json.loads(completed.stdout or "[]")
    if isinstance(payload, dict):
        payload = [payload]
    return [
        {key: str(row.get(key) or "") for key in ("Name", "InterfaceDescription", "Status")}
        for row in payload
        if isinstance(row, dict)
    ]


def require_hide_me_connected(timeout_seconds: float) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []

    def probe():
        rows = vpn_adapters()
        observations.append({"observedAt": round(time.time(), 3), "adapters": rows})
        for row in rows:
            text = f"{row['Name']} {row['InterfaceDescription']}".casefold()
            if "hide.me" in text and row["Status"].casefold() == "up":
                return {"name": row["Name"], "description": row["InterfaceDescription"], "observations": observations}
        return None

    return wait_until("hide.me tunnel adapter", timeout_seconds, probe)


def guest_ipv4() -> str:
    """Returns the guest LAN IPv4 address used for harness control traffic."""

    script = (
        "$rows = Get-NetIPConfiguration | "
        "Where-Object { $_.NetAdapter.Status -eq 'Up' -and "
        "(($_.NetAdapter.Name + ' ' + $_.InterfaceDescription) -notmatch 'hide\\.me') } | "
        "ForEach-Object { $_.IPv4Address | ForEach-Object { $_.IPAddress } }; "
        "$rows | ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode == 0 and completed.stdout.strip():
        payload = json.loads(completed.stdout)
        rows = payload if isinstance(payload, list) else [payload]
        usable = sorted(
            str(address)
            for address in rows
            if str(address) and not str(address).startswith("127.") and str(address) != "0.0.0.0"
        )
        if usable:
            return usable[0]

    candidates: set[str] = set()
    for host in {socket.gethostname(), socket.getfqdn(), ""}:
        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(host, None, socket.AF_INET):
                if family == socket.AF_INET and sockaddr:
                    candidates.add(str(sockaddr[0]))
        except OSError:
            continue
    usable = sorted(
        address
        for address in candidates
        if not address.startswith("127.") and address != "0.0.0.0"
    )
    if not usable:
        raise RuntimeError("No non-loopback LAN IPv4 address is available in the guest.")
    return usable[0]


def compact_status(payload: Any) -> dict[str, Any]:
    data = api_data(payload)
    if not isinstance(data, dict):
        return {}
    network = data.get("network") if isinstance(data.get("network"), dict) else {}
    servers = data.get("servers") if isinstance(data.get("servers"), dict) else {}
    return {"network": network, "servers": servers, "stats": data.get("stats")}


def status_servers(payload: Any) -> dict[str, Any]:
    data = api_data(payload)
    if not isinstance(data, dict):
        return {}
    servers = data.get("servers")
    return servers if isinstance(servers, dict) else {}


def command_prepare_client(args: argparse.Namespace) -> int:
    root = Path(args.root)
    artifacts = root / "artifacts"
    expanded = root / "expanded"
    profile = root / "profile"
    config_dir = profile / "config"
    incoming = profile / "incoming"
    temp = profile / "temp"
    for directory in (artifacts, config_dir, incoming, temp):
        directory.mkdir(parents=True, exist_ok=True)
    if expanded.exists():
        shutil.rmtree(expanded)
    with zipfile.ZipFile(args.package_zip) as archive:
        archive.extractall(expanded)

    app_root = expanded / "eMuleBB"
    exe = app_root / "emulebb.exe"
    if not exe.is_file():
        raise RuntimeError(f"Package did not contain eMuleBB\\emulebb.exe: {args.package_zip}")

    vpn = require_hide_me_connected(args.vpn_timeout_seconds)
    ip_address = guest_ipv4()
    write_preferences_ini(
        config_dir,
        preferences_text(
            target=args.target,
            incoming_dir=incoming,
            temp_dir=temp,
            tcp_port=args.tcp_port,
            udp_port=args.udp_port,
            rest_port=args.rest_port,
            lan_bind_addr=ip_address,
            api_key=args.api_key,
        ),
    )
    repair_result = repair_firewall(
        app_root / "scripts" / "Repair-Firewall.ps1",
        exe,
        artifacts / "firewall-repair.json",
    )
    start_visible_app(
        exe,
        profile,
        task_name=f"eMuleBB VM hide.me live {args.target}",
        username=args.username,
        password=args.password,
    )
    result = {
        "schema": "emulebb.windows-vm-hideme-live-target.v1",
        "target": args.target,
        "status": "prepared",
        "guest": {"computerName": socket.gethostname(), "ipv4": ip_address},
        "vpn": vpn,
        "appExe": str(exe),
        "profile": str(profile),
        "configDir": str(config_dir),
        "incomingDir": str(incoming),
        "tempDir": str(temp),
        "restBaseUrl": f"http://{ip_address}:{args.rest_port}",
        "checks": [{"name": "firewall-repair", "status": "passed", "details": repair_result}],
        "errors": [],
        "artifactsDir": str(artifacts),
    }
    (root / "target-result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return emit(result)


def command_wait_rest(args: argparse.Namespace) -> int:
    result = wait_until(
        "eMuleBB REST API",
        args.timeout_seconds,
        lambda: retry_http_json("REST status", 3, args.base_url, "/api/v1/status", api_key=args.api_key),
    )
    return emit({"name": "rest-ready", "status": "passed", "details": compact_status(result)})


def command_assert_vpn_binding(args: argparse.Namespace) -> int:
    def probe():
        payload = retry_http_json("REST status", 3, args.base_url, "/api/v1/status", api_key=args.api_key)
        data = api_data(payload)
        network = data.get("network") if isinstance(data, dict) and isinstance(data.get("network"), dict) else {}
        text = json.dumps(network, sort_keys=True).casefold()
        if "hide.me" in text:
            return {"name": "vpn-binding", "status": "passed", "details": network}
        return None

    return emit(wait_until("eMuleBB hide.me binding", args.timeout_seconds, probe))


def command_import_server_met(args: argparse.Namespace) -> int:
    response = retry_http_json(
        "server.met import",
        3,
        args.base_url,
        "/api/v1/servers/operations/import-met-url",
        api_key=args.api_key,
        method="POST",
        body={"url": args.server_met_url},
        timeout_seconds=args.timeout_seconds,
    )
    time.sleep(2.0)
    rows = api_rows(retry_http_json("server list", 6, args.base_url, "/api/v1/servers", api_key=args.api_key), "servers")
    return emit({"name": "server-met-import", "status": "passed", "response": response, "serverCount": len(rows)})


def command_connect_live_server(args: argparse.Namespace) -> int:
    rows = api_rows(retry_http_json("server list", 6, args.base_url, "/api/v1/servers", api_key=args.api_key), "servers")
    candidates = [
        row for row in rows
        if row.get("address") and row.get("port")
    ][: args.max_candidates]
    attempts: list[dict[str, Any]] = []
    deadline = time.monotonic() + args.timeout_seconds
    for candidate in candidates:
        if time.monotonic() >= deadline:
            break
        endpoint = f"{candidate['address']}:{candidate['port']}"
        attempt: dict[str, Any] = {"server": {"name": candidate.get("name"), "address": candidate.get("address"), "port": candidate.get("port")}}
        try:
            attempt["connect"] = retry_http_json(
                "server connect",
                4,
                args.base_url,
                f"/api/v1/servers/{endpoint}/operations/connect",
                api_key=args.api_key,
                method="POST",
                body={},
                timeout_seconds=15.0,
            )
            settle_deadline = time.monotonic() + min(45.0, max(5.0, deadline - time.monotonic()))
            while time.monotonic() < settle_deadline:
                status = status_servers(
                    retry_http_json("server status", 4, args.base_url, "/api/v1/status", api_key=args.api_key)
                )
                attempt["lastStatus"] = status
                if status.get("connected"):
                    return emit({"name": "server-connect", "status": "passed", "selected": attempt["server"], "attempts": attempts + [attempt]})
                time.sleep(2.0)
        except Exception as exc:
            attempt["error"] = f"{type(exc).__name__}: {exc}"
        attempts.append(attempt)
    raise RuntimeError(f"Could not connect to a live server: {attempts!r}")


def is_safe_download_candidate(row: dict[str, Any]) -> bool:
    name = str(row.get("name") or "").casefold()
    if not name or any(token in name for token in (".exe", ".msi", ".scr", ".bat", "keygen", "crack")):
        return False
    file_hash = str(row.get("hash") or "")
    size = row.get("sizeBytes", row.get("size"))
    sources = row.get("sources")
    return (
        len(file_hash) == 32
        and all(ch in "0123456789abcdef" for ch in file_hash)
        and isinstance(size, int)
        and 0 < size <= MAX_SAFE_BYTES
        and isinstance(sources, int)
        and sources >= MIN_SAFE_SOURCES
    )


def command_live_search(args: argparse.Namespace) -> int:
    searches: list[dict[str, Any]] = []
    selected_transfer: dict[str, Any] | None = None
    for query in args.queries:
        created = retry_http_json(
            "search create",
            4,
            args.base_url,
            "/api/v1/searches",
            api_key=args.api_key,
            method="POST",
            body={"query": query, "method": args.method, "type": ""},
        )
        search_id = str(api_data(created).get("id") if isinstance(api_data(created), dict) else "")
        if not search_id:
            searches.append({"query": query, "created": created, "error": "missing search id"})
            continue
        observations: list[dict[str, Any]] = []
        deadline = time.monotonic() + args.timeout_seconds
        while time.monotonic() < deadline:
            payload = retry_http_json(
                "search results",
                4,
                args.base_url,
                f"/api/v1/searches/{search_id}",
                api_key=args.api_key,
            )
            data = api_data(payload)
            results = data.get("results") if isinstance(data, dict) and isinstance(data.get("results"), list) else []
            observation = {"status": data.get("status") if isinstance(data, dict) else None, "resultCount": len(results)}
            observations.append(observation)
            safe = next((row for row in results if isinstance(row, dict) and is_safe_download_candidate(row)), None)
            if safe and args.trigger_download and selected_transfer is None:
                download = retry_http_json(
                    "search result download",
                    4,
                    args.base_url,
                    f"/api/v1/searches/{search_id}/results/{safe['hash']}/operations/download",
                    api_key=args.api_key,
                    method="POST",
                    body={"paused": True, "categoryId": 0},
                )
                selected_transfer = {
                    "hash": safe["hash"],
                    "namePresent": bool(safe.get("name")),
                    "sizeBytes": safe.get("sizeBytes", safe.get("size")),
                    "sources": safe.get("sources"),
                    "download": download,
                }
                break
            if results and not args.trigger_download:
                break
            if isinstance(data, dict) and data.get("status") == "complete":
                break
            time.sleep(2.0)
        searches.append({"query": query, "searchId": search_id, "observations": observations})
        if selected_transfer is not None:
            break
    ok = bool(searches) and any(any(obs.get("resultCount", 0) > 0 for obs in row["observations"]) for row in searches)
    if args.trigger_download:
        ok = ok and selected_transfer is not None
    result = {"name": "live-search", "status": "passed" if ok else "failed", "searches": searches, "triggeredTransfer": selected_transfer}
    if not ok:
        raise RuntimeError(json.dumps(result, sort_keys=True))
    return emit(result)


def command_stop_runtime(args: argparse.Namespace) -> int:
    subprocess.run(["taskkill.exe", "/IM", "emulebb.exe", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return emit({"name": "stop-runtime", "status": "passed"})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare-client")
    prepare.add_argument("--root", required=True)
    prepare.add_argument("--target", required=True)
    prepare.add_argument("--package-zip", required=True)
    prepare.add_argument("--username", required=True)
    prepare.add_argument("--password", required=True)
    prepare.add_argument("--tcp-port", type=int, required=True)
    prepare.add_argument("--udp-port", type=int, required=True)
    prepare.add_argument("--rest-port", type=int, required=True)
    prepare.add_argument("--api-key", required=True)
    prepare.add_argument("--vpn-timeout-seconds", type=float, default=180.0)
    prepare.set_defaults(func=command_prepare_client)

    wait_rest = sub.add_parser("wait-rest")
    wait_rest.add_argument("--base-url", required=True)
    wait_rest.add_argument("--api-key", required=True)
    wait_rest.add_argument("--timeout-seconds", type=float, default=120.0)
    wait_rest.set_defaults(func=command_wait_rest)

    binding = sub.add_parser("assert-vpn-binding")
    binding.add_argument("--base-url", required=True)
    binding.add_argument("--api-key", required=True)
    binding.add_argument("--timeout-seconds", type=float, default=90.0)
    binding.set_defaults(func=command_assert_vpn_binding)

    import_met = sub.add_parser("import-server-met")
    import_met.add_argument("--base-url", required=True)
    import_met.add_argument("--api-key", required=True)
    import_met.add_argument("--server-met-url", default=SERVER_MET_URL)
    import_met.add_argument("--timeout-seconds", type=float, default=60.0)
    import_met.set_defaults(func=command_import_server_met)

    connect = sub.add_parser("connect-live-server")
    connect.add_argument("--base-url", required=True)
    connect.add_argument("--api-key", required=True)
    connect.add_argument("--timeout-seconds", type=float, default=180.0)
    connect.add_argument("--max-candidates", type=int, default=8)
    connect.set_defaults(func=command_connect_live_server)

    search = sub.add_parser("live-search")
    search.add_argument("--base-url", required=True)
    search.add_argument("--api-key", required=True)
    search.add_argument("--method", default="server")
    search.add_argument("--query", dest="queries", action="append", default=[])
    search.add_argument("--timeout-seconds", type=float, default=180.0)
    search.add_argument("--trigger-download", action="store_true")
    search.set_defaults(func=command_live_search)

    stop = sub.add_parser("stop-runtime")
    stop.set_defaults(func=command_stop_runtime)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "queries", None) == []:
        args.queries = list(SAFE_QUERIES)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
