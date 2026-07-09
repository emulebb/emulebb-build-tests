"""Local MFC-vs-rust parity swarm on distinct LAN IPs (throw-away, no live wire).

Brings up a local goed2k server plus N eMuleBB-MFC (emulebb-main diagnostics
build) and N eMuleBB-Rust (diagnostics build) clients, each on its OWN secondary
LAN IP with distinct P2P + REST ports, all bound to the physical LAN interface
that holds X_LOCAL_IP (never loopback). Every client is a distinct source IP so
the server/uploader apply real per-IP slot caps, source dedup, and anti-abuse --
the prerequisite for exercising genuine queuing / multi-source / anti-flood
combinations. This module owns bring-up + a connected-roster report; the matrix
cells (queuing, AICH, obfuscation x compression, failures) build on the roster.

Run under an ELEVATED shell (secondary-IP aliasing needs admin). Reuses the
proven single-client primitives from deterministic-two-client-transfer,
emule-live-profile-common, goed2k, and rust_client.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import goed2k  # noqa: E402
from emule_test_harness import rust_client  # noqa: E402
from emule_test_harness.lan_ip_pool import LanIpPool  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES, resolve_manifest_repo  # noqa: E402
from emule_test_harness.script_modules import load_script_module  # noqa: E402

harness_cli_common = load_script_module("harness_cli_common", "harness-cli-common.py")
live_common = load_script_module("emule_live_profile_common", "emule-live-profile-common.py")
dtt = load_script_module("deterministic_two_client_transfer", "deterministic-two-client-transfer.py")

SUITE_NAME = "local-parity-swarm-matrix"
API_KEY = "local-parity-swarm-key"


def request_json(base_url: str, method: str, path: str, api_key: str, body: dict | None = None) -> dict:
    """Minimal REST call returning parsed JSON ({} on empty body)."""

    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base_url.rstrip("/") + path, data=data, method=method)
    req.add_header("X-API-Key", api_key)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode().strip()
    return json.loads(raw) if raw else {}


# Allocate from a low band well BELOW the Windows/WinNAT reserved high-dynamic
# port ranges (Hyper-V excludes many 49669..65271 ranges; a UDP/TCP bind there
# fails with WSAEACCES -- which silently broke the goed2k server's UDP callback
# listener and left rust unable to get a HighID). Every port is verified free for
# BOTH TCP and UDP so eD2K TCP + Kad/eD2K UDP + the server UDP callback all bind.
_PORT_CURSOR = [32000]


def next_free_port(host: str, used: set[int], *, extra_udp_offset: int | None = None) -> int:
    """Returns the next port free (TCP+UDP) on ``host`` in the safe low band."""

    while True:
        port = _PORT_CURSOR[0]
        _PORT_CURSOR[0] += 1
        if port > 48000:
            raise RuntimeError("exhausted the safe swarm port band (32000..48000)")
        if port in used:
            continue
        if not dtt.is_port_available(port, host=host, udp=False):
            continue
        if not dtt.is_port_available(port, host=host, udp=True):
            continue
        if extra_udp_offset is not None and not dtt.is_port_available(port + extra_udp_offset, host=host, udp=True):
            continue
        used.add(port)
        return port


def pick_ports(host: str, used: set[int], count: int) -> list[int]:
    """Reserves ``count`` distinct free (TCP+UDP) ports on ``host``."""

    return [next_free_port(host, used) for _ in range(count)]


@dataclass
class SwarmClient:
    """One launched swarm client (MFC or rust) with its network identity."""

    kind: str  # "mfc" | "rust"
    index: int
    ip: str
    tcp_port: int
    udp_port: int
    rest_port: int
    api_key: str
    process: object = None
    config_dir: Path | None = None
    log_dir: Path | None = None
    connected: bool | None = None
    high_id: bool | None = None

    @property
    def name(self) -> str:
        return f"{self.kind}-{self.index}"

    @property
    def base_url(self) -> str:
        return f"http://{self.ip}:{self.rest_port}"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lan-bind-addr", required=True, help="X_LOCAL_IP: server + IP-pool interface.")
    parser.add_argument("--app-exe", required=True, help="Path to emulebb-diagnostics.exe (MFC diagnostics build).")
    parser.add_argument("--rust-exe", help="Path to emulebb-rust-diagnostics.exe (defaults under the output root).")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--mfc-count", type=int, default=4)
    parser.add_argument("--rust-count", type=int, default=4)
    parser.add_argument("--ip-first-octet4", type=int, default=211)
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--keep-up", action="store_true", help="Leave the swarm running (skip teardown) for manual driving.")
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    return parser.parse_args(argv)


def default_rust_exe() -> Path:
    root = Path(os.environ["EMULEBB_WORKSPACE_OUTPUT_ROOT"])
    return root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust-diagnostics.exe"


def stop_client(client: "SwarmClient") -> None:
    """Kills a launched client. rust is a Popen; the MFC GUI is a pywinauto
    Application whose whole process tree must be taskkill'd by PID (stop_process_tree
    only understands Popen, so the GUI would otherwise leak and hold its ports)."""

    proc = client.process
    if proc is None:
        return
    if client.kind == "rust":
        rust_client.stop_process_tree(proc)
        return
    pid = getattr(proc, "process", None)  # pywinauto Application.process == PID
    if isinstance(pid, int):
        import subprocess as _sp
        _sp.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False)


def launch_mfc(client: SwarmClient, *, app_exe: Path, seed_dir: Path, artifacts: Path, server_ip: str, ed2k_port: int, timeout: float) -> None:
    profile = live_common.prepare_scenario_profile(seed_dir, artifacts, [], client.name)
    config_dir = Path(profile["config_dir"])
    client.config_dir = config_dir
    dtt.configure_client_profile(
        config_dir=config_dir,
        app_exe=app_exe,
        nick=f"swarm-{client.name}",
        tcp_port=client.tcp_port,
        udp_port=client.udp_port,
        ed2k_enabled=True,
        autoconnect=False,
        rest_api_key=client.api_key,
        rest_port=client.rest_port,
        lan_bind_addr=client.ip,
        p2p_bind_addr=client.ip,
    )
    dtt.write_server_met(config_dir / "server.met", address=server_ip, port=ed2k_port, name="swarm-local")
    client.process = live_common.launch_app(app_exe, Path(profile["profile_base"]), minimized_to_tray=True)
    dtt.rest_smoke.wait_for_rest_ready(client.base_url, client.api_key, timeout)
    dtt.add_and_connect_server(
        client.base_url, client.api_key, address=server_ip, port=ed2k_port,
        timeout_seconds=timeout,
    )
    client.connected = True  # add_and_connect_server blocks until connected


def launch_rust(client: SwarmClient, *, rust_exe: Path, rust_repo: Path, artifacts: Path, server_ip: str, ed2k_port: int, kad_port: int, timeout: float) -> None:
    runtime_dir = artifacts / f"{client.name}-runtime"
    log_dir = artifacts / f"{client.name}-packet-dump"
    log_dir.mkdir(parents=True, exist_ok=True)
    client.log_dir = log_dir
    config = artifacts / f"{client.name}.toml"
    rust_client.write_rust_config(
        config,
        runtime_dir=runtime_dir,
        rest_addr=client.ip,
        rest_port=client.rest_port,
        api_key=client.api_key,
        p2p_bind_ip=client.ip,
        ed2k_port=client.tcp_port,
        kad_port=kad_port,
        server_endpoint=f"{server_ip}:{ed2k_port}",
        obfuscation_enabled=True,
    )
    os.environ["EMULEBB_RUST_LOG_DIR"] = str(log_dir)
    client.process = rust_client.start_rust_client_executable(rust_exe, config, artifacts / f"{client.name}.out")
    dtt.rest_smoke.wait_for_rest_ready(client.base_url, client.api_key, timeout)
    request_json(client.base_url, "POST", "/api/v1/servers/operations/connect", client.api_key)
    deadline = time.monotonic() + timeout
    last_servers: dict = {}
    while time.monotonic() < deadline:
        last_servers = request_json(client.base_url, "GET", "/api/v1/servers", client.api_key)
        data = last_servers.get("data") if isinstance(last_servers.get("data"), dict) else last_servers
        items = data.get("items") if isinstance(data, dict) else None
        item = next((s for s in items if isinstance(s, dict) and s.get("connected")), None) if isinstance(items, list) else None
        if item is not None:
            client.connected = True
            # goed2k grants a HighID unless the UDP callback fails; the rust log
            # reports it, but the servers row does not -- read HighID from stats.
            try:
                st = request_json(client.base_url, "GET", "/api/v1/status", client.api_key)
                stats = (st.get("data") or {}).get("stats") if isinstance(st.get("data"), dict) else None
                client.high_id = bool(stats.get("ed2kHighId")) if isinstance(stats, dict) and "ed2kHighId" in stats else None
            except Exception:  # noqa: BLE001
                client.high_id = None
            return
        time.sleep(2.0)
    raise RuntimeError(
        f"rust client {client.name} did not connect to the local server in {timeout}s; "
        f"servers = {json.dumps(last_servers)[:600]}"
    )


def roster_status(client: SwarmClient) -> None:
    try:
        status = request_json(client.base_url, "GET", "/api/v1/status", client.api_key)
    except (urllib.error.URLError, TimeoutError):
        client.connected = False
        return
    server = status.get("server") if isinstance(status.get("server"), dict) else status
    if isinstance(server, dict):
        client.connected = bool(server.get("connected") or server.get("state") == "connected")
        cid = server.get("clientId") or server.get("id")
        client.high_id = bool(server.get("highId")) if "highId" in server else None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration=args.configuration,
        workspace_root=None,
        app_root=args.app_root if hasattr(args, "app_root") else None,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    seed_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    artifacts = paths.source_artifacts_dir
    server_ip = args.lan_bind_addr
    rust_exe = Path(args.rust_exe).resolve() if args.rust_exe else default_rust_exe()
    rust_repo = resolve_manifest_repo(paths.workspace_root, "emulebb_rust")

    report: dict[str, object] = {"suite": SUITE_NAME, "status": "running", "clients": []}
    used_ports: set[int] = set()
    # goed2k derives its UDP callback port from ed2k_tcp + 4; reserve that too so
    # HighID assignment works (no UDP -> LowID -> rust session churn).
    server_ed2k = next_free_port(server_ip, used_ports, extra_udp_offset=4)
    used_ports.add(server_ed2k + 4)
    server_admin = next_free_port(server_ip, used_ports)

    pool = LanIpPool(server_ip, first_octet4=args.ip_first_octet4)
    clients: list[SwarmClient] = []
    server_process = None
    try:
        client_ips = pool.acquire(args.mfc_count + args.rust_count)
        print(f"[swarm] provisioned client IPs: {', '.join(client_ips)}", flush=True)

        server_dir = artifacts / "ed2k-server"
        ed2k_server = goed2k.launch_ed2k_server(
            workspace_root=paths.workspace_root,
            server_dir=server_dir,
            ed2k_port=server_ed2k,
            admin_port=server_admin,
            token=args.api_key,
            admin_address=server_ip,
            ed2k_address=server_ip,
            repo_override=args.ed2k_server_repo,
            exe_override=args.ed2k_server_exe,
        )
        server_process = ed2k_server.process
        print(f"[swarm] goed2k server on {server_ip}:{server_ed2k} (admin {server_admin})", flush=True)

        ip_iter = iter(client_ips)
        for i in range(args.mfc_count):
            ip = next(ip_iter)
            tcp, udp, rest = (pick_ports(ip, used_ports, 1)[0] for _ in range(3))
            c = SwarmClient("mfc", i, ip, tcp, udp, rest, args.api_key)
            print(f"[swarm] launching {c.name} on {ip} (tcp {tcp}/udp {udp}/rest {rest})", flush=True)
            launch_mfc(c, app_exe=Path(args.app_exe), seed_dir=seed_dir, artifacts=artifacts,
                       server_ip=server_ip, ed2k_port=server_ed2k, timeout=args.rest_ready_timeout_seconds)
            clients.append(c)
        for j in range(args.rust_count):
            ip = next(ip_iter)
            tcp, udp, rest, kad = (pick_ports(ip, used_ports, 1)[0] for _ in range(4))
            c = SwarmClient("rust", j, ip, tcp, udp, rest, args.api_key)
            print(f"[swarm] launching {c.name} on {ip} (ed2k {tcp}/kad {kad}/rest {rest})", flush=True)
            launch_rust(c, rust_exe=rust_exe, rust_repo=rust_repo, artifacts=artifacts,
                        server_ip=server_ip, ed2k_port=server_ed2k, kad_port=kad,
                        timeout=args.server_connect_timeout_seconds)
            clients.append(c)

        for c in clients:
            report["clients"].append({
                "name": c.name, "ip": c.ip, "tcp": c.tcp_port, "udp": c.udp_port,
                "rest": c.rest_port, "connected": c.connected, "highId": c.high_id,
            })
            print(f"[swarm] {c.name:8s} {c.ip:15s} connected={c.connected} highId={c.high_id}", flush=True)

        connected = sum(1 for c in clients if c.connected)
        report["status"] = "connected" if connected == len(clients) else "partial"
        print(f"[swarm] roster: {connected}/{len(clients)} connected to the local server", flush=True)

        if args.keep_up:
            print("[swarm] --keep-up set: leaving the swarm running. Ctrl-C to stop (IPs stay until you re-run teardown).", flush=True)
            while True:
                time.sleep(5.0)
        return 0 if connected == len(clients) else 1
    finally:
        if not args.keep_up:
            for c in clients:
                try:
                    stop_client(c)
                except Exception:
                    pass
            try:
                rust_client.stop_process_tree(server_process)
            except Exception:
                pass
            pool.release()
            print("[swarm] torn down (clients, server, IP aliases)", flush=True)
        report_path = artifacts / "swarm-report.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
