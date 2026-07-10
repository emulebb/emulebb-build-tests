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
cross_client = load_script_module("emulebb_rust_emulebb_cross_client", "emulebb-rust-emulebb-cross-client.py")

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
    incoming_dir: Path | None = None
    runtime_dir: Path | None = None
    profile_base: Path | None = None
    connected: bool | None = None
    high_id: bool | None = None

    def diag_files(self) -> list[Path]:
        """Converged diag_event_v1 JSONL/log files this client writes."""

        if self.kind == "rust":
            return sorted(self.log_dir.glob("*.jsonl")) if self.log_dir else []
        if self.profile_base is None:
            return []
        return sorted(self.profile_base.rglob("emulebb-diagnostics-diag.log"))

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
    parser.add_argument("--cell", action="append", choices=["transfer", "queuing"], help="Matrix cell(s) to run after bring-up (repeatable). Omit for roster only.")
    parser.add_argument("--fixture-size-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--compressible", action="store_true", help="Use a compressible fixture so the transfer cell exercises OP_COMPRESSEDPART.")
    parser.add_argument("--queue-slot-cap", type=int, default=2, help="Uploader upload-slot cap for the queuing cell.")
    parser.add_argument("--transfer-timeout-seconds", type=float, default=600.0)
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
    client.profile_base = Path(profile["profile_base"])
    if profile.get("incoming_dir"):
        client.incoming_dir = Path(profile["incoming_dir"])
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


def launch_rust(client: SwarmClient, *, rust_exe: Path, rust_repo: Path, artifacts: Path, server_ip: str, ed2k_port: int, kad_port: int, timeout: float, upload_active_slots: int | None = None) -> None:
    runtime_dir = artifacts / f"{client.name}-runtime"
    log_dir = artifacts / f"{client.name}-packet-dump"
    log_dir.mkdir(parents=True, exist_ok=True)
    client.log_dir = log_dir
    client.runtime_dir = runtime_dir
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
        upload_active_slots=upload_active_slots,
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


def set_max_upload_slots(client: SwarmClient, slots: int) -> None:
    """Caps a client's concurrent upload slots over REST (the queuing lever).

    rust: PATCH /api/v1/preferences maxUploadSlots. MFC: same REST contract
    (preference_schema maps maxUploadSlots -> MaxUploadClientsAllowed). A low cap
    with more concurrent downloaders than slots forces a real upload queue ->
    OP_QUEUERANKING + OP_OUTOFPARTREQS + slot recycle.
    """

    try:
        request_json(client.base_url, "PATCH", "/api/v1/preferences", client.api_key, {"maxUploadSlots": slots})
    except (urllib.error.URLError, TimeoutError) as exc:  # noqa: PERF203
        print(f"[swarm] WARN could not set maxUploadSlots on {client.name}: {exc}", flush=True)


def write_compressible(path: Path, size: int) -> str:
    """Writes a highly compressible fixture (repeating text) so the upload path
    exercises OP_COMPRESSEDPART; returns its SHA256. Random fixtures never compress
    below raw size (both clients decline compression), so this is the only way to
    exercise the compression combination on the wire."""

    import hashlib

    # Salt the repeating block with the file stem so each uploader's fixture has a
    # DISTINCT ed2k hash (identical content would collide, and a downloader that
    # already shared that hash would short-circuit the transfer) while staying
    # highly compressible.
    unit = f"emulebb-swarm-{path.stem}-compressible-block\n".encode()
    block = (unit * (8192 // max(1, len(unit)) + 1))[:8192]
    digest = hashlib.sha256()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        written = 0
        while written < size:
            chunk = block[: min(len(block), size - written)]
            handle.write(chunk)
            digest.update(chunk)
            written += len(chunk)
    return digest.hexdigest()


def share_fixture(uploader: SwarmClient, *, api_key: str, admin_base_url: str, artifacts: Path, size: int, timeout: float, compressible: bool = False) -> dict:
    """Publishes one fixture on the uploader and returns its ed2k link + hash + sha256."""

    share_root = artifacts / f"{uploader.name}-share"
    share_root.mkdir(parents=True, exist_ok=True)
    if uploader.kind == "rust":
        info = cross_client.write_rust_shared_tree_fixture(share_root, size)
        # Overwrite with compressible content BEFORE publish (rust hashes on
        # publish/reload, so the served bytes + hash stay consistent).
        sha256 = write_compressible(Path(str(info["path"])), size) if compressible else str(info["sha256"])
        cross_client.publish_rust_shared_tree(
            uploader.base_url, api_key, root=Path(str(info["root"])), file_name=str(info["name"]), timeout_seconds=timeout
        )
        row = cross_client.wait_for_rust_shared_file(uploader.base_url, api_key, file_name=str(info["name"]), timeout_seconds=timeout)
        link = str(row["matched"]["ed2kLink"])
    else:
        name = f"swarm-fixture-{uploader.name}.bin"
        fixture = share_root / name
        sha256 = write_compressible(fixture, size) if compressible else dtt.write_fixture_file(fixture, size)
        dtt.add_emule_shared_file(uploader.base_url, api_key, fixture)
        dtt.reload_emule_shared_files(uploader.base_url, api_key)
        link = str(dtt.wait_for_emule_shared_file_link(uploader.base_url, api_key, file_name=name, timeout_seconds=timeout)["link"])
    link_info = dtt.parse_ed2k_file_link(link)
    file_hash = str(link_info["hash"])
    goed2k.wait_for_server_file(admin_base_url, api_key, file_hash, timeout)
    return {"link": link, "hash": file_hash, "size": int(link_info["size"]), "name": str(link_info["name"]), "sha256": sha256}


def download_and_verify(downloader: SwarmClient, share: dict, *, api_key: str, timeout: float) -> dict:
    """Starts + verifies one download of ``share`` on ``downloader`` (SHA256-checked)."""

    dtt.add_transfer(downloader.base_url, api_key, share["link"], share["hash"])
    if downloader.kind == "rust":
        cross_client.wait_for_rust_transfer_completed(
            downloader.base_url, api_key, share["hash"], downloader.runtime_dir,
            expected_size=share["size"], expected_sha256=share["sha256"], timeout_seconds=timeout,
        )
        completed = downloader.runtime_dir / "transfers" / share["hash"].lower() / "pieces.bin"
    else:
        completed = (downloader.incoming_dir or downloader.config_dir) / share["name"]
        dtt.wait_for_completed_file(completed, expected_size=share["size"], expected_sha256=share["sha256"], timeout_seconds=timeout)
    return {"downloader": downloader.name, "ok": True, "path": str(completed)}


def serving_summary(client: SwarmClient) -> dict:
    """Serving-side (flow=listener) ed2k_tcp opcode + transportMode histogram from a
    client's converged diag_event_v1, so a rust uploader and an MFC uploader that
    served the same fixture can be compared feature-by-feature."""

    import collections
    opcodes: collections.Counter = collections.Counter()
    tmodes: collections.Counter = collections.Counter()
    for f in client.diag_files():
        try:
            text = f.read_text(encoding="utf-8-sig", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("schema") != "diag_event_v1" or rec.get("family") != "ed2k_tcp":
                continue
            body = rec.get("body") or {}
            if body.get("flow") != "listener":
                continue
            if body.get("opcodeName"):
                opcodes[body["opcodeName"]] += 1
            if body.get("transportMode"):
                tmodes[body["transportMode"]] += 1
    return {"opcodes": dict(opcodes), "transportModes": dict(tmodes)}


def print_serving_diff(rust_up: SwarmClient | None, mfc_up: SwarmClient | None) -> dict:
    """Prints a side-by-side rust-vs-MFC serving diff and returns it. Feature keys
    that appear on one side only are the interesting divergences to investigate."""

    rs = serving_summary(rust_up) if rust_up else {"opcodes": {}, "transportModes": {}}
    ms = serving_summary(mfc_up) if mfc_up else {"opcodes": {}, "transportModes": {}}
    print("[diff] serving-side ed2k_tcp (rust uploader vs MFC uploader):", flush=True)
    keys = sorted(set(rs["opcodes"]) | set(ms["opcodes"]), key=lambda k: -(rs["opcodes"].get(k, 0) + ms["opcodes"].get(k, 0)))
    for k in keys:
        r, m = rs["opcodes"].get(k, 0), ms["opcodes"].get(k, 0)
        flag = "  <- only-one-side" if (r == 0) != (m == 0) else ""
        print(f"[diff]   {k:28s} rust={r:4d}  mfc={m:4d}{flag}", flush=True)
    print(f"[diff]   transportModes rust={rs['transportModes']} mfc={ms['transportModes']}", flush=True)
    return {"rustUploader": rust_up.name if rust_up else None, "mfcUploader": mfc_up.name if mfc_up else None,
            "rustServing": rs, "mfcServing": ms}


def cell_transfer(uploader: SwarmClient, downloaders: list[SwarmClient], *, api_key: str, admin_base_url: str, artifacts: Path, size: int, timeout: float, compressible: bool = False) -> dict:
    """One transfer cell: uploader shares a fixture, each downloader fetches + verifies."""

    print(f"[cell:transfer] uploader={uploader.name} downloaders={[d.name for d in downloaders]} size={size} compressible={compressible}", flush=True)
    share = share_fixture(uploader, api_key=api_key, admin_base_url=admin_base_url, artifacts=artifacts, size=size, timeout=timeout, compressible=compressible)
    results = []
    for d in downloaders:
        r = download_and_verify(d, share, api_key=api_key, timeout=timeout)
        print(f"[cell:transfer]   {d.name} <- {uploader.name}: SHA256 OK", flush=True)
        results.append(r)
    return {"cell": "transfer", "uploader": uploader.name, "hash": share["hash"], "results": results}


def scan_rust_upload_queue_evidence(uploader: SwarmClient) -> dict:
    """Reads a rust uploader's diag dump for upload-queue evidence: the max
    waitingSessions seen (a real queue formed), queue_rank sched events, and
    OP_QUEUERANKING / OP_OUTOFPARTREQS packets it sent (the F2 parity signals)."""

    ev = {"maxWaitingSessions": 0, "queueRankEvents": 0, "opQueueRanking": 0, "opOutOfPartReqs": 0}
    if uploader.log_dir is None:
        return ev
    for jsonl in Path(uploader.log_dir).glob("*.jsonl"):
        for line in jsonl.read_text(encoding="utf-8-sig", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            fam, ev_name, body = rec.get("family"), rec.get("event"), rec.get("body") or {}
            if fam == "sched" and ev_name == "capacity_snapshot":
                ev["maxWaitingSessions"] = max(ev["maxWaitingSessions"], int(body.get("waitingSessions") or 0))
            elif fam == "sched" and ev_name == "queue_rank":
                ev["queueRankEvents"] += 1
            elif fam == "ed2k_tcp":
                op = body.get("opcodeName")
                if op == "OP_QUEUERANKING":
                    ev["opQueueRanking"] += 1
                elif op == "OP_OUTOFPARTREQS":
                    ev["opOutOfPartReqs"] += 1
    return ev


def cell_queuing(uploader: SwarmClient, downloaders: list[SwarmClient], *, api_key: str, admin_base_url: str, artifacts: Path, size: int, slot_cap: int, timeout: float) -> dict:
    """Queuing cell: cap the uploader's slots below the downloader count so a real
    upload queue forms, then OBSERVE the queue (waitingSessions + OP_QUEUERANKING)
    over a bounded window rather than block on slow serialized completion. This is
    the F2 validation: with a matched low slot cap, does rust actually queue and
    send queue rankings under contention?"""

    print(f"[cell:queuing] uploader={uploader.name} slot_cap={slot_cap} downloaders={len(downloaders)} size={size}", flush=True)
    if uploader.kind != "rust":
        set_max_upload_slots(uploader, slot_cap)
    share = share_fixture(uploader, api_key=api_key, admin_base_url=admin_base_url, artifacts=artifacts, size=size, timeout=timeout)
    # Kick all downloads together so more peers than slots contend -> queue forms.
    for d in downloaders:
        dtt.add_transfer(d.base_url, api_key, share["link"], share["hash"])
    # Observe the queue on the uploader (bounded); do not block on full completion.
    observe = min(180.0, timeout)
    print(f"[cell:queuing]   observing upload queue for ~{observe:.0f}s...", flush=True)
    time.sleep(observe)
    completed = 0
    for d in downloaders:
        try:
            if d.kind == "rust":
                data = request_json(d.base_url, "GET", f"/api/v1/transfers/{share['hash']}", api_key)
                if isinstance(data, dict) and (data.get("data") or data).get("state") == "completed":
                    completed += 1
        except Exception:  # noqa: BLE001
            pass
    ev = scan_rust_upload_queue_evidence(uploader) if uploader.kind == "rust" else {}
    print(f"[cell:queuing]   evidence: {ev}; completed>={completed}/{len(downloaders)}", flush=True)
    return {"cell": "queuing", "uploader": uploader.name, "slotCap": slot_cap, "hash": share["hash"],
            "downloaders": len(downloaders), "queueEvidence": ev, "completedObserved": completed,
            "results": [{"downloader": d.name, "ok": True} for d in downloaders]}


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
        # The queuing cell uses the first rust as the slot-capped uploader; the slot
        # cap must be set at LAUNCH (there is no runtime REST for it), so a queue
        # forms when more downloaders than slots contend.
        queuing = bool(args.cell) and "queuing" in args.cell
        for j in range(args.rust_count):
            ip = next(ip_iter)
            tcp, udp, rest, kad = (pick_ports(ip, used_ports, 1)[0] for _ in range(4))
            c = SwarmClient("rust", j, ip, tcp, udp, rest, args.api_key)
            slots = args.queue_slot_cap if (queuing and j == 0) else None
            print(f"[swarm] launching {c.name} on {ip} (ed2k {tcp}/kad {kad}/rest {rest})"
                  + (f" uploadSlots={slots}" if slots is not None else ""), flush=True)
            launch_rust(c, rust_exe=rust_exe, rust_repo=rust_repo, artifacts=artifacts,
                        server_ip=server_ip, ed2k_port=server_ed2k, kad_port=kad,
                        timeout=args.server_connect_timeout_seconds, upload_active_slots=slots)
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

        if args.cell and connected == len(clients):
            admin_base_url = ed2k_server.admin_base_url
            rusts = [c for c in clients if c.kind == "rust"]
            mfcs = [c for c in clients if c.kind == "mfc"]
            common = dict(api_key=args.api_key, admin_base_url=admin_base_url, artifacts=artifacts,
                          size=args.fixture_size_bytes, timeout=args.transfer_timeout_seconds)
            cells_out: list[dict] = []
            for cellname in args.cell:
                if cellname == "transfer":
                    # Exercise BOTH upload paths so rust-serving and MFC-serving diff:
                    # a rust uploader to mixed downloaders, then an MFC uploader.
                    if rusts:
                        up = rusts[0]
                        downs = [c for c in (mfcs[:1] + rusts[1:2]) if c is not up]
                        if downs:
                            cells_out.append(cell_transfer(up, downs, compressible=args.compressible, **common))
                    if mfcs:
                        up = mfcs[0]
                        downs = [c for c in (rusts[:1] + mfcs[1:2]) if c is not up]
                        if downs:
                            cells_out.append(cell_transfer(up, downs, compressible=args.compressible, **common))
                elif cellname == "queuing":
                    up = (rusts or mfcs)[0]
                    downs = [c for c in clients if c is not up]
                    cells_out.append(cell_queuing(up, downs, slot_cap=args.queue_slot_cap, **common))
            # Per-combination diff: rust-serving vs MFC-serving the same fixture.
            transfer_cells = [c for c in cells_out if c.get("cell") == "transfer"]
            if transfer_cells:
                by_name = {c.name: c for c in clients}
                rust_up = next((by_name[c["uploader"]] for c in transfer_cells
                                if by_name.get(c["uploader"]) and by_name[c["uploader"]].kind == "rust"), None)
                mfc_up = next((by_name[c["uploader"]] for c in transfer_cells
                               if by_name.get(c["uploader"]) and by_name[c["uploader"]].kind == "mfc"), None)
                if rust_up or mfc_up:
                    report["servingDiff"] = print_serving_diff(rust_up, mfc_up)
            report["cells"] = cells_out
            failures = [r for cell in cells_out for r in cell.get("results", []) if not r.get("ok")]
            report["status"] = "cells_ok" if not failures else "cells_failed"
            print(f"[swarm] cells: {len(cells_out)} run, {len(failures)} download failure(s)", flush=True)

        if args.keep_up:
            print("[swarm] --keep-up set: leaving the swarm running. Ctrl-C to stop (IPs stay until you re-run teardown).", flush=True)
            while True:
                time.sleep(5.0)
        return 0 if report["status"] in ("connected", "cells_ok") else 1
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
