"""Capture eMuleBB's outbound `OP_REASKFILEPING` bytes for byte-level comparison
against the Rust client's reask ping (FEAT-001 diagnostic).

Inverse of `emulebb-rust-reask-cross-client.py`: here eMuleBB is the *queued
downloader* that emits the reask, and the Rust client is the *uploader* that logs
the inbound datagram verbatim.

Topology (all on the LAN bind addr, through a local goed2k server):
  * a Rust uploader (enableUdpReask=true) shares one fixture and offers it to the
    server. Its upload queue is configured with activeSlots=0, so every requester
    is parked in the WAITING queue instead of being served.
  * eMuleBB adds the Rust client's ed2k link, finds the Rust source via the
    server, connects over TCP, gets a queue rank (OP_QUEUERANKING), then drops the
    TCP socket and periodically UDP-reasks the Rust source.
  * The Rust uploader's reask loop logs every inbound datagram verbatim
    ("ed2k udp reask: PKT-IN <- ... hex=...") and answers with OP_REASKACK.

Plaintext: the Rust uploader advertises no UDP-crypt (obfuscationEnabled=false),
so eMuleBB sends the reask UNobfuscated -> the PKT-IN hex is the clean wire body
([C5][90][hash16][partstatus][u16 complete-count]) for direct comparison.

IMPORTANT timing: eMule's FILEREASKTIME is 29 min and a queued source is only
UDP-reasked within the 2-min window before that, AND only once >=20 min have
passed since the last TCP connect attempt (PartFile.cpp Process / DownloadClient
UDPReaskForDownload). So the first eMuleBB reask arrives ~27 min after queueing;
size the observe timeout accordingly (default 35 min).

Pass = the Rust uploader log shows at least one inbound PKT-IN reask datagram.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import goed2k  # noqa: E402
from emule_test_harness import rust_client  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES, resolve_manifest_repo  # noqa: E402
from emule_test_harness.script_modules import load_script_module  # noqa: E402

cc = load_script_module("emulebb_rust_emulebb_cross_client_for_capture", "emulebb-rust-emulebb-cross-client.py")
dtt = cc.dtt
live_common = cc.live_common
harness_cli_common = cc.harness_cli_common

SUITE_NAME = "emulebb-rust-reask-capture-emulebb"
API_KEY = "emulebb-rust-reask-capture-emulebb-key"
CLIENT_EMULEBB = CLIENT_IDENTITIES["emulebb"]
# Trace the reask path so each inbound PKT-IN datagram is logged verbatim.
RUST_LOG = (
    "info,emulebb_ed2k=info,emulebb_core=info"
    ",emulebb_ed2k::ed2k_tcp=debug"
    ",emulebb_ed2k::ed2k_client_udp=trace"
)
PKT_IN_RE = re.compile(r"ed2k udp reask: PKT-IN <- (\S+) \((\d+) bytes\) hex=([0-9a-f…()+ ]+)")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--p2p-bind-interface-name", default="")
    parser.add_argument("--p2p-bind-interface-address")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    # ~27 min until the first eMuleBB UDP reask; give a margin.
    parser.add_argument("--reask-observe-timeout-seconds", type=float, default=35 * 60.0)
    parser.add_argument("--fixture-size-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    return parser.parse_args(argv)


def start_rust_uploader(*, repo, paths, lan_bind_addr, api_key, p2p_address, server_endpoint,
                        used_ports, shared_dir):
    """Writes a config + launches the Rust uploader (activeSlots=0, reask on, plaintext)."""
    rest_port = cc.choose_extra_port(lan_bind_addr, used_ports)
    ed2k_port = cc.choose_extra_port(lan_bind_addr, used_ports)
    kad_port = cc.choose_extra_port(lan_bind_addr, used_ports)
    runtime = paths.source_artifacts_dir / "rust-uploader-runtime"
    config = paths.source_artifacts_dir / "rust-uploader.toml"
    rust_client.write_rust_config(
        config,
        runtime_dir=runtime,
        rest_addr=lan_bind_addr,
        rest_port=rest_port,
        api_key=api_key,
        p2p_bind_ip=p2p_address,
        ed2k_port=ed2k_port,
        kad_port=kad_port,
        server_endpoint=server_endpoint,
        enable_udp_reask=True,
        # Plaintext so eMuleBB sends the reask unobfuscated (clean wire body).
        obfuscation_enabled=False,
        # Park every requester in the waiting queue so eMuleBB UDP-reasks us.
        upload_active_slots=0,
    )
    out_path = paths.source_artifacts_dir / "rust-uploader.out"
    os.environ["RUST_LOG"] = RUST_LOG
    process = rust_client.start_rust_client(repo, config, out_path)
    base_url = f"http://{lan_bind_addr}:{rest_port}"
    cc.wait_for_rust_rest(base_url, process, out_path, api_key, 60.0)
    # Share the fixture directory before connecting so the offer-files advertisement
    # carries it once the server session comes up.
    cc.request_json(
        base_url, "PATCH", "/api/v1/shared-directories", api_key,
        {"roots": [{"path": str(shared_dir), "recursive": False}], "confirmReplaceRoots": True},
    )
    cc.request_json(base_url, "POST", "/api/v1/shared-directories/operations/reload", api_key)
    cc.request_json(base_url, "POST", "/api/v1/servers/operations/connect", api_key)
    cc.wait_for_rust_ed2k_connected(base_url, api_key, 120.0)
    return base_url, process, out_path, kad_port


def rust_shared_file_link(base_url, api_key, *, file_name, timeout):
    """Polls the Rust shared-file catalog for the fixture and returns (hash, link)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = cc.request_json(base_url, "GET", "/api/v1/shared-files", api_key)
        payload = data.get("data", data)
        rows = payload.get("sharedFiles") if isinstance(payload, dict) else None
        if rows is None and isinstance(payload, dict):
            rows = payload.get("items")
        for row in rows or []:
            if isinstance(row, dict) and row.get("name") == file_name:
                file_hash = str(row.get("hash") or "").lower()
                if file_hash:
                    link = cc.request_json(
                        base_url, "GET", f"/api/v1/shared-files/{file_hash}/ed2k-link", api_key,
                    )
                    link_payload = link.get("data", link)
                    return file_hash, str(link_payload.get("link"))
        time.sleep(2.0)
    raise RuntimeError(f"Rust never published shared file {file_name!r}")


def scan_pkt_in(path: Path) -> list[dict[str, object]]:
    """Returns every inbound reask PKT-IN datagram recorded by the Rust uploader."""
    if not path.is_file():
        return []
    hits: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = PKT_IN_RE.search(line)
        if m:
            hits.append({"from": m.group(1), "bytes": int(m.group(2)), "hex": m.group(3).strip()})
    return hits


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__, suite_name=SUITE_NAME, configuration=args.configuration,
        workspace_root=None, app_root=args.app_root, app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir, keep_artifacts=args.keep_artifacts,
    )
    profile_seed_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    report: dict[str, object] = {"suite": SUITE_NAME, "status": "running", "checks": {}}
    server_process = None
    uploader_proc = None
    emulebb_app = None
    try:
        p2p_address = args.p2p_bind_interface_address or dtt.discover_interface_ipv4(args.p2p_bind_interface_name)
        ports = dtt.choose_distinct_ports(args.lan_bind_addr)
        used_ports = set(ports.values())
        server_endpoint = f"{p2p_address}:{ports['ed2k_tcp']}"
        rust_repo = resolve_manifest_repo(paths.workspace_root, "emulebb_rust")

        ed2k_server = goed2k.launch_ed2k_server(
            workspace_root=paths.workspace_root, server_dir=paths.source_artifacts_dir / "ed2k-server",
            ed2k_port=ports["ed2k_tcp"], admin_port=ports["ed2k_admin"], token=args.api_key,
            admin_address=args.lan_bind_addr, ed2k_address=p2p_address,
            repo_override=args.ed2k_server_repo, exe_override=args.ed2k_server_exe,
        )
        server_process = ed2k_server.process
        admin_base_url = ed2k_server.admin_base_url

        # --- Rust uploader: shares a fixture, parks requesters in the queue ---
        shared_dir = paths.source_artifacts_dir / "rust-shared"
        shared_dir.mkdir(parents=True, exist_ok=True)
        fixture_path = shared_dir / "reask-capture-fixture.bin"
        dtt.write_fixture_file(fixture_path, args.fixture_size_bytes, seed=0x5EA5C0DE)

        up_url, uploader_proc, up_out, up_kad_port = start_rust_uploader(
            repo=rust_repo, paths=paths, lan_bind_addr=args.lan_bind_addr, api_key=args.api_key,
            p2p_address=p2p_address, server_endpoint=server_endpoint, used_ports=used_ports,
            shared_dir=shared_dir,
        )
        transfer_hash, shared_link = rust_shared_file_link(
            up_url, args.api_key, file_name=fixture_path.name, timeout=args.server_publish_timeout_seconds,
        )
        goed2k.wait_for_server_file(admin_base_url, args.api_key, transfer_hash, args.server_publish_timeout_seconds)
        report["checks"]["rust_shared"] = {
            "hash": transfer_hash, "name": fixture_path.name, "link": shared_link, "udpPort": up_kad_port,
        }

        # --- eMuleBB downloader: queues on the Rust source, then UDP-reasks it ---
        emulebb = live_common.prepare_scenario_profile(profile_seed_dir, paths.source_artifacts_dir, [], CLIENT_EMULEBB.profile_id)
        config_dir = Path(emulebb["config_dir"])
        dtt.configure_client_profile(
            config_dir=config_dir, app_exe=paths.app_exe, nick=CLIENT_EMULEBB.nick,
            tcp_port=ports["client1_tcp"], udp_port=ports["client1_udp"], ed2k_enabled=True,
            autoconnect=False, rest_api_key=args.api_key, rest_port=ports["client1_rest"],
            lan_bind_addr=args.lan_bind_addr, p2p_bind_interface_name=args.p2p_bind_interface_name,
            p2p_bind_addr=p2p_address,
        )
        dtt.write_server_met(config_dir / "server.met", address=p2p_address, port=ports["ed2k_tcp"], name="reask-capture")
        emulebb_app = live_common.launch_app(paths.app_exe, Path(emulebb["profile_base"]), minimized_to_tray=True)
        emulebb_base_url = f"http://{args.lan_bind_addr}:{ports['client1_rest']}"
        dtt.rest_smoke.wait_for_rest_ready(emulebb_base_url, args.api_key, args.rest_ready_timeout_seconds)
        dtt.add_and_connect_server(emulebb_base_url, args.api_key, address=p2p_address, port=ports["ed2k_tcp"], timeout_seconds=args.server_connect_timeout_seconds)
        dtt.add_transfer(emulebb_base_url, args.api_key, shared_link, transfer_hash)

        # Observe the Rust uploader log for an inbound eMuleBB reask (~27 min out).
        deadline = time.monotonic() + args.reask_observe_timeout_seconds
        hits: list[dict[str, object]] = []
        while time.monotonic() < deadline:
            hits = scan_pkt_in(up_out)
            if hits:
                break
            time.sleep(10.0)
        report["checks"]["reask_pkt_in"] = hits
        report["status"] = "passed" if hits else "failed"
        if hits:
            print("Captured eMuleBB OP_REASKFILEPING datagrams:")
            for hit in hits:
                print(f"  from={hit['from']} bytes={hit['bytes']} hex={hit['hex']}")
        return 0 if report["status"] == "passed" else 1
    except Exception as exc:  # noqa: BLE001
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        return 1
    finally:
        if emulebb_app is not None:
            try:
                live_common.close_app_cleanly(emulebb_app)
            except Exception:  # noqa: BLE001
                pass
        rust_client.stop_process_tree(uploader_proc)
        goed2k.stop_process(server_process)
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "emulebb-rust-reask-capture-emulebb-result.json", report)
        print(report)


if __name__ == "__main__":
    raise SystemExit(main())
