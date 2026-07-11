"""Local real-process validation of the Rust client's UDP source-reask (FEAT-001).

Topology (all on the LAN bind addr, through a local goed2k server):
  * eMuleBB (reference uploader) shares one fixture, configured with a SINGLE
    upload slot and a slow upload cap so its one slot stays occupied.
  * an "occupier" Rust client downloads the fixture first and holds that slot.
  * the "reask" Rust client (enableUdpReask=true) then downloads the same
    fixture -> eMuleBB has no free slot -> it QUEUES the reask client
    (OP_QUEUERANKING) -> the reask client detaches its TCP socket onto UDP
    reask (QueuedDetachedForUdpReask) and periodically reasks eMuleBB, which
    answers OP_REASKACK with the queue rank.

Pass = the reask client's daemon log shows the detach + an answered reask. This
exercises the downloader detach hook end-to-end against the reference uploader,
which the public live-wire run could not (the server rate-limited searches).
"""

from __future__ import annotations

import argparse
import os
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

cc = load_script_module("emulebb_rust_emulebb_cross_client_for_reask", "emulebb-rust-emulebb-cross-client.py")
dtt = cc.dtt
live_common = cc.live_common
harness_cli_common = cc.harness_cli_common

SUITE_NAME = "emulebb-rust-reask-cross-client"
API_KEY = "emulebb-rust-reask-cross-client-key"
CLIENT_EMULEBB = CLIENT_IDENTITIES["emulebb"]
# eMuleBB upload throttle: one slot, slow enough that the occupier keeps it busy
# across the reask client's first reask ticks (REASK_TICK_INTERVAL = 30s).
EMULEBB_MAX_UPLOAD_KIB = 4
# Trace the reask + transfer paths so the detach / reask / ack are observable.
RUST_LOG = (
    "info,emulebb_ed2k=info,emulebb_core=info"
    ",emulebb_ed2k::ed2k_tcp=debug,emulebb_ed2k::ed2k_transfer=debug"
    ",emulebb_ed2k::ed2k_client_udp=trace"
)


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
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--reask-observe-timeout-seconds", type=float, default=180.0)
    # Large enough that the slow eMuleBB slot stays busy for a few reask ticks.
    parser.add_argument("--fixture-size-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    return parser.parse_args(argv)


def start_rust(*, repo, paths, lan_bind_addr, api_key, p2p_address, server_endpoint,
               used_ports, label, enable_reask):
    """Writes a config + launches one Rust client; returns (base_url, process, out, runtime)."""
    rest_port = cc.choose_extra_port(lan_bind_addr, used_ports)
    ed2k_port = cc.choose_extra_port(lan_bind_addr, used_ports)
    kad_port = cc.choose_extra_port(lan_bind_addr, used_ports)
    runtime = paths.source_artifacts_dir / f"rust-{label}-runtime"
    config = paths.source_artifacts_dir / f"rust-{label}.toml"
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
        enable_udp_reask=enable_reask,
        # Plaintext locally: the client-UDP reask obfuscation keys on our public
        # IP, but the goed2k lab server reports a fake one (2.0.0.1) that does not
        # match our LAN IP, so an obfuscated reask can't be deobfuscated by the
        # peer. Real networks report the true public IP (no mismatch); the
        # obfuscated path is covered by unit tests. Plaintext isolates the reask
        # logic for this local cross-client check.
        obfuscation_enabled=False,
    )
    out_path = paths.source_artifacts_dir / f"rust-{label}.out"
    os.environ["RUST_LOG"] = RUST_LOG
    process = rust_client.start_rust_client(repo, config, out_path)
    base_url = f"http://{lan_bind_addr}:{rest_port}"
    cc.wait_for_rust_rest(base_url, process, out_path, api_key, 60.0)
    cc.request_json(base_url, "POST", "/api/v1/servers/operations/connect", api_key)
    cc.wait_for_rust_ed2k_connected(base_url, api_key, 120.0)
    return base_url, process, out_path, runtime


def rust_download_emulebb_file(base_url, api_key, *, query, transfer_hash, timeout):
    """Drives a Rust server search for the eMuleBB file + starts the download."""
    found = cc.wait_for_rust_search_result(
        base_url, api_key, query=query, transfer_hash=transfer_hash, timeout_seconds=timeout,
    )
    search_id = found["search"]["id"]
    cc.request_json(
        base_url, "POST",
        f"/api/v1/searches/{search_id}/results/{transfer_hash}/operations/download",
        api_key, {"paused": False},
    )
    cc.request_json(base_url, "POST", f"/api/v1/transfers/{transfer_hash}/operations/resume", api_key)


def wait_for_rust_downloading(base_url, api_key, transfer_hash, timeout):
    """Waits until the transfer is pulling bytes (occupier is holding an upload slot)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = cc.request_json(base_url, "GET", "/api/v1/transfers", api_key)
        items = data.get("data", data)
        rows = items.get("items", []) if isinstance(items, dict) else []
        for row in rows:
            if isinstance(row, dict) and str(row.get("hash") or "").lower() == transfer_hash.lower():
                if int(row.get("completedBytes") or 0) > 0:
                    return int(row["completedBytes"])
        time.sleep(2.0)
    return 0


def log_contains(path: Path, needle: str) -> int:
    if not path.is_file():
        return 0
    text = path.read_text(encoding="utf-8", errors="replace")
    return sum(1 for line in text.splitlines() if needle in line)


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
    occupier_proc = None
    reask_proc = None
    emulebb_app = None
    try:
        p2p_address = dtt.resolve_lan_p2p_bind_address(
            lan_bind_addr=args.lan_bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
            p2p_bind_interface_address=args.p2p_bind_interface_address,
        )
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

        # --- eMuleBB uploader: ONE slot, slow upload, shares one fixture ---
        emulebb = live_common.prepare_scenario_profile(profile_seed_dir, paths.source_artifacts_dir, [], CLIENT_EMULEBB.profile_id)
        config_dir = Path(emulebb["config_dir"])
        dtt.configure_client_profile(
            config_dir=config_dir, app_exe=paths.app_exe, nick=CLIENT_EMULEBB.nick,
            tcp_port=ports["client1_tcp"], udp_port=ports["client1_udp"], ed2k_enabled=True,
            autoconnect=False, rest_api_key=args.api_key, rest_port=ports["client1_rest"],
            lan_bind_addr=args.lan_bind_addr, p2p_bind_interface_name=args.p2p_bind_interface_name,
            p2p_bind_addr=p2p_address,
        )
        # Force a queue: a single upload slot, throttled so it stays occupied.
        live_common.apply_section_preferences(config_dir, "UploadPolicy", (("MaxUploadClientsAllowed", "1"),))
        live_common.apply_emule_preferences(config_dir, (("MaxUpload", str(EMULEBB_MAX_UPLOAD_KIB)),))
        dtt.write_server_met(config_dir / "server.met", address=p2p_address, port=ports["ed2k_tcp"], name="reask-local")
        emulebb_app = live_common.launch_app(paths.app_exe, Path(emulebb["profile_base"]), minimized_to_tray=True)
        emulebb_base_url = f"http://{args.lan_bind_addr}:{ports['client1_rest']}"
        dtt.rest_smoke.wait_for_rest_ready(emulebb_base_url, args.api_key, args.rest_ready_timeout_seconds)
        dtt.add_and_connect_server(emulebb_base_url, args.api_key, address=p2p_address, port=ports["ed2k_tcp"], timeout_seconds=args.server_connect_timeout_seconds)

        fixture_path = paths.source_artifacts_dir / "emulebb-shared" / "reask-fixture.bin"
        dtt.write_fixture_file(fixture_path, args.fixture_size_bytes, seed=0x5EA5C0DE)
        dtt.add_emule_shared_file(emulebb_base_url, args.api_key, fixture_path)
        dtt.reload_emule_shared_files(emulebb_base_url, args.api_key)
        shared_link = dtt.wait_for_emule_shared_file_link(emulebb_base_url, args.api_key, file_name=fixture_path.name, timeout_seconds=args.link_export_timeout_seconds)
        link_info = dtt.parse_ed2k_file_link(str(shared_link["link"]))
        transfer_hash = str(link_info["hash"])
        goed2k.wait_for_server_file(admin_base_url, args.api_key, transfer_hash, args.server_publish_timeout_seconds)
        report["checks"]["emulebb_shared"] = {"hash": transfer_hash, "name": fixture_path.name}

        # --- occupier Rust: grabs eMuleBB's single slot and holds it ---
        occ_url, occupier_proc, occ_out, _ = start_rust(
            repo=rust_repo, paths=paths, lan_bind_addr=args.lan_bind_addr, api_key=args.api_key,
            p2p_address=p2p_address, server_endpoint=server_endpoint, used_ports=used_ports,
            label="occupier", enable_reask=False,
        )
        rust_download_emulebb_file(occ_url, args.api_key, query="reask", transfer_hash=transfer_hash, timeout=args.server_publish_timeout_seconds)
        # Wait until the occupier is actually pulling bytes -> it holds eMuleBB's
        # one upload slot, so the reask client that asks next will be queued.
        occ_bytes = wait_for_rust_downloading(occ_url, args.api_key, transfer_hash, 120.0)
        report["checks"]["occupier_downloading_bytes"] = occ_bytes
        if occ_bytes <= 0:
            raise RuntimeError("occupier never engaged eMuleBB's upload slot (no bytes pulled)")

        # --- reask Rust: gets queued -> detaches onto UDP reask ---
        reask_url, reask_proc, reask_out, _ = start_rust(
            repo=rust_repo, paths=paths, lan_bind_addr=args.lan_bind_addr, api_key=args.api_key,
            p2p_address=p2p_address, server_endpoint=server_endpoint, used_ports=used_ports,
            label="reask", enable_reask=True,
        )
        rust_download_emulebb_file(reask_url, args.api_key, query="reask", transfer_hash=transfer_hash, timeout=args.server_publish_timeout_seconds)

        # Observe the detach + an answered reask in the reask client's log.
        deadline = time.monotonic() + args.reask_observe_timeout_seconds
        detaches = acks = 0
        while time.monotonic() < deadline:
            detaches = log_contains(reask_out, "detaching source")
            acks = log_contains(reask_out, "routed reply")
            if detaches > 0 and acks > 0:
                break
            time.sleep(3.0)
        report["checks"]["reask"] = {"detaches": detaches, "ackedReplies": acks}
        report["status"] = "passed" if detaches > 0 and acks > 0 else "failed"
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
        rust_client.stop_process_tree(occupier_proc)
        rust_client.stop_process_tree(reask_proc)
        goed2k.stop_process(server_process)
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "emulebb-rust-reask-cross-client-result.json", report)
        print(report)


if __name__ == "__main__":
    raise SystemExit(main())
