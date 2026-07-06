"""Launch the rust<->MFC soak environment against the persistent profiles.

A pure launcher: it brings up emulebb-rust (diagnostics) and the MFC diagnostics
GUI on the persistent, isolated profiles under
``$EMULEBB_WORKSPACE_OUTPUT_ROOT/soak/`` (same operator eD2K server, same nodes.dat
bootstrap, same shared library roots), auto-starts TrackMuleBB pointed at the rust
REST, then idles until Ctrl-C. You drive searches/downloads by hand (MFC GUI +
TrackMuleBB); both diagnostics builds write their ``ed2k_packet_v1`` /
``diag_event_v1`` dumps continuously into the persistent profile dirs.

No test/diff logic lives here. Analysis runs separately from this repo
(``analyze-packet-coverage.py``, ``diag_event_diff``, or the live observer
``converged-soak-live.py``) over the captured dumps when you ask for it.

REST control plane binds X_LOCAL_IP; P2P binds the hide.me tunnel. The rust
diagnostics binary is the distinctly-named ``emulebb-rust-diagnostics.exe`` (build
it with ``python -m emule_workspace build clients --client emulebb-rust
--diagnostics``).

GENTLE LIVE DISCIPLINE: you drive the pace by hand; keep searches few and widely
spaced, and confirm before starting a live campaign.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import converged_live_wire as clw
from emule_test_harness import soak_launch, soak_run_layout
from emule_test_harness.hideme_split_tunnel import ensure_vpn_ready
from emule_test_harness.kad_nodes import DEFAULT_NODES_DAT_URL, fetch_bootstrap_endpoints
from emule_test_harness.live_wire_inputs import LiveWireInputs, load_live_wire_inputs
from emule_test_harness.paths import get_workspace_output_root
from emule_test_harness.rust_client import stop_process_tree
from emule_test_harness.soak_launch import (
    DEFAULT_MFC_SEED_CONFIG_DIR,
    DEFAULT_SERVER_MET_URL,
    MFC_ED2K_PORT,
    MFC_API_KEY,
    MFC_KAD_PORT,
    MFC_SERVER_UDP_PORT,
    OPERATOR_SERVER,
    RUST_ED2K_PORT,
    RUST_API_KEY,
    RUST_KAD_PORT,
    bring_up_mfc,
    bring_up_rust,
    log,
)
from emule_test_harness.vm_guest_profiles import retry_http_json

# TrackMuleBB lives beside this repo under repos/; it is driven entirely by env.
TRACKMULEBB_REPO = REPO_ROOT.parent / "trackmulebb"
TRACKMULEBB_CONTROL_PORT = 8770


def resolve_direct_mfc_profile(inputs: LiveWireInputs, *, no_mfc: bool) -> Path | None:
    """Returns the operator-owned MFC profile used for the soak launcher."""

    if no_mfc or inputs.mfc_profile_dir is None:
        return None
    return inputs.mfc_profile_dir.resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--inputs",
        help="live-wire-inputs.local.json (shared roots). Default: repo-root copy.",
    )
    parser.add_argument("--rust-rest-port", type=int, default=4731)
    parser.add_argument("--mfc-rest-port", type=int, default=4732)
    parser.add_argument("--rust-ed2k-port", type=int, default=RUST_ED2K_PORT)
    parser.add_argument("--rust-kad-port", type=int, default=RUST_KAD_PORT)
    parser.add_argument("--mfc-ed2k-port", type=int, default=MFC_ED2K_PORT)
    parser.add_argument("--mfc-kad-port", type=int, default=MFC_KAD_PORT)
    parser.add_argument("--mfc-server-udp-port", type=int, default=MFC_SERVER_UDP_PORT)
    parser.add_argument("--rust-server", default=OPERATOR_SERVER, help="eD2K server endpoint for Rust, host:port.")
    parser.add_argument("--mfc-server", default=OPERATOR_SERVER, help="eD2K server endpoint for MFC, host:port.")
    parser.add_argument("--no-mfc", action="store_true", help="Do not launch the MFC diagnostics GUI.")
    parser.add_argument("--no-trackmulebb", action="store_true", help="Do not auto-start TrackMuleBB.")
    parser.add_argument("--no-obfuscation", action="store_true", help="Disable protocol obfuscation on both clients.")
    parser.add_argument("--nodes-url", default=DEFAULT_NODES_DAT_URL, help="Kad nodes.dat URL (same source for both).")
    parser.add_argument("--server-met-url", default=DEFAULT_SERVER_MET_URL, help="server.met URL for rust import (empty to skip).")
    parser.add_argument("--bootstrap-limit", type=int, default=40)
    parser.add_argument("--profile-seed-dir", help="MFC profile seed config directory.")
    parser.add_argument("--mfc-variant", default=clw.DEFAULT_MFC_VARIANT)
    parser.add_argument("--mfc-arch", default=clw.DEFAULT_MFC_ARCH)
    parser.add_argument("--mfc-configuration", default=clw.DEFAULT_MFC_CONFIGURATION)
    return parser


def start_trackmulebb(*, rust_url: str, control_host: str) -> subprocess.Popen:
    """Starts TrackMuleBB (NiceGUI) pointed at the soak rust REST, qBt disabled."""

    if not (TRACKMULEBB_REPO / "trackmulebb" / "__main__.py").is_file():
        raise RuntimeError(f"TrackMuleBB repo not found at '{TRACKMULEBB_REPO}'.")
    env = os.environ.copy()
    env.update(
        {
            "TRACKMULEBB_RUST_URL": rust_url,
            "TRACKMULEBB_RUST_API_KEY": RUST_API_KEY,
            "TRACKMULEBB_RUST_ENABLED": "1",
            "TRACKMULEBB_QBT_ENABLED": "0",
            "TRACKMULEBB_CONTROL_HOST": control_host,
            "TRACKMULEBB_CONTROL_PORT": str(TRACKMULEBB_CONTROL_PORT),
        }
    )
    return subprocess.Popen(
        ["uv", "run", "--project", str(TRACKMULEBB_REPO), "python", "-m", "trackmulebb"],
        env=env,
    )


def graceful_teardown(
    *,
    rust_handles: dict | None,
    mfc_handles: dict | None,
    trackmulebb_proc: subprocess.Popen | None,
    live_common,
    rust_base: str,
    wait_seconds: float = 15.0,
) -> None:
    """Stops everything the launcher started, gracefully, with a bounded fallback.

    Asks each component to stop cleanly (rust via ``POST /api/v1/app/shutdown`` →
    its graceful network teardown; the MFC GUI via ``close_app_cleanly`` → the
    eMule save-and-exit path that persists known.met; TrackMuleBB via terminate),
    then waits up to ``wait_seconds`` for the processes to exit before force-killing
    any straggler. A second Ctrl-C during the wait jumps straight to the kill.
    """

    if rust_handles is not None and rust_handles["process"].poll() is None:
        log("rust: requesting graceful shutdown (POST /api/v1/app/shutdown)...")
        try:
            retry_http_json(
                "rust shutdown", 1, rust_base, "/api/v1/app/shutdown",
                api_key=RUST_API_KEY, method="POST", body={}, timeout_seconds=5.0,
            )
        except Exception:  # noqa: BLE001 - rust may already be tearing down
            pass
    if mfc_handles is not None and mfc_handles.get("app") is not None:
        log("MFC: closing the diagnostics GUI cleanly...")
        try:
            live_common.close_app_cleanly(mfc_handles["app"])
        except Exception:  # noqa: BLE001
            try:
                mfc_handles["app"].kill()
            except Exception:  # noqa: BLE001
                pass
    if trackmulebb_proc is not None and trackmulebb_proc.poll() is None:
        log("TrackMuleBB: requesting stop...")
        try:
            trackmulebb_proc.terminate()
        except Exception:  # noqa: BLE001
            pass

    watched = [
        proc
        for proc in (
            rust_handles["process"] if rust_handles is not None else None,
            trackmulebb_proc,
        )
        if proc is not None
    ]
    deadline = time.monotonic() + wait_seconds
    try:
        while time.monotonic() < deadline and any(proc.poll() is None for proc in watched):
            time.sleep(0.5)
    except KeyboardInterrupt:
        log("second interrupt - force-killing now.")

    if trackmulebb_proc is not None and trackmulebb_proc.poll() is None:
        stop_process_tree(trackmulebb_proc)
    if rust_handles is not None:
        if rust_handles["process"].poll() is None:
            log("rust did not exit in time - force-killing.")
            stop_process_tree(rust_handles["process"])
        try:
            rust_handles["logHandle"].close()
        except Exception:  # noqa: BLE001
            pass


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    obfuscation = not args.no_obfuscation
    endpoint_ports = soak_launch.require_distinct_endpoint_ports(
        rust_ed2k_port=args.rust_ed2k_port,
        rust_kad_port=args.rust_kad_port,
        mfc_ed2k_port=args.mfc_ed2k_port,
        mfc_kad_port=args.mfc_kad_port,
        mfc_server_udp_port=args.mfc_server_udp_port,
    )

    rest_addr = os.environ.get("X_LOCAL_IP", "").strip()
    if not rest_addr:
        raise RuntimeError("X_LOCAL_IP must be set (REST control plane binds the LAN IP).")
    output_root = get_workspace_output_root()

    rust_exe = clw.resolve_rust_diagnostics_exe(output_root)
    mfc_exe = clw.resolve_mfc_diagnostics_exe(
        output_root, variant=args.mfc_variant, arch=args.mfc_arch, configuration=args.mfc_configuration
    )

    mods = soak_launch.load_helper_modules("launcher")
    rust_mod = mods["rust"]

    inputs_path = Path(args.inputs).resolve() if args.inputs else REPO_ROOT / "live-wire-inputs.local.json"
    if not inputs_path.is_file():
        raise RuntimeError(f"live-wire inputs not found: {inputs_path} (pass --inputs).")
    inputs = load_live_wire_inputs(inputs_path)
    direct_mfc_profile = resolve_direct_mfc_profile(inputs, no_mfc=args.no_mfc)
    shared_roots = rust_mod.load_shared_roots(inputs_path)
    if not shared_roots:
        raise RuntimeError("No shared_directories.roots in the live-wire inputs - nothing to share.")

    soak_root = output_root / "soak"
    campaign_id = soak_run_layout.utc_campaign_id()
    rust_runtime = soak_root / "rust-runtime"
    mfc_artifacts = soak_root / "mfc-profile"
    mfc_log_dir = None if args.no_mfc else soak_run_layout.mfc_soak_log_dir(
        mfc_artifacts_dir=mfc_artifacts,
        direct_profile_dir=direct_mfc_profile,
    )
    run_paths = soak_run_layout.build_run_paths(soak_root, campaign_id)
    preflight_manifest = soak_run_layout.prepare_clean_run(
        paths=run_paths,
        rust_runtime_dir=rust_runtime,
        rust_packet_dump_dir=rust_runtime / "packet-dump",
        mfc_log_dir=mfc_log_dir,
    )
    log(
        "preflight cleanup archived "
        f"{preflight_manifest['preflightCleanup']['rust']['archivedCount']} rust file(s) and "
        f"{preflight_manifest['preflightCleanup']['mfc']['archivedCount']} MFC log file(s)"
    )
    if direct_mfc_profile is not None:
        log(f"MFC direct profile from live-wire inputs: {direct_mfc_profile}")
    log(f"persistent rust profile under {soak_root} - sharing {len(shared_roots)} library root(s)")
    log(
        "P2P endpoint ports: "
        f"rust TCP {endpoint_ports['rust']['ed2kTcpPort']}/UDP {endpoint_ports['rust']['kadUdpPort']}; "
        f"MFC TCP {endpoint_ports['mfc']['ed2kTcpPort']}/UDP {endpoint_ports['mfc']['kadUdpPort']}"
    )

    log("ensuring hide.me split tunnel...")
    rust_vpn = ensure_vpn_ready(rust_exe, name="eMuleBB Rust")
    mfc_vpn = None
    if not args.no_mfc:
        mfc_vpn = ensure_vpn_ready(mfc_exe, name="eMuleBB MFC")
    bind_ip = (
        soak_launch.require_same_vpn_bind_ip(rust_vpn, mfc_vpn)
        if mfc_vpn is not None
        else str(rust_vpn["bindIp"])
    )
    log(f"hide.me bind IP: {bind_ip}")

    bootstrap_nodes = fetch_bootstrap_endpoints(args.nodes_url, limit=args.bootstrap_limit)
    log(f"Kad bootstrap from {args.nodes_url}: {len(bootstrap_nodes)} contacts")

    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else DEFAULT_MFC_SEED_CONFIG_DIR
    timeouts = {"rest": 60.0, "connect": 240.0}

    rust_handles: dict | None = None
    mfc_handles: dict | None = None
    trackmulebb_proc: subprocess.Popen | None = None
    rust_base = ""
    try:
        rust_handles = bring_up_rust(
            rust_mod=rust_mod, exe_path=rust_exe, bind_ip=bind_ip, rest_addr=rest_addr,
            rest_port=args.rust_rest_port, runtime_dir=rust_runtime,
            packet_dump_dir=rust_runtime / "packet-dump", incoming_dir=rust_runtime / "incoming",
            bootstrap_nodes=bootstrap_nodes,
            shared_roots=shared_roots, server_met_url=args.server_met_url,
            server_endpoint=args.rust_server, obfuscation=obfuscation, timeouts=timeouts,
            ed2k_port=args.rust_ed2k_port, kad_port=args.rust_kad_port,
        )
        rust_proc = rust_handles["process"]
        rust_base = rust_handles["baseUrl"]

        mfc_base = ""
        if not args.no_mfc:
            mfc_handles = bring_up_mfc(
                live_common=mods["live_common"], rest_smoke=mods["rest_smoke"],
                shared_dirs_mod=mods["shared_dirs"], exe_path=mfc_exe,
                seed_config_dir=seed_config_dir, artifacts_dir=mfc_artifacts,
                direct_profile_dir=direct_mfc_profile,
                rest_host=rest_addr, rest_port=args.mfc_rest_port, shared_roots=shared_roots,
                server_endpoint=args.mfc_server, obfuscation=obfuscation, timeouts=timeouts,
                ed2k_port=args.mfc_ed2k_port, kad_port=args.mfc_kad_port,
                server_udp_port=args.mfc_server_udp_port,
            )
            mfc_base = mfc_handles["baseUrl"]

        if not args.no_trackmulebb:
            trackmulebb_proc = start_trackmulebb(rust_url=rust_base, control_host=rest_addr)

        log("=" * 70)
        log("SOAK ENVIRONMENT UP. Drive searches/downloads by hand:")
        log(f"  emulebb-rust REST : {rust_base}   (X-API-Key: {RUST_API_KEY})")
        if not args.no_mfc:
            log(f"  MFC diagnostics   : {mfc_base}   (X-API-Key: {MFC_API_KEY}) + its GUI window")
        if not args.no_trackmulebb:
            log(f"  TrackMuleBB UI    : http://{rest_addr}:{TRACKMULEBB_CONTROL_PORT}  (drives rust)")
        log(f"  operator server   : {OPERATOR_SERVER}")
        log("Dumps accumulate under the persistent profiles; analyze later from this repo.")
        log("Press Ctrl-C to stop everything (profiles + dumps are kept).")
        log("=" * 70)

        while True:
            if rust_proc.poll() is not None:
                log("rust daemon exited - stopping.")
                break
            time.sleep(2.0)
    except KeyboardInterrupt:
        log("Ctrl-C - stopping all launched apps gracefully...")
    finally:
        graceful_teardown(
            rust_handles=rust_handles,
            mfc_handles=mfc_handles,
            trackmulebb_proc=trackmulebb_proc,
            live_common=mods["live_common"],
            rust_base=rust_base,
        )
    soak_run_layout.mark_run_finished(
        run_paths,
        status="stopped",
        extra={"rustRuntimeDir": str(rust_runtime), "mfcArtifactsDir": str(mfc_artifacts)},
    )
    log("soak environment stopped; profiles + dumps preserved under " + str(soak_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
