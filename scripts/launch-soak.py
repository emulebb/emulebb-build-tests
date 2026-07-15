"""Launch the rust<->MFC soak environment against the persistent profiles.

A pure launcher: it brings up emulebb-rust (diagnostics) and the MFC diagnostics
GUI on the persistent, isolated profiles under
``$EMULEBB_WORKSPACE_OUTPUT_ROOT/soak/`` (same operator eD2K server, same nodes.dat
bootstrap, same shared library roots), then idles until Ctrl-C. Drive the clients
through their REST APIs; both diagnostics builds write their ``ed2k_packet_v1`` /
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
import json
import os
import subprocess
import sys
import time
import traceback
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import converged_live_wire as clw
from emule_test_harness import cpu_profile, live_process_monitor, vpn_guard_live
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

DEFAULT_PROFILE_SECONDS = 300.0
DEFAULT_PROCESS_SAMPLE_INTERVAL_SECONDS = 2.0


def resolve_direct_mfc_profile(inputs: LiveWireInputs, *, no_mfc: bool) -> Path | None:
    """Returns the operator-owned MFC profile used for the soak launcher."""

    if no_mfc or inputs.mfc_profile_dir is None:
        return None
    return inputs.mfc_profile_dir.resolve()


def resolve_direct_rust_profile(inputs: LiveWireInputs) -> Path:
    """Returns the operator-owned Rust profile used for the soak launcher."""

    if inputs.rust_profile_dir is None:
        raise RuntimeError("live-wire inputs must define rust_profile.profile_dir for live soak runs.")
    return inputs.rust_profile_dir.resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--inputs",
        help="live-wire-inputs.local.json (shared roots). Default: repo-root copy.",
    )
    parser.add_argument("--lan-bind-addr", required=True, help="LAN IP for REST/control binding; pass X_LOCAL_IP.")
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
    parser.add_argument(
        "--rust-regular",
        action="store_true",
        help=(
            "Run the plain-release emulebb-rust.exe (no packet-diagnostics feature, "
            "no packet/diag dumps) instead of the diagnostics flavor. Build it with "
            "'python -m emule_workspace build clients --client emulebb-rust'."
        ),
    )
    parser.add_argument("--no-obfuscation", action="store_true", help="Disable protocol obfuscation on both clients.")
    parser.add_argument("--nodes-url", default=DEFAULT_NODES_DAT_URL, help="Kad nodes.dat URL (same source for both).")
    parser.add_argument("--server-met-url", default=DEFAULT_SERVER_MET_URL, help="server.met URL for rust import (empty to skip).")
    parser.add_argument("--bootstrap-limit", type=int, default=40)
    parser.add_argument("--rest-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--connect-timeout-seconds", type=float, default=240.0)
    parser.add_argument(
        "--vpn-guard-live-config",
        help="Ignored local VPN Guard config; required when --vpn-guard-scenario is not off.",
    )
    parser.add_argument(
        "--vpn-guard-allowed-public-ip-cidrs",
        default="",
        help="Approved public VPN CIDR allowlist; defaults to the VPN Guard live config value.",
    )
    parser.add_argument(
        "--vpn-guard-scenario",
        choices=("off", "success"),
        default="off",
        help="Set to success for public live-wire runs; off is only for explicit guard-off scenarios.",
    )
    parser.add_argument("--cpu-profile", action="store_true", help="Run the soak under bounded ETW sampled CPU profiling.")
    parser.add_argument("--cpu-profile-seconds", type=float, default=DEFAULT_PROFILE_SECONDS)
    parser.add_argument("--cpu-profile-max-file-mb", type=int, default=cpu_profile.DEFAULT_CPU_PROFILE_MAX_FILE_MB)
    parser.add_argument("--cpu-profile-stack", action="store_true", help="Export a symbolized xperf stack butterfly report.")
    parser.add_argument("--cpu-profile-stack-min-hits", type=int, default=10)
    parser.add_argument(
        "--cpu-profile-symbols-optional",
        action="store_true",
        help="Continue when the staged app-local PDB is absent.",
    )
    parser.add_argument(
        "--process-metrics",
        action="store_true",
        help="Sample Rust process CPU and memory metrics even when ETW CPU profiling is disabled.",
    )
    parser.add_argument("--process-sample-interval", type=float, default=DEFAULT_PROCESS_SAMPLE_INTERVAL_SECONDS)
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=0.0,
        help="Stop the soak after this many seconds with the same graceful teardown path as Ctrl-C.",
    )
    parser.add_argument("--rust-ui", action="store_true", help="Launch the staged native Rust UI during the soak.")
    parser.add_argument("--rust-ui-poll-interval-ms", type=int, default=5_000)
    parser.add_argument("--profile-seed-dir", help="MFC profile seed config directory.")
    parser.add_argument("--mfc-variant", default=clw.DEFAULT_MFC_VARIANT)
    parser.add_argument("--mfc-arch", default=clw.DEFAULT_MFC_ARCH)
    parser.add_argument("--mfc-configuration", default=clw.DEFAULT_MFC_CONFIGURATION)
    return parser


def resolve_vpn_guard_profile(args: argparse.Namespace) -> dict[str, str | None]:
    """Resolves the VPN Guard mode and approved CIDRs for one launcher run."""

    if args.vpn_guard_scenario == "off":
        return {"mode": "off", "allowed_public_ip_cidrs": "", "config_path": None}

    config_path = Path(args.vpn_guard_live_config).resolve() if args.vpn_guard_live_config else None
    if config_path is None or not config_path.is_file():
        raise RuntimeError("--vpn-guard-live-config is required for --vpn-guard-scenario success.")

    config = vpn_guard_live.load_config(config_path)
    interface_name = str(config.get("p2pBindInterfaceName") or "").strip()
    if interface_name.casefold() != vpn_guard_live.HIDEME_INTERFACE_NAME:
        raise RuntimeError(f"VPN Guard live config must bind P2P to hide.me, got {interface_name!r}.")

    cidrs = args.vpn_guard_allowed_public_ip_cidrs.strip() or str(config.get("allowedPublicIpCidrs") or "").strip()
    vpn_guard_live.require_hideme_public_cidrs(cidrs)
    return {"mode": "block", "allowed_public_ip_cidrs": cidrs, "config_path": str(config_path)}


def initialize_cpu_profile(
    *,
    args: argparse.Namespace,
    run_paths: soak_run_layout.SoakRunPaths,
    rust_exe: Path,
) -> tuple[cpu_profile.CpuProfileTools | None, cpu_profile.CpuProfilePaths | None, dict[str, object] | None]:
    """Starts ETW CPU profiling when requested and returns the mutable report."""

    if not args.cpu_profile:
        return None, None, None
    if args.cpu_profile_seconds <= 0:
        raise RuntimeError("--cpu-profile-seconds must be greater than zero.")
    if args.cpu_profile_max_file_mb <= 0:
        raise RuntimeError("--cpu-profile-max-file-mb must be greater than zero.")
    if args.cpu_profile_stack_min_hits <= 0:
        raise RuntimeError("--cpu-profile-stack-min-hits must be greater than zero.")

    profile_paths = cpu_profile.build_cpu_profile_paths(run_paths.report_dir)
    profile_report: dict[str, object] = {
        "enabled": True,
        "tool": "xperf",
        "app_exe": str(rust_exe),
        "profile_paths": {
            "etl": str(profile_paths.etl_path),
            "detail": str(profile_paths.detail_path),
            "summary": str(profile_paths.summary_path),
            "stack": str(profile_paths.stack_path),
        },
        "max_file_mb": args.cpu_profile_max_file_mb,
        "seconds": args.cpu_profile_seconds,
        "stack": bool(args.cpu_profile_stack),
        "stack_min_hits": args.cpu_profile_stack_min_hits,
    }
    tools = cpu_profile.discover_cpu_profile_tools()
    if not tools.xperf:
        profile_report["status"] = "failed"
        profile_report["error"] = "xperf was not found."
        return tools, profile_paths, profile_report

    pdb_path = cpu_profile.resolve_app_pdb_path(rust_exe)
    profile_report["symbols"] = {"app_pdb": str(pdb_path), "app_pdb_exists": pdb_path.is_file()}
    if not args.cpu_profile_symbols_optional and not pdb_path.is_file():
        profile_report["status"] = "failed"
        profile_report["error"] = f"Required app symbols were not found: {pdb_path}"
        return tools, profile_paths, profile_report

    start = cpu_profile.start_cpu_profile(
        tools=tools,
        paths=profile_paths,
        max_file_mb=args.cpu_profile_max_file_mb,
        timeout_seconds=30.0,
    )
    profile_report["start"] = start
    return tools, profile_paths, profile_report


def finalize_cpu_profile(
    *,
    tools: cpu_profile.CpuProfileTools | None,
    paths: cpu_profile.CpuProfilePaths | None,
    report: dict[str, object] | None,
    rust_exe: Path,
    extra_process_images: list[str] | None = None,
    include_stack: bool,
    stack_min_hits: int,
) -> dict[str, object] | None:
    """Stops and exports ETW CPU profiling when it was started."""

    if tools is None or paths is None or report is None:
        return report
    if not tools.xperf:
        return report
    if report.get("status") == "failed" and "start" not in report:
        return report

    stop = cpu_profile.stop_cpu_profile(tools=tools, paths=paths, timeout_seconds=60.0)
    report["stop"] = stop
    if report.get("start", {}).get("return_code") == 0 and stop.get("return_code") == 0 and paths.etl_path.is_file():
        export = cpu_profile.export_cpu_profile(
            tools=tools,
            paths=paths,
            app_exe=rust_exe,
            timeout_seconds=90.0,
            include_stack=include_stack,
            stack_min_hits=stack_min_hits,
        )
        detail_summary = cpu_profile.parse_xperf_profile_detail_file(paths.detail_path, process_image=rust_exe.name)
        details_by_process = {rust_exe.name: detail_summary}
        for process_image in extra_process_images or []:
            details_by_process[process_image] = cpu_profile.parse_xperf_profile_detail_file(
                paths.detail_path,
                process_image=process_image,
            )
        stack_summary = (
            cpu_profile.parse_xperf_stack_report_file(paths.stack_path)
            if include_stack
            else {"available": False, "reason": "stack export disabled"}
        )
        combined_summary = {"detail": detail_summary, "detail_by_process": details_by_process, "stack": stack_summary}
        paths.summary_path.parent.mkdir(parents=True, exist_ok=True)
        paths.summary_path.write_text(json.dumps(combined_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        report["export"] = export
        report["summary"] = combined_summary
        report["status"] = "passed" if detail_summary.get("available") or stack_summary.get("available") else "failed"
    else:
        report["status"] = "failed"
    return report


class RustProcessMetrics:
    """Samples a launched Rust-family process into the soak report directory."""

    def __init__(self, *, process, report_dir: Path, interval_seconds: float, label: str = "rust") -> None:
        self.process = process
        self.report_dir = report_dir
        self.interval_seconds = interval_seconds
        self.label = label
        self.started = time.monotonic()
        self.last_sample_monotonic: float | None = None
        self.last_cpu_seconds: float | None = None
        self.next_sample = 0.0
        self.rows: list[dict[str, object]] = []
        self.handle: int | None = None
        self.csv_path = report_dir / "analysis" / f"{label}-process-metrics.csv"
        self.summary_path = report_dir / "analysis" / f"{label}-process-metrics-summary.json"
        self.handle = live_process_monitor.open_process(process.pid)

    def maybe_sample(self) -> dict[str, object] | None:
        now = time.monotonic()
        if self.handle is None or now < self.next_sample:
            return None
        row = live_process_monitor.sample_process_metrics(
            handle=self.handle,
            started_monotonic=self.started,
            last_sample_monotonic=self.last_sample_monotonic,
            last_cpu_seconds=self.last_cpu_seconds,
        )
        row["pid"] = self.process.pid
        self.rows.append(row)
        self.last_sample_monotonic = time.monotonic()
        self.last_cpu_seconds = float(row["cpu_seconds"])
        self.next_sample = now + self.interval_seconds
        live_process_monitor.write_metric_csv(self.csv_path, self.rows)
        self.write_summary()
        return row

    def write_summary(self) -> dict[str, object]:
        summary = live_process_monitor.summarize_metric_rows(self.rows)
        payload = {
            "enabled": True,
            "label": self.label,
            "pid": self.process.pid,
            "csv_path": str(self.csv_path),
            "summary": summary,
        }
        self.summary_path.parent.mkdir(parents=True, exist_ok=True)
        self.summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return payload

    def close(self) -> None:
        if self.handle is not None:
            live_process_monitor.close_handle(self.handle)
            self.handle = None


def graceful_teardown(
    *,
    rust_handles: dict | None,
    rust_ui_handles: dict | None,
    mfc_handles: dict | None,
    live_common,
    rust_base: str,
    wait_seconds: float = 15.0,
) -> None:
    """Stops everything the launcher started, gracefully, with a bounded fallback.

    Asks each component to stop cleanly (rust via ``POST /api/v1/app/shutdown`` →
    its graceful network teardown; the MFC GUI via ``close_app_cleanly`` → the
    eMule save-and-exit path that persists known.met), then waits up to
    ``wait_seconds`` for the processes to exit before force-killing any straggler.
    A second Ctrl-C during the wait jumps straight to the kill.
    """

    if rust_handles is not None and rust_handles["process"].poll() is None:
        log("rust: requesting graceful shutdown (POST /api/v1/app/shutdown)...")
        try:
            retry_http_json(
                "rust shutdown", 1, rust_base, "/api/v1/app/shutdown",
                api_key=RUST_API_KEY, method="POST", body={"confirmShutdown": True}, timeout_seconds=5.0,
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
    if rust_ui_handles is not None and rust_ui_handles["process"].poll() is None:
        log("rust UI: closing native window...")
        try:
            rust_ui_handles["closeResult"] = live_process_monitor.close_process_gracefully(
                rust_ui_handles["process"],
                rust_ui_handles["processHandle"],
                timeout_seconds=15.0,
            )
        except Exception:  # noqa: BLE001
            try:
                rust_ui_handles["process"].kill()
            except Exception:  # noqa: BLE001
                pass
    watched = [
        proc
        for proc in (rust_handles["process"] if rust_handles is not None else None,)
        if proc is not None
    ]
    deadline = time.monotonic() + wait_seconds
    try:
        while time.monotonic() < deadline and any(proc.poll() is None for proc in watched):
            time.sleep(0.5)
    except KeyboardInterrupt:
        log("second interrupt - force-killing now.")

    if rust_handles is not None:
        if rust_handles["process"].poll() is None:
            log("rust did not exit in time - force-killing.")
            stop_process_tree(rust_handles["process"])
        try:
            rust_handles["logHandle"].close()
        except Exception:  # noqa: BLE001
            pass
    if rust_ui_handles is not None:
        try:
            live_process_monitor.close_handle(rust_ui_handles["processHandle"])
        except Exception:  # noqa: BLE001
            pass
        try:
            rust_ui_handles["logHandle"].close()
        except Exception:  # noqa: BLE001
            pass


def resolve_rust_ui_exe(output_root: Path) -> Path:
    """Returns the staged native Rust UI executable."""

    path = output_root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust-ui.exe"
    if not path.is_file():
        raise RuntimeError(f"Staged emulebb-rust-ui executable was not found: {path}")
    return path


def launch_rust_ui(
    *,
    ui_exe: Path,
    rust_base: str,
    api_key: str,
    poll_interval_ms: int,
    report_dir: Path,
) -> dict[str, object]:
    """Launches the native Rust UI against the live soak daemon."""

    if poll_interval_ms < 1_000:
        raise RuntimeError("--rust-ui-poll-interval-ms must be at least 1000.")
    output_path = report_dir / "analysis" / "rust-ui.out"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("a", encoding="utf-8")
    base_url = rust_base.rstrip("/") + "/api/v1"
    process = subprocess.Popen(
        [
            str(ui_exe),
            "--base-url",
            base_url,
            "--api-key",
            api_key,
            "--poll-interval-ms",
            str(poll_interval_ms),
        ],
        cwd=ui_exe.parent,
        stdout=output_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    handle = live_process_monitor.open_process(process.pid)
    log(f"rust native UI up - pid {process.pid}, REST {base_url}")
    return {
        "process": process,
        "processHandle": handle,
        "logHandle": output_handle,
        "outputPath": str(output_path),
        "baseUrl": base_url,
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.duration_seconds < 0:
        raise RuntimeError("--duration-seconds must not be negative.")
    if args.rest_timeout_seconds <= 0:
        raise RuntimeError("--rest-timeout-seconds must be greater than zero.")
    if args.connect_timeout_seconds <= 0:
        raise RuntimeError("--connect-timeout-seconds must be greater than zero.")
    obfuscation = not args.no_obfuscation
    endpoint_ports = soak_launch.require_distinct_endpoint_ports(
        rust_ed2k_port=args.rust_ed2k_port,
        rust_kad_port=args.rust_kad_port,
        mfc_ed2k_port=args.mfc_ed2k_port,
        mfc_kad_port=args.mfc_kad_port,
        mfc_server_udp_port=args.mfc_server_udp_port,
    )
    soak_launch.require_operator_server_endpoint(args.rust_server, label="--rust-server")
    soak_launch.require_operator_server_endpoint(args.mfc_server, label="--mfc-server")
    vpn_guard_profile = resolve_vpn_guard_profile(args)

    rest_addr = soak_launch.resolve_lan_rest_bind_addr(args.lan_bind_addr)
    output_root = get_workspace_output_root()

    rust_exe = (
        clw.resolve_rust_regular_exe(output_root)
        if args.rust_regular
        else clw.resolve_rust_diagnostics_exe(output_root)
    )
    rust_ui_exe = resolve_rust_ui_exe(output_root) if args.rust_ui else None
    mfc_exe = None
    if not args.no_mfc:
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
    rust_profile_dir = resolve_direct_rust_profile(inputs)
    shared_roots = rust_mod.load_shared_roots(inputs_path)
    if not shared_roots:
        raise RuntimeError("No shared_directories.roots in the live-wire inputs - nothing to share.")

    soak_root = output_root / "soak"
    campaign_id = soak_run_layout.utc_campaign_id()
    mfc_artifacts = soak_root / "mfc-profile"
    mfc_log_dir = None if args.no_mfc else soak_run_layout.mfc_soak_log_dir(
        mfc_artifacts_dir=mfc_artifacts,
        direct_profile_dir=direct_mfc_profile,
    )
    run_paths = soak_run_layout.build_run_paths(soak_root, campaign_id)
    preflight_manifest = soak_run_layout.prepare_clean_run(
        paths=run_paths,
        rust_profile_dir=rust_profile_dir,
        rust_packet_dump_dir=rust_profile_dir / "packet-dump",
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
    if vpn_guard_profile["mode"] == "block":
        log(
            "VPN Guard enabled for hide.me with CIDRs: "
            + str(vpn_guard_profile["allowed_public_ip_cidrs"])
        )
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
    timeouts = {"rest": args.rest_timeout_seconds, "connect": args.connect_timeout_seconds}

    rust_handles: dict | None = None
    rust_ui_handles: dict | None = None
    mfc_handles: dict | None = None
    rust_base = ""
    profile_tools: cpu_profile.CpuProfileTools | None = None
    profile_paths: cpu_profile.CpuProfilePaths | None = None
    profile_report: dict[str, object] | None = None
    process_metrics: RustProcessMetrics | None = None
    ui_process_metrics: RustProcessMetrics | None = None
    status = "stopped"
    failure: dict[str, object] | None = None
    try:
        profile_tools, profile_paths, profile_report = initialize_cpu_profile(
            args=args,
            run_paths=run_paths,
            rust_exe=rust_exe,
        )
        rust_handles = bring_up_rust(
            rust_mod=rust_mod, exe_path=rust_exe, bind_ip=bind_ip, rest_addr=rest_addr,
            rest_port=args.rust_rest_port, profile_dir=rust_profile_dir,
            packet_dump_dir=rust_profile_dir / "packet-dump", incoming_dir=rust_profile_dir / "incoming",
            bootstrap_nodes=bootstrap_nodes,
            shared_roots=shared_roots, server_met_url=args.server_met_url,
            server_endpoint=args.rust_server, obfuscation=obfuscation, timeouts=timeouts,
            ed2k_port=args.rust_ed2k_port, kad_port=args.rust_kad_port,
            enable_packet_dump=not args.rust_regular,
            vpn_guard_mode=str(vpn_guard_profile["mode"]),
            vpn_guard_allowed_public_ip_cidrs=str(vpn_guard_profile["allowed_public_ip_cidrs"] or ""),
        )
        rust_proc = rust_handles["process"]
        rust_base = rust_handles["baseUrl"]
        if args.cpu_profile or args.process_metrics:
            process_metrics = RustProcessMetrics(
                process=rust_proc,
                report_dir=run_paths.report_dir,
                interval_seconds=args.process_sample_interval,
                label="rust",
            )
        if rust_ui_exe is not None:
            rust_ui_handles = launch_rust_ui(
                ui_exe=rust_ui_exe,
                rust_base=rust_base,
                api_key=RUST_API_KEY,
                poll_interval_ms=args.rust_ui_poll_interval_ms,
                report_dir=run_paths.report_dir,
            )
            if args.cpu_profile or args.process_metrics:
                ui_process_metrics = RustProcessMetrics(
                    process=rust_ui_handles["process"],
                    report_dir=run_paths.report_dir,
                    interval_seconds=args.process_sample_interval,
                    label="rust-ui",
                )

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
                vpn_guard_mode=str(vpn_guard_profile["mode"]),
                vpn_guard_allowed_public_ip_cidrs=str(vpn_guard_profile["allowed_public_ip_cidrs"] or ""),
            )
            mfc_base = mfc_handles["baseUrl"]

        log("=" * 70)
        log("SOAK ENVIRONMENT UP. Drive searches/downloads through REST automation:")
        log(f"  emulebb-rust REST : {rust_base}   (X-API-Key: {RUST_API_KEY})")
        if not args.no_mfc:
            log(f"  MFC diagnostics   : {mfc_base}   (X-API-Key: {MFC_API_KEY}) + its GUI window")
        log(f"  operator server   : {OPERATOR_SERVER}")
        log("Dumps accumulate under the persistent profiles; analyze later from this repo.")
        if args.cpu_profile:
            log(f"Profiling for {args.cpu_profile_seconds:.0f}s; artifacts: {run_paths.report_dir / 'analysis'}")
        log("Press Ctrl-C to stop everything (profiles + dumps are kept).")
        log("=" * 70)

        duration_deadline = time.monotonic() + args.duration_seconds if args.duration_seconds > 0 else None
        profile_deadline = time.monotonic() + args.cpu_profile_seconds if args.cpu_profile and duration_deadline is None else None
        last_metrics_log = 0.0
        while True:
            if rust_proc.poll() is not None:
                log("rust daemon exited - stopping.")
                status = "rust-exited"
                break
            row = process_metrics.maybe_sample() if process_metrics is not None else None
            ui_row = ui_process_metrics.maybe_sample() if ui_process_metrics is not None else None
            if row is not None and time.monotonic() - last_metrics_log >= 30.0:
                log(
                    "rust metrics: "
                    f"cpu_one_core={row['process_pct_one_core']}% "
                    f"private={row['private_mb']}MiB ws={row['working_set_mb']}MiB "
                    f"handles={row['handles']}"
                )
                if ui_row is not None:
                    log(
                        "rust UI metrics: "
                        f"cpu_one_core={ui_row['process_pct_one_core']}% "
                        f"private={ui_row['private_mb']}MiB ws={ui_row['working_set_mb']}MiB "
                        f"handles={ui_row['handles']}"
                    )
                last_metrics_log = time.monotonic()
            if profile_deadline is not None and time.monotonic() >= profile_deadline:
                log("CPU profile window complete - stopping.")
                status = "profile-complete"
                break
            if duration_deadline is not None and time.monotonic() >= duration_deadline:
                log("duration window complete - stopping.")
                status = "duration-complete"
                break
            time.sleep(2.0)
    except KeyboardInterrupt:
        log("Ctrl-C - stopping all launched apps gracefully...")
    except Exception as exc:
        status = "failed"
        failure = {
            "type": type(exc).__name__,
            "message": str(exc) or repr(exc),
            "traceback": traceback.format_exc(),
        }
        log(f"soak launch failed: {failure['type']}: {failure['message']}")
    finally:
        profile_report = finalize_cpu_profile(
            tools=profile_tools,
            paths=profile_paths,
            report=profile_report,
            rust_exe=rust_exe,
            extra_process_images=[rust_ui_exe.name] if rust_ui_exe is not None else None,
            include_stack=args.cpu_profile_stack,
            stack_min_hits=args.cpu_profile_stack_min_hits,
        )
        process_metrics_summary = None
        ui_process_metrics_summary = None
        if process_metrics is not None:
            try:
                process_metrics_summary = process_metrics.write_summary()
            finally:
                process_metrics.close()
        if ui_process_metrics is not None:
            try:
                ui_process_metrics_summary = ui_process_metrics.write_summary()
            finally:
                ui_process_metrics.close()
        graceful_teardown(
            rust_handles=rust_handles,
            rust_ui_handles=rust_ui_handles,
            mfc_handles=mfc_handles,
            live_common=mods["live_common"],
            rust_base=rust_base,
        )
    soak_run_layout.mark_run_finished(
        run_paths,
        status=status,
        extra={
            "rustProfileDir": str(rust_profile_dir),
            "mfcArtifactsDir": str(mfc_artifacts),
            "rustExe": str(rust_exe),
            "rustUi": {
                "enabled": bool(args.rust_ui),
                "exe": str(rust_ui_exe) if rust_ui_exe is not None else None,
                "pid": rust_ui_handles["process"].pid if rust_ui_handles is not None else None,
                "outputPath": rust_ui_handles.get("outputPath") if rust_ui_handles is not None else None,
            },
            "durationSeconds": args.duration_seconds,
            "error": failure,
            "vpnGuard": vpn_guard_profile,
            "cpuProfile": profile_report,
            "processMetrics": process_metrics_summary,
            "rustUiProcessMetrics": ui_process_metrics_summary,
        },
    )
    log("soak environment stopped; profiles + dumps preserved under " + str(soak_root))
    return 1 if status == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
