"""Converged live-wire packet-diff orchestrator for both eMuleBB clients.

Runs the eMuleBB **Rust** client and the eMuleBB **MFC diagnostics** client over
the public network through the hide.me split tunnel, drives the *same* gentle
live exchange against both (eD2K connect + Kad bootstrap, share one small seed
file, run a few widely-spaced keyword searches), captures each side's converged
``ed2k_packet_v1`` packet dump, then diffs the two traces and writes a combined
report.

Both clients expose the same ``/api/v1`` REST surface (``/searches``,
``/shared-directories``, ``/servers/operations/connect``, ``/kad/operations/start``)
and both emit the converged ``ed2k_packet_v1`` packet schema, so a rust-vs-MFC
exchange of the same wire traffic can be checked for wire-faithfulness with
``emule_test_harness.packet_trace_diff`` (and the broader ``diag_event_v1``
envelope with ``emule_test_harness.diag_event_diff``).

No machine paths are baked in: the REST control plane binds ``X_LOCAL_IP``, the
P2P data plane binds the hide.me tunnel, build artifacts live under
``EMULEBB_WORKSPACE_OUTPUT_ROOT``, the search corpus + seed come from the
gitignored live-wire inputs, and the MFC diagnostics exe is resolved from the
output build layout.

This realizes the ``emulebb.flow.converged.live-wire.hideme.v1`` scenario.

GENTLE LIVE DISCIPLINE (hard requirement): a single pass, only a few
widely-spaced searches, one small shared seed file, no run-spamming.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import converged_live_wire as clw
from emule_test_harness import diag_event_diff
from emule_test_harness import packet_trace_diff
from emule_test_harness.hideme_split_tunnel import ensure_vpn_ready
from emule_test_harness.kad_nodes import DEFAULT_NODES_DAT_URL, fetch_bootstrap_endpoints
from emule_test_harness.paths import get_workspace_output_root, reject_windows_temp_path
from emule_test_harness.rust_client import (
    start_rust_client_executable_with_output,
    stop_process_tree,
    write_rust_config,
)
from emule_test_harness.vm_guest_profiles import (
    retry_http_json,
    wait_until,
)

SCENARIO = "emulebb.flow.converged.live-wire.hideme.v1"
OPERATOR_SERVER = "45.82.80.155:5687"
DEFAULT_SERVER_MET_URL = "https://upd.emule-security.org/server.met"
# HIGH listen ports (the 49662/49672 pattern): hide.me's gateway only
# UPnP-forwards high ports, so both clients need high ports for HighID.
ED2K_PORT = 49662
KAD_PORT = 49672
RUST_API_KEY = "converged-live-wire"
MFC_API_KEY = "converged-live-wire-mfc"
# Gentle server-contact policy (avoid Lugdunum IP bans): few, widely-spaced.
DEFAULT_MAX_TERMS = 2
INTER_SEARCH_SECONDS = 60.0
DEFAULT_SEED_FILE_NAME = "converged-seed.txt"
DEFAULT_SEED_BYTES = b"eMuleBB converged live-wire seed fixture\r\n"


def log(message: str) -> None:
    print(f"[converged] {message}", flush=True)


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be set (no local fallbacks are baked in).")
    return value


def load_local_module(module_name: str, filename: str) -> ModuleType:
    """Loads one sibling hyphenated script as an importable module."""

    module_path = SCRIPT_PATH.with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def create_seed_file(seed_dir: Path) -> Path:
    """Creates ONE small shared seed file (gentle: a single tiny fixture)."""

    seed_dir.mkdir(parents=True, exist_ok=True)
    seed_file = seed_dir / DEFAULT_SEED_FILE_NAME
    seed_file.write_bytes(DEFAULT_SEED_BYTES)
    return seed_file


# --------------------------------------------------------------------------- #
# Rust side: reuse rust-live-wire-hideme.py for config/start/connect/search and
# packet-dump summarizers; ADD the share step (it does not share today).
# --------------------------------------------------------------------------- #


def run_rust_side(
    *,
    rust_mod: ModuleType,
    exe_path: Path,
    bind_ip: str,
    rest_addr: str,
    rest_port: int,
    bootstrap_nodes: list[str],
    terms: list[str],
    seed_dir: Path,
    side_dir: Path,
    server_met_url: str,
    timeouts: dict[str, float],
) -> dict[str, Any]:
    """Drives the rust client end-to-end and returns its evidence + dump dir."""

    runtime_dir = side_dir / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    config_path = side_dir / "emulebb-rust.toml"
    daemon_log = side_dir / "daemon.out"
    packet_dump_dir = side_dir / "packet-dump"
    packet_dump_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{rest_addr}:{rest_port}"

    write_rust_config(
        config_path,
        runtime_dir=runtime_dir,
        rest_addr=rest_addr,
        rest_port=rest_port,
        api_key=RUST_API_KEY,
        p2p_bind_ip=bind_ip,
        p2p_bind_interface="hide.me",
        ed2k_port=ED2K_PORT,
        kad_port=KAD_PORT,
        server_endpoint=OPERATOR_SERVER,
        obfuscation_enabled=True,
        kad_bootstrap_nodes=bootstrap_nodes,
        kad_bootstrap_min_routing_contacts=2,
    )
    # Enable UPnP so the P2P stack maps the high ports on the hide.me IGD.
    with config_path.open("a", encoding="utf-8") as cfg:
        cfg.write("\n[nat]\nenabled = true\n")

    os.environ["EMULEBB_RUST_LOG_DIR"] = str(packet_dump_dir)
    handle = daemon_log.open("w", encoding="utf-8")
    process = start_rust_client_executable_with_output(exe_path, config_path, handle)
    evidence: dict[str, Any] = {"client": "rust", "baseUrl": base_url}
    try:
        wait_until("rust REST ready", timeouts["rest"], lambda: rust_mod.get_stats(base_url) or None)
        evidence["serverMetImport"] = rust_mod.import_server_met(base_url, server_met_url)
        retry_http_json(
            "rust kad start", 3, base_url, "/api/v1/kad/operations/start",
            api_key=RUST_API_KEY, method="POST", body={},
        )
        retry_http_json(
            "rust server connect", 3, base_url,
            f"/api/v1/servers/{OPERATOR_SERVER}/operations/connect",
            api_key=RUST_API_KEY, method="POST", body={}, timeout_seconds=15.0,
        )

        # ADDED share step: rust-live-wire-hideme.py never shares; share the same
        # seed file over PATCH /api/v1/shared-directories (same shape as MFC).
        evidence["share"] = retry_http_json(
            "rust share", 2, base_url, "/api/v1/shared-directories",
            api_key=RUST_API_KEY, method="PATCH",
            body=clw.build_shared_directory_patch_payload(seed_dir),
        )

        def connected() -> dict[str, Any] | None:
            stats = rust_mod.get_stats(base_url)
            return stats if (stats.get("ed2kConnected") and stats.get("ed2kHighId")) else None

        stats = wait_until("rust ED2K HighID", timeouts["connect"], connected)
        evidence["ed2kConnected"] = bool(stats.get("ed2kConnected"))
        evidence["ed2kHighId"] = bool(stats.get("ed2kHighId"))

        log("rust: searching corpus (gentle)...")
        search = rust_mod.run_search_corpus(base_url, terms, max_terms=len(terms))
        evidence["search"] = {k: v for k, v in search.items() if k != "candidates"}
    except Exception as exc:  # noqa: BLE001 - record and continue to MFC side
        evidence["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        stop_process_tree(process)
        handle.close()

    evidence["packetDumpDir"] = str(packet_dump_dir)
    evidence["packetSummary"] = rust_mod.summarize_source_exchange_packets(packet_dump_dir)
    return evidence


# --------------------------------------------------------------------------- #
# MFC side: reuse the live profile + REST drivers (search-ui-live /
# shared-directories-rest-e2e / live_e2e_suite). REST binds X_LOCAL_IP, P2P binds
# hide.me, packet diagnostics dump -> side_dir.
# --------------------------------------------------------------------------- #


def run_mfc_side(
    *,
    live_common: ModuleType,
    rest_smoke: ModuleType,
    shared_dirs_mod: ModuleType,
    exe_path: Path,
    seed_config_dir: Path,
    rest_host: str,
    rest_port: int,
    bind_interface: str,
    terms: list[str],
    seed_dir: Path,
    side_dir: Path,
    timeouts: dict[str, float],
) -> dict[str, Any]:
    """Drives the MFC diagnostics client end-to-end and returns its evidence."""

    packet_dump_dir = side_dir / "packet-dump"
    packet_dump_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = side_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{rest_host}:{rest_port}"

    profile = live_common.prepare_profile_base(
        seed_config_dir, artifacts_dir, shared_dirs=[], scenario_id="converged-live-wire"
    )
    config_dir = Path(str(profile["config_dir"]))
    # REST bound to X_LOCAL_IP, P2P bound to the hide.me tunnel interface, both
    # eD2K + Kad enabled for the live exchange.
    rest_smoke.configure_webserver_profile(config_dir, exe_path, MFC_API_KEY, rest_port, rest_host)
    rest_smoke.apply_p2p_bind_interface_override(config_dir, bind_interface)
    live_common.apply_live_network_policy(config_dir)

    # Capture the converged ed2k_packet_v1 dump from the diagnostics build.
    os.environ["EMULEBB_ENABLE_PACKET_DIAGNOSTICS"] = "1"
    os.environ["EMULEBB_PACKET_DIAGNOSTICS_DIR"] = str(packet_dump_dir)

    evidence: dict[str, Any] = {"client": "emule", "baseUrl": base_url}
    app = None
    try:
        app = live_common.launch_app(exe_path, Path(str(profile["profile_base"])))
        rest_smoke.wait_for_rest_ready(base_url, MFC_API_KEY, timeouts["rest"])

        # Same endpoints as rust: server connect, kad start, share, search.
        server_rows = rest_smoke.require_json_array(
            rest_smoke.http_request(base_url, "/api/v1/servers", api_key=MFC_API_KEY), 200
        )
        evidence["serverConnect"] = rest_smoke.connect_to_live_server(
            base_url, MFC_API_KEY, server_rows, timeout_seconds=timeouts["connect"]
        )
        kad_start = rest_smoke.http_request(
            base_url, "/api/v1/kad/operations/start", method="POST",
            api_key=MFC_API_KEY, json_body={},
        )
        evidence["kadStart"] = rest_smoke.compact_http_result(kad_start)

        # Share the SAME seed file via the SAME shared-directories endpoint.
        evidence["share"] = shared_dirs_mod.patch_shared_directories(
            base_url, MFC_API_KEY, clw.build_shared_directory_patch_payload(seed_dir)
        )

        # Run the SAME searches over /api/v1/searches (gentle, widely spaced).
        searches: list[dict[str, Any]] = []
        for index, term in enumerate(terms):
            if index > 0:
                time.sleep(INTER_SEARCH_SECONDS)
            created = rest_smoke.http_request(
                base_url, "/api/v1/searches", method="POST",
                api_key=MFC_API_KEY, json_body=clw.build_search_payload(term),
                request_timeout_seconds=45.0,
            )
            searches.append(rest_smoke.compact_http_result(created))
        evidence["searches"] = searches
    except Exception as exc:  # noqa: BLE001 - record and continue to the diff
        evidence["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
            except Exception:  # noqa: BLE001 - best-effort live cleanup
                try:
                    app.kill()
                except Exception:  # noqa: BLE001
                    pass

    evidence["packetDumpDir"] = str(packet_dump_dir)
    return evidence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inputs", help="Path to the live-wire-inputs.local.json file.")
    parser.add_argument("--profile", default="generic_open", help="search_terms profile to use.")
    parser.add_argument("--profile-seed-dir", help="MFC profile seed config directory.")
    parser.add_argument("--nodes-url", default=DEFAULT_NODES_DAT_URL, help="Kad nodes.dat URL.")
    parser.add_argument("--server-met-url", default=DEFAULT_SERVER_MET_URL, help="server.met URL (empty to disable).")
    parser.add_argument("--rust-rest-port", type=int, default=4731, help="Rust REST port on X_LOCAL_IP.")
    parser.add_argument("--mfc-rest-port", type=int, default=4732, help="MFC REST port on X_LOCAL_IP.")
    parser.add_argument("--bootstrap-limit", type=int, default=40, help="Max Kad bootstrap contacts to seed.")
    parser.add_argument(
        "--max-terms", type=int, default=DEFAULT_MAX_TERMS,
        help="GENTLE: max keyword searches per client (avoid server bans).",
    )
    parser.add_argument("--mfc-variant", default=clw.DEFAULT_MFC_VARIANT, help="MFC build variant.")
    parser.add_argument("--mfc-arch", default=clw.DEFAULT_MFC_ARCH, help="MFC build architecture.")
    parser.add_argument("--mfc-configuration", default=clw.DEFAULT_MFC_CONFIGURATION, help="MFC build configuration.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    rest_addr = require_env("X_LOCAL_IP")
    output_root = get_workspace_output_root()

    rust_exe = output_root / "builds" / "rust" / "target" / "release" / "emulebb-rust.exe"
    if not rust_exe.is_file():
        raise RuntimeError(f"Rust release binary missing: {rust_exe}. Build emulebb-rust (release) first.")
    mfc_exe = clw.resolve_mfc_diagnostics_exe(
        output_root, variant=args.mfc_variant, arch=args.mfc_arch, configuration=args.mfc_configuration
    )

    # Reuse the rust orchestrator + MFC live drivers as importable modules.
    rust_mod = load_local_module("rust_live_wire_hideme_for_converged", "rust-live-wire-hideme.py")
    live_common = load_local_module("emule_live_profile_common_for_converged", "emule-live-profile-common.py")
    rest_smoke = load_local_module("rest_api_smoke_for_converged", "rest-api-smoke.py")
    shared_dirs_mod = load_local_module("shared_directories_rest_e2e_for_converged", "shared-directories-rest-e2e.py")

    inputs_path = Path(args.inputs).resolve() if args.inputs else None
    if inputs_path is None:
        raise RuntimeError("--inputs is required for the live pass (operator-owned live-wire inputs).")
    terms = clw.select_search_terms(rust_mod.load_search_terms(inputs_path, args.profile), max_terms=args.max_terms)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_root / "live-wire" / f"converged-hideme-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)
    seed_dir = run_dir / "seed"
    seed_file = create_seed_file(seed_dir)
    log(f"shared seed file: {seed_file}")

    log(f"ensuring hide.me split tunnel for both clients ({rust_exe.name}, {mfc_exe.name})...")
    rust_vpn = ensure_vpn_ready(rust_exe, name="eMuleBB Rust")
    ensure_vpn_ready(mfc_exe, name="eMuleBB MFC")
    bind_ip = rust_vpn["bindIp"]
    log(f"hide.me bind IP: {bind_ip}")

    log(f"seeding Kad from {args.nodes_url}...")
    bootstrap_nodes = fetch_bootstrap_endpoints(args.nodes_url, limit=args.bootstrap_limit)
    log(f"parsed {len(bootstrap_nodes)} bootstrap contacts")

    timeouts = {"rest": 60.0, "connect": 240.0}

    log("=== rust side ===")
    rust_evidence = run_rust_side(
        rust_mod=rust_mod, exe_path=rust_exe, bind_ip=bind_ip, rest_addr=rest_addr,
        rest_port=args.rust_rest_port, bootstrap_nodes=bootstrap_nodes, terms=terms,
        seed_dir=seed_dir, side_dir=run_dir / "rust", server_met_url=args.server_met_url,
        timeouts=timeouts,
    )

    log("=== MFC diagnostics side ===")
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else mfc_exe.parent
    mfc_evidence = run_mfc_side(
        live_common=live_common, rest_smoke=rest_smoke, shared_dirs_mod=shared_dirs_mod,
        exe_path=mfc_exe, seed_config_dir=seed_config_dir, rest_host=rest_addr,
        rest_port=args.mfc_rest_port, bind_interface="hide.me", terms=terms,
        seed_dir=seed_dir, side_dir=run_dir / "emulebb", timeouts=timeouts,
    )

    # Diff + report.
    log("=== diff + report ===")
    rust_dump_dir = Path(rust_evidence["packetDumpDir"])
    emule_dump_dir = Path(mfc_evidence["packetDumpDir"])
    rust_trace = clw.find_packet_trace(rust_dump_dir, side="rust")
    emule_trace = clw.find_packet_trace(emule_dump_dir, side="emule")

    packet_diff: dict[str, Any] | None = None
    if rust_trace is not None and emule_trace is not None:
        packet_diff = packet_trace_diff.diff_traces(
            packet_trace_diff.load_trace(rust_trace),
            packet_trace_diff.load_trace(emule_trace),
        )
    diag_diff: dict[str, Any] | None = None
    rust_diag = clw.find_diag_trace(rust_dump_dir, side="rust")
    emule_diag = clw.find_diag_trace(emule_dump_dir, side="emule")
    if rust_diag is not None and emule_diag is not None:
        diag_diff = diag_event_diff.diff_traces(
            diag_event_diff.load_trace(rust_diag),
            diag_event_diff.load_trace(emule_diag),
        )

    report = clw.build_converged_report(
        run_id=run_id,
        rust_packet_trace=rust_trace,
        emule_packet_trace=emule_trace,
        packet_diff=packet_diff,
        diag_diff=diag_diff,
        rust_packet_summary=rust_evidence.get("packetSummary"),
        emule_packet_summary=None,
        extra={
            "server": OPERATOR_SERVER,
            "bindIp": bind_ip,
            "ed2kPort": ED2K_PORT,
            "kadPort": KAD_PORT,
            "searchProfile": args.profile,
            "seedFile": str(seed_file),
            "rust": rust_evidence,
            "emule": mfc_evidence,
        },
    )

    report_dir = output_root / "reports" / "converged-live-wire" / run_id
    reject_windows_temp_path(report_dir, "converged report directory")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log(f"report: {report_path}")
    print(json.dumps({"scenario": SCENARIO, "ok": report["ok"], "report": str(report_path)}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
