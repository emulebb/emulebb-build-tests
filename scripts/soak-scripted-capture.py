"""Solo scripted-action capture for the capture-then-offline-diff parity model.

Brings up ONE client (rust OR mfc) on the persisted profile, ensures operator +
Kad, runs the identical scripted action set (``scripted_actions``) with begin/end
markers, packs the run's diag + packet dumps + markers into a compressed recording
under ``$OUTPUT_ROOT/soak/reports/<campaign>/``, then tears the client down.

Run it once per client (``--client rust`` then ``--client mfc``) — SEQUENTIALLY,
never simultaneously: two HighID clients on one hide.me egress IP share a
``client_id`` and the operator flaps rust off (see the converged-soak-live memo).
The two recordings are then diffed offline by ``actionId`` — apples-to-apples,
reproducible, contention-free.

Downloads use fixed ed2k hashes from the git-ignored live-wire inputs; nothing
sensitive is committed. Be-gentle: small spaced action set, single pass.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import converged_live_wire as clw
from emule_test_harness import scripted_actions, soak_launch
from emule_test_harness.hideme_split_tunnel import ensure_vpn_ready
from emule_test_harness.kad_nodes import DEFAULT_NODES_DAT_URL, fetch_bootstrap_endpoints
from emule_test_harness.live_wire_inputs import load_live_wire_inputs
from emule_test_harness.paths import get_workspace_output_root
from emule_test_harness.rust_client import stop_process_tree
from emule_test_harness.soak_launch import (
    DEFAULT_MFC_SEED_CONFIG_DIR,
    DEFAULT_SERVER_MET_URL,
    MFC_API_KEY,
    MFC_ED2K_PORT,
    MFC_KAD_PORT,
    MFC_SERVER_UDP_PORT,
    OPERATOR_SERVER,
    RUST_API_KEY,
    RUST_ED2K_PORT,
    RUST_KAD_PORT,
    bring_up_mfc,
    bring_up_rust,
    log,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--client", required=True, choices=("rust", "mfc"), help="Which client to capture (solo).")
    parser.add_argument("--campaign", default=None, help="Report subfolder name (default: UTC timestamp).")
    parser.add_argument("--inputs", help="live-wire-inputs.local.json. Default: repo-root copy.")
    parser.add_argument("--rest-port", type=int, default=None, help="REST port (default 4731 rust / 4732 mfc).")
    parser.add_argument("--rust-ed2k-port", type=int, default=RUST_ED2K_PORT)
    parser.add_argument("--rust-kad-port", type=int, default=RUST_KAD_PORT)
    parser.add_argument("--mfc-ed2k-port", type=int, default=MFC_ED2K_PORT)
    parser.add_argument("--mfc-kad-port", type=int, default=MFC_KAD_PORT)
    parser.add_argument("--mfc-server-udp-port", type=int, default=MFC_SERVER_UDP_PORT)
    parser.add_argument("--search-methods", default="server,global,kad", help="Comma list of search methods.")
    parser.add_argument(
        "--search-terms",
        default="ubuntu,linux,debian",
        help="Well-sourced search terms (round-robin over methods). AVOID stale terms (e.g. fedora).",
    )
    parser.add_argument(
        "--download-terms",
        default="ubuntu,linux",
        help="Terms searched to RESOLVE well-sourced download fixtures (ranked by source count).",
    )
    parser.add_argument("--fixture-count", type=int, default=2, help="How many sourced download fixtures to use.")
    parser.add_argument(
        "--fixture-hashes",
        default=None,
        help="Explicit CSV of ed2k hashes to download (overrides resolution; use to reuse across runs).",
    )
    parser.add_argument("--spacing-seconds", type=float, default=scripted_actions.DEFAULT_SPACING_SECONDS)
    parser.add_argument("--settle-seconds", type=float, default=90.0, help="Post-action wait for source-acquisition.")
    parser.add_argument(
        "--skip-actions",
        action="store_true",
        help="Skip searches/download fixtures and only hold the operator server connection.",
    )
    parser.add_argument(
        "--hold-seconds",
        type=float,
        default=0.0,
        help="After connect/actions, hold the client open and poll REST server status for this many seconds.",
    )
    parser.add_argument("--hold-poll-seconds", type=float, default=5.0, help="REST poll cadence for --hold-seconds.")
    parser.add_argument(
        "--fresh-profile",
        action="store_true",
        help="Use a per-report client profile/runtime instead of the persisted soak profile.",
    )
    parser.add_argument(
        "--no-shared-roots",
        action="store_true",
        help="Do not import live-wire shared roots; useful for a pure connection hold.",
    )
    parser.add_argument("--no-obfuscation", action="store_true")
    parser.add_argument(
        "--secident",
        choices=("on", "off"),
        default="on",
        help="SecIdent campaign dimension: pins the MFC SecureIdent preference explicitly "
        "(default on). emulebb-rust has NO secident config key (always provisioned), so "
        "'off' captures an asymmetric run that is recorded as such in results.json.",
    )
    parser.add_argument("--nodes-url", default=DEFAULT_NODES_DAT_URL)
    parser.add_argument("--server-met-url", default=DEFAULT_SERVER_MET_URL)
    parser.add_argument("--profile-seed-dir", default=None)
    parser.add_argument("--mfc-variant", default=clw.DEFAULT_MFC_VARIANT)
    parser.add_argument("--mfc-arch", default=clw.DEFAULT_MFC_ARCH)
    parser.add_argument("--mfc-configuration", default=clw.DEFAULT_MFC_CONFIGURATION)
    return parser


def _utc_stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _http(base_url: str, api_key: str, path: str, method: str = "GET", body: object = None, timeout: float = 20.0) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"X-API-Key": api_key}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base_url + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - trusted LAN REST
        return json.loads(response.read())


def _status_data(payload: dict) -> dict:
    data = payload.get("data")
    return data if isinstance(data, dict) else payload


def _server_status_snapshot(payload: dict, *, request_seconds: float, error: str | None = None) -> dict:
    data = _status_data(payload)
    servers = data.get("servers") if isinstance(data, dict) else {}
    servers = servers if isinstance(servers, dict) else {}
    current = servers.get("currentServer")
    current = current if isinstance(current, dict) else {}
    return {
        "epoch": time.time(),
        "requestSeconds": round(request_seconds, 3),
        "restOk": error is None,
        "error": error,
        "connected": bool(servers.get("connected") or current.get("connected")),
        "connecting": bool(servers.get("connecting") or current.get("connecting")),
        "address": str(current.get("address") or ""),
        "port": int(current.get("port") or 0),
        "name": str(current.get("name") or ""),
        "serverCount": int(servers.get("serverCount") or 0),
    }


def observe_operator_hold(
    base_url: str,
    api_key: str,
    *,
    endpoint: str,
    hold_seconds: float,
    poll_seconds: float,
) -> dict:
    """Polls REST while the selected eD2K server connection is expected to stay pinned."""

    expected_host, expected_port_text = endpoint.rsplit(":", 1)
    expected_port = int(expected_port_text)
    deadline = time.monotonic() + hold_seconds
    snapshots: list[dict] = []
    log(f"hold: polling selected server connection for {int(hold_seconds)}s every {poll_seconds:g}s")
    while time.monotonic() < deadline:
        started = time.monotonic()
        try:
            payload = _http(base_url, api_key, "/api/v1/status", timeout=min(10.0, max(2.0, poll_seconds)))
            elapsed = time.monotonic() - started
            snapshot = _server_status_snapshot(payload, request_seconds=elapsed)
        except Exception as exc:  # noqa: BLE001
            elapsed = time.monotonic() - started
            snapshot = _server_status_snapshot({}, request_seconds=elapsed, error=f"{type(exc).__name__}: {exc}")
        snapshots.append(snapshot)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_seconds, remaining))

    mismatches = [
        row
        for row in snapshots
        if row["restOk"] and row["connected"] and (row["address"] != expected_host or row["port"] != expected_port)
    ]
    disconnected = [row for row in snapshots if row["restOk"] and not row["connected"]]
    rest_errors = [row for row in snapshots if not row["restOk"]]
    max_request = max((float(row["requestSeconds"]) for row in snapshots), default=0.0)
    return {
        "seconds": int(hold_seconds),
        "pollSeconds": poll_seconds,
        "expectedEndpoint": endpoint,
        "sampleCount": len(snapshots),
        "restErrors": len(rest_errors),
        "disconnectedSamples": len(disconnected),
        "endpointMismatchSamples": len(mismatches),
        "maxRequestSeconds": round(max_request, 3),
        "passed": not rest_errors and not disconnected and not mismatches,
        "firstFailure": (rest_errors or disconnected or mismatches or [None])[0],
        "snapshots": snapshots,
    }


def ensure_kad(base_url: str, api_key: str, *, wait_seconds: float = 120.0) -> bool:
    """Start Kad and wait (bounded) for it to connect."""

    try:
        _http(base_url, api_key, "/api/v1/kad/operations/start", "POST", {})
    except Exception as exc:  # noqa: BLE001
        log(f"kad start request note: {type(exc).__name__}")
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        try:
            data = _http(base_url, api_key, "/api/v1/status").get("data", {})
            if (data.get("kad") or {}).get("connected"):
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(4.0)
    return False


def resolve_sourced_fixtures(
    base_url: str, api_key: str, terms: list[str], count: int, *, poll_seconds: float = 25.0
) -> list[dict]:
    """Search well-sourced terms and return the top ``count`` results BY SOURCE COUNT
    (sources > 0 only), as {hash,name,size} download fixtures. This is why downloads
    use ubuntu/linux and not a stale/synthetic hash: the source-acquisition + transfer
    comparison is only meaningful against files that actually have sources."""

    seen: dict[str, dict] = {}
    for term in terms:
        result = scripted_actions.run_search(base_url, api_key, term, "global", poll_seconds=poll_seconds)
        search_id = result.get("searchId") or ""
        try:
            page = _http(base_url, api_key, f"/api/v1/searches/{search_id}")
        except Exception:  # noqa: BLE001
            continue
        rows = page.get("data", {}).get("items") if isinstance(page.get("data"), dict) else None
        for row in rows or []:
            file_hash = str(row.get("hash") or "").strip().lower()
            sources = int(row.get("sources") or row.get("completeSources") or 0)
            size = int(row.get("sizeBytes") or row.get("size") or 0)
            name = str(row.get("name") or row.get("fileName") or "").strip()
            if len(file_hash) != 32 or sources <= 0 or size <= 0 or not name:
                continue
            existing = seen.get(file_hash)
            if existing is None or sources > int(existing["sources"]):
                seen[file_hash] = {"hash": file_hash, "name": name, "size": size, "sources": sources}
    ranked = sorted(seen.values(), key=lambda fx: (-int(fx["sources"]), int(fx["size"])))
    return [{"hash": fx["hash"], "name": fx["name"], "size": fx["size"]} for fx in ranked[:count]]


def campaign_fixtures(
    *, campaign_dir: Path, base_url: str, api_key: str, explicit_hashes: str | None,
    download_terms: list[str], count: int,
) -> list[dict]:
    """Resolve download fixtures once per campaign and reuse them across the two solo
    runs so both clients fetch the SAME sourced files (apples-to-apples)."""

    fixtures_path = campaign_dir / "fixtures.json"
    if explicit_hashes:
        # Explicit hashes: sizes/names come from a quick search lookup if resolvable.
        wanted = {h.strip().lower() for h in explicit_hashes.split(",") if h.strip()}
        resolved = [fx for fx in resolve_sourced_fixtures(base_url, api_key, download_terms, count * 4) if fx["hash"] in wanted]
        if resolved:
            return resolved
    if fixtures_path.is_file():
        return json.loads(fixtures_path.read_text(encoding="utf-8"))
    fixtures = resolve_sourced_fixtures(base_url, api_key, download_terms, count)
    fixtures_path.parent.mkdir(parents=True, exist_ok=True)
    fixtures_path.write_text(json.dumps(fixtures, indent=2), encoding="utf-8")
    return fixtures


def gather_recording(dump_dir: Path, dest: Path, since: float) -> int:
    """Copy diag + packet dump files touched at/after ``since`` into ``dest``."""

    dest.mkdir(parents=True, exist_ok=True)
    copied = 0
    for path in dump_dir.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if not (name.endswith(".jsonl") or name.endswith(".log")):
            continue
        if path.stat().st_mtime < since:
            continue
        try:
            shutil.copy2(path, dest / path.name)
            copied += 1
        except Exception:  # noqa: BLE001
            continue
    return copied


def pack_recording(report_dir: Path) -> Path:
    """Zip the recording dir (dumps are text → compress well) and drop the loose dumps."""

    archive = report_dir.with_suffix(".zip")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in report_dir.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(report_dir.parent))
    shutil.rmtree(report_dir, ignore_errors=True)
    return archive


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.skip_actions and args.hold_seconds <= 0:
        raise RuntimeError("--skip-actions requires --hold-seconds so the run records an observable hold window.")
    if args.hold_seconds < 0:
        raise RuntimeError("--hold-seconds must be >= 0.")
    if args.hold_poll_seconds <= 0:
        raise RuntimeError("--hold-poll-seconds must be > 0.")
    client = args.client
    api_key = RUST_API_KEY if client == "rust" else MFC_API_KEY
    rest_port = args.rest_port or (4731 if client == "rust" else 4732)
    obfuscation = not args.no_obfuscation

    rest_addr = os.environ.get("X_LOCAL_IP", "").strip()
    if not rest_addr:
        raise RuntimeError("X_LOCAL_IP must be set (REST control plane binds the LAN IP).")
    output_root = get_workspace_output_root()

    inputs_path = Path(args.inputs).resolve() if args.inputs else REPO_ROOT / "live-wire-inputs.local.json"
    if not inputs_path.is_file():
        raise RuntimeError(f"live-wire inputs not found: {inputs_path} (pass --inputs).")
    inputs = load_live_wire_inputs(inputs_path)
    # Well-sourced terms only (ubuntu/linux/debian) — a stale term like fedora yields no
    # results/sources and makes the search + download comparison meaningless.
    search_terms = [term.strip() for term in args.search_terms.split(",") if term.strip()]
    download_terms = [term.strip() for term in args.download_terms.split(",") if term.strip()]

    mods = soak_launch.load_helper_modules("capture")
    rust_mod = mods["rust"]
    shared_roots = [] if args.no_shared_roots else rust_mod.load_shared_roots(inputs_path)

    soak_root = output_root / "soak"
    campaign = args.campaign or _utc_stamp()
    report_dir = soak_root / "reports" / campaign / f"{client}-{_utc_stamp()}"
    report_dir.mkdir(parents=True, exist_ok=True)
    rust_exe = clw.resolve_rust_diagnostics_exe(output_root)
    mfc_exe = clw.resolve_mfc_diagnostics_exe(
        output_root, variant=args.mfc_variant, arch=args.mfc_arch, configuration=args.mfc_configuration
    )
    exe = rust_exe if client == "rust" else mfc_exe

    log(f"scripted capture: client={client} campaign={campaign} report={report_dir}")
    vpn = ensure_vpn_ready(exe, name=f"eMuleBB {client}")
    bind_ip = str(vpn["bindIp"])
    bootstrap_nodes = fetch_bootstrap_endpoints(args.nodes_url, limit=40)
    timeouts = {"rest": 60.0, "connect": 240.0}

    handles: dict | None = None
    base_url = ""
    dump_dir: Path = report_dir / "dumps"
    results_meta: dict = {}
    run_start = time.time()
    try:
        if client == "rust":
            rust_runtime = report_dir / "rust-runtime" if args.fresh_profile else soak_root / "rust-runtime"
            dump_dir = report_dir / "dumps"  # fresh dir → the whole dir IS this run
            handles = bring_up_rust(
                rust_mod=rust_mod, exe_path=rust_exe, bind_ip=bind_ip, rest_addr=rest_addr,
                rest_port=rest_port, profile_dir=rust_runtime, packet_dump_dir=dump_dir,
                incoming_dir=rust_runtime / "incoming",
                bootstrap_nodes=bootstrap_nodes, shared_roots=shared_roots,
                server_met_url=args.server_met_url, server_endpoint=OPERATOR_SERVER,
                obfuscation=obfuscation, timeouts=timeouts,
                ed2k_port=args.rust_ed2k_port, kad_port=args.rust_kad_port,
            )
        else:
            mfc_artifacts_dir = report_dir / "mfc-profile" if args.fresh_profile else soak_root / "mfc-profile"
            mfc_profile_dir = None if args.fresh_profile else inputs.mfc_profile_dir
            handles = bring_up_mfc(
                live_common=mods["live_common"], rest_smoke=mods["rest_smoke"],
                shared_dirs_mod=mods["shared_dirs"], exe_path=mfc_exe,
                seed_config_dir=Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else DEFAULT_MFC_SEED_CONFIG_DIR,
                artifacts_dir=mfc_artifacts_dir, direct_profile_dir=mfc_profile_dir,
                rest_host=rest_addr, rest_port=rest_port, shared_roots=shared_roots,
                server_endpoint=OPERATOR_SERVER, obfuscation=obfuscation, timeouts=timeouts,
                ed2k_port=args.mfc_ed2k_port, kad_port=args.mfc_kad_port,
                server_udp_port=args.mfc_server_udp_port,
                secure_ident=args.secident == "on",
            )
            dump_dir = Path(handles["packetDumpDir"])
        assert handles is not None
        base_url = handles["baseUrl"]

        kad_ok = ensure_kad(base_url, api_key)
        log(f"{client} up: {base_url}  operator={OPERATOR_SERVER}  kad={kad_ok}")

        markers_path = report_dir / "markers.jsonl"
        with markers_path.open("w", encoding="utf-8") as fh:
            def _write(marker: dict) -> None:
                fh.write(json.dumps(marker) + "\n")
                fh.flush()

            if args.skip_actions:
                log("skipping scripted searches/downloads; hold-only connection capture")
                results = []
            else:
                # Resolve well-sourced download fixtures once per campaign (reused by both solo
                # runs so rust and mfc fetch the SAME sourced files).
                download_fixtures = campaign_fixtures(
                    campaign_dir=report_dir.parent, base_url=base_url, api_key=api_key,
                    explicit_hashes=args.fixture_hashes, download_terms=download_terms, count=args.fixture_count,
                )
                log(f"resolved {len(download_fixtures)} sourced download fixture(s)")
                actions = scripted_actions.default_action_set(
                    search_terms, download_fixtures, methods=tuple(args.search_methods.split(","))
                )
                log(f"running {len(actions)} scripted actions (spacing {args.spacing_seconds}s)...")
                results = scripted_actions.execute_action_set(
                    actions, scripted_actions.make_rest_runner(base_url, api_key), _write,
                    spacing_seconds=args.spacing_seconds,
                )
        if args.skip_actions:
            log("actions skipped; no post-action settle")
        else:
            log(f"actions done; settling {args.settle_seconds}s for source acquisition...")
            time.sleep(args.settle_seconds)
        hold_result = None
        if args.hold_seconds > 0:
            hold_result = observe_operator_hold(
                base_url,
                api_key,
                endpoint=OPERATOR_SERVER,
                hold_seconds=args.hold_seconds,
                poll_seconds=args.hold_poll_seconds,
            )
            status = "passed" if hold_result["passed"] else "failed"
            log(
                "hold done: "
                f"{status}, disconnected={hold_result['disconnectedSamples']}, "
                f"endpointMismatch={hold_result['endpointMismatchSamples']}, "
                f"restErrors={hold_result['restErrors']}"
            )

        results_meta = {
            "client": client, "campaign": campaign, "baseUrl": base_url,
            "operator": OPERATOR_SERVER, "kadConnected": kad_ok,
            "restPort": rest_port, "obfuscation": obfuscation,
            "profileMode": "fresh" if args.fresh_profile else "persisted",
            "sharedRootsEnabled": not args.no_shared_roots,
            # SecIdent campaign dimension: MFC pref pinned by the launcher; rust
            # has no config key (its eD2K secure-ident is always provisioned).
            "secident": {
                "requested": args.secident,
                "applied": args.secident if client == "mfc" else "always-on",
            },
            "actionResults": results,
            "hold": hold_result,
            "runStartEpoch": run_start,
            "runEndEpoch": time.time(),
        }
    finally:
        if handles is not None:
            if client == "rust" and handles.get("process") is not None:
                try:
                    _http(base_url, api_key, "/api/v1/app/shutdown", "POST", {}, timeout=5.0)
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(8.0)
                if handles["process"].poll() is None:
                    stop_process_tree(handles["process"])
                try:
                    handles["logHandle"].close()
                except Exception:  # noqa: BLE001
                    pass
            elif client == "mfc" and handles.get("app") is not None:
                try:
                    mods["live_common"].close_app_cleanly(handles["app"])
                except Exception:  # noqa: BLE001
                    try:
                        handles["app"].kill()
                    except Exception:  # noqa: BLE001
                        pass
            # MFC persists + flushes its logs on the clean save-and-exit; give it a moment.
            if client == "mfc":
                time.sleep(6.0)

    # Gather AFTER shutdown: rust batches diag/packet writes (the REST-starvation fix),
    # so the buffered action-window records only hit disk on the graceful teardown flush.
    if results_meta:
        (report_dir / "results.json").write_text(json.dumps(results_meta, indent=2), encoding="utf-8")
    dumps_dest = report_dir / "dumps"
    if dump_dir.resolve() != dumps_dest.resolve():
        copied = gather_recording(dump_dir, dumps_dest, run_start)  # MFC: external profile logs
        log(f"gathered {copied} dump file(s) for the recording")
    else:
        in_place = len(list(dumps_dest.glob("*"))) if dumps_dest.exists() else 0
        log(f"recording dumps in place (post-flush): {in_place} file(s)")
    archive = pack_recording(report_dir)
    log(f"recording packed: {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
