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
from emule_test_harness import converged_scenarios as cs
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

# Canonical config-only MFC seed profile (preferences.ini/.dat, server.met,
# nodes.dat). The same baseline the other MFC live scripts copy via
# harness_cli_common.prepare_run_paths().seed_config_dir; the profile builder
# validates this exact allowlist before copying it into a fresh per-run profile.
DEFAULT_MFC_SEED_CONFIG_DIR = REPO_ROOT / "manifests" / "live-profile-seed" / "config"

SCENARIO = "emulebb.flow.converged.live-wire.hideme.v1"
OPERATOR_SERVER = "45.82.80.155:5687"
DEFAULT_SERVER_MET_URL = "https://upd.emule-security.org/server.met"
# Rust listen ports. High enough to dodge ISP filtering of classic 4662/4672, but
# BELOW the Windows dynamic/ephemeral range (49152-65535): Hyper-V/WSL reserve
# rolling blocks inside that range (re-rolled each reboot), and a TCP listen bind
# landing in a reserved block fails with WinError 10013 (UDP is unaffected). The
# old 49662/49672 sat just under the first reserved block and was one reboot away
# from breaking. 42662/42672 stay permanently clear. (MFC seed uses 27198/27208,
# already safe.) HighID still works on these ports; LowID is acceptable regardless.
ED2K_PORT = 42662
KAD_PORT = 42672
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


COMPRESSIBLE_BLOCK = (b"eMuleBB converged compressible fixture\n" * 2048)[: 64 * 1024]
# A small fixture body keeps the run gentle while still exercising the
# compression path. 256 KiB is enough for the protocol to attempt zlib on the
# compressible fixture and skip it on the high-entropy one.
FIXTURE_SIZE_BYTES = 256 * 1024


def create_seed_file(seed_dir: Path, *, compression_fixture: str | None = None) -> Path:
    """Creates ONE small shared seed file (gentle: a single tiny fixture).

    ``compression_fixture`` selects the seed body so the compression scenario can
    contrast the zlib path: ``"compressible"`` writes a repeating block,
    ``"low-compressibility"`` writes high-entropy bytes, and ``None`` keeps the
    tiny default text seed.
    """

    seed_dir.mkdir(parents=True, exist_ok=True)
    seed_file = seed_dir / DEFAULT_SEED_FILE_NAME
    if compression_fixture is None:
        seed_file.write_bytes(DEFAULT_SEED_BYTES)
    elif compression_fixture == cs.COMPRESSIBLE:
        body = (COMPRESSIBLE_BLOCK * (FIXTURE_SIZE_BYTES // len(COMPRESSIBLE_BLOCK) + 1))[:FIXTURE_SIZE_BYTES]
        seed_file.write_bytes(body)
    elif compression_fixture == cs.LOW_COMPRESSIBILITY:
        seed_file.write_bytes(os.urandom(FIXTURE_SIZE_BYTES))
    else:
        raise ValueError(f"Unsupported compression fixture: {compression_fixture!r}")
    return seed_file


# --------------------------------------------------------------------------- #
# Rust side: reuse rust-live-wire-hideme.py for config/start/connect/search and
# packet-dump summarizers; ADD the share step (it does not share today).
# --------------------------------------------------------------------------- #


def _unwrap_api_data(payload: dict[str, Any]) -> dict[str, Any]:
    """Returns the ``data`` envelope body when present (eMuleBB REST shape)."""

    data = payload.get("data")
    return data if isinstance(data, dict) else payload


def _compact_json_data(compact_result: dict[str, Any]) -> dict[str, Any]:
    """Returns the compact HTTP result's JSON body, unwrapping ``data``."""

    payload = compact_result.get("json")
    return _unwrap_api_data(payload) if isinstance(payload, dict) else {}


def _poll_rust_search_results(base_url: str, search_id: str) -> int:
    """Polls one rust search page LOCALLY until terminal, then counts ``items``."""

    def completed_page() -> dict[str, Any] | None:
        page = retry_http_json(
            "rust search poll", 2, base_url, f"/api/v1/searches/{search_id}",
            api_key=RUST_API_KEY, timeout_seconds=30.0,
        )
        status = str(_unwrap_api_data(page).get("status") or "")
        return page if status in {"complete", "completed"} else None

    try:
        page = wait_until(f"rust search {search_id}", 60.0, completed_page)
    except RuntimeError:
        return 0
    items = _unwrap_api_data(page).get("items")
    return len(items) if isinstance(items, list) else 0


def run_rust_search(base_url: str, terms: list[str], method: str) -> dict[str, Any]:
    """Runs the gentle search terms on the rust client with an explicit method.

    One query per term over the chosen network (``server`` / ``kad`` /
    ``automatic``), then LOCAL polling of the search page for the terminal status
    (no extra server traffic). Returns a compact per-term result-count summary.
    """

    searches: list[dict[str, Any]] = []
    total_results = 0
    for index, term in enumerate(terms):
        if index > 0:
            time.sleep(INTER_SEARCH_SECONDS)
        created = retry_http_json(
            "rust search create", 2, base_url, "/api/v1/searches",
            api_key=RUST_API_KEY, method="POST",
            body={"query": term, "method": method, "type": ""},
            timeout_seconds=45.0,
        )
        search_id = str(_unwrap_api_data(created).get("id") or "")
        result_count = _poll_rust_search_results(base_url, search_id) if search_id else 0
        total_results += result_count
        searches.append({"query": term, "searchId": search_id, "resultCount": result_count})
    return {"method": method, "searches": searches, "totalResults": total_results}


def poll_mfc_search_page(rest_smoke: ModuleType, base_url: str, search_id: str) -> dict[str, Any]:
    """Polls one MFC search page until terminal and returns a compact result."""

    def completed_page() -> dict[str, Any] | None:
        page = rest_smoke.compact_http_result(
            rest_smoke.http_request(
                base_url,
                f"/api/v1/searches/{search_id}",
                api_key=MFC_API_KEY,
                request_timeout_seconds=30.0,
            )
        )
        status = str(_compact_json_data(page).get("status") or "")
        return page if status in {"complete", "completed"} else None

    return wait_until(f"mfc search {search_id}", 60.0, completed_page)


def clear_mfc_diagnostic_logs(packet_dump_dir: Path) -> list[str]:
    """Removes append-only MFC diagnostics logs so one run owns one trace."""

    removed: list[str] = []
    packet_dump_dir.mkdir(parents=True, exist_ok=True)
    for name in ("emulebb-diagnostics-packet.log", "emulebb-diagnostics-diag.log"):
        path = packet_dump_dir / name
        if path.exists():
            path.unlink()
            removed.append(name)
    return removed


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
    scenario: cs.ConvergedScenario,
    persist_runtime_dir: Path | None = None,
    shared_roots: list[str] | None = None,
) -> dict[str, Any]:
    """Drives the rust client end-to-end for one scenario; returns its evidence."""

    # Persisted runtime (when set): the daemon reuses its cached MD4/AICH catalog
    # across runs (incremental reload), so the shared library is not re-hashed.
    runtime_dir = persist_runtime_dir if persist_runtime_dir is not None else side_dir / "runtime"
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
        obfuscation_enabled=scenario.obfuscation,
        kad_bootstrap_nodes=bootstrap_nodes,
        kad_bootstrap_min_routing_contacts=2,
    )
    # HighID needs UPnP to map the high ports on the hide.me IGD; the
    # firewalled/LowID scenario deliberately leaves NAT/UPnP off so no port
    # forward is published and the server assigns a LowID.
    nat_enabled = "false" if scenario.low_id else "true"
    with config_path.open("a", encoding="utf-8") as cfg:
        cfg.write(f"\n[nat]\nenabled = {nat_enabled}\n")

    os.environ["EMULEBB_RUST_LOG_DIR"] = str(packet_dump_dir)
    handle = daemon_log.open("w", encoding="utf-8")
    process = start_rust_client_executable_with_output(exe_path, config_path, handle)
    evidence: dict[str, Any] = {"client": "rust", "baseUrl": base_url, "scenario": scenario.name}
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

        # Share step: with --full-shares, share the live-wire library roots (same
        # set as MFC); otherwise share the single gentle seed file. Both go over
        # PATCH /api/v1/shared-directories (same shape both clients accept).
        if shared_roots:
            evidence["share"] = rust_mod.share_directories(base_url, shared_roots)
        else:
            evidence["share"] = retry_http_json(
                "rust share", 2, base_url, "/api/v1/shared-directories",
                api_key=RUST_API_KEY, method="PATCH",
                body=clw.build_shared_directory_patch_payload(seed_dir),
            )

        # HighID scenarios wait for ed2kHighId; the LowID scenario only waits for
        # a connected (LowID) session so the firewalled leg does not time out.
        def connected() -> dict[str, Any] | None:
            stats = rust_mod.get_stats(base_url)
            if not stats.get("ed2kConnected"):
                return None
            if scenario.expects_high_id() and not stats.get("ed2kHighId"):
                return None
            return stats

        label = "rust ED2K HighID" if scenario.expects_high_id() else "rust ED2K connected (LowID)"
        stats = wait_until(label, timeouts["connect"], connected)
        evidence["ed2kConnected"] = bool(stats.get("ed2kConnected"))
        evidence["ed2kHighId"] = bool(stats.get("ed2kHighId"))

        # Kad-dependent searches (kad / automatic) must wait for Kad to finish
        # bootstrapping before searching: `kad/operations/start` only spawns the
        # bootstrap (~60s) and ed2kConnected can go true well before Kad has any
        # contacts. Searching too early sends no KADEMLIA2_SEARCH_KEY_REQ (no nodes
        # to query) and returns 0 — a harness race, not a client gap. Mirror the
        # rust-live-wire soak which waits for kad.connected. Tolerate the window
        # expiring (record real end state rather than failing the pass).
        if scenario.search_method in ("kad", "automatic"):
            def _kad_ready() -> dict[str, Any] | None:
                kad = rust_mod.get_kad(base_url)
                return kad if kad.get("connected") else None

            try:
                kad = wait_until("rust Kad bootstrapped", timeouts["connect"], _kad_ready)
            except RuntimeError:
                kad = rust_mod.get_kad(base_url)
            evidence["kadConnected"] = bool(kad.get("connected"))
            evidence["kadContactCount"] = int(kad.get("contactCount") or 0)

        log(f"rust: searching corpus (gentle, method={scenario.search_method})...")
        search = run_rust_search(base_url, terms, scenario.search_method)
        evidence["search"] = search
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


def connect_mfc_to_operator_server(
    rest_smoke: ModuleType, base_url: str, timeout_seconds: float
) -> dict[str, Any]:
    """Connects the MFC client directly to the SAME operator server as rust.

    The reused ``connect_to_live_server`` helper iterates every row in the seed
    ``server.met`` (public servers) and connects to whichever the client lists
    first -- in the failing run that was the dead public Astra-2, which diverged
    from the rust side (operator lab server) and left the connect spinning until
    the app exited. For a valid converged wire diff BOTH clients must connect to
    the SAME server, so this targets the operator lab server by address exactly
    like the rust leg (``POST /api/v1/servers/{OPERATOR_SERVER}/operations/connect``)
    and watches the connect settle, instead of picking a public server.met row.
    """

    connect_result = rest_smoke.http_request(
        base_url,
        f"/api/v1/servers/{OPERATOR_SERVER}/operations/connect",
        method="POST",
        api_key=MFC_API_KEY,
        json_body={},
        request_timeout_seconds=15.0,
    )
    settle = rest_smoke.observe_server_connect_attempt(
        base_url, MFC_API_KEY, min(timeout_seconds, 120.0)
    )
    if rest_smoke.did_rest_listener_disappear(settle.get("observations")):
        raise RuntimeError(
            "REST listener disappeared during operator-server connect. "
            f"Settle: {settle!r}"
        )
    return {
        "server": OPERATOR_SERVER,
        "connect_response": rest_smoke.compact_http_result(connect_result),
        "settle": settle,
        "connected": bool(settle.get("connected")),
    }


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
    scenario: cs.ConvergedScenario,
    persist_artifacts_dir: Path | None = None,
    shared_roots: list[str] | None = None,
) -> dict[str, Any]:
    """Drives the MFC diagnostics client end-to-end for one scenario."""

    # Persisted profile (when set): reuse the same profile-base across runs so
    # MFC's known.met/known2_64.met hash cache survives and the shared library is
    # not re-hashed. With --full-shares the library roots seed shareddir.dat on the
    # first build (and are re-asserted over REST below for parity with rust).
    artifacts_dir = persist_artifacts_dir if persist_artifacts_dir is not None else side_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{rest_host}:{rest_port}"

    profile = live_common.prepare_profile_base(
        seed_config_dir,
        artifacts_dir,
        shared_dirs=list(shared_roots or []),
        scenario_id="converged-live-wire",
        reuse_existing=persist_artifacts_dir is not None,
    )
    config_dir = Path(str(profile["config_dir"]))
    # The diagnostics build writes the converged ed2k_packet_v1 packet dump
    # (emulebb-diagnostics-packet.log) and the diag_event_v1 dump
    # (emulebb-diagnostics-diag.log) into its profile log directory
    # (GetMuleDirectory(EMULE_LOGDIR) == <profile_base>/logs), gated at COMPILE
    # time by the EMULEBB_ENABLE_PACKET_DIAGNOSTICS define in the diagnostics
    # flavor. There is no runtime env-var override for the dump path, so we read
    # the profile log dir rather than setting EMULEBB_PACKET_DIAGNOSTICS_DIR.
    packet_dump_dir = Path(str(profile["log_dir"]))
    cleared_logs = clear_mfc_diagnostic_logs(packet_dump_dir)
    # REST bound to X_LOCAL_IP, P2P bound to the hide.me tunnel interface, both
    # eD2K + Kad enabled for the live exchange. configure_webserver_profile and
    # apply_p2p_bind_interface_override both persist the live network policy
    # (the latter pins BindInterface to the hide.me tunnel), so no extra
    # apply_live_network_policy call is needed.
    rest_smoke.configure_webserver_profile(config_dir, exe_path, MFC_API_KEY, rest_port, rest_host)
    rest_smoke.apply_p2p_bind_interface_override(config_dir, bind_interface)
    # Mirror the rust obfuscation knob: CryptLayerRequested/Supported gate the
    # MFC protocol obfuscation layer (same axis as rust obfuscationEnabled).
    live_common.apply_private_harness_obfuscation(config_dir, scenario.obfuscation)
    if scenario.low_id:
        # Firewalled/LowID: turn UPnP off so no port forward is published and the
        # server assigns a LowID (apply_live_network_policy left EnableUPnP=1).
        live_common.apply_section_preferences(config_dir, "UPnP", (("EnableUPnP", "0"),))

    evidence: dict[str, Any] = {
        "client": "emule",
        "baseUrl": base_url,
        "scenario": scenario.name,
        "clearedDiagnosticsLogs": cleared_logs,
    }
    app = None
    try:
        app = live_common.launch_app(exe_path, Path(str(profile["profile_base"])))
        rest_smoke.wait_for_rest_ready(base_url, MFC_API_KEY, timeouts["rest"])

        # Same endpoints as rust: server connect, kad start, share, search.
        # Connect to the SAME operator lab server as the rust leg (the operator
        # server is seeded into the MFC server.met), not a public server.met pick,
        # so the two captured traces are a like-for-like converged wire diff.
        evidence["serverConnect"] = connect_mfc_to_operator_server(
            rest_smoke, base_url, timeouts["connect"]
        )
        kad_start = rest_smoke.http_request(
            base_url, "/api/v1/kad/operations/start", method="POST",
            api_key=MFC_API_KEY, json_body={},
        )
        evidence["kadStart"] = rest_smoke.compact_http_result(kad_start)

        # Capture the eD2K identity (connected + HighID/LowID) so the scenario
        # row can assert the firewalled/LowID expectation against the rust side.
        status_result = rest_smoke.http_request(base_url, "/api/v1/status", api_key=MFC_API_KEY)
        server_status = rest_smoke.compact_server_status(
            rest_smoke.require_json_object(status_result, 200)
        )
        evidence["serverStatus"] = server_status
        evidence["ed2kConnected"] = bool(server_status.get("connected"))
        evidence["ed2kHighId"] = bool(server_status.get("connected")) and not bool(server_status.get("lowId"))

        # Share the SAME set as rust via the SAME shared-directories endpoint:
        # the live-wire library roots with --full-shares, else the single seed.
        if shared_roots:
            roots_payload = {
                "confirmReplaceRoots": True,
                "roots": [r if r.endswith(("\\", "/")) else r + "\\" for r in shared_roots],
            }
            evidence["share"] = shared_dirs_mod.patch_shared_directories(
                base_url, MFC_API_KEY, roots_payload
            )
        else:
            evidence["share"] = shared_dirs_mod.patch_shared_directories(
                base_url, MFC_API_KEY, clw.build_shared_directory_patch_payload(seed_dir)
            )

        # Run the SAME searches over /api/v1/searches (gentle, widely spaced),
        # using the scenario's network method (server / kad / automatic).
        searches: list[dict[str, Any]] = []
        for index, term in enumerate(terms):
            if index > 0:
                time.sleep(INTER_SEARCH_SECONDS)
            created = rest_smoke.http_request(
                base_url, "/api/v1/searches", method="POST",
                api_key=MFC_API_KEY,
                json_body={"query": term, "method": scenario.search_method, "type": ""},
                request_timeout_seconds=45.0,
            )
            created_compact = rest_smoke.compact_http_result(created)
            created_data = _compact_json_data(created_compact)
            search_id = str(created_data.get("id") or "")
            search_entry: dict[str, Any] = {
                "query": term,
                "searchId": search_id,
                "created": created_compact,
                "status": str(created_data.get("status") or ""),
                "resultCount": 0,
            }
            if search_id:
                try:
                    final_compact = poll_mfc_search_page(rest_smoke, base_url, search_id)
                    final_data = _compact_json_data(final_compact)
                    items = final_data.get("items")
                    search_entry.update(
                        {
                            "final": final_compact,
                            "status": str(final_data.get("status") or ""),
                            "resultCount": len(items) if isinstance(items, list) else int(final_data.get("total") or 0),
                        }
                    )
                except RuntimeError as exc:
                    search_entry["pollError"] = str(exc)
            searches.append(search_entry)
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
    parser.add_argument(
        "--scenarios",
        default=None,
        help=(
            "Comma-separated scenario names to run as gentle single passes "
            f"(or 'all' for the full matrix). Available: {', '.join(cs.list_scenario_names())}. "
            "Default: ed2k-server-search (one deliberate pass)."
        ),
    )
    parser.add_argument(
        "--list-scenarios", action="store_true",
        help="Print the available scenario names and their knobs, then exit.",
    )
    parser.add_argument(
        "--persisted", action="store_true",
        help="Reuse a stable per-client profile across runs (rust runtime dir + MFC "
        "profile-base with its known.met hash cache) so the shared library is hashed "
        "ONCE per client and not re-hashed every launch.",
    )
    parser.add_argument(
        "--full-shares", action="store_true",
        help="Share the live-wire-inputs library roots on BOTH clients (instead of the "
        "single gentle seed), so the two traces compare the real shared libraries.",
    )
    return parser


def require_same_vpn_bind_ip(rust_vpn: dict[str, Any], mfc_vpn: dict[str, Any]) -> str:
    """Returns the common hide.me bind IP or raises when the clients diverge."""

    rust_bind_ip = str(rust_vpn.get("bindIp") or "").strip()
    mfc_bind_ip = str(mfc_vpn.get("bindIp") or "").strip()
    if not rust_bind_ip or not mfc_bind_ip:
        raise RuntimeError(f"hide.me split-tunnel bind IP missing: rust={rust_bind_ip!r}, mfc={mfc_bind_ip!r}.")
    if rust_bind_ip != mfc_bind_ip:
        raise RuntimeError(
            "hide.me split-tunnel bind IP mismatch: "
            f"rust={rust_bind_ip!r}, mfc={mfc_bind_ip!r}. Both clients must use the same VPN adapter."
        )
    return rust_bind_ip


def build_environment_parity_profile(
    *,
    args: argparse.Namespace,
    bootstrap_nodes: list[str],
    terms: list[str],
    shared_roots: list[str] | None,
) -> dict[str, Any]:
    """Builds compact same-input evidence for the rust-vs-MFC live pass."""

    share_mode = "full-shares" if shared_roots is not None else "seed"
    return {
        "server": OPERATOR_SERVER,
        "sameServer": True,
        "serverMetUrl": args.server_met_url,
        "nodesDatUrl": args.nodes_url,
        "sameKadBootstrap": True,
        "bootstrapLimit": args.bootstrap_limit,
        "bootstrapContactCount": len(bootstrap_nodes),
        "searchProfile": args.profile,
        "sameSearchTerms": True,
        "maxTerms": args.max_terms,
        "selectedTermCount": len(terms),
        "shareMode": share_mode,
        "sameShareSet": True,
        "sharedRootCount": len(shared_roots or []),
        "persistedProfiles": bool(args.persisted),
        "rustRestPort": args.rust_rest_port,
        "mfcRestPort": args.mfc_rest_port,
    }


def _shared_opcode_present(
    packet_diff: dict[str, Any],
    *,
    channel: str,
    direction: str,
    protocol_marker: int,
    opcode: int,
) -> bool:
    coverage = packet_diff.get("opcodeCoverage")
    channels = coverage.get("channels") if isinstance(coverage, dict) else None
    if not isinstance(channels, list):
        return False
    for item in channels:
        if not isinstance(item, dict):
            continue
        if item.get("channel") != channel or item.get("direction") != direction:
            continue
        shared = item.get("shared")
        if not isinstance(shared, list):
            return False
        for row in shared:
            if not isinstance(row, dict):
                continue
            if int(row.get("protocolMarker") or 0) == protocol_marker and int(row.get("opcode") or 0) == opcode:
                return int(row.get("rustCount") or 0) > 0 and int(row.get("emuleCount") or 0) > 0
    return False


def build_live_action_coverage(packet_diff: dict[str, Any], scenario: cs.ConvergedScenario) -> dict[str, Any]:
    """Builds the public-live pass gate from scenario-specific action opcodes."""

    required: list[dict[str, Any]] = []
    if scenario.search_method == cs.SEARCH_SERVER:
        required = [
            {
                "label": "server-search-request",
                "channel": "server",
                "direction": "send",
                "protocolMarker": 0xE3,
                "opcode": 0x16,
                "opcodeName": "OP_SEARCHREQUEST",
            },
            {
                "label": "server-search-result",
                "channel": "server",
                "direction": "recv",
                "protocolMarker": 0xE3,
                "opcode": 0x33,
                "opcodeName": "OP_SEARCHRESULT",
            },
        ]

    if not required:
        return {
            "ok": bool(packet_diff.get("coverageOk")),
            "mode": "full-opcode-coverage",
            "required": [],
        }

    checked: list[dict[str, Any]] = []
    for row in required:
        present = _shared_opcode_present(
            packet_diff,
            channel=str(row["channel"]),
            direction=str(row["direction"]),
            protocol_marker=int(row["protocolMarker"]),
            opcode=int(row["opcode"]),
        )
        checked.append({**row, "presentOnBoth": present})
    return {
        "ok": all(row["presentOnBoth"] for row in checked),
        "mode": "scenario-required-opcodes",
        "required": checked,
        "diagnosticFullOpcodeCoverageOk": bool(packet_diff.get("coverageOk")),
    }


def diff_scenario_traces(
    rust_evidence: dict[str, Any], mfc_evidence: dict[str, Any]
) -> tuple[Path | None, Path | None, dict[str, Any] | None, dict[str, Any] | None]:
    """Locates both sides' dumps and runs the packet + diag_event diffs."""

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
    return rust_trace, emule_trace, packet_diff, diag_diff


def run_one_scenario(
    *,
    scenario: cs.ConvergedScenario,
    rust_mod: ModuleType,
    live_common: ModuleType,
    rest_smoke: ModuleType,
    shared_dirs_mod: ModuleType,
    rust_exe: Path,
    mfc_exe: Path,
    seed_config_dir: Path,
    rest_addr: str,
    args: argparse.Namespace,
    bind_ip: str,
    bootstrap_nodes: list[str],
    terms: list[str],
    environment_parity: dict[str, Any],
    scenario_dir: Path,
    timeouts: dict[str, float],
    persist_rust_runtime: Path | None = None,
    persist_mfc_artifacts: Path | None = None,
    shared_roots: list[str] | None = None,
) -> tuple[dict[str, Any], cs.ScenarioResult]:
    """Runs one gentle converged pass for ``scenario`` and returns report+result."""

    log(f"=== scenario '{scenario.name}' ({scenario.description}) ===")
    seed_dir = scenario_dir / "seed"
    seed_file = create_seed_file(seed_dir, compression_fixture=scenario.compression_fixture)
    log(f"shared seed file: {seed_file}")

    log("--- rust side ---")
    rust_evidence = run_rust_side(
        rust_mod=rust_mod, exe_path=rust_exe, bind_ip=bind_ip, rest_addr=rest_addr,
        rest_port=args.rust_rest_port, bootstrap_nodes=bootstrap_nodes, terms=terms,
        seed_dir=seed_dir, side_dir=scenario_dir / "rust", server_met_url=args.server_met_url,
        timeouts=timeouts, scenario=scenario,
        persist_runtime_dir=persist_rust_runtime, shared_roots=shared_roots,
    )

    log("--- MFC diagnostics side ---")
    mfc_evidence = run_mfc_side(
        live_common=live_common, rest_smoke=rest_smoke, shared_dirs_mod=shared_dirs_mod,
        exe_path=mfc_exe, seed_config_dir=seed_config_dir, rest_host=rest_addr,
        rest_port=args.mfc_rest_port, bind_interface="hide.me", terms=terms,
        seed_dir=seed_dir, side_dir=scenario_dir / "emulebb", timeouts=timeouts,
        scenario=scenario,
        persist_artifacts_dir=persist_mfc_artifacts, shared_roots=shared_roots,
    )

    log("--- diff ---")
    rust_trace, emule_trace, packet_diff, diag_diff = diff_scenario_traces(rust_evidence, mfc_evidence)
    if packet_diff is not None:
        packet_diff["liveActionCoverage"] = build_live_action_coverage(packet_diff, scenario)

    report = clw.build_converged_report(
        run_id=scenario.name,
        rust_packet_trace=rust_trace,
        emule_packet_trace=emule_trace,
        packet_diff=packet_diff,
        diag_diff=diag_diff,
        rust_packet_summary=rust_evidence.get("packetSummary"),
        emule_packet_summary=None,
        extra={
            "scenarioKnobs": scenario.summary(),
            "server": OPERATOR_SERVER,
            "bindIp": bind_ip,
            "ed2kPort": ED2K_PORT,
            "kadPort": KAD_PORT,
            "searchProfile": args.profile,
            "environmentParity": environment_parity,
            "seedFile": str(seed_file),
            "rust": rust_evidence,
            "emule": mfc_evidence,
        },
    )
    if packet_diff is not None:
        report["gate"] = "liveActionCoverage"
        report["ok"] = bool(report["traces"]["bothCaptured"]) and bool(
            packet_diff["liveActionCoverage"]["ok"]
        ) and (diag_diff is None or bool(diag_diff.get("ok")))

    rust_search_obj = rust_evidence.get("search")
    rust_search: dict[str, Any] = rust_search_obj if isinstance(rust_search_obj, dict) else {}
    mfc_searches_obj = mfc_evidence.get("searches")
    mfc_searches: list[Any] = mfc_searches_obj if isinstance(mfc_searches_obj, list) else []
    result = cs.ScenarioResult(
        scenario=scenario,
        rust_connected=bool(rust_evidence.get("ed2kConnected")),
        rust_high_id=bool(rust_evidence.get("ed2kHighId")),
        mfc_connected=bool(mfc_evidence.get("ed2kConnected")),
        mfc_high_id=bool(mfc_evidence.get("ed2kHighId")),
        rust_result_count=int(rust_search.get("totalResults") or 0),
        mfc_result_count=sum(int(search.get("resultCount") or 0) for search in mfc_searches if isinstance(search, dict)),
        packet_diff=packet_diff,
        diag_diff=diag_diff,
        both_traces_captured=bool(report["traces"]["bothCaptured"]),
        error=rust_evidence.get("error") or mfc_evidence.get("error"),
        extra={"environmentParity": environment_parity},
    )
    log(
        f"scenario '{scenario.name}': coverage={result.coverage_verdict()} byte={result.packet_verdict()} "
        f"rust(conn={result.rust_connected},high={result.rust_high_id}) "
        f"mfc(conn={result.mfc_connected},high={result.mfc_high_id})"
    )
    return report, result


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_scenarios:
        for scenario in cs.DEFAULT_SCENARIOS:
            print(json.dumps(scenario.summary(), sort_keys=True))
        return 0

    selected = cs.select_scenarios(cs.parse_scenarios_arg(args.scenarios))
    log(f"selected scenarios (gentle single pass each): {', '.join(s.name for s in selected)}")

    rest_addr = require_env("X_LOCAL_IP")
    output_root = get_workspace_output_root()

    rust_exe = clw.resolve_rust_diagnostics_exe(output_root)
    mfc_exe = clw.resolve_mfc_diagnostics_exe(
        output_root, variant=args.mfc_variant, arch=args.mfc_arch, configuration=args.mfc_configuration
    )

    # Reuse the rust orchestrator + MFC live drivers as importable modules.
    rust_mod = load_local_module("rust_live_wire_hideme_for_converged", "rust-live-wire-hideme.py")
    # The reused rust helpers (get_stats / import_server_met) authenticate with
    # their own module-level API_KEY ("live-wire"), but the converged orchestrator
    # configures the rust client with RUST_API_KEY ("converged-live-wire"). Without
    # this override every reused rust REST call returns HTTP 401, so the readiness
    # poll never succeeds. Pin the reused module's key to the converged key so all
    # rust REST traffic in this orchestrator is authenticated consistently.
    setattr(rust_mod, "API_KEY", RUST_API_KEY)  # noqa: B010  # pyright: ignore[reportAttributeAccessIssue]
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

    log(f"ensuring hide.me split tunnel for both clients ({rust_exe.name}, {mfc_exe.name})...")
    rust_vpn = ensure_vpn_ready(rust_exe, name="eMuleBB Rust")
    mfc_vpn = ensure_vpn_ready(mfc_exe, name="eMuleBB MFC")
    bind_ip = require_same_vpn_bind_ip(rust_vpn, mfc_vpn)
    log(f"hide.me bind IP: {bind_ip}")

    log(f"seeding Kad from {args.nodes_url}...")
    bootstrap_nodes = fetch_bootstrap_endpoints(args.nodes_url, limit=args.bootstrap_limit)
    log(f"parsed {len(bootstrap_nodes)} bootstrap contacts")

    seed_config_dir = (
        Path(args.profile_seed_dir).resolve()
        if args.profile_seed_dir
        else DEFAULT_MFC_SEED_CONFIG_DIR
    )
    timeouts = {"rest": 60.0, "connect": 240.0}

    report_dir = output_root / "reports" / "converged-live-wire" / run_id
    reject_windows_temp_path(report_dir, "converged report directory")
    report_dir.mkdir(parents=True, exist_ok=True)

    # Persisted profiles (stable across runs, NOT under the per-run run_dir) so the
    # shared library is hashed once per client; and the live-wire library roots for
    # --full-shares (same set shared on both clients).
    persisted_root = output_root / "live-wire" / "persisted-profile"
    persist_rust_runtime = (persisted_root / "rust-runtime") if args.persisted else None
    persist_mfc_artifacts = (persisted_root / "mfc-runtime") if args.persisted else None
    shared_roots = rust_mod.load_shared_roots(inputs_path) if args.full_shares else None
    if args.full_shares:
        if not shared_roots:
            raise RuntimeError("--full-shares requires at least one shared root in live-wire inputs.")
        log(f"full-shares: {len(shared_roots or [])} library root(s) on both clients")
    if args.persisted:
        log(f"persisted profiles under {persisted_root}")
    environment_parity = build_environment_parity_profile(
        args=args,
        bootstrap_nodes=bootstrap_nodes,
        terms=terms,
        shared_roots=shared_roots,
    )

    results: list[cs.ScenarioResult] = []
    for scenario in selected:
        scenario_dir = run_dir / scenario.name
        scenario_dir.mkdir(parents=True, exist_ok=True)
        report, result = run_one_scenario(
            scenario=scenario, rust_mod=rust_mod, live_common=live_common,
            rest_smoke=rest_smoke, shared_dirs_mod=shared_dirs_mod, rust_exe=rust_exe,
            mfc_exe=mfc_exe, seed_config_dir=seed_config_dir, rest_addr=rest_addr,
            args=args, bind_ip=bind_ip, bootstrap_nodes=bootstrap_nodes, terms=terms,
            environment_parity=environment_parity,
            scenario_dir=scenario_dir, timeouts=timeouts,
            persist_rust_runtime=persist_rust_runtime,
            persist_mfc_artifacts=persist_mfc_artifacts, shared_roots=shared_roots,
        )
        scenario_report_path = report_dir / f"{scenario.name}.json"
        scenario_report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        log(f"scenario report: {scenario_report_path}")
        results.append(result)

    combined = cs.aggregate_scenario_summary(results)
    combined["runId"] = run_id
    combined["scenario"] = SCENARIO
    combined["environmentParity"] = environment_parity
    combined["vpn"] = {
        "rust": {
            "exe": rust_exe.name,
            "whitelistAdded": bool(rust_vpn.get("whitelistAdded")),
            "bindIp": rust_vpn.get("bindIp"),
        },
        "mfc": {
            "exe": mfc_exe.name,
            "whitelistAdded": bool(mfc_vpn.get("whitelistAdded")),
            "bindIp": mfc_vpn.get("bindIp"),
        },
        "sameBindIp": rust_vpn.get("bindIp") == mfc_vpn.get("bindIp"),
    }
    summary_path = report_dir / "report.json"
    summary_path.write_text(json.dumps(combined, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log(f"combined report: {summary_path}")
    print(json.dumps({"scenario": SCENARIO, "ok": combined["ok"], "report": str(summary_path)}, sort_keys=True))
    return 0 if combined["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
