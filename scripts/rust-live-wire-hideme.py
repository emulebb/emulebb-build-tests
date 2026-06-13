"""Host-level hide.me live-wire proof for the eMuleBB Rust client.

Binds the Rust daemon's P2P stack through the hide.me split tunnel, connects to
the operator's eD2K server, bootstraps Kad from the public emule-security
``nodes.dat``, then exercises the full live cycle over the public network —
connection, eD2K server keyword search, Kad participation, source exchange, and
a completed file download — across an obfuscation-ON and an obfuscation-OFF
pass.

No operator-specific local paths are baked in: the REST bind comes from
``X_LOCAL_IP``, the release exe + runtime live under
``EMULEBB_WORKSPACE_OUTPUT_ROOT``, the hide.me settings come from ``%APPDATA%``,
and the search corpus comes from the (gitignored) live-wire inputs file.

This realizes the ``emulebb.flow.rust.live-wire.hideme.v1`` campaign scenario.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.hideme_split_tunnel import ensure_vpn_ready
from emule_test_harness.kad_nodes import DEFAULT_NODES_DAT_URL, fetch_bootstrap_endpoints
from emule_test_harness.paths import get_workspace_output_root
from emule_test_harness.rust_client import (
    start_rust_client_executable_with_output,
    stop_process_tree,
    write_rust_config,
)
from emule_test_harness.vm_guest_profiles import (
    api_data,
    api_rows,
    retry_http_json,
    wait_until,
)

# Operator-fixed network inputs (public identifiers, not local paths).
OPERATOR_SERVER = "45.82.80.155:5687"
# High listen ports — avoid ISP filtering of the classic 4662/4672.
ED2K_PORT = 51662
KAD_PORT = 51672
API_KEY = "live-wire"
# DEBUG on the transfer/peer path so we can see source acquisition (GETSOURCES,
# peer connect/callback) when diagnosing why a live download isn't pulling bytes.
RUST_LOG = (
    "info,emulebb_ed2k=info,emulebb_kad_net=info,emulebb_kad_dht=info,emulebb_core=info"
    ",emulebb_ed2k::ed2k_transfer=debug,emulebb_ed2k::ed2k_tcp=debug"
)

# Pick a small, well-sourced, open-content file so a full download completes.
MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024
MIN_DOWNLOAD_SOURCES = 3
UNSAFE_NAME_TOKENS = (".exe", ".msi", ".scr", ".bat", "keygen", "crack")


# Gentle server-contact policy (avoid Lugdunum IP bans).
CONNECT_COOLDOWN_SECONDS = 300.0  # at most one server connect per 5 minutes


def log(message: str) -> None:
    print(f"[live-wire] {message}", flush=True)


def enforce_connect_cooldown(marker: Path) -> None:
    """Blocks until at least CONNECT_COOLDOWN_SECONDS have passed since the last
    recorded server connect, then stamps the marker. Enforced across runs so we
    never reconnect to the operator server more than once per 5 minutes."""

    marker.parent.mkdir(parents=True, exist_ok=True)
    try:
        last = float(marker.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        last = 0.0
    wait = CONNECT_COOLDOWN_SECONDS - (time.time() - last)
    if wait > 0:
        log(f"connect cooldown: waiting {int(wait)}s (server connect ≤ 1 / 5 min)...")
        time.sleep(wait)
    marker.write_text(str(time.time()), encoding="utf-8")


def load_search_terms(inputs_path: Path, profile: str) -> list[str]:
    """Loads the search corpus from the gitignored live-wire inputs file."""

    data = json.loads(inputs_path.read_text(encoding="utf-8-sig"))
    terms = data.get("search_terms", {}).get(profile)
    if not isinstance(terms, list) or not terms:
        raise RuntimeError(f"search_terms.{profile} is missing or empty in {inputs_path}")
    return [str(term) for term in terms]


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be set (no local fallbacks are baked in).")
    return value


def get_stats(base_url: str) -> dict[str, Any]:
    payload = retry_http_json("status", 3, base_url, "/api/v1/status", api_key=API_KEY)
    data = api_data(payload)
    stats = data.get("stats") if isinstance(data, dict) else {}
    return stats if isinstance(stats, dict) else {}


def get_kad(base_url: str) -> dict[str, Any]:
    data = api_data(retry_http_json("kad", 3, base_url, "/api/v1/kad", api_key=API_KEY))
    return data if isinstance(data, dict) else {}


def p2p_bound_to(bind_ip: str) -> bool:
    """Returns True when the ED2K TCP and Kad UDP listeners are bound to ``bind_ip``."""

    import subprocess

    script = (
        f"$tcp = Get-NetTCPConnection -State Listen -LocalPort {ED2K_PORT} -ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.LocalAddress -eq '{bind_ip}' }}; "
        f"$udp = Get-NetUDPEndpoint -LocalPort {KAD_PORT} -ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.LocalAddress -eq '{bind_ip}' }}; "
        "if ($tcp -and $udp) { 'bound' } else { 'no' }"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30, check=False,
    )
    return "bound" in (completed.stdout or "")


def log_contains(log_path: Path, needle: str) -> bool:
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return needle in text


def count_log_matches(log_path: Path, needles: tuple[str, ...]) -> dict[str, int]:
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {needle: 0 for needle in needles}
    return {needle: text.count(needle) for needle in needles}


def is_safe_download_candidate(row: dict[str, Any]) -> bool:
    name = str(row.get("name") or "").casefold()
    if not name or any(token in name for token in UNSAFE_NAME_TOKENS):
        return False
    file_hash = str(row.get("hash") or "")
    size = row.get("sizeBytes", row.get("size"))
    sources = row.get("sources")
    return (
        len(file_hash) == 32
        and all(ch in "0123456789abcdef" for ch in file_hash.casefold())
        and isinstance(size, int)
        and 0 < size <= MAX_DOWNLOAD_BYTES
        and isinstance(sources, int)
        and sources >= MIN_DOWNLOAD_SOURCES
    )


def run_search_corpus(
    base_url: str,
    terms: list[str],
    *,
    max_terms: int = 3,
    inter_term_seconds: float = 60.0,
) -> dict[str, Any]:
    """Runs a GENTLE set of eD2K server keyword searches and collects candidates.

    Gentle policy (avoid a Lugdunum IP ban): at most a few terms, ONE attempt
    each (no retry bursts), and at least ~60s between searches. ``create_search``
    returns results synchronously, so one well-spaced shot per term is enough; a
    0-result response is accepted as-is rather than retried.
    """

    searches: list[dict[str, Any]] = []
    candidates: dict[str, dict[str, Any]] = {}
    total_results = 0
    selected_terms = terms[:max_terms]
    for index, term in enumerate(selected_terms):
        if index > 0:
            time.sleep(inter_term_seconds)  # stay well under the server rate limit
        created = retry_http_json(
            "search create", 2, base_url, "/api/v1/searches",
            api_key=API_KEY, method="POST",
            body={"query": term, "method": "automatic", "type": ""},
            timeout_seconds=45.0,
        )
        data = api_data(created)
        search_id = str(data.get("id") if isinstance(data, dict) else "")
        results = data.get("results", []) if isinstance(data, dict) else []
        total_results += len(results)
        for row in results:
            if isinstance(row, dict) and is_safe_download_candidate(row):
                row["_searchId"] = search_id
                candidates.setdefault(row["hash"], row)
        log(f"  search {term!r}: {len(results)} results")
        searches.append({"query": term, "searchId": search_id, "resultCount": len(results)})
    # Download as many files as we can in parallel; order by most sources first
    # (smallest size breaks ties) so the healthiest files lead.
    ranked = sorted(
        candidates.values(),
        key=lambda r: (int(r.get("sources") or 0), -int(r.get("sizeBytes") or r.get("size") or 0)),
        reverse=True,
    )
    return {"searches": searches, "totalResults": total_results, "candidates": ranked}


_COMPLETE_STATES = {"complete", "completed", "shared", "seeding", "finished"}


def run_downloads(
    base_url: str,
    candidates: list[dict[str, Any]],
    timeout_seconds: float,
    *,
    max_concurrent: int,
) -> dict[str, Any]:
    """Starts many unpaused downloads at once and tracks completion + source growth.

    Passes as soon as at least one file fully completes; reports aggregate
    progress, source exchange, and bytes pulled across all started transfers.
    """

    selected = candidates[:max_concurrent]
    initial_sources: dict[str, int] = {}
    sizes: dict[str, int] = {}
    names: dict[str, str] = {}
    started = 0
    start_errors: list[str] = []
    for candidate in selected:
        file_hash = candidate["hash"]
        try:
            retry_http_json(
                "download", 3, base_url,
                f"/api/v1/searches/{candidate['_searchId']}/results/{file_hash}/operations/download",
                api_key=API_KEY, method="POST", body={"paused": False, "categoryId": 0},
            )
            # download_search_result only inserts a "queued" transfer; resume is
            # what actually starts the download driver + ED2K source acquisition.
            retry_http_json(
                "resume", 2, base_url,
                f"/api/v1/transfers/{file_hash}/operations/resume",
                api_key=API_KEY, method="POST", body={},
            )
        except Exception as exc:  # noqa: BLE001
            start_errors.append(f"{file_hash}: {type(exc).__name__}")
            continue
        started += 1
        initial_sources[file_hash] = int(candidate.get("sources") or 0)
        sizes[file_hash] = int(candidate.get("sizeBytes") or candidate.get("size") or 0)
        names[file_hash] = str(candidate.get("name") or "")
    log(f"started {started}/{len(selected)} concurrent downloads")

    peak_sources: dict[str, int] = dict(initial_sources)
    best_progress: dict[str, float] = {h: 0.0 for h in initial_sources}
    completed: dict[str, dict[str, Any]] = {}
    total_completed_bytes = 0
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline and len(completed) < started:
        rows = api_rows(
            retry_http_json("transfers", 4, base_url, "/api/v1/transfers", api_key=API_KEY), "transfers",
        )
        snapshot_bytes = 0
        for row in rows:
            file_hash = str(row.get("hash"))
            if file_hash not in initial_sources:
                continue
            peak_sources[file_hash] = max(peak_sources.get(file_hash, 0), int(row.get("sources") or 0))
            completed_bytes = int(row.get("completedBytes") or 0)
            snapshot_bytes += completed_bytes
            size = sizes.get(file_hash, 0)
            if size:
                best_progress[file_hash] = max(best_progress[file_hash], 100.0 * completed_bytes / size)
            state = str(row.get("state") or "").casefold()
            if file_hash not in completed and ((size and completed_bytes >= size) or state in _COMPLETE_STATES):
                completed[file_hash] = {"name": names.get(file_hash), "sizeBytes": size}
                log(f"completed: {names.get(file_hash)!r}")
        total_completed_bytes = max(total_completed_bytes, snapshot_bytes)
        if len(completed) >= started:
            break
        time.sleep(5.0)

    source_exchange = any(peak_sources.get(h, 0) > initial_sources.get(h, 0) for h in initial_sources)
    return {
        "candidatesAvailable": len(candidates),
        "started": started,
        "startErrors": start_errors,
        "completedCount": len(completed),
        "completedFiles": list(completed.values()),
        "anyCompleted": bool(completed),
        "maxProgressPercent": round(max(best_progress.values(), default=0.0), 1),
        "totalCompletedBytes": total_completed_bytes,
        "peakSourcesTotal": sum(peak_sources.values()),
        "initialSourcesTotal": sum(initial_sources.values()),
        "sourceExchangeObserved": source_exchange,
        "completed": bool(completed),
    }


def run_pass(
    *,
    obfuscation: bool,
    exe_path: Path,
    bind_ip: str,
    rest_addr: str,
    rest_port: int,
    bootstrap_nodes: list[str],
    terms: list[str],
    pass_dir: Path,
    timeouts: dict[str, float],
    max_concurrent: int,
    max_terms: int,
    connect_marker: Path,
) -> dict[str, Any]:
    """Runs one obfuscation pass end-to-end and returns its evidence."""

    label = "on" if obfuscation else "off"
    log(f"=== pass: obfuscation {label} ===")
    runtime_dir = pass_dir / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    config_path = pass_dir / "emulebb-rust.toml"
    daemon_log = pass_dir / "daemon.out"
    base_url = f"http://{rest_addr}:{rest_port}"

    write_rust_config(
        config_path,
        runtime_dir=runtime_dir,
        rest_addr=rest_addr,
        rest_port=rest_port,
        api_key=API_KEY,
        p2p_bind_ip=bind_ip,
        ed2k_port=ED2K_PORT,
        kad_port=KAD_PORT,
        server_endpoint=OPERATOR_SERVER,
        obfuscation_enabled=obfuscation,
        kad_bootstrap_nodes=bootstrap_nodes,
        kad_bootstrap_min_routing_contacts=2,
    )
    # Enable UPnP so the P2P stack maps ports on the hide.me IGD (needed for
    # HighID + inbound sources over the tunnel). write_rust_config omits [nat].
    with config_path.open("a", encoding="utf-8") as cfg:
        cfg.write("\n[nat]\nenabled = true\n")

    os.environ["RUST_LOG"] = RUST_LOG
    handle = daemon_log.open("w", encoding="utf-8")
    process = start_rust_client_executable_with_output(exe_path, config_path, handle)
    evidence: dict[str, Any] = {"obfuscation": obfuscation}
    try:
        wait_until("REST ready", timeouts["rest"], lambda: get_stats(base_url) or None)

        # The daemon's auto-start is unreliable; drive Kad + ED2K explicitly.
        # This also brings up the P2P sockets so the VPN-bind check can pass.
        retry_http_json("kad start", 3, base_url, "/api/v1/kad/operations/start", api_key=API_KEY, method="POST", body={})
        # Respect the gentle server-connect cadence (≤ 1 connect / 5 min) before
        # we actually reach out to the operator eD2K server.
        enforce_connect_cooldown(connect_marker)
        retry_http_json(
            "server connect", 3, base_url, "/api/v1/servers/operations/connect",
            api_key=API_KEY, method="POST", body={}, timeout_seconds=15.0,
        )

        # Prove P2P actually bound to the hide.me tunnel IP via the live sockets
        # (independent of NAT/log verbosity), with a log-line fallback.
        evidence["vpnBound"] = wait_until(
            "P2P bound to hide.me", timeouts["bind"],
            lambda: (p2p_bound_to(bind_ip) or log_contains(daemon_log, f"bind_ip={bind_ip}")) or None,
        ) is not None

        def connected():
            stats = get_stats(base_url)
            return stats if (stats.get("ed2kConnected") and stats.get("ed2kHighId")) else None

        stats = wait_until("ED2K HighID", timeouts["connect"], connected)
        evidence["ed2kConnected"] = bool(stats.get("ed2kConnected"))
        evidence["ed2kHighId"] = bool(stats.get("ed2kHighId"))

        kad = wait_until(
            "Kad contacts", timeouts["connect"],
            lambda: get_kad(base_url) if int(get_kad(base_url).get("contactCount") or 0) > 0 else None,
        )
        evidence["kadRunning"] = bool(kad.get("running"))
        evidence["kadContactCount"] = int(kad.get("contactCount") or 0)
        evidence["kadConnected"] = bool(kad.get("connected"))

        log("searching corpus (gentle)...")
        search = run_search_corpus(base_url, terms, max_terms=max_terms)
        evidence["search"] = {k: v for k, v in search.items() if k != "candidates"}
        evidence["serverSearchResults"] = search["totalResults"]

        candidates = search["candidates"]
        if candidates:
            log(f"{len(candidates)} safe candidates; starting concurrent downloads...")
            evidence["download"] = run_downloads(
                base_url, candidates, timeouts["download"], max_concurrent=max_concurrent,
            )
        else:
            evidence["download"] = {"completed": False, "reason": "no safe candidate found"}

        # Daemon-log evidence for Kad participation / source exchange / obfuscation.
        evidence["protocolLog"] = count_log_matches(
            daemon_log,
            ("bootstrap response", "tcp_obfuscation", "Kad source", "source exchange", "KADEMLIA"),
        )
        evidence["status"] = "passed" if (
            evidence.get("ed2kHighId")
            and evidence.get("kadContactCount", 0) > 0
            and evidence.get("serverSearchResults", 0) > 0
            and evidence["download"].get("completed")
        ) else "failed"
    except Exception as exc:  # noqa: BLE001 - record and continue to the next pass
        evidence["status"] = "failed"
        evidence["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        stop_process_tree(process)
        handle.close()
    log(f"pass obfuscation {label}: {evidence.get('status')}")
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="eMuleBB Rust hide.me live-wire proof")
    parser.add_argument("--inputs", required=True, help="Path to the live-wire-inputs.local.json file.")
    parser.add_argument("--profile", default="generic_open", help="search_terms profile to use.")
    parser.add_argument("--nodes-url", default=DEFAULT_NODES_DAT_URL, help="Kad nodes.dat URL.")
    parser.add_argument("--rest-port", type=int, default=4731, help="REST listen port on X_LOCAL_IP.")
    parser.add_argument("--bootstrap-limit", type=int, default=40, help="Max Kad bootstrap contacts to seed.")
    parser.add_argument("--download-timeout", type=float, default=900.0, help="Seconds to await a full download.")
    parser.add_argument("--max-concurrent", type=int, default=50, help="Max concurrent downloads per pass.")
    parser.add_argument("--max-terms", type=int, default=3, help="GENTLE: max keyword searches per pass (avoid server bans).")
    parser.add_argument("--both", action="store_true", help="Run both obfuscation passes (two connect+search cycles). Default: obfuscation-ON only, to stay gentle on the server.")
    args = parser.parse_args(argv)

    rest_addr = require_env("X_LOCAL_IP")
    output_root = get_workspace_output_root()
    exe_path = output_root / "builds" / "rust" / "target" / "release" / "emulebb-rust.exe"
    if not exe_path.is_file():
        raise RuntimeError(f"Release binary missing: {exe_path}. Build emulebb-rust (release) first.")

    inputs_path = Path(args.inputs).resolve()
    terms = load_search_terms(inputs_path, args.profile)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_root / "live-wire" / f"rust-hideme-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)

    log(f"ensuring hide.me split tunnel for {exe_path.name}...")
    vpn = ensure_vpn_ready(exe_path, name="eMuleBB Rust")
    bind_ip = vpn["bindIp"]
    log(f"hide.me bind IP: {bind_ip} (whitelist added: {vpn['whitelistAdded']})")

    log(f"seeding Kad from {args.nodes_url}...")
    bootstrap_nodes = fetch_bootstrap_endpoints(args.nodes_url, limit=args.bootstrap_limit)
    log(f"parsed {len(bootstrap_nodes)} bootstrap contacts")

    timeouts = {"rest": 60.0, "bind": 60.0, "connect": 120.0, "download": args.download_timeout}
    # Cross-run marker enforcing ≤ 1 operator-server connect per 5 minutes.
    connect_marker = output_root / "live-wire" / ".last-server-connect"
    # Gentle default: a single obfuscation-ON pass (one connect + a few searches).
    passes = [True, False] if args.both else [True]
    pass_results = []
    for obfuscation in passes:
        pass_dir = run_dir / ("obf-on" if obfuscation else "obf-off")
        pass_results.append(
            run_pass(
                obfuscation=obfuscation,
                exe_path=exe_path,
                bind_ip=bind_ip,
                rest_addr=rest_addr,
                rest_port=args.rest_port,
                bootstrap_nodes=bootstrap_nodes,
                terms=terms,
                pass_dir=pass_dir,
                timeouts=timeouts,
                max_concurrent=args.max_concurrent,
                max_terms=args.max_terms,
                connect_marker=connect_marker,
            )
        )
        time.sleep(3.0)

    report = {
        "scenario": "emulebb.flow.rust.live-wire.hideme.v1",
        "runId": run_id,
        "server": OPERATOR_SERVER,
        "nodesUrl": args.nodes_url,
        "bindIp": bind_ip,
        "ed2kPort": ED2K_PORT,
        "kadPort": KAD_PORT,
        "bootstrapContacts": len(bootstrap_nodes),
        "searchProfile": args.profile,
        "passes": pass_results,
        "status": "passed" if all(p.get("status") == "passed" for p in pass_results) else "failed",
    }
    report_path = run_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log(f"report: {report_path}")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
