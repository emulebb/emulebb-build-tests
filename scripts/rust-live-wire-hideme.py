"""Host-level hide.me live-wire proof for the eMuleBB Rust client.

Binds the Rust daemon's P2P stack through the hide.me split tunnel, connects to
the operator's eD2K server, bootstraps Kad from the public emule-security
``nodes.dat``, then exercises the full live cycle over the public network:
connection, eD2K server keyword search, Kad participation, source exchange, and
a completed file download across an obfuscation-ON and an obfuscation-OFF
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
from collections import Counter
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
DEFAULT_SERVER_MET_URL = "https://upd.emule-security.org/server.met"
# High listen ports: avoid ISP filtering of the classic 4662/4672.
ED2K_PORT = 51662
KAD_PORT = 51672
API_KEY = "live-wire"
# DEBUG on the transfer/peer path so we can see source acquisition (GETSOURCES,
# peer connect/callback) when diagnosing why a live download isn't pulling bytes.
RUST_LOG = (
    "info,emulebb_ed2k=info,emulebb_kad_net=info,emulebb_kad_dht=info,emulebb_core=info"
    ",emulebb_ed2k::ed2k_transfer=debug,emulebb_ed2k::ed2k_tcp=debug"
)

# Pick a small, open-content file and then let the client prove source growth.
# MFC accepts a search result with one advertised source; the live harness should
# not hide download/source-acquisition regressions behind a stricter prefilter.
MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024
MIN_DOWNLOAD_SOURCES = 1
UNSAFE_NAME_TOKENS = (".exe", ".msi", ".scr", ".bat", "keygen", "crack")


# Gentle server-contact policy (avoid Lugdunum IP bans).
CONNECT_COOLDOWN_SECONDS = 300.0  # at most one server connect per 5 minutes

OP_REQUESTFILENAME = 0x58
OP_SETREQFILEID = 0x4F
OP_REQUESTSOURCES = 0x81
OP_REQUESTSOURCES2 = 0x83
OP_ANSWERSOURCES2 = 0x84
OP_MULTIPACKET = 0x92
OP_MULTIPACKET_EXT = 0xA4
OP_MULTIPACKET_EXT2 = 0xA9
OP_AICHFILEHASHREQ = 0x9E
CLIENT_UDP_REASK_OPS = (
    "OP_REASKFILEPING",
    "OP_REASKACK",
    "OP_FILENOTFOUND",
    "OP_QUEUEFULL",
    "OP_REASKCALLBACKUDP",
    "OP_DIRECTCALLBACKREQ",
)


def log(message: str) -> None:
    print(f"[live-wire] {message}", flush=True)


def _skip_request_filename_ext_info(payload: bytes, offset: int) -> int:
    if offset + 2 > len(payload):
        return len(payload)
    part_count = int.from_bytes(payload[offset:offset + 2], "little")
    bitfield_len = (part_count + 7) // 8
    return min(len(payload), offset + 2 + bitfield_len + 2)


def _skip_file_identifier(payload: bytes) -> int:
    if not payload:
        return 0
    descriptor = payload[0]
    if descriptor & 0xF8 or not descriptor & 0x01:
        return 0
    offset = 1 + 16
    if descriptor & 0x02:
        offset += 8
    if descriptor & 0x04:
        offset += 20
    return min(len(payload), offset)


def _multipacket_subop_counts(opcode: int, payload: bytes) -> Counter[str]:
    counts: Counter[str] = Counter()
    if opcode == OP_MULTIPACKET_EXT2:
        offset = _skip_file_identifier(payload)
    elif opcode == OP_MULTIPACKET_EXT:
        offset = 16 + 8
    elif opcode == OP_MULTIPACKET:
        offset = 16
    else:
        return counts

    while offset < len(payload):
        sub_opcode = payload[offset]
        offset += 1
        if sub_opcode == OP_REQUESTFILENAME:
            offset = _skip_request_filename_ext_info(payload, offset)
        elif sub_opcode == OP_SETREQFILEID:
            counts["embeddedSetReqFileId"] += 1
        elif sub_opcode == OP_REQUESTSOURCES:
            counts["embeddedRequestSources1"] += 1
        elif sub_opcode == OP_REQUESTSOURCES2:
            counts["embeddedRequestSources2"] += 1
            offset = min(len(payload), offset + 3)
        elif sub_opcode == OP_AICHFILEHASHREQ:
            counts["embeddedAichFileHashReq"] += 1
        else:
            # Unknown sub-ops have variable shapes; stop instead of scanning
            # arbitrary hashes/payload bytes as if they were opcodes.
            break
    return counts


def _answer_sources2_source_count(payload: bytes) -> int | None:
    if len(payload) < 19:
        return None
    return int.from_bytes(payload[17:19], "little")


def summarize_source_exchange_packets(packet_dump_dir: Path) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    for dump_file in packet_dump_dir.glob("emulebb-rust-ed2k-tcp-dump-*.jsonl"):
        for line in dump_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            direction = str(record.get("direction") or "")
            opcode = record.get("opcode")
            try:
                opcode_int = int(opcode)
            except (TypeError, ValueError):
                continue
            if opcode_int == OP_REQUESTSOURCES2:
                counts[f"{direction}RequestSources2"] += 1
            elif opcode_int == OP_ANSWERSOURCES2:
                counts[f"{direction}AnswerSources2"] += 1
                payload_hex = str(record.get("payload_hex") or "")
                try:
                    payload = bytes.fromhex(payload_hex)
                except ValueError:
                    payload = b""
                source_count = _answer_sources2_source_count(payload)
                if source_count is None:
                    counts[f"{direction}MalformedAnswerSources2"] += 1
                else:
                    counts[f"{direction}AnswerSources2SourceCount"] += source_count
                    if source_count == 0:
                        counts[f"{direction}EmptyAnswerSources2"] += 1
            elif opcode_int in {OP_MULTIPACKET, OP_MULTIPACKET_EXT, OP_MULTIPACKET_EXT2}:
                payload_hex = str(record.get("payload_hex") or "")
                try:
                    payload = bytes.fromhex(payload_hex)
                except ValueError:
                    continue
                for key, value in _multipacket_subop_counts(opcode_int, payload).items():
                    counts[f"{direction}{key[0].upper()}{key[1:]}"] += value

    return {
        "requestSources2Sent": counts["sendRequestSources2"] + counts["sendEmbeddedRequestSources2"],
        "answerSources2Received": counts["recvAnswerSources2"],
        "answerSources2SourceCount": counts["recvAnswerSources2SourceCount"],
        "emptyAnswerSources2Received": counts["recvEmptyAnswerSources2"],
        "malformedAnswerSources2Received": counts["recvMalformedAnswerSources2"],
        "embeddedRequestSources2Sent": counts["sendEmbeddedRequestSources2"],
        "standaloneRequestSources2Sent": counts["sendRequestSources2"],
        "counts": dict(sorted(counts.items())),
    }


def summarize_client_udp_packets(packet_dump_dir: Path) -> dict[str, Any]:
    """Summarizes retained client-UDP reask packet diagnostics."""

    opcode_counts: Counter[str] = Counter()
    direction_counts: Counter[str] = Counter()
    transport_counts: Counter[str] = Counter()
    direction_opcode_counts: Counter[tuple[str, str]] = Counter()
    files = sorted(packet_dump_dir.glob("emulebb-rust-ed2k-client-udp-dump-*.jsonl"))
    records = 0
    unknown_records = 0
    for dump_file in files:
        for line in dump_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            records += 1
            opcode_name = str(record.get("opcode_name") or "")
            direction = str(record.get("direction") or "")
            transport = str(record.get("transport_mode") or "")
            opcode_counts[opcode_name] += 1
            direction_counts[direction] += 1
            direction_opcode_counts[(direction, opcode_name)] += 1
            transport_counts[transport] += 1
            if opcode_name == "UNKNOWN":
                unknown_records += 1

    return {
        "files": len(files),
        "records": records,
        "captured": records > 0,
        "unknownRecords": unknown_records,
        "opcodes": dict(sorted((key, value) for key, value in opcode_counts.items() if key)),
        "directions": dict(sorted((key, value) for key, value in direction_counts.items() if key)),
        "transportModes": dict(sorted((key, value) for key, value in transport_counts.items() if key)),
        "reaskFilePingSent": direction_opcode_counts[("send", "OP_REASKFILEPING")],
        "reaskAckObserved": opcode_counts["OP_REASKACK"],
        "fileNotFoundObserved": opcode_counts["OP_FILENOTFOUND"],
        "queueFullObserved": opcode_counts["OP_QUEUEFULL"],
        "callbackUdpObserved": opcode_counts["OP_REASKCALLBACKUDP"],
        "callbackUdpSent": direction_opcode_counts[("send", "OP_REASKCALLBACKUDP")],
        "directCallbackReqObserved": opcode_counts["OP_DIRECTCALLBACKREQ"],
        "coveredOps": {name: opcode_counts[name] for name in CLIENT_UDP_REASK_OPS if opcode_counts[name]},
    }


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
        log(f"connect cooldown: waiting {int(wait)}s (server connect <= 1 / 5 min)...")
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


def import_server_met(base_url: str, url: str) -> dict[str, Any]:
    """Imports a server.met URL through the Rust REST API and returns a summary."""

    if not url.strip():
        return {"enabled": False, "imported": False, "serverCount": None}
    payload = retry_http_json(
        "server.met import",
        2,
        base_url,
        "/api/v1/servers/operations/import-met-url",
        api_key=API_KEY,
        method="POST",
        body={"url": url},
        timeout_seconds=60.0,
    )
    rows = api_rows(
        retry_http_json("servers", 2, base_url, "/api/v1/servers", api_key=API_KEY)
    )
    data = api_data(payload)
    return {
        "enabled": True,
        "imported": bool(data.get("imported") if isinstance(data, dict) else False),
        "serverCount": len(rows),
    }


def p2p_bound_to(bind_ip: str) -> bool:
    """Returns True when the ED2K TCP and Kad UDP listeners are bound to ``bind_ip``."""

    tcp_bound = any(
        address == bind_ip and port == ED2K_PORT
        for address, port in _listening_socket_addresses("tcp")
    )
    udp_bound = any(
        address == bind_ip and port == KAD_PORT
        for address, port in _listening_socket_addresses("udp")
    )
    return tcp_bound and udp_bound


def _listening_socket_addresses(protocol: str) -> list[tuple[str, int]]:
    """Return local listener/endpoint addresses using Python APIs only."""

    import psutil

    if protocol == "tcp":
        connections = psutil.net_connections(kind="tcp")
        return [
            _socket_address_tuple(connection.laddr)
            for connection in connections
            if connection.status == psutil.CONN_LISTEN and connection.laddr
        ]
    if protocol == "udp":
        return [
            _socket_address_tuple(connection.laddr)
            for connection in psutil.net_connections(kind="udp")
            if connection.laddr
        ]
    raise ValueError(f"unsupported protocol {protocol!r}")


def _socket_address_tuple(address: Any) -> tuple[str, int]:
    """Normalize psutil's platform-specific address shape."""

    host = getattr(address, "ip", None)
    port = getattr(address, "port", None)
    if host is None or port is None:
        host = address[0]
        port = address[1]
    return str(host), int(port)


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
    return {needle: count_protocol_marker(text, needle) for needle in needles}


def count_protocol_marker(text: str, marker: str) -> int:
    if marker == "udp reask":
        return text.count("ed2k udp reask: PKT-OUT reask ping")
    return text.count(marker)


def safe_download_rejection_reason(row: dict[str, Any]) -> str | None:
    name = str(row.get("name") or "").casefold()
    if not name:
        return "missingName"
    if any(token in name for token in UNSAFE_NAME_TOKENS):
        return "unsafeNameToken"
    file_hash = str(row.get("hash") or "")
    size = row.get("sizeBytes", row.get("size"))
    sources = row.get("sources")
    if len(file_hash) != 32 or not all(ch in "0123456789abcdef" for ch in file_hash.casefold()):
        return "invalidHash"
    if not isinstance(size, int):
        return "missingSize"
    if size <= 0:
        return "emptySize"
    if size > MAX_DOWNLOAD_BYTES:
        return "tooLarge"
    if not isinstance(sources, int):
        return "missingSources"
    if sources < MIN_DOWNLOAD_SOURCES:
        return "tooFewSources"
    return None


def is_safe_download_candidate(row: dict[str, Any]) -> bool:
    return safe_download_rejection_reason(row) is None


def run_search_corpus(
    base_url: str,
    terms: list[str],
    *,
    max_terms: int = 3,
    inter_term_seconds: float = 60.0,
) -> dict[str, Any]:
    """Runs a GENTLE set of eD2K server keyword searches and collects candidates.

    Gentle policy (avoid a Lugdunum IP ban): at most a few terms, ONE server
    query each (no retry bursts), and at least ~60s between searches. The search
    is async (eMuleBB contract): POST /searches returns status "running" with no
    items, so each term is created once and then the search page is POLLED over
    the LOCAL REST API (no extra server traffic) until it reports "complete",
    and the paged ``items`` are read as the results.
    """

    searches: list[dict[str, Any]] = []
    candidates: dict[str, dict[str, Any]] = {}
    rejection_reasons: dict[str, int] = {}
    observed_rows = 0
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
        created_data = api_data(created)
        search_id = str(created_data.get("id") if isinstance(created_data, dict) else "")
        # Async search: poll the search page over the LOCAL REST API until it
        # reports a terminal status, then read the paged `items`. (Polling is
        # local-only; the eD2K server saw a single query for this term.)
        results: list[dict[str, Any]] = []
        if search_id:
            def _completed_page() -> Any:
                page = retry_http_json(
                    "search poll", 2, base_url, f"/api/v1/searches/{search_id}",
                    api_key=API_KEY, timeout_seconds=30.0,
                )
                page_data = api_data(page)
                status = str(page_data.get("status") if isinstance(page_data, dict) else "")
                return page if status in {"complete", "completed"} else None

            try:
                page = wait_until(f"search {term!r} results", 60.0, _completed_page)
                results = api_rows(page, "items")
            except RuntimeError as exc:
                log(f"  search {term!r}: timed out awaiting completion ({exc})")
        total_results += len(results)
        for row in results:
            if not isinstance(row, dict):
                rejection_reasons["nonObjectRow"] = rejection_reasons.get("nonObjectRow", 0) + 1
                continue
            observed_rows += 1
            rejection_reason = safe_download_rejection_reason(row)
            if rejection_reason is None:
                row["_searchId"] = search_id
                candidates.setdefault(row["hash"], row)
            else:
                rejection_reasons[rejection_reason] = rejection_reasons.get(rejection_reason, 0) + 1
        log(f"  search {term!r}: {len(results)} results")
        searches.append({"query": term, "searchId": search_id, "resultCount": len(results)})
    # Download as many files as we can in parallel; order by most sources first
    # (smallest size breaks ties) so the healthiest files lead.
    ranked = sorted(
        candidates.values(),
        key=lambda r: (int(r.get("sources") or 0), -int(r.get("sizeBytes") or r.get("size") or 0)),
        reverse=True,
    )
    return {
        "searches": searches,
        "totalResults": total_results,
        "candidateStats": {
            "observedRows": observed_rows,
            "safeCandidates": len(ranked),
            "rejected": dict(sorted(rejection_reasons.items())),
            "maxDownloadBytes": MAX_DOWNLOAD_BYTES,
            "minDownloadSources": MIN_DOWNLOAD_SOURCES,
        },
        "candidates": ranked,
    }


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
    ordinals: dict[str, int] = {}
    started = 0
    start_errors: list[str] = []
    for index, candidate in enumerate(selected, start=1):
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
            start_errors.append(f"candidate {index}: {type(exc).__name__}")
            continue
        started += 1
        initial_sources[file_hash] = int(candidate.get("sources") or 0)
        sizes[file_hash] = int(candidate.get("sizeBytes") or candidate.get("size") or 0)
        ordinals[file_hash] = index
    log(f"started {started}/{len(selected)} concurrent downloads")

    peak_sources: dict[str, int] = dict(initial_sources)
    best_progress: dict[str, float] = {h: 0.0 for h in initial_sources}
    completed: dict[str, dict[str, Any]] = {}
    aggregate_verified_bytes = 0
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline and not completed:
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
                ordinal = ordinals.get(file_hash, 0)
                completed[file_hash] = {"candidateIndex": ordinal, "sizeBytes": size}
                log(f"completed candidate {ordinal}")
        aggregate_verified_bytes = max(aggregate_verified_bytes, snapshot_bytes)
        if completed:
            break
        time.sleep(5.0)

    source_exchange = any(peak_sources.get(h, 0) > initial_sources.get(h, 0) for h in initial_sources)
    completed_files_total_bytes = sum(item["sizeBytes"] for item in completed.values())
    return {
        "candidatesAvailable": len(candidates),
        "started": started,
        "startErrors": start_errors,
        "completedCount": len(completed),
        "completedFiles": list(completed.values()),
        "anyCompleted": bool(completed),
        "maxProgressPercent": round(max(best_progress.values(), default=0.0), 1),
        "completedFilesTotalBytes": completed_files_total_bytes,
        "aggregateVerifiedBytes": aggregate_verified_bytes,
        "totalCompletedBytes": completed_files_total_bytes,
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
    server_met_url: str,
    enable_reask: bool = False,
    require_packet_diagnostics: bool = False,
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
        p2p_bind_interface="hide.me",
        ed2k_port=ED2K_PORT,
        kad_port=KAD_PORT,
        server_endpoint=OPERATOR_SERVER,
        obfuscation_enabled=obfuscation,
        reconnect_interval_secs=int(CONNECT_COOLDOWN_SECONDS),
        kad_bootstrap_nodes=bootstrap_nodes,
        kad_bootstrap_min_routing_contacts=2,
        enable_udp_reask=enable_reask,
    )
    # Enable UPnP so the P2P stack maps ports on the hide.me IGD (needed for
    # HighID + inbound sources over the tunnel). write_rust_config omits [nat].
    with config_path.open("a", encoding="utf-8") as cfg:
        cfg.write("\n[nat]\nenabled = true\n")

    # Raise the reask module to trace when validating FEAT-001 so detach /
    # reciprocity / reask-send activity is visible in the daemon log.
    rust_log = RUST_LOG
    if enable_reask:
        rust_log += ",emulebb_ed2k::ed2k_client_udp=trace"
    os.environ["RUST_LOG"] = rust_log
    # Capture the converged ed2k_packet_v1 packet dump for this pass so the live
    # eD2k wire traffic against the emule-security server can be diffed against an
    # eMuleBB diagnostic-build trace of the same exchange.
    packet_dump_dir = pass_dir / "packet-dump"
    packet_dump_dir.mkdir(parents=True, exist_ok=True)
    os.environ["EMULEBB_RUST_LOG_DIR"] = str(packet_dump_dir)
    handle = daemon_log.open("w", encoding="utf-8")
    process = start_rust_client_executable_with_output(exe_path, config_path, handle)
    evidence: dict[str, Any] = {"obfuscation": obfuscation}
    try:
        wait_until("REST ready", timeouts["rest"], lambda: get_stats(base_url) or None)
        evidence["serverMetImport"] = import_server_met(base_url, server_met_url)

        # The daemon's auto-start is unreliable; drive Kad + ED2K explicitly.
        # This also brings up the P2P sockets so the VPN-bind check can pass.
        retry_http_json("kad start", 3, base_url, "/api/v1/kad/operations/start", api_key=API_KEY, method="POST", body={})
        # Respect the gentle server-connect cadence (<= 1 connect / 5 min) before
        # we actually reach out to the operator eD2K server.
        enforce_connect_cooldown(connect_marker)
        retry_http_json(
            "server connect", 3, base_url, f"/api/v1/servers/{OPERATOR_SERVER}/operations/connect",
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

        # Wait for Kad to actually finish bootstrapping (connected == is_bootstrapped),
        # not just the first contact; otherwise the snapshot races the ~60s bootstrap
        # and records connected=false with a partial contact count. Tolerate the
        # window expiring (record the real end state rather than failing the pass).
        def _kad_bootstrapped() -> dict[str, Any] | None:
            k = get_kad(base_url)
            return k if k.get("connected") else None

        try:
            kad = wait_until("Kad bootstrapped", timeouts["connect"], _kad_bootstrapped)
        except RuntimeError:
            kad = get_kad(base_url)
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
            ("bootstrap response", "tcp_obfuscation", "Kad source", "source exchange", "KADEMLIA", "udp reask"),
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
    # Summarize the converged ed2k_packet_v1 captures so a silently-empty dump
    # (release exe built without --features packet-diagnostics) is visible.
    ed2k_dump_files = sorted(packet_dump_dir.glob("emulebb-rust-ed2k-*-dump-*.jsonl"))
    udp_dump_files = sorted(packet_dump_dir.glob("emulebb-rust-kad-udp-dump-*.jsonl"))
    diag_dump_files = sorted(packet_dump_dir.glob("emulebb-rust-diag-*.jsonl"))
    ed2k_dump_lines = sum(
        sum(1 for line in f.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
        for f in ed2k_dump_files
    )
    udp_dump_lines = sum(
        sum(1 for line in f.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
        for f in udp_dump_files
    )
    diag_dump_lines = sum(
        sum(1 for line in f.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
        for f in diag_dump_files
    )
    evidence["packetDump"] = {
        "dir": str(packet_dump_dir),
        "files": len(ed2k_dump_files),
        "records": ed2k_dump_lines,
        "captured": ed2k_dump_lines > 0,
        "ed2kFiles": len(ed2k_dump_files),
        "ed2kRecords": ed2k_dump_lines,
        "udpFiles": len(udp_dump_files),
        "udpRecords": udp_dump_lines,
        "diagFiles": len(diag_dump_files),
        "diagRecords": diag_dump_lines,
    }
    source_exchange_packets = summarize_source_exchange_packets(packet_dump_dir)
    evidence["packetDump"]["sourceExchange"] = source_exchange_packets
    evidence["packetDump"]["clientUdp"] = summarize_client_udp_packets(packet_dump_dir)
    if source_exchange_packets["requestSources2Sent"] > 0 and isinstance(evidence.get("download"), dict):
        evidence["download"]["sourceExchangeObserved"] = True
        evidence["download"]["sourceExchangeEvidence"] = "ed2k_packet_v1"
    if ed2k_dump_lines == 0:
        log(
            "WARN: no ed2k_packet_v1 records captured; run "
            "`python -m emule_workspace build clients --client emulebb-rust --diagnostics` "
            "to stage a packet-diagnostics build."
        )
        if require_packet_diagnostics:
            evidence["status"] = "failed"
            packet_error = "packet diagnostics were required but no ed2k_packet_v1 records were captured"
            if "error" in evidence:
                evidence["packetDiagnosticsError"] = packet_error
            else:
                evidence["error"] = packet_error
    log(f"pass obfuscation {label}: {evidence.get('status')} (packet records: {ed2k_dump_lines})")
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="eMuleBB Rust hide.me live-wire proof")
    parser.add_argument("--inputs", required=True, help="Path to the live-wire-inputs.local.json file.")
    parser.add_argument("--profile", default="generic_open", help="search_terms profile to use.")
    parser.add_argument("--nodes-url", default=DEFAULT_NODES_DAT_URL, help="Kad nodes.dat URL.")
    parser.add_argument("--server-met-url", default=DEFAULT_SERVER_MET_URL, help="server.met URL used to seed the ED2K global-search server list. Pass an empty value to disable.")
    parser.add_argument("--rest-port", type=int, default=4731, help="REST listen port on X_LOCAL_IP.")
    parser.add_argument("--bootstrap-limit", type=int, default=40, help="Max Kad bootstrap contacts to seed.")
    parser.add_argument("--download-timeout", type=float, default=900.0, help="Seconds to await a full download.")
    parser.add_argument("--max-concurrent", type=int, default=50, help="Max concurrent downloads per pass.")
    parser.add_argument("--max-terms", type=int, default=3, help="GENTLE: max keyword searches per pass (avoid server bans).")
    parser.add_argument("--both", action="store_true", help="Run both obfuscation passes (two connect+search cycles). Default: obfuscation-ON only, to stay gentle on the server.")
    parser.add_argument("--reask", action="store_true", help="Enable the FEAT-001 UDP source-reask transport (enableUdpReask=true) for live validation.")
    parser.add_argument(
        "--require-packet-diagnostics",
        action="store_true",
        help="Fail the pass unless the staged Rust binary emits ed2k_packet_v1 packet diagnostics.",
    )
    args = parser.parse_args(argv)

    rest_addr = require_env("X_LOCAL_IP")
    output_root = get_workspace_output_root()
    exe_path = output_root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
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
    # Cross-run marker enforcing <= 1 operator-server connect per 5 minutes.
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
                server_met_url=args.server_met_url,
                enable_reask=args.reask,
                require_packet_diagnostics=args.require_packet_diagnostics,
            )
        )
        time.sleep(3.0)

    report = {
        "scenario": "emulebb.flow.rust.live-wire.hideme.v1",
        "runId": run_id,
        "server": OPERATOR_SERVER,
        "nodesUrl": args.nodes_url,
        "serverMetUrl": args.server_met_url,
        "bindIp": bind_ip,
        "ed2kPort": ED2K_PORT,
        "kadPort": KAD_PORT,
        "bootstrapContacts": len(bootstrap_nodes),
        "searchProfile": args.profile,
        "packetDiagnosticsRequired": args.require_packet_diagnostics,
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
