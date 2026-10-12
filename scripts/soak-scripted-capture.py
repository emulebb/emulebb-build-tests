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
import contextlib
import datetime
import json
import os
import shutil
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import converged_live_wire as clw  # noqa: E402
from emule_test_harness import scripted_actions, soak_launch  # noqa: E402
from emule_test_harness.hideme_split_tunnel import ensure_vpn_ready  # noqa: E402
from emule_test_harness.kad_nodes import DEFAULT_NODES_DAT_URL, fetch_bootstrap_endpoints  # noqa: E402
from emule_test_harness.live_wire_inputs import load_live_wire_inputs  # noqa: E402
from emule_test_harness.native_parity_inputs import (  # noqa: E402
    audit_client_processes,
    audit_open_handles,
    audit_process_references,
    compare_forbidden_root_fingerprints,
    fingerprint_forbidden_roots,
    load_ed2k_link_fixture,
    load_native_parity_config,
    load_shared_path_fixture,
    summarize_client_process_audit,
    summarize_forbidden_root_metadata_audit,
    summarize_native_parity_inputs,
    summarize_path_audit,
    validate_campaign_paths,
)
from emule_test_harness.native_windows_network import (  # noqa: E402
    CaptureInterfaceHints,
    ManagedDumpcapCapture,
    UpnpMappingAuditError,
    WindowsInboundBlockRules,
    discover_capture_interfaces,
    make_tshark_frame_inspection_hook,
    make_tshark_protocol_summary_hook,
    resolve_capture_interface,
    resolve_windows_adapter_hints,
    verify_upnp_port_mappings,
)
from emule_test_harness.paths import get_workspace_output_root  # noqa: E402
from emule_test_harness.rust_client import stop_process_tree  # noqa: E402
from emule_test_harness.soak_launch import (  # noqa: E402
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
    parser.add_argument(
        "--route",
        choices=("vpn", "direct"),
        default="vpn",
        help="P2P route. direct activates the bounded native-Windows parity policy.",
    )
    parser.add_argument(
        "--connectivity",
        choices=("upnp", "firewalled"),
        default="upnp",
        help="Direct-route inbound connectivity case.",
    )
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
        "--download-timeout-seconds",
        type=float,
        default=14400.0,
        help="One total deadline for all native-parity fixture downloads.",
    )
    parser.add_argument(
        "--share-ready-timeout-seconds",
        type=float,
        default=1800.0,
        help="Deadline for approved shared roots to finish hashing and become advertised.",
    )
    parser.add_argument(
        "--capture-interface",
        default=None,
        help="dumpcap device override; direct mode otherwise resolves X_LOCAL_IP dynamically.",
    )
    parser.add_argument("--capture-max-size-kib", type=int, default=2_000_000)
    parser.add_argument(
        "--upnp-audit-timeout-seconds",
        type=float,
        default=120.0,
        help="Deadline for exact-port UPnP mapping state and cleanup checks.",
    )
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


def pack_recording(
    report_dir: Path,
    *,
    incoming_dir: Path | None = None,
    private_evidence_path: Path | None = None,
) -> Path:
    """Pack public evidence while retaining downloaded payloads outside the archive."""

    archive = report_dir.with_suffix(".zip")
    payload_dir = report_dir.with_name(f"{report_dir.name}-downloaded-payloads")
    if incoming_dir is not None:
        resolved_report = report_dir.resolve()
        resolved_incoming = incoming_dir.resolve()
        if not resolved_incoming.is_relative_to(resolved_report):
            raise RuntimeError("Native incoming directory is outside the bounded report tree.")
        if resolved_incoming.is_dir() and any(path.is_file() for path in resolved_incoming.rglob("*")):
            if payload_dir.exists():
                raise RuntimeError("Downloaded payload retention directory already exists.")
            resolved_incoming.replace(payload_dir)
    if private_evidence_path is not None and private_evidence_path.is_file():
        payload_dir.mkdir(parents=True, exist_ok=True)
        private_evidence_path.replace(payload_dir / "completion-private.json")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in report_dir.rglob("*"):
            if path.is_file():
                relative = path.relative_to(report_dir)
                # Fresh profiles may contain private configuration and partial
                # payloads. Downloaded incoming payloads were moved to the sibling
                # retention directory; no profile content enters the archive.
                if relative.parts and relative.parts[0] in ("rust-profile", "mfc-profile"):
                    continue
                zf.write(path, path.relative_to(report_dir.parent))
    shutil.rmtree(report_dir, ignore_errors=True)
    return archive


def _require_clean_legacy_audit(forbidden_roots: tuple[str, ...]) -> dict[str, object]:
    """Audit forbidden roots without retaining paths, PIDs, or process names."""

    process_result = audit_process_references(forbidden_roots)
    handle_result = audit_open_handles(forbidden_roots)
    if not process_result.available or not handle_result.available:
        raise RuntimeError("Native parity legacy-root auditing is unavailable.")
    if process_result.findings or handle_result.findings:
        raise RuntimeError("A configured forbidden legacy root is still referenced or open.")
    return {
        "processes": summarize_path_audit(process_result),
        "handles": summarize_path_audit(handle_result),
    }


def _require_no_other_clients(*, allowed_pids: tuple[int, ...] = ()) -> dict[str, object]:
    result = audit_client_processes(allowed_pids=allowed_pids)
    if not result.available:
        raise RuntimeError("Native parity client-process auditing is unavailable.")
    if result.findings:
        raise RuntimeError("Another eMuleBB/eMule client process is active.")
    return summarize_client_process_audit(result)


def _owned_process_ids(client: str, handles: dict[str, object]) -> tuple[int, ...]:
    if client == "rust":
        process = handles.get("process")
        pid = getattr(process, "pid", None)
    else:
        app = handles.get("app")
        pid = getattr(app, "process", None)
        pid = pid() if callable(pid) else pid
    return (int(pid),) if isinstance(pid, int) and pid > 0 else ()


def _client_mapping_ports(client: str, args: argparse.Namespace) -> tuple[tuple[int, ...], tuple[int, ...]]:
    if client == "rust":
        return (args.rust_ed2k_port,), (args.rust_kad_port,)
    return (args.mfc_ed2k_port,), (args.mfc_kad_port,)


def _wait_for_mapping_state(
    *,
    local_address: str,
    tcp_ports: tuple[int, ...],
    udp_ports: tuple[int, ...],
    expected_mapped: bool,
    timeout_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, object]:
    """Poll exact campaign ports and retain only endpoint-free UPnP evidence."""

    deadline = monotonic() + timeout_seconds
    latest: dict[str, object] = {
        "expectedMapped": expected_mapped,
        "expectedCount": len(tcp_ports) + len(udp_ports),
        "observedStatus": "unavailable",
        "passed": False,
    }
    while True:
        try:
            audit = verify_upnp_port_mappings(
                local_address,
                tcp_ports=tcp_ports,
                udp_ports=udp_ports,
                expected_mapped=expected_mapped,
            )
            return {"available": True, **audit.sanitized_counts()}
        except UpnpMappingAuditError as exc:
            latest = {"available": True, **exc.audit.sanitized_counts()}
        except RuntimeError:
            latest = {
                "available": False,
                "expectedMapped": expected_mapped,
                "expectedCount": len(tcp_ports) + len(udp_ports),
                "observedStatus": "unavailable",
                "passed": False,
            }
        remaining = deadline - monotonic()
        if remaining <= 0:
            return latest
        sleep(min(2.0, remaining))


def _resolve_native_capture_interface(local_address: str, override: str | None):
    inventory = discover_capture_interfaces()
    hints = (
        CaptureInterfaceHints(device=override)
        if override and override.casefold() != "auto"
        else resolve_windows_adapter_hints(local_address)
    )
    return resolve_capture_interface(inventory, hints)


def _select_linux_document_term(terms: tuple[str, ...]) -> str:
    matches = [term for term in terms if "linux" in term.casefold().split()]
    if not matches:
        raise RuntimeError(
            "Native parity inputs must include the requested Linux document search term."
        )
    return matches[0]


def _fixture_rows(fixtures: tuple[object, ...]) -> list[dict[str, object]]:
    return [
        {
            "name": fixture.name,
            "size": fixture.size,
            "hash": fixture.ed2k_hash,
            "link": fixture.ed2k_link,
        }
        for fixture in fixtures
    ]


def _verify_native_downloads(
    *,
    actions: list[scripted_actions.ScriptedAction],
    fixtures: list[dict[str, object]],
    incoming_dir: Path,
    timeout_seconds: float,
    marker_writer: Callable[[dict[str, object]], None] | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Wait for all fixtures under one total deadline and return local/private evidence."""

    deadline = time.monotonic() + timeout_seconds
    download_actions = [action for action in actions if action.kind == "download"]
    if len(download_actions) != len(fixtures):
        raise RuntimeError("Native parity download action/fixture count mismatch.")
    private_evidence: list[dict[str, object]] = []
    public_summary: list[dict[str, object]] = []
    for action, fixture in zip(download_actions, fixtures, strict=True):
        remaining = max(0.0, deadline - time.monotonic())
        candidate = incoming_dir / str(fixture["name"])
        try:
            verification = scripted_actions.wait_for_completed_file(
                lambda candidate=candidate: candidate if candidate.is_file() else None,
                expected_size=int(fixture["size"]),
                expected_ed2k_hash=str(fixture["hash"]),
                timeout_seconds=remaining,
                interval_seconds=2.0,
            )
        except RuntimeError:
            status = "invalid" if candidate.is_file() else "incomplete"
            public_summary.append({"actionId": action.id, "status": status})
            private_evidence.append({"actionId": action.id, "status": status})
            if marker_writer is not None:
                marker_writer(
                    {
                        "schema": scripted_actions.MARKER_SCHEMA,
                        "marker": "end",
                        "actionId": action.id,
                        "kind": "download",
                        "terminal": True,
                        "status": status,
                        "ts_utc": scripted_actions.utc_now_iso(),
                    }
                )
            continue
        public_summary.append({"actionId": action.id, **verification.sanitized_result()})
        private_evidence.append(
            {
                "actionId": action.id,
                "status": "verified",
                "sizeBytes": verification.size_bytes,
                "sizeVerified": True,
                "ed2kVerified": True,
                "ed2kHash": verification.ed2k_hash,
                "sha256": verification.sha256,
            }
        )
        if marker_writer is not None:
            marker_writer(
                {
                    "schema": scripted_actions.MARKER_SCHEMA,
                    "marker": "end",
                    "actionId": action.id,
                    "kind": "download",
                    "terminal": True,
                    "status": "verified",
                    "ts_utc": scripted_actions.utc_now_iso(),
                }
            )
    return private_evidence, public_summary


def _approved_shared_file_count(shared_roots: list[dict[str, object]]) -> int:
    """Count distinct regular files under the approved roots without retaining paths."""

    files: set[str] = set()
    for root in shared_roots:
        path = Path(str(root["path"]))
        try:
            for candidate in path.rglob("*"):
                if candidate.is_file():
                    files.add(str(candidate.resolve()).casefold())
        except OSError as exc:
            raise RuntimeError("Could not enumerate an approved shared root.") from exc
    return len(files)


def _shared_runtime_state(
    client: str,
    status_payload: dict[str, object],
    inventory_payload: dict[str, object],
) -> tuple[int, int]:
    data = _status_data(status_payload)
    if client == "mfc":
        runtime = data.get("runtimeDiagnostics")
        data = runtime if isinstance(runtime, dict) else {}
    inventory = _status_data(inventory_payload)
    try:
        if isinstance(inventory, dict):
            advertised = int(inventory.get("total") or len(inventory.get("items") or []))
        elif isinstance(inventory, list):
            advertised = len(inventory)
        else:
            raise TypeError
        return advertised, int(data.get("sharedHashingCount") or 0)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Client returned invalid shared-inventory counters.") from exc


def _wait_for_shared_inventory(
    *,
    client: str,
    base_url: str,
    api_key: str,
    expected_count: int,
    timeout_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, object]:
    """Wait until every approved local file is hashed and advertised."""

    if expected_count <= 0:
        return {"ready": False, "expectedFileCount": expected_count, "advertisedFileCount": 0}
    deadline = monotonic() + timeout_seconds
    latest = (0, 0)
    status_path = "/api/v1/stats" if client == "rust" else "/api/v1/status"
    while True:
        status_payload = _http(base_url, api_key, status_path)
        inventory_payload = _http(
            base_url,
            api_key,
            "/api/v1/shared-files?offset=0&limit=1",
        )
        latest = _shared_runtime_state(client, status_payload, inventory_payload)
        advertised, hashing = latest
        if advertised >= expected_count and hashing == 0:
            return {
                "ready": True,
                "expectedFileCount": expected_count,
                "advertisedFileCount": advertised,
                "hashingFileCount": hashing,
            }
        remaining = deadline - monotonic()
        if remaining <= 0:
            return {
                "ready": False,
                "expectedFileCount": expected_count,
                "advertisedFileCount": advertised,
                "hashingFileCount": hashing,
            }
        sleep(min(2.0, remaining))


def _connectivity_state(client: str, payload: dict, expected_case: str) -> dict[str, object]:
    """Normalize the two REST shapes into a retained state-machine assertion."""

    data = _status_data(payload)
    if client == "rust":
        connected = bool(data.get("ed2kConnected"))
        high_id = data.get("ed2kHighId")
        kad_firewalled = data.get("kadFirewalled")
    else:
        servers = data.get("servers") if isinstance(data.get("servers"), dict) else {}
        kad = data.get("kad") if isinstance(data.get("kad"), dict) else {}
        current = servers.get("currentServer") if isinstance(servers.get("currentServer"), dict) else {}
        connected = bool(servers.get("connected") or current.get("connected"))
        high_id = connected and not bool(servers.get("lowId"))
        kad_firewalled = kad.get("firewalled")
    if expected_case == "upnp":
        matches = connected and high_id is True and kad_firewalled is not True
    else:
        matches = connected and (high_id is False or kad_firewalled is True)
    return {
        "connected": connected,
        "ed2kHighId": high_id,
        "kadFirewalled": kad_firewalled,
        "expectedCase": expected_case,
        "matchesExpectedCase": matches,
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.skip_actions and args.hold_seconds <= 0:
        raise RuntimeError("--skip-actions requires --hold-seconds so the run records an observable hold window.")
    if args.hold_seconds < 0:
        raise RuntimeError("--hold-seconds must be >= 0.")
    if args.hold_poll_seconds <= 0:
        raise RuntimeError("--hold-poll-seconds must be > 0.")
    if args.download_timeout_seconds <= 0:
        raise RuntimeError("--download-timeout-seconds must be > 0.")
    if args.share_ready_timeout_seconds <= 0:
        raise RuntimeError("--share-ready-timeout-seconds must be > 0.")
    if args.upnp_audit_timeout_seconds <= 0:
        raise RuntimeError("--upnp-audit-timeout-seconds must be > 0.")
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

    native_config = load_native_parity_config(inputs_path) if args.route == "direct" else None
    native_fixtures: list[dict[str, object]] = []
    forbidden_roots: tuple[str, ...] = ()
    input_summary: dict[str, int] | None = None
    if native_config is not None:
        if args.skip_actions or args.no_shared_roots:
            raise RuntimeError("Direct native parity requires searches, downloads, and shared roots.")
        args.fresh_profile = True
        links = load_ed2k_link_fixture(native_config.ed2k_links_file)
        shared_paths = load_shared_path_fixture(native_config.shared_paths_file)
        for index, shared_path in enumerate(shared_paths):
            if not Path(shared_path).is_dir():
                raise RuntimeError(f"Native parity shared path index {index} is not an existing directory.")
        forbidden_roots = native_config.forbidden_roots
        native_fixtures = _fixture_rows(links)
        search_terms = [_select_linux_document_term(inputs.document_terms)]
        shared_roots = [{"path": path, "recursive": True} for path in shared_paths]
        input_summary = summarize_native_parity_inputs(links, shared_paths, forbidden_roots)

    mods = soak_launch.load_helper_modules("capture")
    rust_mod = mods["rust"]
    if native_config is None:
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
    if native_config is None:
        vpn = ensure_vpn_ready(exe, name=f"eMuleBB {client}")
        bind_ip = str(vpn["bindIp"])
    else:
        bind_ip = rest_addr
    bootstrap_nodes = fetch_bootstrap_endpoints(args.nodes_url, limit=40)
    timeouts = {"rest": 60.0, "connect": 240.0}

    handles: dict | None = None
    base_url = ""
    dump_dir: Path = report_dir / "dumps"
    results_meta: dict = {}
    completion_evidence: list[dict[str, object]] = []
    completion_summary: list[dict[str, object]] = []
    connectivity_state: dict[str, object] | None = None
    sharing_state: dict[str, object] | None = None
    legacy_audits: dict[str, object] = {}
    client_audits: dict[str, object] = {}
    forbidden_root_fingerprints_before = ()
    upnp_audits: dict[str, object] = {}
    network_audit_failure = False
    mapping_tcp_ports, mapping_udp_ports = _client_mapping_ports(client, args)
    capture = None
    capture_result = None
    network_stack = contextlib.ExitStack()
    if native_config is not None:
        validate_campaign_paths(
            {
                "inputs": inputs_path,
                "download_fixture": native_config.ed2k_links_file,
                "share_fixture": native_config.shared_paths_file,
                "selected_executable": exe,
                "report": report_dir,
                **{f"share_{index}": path["path"] for index, path in enumerate(shared_roots)},
            },
            forbidden_roots,
        )
        client_audits["before"] = _require_no_other_clients()
        legacy_audits["before"] = _require_clean_legacy_audit(forbidden_roots)
        forbidden_root_fingerprints_before = fingerprint_forbidden_roots(forbidden_roots)
        upnp_audits["before"] = _wait_for_mapping_state(
            local_address=rest_addr,
            tcp_ports=mapping_tcp_ports,
            udp_ports=mapping_udp_ports,
            expected_mapped=False,
            timeout_seconds=args.upnp_audit_timeout_seconds,
        )
        if not upnp_audits["before"].get("passed"):
            raise RuntimeError("Campaign ports are not proven free of stale UPnP mappings.")
        capture_interface = _resolve_native_capture_interface(
            rest_addr,
            args.capture_interface or native_config.capture_interface,
        )
        if args.connectivity == "firewalled":
            tcp_ports = (args.rust_ed2k_port,) if client == "rust" else (args.mfc_ed2k_port,)
            udp_ports = (
                (args.rust_kad_port,)
                if client == "rust"
                else (args.mfc_kad_port, args.mfc_server_udp_port)
            )
            network_stack.enter_context(
                WindowsInboundBlockRules(
                    case_id=f"{client}-{args.connectivity}",
                    tcp_ports=tcp_ports,
                    udp_ports=udp_ports,
                )
            )
        try:
            relevant_udp_ports = (*mapping_udp_ports, 1900)
            if client == "mfc":
                relevant_udp_ports = (*relevant_udp_ports, args.mfc_server_udp_port)
            capture = network_stack.enter_context(
                ManagedDumpcapCapture(
                    output_path=report_dir / "native-capture.pcapng",
                    capture_filter=f"host {rest_addr} and not tcp port {rest_port}",
                    interface=capture_interface,
                    maximum_size_kib=args.capture_max_size_kib,
                    inspection_hook=make_tshark_frame_inspection_hook(
                        relevant_tcp_ports=(
                            *mapping_tcp_ports,
                            int(OPERATOR_SERVER.rsplit(":", 1)[1]),
                        ),
                        relevant_udp_ports=relevant_udp_ports,
                    ),
                    summary_hook=make_tshark_protocol_summary_hook(),
                )
            )
        except BaseException:
            network_stack.close()
            raise
    run_start = time.time()
    try:
        if client == "rust":
            rust_profile_dir = report_dir / "rust-profile" if args.fresh_profile else soak_root / "rust-profile"
            dump_dir = report_dir / "dumps"  # fresh dir → the whole dir IS this run
            handles = bring_up_rust(
                rust_mod=rust_mod, exe_path=rust_exe, bind_ip=bind_ip, rest_addr=rest_addr,
                rest_port=rest_port, profile_dir=rust_profile_dir, packet_dump_dir=dump_dir,
                incoming_dir=rust_profile_dir / "incoming",
                bootstrap_nodes=bootstrap_nodes, shared_roots=shared_roots,
                server_met_url=args.server_met_url, server_endpoint=OPERATOR_SERVER,
                obfuscation=obfuscation, timeouts=timeouts,
                ed2k_port=args.rust_ed2k_port, kad_port=args.rust_kad_port,
                p2p_bind_ip=rest_addr if native_config is not None else None,
                p2p_bind_interface=None if native_config is not None else "hide.me",
                nat_enabled=args.connectivity == "upnp" if native_config is not None else True,
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
                p2p_bind_ip=rest_addr if native_config is not None else None,
                p2p_bind_interface=None if native_config is not None else "hide.me",
                nat_enabled=args.connectivity == "upnp" if native_config is not None else True,
            )
            dump_dir = Path(handles["packetDumpDir"])
        assert handles is not None
        base_url = handles["baseUrl"]
        if native_config is not None:
            incoming_dir = handles.get("incomingDir")
            if incoming_dir is None:
                raise RuntimeError("Fresh native profile did not expose its incoming directory.")
            validate_campaign_paths(
                {
                    "profile": handles["profileDir"],
                    "incoming": incoming_dir,
                    "diagnostics": handles["packetDumpDir"],
                },
                forbidden_roots,
            )
            owned_pids = _owned_process_ids(client, handles)
            if not owned_pids:
                raise RuntimeError("Could not identify the campaign-owned client process.")
            client_audits["running"] = _require_no_other_clients(allowed_pids=owned_pids)
            legacy_audits["running"] = _require_clean_legacy_audit(forbidden_roots)

        kad_ok = ensure_kad(base_url, api_key)
        log(f"{client} up: {base_url}  operator={OPERATOR_SERVER}  kad={kad_ok}")

        if native_config is not None:
            upnp_audits["active"] = _wait_for_mapping_state(
                local_address=rest_addr,
                tcp_ports=mapping_tcp_ports,
                udp_ports=mapping_udp_ports,
                expected_mapped=args.connectivity == "upnp",
                timeout_seconds=args.upnp_audit_timeout_seconds,
            )

        if native_config is not None:
            expected_shared_files = _approved_shared_file_count(shared_roots)
            sharing_state = _wait_for_shared_inventory(
                client=client,
                base_url=base_url,
                api_key=api_key,
                expected_count=expected_shared_files,
                timeout_seconds=args.share_ready_timeout_seconds,
            )
            log(
                "shared inventory: "
                f"ready={sharing_state['ready']} "
                f"advertised={sharing_state['advertisedFileCount']}/"
                f"{sharing_state['expectedFileCount']}"
            )

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
                download_fixtures = (
                    native_fixtures
                    if native_config is not None
                    else campaign_fixtures(
                        campaign_dir=report_dir.parent,
                        base_url=base_url,
                        api_key=api_key,
                        explicit_hashes=args.fixture_hashes,
                        download_terms=download_terms,
                        count=args.fixture_count,
                    )
                )
                log(f"resolved {len(download_fixtures)} sourced download fixture(s)")
                actions = scripted_actions.default_action_set(
                    search_terms,
                    download_fixtures,
                    methods=tuple(args.search_methods.split(",")),
                    search_options=(
                        {"type": "doc", "extension": "pdf", "minAvailability": 1}
                        if native_config is not None
                        else None
                    ),
                )
                log(f"running {len(actions)} scripted actions (spacing {args.spacing_seconds}s)...")
                results = scripted_actions.execute_action_set(
                    actions, scripted_actions.make_rest_runner(base_url, api_key), _write,
                    spacing_seconds=args.spacing_seconds,
                )
                if native_config is not None:
                    completion_evidence, completion_summary = _verify_native_downloads(
                        actions=actions,
                        fixtures=download_fixtures,
                        incoming_dir=Path(handles["incomingDir"]),
                        timeout_seconds=args.download_timeout_seconds,
                        marker_writer=_write,
                    )
        if args.skip_actions:
            log("actions skipped; no post-action settle")
        else:
            log(f"actions done; settling {args.settle_seconds}s for source acquisition...")
            time.sleep(args.settle_seconds)
        if native_config is not None:
            status_path = "/api/v1/stats" if client == "rust" else "/api/v1/status"
            connectivity_state = _connectivity_state(
                client,
                _http(base_url, api_key, status_path),
                args.connectivity,
            )
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
            "client": client, "campaign": campaign, "kadConnected": kad_ok,
            "restPort": rest_port, "obfuscation": obfuscation,
            "scenario": {"route": args.route, "connectivity": args.connectivity},
            "profileMode": "fresh" if args.fresh_profile else "persisted",
            "sharedRootsEnabled": not args.no_shared_roots,
            # SecIdent campaign dimension: MFC pref pinned by the launcher; rust
            # has no config key (its eD2K secure-ident is always provisioned).
            "secident": {
                "requested": args.secident,
                "applied": args.secident if client == "mfc" else "always-on",
            },
            "actionResults": results,
            "nativeInputSummary": input_summary,
            "nativeCompletionSummary": completion_summary,
            "nativeSharingState": sharing_state,
            "upnpMappingAudits": upnp_audits,
            "connectivityState": connectivity_state,
            "nativeCompletionEvidence": (
                {
                    "required": True,
                    "expectedCount": len(native_fixtures),
                    "files": [row for row in completion_summary if row.get("status") == "verified"],
                }
                if native_config is not None
                else None
            ),
            "externalInconclusive": bool(
                native_config is not None
                and (
                    any(row.get("status") == "incomplete" for row in completion_evidence)
                    or not bool(sharing_state and sharing_state.get("ready"))
                    or not bool(upnp_audits.get("active", {}).get("passed"))
                    or any(
                        result.get("status") == "ok"
                        and isinstance(result.get("outcome"), dict)
                        and result["outcome"].get("resultCount") == 0
                        for result in results
                    )
                    or not bool(connectivity_state and connectivity_state["matchesExpectedCase"])
                )
            ),
            "hold": hold_result,
            "runStartEpoch": run_start,
            "runEndEpoch": time.time(),
        }
    finally:
        try:
            if handles is not None and client == "rust" and handles.get("process") is not None:
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
            elif handles is not None and client == "mfc" and handles.get("app") is not None:
                try:
                    mods["live_common"].close_app_cleanly(handles["app"])
                except Exception:  # noqa: BLE001
                    try:
                        handles["app"].kill()
                    except Exception:  # noqa: BLE001
                        pass
            # MFC persists + flushes its logs on the clean save-and-exit; give it a moment.
            if handles is not None and client == "mfc":
                time.sleep(6.0)
        finally:
            try:
                if capture is not None:
                    capture_result = capture.stop()
            finally:
                network_stack.close()

    if native_config is not None:
        upnp_audits["after"] = _wait_for_mapping_state(
            local_address=rest_addr,
            tcp_ports=mapping_tcp_ports,
            udp_ports=mapping_udp_ports,
            expected_mapped=False,
            timeout_seconds=args.upnp_audit_timeout_seconds,
        )
        if not upnp_audits["after"].get("passed"):
            network_audit_failure = True
        if args.connectivity == "firewalled" and not upnp_audits.get("active", {}).get("passed"):
            active_status = upnp_audits.get("active", {}).get("observedStatus")
            network_audit_failure = network_audit_failure or active_status != "unavailable"
        results_meta["upnpMappingAudits"] = upnp_audits
        client_audits["after"] = _require_no_other_clients()
        legacy_audits["after"] = _require_clean_legacy_audit(forbidden_roots)
        metadata_audit = compare_forbidden_root_fingerprints(
            forbidden_root_fingerprints_before,
            fingerprint_forbidden_roots(forbidden_roots),
        )
        if metadata_audit.changed_root_indices:
            raise RuntimeError("A configured forbidden legacy root changed during the campaign.")
        results_meta["clientProcessAudits"] = client_audits
        results_meta["legacyRootAudits"] = legacy_audits
        results_meta["legacyRootMetadataAudit"] = summarize_forbidden_root_metadata_audit(
            metadata_audit
        )
        if capture_result is None:
            raise RuntimeError("Native capture did not produce a validated result.")
        results_meta["nativeCapture"] = {
            "created": True,
            "byteCount": capture_result.byte_count,
            **capture_result.sanitized_counts(),
            "summaryCreated": capture_result.tshark_summary is not None,
        }
        if capture_result.tshark_summary is not None:
            (report_dir / "capture-protocol-summary.txt").write_text(
                capture_result.tshark_summary,
                encoding="utf-8",
            )

    # Gather AFTER shutdown: rust batches diag/packet writes (the REST-starvation fix),
    # so the buffered action-window records only hit disk on the graceful teardown flush.
    if results_meta:
        (report_dir / "results.json").write_text(json.dumps(results_meta, indent=2), encoding="utf-8")
    private_completion_path = None
    if native_config is not None:
        private_completion_path = report_dir / "completion-private.json"
        private_completion_path.write_text(
            json.dumps(
                {
                    "required": True,
                    "expectedCount": len(native_fixtures),
                    "files": [row for row in completion_evidence if row.get("status") == "verified"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    dumps_dest = report_dir / "dumps"
    if dump_dir.resolve() != dumps_dest.resolve():
        copied = gather_recording(dump_dir, dumps_dest, run_start)  # MFC: external profile logs
        log(f"gathered {copied} dump file(s) for the recording")
    else:
        in_place = len(list(dumps_dest.glob("*"))) if dumps_dest.exists() else 0
        log(f"recording dumps in place (post-flush): {in_place} file(s)")
    archive = pack_recording(
        report_dir,
        incoming_dir=(Path(handles["incomingDir"]) if native_config is not None and handles else None),
        private_evidence_path=private_completion_path,
    )
    log(f"recording packed: {archive}")
    if any(result.get("status") != "ok" for result in results_meta.get("actionResults", [])):
        return 2
    if network_audit_failure:
        return 2
    completion_rows = results_meta.get("nativeCompletionSummary") or []
    if any(row.get("status") == "invalid" for row in completion_rows):
        return 1
    if results_meta.get("externalInconclusive") is True:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
