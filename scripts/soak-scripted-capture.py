"""Solo scripted-action capture for the capture-then-offline-diff parity model.

Brings up ONE client (rust OR mfc) on the persisted profile, ensures operator +
Kad, runs the identical scripted action set (``scripted_actions``) with begin/end
markers, packs sanitized results and markers into a compressed recording under
``$OUTPUT_ROOT/soak/reports/<campaign>/``, retains raw diagnostics in a private
artifact sibling, then tears the client down.

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
import re
import shutil
import stat
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


def _campaign_leaf(value: str | None) -> str:
    """Return one retention-safe report leaf, never a caller-controlled path."""

    if value is None:
        return _utc_stamp()
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is None
        or value in {".", ".."}
        or ".." in value
        or value.rstrip(". ") != value
    ):
        raise RuntimeError("--campaign must be one safe report-directory leaf.")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{index}" for index in range(1, 10)), *(f"LPT{index}" for index in range(1, 10))}
    if value.split(".", 1)[0].upper() in reserved:
        raise RuntimeError("--campaign must be one safe report-directory leaf.")
    return value


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
    """Copy current diag/dump files without flattening or hiding I/O failures."""

    try:
        dump_info = dump_dir.stat()
        resolved_dump = dump_dir.resolve(strict=True)
        resolved_dest = dest.resolve()
    except OSError:
        raise RuntimeError("Could not inspect the diagnostic dump source.") from None
    if not stat.S_ISDIR(dump_info.st_mode):
        raise RuntimeError("The diagnostic dump source is not a directory.")
    if resolved_dest == resolved_dump or resolved_dest.is_relative_to(resolved_dump):
        raise RuntimeError("The recording destination must be outside the diagnostic dump source.")
    try:
        dest.mkdir(parents=True, exist_ok=True)
        candidates = list(dump_dir.rglob("*"))
    except OSError:
        raise RuntimeError("Could not enumerate the diagnostic dump source.") from None
    copied = 0
    for path in candidates:
        try:
            source_info = path.stat()
        except OSError:
            raise RuntimeError("Could not inspect a diagnostic dump entry.") from None
        if not stat.S_ISREG(source_info.st_mode):
            continue
        name = path.name.lower()
        if not (name.endswith(".jsonl") or name.endswith(".log")):
            continue
        if source_info.st_mtime < since:
            continue
        relative = path.relative_to(dump_dir)
        target = dest / relative
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            raise RuntimeError("Could not inspect a diagnostic recording destination.") from None
        else:
            raise RuntimeError("Diagnostic recording destination collision detected.")
        try:
            shutil.copy2(path, target)
            copied_info = target.stat()
        except OSError:
            raise RuntimeError("Could not copy a diagnostic dump entry.") from None
        if copied_info.st_size != source_info.st_size:
            raise RuntimeError("A copied diagnostic dump entry has an unexpected size.")
        copied += 1
    return copied


def pack_recording(
    report_dir: Path,
    *,
    incoming_dir: Path | None = None,
    private_evidence_path: Path | None = None,
) -> Path:
    """Pack sanitized evidence and move all private/raw artifacts beside it."""

    archive = report_dir.with_suffix(".zip")
    partial_archive = archive.with_suffix(f"{archive.suffix}.partial")
    artifact_dir = report_dir.with_name(f"{report_dir.name}-private-artifacts")
    if archive.exists() or partial_archive.exists():
        raise RuntimeError("Recording archive destination already exists.")
    try:
        artifact_dir.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        raise RuntimeError("Could not inspect the private artifact destination.") from None
    else:
        raise RuntimeError("Private artifact destination already exists.")

    private_moves: list[tuple[Path, Path, str]] = []
    if incoming_dir is not None:
        resolved_report = report_dir.resolve()
        resolved_incoming = incoming_dir.resolve()
        if not resolved_incoming.is_relative_to(resolved_report):
            raise RuntimeError("Native incoming directory is outside the bounded report tree.")
        if not resolved_incoming.is_dir():
            raise RuntimeError("Native incoming directory is missing.")
        try:
            incoming_entries = list(resolved_incoming.rglob("*"))
            incoming_has_files = any(stat.S_ISREG(path.stat().st_mode) for path in incoming_entries)
        except OSError:
            raise RuntimeError("Could not inspect the native incoming directory.") from None
        if incoming_has_files:
            private_moves.append(
                (resolved_incoming, artifact_dir / "downloaded-payloads", "downloaded payloads")
            )
    if private_evidence_path is not None:
        if not private_evidence_path.is_file():
            raise RuntimeError("Private completion evidence is missing.")
        if not private_evidence_path.resolve().is_relative_to(report_dir.resolve()):
            raise RuntimeError("Private completion evidence is outside the bounded report tree.")
        private_moves.append(
            (private_evidence_path, artifact_dir / "completion-private.json", "completion evidence")
        )
    for source, destination, label in (
        (report_dir / "dumps", artifact_dir / "dumps", "diagnostic dumps"),
        (
            report_dir / "native-capture.pcapng",
            artifact_dir / "native-capture.pcapng",
            "native packet capture",
        ),
    ):
        try:
            source.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise RuntimeError(f"Could not inspect the {label}.") from None
        private_moves.append((source, destination, label))

    if private_moves:
        try:
            artifact_dir.mkdir(parents=True, exist_ok=False)
        except OSError:
            raise RuntimeError("Could not create the private artifact directory.") from None
        for source, destination, label in private_moves:
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.lstat()
            except FileNotFoundError:
                pass
            except OSError:
                raise RuntimeError(f"Could not inspect the private {label} destination.") from None
            else:
                raise RuntimeError(f"Private {label} destination already exists.")
            try:
                source.replace(destination)
            except OSError:
                raise RuntimeError(f"Could not retain the private {label}.") from None

    try:
        with zipfile.ZipFile(
            partial_archive,
            "x",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
        ) as zf:
            classification = {
                "schema": "emulebb_recording_evidence_classification_v1",
                "archiveClassification": "sanitized-report",
                "privateArtifactsSibling": f"{report_dir.name}-private-artifacts",
            }
            zf.writestr(
                f"{report_dir.name}/evidence-classification.json",
                json.dumps(classification, indent=2),
            )
            # Only explicitly sanitized products are published in the report ZIP.
            for relative, required in (
                (Path("results.json"), True),
                (Path("markers.jsonl"), True),
                (Path("capture-protocol-summary.txt"), False),
            ):
                path = report_dir / relative
                try:
                    product_info = path.stat()
                except FileNotFoundError:
                    if required:
                        raise RuntimeError("A required sanitized recording product is missing.") from None
                    continue
                except OSError:
                    raise RuntimeError("Could not inspect a sanitized recording product.") from None
                if not stat.S_ISREG(product_info.st_mode):
                    raise RuntimeError("A sanitized recording product is not a regular file.")
                zf.write(path, Path(report_dir.name) / relative)
        partial_archive.replace(archive)
    except Exception:  # noqa: BLE001 - every archive failure must remove the partial file
        try:
            partial_archive.unlink(missing_ok=True)
        except OSError:
            raise RuntimeError("Recording failed and its partial archive could not be removed.") from None
        raise RuntimeError("Could not create the sanitized recording archive.") from None
    try:
        shutil.rmtree(report_dir)
    except OSError:
        raise RuntimeError("Recording archive was created but its source tree could not be removed.") from None
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


def _native_capture_filter(
    *,
    local_address: str,
    rest_port: int,
    tcp_ports: tuple[int, ...],
    udp_ports: tuple[int, ...],
) -> str:
    """Build a host-scoped BPF for only the campaign's protocol ports."""

    unique_tcp = tuple(sorted(set(tcp_ports)))
    unique_udp = tuple(sorted(set(udp_ports)))
    relevant = [
        *(f"tcp port {port}" for port in unique_tcp),
        *(f"udp port {port}" for port in unique_udp),
    ]
    if not relevant:
        raise RuntimeError("Native capture requires at least one protocol port.")
    if any(port <= 0 or port > 65535 for port in (*unique_tcp, *unique_udp, rest_port)):
        raise RuntimeError("Native capture received an invalid port.")
    if rest_port in unique_tcp:
        raise RuntimeError("The REST port overlaps a captured protocol port.")
    protocol_filter = " or ".join(relevant)
    return f"host {local_address} and not tcp port {rest_port} and ({protocol_filter})"


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


class SharedInventorySafetyError(RuntimeError):
    """The client advertised content outside the operator-approved share set."""


class PostRunSafetyError(RuntimeError):
    """One or more teardown or post-run safety checks failed."""

    def __init__(self, failures: list[tuple[str, Exception]]) -> None:
        self.failures = tuple((stage, type(error).__name__) for stage, error in failures)
        summary = ", ".join(f"{stage}:{error_type}" for stage, error_type in self.failures)
        super().__init__(f"Post-run safety failures: {summary}")


def _preserve_post_run_failures(
    primary_error: BaseException | None,
    failures: list[tuple[str, Exception]],
) -> None:
    """Keep a primary failure while attaching endpoint-free cleanup taxonomy."""

    if not failures:
        return
    if primary_error is not None:
        add_note = getattr(primary_error, "add_note", None)
        if callable(add_note):
            for stage, error in failures:
                add_note(f"Additional post-run failure: {stage}:{type(error).__name__}")
        return
    raise PostRunSafetyError(failures)


def _teardown_client(
    *,
    client: str,
    handles: dict[str, object] | None,
    mods: dict[str, object],
    base_url: str,
    api_key: str,
    sleep: Callable[[float], None] = time.sleep,
) -> list[tuple[str, Exception]]:
    """Stop one client and return every sanitized teardown failure."""

    failures: list[tuple[str, Exception]] = []
    if handles is not None and client == "rust" and handles.get("process") is not None:
        try:
            _http(base_url, api_key, "/api/v1/app/shutdown", "POST", {}, timeout=5.0)
        except Exception as error:  # noqa: BLE001 - bounded forced stop remains the fallback
            failures.append(("rust-clean-teardown", error))
        try:
            sleep(8.0)
        except Exception as error:  # noqa: BLE001 - preserve and continue safety cleanup
            failures.append(("rust-shutdown-settle", error))
        try:
            process = handles["process"]
            if process.poll() is None:
                stop_process_tree(process)
        except Exception as error:  # noqa: BLE001 - preserve and continue safety cleanup
            failures.append(("rust-process-teardown", error))
        try:
            handles["logHandle"].close()
        except Exception as error:  # noqa: BLE001 - preserve and continue safety cleanup
            failures.append(("rust-log-close", error))
    elif handles is not None and client == "mfc" and handles.get("app") is not None:
        app = handles["app"]
        try:
            mods["live_common"].close_app_cleanly(app)
        except Exception as error:  # noqa: BLE001 - fallback kill must not hide teardown failure
            failures.append(("mfc-clean-teardown", error))
            try:
                app.kill()
            except Exception as kill_error:  # noqa: BLE001 - always retain failed fallback kill
                failures.append(("mfc-forced-teardown", kill_error))
    if handles is not None and client == "mfc":
        try:
            sleep(6.0)
        except Exception as error:  # noqa: BLE001 - preserve and continue safety cleanup
            failures.append(("mfc-shutdown-settle", error))
    return failures


def _run_post_run_safety_audits(
    *,
    local_address: str,
    tcp_ports: tuple[int, ...],
    udp_ports: tuple[int, ...],
    timeout_seconds: float,
    forbidden_roots: tuple[str, ...],
    forbidden_root_fingerprints_before: tuple[object, ...],
    upnp_audits: dict[str, object],
    client_audits: dict[str, object],
    legacy_audits: dict[str, object],
    results_meta: dict[str, object],
) -> list[tuple[str, Exception]]:
    """Attempt every post-run invariant and return sanitized failure taxonomy."""

    failures: list[tuple[str, Exception]] = []
    try:
        upnp_audits["after"] = _wait_for_mapping_state(
            local_address=local_address,
            tcp_ports=tcp_ports,
            udp_ports=udp_ports,
            expected_mapped=False,
            timeout_seconds=timeout_seconds,
        )
        if not upnp_audits["after"].get("passed"):
            raise RuntimeError("Campaign UPnP mappings remain after teardown.")
    except Exception as error:  # noqa: BLE001 - remaining audits must still run
        failures.append(("upnp-absence-audit", error))
    try:
        client_audits["after"] = _require_no_other_clients()
    except Exception as error:  # noqa: BLE001 - remaining audits must still run
        failures.append(("client-process-audit", error))
    try:
        legacy_audits["after"] = _require_clean_legacy_audit(forbidden_roots)
    except Exception as error:  # noqa: BLE001 - remaining audits must still run
        failures.append(("forbidden-root-reference-audit", error))
    try:
        metadata_audit = compare_forbidden_root_fingerprints(
            forbidden_root_fingerprints_before,
            fingerprint_forbidden_roots(forbidden_roots),
        )
        if metadata_audit.changed_root_indices:
            raise RuntimeError("A configured forbidden legacy root changed during the campaign.")
        results_meta["legacyRootMetadataAudit"] = summarize_forbidden_root_metadata_audit(
            metadata_audit
        )
    except Exception as error:  # noqa: BLE001 - this is the final independent audit
        failures.append(("forbidden-root-metadata-audit", error))
    results_meta["upnpMappingAudits"] = upnp_audits
    results_meta["clientProcessAudits"] = client_audits
    results_meta["legacyRootAudits"] = legacy_audits
    return failures


def _approved_shared_files(shared_roots: list[dict[str, object]]) -> tuple[Path, ...]:
    """Enumerate distinct regular files without returning roots in diagnostics."""

    files: dict[str, Path] = {}
    for root in shared_roots:
        path = Path(str(root["path"]))
        try:
            resolved_root = path.resolve(strict=True)
            candidates = path.rglob("*") if bool(root.get("recursive", True)) else path.iterdir()
            for candidate in candidates:
                candidate_info = candidate.stat()
                if not stat.S_ISREG(candidate_info.st_mode):
                    continue
                resolved = candidate.resolve(strict=True)
                if not resolved.is_relative_to(resolved_root):
                    raise RuntimeError("An approved shared root contains an escaping file link.")
                files[os.path.normcase(str(resolved))] = resolved
        except RuntimeError:
            raise
        except OSError:
            raise RuntimeError("Could not enumerate an approved shared root.") from None
    return tuple(files[key] for key in sorted(files))


def _approved_shared_file_identities(
    shared_roots: list[dict[str, object]],
) -> frozenset[tuple[str, int]]:
    """Hash every approved file into a private, in-memory eD2K identity set."""

    files = _approved_shared_files(shared_roots)
    identities: set[tuple[str, int]] = set()
    for path in files:
        try:
            before = path.stat()
            size_bytes, ed2k_hash, _ = scripted_actions.file_digests(path)
            after = path.stat()
        except OSError:
            raise RuntimeError("Could not hash an approved shared file.") from None
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError("An approved shared file changed while it was hashed.")
        identities.add((ed2k_hash.casefold(), size_bytes))
    if len(identities) != len(files):
        raise RuntimeError("Approved shared files do not have distinct eD2K identities.")
    return frozenset(identities)


def _approved_shared_file_count(shared_roots: list[dict[str, object]]) -> int:
    """Count distinct approved regular files without retaining their paths."""

    return len(_approved_shared_files(shared_roots))


def _shared_inventory_page(payload: dict[str, object]) -> tuple[list[dict[str, object]], int]:
    inventory = _status_data(payload)
    if not isinstance(inventory, dict):
        raise RuntimeError("Client returned an invalid shared-inventory page.")
    items = inventory.get("items")
    total = inventory.get("total")
    if not isinstance(items, list) or not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise RuntimeError("Client returned an invalid shared-inventory page.")
    if not all(isinstance(row, dict) for row in items):
        raise RuntimeError("Client returned an invalid shared-inventory row.")
    return items, total


def _shared_file_identity(row: dict[str, object]) -> tuple[str, int]:
    raw_hash = str(
        row.get("hash") or row.get("fileHash") or row.get("ed2kHash") or ""
    ).strip().casefold()
    raw_size = row.get("sizeBytes", row.get("size"))
    if re.fullmatch(r"[0-9a-f]{32}", raw_hash) is None:
        raise RuntimeError("Client returned an invalid shared-file identity.")
    if not isinstance(raw_size, int) or isinstance(raw_size, bool) or raw_size < 0:
        raise RuntimeError("Client returned an invalid shared-file identity.")
    return raw_hash, raw_size


def _read_shared_inventory_identities(
    base_url: str,
    api_key: str,
    *,
    page_size: int = 256,
) -> tuple[frozenset[tuple[str, int]], int]:
    """Read a stable, complete paged inventory without retaining private rows."""

    offset = 0
    total: int | None = None
    identities: list[tuple[str, int]] = []
    while total is None or offset < total:
        payload = _http(
            base_url,
            api_key,
            f"/api/v1/shared-files?offset={offset}&limit={page_size}",
        )
        rows, page_total = _shared_inventory_page(payload)
        if total is None:
            total = page_total
        elif page_total != total:
            raise RuntimeError("Client shared-inventory total changed during paging.")
        if not rows:
            if offset != total:
                raise RuntimeError("Client shared inventory ended before its reported total.")
            break
        identities.extend(_shared_file_identity(row) for row in rows)
        offset += len(rows)
        if offset > total:
            raise RuntimeError("Client shared inventory exceeded its reported total.")
    assert total is not None
    if offset != total:
        raise RuntimeError("Client shared inventory did not match its reported total.")
    identity_set = frozenset(identities)
    if len(identity_set) != len(identities):
        raise SharedInventorySafetyError("Client shared inventory contains duplicate identities.")
    return identity_set, total


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
    expected_identities: frozenset[tuple[str, int]],
    timeout_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, object]:
    """Wait until exactly the approved local files are hashed and advertised."""

    expected_count = len(expected_identities)
    if expected_count <= 0:
        raise RuntimeError("Native parity requires at least one approved shared file.")
    deadline = monotonic() + timeout_seconds
    status_path = "/api/v1/stats" if client == "rust" else "/api/v1/status"
    while True:
        status_payload = _http(base_url, api_key, status_path)
        identities, advertised = _read_shared_inventory_identities(base_url, api_key)
        data = _status_data(status_payload)
        if client == "mfc":
            runtime = data.get("runtimeDiagnostics")
            data = runtime if isinstance(runtime, dict) else {}
        try:
            hashing = int(data.get("sharedHashingCount") or 0)
        except (AttributeError, TypeError, ValueError):
            raise RuntimeError("Client returned an invalid shared hashing count.") from None
        unexpected = identities - expected_identities
        if unexpected or advertised > expected_count:
            raise SharedInventorySafetyError(
                "Client advertised content outside the approved shared identity set."
            )
        if identities == expected_identities and advertised == expected_count and hashing == 0:
            return {
                "ready": True,
                "expectedFileCount": expected_count,
                "advertisedFileCount": advertised,
                "hashingFileCount": hashing,
                "identitySetMatched": True,
            }
        remaining = deadline - monotonic()
        if remaining <= 0:
            return {
                "ready": False,
                "expectedFileCount": expected_count,
                "advertisedFileCount": advertised,
                "hashingFileCount": hashing,
                "identitySetMatched": identities == expected_identities,
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
    expected_shared_identities: frozenset[tuple[str, int]] = frozenset()
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
    campaign = _campaign_leaf(args.campaign)
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
        expected_shared_identities = _approved_shared_file_identities(shared_roots)
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
            relevant_tcp_ports = (
                *mapping_tcp_ports,
                int(OPERATOR_SERVER.rsplit(":", 1)[1]),
            )
            capture = network_stack.enter_context(
                ManagedDumpcapCapture(
                    output_path=report_dir / "native-capture.pcapng",
                    capture_filter=_native_capture_filter(
                        local_address=rest_addr,
                        rest_port=rest_port,
                        tcp_ports=relevant_tcp_ports,
                        udp_ports=relevant_udp_ports,
                    ),
                    interface=capture_interface,
                    maximum_size_kib=args.capture_max_size_kib,
                    inspection_hook=make_tshark_frame_inspection_hook(
                        relevant_tcp_ports=relevant_tcp_ports,
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
            sharing_state = _wait_for_shared_inventory(
                client=client,
                base_url=base_url,
                api_key=api_key,
                expected_identities=expected_shared_identities,
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
        # ``sys.exception`` is Python 3.11+; the harness supports Python 3.10.
        primary_error = sys.exc_info()[1]
        post_run_failures: list[tuple[str, Exception]] = []
        try:
            post_run_failures.extend(
                _teardown_client(
                    client=client,
                    handles=handles,
                    mods=mods,
                    base_url=base_url,
                    api_key=api_key,
                )
            )
        except Exception as error:  # noqa: BLE001 - audits must still run
            post_run_failures.append(("client-teardown-orchestration", error))
        try:
            if capture is not None:
                capture_result = capture.stop()
        except Exception as error:  # noqa: BLE001 - firewall cleanup and audits must still run
            post_run_failures.append(("capture-stop", error))
        try:
            network_stack.close()
        except Exception as error:  # noqa: BLE001 - post-run audits must still run
            post_run_failures.append(("network-stack-close", error))
        if native_config is not None:
            post_run_failures.extend(
                _run_post_run_safety_audits(
                    local_address=rest_addr,
                    tcp_ports=mapping_tcp_ports,
                    udp_ports=mapping_udp_ports,
                    timeout_seconds=args.upnp_audit_timeout_seconds,
                    forbidden_roots=forbidden_roots,
                    forbidden_root_fingerprints_before=forbidden_root_fingerprints_before,
                    upnp_audits=upnp_audits,
                    client_audits=client_audits,
                    legacy_audits=legacy_audits,
                    results_meta=results_meta,
                )
            )
        _preserve_post_run_failures(primary_error, post_run_failures)

    if native_config is not None:
        if args.connectivity == "firewalled" and not upnp_audits.get("active", {}).get("passed"):
            active_status = upnp_audits.get("active", {}).get("observedStatus")
            network_audit_failure = network_audit_failure or active_status != "unavailable"
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


def _cli_main() -> int:
    """Map unexpected operator-run failures to the harness-failure exit class."""

    try:
        return main()
    except KeyboardInterrupt:
        raise
    except Exception as error:  # noqa: BLE001 - CLI failures are harness failures, never divergences
        # Do not print the exception text: operator-local inputs and paths can be
        # embedded in third-party exception messages.
        print(f"harness-failure: {type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_cli_main())
