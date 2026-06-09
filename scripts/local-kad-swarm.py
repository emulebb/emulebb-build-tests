"""Local deterministic Kad swarm connectivity matrix for eMuleBB."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, asdict
import importlib.util
import ipaddress
import struct
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def load_local_module(module_name: str, filename: str):
    """Loads one sibling helper module from a hyphenated script filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


dtt = load_local_module("deterministic_two_client_transfer_local_kad", "deterministic-two-client-transfer.py")
harness_cli_common = dtt.harness_cli_common
live_common = dtt.live_common
rest_smoke = dtt.rest_smoke

SUITE_NAME = "local-kad-swarm"
API_KEY = "local-kad-swarm-key"
DEFAULT_CLIENT_COUNT = 3
DEFAULT_MIN_CONTACTS_PER_CLIENT = 1
KAD_BOOTSTRAP_THROTTLE_SECONDS = 11.0
KADEMLIA_CONTACT_VERSION = 8
KAD_STATE_FILES = (
    "nodes.dat",
    "nodes.dat.bak",
    "key_index.dat",
    "load_index.dat",
    "src_index.dat",
)


@dataclass(frozen=True)
class KadClientSpec:
    """One local eMuleBB client participating in a deterministic Kad swarm."""

    index: int
    profile_id: str
    nick: str
    tcp_port: int
    udp_port: int
    rest_port: int


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses standalone local Kad swarm arguments."""

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
    parser.add_argument("--client-count", type=int, default=DEFAULT_CLIENT_COUNT)
    parser.add_argument("--min-contacts-per-client", type=int, default=DEFAULT_MIN_CONTACTS_PER_CLIENT)
    parser.add_argument("--bootstrap-mode", choices=["rest", "preseed", "both"], default="rest")
    parser.add_argument("--nodes-dat-fixture-mode", choices=["valid", "truncated", "stale"], default="valid")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--kad-running-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--swarm-ready-timeout-seconds", type=float, default=240.0)
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> None:
    """Rejects matrix settings that cannot form a meaningful local Kad swarm."""

    if args.client_count < 2:
        raise ValueError("client count must be at least 2.")
    if args.min_contacts_per_client < 0:
        raise ValueError("minimum contacts per client must be zero or greater.")
    if args.min_contacts_per_client < 1 and args.nodes_dat_fixture_mode != "truncated":
        raise ValueError("minimum contacts per client may be zero only for truncated nodes.dat chaos.")
    if args.min_contacts_per_client >= args.client_count:
        raise ValueError("minimum contacts per client must be lower than client count.")
    if args.nodes_dat_fixture_mode != "valid" and args.bootstrap_mode not in {"preseed", "both"}:
        raise ValueError("nodes.dat fixture chaos requires preseed or both bootstrap mode.")


def choose_local_kad_ports(client_count: int, host: str | None = None) -> list[tuple[int, int, int]]:
    """Allocates distinct REST/TCP/UDP port triples for local Kad clients."""

    if client_count < 2:
        raise ValueError("client count must be at least 2.")
    used: set[int] = set()
    triples: list[tuple[int, int, int]] = []

    def choose(udp: bool = False) -> int:
        for _ in range(200):
            candidate = rest_smoke.choose_listen_port(host)
            if candidate not in used and dtt.is_port_available(candidate, host=host, udp=udp):
                used.add(candidate)
                return candidate
        raise RuntimeError("Could not allocate a distinct local Kad port.")

    for _ in range(client_count):
        triples.append((choose(False), choose(False), choose(True)))
    return triples


def build_client_specs(client_count: int, ports: list[tuple[int, int, int]]) -> list[KadClientSpec]:
    """Builds stable local Kad client descriptors from allocated ports."""

    if len(ports) != client_count:
        raise ValueError("port triple count must match client count.")
    specs: list[KadClientSpec] = []
    for index, (rest_port, tcp_port, udp_port) in enumerate(ports, start=1):
        profile_id = f"cl-emulebb-{index:03d}"
        specs.append(
            KadClientSpec(
                index=index,
                profile_id=profile_id,
                nick=profile_id,
                tcp_port=tcp_port,
                udp_port=udp_port,
                rest_port=rest_port,
            )
        )
    return specs


def remove_kad_state_files(config_dir: Path) -> list[str]:
    """Deletes public or stale Kad state files from one isolated profile."""

    removed: list[str] = []
    for name in KAD_STATE_FILES:
        path = config_dir / name
        if path.exists():
            path.unlink()
            removed.append(name)
    return removed


def stored_nodes_dat_ip(address: str) -> int:
    """Returns the little-endian IPv4 integer shape used by `nodes.dat`."""

    return int.from_bytes(ipaddress.IPv4Address(address).packed, "little")


def deterministic_kad_node_id(index: int) -> bytes:
    """Builds a stable nonzero Kad node id for local `nodes.dat` fixtures."""

    if index <= 0 or index > 255:
        raise ValueError("Kad fixture node index must fit in one nonzero byte.")
    return bytes([index]) + bytes((index * 37 + offset) % 256 for offset in range(1, 16))


def write_nodes_dat(path: Path, *, owner: KadClientSpec, peers: list[KadClientSpec], peer_address: str) -> dict[str, object]:
    """Writes a deterministic v2 `nodes.dat` containing local peer contacts."""

    contacts = [peer for peer in peers if peer.profile_id != owner.profile_id]
    if not contacts:
        raise ValueError("nodes.dat fixture requires at least one peer contact.")
    path.parent.mkdir(parents=True, exist_ok=True)
    stored_ip = stored_nodes_dat_ip(peer_address)
    with path.open("wb") as handle:
        handle.write(struct.pack("<III", 0, 2, len(contacts)))
        for peer in contacts:
            handle.write(deterministic_kad_node_id(peer.index))
            handle.write(
                struct.pack(
                    "<IHHBIIB",
                    stored_ip,
                    peer.udp_port,
                    peer.tcp_port,
                    KADEMLIA_CONTACT_VERSION,
                    0,
                    0,
                    1,
                )
            )
    return {
        "path": str(path),
        "fixture_mode": "valid",
        "contact_count": len(contacts),
        "peer_address": peer_address,
        "peers": [
            {
                "profile_id": peer.profile_id,
                "udp_port": peer.udp_port,
                "tcp_port": peer.tcp_port,
            }
            for peer in contacts
        ],
    }


def stale_peer_spec(peer: KadClientSpec) -> KadClientSpec:
    """Returns one peer descriptor whose ports should not be accepting traffic."""

    stale_tcp = peer.tcp_port + 1000 if peer.tcp_port <= 64535 else peer.tcp_port - 1000
    stale_udp = peer.udp_port + 1000 if peer.udp_port <= 64535 else peer.udp_port - 1000
    return KadClientSpec(
        index=peer.index,
        profile_id=peer.profile_id,
        nick=peer.nick,
        tcp_port=stale_tcp,
        udp_port=stale_udp,
        rest_port=peer.rest_port,
    )


def write_truncated_nodes_dat(path: Path) -> dict[str, object]:
    """Writes a malformed `nodes.dat` fixture for startup-tolerance chaos."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<II", 0, 2) + b"truncated")
    return {
        "path": str(path),
        "fixture_mode": "truncated",
        "contact_count": 0,
        "expected": "Kad remains running without loading contacts from malformed nodes.dat.",
    }


def write_nodes_dat_fixture(
    path: Path,
    *,
    owner: KadClientSpec,
    peers: list[KadClientSpec],
    peer_address: str,
    fixture_mode: str,
) -> dict[str, object]:
    """Writes the requested local `nodes.dat` fixture mode."""

    if fixture_mode == "valid":
        return write_nodes_dat(path, owner=owner, peers=peers, peer_address=peer_address)
    if fixture_mode == "stale":
        summary = write_nodes_dat(
            path,
            owner=owner,
            peers=[stale_peer_spec(peer) for peer in peers],
            peer_address=peer_address,
        )
        summary["fixture_mode"] = "stale"
        summary["expected"] = "Kad loads stale local contacts but should not become connected without live bootstrap."
        return summary
    if fixture_mode == "truncated":
        return write_truncated_nodes_dat(path)
    raise ValueError(f"Unsupported nodes.dat fixture mode: {fixture_mode!r}")


def configure_kad_client_profile(
    *,
    config_dir: Path,
    app_exe: Path,
    spec: KadClientSpec,
    api_key: str,
    lan_bind_addr: str,
    p2p_bind_interface_name: str,
    p2p_bind_addr: str,
) -> dict[str, object]:
    """Applies local-only Kad and REST preferences to one eMuleBB profile."""

    bind_interface = p2p_bind_interface_name.strip()
    effective_p2p_bind_addr = "" if bind_interface else p2p_bind_addr.strip()
    live_common.apply_emule_preferences(
        config_dir,
        (
            ("Nick", spec.nick),
            ("Port", str(spec.tcp_port)),
            ("UDPPort", str(spec.udp_port)),
            ("ServerUDPPort", "65535"),
            ("ConfirmExit", "0"),
            ("Autoconnect", "0"),
            ("Reconnect", "0"),
            ("NetworkED2K", "0"),
            ("NetworkKademlia", "1"),
            ("AutoConnectStaticOnly", "0"),
            ("SafeServerConnect", "0"),
            ("FilterBadIPs", "0"),
            ("AllowLocalHostIP", "1"),
            ("GeoLocationLookupEnabled", "0"),
            ("IPFilterEnabled", "0"),
            ("DownloadCapacity", str(dtt.DETERMINISTIC_BANDWIDTH_CAPACITY_KIB)),
            ("UploadCapacity", str(dtt.DETERMINISTIC_BANDWIDTH_CAPACITY_KIB)),
            ("UploadCapacityNew", str(dtt.DETERMINISTIC_BANDWIDTH_CAPACITY_KIB)),
            ("MaxUpload", str(dtt.DETERMINISTIC_BANDWIDTH_LIMIT_KIB)),
            ("MaxDownload", str(dtt.DETERMINISTIC_BANDWIDTH_LIMIT_KIB)),
            ("CloseUPnPOnExit", "0"),
            ("BindInterface", bind_interface),
            ("BindAddr", effective_p2p_bind_addr),
            ("BlockNetworkWhenBindUnavailableAtStartup", "1" if bind_interface or effective_p2p_bind_addr else "0"),
            ("DebugClientKadUDP", "1"),
        ),
    )
    live_common.apply_section_preferences(config_dir, "UPnP", (("EnableUPnP", "0"),))
    live_common.apply_webserver_profile(
        config_dir,
        live_common.WebServerProfileSpec(
            app_exe=app_exe,
            api_key=api_key,
            port=spec.rest_port,
            lan_bind_addr=rest_smoke.require_lan_bind_addr(lan_bind_addr),
        ),
    )
    return {
        "removed_kad_state_files": remove_kad_state_files(config_dir),
        "preferences": dtt.read_preferences_snapshot(config_dir),
        "local_bind": {
            "p2p_bind_interface_name": bind_interface,
            "p2p_bind_addr": effective_p2p_bind_addr,
        },
    }


def base_url(lan_bind_addr: str, spec: KadClientSpec) -> str:
    """Returns the REST base URL for one local Kad client."""

    return f"http://{lan_bind_addr}:{spec.rest_port}"


def get_kad_status(base_url_text: str, api_key: str) -> dict[str, Any]:
    """Reads one Kad status payload through REST."""

    result = rest_smoke.http_request(base_url_text, "/api/v1/kad", api_key=api_key, request_timeout_seconds=15.0)
    return rest_smoke.require_json_object(result, 200)


def compact_local_kad_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Keeps local Kad readiness timelines compact and stable."""

    compact = rest_smoke.compact_kad_status(payload)
    compact["contactCount"] = payload.get("contactCount")
    compact["lanMode"] = payload.get("lanMode")
    return compact


def start_kad(base_url_text: str, api_key: str) -> dict[str, object]:
    """Starts Kad on one local client and returns the compact REST result."""

    result = rest_smoke.http_request(
        base_url_text,
        "/api/v1/kad/operations/start",
        method="POST",
        api_key=api_key,
        json_body={},
        request_timeout_seconds=30.0,
    )
    rest_smoke.require_json_object(result, 200)
    return rest_smoke.compact_http_result(result)


def bootstrap_kad(base_url_text: str, api_key: str, *, peer_address: str, peer_udp_port: int) -> dict[str, object]:
    """Queues one Kad bootstrap request toward a local peer."""

    result = rest_smoke.http_request(
        base_url_text,
        "/api/v1/kad/operations/bootstrap",
        method="POST",
        api_key=api_key,
        json_body={"address": peer_address, "port": peer_udp_port},
        request_timeout_seconds=30.0,
    )
    rest_smoke.require_json_object(result, 200)
    return rest_smoke.compact_http_result(result)


def build_bootstrap_plan(specs: list[KadClientSpec]) -> list[tuple[KadClientSpec, KadClientSpec]]:
    """Returns a throttling-safe bootstrap plan that makes every node learn peers."""

    if len(specs) < 2:
        raise ValueError("at least two local Kad clients are required.")
    seed = specs[0]
    plan: list[tuple[KadClientSpec, KadClientSpec]] = []
    for spec in specs[1:]:
        plan.append((spec, seed))
    for spec in specs[1:]:
        plan.append((seed, spec))
    if len(specs) > 2:
        for index, spec in enumerate(specs[1:], start=1):
            plan.append((spec, specs[(index % (len(specs) - 1)) + 1]))
    return plan


def wait_for_local_swarm(
    *,
    specs: list[KadClientSpec],
    lan_bind_addr: str,
    api_key: str,
    min_contacts_per_client: int,
    require_connected: bool,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until every local Kad client has the requested local contact count."""

    observations: list[dict[str, object]] = []

    def resolve():
        snapshot_rows: list[dict[str, object]] = []
        ready = True
        for spec in specs:
            status = get_kad_status(base_url(lan_bind_addr, spec), api_key)
            compact = compact_local_kad_status(status)
            contact_count = compact.get("contactCount")
            row = {
                "profile_id": spec.profile_id,
                "status": compact,
            }
            snapshot_rows.append(row)
            if not bool(compact.get("running")):
                ready = False
            if require_connected and not bool(compact.get("connected")):
                ready = False
            if not isinstance(contact_count, int) or contact_count < min_contacts_per_client:
                ready = False
        observation = {
            "observed_at": round(time.time(), 3),
            "clients": snapshot_rows,
        }
        observations.append(observation)
        if ready:
            return {
                "ready": True,
                "min_contacts_per_client": min_contacts_per_client,
                "require_connected": require_connected,
                "observations": observations,
            }
        return None

    return live_common.wait_for(resolve, timeout_seconds, 2.0, "local Kad swarm contact readiness")


def main(argv: list[str] | None = None) -> int:
    """Runs the deterministic local Kad swarm connectivity matrix."""

    args = parse_args(argv)
    validate_args(args)
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration=args.configuration,
        workspace_root=None,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    profile_seed_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "network_class": "local-live-stack",
        "checks": {},
    }
    apps: dict[str, object] = {}
    current_phase = "initializing"

    try:
        p2p_address = args.p2p_bind_interface_address or dtt.discover_interface_ipv4(args.p2p_bind_interface_name)
        specs = build_client_specs(args.client_count, choose_local_kad_ports(args.client_count, args.lan_bind_addr))
        report["network"] = {
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
            "lan_bind_addr": args.lan_bind_addr,
            "bootstrap_mode": args.bootstrap_mode,
            "nodes_dat_fixture_mode": args.nodes_dat_fixture_mode,
            "clients": [asdict(spec) for spec in specs],
        }

        profile_reports: dict[str, object] = {}
        for spec in specs:
            profile = live_common.prepare_scenario_profile(
                profile_seed_dir,
                paths.source_artifacts_dir,
                [],
                spec.profile_id,
            )
            configured = configure_kad_client_profile(
                config_dir=Path(profile["config_dir"]),
                app_exe=paths.app_exe,
                spec=spec,
                api_key=args.api_key,
                lan_bind_addr=args.lan_bind_addr,
                p2p_bind_interface_name=args.p2p_bind_interface_name,
                p2p_bind_addr=p2p_address,
            )
            preseed_summary = None
            if args.bootstrap_mode in {"preseed", "both"}:
                preseed_summary = write_nodes_dat_fixture(
                    Path(profile["config_dir"]) / "nodes.dat",
                    owner=spec,
                    peers=specs,
                    peer_address=p2p_address,
                    fixture_mode=args.nodes_dat_fixture_mode,
                )
            profile_reports[spec.profile_id] = {
                "profile_base": str(profile["profile_base"]),
                "config_dir": str(profile["config_dir"]),
                "incoming_dir": str(profile["incoming_dir"]),
                "temp_dir": str(profile["temp_dir"]),
                **configured,
                "nodes_dat_preseed": preseed_summary,
            }
        report["profiles"] = profile_reports

        for spec in specs:
            current_phase = f"launch_{spec.profile_id}"
            apps[spec.profile_id] = live_common.launch_app(
                paths.app_exe,
                Path(profile_reports[spec.profile_id]["profile_base"]),
                minimized_to_tray=True,
            )
            report["checks"][f"{spec.profile_id}_rest_ready"] = rest_smoke.compact_http_result(
                rest_smoke.wait_for_rest_ready(base_url(args.lan_bind_addr, spec), args.api_key, args.rest_ready_timeout_seconds)
            )

        for spec in specs:
            current_phase = f"start_kad_{spec.profile_id}"
            report["checks"][f"{spec.profile_id}_kad_start"] = start_kad(base_url(args.lan_bind_addr, spec), args.api_key)
            report["checks"][f"{spec.profile_id}_kad_running"] = rest_smoke.wait_for_kad_running(
                base_url(args.lan_bind_addr, spec),
                args.api_key,
                args.kad_running_timeout_seconds,
            )

        if args.bootstrap_mode in {"rest", "both"}:
            current_phase = "bootstrap_swarm"
            bootstrap_rows: list[dict[str, object]] = []
            for source, target in build_bootstrap_plan(specs):
                bootstrap_rows.append(
                    {
                        "source": source.profile_id,
                        "target": target.profile_id,
                        "target_udp_port": target.udp_port,
                        "result": bootstrap_kad(
                            base_url(args.lan_bind_addr, source),
                            args.api_key,
                            peer_address=p2p_address,
                            peer_udp_port=target.udp_port,
                        ),
                    }
                )
                time.sleep(KAD_BOOTSTRAP_THROTTLE_SECONDS)
            report["checks"]["bootstrap_plan"] = bootstrap_rows
        else:
            report["checks"]["bootstrap_plan"] = {
                "mode": "preseed",
                "rest_bootstrap_skipped": True,
            }

        current_phase = "wait_for_swarm"
        require_connected = args.bootstrap_mode != "preseed" and args.nodes_dat_fixture_mode == "valid"
        report["checks"]["swarm_readiness_policy"] = {
            "min_contacts_per_client": args.min_contacts_per_client,
            "require_connected": require_connected,
            "nodes_dat_fixture_mode": args.nodes_dat_fixture_mode,
        }
        report["checks"]["swarm_ready"] = wait_for_local_swarm(
            specs=specs,
            lan_bind_addr=args.lan_bind_addr,
            api_key=args.api_key,
            min_contacts_per_client=args.min_contacts_per_client,
            require_connected=require_connected,
            timeout_seconds=args.swarm_ready_timeout_seconds,
        )
        report["checks"]["final_kad_status"] = {
            spec.profile_id: compact_local_kad_status(get_kad_status(base_url(args.lan_bind_addr, spec), args.api_key))
            for spec in specs
        }
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["current_phase"] = current_phase
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        return 1
    finally:
        close_results: dict[str, object] = {}
        for profile_id, app in apps.items():
            try:
                live_common.close_app_cleanly(app)
                close_results[profile_id] = {"ok": True}
            except Exception as exc:
                close_results[profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        report["cleanup"] = close_results
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        report_path = paths.source_artifacts_dir / "local-kad-swarm-result.json"
        harness_cli_common.write_json_file(report_path, report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
