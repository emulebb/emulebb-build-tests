"""Local Kad swarm matrix across eMuleBB MFC peers."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import asdict
import importlib.util
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.multi_client import CLIENT_IDENTITIES, resolve_mfc_oracle_client  # noqa: E402
from emule_test_harness import kad_nodes, rust_client  # noqa: E402
from emule_test_harness.local_kad_peer import LocalKadPeer  # noqa: E402
from emule_test_harness.rust_local_ed2k import request_json, wait_for  # noqa: E402


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


dtt = load_local_module("deterministic_two_client_transfer_mixed_kad", "deterministic-two-client-transfer.py")
local_kad = load_local_module("local_kad_swarm_mixed_clients", "local-kad-swarm.py")
harness_cli_common = dtt.harness_cli_common
live_common = dtt.live_common
rest_smoke = dtt.rest_smoke

SUITE_NAME = "local-kad-mixed-client-swarm"
API_KEY = "local-kad-mixed-client-swarm-key"
CLIENT01 = CLIENT_IDENTITIES["emulebb"]
CLIENT02 = CLIENT_IDENTITIES["mfc_oracle"]
DEFAULT_MIN_CONTACTS_PER_EMULE_CLIENT = 1
DEFAULT_BOOTSTRAP_THROTTLE_SECONDS = 11.0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses standalone mixed-client local Kad swarm arguments."""

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
    parser.add_argument("--mfc-oracle-exe")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--kad-running-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--swarm-ready-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--bootstrap-throttle-seconds", type=float, default=DEFAULT_BOOTSTRAP_THROTTLE_SECONDS)
    parser.add_argument("--min-contacts-per-emule-client", type=int, default=DEFAULT_MIN_CONTACTS_PER_EMULE_CLIENT)
    parser.add_argument("--native-firewall-case", choices=("disconnect", "keyed-probe", "silent"))
    return parser.parse_args(argv)


def observe_native_firewall(paths, args: argparse.Namespace) -> dict[str, object]:
    """Drive one fresh native Kad round through reachable, closed, or silent helpers."""
    profile = paths.source_artifacts_dir / "rust-native-firewall"
    rust_repo = dtt.resolve_selected_workspace_repo(REPO_ROOT, "emulebb-rust")
    runtime = rust_client.verified_runtime_stage(rust_repo, dtt.get_workspace_output_root(), diagnostics=True)
    executable = Path(runtime["executable"])
    bind = "127.0.0.1"
    arm_referrals = threading.Event()
    referral_used = threading.Event()
    referral_lock = threading.Lock()
    firewall_case = args.native_firewall_case

    with ExitStack() as owned:
        modes = ("reject-hello", "silent", "silent") if firewall_case == "silent" else (firewall_case,) * 2
        candidates = []
        for index, mode in enumerate(modes, start=21):
            tester = LocalKadPeer(f"127.0.0.{index}", {bind}, firewall_reply=mode)
            owned.callback(tester.close)
            tester.start()
            candidates.append(tester)
        testers = tuple(candidates)

        def referrals(_target: bytes) -> tuple[LocalKadPeer, ...]:
            with referral_lock:
                if not arm_referrals.is_set() or referral_used.is_set():
                    return ()
                if sum(bool(peer.evidence().get("pongReplies")) for peer in reporters) < 2:
                    return ()
                referral_used.set()
                return testers

        reporters: list[LocalKadPeer] = []
        def known_contacts() -> list[kad_nodes.BootstrapContact]:
            return [
                kad_nodes.BootstrapContact(peer.bind_ip, peer.udp_port, peer.tcp_port)
                for peer in reporters
            ]

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as external_listener:
            external_listener.bind((bind, 0))
            external_port = external_listener.getsockname()[1]
        for suffix in range(2, 12):
            reporter = LocalKadPeer(
                f"127.0.0.{suffix}", {bind}, route_referrals=referrals, nodes_contacts=known_contacts,
                reported_udp_port=external_port,
            )
            owned.callback(reporter.close)
            reporters.append(reporter)
        for reporter in reporters:
            reporter.start()
        with (
            socket.create_server((bind, 0)) as rest_listener,
            socket.create_server((bind, 0)) as tcp_listener,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_listener,
        ):
            udp_listener.bind((bind, 0))
            rest_port = rest_listener.getsockname()[1]
            tcp_port = tcp_listener.getsockname()[1]
            udp_port = udp_listener.getsockname()[1]
        rust_client.write_rust_profile(
            profile,
            rust_repo=rust_repo,
            rest_addr=bind,
            rest_port=rest_port,
            api_key=args.api_key,
            local_only_discovery=True,
            local_kad_seed=known_contacts()[0],
            settings={
                "network.ed2kEnabled": False,
                "network.kadEnabled": True,
                "network.p2p.bindIp": bind,
                "network.p2p.tcpPort": tcp_port,
                "network.p2p.udpPort": udp_port,
                "security.obfuscationEnabled": False,
            },
        )
        output = paths.source_artifacts_dir / "rust-native-firewall.out"
        child_env = dtt.rust_diagnostics_child_env(paths.source_artifacts_dir / "diagnostics" / "rust")
        child_env["RUST_LOG"] = "info,emulebb_core::kad_udp_firewall_check=debug"
        process = rust_client.start_rust_client_executable(
            executable,
            profile,
            output,
            env=child_env,
        )
        owned.callback(rust_client.stop_process_tree, process)
        base = f"http://{bind}:{rest_port}"
        rest_smoke.wait_for_rest_ready(base, args.api_key, args.rest_ready_timeout_seconds)
        request_json(base, "POST", "/api/v1/kad/operations/start", args.api_key, {})
        request_json(
            base, "POST", "/api/v1/kad/operations/import-nodes-url", args.api_key,
            {"url": reporters[0].nodes_url},
        )

        def get_ready() -> dict[str, object] | None:
            state = request_json(base, "GET", "/api/v1/kad", args.api_key)
            if state.get("connected") is True and int(state.get("contactCount", 0)) >= len(reporters):
                return state
            return None

        contacts = wait_for(
            get_ready,
            timeout_seconds=args.kad_running_timeout_seconds,
            interval_seconds=1,
            description="native Kad proof's ten known loopback reporters",
        )
        arm_referrals.set()
        request_json(base, "POST", "/api/v1/kad/operations/recheck-firewall", args.api_key, {})
        def round_summary() -> str | None:
            log = output.read_text(encoding="utf-8", errors="replace")
            if firewall_case == "disconnect" and "Kad UDP firewall check: firewalled" in log:
                return "firewalled"
            if firewall_case == "keyed-probe" and log.count("Kad UDP firewall check completed from") >= 2:
                if f"external_udp_port={external_port}" in log and "external_udp_port=0" in log:
                    return "open-internal-preferred"
            if firewall_case == "silent" and "Kad UDP firewall check round produced no verdict" in log:
                if testers[0].evidence().get("closedBeforeRequest") == 1 and all(
                    tester.evidence().get("silentRequests") == 1 for tester in testers[1:]
                ):
                    return "inconclusive"
            return None

        verdict = wait_for(
            round_summary,
            timeout_seconds=55,
            interval_seconds=1,
            description=f"Kad native {firewall_case} round verdict",
        )
        witnesses = [tester.evidence() for tester in testers]
        accepted = [row for row in witnesses if row.get("unbiasedRequests") == 1]
        if len(accepted) < (1 if firewall_case == "keyed-probe" else 2):
            raise RuntimeError("Native round has too few fresh helper requests")
        for row in accepted:
            if row.get("priorUdpPackets", 0) or row["firewallRequestDetails"] != [{
                "internalPort": udp_port,
                "externalPort": external_port,
                "senderKeyPresent": True,
                "priorUdp": False,
            }]:
                raise RuntimeError("Native tester saw a biased request or unexpected UDP port or key")
            if firewall_case == "disconnect" and row.get("closedAfterRequest") != 1:
                raise RuntimeError("Closed verdict lacked a post-request helper disconnect")
            if firewall_case == "keyed-probe" and row.get("keyedUdpProbeReplies") != 2:
                raise RuntimeError("Open verdict lacked keyed external and internal probes")
        return {
            "sourceRevision": runtime["source"]["revision"],
            "executableSha256": dtt.file_sha256(executable),
            "runnerRevision": dtt.git_head_revision(REPO_ROOT),
            "knownContacts": contacts["contactCount"],
            "verdict": verdict,
            "testerWitnesses": witnesses,
        }


def validate_args(args: argparse.Namespace) -> None:
    """Rejects mixed swarm settings that would not validate cross-client Kad paths."""

    if args.min_contacts_per_emule_client < 1:
        raise ValueError("minimum contacts per eMule-family client must be at least 1.")
    if args.bootstrap_throttle_seconds < 0:
        raise ValueError("bootstrap throttle must be zero or greater.")


def build_participant_specs(ports: list[tuple[int, int, int]]) -> dict[str, Any]:
    """Builds stable participant descriptors for the mixed Kad swarm."""

    if len(ports) != 2:
        raise ValueError("mixed Kad swarm requires exactly two REST-capable eMule-family clients.")
    emulebb_rest, emulebb_tcp, emulebb_udp = ports[0]
    mfc_oracle_rest, mfc_oracle_tcp, mfc_oracle_udp = ports[1]
    return {
        "emulebb": local_kad.KadClientSpec(
            index=1,
            profile_id=CLIENT01.profile_id,
            nick=CLIENT01.nick,
            tcp_port=emulebb_tcp,
            udp_port=emulebb_udp,
            rest_port=emulebb_rest,
        ),
        "mfc_oracle": local_kad.KadClientSpec(
            index=2,
            profile_id=CLIENT02.profile_id,
            nick=CLIENT02.nick,
            tcp_port=mfc_oracle_tcp,
            udp_port=mfc_oracle_udp,
            rest_port=mfc_oracle_rest,
        ),
    }


def explicit_rest_bootstrap_plan(specs: dict[str, Any]) -> list[tuple[str, Any, str, Any]]:
    """Returns every targeted REST bootstrap path available from eMuleBB."""

    emulebb = specs["emulebb"]
    mfc_oracle = specs["mfc_oracle"]
    return [
        ("emulebb_to_mfc_oracle", emulebb, "mfc_oracle", mfc_oracle),
        ("mfc_oracle_to_emulebb", mfc_oracle, "emulebb", emulebb),
    ]


def preseed_autoconnect_paths(specs: dict[str, Any]) -> list[dict[str, object]]:
    """Documents non-REST outbound paths driven by preseed plus network start."""

    return []


def resolve_required_mfc_oracle(paths, args: argparse.Namespace):
    """Resolves the MFC peer executable or raises an actionable error."""

    availability = resolve_mfc_oracle_client(paths.workspace_root, args.configuration, args.mfc_oracle_exe)
    if not availability.available or availability.executable is None:
        raise RuntimeError(f"MFC peer is unavailable for mixed Kad E2E: {availability.reason}")
    return availability


def read_client_log_text(log_path: Path) -> str:
    """Reads eMule-family logs regardless of UTF-8 or UTF-16 encoding."""

    data = log_path.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def wait_for_log_patterns(log_path: Path, patterns: tuple[str, ...], timeout_seconds: float, label: str) -> dict[str, object]:
    """Waits until all text patterns are present in a client log file."""

    deadline = time.monotonic() + timeout_seconds
    last_text = ""
    while time.monotonic() < deadline:
        if log_path.exists():
            last_text = read_client_log_text(log_path)
            if all(pattern in last_text for pattern in patterns):
                return {
                    "ready": True,
                    "path": str(log_path),
                    "patterns": list(patterns),
                    "tail": last_text[-4000:],
                }
        time.sleep(1.0)
    raise RuntimeError(f"Timed out waiting for {label}. Last log tail: {last_text[-4000:]!r}")


def main(argv: list[str] | None = None) -> int:
    """Runs the mixed-client deterministic local Kad swarm matrix."""

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
        require_app_exe=args.native_firewall_case is None,
    )
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
        if args.native_firewall_case:
            current_phase = f"native_firewall_{args.native_firewall_case}"
            report["checks"]["nativeFirewall"] = observe_native_firewall(paths, args)
            report["status"] = "passed"
            return 0

        current_phase = "resolve_clients"
        profile_seed_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
        mfc_oracle_client = resolve_required_mfc_oracle(paths, args)

        current_phase = "allocate_ports"
        emule_ports = local_kad.choose_local_kad_ports(2, args.lan_bind_addr)
        specs = build_participant_specs(emule_ports)
        p2p_address = dtt.resolve_lan_p2p_bind_address(
            lan_bind_addr=args.lan_bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
            p2p_bind_interface_address=args.p2p_bind_interface_address,
        )
        all_specs = [specs["emulebb"], specs["mfc_oracle"]]
        report["network"] = {
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
            "lan_bind_addr": args.lan_bind_addr,
            "participants": {key: asdict(value) for key, value in specs.items()},
            "client_inventory": {
                "mfcOracle": mfc_oracle_client.as_report(),
            },
        }

        current_phase = "prepare_emule_profiles"
        profile_reports: dict[str, object] = {}
        emule_profiles = {
            "emulebb": live_common.prepare_scenario_profile(
                profile_seed_dir,
                paths.source_artifacts_dir,
                [],
                CLIENT01.profile_id,
            ),
            "mfc_oracle": live_common.prepare_scenario_profile(
                profile_seed_dir,
                paths.source_artifacts_dir,
                [],
                CLIENT02.profile_id,
            ),
        }
        for key, profile in emule_profiles.items():
            spec = specs[key]
            app_exe = paths.app_exe if key == "emulebb" else mfc_oracle_client.executable
            configured = local_kad.configure_kad_client_profile(
                config_dir=Path(profile["config_dir"]),
                app_exe=app_exe,
                spec=spec,
                api_key=args.api_key,
                lan_bind_addr=args.lan_bind_addr,
                p2p_bind_interface_name=args.p2p_bind_interface_name,
                p2p_bind_addr=p2p_address,
            )
            preseed = local_kad.write_nodes_dat(
                Path(profile["config_dir"]) / "nodes.dat",
                owner=spec,
                peers=all_specs,
                peer_address=p2p_address,
            )
            profile_reports[spec.profile_id] = {
                "profile_base": str(profile["profile_base"]),
                "config_dir": str(profile["config_dir"]),
                "incoming_dir": str(profile["incoming_dir"]),
                "temp_dir": str(profile["temp_dir"]),
                **configured,
                "nodes_dat_preseed": preseed,
            }

        report["profiles"] = profile_reports

        current_phase = "launch_emule_family_clients"
        apps[CLIENT01.profile_id] = live_common.launch_app(
            paths.app_exe,
            Path(emule_profiles["emulebb"]["profile_base"]),
            minimized_to_tray=True,
        )
        apps[CLIENT02.profile_id] = live_common.launch_app(
            mfc_oracle_client.executable,
            Path(emule_profiles["mfc_oracle"]["profile_base"]),
            minimized_to_tray=True,
        )
        report["checks"][f"{CLIENT01.profile_id}_rest_ready"] = rest_smoke.compact_http_result(
            rest_smoke.wait_for_rest_ready(
                local_kad.base_url(args.lan_bind_addr, specs["emulebb"]),
                args.api_key,
                args.rest_ready_timeout_seconds,
            )
        )
        report["checks"][f"{CLIENT02.profile_id}_rest_ready"] = rest_smoke.compact_http_result(
            rest_smoke.wait_for_rest_ready(
                local_kad.base_url(args.lan_bind_addr, specs["mfc_oracle"]),
                args.api_key,
                args.rest_ready_timeout_seconds,
            )
        )

        current_phase = "start_kad"
        report["checks"][f"{CLIENT01.profile_id}_kad_start"] = local_kad.start_kad(
            local_kad.base_url(args.lan_bind_addr, specs["emulebb"]),
            args.api_key,
        )
        report["checks"][f"{CLIENT01.profile_id}_kad_running"] = rest_smoke.wait_for_kad_running(
            local_kad.base_url(args.lan_bind_addr, specs["emulebb"]),
            args.api_key,
            args.kad_running_timeout_seconds,
        )
        report["checks"][f"{CLIENT02.profile_id}_kad_start"] = local_kad.start_kad(
            local_kad.base_url(args.lan_bind_addr, specs["mfc_oracle"]),
            args.api_key,
        )
        report["checks"][f"{CLIENT02.profile_id}_kad_running"] = rest_smoke.wait_for_kad_running(
            local_kad.base_url(args.lan_bind_addr, specs["mfc_oracle"]),
            args.api_key,
            args.kad_running_timeout_seconds,
        )
        current_phase = "bootstrap_all_rest_paths"
        bootstrap_rows: list[dict[str, object]] = []
        for path_id, source, target_key, target in explicit_rest_bootstrap_plan(specs):
            bootstrap_rows.append(
                {
                    "id": path_id,
                    "source": source.profile_id,
                    "target": target.profile_id,
                    "target_kind": target_key,
                    "target_udp_port": target.udp_port,
                    "result": local_kad.bootstrap_kad(
                        local_kad.base_url(args.lan_bind_addr, source),
                        args.api_key,
                        peer_address=p2p_address,
                        peer_udp_port=target.udp_port,
                    ),
                }
            )
            time.sleep(args.bootstrap_throttle_seconds)
        report["checks"]["explicit_rest_bootstrap_plan"] = bootstrap_rows
        report["checks"]["preseed_autoconnect_paths"] = preseed_autoconnect_paths(specs)

        current_phase = "wait_for_mixed_swarm"
        report["checks"]["swarm_readiness_policy"] = {
            "min_contacts_per_emule_client": args.min_contacts_per_emule_client,
            "require_connected": True,
            "single_lan_bind_address_limit": "Kad accepts one contact per IP in this local single-address matrix; multi-contact assertions require per-client local IP aliases or adapters.",
            "mfc_peer_policy": "Both MFC eMule-family clients expose REST and are explicitly bootstrapped through the API.",
        }
        report["checks"]["emule_family_swarm_ready"] = local_kad.wait_for_local_swarm(
            specs=[specs["emulebb"], specs["mfc_oracle"]],
            lan_bind_addr=args.lan_bind_addr,
            api_key=args.api_key,
            min_contacts_per_client=args.min_contacts_per_emule_client,
            require_connected=True,
            timeout_seconds=args.swarm_ready_timeout_seconds,
        )
        report["checks"]["final_kad_status"] = {
            CLIENT01.profile_id: local_kad.compact_local_kad_status(
                local_kad.get_kad_status(local_kad.base_url(args.lan_bind_addr, specs["emulebb"]), args.api_key)
            ),
            CLIENT02.profile_id: local_kad.compact_local_kad_status(
                local_kad.get_kad_status(local_kad.base_url(args.lan_bind_addr, specs["mfc_oracle"]), args.api_key)
            ),
        }
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["current_phase"] = current_phase
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        return 1
    finally:
        cleanup: dict[str, object] = {}
        for profile_id, app in apps.items():
            try:
                live_common.close_app_cleanly(app)
                cleanup[profile_id] = {"ok": True}
            except Exception as exc:
                cleanup[profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        report["cleanup"] = cleanup
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "local-kad-mixed-client-swarm-result.json", report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
