"""Local Kad swarm matrix across eMule BB, tracing harness, and aMule."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import importlib.util
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import amule as amule_harness  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES, resolve_amule_client, resolve_harness_client  # noqa: E402


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
CLIENT02 = CLIENT_IDENTITIES["harness"]
CLIENT04 = CLIENT_IDENTITIES["amule"]
DEFAULT_MIN_CONTACTS_PER_EMULE_CLIENT = 1
DEFAULT_BOOTSTRAP_THROTTLE_SECONDS = 11.0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses standalone mixed-client local Kad swarm arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--p2p-bind-interface-name", default="")
    parser.add_argument("--p2p-bind-interface-address")
    parser.add_argument("--harness-exe")
    parser.add_argument("--amule-daemon-exe")
    parser.add_argument("--amule-control-exe")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--kad-running-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--swarm-ready-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--amule-ec-ready-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--amule-kad-ready-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--bootstrap-throttle-seconds", type=float, default=DEFAULT_BOOTSTRAP_THROTTLE_SECONDS)
    parser.add_argument("--min-contacts-per-emule-client", type=int, default=DEFAULT_MIN_CONTACTS_PER_EMULE_CLIENT)
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> None:
    """Rejects mixed swarm settings that would not validate cross-client Kad paths."""

    if args.min_contacts_per_emule_client < 1:
        raise ValueError("minimum contacts per eMule-family client must be at least 1.")
    if args.bootstrap_throttle_seconds < 0:
        raise ValueError("bootstrap throttle must be zero or greater.")


def choose_amule_ports(used_ports: set[int]) -> dict[str, int]:
    """Allocates distinct aMule TCP, UDP, and EC ports outside the eMule set."""

    ports: dict[str, int] = {}
    for name in ("tcp", "udp", "ec"):
        udp = name == "udp"
        for _ in range(200):
            candidate = rest_smoke.choose_listen_port()
            if candidate not in used_ports and dtt.is_port_available(candidate, udp=udp):
                ports[name] = candidate
                used_ports.add(candidate)
                break
        else:
            raise RuntimeError(f"Could not allocate a local aMule {name} port.")
    return ports


def build_participant_specs(ports: list[tuple[int, int, int]], amule_ports: dict[str, int]) -> dict[str, Any]:
    """Builds stable participant descriptors for the mixed Kad swarm."""

    if len(ports) != 2:
        raise ValueError("mixed Kad swarm requires exactly two REST-capable eMule-family clients.")
    emulebb_rest, emulebb_tcp, emulebb_udp = ports[0]
    harness_rest, harness_tcp, harness_udp = ports[1]
    return {
        "emulebb": local_kad.KadClientSpec(
            index=1,
            profile_id=CLIENT01.profile_id,
            nick=CLIENT01.nick,
            tcp_port=emulebb_tcp,
            udp_port=emulebb_udp,
            rest_port=emulebb_rest,
        ),
        "harness": local_kad.KadClientSpec(
            index=2,
            profile_id=CLIENT02.profile_id,
            nick=CLIENT02.nick,
            tcp_port=harness_tcp,
            udp_port=harness_udp,
            rest_port=harness_rest,
        ),
        "amule": local_kad.KadClientSpec(
            index=4,
            profile_id=CLIENT04.profile_id,
            nick=CLIENT04.nick,
            tcp_port=amule_ports["tcp"],
            udp_port=amule_ports["udp"],
            rest_port=0,
        ),
    }


def explicit_rest_bootstrap_plan(specs: dict[str, Any]) -> list[tuple[str, Any, str, Any]]:
    """Returns every targeted REST bootstrap path available from eMule BB."""

    emulebb = specs["emulebb"]
    harness = specs["harness"]
    amule = specs["amule"]
    return [
        ("emulebb_to_harness", emulebb, "harness", harness),
        ("emulebb_to_amule", emulebb, "amule", amule),
    ]


def preseed_autoconnect_paths(specs: dict[str, Any]) -> list[dict[str, object]]:
    """Documents non-REST outbound paths driven by preseed plus network start."""

    return [
        {
            "source": specs["harness"].profile_id,
            "target": specs[key].profile_id,
            "target_udp_port": specs[key].udp_port,
            "mechanism": "nodes.dat preseed loaded before tracing harness Kad autoconnect",
        }
        for key in ("emulebb", "amule")
    ] + [
        {
            "source": specs["amule"].profile_id,
            "target": specs[key].profile_id,
            "target_udp_port": specs[key].udp_port,
            "mechanism": "nodes.dat preseed loaded before amulecmd 'Connect Kad'",
        }
        for key in ("emulebb", "harness")
    ]


def resolve_required_harness(paths, args: argparse.Namespace):
    """Resolves the tracing harness executable or raises an actionable error."""

    availability = resolve_harness_client(paths.workspace_root, args.configuration, args.harness_exe)
    if not availability.available or availability.executable is None:
        raise RuntimeError(f"tracing harness is unavailable for mixed Kad E2E: {availability.reason}")
    return availability


def resolve_required_amule(paths, args: argparse.Namespace):
    """Resolves the staged aMule daemon/control pair or raises an actionable error."""

    availability = resolve_amule_client(paths.workspace_root, args.amule_daemon_exe, args.amule_control_exe)
    if not availability.available or availability.executable is None or availability.control_executable is None:
        raise RuntimeError(f"aMule is unavailable for mixed Kad E2E: {availability.reason}")
    return availability


def amule_command_summary(completed: subprocess.CompletedProcess) -> dict[str, object]:
    """Returns a bounded diagnostic summary for one `amulecmd` invocation."""

    return {
        "return_code": completed.returncode,
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-2000:],
    }


def shutdown_amule(control_exe: Path | None, profile: amule_harness.AmuleRuntimeProfile | None) -> dict[str, object]:
    """Requests graceful aMule daemon shutdown through EC when possible."""

    if control_exe is None or profile is None:
        return {"skipped": True}
    completed = amule_harness.run_amulecmd(control_exe, profile, "Shutdown", timeout_seconds=30.0, check=False)
    return amule_command_summary(completed)


def terminate_process(process: subprocess.Popen | None) -> dict[str, object]:
    """Terminates a process that did not exit during graceful cleanup."""

    if process is None:
        return {"skipped": True}
    if process.poll() is not None:
        return {"already_exited": True, "return_code": process.returncode}
    process.terminate()
    try:
        process.wait(timeout=10.0)
        return {"terminated": True, "return_code": process.returncode}
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10.0)
        return {"killed": True, "return_code": process.returncode}


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
        workspace_root=args.workspace_root,
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
    amule_process: subprocess.Popen | None = None
    amule_profile: amule_harness.AmuleRuntimeProfile | None = None
    amule_control_exe: Path | None = None
    current_phase = "initializing"

    try:
        current_phase = "resolve_clients"
        harness_client = resolve_required_harness(paths, args)
        amule_client = resolve_required_amule(paths, args)
        amule_control_exe = amule_client.control_executable

        current_phase = "allocate_ports"
        emule_ports = local_kad.choose_local_kad_ports(2)
        used_ports = {port for triple in emule_ports for port in triple}
        amule_ports = choose_amule_ports(used_ports)
        specs = build_participant_specs(emule_ports, amule_ports)
        p2p_address = args.p2p_bind_interface_address or dtt.discover_interface_ipv4(args.p2p_bind_interface_name)
        all_specs = [specs["emulebb"], specs["harness"], specs["amule"]]
        report["network"] = {
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
            "rest_bind_addr": args.bind_addr,
            "participants": {key: asdict(value) for key, value in specs.items()},
            "client_inventory": {
                "harness": harness_client.as_report(),
                "amule": amule_client.as_report(),
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
            "harness": live_common.prepare_scenario_profile(
                profile_seed_dir,
                paths.source_artifacts_dir,
                [],
                CLIENT02.profile_id,
            ),
        }
        for key, profile in emule_profiles.items():
            spec = specs[key]
            app_exe = paths.app_exe if key == "emulebb" else harness_client.executable
            configured = local_kad.configure_kad_client_profile(
                config_dir=Path(profile["config_dir"]),
                app_exe=app_exe,
                spec=spec,
                api_key=args.api_key,
                rest_bind_addr=args.bind_addr,
                p2p_bind_interface_name=args.p2p_bind_interface_name,
                p2p_bind_addr=p2p_address,
            )
            if key == "harness":
                live_common.apply_emule_preferences(
                    Path(profile["config_dir"]),
                    (
                        ("Autoconnect", "1"),
                        ("Reconnect", "0"),
                    ),
                )
                configured["preferences"] = dtt.read_preferences_snapshot(Path(profile["config_dir"]))
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

        current_phase = "prepare_amule_profile"
        amule_profile = amule_harness.prepare_amule_profile(
            root_dir=paths.source_artifacts_dir / "profiles" / CLIENT04.profile_id,
            profile_id=CLIENT04.profile_id,
            nick=CLIENT04.nick,
            tcp_port=specs["amule"].tcp_port,
            udp_port=specs["amule"].udp_port,
            ec_port=amule_ports["ec"],
            advertised_address=p2p_address,
            connect_to_kad=True,
            connect_to_ed2k=False,
        )
        amule_preseed = local_kad.write_nodes_dat(
            amule_profile.config_dir / "nodes.dat",
            owner=specs["amule"],
            peers=all_specs,
            peer_address=p2p_address,
        )
        profile_reports[CLIENT04.profile_id] = {
            **amule_profile.as_report(),
            "nodes_dat_preseed": amule_preseed,
            "preferences": (amule_profile.config_dir / "amule.conf").read_text(encoding="utf-8"),
        }
        report["profiles"] = profile_reports

        current_phase = "launch_emule_family_clients"
        apps[CLIENT01.profile_id] = live_common.launch_app(
            paths.app_exe,
            Path(emule_profiles["emulebb"]["profile_base"]),
            minimized_to_tray=True,
        )
        apps[CLIENT02.profile_id] = live_common.launch_app(
            harness_client.executable,
            Path(emule_profiles["harness"]["profile_base"]),
            minimized_to_tray=True,
        )
        report["checks"][f"{CLIENT01.profile_id}_rest_ready"] = rest_smoke.compact_http_result(
            rest_smoke.wait_for_rest_ready(
                local_kad.base_url(args.bind_addr, specs["emulebb"]),
                args.api_key,
                args.rest_ready_timeout_seconds,
            )
        )
        report["checks"][f"{CLIENT02.profile_id}_startup_log_ready"] = wait_for_log_patterns(
            Path(emule_profiles["harness"]["profile_base"]) / "logs" / "eMule.log",
            ("eMule Version", "ready"),
            args.rest_ready_timeout_seconds,
            "tracing harness startup log readiness",
        )

        current_phase = "launch_amule"
        amule_process = amule_harness.start_amuled(amule_client.executable, amule_profile)
        report["checks"]["amule_ec_ready"] = amule_harness.wait_for_ec_ready(
            amule_client.control_executable,
            amule_profile,
            args.amule_ec_ready_timeout_seconds,
        )

        current_phase = "start_kad"
        report["checks"][f"{CLIENT01.profile_id}_kad_start"] = local_kad.start_kad(
            local_kad.base_url(args.bind_addr, specs["emulebb"]),
            args.api_key,
        )
        report["checks"][f"{CLIENT01.profile_id}_kad_running"] = rest_smoke.wait_for_kad_running(
            local_kad.base_url(args.bind_addr, specs["emulebb"]),
            args.api_key,
            args.kad_running_timeout_seconds,
        )
        report["checks"][f"{CLIENT02.profile_id}_kad_log_started"] = wait_for_log_patterns(
            Path(emule_profiles["harness"]["profile_base"]) / "logs" / "eMule.log",
            ("Connecting", "contacts from file."),
            args.kad_running_timeout_seconds,
            "tracing harness Kad startup from preseeded nodes.dat",
        )
        connect_kad = amule_harness.run_amulecmd(
            amule_client.control_executable,
            amule_profile,
            "Connect Kad",
            timeout_seconds=30.0,
            check=False,
        )
        report["checks"]["amule_connect_kad"] = amule_command_summary(connect_kad)
        report["checks"]["amule_kad_running"] = amule_harness.wait_for_kad_status(
            amule_client.control_executable,
            amule_profile,
            args.amule_kad_ready_timeout_seconds,
            require_connected=False,
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
                        local_kad.base_url(args.bind_addr, source),
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
            "single_bind_address_limit": "Kad accepts one contact per IP in this local single-address matrix; multi-contact assertions require per-client local IP aliases or adapters.",
            "tracing_harness_policy": "Kad autostarts from preferences and preseeded nodes.dat; no eMule BB JSON REST API is expected on the harness branch.",
            "amule_policy": "Kad must be running through EC; outbound paths are driven by nodes.dat preseed.",
        }
        report["checks"]["emule_family_swarm_ready"] = local_kad.wait_for_local_swarm(
            specs=[specs["emulebb"]],
            bind_addr=args.bind_addr,
            api_key=args.api_key,
            min_contacts_per_client=args.min_contacts_per_emule_client,
            require_connected=True,
            timeout_seconds=args.swarm_ready_timeout_seconds,
        )
        report["checks"]["final_kad_status"] = {
            CLIENT01.profile_id: local_kad.compact_local_kad_status(
                local_kad.get_kad_status(local_kad.base_url(args.bind_addr, specs["emulebb"]), args.api_key)
            ),
            CLIENT02.profile_id: local_kad.compact_local_kad_status(
                {
                    "running": True,
                    "connected": None,
                    "firewalled": None,
                    "contactCount": None,
                    "lanMode": True,
                    "source": "tracing harness log evidence",
                }
            ),
            CLIENT04.profile_id: amule_harness.parse_kad_status(
                amule_harness.run_amulecmd(
                    amule_client.control_executable,
                    amule_profile,
                    "Status",
                    timeout_seconds=15.0,
                    check=False,
                ).stdout
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
        try:
            cleanup["amule_shutdown"] = shutdown_amule(amule_control_exe, amule_profile)
        except Exception as exc:
            cleanup["amule_shutdown"] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        cleanup["amule_process"] = terminate_process(amule_process)
        for profile_id, app in apps.items():
            try:
                live_common.close_app_cleanly(app)
                cleanup[profile_id] = {"ok": True}
            except Exception as exc:
                cleanup[profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        report["cleanup"] = cleanup
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "local-kad-mixed-client-swarm.json", report)
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "result.json", report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
