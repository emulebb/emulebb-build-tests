"""Deterministic eMuleBB download from a headless aMule seed client."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import amule as amule_harness  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES, resolve_amule_client  # noqa: E402


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


dtt = load_local_module("deterministic_two_client_transfer_amule_seed", "deterministic-two-client-transfer.py")
harness_cli_common = dtt.harness_cli_common
live_common = dtt.live_common
rest_smoke = dtt.rest_smoke

SUITE_NAME = "deterministic-amule-transfer"
API_KEY = "deterministic-amule-transfer-key"
CLIENT01 = CLIENT_IDENTITIES["emulebb"]
CLIENT04 = CLIENT_IDENTITIES["amule"]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses the standalone deterministic aMule transfer arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root")
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
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--transfer-completion-timeout-seconds", type=float, default=900.0)
    parser.add_argument("--fixture-size-bytes", type=int, default=dtt.DEFAULT_FIXTURE_SIZE_BYTES)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    parser.add_argument("--amule-daemon-exe")
    parser.add_argument("--amule-control-exe")
    return parser.parse_args(argv)


def choose_amule_ports(base_ports: dict[str, int], lan_bind_addr: str | None = None) -> dict[str, int]:
    """Extends the common deterministic-transfer port allocation with aMule ports."""

    ports = dict(base_ports)
    used = set(ports.values())
    for name in ("amule_tcp", "amule_udp", "amule_ec"):
        udp = name.endswith("_udp")
        for _ in range(100):
            candidate = rest_smoke.choose_listen_port(lan_bind_addr)
            if candidate not in used and dtt.is_port_available(candidate, udp=udp):
                ports[name] = candidate
                used.add(candidate)
                break
        else:
            raise RuntimeError(f"Could not allocate port for {name}.")
    return ports


def resolve_required_amule(paths, args: argparse.Namespace):
    """Resolves the staged aMule daemon/control pair or raises an actionable error."""

    availability = resolve_amule_client(paths.workspace_root, args.amule_daemon_exe, args.amule_control_exe)
    if not availability.available or availability.executable is None or availability.control_executable is None:
        raise RuntimeError(f"aMule is unavailable for deterministic E2E: {availability.reason}")
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


def write_reports(paths, report: dict[str, object]) -> None:
    """Writes suite-specific and generic JSON reports for matrix callers."""

    harness_cli_common.write_json_file(paths.source_artifacts_dir / "deterministic-amule-transfer-result.json", report)


def main(argv: list[str] | None = None) -> int:
    """Runs the deterministic eMuleBB versus aMule transfer suite."""

    args = parse_args(argv)
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
    profile_seed_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "checks": {},
    }
    server_process: subprocess.Popen | None = None
    amule_process: subprocess.Popen | None = None
    client1_app = None
    amule_profile: amule_harness.AmuleRuntimeProfile | None = None
    amule_control_exe: Path | None = None
    current_phase = "initializing"

    try:
        amule_client = resolve_required_amule(paths, args)
        amule_daemon_exe = amule_client.executable
        amule_control_exe = amule_client.control_executable
        report["amule_inventory"] = amule_client.as_report()

        p2p_address = args.p2p_bind_interface_address or dtt.discover_interface_ipv4(args.p2p_bind_interface_name)
        ports = choose_amule_ports(dtt.choose_distinct_ports())
        report["network"] = {
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
            "ports": ports,
        }

        ed2k_repo = dtt.resolve_ed2k_server_repo(paths.workspace_root, args.ed2k_server_repo)
        ed2k_exe = dtt.resolve_ed2k_server_exe(paths.workspace_root, args.ed2k_server_exe)
        report["checks"]["server_build"] = dtt.build_ed2k_server_binary(ed2k_repo, ed2k_exe)

        server_dir = paths.source_artifacts_dir / "ed2k-server"
        catalog_path = server_dir / "catalog.json"
        config_path = server_dir / "config.json"
        dtt.write_empty_catalog(catalog_path)
        report["ed2k_server"] = dtt.build_server_config(
            config_path,
            ed2k_port=ports["ed2k_tcp"],
            admin_port=ports["ed2k_admin"],
            catalog_path=catalog_path,
            token=args.api_key,
            admin_address=args.lan_bind_addr,
        )
        current_phase = "start_ed2k_server"
        server_process = dtt.start_ed2k_server(ed2k_exe, config_path, server_dir / "server.log")
        admin_base_url = f"http://{args.lan_bind_addr}:{ports['ed2k_admin']}"
        report["checks"]["ed2k_server_health"] = dtt.wait_for_admin_health(admin_base_url, 30.0)

        current_phase = "prepare_amule_profile"
        amule_profile = amule_harness.prepare_amule_profile(
            root_dir=paths.source_artifacts_dir / "clients" / CLIENT04.profile_id,
            profile_id=CLIENT04.profile_id,
            nick=CLIENT04.nick,
            tcp_port=ports["amule_tcp"],
            udp_port=ports["amule_udp"],
            ec_port=ports["amule_ec"],
            advertised_address=p2p_address,
        )
        dtt.write_server_met(
            amule_profile.config_dir / "server.met",
            address=p2p_address,
            port=ports["ed2k_tcp"],
            name="emulebb-local-e2e",
        )
        fixture_file = amule_profile.incoming_dir / "deterministic-amule-transfer.bin"
        fixture_sha256 = dtt.write_fixture_file(fixture_file, args.fixture_size_bytes)
        report["fixture"] = {
            "path": str(fixture_file),
            "name": fixture_file.name,
            "size": args.fixture_size_bytes,
            "sha256": fixture_sha256,
        }
        report["profiles"] = {CLIENT04.profile_id: amule_profile.as_report()}

        current_phase = "launch_amule"
        amule_process = amule_harness.start_amuled(amule_daemon_exe, amule_profile)
        report["checks"]["amule_ec_ready"] = amule_harness.wait_for_ec_ready(
            amule_control_exe,
            amule_profile,
            args.rest_ready_timeout_seconds,
        )
        report["checks"]["amule_reload_shared"] = amule_command_summary(
            amule_harness.run_amulecmd(amule_control_exe, amule_profile, "Reload Shared", timeout_seconds=30.0)
        )
        shared = amule_harness.wait_for_shared_file_hash(
            amule_control_exe,
            amule_profile,
            fixture_file.name,
            args.link_export_timeout_seconds,
        )
        exported_link = amule_harness.build_file_link(fixture_file.name, args.fixture_size_bytes, str(shared["hash"]))
        link_info = dtt.parse_ed2k_file_link(exported_link)
        transfer_hash = str(link_info["hash"])
        report["checks"]["amule_shared_file"] = {"link": exported_link, "parsed": link_info, **shared}

        current_phase = "amule_server_connect"
        report["checks"]["amule_add_server"] = amule_command_summary(
            amule_harness.run_amulecmd(
                amule_control_exe,
                amule_profile,
                f"Add {amule_harness.build_server_link(p2p_address, ports['ed2k_tcp'])}",
                timeout_seconds=30.0,
            )
        )
        report["checks"]["amule_connect_server"] = amule_command_summary(
            amule_harness.run_amulecmd(
                amule_control_exe,
                amule_profile,
                "Connect ed2k",
                timeout_seconds=30.0,
            )
        )
        report["checks"]["amule_server_client"] = dtt.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT04.nick,
            args.server_connect_timeout_seconds,
        )
        report["checks"]["amule_server_file"] = dtt.wait_for_server_file(
            admin_base_url,
            args.api_key,
            transfer_hash,
            args.server_publish_timeout_seconds,
        )

        current_phase = "prepare_client1"
        client1 = live_common.prepare_scenario_profile(
            profile_seed_dir,
            paths.source_artifacts_dir,
            [],
            CLIENT01.profile_id,
        )
        dtt.configure_client_profile(
            config_dir=Path(client1["config_dir"]),
            app_exe=paths.app_exe,
            nick=CLIENT01.nick,
            tcp_port=ports["client1_tcp"],
            udp_port=ports["client1_udp"],
            ed2k_enabled=True,
            autoconnect=False,
            rest_api_key=args.api_key,
            rest_port=ports["client1_rest"],
            lan_bind_addr=args.lan_bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
        )
        dtt.write_server_met(
            Path(client1["config_dir"]) / "server.met",
            address=p2p_address,
            port=ports["ed2k_tcp"],
            name="emulebb-local-e2e",
        )
        report["profiles"][CLIENT01.profile_id] = {
            "client_key": CLIENT01.key,
            "nick": CLIENT01.nick,
            "profile_base": str(client1["profile_base"]),
            "config_dir": str(client1["config_dir"]),
            "incoming_dir": str(client1["incoming_dir"]),
            "temp_dir": str(client1["temp_dir"]),
            "preferences": dtt.read_preferences_snapshot(Path(client1["config_dir"])),
        }

        current_phase = "launch_client1"
        client1_app = live_common.launch_app(paths.app_exe, Path(client1["profile_base"]), minimized_to_tray=True)
        base_url = f"http://{args.lan_bind_addr}:{ports['client1_rest']}"
        report["checks"]["client1_rest_ready"] = rest_smoke.compact_http_result(
            rest_smoke.wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        )
        current_phase = "client1_server_connect"
        report["checks"]["client1_server_connect"] = dtt.add_and_connect_server(
            base_url,
            args.api_key,
            address=p2p_address,
            port=ports["ed2k_tcp"],
            timeout_seconds=args.server_connect_timeout_seconds,
        )
        report["checks"]["client1_server_client"] = dtt.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT01.nick,
            args.server_connect_timeout_seconds,
        )

        current_phase = "add_transfer"
        report["checks"]["client1_transfer_add"] = dtt.add_transfer(base_url, args.api_key, exported_link, transfer_hash)
        completed_path = Path(client1["incoming_dir"]) / str(link_info["name"])
        report["checks"]["client1_transfer_completed_file"] = dtt.wait_for_completed_file(
            completed_path,
            expected_size=int(link_info["size"]),
            expected_sha256=fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
            snapshot_callback=lambda: dtt.collect_client1_transfer_snapshot(
                base_url=base_url,
                api_key=args.api_key,
                transfer_hash=transfer_hash,
                incoming_path=completed_path,
                temp_dir=Path(client1["temp_dir"]),
                hash_limit_bytes=max(int(link_info["size"]), args.fixture_size_bytes),
            ),
        )
        final_transfer = rest_smoke.http_request(base_url, f"/api/v1/transfers/{transfer_hash}", api_key=args.api_key)
        report["checks"]["client1_transfer_final_rest"] = dtt.compact_transfer_http(final_transfer)
        report["checks"]["ed2k_server_stats_final"] = dtt.admin_request(admin_base_url, args.api_key, "/api/stats")
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["current_phase"] = current_phase
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        if isinstance(exc, dtt.TransferCompletionTimeout):
            report["checks"]["client1_transfer_completion_timeout"] = {"observations": exc.observations}
        return 1
    finally:
        cleanup: dict[str, object] = {}
        if client1_app is not None:
            try:
                live_common.close_app_cleanly(client1_app)
                cleanup[CLIENT01.profile_id] = {"ok": True}
            except Exception as exc:
                cleanup[CLIENT01.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        try:
            cleanup[CLIENT04.profile_id] = shutdown_amule(amule_control_exe, amule_profile)
        except Exception as exc:
            cleanup[CLIENT04.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        dtt.stop_process(amule_process)
        dtt.stop_process(server_process)
        report["cleanup"] = cleanup
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        write_reports(paths, report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
