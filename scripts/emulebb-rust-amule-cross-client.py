"""Bidirectional cross-client eD2K transfer between eMuleBB Rust and aMule."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import amule as amule_harness  # noqa: E402
from emule_test_harness import goed2k  # noqa: E402
from emule_test_harness import rust_client  # noqa: E402
from emule_test_harness import windows_vm_local_ed2k  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES, resolve_manifest_repo  # noqa: E402
from emule_test_harness.script_modules import load_script_module  # noqa: E402


rust_emulebb = load_script_module("emulebb_rust_emulebb_cross_client_for_amule", "emulebb-rust-emulebb-cross-client.py")
amule_seed = load_script_module("deterministic_amule_transfer_for_rust", "deterministic-amule-transfer.py")
dtt = rust_emulebb.dtt
harness_cli_common = rust_emulebb.harness_cli_common

SUITE_NAME = "emulebb-rust-amule-cross-client"
API_KEY = "emulebb-rust-amule-cross-client-key"
CLIENT_RUST = CLIENT_IDENTITIES["emulebb_rust"]
CLIENT_AMULE = CLIENT_IDENTITIES["amule"]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses the Rust/aMule cross-client suite arguments."""

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
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--transfer-completion-timeout-seconds", type=float, default=900.0)
    parser.add_argument("--fixture-size-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    parser.add_argument("--amule-daemon-exe")
    parser.add_argument("--amule-control-exe")
    return parser.parse_args(argv)


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
    """Writes suite-specific JSON reports for matrix callers."""

    harness_cli_common.write_json_file(paths.source_artifacts_dir / "emulebb-rust-amule-cross-client-result.json", report)


def main(argv: list[str] | None = None) -> int:
    """Runs the bidirectional Rust/aMule cross-client transfer scenario."""

    args = parse_args(argv)
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
    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "clients": [CLIENT_RUST.profile_id, CLIENT_AMULE.profile_id],
        "checks": {},
    }
    server_process: subprocess.Popen | None = None
    rust_process: subprocess.Popen[str] | None = None
    amule_process: subprocess.Popen | None = None
    amule_profile: amule_harness.AmuleRuntimeProfile | None = None
    amule_control_exe: Path | None = None
    current_phase = "initializing"

    try:
        amule_client = amule_seed.resolve_required_amule(paths, args)
        amule_daemon_exe = amule_client.executable
        amule_control_exe = amule_client.control_executable
        report["amule_inventory"] = amule_client.as_report()

        p2p_address = args.p2p_bind_interface_address or dtt.discover_interface_ipv4(args.p2p_bind_interface_name)
        ports = amule_seed.choose_amule_ports(dtt.choose_distinct_ports(args.lan_bind_addr), args.lan_bind_addr)
        used_ports = set(ports.values())
        rust_rest_port = rust_emulebb.choose_extra_port(args.lan_bind_addr, used_ports)
        rust_ed2k_port = rust_emulebb.choose_extra_port(args.lan_bind_addr, used_ports)
        rust_kad_port = rust_emulebb.choose_extra_port(args.lan_bind_addr, used_ports)
        server_endpoint = f"{p2p_address}:{ports['ed2k_tcp']}"
        report["network"] = {
            "lan_bind_addr": args.lan_bind_addr,
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
            "server_endpoint": server_endpoint,
            "ports": {**ports, "rust_rest": rust_rest_port, "rust_ed2k": rust_ed2k_port, "rust_kad": rust_kad_port},
        }

        rust_repo = resolve_manifest_repo(paths.workspace_root, "emulebb_rust")
        if not (rust_repo / "Cargo.toml").is_file():
            raise RuntimeError(f"emulebb-rust repo is missing Cargo.toml: {rust_repo}")

        server_dir = paths.source_artifacts_dir / "ed2k-server"
        current_phase = "start_ed2k_server"
        ed2k_server = goed2k.launch_ed2k_server(
            workspace_root=paths.workspace_root,
            server_dir=server_dir,
            ed2k_port=ports["ed2k_tcp"],
            admin_port=ports["ed2k_admin"],
            token=args.api_key,
            admin_address=args.lan_bind_addr,
            ed2k_address=p2p_address,
            repo_override=args.ed2k_server_repo,
            exe_override=args.ed2k_server_exe,
        )
        server_process = ed2k_server.process
        admin_base_url = ed2k_server.admin_base_url
        report["checks"]["server_build"] = ed2k_server.build
        report["checks"]["ed2k_server_health"] = ed2k_server.health
        report["ed2k_server"] = ed2k_server.config

        rust_runtime = paths.source_artifacts_dir / "rust-runtime"
        rust_config = paths.source_artifacts_dir / "rust.toml"
        rust_client.write_rust_config(
            rust_config,
            runtime_dir=rust_runtime,
            rest_addr=args.lan_bind_addr,
            rest_port=rust_rest_port,
            api_key=args.api_key,
            p2p_bind_ip=p2p_address,
            ed2k_port=rust_ed2k_port,
            kad_port=rust_kad_port,
            server_endpoint=server_endpoint,
        )
        current_phase = "launch_rust"
        rust_process = rust_client.start_rust_client(rust_repo, rust_config, paths.source_artifacts_dir / "rust.out")
        rust_base_url = f"http://{args.lan_bind_addr}:{rust_rest_port}"
        report["checks"]["rust_rest_ready"] = rust_emulebb.wait_for_rust_rest(
            rust_base_url,
            rust_process,
            paths.source_artifacts_dir / "rust.out",
            args.api_key,
            args.rest_ready_timeout_seconds,
        )
        report["checks"]["rust_connect"] = rust_emulebb.request_json(rust_base_url, "POST", "/api/v1/servers/operations/connect", args.api_key)
        report["checks"]["rust_ed2k_connected"] = rust_emulebb.wait_for_rust_ed2k_connected(
            rust_base_url,
            args.api_key,
            args.server_connect_timeout_seconds,
        )

        current_phase = "prepare_rust_seed"
        rust_fixture_path = paths.source_artifacts_dir / "rust-shared" / "emulebb-rust-to-amule.bin"
        rust_fixture_sha256 = dtt.write_fixture_file(rust_fixture_path, args.fixture_size_bytes)
        rust_shared = rust_emulebb.request_json(rust_base_url, "POST", "/api/v1/shared-files", args.api_key, {"path": str(rust_fixture_path)})
        rust_file = rust_shared["file"]
        rust_link = str(rust_file["ed2kLink"])
        rust_link_info = dtt.parse_ed2k_file_link(rust_link)
        rust_transfer_hash = str(rust_link_info["hash"])
        rust_link_with_source = windows_vm_local_ed2k.ed2k_link_with_source(
            rust_link,
            source_ip=p2p_address,
            source_port=rust_ed2k_port,
        )
        report["fixture"] = {
            "path": str(rust_fixture_path),
            "size": args.fixture_size_bytes,
            "sha256": rust_fixture_sha256,
            "link": rust_link_with_source,
        }
        report["checks"]["rust_shared_file"] = rust_file
        report["checks"]["rust_server_file"] = goed2k.wait_for_server_file(
            admin_base_url,
            args.api_key,
            rust_transfer_hash,
            args.server_publish_timeout_seconds,
        )

        current_phase = "prepare_amule_profile"
        amule_profile = amule_harness.prepare_amule_profile(
            root_dir=paths.source_artifacts_dir / "clients" / CLIENT_AMULE.profile_id,
            profile_id=CLIENT_AMULE.profile_id,
            nick=CLIENT_AMULE.nick,
            tcp_port=ports["amule_tcp"],
            udp_port=ports["amule_udp"],
            ec_port=ports["amule_ec"],
            ec_address=args.lan_bind_addr,
            advertised_address=p2p_address,
        )
        dtt.write_server_met(
            amule_profile.config_dir / "server.met",
            address=p2p_address,
            port=ports["ed2k_tcp"],
            name="emulebb-rust-amule-local-e2e",
        )
        amule_fixture_path = amule_profile.incoming_dir / "amule-to-emulebb-rust.bin"
        amule_fixture_sha256 = dtt.write_fixture_file(amule_fixture_path, args.fixture_size_bytes, seed=0xA0042026)
        report["amule_fixture"] = {
            "path": str(amule_fixture_path),
            "size": args.fixture_size_bytes,
            "sha256": amule_fixture_sha256,
        }
        report["profiles"] = {CLIENT_AMULE.profile_id: amule_profile.as_report()}

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
        amule_shared = amule_harness.wait_for_shared_file_hash(
            amule_control_exe,
            amule_profile,
            amule_fixture_path.name,
            args.link_export_timeout_seconds,
        )
        amule_link = amule_harness.build_file_link(amule_fixture_path.name, args.fixture_size_bytes, str(amule_shared["hash"]))
        amule_link_info = dtt.parse_ed2k_file_link(amule_link)
        amule_transfer_hash = str(amule_link_info["hash"])
        report["checks"]["amule_shared_file"] = {"link": amule_link, "parsed": amule_link_info, **amule_shared}

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
            amule_harness.run_amulecmd(amule_control_exe, amule_profile, "Connect ed2k", timeout_seconds=30.0)
        )
        report["checks"]["amule_server_client"] = goed2k.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT_AMULE.nick,
            args.server_connect_timeout_seconds,
        )
        report["checks"]["amule_server_file"] = goed2k.wait_for_server_file(
            admin_base_url,
            args.api_key,
            amule_transfer_hash,
            args.server_publish_timeout_seconds,
        )

        current_phase = "amule_downloads_from_rust"
        report["checks"]["amule_add_rust_download"] = amule_command_summary(
            amule_harness.run_amulecmd(amule_control_exe, amule_profile, f"Add {rust_link_with_source}", timeout_seconds=30.0)
        )
        report["checks"]["amule_completed_rust_file"] = amule_harness.wait_for_completed_file(
            amule_profile.incoming_dir / str(rust_link_info["name"]),
            expected_size=int(rust_link_info["size"]),
            expected_sha256=rust_fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
        )

        current_phase = "rust_downloads_from_amule"
        rust_reverse_search = rust_emulebb.wait_for_rust_search_result(
            rust_base_url,
            args.api_key,
            query="amule-to-emulebb-rust",
            transfer_hash=amule_transfer_hash,
            timeout_seconds=args.server_publish_timeout_seconds,
        )
        report["checks"]["rust_reverse_search"] = rust_reverse_search
        rust_search = rust_reverse_search["search"]
        report["checks"]["rust_reverse_download"] = rust_emulebb.request_json(
            rust_base_url,
            "POST",
            f"/api/v1/searches/{rust_search['id']}/results/{amule_transfer_hash}/operations/download",
            args.api_key,
            {"paused": False},
        )
        report["checks"]["rust_reverse_resume"] = rust_emulebb.request_json(
            rust_base_url,
            "POST",
            f"/api/v1/transfers/{amule_transfer_hash}/operations/resume",
            args.api_key,
        )
        report["checks"]["rust_completed_amule_file"] = rust_emulebb.wait_for_rust_transfer_completed(
            rust_base_url,
            args.api_key,
            amule_transfer_hash,
            rust_runtime,
            expected_size=int(amule_link_info["size"]),
            expected_sha256=amule_fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
        )
        report["checks"]["rust_amule_manifest_metadata"] = rust_emulebb.require_rust_download_manifest_metadata(
            rust_runtime,
            transfer_hash=amule_transfer_hash,
            expected_name=str(amule_link_info["name"]),
            expected_size=int(amule_link_info["size"]),
            require_aich_hashset=False,
        )
        report["checks"]["ed2k_server_stats_final"] = goed2k.admin_request(admin_base_url, args.api_key, "/api/stats")
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
            cleanup[CLIENT_AMULE.profile_id] = shutdown_amule(amule_control_exe, amule_profile)
        except Exception as exc:
            cleanup[CLIENT_AMULE.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        rust_client.stop_process_tree(rust_process)
        goed2k.stop_process(amule_process)
        goed2k.stop_process(server_process)
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
