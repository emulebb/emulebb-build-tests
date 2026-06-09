"""Local ED2K chaos proof for metadata corruption, locked files, and path churn."""

from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, replace
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.admin_volume_fixtures import (  # noqa: E402
    AdminVolumeFixture,
    AdminVolumeFixtureConfig,
    build_storage_topology,
    create_admin_volume_fixture,
)
from emule_test_harness.multi_client import CLIENT_IDENTITIES  # noqa: E402
from emule_test_harness.paths import reject_windows_temp_path  # noqa: E402


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


dtt = load_local_module("deterministic_two_client_transfer_local_chaos", "deterministic-two-client-transfer.py")
harness_cli_common = dtt.harness_cli_common
live_common = dtt.live_common
rest_smoke = dtt.rest_smoke

SUITE_NAME = "local-ed2k-chaos-mode"
API_KEY = "local-ed2k-chaos-mode-key"
CLIENT01 = CLIENT_IDENTITIES["emulebb"]
CLIENT02 = CLIENT_IDENTITIES["harness"]
CHAOS_DOWNLOAD_NAME = "local-ed2k-chaos-download.bin"
MIN_ADMIN_VHD_SIZE_MB = 6144
CORRUPT_CONFIG_FILES = (
    "server.met",
    "clients.met",
    "cancelled.met",
    "emfriends.met",
)


def build_parser() -> argparse.ArgumentParser:
    """Builds the local ED2K chaos-mode parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--client2-app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--p2p-bind-interface-name", default="")
    parser.add_argument("--p2p-bind-interface-address")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=240.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--transfer-completion-timeout-seconds", type=float, default=900.0)
    parser.add_argument("--fixture-size-bytes", type=int, default=dtt.DEFAULT_FIXTURE_SIZE_BYTES)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    parser.add_argument("--admin-volume-fixtures", action="store_true")
    parser.add_argument("--vhd-size-mb", type=int, default=MIN_ADMIN_VHD_SIZE_MB)
    parser.add_argument("--mount-root")
    parser.add_argument("--keep-admin-fixtures", action="store_true")
    return parser


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the optional VHD fixture used for path-churn chaos runs."""

    mount_parent = (
        Path(args.mount_root).resolve()
        if args.mount_root
        else paths.source_artifacts_dir.parent / "admin-mounts" / SUITE_NAME
    )
    reject_windows_temp_path(mount_parent, "local ED2K chaos admin fixture mount root")
    return AdminVolumeFixtureConfig(
        vhd_path=paths.source_artifacts_dir / "admin-volumes" / f"{SUITE_NAME}.vhdx",
        mount_root=mount_parent / SUITE_NAME,
        local_control_root=paths.source_artifacts_dir / "local-control-volume",
        size_mb=max(int(args.vhd_size_mb), MIN_ADMIN_VHD_SIZE_MB),
        keep=args.keep_admin_fixtures,
    )


def path_layout(paths, fixture: AdminVolumeFixture | None) -> dict[str, Path]:
    """Returns first-run and churned storage paths for the chaos client."""

    if fixture is None:
        root = paths.source_artifacts_dir / "client1-storage"
        return {
            "initial_temp": root / "initial-temp",
            "initial_incoming": root / "initial-incoming",
            "churned_temp": root / "churned-temp",
            "churned_incoming": root / "churned-incoming",
        }
    topology = build_storage_topology(fixture, SUITE_NAME)
    return {
        "initial_temp": topology.vhd_drive_root / "initial-temp",
        "initial_incoming": topology.vhd_mount_root / "initial-incoming",
        "churned_temp": topology.vhd_mount_root / "churned-temp",
        "churned_incoming": topology.vhd_drive_root / "churned-incoming",
    }


def ensure_storage_dirs(layout: dict[str, Path]) -> dict[str, str]:
    """Creates the chaos storage directories and returns their string paths."""

    for path in layout.values():
        path.mkdir(parents=True, exist_ok=True)
    return {name: str(path) for name, path in layout.items()}


def corrupt_config_metadata(config_dir: Path) -> list[dict[str, object]]:
    """Writes malformed metadata files before launch to prove startup tolerance."""

    rows: list[dict[str, object]] = []
    payload = b"\xE0\xFFcorrupt-local-ed2k-chaos\x00\x01"
    for name in CORRUPT_CONFIG_FILES:
        path = config_dir / name
        path.write_bytes(payload + name.encode("ascii", errors="ignore"))
        rows.append({"path": str(path), "size": path.stat().st_size})
    return rows


def write_stale_corrupt_part_metadata(temp_dir: Path) -> list[dict[str, object]]:
    """Writes stale malformed part metadata into the old temp path before restart."""

    temp_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for name, payload in (
        ("001.part.met", b"\xE0\x00stale-corrupt-part-met"),
        ("001.part.met.bak", b"\xE0\x00stale-corrupt-part-met-bak"),
    ):
        path = temp_dir / name
        path.write_bytes(payload)
        rows.append({"path": str(path), "size": path.stat().st_size})
    return rows


def apply_transfer_paths(config_dir: Path, *, incoming_dir: Path, temp_dir: Path) -> dict[str, str]:
    """Applies incoming and temp path preferences to an existing profile."""

    live_common.apply_emule_preferences(
        config_dir,
        (
            ("IncomingDir", live_common.win_path(incoming_dir, trailing_slash=True)),
            ("TempDir", live_common.win_path(temp_dir, trailing_slash=True)),
            ("TempDirs", live_common.win_path(temp_dir, trailing_slash=True)),
        ),
    )
    return {
        "incoming_dir": str(incoming_dir),
        "temp_dir": str(temp_dir),
    }


@contextmanager
def locked_probe_file(path: Path) -> Iterator[dict[str, object]]:
    """Holds a byte-range lock on a probe file for filesystem-contention coverage."""

    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("w+b")
    handle.write(b"local-ed2k-chaos-lock")
    handle.flush()
    locked = False
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        locked = True
    try:
        yield {"path": str(path), "locked": locked, "size": path.stat().st_size}
    finally:
        if locked:
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        handle.close()


def compact_http(result: dict[str, object]) -> dict[str, object]:
    """Returns bounded HTTP details for chaos-mode JSON reports."""

    return {
        "status": result.get("status"),
        "content_type": result.get("content_type"),
        "json": result.get("json"),
        "body_text": str(result.get("body_text", ""))[:1000],
    }


def add_paused_transfer(base_url: str, api_key: str, link: str, transfer_hash: str) -> dict[str, object]:
    """Queues one deterministic transfer in paused state through REST."""

    result = rest_smoke.http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={"link": link, "paused": True, "categoryId": 0},
        request_timeout_seconds=30.0,
    )
    item = rest_smoke.require_transfer_add_result(result, transfer_hash)
    return {"response": compact_http(result), "item": item}


def transfer_lookup(base_url: str, api_key: str, transfer_hash: str) -> dict[str, object]:
    """Looks up one transfer and returns compact REST diagnostics."""

    return compact_http(
        rest_smoke.http_request(
            base_url,
            f"/api/v1/transfers/{transfer_hash.lower()}",
            api_key=api_key,
            request_timeout_seconds=10.0,
        )
    )


def resume_transfer(base_url: str, api_key: str, transfer_hash: str) -> dict[str, object]:
    """Resumes one transfer through the REST operation endpoint."""

    result = rest_smoke.http_request(
        base_url,
        f"/api/v1/transfers/{transfer_hash.lower()}/operations/resume",
        method="POST",
        api_key=api_key,
        json_body={},
        request_timeout_seconds=30.0,
    )
    return {"response": compact_http(result), "ok": int(result.get("status", 0) or 0) == 200}


def add_or_resume_after_churn(base_url: str, api_key: str, link: str, transfer_hash: str) -> dict[str, object]:
    """Resumes a persisted transfer after path churn or re-adds it if it was discarded."""

    lookup = transfer_lookup(base_url, api_key, transfer_hash)
    if int(lookup.get("status", 0) or 0) == 200:
        resumed = resume_transfer(base_url, api_key, transfer_hash)
        if resumed["ok"]:
            return {"strategy": "resume-persisted-transfer", "lookup": lookup, "operation": resumed}
    add_result = dtt.add_transfer(base_url, api_key, link, transfer_hash)
    return {"strategy": "readd-after-path-churn", "lookup": lookup, "operation": add_result}


def run_local_ed2k_chaos(args: argparse.Namespace) -> dict[str, object]:
    """Runs local ED2K chaos coverage and writes JSON artifacts."""

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
    profile_seed_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "checks": {},
    }
    server_process: subprocess.Popen | None = None
    client1_app = None
    client2_app = None
    current_phase = "initializing"
    stack = ExitStack()

    try:
        fixture = None
        if args.admin_volume_fixtures:
            config = build_admin_fixture_config(paths, args)
            fixture = stack.enter_context(create_admin_volume_fixture(replace(config, keep=args.keep_admin_fixtures)))
            report["admin_volume_fixture"] = {
                "enabled": True,
                "vhd_path": str(config.vhd_path),
                "mount_root": str(config.mount_root),
                "size_mb": config.size_mb,
                "drive_identity": asdict(fixture.drive_identity),
                "mount_identity": asdict(fixture.mount_identity),
                "local_control_identity": asdict(fixture.local_control_identity),
            }
        else:
            report["admin_volume_fixture"] = {"enabled": False}
        storage = path_layout(paths, fixture)
        report["storage_layout"] = ensure_storage_dirs(storage)

        p2p_address = args.p2p_bind_interface_address or dtt.discover_interface_ipv4(args.p2p_bind_interface_name)
        ports = dtt.choose_distinct_ports()
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

        fixture_file = paths.source_artifacts_dir / "client2-shared" / CHAOS_DOWNLOAD_NAME
        fixture_sha256 = dtt.write_fixture_file(fixture_file, args.fixture_size_bytes)
        report["fixture"] = {
            "path": str(fixture_file),
            "name": fixture_file.name,
            "size": args.fixture_size_bytes,
            "sha256": fixture_sha256,
        }

        current_phase = "prepare_profiles"
        client1 = live_common.prepare_scenario_profile(
            profile_seed_dir,
            paths.source_artifacts_dir,
            [],
            CLIENT01.profile_id,
            incoming_dir=storage["initial_incoming"],
            temp_dir=storage["initial_temp"],
        )
        client2 = live_common.prepare_scenario_profile(profile_seed_dir, paths.source_artifacts_dir, [], CLIENT02.profile_id)
        client2_app_exe = dtt.resolve_client2_app_exe(paths.workspace_root, args.configuration, args.client2_app_exe)
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
        dtt.configure_client_profile(
            config_dir=Path(client2["config_dir"]),
            app_exe=client2_app_exe,
            nick=CLIENT02.nick,
            tcp_port=ports["client2_tcp"],
            udp_port=ports["client2_udp"],
            ed2k_enabled=True,
            autoconnect=True,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
        )
        dtt.write_server_met(
            Path(client2["config_dir"]) / "server.met",
            address=p2p_address,
            port=ports["ed2k_tcp"],
            name="emulebb-local-e2e",
        )
        report["checks"]["corrupt_startup_metadata"] = corrupt_config_metadata(Path(client1["config_dir"]))

        harness_export_dir = paths.source_artifacts_dir / "client2-export"
        harness_export_dir.mkdir(parents=True, exist_ok=True)
        harness_ready_path = harness_export_dir / "ready.txt"
        harness_export_link_path = harness_export_dir / "fixture.ed2k.txt"
        current_phase = "launch_harness_seed"
        client2_app = live_common.launch_app(
            client2_app_exe,
            Path(client2["profile_base"]),
            minimized_to_tray=True,
            extra_args=dtt.build_client2_harness_args(
                ready_path=harness_ready_path,
                fixture_file=fixture_file,
                export_link_path=harness_export_link_path,
                source_ip=p2p_address,
            ),
        )
        report["checks"]["harness_ready"] = dtt.wait_for_file(harness_ready_path, 90.0, "tracing harness ready file")
        exported_link = dtt.wait_for_exported_link(harness_export_link_path, args.link_export_timeout_seconds)
        link_info = dtt.parse_ed2k_file_link(exported_link)
        transfer_hash = str(link_info["hash"])
        report["checks"]["harness_exported_link"] = {"path": str(harness_export_link_path), "link": exported_link, "parsed": link_info}
        report["checks"]["harness_server_client"] = dtt.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT02.nick,
            args.server_connect_timeout_seconds,
        )
        report["checks"]["harness_server_file"] = dtt.wait_for_server_file(
            admin_base_url,
            args.api_key,
            transfer_hash,
            args.server_publish_timeout_seconds,
        )

        temp_lock = stack.enter_context(locked_probe_file(storage["initial_temp"] / "locked-temp-probe.bin"))
        report["checks"]["locked_probe_files"] = {"temp_before_startup": temp_lock}

        current_phase = "launch_emulebb_with_corrupt_metadata"
        client1_app = live_common.launch_app(paths.app_exe, Path(client1["profile_base"]), minimized_to_tray=True)
        base_url = f"http://{args.lan_bind_addr}:{ports['client1_rest']}"
        report["checks"]["initial_rest_ready"] = compact_http(
            rest_smoke.wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        )
        incoming_lock = stack.enter_context(locked_probe_file(storage["initial_incoming"] / "locked-incoming-probe.bin"))
        report["checks"]["locked_probe_files"]["incoming_after_startup"] = incoming_lock
        report["checks"]["initial_server_connect_after_corrupt_server_met"] = dtt.add_and_connect_server(
            base_url,
            args.api_key,
            address=p2p_address,
            port=ports["ed2k_tcp"],
            timeout_seconds=args.server_connect_timeout_seconds,
        )
        report["checks"]["initial_server_client"] = dtt.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT01.nick,
            args.server_connect_timeout_seconds,
        )

        current_phase = "queue_paused_transfer_before_path_churn"
        report["checks"]["paused_transfer_add"] = add_paused_transfer(base_url, args.api_key, exported_link, transfer_hash)
        report["checks"]["paused_transfer_lookup"] = transfer_lookup(base_url, args.api_key, transfer_hash)
        report["checks"]["initial_shutdown_before_path_churn"] = rest_smoke.close_app_cleanly_with_timing(client1_app)
        client1_app = None

        current_phase = "path_churn_restart"
        report["checks"]["stale_corrupt_part_metadata"] = write_stale_corrupt_part_metadata(storage["initial_temp"])
        report["checks"]["churned_transfer_paths"] = apply_transfer_paths(
            Path(client1["config_dir"]),
            incoming_dir=storage["churned_incoming"],
            temp_dir=storage["churned_temp"],
        )
        client1_app = live_common.launch_app(paths.app_exe, Path(client1["profile_base"]), minimized_to_tray=True)
        report["checks"]["restart_rest_ready"] = compact_http(
            rest_smoke.wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        )
        report["checks"]["restart_server_connect"] = dtt.add_and_connect_server(
            base_url,
            args.api_key,
            address=p2p_address,
            port=ports["ed2k_tcp"],
            timeout_seconds=args.server_connect_timeout_seconds,
        )
        report["checks"]["restart_add_or_resume"] = add_or_resume_after_churn(base_url, args.api_key, exported_link, transfer_hash)
        completed_path = storage["churned_incoming"] / CHAOS_DOWNLOAD_NAME
        report["checks"]["download_completion_after_chaos"] = dtt.wait_for_completed_file(
            completed_path,
            expected_size=int(link_info["size"]),
            expected_sha256=fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
            snapshot_callback=lambda: dtt.collect_client1_transfer_snapshot(
                base_url=base_url,
                api_key=args.api_key,
                transfer_hash=transfer_hash,
                incoming_path=completed_path,
                temp_dir=storage["churned_temp"],
                hash_limit_bytes=max(int(link_info["size"]), args.fixture_size_bytes),
            ),
        )
        report["checks"]["final_transfer_lookup"] = transfer_lookup(base_url, args.api_key, transfer_hash)
        report["checks"]["ed2k_server_stats_final"] = dtt.admin_request(admin_base_url, args.api_key, "/api/stats")
        report["profiles"] = {
            CLIENT01.profile_id: {
                "profile_base": str(client1["profile_base"]),
                "config_dir": str(client1["config_dir"]),
                "preferences": dtt.read_preferences_snapshot(Path(client1["config_dir"])),
            },
            CLIENT02.profile_id: {
                "profile_base": str(client2["profile_base"]),
                "config_dir": str(client2["config_dir"]),
                "preferences": dtt.read_preferences_snapshot(Path(client2["config_dir"])),
            },
        }
        report["status"] = "passed"
    except Exception as exc:
        report["status"] = "failed"
        report["current_phase"] = current_phase
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        if isinstance(exc, dtt.TransferCompletionTimeout):
            report["checks"]["download_completion_timeout"] = {"observations": exc.observations}
    finally:
        cleanup: dict[str, object] = {}
        for identity, app in ((CLIENT01, client1_app), (CLIENT02, client2_app)):
            if app is None:
                continue
            try:
                live_common.close_app_cleanly(app)
                cleanup[identity.profile_id] = {"ok": True}
            except Exception as exc:
                cleanup[identity.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        try:
            stack.close()
        except Exception as exc:
            cleanup["exit_stack"] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        dtt.stop_process(server_process)
        report["cleanup"] = cleanup
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        report_path = paths.source_artifacts_dir / "local-ed2k-chaos-mode-result.json"
        harness_cli_common.write_json_file(report_path, report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)
    return report


def main() -> int:
    """Runs the local ED2K chaos-mode suite."""

    summary = run_local_ed2k_chaos(build_parser().parse_args())
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
