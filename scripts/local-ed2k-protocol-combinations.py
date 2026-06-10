"""Local ED2K protocol-combination transfer matrix through the workspace server."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, asdict
import hashlib
import importlib.util
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import goed2k  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES  # noqa: E402


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


dtt = load_local_module("deterministic_two_client_transfer_protocol_matrix", "deterministic-two-client-transfer.py")
harness_cli_common = dtt.harness_cli_common
live_common = dtt.live_common
rest_smoke = dtt.rest_smoke

SUITE_NAME = "local-ed2k-protocol-combinations"
API_KEY = "local-ed2k-protocol-combinations-key"
CLIENT01 = CLIENT_IDENTITIES["emulebb"]
CLIENT02 = CLIENT_IDENTITIES["harness"]
PROTOCOL_PADDING_LENGTH = 128


@dataclass(frozen=True)
class ProtocolCase:
    """One local ED2K protocol surface covered by the live matrix."""

    name: str
    artifact_id: str
    server_protocol_obfuscation: bool
    server_udp: bool
    client_crypt_supported: bool
    client_crypt_requested: bool
    client_crypt_required: bool
    fixture_pattern: str = "low-compressibility"


PROTOCOL_CASES = (
    ProtocolCase(
        name="plain-server-plain-clients",
        artifact_id="plain",
        server_protocol_obfuscation=False,
        server_udp=True,
        client_crypt_supported=False,
        client_crypt_requested=False,
        client_crypt_required=False,
    ),
    ProtocolCase(
        name="obfuscated-preferred",
        artifact_id="obf-pref",
        server_protocol_obfuscation=True,
        server_udp=True,
        client_crypt_supported=True,
        client_crypt_requested=True,
        client_crypt_required=False,
    ),
    ProtocolCase(
        name="obfuscated-required",
        artifact_id="obf-req",
        server_protocol_obfuscation=True,
        server_udp=True,
        client_crypt_supported=True,
        client_crypt_requested=True,
        client_crypt_required=True,
    ),
    ProtocolCase(
        name="obfuscated-required-no-server-udp-compressible",
        artifact_id="obf-req-no-udp-z",
        server_protocol_obfuscation=True,
        server_udp=False,
        client_crypt_supported=True,
        client_crypt_requested=True,
        client_crypt_required=True,
        fixture_pattern="compressible",
    ),
)
PROTOCOL_CASE_MAP = {case.name: case for case in PROTOCOL_CASES}


def build_parser() -> argparse.ArgumentParser:
    """Builds the standalone protocol-combination matrix parser."""

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
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--transfer-completion-timeout-seconds", type=float, default=900.0)
    parser.add_argument("--fixture-size-bytes", type=int, default=dtt.DEFAULT_FIXTURE_SIZE_BYTES)
    parser.add_argument("--case", action="append", choices=tuple(PROTOCOL_CASE_MAP.keys()))
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses standalone protocol-combination matrix arguments."""

    return build_parser().parse_args(argv)


def selected_cases(names: list[str] | None) -> list[ProtocolCase]:
    """Returns requested protocol cases in stable matrix order."""

    if not names:
        return list(PROTOCOL_CASES)
    wanted = set(names)
    return [case for case in PROTOCOL_CASES if case.name in wanted]


def bool_pref(value: bool) -> str:
    """Converts a boolean to an eMule integer preference string."""

    return "1" if value else "0"


def apply_protocol_preferences(config_dir: Path, case: ProtocolCase) -> dict[str, object]:
    """Applies protocol-obfuscation preferences shared by eMuleBB and the tracing harness."""

    live_common.apply_emule_preferences(
        config_dir,
        (
            ("CryptLayerSupported", bool_pref(case.client_crypt_supported)),
            ("CryptLayerRequested", bool_pref(case.client_crypt_requested)),
            ("CryptLayerRequired", bool_pref(case.client_crypt_required)),
            ("CryptTCPPaddingLength", str(PROTOCOL_PADDING_LENGTH)),
        ),
    )
    return {
        "CryptLayerSupported": bool_pref(case.client_crypt_supported),
        "CryptLayerRequested": bool_pref(case.client_crypt_requested),
        "CryptLayerRequired": bool_pref(case.client_crypt_required),
        "CryptTCPPaddingLength": str(PROTOCOL_PADDING_LENGTH),
    }


def write_protocol_fixture_file(path: Path, size_bytes: int, pattern: str) -> str:
    """Writes the case fixture and returns its SHA-256 proof hash."""

    if pattern == "low-compressibility":
        return dtt.write_fixture_file(path, size_bytes)
    if pattern != "compressible":
        raise ValueError(f"Unsupported protocol fixture pattern: {pattern!r}")
    if size_bytes <= 0:
        raise ValueError("Fixture size must be greater than zero.")
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    block = (b"emulebb-local-ed2k-compressible-fixture\n" * 2048)[:64 * 1024]
    remaining = size_bytes
    with path.open("wb") as handle:
        while remaining > 0:
            chunk = block[: min(len(block), remaining)]
            handle.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def protocol_surface(case: ProtocolCase) -> dict[str, object]:
    """Returns the explicit protocol surface covered by one matrix case."""

    surface = asdict(case)
    surface["client_data_compression"] = {
        "mode": "stock-auto-negotiated",
        "preference_toggle": False,
        "evidence": (
            "eMule advertises data compression capability during client hello; "
            "the matrix varies fixture compressibility because no stock profile toggle exists."
        ),
    }
    return surface


def run_protocol_case(
    *,
    case: ProtocolCase,
    args: argparse.Namespace,
    paths,
    profile_seed_dir: Path,
    p2p_address: str,
    ed2k_exe: Path,
    client2_app_exe: Path,
) -> dict[str, object]:
    """Runs one deterministic transfer under a concrete local ED2K protocol configuration."""

    case_dir = paths.source_artifacts_dir / case.artifact_id
    report: dict[str, object] = {
        "name": case.name,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "protocol_surface": protocol_surface(case),
        "checks": {},
    }
    server_process: subprocess.Popen | None = None
    client1_app = None
    client2_app = None
    current_phase = "initializing"

    try:
        ports = dtt.choose_distinct_ports()
        report["network"] = {
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
            "ports": ports,
        }

        server_dir = case_dir / "ed2k-server"
        current_phase = "start_ed2k_server"
        ed2k_server = goed2k.launch_ed2k_server(
            workspace_root=paths.workspace_root,
            server_dir=server_dir,
            ed2k_port=ports["ed2k_tcp"],
            admin_port=ports["ed2k_admin"],
            token=args.api_key,
            admin_address=args.lan_bind_addr,
            exe_override=str(ed2k_exe),
            protocol_obfuscation=case.server_protocol_obfuscation,
            server_udp=case.server_udp,
        )
        server_process = ed2k_server.process
        admin_base_url = ed2k_server.admin_base_url
        report["checks"]["ed2k_server_health"] = ed2k_server.health
        report["ed2k_server"] = ed2k_server.config

        fixture_file = case_dir / "client2-shared" / f"{case.artifact_id}.bin"
        fixture_sha256 = write_protocol_fixture_file(fixture_file, args.fixture_size_bytes, case.fixture_pattern)
        report["fixture"] = {
            "path": str(fixture_file),
            "name": fixture_file.name,
            "size": args.fixture_size_bytes,
            "sha256": fixture_sha256,
            "pattern": case.fixture_pattern,
        }

        current_phase = "prepare_profiles"
        client1 = live_common.prepare_scenario_profile(profile_seed_dir, case_dir, [], CLIENT01.profile_id)
        client2 = live_common.prepare_scenario_profile(profile_seed_dir, case_dir, [], CLIENT02.profile_id)
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
        report["checks"]["client1_protocol_preferences"] = apply_protocol_preferences(Path(client1["config_dir"]), case)
        report["checks"]["client2_protocol_preferences"] = apply_protocol_preferences(Path(client2["config_dir"]), case)
        for profile in (client1, client2):
            dtt.write_server_met(
                Path(profile["config_dir"]) / "server.met",
                address=p2p_address,
                port=ports["ed2k_tcp"],
                name="emulebb-local-e2e",
            )

        report["profiles"] = {
            CLIENT01.profile_id: {
                "client_key": CLIENT01.key,
                "nick": CLIENT01.nick,
                "profile_base": str(client1["profile_base"]),
                "config_dir": str(client1["config_dir"]),
                "incoming_dir": str(client1["incoming_dir"]),
                "temp_dir": str(client1["temp_dir"]),
                "preferences": dtt.read_preferences_snapshot(Path(client1["config_dir"])),
            },
            CLIENT02.profile_id: {
                "client_key": CLIENT02.key,
                "nick": CLIENT02.nick,
                "profile_base": str(client2["profile_base"]),
                "config_dir": str(client2["config_dir"]),
                "incoming_dir": str(client2["incoming_dir"]),
                "temp_dir": str(client2["temp_dir"]),
                "app_exe": str(client2_app_exe),
                "preferences": dtt.read_preferences_snapshot(Path(client2["config_dir"])),
            },
        }

        export_dir = case_dir / "client2-export"
        export_dir.mkdir(parents=True, exist_ok=True)
        ready_path = export_dir / "ready.txt"
        export_link_path = export_dir / "fixture.ed2k.txt"
        current_phase = "launch_client2"
        client2_app = live_common.launch_app(
            client2_app_exe,
            Path(client2["profile_base"]),
            minimized_to_tray=True,
            extra_args=dtt.build_client2_harness_args(
                ready_path=ready_path,
                fixture_file=fixture_file,
                export_link_path=export_link_path,
                source_ip=p2p_address,
            ),
        )
        report["checks"]["client2_ready"] = dtt.wait_for_file(ready_path, 90.0, "tracing harness ready file")
        exported_link = dtt.wait_for_exported_link(export_link_path, args.link_export_timeout_seconds)
        link_info = dtt.parse_ed2k_file_link(exported_link)
        transfer_hash = str(link_info["hash"])
        report["checks"]["client2_exported_link"] = {"path": str(export_link_path), "link": exported_link, "parsed": link_info}
        report["checks"]["client2_server_client"] = goed2k.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT02.nick,
            args.server_connect_timeout_seconds,
        )
        report["checks"]["client2_server_file"] = goed2k.wait_for_server_file(
            admin_base_url,
            args.api_key,
            transfer_hash,
            args.server_publish_timeout_seconds,
        )

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
        report["checks"]["client1_server_client"] = goed2k.wait_for_server_client(
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
        report["checks"]["ed2k_server_stats_final"] = goed2k.admin_request(admin_base_url, args.api_key, "/api/stats")
        report["status"] = "passed"
    except Exception as exc:
        report["status"] = "failed"
        report["current_phase"] = current_phase
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        if isinstance(exc, dtt.TransferCompletionTimeout):
            report["checks"]["client1_transfer_completion_timeout"] = {"observations": exc.observations}
    finally:
        close_results: dict[str, object] = {}
        for name, app in ((CLIENT01.profile_id, client1_app), (CLIENT02.profile_id, client2_app)):
            if app is None:
                continue
            try:
                live_common.close_app_cleanly(app)
                close_results[name] = {"ok": True}
            except Exception as exc:
                close_results[name] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        goed2k.stop_process(server_process)
        report["cleanup"] = close_results
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    return report


def main(argv: list[str] | None = None) -> int:
    """Runs all requested protocol-combination transfer cases."""

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
    profile_seed_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "checks": {},
        "cases": [],
    }

    try:
        p2p_address = args.p2p_bind_interface_address or dtt.discover_interface_ipv4(args.p2p_bind_interface_name)
        report["network"] = {
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
        }
        ed2k_binary = goed2k.prepare_ed2k_server_binary(
            paths.workspace_root,
            repo_override=args.ed2k_server_repo,
            exe_override=args.ed2k_server_exe,
        )
        report["checks"]["server_build"] = ed2k_binary.build
        client2_app_exe = dtt.resolve_client2_app_exe(paths.workspace_root, args.configuration, args.client2_app_exe)

        for case in selected_cases(args.case):
            case_report = run_protocol_case(
                case=case,
                args=args,
                paths=paths,
                profile_seed_dir=profile_seed_dir,
                p2p_address=p2p_address,
                ed2k_exe=ed2k_binary.server_exe,
                client2_app_exe=client2_app_exe,
            )
            report["cases"].append(case_report)
            if case_report["status"] != "passed":
                raise RuntimeError(f"Protocol case {case.name!r} failed.")
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        return 1
    finally:
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        report_path = paths.source_artifacts_dir / "local-ed2k-protocol-combinations-result.json"
        harness_cli_common.write_json_file(report_path, report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
