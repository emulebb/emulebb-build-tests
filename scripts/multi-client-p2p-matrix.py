"""Windows-only multi-client P2P matrix for deterministic local E2E coverage."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.multi_client import (  # noqa: E402
    CLIENT_IDENTITIES,
    resolve_windows_client_inventory,
    workspace_parent_root,
)
from emule_test_harness import goed2k  # noqa: E402
from emule_test_harness.script_modules import load_script_module  # noqa: E402

SUITE_NAME = "multi-client-p2p-matrix"
API_KEY = "multi-client-p2p-matrix-key"
HARNESS_TRANSFER_SCENARIO_ID = "cl-emulebb-001-downloads-from-cl-harness-002"
RUST_BIDIRECTIONAL_SCENARIO_ID = "cl-emulebb-rust-005-cl-emulebb-rust-006-bidirectional-exchange"
RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID = "cl-emulebb-001-cl-emulebb-rust-005-bidirectional-exchange"
OPTIONAL_SCENARIO_DEFINITIONS = (
    ("cl-emulebb-001-downloads-from-cl-emuleai-003", "emuleai"),
    (RUST_BIDIRECTIONAL_SCENARIO_ID, "emulebb_rust", "emulebb_rust_peer"),
    (RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID, "emulebb_rust"),
)


harness_cli_common = load_script_module("harness_cli_common", "harness-cli-common.py")
dtt = load_script_module("deterministic_two_client_transfer_matrix", "deterministic-two-client-transfer.py")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses the standalone multi-client matrix arguments."""

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
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--transfer-completion-timeout-seconds", type=float, default=1800.0)
    parser.add_argument("--fixture-size-bytes", type=int, default=dtt.DEFAULT_FIXTURE_SIZE_BYTES)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    parser.add_argument("--emuleai-exe")
    parser.add_argument("--require-optional-clients", action="store_true")
    parser.add_argument(
        "--require-scenario",
        action="append",
        choices=[definition[0] for definition in OPTIONAL_SCENARIO_DEFINITIONS],
        default=[],
        help="Require one optional matrix scenario without requiring every optional client.",
    )
    return parser.parse_args(argv)


def build_python_command() -> list[str]:
    """Returns the current Python interpreter command for child suites."""

    return [sys.executable]


def emule_workspace_build_repo(workspace_root: Path) -> Path:
    """Returns the build repo used for `python -m emule_workspace` child runs."""

    return workspace_parent_root(workspace_root) / "repos" / "emulebb-build"


def compact_child_report(path: Path) -> dict[str, object] | None:
    """Reads a child scenario report if it was published under its artifact root."""

    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def add_common_child_args(command: list[str], args: argparse.Namespace) -> None:
    """Appends the shared live-suite arguments forwarded to child scenarios."""

    command.extend(
        [
            "--configuration",
            args.configuration,
            "--api-key",
            args.api_key,
            "--lan-bind-addr",
            args.lan_bind_addr,
            "--rest-ready-timeout-seconds",
            str(args.rest_ready_timeout_seconds),
            "--server-connect-timeout-seconds",
            str(args.server_connect_timeout_seconds),
            "--link-export-timeout-seconds",
            str(args.link_export_timeout_seconds),
            "--server-publish-timeout-seconds",
            str(args.server_publish_timeout_seconds),
            "--transfer-completion-timeout-seconds",
            str(args.transfer_completion_timeout_seconds),
            "--fixture-size-bytes",
            str(args.fixture_size_bytes),
        ]
    )
    if args.app_root:
        command.extend(["--app-root", str(Path(args.app_root).resolve())])
    if args.app_exe:
        command.extend(["--app-exe", str(Path(args.app_exe).resolve())])
    if args.profile_seed_dir:
        command.extend(["--profile-seed-dir", str(Path(args.profile_seed_dir).resolve())])
    if args.p2p_bind_interface_name:
        command.extend(["--p2p-bind-interface-name", args.p2p_bind_interface_name])
    if args.p2p_bind_interface_address:
        command.extend(["--p2p-bind-interface-address", args.p2p_bind_interface_address])
    if args.ed2k_server_repo:
        command.extend(["--ed2k-server-repo", str(Path(args.ed2k_server_repo).resolve())])
    if args.ed2k_server_exe:
        command.extend(["--ed2k-server-exe", str(Path(args.ed2k_server_exe).resolve())])


def prepare_shared_ed2k_server_binary(paths, args: argparse.Namespace) -> dict[str, object]:
    """Stages one goed2k-server executable for every child scenario in this matrix run."""

    prepared = goed2k.prepare_ed2k_server_binary(
        paths.workspace_root,
        repo_override=args.ed2k_server_repo,
        exe_override=args.ed2k_server_exe,
    )
    args.ed2k_server_exe = str(prepared.server_exe)
    args.ed2k_server_repo = None
    return prepared.build


def run_child_scenario(
    *,
    scenario_id: str,
    clients: list[str],
    command: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
    report_path: Path | None = None,
    artifacts_dir: Path | None = None,
) -> dict[str, object]:
    """Runs one existing child suite and returns the normalized matrix row."""

    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    row: dict[str, object] = {
        "id": scenario_id,
        "status": "passed" if completed.returncode == 0 else "failed",
        "clients": clients,
        "command": command,
        "return_code": completed.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-4000:],
    }
    if report_path is not None:
        row["report_path"] = str(report_path)
        row["report"] = compact_child_report(report_path)
    if artifacts_dir is not None:
        row["artifacts_dir"] = str(artifacts_dir)
    return row


def build_child_script_command(script_name: str, scenario_artifacts: Path, args: argparse.Namespace) -> list[str]:
    """Builds a command line for one existing live-suite script."""

    command = build_python_command()
    command.extend(
        [
            str((Path(__file__).resolve().with_name(script_name))),
            "--artifacts-dir",
            str(scenario_artifacts),
        ]
    )
    add_common_child_args(command, args)
    return command


def run_deterministic_transfer_scenario(paths, args: argparse.Namespace) -> dict[str, object]:
    """Runs the mandatory eMuleBB download from the MFC main parity peer."""

    scenario_id = HARNESS_TRANSFER_SCENARIO_ID
    scenario_artifacts = paths.source_artifacts_dir / "h2"
    command = build_child_script_command("deterministic-two-client-transfer.py", scenario_artifacts, args)
    if args.client2_app_exe:
        command.extend(["--client2-app-exe", str(Path(args.client2_app_exe).resolve())])

    return run_child_scenario(
        scenario_id=scenario_id,
        clients=[CLIENT_IDENTITIES["emulebb"].profile_id, CLIENT_IDENTITIES["harness"].profile_id],
        command=command,
        cwd=REPO_ROOT,
        report_path=scenario_artifacts / "deterministic-two-client-transfer.json",
    )


def run_emulebb_rust_exchange_scenario(paths, args: argparse.Namespace) -> dict[str, object]:
    """Runs the existing Rust local-client suite for bidirectional peer exchange."""

    scenario_artifacts = paths.source_artifacts_dir / "r5"
    scenario_artifacts.mkdir(parents=True, exist_ok=True)
    report_path = scenario_artifacts / "emulebb-rust-peer-exchange-result.json"
    command = build_python_command()
    command.extend(
        [
            "-m",
            "emule_workspace",
            "test",
            "python",
            "--path",
            "tests/python/test_emulebb_rust_local_client.py",
            "--quiet",
            "-k",
            "peers_exchange",
        ]
    )

    child_env = os.environ.copy()
    child_env["X_LOCAL_IP"] = args.lan_bind_addr
    if args.ed2k_server_exe:
        child_env = goed2k.with_ed2k_server_exe_env(child_env, args.ed2k_server_exe)
    child_env["EMULEBB_RUST_PEER_EXCHANGE_REPORT"] = str(report_path)
    return run_child_scenario(
        scenario_id=RUST_BIDIRECTIONAL_SCENARIO_ID,
        clients=[
            CLIENT_IDENTITIES["emulebb_rust"].profile_id,
            CLIENT_IDENTITIES["emulebb_rust_peer"].profile_id,
        ],
        command=command,
        cwd=emule_workspace_build_repo(paths.workspace_root),
        env=child_env,
        report_path=report_path,
        artifacts_dir=scenario_artifacts,
    )


def run_emulebb_rust_emulebb_bidirectional_scenario(paths, args: argparse.Namespace) -> dict[str, object]:
    """Runs the REST-controlled bidirectional Rust/eMuleBB transfer scenario."""

    scenario_artifacts = paths.source_artifacts_dir / "r5-e1"
    command = build_child_script_command("emulebb-rust-emulebb-cross-client.py", scenario_artifacts, args)

    return run_child_scenario(
        scenario_id=RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID,
        clients=[CLIENT_IDENTITIES["emulebb"].profile_id, CLIENT_IDENTITIES["emulebb_rust"].profile_id],
        command=command,
        cwd=REPO_ROOT,
        report_path=scenario_artifacts / "emulebb-rust-emulebb-cross-client-result.json",
    )


def build_optional_scenario_rows(
    inventory: dict[str, object],
    *,
    require_optional_clients: bool,
    required_scenario_ids: set[str] | None = None,
    selected_scenario_ids: set[str] | None = None,
    completed_scenario_ids: set[str] | None = None,
) -> list[dict[str, object]]:
    """Builds explicit rows for optional Windows clients that are not silently ignored."""

    required_scenario_ids = required_scenario_ids or set()
    selected_scenario_ids = selected_scenario_ids or set()
    completed_scenario_ids = completed_scenario_ids or set()
    rows: list[dict[str, object]] = []
    for definition in OPTIONAL_SCENARIO_DEFINITIONS:
        scenario_id = definition[0]
        if scenario_id in completed_scenario_ids:
            continue
        required = require_optional_clients or scenario_id in required_scenario_ids
        client_keys = definition[1:]
        availability = [inventory[key] for key in client_keys]
        if selected_scenario_ids and scenario_id not in selected_scenario_ids:
            rows.append(
                {
                    "id": scenario_id,
                    "status": "skipped",
                    "reason": "not selected by --require-scenario",
                    "clients": [CLIENT_IDENTITIES["emulebb"].profile_id, *[row.identity.profile_id for row in availability]],
                }
            )
            continue
        missing = [row for row in availability if not row.available]
        if missing:
            rows.append(
                {
                    "id": scenario_id,
                    "status": "failed" if required else "skipped",
                    "reason": "optional client artifact missing",
                    "missing_clients": [row.identity.profile_id for row in missing],
                    "clients": [CLIENT_IDENTITIES["emulebb"].profile_id, *[row.identity.profile_id for row in availability]],
                }
            )
            continue
        adapter_blocked = [row for row in availability if not row.deterministic_transfer_adapter]
        if adapter_blocked:
            rows.append(
                {
                    "id": scenario_id,
                    "status": "failed" if required else "skipped",
                    "reason": "deterministic transfer adapter is not enabled for optional client",
                    "adapter_blocked_clients": [row.identity.profile_id for row in adapter_blocked],
                    "launch_adapters": {row.identity.profile_id: row.launch_adapter for row in availability},
                    "clients": [CLIENT_IDENTITIES["emulebb"].profile_id, *[row.identity.profile_id for row in availability]],
                }
            )
            continue
        rows.append(
            {
                "id": scenario_id,
                "status": "failed" if required else "skipped",
                "reason": "optional deterministic scenario runner is not implemented yet",
                "clients": [CLIENT_IDENTITIES["emulebb"].profile_id, *[row.identity.profile_id for row in availability]],
            }
        )
    return rows


def write_reports(paths, report: dict[str, object]) -> None:
    """Writes matrix report files using both suite-specific and generic names."""

    harness_cli_common.write_json_file(paths.source_artifacts_dir / "multi-client-p2p-matrix-result.json", report)


def main(argv: list[str] | None = None) -> int:
    """Runs the Windows multi-client P2P matrix."""

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
        "windows_only": True,
        "scenarios": [],
    }
    try:
        inventory = resolve_windows_client_inventory(
            workspace_root=paths.workspace_root,
            app_exe=paths.app_exe,
            configuration=args.configuration,
            harness_exe=args.client2_app_exe,
            emuleai_exe=args.emuleai_exe,
        )
        report["client_inventory"] = {key: value.as_report() for key, value in inventory.items()}
        mandatory_missing = [
            row.identity.profile_id
            for row in (inventory["emulebb"], inventory["harness"])
            if not row.available
        ]
        if mandatory_missing:
            report["status"] = "failed"
            report["error"] = {
                "type": "MissingMandatoryClient",
                "message": "Mandatory clients are unavailable.",
                "clients": mandatory_missing,
            }
            return 1

        report["ed2k_server_binary"] = prepare_shared_ed2k_server_binary(paths, args)
        selected_optional_ids = set(args.require_scenario or ())
        run_all_optional = not selected_optional_ids
        scenarios = []
        if run_all_optional or HARNESS_TRANSFER_SCENARIO_ID in selected_optional_ids:
            scenarios.append(run_deterministic_transfer_scenario(paths, args))
        completed_optional_ids: set[str] = set()
        rust = inventory["emulebb_rust"]
        rust_peer = inventory["emulebb_rust_peer"]
        if (
            (run_all_optional or RUST_BIDIRECTIONAL_SCENARIO_ID in selected_optional_ids)
            and rust.available
            and rust_peer.available
            and rust.deterministic_transfer_adapter
            and rust_peer.deterministic_transfer_adapter
        ):
            scenarios.append(run_emulebb_rust_exchange_scenario(paths, args))
            completed_optional_ids.add(RUST_BIDIRECTIONAL_SCENARIO_ID)
        if (
            (run_all_optional or RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID in selected_optional_ids)
            and rust.available
            and rust.deterministic_transfer_adapter
        ):
            scenarios.append(run_emulebb_rust_emulebb_bidirectional_scenario(paths, args))
            completed_optional_ids.add(RUST_EMULEBB_BIDIRECTIONAL_SCENARIO_ID)
        scenarios.extend(
            build_optional_scenario_rows(
                inventory,
                require_optional_clients=args.require_optional_clients,
                required_scenario_ids=set(args.require_scenario or ()),
                selected_scenario_ids=selected_optional_ids,
                completed_scenario_ids=completed_optional_ids,
            )
        )
        report["scenarios"] = scenarios
        failed = [row for row in scenarios if row.get("status") == "failed"]
        report["status"] = "failed" if failed else "passed"
        return 1 if failed else 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        return 1
    finally:
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        write_reports(paths, report)
        goed2k.stop_server_processes()
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
