"""Windows-only multi-client P2P matrix for deterministic local E2E coverage."""

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

from emule_test_harness.multi_client import resolve_windows_client_inventory  # noqa: E402

SUITE_NAME = "multi-client-p2p-matrix"
API_KEY = "multi-client-p2p-matrix-key"


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


harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses the standalone multi-client matrix arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--client2-app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--p2p-bind-interface-name", default="hide.me")
    parser.add_argument("--p2p-bind-interface-address")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--transfer-completion-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--fixture-size-bytes", type=int, default=10 * 1024 * 1024)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    parser.add_argument("--emuleai-exe")
    parser.add_argument("--amule-daemon-exe")
    parser.add_argument("--amule-control-exe")
    parser.add_argument("--require-optional-clients", action="store_true")
    return parser.parse_args(argv)


def build_python_command() -> list[str]:
    """Returns the current Python interpreter command for child suites."""

    return [sys.executable]


def compact_child_report(path: Path) -> dict[str, object] | None:
    """Reads a child scenario report if it was published under its artifact root."""

    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def run_deterministic_transfer_scenario(paths, args: argparse.Namespace) -> dict[str, object]:
    """Runs the mandatory eMule BB download from tracing-harness seed scenario."""

    scenario_id = "client01-emulebb-downloads-from-client02-harness"
    scenario_artifacts = paths.source_artifacts_dir / scenario_id
    command = build_python_command()
    command.extend(
        [
            str((Path(__file__).resolve().with_name("deterministic-two-client-transfer.py"))),
            "--configuration",
            args.configuration,
            "--artifacts-dir",
            str(scenario_artifacts),
            "--api-key",
            args.api_key,
            "--bind-addr",
            args.bind_addr,
            "--p2p-bind-interface-name",
            args.p2p_bind_interface_name,
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
    if args.workspace_root:
        command.extend(["--workspace-root", str(Path(args.workspace_root).resolve())])
    if args.app_root:
        command.extend(["--app-root", str(Path(args.app_root).resolve())])
    if args.app_exe:
        command.extend(["--app-exe", str(Path(args.app_exe).resolve())])
    if args.client2_app_exe:
        command.extend(["--client2-app-exe", str(Path(args.client2_app_exe).resolve())])
    if args.profile_seed_dir:
        command.extend(["--profile-seed-dir", str(Path(args.profile_seed_dir).resolve())])
    if args.p2p_bind_interface_address:
        command.extend(["--p2p-bind-interface-address", args.p2p_bind_interface_address])
    if args.ed2k_server_repo:
        command.extend(["--ed2k-server-repo", str(Path(args.ed2k_server_repo).resolve())])
    if args.ed2k_server_exe:
        command.extend(["--ed2k-server-exe", str(Path(args.ed2k_server_exe).resolve())])

    started = time.monotonic()
    completed = subprocess.run(command, cwd=REPO_ROOT, text=True, capture_output=True, check=False)
    child_report = compact_child_report(scenario_artifacts / "deterministic-two-client-transfer.json")
    return {
        "id": scenario_id,
        "status": "passed" if completed.returncode == 0 else "failed",
        "clients": ["client01-emulebb", "client02-harness"],
        "command": command,
        "return_code": completed.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-4000:],
        "report": child_report,
    }


def build_optional_scenario_rows(inventory: dict[str, object], *, require_optional_clients: bool) -> list[dict[str, object]]:
    """Builds explicit rows for optional Windows clients that are not silently ignored."""

    rows: list[dict[str, object]] = []
    definitions = (
        ("client01-emulebb-downloads-from-client03-emuleai", "emuleai"),
        ("client01-emulebb-downloads-from-client04-amule", "amule"),
        ("client03-emuleai-and-client04-amule-discovery", "emuleai", "amule"),
    )
    for definition in definitions:
        scenario_id = definition[0]
        client_keys = definition[1:]
        availability = [inventory[key] for key in client_keys]
        missing = [row for row in availability if not row.available]
        if missing:
            rows.append(
                {
                    "id": scenario_id,
                    "status": "failed" if require_optional_clients else "skipped",
                    "reason": "optional client artifact missing",
                    "missing_clients": [row.identity.profile_id for row in missing],
                    "clients": ["client01-emulebb", *[row.identity.profile_id for row in availability]],
                }
            )
            continue
        rows.append(
            {
                "id": scenario_id,
                "status": "failed" if require_optional_clients else "skipped",
                "reason": "optional client executable found, but deterministic launch/control adapter is not enabled yet",
                "clients": ["client01-emulebb", *[row.identity.profile_id for row in availability]],
            }
        )
    return rows


def write_reports(paths, report: dict[str, object]) -> None:
    """Writes matrix report files using both suite-specific and generic names."""

    harness_cli_common.write_json_file(paths.source_artifacts_dir / "multi-client-p2p-matrix.json", report)
    harness_cli_common.write_json_file(paths.source_artifacts_dir / "result.json", report)


def main(argv: list[str] | None = None) -> int:
    """Runs the Windows multi-client P2P matrix."""

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
            amule_daemon_exe=args.amule_daemon_exe,
            amule_control_exe=args.amule_control_exe,
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

        scenarios = [run_deterministic_transfer_scenario(paths, args)]
        scenarios.extend(build_optional_scenario_rows(inventory, require_optional_clients=args.require_optional_clients))
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
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
