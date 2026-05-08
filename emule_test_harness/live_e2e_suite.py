"""Aggregate live UI, REST, and live-wire E2E suite orchestration."""

from __future__ import annotations

import argparse
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from emule_test_harness.live_seed_sources import EMULE_SECURITY_HOME_URL
from emule_test_harness import live_wire_inputs

SHARED_FILES_UI_SCENARIOS = (
    "fixture-three-files",
    "generated-robustness-recursive",
    "tree-refresh-stress-10k",
    "duplicate-startup-reuse",
    "dynamic-folder-lifecycle",
    "monitored-folder-events",
)
CONFIG_STABILITY_UI_SCENARIOS = (
    "long-config-settings-roundtrip",
    "long-config-shared-stress",
)
STARTUP_PROFILE_SCENARIOS = (
    "baseline-no-shares",
    "fixture-three-files",
    "long-paths-root-only",
    "long-paths-recursive",
    "long-path-output-root-only",
    "long-path-output-recursive",
    "long-path-emule-fixture-root-only",
    "long-path-emule-fixture-recursive",
    "shared-files-robustness-root-only",
    "shared-files-robustness-recursive",
)
DEFAULT_REST_SEARCH_COUNT = 6
DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT = 1
DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT = 6
DEFAULT_ARR_PROWLARR_SEARCH_STRESS_COUNT = 4
DEFAULT_ARR_QBIT_LIVE_WIRE_ROUNDS = 2


@dataclass(frozen=True)
class SuiteSpec:
    """One child live E2E suite invoked by the aggregate runner."""

    name: str
    script_name: str
    category: str
    scenarios: tuple[str, ...] = ()
    accepts_startup_trace_mode: bool = False
    accepts_shared_root: bool = False
    uses_live_seed_refresh: bool = False
    is_rest_api: bool = False
    is_auto_browse: bool = False
    is_amutorrent_browser: bool = False
    is_prowlarr_emulebb: bool = False
    is_arr_emulebb: bool = False


SUITE_SPECS = (
    SuiteSpec(name="preference-ui", script_name="preference-ui-e2e.py", category="ui"),
    SuiteSpec(
        name="shared-files-ui",
        script_name="shared-files-ui-e2e.py",
        category="ui",
        scenarios=SHARED_FILES_UI_SCENARIOS,
        accepts_startup_trace_mode=True,
        accepts_shared_root=True,
    ),
    SuiteSpec(
        name="config-stability-ui",
        script_name="config-stability-ui-e2e.py",
        category="ui",
        scenarios=CONFIG_STABILITY_UI_SCENARIOS,
        accepts_startup_trace_mode=True,
        accepts_shared_root=True,
    ),
    SuiteSpec(
        name="shared-hash-ui",
        script_name="shared-hash-ui-e2e.py",
        category="ui",
        accepts_startup_trace_mode=True,
    ),
    SuiteSpec(
        name="startup-profile",
        script_name="startup-profile-scenarios.py",
        category="ui",
        scenarios=STARTUP_PROFILE_SCENARIOS,
        accepts_startup_trace_mode=True,
        accepts_shared_root=True,
    ),
    SuiteSpec(
        name="shared-directories-rest",
        script_name="shared-directories-rest-e2e.py",
        category="rest",
    ),
    SuiteSpec(
        name="rest-api",
        script_name="rest-api-smoke.py",
        category="rest",
        uses_live_seed_refresh=True,
        is_rest_api=True,
    ),
    SuiteSpec(
        name="amutorrent-browser-smoke",
        script_name="amutorrent-browser-smoke.py",
        category="rest",
        is_amutorrent_browser=True,
    ),
    SuiteSpec(
        name="prowlarr-emulebb",
        script_name="prowlarr-emulebb-live.py",
        category="rest",
        uses_live_seed_refresh=True,
        is_prowlarr_emulebb=True,
    ),
    SuiteSpec(
        name="radarr-sonarr-emulebb",
        script_name="radarr-sonarr-emulebb-live.py",
        category="live-wire",
        uses_live_seed_refresh=True,
        is_arr_emulebb=True,
    ),
    SuiteSpec(
        name="auto-browse-live",
        script_name="auto-browse-live.py",
        category="live-wire",
        uses_live_seed_refresh=True,
        is_auto_browse=True,
    ),
)
SUITE_NAMES = tuple(spec.name for spec in SUITE_SPECS)
SUITE_INCONCLUSIVE_RETURN_CODE = 2


def resolve_suite_specs(selected_names: list[str] | None) -> tuple[SuiteSpec, ...]:
    """Resolves selected suite names while preserving the canonical order."""

    if not selected_names:
        return SUITE_SPECS

    requested = set(selected_names)
    return tuple(spec for spec in SUITE_SPECS if spec.name in requested)


def build_python_command(python_executable: str) -> list[str]:
    """Builds the Python executable prefix, including `py -3` when needed."""

    command = [python_executable]
    if Path(python_executable).stem.lower() == "py":
        command.append("-3")
    return command


def build_suite_command(
    *,
    spec: SuiteSpec,
    scripts_dir: Path,
    python_executable: str,
    workspace_root: Path,
    configuration: str,
    artifacts_dir: Path,
    app_root: Path | None = None,
    app_exe: Path | None = None,
    seed_config_dir: Path | None = None,
    startup_trace_mode: str = "required",
    shared_root: Path | None = None,
    shared_files_tree_stress_churn_cycles: int | None = None,
    skip_live_seed_refresh: bool = False,
    rest_server_search_count: int = DEFAULT_REST_SEARCH_COUNT,
    rest_kad_search_count: int = DEFAULT_REST_SEARCH_COUNT,
    rest_download_trigger_count: int = DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT,
    rest_search_method_override: str | None = None,
    rest_webserver_scheme: str = "http",
    rest_coverage_budget: str = "contract",
    rest_stress_budget: str = "smoke",
    rest_stress_duration_seconds: float = 30.0,
    rest_stress_concurrency: int = 4,
    rest_stress_max_failures: int = 1,
    rest_stress_request_timeout_seconds: float = 5.0,
    rest_socket_adversity_budget: str = "off",
    rest_tls_handshake_adversity_budget: str = "off",
    rest_leak_churn_budget: str = "off",
    rest_leak_churn_cycles: int | None = None,
    p2p_bind_interface_name: str = "hide.me",
    live_wire_inputs_file: Path | None = None,
    arr_direct_search_stress_count: int = DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT,
    arr_prowlarr_search_stress_count: int = DEFAULT_ARR_PROWLARR_SEARCH_STRESS_COUNT,
    arr_qbit_live_wire_rounds: int = DEFAULT_ARR_QBIT_LIVE_WIRE_ROUNDS,
) -> list[str]:
    """Builds one child suite command line."""

    command = build_python_command(python_executable)
    command.extend(
        [
            str((scripts_dir / spec.script_name).resolve()),
            "--workspace-root",
            str(workspace_root.resolve()),
            "--configuration",
            configuration,
            "--artifacts-dir",
            str((artifacts_dir / spec.name).resolve()),
        ]
    )
    if app_root is not None:
        command.extend(["--app-root", str(app_root.resolve())])
    if app_exe is not None:
        command.extend(["--app-exe", str(app_exe.resolve())])
    if seed_config_dir is not None:
        command.extend(["--profile-seed-dir", str(seed_config_dir.resolve())])
    if spec.accepts_startup_trace_mode:
        command.extend(["--startup-trace-mode", startup_trace_mode])
    if spec.accepts_shared_root and shared_root is not None:
        command.extend(["--shared-root", str(shared_root.resolve())])
    if spec.name == "shared-files-ui" and shared_files_tree_stress_churn_cycles is not None:
        command.extend(["--tree-stress-churn-cycles", str(shared_files_tree_stress_churn_cycles)])
    for scenario in spec.scenarios:
        command.extend(["--scenario", scenario])
    if spec.uses_live_seed_refresh and skip_live_seed_refresh:
        command.append("--skip-live-seed-refresh")
    if spec.is_rest_api:
        if live_wire_inputs_file is not None:
            command.extend(["--live-wire-inputs-file", str(live_wire_inputs_file.resolve())])
        command.extend(["--server-search-count", str(rest_server_search_count)])
        command.extend(["--kad-search-count", str(rest_kad_search_count)])
        command.extend(["--live-download-trigger-count", str(rest_download_trigger_count)])
        if rest_search_method_override:
            command.extend(["--search-method-override", rest_search_method_override])
        command.extend(["--webserver-scheme", rest_webserver_scheme])
        command.extend(["--rest-coverage-budget", rest_coverage_budget])
        command.extend(["--rest-stress-budget", rest_stress_budget])
        command.extend(["--rest-stress-duration-seconds", str(rest_stress_duration_seconds)])
        command.extend(["--rest-stress-concurrency", str(rest_stress_concurrency)])
        command.extend(["--rest-stress-max-failures", str(rest_stress_max_failures)])
        command.extend(["--rest-stress-request-timeout-seconds", str(rest_stress_request_timeout_seconds)])
        command.extend(["--rest-socket-adversity-budget", rest_socket_adversity_budget])
        command.extend(["--rest-tls-handshake-adversity-budget", rest_tls_handshake_adversity_budget])
        command.extend(["--rest-leak-churn-budget", rest_leak_churn_budget])
        if rest_leak_churn_cycles is not None:
            command.extend(["--rest-leak-churn-cycles", str(rest_leak_churn_cycles)])
        command.append("--enable-upnp")
        if p2p_bind_interface_name:
            command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
    if spec.is_auto_browse:
        if live_wire_inputs_file is not None:
            command.extend(["--live-wire-inputs-file", str(live_wire_inputs_file.resolve())])
    if spec.is_auto_browse and p2p_bind_interface_name:
        command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
    if spec.is_amutorrent_browser and p2p_bind_interface_name:
        command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
    if spec.is_prowlarr_emulebb:
        if live_wire_inputs_file is not None:
            command.extend(["--live-wire-inputs-file", str(live_wire_inputs_file.resolve())])
        command.extend(["--direct-search-stress-count", str(arr_direct_search_stress_count)])
        command.extend(["--prowlarr-search-stress-count", str(arr_prowlarr_search_stress_count)])
        command.append("--enable-upnp")
        if p2p_bind_interface_name:
            command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
    if spec.is_arr_emulebb:
        if live_wire_inputs_file is not None:
            command.extend(["--live-wire-inputs-file", str(live_wire_inputs_file.resolve())])
        command.extend(["--qbit-live-wire-rounds", str(arr_qbit_live_wire_rounds)])
        command.append("--enable-upnp")
        if p2p_bind_interface_name:
            command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
    return command


def run_suite_command(command: list[str]) -> int:
    """Runs one child suite command and returns its process exit code."""

    completed = subprocess.run(command, check=False)
    return completed.returncode


def get_suite_status_from_return_code(return_code: int) -> str:
    """Maps one child process return code into an aggregate suite status."""

    if return_code == 0:
        return "passed"
    if return_code == SUITE_INCONCLUSIVE_RETURN_CODE:
        return "inconclusive"
    return "failed"


def build_parser() -> argparse.ArgumentParser:
    """Builds the aggregate live E2E argument parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--startup-trace-mode", choices=["required", "optional"], default="required")
    parser.add_argument("--shared-root", default=r"C:\tmp\00_long_paths")
    parser.add_argument("--shared-files-tree-stress-churn-cycles", type=int)
    parser.add_argument("--suite", action="append", choices=SUITE_NAMES)
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument("--rest-server-search-count", type=int, default=DEFAULT_REST_SEARCH_COUNT)
    parser.add_argument("--rest-kad-search-count", type=int, default=DEFAULT_REST_SEARCH_COUNT)
    parser.add_argument("--rest-download-trigger-count", type=int, default=DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT)
    parser.add_argument("--rest-search-method-override", choices=["automatic", "server", "global", "kad"])
    parser.add_argument("--rest-webserver-scheme", choices=["http", "https"], default="http")
    parser.add_argument("--rest-coverage-budget", choices=["smoke", "contract", "contract-stress"], default="contract")
    parser.add_argument("--rest-stress-budget", choices=["off", "smoke", "soak"], default="smoke")
    parser.add_argument("--rest-stress-duration-seconds", type=float, default=30.0)
    parser.add_argument("--rest-stress-concurrency", type=int, default=4)
    parser.add_argument("--rest-stress-max-failures", type=int, default=1)
    parser.add_argument("--rest-stress-request-timeout-seconds", type=float, default=5.0)
    parser.add_argument("--rest-socket-adversity-budget", choices=["off", "smoke"], default="off")
    parser.add_argument("--rest-tls-handshake-adversity-budget", choices=["off", "smoke"], default="off")
    parser.add_argument("--rest-leak-churn-budget", choices=["off", "smoke", "soak"], default="off")
    parser.add_argument("--rest-leak-churn-cycles", type=int)
    parser.add_argument("--arr-direct-search-stress-count", type=int, default=DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT)
    parser.add_argument("--arr-prowlarr-search-stress-count", type=int, default=DEFAULT_ARR_PROWLARR_SEARCH_STRESS_COUNT)
    parser.add_argument("--arr-qbit-live-wire-rounds", type=int, default=DEFAULT_ARR_QBIT_LIVE_WIRE_ROUNDS)
    parser.add_argument("--p2p-bind-interface-name", default="hide.me")
    parser.add_argument(
        "--live-wire-inputs-file",
        default=str(live_wire_inputs.get_default_inputs_path(Path(__file__).resolve().parent.parent)),
    )
    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validates aggregate runner arguments that affect child network searches."""

    if args.rest_server_search_count < 0 or args.rest_kad_search_count < 0:
        raise ValueError("REST live search counts must be zero or greater.")
    if args.rest_download_trigger_count < 0:
        raise ValueError("REST live download trigger count must be zero or greater.")
    if args.rest_stress_duration_seconds <= 0:
        raise ValueError("REST stress duration must be greater than zero.")
    if args.rest_stress_concurrency <= 0:
        raise ValueError("REST stress concurrency must be greater than zero.")
    if args.rest_stress_max_failures < 0:
        raise ValueError("REST stress max failures must be zero or greater.")
    if args.rest_stress_request_timeout_seconds <= 0:
        raise ValueError("REST stress request timeout must be greater than zero.")
    if args.arr_direct_search_stress_count <= 0:
        raise ValueError("Arr direct search stress count must be greater than zero.")
    if args.arr_prowlarr_search_stress_count <= 0:
        raise ValueError("Arr Prowlarr search stress count must be greater than zero.")
    if args.arr_qbit_live_wire_rounds <= 0:
        raise ValueError("Arr qBit live-wire rounds must be greater than zero.")


def run_live_e2e_suite(args: argparse.Namespace, harness_cli_common) -> dict[str, object]:
    """Runs the selected live E2E suites and returns the aggregate summary."""

    validate_args(args)
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="live-e2e-suite",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    selected_specs = resolve_suite_specs(args.suite)
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    python_executable = harness_cli_common.find_python_executable()
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else None
    shared_root = Path(args.shared_root).resolve() if args.shared_root else None
    live_wire_inputs_file = live_wire_inputs.resolve_inputs_path(
        Path(__file__).resolve().parent.parent,
        args.live_wire_inputs_file,
    )

    summary: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": "passed",
        "suite": "live-e2e-suite",
        "configuration": args.configuration,
        "app_exe": str(paths.app_exe),
        "workspace_root": str(paths.workspace_root),
        "app_root": str(paths.app_root),
        "artifact_dir": str(paths.run_report_dir),
        "latest_report_dir": str(paths.latest_report_dir),
        "source_artifact_dir": str(paths.source_artifacts_dir),
        "live_seed_source_url": EMULE_SECURITY_HOME_URL,
        "live_seed_refresh_enabled": not args.skip_live_seed_refresh,
        "live_wire_inputs_file": str(live_wire_inputs_file),
        "rest_coverage_budget": args.rest_coverage_budget,
        "rest_stress_budget": args.rest_stress_budget,
        "rest_stress_duration_seconds": args.rest_stress_duration_seconds,
        "rest_stress_concurrency": args.rest_stress_concurrency,
        "rest_stress_max_failures": args.rest_stress_max_failures,
        "rest_stress_request_timeout_seconds": args.rest_stress_request_timeout_seconds,
        "rest_download_trigger_count": args.rest_download_trigger_count,
        "rest_search_method_override": args.rest_search_method_override,
        "arr_direct_search_stress_count": args.arr_direct_search_stress_count,
        "arr_prowlarr_search_stress_count": args.arr_prowlarr_search_stress_count,
        "arr_qbit_live_wire_rounds": args.arr_qbit_live_wire_rounds,
        "rest_contract_completeness_expected": args.rest_coverage_budget != "smoke",
        "arr_live_wire_suites": [
            spec.name
            for spec in selected_specs
            if spec.is_prowlarr_emulebb or spec.is_arr_emulebb
        ],
        "fail_fast": bool(args.fail_fast),
        "has_inconclusive_suites": False,
        "suites": [],
    }

    for spec in selected_specs:
        child_artifacts_dir = paths.source_artifacts_dir / spec.name
        command = build_suite_command(
            spec=spec,
            scripts_dir=scripts_dir,
            python_executable=python_executable,
            workspace_root=paths.workspace_root,
            configuration=args.configuration,
            artifacts_dir=paths.source_artifacts_dir,
            app_root=paths.app_root,
            app_exe=paths.app_exe,
            seed_config_dir=seed_config_dir,
            startup_trace_mode=args.startup_trace_mode,
            shared_root=shared_root,
            shared_files_tree_stress_churn_cycles=args.shared_files_tree_stress_churn_cycles,
            skip_live_seed_refresh=args.skip_live_seed_refresh,
            rest_server_search_count=args.rest_server_search_count,
            rest_kad_search_count=args.rest_kad_search_count,
            rest_download_trigger_count=args.rest_download_trigger_count,
            rest_search_method_override=args.rest_search_method_override,
            rest_webserver_scheme=args.rest_webserver_scheme,
            rest_coverage_budget=args.rest_coverage_budget,
            rest_stress_budget=args.rest_stress_budget,
            rest_stress_duration_seconds=args.rest_stress_duration_seconds,
                rest_stress_concurrency=args.rest_stress_concurrency,
                rest_stress_max_failures=args.rest_stress_max_failures,
                rest_stress_request_timeout_seconds=args.rest_stress_request_timeout_seconds,
                rest_socket_adversity_budget=args.rest_socket_adversity_budget,
                rest_tls_handshake_adversity_budget=args.rest_tls_handshake_adversity_budget,
                rest_leak_churn_budget=args.rest_leak_churn_budget,
                rest_leak_churn_cycles=args.rest_leak_churn_cycles,
                p2p_bind_interface_name=args.p2p_bind_interface_name,
            live_wire_inputs_file=live_wire_inputs_file,
            arr_direct_search_stress_count=args.arr_direct_search_stress_count,
            arr_prowlarr_search_stress_count=args.arr_prowlarr_search_stress_count,
            arr_qbit_live_wire_rounds=args.arr_qbit_live_wire_rounds,
        )
        started = time.monotonic()
        return_code = run_suite_command(command)
        suite_status = get_suite_status_from_return_code(return_code)
        result = {
            "name": spec.name,
            "category": spec.category,
            "status": suite_status,
            "return_code": return_code,
            "duration_seconds": round(time.monotonic() - started, 3),
            "artifacts_dir": str(child_artifacts_dir.resolve()),
            "command": command,
            "scenario_names": list(spec.scenarios),
            "uses_live_seed_refresh": bool(spec.uses_live_seed_refresh and not args.skip_live_seed_refresh),
        }
        if spec.is_rest_api:
            result.update(
                {
                    "rest_coverage_budget": args.rest_coverage_budget,
                    "rest_stress_budget": args.rest_stress_budget,
                    "rest_stress_duration_seconds": args.rest_stress_duration_seconds,
                    "rest_stress_concurrency": args.rest_stress_concurrency,
                    "rest_stress_max_failures": args.rest_stress_max_failures,
                    "rest_stress_request_timeout_seconds": args.rest_stress_request_timeout_seconds,
                    "rest_download_trigger_count": args.rest_download_trigger_count,
                    "rest_search_method_override": args.rest_search_method_override,
                    "rest_contract_completeness_expected": args.rest_coverage_budget != "smoke",
                }
            )
        if spec.is_prowlarr_emulebb or spec.is_arr_emulebb:
            arr_result = {
                "arr_integration": True,
                "live_wire_inputs_file": str(live_wire_inputs_file),
            }
            if spec.is_prowlarr_emulebb:
                arr_result.update(
                    {
                        "arr_direct_search_stress_count": args.arr_direct_search_stress_count,
                        "arr_prowlarr_search_stress_count": args.arr_prowlarr_search_stress_count,
                    }
                )
            if spec.is_arr_emulebb:
                arr_result["arr_qbit_live_wire_rounds"] = args.arr_qbit_live_wire_rounds
            result.update(arr_result)
        summary["suites"].append(result)  # type: ignore[index]
        if suite_status == "inconclusive":
            summary["has_inconclusive_suites"] = True
        if suite_status == "failed":
            summary["status"] = "failed"
            if args.fail_fast:
                break

    result_path = paths.source_artifacts_dir / "result.json"
    harness_cli_common.write_json_file(result_path, summary)
    harness_cli_common.publish_run_artifacts(paths)
    harness_cli_common.publish_latest_report(paths)
    harness_cli_common.cleanup_source_artifacts(paths)
    return summary
