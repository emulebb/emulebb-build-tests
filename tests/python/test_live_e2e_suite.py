from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from emule_test_harness import live_e2e_suite
from emule_test_harness.live_seed_sources import EMULE_SECURITY_HOME_URL


class FakeHarnessCliCommon:
    def __init__(self, root: Path) -> None:
        self.root = root

    def prepare_run_paths(self, **kwargs):
        source_artifacts_dir = self.root / "source-artifacts"
        source_artifacts_dir.mkdir(parents=True)
        return SimpleNamespace(
            repo_root=self.root,
            workspace_root=self.root / "workspaces" / "v0.72a",
            app_root=self.root / "workspaces" / "v0.72a" / "app" / "eMule-main",
            app_exe=self.root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid" / "x64" / kwargs["configuration"] / "emule.exe",
            seed_config_dir=self.root / "repos" / "eMule-build-tests" / "manifests" / "live-profile-seed" / "config",
            configuration=kwargs["configuration"],
            suite_name=kwargs["suite_name"],
            source_artifacts_dir=source_artifacts_dir,
            run_report_dir=self.root / "reports" / kwargs["suite_name"] / "run",
            latest_report_dir=self.root / "reports" / f"{kwargs['suite_name']}-latest",
            keep_source_artifacts=True,
            local_dumps={"dump_folder": str(source_artifacts_dir / "crash-dumps"), "image_names": ["emule.exe"]},
        )

    def find_python_executable(self) -> str:
        return "python"

    def write_json_file(self, path: Path, payload) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")

    def publish_run_artifacts(self, paths) -> None:
        paths.run_report_dir.mkdir(parents=True, exist_ok=True)

    def publish_latest_report(self, paths) -> None:
        paths.latest_report_dir.mkdir(parents=True, exist_ok=True)

    def cleanup_source_artifacts(self, paths) -> None:
        return None

    def collect_local_dump_files(self, _local_dumps):
        return {"count": 0, "files": []}


def parse_args(*argv: str):
    return live_e2e_suite.build_parser().parse_args(list(argv))


def script_name(command: list[str]) -> str:
    return Path(command[1]).name


def option_values(command: list[str], option: str) -> list[str]:
    return [command[index + 1] for index, value in enumerate(command[:-1]) if value == option]


def test_child_suite_command_omits_workspace_root_when_env_matches(tmp_path: Path, monkeypatch) -> None:
    workspace_root = tmp_path / "workspaces" / "v0.72a"
    monkeypatch.setenv("EMULE_WORKSPACE_ROOT", str(tmp_path))

    command = live_e2e_suite.build_suite_command(
        spec=live_e2e_suite.SUITE_SPECS[0],
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=workspace_root,
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
    )

    assert "--workspace-root" not in command


def test_child_suite_command_keeps_workspace_root_without_env(tmp_path: Path, monkeypatch) -> None:
    workspace_root = tmp_path / "workspaces" / "v0.72a"
    monkeypatch.delenv("EMULE_WORKSPACE_ROOT", raising=False)

    command = live_e2e_suite.build_suite_command(
        spec=live_e2e_suite.SUITE_SPECS[0],
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=workspace_root,
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
    )

    assert option_values(command, "--workspace-root") == [str(workspace_root.resolve())]


def test_default_suite_commands_cover_ui_rest_and_live_wire(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "v0.72a")),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["live_seed_source_url"] == EMULE_SECURITY_HOME_URL
    assert summary["live_wire_inputs_file"].endswith("live-wire-inputs.local.json")
    assert summary["shared_files_ui_scenarios"] == list(live_e2e_suite.SHARED_FILES_UI_SCENARIOS)
    assert summary["rest_contract_completeness_expected"] is True
    assert summary["arr_live_wire_suites"] == ["prowlarr-emulebb", "radarr-sonarr-emulebb"]
    assert [suite["name"] for suite in summary["suites"]] == [
        spec.name for spec in live_e2e_suite.SUITE_SPECS if spec.default_enabled
    ]
    assert [script_name(command) for command in commands] == [
        "preference-ui-e2e.py",
        "shared-files-ui-e2e.py",
        "config-stability-ui-e2e.py",
        "shared-hash-ui-e2e.py",
        "startup-profile-scenarios.py",
        "shared-directories-rest-e2e.py",
        "rest-api-smoke.py",
        "amutorrent-browser-smoke.py",
        "prowlarr-emulebb-live.py",
        "radarr-sonarr-emulebb-live.py",
        "auto-browse-live.py",
    ]

    shared_files_command = commands[1]
    assert option_values(shared_files_command, "--scenario") == list(live_e2e_suite.SHARED_FILES_UI_SCENARIOS)
    assert "dynamic-folder-lifecycle" in option_values(shared_files_command, "--scenario")
    assert "--tree-stress-churn-cycles" not in shared_files_command
    config_command = commands[2]
    assert option_values(config_command, "--scenario") == list(live_e2e_suite.CONFIG_STABILITY_UI_SCENARIOS)
    startup_command = commands[4]
    assert option_values(startup_command, "--scenario") == list(live_e2e_suite.STARTUP_PROFILE_SCENARIOS)

    rest_command = commands[6]
    assert "--enable-upnp" in rest_command
    assert option_values(rest_command, "--p2p-bind-interface-name") == ["hide.me"]
    assert option_values(rest_command, "--live-wire-inputs-file") == [summary["live_wire_inputs_file"]]
    assert option_values(rest_command, "--server-search-count") == [str(live_e2e_suite.DEFAULT_REST_SEARCH_COUNT)]
    assert option_values(rest_command, "--kad-search-count") == [str(live_e2e_suite.DEFAULT_REST_SEARCH_COUNT)]
    assert option_values(rest_command, "--live-download-trigger-count") == [str(live_e2e_suite.DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT)]
    assert option_values(rest_command, "--webserver-scheme") == ["http"]
    assert option_values(rest_command, "--rest-coverage-budget") == ["contract"]
    assert option_values(rest_command, "--rest-stress-budget") == ["smoke"]
    assert option_values(rest_command, "--rest-stress-concurrency") == ["4"]
    assert option_values(rest_command, "--rest-stress-max-failures") == ["1"]
    assert option_values(rest_command, "--rest-stress-request-timeout-seconds") == ["5.0"]
    assert option_values(rest_command, "--rest-socket-adversity-budget") == ["off"]
    assert option_values(rest_command, "--rest-tls-handshake-adversity-budget") == ["off"]
    assert option_values(rest_command, "--rest-leak-churn-budget") == ["off"]
    assert "--skip-live-seed-refresh" not in rest_command
    assert summary["suites"][6]["rest_coverage_budget"] == "contract"
    assert summary["suites"][6]["rest_stress_budget"] == "smoke"
    assert summary["suites"][6]["rest_stress_max_failures"] == 1
    assert summary["suites"][6]["rest_download_trigger_count"] == live_e2e_suite.DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT
    assert summary["arr_direct_search_stress_count"] == live_e2e_suite.DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT
    assert summary["arr_prowlarr_search_stress_count"] == live_e2e_suite.DEFAULT_ARR_PROWLARR_SEARCH_STRESS_COUNT
    assert summary["arr_qbit_live_wire_rounds"] == live_e2e_suite.DEFAULT_ARR_QBIT_LIVE_WIRE_ROUNDS
    assert summary["suites"][6]["rest_contract_completeness_expected"] is True

    browser_command = commands[7]
    assert script_name(browser_command) == "amutorrent-browser-smoke.py"
    assert option_values(browser_command, "--p2p-bind-interface-name") == ["hide.me"]

    prowlarr_command = commands[8]
    assert script_name(prowlarr_command) == "prowlarr-emulebb-live.py"
    assert "--enable-upnp" in prowlarr_command
    assert option_values(prowlarr_command, "--p2p-bind-interface-name") == ["hide.me"]
    assert option_values(prowlarr_command, "--live-wire-inputs-file") == [summary["live_wire_inputs_file"]]
    assert option_values(prowlarr_command, "--direct-search-stress-count") == [str(live_e2e_suite.DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT)]
    assert option_values(prowlarr_command, "--prowlarr-search-stress-count") == [str(live_e2e_suite.DEFAULT_ARR_PROWLARR_SEARCH_STRESS_COUNT)]
    assert "--skip-live-seed-refresh" not in prowlarr_command
    assert summary["suites"][8]["arr_integration"] is True
    assert summary["suites"][8]["arr_direct_search_stress_count"] == live_e2e_suite.DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT

    arr_command = commands[9]
    assert script_name(arr_command) == "radarr-sonarr-emulebb-live.py"
    assert "--enable-upnp" in arr_command
    assert option_values(arr_command, "--p2p-bind-interface-name") == ["hide.me"]
    assert option_values(arr_command, "--live-wire-inputs-file") == [summary["live_wire_inputs_file"]]
    assert option_values(arr_command, "--qbit-live-wire-rounds") == [str(live_e2e_suite.DEFAULT_ARR_QBIT_LIVE_WIRE_ROUNDS)]
    assert "--skip-live-seed-refresh" not in arr_command
    assert summary["suites"][9]["arr_integration"] is True
    assert summary["suites"][9]["arr_qbit_live_wire_rounds"] == live_e2e_suite.DEFAULT_ARR_QBIT_LIVE_WIRE_ROUNDS

    auto_browse_command = commands[10]
    assert option_values(auto_browse_command, "--live-wire-inputs-file") == [summary["live_wire_inputs_file"]]
    assert option_values(auto_browse_command, "--p2p-bind-interface-name") == ["hide.me"]
    assert "--update-live-wire-inputs" not in auto_browse_command


def test_shared_files_ui_scenario_selector_limits_child_scenarios(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "v0.72a"),
            "--suite",
            "shared-files-ui",
            "--shared-files-ui-scenario",
            "dynamic-folder-lifecycle",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["shared_files_ui_scenarios"] == ["dynamic-folder-lifecycle"]
    assert option_values(commands[0], "--scenario") == ["dynamic-folder-lifecycle"]
    assert summary["suites"][0]["scenario_names"] == ["dynamic-folder-lifecycle"]


def test_search_ui_live_suite_is_selectable_with_live_network_policy(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "v0.72a"),
            "--suite",
            "search-ui-live",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert [suite["name"] for suite in summary["suites"]] == ["search-ui-live"]
    assert script_name(commands[0]) == "search-ui-live.py"
    assert option_values(commands[0], "--p2p-bind-interface-name") == ["hide.me"]
    assert "--skip-live-seed-refresh" not in commands[0]


def test_suite_continues_after_failures_by_default(tmp_path: Path, monkeypatch) -> None:
    calls = 0

    def fail_first_suite(command: list[str]) -> int:
        nonlocal calls
        calls += 1
        return 1 if calls == 1 else 0

    monkeypatch.setattr(live_e2e_suite, "run_suite_command", fail_first_suite)

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "v0.72a")),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "failed"
    assert calls == len([spec for spec in live_e2e_suite.SUITE_SPECS if spec.default_enabled])


def test_inconclusive_live_wire_suite_does_not_fail_aggregate(tmp_path: Path, monkeypatch) -> None:
    def return_inconclusive_for_auto_browse(command: list[str]) -> int:
        return live_e2e_suite.SUITE_INCONCLUSIVE_RETURN_CODE if script_name(command) == "auto-browse-live.py" else 0

    monkeypatch.setattr(live_e2e_suite, "run_suite_command", return_inconclusive_for_auto_browse)

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "v0.72a")),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["has_inconclusive_suites"] is True
    assert summary["suites"][-1]["name"] == "auto-browse-live"
    assert summary["suites"][-1]["status"] == "inconclusive"


def test_fail_fast_stops_after_first_failed_suite(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 1,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "v0.72a"), "--fail-fast"),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "failed"
    assert [script_name(command) for command in commands] == ["preference-ui-e2e.py"]


def test_rest_profile_flags_are_passed_to_rest_child(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "v0.72a"),
            "--suite",
            "rest-api",
            "--rest-coverage-budget",
            "contract-stress",
            "--rest-stress-budget",
            "soak",
            "--rest-stress-duration-seconds",
            "45",
            "--rest-stress-concurrency",
            "2",
            "--rest-leak-churn-budget",
            "smoke",
            "--rest-stop-start-after-churn",
            "--p2p-bind-interface-name",
            "hide.me",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    rest_command = commands[0]
    assert "--enable-upnp" in rest_command
    assert option_values(rest_command, "--p2p-bind-interface-name") == ["hide.me"]
    assert option_values(rest_command, "--rest-coverage-budget") == ["contract-stress"]
    assert option_values(rest_command, "--rest-stress-budget") == ["soak"]
    assert option_values(rest_command, "--rest-stress-duration-seconds") == ["45.0"]
    assert option_values(rest_command, "--rest-stress-concurrency") == ["2"]
    assert option_values(rest_command, "--rest-leak-churn-budget") == ["smoke"]
    assert "--rest-stop-start-after-churn" in rest_command
    assert summary["suites"][0]["rest_coverage_budget"] == "contract-stress"
    assert summary["suites"][0]["rest_stress_budget"] == "soak"
    assert summary["suites"][0]["rest_stop_start_after_churn"] is True


def test_cold_start_dump_stress_flags_are_passed_to_child(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or live_e2e_suite.SUITE_INCONCLUSIVE_RETURN_CODE,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "v0.72a"),
            "--suite",
            "rest-cold-start-dump-stress",
            "--rest-cold-start-dump-stress-waves",
            "2",
            "--rest-cold-start-dump-stress-searches-per-wave",
            "3",
            "--rest-cold-start-dump-stress-max-concurrent-searches",
            "4",
            "--rest-cold-start-dump-stress-search-observation-timeout-seconds",
            "12",
            "--rest-cold-start-dump-stress-downloads-per-wave",
            "1",
            "--rest-cold-start-dump-stress-downloads-per-search",
            "7",
            "--rest-cold-start-dump-stress-max-missing-download-triggers",
            "1",
            "--rest-cold-start-dump-stress-synthetic-queue-fill-count",
            "5",
            "--rest-cold-start-dump-stress-synthetic-queue-fill-size-bytes",
            "4096",
            "--rest-cold-start-dump-stress-synthetic-queue-fill-batch-size",
            "3",
            "--rest-cold-start-dump-stress-target-completed-downloads",
            "3",
            "--rest-cold-start-dump-stress-completion-timeout-seconds",
            "8",
            "--rest-cold-start-dump-stress-max-active-downloads",
            "9",
            "--rest-cold-start-dump-stress-allow-required-zero-result-searches",
            "--rest-cold-start-dump-stress-skip-transfer-cleanup",
            "--rest-cold-start-dump-stress-download-churn-interval-seconds",
            "10",
            "--rest-cold-start-dump-stress-download-remove-count-per-churn",
            "2",
            "--rest-cold-start-dump-stress-resource-monitor-interval-seconds",
            "11",
            "--rest-cold-start-dump-stress-post-drain-seconds",
            "5",
            "--rest-cold-start-dump-stress-tool-timeout-seconds",
            "6",
            "--rest-cold-start-dump-stress-enable-umdh",
            "--rest-cold-start-dump-stress-skip-umdh-diffs",
            "--rest-cold-start-dump-stress-cpu-profile",
            "--rest-cold-start-dump-stress-cpu-profile-max-file-mb",
            "64",
            "--rest-cold-start-dump-stress-cpu-profile-stack",
            "--rest-cold-start-dump-stress-cpu-profile-stack-min-hits",
            "25",
            "--no-rest-cold-start-dump-stress-cpu-profile-symbols-required",
            "--rest-cold-start-dump-stress-skip-dumps",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    command = commands[0]
    assert script_name(command) == "rest-cold-start-dump-stress.py"
    assert "--enable-upnp" in command
    assert option_values(command, "--waves") == ["2"]
    assert option_values(command, "--searches-per-wave") == ["3"]
    assert option_values(command, "--max-concurrent-searches") == ["4"]
    assert option_values(command, "--search-observation-timeout-seconds") == ["12.0"]
    assert option_values(command, "--downloads-per-wave") == ["1"]
    assert option_values(command, "--downloads-per-search") == ["7"]
    assert option_values(command, "--max-missing-download-triggers") == ["1"]
    assert option_values(command, "--synthetic-queue-fill-count") == ["5"]
    assert option_values(command, "--synthetic-queue-fill-size-bytes") == ["4096"]
    assert option_values(command, "--synthetic-queue-fill-batch-size") == ["3"]
    assert option_values(command, "--target-completed-downloads") == ["3"]
    assert option_values(command, "--completion-timeout-seconds") == ["8.0"]
    assert option_values(command, "--max-active-downloads") == ["9"]
    assert "--allow-required-zero-result-searches" in command
    assert "--skip-transfer-cleanup" in command
    assert option_values(command, "--download-churn-interval-seconds") == ["10.0"]
    assert option_values(command, "--download-remove-count-per-churn") == ["2"]
    assert option_values(command, "--resource-monitor-interval-seconds") == ["11.0"]
    assert option_values(command, "--post-drain-seconds") == ["5.0"]
    assert option_values(command, "--tool-timeout-seconds") == ["6.0"]
    assert "--enable-umdh" in command
    assert "--skip-umdh-diffs" in command
    assert "--cpu-profile" in command
    assert option_values(command, "--cpu-profile-max-file-mb") == ["64"]
    assert "--cpu-profile-stack" in command
    assert option_values(command, "--cpu-profile-stack-min-hits") == ["25"]
    assert "--no-cpu-profile-symbols-required" in command
    assert "--skip-dumps" in command
    assert summary["rest_cold_start_dump_stress"]["cpu_profile"] is True
    assert summary["rest_cold_start_dump_stress"]["cpu_profile_max_file_mb"] == 64
    assert summary["rest_cold_start_dump_stress"]["cpu_profile_stack"] is True
    assert summary["rest_cold_start_dump_stress"]["cpu_profile_stack_min_hits"] == 25
    assert summary["rest_cold_start_dump_stress"]["cpu_profile_symbols_required"] is False
    assert summary["rest_cold_start_dump_stress"]["max_missing_download_triggers"] == 1
    assert summary["rest_cold_start_dump_stress"]["synthetic_queue_fill_count"] == 5
    assert summary["rest_cold_start_dump_stress"]["synthetic_queue_fill_size_bytes"] == 4096
    assert summary["rest_cold_start_dump_stress"]["synthetic_queue_fill_batch_size"] == 3
    assert summary["rest_cold_start_dump_stress"]["search_observation_timeout_seconds"] == 12.0
    assert summary["rest_cold_start_dump_stress"]["allow_required_zero_result_searches"] is True
    assert summary["rest_cold_start_dump_stress"]["skip_transfer_cleanup"] is True
    assert summary["rest_cold_start_dump_stress"]["skip_umdh_diffs"] is True
    assert summary["status"] == "passed"
    assert summary["has_inconclusive_suites"] is True
    assert summary["suites"][0]["status"] == "inconclusive"


def test_local_dumps_crash_smoke_forwards_live_bind_policy(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "v0.72a"),
            "--suite",
            "local-dumps-crash-smoke",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    command = commands[0]
    assert script_name(command) == "local-dumps-crash-smoke.py"
    assert option_values(command, "--p2p-bind-interface-name") == ["hide.me"]
    assert summary["status"] == "passed"
    assert summary["suites"][0]["name"] == "local-dumps-crash-smoke"


def test_profile_seed_dir_flag_is_forwarded_with_hard_renamed_name(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    profile_seed_dir = tmp_path / "seed" / "config"
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "v0.72a"),
            "--suite",
            "rest-api",
            "--profile-seed-dir",
            str(profile_seed_dir),
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    removed_flag_name = "--seed" + "-config-dir"
    assert option_values(commands[0], "--profile-seed-dir") == [str(profile_seed_dir.resolve())]
    assert removed_flag_name not in commands[0]


def test_operator_script_help_loads_hyphenated_helpers() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [sys.executable, str(repo_root / "scripts" / "run-live-e2e-suite.py"), "--help"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "--skip-live-seed-refresh" in completed.stdout
    assert "--profile-seed-dir" in completed.stdout
    assert "--seed" + "-config-dir" not in completed.stdout
