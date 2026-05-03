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


def parse_args(*argv: str):
    return live_e2e_suite.build_parser().parse_args(list(argv))


def script_name(command: list[str]) -> str:
    return Path(command[1]).name


def option_values(command: list[str], option: str) -> list[str]:
    return [command[index + 1] for index, value in enumerate(command[:-1]) if value == option]


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
    assert summary["live_wire_search_queries"] == ["linux", "ubuntu", "fedora", "freebsd", "debian", "emule"]
    assert [suite["name"] for suite in summary["suites"]] == list(live_e2e_suite.SUITE_NAMES)
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
        "auto-browse-live.py",
    ]

    shared_files_command = commands[1]
    assert option_values(shared_files_command, "--scenario") == list(live_e2e_suite.SHARED_FILES_UI_SCENARIOS)
    assert "dynamic-folder-lifecycle" in option_values(shared_files_command, "--scenario")
    config_command = commands[2]
    assert option_values(config_command, "--scenario") == list(live_e2e_suite.CONFIG_STABILITY_UI_SCENARIOS)
    startup_command = commands[4]
    assert option_values(startup_command, "--scenario") == list(live_e2e_suite.STARTUP_PROFILE_SCENARIOS)

    rest_command = commands[6]
    assert "--enable-upnp" in rest_command
    assert option_values(rest_command, "--server-search-count") == [str(live_e2e_suite.DEFAULT_REST_SEARCH_COUNT)]
    assert option_values(rest_command, "--kad-search-count") == [str(live_e2e_suite.DEFAULT_REST_SEARCH_COUNT)]
    assert option_values(rest_command, "--live-download-trigger-count") == [str(live_e2e_suite.DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT)]
    assert option_values(rest_command, "--rest-coverage-profile") == ["contract"]
    assert option_values(rest_command, "--rest-stress-profile") == ["smoke"]
    assert option_values(rest_command, "--rest-stress-concurrency") == ["4"]
    assert "--skip-live-seed-refresh" not in rest_command
    assert summary["suites"][6]["rest_coverage_profile"] == "contract"
    assert summary["suites"][6]["rest_stress_profile"] == "smoke"
    assert summary["suites"][6]["rest_download_trigger_count"] == live_e2e_suite.DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT

    browser_command = commands[7]
    assert script_name(browser_command) == "amutorrent-browser-smoke.py"

    prowlarr_command = commands[8]
    assert script_name(prowlarr_command) == "prowlarr-emulebb-live.py"
    assert "--enable-upnp" in prowlarr_command
    assert "--skip-live-seed-refresh" not in prowlarr_command

    auto_browse_command = commands[9]
    assert option_values(auto_browse_command, "--p2p-bind-interface-name") == ["hide.me"]


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
    assert calls == len(live_e2e_suite.SUITE_SPECS)


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
            "--rest-coverage-profile",
            "contract-stress",
            "--rest-stress-profile",
            "soak",
            "--rest-stress-duration-seconds",
            "45",
            "--rest-stress-concurrency",
            "2",
            "--disable-upnp",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    rest_command = commands[0]
    assert "--enable-upnp" not in rest_command
    assert option_values(rest_command, "--rest-coverage-profile") == ["contract-stress"]
    assert option_values(rest_command, "--rest-stress-profile") == ["soak"]
    assert option_values(rest_command, "--rest-stress-duration-seconds") == ["45.0"]
    assert option_values(rest_command, "--rest-stress-concurrency") == ["2"]
    assert summary["suites"][0]["rest_coverage_profile"] == "contract-stress"
    assert summary["suites"][0]["rest_stress_profile"] == "soak"


def test_operator_script_help_loads_hyphenated_helpers() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [sys.executable, str(repo_root / "scripts" / "run_live_e2e_suite.py"), "--help"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "--skip-live-seed-refresh" in completed.stdout
