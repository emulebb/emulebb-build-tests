from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import live_e2e_suite
from emule_test_harness.live_seed_sources import EMULE_SECURITY_HOME_URL


class FakeHarnessCliCommon:
    def __init__(self, root: Path) -> None:
        self.root = root

    def prepare_run_paths(self, **kwargs):
        source_artifacts_dir = self.root / "source-artifacts"
        source_artifacts_dir.mkdir(parents=True)
        appdata = self.root / "appdata"
        os.environ["APPDATA"] = str(appdata)
        hide_logs = appdata / "Hide.me" / "Logs"
        hide_logs.mkdir(parents=True, exist_ok=True)
        hide_logs.joinpath("log.txt").write_text("Remote host resolved: 198.51.100.9\n", encoding="utf-8")
        for spec in live_e2e_suite.SUITE_SPECS:
            if spec.network_scope != "vpn":
                continue
            app_logs = source_artifacts_dir / spec.name / "profile" / "logs"
            app_logs.mkdir(parents=True, exist_ok=True)
            app_logs.joinpath("emulebb-verbose.log").write_text(
                "VPN public IPv4 probe: provider=http://api.ipify.org/ "
                "bindInterface=hide.me localBind=10.8.0.4 ifIndex=11 publicIp=198.51.100.9\n",
                encoding="utf-8",
            )
        return SimpleNamespace(
            repo_root=self.root,
            workspace_root=self.root / "workspaces" / "workspace",
            app_root=self.root / "workspaces" / "workspace" / "app" / "emulebb-main",
            app_exe=self.root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid" / "x64" / kwargs["configuration"] / "emulebb.exe",
            seed_config_dir=self.root / "repos" / "emulebb-build-tests" / "manifests" / "live-profile-seed" / "config",
            configuration=kwargs["configuration"],
            suite_name=kwargs["suite_name"],
            source_artifacts_dir=source_artifacts_dir,
            run_report_dir=self.root / "reports" / kwargs["suite_name"] / "run",
            latest_report_dir=self.root / "reports" / kwargs["suite_name"] / "latest",
            keep_source_artifacts=True,
            local_dumps={"dump_folder": str(source_artifacts_dir / "crash-dumps"), "image_names": ["emulebb.exe"]},
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
    args = list(argv)
    if "--test-network" not in args:
        args.extend(["--test-network", "all"])
    if "--vpn-guard-scenario" not in args and "--vpn-guard-live-config" not in args:
        args.extend(["--vpn-guard-live-config", str(Path("vpn-guard-live.json").resolve())])
    return live_e2e_suite.build_parser().parse_args(args)


def script_name(command: list[str]) -> str:
    return Path(command[1]).name


def option_values(command: list[str], option: str) -> list[str]:
    return [command[index + 1] for index, value in enumerate(command[:-1]) if value == option]


def install_profiled_command_capture(monkeypatch, commands: list[list[str]]) -> None:
    """Captures aggregate child commands without requiring local xperf tools."""

    def write_matching_vpn_probe_logs(child_artifacts_dir: Path) -> None:
        appdata = child_artifacts_dir.parents[1] / "appdata"
        monkeypatch.setenv("APPDATA", str(appdata))
        hide_logs = appdata / "Hide.me" / "Logs"
        hide_logs.mkdir(parents=True, exist_ok=True)
        hide_logs.joinpath("log.txt").write_text("Remote host resolved: 198.51.100.9\n", encoding="utf-8")
        app_logs = child_artifacts_dir / "profile" / "logs"
        app_logs.mkdir(parents=True, exist_ok=True)
        app_logs.joinpath("emulebb-verbose.log").write_text(
            "VPN public IPv4 probe: provider=http://api.ipify.org/ bindInterface=hide.me localBind=10.8.0.4 ifIndex=11 publicIp=198.51.100.9\n",
            encoding="utf-8",
        )

    def fake_run_profiled(command, *, spec, args, child_artifacts_dir, app_exe):
        commands.append(command)
        if spec.network_scope == "vpn":
            write_matching_vpn_probe_logs(child_artifacts_dir)
        profile_options = live_e2e_suite.resolve_suite_cpu_profile_options(spec, args)
        if not profile_options.enabled:
            return 0, None
        return (
            0,
            {
                "enabled": True,
                "source": profile_options.source,
                "status": "passed",
                "stack": profile_options.stack,
                "summary": {"detail": {"available": True}},
            },
        )

    monkeypatch.setattr(live_e2e_suite, "run_suite_command_with_optional_cpu_profile", fake_run_profiled)


def suite_spec(name: str) -> live_e2e_suite.SuiteSpec:
    return next(spec for spec in live_e2e_suite.SUITE_SPECS if spec.name == name)


def test_test_network_default_keeps_offline_and_lan_scopes() -> None:
    selected, skipped = live_e2e_suite.filter_suite_specs_for_network(
        (
            suite_spec("preference-ui"),
            suite_spec("deterministic-two-client-transfer"),
            suite_spec("rest-api"),
        ),
        "default",
    )

    assert [spec.name for spec in selected] == ["preference-ui", "deterministic-two-client-transfer"]
    assert skipped == [
        {
            "name": "rest-api",
            "category": "rest",
            "network_scope": "vpn",
            "reason": "excluded by test_network=default",
        }
    ]


def test_test_network_vpn_keeps_only_public_network_scope() -> None:
    selected, skipped = live_e2e_suite.filter_suite_specs_for_network(
        (
            suite_spec("preference-ui"),
            suite_spec("deterministic-two-client-transfer"),
            suite_spec("rest-api"),
        ),
        "vpn",
    )

    assert [spec.name for spec in selected] == ["rest-api"]
    assert [row["name"] for row in skipped] == ["preference-ui", "deterministic-two-client-transfer"]


def test_parse_latest_hide_me_remote_host_ipv4(tmp_path: Path) -> None:
    logs = tmp_path / "Hide.me" / "Logs"
    logs.mkdir(parents=True)
    first = logs / "log_old.txt"
    latest = logs / "log_latest.txt"
    first.write_text("05/30/2026 [INF] [Connection] Remote host resolved: 203.0.113.4\n", encoding="utf-8")
    latest.write_text(
        "05/30/2026 [INF] [Connection] Remote host resolved: 198.51.100.7\n"
        "05/30/2026 [INF] [Connection] Remote host resolved: 198.51.100.9\n",
        encoding="utf-8",
    )

    result = live_e2e_suite.parse_latest_hide_me_remote_host_ipv4(logs)

    assert result["found"] is True
    assert result["ip"] == "198.51.100.9"
    assert result["line_number"] == 2


def test_parse_latest_emulebb_public_probe_ipv4(tmp_path: Path) -> None:
    log_dir = tmp_path / "suite" / "profile" / "logs"
    log_dir.mkdir(parents=True)
    (log_dir / "emulebb-verbose.log").write_text(
        "VPN public IPv4 probe: provider=http://ipv4.icanhazip.com/ "
        "bindInterface=hide.me localBind=10.8.0.4 ifIndex=11 publicIp=198.51.100.9\n",
        encoding="utf-8",
    )

    result = live_e2e_suite.parse_latest_emulebb_public_probe_ipv4(tmp_path)

    assert result["found"] is True
    assert result["ip"] == "198.51.100.9"


def test_parse_latest_emulebb_public_probe_ipv4_reads_utf16_logs(tmp_path: Path) -> None:
    log_dir = tmp_path / "suite" / "profile" / "logs"
    log_dir.mkdir(parents=True)
    (log_dir / "emulebb-verbose.log").write_text(
        "VPN public IPv4 probe: provider=http://api.ipify.org/ "
        "bindInterface=hide.me localBind=10.8.0.4 ifIndex=11 publicIp=198.51.100.10\n",
        encoding="utf-16",
    )

    result = live_e2e_suite.parse_latest_emulebb_public_probe_ipv4(tmp_path)

    assert result["found"] is True
    assert result["ip"] == "198.51.100.10"


def test_parse_latest_emulebb_public_probe_ipv4_searches_extra_roots(tmp_path: Path) -> None:
    external_profile_logs = tmp_path / "external-profile" / "logs"
    external_profile_logs.mkdir(parents=True)
    external_profile_logs.joinpath("emulebb-verbose.log").write_text(
        "VPN public IPv4 probe: provider=http://api.ipify.org/ "
        "bindInterface=hide.me localBind=10.8.0.4 ifIndex=11 publicIp=198.51.100.11\n",
        encoding="utf-8",
    )

    result = live_e2e_suite.parse_latest_emulebb_public_probe_ipv4(
        tmp_path / "artifacts",
        extra_roots=[tmp_path / "external-profile"],
    )

    assert result["found"] is True
    assert result["ip"] == "198.51.100.11"


def test_parse_latest_emulebb_public_probe_ipv4_searches_rotated_logs(tmp_path: Path) -> None:
    log_dir = tmp_path / "profile" / "logs"
    log_dir.mkdir(parents=True)
    log_dir.joinpath("emulebb-verbose.log").write_text("current run without probe\n", encoding="utf-8")
    log_dir.joinpath("emulebb-verbose-20260531-060650.log").write_text(
        "VPN public IPv4 probe: provider=http://api.ipify.org/ "
        "bindInterface=hide.me localBind=10.8.0.4 ifIndex=11 publicIp=198.51.100.12\n",
        encoding="utf-8",
    )

    result = live_e2e_suite.parse_latest_emulebb_public_probe_ipv4(tmp_path)

    assert result["found"] is True
    assert result["ip"] == "198.51.100.12"


def test_vpn_public_ip_check_matches_hide_me_and_emulebb_logs(tmp_path: Path) -> None:
    appdata = tmp_path / "appdata"
    logs = appdata / "Hide.me" / "Logs"
    logs.mkdir(parents=True)
    logs.joinpath("log.txt").write_text("Remote host resolved: 198.51.100.9\n", encoding="utf-8")
    profile_logs = tmp_path / "artifacts" / "profile" / "logs"
    profile_logs.mkdir(parents=True)
    profile_logs.joinpath("emulebb-verbose.log").write_text(
        "VPN public IPv4 probe: provider=http://api.ipify.org/ bindInterface=hide.me localBind=10.8.0.4 ifIndex=11 publicIp=198.51.100.9\n",
        encoding="utf-8",
    )

    result = live_e2e_suite.build_vpn_public_ip_check(
        child_artifacts_dir=tmp_path / "artifacts",
        p2p_bind_interface_name="hide.me",
        network_scope="vpn",
        appdata_dir=str(appdata),
        probe_wait_seconds=0.0,
    )

    assert result["enabled"] is True
    assert result["matched"] is True
    assert result["expected"]["ip"] == "198.51.100.9"
    assert result["actual"]["ip"] == "198.51.100.9"


def test_vpn_public_ip_check_detects_mismatch(tmp_path: Path) -> None:
    appdata = tmp_path / "appdata"
    logs = appdata / "Hide.me" / "Logs"
    logs.mkdir(parents=True)
    logs.joinpath("log.txt").write_text("Remote host resolved: 198.51.100.9\n", encoding="utf-8")
    profile_logs = tmp_path / "artifacts" / "profile" / "logs"
    profile_logs.mkdir(parents=True)
    profile_logs.joinpath("emulebb-verbose.log").write_text(
        "VPN public IPv4 probe: provider=http://api.ipify.org/ bindInterface=hide.me localBind=10.8.0.4 ifIndex=11 publicIp=203.0.113.4\n",
        encoding="utf-8",
    )

    result = live_e2e_suite.build_vpn_public_ip_check(
        child_artifacts_dir=tmp_path / "artifacts",
        p2p_bind_interface_name="hide.me",
        network_scope="vpn",
        appdata_dir=str(appdata),
        probe_wait_seconds=0.0,
    )

    assert result["enabled"] is True
    assert result["matched"] is False
    assert result["expected"]["ip"] == "198.51.100.9"
    assert result["actual"]["ip"] == "203.0.113.4"


def test_vpn_public_ip_check_waits_for_delayed_emulebb_probe(tmp_path: Path, monkeypatch) -> None:
    appdata = tmp_path / "appdata"
    logs = appdata / "Hide.me" / "Logs"
    logs.mkdir(parents=True)
    logs.joinpath("log.txt").write_text("Remote host resolved: 198.51.100.9\n", encoding="utf-8")
    profile_logs = tmp_path / "artifacts" / "profile" / "logs"
    profile_logs.mkdir(parents=True)
    sleep_calls = []

    def fake_sleep(_seconds: float) -> None:
        sleep_calls.append(_seconds)
        profile_logs.joinpath("emulebb-verbose.log").write_text(
            "VPN public IPv4 probe: provider=http://api.ipify.org/ bindInterface=hide.me localBind=10.8.0.4 ifIndex=11 publicIp=198.51.100.9\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(live_e2e_suite.time, "sleep", fake_sleep)

    result = live_e2e_suite.build_vpn_public_ip_check(
        child_artifacts_dir=tmp_path / "artifacts",
        p2p_bind_interface_name="hide.me",
        network_scope="vpn",
        appdata_dir=str(appdata),
        probe_wait_seconds=10.0,
    )

    assert sleep_calls
    assert result["matched"] is True


def test_child_suite_command_omits_workspace_root_when_env_matches(tmp_path: Path, monkeypatch) -> None:
    workspace_root = tmp_path / "workspaces" / "workspace"
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(tmp_path))

    command = live_e2e_suite.build_suite_command(
        spec=suite_spec("preference-ui"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=workspace_root,
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
    )

    assert "--workspace-root" not in command


def test_child_suite_command_keeps_workspace_root_without_env(tmp_path: Path, monkeypatch) -> None:
    workspace_root = tmp_path / "workspaces" / "workspace"
    monkeypatch.delenv("EMULEBB_WORKSPACE_ROOT", raising=False)

    command = live_e2e_suite.build_suite_command(
        spec=suite_spec("preference-ui"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=workspace_root,
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
    )

    assert option_values(command, "--workspace-root") == [str(workspace_root.resolve())]


def test_child_suite_command_passes_mounted_shared_root_only_to_shared_directories_rest(tmp_path: Path) -> None:
    mounted_root = tmp_path / "mount-parent" / "mounted"
    mounted_root.mkdir(parents=True)

    shared_directories_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("shared-directories-rest"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        mounted_shared_root=mounted_root,
    )
    preference_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("preference-ui"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        mounted_shared_root=mounted_root,
    )

    assert option_values(shared_directories_command, "--mounted-shared-root") == [str(mounted_root.resolve())]
    assert "--mounted-shared-root" not in preference_command


def test_admin_volume_fixture_options_reach_admin_aware_suites(tmp_path: Path) -> None:
    mount_root = tmp_path / "mount-parent"
    admin_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("shared-cache-volume-identity"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    shared_directories_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("shared-directories-rest"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    shared_files_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("shared-files-ui"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    regular_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("rest-api"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )

    assert "--admin-volume-fixtures" in admin_command
    assert option_values(admin_command, "--vhd-size-mb") == ["384"]
    assert option_values(admin_command, "--mount-root") == [str(mount_root.resolve())]
    assert "--keep-admin-fixtures" in admin_command
    assert "--admin-volume-fixtures" in shared_directories_command
    assert option_values(shared_directories_command, "--vhd-size-mb") == ["384"]
    assert "--admin-volume-fixtures" in shared_files_command
    assert option_values(shared_files_command, "--scenario")[-1] == "monitored-folder-events-vhd"
    cleanup_audit_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("admin-volume-cleanup-audit"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    assert "--admin-volume-fixtures" in cleanup_audit_command
    assert option_values(cleanup_audit_command, "--mount-root") == [str(mount_root.resolve())]
    assert "--keep-admin-fixtures" in cleanup_audit_command
    profile_isolation_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("vhd-profile-isolation"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    assert "--admin-volume-fixtures" in profile_isolation_command
    assert option_values(profile_isolation_command, "--mount-root") == [str(mount_root.resolve())]
    profile_durability_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("vhd-profile-durability"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    assert "--admin-volume-fixtures" in profile_durability_command
    assert option_values(profile_durability_command, "--mount-root") == [str(mount_root.resolve())]
    category_matrix_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("category-incoming-path-matrix"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    assert "--admin-volume-fixtures" in category_matrix_command
    assert option_values(category_matrix_command, "--mount-root") == [str(mount_root.resolve())]
    partfile_recovery_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("vhd-partfile-recovery"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    assert "--admin-volume-fixtures" in partfile_recovery_command
    assert option_values(partfile_recovery_command, "--mount-root") == [str(mount_root.resolve())]
    amutorrent_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("amutorrent-browser-smoke"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    assert "--admin-volume-fixtures" in amutorrent_command
    assert option_values(amutorrent_command, "--mount-root") == [str(mount_root.resolve())]
    assert option_values(amutorrent_command, "--vhd-size-mb") == [str(live_e2e_suite.DEFAULT_CONTROLLER_STORAGE_VHD_SIZE_MB)]
    radarr_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("radarr-emulebb"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    assert "--admin-volume-fixtures" in radarr_command
    assert option_values(radarr_command, "--mount-root") == [str(mount_root.resolve())]
    assert option_values(radarr_command, "--vhd-size-mb") == [str(live_e2e_suite.DEFAULT_ARR_CONTROLLER_STORAGE_VHD_SIZE_MB)]
    radarr_local_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("radarr-emulebb-local"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        p2p_bind_interface_name="hide.me",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    assert radarr_local_command[1].endswith("radarr-emulebb-local.py")
    assert "--admin-volume-fixtures" in radarr_local_command
    assert option_values(radarr_local_command, "--mount-root") == [str(mount_root.resolve())]
    assert option_values(radarr_local_command, "--p2p-bind-interface-name") == []
    sonarr_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("sonarr-emulebb"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    assert "--admin-volume-fixtures" in sonarr_command
    assert option_values(sonarr_command, "--mount-root") == [str(mount_root.resolve())]
    assert option_values(sonarr_command, "--vhd-size-mb") == [str(live_e2e_suite.DEFAULT_ARR_CONTROLLER_STORAGE_VHD_SIZE_MB)]
    long_path_command = live_e2e_suite.build_suite_command(
        spec=suite_spec("vhd-long-path-special-names"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        admin_volume_fixtures=True,
        vhd_size_mb=384,
        mount_root=mount_root,
        keep_admin_fixtures=True,
    )
    assert "--admin-volume-fixtures" in long_path_command
    assert option_values(long_path_command, "--mount-root") == [str(mount_root.resolve())]
    assert "--admin-volume-fixtures" not in regular_command
    assert "--vhd-size-mb" not in regular_command


def test_arr_emulebb_suites_forward_http_and_https_rest_scheme(tmp_path: Path) -> None:
    for scheme in ("http", "https"):
        prowlarr_command = live_e2e_suite.build_suite_command(
            spec=suite_spec("prowlarr-emulebb"),
            scripts_dir=tmp_path / "scripts",
            python_executable="python",
            workspace_root=tmp_path / "workspace",
            configuration="Release",
            artifacts_dir=tmp_path / "artifacts",
            rest_webserver_scheme=scheme,
        )
        radarr_command = live_e2e_suite.build_suite_command(
            spec=suite_spec("radarr-emulebb"),
            scripts_dir=tmp_path / "scripts",
            python_executable="python",
            workspace_root=tmp_path / "workspace",
            configuration="Release",
            artifacts_dir=tmp_path / "artifacts",
            rest_webserver_scheme=scheme,
        )
        sonarr_command = live_e2e_suite.build_suite_command(
            spec=suite_spec("sonarr-emulebb"),
            scripts_dir=tmp_path / "scripts",
            python_executable="python",
            workspace_root=tmp_path / "workspace",
            configuration="Release",
            artifacts_dir=tmp_path / "artifacts",
            rest_webserver_scheme=scheme,
        )

        assert option_values(prowlarr_command, "--rest-webserver-scheme") == [scheme]
        assert option_values(radarr_command, "--rest-webserver-scheme") == [scheme]
        assert option_values(sonarr_command, "--rest-webserver-scheme") == [scheme]


def test_lan_network_context_reaches_local_child_suites(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.delenv("X_LOCAL_IP", raising=False)
    monkeypatch.setenv("EMULEBB_TEST_LAN_INTERFACE", "Wi-Fi")
    monkeypatch.setenv("EMULEBB_TEST_LAN_IP_RESOLVED", "192.0.2.11")
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--suite",
            "deterministic-two-client-transfer",
            "--suite",
            "radarr-emulebb-local",
            "--test-network",
            "lan",
            "--admin-volume-fixtures",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["test_network"] == "lan"
    assert summary["network_context"]["lan"] == {"interface_name": "Wi-Fi", "ip_address": "192.0.2.11"}
    assert summary["network_context"]["lan_bind_address"] == "192.0.2.11"
    assert [suite["network_scope"] for suite in summary["suites"]] == ["lan", "lan"]
    assert option_values(commands[0], "--p2p-bind-interface-name") == ["Wi-Fi"]
    assert option_values(commands[0], "--p2p-bind-interface-address") == ["192.0.2.11"]
    assert option_values(commands[0], "--lan-bind-addr") == ["192.0.2.11"]
    assert option_values(commands[1], "--lan-bind-addr") == ["192.0.2.11"]
    assert option_values(commands[1], "--p2p-bind-interface-address") == ["192.0.2.11"]


def test_vpn_search_ui_uses_lan_rest_bind_and_vpn_p2p_bind(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--suite",
            "search-ui-live",
            "--test-network",
            "vpn",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["test_network"] == "vpn"
    assert summary["network_context"]["lan_bind_address"] == "192.0.2.10"
    assert [suite["network_scope"] for suite in summary["suites"]] == ["vpn"]
    assert option_values(commands[0], "--lan-bind-addr") == ["192.0.2.10"]
    assert option_values(commands[0], "--p2p-bind-interface-name") == ["hide.me"]


def test_preference_ui_directory_tree_stress_reaches_child_suite(tmp_path: Path, monkeypatch) -> None:
    workspace_root = tmp_path / "workspaces" / "workspace"
    shared_root = tmp_path / "shared"
    monkeypatch.delenv("EMULEBB_WORKSPACE_ROOT", raising=False)

    command = live_e2e_suite.build_suite_command(
        spec=suite_spec("preference-ui"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=workspace_root,
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        shared_root=shared_root,
        preference_ui_directories_tree_stress=True,
    )

    assert "--directories-tree-stress" in command
    assert option_values(command, "--shared-root") == [str(shared_root.resolve())]


def test_default_network_run_skips_public_vpn_default_suites(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--test-network",
            "default",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["test_network"] == "default"
    assert summary["network_scopes"] == ["offline"]
    assert [suite["name"] for suite in summary["suites"]] == [
        "preference-ui",
        "shared-files-ui",
        "config-stability-ui",
        "shared-hash-ui",
        "startup-profile",
        "shared-directories-rest",
    ]
    assert [row["name"] for row in summary["skipped_suites"]] == [
        "rest-api",
        "amutorrent-browser-smoke",
        "prowlarr-emulebb",
        "radarr-emulebb",
        "sonarr-emulebb",
        "auto-browse-live",
    ]
    assert [script_name(command) for command in commands] == [
        "preference-ui-e2e.py",
        "shared-files-ui-e2e.py",
        "config-stability-ui-e2e.py",
        "shared-hash-ui-e2e.py",
        "startup-profile-scenarios.py",
        "shared-directories-rest-e2e.py",
    ]


def test_default_suite_commands_cover_ui_rest_and_live_wire(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace")),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["live_seed_source_url"] == EMULE_SECURITY_HOME_URL
    assert summary["live_wire_inputs_file"].endswith("live-wire-inputs.local.json")
    assert summary["shared_files_ui_scenarios"] == list(live_e2e_suite.SHARED_FILES_UI_CORE_SCENARIOS)
    assert summary["rest_contract_completeness_expected"] is True
    assert summary["arr_live_wire_suites"] == ["prowlarr-emulebb", "radarr-emulebb", "sonarr-emulebb"]
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
        "radarr-emulebb-live.py",
        "sonarr-emulebb-live.py",
        "auto-browse-live.py",
    ]

    shared_files_command = commands[1]
    assert option_values(shared_files_command, "--scenario") == list(live_e2e_suite.SHARED_FILES_UI_CORE_SCENARIOS)
    assert "dynamic-folder-lifecycle" in option_values(shared_files_command, "--scenario")
    assert "tree-refresh-smoke-1k" not in option_values(shared_files_command, "--scenario")
    assert "tree-refresh-stress-50k" not in option_values(shared_files_command, "--scenario")
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
    assert option_values(rest_command, "--webserver-scheme") == ["https"]
    assert option_values(rest_command, "--rest-coverage-budget") == ["contract"]
    assert option_values(rest_command, "--rest-stress-budget") == ["smoke"]
    assert option_values(rest_command, "--rest-stress-concurrency") == ["4"]
    assert option_values(rest_command, "--rest-stress-max-failures") == ["1"]
    assert option_values(rest_command, "--rest-stress-request-timeout-seconds") == ["5.0"]
    assert option_values(rest_command, "--rest-socket-adversity-budget") == ["off"]
    assert option_values(rest_command, "--rest-tls-handshake-adversity-budget") == ["off"]
    assert option_values(rest_command, "--rest-leak-churn-budget") == ["off"]
    assert option_values(rest_command, "--vpn-guard-live-config") == [summary["vpn_guard"]["live_config"]]
    assert option_values(rest_command, "--vpn-guard-scenario") == ["success"]
    assert "--skip-live-seed-refresh" not in rest_command
    assert summary["suites"][6]["rest_coverage_budget"] == "contract"
    assert summary["suites"][6]["rest_stress_budget"] == "smoke"
    assert summary["suites"][6]["rest_stress_max_failures"] == 1
    assert summary["suites"][6]["rest_download_trigger_count"] == live_e2e_suite.DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT
    assert summary["suites"][6]["vpn_guard"]["scenario"] == "success"
    assert summary["arr_direct_search_stress_count"] == live_e2e_suite.DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT
    assert summary["arr_prowlarr_search_stress_count"] == live_e2e_suite.DEFAULT_ARR_PROWLARR_SEARCH_STRESS_COUNT
    assert summary["radarr_movie_root_configured"] is False
    assert summary["radarr_movie_root_present"] is False
    assert summary["suites"][6]["rest_contract_completeness_expected"] is True

    browser_command = commands[7]
    assert script_name(browser_command) == "amutorrent-browser-smoke.py"
    assert option_values(browser_command, "--p2p-bind-interface-name") == ["hide.me"]

    prowlarr_command = commands[8]
    assert script_name(prowlarr_command) == "prowlarr-emulebb-live.py"
    assert "--enable-upnp" in prowlarr_command
    assert option_values(prowlarr_command, "--p2p-bind-interface-name") == ["hide.me"]
    assert option_values(prowlarr_command, "--live-wire-inputs-file") == [summary["live_wire_inputs_file"]]
    assert option_values(prowlarr_command, "--rest-webserver-scheme") == ["https"]
    assert option_values(prowlarr_command, "--direct-search-stress-count") == [str(live_e2e_suite.DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT)]
    assert option_values(prowlarr_command, "--prowlarr-search-stress-count") == [str(live_e2e_suite.DEFAULT_ARR_PROWLARR_SEARCH_STRESS_COUNT)]
    assert "--skip-live-seed-refresh" not in prowlarr_command
    assert summary["suites"][8]["arr_integration"] is True
    assert summary["suites"][8]["arr_direct_search_stress_count"] == live_e2e_suite.DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT

    arr_command = commands[9]
    assert script_name(arr_command) == "radarr-emulebb-live.py"
    assert "--enable-upnp" in arr_command
    assert option_values(arr_command, "--p2p-bind-interface-name") == ["hide.me"]
    assert option_values(arr_command, "--live-wire-inputs-file") == [summary["live_wire_inputs_file"]]
    assert option_values(arr_command, "--rest-webserver-scheme") == ["https"]
    assert "--qbit-live-wire-rounds" not in arr_command
    assert "--radarr-movie-root" not in arr_command
    assert "--skip-live-seed-refresh" not in arr_command
    assert summary["suites"][9]["arr_integration"] is True
    assert summary["suites"][9]["radarr_movie_root_configured"] is False

    sonarr_command = commands[10]
    assert script_name(sonarr_command) == "sonarr-emulebb-live.py"
    assert "--enable-upnp" in sonarr_command
    assert option_values(sonarr_command, "--p2p-bind-interface-name") == ["hide.me"]
    assert option_values(sonarr_command, "--live-wire-inputs-file") == [summary["live_wire_inputs_file"]]
    assert option_values(sonarr_command, "--rest-webserver-scheme") == ["https"]
    assert "--sonarr-series-root" not in sonarr_command
    assert "--skip-live-seed-refresh" not in sonarr_command
    assert summary["suites"][10]["arr_integration"] is True
    assert summary["suites"][10]["sonarr_series_root_configured"] is False

    auto_browse_command = commands[11]
    assert option_values(auto_browse_command, "--live-wire-inputs-file") == [summary["live_wire_inputs_file"]]
    assert option_values(auto_browse_command, "--p2p-bind-interface-name") == ["hide.me"]
    assert "--update-live-wire-inputs" not in auto_browse_command


def test_protocol_parity_profile_runs_live_rest_protocol_smoke(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace"), "--profile", "protocol-parity"),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "protocol-parity"
    assert summary["profile_suite_selection_applied"] is True
    assert [script_name(command) for command in commands] == [
        "deterministic-two-client-transfer.py",
        "rest-api-smoke.py",
    ]
    assert [suite["name"] for suite in summary["suites"]] == [
        "deterministic-two-client-transfer",
        "rest-api",
    ]

    deterministic_command = commands[0]
    assert option_values(deterministic_command, "--p2p-bind-interface-name") == []

    rest_command = commands[1]
    assert option_values(rest_command, "--server-search-count") == [str(live_e2e_suite.DEFAULT_REST_SEARCH_COUNT)]
    assert option_values(rest_command, "--kad-search-count") == [str(live_e2e_suite.DEFAULT_REST_SEARCH_COUNT)]
    assert option_values(rest_command, "--p2p-bind-interface-name") == ["hide.me"]
    assert option_values(rest_command, "--live-wire-inputs-file") == [summary["live_wire_inputs_file"]]


def test_multi_client_p2p_profile_runs_windows_matrix(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace"), "--profile", "multi-client-p2p"),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "multi-client-p2p"
    assert summary["profile_suite_selection_applied"] is True
    assert [script_name(command) for command in commands] == [
        "multi-client-p2p-matrix.py",
        "local-ed2k-search-soak.py",
        "local-ed2k-chaos-mode.py",
        "local-ed2k-protocol-combinations.py",
        "local-kad-swarm.py",
        "local-kad-mixed-client-swarm.py",
        "amutorrent-local-ed2k-ui-live.py",
    ]
    assert [suite["name"] for suite in summary["suites"]] == [
        "multi-client-p2p-matrix",
        "local-ed2k-search-soak",
        "local-ed2k-chaos-mode",
        "local-ed2k-protocol-combinations",
        "local-kad-swarm",
        "local-kad-mixed-client-swarm",
        "amutorrent-local-ed2k-ui-live",
    ]
    assert option_values(commands[0], "--p2p-bind-interface-name") == []
    assert option_values(commands[1], "--p2p-bind-interface-name") == []
    assert option_values(commands[2], "--p2p-bind-interface-name") == []
    assert option_values(commands[3], "--p2p-bind-interface-name") == []
    assert option_values(commands[4], "--p2p-bind-interface-name") == []
    assert option_values(commands[4], "--bootstrap-mode") == ["rest"]
    assert option_values(commands[5], "--p2p-bind-interface-name") == []
    assert option_values(commands[6], "--p2p-bind-interface-name") == []


def test_multi_client_optional_clients_can_be_required_from_aggregate_runner(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--suite",
            "multi-client-p2p-matrix",
            "--multi-client-require-optional-clients",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["multi_client_p2p_matrix"]["require_optional_clients"] is True
    assert [script_name(command) for command in commands] == ["multi-client-p2p-matrix.py"]
    assert "--require-optional-clients" in commands[0]


def test_multi_client_required_profile_enables_required_optional_clients(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--profile",
            "multi-client-p2p-required",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "multi-client-p2p-required"
    assert summary["multi_client_p2p_matrix"]["require_optional_clients"] is True
    assert [script_name(command) for command in commands] == [
        "multi-client-p2p-matrix.py",
        "local-ed2k-search-soak.py",
        "local-ed2k-chaos-mode.py",
        "local-ed2k-protocol-combinations.py",
        "local-kad-swarm.py",
        "local-kad-mixed-client-swarm.py",
        "amutorrent-local-ed2k-ui-live.py",
    ]
    assert "--require-optional-clients" in commands[0]


def test_controller_local_profile_owns_lan_arr_lanes(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--profile",
            "controller-local",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "controller-local"
    assert [script_name(command) for command in commands] == [
        "radarr-emulebb-local.py",
        "sonarr-emulebb-local.py",
    ]
    assert summary["arr_live_wire_suites"] == ["radarr-emulebb-local", "sonarr-emulebb-local"]


def test_diagnostics_soak_profile_owns_live_process_monitor(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--profile",
            "diagnostics-soak",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "diagnostics-soak"
    assert summary["profiling"]["memory"]["enabled"] is True
    assert [script_name(command) for command in commands] == ["live-process-monitor.py"]


def test_godzilla_local_swarm_is_explicit_local_protocol_suite(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--suite",
            "godzilla-local-swarm",
            "--admin-volume-fixtures",
            "--p2p-bind-interface-name",
            "hide.me",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert [script_name(command) for command in commands] == ["godzilla-local-swarm.py"]
    assert [suite["name"] for suite in summary["suites"]] == ["godzilla-local-swarm"]
    assert "--admin-volume-fixtures" in commands[0]
    assert option_values(commands[0], "--stage") == [live_e2e_suite.DEFAULT_GODZILLA_STAGE]
    assert option_values(commands[0], "--vhd-runtime-root") == ["drive-letter"]
    assert option_values(commands[0], "--total-client-count") == [str(live_e2e_suite.DEFAULT_GODZILLA_TOTAL_CLIENT_COUNT)]
    assert option_values(commands[0], "--peer-transfer-count") == [str(live_e2e_suite.DEFAULT_GODZILLA_PEER_TRANSFER_COUNT)]
    assert option_values(commands[0], "--harness-transfer-count") == [str(live_e2e_suite.DEFAULT_GODZILLA_HARNESS_TRANSFER_COUNT)]
    assert option_values(commands[0], "--emulebb-files") == [str(live_e2e_suite.DEFAULT_GODZILLA_EMULEBB_FILES)]
    assert option_values(commands[0], "--extra-emulebb-files") == [str(live_e2e_suite.DEFAULT_GODZILLA_EXTRA_EMULEBB_FILES)]
    assert option_values(commands[0], "--harness-files") == [str(live_e2e_suite.DEFAULT_GODZILLA_HARNESS_FILES)]
    assert option_values(commands[0], "--amule-files") == [str(live_e2e_suite.DEFAULT_GODZILLA_AMULE_FILES)]
    assert option_values(commands[0], "--adverse-kill-cycles") == [str(live_e2e_suite.DEFAULT_GODZILLA_ADVERSE_KILL_CYCLES)]
    assert option_values(commands[0], "--p2p-bind-interface-name") == []
    assert summary["suites"][0]["timeout_seconds"] == live_e2e_suite.DEFAULT_GODZILLA_CHILD_SUITE_TIMEOUT_SECONDS


def test_godzilla_local_swarm_rejects_folder_mount_runtime_root() -> None:
    with pytest.raises(SystemExit):
        parse_args(
            "--suite",
            "godzilla-local-swarm",
            "--admin-volume-fixtures",
            "--godzilla-vhd-runtime-root",
            "folder-mount",
        )


def test_godzilla_local_swarm_forwards_visible_ui_and_lan_bind(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--suite",
            "godzilla-local-swarm",
            "--p2p-bind-interface-name",
            "Ethernet",
            "--godzilla-p2p-bind-interface-address",
            "192.0.2.10",
            "--godzilla-visible-ui",
            "--godzilla-cpu-profile",
            "--godzilla-stage",
            "launch-scale",
            "--godzilla-vhd-runtime-root",
            "drive-letter",
            "--admin-volume-fixtures",
            "--vhd-size-mb",
            "8192",
            "--godzilla-total-client-count",
            "12",
            "--godzilla-peer-transfer-count",
            "444",
            "--godzilla-harness-transfer-count",
            "222",
            "--godzilla-emulebb-files",
            "700",
            "--godzilla-extra-emulebb-files",
            "70",
            "--godzilla-harness-files",
            "500",
            "--godzilla-amule-files",
            "120",
            "--godzilla-adverse-kill-cycles",
            "3",
            "--godzilla-adverse-kill-warmup-seconds",
            "0.5",
            "--godzilla-adverse-recovery-timeout-seconds",
            "45",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert "--visible-ui" in commands[0]
    assert "--cpu-profile" in commands[0]
    assert "--admin-volume-fixtures" in commands[0]
    assert option_values(commands[0], "--vhd-size-mb") == [str(live_e2e_suite.DEFAULT_GODZILLA_VHD_SIZE_MB)]
    assert option_values(commands[0], "--stage") == ["launch-scale"]
    assert option_values(commands[0], "--vhd-runtime-root") == ["drive-letter"]
    assert option_values(commands[0], "--p2p-bind-interface-name") == ["Ethernet"]
    assert option_values(commands[0], "--p2p-bind-interface-address") == ["192.0.2.10"]
    assert option_values(commands[0], "--total-client-count") == ["12"]
    assert option_values(commands[0], "--peer-transfer-count") == ["444"]
    assert option_values(commands[0], "--harness-transfer-count") == ["222"]
    assert option_values(commands[0], "--emulebb-files") == ["700"]
    assert option_values(commands[0], "--extra-emulebb-files") == ["70"]
    assert option_values(commands[0], "--harness-files") == ["500"]
    assert option_values(commands[0], "--amule-files") == ["120"]
    assert option_values(commands[0], "--adverse-kill-cycles") == ["3"]
    assert option_values(commands[0], "--adverse-kill-warmup-seconds") == ["0.5"]
    assert option_values(commands[0], "--adverse-recovery-timeout-seconds") == ["45.0"]
    assert summary["godzilla_local_swarm"] == {
        "visible_ui": True,
        "p2p_bind_interface_address": "192.0.2.10",
        "cpu_profile": True,
        "stage": "launch-scale",
        "vhd_runtime_root": "drive-letter",
        "total_client_count": 12,
        "peer_transfer_count": 444,
        "harness_transfer_count": 222,
        "emulebb_files": 700,
        "extra_emulebb_files": 70,
        "harness_files": 500,
        "amule_files": 120,
        "adverse_kill_cycles": 3,
        "adverse_kill_warmup_seconds": 0.5,
        "adverse_recovery_timeout_seconds": 45.0,
    }


def test_local_kad_bootstrap_mode_reaches_local_kad_suite(tmp_path: Path) -> None:
    command = live_e2e_suite.build_suite_command(
        spec=suite_spec("local-kad-swarm"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        local_kad_bootstrap_mode="preseed",
        local_kad_nodes_dat_fixture_mode="truncated",
    )

    assert script_name(command) == "local-kad-swarm.py"
    assert option_values(command, "--bootstrap-mode") == ["preseed"]
    assert option_values(command, "--nodes-dat-fixture-mode") == ["truncated"]
    assert option_values(command, "--min-contacts-per-client") == ["0"]


def test_rest_api_vpn_lan_bind_address_does_not_override_webserver_loopback(tmp_path: Path) -> None:
    command = live_e2e_suite.build_suite_command(
        spec=suite_spec("rest-api"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        p2p_bind_interface_address="10.54.221.82",
    )

    assert script_name(command) == "rest-api-smoke.py"
    assert option_values(command, "--lan-bind-addr") == []
    assert option_values(command, "--p2p-bind-interface-name") == ["hide.me"]


def test_rest_api_vpn_address_is_resolved_from_network_context() -> None:
    spec = suite_spec("rest-api")

    assert live_e2e_suite.suite_p2p_bind_interface_address(spec, "", "10.54.221.82") == "10.54.221.82"


def test_rest_api_can_run_explicit_vpn_guard_off_scenario(tmp_path: Path) -> None:
    command = live_e2e_suite.build_suite_command(
        spec=suite_spec("rest-api"),
        scripts_dir=tmp_path / "scripts",
        python_executable="python",
        workspace_root=tmp_path / "workspace",
        configuration="Release",
        artifacts_dir=tmp_path / "artifacts",
        p2p_bind_interface_name="hide.me",
        vpn_guard_scenario="off",
    )

    assert option_values(command, "--vpn-guard-scenario") == ["off"]
    assert option_values(command, "--p2p-bind-interface-name") == ["hide.me"]


def test_beta_green_profile_runs_short_api_resilience_suite(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace"), "--profile", "beta-green"),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "beta-green"
    assert summary["profile_suite_selection_applied"] is True
    assert summary["explicit_suite_names"] == []
    assert [script_name(command) for command in commands] == [
        "shared-directories-rest-e2e.py",
        "rest-api-smoke.py",
        "prowlarr-emulebb-live.py",
    ]
    assert [suite["name"] for suite in summary["suites"]] == [
        "shared-directories-rest",
        "rest-api",
        "prowlarr-emulebb",
    ]
    assert summary["arr_live_wire_suites"] == ["prowlarr-emulebb"]
    assert summary["arr_direct_search_stress_count"] == live_e2e_suite.BETA_GREEN_ARR_DIRECT_SEARCH_STRESS_COUNT
    assert summary["arr_prowlarr_search_stress_count"] == live_e2e_suite.BETA_GREEN_ARR_PROWLARR_SEARCH_STRESS_COUNT

    rest_command = commands[1]
    assert option_values(rest_command, "--rest-coverage-budget") == ["contract"]
    assert option_values(rest_command, "--rest-stress-budget") == ["smoke"]
    assert option_values(rest_command, "--live-download-trigger-count") == [str(live_e2e_suite.DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT)]

    prowlarr_command = commands[2]
    assert option_values(prowlarr_command, "--direct-search-stress-count") == [
        str(live_e2e_suite.BETA_GREEN_ARR_DIRECT_SEARCH_STRESS_COUNT)
    ]
    assert option_values(prowlarr_command, "--prowlarr-search-stress-count") == [
        str(live_e2e_suite.BETA_GREEN_ARR_PROWLARR_SEARCH_STRESS_COUNT)
    ]


def test_controller_surface_profile_runs_controller_api_surface(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace"), "--profile", "controller-surface"),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "controller-surface"
    assert summary["profile_suite_selection_applied"] is True
    assert summary["explicit_suite_names"] == []
    assert [script_name(command) for command in commands] == [
        "rest-api-smoke.py",
        "amutorrent-browser-smoke.py",
        "prowlarr-emulebb-live.py",
        "radarr-emulebb-live.py",
        "sonarr-emulebb-live.py",
    ]
    assert [suite["name"] for suite in summary["suites"]] == [
        "rest-api",
        "amutorrent-browser-smoke",
        "prowlarr-emulebb",
        "radarr-emulebb",
        "sonarr-emulebb",
    ]
    assert summary["arr_live_wire_suites"] == ["prowlarr-emulebb", "radarr-emulebb", "sonarr-emulebb"]
    assert summary["arr_download_proof_mode"] == live_e2e_suite.CONTROLLER_SURFACE_ARR_DOWNLOAD_PROOF_MODE
    assert summary["arr_direct_search_stress_count"] == live_e2e_suite.BETA_GREEN_ARR_DIRECT_SEARCH_STRESS_COUNT
    assert summary["arr_prowlarr_search_stress_count"] == live_e2e_suite.BETA_GREEN_ARR_PROWLARR_SEARCH_STRESS_COUNT

    rest_command = commands[0]
    assert option_values(rest_command, "--rest-coverage-budget") == ["contract"]
    assert option_values(rest_command, "--rest-stress-budget") == ["smoke"]

    browser_command = commands[1]
    assert option_values(browser_command, "--p2p-bind-interface-name") == ["hide.me"]

    prowlarr_command = commands[2]
    assert option_values(prowlarr_command, "--direct-search-stress-count") == [
        str(live_e2e_suite.BETA_GREEN_ARR_DIRECT_SEARCH_STRESS_COUNT)
    ]
    assert option_values(prowlarr_command, "--prowlarr-search-stress-count") == [
        str(live_e2e_suite.BETA_GREEN_ARR_PROWLARR_SEARCH_STRESS_COUNT)
    ]
    assert option_values(commands[3], "--download-proof-mode") == [
        live_e2e_suite.CONTROLLER_SURFACE_ARR_DOWNLOAD_PROOF_MODE
    ]
    assert option_values(commands[4], "--download-proof-mode") == [
        live_e2e_suite.CONTROLLER_SURFACE_ARR_DOWNLOAD_PROOF_MODE
    ]


def test_beta_release_profile_adds_acquisition_and_cold_start_stress(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace"), "--profile", "beta-release"),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "beta-release"
    assert summary["arr_download_proof_mode"] == live_e2e_suite.DEFAULT_ARR_DOWNLOAD_PROOF_MODE
    assert summary["rest_cold_start_dump_stress"]["waves"] == live_e2e_suite.BETA_RELEASE_REST_COLD_START_DUMP_STRESS_WAVES
    assert summary["rest_cold_start_dump_stress"]["searches_per_wave"] == (
        live_e2e_suite.BETA_RELEASE_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE
    )
    assert summary["rest_cold_start_dump_stress"]["downloads_per_wave"] == (
        live_e2e_suite.BETA_RELEASE_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE
    )
    assert [script_name(command) for command in commands] == [
        "command-line-smoke.py",
        "shared-directories-rest-e2e.py",
        "rest-api-smoke.py",
        "rest-cold-start-dump-stress.py",
        "prowlarr-emulebb-live.py",
        "radarr-emulebb-live.py",
        "sonarr-emulebb-live.py",
    ]
    assert summary["arr_live_wire_suites"] == ["prowlarr-emulebb", "radarr-emulebb", "sonarr-emulebb"]
    assert "auto-browse-live.py" not in [script_name(command) for command in commands]
    assert "shared-files-ui-e2e.py" not in [script_name(command) for command in commands]

    cold_start_command = commands[3]
    assert option_values(cold_start_command, "--waves") == [str(live_e2e_suite.BETA_RELEASE_REST_COLD_START_DUMP_STRESS_WAVES)]
    assert option_values(cold_start_command, "--searches-per-wave") == [
        str(live_e2e_suite.BETA_RELEASE_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE)
    ]
    assert option_values(cold_start_command, "--downloads-per-wave") == [
        str(live_e2e_suite.BETA_RELEASE_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE)
    ]


def test_stabilization_stress_profile_bundles_rest_leak_cpu_and_crash_coverage(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    install_profiled_command_capture(monkeypatch, commands)

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace"), "--profile", "stabilization-stress"),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "stabilization-stress"
    assert summary["profile_suite_selection_applied"] is True
    assert [script_name(command) for command in commands] == [
        "shared-files-ui-e2e.py",
        "search-ui-live.py",
        "deterministic-two-client-transfer.py",
        "godzilla-local-swarm.py",
        "shared-directories-rest-e2e.py",
        "rest-api-smoke.py",
        "rest-cold-start-dump-stress.py",
        "local-dumps-crash-smoke.py",
    ]
    assert [suite["name"] for suite in summary["suites"]] == [
        "shared-files-ui",
        "search-ui-live",
        "deterministic-two-client-transfer",
        "godzilla-local-swarm",
        "shared-directories-rest",
        "rest-api",
        "rest-cold-start-dump-stress",
        "local-dumps-crash-smoke",
    ]
    assert summary["shared_files_ui_scenarios"] == list(live_e2e_suite.SHARED_FILES_UI_FULL_STRESS_SCENARIOS)
    assert summary["arr_live_wire_suites"] == []
    assert summary["rest_coverage_budget"] == "contract-stress"
    assert summary["rest_stress_budget"] == "soak"
    assert summary["rest_stress_duration_seconds"] == live_e2e_suite.STABILIZATION_REST_STRESS_DURATION_SECONDS
    assert summary["rest_stress_concurrency"] == live_e2e_suite.STABILIZATION_REST_STRESS_CONCURRENCY
    assert summary["rest_stress_max_failures"] == live_e2e_suite.STABILIZATION_REST_STRESS_MAX_FAILURES
    assert summary["rest_socket_adversity_budget"] == "off"
    assert summary["rest_tls_handshake_adversity_budget"] == "smoke"
    assert summary["rest_leak_churn_budget"] == "smoke"
    assert summary["rest_leak_churn_cycles"] == live_e2e_suite.STABILIZATION_REST_LEAK_CHURN_CYCLES
    assert summary["rest_stop_start_after_churn"] is True
    assert summary["profiling"]["cpu"]["enabled"] is True
    assert summary["profiling"]["cpu"]["stack"] is True
    assert summary["profiling"]["memory"]["enabled"] is True
    assert summary["admin_volume_fixtures"]["enabled"] is True
    assert summary["admin_volume_fixtures"]["suite_names"] == [
        "shared-files-ui",
        "godzilla-local-swarm",
        "shared-directories-rest",
    ]
    assert summary["godzilla_local_swarm"]["stage"] == live_e2e_suite.RELEASE_EXPANDED_GODZILLA_STAGE
    assert summary["rest_cold_start_dump_stress"]["cpu_profile"] is True
    assert summary["rest_cold_start_dump_stress"]["cpu_profile_stack"] is True
    assert summary["rest_cold_start_dump_stress"]["resource_monitor_interval_seconds"] == (
        live_e2e_suite.DEFAULT_PROFILE_RESOURCE_MONITOR_INTERVAL_SECONDS
    )
    assert [suite["name"] for suite in summary["suites"] if "cpu_profile" in suite] == [
        "shared-files-ui",
        "search-ui-live",
        "rest-api",
        "rest-cold-start-dump-stress",
    ]
    assert summary["search_ui"] == {"search_rounds": 3, "download_lifecycle_count": 2}
    assert summary["suites"][1]["search_ui_search_rounds"] == 3
    assert summary["suites"][1]["search_ui_download_lifecycle_count"] == 2
    assert summary["weak_path_matrix"]["ui"]["shared_directories_rest"] is True
    assert summary["suites"][5]["rest_leak_churn_budget"] == "smoke"
    assert summary["suites"][5]["rest_leak_churn_cycles"] == live_e2e_suite.STABILIZATION_REST_LEAK_CHURN_CYCLES

    shared_files_command = commands[0]
    assert option_values(shared_files_command, "--scenario") == list(live_e2e_suite.SHARED_FILES_UI_FULL_STRESS_SCENARIOS)

    search_ui_command = commands[1]
    assert option_values(search_ui_command, "--ui-search-rounds") == ["3"]
    assert option_values(search_ui_command, "--ui-download-lifecycle-count") == ["2"]

    deterministic_command = commands[2]
    assert script_name(deterministic_command) == "deterministic-two-client-transfer.py"
    assert option_values(deterministic_command, "--p2p-bind-interface-name") == []

    godzilla_command = commands[3]
    assert option_values(godzilla_command, "--stage") == [live_e2e_suite.RELEASE_EXPANDED_GODZILLA_STAGE]
    assert "--admin-volume-fixtures" in godzilla_command

    shared_directories_command = commands[4]
    assert script_name(shared_directories_command) == "shared-directories-rest-e2e.py"

    rest_command = commands[5]
    assert option_values(rest_command, "--rest-coverage-budget") == ["contract-stress"]
    assert option_values(rest_command, "--rest-stress-budget") == ["soak"]
    assert option_values(rest_command, "--rest-stress-duration-seconds") == [
        str(live_e2e_suite.STABILIZATION_REST_STRESS_DURATION_SECONDS)
    ]
    assert option_values(rest_command, "--rest-stress-concurrency") == [
        str(live_e2e_suite.STABILIZATION_REST_STRESS_CONCURRENCY)
    ]
    assert option_values(rest_command, "--rest-stress-max-failures") == [
        str(live_e2e_suite.STABILIZATION_REST_STRESS_MAX_FAILURES)
    ]
    assert option_values(rest_command, "--rest-socket-adversity-budget") == ["off"]
    assert option_values(rest_command, "--rest-tls-handshake-adversity-budget") == ["smoke"]
    assert option_values(rest_command, "--rest-leak-churn-budget") == ["smoke"]
    assert option_values(rest_command, "--rest-leak-churn-cycles") == [
        str(live_e2e_suite.STABILIZATION_REST_LEAK_CHURN_CYCLES)
    ]
    assert "--rest-stop-start-after-churn" in rest_command

    cold_start_command = commands[6]
    assert option_values(cold_start_command, "--waves") == [
        str(live_e2e_suite.STABILIZATION_REST_COLD_START_DUMP_STRESS_WAVES)
    ]
    assert option_values(cold_start_command, "--searches-per-wave") == [
        str(live_e2e_suite.STABILIZATION_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE)
    ]
    assert option_values(cold_start_command, "--max-concurrent-searches") == [
        str(live_e2e_suite.STABILIZATION_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES)
    ]
    assert option_values(cold_start_command, "--downloads-per-wave") == [
        str(live_e2e_suite.STABILIZATION_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE)
    ]
    assert option_values(cold_start_command, "--downloads-per-search") == [
        str(live_e2e_suite.STABILIZATION_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_SEARCH)
    ]
    assert option_values(cold_start_command, "--synthetic-queue-fill-count") == [
        str(live_e2e_suite.STABILIZATION_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_COUNT)
    ]
    assert option_values(cold_start_command, "--download-churn-interval-seconds") == [
        str(live_e2e_suite.STABILIZATION_REST_COLD_START_DUMP_STRESS_DOWNLOAD_CHURN_INTERVAL_SECONDS)
    ]
    assert option_values(cold_start_command, "--download-remove-count-per-churn") == [
        str(live_e2e_suite.STABILIZATION_REST_COLD_START_DUMP_STRESS_DOWNLOAD_REMOVE_COUNT_PER_CHURN)
    ]


def test_release_expanded_profile_requires_100_live_download_triggers_and_adversity(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    install_profiled_command_capture(monkeypatch, commands)

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace"), "--profile", "release-expanded"),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "release-expanded"
    assert summary["profile_suite_selection_applied"] is True
    assert [script_name(command) for command in commands] == [
        "command-line-smoke.py",
        "preference-ui-e2e.py",
        "shared-files-ui-e2e.py",
        "config-stability-ui-e2e.py",
        "search-ui-live.py",
        "deterministic-two-client-transfer.py",
        "godzilla-local-swarm.py",
        "shared-hash-ui-e2e.py",
        "startup-profile-scenarios.py",
        "shared-directories-rest-e2e.py",
        "shared-cache-volume-identity.py",
        "shared-cache-invalidation.py",
        "unc-mapped-drive-identity.py",
        "vhd-long-path-special-names.py",
        "rest-api-smoke.py",
        "disk-space-guard-live.py",
        "vhd-profile-isolation.py",
        "vhd-profile-durability.py",
        "category-incoming-path-matrix.py",
        "vhd-partfile-recovery.py",
        "admin-volume-cleanup-audit.py",
        "rest-cold-start-dump-stress.py",
        "local-dumps-crash-smoke.py",
        "amutorrent-browser-smoke.py",
        "auto-browse-live.py",
    ]
    assert summary["preference_ui_directories_tree_stress"] is True
    assert summary["rest_coverage_budget"] == "contract-stress"
    assert summary["rest_stress_budget"] == "smoke"
    assert summary["rest_stress_duration_seconds"] == live_e2e_suite.RELEASE_EXPANDED_REST_STRESS_DURATION_SECONDS
    assert summary["rest_stress_concurrency"] == live_e2e_suite.RELEASE_EXPANDED_REST_STRESS_CONCURRENCY
    assert summary["rest_stress_max_failures"] == live_e2e_suite.RELEASE_EXPANDED_REST_STRESS_MAX_FAILURES
    assert summary["rest_socket_adversity_budget"] == "off"
    assert summary["rest_tls_handshake_adversity_budget"] == "smoke"
    assert summary["rest_leak_churn_budget"] == "smoke"
    assert summary["rest_leak_churn_cycles"] == live_e2e_suite.RELEASE_EXPANDED_REST_LEAK_CHURN_CYCLES
    assert summary["rest_stop_start_after_churn"] is True
    assert summary["rest_download_trigger_count"] == live_e2e_suite.RELEASE_EXPANDED_REST_DOWNLOAD_TRIGGER_COUNT
    assert summary["profiling"]["cpu"]["enabled"] is True
    assert summary["profiling"]["cpu"]["stack"] is True
    assert summary["profiling"]["memory"]["enabled"] is True
    assert summary["admin_volume_fixtures"]["enabled"] is True
    assert summary["admin_volume_fixtures"]["suite_names"] == [
        "shared-files-ui",
        "godzilla-local-swarm",
        "shared-directories-rest",
        "shared-cache-volume-identity",
        "shared-cache-invalidation",
        "unc-mapped-drive-identity",
        "vhd-long-path-special-names",
        "disk-space-guard-live",
        "vhd-profile-isolation",
        "vhd-profile-durability",
        "category-incoming-path-matrix",
        "vhd-partfile-recovery",
        "admin-volume-cleanup-audit",
        "amutorrent-browser-smoke",
    ]
    assert summary["search_ui"] == {"search_rounds": 2, "download_lifecycle_count": 2}
    assert summary["weak_path_matrix"]["live_download_triggers"] == {
        "server_search_count": live_e2e_suite.RELEASE_EXPANDED_REST_SEARCH_COUNT_PER_NETWORK,
        "kad_search_count": live_e2e_suite.RELEASE_EXPANDED_REST_SEARCH_COUNT_PER_NETWORK,
        "required_queued_triggers": live_e2e_suite.RELEASE_EXPANDED_REST_DOWNLOAD_TRIGGER_COUNT,
        "success_policy": "accepted_and_materialized_in_transfer_queue",
    }
    assert summary["weak_path_matrix"]["adversity"]["local_dumps_crash_smoke"] is True
    assert summary["weak_path_matrix"]["storage"] == {
        "shared_cache_volume_identity": True,
        "shared_cache_invalidation": True,
        "unc_mapped_drive_identity": True,
        "vhd_long_path_special_names": True,
        "disk_space_guard_live": True,
        "vhd_profile_isolation": True,
        "vhd_profile_durability": True,
        "category_incoming_path_matrix": True,
        "vhd_partfile_recovery": True,
        "admin_volume_cleanup_audit": True,
        "admin_volume_fixtures": True,
    }
    assert summary["weak_path_matrix"]["integrations"]["amutorrent_browser_smoke"] is True

    preference_command = commands[1]
    assert "--directories-tree-stress" in preference_command

    search_ui_command = commands[4]
    assert option_values(search_ui_command, "--ui-search-rounds") == ["2"]
    assert option_values(search_ui_command, "--ui-download-lifecycle-count") == ["2"]

    deterministic_command = commands[5]
    assert option_values(deterministic_command, "--p2p-bind-interface-name") == []

    godzilla_command = commands[6]
    assert "--admin-volume-fixtures" in godzilla_command
    assert option_values(godzilla_command, "--stage") == [live_e2e_suite.RELEASE_EXPANDED_GODZILLA_STAGE]
    assert option_values(godzilla_command, "--vhd-size-mb") == [str(live_e2e_suite.DEFAULT_GODZILLA_VHD_SIZE_MB)]

    cache_volume_command = commands[10]
    assert option_values(cache_volume_command, "--vhd-size-mb") == ["256"]
    assert "--admin-volume-fixtures" in cache_volume_command

    cache_invalidation_command = commands[11]
    assert option_values(cache_invalidation_command, "--vhd-size-mb") == ["256"]
    assert "--admin-volume-fixtures" in cache_invalidation_command

    unc_mapped_command = commands[12]
    assert option_values(unc_mapped_command, "--vhd-size-mb") == ["256"]
    assert "--admin-volume-fixtures" in unc_mapped_command

    long_path_command = commands[13]
    assert option_values(long_path_command, "--vhd-size-mb") == ["256"]
    assert "--admin-volume-fixtures" in long_path_command

    rest_command = commands[14]
    assert option_values(rest_command, "--server-search-count") == [
        str(live_e2e_suite.RELEASE_EXPANDED_REST_SEARCH_COUNT_PER_NETWORK)
    ]
    assert option_values(rest_command, "--kad-search-count") == [
        str(live_e2e_suite.RELEASE_EXPANDED_REST_SEARCH_COUNT_PER_NETWORK)
    ]
    assert option_values(rest_command, "--live-download-trigger-count") == [
        str(live_e2e_suite.RELEASE_EXPANDED_REST_DOWNLOAD_TRIGGER_COUNT)
    ]
    assert option_values(rest_command, "--rest-coverage-budget") == ["contract-stress"]
    assert option_values(rest_command, "--rest-stress-budget") == ["smoke"]
    assert option_values(rest_command, "--rest-stress-duration-seconds") == [
        str(live_e2e_suite.RELEASE_EXPANDED_REST_STRESS_DURATION_SECONDS)
    ]
    assert option_values(rest_command, "--rest-stress-concurrency") == [
        str(live_e2e_suite.RELEASE_EXPANDED_REST_STRESS_CONCURRENCY)
    ]
    assert option_values(rest_command, "--rest-stress-max-failures") == [
        str(live_e2e_suite.RELEASE_EXPANDED_REST_STRESS_MAX_FAILURES)
    ]
    assert option_values(rest_command, "--rest-socket-adversity-budget") == ["off"]
    assert option_values(rest_command, "--rest-tls-handshake-adversity-budget") == ["smoke"]
    assert option_values(rest_command, "--rest-leak-churn-budget") == ["smoke"]
    assert option_values(rest_command, "--rest-leak-churn-cycles") == [
        str(live_e2e_suite.RELEASE_EXPANDED_REST_LEAK_CHURN_CYCLES)
    ]
    assert "--rest-stop-start-after-churn" in rest_command

    disk_space_command = commands[15]
    assert option_values(disk_space_command, "--vhd-size-mb") == ["256"]
    assert "--admin-volume-fixtures" in disk_space_command

    profile_isolation_command = commands[16]
    assert option_values(profile_isolation_command, "--vhd-size-mb") == ["256"]
    assert "--admin-volume-fixtures" in profile_isolation_command

    profile_durability_command = commands[17]
    assert option_values(profile_durability_command, "--vhd-size-mb") == ["256"]
    assert "--admin-volume-fixtures" in profile_durability_command

    category_matrix_command = commands[18]
    assert option_values(category_matrix_command, "--vhd-size-mb") == ["256"]
    assert "--admin-volume-fixtures" in category_matrix_command

    partfile_recovery_command = commands[19]
    assert option_values(partfile_recovery_command, "--vhd-size-mb") == ["256"]
    assert "--admin-volume-fixtures" in partfile_recovery_command

    cleanup_audit_command = commands[20]
    assert option_values(cleanup_audit_command, "--vhd-size-mb") == ["256"]
    assert "--admin-volume-fixtures" in cleanup_audit_command

    cold_start_command = commands[21]
    assert option_values(cold_start_command, "--waves") == [
        str(live_e2e_suite.RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_WAVES)
    ]
    assert option_values(cold_start_command, "--searches-per-wave") == [
        str(live_e2e_suite.RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE)
    ]
    assert option_values(cold_start_command, "--downloads-per-wave") == [
        str(live_e2e_suite.RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE)
    ]

    amutorrent_command = commands[23]
    assert script_name(amutorrent_command) == "amutorrent-browser-smoke.py"
    assert "--admin-volume-fixtures" in amutorrent_command
    assert option_values(amutorrent_command, "--vhd-size-mb") == [str(live_e2e_suite.DEFAULT_CONTROLLER_STORAGE_VHD_SIZE_MB)]


def test_release_expanded_quick_profile_tolerates_sparse_live_cold_start_candidates(
    tmp_path: Path,
    monkeypatch,
) -> None:
    commands: list[list[str]] = []
    install_profiled_command_capture(monkeypatch, commands)

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--profile",
            "release-expanded-quick",
            "--suite",
            "rest-cold-start-dump-stress",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["rest_cold_start_dump_stress"]["max_missing_download_triggers"] == (
        live_e2e_suite.RELEASE_EXPANDED_QUICK_REST_COLD_START_DUMP_STRESS_MAX_MISSING_DOWNLOAD_TRIGGERS
    )
    assert summary["rest_cold_start_dump_stress"]["synthetic_queue_fill_count"] == (
        live_e2e_suite.RELEASE_EXPANDED_QUICK_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_COUNT
    )
    cold_start_command = commands[0]
    assert option_values(cold_start_command, "--max-missing-download-triggers") == [
        str(live_e2e_suite.RELEASE_EXPANDED_QUICK_REST_COLD_START_DUMP_STRESS_MAX_MISSING_DOWNLOAD_TRIGGERS)
    ]
    assert option_values(cold_start_command, "--synthetic-queue-fill-count") == [
        str(live_e2e_suite.RELEASE_EXPANDED_QUICK_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_COUNT)
    ]


def test_release_expanded_quick_profile_keeps_required_search_ui_live() -> None:
    assert "search-ui-live" in live_e2e_suite.PROFILE_SUITE_NAMES["release-expanded-quick"]


def test_release_expanded_profile_propagates_real_live_profile_inputs(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    install_profiled_command_capture(monkeypatch, commands)
    live_wire_inputs_file = tmp_path / "live-wire-inputs.local.json"
    live_wire_inputs_file.write_text("{}", encoding="utf-8")

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--profile",
            "release-expanded",
            "--live-wire-inputs-file",
            str(live_wire_inputs_file),
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    by_script = {script_name(command): command for command in commands}
    for script in ("search-ui-live.py", "rest-api-smoke.py", "rest-cold-start-dump-stress.py", "amutorrent-browser-smoke.py"):
        command = by_script[script]
        assert option_values(command, "--p2p-bind-interface-name") == ["hide.me"]
        if script in {"rest-api-smoke.py", "rest-cold-start-dump-stress.py"}:
            assert "--enable-upnp" in command
        if script in {"search-ui-live.py", "rest-api-smoke.py", "rest-cold-start-dump-stress.py"}:
            assert option_values(command, "--live-wire-inputs-file") == [str(live_wire_inputs_file.resolve())]

    deterministic_command = by_script["deterministic-two-client-transfer.py"]
    assert option_values(deterministic_command, "--p2p-bind-interface-name") == []


def test_admin_storage_suite_requires_explicit_fixture_gate(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="require --admin-volume-fixtures"):
        live_e2e_suite.run_live_e2e_suite(
            parse_args(
                "--workspace-root",
                str(tmp_path / "workspaces" / "workspace"),
                "--suite",
                "disk-space-guard-live",
            ),
            FakeHarnessCliCommon(tmp_path),
        )


def test_stabilization_stress_profile_enables_tls_adversity_for_https(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    install_profiled_command_capture(monkeypatch, commands)

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--profile",
            "stabilization-stress",
            "--rest-webserver-scheme",
            "https",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["rest_socket_adversity_budget"] == "off"
    assert summary["rest_tls_handshake_adversity_budget"] == "smoke"
    assert summary["rest_stress_budget"] == "soak"
    assert summary["rest_leak_churn_budget"] == "smoke"

    rest_command = commands[5]
    assert option_values(rest_command, "--rest-socket-adversity-budget") == ["off"]
    assert option_values(rest_command, "--rest-tls-handshake-adversity-budget") == ["smoke"]
    assert option_values(rest_command, "--rest-stress-budget") == ["soak"]
    assert option_values(rest_command, "--rest-leak-churn-budget") == ["smoke"]


def test_stabilization_stress_profile_enables_raw_socket_adversity_for_http(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    install_profiled_command_capture(monkeypatch, commands)

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--profile",
            "stabilization-stress",
            "--rest-webserver-scheme",
            "http",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["rest_socket_adversity_budget"] == "smoke"
    assert summary["rest_tls_handshake_adversity_budget"] == "off"

    rest_command = commands[5]
    assert option_values(rest_command, "--rest-socket-adversity-budget") == ["smoke"]
    assert option_values(rest_command, "--rest-tls-handshake-adversity-budget") == ["off"]


def test_cpu_heavy_profile_runs_shared_files_50k_under_cpu_profile(tmp_path: Path, monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_run_profiled(command, *, spec, args, child_artifacts_dir, app_exe):
        calls.append(
            {
                "command": command,
                "spec": spec.name,
                "profile": args.profile,
                "child_artifacts_dir": str(child_artifacts_dir),
                "app_exe": str(app_exe),
            }
        )
        return 0, {"enabled": True, "status": "passed", "summary": {"detail": {"available": True}}}

    monkeypatch.setattr(live_e2e_suite, "run_suite_command_with_optional_cpu_profile", fake_run_profiled)

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace"), "--profile", "cpu-heavy"),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "cpu-heavy"
    assert summary["profile_suite_selection_applied"] is True
    assert summary["shared_files_ui_scenarios"] == list(live_e2e_suite.SHARED_FILES_UI_FULL_STRESS_SCENARIOS)
    assert summary["shared_files_ui_cpu_profile"]["enabled"] is True
    assert summary["shared_files_ui_cpu_profile"]["stack"] is True
    assert [script_name(call["command"]) for call in calls] == ["shared-files-ui-e2e.py"]
    shared_files_command = calls[0]["command"]
    assert option_values(shared_files_command, "--scenario") == list(live_e2e_suite.SHARED_FILES_UI_FULL_STRESS_SCENARIOS)
    assert option_values(shared_files_command, "--tree-stress-churn-cycles") == ["80"]
    assert summary["suites"][0]["cpu_profile"]["status"] == "passed"


def test_cpu_heavy_quick_profile_runs_shared_files_1k_under_cpu_profile(tmp_path: Path, monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_run_profiled(command, *, spec, args, child_artifacts_dir, app_exe):
        calls.append(
            {
                "command": command,
                "spec": spec.name,
                "profile": args.profile,
                "child_artifacts_dir": str(child_artifacts_dir),
                "app_exe": str(app_exe),
            }
        )
        return 0, {"enabled": True, "status": "passed", "summary": {"detail": {"available": True}}}

    monkeypatch.setattr(live_e2e_suite, "run_suite_command_with_optional_cpu_profile", fake_run_profiled)

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace"), "--profile", "cpu-heavy-quick"),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "cpu-heavy-quick"
    assert summary["shared_files_ui_scenarios"] == list(live_e2e_suite.SHARED_FILES_UI_SMOKE_STRESS_SCENARIOS)
    shared_files_command = calls[0]["command"]
    assert option_values(shared_files_command, "--scenario") == list(live_e2e_suite.SHARED_FILES_UI_SMOKE_STRESS_SCENARIOS)
    assert option_values(shared_files_command, "--tree-stress-churn-cycles") == ["8"]
    assert summary["suites"][0]["cpu_profile"]["status"] == "passed"


def test_child_resource_diagnostics_are_bounded_for_aggregate_memory_profiles() -> None:
    child_result = {
        "diagnostics": {
            "resource_monitor": {
                "enabled": True,
                "interval_seconds": 2.0,
                "summary": {"sample_count": 3, "peak_working_set_bytes": 4096},
                "samples": [{"working_set_bytes": 1024}],
                "thread_alive_after_stop": False,
            },
            "resource_deltas": {"baseline_to_peak": {"working_set_delta_bytes": 2048}},
            "findings": {"resources": [{"severity": "warning", "text": "growth"}]},
        }
    }

    extracted = live_e2e_suite.extract_child_resource_diagnostics(child_result)

    assert extracted == {
        "resource_monitor": {
            "enabled": True,
            "interval_seconds": 2.0,
            "summary": {"sample_count": 3, "peak_working_set_bytes": 4096},
            "thread_alive_after_stop": False,
        },
        "resource_deltas": {"baseline_to_peak": {"working_set_delta_bytes": 2048}},
        "findings": {"resources": [{"severity": "warning", "text": "growth"}]},
    }


def test_ui_resource_depth_profile_runs_resource_smoke_and_preferences(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    workspace_root = tmp_path / "workspaces" / "workspace"
    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(workspace_root), "--profile", "ui-resource-depth"),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "ui-resource-depth"
    assert summary["weak_path_matrix"]["ui"]["resource_ui_smoke"] is True
    assert [script_name(command) for command in commands] == ["resource-ui-smoke.py", "preference-ui-e2e.py"]
    resource_command = commands[0]
    assert option_values(resource_command, "--language-scope") == ["release"]
    assert option_values(resource_command, "--release-languages-json") == [
        str((tmp_path / "repos" / "emulebb-tooling" / "helpers" / "rc-release-languages.json").resolve())
    ]
    assert option_values(resource_command, "--language-timeout-seconds") == [str(live_e2e_suite.DEFAULT_RESOURCE_UI_LANGUAGE_TIMEOUT_SECONDS)]
    assert "--fail-fast-languages" not in resource_command
    assert summary["suites"][0]["language_scope"] == "release"


def test_ui_resource_depth_fail_fast_propagates_to_language_rows(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--profile",
            "ui-resource-depth",
            "--fail-fast",
            "--resource-ui-language-timeout-seconds",
            "30",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    resource_command = commands[0]
    assert option_values(resource_command, "--language-timeout-seconds") == ["30.0"]
    assert "--fail-fast-languages" in resource_command


def test_profile_does_not_override_explicit_suite_selection(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--profile",
            "beta-green",
            "--suite",
            "rest-api",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["profile"] == "beta-green"
    assert summary["profile_suite_selection_applied"] is False
    assert summary["explicit_suite_names"] == ["rest-api"]
    assert [script_name(command) for command in commands] == ["rest-api-smoke.py"]


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
            str(tmp_path / "workspaces" / "workspace"),
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


def test_radarr_movie_root_option_reaches_arr_suite(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )
    root_path = "/media/radarr-import-root"

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--suite",
            "radarr-emulebb",
            "--radarr-movie-root",
            root_path,
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["radarr_movie_root_configured"] is True
    assert summary["radarr_movie_root_present"] is True
    assert option_values(commands[0], "--radarr-movie-root") == [root_path]
    assert summary["suites"][0]["radarr_movie_root_configured"] is True


def test_sonarr_series_root_option_reaches_arr_suite(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )
    root_path = "/media/sonarr-import-root"

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--suite",
            "sonarr-emulebb",
            "--sonarr-series-root",
            root_path,
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["sonarr_series_root_configured"] is True
    assert summary["sonarr_series_root_present"] is True
    assert option_values(commands[0], "--sonarr-series-root") == [root_path]
    assert summary["suites"][0]["sonarr_series_root_configured"] is True


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
            str(tmp_path / "workspaces" / "workspace"),
            "--suite",
            "search-ui-live",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert [suite["name"] for suite in summary["suites"]] == ["search-ui-live"]
    assert script_name(commands[0]) == "search-ui-live.py"
    assert option_values(commands[0], "--p2p-bind-interface-name") == ["hide.me"]
    assert option_values(commands[0], "--live-wire-inputs-file")
    assert option_values(commands[0], "--ui-search-rounds") == ["1"]
    assert option_values(commands[0], "--ui-download-lifecycle-count") == ["1"]
    assert summary["search_ui"] == {"search_rounds": 1, "download_lifecycle_count": 1}
    assert summary["suites"][0]["search_ui_search_rounds"] == 1
    assert summary["suites"][0]["search_ui_download_lifecycle_count"] == 1
    assert "--skip-live-seed-refresh" not in commands[0]


def test_stabilization_stress_profile_includes_expanded_search_ui_live(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    install_profiled_command_capture(monkeypatch, commands)

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--profile",
            "stabilization-stress",
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    suite_names = [suite["name"] for suite in summary["suites"]]
    assert "search-ui-live" in suite_names
    search_command = next(command for command in commands if script_name(command) == "search-ui-live.py")
    assert option_values(search_command, "--ui-search-rounds") == ["3"]
    assert option_values(search_command, "--ui-download-lifecycle-count") == ["2"]
    assert option_values(search_command, "--p2p-bind-interface-name") == ["hide.me"]
    assert option_values(search_command, "--live-wire-inputs-file")
    assert summary["search_ui"] == {"search_rounds": 3, "download_lifecycle_count": 2}


def test_suite_continues_after_failures_by_default(tmp_path: Path, monkeypatch) -> None:
    calls = 0

    def fail_first_suite(command: list[str]) -> int:
        nonlocal calls
        calls += 1
        return 1 if calls == 1 else 0

    monkeypatch.setattr(live_e2e_suite, "run_suite_command", fail_first_suite)

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace")),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "failed"
    assert calls == len([spec for spec in live_e2e_suite.SUITE_SPECS if spec.default_enabled])


def test_inconclusive_live_wire_suite_fails_aggregate(tmp_path: Path, monkeypatch) -> None:
    def return_inconclusive_for_auto_browse(command: list[str]) -> int:
        return live_e2e_suite.SUITE_INCONCLUSIVE_RETURN_CODE if script_name(command) == "auto-browse-live.py" else 0

    monkeypatch.setattr(live_e2e_suite, "run_suite_command", return_inconclusive_for_auto_browse)

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace")),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "failed"
    assert summary["strict_success_required"] is True
    assert "has_inconclusive_suites" not in summary
    assert "inconclusive_suite_names" not in summary
    assert "inconclusive_classification" not in summary
    assert summary["suites"][-1]["name"] == "auto-browse-live"
    assert summary["suites"][-1]["status"] == "failed"


def test_fail_fast_stops_after_first_failed_suite(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 1,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args("--workspace-root", str(tmp_path / "workspaces" / "workspace"), "--fail-fast"),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "failed"
    assert [script_name(command) for command in commands] == ["preference-ui-e2e.py"]


def test_run_suite_command_times_out_and_terminates_process_tree(monkeypatch) -> None:
    killed: list[tuple[int, list[str]]] = []
    observed_timeouts: list[float] = []

    class FakeProcess:
        pid = 4321

        def __init__(self) -> None:
            self.calls = 0

        def wait(self, timeout=None):
            self.calls += 1
            observed_timeouts.append(timeout)
            raise subprocess.TimeoutExpired(cmd=["child-suite"], timeout=timeout or 0.0)

    monkeypatch.setattr(live_e2e_suite.subprocess, "Popen", lambda _command: FakeProcess())
    monkeypatch.setattr(
        live_e2e_suite,
        "terminate_process_tree",
        lambda process_id, command=None: killed.append((process_id, command or [])) or {"return_code": 0},
    )

    assert live_e2e_suite.run_suite_command(["child-suite"]) == live_e2e_suite.SUITE_TIMEOUT_RETURN_CODE
    assert killed == [(4321, ["child-suite"])]
    assert observed_timeouts[0] == live_e2e_suite.DEFAULT_CHILD_SUITE_TIMEOUT_SECONDS


def test_run_suite_command_uses_extended_godzilla_timeout(monkeypatch) -> None:
    observed_timeouts: list[float] = []

    class FakeProcess:
        pid = 4321

        def wait(self, timeout=None):
            observed_timeouts.append(timeout)
            raise subprocess.TimeoutExpired(cmd=["python", "godzilla-local-swarm.py"], timeout=timeout or 0.0)

    monkeypatch.setattr(live_e2e_suite.subprocess, "Popen", lambda _command: FakeProcess())
    monkeypatch.setattr(live_e2e_suite, "terminate_process_tree", lambda _process_id, command=None: {"return_code": 0})

    assert live_e2e_suite.run_suite_command(["python", r"C:\tests\godzilla-local-swarm.py"]) == live_e2e_suite.SUITE_TIMEOUT_RETURN_CODE
    assert observed_timeouts[0] == live_e2e_suite.DEFAULT_GODZILLA_CHILD_SUITE_TIMEOUT_SECONDS


def test_run_suite_command_uses_extended_live_process_monitor_timeout(monkeypatch) -> None:
    observed_timeouts: list[float] = []

    class FakeProcess:
        pid = 4321

        def wait(self, timeout=None):
            observed_timeouts.append(timeout)
            raise subprocess.TimeoutExpired(cmd=["python", "live-process-monitor.py"], timeout=timeout or 0.0)

    monkeypatch.setattr(live_e2e_suite.subprocess, "Popen", lambda _command: FakeProcess())
    monkeypatch.setattr(live_e2e_suite, "terminate_process_tree", lambda _process_id, command=None: {"return_code": 0})

    assert live_e2e_suite.run_suite_command(["python", r"C:\tests\live-process-monitor.py"]) == live_e2e_suite.SUITE_TIMEOUT_RETURN_CODE
    assert observed_timeouts[0] == live_e2e_suite.DEFAULT_LIVE_PROCESS_MONITOR_TIMEOUT_SECONDS


def test_timeout_command_markers_include_launcher_and_script() -> None:
    assert live_e2e_suite.timeout_command_markers(
        [r"C:\Python313\python.exe", r"C:\tests\godzilla-local-swarm.py", "--flag"]
    ) == ["python.exe", "godzilla-local-swarm.py"]


def test_terminate_process_tree_reports_windows_cleanup_exception(monkeypatch) -> None:
    monkeypatch.setattr(live_e2e_suite.os, "name", "nt")
    monkeypatch.setattr(
        live_e2e_suite.windows_processes,
        "terminate_process_tree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("wmi unavailable")),
    )

    result = live_e2e_suite.terminate_process_tree(4321, ["python.exe", "godzilla-local-swarm.py"])

    assert result["return_code"] == 1
    assert result["type"] == "RuntimeError"
    assert "wmi unavailable" in result["error"]


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
            str(tmp_path / "workspaces" / "workspace"),
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
            str(tmp_path / "workspaces" / "workspace"),
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
    assert summary["status"] == "failed"
    assert summary["strict_success_required"] is True
    assert summary["suites"][0]["status"] == "failed"


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
            str(tmp_path / "workspaces" / "workspace"),
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
            str(tmp_path / "workspaces" / "workspace"),
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


def test_live_process_monitor_uses_materialized_profile_root(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    profile_seed_dir = tmp_path / "install" / "profiles" / "emulebb" / "config"
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--suite",
            "live-process-monitor",
            "--profile-seed-dir",
            str(profile_seed_dir),
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert script_name(commands[0]) == "live-process-monitor.py"
    assert option_values(commands[0], "--profile-seed-dir") == [str(profile_seed_dir.resolve())]
    assert option_values(commands[0], "--profile-dir") == [str(profile_seed_dir.parent.resolve())]


def test_live_process_monitor_profile_dir_is_separate_from_synthetic_seed(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    profile_dir = tmp_path / "install" / "profiles" / "emulebb"
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--suite",
            "live-process-monitor",
            "--live-process-monitor-profile-dir",
            str(profile_dir),
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert script_name(commands[0]) == "live-process-monitor.py"
    assert "--profile-seed-dir" not in commands[0]
    assert option_values(commands[0], "--profile-dir") == [str(profile_dir.resolve())]
    assert summary["live_process_monitor_profile_dir"] == str(profile_dir.resolve())


def test_package_helper_profile_forwards_dependency_options(tmp_path: Path, monkeypatch) -> None:
    commands: list[list[str]] = []
    cache_root = tmp_path / "arr-cache"
    prowlarr_exe = tmp_path / "tools" / "Prowlarr.exe"
    radarr_exe = tmp_path / "tools" / "Radarr.exe"
    sonarr_exe = tmp_path / "tools" / "Sonarr.exe"
    monkeypatch.setattr(
        live_e2e_suite,
        "run_suite_command",
        lambda command: commands.append(command) or 0,
    )

    summary = live_e2e_suite.run_live_e2e_suite(
        parse_args(
            "--workspace-root",
            str(tmp_path / "workspaces" / "workspace"),
            "--profile",
            "package-helpers",
            "--dependency-mode",
            "auto-download",
            "--dependency-channel",
            "latest",
            "--dependency-cache-root",
            str(cache_root),
            "--refresh-dependencies",
            "--prowlarr-exe",
            str(prowlarr_exe),
            "--radarr-exe",
            str(radarr_exe),
            "--sonarr-exe",
            str(sonarr_exe),
        ),
        FakeHarnessCliCommon(tmp_path),
    )

    assert summary["status"] == "passed"
    assert summary["dependency_resolution"] == {
        "mode": "auto-download",
        "channel": "latest",
        "cache_root": str(cache_root),
        "refresh": True,
    }
    assert [script_name(command) for command in commands] == ["package-helper-integration.py"]
    command = commands[0]
    assert option_values(command, "--dependency-mode") == ["auto-download"]
    assert option_values(command, "--dependency-channel") == ["latest"]
    assert option_values(command, "--dependency-cache-root") == [str(cache_root.resolve())]
    assert "--refresh-dependencies" in command
    assert option_values(command, "--prowlarr-exe") == [str(prowlarr_exe.resolve())]
    assert option_values(command, "--radarr-exe") == [str(radarr_exe.resolve())]
    assert option_values(command, "--sonarr-exe") == [str(sonarr_exe.resolve())]


def test_package_helper_integration_uses_emulebb_release_asset_scripts() -> None:
    script_text = (Path(__file__).resolve().parents[2] / "scripts" / "package-helper-integration.py").read_text(encoding="utf-8")

    assert "workspace_layout.resolve_workspace_repo(paths.workspace_root, \"build\")" in script_text
    assert "workspace_layout.resolve_workspace_repo(paths.workspace_root, \"amutorrent\")" in script_text
    assert '"release_assets" / "emulebb" / "scripts"' in script_text
    assert '"release_assets" / "emule" / "scripts"' not in script_text
    assert '"repos" / "emulebb-build"' not in script_text


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
    assert "--profile-cpu" in completed.stdout
    assert "--profile-cpu-stack" in completed.stdout
    assert "--profile-memory" in completed.stdout
    assert "--profile-resource-interval-seconds" in completed.stdout
    assert "--test-network" in completed.stdout
    assert "--admin-volume-fixtures" in completed.stdout
    assert "--vhd-size-mb" in completed.stdout
    assert "--mount-root" in completed.stdout
    assert "--keep-admin-fixtures" in completed.stdout
    assert "--dependency-mode" in completed.stdout
    assert "--dependency-channel" in completed.stdout
    assert "--dependency-cache-root" in completed.stdout
    assert "--refresh-dependencies" in completed.stdout
    assert "--prowlarr-exe" in completed.stdout
    assert "--radarr-exe" in completed.stdout
    assert "--sonarr-exe" in completed.stdout
    assert "--skip-live-seed-refresh" in completed.stdout
    assert "--profile-seed-dir" in completed.stdout
    assert "--seed" + "-config-dir" not in completed.stdout
