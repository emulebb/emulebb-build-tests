from __future__ import annotations

from pathlib import Path

from emule_test_harness import campaign_scenarios, live_e2e_suite, windows_vm_host, windows_vm_profile_smoke


def test_local_swarm_contract_records_selected_tier() -> None:
    check = windows_vm_profile_smoke.local_swarm_contract_check("search-ui-local-swarm-vm", 3)

    assert check["status"] == "passed"
    assert check["details"]["selectedSwarmTier"] == 3
    assert check["details"]["swarmTiers"] == [1, 2, 3]
    assert check["details"]["vmProfile"] == "search-ui-local-swarm-vm"
    assert check["details"]["localSuites"] == ["local-ed2k-search-soak", "local-kad-swarm"]


def test_profile_smoke_parser_accepts_swarm_tier() -> None:
    args = windows_vm_profile_smoke.build_parser().parse_args(
        [
            "--profile",
            "search-ui-local-swarm-vm",
            "--root",
            "C:/tmp/root",
            "--target",
            "win10",
            "--package-zip",
            "C:/tmp/package.zip",
            "--username",
            "emulebbtest",
            "--password",
            "a",
            "--swarm-tier",
            "2",
            "--harness-root",
            "C:/tmp/harness",
            "--ed2k-server-exe",
            "C:/tmp/harness/tools/goed2k-server.exe",
            "--client2-app-exe",
            "C:/tmp/harness/tools/tracing-harness/emule.exe",
            "--amule-daemon-exe",
            "C:/tmp/harness/tools/amule/bin/amuled.exe",
            "--amule-control-exe",
            "C:/tmp/harness/tools/amule/bin/amulecmd.exe",
            "--local-swarm-mode",
            "execute",
            "--lan-bind-addr",
            "192.0.2.10",
        ]
    )

    assert args.swarm_tier == 2
    assert str(args.harness_root).replace("\\", "/").endswith("C:/tmp/harness")
    assert str(args.ed2k_server_exe).replace("\\", "/").endswith("C:/tmp/harness/tools/goed2k-server.exe")
    assert str(args.client2_app_exe).replace("\\", "/").endswith("C:/tmp/harness/tools/tracing-harness/emule.exe")
    assert str(args.amule_daemon_exe).replace("\\", "/").endswith("C:/tmp/harness/tools/amule/bin/amuled.exe")
    assert str(args.amule_control_exe).replace("\\", "/").endswith("C:/tmp/harness/tools/amule/bin/amulecmd.exe")
    assert args.local_swarm_mode == "execute"
    assert args.lan_bind_addr == "192.0.2.10"


def test_local_swarm_payload_check_accepts_staged_harness(tmp_path) -> None:
    harness_root = tmp_path / "harness"
    (harness_root / "emule_test_harness").mkdir(parents=True)
    (harness_root / "emule_test_harness" / "live_e2e_suite.py").write_text("", encoding="utf-8")
    scripts = harness_root / "scripts"
    scripts.mkdir()
    for name in windows_vm_host.LOCAL_SWARM_PAYLOAD_SCRIPT_FILES:
        (scripts / name).write_text("", encoding="utf-8")

    check = windows_vm_profile_smoke.local_swarm_payload_check(harness_root)

    assert check["status"] == "passed"
    assert check["details"]["expectedCount"] == len(windows_vm_host.LOCAL_SWARM_PAYLOAD_SCRIPT_FILES) + 1


def test_local_swarm_payload_check_reports_missing_harness() -> None:
    check = windows_vm_profile_smoke.local_swarm_payload_check(None)

    assert check["status"] == "failed"


def test_prepare_staged_workspace_manifest_mirrors_package_helper_scripts(tmp_path) -> None:
    root = tmp_path / "guest-root"
    app_root = tmp_path / "expanded" / "eMuleBB"
    scripts_root = app_root / "scripts"
    scripts_root.mkdir(parents=True)
    (scripts_root / "Register-Prowlarr.ps1").write_text("# helper\n", encoding="utf-8")
    (scripts_root / "ignored.txt").write_text("ignored\n", encoding="utf-8")

    workspace_root = windows_vm_profile_smoke.prepare_staged_workspace_manifest(root, app_root)

    deps_json = (workspace_root / "deps.json").read_text(encoding="utf-8")
    staged_scripts = workspace_root / "repos" / "emulebb-build" / "emule_workspace" / "release_assets" / "emulebb" / "scripts"
    assert '"build": "repos/emulebb-build"' in deps_json
    assert (staged_scripts / "Register-Prowlarr.ps1").read_text(encoding="utf-8") == "# helper\n"
    assert not (staged_scripts / "ignored.txt").exists()


def test_local_swarm_plan_check_reuses_staged_live_suite_planner(tmp_path) -> None:
    repo_root = Path(windows_vm_profile_smoke.__file__).resolve().parents[1]
    app_root = tmp_path / "expanded" / "eMuleBB"
    app_root.mkdir(parents=True)
    (app_root / "emulebb.exe").write_text("", encoding="utf-8")
    ed2k_server_exe = tmp_path / "harness" / "tools" / "goed2k-server.exe"
    ed2k_server_exe.parent.mkdir(parents=True)
    ed2k_server_exe.write_text("", encoding="utf-8")
    client2_app_exe = tmp_path / "harness" / "tools" / "tracing-harness" / "emule.exe"
    amule_daemon_exe = tmp_path / "harness" / "tools" / "amule" / "bin" / "amuled.exe"
    amule_control_exe = tmp_path / "harness" / "tools" / "amule" / "bin" / "amulecmd.exe"
    for path in (client2_app_exe, amule_daemon_exe, amule_control_exe):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    check = windows_vm_profile_smoke.local_swarm_plan_check(
        "search-ui-local-swarm-vm",
        1,
        repo_root,
        tmp_path / "guest-root",
        app_root,
        tmp_path / "artifacts",
        ed2k_server_exe=ed2k_server_exe,
        client2_app_exe=client2_app_exe,
        amule_daemon_exe=amule_daemon_exe,
        amule_control_exe=amule_control_exe,
        lan_bind_addr="192.0.2.10",
    )

    command_names = [Path(command[1]).name for command in check["details"]["commands"]]
    assert check["status"] == "passed"
    assert check["details"]["summaryStatus"] == "planned"
    assert set(check["details"]["suiteNames"]) == {"local-ed2k-search-soak", "local-kad-swarm", "godzilla-local-swarm"}
    assert set(command_names) == {"local-ed2k-search-soak.py", "local-kad-swarm.py", "godzilla-local-swarm.py"}
    assert check["details"]["testNetwork"] == "default"
    assert check["details"]["tierOptions"]["total_client_count"] == 4
    assert check["details"]["ed2kServerExe"] == str(ed2k_server_exe)
    assert check["details"]["client2AppExe"] == str(client2_app_exe)
    assert check["details"]["amuleDaemonExe"] == str(amule_daemon_exe)
    assert check["details"]["amuleControlExe"] == str(amule_control_exe)
    assert check["details"]["lanBindAddr"] == "192.0.2.10"
    for command in check["details"]["commands"]:
        assert "--lan-bind-addr" in command
        assert "192.0.2.10" in command
        if Path(command[1]).name in {"local-ed2k-search-soak.py", "godzilla-local-swarm.py"}:
            assert "--ed2k-server-exe" in command
        if Path(command[1]).name == "godzilla-local-swarm.py":
            assert "--client2-app-exe" in command
            assert "--amule-daemon-exe" in command
            assert "--amule-control-exe" in command


def test_all_reusable_campaign_vm_profiles_plan_declared_local_suites(tmp_path) -> None:
    repo_root = Path(windows_vm_profile_smoke.__file__).resolve().parents[1]
    script_by_suite = {spec.name: spec.script_name for spec in live_e2e_suite.SUITE_SPECS}
    app_root = tmp_path / "expanded" / "eMuleBB"
    app_root.mkdir(parents=True)
    (app_root / "emulebb.exe").write_text("", encoding="utf-8")
    ed2k_server_exe = tmp_path / "harness" / "tools" / "goed2k-server.exe"
    client2_app_exe = tmp_path / "harness" / "tools" / "tracing-harness" / "emule.exe"
    amule_daemon_exe = tmp_path / "harness" / "tools" / "amule" / "bin" / "amuled.exe"
    amule_control_exe = tmp_path / "harness" / "tools" / "amule" / "bin" / "amulecmd.exe"
    for path in (ed2k_server_exe, client2_app_exe, amule_daemon_exe, amule_control_exe):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    for profile, scenario in campaign_scenarios.REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE.items():
        check = windows_vm_profile_smoke.local_swarm_plan_check(
            profile,
            1,
            repo_root,
            tmp_path / profile / "guest-root",
            app_root,
            tmp_path / profile / "artifacts",
            ed2k_server_exe=ed2k_server_exe,
            client2_app_exe=client2_app_exe,
            amule_daemon_exe=amule_daemon_exe,
            amule_control_exe=amule_control_exe,
            lan_bind_addr="192.0.2.10",
        )
        expected_suites = set(scenario.local_suites)
        if scenario.uses_local_swarm:
            expected_suites.add("godzilla-local-swarm")

        assert check["status"] == "passed", (profile, check["details"])
        command_names = {Path(command[1]).name for command in check["details"]["commands"]}
        assert check["details"]["summaryStatus"] == "planned"
        assert set(check["details"]["suiteNames"]) == expected_suites
        assert command_names == {script_by_suite[suite] for suite in expected_suites}


def test_local_swarm_execute_check_runs_live_suite_without_plan_only(tmp_path, monkeypatch) -> None:
    from emule_test_harness import live_e2e_suite

    repo_root = Path(windows_vm_profile_smoke.__file__).resolve().parents[1]
    app_root = tmp_path / "expanded" / "eMuleBB"
    app_root.mkdir(parents=True)
    (app_root / "emulebb.exe").write_text("", encoding="utf-8")
    stopped = []
    observed_plan_only = []

    def fake_run_live_e2e_suite(args, _harness_cli_common):
        observed_plan_only.append(args.plan_only)
        suites = ["godzilla-local-swarm", "local-ed2k-search-soak", "local-kad-swarm"]
        return {
            "status": "passed",
            "suites": [
                {"name": name, "status": "passed", "command": ["python", f"{name}.py"]}
                for name in suites
            ],
        }

    monkeypatch.setattr(windows_vm_profile_smoke, "stop_runtime", lambda: stopped.append(True))
    monkeypatch.setattr(live_e2e_suite, "run_live_e2e_suite", fake_run_live_e2e_suite)

    check = windows_vm_profile_smoke.local_swarm_plan_check(
        "search-ui-local-swarm-vm",
        1,
        repo_root,
        tmp_path / "guest-root",
        app_root,
        tmp_path / "artifacts",
        execution_mode="execute",
        lan_bind_addr="192.0.2.10",
    )

    assert check["name"] == "local-swarm-execute"
    assert check["status"] == "passed"
    assert check["details"]["executionMode"] == "execute"
    assert observed_plan_only == [False]
    assert stopped == [True]
