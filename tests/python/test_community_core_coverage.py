from __future__ import annotations

import json
import os
import time
from pathlib import Path

from emule_test_harness.community_core_coverage import (
    build_config,
    get_latest_coverage_summary_path,
    run_live_rest_e2e_for_community_summary,
)


def test_get_latest_coverage_summary_path_returns_newest_summary(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces" / "workspace"
    older = workspace_root / "state" / "test-reports" / "native-coverage" / "older" / "coverage-summary.json"
    newer = workspace_root / "state" / "test-reports" / "native-coverage" / "newer" / "coverage-summary.json"
    older.parent.mkdir(parents=True)
    newer.parent.mkdir(parents=True)
    older.write_text(json.dumps({"name": "older"}), encoding="utf-8")
    newer.write_text(json.dumps({"name": "newer"}), encoding="utf-8")
    old_time = time.time() - 100
    new_time = time.time()
    older.touch()
    newer.touch()

    os.utime(older, (old_time, old_time))
    os.utime(newer, (new_time, new_time))

    assert get_latest_coverage_summary_path(workspace_root) == newer


def test_build_config_resolves_default_app_roots(tmp_path: Path) -> None:
    test_repo_root = tmp_path / "repos" / "emulebb-build-tests"
    workspace_root = tmp_path / "workspaces" / "workspace"
    (workspace_root / "app" / "emulebb-main").mkdir(parents=True)
    (workspace_root / "app" / "emulebb-community-baseline").mkdir(parents=True)

    config = build_config(
        test_repo_root=test_repo_root,
        workspace_root=workspace_root,
        main_app_root=None,
        community_app_root=None,
        configuration="Debug",
        platform="x64",
        preferred_coverage_root=None,
    )

    assert config.main_app_root == workspace_root / "app" / "emulebb-main"
    assert config.community_app_root == workspace_root / "app" / "emulebb-community-baseline"
    assert config.include_live_rest_e2e is False


def test_optional_live_rest_e2e_builds_main_only_command(tmp_path: Path, monkeypatch) -> None:
    test_repo_root = tmp_path / "repos" / "emulebb-build-tests"
    workspace_root = tmp_path / "workspaces" / "workspace"
    main_app_root = workspace_root / "app" / "emulebb-main"
    community_app_root = workspace_root / "app" / "emulebb-community-baseline"
    main_app_root.mkdir(parents=True)
    community_app_root.mkdir(parents=True)
    captured: dict[str, object] = {}

    def fake_run(command, check=False, env=None):
        captured["command"] = command
        captured["check"] = check
        captured["env"] = env
        return type("Completed", (), {"returncode": 0})()

    monkeypatch.setattr("emule_test_harness.community_core_coverage.subprocess.run", fake_run)
    config = build_config(
        test_repo_root=test_repo_root,
        workspace_root=workspace_root,
        main_app_root=main_app_root,
        community_app_root=community_app_root,
        configuration="Debug",
        platform="x64",
        preferred_coverage_root=None,
        include_live_rest_e2e=True,
        rest_coverage_budget="contract",
        rest_stress_budget="smoke",
        rest_app_scope="main-only",
    )

    summary = run_live_rest_e2e_for_community_summary(config, tmp_path / "report")

    command = captured["command"]
    assert isinstance(command, list)
    assert summary["status"] == "passed"
    assert "--app-root" in command
    assert str(main_app_root) in command
    assert "--rest-coverage-budget" in command
    assert "contract" in command
    assert "--rest-stress-budget" in command
    assert "smoke" in command
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["EMULE_WORKSPACE_ROOT"] == str(tmp_path)
    assert summary["rest_coverage_budget"] == "contract"
    assert summary["rest_stress_budget"] == "smoke"
