from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness.build_tests import (
    BuildTestsConfig,
    build_msbuild_arguments,
    format_duration,
    get_build_log_paths,
    resolve_build_config,
)


def make_config(tmp_path: Path) -> BuildTestsConfig:
    return BuildTestsConfig(
        test_repo_root=tmp_path / "repos" / "emulebb-build-tests",
        workspace_root=tmp_path / "workspaces" / "workspace",
        output_root=tmp_path / "emulebb-output",
        app_root=tmp_path / "workspaces" / "workspace" / "app" / "emulebb-main",
        configuration="Debug",
        platform="x64",
        build_output_mode="ErrorsOnly",
        clean=False,
        run_tests=False,
        out_file=None,
        allow_test_failure=False,
        build_tag="tag",
        build_log_session_stamp="20260421T120000Z",
        skip_tracked_file_privacy_guard=False,
    )


def test_build_log_paths_match_output_root_layout(tmp_path: Path) -> None:
    config = make_config(tmp_path)

    paths = get_build_log_paths(config)

    assert paths.text_log_path == tmp_path / "emulebb-output" / "logs" / "builds" / "20260421T120000Z" / "emule-tests-tag-debug-x64.log"
    assert paths.binary_log_path.name == "emule-tests-tag-debug-x64.binlog"


def test_build_msbuild_arguments_match_native_test_contract(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    paths = get_build_log_paths(config)

    arguments = build_msbuild_arguments(config, paths)

    assert str(config.test_repo_root / "emule-tests.vcxproj") == arguments[0]
    assert "/t:Build" in arguments
    assert f"/p:AppRoot={config.app_root}" in arguments
    assert f"/p:WorkspaceRoot={config.workspace_root}" in arguments
    assert "/p:BuildTag=tag" in arguments
    assert f"/p:OutDir={config.output_root / 'builds' / 'tests' / 'tag' / 'x64' / 'Debug' / 'bin'}\\" in arguments
    assert f"/p:IntDir={config.output_root / 'builds' / 'tests' / 'tag' / 'x64' / 'Debug' / 'obj'}\\" in arguments
    assert "/clp:ErrorsOnly" in arguments


def test_resolve_build_config_requires_output_root_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.delenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", raising=False)

    with pytest.raises(RuntimeError, match="EMULEBB_WORKSPACE_OUTPUT_ROOT must be set"):
        resolve_build_config(
            test_repo_root=tmp_path / "repos" / "emulebb-build-tests",
            app_root=tmp_path / "workspaces" / "workspace" / "app" / "emulebb-main",
            configuration="Debug",
            platform="x64",
            build_output_mode="ErrorsOnly",
            clean=False,
            run_tests=False,
            out_file=None,
            allow_test_failure=False,
            build_tag="tag",
            build_log_session_stamp="20260421T120000Z",
            skip_tracked_file_privacy_guard=True,
            test_arguments=(),
        )


def test_format_duration_keeps_compact_summary_style() -> None:
    assert format_duration(1.25) == "1.2s"
    assert format_duration(12.5) == "12s"
