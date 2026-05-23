from __future__ import annotations

from pathlib import Path

from emule_test_harness.paths import get_build_tag, get_test_binary_path, make_file_token


def test_make_file_token_matches_workspace_safe_filename_shape() -> None:
    assert make_file_token('emule tests: Debug/x64?') == "emule-tests-Debug-x64"
    assert make_file_token("   ") == "build"


def test_get_build_tag_matches_workspace_and_app_segments(tmp_path: Path) -> None:
    workspace_root = tmp_path / "owner with space" / "workspaces" / "workspace"
    app_root = workspace_root / "app" / "emulebb-main"
    app_root.mkdir(parents=True)

    assert get_build_tag(workspace_root, app_root) == "owner_with_space-workspace-emulebb-main"


def test_get_test_binary_path_uses_existing_repo_layout(tmp_path: Path) -> None:
    assert get_test_binary_path(
        tmp_path,
        build_tag="tag",
        platform="x64",
        configuration="Debug",
    ) == tmp_path / "build" / "tag" / "x64" / "Debug" / "emule-tests.exe"
