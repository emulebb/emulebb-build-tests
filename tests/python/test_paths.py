from __future__ import annotations

from pathlib import Path

from emule_test_harness.paths import get_build_tag, get_test_binary_path, make_file_token


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_make_file_token_matches_workspace_safe_filename_shape() -> None:
    assert make_file_token('emule tests: Debug/x64?') == "emule-tests-Debug-x64"
    assert make_file_token("   ") == "build"


def test_get_build_tag_matches_workspace_and_app_segments(tmp_path: Path) -> None:
    workspace_root = tmp_path / "owner with space" / "workspaces" / "workspace"
    app_root = workspace_root / "app" / "emulebb-main"
    app_root.mkdir(parents=True)

    assert get_build_tag(workspace_root, app_root) == "owner_with_space-workspace-emulebb-main"


def test_get_test_binary_path_uses_output_root_layout(tmp_path: Path) -> None:
    assert get_test_binary_path(
        build_tag="tag",
        platform="x64",
        configuration="Debug",
        output_root=tmp_path / "emulebb-output",
    ) == tmp_path / "emulebb-output" / "builds" / "tests" / "tag" / "x64" / "Debug" / "bin" / "emule-tests.exe"


def test_production_harness_scripts_do_not_expose_workspace_root_argument() -> None:
    roots = (repo_root() / "scripts", repo_root() / "emule_test_harness")
    offenders = [
        path.relative_to(repo_root())
        for root in roots
        for path in root.rglob("*.py")
        if "--workspace-root" in path.read_text(encoding="utf-8")
    ]

    assert offenders == []


def test_harness_paths_do_not_expose_workspace_state_helper() -> None:
    paths_text = (repo_root() / "emule_test_harness" / "paths.py").read_text(encoding="utf-8")

    assert "get_workspace_state_root" not in paths_text
