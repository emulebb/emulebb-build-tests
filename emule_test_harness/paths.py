"""Path helpers shared by Python harness runners."""

from __future__ import annotations

import os
import re
from pathlib import Path

WORKSPACE_NAME = "workspace"
WORKSPACE_ROOT_ENV = "EMULEBB_WORKSPACE_ROOT"
WORKSPACE_OUTPUT_ROOT_ENV = "EMULEBB_WORKSPACE_OUTPUT_ROOT"
TEST_ARTIFACTS_DIR_NAME = "test-artifacts"
TEST_REPORTS_DIR_NAME = "test-reports"


def make_file_token(value: str) -> str:
    """Converts a free-form string into the file token used by test reports."""

    token = re.sub(r'[\\/:*?"<>|\s]+', "-", value)
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", token).strip("-")
    return token or "build"


def get_build_tag(workspace_root: Path, app_root: Path | None = None) -> str:
    """Returns the native-test build tag used by build and report wrappers."""

    resolved_workspace_root = workspace_root.resolve()
    workspace_leaf = resolved_workspace_root.name
    workspaces_root = resolved_workspace_root.parent
    workspace_owner = workspaces_root.parent.name if workspaces_root.parent else ""
    if not workspace_leaf or not workspace_owner:
        raise RuntimeError(f"Unable to derive build tag from workspace path: {workspace_root}")

    segments = [workspace_owner, workspace_leaf]
    if app_root is not None:
        segments.append(app_root.resolve().name)
    return re.sub(r"[^A-Za-z0-9._-]", "_", "-".join(segments))


def get_emule_workspace_root(test_repo_root: Path) -> Path:
    """Returns the canonical root that owns `repos/` and `workspaces/`."""

    if os.environ.get(WORKSPACE_ROOT_ENV):
        return Path(os.environ[WORKSPACE_ROOT_ENV]).resolve()
    return test_repo_root.resolve().parent.parent


def get_required_emule_workspace_root() -> Path:
    """Returns the mandatory EMULEBB_WORKSPACE_ROOT value."""

    value = os.environ.get(WORKSPACE_ROOT_ENV, "").strip()
    if not value:
        raise RuntimeError(f"{WORKSPACE_ROOT_ENV} must be set.")
    return Path(value).resolve()


def get_workspace_output_root() -> Path:
    """Returns the mandatory EMULEBB_WORKSPACE_OUTPUT_ROOT value."""

    value = os.environ.get(WORKSPACE_OUTPUT_ROOT_ENV, "").strip()
    if not value:
        raise RuntimeError(f"{WORKSPACE_OUTPUT_ROOT_ENV} must be set.")
    output_root = Path(value).resolve()
    workspace_root = get_required_emule_workspace_root()
    if path_is_relative_to(output_root, workspace_root):
        raise RuntimeError(f"{WORKSPACE_OUTPUT_ROOT_ENV} must not be inside {WORKSPACE_ROOT_ENV}: {output_root}")
    return output_root


def get_default_workspace_root(test_repo_root: Path, workspace_name: str = WORKSPACE_NAME) -> Path:
    """Returns the default managed workspace root for one test checkout."""

    return get_emule_workspace_root(test_repo_root) / "workspaces" / workspace_name


def get_test_artifacts_root(workspace_root: Path) -> Path:
    """Returns the canonical scratch artifact root for test harness runs."""

    return get_workspace_output_root() / "artifacts"


def get_test_reports_root(workspace_root: Path) -> Path:
    """Returns the canonical published report root for test harness runs."""

    return get_workspace_output_root() / "reports"


def _normalized_path_text(path: Path) -> str:
    return os.path.normcase(str(path.resolve()))


def path_is_relative_to(path: Path, root: Path) -> bool:
    """Returns whether `path` is equal to or below `root` after resolution."""

    path_text = _normalized_path_text(path)
    root_text = _normalized_path_text(root).rstrip("\\/")
    return path_text == root_text or path_text.startswith(root_text + os.sep)


def windows_temp_roots() -> tuple[Path, ...]:
    """Returns known Windows temp roots that must not hold harness outcomes."""

    roots: list[Path] = []
    for variable_name in ("TEMP", "TMP"):
        value = os.environ.get(variable_name)
        if value:
            roots.append(Path(value))
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        roots.append(Path(local_app_data) / "Temp")

    unique_roots: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = _normalized_path_text(root)
        if key not in seen:
            seen.add(key)
            unique_roots.append(root)
    return tuple(unique_roots)


def reject_windows_temp_path(path: Path, purpose: str) -> None:
    """Rejects harness output roots below Windows temp directories."""

    for temp_root in windows_temp_roots():
        if path_is_relative_to(path, temp_root):
            raise RuntimeError(f"{purpose} must be under the workspace output root, not Windows temp: {path.resolve()}")


def get_test_binary_path(
    *,
    build_tag: str,
    platform: str,
    configuration: str,
    output_root: Path | None = None,
) -> Path:
    """Returns the expected emule-tests.exe path for one build tag."""

    root = output_root.resolve() if output_root is not None else get_workspace_output_root()
    return root / "builds" / "tests" / build_tag / platform / configuration / "bin" / "emule-tests.exe"
