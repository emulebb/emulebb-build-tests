"""Shared Python-first CLI helpers for the canonical live/UI harness entrypoints."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

WORKSPACE_NAME = "v0.72a"
DEFAULT_APP_VARIANTS = ("main", "community", "broadband")
REPORT_EXCLUDED_DIRECTORY_NAMES = frozenset(("shared-hash-root",))


@dataclass(frozen=True)
class HarnessRunPaths:
    """Resolved filesystem layout for one canonical harness invocation."""

    repo_root: Path
    workspace_root: Path
    app_root: Path
    app_exe: Path
    seed_config_dir: Path
    configuration: str
    suite_name: str
    source_artifacts_dir: Path
    run_report_dir: Path
    latest_report_dir: Path
    keep_source_artifacts: bool


def read_json_file(path: Path):
    """Reads one JSON artifact when present."""

    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_file(path: Path, payload) -> None:
    """Writes one JSON artifact with stable formatting."""

    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def get_repo_root(script_file: str | Path) -> Path:
    """Returns the `eMule-build-tests` repo root from one script path."""

    return Path(script_file).resolve().parent.parent


def get_emule_workspace_root(repo_root: Path) -> Path:
    """Returns the canonical eMule workspace root that owns `repos/` and `workspaces/`."""

    if os.environ.get("EMULE_WORKSPACE_ROOT"):
        return Path(os.environ["EMULE_WORKSPACE_ROOT"]).resolve()
    return (repo_root / ".." / "..").resolve()


def get_default_workspace_root(repo_root: Path, workspace_name: str = WORKSPACE_NAME) -> Path:
    """Returns the canonical default workspace variant root."""

    return (get_emule_workspace_root(repo_root) / "workspaces" / workspace_name).resolve()


def sanitize_report_token(value: str) -> str:
    """Normalizes one path-ish value into a stable report token."""

    token = "".join(char if char.isalnum() or char in "._-" else "-" for char in value).strip("-")
    while "--" in token:
        token = token.replace("--", "-")
    return token or "run"


def get_app_variant_label(app_exe: Path) -> str:
    """Returns the app-root label used in report directory names."""

    return app_exe.resolve().parent.parent.parent.parent.name


def resolve_app_root(
    repo_root: Path,
    workspace_root: Path | None = None,
    app_root: str | Path | None = None,
    preferred_variant_names: tuple[str, ...] = DEFAULT_APP_VARIANTS,
) -> Path:
    """Resolves the canonical app root without a PowerShell helper."""

    if app_root:
        resolved = Path(app_root).resolve()
        if not resolved.is_dir():
            raise RuntimeError(f"Explicit app root does not exist: {resolved}")
        return resolved

    resolved_workspace_root = (workspace_root or get_default_workspace_root(repo_root)).resolve()
    app_parent = resolved_workspace_root / "app"
    if not app_parent.is_dir():
        raise RuntimeError(f"Workspace app directory does not exist: {app_parent}")

    candidates: list[Path] = [app_parent / "eMule-main"]
    for variant_name in preferred_variant_names:
        if variant_name == "main":
            continue
        candidates.append(app_parent / f"eMule-v0.72a-{variant_name}")
        candidates.append(app_parent / f"eMule-{variant_name}")
    candidates.extend(sorted(path for path in app_parent.glob("eMule-*") if path.is_dir()))

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_dir():
            return resolved

    raise RuntimeError(f"Unable to resolve a canonical app root under '{app_parent}'.")


def resolve_app_executable(
    repo_root: Path,
    configuration: str,
    workspace_root: Path | None = None,
    app_root: str | Path | None = None,
    app_exe: str | Path | None = None,
) -> tuple[Path, Path, Path]:
    """Resolves the concrete app executable plus its workspace/app roots."""

    resolved_workspace_root = (workspace_root or get_default_workspace_root(repo_root)).resolve()
    resolved_app_root = resolve_app_root(
        repo_root=repo_root,
        workspace_root=resolved_workspace_root,
        app_root=app_root,
    )
    if app_exe:
        resolved_app_exe = Path(app_exe).resolve()
    else:
        resolved_app_exe = (resolved_app_root / "srchybrid" / "x64" / configuration / "emule.exe").resolve()
    if not resolved_app_exe.is_file():
        raise RuntimeError(f"App executable was not found at '{resolved_app_exe}'.")
    return resolved_workspace_root, resolved_app_root, resolved_app_exe


def prepare_run_paths(
    *,
    script_file: str | Path,
    suite_name: str,
    configuration: str,
    workspace_root: str | Path | None = None,
    app_root: str | Path | None = None,
    app_exe: str | Path | None = None,
    artifacts_dir: str | Path | None = None,
    keep_artifacts: bool = False,
) -> HarnessRunPaths:
    """Resolves canonical paths for one Python-first harness invocation."""

    repo_root = get_repo_root(script_file)
    resolved_workspace_root, resolved_app_root, resolved_app_exe = resolve_app_executable(
        repo_root=repo_root,
        configuration=configuration,
        workspace_root=Path(workspace_root).resolve() if workspace_root else None,
        app_root=app_root,
        app_exe=app_exe,
    )
    seed_config_dir = (repo_root / "manifests" / "live-profile-seed" / "config").resolve()
    if not seed_config_dir.is_dir():
        raise RuntimeError(f"Seed config directory was not found at '{seed_config_dir}'.")

    report_root = repo_root / "reports"
    suite_report_root = report_root / suite_name
    report_stamp = time.strftime("%Y%m%d-%H%M%S")
    report_label = f"{report_stamp}-{sanitize_report_token(get_app_variant_label(resolved_app_exe))}-{configuration.lower()}"
    source_artifacts_dir = (
        Path(artifacts_dir).resolve()
        if artifacts_dir
        else Path(tempfile.gettempdir(), f"emule-{suite_name}-{uuid.uuid4().hex}").resolve()
    )
    source_artifacts_dir.mkdir(parents=True, exist_ok=True)

    return HarnessRunPaths(
        repo_root=repo_root,
        workspace_root=resolved_workspace_root,
        app_root=resolved_app_root,
        app_exe=resolved_app_exe,
        seed_config_dir=seed_config_dir,
        configuration=configuration,
        suite_name=suite_name,
        source_artifacts_dir=source_artifacts_dir,
        run_report_dir=(suite_report_root / report_label).resolve(),
        latest_report_dir=(report_root / f"{suite_name}-latest").resolve(),
        keep_source_artifacts=keep_artifacts or bool(artifacts_dir),
    )


def publish_directory_snapshot(source_directory: Path, destination_directory: Path) -> None:
    """Refreshes one report directory from another directory snapshot."""

    if destination_directory.exists():
        shutil.rmtree(destination_directory)
    destination_directory.mkdir(parents=True, exist_ok=True)
    for entry in source_directory.iterdir():
        if entry.is_dir() and entry.name in REPORT_EXCLUDED_DIRECTORY_NAMES:
            continue
        target_path = destination_directory / entry.name
        if entry.is_dir():
            shutil.copytree(
                entry,
                target_path,
                ignore=shutil.ignore_patterns(*REPORT_EXCLUDED_DIRECTORY_NAMES),
            )
        else:
            shutil.copy2(entry, target_path)


def publish_run_artifacts(paths: HarnessRunPaths) -> None:
    """Copies the source artifact directory into the stable report directory."""

    paths.run_report_dir.parent.mkdir(parents=True, exist_ok=True)
    publish_directory_snapshot(paths.source_artifacts_dir, paths.run_report_dir)


def publish_latest_report(paths: HarnessRunPaths) -> None:
    """Refreshes the suite-level `-latest` snapshot from one run report."""

    publish_directory_snapshot(paths.run_report_dir, paths.latest_report_dir)


def cleanup_source_artifacts(paths: HarnessRunPaths) -> None:
    """Removes transient source artifacts when the invocation does not retain them."""

    if paths.keep_source_artifacts:
        return
    if paths.source_artifacts_dir.exists():
        shutil.rmtree(paths.source_artifacts_dir)


def build_live_ui_summary(
    *,
    status: str,
    paths: HarnessRunPaths,
    result_filename: str = "result.json",
    error_message: str = "",
) -> dict[str, object]:
    """Builds the UI-harness summary shape consumed by the shared summary publisher."""

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": status,
        "app_exe": str(paths.app_exe),
        "configuration": paths.configuration,
        "artifact_dir": str(paths.run_report_dir),
        "latest_report_dir": str(paths.latest_report_dir),
        "source_artifact_dir": str(paths.source_artifacts_dir),
        "result": read_json_file(paths.run_report_dir / result_filename),
        "error": error_message or None,
    }


def build_startup_profiles_summary(
    *,
    status: str,
    paths: HarnessRunPaths,
    shared_root: Path,
    result_filename: str = "startup-profiles-summary.json",
    error_message: str = "",
) -> dict[str, object]:
    """Builds the startup-profile wrapper summary consumed by the shared harness summary."""

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": status,
        "app_exe": str(paths.app_exe),
        "configuration": paths.configuration,
        "shared_root": str(shared_root.resolve()),
        "artifact_dir": str(paths.run_report_dir),
        "latest_report_dir": str(paths.latest_report_dir),
        "source_artifact_dir": str(paths.source_artifacts_dir),
        "result": read_json_file(paths.run_report_dir / result_filename),
        "error": error_message or None,
    }


def find_python_executable() -> str:
    """Returns the preferred Python 3 executable for the harness repo."""

    for candidate in ("python", "py"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise RuntimeError("Python 3 was not found on PATH.")


def update_harness_summary(
    repo_root: Path,
    *,
    live_ui_summary_path: Path | None = None,
    startup_profile_summary_path: Path | None = None,
) -> None:
    """Refreshes the shared harness summary using the canonical Python publisher."""

    python_executable = find_python_executable()
    command = [python_executable]
    if Path(python_executable).stem.lower() == "py":
        command.append("-3")
    command.extend(
        [
            str((repo_root / "scripts" / "publish-harness-summary.py").resolve()),
            "--test-repo-root",
            str(repo_root.resolve()),
        ]
    )
    if live_ui_summary_path is not None:
        command.extend(["--live-ui-summary-path", str(live_ui_summary_path.resolve())])
    if startup_profile_summary_path is not None:
        command.extend(["--startup-profile-summary-path", str(startup_profile_summary_path.resolve())])
    subprocess.run(command, check=True)
