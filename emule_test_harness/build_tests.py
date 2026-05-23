"""Build orchestration for the shared native `emule-tests.exe` target."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .paths import get_build_tag, make_file_token
from .artifact_names import utc_run_id
from .privacy_guard import PrivacyGuardFailure, run_privacy_guard
from .workspace_layout import get_default_workspace_root, resolve_workspace_app_root


@dataclass(frozen=True)
class BuildTestsConfig:
    """Resolved configuration for one native test build invocation."""

    test_repo_root: Path
    workspace_root: Path
    app_root: Path
    configuration: str
    platform: str
    build_output_mode: str
    clean: bool
    run_tests: bool
    out_file: Path | None
    allow_test_failure: bool
    build_tag: str
    build_log_session_stamp: str
    skip_tracked_file_privacy_guard: bool
    test_arguments: tuple[str, ...] = ()


@dataclass(frozen=True)
class BuildLogPaths:
    """MSBuild text and binary log paths for one native-test build."""

    text_log_path: Path
    binary_log_path: Path


def resolve_build_config(
    *,
    test_repo_root: Path,
    workspace_root: Path | None,
    app_root: Path | None,
    configuration: str,
    platform: str,
    build_output_mode: str,
    clean: bool,
    run_tests: bool,
    out_file: Path | None,
    allow_test_failure: bool,
    build_tag: str | None,
    build_log_session_stamp: str | None,
    skip_tracked_file_privacy_guard: bool,
    test_arguments: Sequence[str],
) -> BuildTestsConfig:
    """Resolves CLI inputs into the build configuration used by the runner."""

    resolved_test_repo_root = test_repo_root.resolve()
    resolved_workspace_root = (workspace_root or get_default_workspace_root(resolved_test_repo_root)).resolve()
    resolved_app_root = app_root.resolve() if app_root is not None else resolve_workspace_app_root(resolved_workspace_root)
    resolved_build_tag = build_tag or get_build_tag(resolved_workspace_root, resolved_app_root)
    return BuildTestsConfig(
        test_repo_root=resolved_test_repo_root,
        workspace_root=resolved_workspace_root,
        app_root=resolved_app_root,
        configuration=configuration,
        platform=platform,
        build_output_mode=build_output_mode,
        clean=clean,
        run_tests=run_tests,
        out_file=out_file.resolve() if out_file is not None else None,
        allow_test_failure=allow_test_failure,
        build_tag=resolved_build_tag,
        build_log_session_stamp=build_log_session_stamp or utc_run_id(),
        skip_tracked_file_privacy_guard=skip_tracked_file_privacy_guard,
        test_arguments=tuple(test_arguments),
    )


def find_msbuild_path() -> Path:
    """Resolves the Visual Studio MSBuild executable path."""

    path_msbuild = shutil.which("MSBuild.exe")
    if path_msbuild:
        return Path(path_msbuild).resolve()

    vswhere_path = find_vswhere_path()
    if vswhere_path is not None:
        completed = subprocess.run(
            [
                str(vswhere_path),
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.Component.MSBuild",
                "-property",
                "installationPath",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        installation_path = completed.stdout.strip().splitlines()[0] if completed.returncode == 0 and completed.stdout.strip() else ""
        if installation_path:
            candidate = Path(installation_path) / "MSBuild" / "Current" / "Bin" / "MSBuild.exe"
            if candidate.is_file():
                return candidate.resolve()

    for base_name in ("ProgramFiles", "ProgramFiles(x86)"):
        base_value = os.environ.get(base_name)
        if not base_value:
            continue
        for edition in ("Enterprise", "Professional", "Community", "BuildTools"):
            candidate = Path(base_value) / "Microsoft Visual Studio" / "2022" / edition / "MSBuild" / "Current" / "Bin" / "MSBuild.exe"
            if candidate.is_file():
                return candidate.resolve()

    raise RuntimeError("MSBuild.exe not found.")


def find_vswhere_path() -> Path | None:
    """Resolves `vswhere.exe` from PATH or default Visual Studio installer locations."""

    path_vswhere = shutil.which("vswhere.exe")
    if path_vswhere:
        return Path(path_vswhere).resolve()
    for base_name in ("ProgramFiles", "ProgramFiles(x86)"):
        base_value = os.environ.get(base_name)
        if not base_value:
            continue
        candidate = Path(base_value) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
        if candidate.is_file():
            return candidate.resolve()
    return None


def get_build_log_directory(workspace_root: Path, build_log_session_stamp: str) -> Path:
    """Returns the per-session build-log directory under workspace state."""

    directory = workspace_root.resolve() / "state" / "build-logs" / build_log_session_stamp
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def get_build_log_paths(config: BuildTestsConfig) -> BuildLogPaths:
    """Returns text and binary MSBuild log paths for one resolved build config."""

    log_directory = get_build_log_directory(config.workspace_root, config.build_log_session_stamp)
    token = make_file_token(f"emule-tests-{config.build_tag}")
    suffix = f"{config.configuration.lower()}-{config.platform.lower()}"
    return BuildLogPaths(
        text_log_path=log_directory / f"{token}-{suffix}.log",
        binary_log_path=log_directory / f"{token}-{suffix}.binlog",
    )


def build_msbuild_arguments(config: BuildTestsConfig, log_paths: BuildLogPaths) -> tuple[str, ...]:
    """Builds the MSBuild command-line arguments for `emule-tests.vcxproj`."""

    project_path = config.test_repo_root / "emule-tests.vcxproj"
    arguments = [
        str(project_path),
        "/m",
        "/nologo",
        f"/t:{'Rebuild' if config.clean else 'Build'}",
        f"/p:AppRoot={config.app_root}",
        f"/p:WorkspaceRoot={config.workspace_root}",
        f"/p:BuildTag={config.build_tag}",
        f"/p:Configuration={config.configuration}",
        f"/p:Platform={config.platform}",
        f"/flp:LogFile={log_paths.text_log_path};Verbosity=normal;Encoding=UTF-8",
        f"/bl:{log_paths.binary_log_path}",
    ]
    if config.build_output_mode != "Full":
        clp_mode = "WarningsOnly" if config.build_output_mode == "Warnings" else "ErrorsOnly"
        arguments.append(f"/clp:{clp_mode}")
    return tuple(arguments)


def run_build_tests(config: BuildTestsConfig) -> int:
    """Builds the native test executable and optionally runs it."""

    if not config.skip_tracked_file_privacy_guard:
        policy_path = config.test_repo_root / "manifests" / "privacy-guard" / "policy.v1.json"
        try:
            guard_summary = run_privacy_guard(repo_root=config.test_repo_root, policy_path=policy_path)
        except PrivacyGuardFailure as exc:
            print(json.dumps(exc.summary, indent=2))
            raise
        print(json.dumps(guard_summary, indent=2))

    if config.clean:
        remove_intermediate_root(config)

    msbuild_path = find_msbuild_path()
    log_paths = get_build_log_paths(config)
    arguments = build_msbuild_arguments(config, log_paths)
    if config.build_output_mode == "Full":
        print(
            "Building "
            f"{config.test_repo_root / 'emule-tests.vcxproj'} for {config.workspace_root} "
            f"using app root {config.app_root} ({config.platform}|{config.configuration}, tag={config.build_tag})"
        )

    started_at = time.monotonic()
    completed = subprocess.run([str(msbuild_path), *arguments], check=False)
    duration_seconds = time.monotonic() - started_at
    write_build_step_summary(
        succeeded=completed.returncode == 0,
        log_path=log_paths.text_log_path,
        duration_seconds=duration_seconds,
        build_output_mode=config.build_output_mode,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"MSBuild failed with exit code {completed.returncode}.")

    if config.run_tests:
        run_native_test_binary(config)
    return 0


def remove_intermediate_root(config: BuildTestsConfig) -> None:
    """Removes the clean-build intermediate directory after validating its root."""

    build_root = config.test_repo_root / "build" / config.build_tag / config.platform / config.configuration
    intermediate_root = (build_root / "obj").resolve()
    allowed_root = (config.test_repo_root / "build").resolve()
    try:
        intermediate_root.relative_to(allowed_root)
    except ValueError as exc:
        raise RuntimeError(f"Refusing to clean unexpected intermediate path: {intermediate_root}") from exc
    if intermediate_root.exists():
        shutil.rmtree(intermediate_root)


def run_native_test_binary(config: BuildTestsConfig) -> None:
    """Runs the built native test executable with optional tee-to-file output."""

    binary_path = config.test_repo_root / "build" / config.build_tag / config.platform / config.configuration / "emule-tests.exe"
    if not binary_path.is_file():
        raise RuntimeError(f"Built test executable not found: {binary_path}")

    print(f"Running {binary_path}")
    command = [str(binary_path), *config.test_arguments]
    output_file = None
    try:
        if config.out_file is not None:
            config.out_file.parent.mkdir(parents=True, exist_ok=True)
            output_file = config.out_file.open("w", encoding="utf-8")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert process.stdout is not None
        for line in process.stdout:
            print(line, end="")
            if output_file is not None:
                output_file.write(line)
        returncode = process.wait()
    finally:
        if output_file is not None:
            output_file.close()

    if returncode != 0 and not config.allow_test_failure:
        raise RuntimeError(f"The test executable failed with exit code {returncode}.")
    if returncode != 0:
        print(f"WARNING: The test executable failed with exit code {returncode}.", file=sys.stderr)


def format_duration(total_seconds: float) -> str:
    """Formats elapsed seconds using the retained build-summary style."""

    if total_seconds < 10:
        return f"{total_seconds:.1f}s"
    return f"{round(total_seconds):.0f}s"


def write_build_step_summary(
    *,
    succeeded: bool,
    log_path: Path,
    duration_seconds: float,
    build_output_mode: str,
) -> None:
    """Prints the compact native-test build summary line."""

    duration_text = format_duration(duration_seconds)
    if succeeded:
        if build_output_mode != "Full":
            print(f"OK   TEST emule-tests ({duration_text})")
        return
    print(f"FAIL TEST emule-tests ({duration_text}) -> {log_path}")
