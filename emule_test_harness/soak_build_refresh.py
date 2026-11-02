"""Canonical incremental client builds used immediately before soak launch."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def diagnostics_build_command(
    client: str,
    *,
    mfc_variant: str = "main",
    mfc_arch: str = "x64",
    mfc_configuration: str = "Release",
    clean: bool = False,
) -> list[str]:
    """Return the official incremental diagnostics build for one soak client."""

    common = [sys.executable, "-m", "emule_workspace", "build"]
    if client == "rust":
        command = [
            *common,
            "clients",
            "--client",
            "emulebb-rust",
            "--config",
            "Release",
            "--platform",
            "x64",
            "--build-output-mode",
            "ErrorsOnly",
            "--diagnostics",
        ]
        if clean:
            command.append("--clean")
        return command
    if client == "mfc":
        if mfc_configuration != "Release":
            raise RuntimeError(
                "MFC diagnostics soaks require --mfc-configuration Release."
            )
        command = [
            *common,
            "app",
            "--variant",
            mfc_variant,
            "--config",
            mfc_configuration,
            "--platform",
            mfc_arch,
            "--build-output-mode",
            "ErrorsOnly",
            "--diagnostics",
        ]
        if clean:
            command.append("--clean")
        return command
    raise ValueError(f"Unsupported soak client: {client}")


def refresh_diagnostics_build(
    workspace_root: Path,
    client: str,
    *,
    mfc_variant: str = "main",
    mfc_arch: str = "x64",
    mfc_configuration: str = "Release",
) -> None:
    """Run one canonical incremental build and fail before client launch."""

    build_repo = workspace_root / "repos" / "emulebb-build"
    if not build_repo.is_dir():
        raise RuntimeError(
            f"Workspace build orchestrator repo was not found: {build_repo}"
        )
    command = diagnostics_build_command(
        client,
        mfc_variant=mfc_variant,
        mfc_arch=mfc_arch,
        mfc_configuration=mfc_configuration,
    )
    completed = subprocess.run(command, cwd=build_repo, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"{client} diagnostics build failed with exit code {completed.returncode}."
        )
