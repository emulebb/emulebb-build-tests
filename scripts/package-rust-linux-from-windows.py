#!/usr/bin/env python3
"""Launch the approved Rust Linux packager across the Windows/WSL boundary."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def wsl_path(path: Path, distribution: str | None) -> str:
    command = ["wsl.exe"]
    if distribution:
        command.extend(("--distribution", distribution))
    command.extend(("--", "wslpath", "-a", "-u", path.as_posix()))
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    translated = result.stdout.strip()
    if not translated.startswith("/"):
        raise RuntimeError(f"WSL path translation returned an invalid path for {path}.")
    return translated


def require_operator_path(name: str) -> Path:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must already be set.")
    return Path(value).resolve()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--platform", choices=("x64", "ARM64"), default="x64")
    parser.add_argument(
        "--build-output-mode",
        choices=("Full", "Warnings", "ErrorsOnly"),
        default="ErrorsOnly",
    )
    parser.add_argument("--appimagetool", type=Path, required=True)
    parser.add_argument("--wsl-distribution")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args(argv)

    if os.name != "nt":
        raise RuntimeError("this boundary launcher must run on Windows")
    workspace_root = require_operator_path("EMULEBB_WORKSPACE_ROOT")
    output_root = require_operator_path("EMULEBB_WORKSPACE_OUTPUT_ROOT")
    cargo_target = require_operator_path("CARGO_TARGET_DIR")
    if not workspace_root.is_dir():
        raise RuntimeError(f"EMULEBB_WORKSPACE_ROOT is missing: {workspace_root}")
    if output_root == workspace_root or output_root.is_relative_to(workspace_root):
        raise RuntimeError("EMULEBB_WORKSPACE_OUTPUT_ROOT must remain outside the workspace")
    if cargo_target == output_root or not cargo_target.is_relative_to(output_root):
        raise RuntimeError("CARGO_TARGET_DIR must remain below EMULEBB_WORKSPACE_OUTPUT_ROOT")
    appimagetool = args.appimagetool.resolve()
    if not appimagetool.is_file():
        raise RuntimeError(f"appimagetool is missing: {appimagetool}")
    build_repo = workspace_root / "repos" / "emulebb-build"
    if not build_repo.is_dir():
        raise RuntimeError(f"emulebb-build is missing: {build_repo}")

    translated = {
        "workspaceRoot": wsl_path(workspace_root, args.wsl_distribution),
        "outputRoot": wsl_path(output_root, args.wsl_distribution),
        "cargoTargetDir": wsl_path(output_root / "builds" / "rust" / "target-wsl", args.wsl_distribution),
        "buildRepo": wsl_path(build_repo, args.wsl_distribution),
        "appimagetool": wsl_path(appimagetool, args.wsl_distribution),
    }
    command = ["wsl.exe"]
    if args.wsl_distribution:
        command.extend(("--distribution", args.wsl_distribution))
    command.extend(
        (
            "--cd",
            translated["buildRepo"],
            "--",
            "env",
            f"EMULEBB_WORKSPACE_ROOT={translated['workspaceRoot']}",
            f"EMULEBB_WORKSPACE_OUTPUT_ROOT={translated['outputRoot']}",
            f"CARGO_TARGET_DIR={translated['cargoTargetDir']}",
            f"APPIMAGETOOL={translated['appimagetool']}",
            "APPIMAGE_EXTRACT_AND_RUN=1",
            # WSL Git otherwise treats the Windows CRLF worktrees as dirty.
            # Pass the operator's Windows checkout semantics without mutating
            # either the Windows or WSL Git configuration.
            "GIT_CONFIG_COUNT=1",
            "GIT_CONFIG_KEY_0=core.autocrlf",
            "GIT_CONFIG_VALUE_0=true",
            "python3",
            "-m",
            "emule_workspace",
            "package-emulebb-rust",
            "--release-version",
            args.release_version,
            "--target-os",
            "linux",
            "--platform",
            args.platform,
            "--build-output-mode",
            args.build_output_mode,
        )
    )
    if args.skip_build:
        command.append("--skip-build")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_dir = output_root / "reports" / "rust-linux-package-launch" / run_id
    evidence_dir.mkdir(parents=True, exist_ok=False)
    evidence_path = evidence_dir / "wsl-boundary.json"
    evidence = {
        "schema": "emulebb.rust-linux-package-wsl-boundary.v1",
        "runId": run_id,
        "source": {
            "workspaceRoot": str(workspace_root),
            "outputRoot": str(output_root),
            "cargoTargetDir": str(cargo_target),
        },
        "translated": translated,
    }
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    completed = subprocess.run(command, check=False)
    evidence["exitCode"] = completed.returncode
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"wslBoundaryEvidence": str(evidence_path), "exitCode": completed.returncode}))
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
