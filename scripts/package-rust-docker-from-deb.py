#!/usr/bin/env python3
"""Build and archive the local eMuleBB Rust image from a certified Linux DEB."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def require_operator_path(name: str) -> Path:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must already be set")
    return Path(value).resolve()


def command(*argv: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def wsl_path(path: Path, distribution: str | None) -> str:
    argv = ["wsl.exe"]
    if distribution:
        argv.extend(("--distribution", distribution))
    argv.extend(("--", "wslpath", "-a", "-u", path.as_posix()))
    translated = command(*argv).stdout.strip()
    if not translated.startswith("/"):
        raise RuntimeError(f"WSL path translation returned an invalid path for {path}")
    return translated


def launch_wsl(
    args: argparse.Namespace, workspace_root: Path, output_root: Path
) -> int:
    build_tests = workspace_root / "repos" / "emulebb-build-tests"
    translated_workspace = wsl_path(workspace_root, args.wsl_distribution)
    translated_output = wsl_path(output_root, args.wsl_distribution)
    translated_build_tests = wsl_path(build_tests, args.wsl_distribution)
    argv = ["wsl.exe"]
    if args.wsl_distribution:
        argv.extend(("--distribution", args.wsl_distribution))
    argv.extend(
        (
            "--cd",
            translated_build_tests,
            "--",
            "env",
            f"EMULEBB_WORKSPACE_ROOT={translated_workspace}",
            f"EMULEBB_WORKSPACE_OUTPUT_ROOT={translated_output}",
            "GIT_CONFIG_COUNT=1",
            "GIT_CONFIG_KEY_0=core.autocrlf",
            "GIT_CONFIG_VALUE_0=true",
            "python3",
            "scripts/package-rust-docker-from-deb.py",
            "--release-version",
            args.release_version,
            "--architecture",
            args.architecture,
        )
    )
    if args.deb:
        argv.extend(("--deb", wsl_path(args.deb.resolve(), args.wsl_distribution)))
    if args.image:
        argv.extend(("--image", args.image))
    return subprocess.run(argv, check=False).returncode


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--architecture", default="amd64")
    parser.add_argument("--deb", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--wsl-distribution")
    parser.add_argument("--native", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    workspace_root = require_operator_path("EMULEBB_WORKSPACE_ROOT")
    output_root = require_operator_path("EMULEBB_WORKSPACE_OUTPUT_ROOT")
    if not workspace_root.is_dir():
        raise RuntimeError(f"EMULEBB_WORKSPACE_ROOT is missing: {workspace_root}")
    if output_root == workspace_root or output_root.is_relative_to(workspace_root):
        raise RuntimeError("EMULEBB_WORKSPACE_OUTPUT_ROOT must remain outside the workspace")
    if os.name == "nt" and not args.native:
        return launch_wsl(args, workspace_root, output_root)

    rust_repo = workspace_root / "repos" / "emulebb-rust"
    docker_source = rust_repo / "packaging" / "docker"
    if not (docker_source / "Dockerfile").is_file():
        raise RuntimeError(f"Rust Docker context is missing: {docker_source}")
    dirty = command("git", "status", "--porcelain", cwd=rust_repo).stdout.strip()
    if dirty:
        raise RuntimeError("emulebb-rust must be clean before Docker packaging")
    commit = command("git", "rev-parse", "HEAD", cwd=rust_repo).stdout.strip().lower()
    if len(commit) != 40:
        raise RuntimeError("could not resolve the emulebb-rust commit")

    version = args.release_version
    architecture = args.architecture
    deb = (args.deb or (
        output_root
        / "release"
        / f"rust-v{version}"
        / f"emulebb-rust-v{version}-linux-{architecture}.deb"
    )).resolve()
    if not deb.is_file():
        raise RuntimeError(f"certified Linux DEB is missing: {deb}")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    image = args.image or f"local/emulebb-rust:{version}-{commit[:8]}"
    report_dir = output_root / "reports" / "rust-docker-package" / run_id
    context = output_root / "staging" / "rust-docker-package" / run_id
    archive = (
        output_root
        / "artifacts"
        / f"emulebb-rust-v{version}-linux-{architecture}-{commit[:8]}.docker.tar"
    )
    override = report_dir / "compose.override.yaml"
    report_path = report_dir / "report.json"
    for path in (context, archive, report_dir):
        if path.exists():
            raise RuntimeError(f"refusing to overwrite Docker package evidence: {path}")

    report_dir.mkdir(parents=True)
    archive.parent.mkdir(parents=True, exist_ok=True)
    context.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(docker_source, context)
    dist = context / "dist"
    dist.mkdir()
    staged_deb = dist / f"emulebb-rust-v{version}-linux-{architecture}.deb"
    shutil.copy2(deb, staged_deb)
    override.write_text(
        "services:\n  emulebb-rust:\n    image: " + image + "\n",
        encoding="utf-8",
        newline="\n",
    )

    command(
        "docker",
        "build",
        "--file",
        str(context / "Dockerfile"),
        "--build-arg",
        f"VERSION={version}",
        "--build-arg",
        f"TARGETARCH={architecture}",
        "--tag",
        image,
        str(context),
    )
    command("docker", "save", "--output", str(archive), image)
    if not archive.is_file() or archive.stat().st_size == 0:
        raise RuntimeError("docker save did not create a non-empty OCI archive")

    report = {
        "schema": "emulebb.rust-docker-package.v1",
        "status": "passed",
        "runId": run_id,
        "sourceCommit": commit,
        "image": image,
        "architecture": architecture,
        "deb": str(deb),
        "debSha256": sha256_file(deb),
        "archive": str(archive),
        "archiveSha256": sha256_file(archive),
        "composeOverride": str(override),
        "context": str(context),
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
