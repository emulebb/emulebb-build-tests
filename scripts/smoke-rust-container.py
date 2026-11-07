#!/usr/bin/env python3
"""Smoke an OCI release image's first-run s6, PUID/PGID, /config, /data, and WebUI."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from uuid import uuid4


def docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments], text=True, capture_output=True, check=check, timeout=60
    )


def oci_platform_configs(path: Path) -> dict[str, str]:
    """Verify OCI metadata blobs and identify the exact config for each CPU."""
    configs: dict[str, str] = {}
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        def read_json(name: str, expected_digest: str | None = None) -> dict:
            matches = [member for member in members if member.name == name]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 1024 * 1024:
                raise RuntimeError(f"OCI metadata must contain one bounded regular file: {name}")
            stream = archive.extractfile(matches[0])
            if stream is None:
                raise RuntimeError(f"Cannot read OCI metadata: {name}")
            data = stream.read()
            if expected_digest and "sha256:" + hashlib.sha256(data).hexdigest() != expected_digest:
                raise RuntimeError(f"OCI metadata digest mismatch: {name}")
            result = json.loads(data)
            if not isinstance(result, dict):
                raise RuntimeError(f"OCI metadata must be an object: {name}")
            return result

        def blob(descriptor: dict) -> dict:
            digest = descriptor.get("digest")
            if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
                raise RuntimeError("OCI descriptor requires a SHA-256 digest")
            return read_json("blobs/sha256/" + digest.removeprefix("sha256:"), digest)

        def visit(document: dict, depth: int = 0) -> None:
            if depth > 4 or document.get("schemaVersion") != 2:
                raise RuntimeError("OCI index nesting or schema is invalid")
            manifests = document.get("manifests")
            if not isinstance(manifests, list):
                raise RuntimeError("OCI index requires manifests")
            for descriptor in manifests:
                if not isinstance(descriptor, dict):
                    raise RuntimeError("OCI manifest descriptor must be an object")
                if descriptor.get("platform", {}).get("os") == "unknown":
                    continue  # BuildKit attestations are not runnable platforms.
                child = blob(descriptor)
                if "manifests" in child:
                    visit(child, depth + 1)
                    continue
                config = child.get("config")
                if child.get("schemaVersion") != 2 or not isinstance(config, dict):
                    raise RuntimeError("OCI image manifest requires a config descriptor")
                identity = blob(config)
                platform = f"{identity.get('os')}/{identity.get('architecture')}"
                if platform not in {"linux/amd64", "linux/arm64"}:
                    continue
                if platform in configs:
                    raise RuntimeError(f"OCI archive repeats a runnable platform: {platform}")
                configs[platform] = config["digest"]
        visit(read_json("index.json"))
    return configs


def smoke_platform(image: str, platform: str, expected_config: str) -> dict[str, object]:
    architecture = platform.removeprefix("linux/")
    container = f"emulebb-rust-image-smoke-{architecture}-{uuid4().hex}"
    if docker("container", "inspect", container, check=False).returncode == 0:
        raise RuntimeError(f"refusing to replace existing container {container}")
    try:
        docker(
            "run", "--detach", "--pull", "never", "--name", container, "--platform", platform,
            "--network", "bridge",
            "--tmpfs", "/config", "--tmpfs", "/data",
            "--env", "PUID=1234", "--env", "PGID=1235", "--env", "TZ=UTC", image,
        )
        actual_config = docker("inspect", "--format", "{{.Image}}", container).stdout.strip()
        if actual_config != expected_config:
            raise RuntimeError(f"Running image does not match the OCI archive: {actual_config} != {expected_config}")
        deadline = time.monotonic() + 90
        while True:
            running = docker("inspect", "--format", "{{.State.Running}}", container,
                             check=False).stdout.strip() == "true"
            if not running:
                logs = docker("logs", "--tail", "30", container, check=False)
                raise RuntimeError("image exited before serving REST/WebUI: "
                                   + logs.stdout[-3000:] + logs.stderr[-3000:])
            response = docker(
                "exec", container, "curl", "--fail", "--silent", "--max-time", "2",
                "http://127.0.0.1:4711/", check=False,
            )
            if response.returncode == 0 and "eMuleBB WebUI" in response.stdout:
                break
            if time.monotonic() >= deadline:
                logs = docker("logs", "--tail", "30", container, check=False)
                raise RuntimeError(
                    "image first-run daemon/WebUI did not start: " + logs.stdout[-3000:] + logs.stderr[-3000:]
                )
            time.sleep(1)
        uid = docker("exec", container, "id", "-u", "abc").stdout.strip()
        gid = docker("exec", container, "id", "-g", "abc").stdout.strip()
        owners = docker("exec", container, "stat", "-c", "%u:%g", "/config", "/data/ed2k").stdout.splitlines()
        docker("exec", container, "test", "-f", "/config/emulebb-rust/emulebb-rust-settings.toml")
        daemon = docker("exec", container, "pgrep", "-f", "/usr/lib/emulebb-rust/emulebb-rust")
        ports = docker("port", container).stdout.strip()
        actual_architecture = docker("exec", container, "dpkg", "--print-architecture").stdout.strip()
        docker("exec", container, "/usr/local/bin/emulebb-rust-healthcheck")
        auth_status = docker("exec", container, "curl", "--silent", "--max-time", "2", "--output", "/dev/null",
                             "--write-out", "%{http_code}", "http://127.0.0.1:4711/api/v1/status").stdout.strip()
        if ((uid, gid) != ("1234", "1235") or owners != ["1234:1235", "1234:1235"]
                or not daemon.stdout.strip() or ports or actual_architecture != architecture):
            raise RuntimeError(f"image PUID/PGID or volume contract failed: uid={uid}, gid={gid}, owners={owners}")
        if auth_status != "401":
            raise RuntimeError(f"Image REST API must reject unauthenticated access, got {auth_status}")
        docker("stop", "--time", "30", container)
        exit_code = docker("inspect", "--format", "{{.State.ExitCode}}", container).stdout.strip()
        if exit_code != "0":
            raise RuntimeError(f"Image did not stop gracefully: exit {exit_code}")
        return {
            "platform": platform,
            "firstRunProfile": True, "webui": True, "uid": int(uid), "gid": int(gid),
            "configOwner": owners[0], "dataOwner": owners[1], "publishedPorts": 0,
            "imageConfigDigest": actual_config, "restAuthentication": True, "gracefulShutdown": True,
        }
    finally:
        original_error = sys.exception()
        try:
            cleanup = docker("rm", "--force", container, check=False)
            if cleanup.returncode:
                raise RuntimeError(f"Could not remove owned smoke container {container}")
        except Exception as cleanup_error:
            if original_error is None:
                raise
            original_error.add_note(f"Owned smoke container cleanup failed: {cleanup_error}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), action="append")
    parser.add_argument("--report-path", type=Path)
    args = parser.parse_args()
    if not args.archive.is_file():
        raise RuntimeError(f"OCI archive is missing: {args.archive}")

    configs = oci_platform_configs(args.archive)
    selected = args.platform or ["linux/amd64", "linux/arm64"]
    if not selected or len(set(selected)) != len(selected) or set(selected) - configs.keys():
        raise RuntimeError("OCI archive does not contain exactly one image for every requested platform")
    with args.archive.open("rb") as stream:
        archive_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    report = {"schema": "emulebb.rust.image-smoke/3", "status": "failed", "image": args.image,
              "archiveSha256": archive_sha256, "platforms": []}
    try:
        loaded = docker("load", "--input", str(args.archive), check=False)
        if loaded.returncode:
            raise RuntimeError("Docker could not load the OCI candidate: "
                               + loaded.stderr[-2000:] + loaded.stdout[-2000:])
        for platform in selected:
            report["platforms"].append(smoke_platform(args.image, platform, configs[platform]))
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        if args.report_path:
            args.report_path.parent.mkdir(parents=True, exist_ok=True)
            args.report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
