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
import tomllib
from pathlib import Path
from uuid import uuid4


def docker(*arguments: str, check: bool = True, input: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments], text=True, capture_output=True, check=check, timeout=60, input=input
    )


def authenticated_app(container: str, architecture: str) -> dict[str, object]:
    """Prove the generated key works without placing it in argv or evidence."""
    try:
        settings = docker("exec", container, "cat", "/config/emulebb-rust/emulebb-rust-settings.toml", check=False)
        if settings.returncode or len(settings.stdout) > 64 * 1024:
            raise ValueError("invalid settings")
        rest = tomllib.loads(settings.stdout).get("rest")
        key = rest.get("api_key") if isinstance(rest, dict) else None
        if not isinstance(key, str) or len(key) < 32 or not all(33 <= ord(char) <= 126 for char in key):
            raise ValueError("invalid key")
    except (OSError, subprocess.SubprocessError, ValueError):
        # WHY: parser diagnostics can include the private TOML input. Keep the
        # generated credential out of failure reports as well as successful ones.
        raise RuntimeError("Cannot read a valid generated image REST credential") from None
    try:
        response = docker("exec", "--interactive", container, "curl", "--fail", "--silent", "--max-time", "2",
                          "--header", "@-", "--write-out", "\n%{http_code}", "http://127.0.0.1:20017/api/v1/app",
                          check=False, input=f"X-API-Key: {key}\n")
        body, separator, status = response.stdout.rpartition("\n")
        if response.returncode or not separator or status != "200" or len(body) > 64 * 1024:
            raise ValueError("invalid HTTP response")
        document = json.loads(body)
        app = document.get("data") if isinstance(document, dict) else None
        expected_cpu = "x64" if architecture == "amd64" else "arm64"
        if (not isinstance(app, dict) or app.get("name") != "eMuleBB" or app.get("apiVersion") != "v1"
                or not isinstance(app.get("version"), str) or not app["version"].strip()
                or app.get("build") != "release" or app.get("platform") != expected_cpu
                or not isinstance(app.get("lifecycle"), dict) or app["lifecycle"].get("state") != "running"):
            raise ValueError("invalid app identity")
    except (OSError, subprocess.SubprocessError, ValueError):
        raise RuntimeError("Authenticated image REST must return HTTP 200 and the running release app for the selected CPU") from None
    return {"authenticatedStatus": 200, "appVersion": app["version"],
            "appBuild": app["build"], "appPlatform": app["platform"]}


def oci_platform_identities(path: Path) -> dict[str, dict[str, str]]:
    """Verify OCI metadata blobs and identify the manifest/config for each CPU."""
    identities: dict[str, dict[str, str]] = {}
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
                if platform in identities:
                    raise RuntimeError(f"OCI archive repeats a runnable platform: {platform}")
                identities[platform] = {"manifestDigest": descriptor["digest"], "configDigest": config["digest"]}
        visit(read_json("index.json"))
    return identities


def smoke_platform(image: str, platform: str, expected_identity: dict[str, str], *, run_id: str | None = None) -> dict[str, object]:
    architecture = platform.removeprefix("linux/")
    run_id = run_id or uuid4().hex
    container = f"emulebb-rust-image-smoke-{architecture}-{run_id}"
    network = f"emulebb-rust-image-smoke-net-{architecture}-{run_id}"
    if docker("container", "inspect", container, check=False).returncode == 0:
        raise RuntimeError(f"refusing to replace existing container {container}")
    if docker("network", "inspect", network, check=False).returncode == 0:
        raise RuntimeError(f"refusing to replace existing network {network}")
    try:
        docker("network", "create", "--internal", "--label", f"io.emulebb.ci.image-smoke-owner={run_id}", network)
        if docker("network", "inspect", "--format", "{{.Internal}}", network).stdout.strip() != "true":
            raise RuntimeError("Image smoke requires an internal Docker network")
        docker(
            "run", "--detach", "--pull", "never", "--name", container, "--platform", platform,
            "--label", f"io.emulebb.ci.image-smoke-owner={run_id}",
            "--network", network, "--dns", "127.0.0.1", "--dns-option", "attempts:1", "--dns-option", "timeout:1",
            "--tmpfs", "/config", "--tmpfs", "/data",
            "--env", "PUID=1234", "--env", "PGID=1235", "--env", "TZ=UTC",
            "--env", "EMULEBB_RUST_P2P_INTERFACE=eth0",
            # Explicitly contain first-run HTTP discovery, including client proxy defaults.
            "--env", "HTTP_PROXY=", "--env", "HTTPS_PROXY=", "--env", "ALL_PROXY=",
            "--env", "http_proxy=", "--env", "https_proxy=", "--env", "all_proxy=", image,
        )
        # The containerd image store's .Image is an index ID, not a config ID.
        # Its platform descriptor binds the running container to exact CPU bytes.
        descriptor = json.loads(docker("inspect", "--format", "{{json .ImageManifestDescriptor}}", container).stdout)
        actual_manifest = descriptor.get("digest") if isinstance(descriptor, dict) else None
        if actual_manifest != expected_identity["manifestDigest"]:
            raise RuntimeError(f"Running platform manifest does not match the OCI archive: {actual_manifest} != {expected_identity['manifestDigest']}")
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
                "http://127.0.0.1:20017/", check=False,
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
        pid = daemon.stdout.strip()
        if re.fullmatch(r"[1-9][0-9]{0,9}", pid) is None:
            raise RuntimeError("Image smoke requires exactly one daemon PID")
        daemon_owner = docker("exec", container, "ps", "-o", "uid=,gid=", "-p", pid).stdout.split()
        ports = docker("port", container).stdout.strip()
        variant = docker("inspect", "--format", '{{index .Config.Labels "io.emulebb.image.variant"}}', container).stdout.strip()
        if variant == "ubuntu":
            actual_architecture = docker("exec", container, "dpkg", "--print-architecture").stdout.strip()
            expected_architecture = architecture
        elif variant == "alpine":
            actual_architecture = docker("exec", container, "apk", "--print-arch").stdout.strip()
            expected_architecture = {"amd64": "x86_64", "arm64": "aarch64"}[architecture]
        else:
            raise RuntimeError("Image smoke requires an explicit Ubuntu or Alpine variant label")
        docker("exec", container, "/usr/local/bin/emulebb-rust-healthcheck")
        auth_status = docker("exec", container, "curl", "--silent", "--max-time", "2", "--output", "/dev/null",
                             "--write-out", "%{http_code}", "http://127.0.0.1:20017/api/v1/status").stdout.strip()
        if ((uid, gid) != ("1234", "1235") or owners != ["1234:1235", "1234:1235"]
                or daemon_owner != ["1234", "1235"] or ports or actual_architecture != expected_architecture):
            raise RuntimeError(f"image PUID/PGID or volume contract failed: uid={uid}, gid={gid}, daemonOwner={daemon_owner}, owners={owners}")
        if auth_status != "401":
            raise RuntimeError(f"Image REST API must reject unauthenticated access, got {auth_status}")
        app = authenticated_app(container, architecture)
        docker("stop", "--time", "30", container)
        exit_code = docker("inspect", "--format", "{{.State.ExitCode}}", container).stdout.strip()
        if exit_code != "0":
            raise RuntimeError(f"Image did not stop gracefully: exit {exit_code}")
        return {
            "platform": platform,
            "imageVariant": variant, "osPackageArchitecture": actual_architecture,
            "firstRunProfile": True, "webui": True, "uid": int(uid), "gid": int(gid),
            "daemonUid": int(daemon_owner[0]), "daemonGid": int(daemon_owner[1]),
            "configOwner": owners[0], "dataOwner": owners[1], "publishedPorts": 0,
            "imageManifestDigest": actual_manifest, "imageConfigDigest": expected_identity["configDigest"],
            "unauthenticatedStatus": 401, **app, "restAuthentication": True, "gracefulShutdown": True,
            "networkIsolation": "internal-bridge", "dns": "loopback-only",
        }
    finally:
        original_error = sys.exception()
        cleanup_errors = []
        for arguments in (("rm", "--force", container), ("network", "rm", network)):
            try:
                cleanup = docker(*arguments, check=False)
                if cleanup.returncode:
                    raise RuntimeError(f"Could not remove owned image-smoke resource: {arguments[-1]}")
            except Exception as cleanup_error:
                cleanup_errors.append(str(cleanup_error))
        if cleanup_errors:
            detail = "Owned image-smoke cleanup failed: " + "; ".join(cleanup_errors)
            if original_error is None:
                raise RuntimeError(detail)
            original_error.add_note(detail)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), action="append")
    parser.add_argument("--report-path", type=Path)
    parser.add_argument("--run-id", default=uuid4().hex, help="Owner token for orchestration cleanup.")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{32}", args.run_id) is None:
        parser.error("--run-id must be a lowercase UUID hex owner token")
    if not args.archive.is_file():
        raise RuntimeError(f"OCI archive is missing: {args.archive}")

    identities = oci_platform_identities(args.archive)
    selected = args.platform or ["linux/amd64", "linux/arm64"]
    if not selected or len(set(selected)) != len(selected) or set(selected) - identities.keys():
        raise RuntimeError("OCI archive does not contain exactly one image for every requested platform")
    with args.archive.open("rb") as stream:
        archive_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    report = {"schema": "emulebb.rust.image-smoke/4", "status": "failed", "image": args.image,
              "archiveSha256": archive_sha256, "platforms": []}
    try:
        loaded = docker("load", "--input", str(args.archive), check=False)
        if loaded.returncode:
            raise RuntimeError("Docker could not load the OCI candidate: "
                               + loaded.stderr[-2000:] + loaded.stdout[-2000:])
        for platform in selected:
            report["platforms"].append(smoke_platform(args.image, platform, identities[platform], run_id=args.run_id))
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
