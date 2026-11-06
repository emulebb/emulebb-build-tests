"""Offline stock hash import and target-filesystem reconciliation evidence."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import time
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from . import emule_profile_export
from .paths import get_workspace_output_root


def run_json(command: list[str], timeout: int) -> dict:
    """Run an offline product command and parse its JSON result."""
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=True)
    return json.loads(completed.stdout)


def profile_counts(profile: Path) -> dict[str, int]:
    """Read durable hash counts after the offline process has closed SQLite."""
    database = profile / "emulebb-rust-metadata.db"
    if not database.is_file():
        raise FileNotFoundError(database)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA query_only = ON")
        return {
            table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in (
                "imported_known_files", "known_files", "verified_local_content",
                "verified_local_md4_hashes", "verified_local_aich_hashes", "local_file_instances",
                "transfers",
            )
        }


def validate_imported_hashes(profile: Path, manifest: dict) -> dict[str, int]:
    """Compare every imported hash and ordered part hashset with the export."""
    with sqlite3.connect(profile / "emulebb-rust-metadata.db") as connection:
        connection.execute("PRAGMA query_only = ON")
        md4: dict[int, list[str]] = {}
        aich: dict[int, list[str]] = {}
        for table, column, destination in (
            ("imported_known_file_md4_hashes", "md4_hash", md4),
            ("imported_known_file_aich_hashes", "aich_hash", aich),
        ):
            for row_id, value in connection.execute(
                f"SELECT imported_known_file_id, lower(hex({column})) FROM {table} "
                "ORDER BY imported_known_file_id, part_index"
            ):
                destination.setdefault(row_id, []).append(value)
        expected = {
            (row["fileHash"], row["displayName"], row["fileSize"], row["modifiedS"]): row
            for row in manifest["knownFiles"]
        }
        matched = 0
        for row_id, file_hash, name, size, modified, root in connection.execute(
            "SELECT id, lower(hex(ed2k_hash)), display_name, size_bytes, modified_s, "
            "CASE WHEN aich_root IS NULL THEN NULL ELSE lower(hex(aich_root)) END "
            "FROM imported_known_files"
        ):
            exported = expected.get((file_hash, name, size, modified))
            if exported is None:
                continue
            if (root, md4.get(row_id, []), aich.get(row_id, [])) != (
                exported["aichRoot"], exported["md4Hashset"], exported["aichHashset"],
            ):
                raise RuntimeError("imported hashset differs from the export")
            matched += 1
        if matched != len(expected):
            raise RuntimeError("the profile is missing exported known-file records")
        return {"verifiedImportedRecords": matched, "verifiedMd4Parts": sum(map(len, md4.values())),
                "verifiedAichParts": sum(map(len, aich.values()))}


def mount_argument(value: str) -> tuple[str, str]:
    """Parse an explicit WSL host directory to container directory mapping."""
    source, separator, target = value.partition("=")
    if not separator or not source.startswith("/") or not target.startswith("/"):
        raise argparse.ArgumentTypeError("mount must be /host/path=/container/path")
    return source, target


def validate_reconciliation(report: dict) -> None:
    """Fail if an offline pass reports hashing, payload reads, or active work."""
    if any(report[key] for key in ("hashedCount", "completedReadBytes", "activeHashCount", "running")):
        raise RuntimeError("offline reconciliation performed unexpected payload work")


def prepare_windows_mounts(wsl: list[str], job: emule_profile_export.ExportJob,
                          mounts: list[tuple[str, str]], cleanup: ExitStack) -> None:
    """Temporarily mount missing Windows volumes read-only for the Docker audit."""
    for host, target in mounts:
        source = next((mapping.source for mapping in job.path_mappings if mapping.target == target), None)
        if source is None or not Path(source).is_dir():
            raise ValueError(f"no accessible Windows source mapping for {target}")
        if subprocess.run(wsl + ["mountpoint", "-q", host], check=False).returncode == 0:
            continue
        # Ordinary drive paths are already visible through WSL automounts.
        if host.startswith("/mnt/") and len(host.split("/")[2]) == 1:
            continue
        root_wsl = wsl[:-1] + ["-u", "root", "--"]
        subprocess.run(root_wsl + ["mkdir", "-p", host], check=True)
        subprocess.run(root_wsl + ["mount", "-t", "drvfs", "-o", "ro", source, host], check=True)
        cleanup.callback(subprocess.run, root_wsl + ["umount", host], check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--profile", required=True, help="Windows path, or WSL path with --image")
    parser.add_argument("--image", help="Use isolated network-none Docker containers in WSL")
    parser.add_argument("--wsl-distro", default="Ubuntu")
    parser.add_argument("--mount", action="append", type=mount_argument, default=[])
    parser.add_argument("--prepare-windows-mounts", action="store_true",
                        help="Temporarily mount missing mapped Windows volumes read-only")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--timeout", type=int, default=7200)
    args = parser.parse_args(argv)
    started = time.monotonic()
    output = get_workspace_output_root()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_root = output / "reports" / "stock-hash-import" / ("docker" if args.image else "windows") / stamp
    job = emule_profile_export.load_export_job(args.config)
    if not args.image:
        job = replace(job, target_platform="windows", path_mappings=())
    manifest = emule_profile_export.build_export_manifest(job)
    report_root.mkdir(parents=True, exist_ok=False)
    manifest_path = report_root / "profile-import.json"
    emule_profile_export.export_manifest(replace(job, output_manifest=manifest_path), manifest)

    wsl = ["wsl.exe", "-d", args.wsl_distro, "--"]
    if args.image:
        if not args.profile.startswith("/"):
            raise ValueError("Docker profile must be an absolute WSL path")
        if manifest["targetPlatform"] != "unix":
            raise ValueError("Docker requires a Linux-target export job")
        windows_profile = subprocess.check_output(wsl + ["wslpath", "-w", args.profile], text=True).strip()
        profile = Path(windows_profile)
        profile.mkdir(parents=True, exist_ok=True)
        manifest_wsl = subprocess.check_output(wsl + ["wslpath", "-a", "-u", str(manifest_path)], text=True).strip()
        # Each invocation creates and removes a distinct container. Data mounts
        # are read-only; the image init and all network startup are bypassed.
        prefix = wsl + ["docker", "run", "--rm", "--network", "none", "--user", "1000:1000",
                        "--entrypoint", "/usr/lib/emulebb-rust/emulebb-rust",
                        "--mount", f"type=bind,src={args.profile},dst=/profile",
                        "--mount", f"type=bind,src={manifest_wsl},dst=/import.json,readonly"]
        for source, target in args.mount:
            prefix += ["--mount", f"type=bind,src={source},dst={target},readonly"]
        prefix += [args.image, "--profile", "/profile"]
        import_path = "/import.json"
    else:
        if os.name != "nt":
            raise RuntimeError("native audit requires Windows; use --image for Docker")
        profile = Path(args.profile).resolve()
        binary = args.binary or output / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
        if not binary.is_file():
            raise FileNotFoundError(binary)
        prefix = [str(binary), "--profile", str(profile)]
        import_path = str(manifest_path)

    report = {
        "schema": "emulebb.stock-hash-import-audit.v1",
        "target": "docker" if args.image else "windows",
        "image": args.image,
        "profile": str(profile),
        "manifest": str(manifest_path),
        "export": manifest["summary"],
        "networkStarted": False,
    }
    report_path = report_root / "summary.json"
    cleanup = ExitStack()
    try:
        if args.prepare_windows_mounts:
            if not args.image:
                raise ValueError("--prepare-windows-mounts requires --image")
            prepare_windows_mounts(wsl, job, args.mount, cleanup)
        report["import"] = run_json(prefix + ["import-emule-profile", import_path], args.timeout)
        report["hashValidation"] = validate_imported_hashes(profile, manifest)
        report["firstPass"] = run_json(prefix + ["reconcile-shared-files"], args.timeout)
        validate_reconciliation(report["firstPass"])
        report["firstCounts"] = profile_counts(profile)
        report["secondPass"] = run_json(prefix + ["reconcile-shared-files"], args.timeout)
        validate_reconciliation(report["secondPass"])
        report["secondCounts"] = profile_counts(profile)
        if report["firstCounts"] != report["secondCounts"]:
            raise RuntimeError("durable hash counts changed on the repeated offline pass")
        if report["firstPass"]["reusedCount"] == 0:
            raise RuntimeError("no target files reused imported hashes")
        if report["firstPass"]["reusedCount"] != report["secondPass"]["reusedCount"]:
            raise RuntimeError("hash reuse changed across process/container recreation")
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["error"] = str(error)
        raise
    finally:
        cleanup.close()
        report["elapsedSeconds"] = round(time.monotonic() - started, 3)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report_path), **report}, indent=2))
    return 0
