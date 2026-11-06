"""Offline stock hash import and target-filesystem reconciliation evidence."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import time
from contextlib import ExitStack, closing
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from . import emule_profile_export
from .paths import get_workspace_output_root


def run_json(command: list[str], timeout: int) -> dict:
    """Run an offline product command and parse its JSON result."""
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    if completed.returncode:
        raise RuntimeError(f"offline command failed ({completed.returncode}): {completed.stderr.strip()}")
    return json.loads(completed.stdout)


def open_profile_snapshot(profile: Path) -> sqlite3.Connection:
    """Open a closed profile without creating cross-platform WAL/shm files."""
    database = profile / "emulebb-rust-metadata.db"
    if not database.is_file():
        raise FileNotFoundError(database)
    wal = database.with_name(database.name + "-wal")
    if wal.exists() and wal.stat().st_size:
        raise RuntimeError("profile still has uncheckpointed WAL data")
    return sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True)


def profile_counts(profile: Path) -> dict[str, int]:
    """Read durable hash counts after the offline process has closed SQLite."""
    with closing(open_profile_snapshot(profile)) as connection:
        return {
            table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in (
                "imported_known_files", "known_files", "verified_local_content",
                "verified_local_md4_hashes", "verified_local_aich_hashes", "local_file_instances",
                "transfers", "shared_directory_roots", "aich_recovery_sets", "aich_recovery_parts",
            )
        }


def validate_imported_hashes(profile: Path, exchange: Path) -> dict[str, int]:
    """Compare every ordered hashset using indexed lookups and bounded memory."""
    result = {"verifiedImportedRecords":0,"verifiedMd4Parts":0,"verifiedAichParts":0,"verifiedRecoverySets":0,"verifiedRecoveryParts":0}
    with closing(open_profile_snapshot(profile)) as target, closing(sqlite3.connect(exchange.as_uri()+"?mode=ro&immutable=1",uri=True)) as source:
        for record,md4,aich in source.execute("SELECT record,md4,aich FROM known_files ORDER BY id"):
            record=json.loads(record)
            row=target.execute("SELECT id,lower(hex(aich_root)) FROM imported_known_files WHERE display_name=? AND size_bytes=? AND modified_s=? AND ed2k_hash=?",(record["displayName"],record["fileSize"],record["modifiedS"],bytes.fromhex(record["fileHash"]))).fetchone()
            if row is None:
                raise RuntimeError("the profile is missing exported known-file records")
            if (row[1] or None)!=record["aichRoot"]:
                raise RuntimeError("imported hashset differs from the export")
            for table,column,expected,counter in [("imported_known_file_md4_hashes","md4_hash",md4,"verifiedMd4Parts"),("imported_known_file_aich_hashes","aich_hash",aich,"verifiedAichParts")]:
                hashes=[r[0] for r in target.execute(f"SELECT {column} FROM {table} WHERE imported_known_file_id=? ORDER BY part_index",(row[0],))]
                if column=="aich_hash" and not expected and hashes and record["aichRoot"]:
                    # A complete recovery import legitimately enriches a stock
                    # entry that had a master but no separate part-hash list.
                    recovered=[r[0] for r in target.execute("SELECT part_root FROM aich_recovery_parts WHERE root=? AND size_bytes=? ORDER BY part_index",(bytes.fromhex(record["aichRoot"]),record["fileSize"]))]
                    if recovered!=hashes:
                        raise RuntimeError("enriched AICH part hashes differ from recovery cache")
                    expected=b"".join(recovered)
                if b"".join(hashes)!=expected:
                    raise RuntimeError("imported hashset differs from the export")
                result[counter]+=len(hashes)
            result["verifiedImportedRecords"]+=1
        for root,size in source.execute("SELECT root,size_bytes FROM recovery_sets"):
            for index,leaves in source.execute("SELECT part_index,leaves FROM recovery_parts WHERE root=? AND size_bytes=? ORDER BY part_index",(root,size)):
                row=target.execute("SELECT leaves FROM aich_recovery_parts WHERE root=? AND size_bytes=? AND part_index=?",(root,size,index)).fetchone()
                if row is None or row[0]!=leaves:
                    raise RuntimeError("imported AICH recovery leaves differ from the export")
                result["verifiedRecoveryParts"]+=1
            result["verifiedRecoverySets"]+=1
    return result


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
        subprocess.run(root_wsl + ["mount", "-t", "drvfs", "-o", "ro", Path(source).as_posix(), host], check=True)
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
    from .profile_exchange import write_exchange
    report_root.mkdir(parents=True, exist_ok=False)
    manifest_path = report_root / "profile-import.sqlite"
    manifest=write_exchange(replace(job,output_manifest=manifest_path))
    hash_manifest_path=report_root/"portable-hashes.sqlite"
    write_exchange(replace(job,output_manifest=hash_manifest_path,target_platform="windows" if args.image else "unix"),hashes_only=True)

    wsl = ["wsl.exe", "-d", args.wsl_distro, "--"]
    if args.image:
        if not args.profile.startswith("/"):
            raise ValueError("Docker profile must be an absolute WSL path")
        if manifest["targetPlatform"] != "unix":
            raise ValueError("Docker requires a Linux-target export job")
        windows_profile = subprocess.check_output(wsl + ["wslpath", "-w", args.profile], text=True).strip()
        profile = Path(windows_profile)
        profile.mkdir(parents=True, exist_ok=True)
        manifest_wsl = subprocess.check_output(wsl + ["wslpath", "-a", "-u", manifest_path.as_posix()], text=True).strip()
        hashes_wsl = subprocess.check_output(wsl + ["wslpath", "-a", "-u", hash_manifest_path.as_posix()], text=True).strip()
        # Each invocation creates and removes a distinct container. Data mounts
        # are read-only; the image init and all network startup are bypassed.
        prefix = wsl + ["docker", "run", "--rm", "--network", "none", "--no-healthcheck", "--user", "1000:1000",
                        "--entrypoint", "/usr/lib/emulebb-rust/emulebb-rust",
                        "--mount", f"type=bind,src={args.profile},dst=/profile",
                        "--mount", f"type=bind,src={manifest_wsl},dst=/import.sqlite,readonly",
                        "--mount", f"type=bind,src={hashes_wsl},dst=/hashes.sqlite,readonly"]
        for source, target in args.mount:
            prefix += ["--mount", f"type=bind,src={source},dst={target},readonly"]
        prefix += [args.image, "--profile", "/profile"]
        import_path = "/import.sqlite"
        hashes_path = "/hashes.sqlite"
    else:
        if os.name != "nt":
            raise RuntimeError("native audit requires Windows; use --image for Docker")
        profile = Path(args.profile).resolve()
        binary = args.binary or output / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
        if not binary.is_file():
            raise FileNotFoundError(binary)
        prefix = [str(binary), "--profile", str(profile)]
        import_path = str(manifest_path)
        hashes_path = str(hash_manifest_path)

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
        if args.image and profile.resolve().is_relative_to(output.resolve()):
            # Reuse the harness's metadata-enabled output view so Linux can
            # enforce private settings permissions without moving generated data
            # outside the inherited workspace output root.
            from .rust_upload_soak import mount_wsl_output_with_metadata, unmount_wsl_output, wsl_metadata_path
            metadata_mount = mount_wsl_output_with_metadata(stamp, profile, distribution=args.wsl_distro)
            cleanup.callback(unmount_wsl_output, metadata_mount, distribution=args.wsl_distro)
            profile_mount = f"type=bind,src={args.profile},dst=/profile"
            prefix[prefix.index(profile_mount)] = f"type=bind,src={wsl_metadata_path(metadata_mount, profile)},dst=/profile"
        if args.prepare_windows_mounts:
            if not args.image:
                raise ValueError("--prepare-windows-mounts requires --image")
            prepare_windows_mounts(wsl, job, args.mount, cleanup)
        report["import"] = run_json(prefix + ["import-emule-profile", import_path], args.timeout)
        report["hashValidation"] = validate_imported_hashes(profile, manifest_path)
        report["firstPass"] = run_json(prefix + ["reconcile-shared-files"], args.timeout)
        validate_reconciliation(report["firstPass"])
        report["firstCounts"] = profile_counts(profile)
        report["hashOnlyReimport"] = run_json(
            prefix + ["import-emule-profile", "--hashes-only", hashes_path], args.timeout,
        )
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
        try:
            cleanup.close()
        finally:
            report["elapsedSeconds"] = round(time.monotonic() - started, 3)
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"report": str(report_path), **report}, indent=2))
    return 0
