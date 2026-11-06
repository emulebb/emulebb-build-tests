"""Offline stock hash import and target-filesystem reconciliation evidence."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
import subprocess
import time
from contextlib import ExitStack, closing
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import emule_profile_export
from .paths import get_workspace_output_root
from . import mfc_known_met, rust_native_fingerprint


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


def validate_stock_records(profile: Path, config: Path) -> dict[str, int]:
    """Compare imported identities and MD4 hashes directly with the stock reader."""
    result = {"verifiedStockRecords": 0, "verifiedStockMd4Parts": 0, "unusableStockRecords": 0}
    with closing(open_profile_snapshot(profile)) as target:
        for entry in mfc_known_met.iter_known_met(config / "known.met"):
            if (not entry.name or not entry.size_bytes or not 0 < entry.size_bytes <= 0x4000000000
                    or entry.modified_s <= 0
                    or len(entry.md4_hashset) != mfc_known_met.expected_md4_hash_count(entry.size_bytes)):
                result["unusableStockRecords"] += 1
                continue
            row = target.execute(
                "SELECT id,aich_root FROM imported_known_files "
                "WHERE ed2k_hash=? AND display_name=? AND size_bytes=? AND modified_s=?",
                (bytes.fromhex(entry.ed2k_hash), entry.name, entry.size_bytes, entry.modified_s),
            ).fetchone()
            if row is None:
                raise RuntimeError("stock record is missing from the imported aliases")
            root = bytes.fromhex(entry.aich_root) if entry.aich_root else None
            md4 = [r[0].hex() for r in target.execute(
                "SELECT md4_hash FROM imported_known_file_md4_hashes "
                "WHERE imported_known_file_id=? ORDER BY part_index", (row[0],),
            )]
            if row[1] != root or md4 != entry.md4_hashset:
                raise RuntimeError("stock identity or MD4 hashset differs from the imported alias")
            if entry.aich_hashset:
                aich = [r[0].hex() for r in target.execute(
                    "SELECT aich_hash FROM imported_known_file_aich_hashes "
                    "WHERE imported_known_file_id=? ORDER BY part_index", (row[0],),
                )]
                if aich != entry.aich_hashset:
                    raise RuntimeError("stock AICH part hashes differ from the imported alias")
            result["verifiedStockRecords"] += 1
            result["verifiedStockMd4Parts"] += len(md4)
    return result


def source_path_for_binding(platform: str, native: bytes,
                            mappings: tuple[emule_profile_export.PathMapping, ...]) -> Path:
    """Decode native path bytes and reverse explicit container mappings by boundary."""
    if platform == "windows":
        return Path(mfc_known_met.normal_windows_display_path(native.decode("utf-16-le", "surrogatepass")))
    if platform != "unix":
        raise RuntimeError("unsupported native path platform in import audit")
    path = PurePosixPath(native.decode("utf-8", "surrogateescape"))
    if not path.is_absolute() or ".." in path.parts:
        raise RuntimeError("invalid native path in import audit")
    for mapping in sorted(mappings, key=lambda item: len(PurePosixPath(item.target).parts), reverse=True):
        try:
            relative = path.relative_to(PurePosixPath(mapping.target))
        except ValueError:
            continue
        return Path(mapping.source).joinpath(*relative.parts)
    raise RuntimeError("native path has no explicit source mapping")


def validate_native_bindings(profile: Path, job: emule_profile_export.ExportJob) -> dict[str, int]:
    """Independently check every accepted path, stock match, and native hashset.

    Files are only stat-ed; Windows file-ID checks open handles without reading
    payload bytes. The lookup uses the path's actual basename and current mtime,
    not the content ID already chosen by the Rust importer.
    """
    config = emule_profile_export.resolve_emule_config_dir(job.source_profile)
    flavor = emule_profile_export.detect_profile_flavor(config)
    roots = [Path(r.path) for r in emule_profile_export.discover_shared_roots(config, flavor)]
    result = {"verifiedPathBindings": 0, "verifiedNativeMd4Parts": 0,
              "verifiedNativeAichParts": 0, "verifiedWindowsFingerprints": 0,
              "verifiedRemappedPaths": 0}
    with closing(open_profile_snapshot(profile)) as target:
        rows = target.execute(
            "SELECT p.platform,p.native_path,i.file_size,i.verified_fingerprint,"
            "k.id,k.ed2k_hash,k.size_bytes,k.aich_root,c.aich_root "
            "FROM local_file_instances i JOIN local_paths p ON p.id=i.path_id "
            "JOIN known_files k ON k.id=i.known_file_id "
            "JOIN verified_local_content c ON c.known_file_id=k.id"
        )
        for platform, native, size, stored, content_id, file_hash, content_size, root, verified_root in rows:
            path = source_path_for_binding(platform, native, job.path_mappings)
            if not any(path.is_relative_to(parent) for parent in roots):
                raise RuntimeError("native binding is outside the stock shared roots")
            current = path.stat()
            fingerprint = rust_native_fingerprint.decode_fingerprint(stored)
            if (not stat.S_ISREG(current.st_mode) or size != current.st_size or content_size != size
                    or fingerprint.size_bytes != size
                    or (fingerprint.modified.seconds, fingerprint.modified.nanoseconds)
                    != divmod(current.st_mtime_ns, 1_000_000_000)):
                raise RuntimeError("native binding fingerprint differs from the current source file")
            if platform == "windows":
                if os.name != "nt":
                    raise RuntimeError("Windows file-ID validation requires Windows")
                if rust_native_fingerprint.windows_native_fingerprint(path) != fingerprint:
                    raise RuntimeError("native Windows file identity differs from the source file")
                result["verifiedWindowsFingerprints"] += 1
            else:
                if fingerprint.identity_kind != rust_native_fingerprint.IDENTITY_UNIX:
                    raise RuntimeError("native binding fingerprint belongs to another platform")
                result["verifiedRemappedPaths"] += 1
            candidates = target.execute(
                "SELECT id,ed2k_hash,aich_root FROM imported_known_files "
                "WHERE display_name=? AND size_bytes=? AND modified_s=?",
                (path.name, size, current.st_mtime_ns // 1_000_000_000),
            )
            signature = None
            for alias_id, candidate_hash, candidate_root in candidates:
                parts = []
                for table, column in (("imported_known_file_md4_hashes", "md4_hash"),
                                      ("imported_known_file_aich_hashes", "aich_hash")):
                    parts.append(tuple(r[0] for r in target.execute(
                        f"SELECT {column} FROM {table} WHERE imported_known_file_id=? ORDER BY part_index",
                        (alias_id,),
                    )))
                candidate = (candidate_hash, candidate_root, *parts)
                if signature is not None and candidate != signature:
                    raise RuntimeError("native binding has no unambiguous stock identity match")
                signature = candidate
            if signature is None:
                raise RuntimeError("native binding has no unambiguous stock identity match")
            expected_hash, expected_root, md4, aich = signature
            if file_hash != expected_hash or root != expected_root or verified_root != expected_root:
                raise RuntimeError("native content identity differs from the matched stock record")
            for table, column, expected, counter in (
                ("verified_local_md4_hashes", "md4_hash", md4, "verifiedNativeMd4Parts"),
                ("verified_local_aich_hashes", "aich_hash", aich, "verifiedNativeAichParts"),
            ):
                actual = tuple(r[0] for r in target.execute(
                    f"SELECT {column} FROM {table} WHERE known_file_id=? ORDER BY part_index", (content_id,),
                ))
                if actual != expected:
                    raise RuntimeError("native content hashset differs from the matched stock record")
                result[counter] += len(actual)
            result["verifiedPathBindings"] += 1
        if result["verifiedPathBindings"] != target.execute("SELECT count(*) FROM local_file_instances").fetchone()[0]:
            raise RuntimeError("native bindings contain content without verified hash metadata")
    return result


def validate_reconciliation(report: dict, *, require_complete_reuse: bool = False) -> None:
    """Fail if an offline pass reports hashing, payload reads, or active work."""
    if any(report[key] for key in ("hashedCount", "completedReadBytes", "activeHashCount", "running")):
        raise RuntimeError("offline reconciliation performed unexpected payload work")
    if require_complete_reuse and report.get("plannedHashCount",0):
        raise RuntimeError("complete reuse audit found files queued for hashing")


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
    parser.add_argument("--create-fixture", type=Path, help="Create a fresh output-root stock profile from standard MD4 test vectors and exit")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--profile", help="Windows path, or WSL path with --image")
    parser.add_argument("--image", help="Use isolated network-none Docker containers in WSL")
    parser.add_argument("--wsl-distro", default="Ubuntu")
    parser.add_argument("--mount", action="append", type=mount_argument, default=[])
    parser.add_argument("--prepare-windows-mounts", action="store_true",
                        help="Temporarily mount missing mapped Windows volumes read-only")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--timeout", type=int, default=7200)
    parser.add_argument("--require-complete-reuse", action="store_true", help="Fail if reconciliation plans any payload hashing")
    args = parser.parse_args(argv)
    if args.create_fixture:
        print(json.dumps(create_import_fixture(args.create_fixture),indent=2))
        return 0
    if args.config is None or args.profile is None:
        parser.error("--config and --profile are required for an import audit")
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
        report["stockValidation"] = validate_stock_records(
            profile, emule_profile_export.resolve_emule_config_dir(job.source_profile),
        )
        report["firstPass"] = run_json(prefix + ["reconcile-shared-files"], args.timeout)
        validate_reconciliation(report["firstPass"],require_complete_reuse=args.require_complete_reuse)
        report["firstCounts"] = profile_counts(profile)
        report["firstBindingValidation"] = validate_native_bindings(profile, job)
        if report["firstBindingValidation"]["verifiedPathBindings"] != report["firstPass"]["reusedCount"]:
            raise RuntimeError("accepted native bindings differ from the reported reused files")
        report["hashOnlyReimport"] = run_json(
            prefix + ["import-emule-profile", "--hashes-only", hashes_path], args.timeout,
        )
        report["secondPass"] = run_json(prefix + ["reconcile-shared-files"], args.timeout)
        validate_reconciliation(report["secondPass"],require_complete_reuse=args.require_complete_reuse)
        report["secondCounts"] = profile_counts(profile)
        report["secondHashValidation"] = validate_imported_hashes(profile, manifest_path)
        report["secondBindingValidation"] = validate_native_bindings(profile, job)
        if report["hashValidation"] != report["secondHashValidation"]:
            raise RuntimeError("hash validation changed across the hash-only reimport")
        if report["firstBindingValidation"] != report["secondBindingValidation"]:
            raise RuntimeError("native bindings changed across the hash-only reimport")
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


def create_import_fixture(root: Path) -> dict:
    """Create an isolated stock profile using RFC 1320 MD4 vectors, never operator data."""
    import base64
    import hashlib
    import struct
    from .ini import write_utf16_ini_text
    from . import mfc_known_met as known
    root=root.resolve()
    if not root.is_relative_to(get_workspace_output_root().resolve()):
        raise ValueError("synthetic import fixtures must remain under the workspace output root")
    if root.exists() and any(root.iterdir()):
        raise ValueError("synthetic fixture target must be new or empty")
    config=root/"stock"/"config"
    config.mkdir(parents=True)
    shared=root/"shared"
    shared.mkdir()
    vectors=[(b"a","bde52cb31de33e46245e05fbdbd6fb24"),(b"abc","a448017aaf21d8525fc10ae87aa6729d"),(b"message digest","d9130a8164549fe818874806e1c7014b"),(b"a","bde52cb31de33e46245e05fbdbd6fb24")]
    records=[]
    recovery=bytearray(b"\x02")
    timestamp=1_700_000_000
    for index,(payload,md4) in enumerate(vectors):
        name=f"Sample-{index}-caf\u00e9-\u6f22.bin" if index==3 else f"Sample-{index}.bin"
        path=shared/name
        path.write_bytes(payload)
        os.utime(path,(timestamp,timestamp))
        master=hashlib.sha1(payload).digest()
        def string_tag(identifier,value):
            raw=value.encode("utf-8")
            if not value.isascii():
                raw=b"\xef\xbb\xbf"+raw
            return bytes([known.TAGTYPE_STRING])+struct.pack("<H",1)+bytes([identifier])+struct.pack("<H",len(raw))+raw
        tags=[string_tag(known.FT_FILENAME,name),bytes([known.TAGTYPE_UINT64])+struct.pack("<H",1)+bytes([known.FT_FILESIZE])+struct.pack("<Q",len(payload)),string_tag(known.FT_AICH_HASH,base64.b32encode(master).decode().rstrip("="))]
        records.append(struct.pack("<I",timestamp)+bytes.fromhex(md4)+struct.pack("<HI",0,len(tags))+b"".join(tags))
        recovery+=master+struct.pack("<I",1)+master
    (config/"known.met").write_bytes(bytes([known.MET_HEADER_I64TAGS])+struct.pack("<I",len(records))+b"".join(records))
    (config/"known2_64.met").write_bytes(recovery)
    write_utf16_ini_text(config/"preferences.ini",f"IncomingDir={shared}\r\n")
    write_utf16_ini_text(config/"shareddir.dat",f"{shared}\r\n")
    result={"fixture":str(root),"shared":str(shared),"files":len(vectors)}
    for platform in ("windows","linux"):
        job=root/f"{platform}.toml"
        text=f"schema_version=1\n[source]\nprofile='{(root/'stock').as_posix()}'\nflavor='stock'\n[target]\nplatform='{platform}'\n[output]\nmanifest='{(root/(platform+'.sqlite')).as_posix()}'\n"
        if platform=="linux":
            text+=f"[[path_mappings]]\nsource='{shared.as_posix()}'\ntarget='/data/sample'\n"
        job.write_text(text,encoding="utf-8",newline="\n")
        result[platform+"Config"]=str(job)
    return result
