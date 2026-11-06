"""Offline stock hash import and target-filesystem reconciliation evidence."""

from __future__ import annotations

import argparse
import hashlib
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
                "known_files", "verified_local_content",
                "verified_local_md4_hashes", "verified_local_aich_hashes", "local_file_instances",
                "transfers", "shared_directory_roots", "aich_recovery_sets", "aich_recovery_parts",
            )
        }


def _rows_digest(rows) -> bytes:
    """Fingerprint ordered metadata rows while retaining only one row in memory."""
    digest = hashlib.sha256()
    for row in rows:
        digest.update(json.dumps([value.hex() if isinstance(value, bytes) else value for value in row],
                                 separators=(",", ":")).encode("utf-8") + b"\n")
    return digest.digest()


def _content_digest(connection, content_id: int) -> bytes:
    header = connection.execute("SELECT f.size_bytes,f.aich_root,c.aich_root FROM known_files f JOIN verified_local_content c ON c.known_file_id=f.id WHERE f.id=?", (content_id,)).fetchone()
    hashes = [header]
    # Each child collection contributes its own fixed-size digest, including
    # indices, so missing/reordered hashes cannot resemble an unchanged record.
    for table, column in (("verified_local_md4_hashes", "md4_hash"), ("verified_local_aich_hashes", "aich_hash")):
        hashes.append((_rows_digest(connection.execute(f"SELECT part_index,{column} FROM {table} WHERE known_file_id=? ORDER BY part_index", (content_id,))),))
    return _rows_digest(hashes)


def _recovery_digest(connection, root: bytes, size: int) -> bytes:
    return _rows_digest(connection.execute("SELECT part_index,leaves,part_root FROM aich_recovery_parts WHERE root=? AND size_bytes=? ORDER BY part_index", (root, size)))


def capture_import_baseline(profile: Path, exchange: Path, destination: Path) -> dict[str, int]:
    """Retain bounded-memory preservation evidence outside the live profile DB.

    Only digests are retained for content/tree metadata; no payload is opened.
    Recovery fingerprints are limited to sets present in the incoming archive.
    """
    result = {"contentRecords": 0, "pathBindings": 0, "recoverySets": 0}
    with closing(sqlite3.connect(destination)) as baseline:
        baseline.executescript("CREATE TABLE content(file_hash BLOB PRIMARY KEY,signature BLOB); CREATE TABLE bindings(platform TEXT,native_path BLOB,signature BLOB,PRIMARY KEY(platform,native_path)); CREATE TABLE recovery(root BLOB,size_bytes INTEGER,signature BLOB,PRIMARY KEY(root,size_bytes));")
        if not (profile / "emulebb-rust-metadata.db").exists():
            return result
        with closing(open_profile_snapshot(profile)) as target:
            target.execute("ATTACH DATABASE ? AS exchange", (exchange.as_uri() + "?mode=ro&immutable=1",))
            for content_id, file_hash in target.execute("SELECT known_file_id,ed2k_hash FROM verified_local_content JOIN known_files ON known_files.id=known_file_id"):
                baseline.execute("INSERT INTO content VALUES (?,?)", (file_hash, _content_digest(target, content_id)))
                result["contentRecords"] += 1
            for row in target.execute("SELECT p.platform,p.native_path,i.file_size,i.verified_fingerprint,f.ed2k_hash FROM local_file_instances i JOIN local_paths p ON p.id=i.path_id JOIN known_files f ON f.id=i.known_file_id"):
                baseline.execute("INSERT INTO bindings VALUES (?,?,?)", (row[0], row[1], _rows_digest([row])))
                result["pathBindings"] += 1
            for root, size in target.execute("SELECT r.root,r.size_bytes FROM aich_recovery_sets r JOIN exchange.recovery_sets e ON e.root=r.root AND e.size_bytes=r.size_bytes"):
                baseline.execute("INSERT INTO recovery VALUES (?,?,?)", (root, size, _recovery_digest(target, root, size)))
                result["recoverySets"] += 1
        baseline.commit()
    return result


def _unchanged_content(target, baseline, content_id: int, file_hash: bytes) -> bool:
    if baseline is None:
        return False
    before = baseline.execute("SELECT signature FROM content WHERE file_hash=?", (file_hash,)).fetchone()
    return before is not None and before[0] == _content_digest(target, content_id)


def _unchanged_binding(target, baseline, row, content_id: int) -> bool:
    if baseline is None:
        return False
    before = baseline.execute("SELECT signature FROM bindings WHERE platform=? AND native_path=?", row[:2]).fetchone()
    return (before is not None and before[0] == _rows_digest([row])
            and _unchanged_content(target, baseline, content_id, row[4]))


def _validate_record_hashes(target, record, md4, aich, row) -> tuple[int, int]:
    if record["aichRoot"] and (row[1] or None) != record["aichRoot"].lower():
        raise RuntimeError("imported hashset differs from the export")
    counts = []
    for table, column, expected in (("verified_local_md4_hashes", "md4_hash", md4), ("verified_local_aich_hashes", "aich_hash", aich)):
        hashes = [r[0] for r in target.execute(f"SELECT {column} FROM {table} WHERE known_file_id=? ORDER BY part_index", (row[0],))]
        if column == "aich_hash" and not expected:
            if not record["aichRoot"]:
                counts.append(len(hashes))
                continue
            if hashes:
                recovered = [r[0] for r in target.execute("SELECT part_root FROM aich_recovery_parts WHERE root=? AND size_bytes=? ORDER BY part_index", (bytes.fromhex(record["aichRoot"]), record["fileSize"]))]
                if recovered != hashes:
                    raise RuntimeError("enriched AICH part hashes differ from recovery cache")
                expected = b"".join(recovered)
        if b"".join(hashes) != expected:
            raise RuntimeError("imported hashset differs from the export")
        counts.append(len(hashes))
    return tuple(counts)


def validate_imported_hashes(profile: Path, exchange: Path, *, rejected_recovery_sets: int = 0,
                             baseline: Path | None = None) -> dict[str, int]:
    """Verify accepted hashes and prove rejected preexisting metadata unchanged."""
    if type(rejected_recovery_sets) is not int or rejected_recovery_sets < 0:
        raise ValueError("rejected recovery count must be a nonnegative integer")
    result = {"verifiedImportedRecords":0,"verifiedMd4Parts":0,"verifiedAichParts":0,"verifiedRecoverySets":0,"verifiedRecoveryParts":0,"unavailableRecoverySets":0,
              "preservedConflictingRecords":0,"retainedExistingRecoverySets":0}
    with ExitStack() as resources, closing(open_profile_snapshot(profile)) as target, closing(sqlite3.connect(exchange.as_uri()+"?mode=ro&immutable=1",uri=True)) as source:
        previous = resources.enter_context(closing(sqlite3.connect(baseline.as_uri()+"?mode=ro&immutable=1",uri=True))) if baseline else None
        for record,md4,aich in source.execute("SELECT record,md4,aich FROM known_files ORDER BY id"):
            record=json.loads(record)
            row=target.execute("SELECT c.known_file_id,lower(hex(c.aich_root)) FROM verified_local_content c JOIN known_files f ON f.id=c.known_file_id WHERE f.ed2k_hash=? AND f.size_bytes=?",(bytes.fromhex(record["fileHash"]),record["fileSize"])).fetchone()
            if row is None:
                if previous is not None and previous.execute("SELECT 1 FROM content WHERE file_hash=?", (bytes.fromhex(record["fileHash"]),)).fetchone():
                    existing = target.execute("SELECT c.known_file_id FROM verified_local_content c JOIN known_files f ON f.id=c.known_file_id WHERE f.ed2k_hash=?", (bytes.fromhex(record["fileHash"]),)).fetchone()
                    if existing is None or not _unchanged_content(target, previous, existing[0], bytes.fromhex(record["fileHash"])):
                        raise RuntimeError("preexisting verified content disappeared or changed size during import")
                continue
            try:
                md4_count, aich_count = _validate_record_hashes(target, record, md4, aich, row)
            except RuntimeError:
                # WHY: a source conflict is not corruption of accepted data.
                # Independently prove exact preservation, never waive by count.
                if not _unchanged_content(target, previous, row[0], bytes.fromhex(record["fileHash"])):
                    raise
                result["preservedConflictingRecords"] += 1
                continue
            result["verifiedMd4Parts"] += md4_count
            result["verifiedAichParts"] += aich_count
            result["verifiedImportedRecords"]+=1
        for root,size in source.execute("SELECT root,size_bytes FROM recovery_sets"):
            if target.execute("SELECT 1 FROM verified_local_content c JOIN known_files f ON f.id=c.known_file_id WHERE c.aich_root=? AND f.size_bytes=? LIMIT 1", (root,size)).fetchone() is None:
                continue
            present = target.execute("SELECT 1 FROM aich_recovery_sets WHERE root=? AND size_bytes=?", (root,size)).fetchone()
            target_count = target.execute("SELECT count(*) FROM aich_recovery_parts WHERE root=? AND size_bytes=?", (root,size)).fetchone()[0]
            if present is None:
                if target_count:
                    raise RuntimeError("absent recovery set has partial imported leaves")
                if previous is not None and previous.execute("SELECT 1 FROM recovery WHERE root=? AND size_bytes=?", (root, size)).fetchone():
                    raise RuntimeError("preexisting AICH recovery set disappeared during import")
                result["unavailableRecoverySets"] += 1
                continue
            if target_count != (size + 9_727_999) // 9_728_000:
                raise RuntimeError("imported AICH recovery set is partial or has extra parts")
            for index, length in target.execute("SELECT part_index,length(leaves) FROM aich_recovery_parts WHERE root=? AND size_bytes=? ORDER BY part_index", (root, size)):
                expected_length = (min(size-index*9_728_000,9_728_000)+184_319)//184_320*20
                if index < 0 or index >= target_count or length != expected_length:
                    raise RuntimeError("imported AICH recovery set has invalid part geometry")
            source_count = source.execute("SELECT count(*) FROM recovery_parts WHERE root=? AND size_bytes=?", (root,size)).fetchone()[0]
            differs = source_count != target_count
            for index,leaves in source.execute("SELECT part_index,leaves FROM recovery_parts WHERE root=? AND size_bytes=? ORDER BY part_index",(root,size)):
                row=target.execute("SELECT leaves FROM aich_recovery_parts WHERE root=? AND size_bytes=? AND part_index=?",(root,size,index)).fetchone()
                if row is None or row[0]!=leaves:
                    differs = True
            if differs:
                before = previous.execute("SELECT signature FROM recovery WHERE root=? AND size_bytes=?", (root, size)).fetchone() if previous else None
                if before is None or before[0] != _recovery_digest(target, root, size):
                    raise RuntimeError("imported AICH recovery leaves differ from the export")
                result["retainedExistingRecoverySets"] += 1
                continue
            result["verifiedRecoveryParts"] += target_count
            result["verifiedRecoverySets"]+=1
        # WHY: optional-cache rejection must not abort valid MD4 reconciliation,
        # but a rejection count must never excuse partial or altered accepted sets.
        if result["unavailableRecoverySets"] + result["retainedExistingRecoverySets"] != rejected_recovery_sets:
            raise RuntimeError("missing AICH recovery sets do not match reported rejections")
    return result


def mount_argument(value: str) -> tuple[str, str]:
    """Parse an explicit WSL host directory to container directory mapping."""
    source, separator, target = value.partition("=")
    if not separator or not source.startswith("/") or not target.startswith("/"):
        raise argparse.ArgumentTypeError("mount must be /host/path=/container/path")
    return source, target


def validate_stock_records(profile: Path, config: Path, exchange: Path | None = None) -> dict[str, int]:
    """Check stock records against the retained archive, never native staging tables."""
    if exchange is None:
        raise ValueError("stock validation requires the retained exchange archive")
    result = {"verifiedStockRecords": 0, "verifiedStockMd4Parts": 0}
    with closing(sqlite3.connect(exchange.as_uri()+"?mode=ro&immutable=1",uri=True)) as source:
        for entry in mfc_known_met.iter_known_met(config / "known.met"):
            if not entry.name or not entry.size_bytes or len(entry.md4_hashset) != mfc_known_met.expected_md4_hash_count(entry.size_bytes):
                continue
            row=source.execute("SELECT md4,record FROM known_files WHERE json_extract(record,'$.fileHash')=? AND json_extract(record,'$.displayName')=? AND json_extract(record,'$.fileSize')=? AND json_extract(record,'$.modifiedS')=?",(entry.ed2k_hash,entry.name,entry.size_bytes,entry.modified_s)).fetchone()
            if row is None or row[0] != bytes.fromhex(''.join(entry.md4_hashset)) or json.loads(row[1])["aichRoot"] != entry.aich_root:
                raise RuntimeError("stock record differs from portable archive")
            result["verifiedStockRecords"] += 1
            result["verifiedStockMd4Parts"] += len(entry.md4_hashset)
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


def validate_native_bindings(profile: Path, job: emule_profile_export.ExportJob, *,
                             host_mappings: tuple[emule_profile_export.PathMapping, ...] | None = None,
                             exchange: Path | None = None, allow_unrelated: bool = False,
                             conflicting_paths: int = 0, baseline: Path | None = None) -> dict[str, int]:
    """Independently check every accepted path, stock match, and native hashset.

    Files are only stat-ed; Windows file-ID checks open handles without reading
    payload bytes. The lookup uses the path's actual basename and current mtime,
    not the content ID already chosen by the Rust importer.
    """
    config = emule_profile_export.resolve_emule_config_dir(job.source_profile)
    flavor = emule_profile_export.detect_profile_flavor(config)
    roots = [Path(r.path) for r in emule_profile_export.discover_shared_roots(config, flavor)]
    if host_mappings is not None:
        roots = [Path(emule_profile_export.map_shared_root(str(r), job)) if job.target_platform == "windows"
                 else source_path_for_binding("unix", emule_profile_export.map_shared_root(str(r), job).encode(), host_mappings)
                 for r in roots]
    result = {"verifiedPathBindings": 0, "verifiedNativeMd4Parts": 0,
              "verifiedNativeAichParts": 0, "verifiedWindowsFingerprints": 0,
              "verifiedRemappedPaths": 0}
    if exchange is None:
        exchange = job.output_manifest
    untouched = skipped_conflicts = 0
    with ExitStack() as resources, closing(open_profile_snapshot(profile)) as target, closing(sqlite3.connect(exchange.as_uri()+"?mode=ro&immutable=1",uri=True)) as source:
        previous = resources.enter_context(closing(sqlite3.connect(baseline.as_uri()+"?mode=ro&immutable=1",uri=True))) if baseline else None
        rows = target.execute(
            "SELECT p.platform,p.native_path,i.file_size,i.verified_fingerprint,"
            "k.id,k.ed2k_hash,k.size_bytes,k.aich_root,c.aich_root "
            "FROM local_file_instances i JOIN local_paths p ON p.id=i.path_id "
            "JOIN known_files k ON k.id=i.known_file_id "
            "JOIN verified_local_content c ON c.known_file_id=k.id"
        )
        for platform, native, size, stored, content_id, file_hash, content_size, root, verified_root in rows:
            if allow_unrelated:
                display = mfc_known_met.normal_windows_display_path(native.decode("utf-16-le", "surrogatepass")) if platform == "windows" else native.decode("utf-8", "surrogateescape")
                candidate = source.execute("SELECT k.record,k.md4,k.aich FROM file_paths p JOIN known_files k ON k.id=p.known_file_id WHERE p.path=?",(display,)).fetchone()
                if candidate is None:
                    untouched += 1
                    continue
                record = json.loads(candidate[0])
                differs = (bytes.fromhex(record["fileHash"]) != file_hash or record["fileSize"] != content_size
                           or bool(record["aichRoot"] and root != bytes.fromhex(record["aichRoot"])))
                if skipped_conflicts < conflicting_paths:
                    try:
                        _validate_record_hashes(target, record, candidate[1], candidate[2], (content_id, verified_root.hex() if verified_root else None))
                    except RuntimeError:
                        differs = True
                if differs and conflicting_paths:
                    if not _unchanged_binding(target, previous, (platform, native, size, stored, file_hash), content_id):
                        raise RuntimeError("conflicting native binding lacks unchanged pre-import evidence")
                    skipped_conflicts += 1
                    continue
            path = source_path_for_binding(platform, native, host_mappings if host_mappings is not None else job.path_mappings)
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
            candidates = source.execute(
                "SELECT record,md4,aich FROM known_files WHERE json_extract(record,'$.displayName')=? AND json_extract(record,'$.fileSize')=? AND json_extract(record,'$.modifiedS')=?",
                (path.name,size,current.st_mtime_ns//1_000_000_000),
            )
            signature = None
            for record,md4,aich in candidates:
                record=json.loads(record)
                candidate_root=bytes.fromhex(record["aichRoot"]) if record["aichRoot"] else None
                if not aich and size > 9728000 and candidate_root:
                    aich=b''.join(r[0] for r in target.execute("SELECT part_root FROM aich_recovery_parts WHERE root=? AND size_bytes=? ORDER BY part_index",(candidate_root,size)))
                candidate=(bytes.fromhex(record["fileHash"]),candidate_root,tuple(md4[i:i+16] for i in range(0,len(md4),16)),tuple(aich[i:i+20] for i in range(0,len(aich),20)))
                if signature is not None and candidate != signature:
                    raise RuntimeError("native binding has no unambiguous stock identity match")
                signature=candidate
            if signature is None:
                raise RuntimeError("native binding has no unambiguous stock identity match")
            expected_hash, expected_root, md4, aich = signature
            if file_hash != expected_hash or (expected_root is not None and (root != expected_root or verified_root != expected_root)):
                raise RuntimeError("native content identity differs from the matched stock record")
            for table, column, expected, counter in (
                ("verified_local_md4_hashes", "md4_hash", md4, "verifiedNativeMd4Parts"),
                ("verified_local_aich_hashes", "aich_hash", aich, "verifiedNativeAichParts"),
            ):
                if column == "aich_hash" and not expected and expected_root is None:
                    continue
                actual = tuple(r[0] for r in target.execute(
                    f"SELECT {column} FROM {table} WHERE known_file_id=? ORDER BY part_index", (content_id,),
                ))
                if actual != expected:
                    raise RuntimeError("native content hashset differs from the matched stock record")
                result[counter] += len(actual)
            result["verifiedPathBindings"] += 1
        if skipped_conflicts != conflicting_paths:
            raise RuntimeError("live binding conflicts differ from the import report")
        result["preservedConflictingBindings"] = skipped_conflicts
        if result["verifiedPathBindings"] + untouched + skipped_conflicts != target.execute("SELECT count(*) FROM local_file_instances").fetchone()[0]:
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
            profile, emule_profile_export.resolve_emule_config_dir(job.source_profile), manifest_path,
        )
        report["firstPass"] = run_json(prefix + ["reconcile-shared-files"], args.timeout)
        validate_reconciliation(report["firstPass"],require_complete_reuse=args.require_complete_reuse)
        report["firstCounts"] = profile_counts(profile)
        report["firstBindingValidation"] = validate_native_bindings(profile, job, exchange=manifest_path)
        if report["firstBindingValidation"]["verifiedPathBindings"] != report["firstPass"]["reusedCount"]:
            raise RuntimeError("accepted native bindings differ from the reported reused files")
        report["hashOnlyReimport"] = run_json(
            prefix + ["import-emule-profile", "--hashes-only", hashes_path], args.timeout,
        )
        report["secondPass"] = run_json(prefix + ["reconcile-shared-files"], args.timeout)
        validate_reconciliation(report["secondPass"],require_complete_reuse=args.require_complete_reuse)
        report["secondCounts"] = profile_counts(profile)
        report["secondHashValidation"] = validate_imported_hashes(profile, manifest_path)
        report["secondBindingValidation"] = validate_native_bindings(profile, job, exchange=manifest_path)
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
