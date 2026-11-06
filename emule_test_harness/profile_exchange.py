"""Streaming portable profile exchange; only metadata is read, never payloads.

SQLite is the interchange container, independent of the runtime database schema.
Cryptographic acceptance of imported recovery leaves belongs to Rust.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from contextlib import closing
from dataclasses import asdict
from pathlib import Path

from . import mfc_known_met as known

SCHEMA = "emulebb.profile-exchange.v1"
PART = 9_728_000
BLOCK = 184_320
MAX_FILE = 0x4000000000


def write_exchange(job, *, hashes_only=False):
    """Publish one closed, indexed exchange database after a consistent export."""
    from . import emule_profile_export as export
    config = export.resolve_emule_config_dir(job.source_profile)
    flavor = export.detect_profile_flavor(config)
    if job.flavor not in ("auto", flavor):
        raise ValueError("source flavor does not match the selected profile")
    paths = [config / "known.met", config / "known2_64.met"]
    before = {p: p.stat() for p in paths if p.exists()}
    roots = [] if hashes_only else [
        {"path": export.map_shared_root(r.path, job), "origin": r.origin}
        for r in export.discover_shared_roots(config, flavor)
    ]
    header = {"schema": SCHEMA, "targetPlatform": job.target_platform,
              "source": {"flavor": flavor}, "sharedRoots": roots}
    destination = job.output_manifest
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix="profile-exchange-", suffix=".tmp", delete=False) as f:
        temporary = Path(f.name)
    summary = {"knownRecords": 0, "recoverySets": 0, "recoveryParts": 0, "skippedKnown": 0}
    try:
        with closing(sqlite3.connect(temporary)) as db:
            db.executescript('''
                CREATE TABLE header(value TEXT NOT NULL);
                CREATE TABLE known_files(id INTEGER PRIMARY KEY, record TEXT NOT NULL, md4 BLOB NOT NULL, aich BLOB NOT NULL);
                CREATE TABLE recovery_sets(root BLOB NOT NULL, size_bytes INTEGER NOT NULL, PRIMARY KEY(root,size_bytes));
                CREATE TABLE recovery_parts(root BLOB NOT NULL,size_bytes INTEGER NOT NULL,part_index INTEGER NOT NULL,leaves BLOB NOT NULL,PRIMARY KEY(root,size_bytes,part_index));
                CREATE TABLE wanted_roots(root BLOB NOT NULL,size_bytes INTEGER NOT NULL,PRIMARY KEY(root,size_bytes));
            ''')
            db.execute("INSERT INTO header VALUES (?)", (json.dumps(header),))
            for entry in known.iter_known_met(config / "known.met"):
                size = entry.size_bytes
                if not entry.name or not size or not 0 < size <= MAX_FILE or entry.modified_s <= 0 or len(entry.md4_hashset) != known.expected_md4_hash_count(size):
                    summary["skippedKnown"] += 1
                    continue
                record = export._manifest_known_file({**asdict(entry), "size_bytes": size})
                md4 = bytes.fromhex("".join(record.pop("md4Hashset")))
                aich = bytes.fromhex("".join(record.pop("aichHashset")))
                db.execute("INSERT INTO known_files(record,md4,aich) VALUES (?,?,?)", (json.dumps(record), md4, aich))
                if entry.aich_root:
                    db.execute("INSERT OR IGNORE INTO wanted_roots VALUES (?,?)", (bytes.fromhex(entry.aich_root),size))
                summary["knownRecords"] += 1
            recovery = config / "known2_64.met"
            if recovery.exists():
                _copy_recovery(recovery, db, summary)
            db.execute("DROP TABLE wanted_roots")
            db.commit()
            if not summary["knownRecords"]:
                raise ValueError("profile has no reusable known-file records")
        for path, original in before.items():
            current = path.stat()
            if (current.st_size,current.st_mtime_ns,current.st_ino) != (original.st_size,original.st_mtime_ns,original.st_ino):
                raise RuntimeError("stock metadata changed during export; close MFC before exporting")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {**header,"summary":summary,"outputManifest":str(destination),"written":True}


def _copy_recovery(path, db, summary):
    """Index wanted roots in SQLite; copy a part-sized block at a time."""
    with path.open("rb") as stream:
        length = os.fstat(stream.fileno()).st_size
        if stream.read(1) != b"\x02":
            raise ValueError("unsupported known2_64.met version")
        while stream.tell() < length:
            root = stream.read(20)
            count = stream.read(4)
            if len(root) != 20 or len(count) != 4:
                raise ValueError("truncated AICH recovery header")
            count = int.from_bytes(count,"little")
            start = stream.tell()
            end = start + count * 20
            if end > length:
                raise ValueError("truncated AICH recovery leaves")
            for (size,) in db.execute("SELECT size_bytes FROM wanted_roots WHERE root=?", (root,)).fetchall():
                full, tail = divmod(size,PART)
                expected = full * ((PART+BLOCK-1)//BLOCK) + (tail+BLOCK-1)//BLOCK
                if count != expected:
                    continue
                if db.execute("SELECT 1 FROM recovery_sets WHERE root=? AND size_bytes=?",(root,size)).fetchone():
                    continue
                stream.seek(start)
                for index in range((size+PART-1)//PART):
                    n = (min(PART,size-index*PART)+BLOCK-1)//BLOCK * 20
                    leaves = stream.read(n)
                    db.execute("INSERT INTO recovery_parts VALUES (?,?,?,?)",(root,size,index,leaves))
                    summary["recoveryParts"] += 1
                db.execute("INSERT INTO recovery_sets VALUES (?,?)",(root,size))
                summary["recoverySets"] += 1
            stream.seek(end)
