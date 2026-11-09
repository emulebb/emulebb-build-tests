"""Verify universal Android APK native payloads before device qualification.

WHY: native archive and OCI smoke owners do not understand APK ZIP alignment.
The packaging owner supplies its canonical ELF auditor; this module owns only
the Android archive boundary, without duplicating ELF parsing or launching apps.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import stat
import struct
import tempfile
import zipfile

ABIS = ("arm64-v8a", "x86_64")
PAGE_SIZE = 16384
MAX_APK_SIZE = 512 * 1024 * 1024
MAX_NATIVE_SIZE = 256 * 1024 * 1024


def audit_native_payloads(apk: Path, *, scratch: Path, elf_auditor: Callable[..., dict],
                          library_name: str = "libemulebb_android.so") -> dict:
    """Bind both audited JNI libraries to stored, 16KB-aligned APK entries.

    Signature, package identity and source provenance require separate checks;
    successful static payload inspection does not qualify an Android runtime.
    """
    if (not library_name.startswith("lib") or not library_name.endswith(".so")
            or PurePosixPath(library_name).name != library_name or "\\" in library_name):
        raise ValueError("Expected a single native library filename")
    if apk.is_symlink() or not apk.is_file() or not 0 < apk.stat().st_size <= MAX_APK_SIZE:
        raise RuntimeError("Expected one bounded regular APK")
    if not scratch.is_absolute() or not scratch.is_dir() or scratch.is_symlink():
        raise RuntimeError("APK auditing requires an existing absolute owned scratch directory")
    expected = {f"lib/{abi}/{library_name}": abi for abi in ABIS}
    evidence = {}
    with apk.open("rb") as raw, zipfile.ZipFile(raw) as archive:
        raw.seek(0)
        original_checksum = hashlib.file_digest(raw, "sha256").hexdigest()
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) > 50000 or len(set(names)) != len(names):
            raise RuntimeError("APK has an excessive or duplicate ZIP inventory")
        for entry in entries:
            name = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if (not name.parts or name.is_absolute() or ".." in name.parts or "\\" in entry.filename
                    or stat.S_ISLNK(mode)):
                raise RuntimeError("APK ZIP inventory contains an unsafe path or symlink")
        native = {entry.filename: entry for entry in entries if entry.filename.startswith("lib/") and not entry.is_dir()}
        if set(native) != set(expected):
            raise RuntimeError("Universal APK must contain exactly the ARM64 and x86_64 JNI libraries")
        with tempfile.TemporaryDirectory(prefix="apk-native-", dir=scratch) as temporary:
            for name, abi in expected.items():
                entry = native[name]
                if (entry.compress_type != zipfile.ZIP_STORED or entry.flag_bits & 1
                        or entry.compress_size != entry.file_size or not 0 < entry.file_size <= MAX_NATIVE_SIZE):
                    raise RuntimeError("APK native libraries must be bounded, unencrypted and stored without compression")
                if entry.header_offset < 0 or entry.header_offset + 30 > apk.stat().st_size:
                    raise RuntimeError("APK native local header is out of bounds")
                raw.seek(entry.header_offset)
                header = raw.read(30)
                if len(header) != 30 or header[:4] != b"PK\x03\x04":
                    raise RuntimeError("APK native local ZIP header is invalid")
                flags, method = struct.unpack_from("<HH", header, 6)
                filename_length, extra_length = struct.unpack_from("<HH", header, 26)
                filename = raw.read(filename_length)
                offset = entry.header_offset + 30 + filename_length + extra_length
                if (flags & 1 or method != zipfile.ZIP_STORED or filename != name.encode("ascii")
                        or offset + entry.file_size > apk.stat().st_size or offset % PAGE_SIZE):
                    raise RuntimeError("APK native payload must have a matching local header and 16KB ZIP alignment")
                path = Path(temporary) / (abi + ".so")
                # Read through ZipFile to validate the central directory and CRC;
                # extraction names are owned constants, never archive paths.
                with archive.open(entry) as source, path.open("xb") as destination:
                    shutil.copyfileobj(source, destination)
                result = elf_auditor(path, abi, shared_library=True)
                if (result.get("abi") != abi or result.get("sharedLibrary") is not True
                        or result.get("pageSize") != PAGE_SIZE):
                    raise RuntimeError("APK ELF auditor returned inconsistent target evidence")
                with path.open("rb") as source:
                    checksum = hashlib.file_digest(source, "sha256").hexdigest()
                evidence[abi] = {"entry": name, "sha256": checksum, "size": entry.file_size,
                                 "zipOffset": offset, "zipAlignment": PAGE_SIZE, "elf": result}
        raw.seek(0)
        checksum = hashlib.file_digest(raw, "sha256").hexdigest()
        if checksum != original_checksum:
            raise RuntimeError("APK bytes changed during native validation")
    return {"schema": "emulebb.android.apk-native/1", "apk": apk.name,
            "apkSha256": checksum, "native": evidence, "runtimeExecution": "not-run"}
