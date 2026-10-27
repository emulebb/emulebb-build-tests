"""Read and write the current Rust native-file fingerprint blob on Windows."""

from __future__ import annotations

import ctypes
import os
import struct
from dataclasses import dataclass
from pathlib import Path

FINGERPRINT_STORAGE_VERSION = 1
IDENTITY_UNIX = 1
IDENTITY_WINDOWS_LOW_RESOLUTION = 2
IDENTITY_WINDOWS_HIGH_RESOLUTION = 3
WINDOWS_TO_UNIX_EPOCH_100NS = 116_444_736_000_000_000
WINDOWS_TICKS_PER_SECOND = 10_000_000


@dataclass(frozen=True)
class NativeTimestamp:
    """One decoded Rust native timestamp."""

    seconds: int
    nanoseconds: int


@dataclass(frozen=True)
class NativeFingerprint:
    """One decoded Rust native-file fingerprint."""

    identity_kind: int
    identity_bytes: bytes
    size_bytes: int
    modified: NativeTimestamp
    changed: NativeTimestamp | None


def windows_ticks_to_timestamp(file_time_100ns: int) -> NativeTimestamp:
    """Converts one signed Windows FILETIME value to the Rust timestamp model."""

    unix_ticks = int(file_time_100ns) - WINDOWS_TO_UNIX_EPOCH_100NS
    seconds, remainder = divmod(unix_ticks, WINDOWS_TICKS_PER_SECOND)
    return NativeTimestamp(seconds=seconds, nanoseconds=remainder * 100)


def encode_fingerprint(fingerprint: NativeFingerprint) -> bytes:
    """Encodes the exact current Rust native-file fingerprint storage format."""

    if fingerprint.identity_kind == IDENTITY_UNIX:
        expected_identity_bytes = 16
    elif fingerprint.identity_kind == IDENTITY_WINDOWS_LOW_RESOLUTION:
        expected_identity_bytes = 12
    elif fingerprint.identity_kind == IDENTITY_WINDOWS_HIGH_RESOLUTION:
        expected_identity_bytes = 24
    else:
        raise ValueError(f"unsupported native identity kind: {fingerprint.identity_kind}")
    if len(fingerprint.identity_bytes) != expected_identity_bytes:
        raise ValueError("native identity payload has the wrong length")
    for timestamp in (fingerprint.modified, fingerprint.changed):
        if timestamp is not None and not 0 <= timestamp.nanoseconds < 1_000_000_000:
            raise ValueError("native timestamp nanoseconds are out of range")
    payload = bytearray((FINGERPRINT_STORAGE_VERSION, fingerprint.identity_kind))
    payload.extend(fingerprint.identity_bytes)
    payload.extend(struct.pack("<QqI", fingerprint.size_bytes, fingerprint.modified.seconds, fingerprint.modified.nanoseconds))
    if fingerprint.changed is None:
        payload.append(0)
    else:
        payload.append(1)
        payload.extend(struct.pack("<qI", fingerprint.changed.seconds, fingerprint.changed.nanoseconds))
    return bytes(payload)


def decode_fingerprint(payload: bytes) -> NativeFingerprint:
    """Decodes the exact current Rust native-file fingerprint storage format."""

    if len(payload) < 2 or payload[0] != FINGERPRINT_STORAGE_VERSION:
        raise ValueError("unsupported native fingerprint storage version")
    identity_kind = payload[1]
    identity_length = {
        IDENTITY_UNIX: 16,
        IDENTITY_WINDOWS_LOW_RESOLUTION: 12,
        IDENTITY_WINDOWS_HIGH_RESOLUTION: 24,
    }.get(identity_kind)
    if identity_length is None:
        raise ValueError(f"unsupported native identity kind: {identity_kind}")
    offset = 2
    identity_bytes = payload[offset : offset + identity_length]
    if len(identity_bytes) != identity_length:
        raise ValueError("truncated native identity payload")
    offset += identity_length
    if len(payload) < offset + 21:
        raise ValueError("truncated native fingerprint payload")
    size_bytes, modified_seconds, modified_nanoseconds = struct.unpack_from("<QqI", payload, offset)
    offset += 20
    changed_marker = payload[offset]
    offset += 1
    changed = None
    if changed_marker == 1:
        if len(payload) < offset + 12:
            raise ValueError("truncated native change timestamp")
        changed_seconds, changed_nanoseconds = struct.unpack_from("<qI", payload, offset)
        changed = NativeTimestamp(changed_seconds, changed_nanoseconds)
        offset += 12
    elif changed_marker != 0:
        raise ValueError("invalid native change timestamp marker")
    if offset != len(payload):
        raise ValueError("native fingerprint payload has trailing bytes")
    fingerprint = NativeFingerprint(
        identity_kind=identity_kind,
        identity_bytes=bytes(identity_bytes),
        size_bytes=size_bytes,
        modified=NativeTimestamp(modified_seconds, modified_nanoseconds),
        changed=changed,
    )
    encode_fingerprint(fingerprint)
    return fingerprint


def windows_native_fingerprint(path: Path) -> NativeFingerprint:
    """Reads the same Windows identity and timestamps used by the Rust runtime."""

    if os.name != "nt":
        raise RuntimeError("Windows native fingerprints require Windows.")
    import msvcrt

    from ctypes import wintypes

    class FileId128(ctypes.Structure):
        _fields_ = [("identifier", ctypes.c_ubyte * 16)]

    class FileIdInfo(ctypes.Structure):
        _fields_ = [("volume_serial_number", ctypes.c_ulonglong), ("file_id", FileId128)]

    class FileBasicInfo(ctypes.Structure):
        _fields_ = [
            ("creation_time", ctypes.c_longlong),
            ("last_access_time", ctypes.c_longlong),
            ("last_write_time", ctypes.c_longlong),
            ("change_time", ctypes.c_longlong),
            ("file_attributes", wintypes.DWORD),
        ]

    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("file_attributes", wintypes.DWORD),
            ("creation_time", FileTime),
            ("last_access_time", FileTime),
            ("last_write_time", FileTime),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_information_ex = kernel32.GetFileInformationByHandleEx
    get_information_ex.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    get_information_ex.restype = wintypes.BOOL
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(ByHandleFileInformation)]
    get_information.restype = wintypes.BOOL

    with path.open("rb") as stream:
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(stream.fileno()))
        basic = FileBasicInfo()
        if not get_information_ex(handle, 0, ctypes.byref(basic), ctypes.sizeof(basic)):
            raise OSError(ctypes.get_last_error(), f"FileBasicInfo failed for {path}")
        high_resolution = FileIdInfo()
        if get_information_ex(handle, 18, ctypes.byref(high_resolution), ctypes.sizeof(high_resolution)):
            identity_kind = IDENTITY_WINDOWS_HIGH_RESOLUTION
            identity_bytes = struct.pack("<Q", high_resolution.volume_serial_number) + bytes(
                high_resolution.file_id.identifier
            )
        else:
            low_resolution = ByHandleFileInformation()
            if not get_information(handle, ctypes.byref(low_resolution)):
                raise OSError(ctypes.get_last_error(), f"file identity query failed for {path}")
            file_index = (int(low_resolution.file_index_high) << 32) | int(low_resolution.file_index_low)
            identity_kind = IDENTITY_WINDOWS_LOW_RESOLUTION
            identity_bytes = struct.pack("<IQ", low_resolution.volume_serial_number, file_index)
        size_bytes = os.fstat(stream.fileno()).st_size

    return NativeFingerprint(
        identity_kind=identity_kind,
        identity_bytes=identity_bytes,
        size_bytes=size_bytes,
        modified=windows_ticks_to_timestamp(basic.last_write_time),
        changed=windows_ticks_to_timestamp(basic.change_time),
    )
