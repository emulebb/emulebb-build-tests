from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from emule_test_harness import rust_native_fingerprint


@pytest.mark.unit
def test_native_fingerprint_storage_round_trip() -> None:
    fingerprint = rust_native_fingerprint.NativeFingerprint(
        identity_kind=rust_native_fingerprint.IDENTITY_WINDOWS_HIGH_RESOLUTION,
        identity_bytes=bytes(range(24)),
        size_bytes=123,
        modified=rust_native_fingerprint.NativeTimestamp(1_700_000_000, 100),
        changed=rust_native_fingerprint.NativeTimestamp(1_700_000_001, 200),
    )

    payload = rust_native_fingerprint.encode_fingerprint(fingerprint)

    assert rust_native_fingerprint.decode_fingerprint(payload) == fingerprint


@pytest.mark.unit
def test_windows_ticks_to_timestamp_handles_pre_epoch_values() -> None:
    epoch = rust_native_fingerprint.WINDOWS_TO_UNIX_EPOCH_100NS

    assert rust_native_fingerprint.windows_ticks_to_timestamp(epoch - 1) == (
        rust_native_fingerprint.NativeTimestamp(-1, 999_999_900)
    )


@pytest.mark.unit
@pytest.mark.skipif(sys.platform != "win32", reason="requires Windows file handles")
def test_windows_native_fingerprint_includes_change_time(tmp_path: Path) -> None:
    source = tmp_path / "payload.bin"
    source.write_bytes(b"payload")

    fingerprint = rust_native_fingerprint.windows_native_fingerprint(source)
    payload = rust_native_fingerprint.encode_fingerprint(fingerprint)

    assert fingerprint.size_bytes == source.stat().st_size
    assert fingerprint.changed is not None
    assert rust_native_fingerprint.decode_fingerprint(payload) == fingerprint


@pytest.mark.unit
@pytest.mark.skipif(sys.platform != "win32", reason="requires Windows file handles")
def test_windows_change_time_detects_same_size_rewrite_with_restored_mtime(
    tmp_path: Path,
) -> None:
    source = tmp_path / "payload.bin"
    source.write_bytes(b"original")
    original_stat = source.stat()
    original = rust_native_fingerprint.windows_native_fingerprint(source)

    time.sleep(0.02)
    source.write_bytes(b"rewrote!")
    os.utime(source, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    rewritten = rust_native_fingerprint.windows_native_fingerprint(source)

    assert original.size_bytes == rewritten.size_bytes
    assert original.modified == rewritten.modified
    assert original.changed != rewritten.changed
