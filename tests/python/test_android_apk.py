"""Reject Android packaging faults before installing an APK on a device."""
from __future__ import annotations

import hashlib
import struct
import zipfile

import pytest

from emule_test_harness import android_apk as apk


def fixture(tmp_path, *, abis=apk.ABIS, aligned=True, compressed=False, duplicate=False, extra=None, runtime=False):
    path = tmp_path / "universal.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"synthetic manifest")
        for abi in abis:
            name = f"lib/{abi}/libemulebb_android.so"
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
            if aligned:
                padding = -(archive.fp.tell() + 30 + len(name)) % apk.PAGE_SIZE
                if padding < 4:
                    padding += apk.PAGE_SIZE
                info.extra = struct.pack("<HH", 0xFFFF, padding - 4) + bytes(padding - 4)
            archive.writestr(info, b"synthetic native " + abi.encode("ascii"))
            if runtime:
                runtime_name = f"lib/{abi}/libc++_shared.so"
                runtime_info = zipfile.ZipInfo(runtime_name)
                padding = -(archive.fp.tell() + 30 + len(runtime_name)) % apk.PAGE_SIZE
                if padding < 4:
                    padding += apk.PAGE_SIZE
                runtime_info.extra = struct.pack("<HH", 0xFFFF, padding - 4) + bytes(padding - 4)
                archive.writestr(runtime_info, b"synthetic pinned NDK runtime")
        if duplicate:
            with pytest.warns(UserWarning, match="Duplicate name"):
                archive.writestr("AndroidManifest.xml", b"duplicate")
        if extra:
            archive.writestr(extra, b"unexpected")
    return path


def auditor(path, abi, *, shared_library):
    assert path.read_bytes() == b"synthetic native " + abi.encode("ascii")
    assert shared_library is True
    return {"abi": abi, "sharedLibrary": True, "pageSize": 16384}


def test_both_native_payloads_are_bound_to_actual_apk_bytes(tmp_path):
    path = fixture(tmp_path)
    result = apk.audit_native_payloads(path, scratch=tmp_path, elf_auditor=auditor)
    assert result["apkSha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert set(result["native"]) == {"arm64-v8a", "x86_64"}
    assert all(item["zipOffset"] % 16384 == 0 for item in result["native"].values())
    assert result["runtimeExecution"] == "not-run"
    assert not list(tmp_path.glob("apk-native-*"))


def test_pinned_runtime_requires_exact_per_abi_inventory_and_bytes(tmp_path):
    path = fixture(tmp_path, runtime=True)
    digest = hashlib.sha256(b"synthetic pinned NDK runtime").hexdigest()
    inventory = {abi: {"libc++_shared.so": digest} for abi in apk.ABIS}

    def runtime_auditor(path, abi, *, shared_library):
        if path.name.endswith("libc++_shared.so"):
            assert path.read_bytes() == b"synthetic pinned NDK runtime"
            return {"abi": abi, "sharedLibrary": True, "pageSize": 16384}
        return auditor(path, abi, shared_library=shared_library)

    result = apk.audit_native_payloads(path, scratch=tmp_path, elf_auditor=runtime_auditor, runtime_libraries=inventory)
    assert all(result["runtime"][abi]["libc++_shared.so"]["sha256"] == digest for abi in apk.ABIS)
    assert set(result["native"]) == set(apk.ABIS)
    with pytest.raises(RuntimeError, match="exactly"):
        apk.audit_native_payloads(path, scratch=tmp_path, elf_auditor=runtime_auditor)
    inventory["x86_64"]["libc++_shared.so"] = "f" * 64
    with pytest.raises(RuntimeError, match="runtime bytes differ"):
        apk.audit_native_payloads(path, scratch=tmp_path, elf_auditor=runtime_auditor, runtime_libraries=inventory)


@pytest.mark.parametrize("inventory", [{}, {"x86_64": {}},
    {abi: {"unreviewed.so": "a" * 64} for abi in apk.ABIS},
    {abi: {"libc++_shared.so": "not-a-hash"} for abi in apk.ABIS}])
def test_runtime_inventory_cannot_relax_the_native_boundary(tmp_path, inventory):
    path = fixture(tmp_path)
    with pytest.raises(ValueError, match="runtime inventory"):
        apk.audit_native_payloads(path, scratch=tmp_path, elf_auditor=auditor, runtime_libraries=inventory)


@pytest.mark.parametrize("arguments,reason", [
    ({"abis": ("arm64-v8a",)}, "exactly"),
    ({"abis": ("arm64-v8a", "x86_64", "armeabi-v7a")}, "exactly"),
    ({"aligned": False}, "16KB"),
    ({"compressed": True}, "without compression"),
    ({"duplicate": True}, "duplicate"),
    ({"extra": "../outside"}, "unsafe path"),
    ({"extra": "lib/arm64-v8a/unreviewed.so"}, "exactly"),
])
def test_bad_apk_layout_is_rejected(tmp_path, arguments, reason):
    path = fixture(tmp_path, **arguments)
    with pytest.raises(RuntimeError, match=reason):
        apk.audit_native_payloads(path, scratch=tmp_path, elf_auditor=auditor)
    assert not list(tmp_path.glob("apk-native-*"))


def test_mismatched_elf_identity_is_rejected_and_scratch_cleaned(tmp_path):
    path = fixture(tmp_path)
    with pytest.raises(RuntimeError, match="inconsistent target"):
        apk.audit_native_payloads(path, scratch=tmp_path, elf_auditor=lambda *args, **kwargs:
                                 {"abi": "wrong", "sharedLibrary": True, "pageSize": 16384})
    assert not list(tmp_path.glob("apk-native-*"))


def test_local_header_cannot_disagree_with_signed_central_inventory(tmp_path):
    path = fixture(tmp_path)
    with zipfile.ZipFile(path) as source:
        entry = source.getinfo("lib/arm64-v8a/libemulebb_android.so")
    with path.open("r+b") as target:
        target.seek(entry.header_offset + 8)
        target.write(struct.pack("<H", zipfile.ZIP_DEFLATED))
    with pytest.raises(RuntimeError, match="matching local header"):
        apk.audit_native_payloads(path, scratch=tmp_path, elf_auditor=auditor)


def test_native_crc_damage_is_detected_before_elf_auditing(tmp_path):
    path = fixture(tmp_path)
    result = apk.audit_native_payloads(path, scratch=tmp_path, elf_auditor=auditor)
    with path.open("r+b") as target:
        target.seek(result["native"]["arm64-v8a"]["zipOffset"])
        target.write(b"!")
    with pytest.raises(zipfile.BadZipFile, match="CRC"):
        apk.audit_native_payloads(path, scratch=tmp_path, elf_auditor=lambda *args, **kwargs: pytest.fail("corrupt ELF audited"))
    assert not list(tmp_path.glob("apk-native-*"))


def test_apk_mutation_during_audit_cannot_produce_valid_evidence(tmp_path):
    path = fixture(tmp_path)
    def change_after_audit(native, abi, **kwargs):
        result = auditor(native, abi, **kwargs)
        if abi == "x86_64":
            with path.open("ab") as target:
                target.write(b"changed during audit")
        return result
    with pytest.raises(RuntimeError, match="changed during native validation"):
        apk.audit_native_payloads(path, scratch=tmp_path, elf_auditor=change_after_audit)
    assert not list(tmp_path.glob("apk-native-*"))
