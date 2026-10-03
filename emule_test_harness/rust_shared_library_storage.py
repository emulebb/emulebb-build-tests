"""Cross-platform storage and long-path helpers for the Rust library I/O harness."""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Iterator


@dataclass(frozen=True)
class StorageTarget:
    """One owned library root and the physical device used for its I/O."""

    role: str
    root: Path
    disk_number: int | None
    counter_key: str | int | None
    media_type: str
    bus_type: str
    friendly_name: str
    mount_path: Path
    expected_file_count: int
    expected_bytes: int

    def sanitized(self, fingerprint: Callable[[Path], str]) -> dict[str, object]:
        return {
            "role": self.role,
            "rootFingerprint": fingerprint(self.root),
            "diskNumber": self.disk_number,
            "counterKey": self.counter_key,
            "mediaType": self.media_type,
            "busType": self.bus_type,
            "friendlyName": self.friendly_name,
            "mountPointFingerprint": fingerprint(self.mount_path),
            "expectedFileCount": self.expected_file_count,
            "expectedBytes": self.expected_bytes,
        }


def windows_verbatim_path(text: str) -> str:
    """Convert one absolute Windows path string to verbatim form."""

    if text.startswith("\\\\?\\"):
        return text
    if text.startswith("\\\\"):
        return "\\\\?\\UNC\\" + text[2:]
    return "\\\\?\\" + text


def filesystem_path(path: Path) -> str:
    """Return a filesystem-call spelling that bypasses legacy MAX_PATH on Windows."""

    text = os.path.abspath(os.fspath(path))
    if os.name != "nt" or text.startswith("\\\\?\\"):
        return text
    return windows_verbatim_path(text)


def logical_path(path: str | Path) -> Path:
    """Remove a Windows verbatim prefix for comparison and reporting."""

    text = os.fspath(path)
    if text.startswith("\\\\?\\UNC\\"):
        return Path("\\\\" + text[8:])
    if text.startswith("\\\\?\\"):
        return Path(text[4:])
    return Path(text)


def make_directories(path: Path) -> None:
    os.makedirs(filesystem_path(path), exist_ok=True)


def open_binary(path: Path, mode: str) -> BinaryIO:
    return open(filesystem_path(path), mode)  # noqa: SIM115 - caller owns handle


def is_file(path: Path) -> bool:
    return os.path.isfile(filesystem_path(path))


def is_directory(path: Path) -> bool:
    return os.path.isdir(filesystem_path(path))


def stat(path: Path) -> os.stat_result:
    return os.stat(filesystem_path(path))


def replace(source: Path, destination: Path) -> None:
    os.replace(filesystem_path(source), filesystem_path(destination))


def rename(source: Path, destination: Path) -> None:
    make_directories(destination.parent)
    os.replace(filesystem_path(source), filesystem_path(destination))


def set_mtime(path: Path, mtime_ns: int) -> None:
    os.utime(filesystem_path(path), ns=(mtime_ns, mtime_ns))


def unlink(path: Path, *, missing_ok: bool = False) -> None:
    try:
        os.unlink(filesystem_path(path))
    except FileNotFoundError:
        if not missing_ok:
            raise


def remove_tree(path: Path) -> None:
    prepared = filesystem_path(path)
    if os.path.isdir(prepared):
        shutil.rmtree(prepared)


def walk(path: Path) -> Iterator[tuple[Path, list[str], list[str]]]:
    """Walk a tree while returning ordinary logical paths to callers."""

    for directory, subdirs, files in os.walk(filesystem_path(path)):
        yield logical_path(directory), subdirs, files


def absolute_path_length(path: Path) -> int:
    return len(os.path.abspath(os.fspath(path)))


def _windows_volume_identity(path: Path) -> tuple[str, str, int | None]:
    """Return the containing mount point, GUID volume, and physical disk number."""

    if os.name != "nt":
        return (str(path.anchor), "", None)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetVolumePathNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel32.GetVolumePathNameW.restype = ctypes.c_int
    kernel32.GetVolumeNameForVolumeMountPointW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel32.GetVolumeNameForVolumeMountPointW.restype = ctypes.c_int
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    mount_buffer = ctypes.create_unicode_buffer(32_768)
    if not kernel32.GetVolumePathNameW(str(path), mount_buffer, len(mount_buffer)):
        raise OSError(ctypes.get_last_error(), f"GetVolumePathNameW failed for {path}")
    mount_path = mount_buffer.value
    volume_buffer = ctypes.create_unicode_buffer(64)
    if not kernel32.GetVolumeNameForVolumeMountPointW(
        mount_path, volume_buffer, len(volume_buffer)
    ):
        raise OSError(
            ctypes.get_last_error(),
            f"GetVolumeNameForVolumeMountPointW failed for {mount_path}",
        )
    volume_name = volume_buffer.value

    kernel32.CreateFileW.restype = ctypes.c_void_p
    handle = kernel32.CreateFileW(volume_name.rstrip("\\/"), 0, 3, None, 3, 0, None)
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise OSError(ctypes.get_last_error(), "CreateFileW failed for resolved volume")
    kernel32.DeviceIoControl.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
    ]
    kernel32.DeviceIoControl.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    try:
        buffer = ctypes.create_string_buffer(4096)
        returned = ctypes.c_uint32()
        ok = kernel32.DeviceIoControl(
            handle,
            0x00560000,
            None,
            0,
            buffer,
            len(buffer),
            ctypes.byref(returned),
            None,
        )
        disk_number = (
            int.from_bytes(buffer.raw[8:12], "little")
            if ok and returned.value >= 12
            else None
        )
    finally:
        kernel32.CloseHandle(handle)
    return mount_path, volume_name, disk_number


def _run_json(command: list[str], *, label: str) -> object:
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{label} failed: {completed.stderr.strip()}")
    return json.loads(completed.stdout or "[]")


def parse_linux_lsblk(payload: object) -> list[dict[str, object]]:
    """Normalize lsblk JSON into physical-disk rows with child device aliases."""

    if not isinstance(payload, dict) or not isinstance(
        payload.get("blockdevices"), list
    ):
        raise RuntimeError("lsblk returned an unexpected JSON shape")
    rows: list[dict[str, object]] = []

    def device_names(node: dict[str, object]) -> list[str]:
        values = [node.get("name"), node.get("path"), node.get("kname")]
        names = [str(value) for value in values if value]
        for child in node.get("children") or []:
            if isinstance(child, dict):
                names.extend(device_names(child))
        return names

    for node in payload["blockdevices"]:
        if not isinstance(node, dict) or node.get("type") != "disk":
            continue
        rotational = node.get("rota")
        if isinstance(rotational, str):
            rotational = rotational.strip() not in {"0", "false", "False"}
        media_type = (
            "HDD"
            if rotational is True
            else "SSD"
            if rotational is False
            else "Unspecified"
        )
        rows.append(
            {
                "diskNumber": None,
                "counterKey": Path(
                    str(node.get("kname") or node.get("name") or "")
                ).name,
                "devicePaths": sorted(set(device_names(node))),
                "friendlyName": str(node.get("model") or "").strip(),
                "busType": str(node.get("tran") or "").upper(),
                "mediaType": media_type,
                "sizeBytes": int(node.get("size") or 0),
                "healthStatus": "Unknown",
                "operationalStatus": "Unknown",
                "volumes": [],
            }
        )
    return rows


def physical_disk_inventory() -> list[dict[str, object]]:
    """Read physical-disk topology without collecting serial numbers."""

    if os.name != "nt":
        payload = _run_json(
            [
                "lsblk",
                "--json",
                "--bytes",
                "--paths",
                "--output",
                "NAME,KNAME,PATH,TYPE,SIZE,MODEL,ROTA,TRAN",
            ],
            label="physical disk inventory",
        )
        return parse_linux_lsblk(payload)
    script = r"""
$ErrorActionPreference = 'Stop'
$media = @{}
Get-PhysicalDisk | ForEach-Object { $media[[int]$_.DeviceId] = $_ }
$rows = @(Get-Disk | Sort-Object Number | ForEach-Object {
  $disk = $_
  $physical = $media[[int]$disk.Number]
  $volumes = @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | ForEach-Object {
    $partition = $_
    $volume = $partition | Get-Volume -ErrorAction SilentlyContinue
    [pscustomobject]@{
      accessPaths = @($partition.AccessPaths | Where-Object { $_ -notlike '\\?\Volume*' })
      sizeBytes = if ($volume) { [uint64]$volume.Size } else { 0 }
      freeBytes = if ($volume) { [uint64]$volume.SizeRemaining } else { 0 }
    }
  })
  [pscustomobject]@{
    diskNumber = [int]$disk.Number
    counterKey = "physicaldrive$($disk.Number)"
    friendlyName = [string]$disk.FriendlyName
    busType = [string]$disk.BusType
    mediaType = if ($physical) { [string]$physical.MediaType } else { 'Unspecified' }
    sizeBytes = [uint64]$disk.Size
    healthStatus = if ($physical) { [string]$physical.HealthStatus } else { 'Unknown' }
    operationalStatus = [string]($disk.OperationalStatus -join ',')
    volumes = $volumes
  }
})
$rows | ConvertTo-Json -Depth 5 -Compress
"""
    payload = _run_json(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        label="physical disk inventory",
    )
    rows = payload if isinstance(payload, list) else [payload]
    return [row for row in rows if isinstance(row, dict)]


def target_disk(
    scenario_root: Path, output_root: Path, inventory: list[dict[str, object]]
) -> dict[str, object]:
    """Resolve one generated fixture location to its physical disk record."""

    probe = scenario_root
    while not probe.exists() and probe != output_root:
        probe = probe.parent
    if not probe.exists():
        raise RuntimeError(
            f"EMULEBB_WORKSPACE_OUTPUT_ROOT does not exist: {output_root}"
        )
    if os.name == "nt":
        mount_path, volume_name, disk_number = _windows_volume_identity(probe)
        row = next(
            (item for item in inventory if item.get("diskNumber") == disk_number), {}
        )
        return dict(row) | {
            "diskNumber": disk_number,
            "counterKey": row.get("counterKey")
            or (f"physicaldrive{disk_number}" if disk_number is not None else None),
            "mountPath": mount_path,
            "volumeName": volume_name,
        }

    findmnt = _run_json(
        [
            "findmnt",
            "--json",
            "--target",
            str(probe),
            "--output",
            "SOURCE,TARGET,FSTYPE",
        ],
        label="target filesystem lookup",
    )
    filesystems = findmnt.get("filesystems") if isinstance(findmnt, dict) else None
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise RuntimeError("target filesystem lookup was ambiguous")
    filesystem = filesystems[0]
    source = str(filesystem.get("source") or "") if isinstance(filesystem, dict) else ""
    source_base = source.split("[", 1)[0]
    source_aliases = {source_base, os.path.realpath(source_base)}
    candidates = [
        row
        for row in inventory
        if source_aliases.intersection(
            {name for name in row.get("devicePaths", []) if isinstance(name, str)}
        )
    ]
    if len(candidates) > 1:
        raise RuntimeError(
            f"target filesystem source {source!r} resolved to multiple physical disks"
        )
    if not candidates:
        return {
            "diskNumber": None,
            "counterKey": None,
            "friendlyName": "",
            "busType": "",
            "mediaType": "Unspecified",
            "sizeBytes": 0,
            "healthStatus": "Unknown",
            "operationalStatus": "Unknown",
            "volumes": [],
            "mountPath": str(filesystem.get("target") or ""),
            "volumeName": source,
            "filesystemType": str(filesystem.get("fstype") or ""),
        }
    return dict(candidates[0]) | {
        "mountPath": str(filesystem.get("target") or ""),
        "volumeName": source,
        "filesystemType": str(filesystem.get("fstype") or ""),
    }


def assert_ssd_target(target: dict[str, object], *, allow_non_ssd: bool) -> None:
    media_type = str(target.get("mediaType") or "").casefold()
    if media_type != "ssd" and not allow_non_ssd:
        identity = target.get("diskNumber")
        if identity is None:
            identity = target.get("counterKey")
        raise RuntimeError(
            f"fixture target disk {identity} is {target.get('mediaType')!r}, not SSD; "
            "use --allow-non-ssd only for an intentional override"
        )


def disk_io_snapshot(counter_key: str | int | None) -> dict[str, int] | None:
    if counter_key is None:
        return None
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "run requires the build-tests live dependency 'psutil'"
        ) from exc
    rows = psutil.disk_io_counters(perdisk=True) or {}
    wanted = str(counter_key).casefold()
    keys = {wanted, f"physicaldrive{wanted}"}
    counter = next(
        (value for name, value in rows.items() if name.casefold() in keys), None
    )
    if counter is None:
        return None
    return {
        field: int(getattr(counter, field, 0))
        for field in (
            "read_count",
            "write_count",
            "read_bytes",
            "write_bytes",
            "read_time",
            "write_time",
        )
    }
