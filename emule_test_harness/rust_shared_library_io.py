"""Deterministic 100k-file SSD I/O characterization for eMuleBB Rust."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from . import rust_client, rust_metadata
from .paths import (
    get_required_emule_workspace_root,
    get_workspace_output_root,
    path_is_relative_to,
)

REPORT_SCHEMA = "emulebb.rust-shared-library-io.v1"
OWNER_SCHEMA = "emulebb.rust-shared-library-io-owner.v1"
FIXTURE_SCHEMA = "emulebb.rust-shared-library-fixture.v1"
API_KEY = "rust-shared-library-io-local"
DEFAULT_TIMEOUT_SECONDS = 2 * 60 * 60
STATUS_LATENCY_LIMIT_SECONDS = 10.0
MIB = 1024 * 1024


@dataclass(frozen=True)
class FixtureSpec:
    """Shape and size distribution for a deterministic synthetic library."""

    top_directories: int = 100
    leaf_directories_per_top: int = 100
    files_per_leaf: int = 10
    small_count: int = 80_000
    small_size: int = 16 * 1024
    medium_count: int = 15_000
    medium_size: int = 256 * 1024
    large_count: int = 5_000
    large_size: int = 1 * MIB

    @property
    def file_count(self) -> int:
        return (
            self.top_directories * self.leaf_directories_per_top * self.files_per_leaf
        )

    @property
    def bucket_count(self) -> int:
        return self.small_count + self.medium_count + self.large_count

    @property
    def total_bytes(self) -> int:
        return (
            self.small_count * self.small_size
            + self.medium_count * self.medium_size
            + self.large_count * self.large_size
        )

    def validate(self) -> None:
        if self.file_count != self.bucket_count:
            raise ValueError("fixture layout and size bucket counts must match")
        if min(asdict(self).values()) <= 0:
            raise ValueError("fixture dimensions, counts, and sizes must be positive")


PRODUCTION_SPEC = FixtureSpec()
MUTATION_COUNTS = (800, 150, 50)


@dataclass(frozen=True)
class HarnessPaths:
    """Canonical source, fixture, run, and report paths for this harness."""

    workspace_root: Path
    output_root: Path
    rust_repo: Path
    scenario_root: Path
    fixture_root: Path
    manifest_path: Path
    owner_path: Path
    runs_root: Path
    reports_root: Path
    staged_executable: Path


def resolve_paths() -> HarnessPaths:
    """Resolve mandatory operator state without mutating environment variables."""

    workspace_root = get_required_emule_workspace_root()
    output_root = get_workspace_output_root()
    rust_repo = workspace_root / "repos" / "emulebb-rust"
    scenario_root = output_root / "profiles" / "emulebb-rust-shared-library-io"
    if not rust_repo.is_dir():
        raise RuntimeError(
            f"emulebb-rust repository is missing below EMULEBB_WORKSPACE_ROOT: {rust_repo}"
        )
    if not path_is_relative_to(scenario_root, output_root):
        raise RuntimeError(
            "shared-library I/O scenario root escaped EMULEBB_WORKSPACE_OUTPUT_ROOT"
        )
    executable_name = "emulebb-rust.exe" if os.name == "nt" else "emulebb-rust"
    return HarnessPaths(
        workspace_root=workspace_root,
        output_root=output_root,
        rust_repo=rust_repo,
        scenario_root=scenario_root,
        fixture_root=scenario_root / "fixture" / "library",
        manifest_path=scenario_root / "fixture-manifest.json",
        owner_path=scenario_root / ".emulebb-rust-shared-library-io-owner.json",
        runs_root=scenario_root / "runs",
        reports_root=output_root / "reports" / "emulebb-rust" / "shared-library-io",
        staged_executable=output_root
        / "tools"
        / "emulebb-rust"
        / "bin"
        / executable_name,
    )


def path_fingerprint(path: Path) -> str:
    """Return a stable non-reversible identifier without publishing a local path."""

    normalized = os.path.normcase(str(path.resolve())).encode(
        "utf-8", errors="surrogatepass"
    )
    return hashlib.sha256(normalized).hexdigest()[:16]


def utc_now() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def write_json(path: Path, payload: object) -> None:
    """Atomically writes a human-readable JSON artifact."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def file_size_for_index(index: int, spec: FixtureSpec = PRODUCTION_SPEC) -> int:
    """Map a stable file index to its requested payload size."""

    if not 0 <= index < spec.file_count:
        raise IndexError(index)
    if index < spec.small_count:
        return spec.small_size
    if index < spec.small_count + spec.medium_count:
        return spec.medium_size
    return spec.large_size


def relative_file_for_index(index: int, spec: FixtureSpec = PRODUCTION_SPEC) -> Path:
    """Map one file to the 100 x 100 x 10 production tree."""

    if not 0 <= index < spec.file_count:
        raise IndexError(index)
    files_per_top = spec.leaf_directories_per_top * spec.files_per_leaf
    top = index // files_per_top
    leaf = (index % files_per_top) // spec.files_per_leaf
    return Path(f"group-{top:03d}") / f"leaf-{leaf:03d}" / f"file-{index:06d}.bin"


def iter_fixture_files(
    root: Path, spec: FixtureSpec = PRODUCTION_SPEC
) -> Iterator[tuple[int, Path, int]]:
    for index in range(spec.file_count):
        yield (
            index,
            root / relative_file_for_index(index, spec),
            file_size_for_index(index, spec),
        )


def mutation_indices(spec: FixtureSpec = PRODUCTION_SPEC) -> tuple[int, ...]:
    """Select a deterministic, evenly spread 1% sample across all size tiers."""

    if spec == PRODUCTION_SPEC:
        requested = MUTATION_COUNTS
    else:
        requested = tuple(
            min(count, bucket)
            for count, bucket in zip(
                MUTATION_COUNTS,
                (
                    spec.small_count,
                    spec.medium_count,
                    spec.large_count,
                ),
            )
        )
    starts = (0, spec.small_count, spec.small_count + spec.medium_count)
    buckets = (spec.small_count, spec.medium_count, spec.large_count)
    selected: list[int] = []
    for start, bucket_count, requested_count in zip(starts, buckets, requested):
        if requested_count == 0:
            continue
        selected.extend(
            start + (offset * bucket_count // requested_count)
            for offset in range(requested_count)
        )
    return tuple(selected)


def expected_mutation_bytes(spec: FixtureSpec = PRODUCTION_SPEC) -> int:
    return sum(file_size_for_index(index, spec) for index in mutation_indices(spec))


def deterministic_payload(
    index: int, size: int, *, generation: str = "base-v1"
) -> bytes:
    """Generate reproducible, non-compressibility-dependent file content."""

    seed = f"emulebb-rust-shared-library-io:{generation}:{index}".encode("ascii")
    return hashlib.shake_256(seed).digest(size)


def fixture_manifest(
    spec: FixtureSpec, *, status: str, disk_number: int | None
) -> dict[str, object]:
    return {
        "schema": FIXTURE_SCHEMA,
        "status": status,
        "contentGeneration": "base-v1",
        "generatedAtUtc": utc_now(),
        "cacheCondition": "bestEffort",
        "cacheFlushAttempted": False,
        "diskNumber": disk_number,
        "fileCount": spec.file_count,
        "totalBytes": spec.total_bytes,
        "layout": {
            "topDirectories": spec.top_directories,
            "leafDirectoriesPerTop": spec.leaf_directories_per_top,
            "filesPerLeaf": spec.files_per_leaf,
        },
        "sizeBuckets": [
            {"count": spec.small_count, "sizeBytes": spec.small_size},
            {"count": spec.medium_count, "sizeBytes": spec.medium_size},
            {"count": spec.large_count, "sizeBytes": spec.large_size},
        ],
        "mutation": {
            "fileCount": len(mutation_indices(spec)),
            "totalBytes": expected_mutation_bytes(spec),
        },
    }


def _write_payload(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def validate_fixture(
    root: Path, spec: FixtureSpec = PRODUCTION_SPEC
) -> dict[str, object]:
    """Fully inventory a fixture without reading payload bytes."""

    file_count = 0
    total_bytes = 0
    empty_directory_count = 0
    unexpected_size_count = 0
    expected_paths = {
        relative_file_for_index(index, spec): file_size_for_index(index, spec)
        for index in range(spec.file_count)
    }
    seen: set[Path] = set()
    for directory, subdirs, files in os.walk(root):
        if not subdirs and not files:
            empty_directory_count += 1
        directory_path = Path(directory)
        for name in files:
            path = directory_path / name
            relative = path.relative_to(root)
            size = path.stat().st_size
            file_count += 1
            total_bytes += size
            seen.add(relative)
            if expected_paths.get(relative) != size:
                unexpected_size_count += 1
    missing_count = len(set(expected_paths) - seen)
    unexpected_path_count = len(seen - set(expected_paths))
    return {
        "ok": (
            file_count == spec.file_count
            and total_bytes == spec.total_bytes
            and empty_directory_count == 0
            and unexpected_size_count == 0
            and missing_count == 0
            and unexpected_path_count == 0
        ),
        "fileCount": file_count,
        "totalBytes": total_bytes,
        "emptyDirectoryCount": empty_directory_count,
        "unexpectedSizeCount": unexpected_size_count,
        "missingCount": missing_count,
        "unexpectedPathCount": unexpected_path_count,
    }


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


def physical_disk_inventory() -> list[dict[str, object]]:
    """Read Windows disk/media/mount data without collecting serial numbers."""

    if os.name != "nt":
        return []
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
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"physical disk inventory failed: {completed.stderr.strip()}"
        )
    payload = json.loads(completed.stdout or "[]")
    rows = payload if isinstance(payload, list) else [payload]
    return [row for row in rows if isinstance(row, dict)]


def sanitized_disk_inventory(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Remove local paths while retaining capacity/topology evidence."""

    sanitized: list[dict[str, object]] = []
    for row in rows:
        volumes = []
        volume_rows = row.get("volumes") or []
        if isinstance(volume_rows, dict):
            volume_rows = [volume_rows]
        for volume in volume_rows:
            if not isinstance(volume, dict):
                continue
            access_paths = volume.get("accessPaths") or []
            if isinstance(access_paths, str):
                access_paths = [access_paths]
            volumes.append(
                {
                    "mountPointFingerprints": [
                        path_fingerprint(Path(value))
                        for value in access_paths
                        if isinstance(value, str) and value
                    ],
                    "sizeBytes": volume.get("sizeBytes"),
                    "freeBytes": volume.get("freeBytes"),
                }
            )
        sanitized.append(
            {
                key: row.get(key)
                for key in (
                    "diskNumber",
                    "friendlyName",
                    "busType",
                    "mediaType",
                    "sizeBytes",
                    "healthStatus",
                    "operationalStatus",
                )
            }
            | {"volumes": volumes}
        )
    return sanitized


def target_disk(
    paths: HarnessPaths, inventory: list[dict[str, object]]
) -> dict[str, object]:
    """Resolve the generated fixture location to its physical disk record."""

    probe = paths.scenario_root
    while not probe.exists() and probe != paths.output_root:
        probe = probe.parent
    if not probe.exists():
        raise RuntimeError(
            f"EMULEBB_WORKSPACE_OUTPUT_ROOT does not exist: {paths.output_root}"
        )
    mount_path, volume_name, disk_number = _windows_volume_identity(probe)
    row = next(
        (item for item in inventory if item.get("diskNumber") == disk_number), {}
    )
    return {
        "diskNumber": disk_number,
        "mediaType": row.get("mediaType"),
        "busType": row.get("busType"),
        "friendlyName": row.get("friendlyName"),
        "mountPath": mount_path,
        "volumeName": volume_name,
    }


def assert_ssd_target(target: dict[str, object], *, allow_non_ssd: bool) -> None:
    media_type = str(target.get("mediaType") or "").casefold()
    if media_type != "ssd" and not allow_non_ssd:
        raise RuntimeError(
            f"fixture target disk {target.get('diskNumber')} is {target.get('mediaType')!r}, not SSD; "
            "use --allow-non-ssd only for an intentional override"
        )


def prepare_fixture(
    paths: HarnessPaths,
    *,
    allow_non_ssd: bool = False,
    spec: FixtureSpec = PRODUCTION_SPEC,
) -> dict[str, object]:
    """Create or resume the owned synthetic library; never removes user data."""

    spec.validate()
    inventory = physical_disk_inventory()
    target = target_disk(paths, inventory)
    assert_ssd_target(target, allow_non_ssd=allow_non_ssd)
    if paths.scenario_root.exists() and not paths.owner_path.is_file():
        raise RuntimeError(
            f"refusing to use unowned scenario directory: {paths.scenario_root}"
        )
    if paths.owner_path.is_file() and paths.manifest_path.is_file():
        existing = json.loads(paths.manifest_path.read_text(encoding="utf-8"))
        if (
            existing.get("schema") == FIXTURE_SCHEMA
            and existing.get("status") == "prepared"
        ):
            validation = validate_fixture(paths.fixture_root, spec)
            if validation["ok"]:
                return {
                    "status": "prepared",
                    "createdCount": 0,
                    "reusedCount": spec.file_count,
                    "elapsedSeconds": 0.0,
                    "fixture": validation,
                    "contentGeneration": existing.get("contentGeneration"),
                    "targetDisk": {
                        key: target.get(key)
                        for key in (
                            "diskNumber",
                            "mediaType",
                            "busType",
                            "friendlyName",
                        )
                    },
                }
    paths.scenario_root.mkdir(parents=True, exist_ok=True)
    if not paths.owner_path.exists():
        write_json(
            paths.owner_path, {"schema": OWNER_SCHEMA, "createdAtUtc": utc_now()}
        )
    write_json(
        paths.manifest_path,
        fixture_manifest(
            spec, status="preparing", disk_number=target.get("diskNumber")
        ),
    )

    created = 0
    reused = 0
    started = time.monotonic()
    for index, path, size in iter_fixture_files(paths.fixture_root, spec):
        if path.is_file() and path.stat().st_size == size:
            reused += 1
            continue
        _write_payload(path, deterministic_payload(index, size))
        created += 1
        if (created + reused) % 1000 == 0:
            print(
                f"prepared {created + reused:,}/{spec.file_count:,} files", flush=True
            )
    validation = validate_fixture(paths.fixture_root, spec)
    if not validation["ok"]:
        raise RuntimeError(f"fixture validation failed: {validation}")
    manifest = fixture_manifest(
        spec, status="prepared", disk_number=target.get("diskNumber")
    )
    manifest["fixtureFingerprint"] = path_fingerprint(paths.fixture_root)
    manifest["validation"] = validation
    write_json(paths.manifest_path, manifest)
    return {
        "status": "prepared",
        "createdCount": created,
        "reusedCount": reused,
        "elapsedSeconds": round(time.monotonic() - started, 3),
        "fixture": validation,
        "targetDisk": {
            key: target.get(key)
            for key in ("diskNumber", "mediaType", "busType", "friendlyName")
        },
    }


def load_prepared_manifest(paths: HarnessPaths) -> dict[str, object]:
    if not paths.owner_path.is_file() or not paths.manifest_path.is_file():
        raise RuntimeError("fixture is not prepared; run the prepare subcommand first")
    owner = json.loads(paths.owner_path.read_text(encoding="utf-8"))
    manifest = json.loads(paths.manifest_path.read_text(encoding="utf-8"))
    if owner.get("schema") != OWNER_SCHEMA or manifest.get("schema") != FIXTURE_SCHEMA:
        raise RuntimeError("fixture ownership or manifest schema is invalid")
    if manifest.get("status") != "prepared":
        raise RuntimeError("fixture preparation did not complete")
    return manifest


def mutate_fixture(root: Path, spec: FixtureSpec = PRODUCTION_SPEC) -> dict[str, int]:
    """Rewrite the deterministic 1% sample and force a changed source mtime."""

    total_bytes = 0
    for index in mutation_indices(spec):
        path = root / relative_file_for_index(index, spec)
        size = file_size_for_index(index, spec)
        old_mtime_ns = path.stat().st_mtime_ns
        _write_payload(
            path, deterministic_payload(index, size, generation="mutation-v1")
        )
        new_mtime_ns = max(time.time_ns(), old_mtime_ns + 2_000_000_000)
        os.utime(path, ns=(new_mtime_ns, new_mtime_ns))
        total_bytes += size
    return {"fileCount": len(mutation_indices(spec)), "totalBytes": total_bytes}


def restore_fixture_baseline(
    root: Path, spec: FixtureSpec = PRODUCTION_SPEC
) -> dict[str, int]:
    """Restore only the mutation sample to its deterministic base generation."""

    total_bytes = 0
    for index in mutation_indices(spec):
        path = root / relative_file_for_index(index, spec)
        size = file_size_for_index(index, spec)
        _write_payload(path, deterministic_payload(index, size))
        total_bytes += size
    return {"fileCount": len(mutation_indices(spec)), "totalBytes": total_bytes}


def update_fixture_generation(paths: HarnessPaths, generation: str) -> None:
    """Persist which deterministic content generation currently occupies the tree."""

    manifest = load_prepared_manifest(paths)
    manifest["contentGeneration"] = generation
    manifest["generationUpdatedAtUtc"] = utc_now()
    write_json(paths.manifest_path, manifest)


def choose_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class RestClient:
    """Authenticated REST client that records status-call latency and errors."""

    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.samples: list[dict[str, object]] = []
        self.errors: list[dict[str, object]] = []

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
        *,
        timeout_seconds: float = 120.0,
        record: bool = True,
    ) -> dict[str, object]:
        payload = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=payload,
            method=method,
            headers={"X-API-Key": self.api_key, "Accept": "application/json"},
        )
        if payload is not None:
            request.add_header("Content-Type", "application/json; charset=utf-8")
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                text = response.read().decode("utf-8")
            parsed = json.loads(text) if text else {}
            data = (
                parsed.get("data")
                if isinstance(parsed, dict) and isinstance(parsed.get("data"), dict)
                else parsed
            )
            if not isinstance(data, dict):
                raise RuntimeError("REST response was not a JSON object")
            return data
        except Exception as exc:
            if record:
                self.errors.append(
                    {"method": method, "path": path, "errorType": type(exc).__name__}
                )
            raise
        finally:
            if record:
                self.samples.append(
                    {
                        "method": method,
                        "path": path.split("?", 1)[0],
                        "latencySeconds": round(time.monotonic() - started, 6),
                    }
                )


def wait_for_rest(
    client: RestClient, process: subprocess.Popen[str], timeout_seconds: float
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"emulebb-rust exited during REST startup with code {process.returncode}"
            )
        try:
            client.request(
                "GET", "/shared-directories", timeout_seconds=2.0, record=False
            )
            return
        except Exception as exc:  # noqa: BLE001 - preserve only the final error type below
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(
        f"REST did not become ready: {type(last_error).__name__ if last_error else 'timeout'}"
    )


def _load_psutil():
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "run requires the build-tests live dependency 'psutil'"
        ) from exc
    return psutil


def disk_io_snapshot(disk_number: int | None) -> dict[str, int] | None:
    if disk_number is None:
        return None
    psutil = _load_psutil()
    rows = psutil.disk_io_counters(perdisk=True) or {}
    keys = (f"physicaldrive{disk_number}", str(disk_number))
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


def counter_delta(
    before: dict[str, int] | None, after: dict[str, int] | None
) -> dict[str, int] | None:
    if before is None or after is None:
        return None
    return {
        key: max(0, int(after.get(key, 0)) - int(before.get(key, 0))) for key in before
    }


class ProcessSampler:
    """Collect compact process CPU, memory, handle, and I/O observations."""

    def __init__(self, process: subprocess.Popen[str], interval_seconds: float) -> None:
        psutil = _load_psutil()
        self.process = psutil.Process(process.pid)
        self.interval_seconds = interval_seconds
        self.next_sample = 0.0
        self.samples: list[dict[str, object]] = []

    def maybe_sample(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now < self.next_sample:
            return
        try:
            memory = self.process.memory_info()
            cpu = self.process.cpu_times()
            io = self.process.io_counters()
            self.samples.append(
                {
                    "cpuSeconds": round(float(cpu.user + cpu.system), 3),
                    "workingSetBytes": int(memory.rss),
                    "privateBytes": int(
                        getattr(memory, "private", getattr(memory, "vms", 0))
                    ),
                    "handleCount": int(self.process.num_handles())
                    if os.name == "nt"
                    else None,
                    "readCount": int(io.read_count),
                    "writeCount": int(io.write_count),
                    "readBytes": int(io.read_bytes),
                    "writeBytes": int(io.write_bytes),
                }
            )
        except Exception:  # process may be exiting between poll and sample
            return
        self.next_sample = now + self.interval_seconds

    def summary(self, start_index: int = 0) -> dict[str, object]:
        rows = self.samples[start_index:]
        if not rows:
            return {"sampleCount": 0}
        first, last = rows[0], rows[-1]
        return {
            "sampleCount": len(rows),
            "cpuSecondsDelta": round(
                float(last["cpuSeconds"]) - float(first["cpuSeconds"]), 3
            ),
            "peakWorkingSetBytes": max(int(row["workingSetBytes"]) for row in rows),
            "peakPrivateBytes": max(int(row["privateBytes"]) for row in rows),
            "peakHandleCount": max(int(row["handleCount"] or 0) for row in rows),
            "readBytesDelta": int(last["readBytes"]) - int(first["readBytes"]),
            "writeBytesDelta": int(last["writeBytes"]) - int(first["writeBytes"]),
            "readCountDelta": int(last["readCount"]) - int(first["readCount"]),
            "writeCountDelta": int(last["writeCount"]) - int(first["writeCount"]),
        }


PROGRESS_FIELDS = (
    "phase",
    "running",
    "pending",
    "scannedCount",
    "plannedHashCount",
    "reusedCount",
    "newCount",
    "changedCount",
    "missingMtimeCount",
    "statFailedCount",
    "skippedFailedCount",
    "skippedIntakeCount",
    "prunedCount",
    "staleHashCount",
    "diskCount",
    "activeHashCount",
    "hashedCount",
    "failedHashCount",
    "plannedHashBytes",
    "completedHashBytes",
    "plannedReadBytes",
    "completedReadBytes",
    "readRateBytesPerSec",
    "startedAtMs",
    "updatedAtMs",
)


def compact_progress(data: dict[str, object]) -> dict[str, object]:
    progress = (
        data.get("reloadProgress")
        if isinstance(data.get("reloadProgress"), dict)
        else {}
    )
    return {field: progress.get(field) for field in PROGRESS_FIELDS} | {
        "diskActiveCounts": [
            disk.get("activeCount")
            for disk in progress.get("disks", [])
            if isinstance(disk, dict)
        ]
    }


def wait_for_reload(
    *,
    label: str,
    client: RestClient,
    process: subprocess.Popen[str],
    sampler: ProcessSampler,
    disk_number: int | None,
    expected_scanned: int,
    timeout_seconds: float,
    poll_seconds: float,
) -> dict[str, object]:
    """Poll one reload to completion while retaining only sanitized counters."""

    started = time.monotonic()
    deadline = started + timeout_seconds
    process_start = len(sampler.samples)
    disk_before = disk_io_snapshot(disk_number)
    max_active = 0
    max_disk_active = 0
    observations: list[dict[str, object]] = []
    final: dict[str, object] | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"emulebb-rust exited during {label} with code {process.returncode}"
            )
        sampler.maybe_sample()
        data = client.request(
            "GET", "/shared-directories", timeout_seconds=STATUS_LATENCY_LIMIT_SECONDS
        )
        progress = compact_progress(data)
        max_active = max(max_active, int(progress.get("activeHashCount") or 0))
        max_disk_active = max(
            max_disk_active,
            *(int(value or 0) for value in progress["diskActiveCounts"]),
            0,
        )
        if not observations or time.monotonic() - started >= len(observations) * 30:
            observations.append(progress)
        if (
            progress.get("running") is False
            and progress.get("pending") is False
            and int(data.get("hashingCount") or 0) == 0
            and int(progress.get("scannedCount") or 0) == expected_scanned
        ):
            final = progress
            break
        time.sleep(poll_seconds)
    if final is None:
        raise TimeoutError(f"{label} did not settle within {timeout_seconds:.0f}s")
    sampler.maybe_sample(force=True)
    disk_after = disk_io_snapshot(disk_number)
    shared = client.request(
        "GET",
        "/shared-files?offset=0&limit=1",
        timeout_seconds=STATUS_LATENCY_LIMIT_SECONDS,
    )
    return {
        "label": label,
        "elapsedSeconds": round(time.monotonic() - started, 3),
        "sharedFilesTotal": shared.get("total"),
        "progress": final,
        "maxActiveHashCount": max_active,
        "maxPerDiskActiveCount": max_disk_active,
        "process": sampler.summary(process_start),
        "physicalDiskIoDelta": counter_delta(disk_before, disk_after),
        "observations": observations[-20:],
    }


def profile_storage_snapshot(profile_dir: Path) -> dict[str, object]:
    database = profile_dir / rust_metadata.RUST_PROFILE_METADATA_FILE
    paths = (database, Path(str(database) + "-wal"), Path(str(database) + "-shm"))
    transfer_root = profile_dir / "transfers"
    transfer_directory_count = 0
    transfer_file_count = 0
    if transfer_root.is_dir():
        for entry in os.scandir(transfer_root):
            transfer_directory_count += int(entry.is_dir(follow_symlinks=False))
            transfer_file_count += int(entry.is_file(follow_symlinks=False))
    counts: dict[str, int] = {}
    if database.is_file():
        with sqlite3.connect(
            f"file:{database.as_posix()}?mode=ro", uri=True, timeout=30
        ) as connection:
            for key, query in {
                "knownFiles": "SELECT COUNT(*) FROM known_files",
                "activeShareSources": "SELECT COUNT(*) FROM shared_file_sources",
                "activeShareTransfers": "SELECT COUNT(*) FROM transfers WHERE source_path_id IS NOT NULL AND removed_at_ms IS NULL",
                "activeMemberships": "SELECT COUNT(*) FROM shared_file_memberships WHERE removed_at_ms IS NULL",
                "scanFailures": "SELECT COUNT(*) FROM shared_file_scan_failures",
            }.items():
                counts[key] = int(connection.execute(query).fetchone()[0])
    return {
        "databaseBytes": paths[0].stat().st_size if paths[0].is_file() else 0,
        "walBytes": paths[1].stat().st_size if paths[1].is_file() else 0,
        "shmBytes": paths[2].stat().st_size if paths[2].is_file() else 0,
        "transferDirectoryCount": transfer_directory_count,
        "transferRootFileCount": transfer_file_count,
        "rowCounts": counts,
    }


def start_daemon(
    paths: HarnessPaths, profile_dir: Path, log_path: Path, port: int
) -> tuple[subprocess.Popen[str], RestClient, ProcessSampler]:
    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=paths.rust_repo,
        incoming_dir=profile_dir / "incoming",
        rest_addr="127.0.0.1",
        rest_port=port,
        api_key=API_KEY,
        auto_connect=False,
        nat_enabled=False,
        initial_shared_directory_reload=False,
        local_only_discovery=True,
        replace_servers=True,
    )
    rust_metadata.replace_settings_section(
        profile_dir / rust_metadata.RUST_PROFILE_METADATA_FILE,
        "core",
        {"autoConnect": False, "networkEd2k": False, "networkKademlia": False},
    )
    process = rust_client.start_rust_client_executable(
        paths.staged_executable, profile_dir, log_path
    )
    client = RestClient(f"http://127.0.0.1:{port}/api/v1", API_KEY)
    wait_for_rest(client, process, 60.0)
    sampler = ProcessSampler(process, 2.0)
    sampler.maybe_sample(force=True)
    return process, client, sampler


def stop_daemon(
    process: subprocess.Popen[str] | None, client: RestClient | None
) -> dict[str, object]:
    if process is None:
        return {"method": "notStarted"}
    if process.poll() is not None:
        return {"method": "alreadyExited", "exitCode": process.returncode}
    try:
        if client is not None:
            client.request(
                "POST", "/app/shutdown", {"confirmShutdown": True}, timeout_seconds=5.0
            )
        process.wait(timeout=30)
        return {"method": "rest", "exitCode": process.returncode}
    except Exception:
        rust_client.stop_process_tree(process, timeout_seconds=10.0)
        return {"method": "forcedFallback", "exitCode": process.returncode}


def phase_acceptance(
    phase: dict[str, object], expected: dict[str, int]
) -> dict[str, object]:
    progress = phase.get("progress") if isinstance(phase.get("progress"), dict) else {}
    checks = {
        "sharedFilesTotal": phase.get("sharedFilesTotal")
        == expected["sharedFilesTotal"],
        "scannedCount": progress.get("scannedCount") == expected["scannedCount"],
        "plannedHashCount": progress.get("plannedHashCount")
        == expected["plannedHashCount"],
        "hashedCount": progress.get("hashedCount") == expected["hashedCount"],
        "failedHashCount": progress.get("failedHashCount") == 0,
        "statFailedCount": progress.get("statFailedCount") == 0,
        "skippedFailedCount": progress.get("skippedFailedCount") == 0,
        "skippedIntakeCount": progress.get("skippedIntakeCount") == 0,
        "reusedCount": progress.get("reusedCount") == expected["reusedCount"],
        "plannedReadBytes": progress.get("plannedReadBytes")
        == expected["plannedReadBytes"],
        "completedReadBytes": progress.get("completedReadBytes")
        == expected["plannedReadBytes"],
        "diskCount": progress.get("diskCount") == expected["diskCount"],
        "serializedPerDisk": int(phase.get("maxPerDiskActiveCount") or 0) <= 1,
        "serializedSingleDisk": expected["diskCount"] != 1
        or int(phase.get("maxActiveHashCount") or 0) <= 1,
    }
    if "changedCount" in expected:
        checks["changedCount"] = (
            progress.get("changedCount") == expected["changedCount"]
        )
    if "newCount" in expected:
        checks["newCount"] = progress.get("newCount") == expected["newCount"]
    return {"ok": all(checks.values()), "checks": checks}


def rest_summary(clients: list[RestClient]) -> dict[str, object]:
    samples = [sample for client in clients for sample in client.samples]
    errors = [error for client in clients for error in client.errors]
    latencies = [float(sample["latencySeconds"]) for sample in samples]
    status_latencies = [
        float(sample["latencySeconds"])
        for sample in samples
        if sample.get("method") == "GET" and sample.get("path") == "/shared-directories"
    ]
    return {
        "requestCount": len(samples),
        "errorCount": len(errors),
        "errors": errors,
        "maxLatencySeconds": max(latencies, default=0.0),
        "maxStatusLatencySeconds": max(status_latencies, default=0.0),
        "statusLatencyLimitSeconds": STATUS_LATENCY_LIMIT_SECONDS,
    }


def run_campaign(
    paths: HarnessPaths, args: argparse.Namespace
) -> tuple[Path, dict[str, object]]:
    """Run initial, warm/no-change, and 1%-mutation phases against one profile."""

    manifest = load_prepared_manifest(paths)
    restored = {"fileCount": 0, "totalBytes": 0}
    if manifest.get("contentGeneration") == "mutation-v1":
        restored = restore_fixture_baseline(paths.fixture_root)
        update_fixture_generation(paths, "base-v1")
    elif manifest.get("contentGeneration") != "base-v1":
        raise RuntimeError(
            "fixture content generation is unknown; rerun prepare after cleanup"
        )
    validation = validate_fixture(paths.fixture_root)
    if not validation["ok"]:
        raise RuntimeError(f"fixture failed pre-run validation: {validation}")
    if not paths.staged_executable.is_file():
        raise RuntimeError(
            f"staged emulebb-rust executable is missing: {paths.staged_executable}"
        )
    inventory = physical_disk_inventory()
    target = target_disk(paths, inventory)
    assert_ssd_target(target, allow_non_ssd=args.allow_non_ssd)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
    run_root = paths.runs_root / run_id
    profile_dir = run_root / "profile"
    run_root.mkdir(parents=True, exist_ok=False)
    report_path = paths.reports_root / f"rust-shared-library-io-{run_id}.json"
    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "status": "running",
        "runId": run_id,
        "startedAtUtc": utc_now(),
        "cacheCondition": {
            "classification": "bestEffortInitial",
            "cacheFlushAttempted": False,
            "coldClaimAllowed": False,
        },
        "paths": {
            "fixtureFingerprint": path_fingerprint(paths.fixture_root),
            "profileFingerprint": path_fingerprint(profile_dir),
            "outputRootFingerprint": path_fingerprint(paths.output_root),
        },
        "fixture": validation,
        "preRunBaselineRestore": restored,
        "targetDisk": {
            "diskNumber": target.get("diskNumber"),
            "mediaType": target.get("mediaType"),
            "busType": target.get("busType"),
            "friendlyName": target.get("friendlyName"),
            "mountPointFingerprint": path_fingerprint(
                Path(str(target.get("mountPath")))
            ),
        },
        "diskInventory": sanitized_disk_inventory(inventory),
        "phases": [],
    }
    process: subprocess.Popen[str] | None = None
    client: RestClient | None = None
    clients: list[RestClient] = []
    overall_started = time.monotonic()
    overall_deadline = overall_started + args.timeout_seconds

    def remaining_seconds() -> float:
        remaining = overall_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"campaign exceeded the {args.timeout_seconds:.0f}s overall timeout"
            )
        return remaining

    try:
        port = choose_loopback_port()
        process, client, sampler = start_daemon(
            paths, profile_dir, run_root / "initial.log", port
        )
        clients.append(client)
        client.request(
            "PATCH",
            "/shared-directories",
            {
                "confirmReplaceRoots": True,
                "roots": [{"path": str(paths.fixture_root) + os.sep}],
            },
        )
        initial = wait_for_reload(
            label="bestEffortInitial",
            client=client,
            process=process,
            sampler=sampler,
            disk_number=target.get("diskNumber"),
            expected_scanned=PRODUCTION_SPEC.file_count,
            timeout_seconds=remaining_seconds(),
            poll_seconds=args.poll_seconds,
        )
        initial["storage"] = profile_storage_snapshot(profile_dir)
        initial["acceptance"] = phase_acceptance(
            initial,
            {
                "sharedFilesTotal": PRODUCTION_SPEC.file_count,
                "scannedCount": PRODUCTION_SPEC.file_count,
                "plannedHashCount": PRODUCTION_SPEC.file_count,
                "hashedCount": PRODUCTION_SPEC.file_count,
                "reusedCount": 0,
                "plannedReadBytes": PRODUCTION_SPEC.total_bytes,
                "diskCount": 1,
                "newCount": PRODUCTION_SPEC.file_count,
            },
        )
        report["phases"].append(initial)
        report["initialShutdown"] = stop_daemon(process, client)
        process = None
        client = None

        port = choose_loopback_port()
        process, client, sampler = start_daemon(
            paths, profile_dir, run_root / "restart.log", port
        )
        clients.append(client)
        warm_shared = client.request(
            "GET",
            "/shared-files?offset=0&limit=1",
            timeout_seconds=STATUS_LATENCY_LIMIT_SECONDS,
        )
        warm_dirs = client.request(
            "GET", "/shared-directories", timeout_seconds=STATUS_LATENCY_LIMIT_SECONDS
        )
        report["warmRestart"] = {
            "sharedFilesTotal": warm_shared.get("total"),
            "hashingCount": warm_dirs.get("hashingCount"),
            "storage": profile_storage_snapshot(profile_dir),
        }

        client.request("POST", "/shared-directories/operations/reload", {})
        no_change = wait_for_reload(
            label="noChangeReload",
            client=client,
            process=process,
            sampler=sampler,
            disk_number=target.get("diskNumber"),
            expected_scanned=PRODUCTION_SPEC.file_count,
            timeout_seconds=remaining_seconds(),
            poll_seconds=args.poll_seconds,
        )
        no_change["storage"] = profile_storage_snapshot(profile_dir)
        no_change["acceptance"] = phase_acceptance(
            no_change,
            {
                "sharedFilesTotal": PRODUCTION_SPEC.file_count,
                "scannedCount": PRODUCTION_SPEC.file_count,
                "plannedHashCount": 0,
                "hashedCount": 0,
                "reusedCount": PRODUCTION_SPEC.file_count,
                "plannedReadBytes": 0,
                "diskCount": 0,
                "newCount": 0,
            },
        )
        report["phases"].append(no_change)

        # Mutate with the watcher stopped so the explicit reload owns all 1,000
        # changed-file hashes instead of racing live filesystem notifications.
        report["preMutationShutdown"] = stop_daemon(process, client)
        process = None
        client = None

        mutation = mutate_fixture(paths.fixture_root)
        update_fixture_generation(paths, "mutation-v1")
        report["mutation"] = mutation
        port = choose_loopback_port()
        process, client, sampler = start_daemon(
            paths, profile_dir, run_root / "mutation.log", port
        )
        clients.append(client)
        client.request("POST", "/shared-directories/operations/reload", {})
        changed = wait_for_reload(
            label="onePercentMutation",
            client=client,
            process=process,
            sampler=sampler,
            disk_number=target.get("diskNumber"),
            expected_scanned=PRODUCTION_SPEC.file_count,
            timeout_seconds=remaining_seconds(),
            poll_seconds=args.poll_seconds,
        )
        changed["storage"] = profile_storage_snapshot(profile_dir)
        changed["acceptance"] = phase_acceptance(
            changed,
            {
                "sharedFilesTotal": PRODUCTION_SPEC.file_count,
                "scannedCount": PRODUCTION_SPEC.file_count,
                "plannedHashCount": len(mutation_indices()),
                "hashedCount": len(mutation_indices()),
                "reusedCount": PRODUCTION_SPEC.file_count - len(mutation_indices()),
                "plannedReadBytes": expected_mutation_bytes(),
                "diskCount": 1,
                "changedCount": len(mutation_indices()),
                "newCount": 0,
            },
        )
        report["phases"].append(changed)
        report["finalShutdown"] = stop_daemon(process, client)
        process = None
        client = None
        report["finalStorage"] = profile_storage_snapshot(profile_dir)

        rest = rest_summary(clients)
        report["rest"] = rest
        warm = report["warmRestart"]
        phase_results = [phase["acceptance"]["ok"] for phase in report["phases"]]
        global_checks = {
            "fixtureExact": validation["ok"] is True,
            "warmRestartCatalog": warm["sharedFilesTotal"]
            == PRODUCTION_SPEC.file_count,
            "warmRestartIdle": int(warm["hashingCount"] or 0) == 0,
            "mutationExact": mutation
            == {
                "fileCount": len(mutation_indices()),
                "totalBytes": expected_mutation_bytes(),
            },
            "noRestErrors": rest["errorCount"] == 0,
            "statusLatency": float(rest["maxStatusLatencySeconds"])
            < STATUS_LATENCY_LIMIT_SECONDS,
            "withinTimeout": time.monotonic() - overall_started <= args.timeout_seconds,
        }
        report["acceptance"] = {
            "ok": all(phase_results) and all(global_checks.values()),
            "phaseResults": phase_results,
            "globalChecks": global_checks,
        }
        report["status"] = "passed" if report["acceptance"]["ok"] else "failed"
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__}
        raise
    finally:
        if process is not None:
            report["emergencyShutdown"] = stop_daemon(process, client)
        report["rest"] = rest_summary(clients)
        report["finishedAtUtc"] = utc_now()
        report["elapsedSeconds"] = round(time.monotonic() - overall_started, 3)
        write_json(report_path, report)
    return report_path, report


def describe(paths: HarnessPaths) -> dict[str, object]:
    inventory = physical_disk_inventory()
    target = target_disk(paths, inventory)
    return {
        "schema": REPORT_SCHEMA,
        "command": "describe",
        "fixturePath": str(paths.fixture_root),
        "fixtureFingerprint": path_fingerprint(paths.fixture_root),
        "reportDirectory": str(paths.reports_root),
        "stagedExecutable": str(paths.staged_executable),
        "fixture": fixture_manifest(
            PRODUCTION_SPEC, status="planned", disk_number=target.get("diskNumber")
        ),
        "targetDisk": {
            key: target.get(key)
            for key in (
                "diskNumber",
                "mediaType",
                "busType",
                "friendlyName",
                "mountPath",
            )
        },
        "physicalDisks": inventory,
        "commands": {
            "prepare": "python scripts/rust-shared-library-io.py prepare",
            "run": "python scripts/rust-shared-library-io.py run",
            "cleanup": "python scripts/rust-shared-library-io.py cleanup --confirm-delete",
        },
    }


def cleanup(paths: HarnessPaths, *, confirmed: bool) -> dict[str, object]:
    """Delete only this harness's owned profile/fixture tree after confirmation."""

    if not confirmed:
        raise RuntimeError("cleanup requires --confirm-delete")
    expected = paths.output_root / "profiles" / "emulebb-rust-shared-library-io"
    if paths.scenario_root.resolve() != expected.resolve() or not path_is_relative_to(
        paths.scenario_root, paths.output_root
    ):
        raise RuntimeError("cleanup target is not the exact managed scenario root")
    if not paths.owner_path.is_file():
        raise RuntimeError("cleanup refused because the ownership marker is missing")
    owner = json.loads(paths.owner_path.read_text(encoding="utf-8"))
    if owner.get("schema") != OWNER_SCHEMA:
        raise RuntimeError("cleanup refused because the ownership marker is invalid")
    shutil.rmtree(paths.scenario_root)
    return {
        "status": "removed",
        "recoverable": False,
        "targetFingerprint": path_fingerprint(expected),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "describe",
        help="show disks, paths, and the exact fixture plan without creating it",
    )
    prepare = subparsers.add_parser(
        "prepare", help="create or resume the deterministic 100k-file SSD fixture"
    )
    prepare.add_argument("--allow-non-ssd", action="store_true")
    run = subparsers.add_parser(
        "run", help="run initial, warm/no-change, and mutation characterization phases"
    )
    run.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    run.add_argument("--poll-seconds", type=float, default=2.0)
    run.add_argument("--allow-non-ssd", action="store_true")
    cleanup_parser = subparsers.add_parser(
        "cleanup", help="remove only the owned fixture/profile tree"
    )
    cleanup_parser.add_argument("--confirm-delete", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        paths = resolve_paths()
        if args.command == "describe":
            result = describe(paths)
        elif args.command == "prepare":
            result = prepare_fixture(paths, allow_non_ssd=args.allow_non_ssd)
        elif args.command == "run":
            if args.timeout_seconds <= 0 or args.poll_seconds <= 0:
                raise RuntimeError("timeouts and poll interval must be positive")
            report_path, report = run_campaign(paths, args)
            result = {
                "status": report["status"],
                "reportPath": str(report_path),
                "reportFingerprint": path_fingerprint(report_path),
            }
        elif args.command == "cleanup":
            result = cleanup(paths, confirmed=args.confirm_delete)
        else:  # pragma: no cover - argparse enforces this
            raise RuntimeError(f"unsupported command: {args.command}")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("status") not in {"failed"} else 1
    except (
        OSError,
        RuntimeError,
        ValueError,
        TimeoutError,
        urllib.error.URLError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
