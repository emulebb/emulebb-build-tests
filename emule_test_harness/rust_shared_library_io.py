"""SSD fixture and read-only multi-disk I/O characterization for eMuleBB Rust."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import (
    rust_client,
    rust_metadata,
    rust_shared_library_fixture as fixture,
    rust_shared_library_storage as storage,
)
from .paths import (
    get_required_emule_workspace_root,
    get_workspace_output_root,
    path_is_relative_to,
)

REPORT_SCHEMA = "emulebb.rust-shared-library-io.v4"
MEDIA_REPORT_SCHEMA = "emulebb.rust-shared-library-media-io.v1"
OWNER_SCHEMA = "emulebb.rust-shared-library-io-owner.v1"
FIXTURE_SCHEMA = fixture.FIXTURE_SCHEMA
API_KEY = "rust-shared-library-io-local"
DEFAULT_TIMEOUT_SECONDS = 2 * 60 * 60
DEFAULT_WATCHER_TIMEOUT_SECONDS = 10 * 60
DEFAULT_WATCHER_POLL_SECONDS = 0.5
STATUS_LATENCY_LIMIT_SECONDS = 10.0
DEFAULT_MEDIA_ROOTS_FILE = (
    Path(__file__).resolve().parent.parent
    / "live-wire-emulebb-rust-sharedroots.local.txt"
)


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


def fixture_manifest(
    spec: FixtureSpec, *, status: str, disk_number: int | None
) -> dict[str, object]:
    return {
        "schema": FIXTURE_SCHEMA,
        "status": status,
        "contentGeneration": "base-v2",
        "generatedAtUtc": utc_now(),
        "cacheCondition": "bestEffort",
        "cacheFlushAttempted": False,
        "targetRoots": [{"role": "ssdBaseline", "diskNumber": disk_number}],
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
        "longPaths": {
            "fileCount": fixture.baseline_long_path_count(spec),
            "minimumRelativeCharacters": fixture.LONG_PATH_MIN_RELATIVE_CHARS,
            "maximumComponentCharacters": fixture.LONG_SEGMENT_LENGTH,
        },
        "watcherCohort": fixture.watcher_cohort_summary(),
    }


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


# Public facade aliases keep existing harness imports stable while the implementation
# is split by responsibility.
FixtureSpec = fixture.FixtureSpec
PRODUCTION_SPEC = fixture.PRODUCTION_SPEC
MIB = fixture.MIB
MUTATION_COUNTS = fixture.MUTATION_COUNTS
file_size_for_index = fixture.file_size_for_index
relative_file_for_index = fixture.relative_file_for_index
iter_fixture_files = fixture.iter_fixture_files
mutation_indices = fixture.mutation_indices
expected_mutation_bytes = fixture.expected_mutation_bytes
deterministic_payload = fixture.deterministic_payload
validate_fixture = fixture.validate_fixture
_write_payload = fixture.write_payload
physical_disk_inventory = storage.physical_disk_inventory
assert_ssd_target = storage.assert_ssd_target


def target_disk(
    paths: HarnessPaths, inventory: list[dict[str, object]]
) -> dict[str, object]:
    return storage.target_disk(paths.scenario_root, paths.output_root, inventory)


def load_media_roots(path: Path) -> list[Path]:
    """Load private operator roots without publishing their names in reports."""

    if not path.is_file():
        raise RuntimeError(f"multi-HDD roots file is missing: {path}")
    roots: list[Path] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        candidate = Path(value)
        if not candidate.is_absolute():
            raise RuntimeError(
                f"multi-HDD root on line {line_number} must be absolute"
            )
        if not candidate.is_dir():
            raise RuntimeError(
                f"multi-HDD root on line {line_number} is not an existing directory"
            )
        resolved = candidate.resolve(strict=True)
        key = os.path.normcase(str(resolved))
        if key in seen:
            raise RuntimeError(f"multi-HDD root on line {line_number} is duplicated")
        seen.add(key)
        roots.append(resolved)
    if not roots:
        raise RuntimeError("multi-HDD roots file contains no directories")
    for index, root in enumerate(roots):
        for other in roots[index + 1 :]:
            if path_is_relative_to(root, other) or path_is_relative_to(other, root):
                raise RuntimeError("multi-HDD roots must not overlap or nest")
    return roots


def media_storage_targets(
    roots: list[Path], inventory: list[dict[str, object]], *, allow_non_hdd: bool
) -> list[storage.StorageTarget]:
    """Resolve private roots to distinct physical-disk evidence."""

    targets: list[storage.StorageTarget] = []
    for index, root in enumerate(roots):
        target = storage.target_disk(root, Path(root.anchor), inventory)
        media_type = str(target.get("mediaType") or "Unspecified")
        if media_type.casefold() != "hdd" and not allow_non_hdd:
            raise RuntimeError(
                f"multi-HDD root {index + 1} resolved to {media_type!r}; "
                "use --allow-non-hdd only for an intentional mixed-media run"
            )
        counter_key = target.get("counterKey")
        if counter_key is None:
            raise RuntimeError(
                f"multi-HDD root {index + 1} has no physical-disk counter"
            )
        targets.append(
            storage.StorageTarget(
                role=f"mediaRoot{index + 1}",
                root=root,
                disk_number=target.get("diskNumber"),
                counter_key=counter_key,
                media_type=media_type,
                bus_type=str(target.get("busType") or ""),
                friendly_name=str(target.get("friendlyName") or ""),
                mount_path=Path(str(target.get("mountPath") or root.anchor)),
                expected_file_count=0,
                expected_bytes=0,
            )
        )
    return targets


def distinct_counter_keys(
    targets: list[storage.StorageTarget],
) -> list[str | int]:
    """Return stable physical counters in first-root order."""

    result: list[str | int] = []
    seen: set[str] = set()
    for target in targets:
        if target.counter_key is None:
            continue
        key = str(target.counter_key).casefold()
        if key not in seen:
            seen.add(key)
            result.append(target.counter_key)
    return result


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
        if existing.get("schema") != FIXTURE_SCHEMA:
            raise RuntimeError(
                "fixture manifest is not v2; run cleanup --confirm-delete and prepare again"
            )
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
                    "targetRoots": [
                        {"role": "ssdBaseline"}
                        | {
                            key: target.get(key)
                            for key in (
                                "diskNumber",
                                "counterKey",
                                "mediaType",
                                "busType",
                                "friendlyName",
                            )
                        }
                    ],
                }
    storage.make_directories(paths.scenario_root)
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
        if storage.is_file(path) and storage.stat(path).st_size == size:
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
        "targetRoots": [
            {"role": "ssdBaseline"}
            | {
                key: target.get(key)
                for key in (
                    "diskNumber",
                    "counterKey",
                    "mediaType",
                    "busType",
                    "friendlyName",
                )
            }
        ],
    }


def load_prepared_manifest(paths: HarnessPaths) -> dict[str, object]:
    if not paths.owner_path.is_file() or not paths.manifest_path.is_file():
        raise RuntimeError("fixture is not prepared; run the prepare subcommand first")
    owner = json.loads(paths.owner_path.read_text(encoding="utf-8"))
    manifest = json.loads(paths.manifest_path.read_text(encoding="utf-8"))
    if owner.get("schema") != OWNER_SCHEMA:
        raise RuntimeError("fixture ownership marker is invalid")
    if manifest.get("schema") != FIXTURE_SCHEMA:
        raise RuntimeError(
            "fixture manifest is not v2; run cleanup --confirm-delete and prepare again"
        )
    if manifest.get("status") != "prepared":
        raise RuntimeError("fixture preparation did not complete")
    return manifest


def update_fixture_generation(paths: HarnessPaths, generation: str) -> None:
    """Persist which deterministic content generation currently occupies the tree."""

    manifest = load_prepared_manifest(paths)
    manifest["contentGeneration"] = generation
    manifest["generationUpdatedAtUtc"] = utc_now()
    write_json(paths.manifest_path, manifest)


# These implementations own long-path-safe fixture mutation after the facade's
# legacy helpers above have finished defining the command surface.
mutate_fixture = fixture.mutate_fixture
restore_fixture_baseline = fixture.restore_fixture_baseline


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


def disk_io_snapshot(counter_key: str | int | None) -> dict[str, int] | None:
    return storage.disk_io_snapshot(counter_key)


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
    disk_counter_key: str | int | None,
    expected_scanned: int,
    timeout_seconds: float,
    poll_seconds: float,
) -> dict[str, object]:
    """Poll one reload to completion while retaining only sanitized counters."""

    started = time.monotonic()
    deadline = started + timeout_seconds
    process_start = len(sampler.samples)
    disk_before = disk_io_snapshot(disk_counter_key)
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
    disk_after = disk_io_snapshot(disk_counter_key)
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


def disk_io_snapshots(
    counter_keys: list[str | int],
) -> dict[str, dict[str, int] | None]:
    return {str(key): disk_io_snapshot(key) for key in counter_keys}


def disk_io_deltas(
    before: dict[str, dict[str, int] | None],
    after: dict[str, dict[str, int] | None],
) -> dict[str, dict[str, int] | None]:
    return {
        key: counter_delta(snapshot, after.get(key))
        for key, snapshot in before.items()
    }


def run_dynamic_reload_phase(
    *,
    label: str,
    action: Callable[[], object],
    client: RestClient,
    process: subprocess.Popen[str],
    sampler: ProcessSampler,
    counter_keys: list[str | int],
    timeout_seconds: float,
    poll_seconds: float,
    expected_scanned: int | None = None,
) -> dict[str, object]:
    """Run a reload whose real-media file count is intentionally unknown."""

    before_dirs = client.request(
        "GET", "/shared-directories", timeout_seconds=STATUS_LATENCY_LIMIT_SECONDS
    )
    before_progress = compact_progress(before_dirs)
    before_started = before_progress.get("startedAtMs")
    disk_before = disk_io_snapshots(counter_keys)
    process_start = len(sampler.samples)
    started = time.monotonic()
    deadline = started + timeout_seconds
    action()
    max_active = 0
    max_disk_active = 0
    observations: list[dict[str, object]] = []
    final: dict[str, object] | None = None
    saw_activity = False
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
        scanned = int(progress.get("scannedCount") or 0)
        saw_activity = saw_activity or bool(progress.get("running")) or (
            progress.get("startedAtMs") is not None
            and progress.get("startedAtMs") != before_started
        )
        max_active = max(max_active, int(progress.get("activeHashCount") or 0))
        max_disk_active = max(
            max_disk_active,
            *(int(value or 0) for value in progress["diskActiveCounts"]),
            0,
        )
        if not observations or time.monotonic() - started >= len(observations) * 30:
            observations.append(progress)
        count_ok = expected_scanned is None or scanned == expected_scanned
        if (
            saw_activity
            and count_ok
            and progress.get("running") is False
            and progress.get("pending") is False
            and int(data.get("hashingCount") or 0) == 0
        ):
            final = progress
            break
        time.sleep(poll_seconds)
    if final is None:
        raise TimeoutError(f"{label} did not settle within {timeout_seconds:.0f}s")
    sampler.maybe_sample(force=True)
    disk_after = disk_io_snapshots(counter_keys)
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
        "physicalDiskIoDeltas": disk_io_deltas(disk_before, disk_after),
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
                "shareSourceRows": "SELECT COUNT(*) FROM shared_file_sources",
                "unsharedFiles": "SELECT COUNT(*) FROM unshared_files",
                "transferRows": "SELECT COUNT(*) FROM transfers",
                "activeTransferRows": (
                    "SELECT COUNT(*) FROM transfers WHERE removed_at_ms IS NULL"
                ),
                "activeShareSources": """
                    SELECT COUNT(*)
                    FROM shared_file_sources
                    WHERE NOT EXISTS (
                        SELECT 1 FROM unshared_files
                        WHERE unshared_files.known_file_id =
                              shared_file_sources.known_file_id
                    )
                """,
                "activeShareBytes": """
                    SELECT coalesce(sum(shared_file_sources.file_size), 0)
                    FROM shared_file_sources
                    WHERE NOT EXISTS (
                        SELECT 1 FROM unshared_files
                        WHERE unshared_files.known_file_id =
                              shared_file_sources.known_file_id
                    )
                """,
                "activeLongPathSources": """
                    SELECT COUNT(*)
                    FROM shared_file_sources
                    JOIN local_paths
                      ON local_paths.id = shared_file_sources.path_id
                    WHERE length(local_paths.display_path) > 260
                      AND NOT EXISTS (
                          SELECT 1 FROM unshared_files
                          WHERE unshared_files.known_file_id =
                                shared_file_sources.known_file_id
                      )
                """,
                "invalidActiveShareIntegrity": """
                    SELECT COUNT(*)
                    FROM shared_file_sources
                    JOIN known_files
                      ON known_files.id = shared_file_sources.known_file_id
                    WHERE NOT EXISTS (
                        SELECT 1 FROM unshared_files
                        WHERE unshared_files.known_file_id =
                              shared_file_sources.known_file_id
                    )
                      AND (
                          known_files.completed != 1
                          OR known_files.md4_hashset_acquired != 1
                          OR known_files.aich_hashset_acquired != 1
                          OR known_files.aich_root IS NULL
                          OR length(known_files.aich_root) != 20
                          OR known_files.size_bytes != shared_file_sources.file_size
                      )
                """,
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


def storage_acceptance(
    snapshot: dict[str, object],
    *,
    expected_active: int,
    expected_bytes: int,
    expected_minimum_long: int,
    require_known_exact: bool = False,
) -> dict[str, bool]:
    counts = (
        snapshot.get("rowCounts") if isinstance(snapshot.get("rowCounts"), dict) else {}
    )
    checks = {
        "databaseActiveShares": counts.get("activeShareSources") == expected_active,
        "databaseActiveBytes": counts.get("activeShareBytes") == expected_bytes,
        "databaseHashIntegrity": counts.get("invalidActiveShareIntegrity") == 0,
        "databaseLongPathShares": int(counts.get("activeLongPathSources") or 0)
        >= expected_minimum_long,
        "databaseScanFailures": counts.get("scanFailures") == 0,
    }
    if require_known_exact:
        checks["databaseKnownFiles"] = counts.get("knownFiles") == expected_active
    return checks


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


def media_initial_acceptance(
    phase: dict[str, object], *, expected_disk_count: int
) -> dict[str, object]:
    progress = phase.get("progress") if isinstance(phase.get("progress"), dict) else {}
    storage_snapshot = (
        phase.get("storage") if isinstance(phase.get("storage"), dict) else {}
    )
    counts = (
        storage_snapshot.get("rowCounts")
        if isinstance(storage_snapshot.get("rowCounts"), dict)
        else {}
    )
    planned = int(progress.get("plannedHashCount") or 0)
    hashed = int(progress.get("hashedCount") or 0)
    failed = int(progress.get("failedHashCount") or 0)
    shared_total = int(phase.get("sharedFilesTotal") or 0)
    disk_deltas = (
        phase.get("physicalDiskIoDeltas")
        if isinstance(phase.get("physicalDiskIoDeltas"), dict)
        else {}
    )
    checks = {
        "scannedFiles": int(progress.get("scannedCount") or 0) > 0,
        "plannedFiles": planned > 0,
        "hashPlanCompleted": hashed + failed == planned,
        "hashFailures": failed == 0,
        "statFailures": int(progress.get("statFailedCount") or 0) == 0,
        "skippedFailures": int(progress.get("skippedFailedCount") or 0) == 0,
        "skippedIntake": int(progress.get("skippedIntakeCount") or 0) == 0,
        "physicalDiskCount": progress.get("diskCount") == expected_disk_count,
        "crossDiskConcurrency": int(phase.get("maxActiveHashCount") or 0) >= 2,
        "boundedCrossDiskConcurrency": int(phase.get("maxActiveHashCount") or 0)
        <= expected_disk_count,
        "serializedPerDisk": int(phase.get("maxPerDiskActiveCount") or 0) <= 1,
        "diskCountersAvailable": len(disk_deltas) == expected_disk_count
        and all(isinstance(value, dict) for value in disk_deltas.values()),
        "physicalReadsObserved": len(disk_deltas) == expected_disk_count
        and all(
            int(value.get("read_count") or 0) > 0
            for value in disk_deltas.values()
            if isinstance(value, dict)
        ),
        "catalogNonEmpty": shared_total > 0,
        "databaseHasSources": int(counts.get("activeShareSources") or 0) > 0,
        "databaseHashIntegrity": int(counts.get("invalidActiveShareIntegrity") or 0)
        == 0,
        "databaseScanFailures": int(counts.get("scanFailures") or 0) == 0,
        "noTransferRows": int(counts.get("activeTransferRows") or 0) == 0,
    }
    return {"ok": all(checks.values()), "checks": checks}


def media_no_change_acceptance(
    phase: dict[str, object], *, initial: dict[str, object]
) -> dict[str, object]:
    progress = phase.get("progress") if isinstance(phase.get("progress"), dict) else {}
    initial_progress = (
        initial.get("progress") if isinstance(initial.get("progress"), dict) else {}
    )
    checks = {
        "catalogStable": phase.get("sharedFilesTotal") == initial.get("sharedFilesTotal"),
        "scannedCountStable": progress.get("scannedCount")
        == initial_progress.get("scannedCount"),
        "noHashPlan": int(progress.get("plannedHashCount") or 0) == 0,
        "noHashing": int(progress.get("hashedCount") or 0) == 0,
        "noPayloadReadPlan": int(progress.get("plannedReadBytes") or 0) == 0,
        "noPayloadRead": int(progress.get("completedReadBytes") or 0) == 0,
        "allReused": progress.get("reusedCount") == progress.get("scannedCount"),
        "noHashDisks": int(progress.get("diskCount") or 0) == 0,
        "noFailures": all(
            int(progress.get(field) or 0) == 0
            for field in (
                "failedHashCount",
                "statFailedCount",
                "skippedFailedCount",
                "skippedIntakeCount",
            )
        ),
        "serializedPerDisk": int(phase.get("maxPerDiskActiveCount") or 0) <= 1,
    }
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


def _normalized_path_key(path: str | Path) -> str:
    logical = storage.logical_path(path)
    normalized = os.path.normpath(os.path.abspath(os.fspath(logical)))
    return os.path.normcase(normalized)


def _watcher_database_rows(profile_dir: Path) -> dict[str, dict[str, object]]:
    """Read active watcher-probe identities without returning paths to reports."""

    database = profile_dir / rust_metadata.RUST_PROFILE_METADATA_FILE
    if not database.is_file():
        return {}
    with sqlite3.connect(
        f"file:{database.as_posix()}?mode=ro", uri=True, timeout=5
    ) as connection:
        rows = connection.execute(
            """
            SELECT lower(hex(known_files.ed2k_hash)), known_files.display_name,
                   known_files.size_bytes, known_files.completed,
                   known_files.md4_hashset_acquired,
                   known_files.aich_hashset_acquired,
                   length(known_files.aich_root), local_paths.display_path,
                   shared_file_sources.source_mtime_ms
            FROM shared_file_sources
            JOIN known_files
              ON known_files.id = shared_file_sources.known_file_id
            JOIN local_paths ON local_paths.id = shared_file_sources.path_id
            WHERE known_files.display_name GLOB 'watch-probe-*.bin'
              AND NOT EXISTS (
                  SELECT 1 FROM unshared_files
                  WHERE unshared_files.known_file_id = known_files.id
              )
            """
        ).fetchall()
    return {
        _normalized_path_key(str(row[7])): {
            "hash": str(row[0]),
            "name": str(row[1]),
            "sizeBytes": int(row[2]),
            "completed": int(row[3]),
            "md4Acquired": int(row[4]),
            "aichAcquired": int(row[5]),
            "aichRootBytes": int(row[6] or 0),
            "sourceMtimeMs": row[8],
            "sourcePath": str(row[7]),
        }
        for row in rows
    }


def _expected_watcher_paths(
    fixture_root: Path, *, renamed: bool
) -> dict[str, dict[str, object]]:
    expected: dict[str, dict[str, object]] = {}
    for index in range(fixture.WATCHER_FILE_COUNT):
        path = fixture_root / fixture.watcher_relative_file(index, renamed=renamed)
        expected[_normalized_path_key(path)] = {
            "sizeBytes": fixture.watcher_size_for_index(index),
            "pathClass": "long"
            if index >= fixture.WATCHER_FILE_COUNT - fixture.WATCHER_LONG_PATH_COUNT
            else "normal",
        }
    return expected


def _watcher_row_evidence(
    rows: dict[str, dict[str, object]],
    expected: dict[str, dict[str, object]],
    *,
    previous_hashes: dict[str, str] | None = None,
    require_changed_hashes: bool = False,
    require_same_hashes: bool = False,
) -> tuple[dict[str, object], bool]:
    actual_keys = set(rows)
    expected_keys = set(expected)
    invalid_integrity = sum(
        1
        for key, row in rows.items()
        if key not in expected
        or row["sizeBytes"] != expected[key]["sizeBytes"]
        or row["completed"] != 1
        or row["md4Acquired"] != 1
        or row["aichAcquired"] != 1
        or row["aichRootBytes"] != 20
        or row["sourceMtimeMs"] is None
    )
    normal_count = sum(
        1
        for key in actual_keys & expected_keys
        if expected[key]["pathClass"] == "normal"
    )
    long_count = sum(
        1 for key in actual_keys & expected_keys if expected[key]["pathClass"] == "long"
    )
    current_hashes = {key: str(row["hash"]) for key, row in rows.items()}
    hash_transition_ok = True
    if previous_hashes is not None:
        comparable = expected_keys & set(previous_hashes) & set(current_hashes)
        if require_changed_hashes:
            hash_transition_ok = len(comparable) == len(expected_keys) and all(
                previous_hashes[key] != current_hashes[key] for key in comparable
            )
        elif require_same_hashes:
            # Renames change path keys. Content identity is therefore compared as sets.
            hash_transition_ok = set(previous_hashes.values()) == set(
                current_hashes.values()
            )
    evidence = {
        "activeCount": len(rows),
        "normalPathCount": normal_count,
        "longPathCount": long_count,
        "totalBytes": sum(int(row["sizeBytes"]) for row in rows.values()),
        "missingPathCount": len(expected_keys - actual_keys),
        "unexpectedPathCount": len(actual_keys - expected_keys),
        "invalidIntegrityCount": invalid_integrity,
        "hashTransitionOk": hash_transition_ok,
    }
    ok = actual_keys == expected_keys and invalid_integrity == 0 and hash_transition_ok
    return evidence, ok


def _sample_watcher_rest(
    client: RestClient,
    rows: dict[str, dict[str, object]],
    expected: dict[str, dict[str, object]],
) -> dict[str, object]:
    """Verify a bounded 20+20 normal/long sample without paginating 100k rows."""

    selected: list[tuple[str, dict[str, object]]] = []
    for path_class in ("normal", "long"):
        candidates = sorted(
            (
                (key, rows[key])
                for key in set(rows) & set(expected)
                if expected[key]["pathClass"] == path_class
            ),
            key=lambda item: str(item[1]["hash"]),
        )
        selected.extend(candidates[:20])
    failures = 0
    for key, row in selected:
        data = client.request(
            "GET",
            f"/shared-files/{row['hash']}",
            timeout_seconds=STATUS_LATENCY_LIMIT_SECONDS,
        )
        source_path = data.get("path")
        if (
            str(data.get("hash") or "").casefold() != str(row["hash"]).casefold()
            or int(data.get("sizeBytes") or -1) != int(row["sizeBytes"])
            or not isinstance(source_path, str)
            or _normalized_path_key(source_path) != key
        ):
            failures += 1
    return {
        "sampleCount": len(selected),
        "failureCount": failures,
        "normalSampleCount": min(
            20, sum(1 for value in expected.values() if value["pathClass"] == "normal")
        ),
        "longSampleCount": min(
            20, sum(1 for value in expected.values() if value["pathClass"] == "long")
        ),
    }


class WatcherConvergenceError(TimeoutError):
    """A strict watcher failure carrying only sanitized phase evidence."""

    def __init__(self, phase_report: dict[str, object]) -> None:
        self.phase_report = phase_report
        reason = (
            "did not converge within its phase timeout"
            if not phase_report["acceptance"]["checks"]["converged"]
            else "failed strict post-convergence acceptance"
        )
        super().__init__(f"{phase_report['label']} {reason}")


def run_watcher_phase(
    *,
    label: str,
    action: Callable[[], dict[str, int]],
    expected_paths: dict[str, dict[str, object]],
    expected_catalog_total: int,
    client: RestClient,
    process: subprocess.Popen[str],
    sampler: ProcessSampler,
    profile_dir: Path,
    disk_counter_key: str | int | None,
    timeout_seconds: float,
    poll_seconds: float,
    previous_hashes: dict[str, str] | None = None,
    require_changed_hashes: bool = False,
    require_same_hashes: bool = False,
) -> tuple[dict[str, object], dict[str, str]]:
    """Apply one live mutation and wait for REST plus SQLite convergence."""

    started = time.monotonic()
    deadline = started + timeout_seconds
    process_start = len(sampler.samples)
    disk_before = disk_io_snapshot(disk_counter_key)
    operation = action()
    final_rows: dict[str, dict[str, object]] = {}
    final_evidence, _ = _watcher_row_evidence(
        {},
        expected_paths,
        previous_hashes=previous_hashes,
        require_changed_hashes=require_changed_hashes,
        require_same_hashes=require_same_hashes,
    )
    shared_total: int | None = None
    converged = False
    class_convergence: dict[str, float | None] = {"normal": None, "long": None}
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"emulebb-rust exited during {label} with code {process.returncode}"
            )
        sampler.maybe_sample()
        try:
            shared = client.request(
                "GET",
                "/shared-files?offset=0&limit=1",
                timeout_seconds=STATUS_LATENCY_LIMIT_SECONDS,
            )
            shared_total = int(shared.get("total") or 0)
            rows = _watcher_database_rows(profile_dir)
            evidence, rows_ok = _watcher_row_evidence(
                rows,
                expected_paths,
                previous_hashes=previous_hashes,
                require_changed_hashes=require_changed_hashes,
                require_same_hashes=require_same_hashes,
            )
            final_rows = rows
            final_evidence = evidence
            for path_class in class_convergence:
                if class_convergence[path_class] is not None:
                    continue
                if expected_paths:
                    class_expected = {
                        key: value
                        for key, value in expected_paths.items()
                        if value["pathClass"] == path_class
                    }
                    class_rows = {
                        key: value
                        for key, value in rows.items()
                        if key in class_expected
                    }
                    class_previous = (
                        {
                            key: value
                            for key, value in previous_hashes.items()
                            if ("watcher-long-segment" in key) == (path_class == "long")
                        }
                        if previous_hashes is not None
                        else None
                    )
                    _, class_ok = _watcher_row_evidence(
                        class_rows,
                        class_expected,
                        previous_hashes=class_previous,
                        require_changed_hashes=require_changed_hashes,
                        require_same_hashes=require_same_hashes,
                    )
                else:
                    class_ok = not rows
                if class_ok:
                    class_convergence[path_class] = round(time.monotonic() - started, 3)
            if shared_total == expected_catalog_total and rows_ok:
                converged = True
                break
        except sqlite3.OperationalError:
            pass
        time.sleep(poll_seconds)
    sampler.maybe_sample(force=True)
    disk_after = disk_io_snapshot(disk_counter_key)
    rest_sample = (
        _sample_watcher_rest(client, final_rows, expected_paths)
        if converged and expected_paths
        else {
            "sampleCount": 0,
            "failureCount": 0,
            "normalSampleCount": 0,
            "longSampleCount": 0,
        }
    )
    elapsed = time.monotonic() - started
    storage_snapshot = profile_storage_snapshot(profile_dir)
    acceptance_checks = {
        "converged": converged,
        "catalogTotal": shared_total == expected_catalog_total,
        "exactPaths": final_evidence["missingPathCount"] == 0
        and final_evidence["unexpectedPathCount"] == 0,
        "metadataIntegrity": final_evidence["invalidIntegrityCount"] == 0,
        "hashTransition": final_evidence["hashTransitionOk"] is True,
        "restIdentitySample": rest_sample["failureCount"] == 0,
    } | storage_acceptance(
        storage_snapshot,
        expected_active=expected_catalog_total,
        expected_bytes=PRODUCTION_SPEC.total_bytes
        + sum(int(value["sizeBytes"]) for value in expected_paths.values()),
        expected_minimum_long=fixture.baseline_long_path_count()
        + sum(1 for value in expected_paths.values() if value["pathClass"] == "long"),
    )
    report = {
        "label": label,
        "elapsedSeconds": round(elapsed, 3),
        "operation": operation,
        "sharedFilesTotal": shared_total,
        "database": final_evidence,
        "restIdentitySample": rest_sample,
        "throughput": {
            "filesPerSecond": round(operation["fileCount"] / elapsed, 3),
            "mibPerSecond": round(operation["totalBytes"] / MIB / elapsed, 3),
        },
        "pathClassConvergenceSeconds": class_convergence,
        "process": sampler.summary(process_start),
        "physicalDiskIoDelta": counter_delta(disk_before, disk_after),
        "storage": storage_snapshot,
        "acceptance": {
            "ok": converged and all(acceptance_checks.values()),
            "checks": acceptance_checks,
        },
    }
    if not report["acceptance"]["ok"]:
        raise WatcherConvergenceError(report)
    return report, {key: str(row["hash"]) for key, row in final_rows.items()}


def watcher_log_summary(log_paths: list[Path]) -> dict[str, object]:
    marker_counts = {
        "logByteCount": 0,
        "nonEmptyLogCount": 0,
        "watcherRegistrations": 0,
        "autoShared": 0,
        "autoRemoved": 0,
        "watcherErrors": 0,
    }
    error_markers = (
        "failed to auto-share monitored file",
        "failed to auto-remove monitored file",
        "shared-directory watcher reported an error",
        "failed to create shared-directory watcher",
        "failed to watch shared directory",
    )
    for path in log_paths:
        if not path.is_file():
            continue
        byte_count = path.stat().st_size
        marker_counts["logByteCount"] += byte_count
        marker_counts["nonEmptyLogCount"] += int(byte_count > 0)
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            marker_counts["watcherRegistrations"] += int(
                "watching shared directory for auto-pickup" in line
            )
            marker_counts["autoShared"] += int("auto-shared monitored file" in line)
            marker_counts["autoRemoved"] += int(
                "auto-removed monitored file from shared catalog" in line
            )
            marker_counts["watcherErrors"] += int(
                any(marker in line for marker in error_markers)
            )
    return marker_counts


def run_campaign(
    paths: HarnessPaths, args: argparse.Namespace
) -> tuple[Path, dict[str, object]]:
    """Run initial scan, watcher lifecycle, reload, and persistence phases."""

    manifest = load_prepared_manifest(paths)
    # A terminated prior run may have left only harness-owned probe files behind.
    storage.remove_tree(paths.fixture_root / "_watcher-probe-v2")
    storage.remove_tree(paths.scenario_root / "watcher-staging")
    restored = {"fileCount": 0, "totalBytes": 0}
    if manifest.get("contentGeneration") == "mutation-v2":
        restored = restore_fixture_baseline(paths.fixture_root)
        update_fixture_generation(paths, "base-v2")
    elif manifest.get("contentGeneration") != "base-v2":
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
    staging_root = paths.scenario_root / "watcher-staging"
    if storage.is_directory(run_root):
        raise RuntimeError("generated run directory already exists")
    storage.make_directories(run_root)
    report_path = paths.reports_root / f"rust-shared-library-io-{run_id}.json"
    mount_path = str(target.get("mountPath") or paths.output_root.anchor)
    storage_targets = [
        storage.StorageTarget(
            role="ssdBaseline",
            root=paths.fixture_root,
            disk_number=target.get("diskNumber"),
            counter_key=target.get("counterKey"),
            media_type=str(target.get("mediaType") or "Unspecified"),
            bus_type=str(target.get("busType") or ""),
            friendly_name=str(target.get("friendlyName") or ""),
            mount_path=Path(mount_path),
            expected_file_count=PRODUCTION_SPEC.file_count,
            expected_bytes=PRODUCTION_SPEC.total_bytes,
        )
    ]
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
        "targetRoots": [item.sanitized(path_fingerprint) for item in storage_targets],
        "diskInventory": sanitized_disk_inventory(inventory),
        "phases": [],
        "watcherLifecycle": [],
    }
    process: subprocess.Popen[str] | None = None
    client: RestClient | None = None
    clients: list[RestClient] = []
    log_paths: list[Path] = []
    overall_started = time.monotonic()
    overall_deadline = overall_started + args.timeout_seconds

    def remaining_seconds() -> float:
        remaining = overall_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"campaign exceeded the {args.timeout_seconds:.0f}s overall timeout"
            )
        return remaining

    def watcher_timeout() -> float:
        return min(args.watcher_timeout_seconds, remaining_seconds())

    try:
        initial_log = run_root / "initial.log"
        log_paths.append(initial_log)
        process, client, sampler = start_daemon(
            paths, profile_dir, initial_log, choose_loopback_port()
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
            disk_counter_key=target.get("counterKey"),
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
        initial["acceptance"]["checks"].update(
            storage_acceptance(
                initial["storage"],
                expected_active=PRODUCTION_SPEC.file_count,
                expected_bytes=PRODUCTION_SPEC.total_bytes,
                expected_minimum_long=fixture.baseline_long_path_count(),
                require_known_exact=True,
            )
        )
        initial["acceptance"]["ok"] = all(initial["acceptance"]["checks"].values())
        report["phases"].append(initial)

        report["watcherStaging"] = fixture.stage_watcher_cohort(staging_root)
        created_paths = _expected_watcher_paths(paths.fixture_root, renamed=False)
        renamed_paths = _expected_watcher_paths(paths.fixture_root, renamed=True)
        created, created_hashes = run_watcher_phase(
            label="watcherCreate",
            action=lambda: fixture.install_watcher_cohort(
                staging_root, paths.fixture_root
            ),
            expected_paths=created_paths,
            expected_catalog_total=PRODUCTION_SPEC.file_count
            + fixture.WATCHER_FILE_COUNT,
            client=client,
            process=process,
            sampler=sampler,
            profile_dir=profile_dir,
            disk_counter_key=target.get("counterKey"),
            timeout_seconds=watcher_timeout(),
            poll_seconds=args.watcher_poll_seconds,
        )
        report["watcherLifecycle"].append(created)
        modified, modified_hashes = run_watcher_phase(
            label="watcherModify",
            action=lambda: fixture.modify_watcher_cohort(paths.fixture_root),
            expected_paths=created_paths,
            expected_catalog_total=PRODUCTION_SPEC.file_count
            + fixture.WATCHER_FILE_COUNT,
            client=client,
            process=process,
            sampler=sampler,
            profile_dir=profile_dir,
            disk_counter_key=target.get("counterKey"),
            timeout_seconds=watcher_timeout(),
            poll_seconds=args.watcher_poll_seconds,
            previous_hashes=created_hashes,
            require_changed_hashes=True,
        )
        report["watcherLifecycle"].append(modified)
        renamed, renamed_hashes = run_watcher_phase(
            label="watcherRename",
            action=lambda: fixture.rename_watcher_cohort(paths.fixture_root),
            expected_paths=renamed_paths,
            expected_catalog_total=PRODUCTION_SPEC.file_count
            + fixture.WATCHER_FILE_COUNT,
            client=client,
            process=process,
            sampler=sampler,
            profile_dir=profile_dir,
            disk_counter_key=target.get("counterKey"),
            timeout_seconds=watcher_timeout(),
            poll_seconds=args.watcher_poll_seconds,
            previous_hashes=modified_hashes,
            require_same_hashes=True,
        )
        report["watcherLifecycle"].append(renamed)
        deleted, _ = run_watcher_phase(
            label="watcherDelete",
            action=lambda: fixture.delete_watcher_cohort(paths.fixture_root),
            expected_paths={},
            expected_catalog_total=PRODUCTION_SPEC.file_count,
            client=client,
            process=process,
            sampler=sampler,
            profile_dir=profile_dir,
            disk_counter_key=target.get("counterKey"),
            timeout_seconds=watcher_timeout(),
            poll_seconds=args.watcher_poll_seconds,
            previous_hashes=renamed_hashes,
        )
        report["watcherLifecycle"].append(deleted)
        report["initialShutdown"] = stop_daemon(process, client)
        process = None
        client = None

        restart_log = run_root / "restart.log"
        log_paths.append(restart_log)
        process, client, sampler = start_daemon(
            paths, profile_dir, restart_log, choose_loopback_port()
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
            "watcherActiveCount": len(_watcher_database_rows(profile_dir)),
            "storage": profile_storage_snapshot(profile_dir),
        }

        client.request("POST", "/shared-directories/operations/reload", {})
        no_change = wait_for_reload(
            label="noChangeReload",
            client=client,
            process=process,
            sampler=sampler,
            disk_counter_key=target.get("counterKey"),
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
        no_change["acceptance"]["checks"].update(
            storage_acceptance(
                no_change["storage"],
                expected_active=PRODUCTION_SPEC.file_count,
                expected_bytes=PRODUCTION_SPEC.total_bytes,
                expected_minimum_long=fixture.baseline_long_path_count(),
            )
        )
        no_change["acceptance"]["ok"] = all(no_change["acceptance"]["checks"].values())
        report["phases"].append(no_change)
        report["preMutationShutdown"] = stop_daemon(process, client)
        process = None
        client = None

        mutation = mutate_fixture(paths.fixture_root)
        update_fixture_generation(paths, "mutation-v2")
        report["mutation"] = mutation
        mutation_log = run_root / "mutation.log"
        log_paths.append(mutation_log)
        process, client, sampler = start_daemon(
            paths, profile_dir, mutation_log, choose_loopback_port()
        )
        clients.append(client)
        client.request("POST", "/shared-directories/operations/reload", {})
        changed = wait_for_reload(
            label="onePercentMutation",
            client=client,
            process=process,
            sampler=sampler,
            disk_counter_key=target.get("counterKey"),
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
        changed["acceptance"]["checks"].update(
            storage_acceptance(
                changed["storage"],
                expected_active=PRODUCTION_SPEC.file_count,
                expected_bytes=PRODUCTION_SPEC.total_bytes,
                expected_minimum_long=fixture.baseline_long_path_count(),
            )
        )
        changed["acceptance"]["ok"] = all(changed["acceptance"]["checks"].values())
        report["phases"].append(changed)
        report["mutationShutdown"] = stop_daemon(process, client)
        process = None
        client = None

        final_log = run_root / "final-restart.log"
        log_paths.append(final_log)
        process, client, _ = start_daemon(
            paths, profile_dir, final_log, choose_loopback_port()
        )
        clients.append(client)
        final_shared = client.request(
            "GET",
            "/shared-files?offset=0&limit=1",
            timeout_seconds=STATUS_LATENCY_LIMIT_SECONDS,
        )
        final_dirs = client.request(
            "GET", "/shared-directories", timeout_seconds=STATUS_LATENCY_LIMIT_SECONDS
        )
        report["finalRestart"] = {
            "sharedFilesTotal": final_shared.get("total"),
            "hashingCount": final_dirs.get("hashingCount"),
            "watcherActiveCount": len(_watcher_database_rows(profile_dir)),
            "storage": profile_storage_snapshot(profile_dir),
        }
        report["finalShutdown"] = stop_daemon(process, client)
        process = None
        client = None

        rest = rest_summary(clients)
        logs = watcher_log_summary(log_paths)
        report["rest"] = rest
        report["watcherLogs"] = logs
        warm = report["warmRestart"]
        final = report["finalRestart"]
        phase_results = [phase["acceptance"]["ok"] for phase in report["phases"]]
        watcher_results = [
            phase["acceptance"]["ok"] for phase in report["watcherLifecycle"]
        ]
        functional_watcher_registration = len(watcher_results) == 4 and all(
            watcher_results
        )
        report["watcherRegistrationEvidence"] = {
            "method": (
                "tracingLog"
                if int(logs["watcherRegistrations"]) > 0
                else "functionalLifecycle"
            ),
            "logMarkerCount": int(logs["watcherRegistrations"]),
            "successfulLifecyclePhaseCount": sum(
                bool(value) for value in watcher_results
            ),
        }
        global_checks = {
            "fixtureExact": validation["ok"] is True,
            "longPathBaselineExact": validation["longPathFileCount"]
            == fixture.baseline_long_path_count(),
            "warmRestartCatalog": warm["sharedFilesTotal"]
            == PRODUCTION_SPEC.file_count,
            "warmRestartIdle": int(warm["hashingCount"] or 0) == 0,
            "warmRestartNoWatcherRows": int(warm["watcherActiveCount"]) == 0,
            "warmRestartStorage": all(
                storage_acceptance(
                    warm["storage"],
                    expected_active=PRODUCTION_SPEC.file_count,
                    expected_bytes=PRODUCTION_SPEC.total_bytes,
                    expected_minimum_long=fixture.baseline_long_path_count(),
                ).values()
            ),
            "finalRestartCatalog": final["sharedFilesTotal"]
            == PRODUCTION_SPEC.file_count,
            "finalRestartIdle": int(final["hashingCount"] or 0) == 0,
            "finalRestartNoWatcherRows": int(final["watcherActiveCount"]) == 0,
            "finalRestartStorage": all(
                storage_acceptance(
                    final["storage"],
                    expected_active=PRODUCTION_SPEC.file_count,
                    expected_bytes=PRODUCTION_SPEC.total_bytes,
                    expected_minimum_long=fixture.baseline_long_path_count(),
                ).values()
            ),
            "mutationExact": mutation
            == {
                "fileCount": len(mutation_indices()),
                "totalBytes": expected_mutation_bytes(),
            },
            "watcherRegistered": int(logs["watcherRegistrations"]) > 0
            or functional_watcher_registration,
            "noWatcherErrors": int(logs["watcherErrors"]) == 0,
            "noRestErrors": rest["errorCount"] == 0,
            "withinTimeout": time.monotonic() - overall_started <= args.timeout_seconds,
        }
        report["acceptance"] = {
            "ok": all(phase_results)
            and all(watcher_results)
            and all(global_checks.values()),
            "phaseResults": phase_results,
            "watcherResults": watcher_results,
            "globalChecks": global_checks,
        }
        report["status"] = "passed" if report["acceptance"]["ok"] else "failed"
    except WatcherConvergenceError as exc:
        report["watcherLifecycle"].append(exc.phase_report)
        report["status"] = "failed"
        report["error"] = {
            "type": type(exc).__name__,
            "phase": exc.phase_report["label"],
        }
        raise
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__}
        raise
    finally:
        if process is not None:
            report["emergencyShutdown"] = stop_daemon(process, client)
        storage.remove_tree(staging_root)
        storage.remove_tree(paths.fixture_root / "_watcher-probe-v2")
        report["rest"] = rest_summary(clients)
        report["watcherLogs"] = watcher_log_summary(log_paths)
        report["finishedAtUtc"] = utc_now()
        report["elapsedSeconds"] = round(time.monotonic() - overall_started, 3)
        write_json(report_path, report)
    return report_path, report


def media_campaign_paths(paths: HarnessPaths) -> tuple[Path, Path]:
    scenario_root = paths.output_root / "profiles" / "emulebb-rust-shared-library-media-io"
    reports_root = paths.output_root / "reports" / "emulebb-rust" / "shared-library-media-io"
    if not path_is_relative_to(scenario_root, paths.output_root):
        raise RuntimeError("multi-HDD profile root escaped EMULEBB_WORKSPACE_OUTPUT_ROOT")
    return scenario_root, reports_root


def run_media_campaign(
    paths: HarnessPaths, args: argparse.Namespace
) -> tuple[Path, dict[str, object]]:
    """Hash operator-selected media roots without mutating their contents."""

    roots_file = Path(args.roots_file).resolve(strict=True)
    roots = load_media_roots(roots_file)
    inventory = physical_disk_inventory()
    targets = media_storage_targets(
        roots, inventory, allow_non_hdd=bool(args.allow_non_hdd)
    )
    counter_keys = distinct_counter_keys(targets)
    if len(counter_keys) < args.minimum_disks:
        raise RuntimeError(
            f"multi-HDD run resolved only {len(counter_keys)} physical disks; "
            f"at least {args.minimum_disks} are required"
        )
    if not paths.staged_executable.is_file():
        raise RuntimeError(
            f"staged emulebb-rust executable is missing: {paths.staged_executable}"
        )
    scenario_root, reports_root = media_campaign_paths(paths)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
    run_root = scenario_root / "runs" / run_id
    profile_dir = run_root / "profile"
    report_path = reports_root / f"rust-shared-library-media-io-{run_id}.json"
    if run_root.exists():
        raise RuntimeError("generated multi-HDD run directory already exists")
    storage.make_directories(run_root)
    report: dict[str, object] = {
        "schema": MEDIA_REPORT_SCHEMA,
        "status": "running",
        "runId": run_id,
        "startedAtUtc": utc_now(),
        "mode": "readOnlyExistingMedia",
        "sourceRootCount": len(roots),
        "physicalDiskCount": len(counter_keys),
        "paths": {
            "rootsFileFingerprint": path_fingerprint(roots_file),
            "profileFingerprint": path_fingerprint(profile_dir),
            "outputRootFingerprint": path_fingerprint(paths.output_root),
        },
        "targetRoots": [target.sanitized(path_fingerprint) for target in targets],
        "diskInventory": sanitized_disk_inventory(inventory),
        "phases": [],
    }
    process: subprocess.Popen[str] | None = None
    client: RestClient | None = None
    clients: list[RestClient] = []
    started = time.monotonic()
    deadline = started + args.timeout_seconds

    def remaining_seconds() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"multi-HDD campaign exceeded the {args.timeout_seconds:.0f}s timeout"
            )
        return remaining

    try:
        process, client, sampler = start_daemon(
            paths, profile_dir, run_root / "initial.log", choose_loopback_port()
        )
        clients.append(client)
        initial = run_dynamic_reload_phase(
            label="multiHddInitial",
            action=lambda: client.request(
                "PATCH",
                "/shared-directories",
                {
                    "confirmReplaceRoots": True,
                    "roots": [{"path": str(root) + os.sep} for root in roots],
                },
            ),
            client=client,
            process=process,
            sampler=sampler,
            counter_keys=counter_keys,
            timeout_seconds=remaining_seconds(),
            poll_seconds=args.poll_seconds,
        )
        initial["storage"] = profile_storage_snapshot(profile_dir)
        initial["acceptance"] = media_initial_acceptance(
            initial, expected_disk_count=len(counter_keys)
        )
        report["phases"].append(initial)
        report["initialShutdown"] = stop_daemon(process, client)
        process = None
        client = None

        process, client, sampler = start_daemon(
            paths, profile_dir, run_root / "restart.log", choose_loopback_port()
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
        no_change = run_dynamic_reload_phase(
            label="multiHddNoChangeReload",
            action=lambda: client.request(
                "POST", "/shared-directories/operations/reload", {}
            ),
            client=client,
            process=process,
            sampler=sampler,
            counter_keys=counter_keys,
            timeout_seconds=remaining_seconds(),
            poll_seconds=args.poll_seconds,
            expected_scanned=int(initial["progress"]["scannedCount"]),
        )
        no_change["storage"] = profile_storage_snapshot(profile_dir)
        no_change["acceptance"] = media_no_change_acceptance(
            no_change, initial=initial
        )
        report["phases"].append(no_change)
        report["finalShutdown"] = stop_daemon(process, client)
        process = None
        client = None

        warm = report["warmRestart"]
        global_checks = {
            "readOnlyMode": report["mode"] == "readOnlyExistingMedia",
            "initialAccepted": initial["acceptance"]["ok"] is True,
            "warmCatalogStable": warm["sharedFilesTotal"]
            == initial["sharedFilesTotal"],
            "warmIdle": int(warm["hashingCount"] or 0) == 0,
            "noChangeAccepted": no_change["acceptance"]["ok"] is True,
            "noRestErrors": rest_summary(clients)["errorCount"] == 0,
            "withinTimeout": time.monotonic() - started <= args.timeout_seconds,
        }
        report["acceptance"] = {
            "ok": all(global_checks.values()),
            "globalChecks": global_checks,
            "phaseResults": [
                initial["acceptance"]["ok"],
                no_change["acceptance"]["ok"],
            ],
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
        report["elapsedSeconds"] = round(time.monotonic() - started, 3)
        write_json(report_path, report)
    return report_path, report


def describe_media_roots(
    paths: HarnessPaths, roots_file: Path, *, allow_non_hdd: bool
) -> dict[str, object]:
    roots_file = roots_file.resolve(strict=True)
    roots = load_media_roots(roots_file)
    inventory = physical_disk_inventory()
    targets = media_storage_targets(roots, inventory, allow_non_hdd=allow_non_hdd)
    counter_keys = distinct_counter_keys(targets)
    _, reports_root = media_campaign_paths(paths)
    return {
        "schema": MEDIA_REPORT_SCHEMA,
        "command": "media-describe",
        "mode": "readOnlyExistingMedia",
        "sourceRootCount": len(roots),
        "physicalDiskCount": len(counter_keys),
        "rootsFileFingerprint": path_fingerprint(roots_file),
        "targetRoots": [target.sanitized(path_fingerprint) for target in targets],
        "physicalDisks": sanitized_disk_inventory(inventory),
        "reportDirectory": str(reports_root),
        "stagedExecutable": str(paths.staged_executable),
        "commands": {
            "run": "python scripts/rust-shared-library-io.py media-run"
        },
    }


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
        "targetRoots": [
            {"role": "ssdBaseline"}
            | {
                key: target.get(key)
                for key in (
                    "diskNumber",
                    "counterKey",
                    "mediaType",
                    "busType",
                    "friendlyName",
                    "mountPath",
                )
            }
        ],
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
    storage.remove_tree(paths.scenario_root)
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
    run.add_argument(
        "--watcher-timeout-seconds",
        type=float,
        default=DEFAULT_WATCHER_TIMEOUT_SECONDS,
    )
    run.add_argument(
        "--watcher-poll-seconds",
        type=float,
        default=DEFAULT_WATCHER_POLL_SECONDS,
    )
    run.add_argument("--allow-non-ssd", action="store_true")
    media_describe = subparsers.add_parser(
        "media-describe",
        help="resolve private existing media roots without scanning their contents",
    )
    media_describe.add_argument(
        "--roots-file", type=Path, default=DEFAULT_MEDIA_ROOTS_FILE
    )
    media_describe.add_argument("--allow-non-hdd", action="store_true")
    media_run = subparsers.add_parser(
        "media-run",
        help="run a read-only initial and no-change scan across existing media roots",
    )
    media_run.add_argument("--roots-file", type=Path, default=DEFAULT_MEDIA_ROOTS_FILE)
    media_run.add_argument("--timeout-seconds", type=float, default=12 * 60 * 60)
    media_run.add_argument("--poll-seconds", type=float, default=2.0)
    media_run.add_argument("--minimum-disks", type=int, default=2)
    media_run.add_argument("--allow-non-hdd", action="store_true")
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
            if (
                args.timeout_seconds <= 0
                or args.poll_seconds <= 0
                or args.watcher_timeout_seconds <= 0
                or args.watcher_poll_seconds <= 0
            ):
                raise RuntimeError("timeouts and poll interval must be positive")
            report_path, report = run_campaign(paths, args)
            result = {
                "status": report["status"],
                "reportPath": str(report_path),
                "reportFingerprint": path_fingerprint(report_path),
            }
        elif args.command == "media-describe":
            result = describe_media_roots(
                paths, args.roots_file, allow_non_hdd=args.allow_non_hdd
            )
        elif args.command == "media-run":
            if (
                args.timeout_seconds <= 0
                or args.poll_seconds <= 0
                or args.minimum_disks < 2
            ):
                raise RuntimeError(
                    "media timeout/poll must be positive and minimum disks at least two"
                )
            report_path, report = run_media_campaign(paths, args)
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
