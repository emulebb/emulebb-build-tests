"""Deterministic baseline and watcher fixtures for Rust shared-library I/O."""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator

from . import rust_shared_library_storage as storage

FIXTURE_SCHEMA = "emulebb.rust-shared-library-fixture.v2"
MIB = 1024 * 1024
LONG_PATH_MIN_RELATIVE_CHARS = 300
LONG_SEGMENT_LENGTH = 60
WATCHER_FILE_COUNT = 1_000
WATCHER_TOTAL_BYTES = 100 * MIB
WATCHER_LONG_PATH_COUNT = 500
MUTATION_COUNTS = (800, 150, 50)


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


def baseline_long_path_count(spec: FixtureSpec = PRODUCTION_SPEC) -> int:
    """Reserve one 1,000-file top-level group in the production fixture."""

    return 1_000 if spec == PRODUCTION_SPEC else 0


def _long_segments(namespace: str) -> tuple[str, ...]:
    segments = []
    for index in range(5):
        prefix = f"{namespace}-{index:02d}-"
        segments.append(
            prefix + (chr(ord("a") + index) * (LONG_SEGMENT_LENGTH - len(prefix)))
        )
    return tuple(segments)


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
    """Map one file to the production tree, including its long-path cohort."""

    if not 0 <= index < spec.file_count:
        raise IndexError(index)
    files_per_top = spec.leaf_directories_per_top * spec.files_per_leaf
    top = index // files_per_top
    leaf = (index % files_per_top) // spec.files_per_leaf
    relative = Path(f"group-{top:03d}") / f"leaf-{leaf:03d}"
    if index >= spec.file_count - baseline_long_path_count(spec):
        relative = relative.joinpath(*_long_segments("baseline-long-segment"))
    relative /= f"file-{index:06d}.bin"
    if index >= spec.file_count - baseline_long_path_count(spec):
        if len(str(relative)) < LONG_PATH_MIN_RELATIVE_CHARS:
            raise AssertionError(
                "long-path fixture layout is shorter than its contract"
            )
    return relative


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

    requested = (
        MUTATION_COUNTS
        if spec == PRODUCTION_SPEC
        else tuple(
            min(count, bucket)
            for count, bucket in zip(
                MUTATION_COUNTS,
                (spec.small_count, spec.medium_count, spec.large_count),
            )
        )
    )
    starts = (0, spec.small_count, spec.small_count + spec.medium_count)
    buckets = (spec.small_count, spec.medium_count, spec.large_count)
    selected: list[int] = []
    for start, bucket_count, requested_count in zip(starts, buckets, requested):
        if requested_count:
            selected.extend(
                start + (offset * bucket_count // requested_count)
                for offset in range(requested_count)
            )
    return tuple(selected)


def expected_mutation_bytes(spec: FixtureSpec = PRODUCTION_SPEC) -> int:
    return sum(file_size_for_index(index, spec) for index in mutation_indices(spec))


def deterministic_payload(
    index: int, size: int, *, generation: str = "base-v2"
) -> bytes:
    """Generate reproducible, non-compressibility-dependent file content."""

    seed = f"emulebb-rust-shared-library-io:{generation}:{index}".encode("ascii")
    return hashlib.shake_256(seed).digest(size)


def write_payload(path: Path, payload: bytes, *, atomic: bool = True) -> None:
    storage.make_directories(path.parent)
    if not atomic:
        with storage.open_binary(path, "wb") as handle:
            handle.write(payload)
        return
    temporary = path.with_name(path.name + ".tmp")
    with storage.open_binary(temporary, "wb") as handle:
        handle.write(payload)
    storage.replace(temporary, path)


def validate_fixture(
    root: Path, spec: FixtureSpec = PRODUCTION_SPEC
) -> dict[str, object]:
    """Fully inventory a fixture without reading payload bytes."""

    expected_paths = {
        relative_file_for_index(index, spec): file_size_for_index(index, spec)
        for index in range(spec.file_count)
    }
    expected_set = set(expected_paths)
    seen: set[Path] = set()
    total_bytes = 0
    empty_directory_count = 0
    unexpected_size_count = 0
    long_path_count = 0
    path_lengths: list[int] = []
    for directory, subdirs, files in storage.walk(root):
        if not subdirs and not files:
            empty_directory_count += 1
        for name in files:
            path = directory / name
            relative = path.relative_to(root)
            size = storage.stat(path).st_size
            total_bytes += size
            seen.add(relative)
            if expected_paths.get(relative) != size:
                unexpected_size_count += 1
            length = storage.absolute_path_length(path)
            path_lengths.append(length)
            if len(str(relative)) >= LONG_PATH_MIN_RELATIVE_CHARS:
                long_path_count += 1
    missing_count = len(expected_set - seen)
    unexpected_path_count = len(seen - expected_set)
    expected_long = baseline_long_path_count(spec)
    return {
        "ok": (
            len(seen) == spec.file_count
            and total_bytes == spec.total_bytes
            and empty_directory_count == 0
            and unexpected_size_count == 0
            and missing_count == 0
            and unexpected_path_count == 0
            and long_path_count == expected_long
        ),
        "fileCount": len(seen),
        "totalBytes": total_bytes,
        "longPathFileCount": long_path_count,
        "minimumAbsolutePathLength": min(path_lengths, default=0),
        "maximumAbsolutePathLength": max(path_lengths, default=0),
        "emptyDirectoryCount": empty_directory_count,
        "unexpectedSizeCount": unexpected_size_count,
        "missingCount": missing_count,
        "unexpectedPathCount": unexpected_path_count,
    }


def watcher_size_for_index(index: int) -> int:
    if not 0 <= index < WATCHER_FILE_COUNT:
        raise IndexError(index)
    half_index = index % (WATCHER_FILE_COUNT // 2)
    if half_index < 400:
        return 16 * 1024
    if half_index < 475:
        return 256 * 1024
    return MIB


def watcher_relative_file(index: int, *, renamed: bool = False) -> Path:
    """Return one deterministic live-watcher path with a 50/50 path-class split."""

    if not 0 <= index < WATCHER_FILE_COUNT:
        raise IndexError(index)
    path_class = (
        "long" if index >= WATCHER_FILE_COUNT - WATCHER_LONG_PATH_COUNT else "normal"
    )
    state = "renamed" if renamed else "created"
    relative = Path("_watcher-probe-v2") / state / path_class
    if path_class == "long":
        relative = relative.joinpath(*_long_segments("watcher-long-segment"))
    relative /= f"watch-probe-{index:04d}.bin"
    if path_class == "long" and len(str(relative)) < LONG_PATH_MIN_RELATIVE_CHARS:
        raise AssertionError("watcher long-path layout is shorter than its contract")
    return relative


def watcher_cohort_summary() -> dict[str, int]:
    total_bytes = sum(
        watcher_size_for_index(index) for index in range(WATCHER_FILE_COUNT)
    )
    return {
        "fileCount": WATCHER_FILE_COUNT,
        "totalBytes": total_bytes,
        "normalPathFileCount": WATCHER_FILE_COUNT - WATCHER_LONG_PATH_COUNT,
        "longPathFileCount": WATCHER_LONG_PATH_COUNT,
    }


def stage_watcher_cohort(staging_root: Path) -> dict[str, int]:
    """Create the cohort outside the watched root so temporary files stay invisible."""

    storage.remove_tree(staging_root)
    for index in range(WATCHER_FILE_COUNT):
        path = staging_root / watcher_relative_file(index)
        write_payload(
            path,
            deterministic_payload(
                index, watcher_size_for_index(index), generation="watcher-create-v2"
            ),
        )
    return watcher_cohort_summary()


def install_watcher_cohort(staging_root: Path, fixture_root: Path) -> dict[str, int]:
    for index in range(WATCHER_FILE_COUNT):
        storage.rename(
            staging_root / watcher_relative_file(index),
            fixture_root / watcher_relative_file(index),
        )
    storage.remove_tree(staging_root)
    return watcher_cohort_summary()


def modify_watcher_cohort(fixture_root: Path) -> dict[str, int]:
    """Overwrite in place so the watcher receives data-modification events."""

    for index in range(WATCHER_FILE_COUNT):
        path = fixture_root / watcher_relative_file(index)
        old_mtime_ns = storage.stat(path).st_mtime_ns
        write_payload(
            path,
            deterministic_payload(
                index, watcher_size_for_index(index), generation="watcher-modify-v2"
            ),
            atomic=False,
        )
        storage.set_mtime(path, max(time.time_ns(), old_mtime_ns + 2_000_000_000))
    return watcher_cohort_summary()


def rename_watcher_cohort(fixture_root: Path) -> dict[str, int]:
    for index in range(WATCHER_FILE_COUNT):
        storage.rename(
            fixture_root / watcher_relative_file(index),
            fixture_root / watcher_relative_file(index, renamed=True),
        )
    return watcher_cohort_summary()


def delete_watcher_cohort(fixture_root: Path) -> dict[str, int]:
    for index in range(WATCHER_FILE_COUNT):
        storage.unlink(fixture_root / watcher_relative_file(index, renamed=True))
    storage.remove_tree(fixture_root / "_watcher-probe-v2")
    return watcher_cohort_summary()


def mutate_fixture(root: Path, spec: FixtureSpec = PRODUCTION_SPEC) -> dict[str, int]:
    total_bytes = 0
    for index in mutation_indices(spec):
        path = root / relative_file_for_index(index, spec)
        size = file_size_for_index(index, spec)
        old_mtime_ns = storage.stat(path).st_mtime_ns
        write_payload(
            path, deterministic_payload(index, size, generation="mutation-v2")
        )
        storage.set_mtime(path, max(time.time_ns(), old_mtime_ns + 2_000_000_000))
        total_bytes += size
    return {"fileCount": len(mutation_indices(spec)), "totalBytes": total_bytes}


def restore_fixture_baseline(
    root: Path, spec: FixtureSpec = PRODUCTION_SPEC
) -> dict[str, int]:
    total_bytes = 0
    for index in mutation_indices(spec):
        path = root / relative_file_for_index(index, spec)
        size = file_size_for_index(index, spec)
        write_payload(path, deterministic_payload(index, size))
        total_bytes += size
    return {"fileCount": len(mutation_indices(spec)), "totalBytes": total_bytes}
