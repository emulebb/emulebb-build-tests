"""Validated storage policy for persisted diagnostic soak artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping

SCHEMA = "emulebb-build-tests.soak-storage-policy.v1"
REQUIRED_STREAMS = ("controller_output", "daemon_output")
ACTIVE_SEGMENT_INSTANCES = {
    "controller_output": 4,
    "daemon_output": 1,
}
_POLICY_KEYS = {
    "schema",
    "max_total_bytes",
    "max_age_seconds",
    "minimum_free_bytes",
    "bundle_interval_seconds",
    "streams",
}
_STREAM_KEYS = {"max_segment_bytes", "retained_segments"}


@dataclass(frozen=True)
class ArtifactStreamPolicy:
    """Rotation limits for one non-protocol artifact stream."""

    max_segment_bytes: int
    retained_segments: int


@dataclass(frozen=True)
class SoakStoragePolicy:
    """Aggregate and per-stream limits for one persisted soak evidence store."""

    max_total_bytes: int
    max_age_seconds: int
    minimum_free_bytes: int
    bundle_interval_seconds: int
    streams: Mapping[str, ArtifactStreamPolicy]

    def stream(self, name: str) -> ArtifactStreamPolicy:
        """Returns one required stream policy by its stable name."""

        try:
            return self.streams[name]
        except KeyError as exc:
            raise RuntimeError(f"Unknown soak storage stream: {name}") from exc


@dataclass(frozen=True)
class ArtifactFile:
    """One immutable artifact candidate below the bounded store root."""

    path: Path
    relative_path: Path
    size_bytes: int
    modified_ns: int


@dataclass(frozen=True)
class ArtifactInventory:
    """Deterministic whole-file inventory for one bounded store root."""

    files: tuple[ArtifactFile, ...]
    total_bytes: int


@dataclass(frozen=True)
class DiskSpaceSnapshot:
    """Capacity information for the nearest existing artifact-store ancestor."""

    measured_path: Path
    total_bytes: int
    used_bytes: int
    free_bytes: int


@dataclass(frozen=True)
class PlannedDeletion:
    """One whole immutable artifact selected for a single pruning trigger."""

    artifact: ArtifactFile
    reason: str


@dataclass(frozen=True)
class StoragePrunePlan:
    """Deterministic projection for enforcing one storage policy."""

    inventory: ArtifactInventory
    disk_space: DiskSpaceSnapshot
    reserved_bytes: int
    deletions: tuple[PlannedDeletion, ...]
    protected_files: tuple[ArtifactFile, ...]
    projected_total_bytes: int
    projected_free_bytes: int
    triggered_constraints: tuple[str, ...]
    unresolved_constraints: tuple[str, ...]

    @property
    def within_limits(self) -> bool:
        """Returns whether the projected store satisfies every hard limit."""

        return not self.unresolved_constraints


@dataclass(frozen=True)
class StorageEnforcementResult:
    """Applied whole-file deletions and any fail-closed removal errors."""

    plan: StoragePrunePlan
    verification: StoragePrunePlan
    deleted_paths: tuple[Path, ...]
    failures: tuple[str, ...]

    @property
    def within_limits(self) -> bool:
        """Returns whether planning succeeded and every deletion was applied."""

        return (
            self.plan.within_limits
            and not self.failures
            and self.verification.within_limits
            and not self.verification.deletions
        )


class BoundedArtifactStore:
    """Plans and applies whole-artifact retention below one owned root."""

    def __init__(
        self,
        root: Path,
        policy: SoakStoragePolicy,
        *,
        inventory: Callable[[Path], ArtifactInventory] | None = None,
        disk_space: Callable[[Path], DiskSpaceSnapshot] | None = None,
        remove_file: Callable[[Path], None] | None = None,
    ) -> None:
        self.root = root.resolve()
        self.policy = policy
        self._inventory = inventory or inventory_artifacts
        self._disk_space = disk_space or disk_space_snapshot
        self._remove_file = remove_file or _unlink_artifact

    def plan(
        self,
        *,
        active_campaign: Path | None = None,
        pinned_paths: Iterable[Path] = (),
        reserved_bytes: int = 0,
        now_ns: int | None = None,
    ) -> StoragePrunePlan:
        """Builds one oldest-first plan including projected future allocation."""

        if (
            isinstance(reserved_bytes, bool)
            or not isinstance(reserved_bytes, int)
            or reserved_bytes < 0
        ):
            raise ValueError("reserved_bytes must be a non-negative integer.")

        inventory = self._inventory(self.root)
        disk_space = self._disk_space(self.root)
        protected_roots = self._protected_roots(active_campaign, pinned_paths)
        protected_files: list[ArtifactFile] = []
        candidates: list[ArtifactFile] = []
        seen_paths: set[Path] = set()
        for artifact in inventory.files:
            artifact_path = artifact.path.resolve()
            if artifact_path in seen_paths:
                raise RuntimeError(
                    f"Soak artifact inventory contains a duplicate path: {artifact_path}"
                )
            seen_paths.add(artifact_path)
            if not _path_is_relative_to(artifact_path, self.root):
                raise RuntimeError(
                    f"Soak artifact inventory escaped its store root: {artifact_path}"
                )
            if any(
                _path_is_relative_to(artifact_path, protected)
                for protected in protected_roots
            ):
                protected_files.append(artifact)
            else:
                candidates.append(artifact)

        candidates.sort(
            key=lambda item: (
                item.modified_ns,
                item.relative_path.as_posix().casefold(),
            )
        )
        selected: list[PlannedDeletion] = []
        selected_paths: set[Path] = set()
        triggered: list[str] = []
        projected_total = inventory.total_bytes + reserved_bytes
        projected_free = disk_space.free_bytes - reserved_bytes

        def select(artifact: ArtifactFile, reason: str) -> None:
            nonlocal projected_free, projected_total
            if artifact.path in selected_paths:
                return
            selected_paths.add(artifact.path)
            selected.append(PlannedDeletion(artifact=artifact, reason=reason))
            projected_total -= artifact.size_bytes
            projected_free = min(
                disk_space.total_bytes, projected_free + artifact.size_bytes
            )

        current_ns = time.time_ns() if now_ns is None else now_ns
        oldest_allowed_ns = current_ns - self.policy.max_age_seconds * 1_000_000_000
        expired = [
            artifact
            for artifact in candidates
            if artifact.modified_ns < oldest_allowed_ns
        ]
        if expired:
            triggered.append("max_age_seconds")
            for artifact in expired:
                select(artifact, "max_age_seconds")

        remaining = [
            artifact for artifact in candidates if artifact.path not in selected_paths
        ]
        if projected_total > self.policy.max_total_bytes:
            triggered.append("max_total_bytes")
            while projected_total > self.policy.max_total_bytes and remaining:
                select(remaining.pop(0), "max_total_bytes")

        remaining = [
            artifact for artifact in remaining if artifact.path not in selected_paths
        ]
        if projected_free < self.policy.minimum_free_bytes:
            triggered.append("minimum_free_bytes")
            while projected_free < self.policy.minimum_free_bytes and remaining:
                select(remaining.pop(0), "minimum_free_bytes")

        unresolved: list[str] = []
        if projected_total > self.policy.max_total_bytes:
            unresolved.append("max_total_bytes")
        if projected_free < self.policy.minimum_free_bytes:
            unresolved.append("minimum_free_bytes")

        return StoragePrunePlan(
            inventory=inventory,
            disk_space=disk_space,
            reserved_bytes=reserved_bytes,
            deletions=tuple(selected),
            protected_files=tuple(protected_files),
            projected_total_bytes=projected_total,
            projected_free_bytes=projected_free,
            triggered_constraints=tuple(triggered),
            unresolved_constraints=tuple(unresolved),
        )

    def enforce(
        self,
        *,
        active_campaign: Path | None = None,
        pinned_paths: Iterable[Path] = (),
        reserved_bytes: int = 0,
        now_ns: int | None = None,
    ) -> StorageEnforcementResult:
        """Deletes only whole planned artifacts and reports every failure."""

        plan = self.plan(
            active_campaign=active_campaign,
            pinned_paths=pinned_paths,
            reserved_bytes=reserved_bytes,
            now_ns=now_ns,
        )
        deleted_paths: list[Path] = []
        failures: list[str] = []
        for deletion in plan.deletions:
            try:
                self._remove_file(deletion.artifact.path)
            except OSError as exc:
                failures.append(
                    f"{deletion.artifact.relative_path.as_posix()}: {type(exc).__name__}: {exc}"
                )
            else:
                deleted_paths.append(deletion.artifact.path)
        verification = self.plan(
            active_campaign=active_campaign,
            pinned_paths=pinned_paths,
            reserved_bytes=reserved_bytes,
            now_ns=now_ns,
        )
        return StorageEnforcementResult(
            plan=plan,
            verification=verification,
            deleted_paths=tuple(deleted_paths),
            failures=tuple(failures),
        )

    def _protected_roots(
        self, active_campaign: Path | None, pinned_paths: Iterable[Path]
    ) -> tuple[Path, ...]:
        protected = list(pinned_paths)
        if active_campaign is not None:
            protected.append(active_campaign)
        roots: list[Path] = []
        for path in protected:
            resolved = path.resolve()
            if not _path_is_relative_to(resolved, self.root):
                raise RuntimeError(
                    f"Protected soak artifact path escaped its store root: {resolved}"
                )
            roots.append(resolved)
        return tuple(roots)


def storage_policy_payload(policy: SoakStoragePolicy) -> dict[str, Any]:
    """Returns the canonical strict payload accepted by the policy parser."""

    return {
        "schema": SCHEMA,
        "max_total_bytes": policy.max_total_bytes,
        "max_age_seconds": policy.max_age_seconds,
        "minimum_free_bytes": policy.minimum_free_bytes,
        "bundle_interval_seconds": policy.bundle_interval_seconds,
        "streams": {
            name: {
                "max_segment_bytes": policy.stream(name).max_segment_bytes,
                "retained_segments": policy.stream(name).retained_segments,
            }
            for name in REQUIRED_STREAMS
        },
    }


def storage_policy_sha256(policy: SoakStoragePolicy) -> str:
    """Returns a deterministic SHA-256 for one canonical policy payload."""

    encoded = json.dumps(
        storage_policy_payload(policy),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_soak_storage_policy(payload: object) -> SoakStoragePolicy:
    """Validates one strict ignored-input storage-policy object."""

    if not isinstance(payload, dict):
        raise RuntimeError("Live-wire inputs field 'soak_storage' must be an object.")
    _require_exact_keys(payload, _POLICY_KEYS, context="soak_storage")
    if payload.get("schema") != SCHEMA:
        raise RuntimeError(f"soak_storage.schema must be {SCHEMA!r}.")

    max_total_bytes = _positive_integer(
        payload, "max_total_bytes", context="soak_storage"
    )
    max_age_seconds = _positive_integer(
        payload, "max_age_seconds", context="soak_storage"
    )
    minimum_free_bytes = _positive_integer(
        payload, "minimum_free_bytes", context="soak_storage"
    )
    bundle_interval_seconds = _positive_integer(
        payload, "bundle_interval_seconds", context="soak_storage"
    )

    streams_payload = payload.get("streams")
    if not isinstance(streams_payload, dict):
        raise RuntimeError("soak_storage.streams must be an object.")
    _require_exact_keys(
        streams_payload, set(REQUIRED_STREAMS), context="soak_storage.streams"
    )

    streams: dict[str, ArtifactStreamPolicy] = {}
    active_segment_budget = 0
    for name in REQUIRED_STREAMS:
        stream_payload = streams_payload[name]
        context = f"soak_storage.streams.{name}"
        if not isinstance(stream_payload, dict):
            raise RuntimeError(f"{context} must be an object.")
        _require_exact_keys(stream_payload, _STREAM_KEYS, context=context)
        max_segment_bytes = _positive_integer(
            stream_payload, "max_segment_bytes", context=context
        )
        retained_segments = _positive_integer(
            stream_payload, "retained_segments", context=context
        )
        if max_segment_bytes > max_total_bytes:
            raise RuntimeError(
                f"{context}.max_segment_bytes must not exceed soak_storage.max_total_bytes."
            )
        active_segment_budget += max_segment_bytes * ACTIVE_SEGMENT_INSTANCES[name]
        streams[name] = ArtifactStreamPolicy(
            max_segment_bytes=max_segment_bytes,
            retained_segments=retained_segments,
        )

    if active_segment_budget > max_total_bytes:
        raise RuntimeError(
            "soak_storage.max_total_bytes must cover every active required-stream instance."
        )

    return SoakStoragePolicy(
        max_total_bytes=max_total_bytes,
        max_age_seconds=max_age_seconds,
        minimum_free_bytes=minimum_free_bytes,
        bundle_interval_seconds=bundle_interval_seconds,
        streams=MappingProxyType(streams),
    )


def inventory_artifacts(root: Path) -> ArtifactInventory:
    """Inventories regular files without following directory symlinks."""

    resolved_root = root.resolve()
    if not resolved_root.exists():
        return ArtifactInventory(files=(), total_bytes=0)
    if not resolved_root.is_dir():
        raise RuntimeError(
            f"Soak artifact store root is not a directory: {resolved_root}"
        )

    files: list[ArtifactFile] = []
    for current_root, directory_names, file_names in os.walk(
        resolved_root, followlinks=False
    ):
        current = Path(current_root)
        directory_names[:] = sorted(
            (name for name in directory_names if not (current / name).is_symlink()),
            key=str.casefold,
        )
        for name in sorted(file_names, key=str.casefold):
            path = current / name
            if path.is_symlink():
                raise RuntimeError(
                    f"Soak artifact store contains a file symlink: {path}"
                )
            stat = path.stat()
            if not path.is_file():
                continue
            files.append(
                ArtifactFile(
                    path=path.resolve(),
                    relative_path=path.relative_to(resolved_root),
                    size_bytes=stat.st_size,
                    modified_ns=stat.st_mtime_ns,
                )
            )

    files.sort(
        key=lambda item: (item.modified_ns, item.relative_path.as_posix().casefold())
    )
    return ArtifactInventory(
        files=tuple(files), total_bytes=sum(item.size_bytes for item in files)
    )


def disk_space_snapshot(
    path: Path,
    *,
    disk_usage: Callable[[Path], tuple[int, int, int]] = shutil.disk_usage,
) -> DiskSpaceSnapshot:
    """Measures capacity at the nearest existing ancestor of one store path."""

    measured_path = nearest_existing_ancestor(path)
    total_bytes, used_bytes, free_bytes = disk_usage(measured_path)
    values = (total_bytes, used_bytes, free_bytes)
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in values
    ):
        raise RuntimeError(
            f"Disk-usage provider returned invalid capacity values for {measured_path}."
        )
    if used_bytes + free_bytes > total_bytes:
        raise RuntimeError(
            f"Disk-usage provider returned inconsistent capacity values for {measured_path}."
        )
    return DiskSpaceSnapshot(
        measured_path=measured_path,
        total_bytes=total_bytes,
        used_bytes=used_bytes,
        free_bytes=free_bytes,
    )


def nearest_existing_ancestor(path: Path) -> Path:
    """Returns the nearest existing path used for a future store's disk check."""

    candidate = path.resolve()
    while not candidate.exists():
        parent = candidate.parent
        if parent == candidate:
            raise RuntimeError(
                f"No existing ancestor is available for soak storage path: {path}"
            )
        candidate = parent
    return candidate


def _path_is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _unlink_artifact(path: Path) -> None:
    path.unlink()


def _positive_integer(payload: dict[str, Any], key: str, *, context: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RuntimeError(f"{context}.{key} must be a positive integer.")
    return value


def _require_exact_keys(
    payload: dict[str, Any], expected: set[str], *, context: str
) -> None:
    actual = set(payload)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        raise RuntimeError(
            f"{context} is missing required fields: {', '.join(missing)}."
        )
    if unknown:
        raise RuntimeError(f"{context} contains unknown fields: {', '.join(unknown)}.")
