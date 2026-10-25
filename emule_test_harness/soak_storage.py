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

SCHEMA = "emulebb-build-tests.soak-storage-policy.v4"
REQUIRED_STREAMS = (
    "controller_output",
    "daemon_output",
    "diagnostic_bundles",
    "diagnostic_segments",
)
REQUIRED_STREAM_INSTANCES = {
    "controller_output": 4,
    "daemon_output": 1,
    "diagnostic_bundles": 1,
    "diagnostic_segments": 2,
}
_POLICY_KEYS = {
    "schema",
    "max_total_bytes",
    "max_age_seconds",
    "minimum_free_bytes",
    "bundle_interval_seconds",
    "rust_diagnostics",
    "streams",
}
_STREAM_KEYS = {"max_segment_bytes", "retained_segments"}
_RUST_DIAGNOSTIC_KEYS = {
    "max_segment_bytes",
    "max_segment_seconds",
    "retained_segments",
    "max_total_bytes",
    "max_retained_seconds",
    "minimum_free_bytes",
}
_MEBIBYTE = 1024 * 1024
_RUST_MAX_SEGMENT_BYTES = 1024 * _MEBIBYTE
_RUST_MAX_SEGMENT_SECONDS = 24 * 60 * 60
_RUST_MAX_RETAINED_SEGMENTS = 128
_RUST_MAX_TOTAL_BYTES = 16 * 1024 * 1024 * 1024 * 1024
_RUST_MAX_RETAINED_SECONDS = 365 * 24 * 60 * 60


@dataclass(frozen=True)
class ArtifactStreamPolicy:
    """Rotation limits for one non-protocol artifact stream."""

    max_segment_bytes: int
    retained_segments: int


@dataclass(frozen=True)
class RustDiagnosticWriterPolicy:
    """Hard limits for the Rust profile-resident diagnostic event ring."""

    max_segment_bytes: int
    max_segment_seconds: int
    retained_segments: int
    max_total_bytes: int
    max_retained_seconds: int
    minimum_free_bytes: int


@dataclass(frozen=True)
class SoakStoragePolicy:
    """Aggregate and per-stream limits for one persisted soak evidence store."""

    max_total_bytes: int
    max_age_seconds: int
    minimum_free_bytes: int
    bundle_interval_seconds: int
    rust_diagnostics: RustDiagnosticWriterPolicy
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


@dataclass(frozen=True)
class PersistedArtifact:
    """One atomically persisted artifact in a bounded immutable stream."""

    path: Path
    byte_count: int
    sha256: str
    deleted_paths: tuple[Path, ...]
    retained_count: int
    retained_bytes: int


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


def persist_bounded_json_artifact(
    *,
    store: BoundedArtifactStore,
    active_campaign: Path,
    directory: Path,
    stream_name: str,
    stem: str,
    payload: object,
    now_ns: int | None = None,
) -> PersistedArtifact:
    """Atomically writes one JSON artifact while enforcing stream and store bounds."""

    if not stem or any(
        not (character.isalnum() or character == "-") for character in stem
    ):
        raise ValueError("stem must contain only ASCII letters, digits, and hyphens.")
    if not stem.isascii():
        raise ValueError("stem must contain only ASCII letters, digits, and hyphens.")
    timestamp_ns = time.time_ns() if now_ns is None else now_ns
    if (
        isinstance(timestamp_ns, bool)
        or not isinstance(timestamp_ns, int)
        or timestamp_ns < 0
    ):
        raise ValueError("now_ns must be a non-negative integer.")

    resolved_campaign = active_campaign.resolve()
    resolved_directory = directory.resolve()
    if not _path_is_relative_to(resolved_campaign, store.root):
        raise RuntimeError(
            f"Active campaign escaped its soak artifact store: {resolved_campaign}"
        )
    if not _path_is_relative_to(resolved_directory, resolved_campaign):
        raise RuntimeError(
            f"Bounded JSON artifact directory escaped its active campaign: {resolved_directory}"
        )

    policy = store.policy.stream(stream_name)
    encoded = (
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    if len(encoded) > policy.max_segment_bytes:
        raise RuntimeError(
            f"{stream_name} artifact requires {len(encoded)} bytes, exceeding its "
            f"{policy.max_segment_bytes}-byte limit."
        )

    resolved_directory.mkdir(parents=True, exist_ok=True)
    artifacts = _json_stream_artifacts(resolved_directory, stem)
    deleted_paths: list[Path] = []
    while len(artifacts) >= policy.retained_segments:
        oldest = artifacts.pop(0)
        oldest.unlink()
        deleted_paths.append(oldest)

    reservation = store.enforce(
        active_campaign=resolved_campaign,
        reserved_bytes=len(encoded),
        now_ns=timestamp_ns,
    )
    if not reservation.within_limits:
        raise RuntimeError(
            "Bounded JSON artifact reservation failed: "
            f"failures={reservation.failures!r}, "
            f"constraints={reservation.verification.unresolved_constraints!r}."
        )

    path = resolved_directory / f"{stem}-{timestamp_ns:020d}.json"
    temporary = path.with_suffix(path.suffix + ".tmp")
    if path.exists() or temporary.exists():
        raise RuntimeError(
            f"Bounded JSON artifact identity already exists: {path.name}"
        )
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()

    verification = store.enforce(
        active_campaign=resolved_campaign,
        now_ns=timestamp_ns,
    )
    if not verification.within_limits:
        raise RuntimeError(
            "Bounded JSON artifact persistence violated the aggregate policy: "
            f"failures={verification.failures!r}, "
            f"constraints={verification.verification.unresolved_constraints!r}."
        )

    retained = _json_stream_artifacts(resolved_directory, stem)
    if len(retained) > policy.retained_segments:
        raise RuntimeError(
            f"{stream_name} retention exceeded its configured file count."
        )
    return PersistedArtifact(
        path=path,
        byte_count=len(encoded),
        sha256=hashlib.sha256(encoded).hexdigest(),
        deleted_paths=tuple(deleted_paths),
        retained_count=len(retained),
        retained_bytes=sum(item.stat().st_size for item in retained),
    )


def persist_bounded_file_artifact(
    *,
    store: BoundedArtifactStore,
    active_campaign: Path,
    directory: Path,
    stream_name: str,
    source: Path,
    artifact_name: str,
    now_ns: int | None = None,
) -> PersistedArtifact:
    """Atomically copies and verifies one immutable file into a bounded stream."""

    if (
        not artifact_name
        or Path(artifact_name).name != artifact_name
        or artifact_name in {".", ".."}
        or not artifact_name.isascii()
        or any(
            not (character.isalnum() or character in {".", "_", "-"})
            for character in artifact_name
        )
    ):
        raise ValueError(
            "artifact_name must be one safe ASCII filename using letters, digits, dots, "
            "underscores, and hyphens."
        )
    timestamp_ns = time.time_ns() if now_ns is None else now_ns
    if (
        isinstance(timestamp_ns, bool)
        or not isinstance(timestamp_ns, int)
        or timestamp_ns < 0
    ):
        raise ValueError("now_ns must be a non-negative integer.")

    if source.is_symlink():
        raise RuntimeError(
            f"Bounded file artifact source must not be a symlink: {source}"
        )
    resolved_source = source.resolve()
    if not resolved_source.is_file():
        raise RuntimeError(
            f"Bounded file artifact source is not a file: {resolved_source}"
        )
    if resolved_source.name != artifact_name:
        raise RuntimeError(
            "Bounded file artifact name must preserve the source filename: "
            f"{resolved_source.name!r}."
        )

    resolved_campaign = active_campaign.resolve()
    resolved_directory = directory.resolve()
    if not _path_is_relative_to(resolved_campaign, store.root):
        raise RuntimeError(
            f"Active campaign escaped its soak artifact store: {resolved_campaign}"
        )
    if not _path_is_relative_to(resolved_directory, resolved_campaign):
        raise RuntimeError(
            f"Bounded file artifact directory escaped its active campaign: {resolved_directory}"
        )

    policy = store.policy.stream(stream_name)
    source_stat = resolved_source.stat()
    if source_stat.st_size > policy.max_segment_bytes:
        raise RuntimeError(
            f"{stream_name} artifact requires {source_stat.st_size} bytes, exceeding its "
            f"{policy.max_segment_bytes}-byte limit."
        )

    reservation = store.enforce(
        active_campaign=resolved_campaign,
        reserved_bytes=source_stat.st_size,
        now_ns=timestamp_ns,
    )
    if not reservation.within_limits:
        raise RuntimeError(
            "Bounded file artifact reservation failed: "
            f"failures={reservation.failures!r}, "
            f"constraints={reservation.verification.unresolved_constraints!r}."
        )

    resolved_directory.mkdir(parents=True, exist_ok=True)
    path = resolved_directory / artifact_name
    temporary = path.with_suffix(path.suffix + ".tmp")
    if path.exists() or temporary.exists():
        raise RuntimeError(
            f"Bounded file artifact identity already exists: {path.name}"
        )

    digest = hashlib.sha256()
    try:
        with (
            resolved_source.open("rb") as source_handle,
            temporary.open("xb") as target_handle,
        ):
            while chunk := source_handle.read(1024 * 1024):
                target_handle.write(chunk)
                digest.update(chunk)
            target_handle.flush()
            os.fsync(target_handle.fileno())

        final_source_stat = resolved_source.stat()
        if (
            final_source_stat.st_size != source_stat.st_size
            or final_source_stat.st_mtime_ns != source_stat.st_mtime_ns
        ):
            raise RuntimeError(
                f"Bounded file artifact source changed during copy: {resolved_source}"
            )
        sha256 = digest.hexdigest()
        if _sha256_file(resolved_source) != sha256:
            raise RuntimeError(
                f"Bounded file artifact source hash changed during copy: {resolved_source}"
            )
        if temporary.stat().st_size != source_stat.st_size:
            raise RuntimeError(
                f"Bounded file artifact copy size mismatch: {resolved_source}"
            )
        if _sha256_file(temporary) != sha256:
            raise RuntimeError(
                f"Bounded file artifact copy hash mismatch: {resolved_source}"
            )

        artifacts = _file_stream_artifacts(resolved_directory)
        deleted_paths: list[Path] = []
        while len(artifacts) >= policy.retained_segments:
            oldest = artifacts.pop(0)
            oldest.unlink()
            deleted_paths.append(oldest)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()

    if path.stat().st_size != source_stat.st_size or _sha256_file(path) != sha256:
        path.unlink(missing_ok=True)
        raise RuntimeError(f"Bounded file artifact verification failed: {path}")

    verification = store.enforce(
        active_campaign=resolved_campaign,
        now_ns=timestamp_ns,
    )
    if not verification.within_limits:
        raise RuntimeError(
            "Bounded file artifact persistence violated the aggregate policy: "
            f"failures={verification.failures!r}, "
            f"constraints={verification.verification.unresolved_constraints!r}."
        )

    retained = _file_stream_artifacts(resolved_directory)
    if len(retained) > policy.retained_segments:
        raise RuntimeError(
            f"{stream_name} retention exceeded its configured file count."
        )
    return PersistedArtifact(
        path=path,
        byte_count=source_stat.st_size,
        sha256=sha256,
        deleted_paths=tuple(deleted_paths),
        retained_count=len(retained),
        retained_bytes=sum(item.stat().st_size for item in retained),
    )


def _json_stream_artifacts(directory: Path, stem: str) -> list[Path]:
    artifacts: list[tuple[int, str, Path]] = []
    for path in directory.glob(f"{stem}-*.json"):
        if path.is_symlink():
            raise RuntimeError(
                f"Bounded JSON artifact stream contains a symlink: {path}"
            )
        if not path.is_file():
            continue
        stat = path.stat()
        artifacts.append((stat.st_mtime_ns, path.name.casefold(), path.resolve()))
    artifacts.sort()
    return [path for _, _, path in artifacts]


def _file_stream_artifacts(directory: Path) -> list[Path]:
    artifacts: list[tuple[int, str, Path]] = []
    for path in directory.iterdir():
        if path.name.endswith(".tmp"):
            continue
        if path.is_symlink():
            raise RuntimeError(
                f"Bounded file artifact stream contains a symlink: {path}"
            )
        if not path.is_file():
            continue
        stat = path.stat()
        artifacts.append((stat.st_mtime_ns, path.name.casefold(), path.resolve()))
    artifacts.sort()
    return [path for _, _, path in artifacts]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def storage_policy_payload(policy: SoakStoragePolicy) -> dict[str, Any]:
    """Returns the canonical strict payload accepted by the policy parser."""

    return {
        "schema": SCHEMA,
        "max_total_bytes": policy.max_total_bytes,
        "max_age_seconds": policy.max_age_seconds,
        "minimum_free_bytes": policy.minimum_free_bytes,
        "bundle_interval_seconds": policy.bundle_interval_seconds,
        "rust_diagnostics": rust_diagnostic_writer_policy_payload(
            policy.rust_diagnostics
        ),
        "streams": {
            name: {
                "max_segment_bytes": policy.stream(name).max_segment_bytes,
                "retained_segments": policy.stream(name).retained_segments,
            }
            for name in REQUIRED_STREAMS
        },
    }


def rust_diagnostic_writer_policy_payload(
    policy: RustDiagnosticWriterPolicy,
) -> dict[str, int]:
    """Returns the exact Rust diagnostic-writer configuration payload."""

    return {
        "max_segment_bytes": policy.max_segment_bytes,
        "max_segment_seconds": policy.max_segment_seconds,
        "retained_segments": policy.retained_segments,
        "max_total_bytes": policy.max_total_bytes,
        "max_retained_seconds": policy.max_retained_seconds,
        "minimum_free_bytes": policy.minimum_free_bytes,
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


def required_stream_capacity_bytes(policy: SoakStoragePolicy) -> int:
    """Returns maximum retained bytes for every required stream instance."""

    return sum(
        policy.stream(name).max_segment_bytes
        * policy.stream(name).retained_segments
        * REQUIRED_STREAM_INSTANCES[name]
        for name in REQUIRED_STREAMS
    )


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

    rust_payload = payload.get("rust_diagnostics")
    if not isinstance(rust_payload, dict):
        raise RuntimeError("soak_storage.rust_diagnostics must be an object.")
    _require_exact_keys(
        rust_payload,
        _RUST_DIAGNOSTIC_KEYS,
        context="soak_storage.rust_diagnostics",
    )
    rust_diagnostics = RustDiagnosticWriterPolicy(
        max_segment_bytes=_bounded_integer(
            rust_payload,
            "max_segment_bytes",
            context="soak_storage.rust_diagnostics",
            minimum=_MEBIBYTE,
            maximum=_RUST_MAX_SEGMENT_BYTES,
        ),
        max_segment_seconds=_bounded_integer(
            rust_payload,
            "max_segment_seconds",
            context="soak_storage.rust_diagnostics",
            minimum=60,
            maximum=_RUST_MAX_SEGMENT_SECONDS,
        ),
        retained_segments=_bounded_integer(
            rust_payload,
            "retained_segments",
            context="soak_storage.rust_diagnostics",
            minimum=2,
            maximum=_RUST_MAX_RETAINED_SEGMENTS,
        ),
        max_total_bytes=_bounded_integer(
            rust_payload,
            "max_total_bytes",
            context="soak_storage.rust_diagnostics",
            minimum=_MEBIBYTE,
            maximum=_RUST_MAX_TOTAL_BYTES,
        ),
        max_retained_seconds=_bounded_integer(
            rust_payload,
            "max_retained_seconds",
            context="soak_storage.rust_diagnostics",
            minimum=60,
            maximum=_RUST_MAX_RETAINED_SECONDS,
        ),
        minimum_free_bytes=_bounded_integer(
            rust_payload,
            "minimum_free_bytes",
            context="soak_storage.rust_diagnostics",
            minimum=1,
            maximum=_RUST_MAX_TOTAL_BYTES,
        ),
    )
    if rust_diagnostics.max_total_bytes < rust_diagnostics.max_segment_bytes:
        raise RuntimeError(
            "soak_storage.rust_diagnostics.max_total_bytes must not be below "
            "soak_storage.rust_diagnostics.max_segment_bytes."
        )

    streams_payload = payload.get("streams")
    if not isinstance(streams_payload, dict):
        raise RuntimeError("soak_storage.streams must be an object.")
    _require_exact_keys(
        streams_payload, set(REQUIRED_STREAMS), context="soak_storage.streams"
    )

    streams: dict[str, ArtifactStreamPolicy] = {}
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
        streams[name] = ArtifactStreamPolicy(
            max_segment_bytes=max_segment_bytes,
            retained_segments=retained_segments,
        )

    policy = SoakStoragePolicy(
        max_total_bytes=max_total_bytes,
        max_age_seconds=max_age_seconds,
        minimum_free_bytes=minimum_free_bytes,
        bundle_interval_seconds=bundle_interval_seconds,
        rust_diagnostics=rust_diagnostics,
        streams=MappingProxyType(streams),
    )
    if required_stream_capacity_bytes(policy) > max_total_bytes:
        raise RuntimeError(
            "soak_storage.max_total_bytes must cover every retained required-stream instance."
        )
    return policy


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


def _bounded_integer(
    payload: dict[str, Any],
    key: str,
    *,
    context: str,
    minimum: int,
    maximum: int,
) -> int:
    value = payload.get(key)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise RuntimeError(
            f"{context}.{key} must be an integer in {minimum}..={maximum}."
        )
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
