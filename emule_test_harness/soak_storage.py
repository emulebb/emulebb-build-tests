"""Validated storage policy for persisted diagnostic soak artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

SCHEMA = "emulebb-build-tests.soak-storage-policy.v1"
REQUIRED_STREAMS = ("controller_output", "daemon_output")
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
        active_segment_budget += max_segment_bytes
        streams[name] = ArtifactStreamPolicy(
            max_segment_bytes=max_segment_bytes,
            retained_segments=retained_segments,
        )

    if active_segment_budget > max_total_bytes:
        raise RuntimeError(
            "soak_storage.max_total_bytes must cover one active segment for every required stream."
        )

    return SoakStoragePolicy(
        max_total_bytes=max_total_bytes,
        max_age_seconds=max_age_seconds,
        minimum_free_bytes=minimum_free_bytes,
        bundle_interval_seconds=bundle_interval_seconds,
        streams=MappingProxyType(streams),
    )


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
