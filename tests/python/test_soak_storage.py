from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import MappingProxyType

import pytest

from emule_test_harness import soak_storage


def policy_payload() -> dict[str, object]:
    return {
        "schema": soak_storage.SCHEMA,
        "max_total_bytes": 4_200,
        "max_age_seconds": 3_600,
        "minimum_free_bytes": 500,
        "bundle_interval_seconds": 900,
        "rust_diagnostics": {
            "max_segment_bytes": 1_048_576,
            "max_segment_seconds": 60,
            "retained_segments": 2,
            "max_total_bytes": 2_097_152,
            "max_retained_seconds": 3_600,
            "minimum_free_bytes": 500,
        },
        "streams": {
            "controller_output": {
                "max_segment_bytes": 100,
                "retained_segments": 4,
            },
            "daemon_output": {
                "max_segment_bytes": 200,
                "retained_segments": 8,
            },
            "diagnostic_bundles": {
                "max_segment_bytes": 300,
                "retained_segments": 2,
            },
            "diagnostic_indexes": {
                "max_segment_bytes": 100,
                "retained_segments": 1,
            },
            "diagnostic_segments": {
                "max_segment_bytes": 50,
                "retained_segments": 2,
            },
        },
    }


def direct_policy(
    *,
    max_total_bytes: int = 1_000,
    max_age_seconds: int = 3_600,
    minimum_free_bytes: int = 100,
    bundle_max_bytes: int = 256,
    bundle_retained: int = 2,
    index_max_bytes: int = 1,
    index_retained: int = 1,
    segment_max_bytes: int = 1,
    segment_retained: int = 1,
) -> soak_storage.SoakStoragePolicy:
    return soak_storage.SoakStoragePolicy(
        max_total_bytes=max_total_bytes,
        max_age_seconds=max_age_seconds,
        minimum_free_bytes=minimum_free_bytes,
        bundle_interval_seconds=900,
        rust_diagnostics=soak_storage.RustDiagnosticWriterPolicy(
            max_segment_bytes=1_048_576,
            max_segment_seconds=60,
            retained_segments=2,
            max_total_bytes=2_097_152,
            max_retained_seconds=3_600,
            minimum_free_bytes=500,
        ),
        streams=MappingProxyType(
            {
                "controller_output": soak_storage.ArtifactStreamPolicy(1, 1),
                "daemon_output": soak_storage.ArtifactStreamPolicy(1, 1),
                "diagnostic_bundles": soak_storage.ArtifactStreamPolicy(
                    bundle_max_bytes,
                    bundle_retained,
                ),
                "diagnostic_indexes": soak_storage.ArtifactStreamPolicy(
                    index_max_bytes,
                    index_retained,
                ),
                "diagnostic_segments": soak_storage.ArtifactStreamPolicy(
                    segment_max_bytes,
                    segment_retained,
                ),
            }
        ),
    )


def fake_inventory(
    root: Path, rows: list[tuple[str, int, int]]
) -> soak_storage.ArtifactInventory:
    files = tuple(
        soak_storage.ArtifactFile(
            path=(root / relative_path).resolve(),
            relative_path=Path(relative_path),
            size_bytes=size_bytes,
            modified_ns=modified_ns,
        )
        for relative_path, size_bytes, modified_ns in rows
    )
    return soak_storage.ArtifactInventory(
        files=files,
        total_bytes=sum(item.size_bytes for item in files),
    )


def fake_disk_space(
    root: Path, *, free_bytes: int = 1_000
) -> soak_storage.DiskSpaceSnapshot:
    return soak_storage.DiskSpaceSnapshot(
        measured_path=root,
        total_bytes=10_000,
        used_bytes=10_000 - free_bytes,
        free_bytes=free_bytes,
    )


def test_parse_soak_storage_policy_accepts_strict_complete_contract() -> None:
    policy = soak_storage.parse_soak_storage_policy(policy_payload())

    assert policy.max_total_bytes == 4_200
    assert policy.max_age_seconds == 3_600
    assert policy.minimum_free_bytes == 500
    assert policy.bundle_interval_seconds == 900
    assert policy.rust_diagnostics == soak_storage.RustDiagnosticWriterPolicy(
        max_segment_bytes=1_048_576,
        max_segment_seconds=60,
        retained_segments=2,
        max_total_bytes=2_097_152,
        max_retained_seconds=3_600,
        minimum_free_bytes=500,
    )
    assert policy.stream("controller_output") == soak_storage.ArtifactStreamPolicy(
        max_segment_bytes=100,
        retained_segments=4,
    )
    assert policy.stream("daemon_output").max_segment_bytes == 200


def test_storage_policy_payload_round_trips_and_hashes_canonically() -> None:
    policy = soak_storage.parse_soak_storage_policy(policy_payload())
    payload = soak_storage.storage_policy_payload(policy)

    assert payload == policy_payload()
    assert soak_storage.parse_soak_storage_policy(payload) == policy
    assert soak_storage.storage_policy_sha256(
        policy
    ) == soak_storage.storage_policy_sha256(
        soak_storage.parse_soak_storage_policy(
            {
                **payload,
                "streams": {
                    "daemon_output": payload["streams"]["daemon_output"],
                    "controller_output": payload["streams"]["controller_output"],
                    "diagnostic_bundles": payload["streams"]["diagnostic_bundles"],
                    "diagnostic_indexes": payload["streams"]["diagnostic_indexes"],
                    "diagnostic_segments": payload["streams"]["diagnostic_segments"],
                },
            }
        )
    )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda payload: payload.update(schema="wrong"), "schema"),
        (lambda payload: payload.pop("max_total_bytes"), "missing required fields"),
        (lambda payload: payload.update(extra=True), "unknown fields"),
        (lambda payload: payload.update(max_age_seconds=True), "positive integer"),
        (lambda payload: payload.update(minimum_free_bytes=0), "positive integer"),
        (lambda payload: payload.pop("rust_diagnostics"), "missing required fields"),
        (lambda payload: payload.update(streams=[]), "streams must be an object"),
    ],
)
def test_parse_soak_storage_policy_rejects_invalid_top_level_contract(
    mutate, message: str
) -> None:
    payload = policy_payload()
    mutate(payload)

    with pytest.raises(RuntimeError, match=message):
        soak_storage.parse_soak_storage_policy(payload)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda policy: policy.update(extra=True), "unknown fields"),
        (
            lambda policy: policy.update(max_segment_bytes=1_048_575),
            "max_segment_bytes",
        ),
        (lambda policy: policy.update(max_segment_seconds=59), "max_segment_seconds"),
        (lambda policy: policy.update(retained_segments=1), "retained_segments"),
        (
            lambda policy: policy.update(max_retained_seconds=True),
            "max_retained_seconds",
        ),
        (lambda policy: policy.update(minimum_free_bytes=0), "minimum_free_bytes"),
        (
            lambda policy: policy.update(
                max_segment_bytes=2_097_152,
                max_total_bytes=1_048_576,
            ),
            "must not be below",
        ),
    ],
)
def test_parse_soak_storage_policy_rejects_invalid_rust_diagnostics(
    mutate, message: str
) -> None:
    payload = policy_payload()
    policy = payload["rust_diagnostics"]
    assert isinstance(policy, dict)
    mutate(policy)

    with pytest.raises(RuntimeError, match=message):
        soak_storage.parse_soak_storage_policy(payload)


def test_parse_soak_storage_policy_requires_exact_streams() -> None:
    payload = policy_payload()
    streams = payload["streams"]
    assert isinstance(streams, dict)
    streams.pop("daemon_output")

    with pytest.raises(RuntimeError, match="missing required fields: daemon_output"):
        soak_storage.parse_soak_storage_policy(payload)


def test_parse_soak_storage_policy_rejects_unknown_stream_fields() -> None:
    payload = policy_payload()
    streams = payload["streams"]
    assert isinstance(streams, dict)
    controller = streams["controller_output"]
    assert isinstance(controller, dict)
    controller["truncate_bytes"] = 1

    with pytest.raises(RuntimeError, match="unknown fields: truncate_bytes"):
        soak_storage.parse_soak_storage_policy(payload)


def test_required_stream_capacity_includes_every_retained_instance() -> None:
    policy = soak_storage.parse_soak_storage_policy(policy_payload())

    assert soak_storage.required_stream_capacity_bytes(policy) == 4_200


def test_parse_soak_storage_policy_requires_total_to_cover_retained_streams() -> None:
    payload = policy_payload()
    payload["max_total_bytes"] = 4_199

    with pytest.raises(RuntimeError, match="every retained required-stream instance"):
        soak_storage.parse_soak_storage_policy(payload)


def test_stream_rejects_unknown_name() -> None:
    policy = soak_storage.parse_soak_storage_policy(policy_payload())

    with pytest.raises(RuntimeError, match="Unknown soak storage stream"):
        policy.stream("protocol")


def test_inventory_artifacts_is_deterministic_and_counts_whole_files(
    tmp_path: Path,
) -> None:
    newer = tmp_path / "z" / "newer.jsonl"
    older = tmp_path / "a" / "older.json"
    newer.parent.mkdir()
    older.parent.mkdir()
    newer.write_bytes(b"newer")
    older.write_bytes(b"old")
    os.utime(older, ns=(100, 100))
    os.utime(newer, ns=(200, 200))

    inventory = soak_storage.inventory_artifacts(tmp_path)

    assert inventory.total_bytes == 8
    assert [item.relative_path.as_posix() for item in inventory.files] == [
        "a/older.json",
        "z/newer.jsonl",
    ]
    assert [item.size_bytes for item in inventory.files] == [3, 5]


def test_inventory_artifacts_returns_empty_for_future_root(tmp_path: Path) -> None:
    assert soak_storage.inventory_artifacts(
        tmp_path / "future"
    ) == soak_storage.ArtifactInventory(
        files=(),
        total_bytes=0,
    )


def test_inventory_artifacts_rejects_non_directory_root(tmp_path: Path) -> None:
    file_root = tmp_path / "artifact.bin"
    file_root.write_bytes(b"x")

    with pytest.raises(RuntimeError, match="not a directory"):
        soak_storage.inventory_artifacts(file_root)


def test_disk_space_snapshot_uses_nearest_existing_ancestor(tmp_path: Path) -> None:
    measured: list[Path] = []

    def fake_disk_usage(path: Path) -> tuple[int, int, int]:
        measured.append(path)
        return (1_000, 600, 400)

    snapshot = soak_storage.disk_space_snapshot(
        tmp_path / "future" / "campaign",
        disk_usage=fake_disk_usage,
    )

    assert measured == [tmp_path.resolve()]
    assert snapshot == soak_storage.DiskSpaceSnapshot(
        measured_path=tmp_path.resolve(),
        total_bytes=1_000,
        used_bytes=600,
        free_bytes=400,
    )


@pytest.mark.parametrize(
    "values",
    [
        (-1, 0, 0),
        (100, -1, 100),
        (100, 0, True),
        (100, 80, 30),
    ],
)
def test_disk_space_snapshot_rejects_invalid_provider_values(
    tmp_path: Path, values
) -> None:
    with pytest.raises(RuntimeError, match="capacity values"):
        soak_storage.disk_space_snapshot(tmp_path, disk_usage=lambda _path: values)


def test_bounded_store_prunes_expired_closed_artifacts_but_protects_active_campaign(
    tmp_path: Path,
) -> None:
    inventory = fake_inventory(
        tmp_path,
        [
            ("campaigns/old/expired.jsonl", 50, 1),
            ("campaigns/active/also-old.jsonl", 50, 1),
            ("campaigns/recent/current.jsonl", 50, 9_950_000_000_000),
        ],
    )
    store = soak_storage.BoundedArtifactStore(
        tmp_path,
        direct_policy(max_age_seconds=100),
        inventory=lambda _root: inventory,
        disk_space=lambda root: fake_disk_space(root),
    )

    plan = store.plan(
        active_campaign=tmp_path / "campaigns" / "active",
        now_ns=10_000_000_000_000,
    )

    assert [item.artifact.relative_path.as_posix() for item in plan.deletions] == [
        "campaigns/old/expired.jsonl"
    ]
    assert [item.reason for item in plan.deletions] == ["max_age_seconds"]
    assert [item.relative_path.as_posix() for item in plan.protected_files] == [
        "campaigns/active/also-old.jsonl"
    ]
    assert plan.within_limits


def test_bounded_store_deletes_oldest_artifacts_until_total_is_within_budget(
    tmp_path: Path,
) -> None:
    inventory = fake_inventory(
        tmp_path,
        [("first", 60, 100), ("second", 60, 200), ("third", 60, 300)],
    )
    store = soak_storage.BoundedArtifactStore(
        tmp_path,
        direct_policy(max_total_bytes=100),
        inventory=lambda _root: inventory,
        disk_space=lambda root: fake_disk_space(root),
    )

    plan = store.plan(now_ns=300)

    assert [item.artifact.relative_path.as_posix() for item in plan.deletions] == [
        "first",
        "second",
    ]
    assert [item.reason for item in plan.deletions] == [
        "max_total_bytes",
        "max_total_bytes",
    ]
    assert plan.projected_total_bytes == 60
    assert plan.within_limits


def test_bounded_store_deletes_oldest_artifacts_until_free_reserve_is_met(
    tmp_path: Path,
) -> None:
    inventory = fake_inventory(
        tmp_path,
        [("first", 50, 100), ("second", 50, 200), ("third", 50, 300)],
    )
    store = soak_storage.BoundedArtifactStore(
        tmp_path,
        direct_policy(minimum_free_bytes=100),
        inventory=lambda _root: inventory,
        disk_space=lambda root: fake_disk_space(root, free_bytes=10),
    )

    plan = store.plan(now_ns=300)

    assert [item.artifact.relative_path.as_posix() for item in plan.deletions] == [
        "first",
        "second",
    ]
    assert [item.reason for item in plan.deletions] == [
        "minimum_free_bytes",
        "minimum_free_bytes",
    ]
    assert plan.projected_free_bytes == 110
    assert plan.within_limits


def test_bounded_store_reserves_future_bytes_at_exact_policy_boundaries(
    tmp_path: Path,
) -> None:
    inventory = fake_inventory(tmp_path, [("protected.bin", 40, 100)])
    store = soak_storage.BoundedArtifactStore(
        tmp_path,
        direct_policy(max_total_bytes=100, minimum_free_bytes=50),
        inventory=lambda _root: inventory,
        disk_space=lambda root: fake_disk_space(root, free_bytes=110),
    )

    plan = store.plan(
        pinned_paths=[tmp_path / "protected.bin"],
        reserved_bytes=60,
        now_ns=100,
    )

    assert plan.reserved_bytes == 60
    assert plan.projected_total_bytes == 100
    assert plan.projected_free_bytes == 50
    assert not plan.deletions
    assert plan.within_limits


def test_bounded_store_prunes_closed_artifacts_for_reserved_future_bytes(
    tmp_path: Path,
) -> None:
    inventory = fake_inventory(
        tmp_path,
        [("old.bin", 60, 100), ("pinned/evidence.bin", 20, 200)],
    )
    store = soak_storage.BoundedArtifactStore(
        tmp_path,
        direct_policy(max_total_bytes=100, minimum_free_bytes=50),
        inventory=lambda _root: inventory,
        disk_space=lambda root: fake_disk_space(root, free_bytes=100),
    )

    plan = store.plan(
        pinned_paths=[tmp_path / "pinned"],
        reserved_bytes=60,
        now_ns=200,
    )

    assert [item.artifact.relative_path.as_posix() for item in plan.deletions] == [
        "old.bin"
    ]
    assert plan.projected_total_bytes == 80
    assert plan.projected_free_bytes == 100
    assert plan.within_limits


def test_bounded_store_reports_unresolved_reserved_future_bytes(
    tmp_path: Path,
) -> None:
    store = soak_storage.BoundedArtifactStore(
        tmp_path,
        direct_policy(max_total_bytes=50, minimum_free_bytes=10),
        inventory=lambda _root: fake_inventory(tmp_path, []),
        disk_space=lambda root: fake_disk_space(root, free_bytes=50),
    )

    plan = store.plan(reserved_bytes=60, now_ns=1)

    assert plan.projected_total_bytes == 60
    assert plan.projected_free_bytes == -10
    assert plan.unresolved_constraints == (
        "max_total_bytes",
        "minimum_free_bytes",
    )
    assert not plan.within_limits


@pytest.mark.parametrize("reserved_bytes", [-1, True, 1.5])
def test_bounded_store_rejects_invalid_reserved_bytes(
    tmp_path: Path,
    reserved_bytes: object,
) -> None:
    store = soak_storage.BoundedArtifactStore(tmp_path, direct_policy())

    with pytest.raises(ValueError, match="non-negative integer"):
        store.plan(reserved_bytes=reserved_bytes)  # type: ignore[arg-type]


def test_bounded_store_reports_limits_blocked_by_active_campaign(
    tmp_path: Path,
) -> None:
    inventory = fake_inventory(tmp_path, [("active/data.jsonl", 200, 1)])
    store = soak_storage.BoundedArtifactStore(
        tmp_path,
        direct_policy(max_total_bytes=100, minimum_free_bytes=500),
        inventory=lambda _root: inventory,
        disk_space=lambda root: fake_disk_space(root, free_bytes=100),
    )

    plan = store.plan(active_campaign=tmp_path / "active", now_ns=1)

    assert not plan.deletions
    assert [item.relative_path.as_posix() for item in plan.protected_files] == [
        "active/data.jsonl"
    ]
    assert plan.unresolved_constraints == (
        "max_total_bytes",
        "minimum_free_bytes",
    )
    assert not plan.within_limits


def test_bounded_store_never_selects_pinned_artifacts(tmp_path: Path) -> None:
    inventory = fake_inventory(
        tmp_path,
        [("pinned/evidence.jsonl", 60, 100), ("closed/data.jsonl", 60, 200)],
    )
    store = soak_storage.BoundedArtifactStore(
        tmp_path,
        direct_policy(max_total_bytes=70),
        inventory=lambda _root: inventory,
        disk_space=lambda root: fake_disk_space(root),
    )

    plan = store.plan(pinned_paths=[tmp_path / "pinned"], now_ns=200)

    assert [item.artifact.relative_path.as_posix() for item in plan.deletions] == [
        "closed/data.jsonl"
    ]
    assert [item.relative_path.as_posix() for item in plan.protected_files] == [
        "pinned/evidence.jsonl"
    ]
    assert plan.projected_total_bytes == 60
    assert plan.within_limits


def test_bounded_store_rejects_protected_paths_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "store"
    store = soak_storage.BoundedArtifactStore(
        root,
        direct_policy(),
        inventory=lambda _root: fake_inventory(root, []),
        disk_space=lambda path: fake_disk_space(path),
    )

    with pytest.raises(RuntimeError, match="escaped"):
        store.plan(pinned_paths=[tmp_path / "outside.bin"])


def test_bounded_store_enforce_deletes_only_planned_whole_files(
    tmp_path: Path,
) -> None:
    oldest = tmp_path / "oldest.jsonl"
    newest = tmp_path / "newest.jsonl"
    oldest.write_bytes(b"a" * 60)
    newest.write_bytes(b"b" * 60)
    os.utime(oldest, ns=(100, 100))
    os.utime(newest, ns=(200, 200))
    store = soak_storage.BoundedArtifactStore(
        tmp_path,
        direct_policy(max_total_bytes=70),
        disk_space=lambda root: fake_disk_space(root),
    )

    result = store.enforce(now_ns=200)

    assert result.deleted_paths == (oldest.resolve(),)
    assert not oldest.exists()
    assert newest.read_bytes() == b"b" * 60
    assert not result.verification.deletions
    assert result.within_limits


def test_bounded_store_enforcement_reports_removal_failure(tmp_path: Path) -> None:
    inventory = fake_inventory(tmp_path, [("old.bin", 60, 1)])

    def reject_removal(_path: Path) -> None:
        raise PermissionError("busy")

    store = soak_storage.BoundedArtifactStore(
        tmp_path,
        direct_policy(max_total_bytes=10),
        inventory=lambda _root: inventory,
        disk_space=lambda root: fake_disk_space(root),
        remove_file=reject_removal,
    )

    result = store.enforce(now_ns=1)

    assert not result.deleted_paths
    assert result.failures == ("old.bin: PermissionError: busy",)
    assert not result.within_limits


def test_bounded_store_enforcement_verifies_actual_free_space(tmp_path: Path) -> None:
    artifact = tmp_path / "old.bin"
    artifact.write_bytes(b"x" * 100)
    os.utime(artifact, ns=(1, 1))
    snapshots = iter(
        [
            fake_disk_space(tmp_path, free_bytes=10),
            fake_disk_space(tmp_path, free_bytes=10),
        ]
    )
    store = soak_storage.BoundedArtifactStore(
        tmp_path,
        direct_policy(minimum_free_bytes=100),
        disk_space=lambda _root: next(snapshots),
    )

    result = store.enforce(now_ns=1)

    assert result.deleted_paths == (artifact.resolve(),)
    assert result.verification.unresolved_constraints == ("minimum_free_bytes",)
    assert not result.within_limits


def test_persist_bounded_json_artifact_rotates_whole_atomic_files(
    tmp_path: Path,
) -> None:
    soak_root = tmp_path / "soak"
    campaign = soak_root / "campaigns" / "20261025T120000Z"
    directory = campaign / "report" / "diagnostic-bundles"
    store = soak_storage.BoundedArtifactStore(
        soak_root,
        direct_policy(
            max_total_bytes=10_000,
            minimum_free_bytes=1,
            bundle_max_bytes=1_024,
            bundle_retained=2,
        ),
    )

    first = soak_storage.persist_bounded_json_artifact(
        store=store,
        active_campaign=campaign,
        directory=directory,
        stream_name="diagnostic_bundles",
        stem="rust-diagnostic-bundle-ready",
        payload={"schema": "emulebb.diagnostic-bundle.v4", "seq": 1},
        now_ns=1,
    )
    second = soak_storage.persist_bounded_json_artifact(
        store=store,
        active_campaign=campaign,
        directory=directory,
        stream_name="diagnostic_bundles",
        stem="rust-diagnostic-bundle-ready",
        payload={"schema": "emulebb.diagnostic-bundle.v4", "seq": 2},
        now_ns=2,
    )
    third = soak_storage.persist_bounded_json_artifact(
        store=store,
        active_campaign=campaign,
        directory=directory,
        stream_name="diagnostic_bundles",
        stem="rust-diagnostic-bundle-ready",
        payload={"schema": "emulebb.diagnostic-bundle.v4", "seq": 3},
        now_ns=3,
    )

    assert first.path in third.deleted_paths
    assert not first.path.exists()
    assert second.path.is_file()
    assert third.path.is_file()
    assert third.retained_count == 2
    assert third.retained_bytes == second.byte_count + third.byte_count
    assert third.sha256 == hashlib.sha256(third.path.read_bytes()).hexdigest()
    assert json.loads(third.path.read_text(encoding="utf-8"))["seq"] == 3
    assert not list(directory.glob("*.tmp"))


def test_persist_bounded_json_artifact_rejects_oversized_payload_before_write(
    tmp_path: Path,
) -> None:
    soak_root = tmp_path / "soak"
    campaign = soak_root / "campaigns" / "20261025T120000Z"
    directory = campaign / "report" / "diagnostic-bundles"
    store = soak_storage.BoundedArtifactStore(
        soak_root,
        direct_policy(
            max_total_bytes=10_000,
            minimum_free_bytes=1,
            bundle_max_bytes=32,
        ),
    )

    with pytest.raises(RuntimeError, match="exceeding its 32-byte limit"):
        soak_storage.persist_bounded_json_artifact(
            store=store,
            active_campaign=campaign,
            directory=directory,
            stream_name="diagnostic_bundles",
            stem="rust-diagnostic-bundle-ready",
            payload={"value": "x" * 100},
            now_ns=1,
        )

    assert not directory.exists()


def test_persist_bounded_json_artifact_fails_closed_on_store_reservation(
    tmp_path: Path,
) -> None:
    soak_root = tmp_path / "soak"
    campaign = soak_root / "campaigns" / "20261025T120000Z"
    directory = campaign / "report" / "diagnostic-bundles"
    store = soak_storage.BoundedArtifactStore(
        soak_root,
        direct_policy(
            max_total_bytes=10_000,
            minimum_free_bytes=100,
            bundle_max_bytes=1_024,
        ),
        disk_space=lambda root: fake_disk_space(root, free_bytes=100),
    )

    with pytest.raises(RuntimeError, match="reservation failed"):
        soak_storage.persist_bounded_json_artifact(
            store=store,
            active_campaign=campaign,
            directory=directory,
            stream_name="diagnostic_bundles",
            stem="rust-diagnostic-bundle-ready",
            payload={"schema": "emulebb.diagnostic-bundle.v4"},
            now_ns=1,
        )

    assert not list(directory.glob("*.json"))


def test_persist_bounded_json_checkpoint_replaces_one_verified_file(
    tmp_path: Path,
) -> None:
    soak_root = tmp_path / "soak"
    campaign = soak_root / "campaigns" / "20261025T120000Z"
    directory = campaign / "report" / "diagnostic-indexes" / "rust"
    store = soak_storage.BoundedArtifactStore(
        soak_root,
        direct_policy(
            max_total_bytes=10_000,
            minimum_free_bytes=1,
            index_max_bytes=1_024,
        ),
    )

    first = soak_storage.persist_bounded_json_checkpoint(
        store=store,
        active_campaign=campaign,
        directory=directory,
        stream_name="diagnostic_indexes",
        artifact_name="diagnostic-run-index.json",
        payload={"schema": "checkpoint-v1", "seq": 1},
        now_ns=1,
    )
    second = soak_storage.persist_bounded_json_checkpoint(
        store=store,
        active_campaign=campaign,
        directory=directory,
        stream_name="diagnostic_indexes",
        artifact_name="diagnostic-run-index.json",
        payload={"schema": "checkpoint-v1", "seq": 2},
        now_ns=2,
    )

    assert first.path == second.path
    assert json.loads(second.path.read_text(encoding="utf-8"))["seq"] == 2
    assert second.sha256 == hashlib.sha256(second.path.read_bytes()).hexdigest()
    assert second.retained_count == 1
    assert second.retained_bytes == second.byte_count
    assert not list(directory.glob("*.tmp"))


def test_persist_bounded_json_checkpoint_recovers_stale_temporary_file(
    tmp_path: Path,
) -> None:
    soak_root = tmp_path / "soak"
    campaign = soak_root / "campaigns" / "20261025T120000Z"
    directory = campaign / "report" / "diagnostic-indexes" / "mfc"
    directory.mkdir(parents=True)
    temporary = directory / ".diagnostic-run-index.json.tmp"
    temporary.write_text("stale", encoding="utf-8")
    store = soak_storage.BoundedArtifactStore(
        soak_root,
        direct_policy(
            max_total_bytes=10_000,
            minimum_free_bytes=1,
            index_max_bytes=1_024,
        ),
    )

    persisted = soak_storage.persist_bounded_json_checkpoint(
        store=store,
        active_campaign=campaign,
        directory=directory,
        stream_name="diagnostic_indexes",
        artifact_name="diagnostic-run-index.json",
        payload={"schema": "checkpoint-v1"},
        now_ns=1,
    )

    assert persisted.path.is_file()
    assert not temporary.exists()


def test_persist_bounded_json_checkpoint_rejects_oversized_payload(
    tmp_path: Path,
) -> None:
    soak_root = tmp_path / "soak"
    campaign = soak_root / "campaigns" / "20261025T120000Z"
    directory = campaign / "report" / "diagnostic-indexes" / "rust"
    store = soak_storage.BoundedArtifactStore(
        soak_root,
        direct_policy(
            max_total_bytes=10_000,
            minimum_free_bytes=1,
            index_max_bytes=32,
        ),
    )

    with pytest.raises(RuntimeError, match="exceeding its 32-byte limit"):
        soak_storage.persist_bounded_json_checkpoint(
            store=store,
            active_campaign=campaign,
            directory=directory,
            stream_name="diagnostic_indexes",
            artifact_name="diagnostic-run-index.json",
            payload={"value": "x" * 100},
            now_ns=1,
        )

    assert not directory.exists()


def test_persist_bounded_json_checkpoint_requires_single_retained_artifact(
    tmp_path: Path,
) -> None:
    soak_root = tmp_path / "soak"
    campaign = soak_root / "campaigns" / "20261025T120000Z"
    store = soak_storage.BoundedArtifactStore(
        soak_root,
        direct_policy(index_max_bytes=1_024, index_retained=2),
    )

    with pytest.raises(RuntimeError, match="retain exactly one"):
        soak_storage.persist_bounded_json_checkpoint(
            store=store,
            active_campaign=campaign,
            directory=campaign / "report" / "diagnostic-indexes" / "rust",
            stream_name="diagnostic_indexes",
            artifact_name="diagnostic-run-index.json",
            payload={"schema": "checkpoint-v1"},
            now_ns=1,
        )


def test_persist_bounded_file_artifact_copies_exact_bytes_and_preserves_source(
    tmp_path: Path,
) -> None:
    soak_root = tmp_path / "soak"
    campaign = soak_root / "campaigns" / "20261025T120000Z"
    directory = campaign / "archive" / "diagnostic-segments" / "rust"
    source = tmp_path / "profile" / "diag-event-p1-r1-s000001.jsonl"
    source.parent.mkdir()
    source.write_bytes(b'{"schema":"diag_event_v2"}\n\x00raw')
    store = soak_storage.BoundedArtifactStore(
        soak_root,
        direct_policy(
            max_total_bytes=10_000,
            minimum_free_bytes=1,
            segment_max_bytes=1_024,
            segment_retained=2,
        ),
    )

    persisted = soak_storage.persist_bounded_file_artifact(
        store=store,
        active_campaign=campaign,
        directory=directory,
        stream_name="diagnostic_segments",
        source=source,
        artifact_name=source.name,
        now_ns=1,
    )

    assert source.read_bytes() == persisted.path.read_bytes()
    assert persisted.byte_count == source.stat().st_size
    assert persisted.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert persisted.retained_count == 1
    assert persisted.retained_bytes == persisted.byte_count
    assert not list(directory.glob("*.tmp"))


def test_persist_bounded_file_artifact_rotates_whole_files(tmp_path: Path) -> None:
    soak_root = tmp_path / "soak"
    campaign = soak_root / "campaigns" / "20261025T120000Z"
    directory = campaign / "archive" / "diagnostic-segments" / "mfc"
    source_dir = tmp_path / "profile"
    source_dir.mkdir()
    sources = [
        source_dir / f"diag-event-p1-r1-s{index:06d}.jsonl" for index in range(3)
    ]
    for index, source in enumerate(sources):
        source.write_bytes(bytes([index]) * 8)
    store = soak_storage.BoundedArtifactStore(
        soak_root,
        direct_policy(
            max_total_bytes=10_000,
            minimum_free_bytes=1,
            segment_max_bytes=1_024,
            segment_retained=2,
        ),
    )

    persisted = [
        soak_storage.persist_bounded_file_artifact(
            store=store,
            active_campaign=campaign,
            directory=directory,
            stream_name="diagnostic_segments",
            source=source,
            artifact_name=source.name,
            now_ns=index,
        )
        for index, source in enumerate(sources)
    ]

    assert persisted[0].path in persisted[2].deleted_paths
    assert not persisted[0].path.exists()
    assert persisted[1].path.read_bytes() == sources[1].read_bytes()
    assert persisted[2].path.read_bytes() == sources[2].read_bytes()
    assert persisted[2].retained_count == 2
    assert all(source.is_file() for source in sources)


def test_persist_bounded_file_artifact_rejects_oversized_source_before_write(
    tmp_path: Path,
) -> None:
    soak_root = tmp_path / "soak"
    campaign = soak_root / "campaigns" / "20261025T120000Z"
    directory = campaign / "archive" / "diagnostic-segments" / "rust"
    source = tmp_path / "profile" / "diag-event-p1-r1-s000001.jsonl"
    source.parent.mkdir()
    source.write_bytes(b"x" * 33)
    store = soak_storage.BoundedArtifactStore(
        soak_root,
        direct_policy(
            max_total_bytes=10_000,
            minimum_free_bytes=1,
            segment_max_bytes=32,
        ),
    )

    with pytest.raises(RuntimeError, match="exceeding its 32-byte limit"):
        soak_storage.persist_bounded_file_artifact(
            store=store,
            active_campaign=campaign,
            directory=directory,
            stream_name="diagnostic_segments",
            source=source,
            artifact_name=source.name,
            now_ns=1,
        )

    assert not directory.exists()


@pytest.mark.parametrize("artifact_name", ("../segment.jsonl", "segment:ads.jsonl", ""))
def test_persist_bounded_file_artifact_rejects_unsafe_name(
    tmp_path: Path, artifact_name: str
) -> None:
    with pytest.raises(ValueError, match="safe ASCII filename"):
        soak_storage.persist_bounded_file_artifact(
            store=soak_storage.BoundedArtifactStore(tmp_path / "soak", direct_policy()),
            active_campaign=tmp_path / "soak" / "campaigns" / "20261025T120000Z",
            directory=tmp_path / "soak" / "campaigns" / "20261025T120000Z" / "archive",
            stream_name="diagnostic_segments",
            source=tmp_path / "source.jsonl",
            artifact_name=artifact_name,
            now_ns=1,
        )
