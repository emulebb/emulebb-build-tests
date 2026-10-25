from __future__ import annotations

import os
from pathlib import Path
from types import MappingProxyType

import pytest

from emule_test_harness import soak_storage


def policy_payload() -> dict[str, object]:
    return {
        "schema": soak_storage.SCHEMA,
        "max_total_bytes": 1_000,
        "max_age_seconds": 3_600,
        "minimum_free_bytes": 500,
        "bundle_interval_seconds": 900,
        "streams": {
            "controller_output": {
                "max_segment_bytes": 100,
                "retained_segments": 4,
            },
            "daemon_output": {
                "max_segment_bytes": 200,
                "retained_segments": 8,
            },
        },
    }


def direct_policy(
    *,
    max_total_bytes: int = 1_000,
    max_age_seconds: int = 3_600,
    minimum_free_bytes: int = 100,
) -> soak_storage.SoakStoragePolicy:
    return soak_storage.SoakStoragePolicy(
        max_total_bytes=max_total_bytes,
        max_age_seconds=max_age_seconds,
        minimum_free_bytes=minimum_free_bytes,
        bundle_interval_seconds=900,
        streams=MappingProxyType(
            {
                "controller_output": soak_storage.ArtifactStreamPolicy(1, 1),
                "daemon_output": soak_storage.ArtifactStreamPolicy(1, 1),
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

    assert policy.max_total_bytes == 1_000
    assert policy.max_age_seconds == 3_600
    assert policy.minimum_free_bytes == 500
    assert policy.bundle_interval_seconds == 900
    assert policy.stream("controller_output") == soak_storage.ArtifactStreamPolicy(
        max_segment_bytes=100,
        retained_segments=4,
    )
    assert policy.stream("daemon_output").max_segment_bytes == 200


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda payload: payload.update(schema="wrong"), "schema"),
        (lambda payload: payload.pop("max_total_bytes"), "missing required fields"),
        (lambda payload: payload.update(extra=True), "unknown fields"),
        (lambda payload: payload.update(max_age_seconds=True), "positive integer"),
        (lambda payload: payload.update(minimum_free_bytes=0), "positive integer"),
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


def test_parse_soak_storage_policy_requires_total_to_cover_active_segments() -> None:
    payload = policy_payload()
    payload["max_total_bytes"] = 599

    with pytest.raises(RuntimeError, match="every active required-stream instance"):
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
