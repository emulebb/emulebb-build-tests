from __future__ import annotations

import os
from pathlib import Path

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
    payload["max_total_bytes"] = 250

    with pytest.raises(RuntimeError, match="cover one active segment"):
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
