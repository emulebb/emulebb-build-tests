from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType

import pytest

from emule_test_harness import persisted_soak_controller as controller
from emule_test_harness import soak_storage
from emule_test_harness.live_wire_inputs import LiveWireInputs
from emule_test_harness.windows_processes import WindowsProcessInfo


def make_paths(tmp_path: Path) -> controller.ControlPaths:
    return controller.build_control_paths(tmp_path / "output")


def storage_policy(
    *,
    max_total_bytes: int = 1_000,
    index_max_bytes: int = 1,
    pin_max_bytes: int = 1,
    pin_retained: int = 1,
    segment_max_bytes: int = 1,
    segment_retained: int = 1,
) -> soak_storage.SoakStoragePolicy:
    return soak_storage.SoakStoragePolicy(
        max_total_bytes=max_total_bytes,
        max_age_seconds=3_600,
        minimum_free_bytes=1,
        bundle_interval_seconds=900,
        rust_diagnostics=soak_storage.RustDiagnosticWriterPolicy(
            max_segment_bytes=1_048_576,
            max_segment_seconds=60,
            retained_segments=2,
            max_total_bytes=2_097_152,
            max_retained_seconds=3_600,
            minimum_free_bytes=1,
        ),
        streams=MappingProxyType(
            {
                "controller_output": soak_storage.ArtifactStreamPolicy(1, 1),
                "daemon_output": soak_storage.ArtifactStreamPolicy(1, 1),
                "diagnostic_bundles": soak_storage.ArtifactStreamPolicy(1, 1),
                "diagnostic_indexes": soak_storage.ArtifactStreamPolicy(
                    index_max_bytes, 1
                ),
                "diagnostic_pins": soak_storage.ArtifactStreamPolicy(
                    pin_max_bytes, pin_retained
                ),
                "diagnostic_segments": soak_storage.ArtifactStreamPolicy(
                    segment_max_bytes, segment_retained
                ),
                "observer_actions": soak_storage.ArtifactStreamPolicy(1, 1),
                "observer_checkpoints": soak_storage.ArtifactStreamPolicy(1, 1),
                "observer_summary": soak_storage.ArtifactStreamPolicy(1, 1),
                "preflight_archive_manifest": soak_storage.ArtifactStreamPolicy(1, 1),
                "preflight_mfc_outputs": soak_storage.ArtifactStreamPolicy(1, 1),
                "preflight_rust_outputs": soak_storage.ArtifactStreamPolicy(1, 1),
                "process_metrics": soak_storage.ArtifactStreamPolicy(1, 1),
                "process_metrics_summary": soak_storage.ArtifactStreamPolicy(1, 1),
            }
        ),
    )


def live_inputs(
    tmp_path: Path,
    *,
    policy: soak_storage.SoakStoragePolicy | None,
) -> LiveWireInputs:
    return LiveWireInputs(
        path=tmp_path / "inputs.json",
        generic_open_terms=("linux",),
        document_terms=("manual",),
        radarr_movie_terms=("movie",),
        sonarr_series_terms=("series",),
        video_roots=(),
        bootstrap_transfer_hashes=(),
        direct_bootstrap_transfers=(),
        soak_storage=policy,
    )


def test_control_paths_must_stay_under_output_root(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="must stay below"):
        controller.build_control_paths(tmp_path / "output", tmp_path / "elsewhere")


def test_persisted_storage_policy_is_mandatory(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="require soak_storage"):
        controller.required_storage_policy(live_inputs(tmp_path, policy=None))


def test_campaign_storage_preflight_is_read_only_and_protects_latest(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    campaigns = controller.campaign_storage_root(output_root)
    old_file = campaigns / "20261023T120000Z" / "report" / "old.json"
    latest_file = campaigns / "20261024T120000Z" / "report" / "latest.json"
    old_file.parent.mkdir(parents=True)
    latest_file.parent.mkdir(parents=True)
    old_file.write_bytes(b"o" * 60)
    latest_file.write_bytes(b"n" * 60)
    os.utime(old_file, ns=(100, 100))
    os.utime(latest_file, ns=(200, 200))

    summary = controller.preflight_campaign_storage(
        live_inputs(tmp_path, policy=storage_policy(max_total_bytes=82)),
        output_root,
        protected_campaigns=(latest_file.parents[1],),
    )

    assert summary["deletionCount"] == 1
    assert summary["deletionBytes"] == 60
    assert summary["protectedFileCount"] == 1
    assert summary["reservedBytes"] == 22
    assert summary["projectedTotalBytes"] == 82
    assert summary["reservation"] == {
        "totalBytes": 22,
        "streams": {
            "controller_output": {
                "instances": 6,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 6,
            },
            "daemon_output": {
                "instances": 1,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 1,
            },
            "diagnostic_bundles": {
                "instances": 1,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 1,
            },
            "diagnostic_indexes": {
                "instances": 2,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 2,
            },
            "diagnostic_pins": {
                "instances": 2,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 2,
            },
            "diagnostic_segments": {
                "instances": 2,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 2,
            },
            "observer_actions": {
                "instances": 1,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 1,
            },
            "observer_checkpoints": {
                "instances": 1,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 1,
            },
            "observer_summary": {
                "instances": 1,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 1,
            },
            "preflight_archive_manifest": {
                "instances": 1,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 1,
            },
            "preflight_mfc_outputs": {
                "instances": 1,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 1,
            },
            "preflight_rust_outputs": {
                "instances": 1,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 1,
            },
            "process_metrics": {
                "instances": 1,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 1,
            },
            "process_metrics_summary": {
                "instances": 1,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 1,
            },
        },
    }
    assert summary["feasible"] is True
    assert old_file.is_file()
    assert latest_file.is_file()


def test_campaign_storage_enforcement_deletes_closed_and_preserves_latest(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    campaigns = controller.campaign_storage_root(output_root)
    old_file = campaigns / "20261023T120000Z" / "report" / "old.json"
    latest_campaign = campaigns / "20261024T120000Z"
    latest_file = latest_campaign / "report" / "latest.json"
    old_file.parent.mkdir(parents=True)
    latest_file.parent.mkdir(parents=True)
    old_file.write_bytes(b"o" * 60)
    latest_file.write_bytes(b"n" * 60)
    os.utime(old_file, ns=(100, 100))
    os.utime(latest_file, ns=(200, 200))
    inputs = live_inputs(tmp_path, policy=storage_policy(max_total_bytes=82))

    summary = controller.enforce_campaign_storage(
        inputs,
        output_root,
        protected_campaigns=(latest_campaign,),
    )

    assert summary["deletedCount"] == 1
    assert summary["deletedBytes"] == 60
    assert summary["planned"]["reservedBytes"] == 22
    assert summary["verification"]["reservedBytes"] == 22
    assert summary["verification"]["projectedTotalBytes"] == 82
    assert summary["reservation"]["totalBytes"] == 22
    assert summary["reservation"]["streams"]["controller_output"]["capacityBytes"] == 6
    assert summary["verification"]["deletionCount"] == 0
    assert summary["withinLimits"] is True
    assert not old_file.exists()
    assert latest_file.read_bytes() == b"n" * 60


def test_campaign_storage_preflight_rejects_unreservable_required_streams(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"

    with pytest.raises(RuntimeError, match="max_total_bytes"):
        controller.preflight_campaign_storage(
            live_inputs(tmp_path, policy=storage_policy(max_total_bytes=4)),
            output_root,
            protected_campaigns=(),
        )


def test_campaign_storage_preflight_reserves_minimum_free_space(
    tmp_path: Path,
    monkeypatch,
) -> None:
    output_root = tmp_path / "output"
    monkeypatch.setattr(
        soak_storage,
        "disk_space_snapshot",
        lambda root: soak_storage.DiskSpaceSnapshot(
            measured_path=root,
            total_bytes=100,
            used_bytes=95,
            free_bytes=5,
        ),
    )

    with pytest.raises(RuntimeError, match="minimum_free_bytes"):
        controller.preflight_campaign_storage(
            live_inputs(tmp_path, policy=storage_policy()),
            output_root,
            protected_campaigns=(),
        )


def test_latest_campaign_path_rejects_manifest_escape(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    controller.write_json_atomic(
        paths.last_run_manifest,
        {"campaignDir": str(tmp_path / "outside")},
    )

    with pytest.raises(RuntimeError, match="escaped"):
        controller.latest_campaign_path(
            paths,
            controller.campaign_storage_root(tmp_path / "output"),
        )


def preflight_payload(tmp_path: Path) -> dict[str, object]:
    return {
        "inputs": str(tmp_path / "inputs.json"),
        "profiles": {
            "mfc": str(tmp_path / "EMULE_BIN"),
            "rust": str(tmp_path / "EMULE_RUST_PROFILE_PERSISTED"),
        },
        "diagnosticDirs": {
            "mfc": str(tmp_path / "EMULE_BIN" / "logs"),
            "rust": str(tmp_path / "EMULE_RUST_PROFILE_PERSISTED" / "packet-dump"),
        },
        "executables": {
            "mfc": str(tmp_path / "bin" / "emule.exe"),
            "rust": str(tmp_path / "bin" / "emulebb-rust-diagnostics.exe"),
        },
        "control": {
            "bindAddress": "127.0.0.1",
            "rustBaseUrl": "http://127.0.0.1:4731/api/v1",
            "mfcBaseUrl": "http://127.0.0.1:4732/api/v1",
        },
        "vpn": {
            "topology": "full-tunnel",
            "adapterUp": True,
            "routesThroughHideMe": True,
            "guardMode": "block",
            "guardConfig": str(tmp_path / "vpn.json"),
        },
        "storage": {
            "feasible": True,
            "deletionCount": 0,
            "deletionBytes": 0,
            "protectedFileCount": 0,
        },
    }


def diagnostic_writer_health(
    *, client: str = "rust", active_segment_id: int = 0, records_written: int = 1
) -> dict[str, object]:
    prefix = "emulebb-rust" if client == "rust" else "emulebb-mfc"
    return {
        "schema": "diag_event_v2",
        "enabled": True,
        "configured": True,
        "initialized": True,
        "runId": "run-a",
        "processId": 42,
        "activeSegmentId": active_segment_id,
        "activeFileName": (f"{prefix}-diag-42-run-a-{active_segment_id:06}.jsonl"),
        "activeSegmentBytes": 10,
        "recordsWritten": records_written,
        "bytesWritten": 10,
        "droppedEvents": 0,
        "encodeErrors": 0,
        "writeErrors": 0,
        "rotations": active_segment_id,
        "retentionDeletes": 0,
        "retentionDeleteErrors": 0,
        "retentionScanErrors": 0,
        "freeSpaceProbeErrors": 0,
        "retentionPolicyErrors": 0,
        "storagePolicyDrops": 0,
        "storageFaultDrops": 0,
        "retentionLimitDrops": 0,
        "aggregateLimitDrops": 0,
        "minimumFreeSpaceDrops": 0,
        "writerFaultDrops": 0,
        "retainedSegmentCount": 1,
        "retainedBytes": 10,
        "availableBytes": 10_000,
        "storageAuthorityFaulted": False,
        "writerIoFaulted": False,
        "storageBlockReason": None,
        "storagePolicySatisfied": True,
        "maximumGrowthBytes": 100,
        "maxSegmentBytes": 100,
        "maxSegmentSeconds": 60,
        "retainedSegments": 2,
        "maxTotalBytes": 200,
        "maxRetainedSeconds": 3_600,
        "minimumFreeBytes": 500,
        "initializationFailure": None,
    }


def diagnostic_record(
    *, client: str, segment_id: int, sequence: int, severity: str = "info"
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "client": client,
        "processId": 42,
        "runId": "run-a",
        "segmentId": segment_id,
        "seq": sequence,
        "streamSeq": sequence,
        "family": "ed2k_tcp",
        "event": "packet",
        "severity": severity,
        "keys": {"protocolMarker": 0xE3, "opcode": 1},
        "body": {
            "direction": "send",
            "protocolMarker": 0xE3,
            "opcode": 1,
            "opcodeName": "OP_01",
        },
    }


def healthy_rest_health() -> dict[str, object]:
    return {
        "ok": True,
        "responseType": "dict",
        "vpnGuard": {
            "ok": True,
            "health": {
                "enabled": True,
                "mode": "block",
                "allowedPublicIpCidrs": "149.88.27.0/24",
                "startupBlocked": False,
            },
            "violations": [],
        },
        "p2pBinding": {
            "ok": True,
            "health": {
                "activeInterfaceName": "hide.me",
                "resolveResult": "resolved",
            },
            "violations": [],
        },
    }


def storage_context_manifest(
    tmp_path: Path,
    *,
    previous_campaign: Path | None = None,
) -> tuple[Path, dict[str, object]]:
    output_root = tmp_path / "output"
    root = controller.campaign_storage_root(output_root)
    active_campaign = root / "20261025T120000Z"
    policy = storage_policy()
    return output_root, {
        "campaignId": active_campaign.name,
        "storage": controller.session_storage_manifest(
            root=root,
            policy=policy,
            active_campaign=active_campaign,
            previous_campaign=previous_campaign,
            preflight_plan={"feasible": True},
            launch_enforcement={"withinLimits": True},
        ),
    }


def test_session_storage_context_round_trips_previous_campaign(tmp_path: Path) -> None:
    previous_campaign = (
        controller.campaign_storage_root(tmp_path / "output") / "20261024T120000Z"
    )
    output_root, manifest = storage_context_manifest(
        tmp_path,
        previous_campaign=previous_campaign,
    )

    context = controller.parse_session_storage_context(manifest, output_root)

    assert context.root == controller.campaign_storage_root(output_root)
    assert context.active_campaign.name == "20261025T120000Z"
    assert context.previous_campaign == previous_campaign
    assert context.policy_sha256 == soak_storage.storage_policy_sha256(context.policy)


def test_session_storage_context_rejects_policy_tampering(tmp_path: Path) -> None:
    output_root, manifest = storage_context_manifest(tmp_path)
    storage = manifest["storage"]
    assert isinstance(storage, dict)
    policy = storage["policy"]
    assert isinstance(policy, dict)
    policy["max_total_bytes"] = 2_000

    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        controller.parse_session_storage_context(manifest, output_root)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("root", "outside", "root mismatch"),
        ("activeCampaignDir", "outside", "escaped its storage root"),
        ("preflightPlan", [], "preflight plan is invalid"),
        ("launchEnforcement", [], "launch enforcement is invalid"),
    ],
)
def test_session_storage_context_rejects_invalid_authority(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    output_root, manifest = storage_context_manifest(tmp_path)
    storage = manifest["storage"]
    assert isinstance(storage, dict)
    storage[field] = str(tmp_path / value) if value == "outside" else value

    with pytest.raises(RuntimeError, match=message):
        controller.parse_session_storage_context(manifest, output_root)


def test_session_storage_context_rejects_missing_or_unknown_fields(tmp_path: Path) -> None:
    output_root, manifest = storage_context_manifest(tmp_path)
    storage = manifest["storage"]
    assert isinstance(storage, dict)
    del storage["launchEnforcement"]
    storage["unexpected"] = True

    with pytest.raises(RuntimeError, match=r"missing=launchEnforcement unknown=unexpected"):
        controller.parse_session_storage_context(manifest, output_root)


def test_session_storage_enforcement_protects_active_and_previous_campaigns(
    tmp_path: Path,
) -> None:
    root = controller.campaign_storage_root(tmp_path / "output")
    active_campaign = root / "20261025T120000Z"
    previous_campaign = root / "20261024T120000Z"
    old_campaign = root / "20261023T120000Z"
    active_file = active_campaign / "active.log"
    previous_file = previous_campaign / "previous.log"
    old_file = old_campaign / "old.log"
    for path, contents in (
        (active_file, b"active"),
        (previous_file, b"previous"),
        (old_file, b"old artifact"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
    policy = storage_policy(max_total_bytes=20)
    context = controller.SessionStorageContext(
        root=root,
        policy=policy,
        policy_sha256=soak_storage.storage_policy_sha256(policy),
        active_campaign=active_campaign,
        previous_campaign=previous_campaign,
    )

    result = controller.enforce_session_storage_context(context)

    assert result["ok"] is True
    assert result["enforcement"]["deletedCount"] == 1
    assert active_file.is_file()
    assert previous_file.is_file()
    assert not old_file.exists()


def test_session_storage_enforcement_reports_unprunable_active_growth(tmp_path: Path) -> None:
    root = controller.campaign_storage_root(tmp_path / "output")
    active_campaign = root / "20261025T120000Z"
    active_file = active_campaign / "active.log"
    active_file.parent.mkdir(parents=True)
    active_file.write_bytes(b"active")
    policy = storage_policy(max_total_bytes=5)
    context = controller.SessionStorageContext(
        root=root,
        policy=policy,
        policy_sha256=soak_storage.storage_policy_sha256(policy),
        active_campaign=active_campaign,
        previous_campaign=None,
    )

    result = controller.enforce_session_storage_context(context)

    assert result["ok"] is False
    assert result["errorType"] == "StoragePolicyUnsatisfied"
    assert result["error"] == "max_total_bytes"
    assert active_file.is_file()


def test_advance_diagnostic_indexes_persists_and_resumes_both_clients(
    tmp_path: Path,
) -> None:
    root = controller.campaign_storage_root(tmp_path / "output")
    active_campaign = root / "20261025T120000Z"
    policy = storage_policy(
        max_total_bytes=1_000_000,
        index_max_bytes=64 * 1024,
        pin_max_bytes=64 * 1024,
        pin_retained=2,
    )
    context = controller.SessionStorageContext(
        root=root,
        policy=policy,
        policy_sha256=soak_storage.storage_policy_sha256(policy),
        active_campaign=active_campaign,
        previous_campaign=None,
    )
    profiles = {
        "rust": tmp_path / "rust-profile",
        "mfc": tmp_path / "mfc-profile",
    }
    diagnostic_dirs = {
        "rust": profiles["rust"] / "packet-dump",
        "mfc": profiles["mfc"] / "logs",
    }
    for client, profile in profiles.items():
        profile.mkdir()
        diagnostic_dir = diagnostic_dirs[client]
        diagnostic_dir.mkdir()
        prefix = "emulebb-rust" if client == "rust" else "emulebb-mfc"
        segment = diagnostic_dir / f"{prefix}-diag-42-run-a-000000.jsonl"
        segment.write_text(
            json.dumps(
                diagnostic_record(
                    client=client,
                    segment_id=0,
                    sequence=1,
                    severity="warning" if client == "rust" else "info",
                )
            )
            + "\n",
            encoding="utf-8",
        )
    status = {
        "timestampUtc": "2026-10-25T12:00:00+00:00",
        "profiles": {client: str(path) for client, path in profiles.items()},
        "diagnosticDirs": {
            client: str(path) for client, path in diagnostic_dirs.items()
        },
        "diagnosticWriters": {
            "required": True,
            "rust": {
                "ok": True,
                "health": diagnostic_writer_health(
                    client="rust", active_segment_id=1, records_written=1
                ),
                "violations": [],
            },
            "mfc": {
                "ok": True,
                "health": diagnostic_writer_health(
                    client="mfc", active_segment_id=1, records_written=1
                ),
                "violations": [],
            },
        },
    }

    first = controller.advance_diagnostic_indexes(status, context)
    status["timestampUtc"] = "2026-10-25T12:01:00+00:00"
    second = controller.advance_diagnostic_indexes(status, context)

    assert first["required"] is True
    for client in ("rust", "mfc"):
        first_client = first[client]
        second_client = second[client]
        assert first_client["coverage"] == "from-run-start"
        assert first_client["closedSegmentCount"] == 1
        assert first_client["recordCount"] == 1
        assert [item["segmentId"] for item in first_client["processedSegments"]] == [0]
        assert second_client["processedSegments"] == []
        assert second_client["writerHealthSamples"] == 2
        checkpoint = json.loads(
            Path(second_client["checkpoint"]).read_text(encoding="utf-8")
        )
        assert checkpoint["client"] == client
        assert checkpoint["index"]["recordCount"] == 1
    assert len(first["rust"]["evidencePins"]) == 1
    assert first["rust"]["evidencePins"][0]["reasons"] == ["severity:warning"]
    assert Path(first["rust"]["evidencePins"][0]["destination"]).is_file()
    assert first["mfc"]["evidencePins"] == []


def test_reconcile_diagnostic_evidence_pins_keeps_highest_value_segments(
    tmp_path: Path,
) -> None:
    root = controller.campaign_storage_root(tmp_path / "output")
    campaign = root / "20261025T120000Z"
    policy = storage_policy(
        max_total_bytes=1_000_000,
        pin_max_bytes=1_024,
        pin_retained=2,
    )
    context = controller.SessionStorageContext(
        root=root,
        policy=policy,
        policy_sha256=soak_storage.storage_policy_sha256(policy),
        active_campaign=campaign,
        previous_campaign=None,
    )
    profile = tmp_path / "profile"
    profile.mkdir()

    def metadata(segment_id: int, reasons: list[str]) -> dict[str, object]:
        source = profile / f"emulebb-rust-diag-42-run-a-{segment_id:06}.jsonl"
        payload = f"segment-{segment_id}".encode()
        source.write_bytes(payload)
        return {
            "segmentId": segment_id,
            "fileName": source.name,
            "source": str(source.resolve()),
            "bytes": len(payload),
            "modifiedNs": source.stat().st_mtime_ns,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "recordCount": 1,
            "interestingReasons": reasons,
        }

    processed = (
        metadata(0, ["severity:warning"]),
        metadata(1, []),
        metadata(2, ["severity:critical"]),
    )
    checkpoint = {"evidencePins": []}

    result = controller.reconcile_diagnostic_evidence_pins(
        client="rust",
        checkpoint=checkpoint,
        prior_checkpoint=None,
        processed_segments=processed,
        context=context,
        observed_utc="2026-10-25T12:00:00+00:00",
    )

    assert [pin["segmentId"] for pin in result["pins"]] == [0, 2]
    assert [pin["priority"] for pin in result["pins"]] == [300, 400]
    assert any(
        action["action"] == "replaced" and action["replacedSegmentId"] == 1
        for action in result["actions"]
    )
    controller._finalize_diagnostic_evidence_pin_swaps(result["pendingCleanup"])
    destination = campaign / "archive" / "diagnostic-pins" / "rust"
    assert sorted(path.name for path in destination.glob("*.jsonl")) == [
        "emulebb-rust-diag-42-run-a-000000.jsonl",
        "emulebb-rust-diag-42-run-a-000002.jsonl",
    ]
    assert not list(destination.glob("*.tmp"))


def test_diagnostic_evidence_pin_recovery_restores_checkpoint_manifest(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "diagnostic-pins" / "rust"
    directory.mkdir(parents=True)
    victim = directory / "emulebb-rust-diag-42-run-a-000000.jsonl"
    victim.write_bytes(b"checkpoint-segment")
    backup = victim.with_name(f".{victim.name}.pin-swap.tmp")
    victim.replace(backup)
    orphan = directory / "emulebb-rust-diag-42-run-a-000001.jsonl"
    orphan.write_bytes(b"uncommitted-segment")
    manifest = [
        {
            "segmentId": 0,
            "fileName": victim.name,
            "source": str((tmp_path / victim.name).resolve()),
            "destination": str(victim.resolve()),
            "bytes": len(b"checkpoint-segment"),
            "sha256": hashlib.sha256(b"checkpoint-segment").hexdigest(),
            "priority": 300,
            "reasons": ["severity:warning"],
            "pinnedUtc": "2026-10-25T12:00:00+00:00",
        }
    ]

    controller._recover_diagnostic_evidence_pin_swaps(
        manifest,
        directory=directory.resolve(),
        retained_segments=1,
    )

    assert victim.read_bytes() == b"checkpoint-segment"
    assert not backup.exists()
    assert not orphan.exists()


def test_diagnostic_evidence_pin_recovery_keeps_committed_manifest(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "diagnostic-pins" / "rust"
    directory.mkdir(parents=True)
    committed = directory / "emulebb-rust-diag-42-run-a-000001.jsonl"
    committed.write_bytes(b"committed-segment")
    replaced_name = "emulebb-rust-diag-42-run-a-000000.jsonl"
    backup = directory / f".{replaced_name}.pin-swap.tmp"
    backup.write_bytes(b"replaced-segment")
    manifest = [
        {
            "segmentId": 1,
            "fileName": committed.name,
            "source": str((tmp_path / committed.name).resolve()),
            "destination": str(committed.resolve()),
            "bytes": len(b"committed-segment"),
            "sha256": hashlib.sha256(b"committed-segment").hexdigest(),
            "priority": 400,
            "reasons": ["severity:critical"],
            "pinnedUtc": "2026-10-25T12:01:00+00:00",
        }
    ]

    controller._recover_diagnostic_evidence_pin_swaps(
        manifest,
        directory=directory.resolve(),
        retained_segments=1,
    )

    assert committed.read_bytes() == b"committed-segment"
    assert not backup.exists()


def test_reconcile_diagnostic_evidence_pins_restores_victim_on_copy_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = controller.campaign_storage_root(tmp_path / "output")
    campaign = root / "20261025T120000Z"
    policy = storage_policy(
        max_total_bytes=1_000_000,
        pin_max_bytes=1_024,
        pin_retained=1,
    )
    context = controller.SessionStorageContext(
        root=root,
        policy=policy,
        policy_sha256=soak_storage.storage_policy_sha256(policy),
        active_campaign=campaign,
        previous_campaign=None,
    )
    profile = tmp_path / "profile"
    profile.mkdir()

    def metadata(segment_id: int, severity: str) -> dict[str, object]:
        source = profile / f"emulebb-rust-diag-42-run-a-{segment_id:06}.jsonl"
        payload = f"segment-{segment_id}".encode()
        source.write_bytes(payload)
        return {
            "segmentId": segment_id,
            "fileName": source.name,
            "source": str(source.resolve()),
            "bytes": len(payload),
            "modifiedNs": source.stat().st_mtime_ns,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "recordCount": 1,
            "interestingReasons": [f"severity:{severity}"],
        }

    initial = controller.reconcile_diagnostic_evidence_pins(
        client="rust",
        checkpoint={"evidencePins": []},
        prior_checkpoint=None,
        processed_segments=(metadata(0, "warning"),),
        context=context,
        observed_utc="2026-10-25T12:00:00+00:00",
    )
    candidate = metadata(1, "critical")

    def reject_copy(**_kwargs):
        raise RuntimeError("copy failed")

    monkeypatch.setattr(
        controller.soak_storage,
        "persist_bounded_file_artifact",
        reject_copy,
    )

    with pytest.raises(RuntimeError, match="copy failed"):
        controller.reconcile_diagnostic_evidence_pins(
            client="rust",
            checkpoint={"evidencePins": initial["pins"]},
            prior_checkpoint=None,
            processed_segments=(candidate,),
            context=context,
            observed_utc="2026-10-25T12:01:00+00:00",
        )

    victim = Path(initial["pins"][0]["destination"])
    assert victim.is_file()
    assert victim.read_bytes() == b"segment-0"
    assert not list(victim.parent.glob("*.tmp"))


def test_build_launch_command_is_until_stopped_dual_diagnostics(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    config = controller.SessionConfig(
        inputs=tmp_path / "inputs.json",
        vpn_guard_config=tmp_path / "vpn.json",
    )

    command = controller.build_launch_command(
        config,
        paths,
        campaign_id="20261025T120000Z",
    )

    assert command[1].endswith("scripts\\launch-soak.py")
    assert command[command.index("--vpn-topology") + 1] == "full-tunnel"
    assert command[command.index("--lan-bind-addr") + 1] == "127.0.0.1"
    assert command[command.index("--duration-seconds") + 1] == "0"
    assert command[command.index("--campaign-id") + 1] == "20261025T120000Z"
    assert command[command.index("--stop-file") + 1] == str(paths.stop_file)
    assert "--vpn-guard-scenario" in command
    assert "success" in command
    assert "--reuse-rust-shared-profile" in command
    assert "--reuse-kad-bootstrap" in command
    assert "--no-mfc" not in command
    assert "--rust-regular" not in command
    assert "--cpu-profile" not in command


def test_bounded_process_command_preserves_policy_paths_and_target(tmp_path: Path) -> None:
    command = controller.build_bounded_process_command(
        ["python", "target.py", "--flag"],
        stdout_path=tmp_path / "stdout.log",
        stderr_path=tmp_path / "stderr.log",
        policy=soak_storage.ArtifactStreamPolicy(
            max_segment_bytes=128,
            retained_segments=3,
        ),
        stop_files=(tmp_path / "stop", tmp_path / "watch.stop"),
    )

    assert Path(command[1]).name == "run-bounded-process.py"
    assert command[command.index("--max-segment-bytes") + 1] == "128"
    assert command[command.index("--retained-segments") + 1] == "3"
    assert command.count("--stop-file") == 2
    assert command[-3:] == ["python", "target.py", "--flag"]


def test_build_observer_action_config_resolves_exact_manifest_terms(tmp_path: Path) -> None:
    inputs = live_inputs(tmp_path, policy=storage_policy())

    fallback = controller.build_observer_action_config(
        inputs,
        enabled=True,
        terms=(),
        methods=("server", "kad"),
        start_delay_seconds=30,
        search_interval_seconds=900,
        search_timeout_seconds=120,
        max_cycles=12,
    )
    explicit = controller.build_observer_action_config(
        inputs,
        enabled=True,
        terms=("Exact Local Term", "Exact Local Term", "debian"),
        methods=("global",),
        start_delay_seconds=60,
        search_interval_seconds=1_800,
        search_timeout_seconds=180,
        max_cycles=0,
    )

    assert fallback == {
        "enabled": True,
        "sourceProfile": "generic_open",
        "terms": ["linux"],
        "methods": ["server", "kad"],
        "startDelaySeconds": 30.0,
        "searchIntervalSeconds": 900.0,
        "searchTimeoutSeconds": 120.0,
        "maxCycles": 12,
    }
    assert explicit["sourceProfile"] == "explicit"
    assert explicit["terms"] == ["Exact Local Term", "debian"]


def test_exact_process_row_rejects_pid_reuse() -> None:
    rows = [
        WindowsProcessInfo(
            pid=123,
            parent_pid=1,
            name="python.exe",
            command_line="python launch-soak.py",
            creation_date="new",
        )
    ]

    assert controller.exact_process_row({"pid": 123, "creationDate": "old"}, rows) is None
    assert controller.exact_process_row({"pid": 123, "creationDate": "new"}, rows) == rows[0]
    assert controller.exact_process_row(None, rows) is None


def test_start_session_records_launcher_observer_and_watcher_identities(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root = tmp_path / "output"
    output_root.mkdir()
    config = controller.SessionConfig(
        inputs=tmp_path / "inputs.json",
        vpn_guard_config=tmp_path / "vpn.json",
    )
    loaded_inputs = live_inputs(tmp_path, policy=storage_policy())
    input_loads: list[Path] = []
    observed_inputs: list[LiveWireInputs] = []
    spawned: list[list[str]] = []

    class FakeProcess:
        def __init__(self, pid: int) -> None:
            self.pid = pid
            self.terminated = False

        def poll(self):
            return None

        def terminate(self) -> None:
            self.terminated = True

    def fake_spawn(command: list[str], **_kwargs) -> FakeProcess:
        spawned.append(command)
        return FakeProcess(100 + len(spawned))

    def fake_identity(pid: int, *, markers: tuple[str, ...], timeout_seconds: float = 10.0):
        del timeout_seconds
        return WindowsProcessInfo(
            pid=pid,
            parent_pid=1,
            name="python.exe",
            command_line=" ".join(markers),
            creation_date=f"created-{pid}",
        )

    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(
        controller,
        "load_live_wire_inputs",
        lambda path: input_loads.append(path) or loaded_inputs,
    )

    def fake_preflight(_config, _root, *, inputs, **_kwargs):
        observed_inputs.append(inputs)
        return preflight_payload(tmp_path)

    def fake_enforcement(inputs, *_args, **_kwargs):
        observed_inputs.append(inputs)
        return {"withinLimits": True}

    monkeypatch.setattr(
        controller,
        "preflight_session",
        fake_preflight,
    )
    monkeypatch.setattr(
        controller,
        "enforce_campaign_storage",
        fake_enforcement,
    )
    monkeypatch.setattr(
        controller.soak_run_layout,
        "utc_campaign_id",
        lambda: "20261025T120000Z",
    )
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [])
    monkeypatch.setattr(controller, "spawn_detached", fake_spawn)
    monkeypatch.setattr(controller, "wait_process_identity", fake_identity)

    result = controller.start_session(
        config,
        paths,
        watch_interval_seconds=30.0,
        observer_drive_actions=True,
        observer_action_methods=("server", "kad"),
        observer_action_start_delay_seconds=30,
        observer_action_search_interval_seconds=900,
        observer_action_search_timeout_seconds=120,
        observer_action_max_cycles=12,
    )

    assert result["schema"] == controller.MANIFEST_SCHEMA
    assert result["launcher"]["pid"] == 101
    assert result["launcher"]["creationDate"] == "created-101"
    assert result["observer"]["pid"] == 102
    assert result["observer"]["creationDate"] == "created-102"
    assert result["watcher"]["pid"] == 103
    assert result["watcher"]["creationDate"] == "created-103"
    assert result["campaignId"] == "20261025T120000Z"
    assert result["storage"]["launchEnforcement"]["withinLimits"] is True
    assert result["observerConfig"]["actionDriving"] == {
        "enabled": True,
        "sourceProfile": "generic_open",
        "terms": ["linux"],
        "methods": ["server", "kad"],
        "startDelaySeconds": 30.0,
        "searchIntervalSeconds": 900.0,
        "searchTimeoutSeconds": 120.0,
        "maxCycles": 12,
    }
    storage_context = controller.parse_session_storage_context(result, output_root)
    assert storage_context.active_campaign == (
        output_root / "soak" / "campaigns" / "20261025T120000Z"
    )
    assert storage_context.previous_campaign is None
    assert storage_context.policy == loaded_inputs.soak_storage
    assert input_loads == [config.inputs.resolve()]
    assert observed_inputs == [loaded_inputs, loaded_inputs]
    assert len(spawned) == 3
    assert Path(spawned[0][1]).name == "run-bounded-process.py"
    assert any(Path(value).name == "launch-soak.py" for value in spawned[0])
    assert Path(spawned[1][1]).name == "run-bounded-process.py"
    assert any(Path(value).name == "converged-soak-observer.py" for value in spawned[1])
    assert not any(Path(value).name == "launch-soak.py" for value in spawned[1])
    assert "linux" not in result["observerTargetCommand"]
    assert Path(spawned[2][1]).name == "run-bounded-process.py"
    assert any(Path(value).name == "persisted-soak-control.py" for value in spawned[2])
    assert result["watchTargetCommand"][result["watchTargetCommand"].index("--launcher-pid") + 1] == "101"
    assert (
        result["watchTargetCommand"][
            result["watchTargetCommand"].index("--launcher-creation-date") + 1
        ]
        == "created-101"
    )
    assert result["launcher"]["commandFingerprint"] == controller.command_fingerprint(spawned[0])
    assert result["observer"]["commandFingerprint"] == controller.command_fingerprint(spawned[1])
    assert result["watcher"]["commandFingerprint"] == controller.command_fingerprint(spawned[2])
    assert result["logs"]["root"] == str(
        output_root / "soak" / "campaigns" / "20261025T120000Z" / "controller-output"
    )
    assert result["logs"]["maxSegmentBytes"] == 1
    assert result["logs"]["retainedSegments"] == 1
    assert result["logs"]["observerStdout"].endswith("observer.stdout.log")
    persisted = json.loads(paths.manifest.read_text(encoding="utf-8"))
    assert persisted["observer"]["pid"] == 102
    assert persisted["watcher"]["pid"] == 103


def test_start_session_can_disable_optional_observer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root = tmp_path / "output"
    output_root.mkdir()
    config = controller.SessionConfig(
        inputs=tmp_path / "inputs.json",
        vpn_guard_config=tmp_path / "vpn.json",
    )
    spawned: list[list[str]] = []

    class FakeProcess:
        def __init__(self, pid: int) -> None:
            self.pid = pid

        def poll(self):
            return None

    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(
        controller,
        "load_live_wire_inputs",
        lambda _path: live_inputs(tmp_path, policy=storage_policy()),
    )
    monkeypatch.setattr(
        controller,
        "preflight_session",
        lambda *_args, **_kwargs: preflight_payload(tmp_path),
    )
    monkeypatch.setattr(
        controller,
        "enforce_campaign_storage",
        lambda *_args, **_kwargs: {"withinLimits": True},
    )
    monkeypatch.setattr(
        controller.soak_run_layout,
        "utc_campaign_id",
        lambda: "20261025T120000Z",
    )
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [])

    def fake_spawn(command: list[str], **_kwargs) -> FakeProcess:
        spawned.append(command)
        return FakeProcess(100 + len(spawned))

    monkeypatch.setattr(controller, "spawn_detached", fake_spawn)
    monkeypatch.setattr(
        controller,
        "wait_process_identity",
        lambda pid, **_kwargs: WindowsProcessInfo(
            pid,
            1,
            "python.exe",
            "python",
            f"created-{pid}",
        ),
    )

    result = controller.start_session(config, paths, start_observer=False)

    assert result["observer"] is None
    assert result["observerConfig"]["enabled"] is False
    assert result["observerConfig"]["actionDriving"]["enabled"] is False
    assert result["observerConfig"]["actionDriving"]["terms"] == []
    assert len(spawned) == 2
    assert not any(
        Path(value).name == "converged-soak-observer.py"
        for command in spawned
        for value in command
    )


def test_observer_start_failure_stops_launcher_and_persists_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root = tmp_path / "output"
    output_root.mkdir()
    config = controller.SessionConfig(
        inputs=tmp_path / "inputs.json",
        vpn_guard_config=tmp_path / "vpn.json",
    )
    processes: list[FakeProcess] = []
    stopped: list[tuple[object, tuple[str, ...]]] = []

    class FakeProcess:
        def __init__(self, pid: int) -> None:
            self.pid = pid
            self.terminated = False

        def poll(self):
            return None

        def terminate(self) -> None:
            self.terminated = True

    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(
        controller,
        "load_live_wire_inputs",
        lambda _path: live_inputs(tmp_path, policy=storage_policy()),
    )
    monkeypatch.setattr(
        controller,
        "preflight_session",
        lambda *_args, **_kwargs: preflight_payload(tmp_path),
    )
    monkeypatch.setattr(
        controller,
        "enforce_campaign_storage",
        lambda *_args, **_kwargs: {"withinLimits": True},
    )
    monkeypatch.setattr(
        controller.soak_run_layout,
        "utc_campaign_id",
        lambda: "20261025T120000Z",
    )
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [])

    def fake_spawn(_command: list[str], **_kwargs) -> FakeProcess:
        process = FakeProcess(101 + len(processes))
        processes.append(process)
        return process

    def fake_identity(pid: int, *, markers: tuple[str, ...], **_kwargs):
        if markers == ("converged-soak-observer.py",):
            raise RuntimeError("observer identity unavailable")
        return WindowsProcessInfo(pid, 1, "python.exe", "python", f"created-{pid}")

    monkeypatch.setattr(controller, "spawn_detached", fake_spawn)
    monkeypatch.setattr(controller, "wait_process_identity", fake_identity)
    monkeypatch.setattr(
        controller,
        "stop_owned_process",
        lambda identity, *, markers, **_kwargs: stopped.append((identity, markers))
        or {"graceful": True, "force": {"forced": False}},
    )

    with pytest.raises(RuntimeError, match="observer identity unavailable"):
        controller.start_session(config, paths)

    assert len(processes) == 2
    assert processes[1].terminated is True
    assert stopped[0][0]["pid"] == 101
    assert stopped[0][1] == ("launch-soak.py",)
    persisted = json.loads(paths.manifest.read_text(encoding="utf-8"))
    assert persisted["state"] == "start-failed"
    assert persisted["startFailure"]["role"] == "observer"
    assert paths.stop_file.is_file()


def test_start_session_enforces_storage_before_control_mutation_or_spawn(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root = tmp_path / "output"
    config = controller.SessionConfig(
        inputs=tmp_path / "inputs.json",
        vpn_guard_config=tmp_path / "vpn.json",
    )
    spawned = False

    def reject_storage(*_args, **_kwargs):
        raise RuntimeError("reserve verification failed")

    def reject_spawn(*_args, **_kwargs):
        nonlocal spawned
        spawned = True
        raise AssertionError("spawn must not be reached")

    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(
        controller,
        "load_live_wire_inputs",
        lambda _path: live_inputs(tmp_path, policy=storage_policy()),
    )
    monkeypatch.setattr(
        controller,
        "preflight_session",
        lambda _config, _root, **_kwargs: preflight_payload(tmp_path),
    )
    monkeypatch.setattr(controller, "enforce_campaign_storage", reject_storage)
    monkeypatch.setattr(controller, "spawn_detached", reject_spawn)
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [])
    monkeypatch.setattr(
        controller.soak_run_layout,
        "utc_campaign_id",
        lambda: "20261025T120000Z",
    )

    with pytest.raises(RuntimeError, match="reserve verification failed"):
        controller.start_session(config, paths)

    assert spawned is False
    assert not paths.control_dir.exists()


def test_start_session_rejects_invalid_watch_budget_before_preflight(tmp_path: Path, monkeypatch) -> None:
    paths = make_paths(tmp_path)
    config = controller.SessionConfig(inputs=tmp_path / "inputs.json", vpn_guard_config=tmp_path / "vpn.json")
    preflight_called = False

    def fake_preflight(_config, _output_root):
        nonlocal preflight_called
        preflight_called = True

    monkeypatch.setattr(controller, "preflight_session", fake_preflight)

    with pytest.raises(ValueError, match="watch_max_bytes"):
        controller.start_session(config, paths, watch_max_bytes=0)

    assert preflight_called is False


def test_start_session_rejects_action_driving_without_observer_before_preflight(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    config = controller.SessionConfig(
        inputs=tmp_path / "inputs.json",
        vpn_guard_config=tmp_path / "vpn.json",
    )
    preflight_called = False

    def fake_preflight(*_args, **_kwargs):
        nonlocal preflight_called
        preflight_called = True

    monkeypatch.setattr(controller, "preflight_session", fake_preflight)

    with pytest.raises(ValueError, match="requires the converged observer"):
        controller.start_session(
            config,
            paths,
            start_observer=False,
            observer_drive_actions=True,
        )

    assert preflight_called is False


def test_start_parser_accepts_observer_action_schedule() -> None:
    args = controller.build_parser().parse_args(
        [
            "start",
            "--observer-drive-actions",
            "--observer-action-term",
            "Exact Local Term",
            "--observer-action-method",
            "server",
            "--observer-action-method",
            "kad",
            "--observer-action-start-delay-seconds",
            "30",
            "--observer-action-search-interval-seconds",
            "900",
            "--observer-action-search-timeout-seconds",
            "120",
            "--observer-action-max-cycles",
            "12",
        ]
    )

    assert args.observer_drive_actions is True
    assert args.observer_action_term == ["Exact Local Term"]
    assert args.observer_action_methods == ["server", "kad"]
    assert args.observer_action_start_delay_seconds == 30
    assert args.observer_action_search_interval_seconds == 900
    assert args.observer_action_search_timeout_seconds == 120
    assert args.observer_action_max_cycles == 12


def test_preflight_parser_uses_shared_session_selection() -> None:
    args = controller.build_parser().parse_args(
        [
            "preflight",
            "--inputs",
            "operator-inputs.json",
            "--vpn-guard-live-config",
            "operator-vpn.json",
            "--lan-bind-addr",
            "127.0.0.1",
            "--mfc-variant",
            "emulebb-main",
        ]
    )

    config = controller.session_config_from_args(args)

    assert config.inputs == Path("operator-inputs.json")
    assert config.vpn_guard_config == Path("operator-vpn.json")
    assert config.lan_bind_addr == controller.DEFAULT_CONTROL_BIND
    assert config.mfc_variant == "emulebb-main"


def test_preflight_command_reports_existing_preflight_without_launch(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    output_root = tmp_path / "output"
    expected = preflight_payload(tmp_path)
    launched = False

    def reject_launch(*_args, **_kwargs):
        nonlocal launched
        launched = True
        raise AssertionError("preflight must not launch the soak")

    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "preflight_session", lambda *_args, **_kwargs: expected)
    monkeypatch.setattr(controller, "start_session", reject_launch)

    assert controller.main(["preflight"]) == 0
    assert json.loads(capsys.readouterr().out) == expected
    assert launched is False


def test_session_status_reports_exact_dual_process_tree(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    preflight = preflight_payload(tmp_path)
    controller.write_json_atomic(
        paths.manifest,
        {
            "schema": controller.MANIFEST_SCHEMA,
            "state": "running",
            "launcher": {"pid": 10, "creationDate": "launcher"},
            "observer": {"pid": 30, "creationDate": "observer"},
            "observerConfig": {"enabled": True},
            "watcher": {"pid": 20, "creationDate": "watcher"},
            "preflight": preflight,
        },
    )
    controller.write_json_atomic(paths.last_run_manifest, {"campaignId": "20261024T120000Z", "status": "starting"})
    processes = [
        WindowsProcessInfo(10, 1, "python.exe", "python run-bounded-process.py -- launch-soak.py", "launcher"),
        WindowsProcessInfo(13, 10, "python.exe", "python launch-soak.py", "launch-target"),
        WindowsProcessInfo(11, 13, "emulebb-rust-diagnostics.exe", "rust", "rust"),
        WindowsProcessInfo(12, 13, "emule.exe", "mfc", "mfc"),
        WindowsProcessInfo(
            30,
            1,
            "python.exe",
            "python run-bounded-process.py -- converged-soak-observer.py",
            "observer",
        ),
        WindowsProcessInfo(
            20,
            1,
            "python.exe",
            "python run-bounded-process.py -- persisted-soak-control.py watch",
            "watcher",
        ),
    ]
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: processes)
    monkeypatch.setattr(controller, "rest_health", lambda _url, _key: healthy_rest_health())
    monkeypatch.setattr(
        controller,
        "diagnostic_writer_health",
        lambda _url, _key: (_ for _ in ()).throw(
            AssertionError("writer health must wait for persisted readiness")
        ),
    )
    monkeypatch.setattr(controller, "full_tunnel_health", lambda: {"ok": True})
    exact_observer_report = {
        "schema": "emulebb-build-tests.converged-soak-report.v2",
        "campaignId": "20261024T120000Z",
        "observerState": {"exact": "unredacted local evidence"},
        "retainedWindow": {},
    }
    monkeypatch.setattr(
        controller,
        "current_observer_report",
        lambda _manifest, _last_run: exact_observer_report,
    )

    result = controller.session_status(paths)

    assert result["schema"] == "emulebb.persisted-soak-status.v2"
    assert result["observerReport"] is exact_observer_report
    assert result["ok"] is True
    assert result["launcher"]["alive"] is True
    assert result["observer"]["alive"] is True
    assert result["watcher"]["alive"] is True
    assert result["clients"]["rustCount"] == 1
    assert result["clients"]["mfcCount"] == 1
    assert [row["role"] for row in result["clients"]["processes"]] == ["rust", "mfc"]
    assert all("commandLine" not in row for row in result["clients"]["processes"])
    assert result["diagnosticWriters"] == {
        "required": False,
        "rust": None,
        "mfc": None,
    }
    assert result["findings"] == []


def test_current_observer_report_loads_exact_current_campaign(
    tmp_path: Path,
    monkeypatch,
) -> None:
    campaign_id = "20261024T120000Z"
    campaign_dir = tmp_path / "soak" / "campaigns" / campaign_id
    report_dir = campaign_dir / "report"
    controller.write_json_atomic(report_dir / "summary.json", {"placeholder": True})
    exact_report = {
        "schema": "emulebb-build-tests.converged-soak-report.v2",
        "campaignId": campaign_id,
        "observerState": {"exact": "unredacted local evidence"},
        "retainedWindow": {},
    }
    calls: list[Path] = []

    def summarize_report(path: Path) -> dict[str, object]:
        calls.append(path)
        return exact_report

    monkeypatch.setattr(
        controller.soak_report_summary,
        "summarize_report",
        summarize_report,
    )

    result = controller.current_observer_report(
        {
            "campaignId": campaign_id,
            "campaignDir": str(campaign_dir),
            "observerConfig": {"enabled": True},
        },
        {
            "campaignId": campaign_id,
            "reportDir": str(report_dir),
        },
    )

    assert result is exact_report
    assert calls == [report_dir.resolve()]


def test_current_observer_report_allows_not_ready_campaign(tmp_path: Path) -> None:
    campaign_id = "20261024T120000Z"

    result = controller.current_observer_report(
        {
            "campaignId": campaign_id,
            "campaignDir": str(tmp_path / campaign_id),
            "observerConfig": {"enabled": True},
        },
        {
            "campaignId": campaign_id,
            "reportDir": str(tmp_path / campaign_id / "report"),
        },
    )

    assert result is None


def test_current_observer_report_rejects_stale_or_misdirected_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    campaign_id = "20261024T120000Z"
    campaign_dir = tmp_path / "soak" / "campaigns" / campaign_id
    report_dir = campaign_dir / "report"
    controller.write_json_atomic(report_dir / "summary.json", {"placeholder": True})
    manifest = {
        "campaignId": campaign_id,
        "campaignDir": str(campaign_dir),
        "observerConfig": {"enabled": True},
    }

    with pytest.raises(
        controller.soak_report_summary.SoakReportSummaryError,
        match="directory does not match",
    ):
        controller.current_observer_report(
            manifest,
            {
                "campaignId": campaign_id,
                "reportDir": str(tmp_path / "other" / "report"),
            },
        )

    with pytest.raises(
        controller.soak_report_summary.SoakReportSummaryError,
        match="campaign directory is unavailable",
    ):
        controller.current_observer_report(
            {
                "campaignId": campaign_id,
                "observerConfig": {"enabled": True},
            },
            {
                "campaignId": campaign_id,
                "reportDir": str(report_dir),
            },
        )

    monkeypatch.setattr(
        controller.soak_report_summary,
        "summarize_report",
        lambda _path: {
            "schema": "emulebb-build-tests.converged-soak-report.v2",
            "campaignId": "20261023T120000Z",
        },
    )
    with pytest.raises(
        controller.soak_report_summary.SoakReportSummaryError,
        match="campaign does not match",
    ):
        controller.current_observer_report(
            manifest,
            {
                "campaignId": campaign_id,
                "reportDir": str(report_dir),
            },
        )

    def reject_inconsistent_report(_path: Path) -> dict[str, object]:
        raise controller.soak_report_summary.SoakReportSummaryError(
            "exact retained-window integrity failure"
        )

    monkeypatch.setattr(
        controller.soak_report_summary,
        "summarize_report",
        reject_inconsistent_report,
    )
    with pytest.raises(
        controller.soak_report_summary.SoakReportSummaryError,
        match="exact retained-window integrity failure",
    ):
        controller.current_observer_report(
            manifest,
            {
                "campaignId": campaign_id,
                "reportDir": str(report_dir),
            },
        )


def test_diagnostic_writer_health_retains_complete_strict_payload(
    monkeypatch,
) -> None:
    health = diagnostic_writer_health()
    calls: list[tuple[str, str, str]] = []

    def fake_http_json(base_url, path, *, api_key, timeout_seconds):
        assert timeout_seconds == 5.0
        calls.append((base_url, path, api_key))
        return {"data": {"diagnosticWriter": health}}

    monkeypatch.setattr(controller, "http_json", fake_http_json)

    result = controller.diagnostic_writer_health("http://127.0.0.1/api/v1", "key")

    assert result == {
        "reachable": True,
        "ok": True,
        "health": health,
        "violations": [],
    }
    assert calls == [("http://127.0.0.1/api/v1", "/diagnostics", "key")]

    health["writeErrors"] = 1
    result = controller.diagnostic_writer_health("http://127.0.0.1/api/v1", "key")
    assert result["ok"] is False
    assert result["reachable"] is True
    assert result["health"] == health
    assert "writeErrors=1 expected 0" in result["violations"]

    monkeypatch.setattr(
        controller,
        "http_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("offline")),
    )
    result = controller.diagnostic_writer_health("http://127.0.0.1/api/v1", "key")
    assert result == {
        "reachable": False,
        "ok": False,
        "health": None,
        "violations": ["TimeoutError: offline"],
    }


def test_rest_health_requires_blocking_guard_and_hide_me_binding(monkeypatch) -> None:
    status = {
        "network": {
            "vpnGuard": {
                "enabled": True,
                "mode": "block",
                "allowedPublicIpCidrs": "149.88.27.0/24",
                "startupBlocked": False,
            },
            "binding": {
                "activeInterfaceName": "hide.me",
                "resolveResult": "resolved",
            },
        }
    }
    monkeypatch.setattr(
        controller,
        "http_json",
        lambda *_args, **_kwargs: {"data": status},
    )

    result = controller.rest_health("http://127.0.0.1/api/v1", "key")

    assert result == healthy_rest_health()

    status["network"]["vpnGuard"]["mode"] = "off"
    status["network"]["binding"]["activeInterfaceName"] = "Ethernet"
    result = controller.rest_health("http://127.0.0.1/api/v1", "key")
    assert result["ok"] is True
    assert result["vpnGuard"]["ok"] is False
    assert result["p2pBinding"]["ok"] is False


def test_session_status_requires_both_writers_after_persisted_readiness(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    campaign_id = "20261024T120000Z"
    controller.write_json_atomic(
        paths.manifest,
        {
            "schema": controller.MANIFEST_SCHEMA,
            "state": "running",
            "campaignId": campaign_id,
            "launcher": {"pid": 10, "creationDate": "launcher"},
            "preflight": preflight_payload(tmp_path),
        },
    )
    controller.write_json_atomic(
        paths.last_run_manifest,
        {"campaignId": campaign_id, "status": "running"},
    )
    processes = [
        WindowsProcessInfo(10, 1, "python.exe", "launcher", "launcher"),
        WindowsProcessInfo(11, 10, "emulebb-rust-diagnostics.exe", "rust", "rust"),
        WindowsProcessInfo(12, 10, "emule.exe", "mfc", "mfc"),
    ]
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: processes)
    monkeypatch.setattr(controller, "rest_health", lambda _url, _key: healthy_rest_health())
    monkeypatch.setattr(controller, "full_tunnel_health", lambda: {"ok": True})

    def fake_writer_health(_url: str, key: str) -> dict[str, object]:
        if key == controller.soak_launch.RUST_API_KEY:
            return {
                "reachable": True,
                "ok": True,
                "health": diagnostic_writer_health(),
                "violations": [],
            }
        return {
            "reachable": True,
            "ok": False,
            "health": diagnostic_writer_health(),
            "violations": ["writeErrors=1 expected 0"],
        }

    monkeypatch.setattr(controller, "diagnostic_writer_health", fake_writer_health)

    result = controller.session_status(paths)

    assert result["diagnosticWriters"]["required"] is True
    assert result["diagnosticWriters"]["rust"]["ok"] is True
    assert result["diagnosticWriters"]["mfc"]["ok"] is False
    assert "mfc-diagnostic-writer-unhealthy" in result["findings"]


def test_status_findings_distinguishes_writer_transport_from_integrity() -> None:
    status = {
        "launcher": {"alive": True},
        "manifest": {"state": "running"},
        "watcher": {},
        "clients": {"rustCount": 1, "mfcCount": 1},
        "rest": {
            "rust": healthy_rest_health(),
            "mfc": healthy_rest_health(),
        },
        "diagnosticWriters": {
            "required": True,
            "rust": {
                "reachable": False,
                "ok": False,
                "health": None,
                "violations": ["TimeoutError: offline"],
            },
            "mfc": {
                "reachable": True,
                "ok": False,
                "health": diagnostic_writer_health(),
                "violations": ["writeErrors=1 expected 0"],
            },
        },
        "vpn": {"ok": True},
        "lastRun": {"status": "running"},
        "storage": {"ok": True},
    }

    findings = controller.status_findings(status)

    assert "rust-diagnostic-writer-unavailable" in findings
    assert "rust-diagnostic-writer-unhealthy" not in findings
    assert "mfc-diagnostic-writer-unhealthy" in findings


def test_status_findings_scopes_launcher_failure_to_current_campaign() -> None:
    status = {
        "launcher": {"alive": True},
        "manifest": {"state": "running", "campaignId": "current"},
        "watcher": {},
        "clients": {"rustCount": 1, "mfcCount": 1},
        "rest": None,
        "diagnosticWriters": {"required": False},
        "vpn": {"ok": True},
        "lastRun": {"campaignId": "previous", "status": "failed"},
        "storage": {"ok": True},
    }

    assert "launcher-reported-failure" not in controller.status_findings(status)

    status["lastRun"] = {"campaignId": "current", "status": "failed"}
    assert "launcher-reported-failure" in controller.status_findings(status)


def test_session_status_reports_current_storage_failure_and_dead_watcher(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    campaign_id = "20261025T120000Z"
    output_root, manifest = storage_context_manifest(tmp_path)
    del output_root
    storage = manifest["storage"]
    assert isinstance(storage, dict)
    manifest.update(
        {
            "schema": controller.MANIFEST_SCHEMA,
            "state": "running",
            "startedUtc": datetime.now(UTC).isoformat(),
            "campaignId": campaign_id,
            "launcher": {"pid": 10, "creationDate": "launcher"},
            "watcher": {"pid": 20, "creationDate": "watcher"},
            "watchConfig": {
                "enabled": True,
                "intervalSeconds": 60.0,
                "heartbeatStaleSeconds": 180.0,
            },
        }
    )
    controller.write_json_atomic(
        paths.manifest,
        manifest,
    )
    controller.write_json_atomic(
        paths.watch_heartbeat,
        {
            "schema": controller.WATCH_SCHEMA,
            "campaignId": campaign_id,
            "timestampUtc": datetime.now(UTC).isoformat(),
            "storage": {
                "ok": False,
                "error": "minimum_free_bytes",
                "policySha256": storage["policySha256"],
                "activeCampaignDir": storage["activeCampaignDir"],
                "previousCampaignDir": storage["previousCampaignDir"],
            },
        },
    )
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [])

    result = controller.session_status(paths, check_rest=False, check_vpn=False)

    assert result["storage"]["error"] == "minimum_free_bytes"
    assert "watcher-not-running" in result["findings"]
    assert controller.STORAGE_FAILURE_FINDING in result["findings"]


def test_session_status_ignores_stale_watch_storage_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    controller.write_json_atomic(
        paths.manifest,
        {
            "schema": controller.MANIFEST_SCHEMA,
            "state": "running",
            "startedUtc": datetime.now(UTC).isoformat(),
            "campaignId": "20261025T120000Z",
            "launcher": {},
            "watcher": None,
            "watchConfig": {
                "enabled": True,
                "intervalSeconds": 60.0,
                "heartbeatStaleSeconds": 180.0,
            },
        },
    )
    controller.write_json_atomic(
        paths.watch_heartbeat,
        {
            "schema": controller.WATCH_SCHEMA,
            "campaignId": "20261024T120000Z",
            "timestampUtc": datetime.now(UTC).isoformat(),
            "storage": {"ok": False, "error": "stale"},
        },
    )
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [])

    result = controller.session_status(paths, check_rest=False, check_vpn=False)

    assert result["storage"] is None
    assert controller.STORAGE_FAILURE_FINDING not in result["findings"]
    assert result["watcher"]["heartbeatHealth"]["state"] == "pending"


@pytest.mark.parametrize(
    ("age_seconds", "policy_sha256", "expected_state"),
    [(10, "expected", "current"), (181, "expected", "stale"), (10, "tampered", "invalid")],
)
def test_watch_heartbeat_health_requires_fresh_manifest_authority(
    tmp_path: Path,
    age_seconds: int,
    policy_sha256: str,
    expected_state: str,
) -> None:
    now = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
    _output_root, manifest = storage_context_manifest(tmp_path)
    storage = manifest["storage"]
    assert isinstance(storage, dict)
    manifest.update(
        {
            "startedUtc": (now - timedelta(minutes=10)).isoformat(),
            "watchConfig": {
                "enabled": True,
                "intervalSeconds": 60.0,
                "heartbeatStaleSeconds": 180.0,
            },
        }
    )
    heartbeat = {
        "schema": controller.WATCH_SCHEMA,
        "campaignId": manifest["campaignId"],
        "timestampUtc": (now - timedelta(seconds=age_seconds)).isoformat(),
        "storage": {
            "ok": True,
            "policySha256": (
                storage["policySha256"] if policy_sha256 == "expected" else policy_sha256
            ),
            "activeCampaignDir": storage["activeCampaignDir"],
            "previousCampaignDir": storage["previousCampaignDir"],
        },
    }

    result = controller.watch_heartbeat_health(manifest, heartbeat, now=now)

    assert result["state"] == expected_state
    assert result["accepted"] is (expected_state == "current")


def test_watch_heartbeat_health_rejects_previous_campaign_pin_mismatch(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
    _output_root, manifest = storage_context_manifest(tmp_path)
    storage = manifest["storage"]
    assert isinstance(storage, dict)
    storage["previousCampaignDir"] = str(tmp_path / "expected-previous")
    manifest.update(
        {
            "startedUtc": (now - timedelta(minutes=10)).isoformat(),
            "watchConfig": {
                "enabled": True,
                "intervalSeconds": 60.0,
                "heartbeatStaleSeconds": 180.0,
            },
        }
    )
    heartbeat = {
        "schema": controller.WATCH_SCHEMA,
        "campaignId": manifest["campaignId"],
        "timestampUtc": now.isoformat(),
        "storage": {
            "ok": True,
            "policySha256": storage["policySha256"],
            "activeCampaignDir": storage["activeCampaignDir"],
            "previousCampaignDir": None,
        },
    }

    result = controller.watch_heartbeat_health(manifest, heartbeat, now=now)

    assert result == {"state": "invalid", "accepted": False, "reason": "previous-campaign"}


def test_stop_session_requests_graceful_teardown_without_force(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    controller.write_json_atomic(
        paths.manifest,
        {
            "schema": controller.MANIFEST_SCHEMA,
            "state": "running",
            "launcher": {"pid": 10, "creationDate": "launcher"},
            "observer": {"pid": 30, "creationDate": "observer"},
            "watcher": {"pid": 20, "creationDate": "watcher"},
        },
    )
    waited: list[dict[str, object]] = []

    def fake_wait(identity: dict[str, object], _timeout: float) -> bool:
        waited.append(identity)
        return True

    monkeypatch.setattr(controller, "wait_exact_exit", fake_wait)
    monkeypatch.setattr(
        controller,
        "session_status",
        lambda *_args, **_kwargs: {"schema": controller.STATUS_SCHEMA, "ok": False},
    )

    result = controller.stop_session(paths, graceful_timeout_seconds=1.0)

    assert paths.stop_file.is_file()
    assert paths.watch_stop_file.is_file()
    assert [identity["pid"] for identity in waited] == [30, 10, 20]
    assert result["launcherGraceful"] is True
    assert result["launcherForce"]["forced"] is False
    assert result["observerGraceful"] is True
    assert result["observerForce"]["forced"] is False
    assert result["watcherGraceful"] is True
    assert json.loads(paths.manifest.read_text(encoding="utf-8"))["state"] == "stopped"


def test_stop_session_accepts_authoritative_no_writer_heartbeat(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    campaign_id = "20261025T120000Z"
    controller.write_json_atomic(
        paths.manifest,
        {
            "schema": controller.MANIFEST_SCHEMA,
            "state": "running",
            "campaignId": campaign_id,
            "launcher": {"pid": 10, "creationDate": "launcher"},
            "observer": {"pid": 30, "creationDate": "observer"},
            "watcher": {"pid": 20, "creationDate": "watcher"},
            "preflight": {
                "diagnosticDirs": {
                    "rust": str(tmp_path / "rust-profile" / "packet-dump"),
                    "mfc": str(tmp_path / "mfc-profile" / "logs"),
                }
            },
        },
    )
    controller.write_json_atomic(
        paths.watch_heartbeat,
        {
            "campaignId": campaign_id,
            "diagnosticWriters": {
                "required": False,
                "rust": None,
                "mfc": None,
            },
        },
    )
    monkeypatch.setattr(controller, "wait_exact_exit", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        controller,
        "session_status",
        lambda *_args, **_kwargs: {"schema": controller.STATUS_SCHEMA, "ok": False},
    )

    result = controller.stop_session(paths, graceful_timeout_seconds=1.0)

    assert result["ok"] is True
    assert result["diagnosticFinalization"] == {
        "required": False,
        "ok": True,
        "indexes": None,
        "reason": "diagnostic-writers-not-started",
    }
    assert json.loads(paths.manifest.read_text(encoding="utf-8"))["state"] == "stopped"


def test_stop_session_finalizes_both_active_diagnostic_segments(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root = tmp_path / "output"
    root = controller.campaign_storage_root(output_root)
    active_campaign = root / "20261025T120000Z"
    policy = storage_policy(
        max_total_bytes=1_000_000,
        index_max_bytes=64 * 1024,
        pin_max_bytes=64 * 1024,
        pin_retained=2,
    )
    diagnostic_dirs = {
        "rust": tmp_path / "rust-profile" / "packet-dump",
        "mfc": tmp_path / "mfc-profile" / "logs",
    }
    for client, diagnostic_dir in diagnostic_dirs.items():
        diagnostic_dir.mkdir(parents=True)
        prefix = "emulebb-rust" if client == "rust" else "emulebb-mfc"
        segment = diagnostic_dir / f"{prefix}-diag-42-run-a-000000.jsonl"
        segment.write_text(
            json.dumps(
                diagnostic_record(client=client, segment_id=0, sequence=1)
            )
            + "\n",
            encoding="utf-8",
        )
    manifest = {
        "schema": controller.MANIFEST_SCHEMA,
        "state": "running",
        "campaignId": active_campaign.name,
        "launcher": {"pid": 10, "creationDate": "launcher"},
        "observer": {"pid": 30, "creationDate": "observer"},
        "watcher": {"pid": 20, "creationDate": "watcher"},
        "preflight": {
            "diagnosticDirs": {
                client: str(path) for client, path in diagnostic_dirs.items()
            }
        },
        "storage": controller.session_storage_manifest(
            root=root,
            policy=policy,
            active_campaign=active_campaign,
            previous_campaign=None,
            preflight_plan={"feasible": True},
            launch_enforcement={"withinLimits": True},
        ),
    }
    controller.write_json_atomic(paths.manifest, manifest)
    controller.write_json_atomic(
        paths.watch_heartbeat,
        {
            "campaignId": active_campaign.name,
            "diagnosticWriters": {
                "required": True,
                "rust": {
                    "health": diagnostic_writer_health(
                        client="rust", active_segment_id=0
                    )
                },
                "mfc": {
                    "health": diagnostic_writer_health(
                        client="mfc", active_segment_id=0
                    )
                },
            },
        },
    )
    events: list[str] = []

    def fake_wait(identity: dict[str, object], _timeout: float) -> bool:
        events.append(f"wait-{identity['pid']}")
        return True

    original_finalize = controller.finalize_stopped_session_diagnostics

    def record_finalize(*args, **kwargs):
        events.append("finalize")
        return original_finalize(*args, **kwargs)

    monkeypatch.setattr(controller, "wait_exact_exit", fake_wait)
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(
        controller,
        "finalize_stopped_session_diagnostics",
        record_finalize,
    )
    monkeypatch.setattr(
        controller,
        "session_status",
        lambda *_args, **_kwargs: {"schema": controller.STATUS_SCHEMA, "ok": False},
    )

    result = controller.stop_session(paths, graceful_timeout_seconds=1.0)

    assert events == ["wait-30", "wait-10", "wait-20", "finalize"]
    assert result["ok"] is True
    assert result["diagnosticFinalization"]["ok"] is True
    for client in ("rust", "mfc"):
        finalized = result["diagnosticFinalization"]["indexes"][client]
        assert finalized["finalized"] is True
        assert [item["segmentId"] for item in finalized["processedSegments"]] == [0]
        checkpoint = json.loads(Path(finalized["checkpoint"]).read_text(encoding="utf-8"))
        assert checkpoint["source"]["activeSegmentId"] is None
        assert checkpoint["source"]["finalized"] is True
        assert checkpoint["index"]["recordCount"] == 1


def test_stop_session_without_manifest_does_not_create_control_files(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)

    result = controller.stop_session(paths)

    assert result["noSession"] is True
    assert not paths.stop_file.exists()
    assert not paths.watch_stop_file.exists()


def test_append_bounded_jsonl_rotates_old_segments(tmp_path: Path) -> None:
    path = tmp_path / "watch.jsonl"

    controller.append_bounded_jsonl(path, {"sample": 1, "padding": "x" * 80}, max_bytes=100, segments=2)
    controller.append_bounded_jsonl(path, {"sample": 2, "padding": "x" * 80}, max_bytes=100, segments=2)
    controller.append_bounded_jsonl(path, {"sample": 3, "padding": "x" * 80}, max_bytes=100, segments=2)

    assert json.loads(path.read_text(encoding="utf-8"))["sample"] == 3
    assert json.loads(controller.rotated_path(path, 1).read_text(encoding="utf-8"))["sample"] == 2
    assert json.loads(controller.rotated_path(path, 2).read_text(encoding="utf-8"))["sample"] == 1
    assert not controller.rotated_path(path, 3).exists()


def watch_status_payload() -> dict[str, object]:
    campaign_id = "20261025T120000Z"
    return {
        "timestampUtc": "2026-10-24T12:00:00+00:00",
        "ok": True,
        "findings": [],
        "manifest": {"campaignId": campaign_id},
        "launcher": {"alive": True},
        "clients": {"rustCount": 1, "mfcCount": 1},
        "rest": {"rust": {"ok": True}, "mfc": {"ok": True}},
        "diagnosticWriters": {"required": False, "rust": None, "mfc": None},
        "vpn": {"ok": True},
        "lastRun": {"campaignId": campaign_id, "status": "starting"},
    }


def test_watch_finding_annotation_gates_terminal_health_on_readiness() -> None:
    sample = {
        "campaignId": "campaign",
        "lastRun": {"campaignId": "campaign", "status": "starting"},
        "findings": [
            "full-tunnel-unhealthy",
            "rust-vpn-guard-unhealthy",
            "rust-process-count",
        ],
    }

    assert controller.watch_finding_annotation(sample, {}) == {
        "findingStreaks": {},
        "terminalFindings": [],
    }

    sample["lastRun"]["status"] = "running"
    annotation = controller.watch_finding_annotation(sample, {})
    assert annotation["findingStreaks"] == {}
    assert annotation["terminalFindings"] == [
        "full-tunnel-unhealthy",
        "rust-process-count",
        "rust-vpn-guard-unhealthy",
    ]


def test_dead_enabled_observer_is_terminal_only_after_readiness() -> None:
    sample = {
        "campaignId": "campaign",
        "lastRun": {"campaignId": "campaign", "status": "starting"},
        "findings": ["observer-not-running"],
    }

    assert controller.watch_finding_annotation(sample, {})["terminalFindings"] == []
    sample["lastRun"]["status"] = "running"
    assert controller.watch_finding_annotation(sample, {})["terminalFindings"] == [
        "observer-not-running"
    ]


def test_watch_finding_annotation_requires_three_consecutive_rest_failures() -> None:
    sample = {
        "campaignId": "campaign",
        "lastRun": {"campaignId": "campaign", "status": "running"},
        "findings": ["rust-rest-unhealthy"],
    }

    first = controller.watch_finding_annotation(sample, {})
    second = controller.watch_finding_annotation(sample, first["findingStreaks"])
    third = controller.watch_finding_annotation(sample, second["findingStreaks"])

    assert first == {
        "findingStreaks": {"rust-rest-unhealthy": 1},
        "terminalFindings": [],
    }
    assert second == {
        "findingStreaks": {"rust-rest-unhealthy": 2},
        "terminalFindings": [],
    }
    assert third == {
        "findingStreaks": {"rust-rest-unhealthy": 3},
        "terminalFindings": ["rust-rest-unhealthy"],
    }
    assert controller.watch_finding_annotation(
        {**sample, "findings": []}, third["findingStreaks"]
    )["findingStreaks"] == {}


def test_restored_finding_streaks_is_campaign_scoped_and_bounded() -> None:
    heartbeat = {
        "campaignId": "campaign",
        "findingStreaks": {
            "rust-rest-unhealthy": 2,
            "mfc-rest-unhealthy": True,
            "unknown": 99,
        },
    }

    assert controller.restored_finding_streaks(heartbeat, "campaign") == {
        "rust-rest-unhealthy": 2
    }
    assert controller.restored_finding_streaks(heartbeat, "other") == {}
    heartbeat["shutdown"] = {"launcherStopped": True}
    assert controller.restored_finding_streaks(heartbeat, "campaign") == {}


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_bytes": 0}, "max_bytes"),
        ({"segments": 0}, "segments"),
        ({"max_samples": -1}, "max_samples"),
    ],
)
def test_watch_session_rejects_invalid_limits_before_reading_manifest(
    tmp_path: Path,
    monkeypatch,
    kwargs: dict[str, int],
    message: str,
) -> None:
    paths = make_paths(tmp_path)
    manifest_read = False

    def fake_load(_path: Path) -> dict[str, object]:
        nonlocal manifest_read
        manifest_read = True
        return {}

    monkeypatch.setattr(controller, "load_json", fake_load)
    options = {"interval_seconds": 1.0, "max_bytes": 1024, "segments": 2, **kwargs}

    with pytest.raises(ValueError, match=message):
        controller.watch_session(paths, **options)

    assert manifest_read is False


def test_watch_session_persists_one_bounded_health_sample(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    status = watch_status_payload()
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: status)
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
        max_samples=1,
    )

    assert result["ok"] is True
    assert result["samples"] == 1
    assert json.loads(paths.watch_heartbeat.read_text(encoding="utf-8"))["ok"] is True
    sample = json.loads(paths.watch_jsonl.read_text(encoding="utf-8"))
    assert sample["rustProcessCount"] == 1
    assert sample["storage"]["policySha256"] == "abc"
    assert sample["diagnosticIndexes"] == {
        "required": False,
        "rust": None,
        "mfc": None,
    }


def test_watch_session_fails_closed_on_storage_enforcement_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: watch_status_payload())
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {
            "ok": False,
            "policySha256": "abc",
            "errorType": "StoragePolicyUnsatisfied",
            "error": "minimum_free_bytes",
        },
    )
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
    )

    assert result["ok"] is False
    assert result["samples"] == 1
    assert result["latest"]["storage"]["error"] == "minimum_free_bytes"
    assert controller.STORAGE_FAILURE_FINDING in result["latest"]["findings"]
    assert result["latest"]["shutdown"]["launcherGraceful"] is True
    assert json.loads(paths.watch_heartbeat.read_text(encoding="utf-8"))["shutdown"] == {
        "launcherGraceful": True
    }
    assert stop_requests == [manifest]


def test_watch_session_fails_closed_on_diagnostic_writer_fault(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    status = watch_status_payload()
    status.update(
        {
            "ok": False,
            "findings": ["rust-diagnostic-writer-unhealthy"],
            "lastRun": {
                "campaignId": "20261025T120000Z",
                "status": "running",
            },
            "diagnosticWriters": {
                "required": True,
                "rust": {
                    "ok": False,
                    "health": diagnostic_writer_health(),
                    "violations": ["writeErrors=1 expected 0"],
                },
                "mfc": {
                    "ok": True,
                    "health": diagnostic_writer_health(),
                    "violations": [],
                },
            },
        }
    )
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: status)
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
    )
    monkeypatch.setattr(
        controller,
        "advance_diagnostic_indexes",
        lambda _status, _context: {
            "required": True,
            "rust": {"ok": True},
            "mfc": {"ok": True},
        },
    )
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024 * 1024,
        segments=2,
    )

    assert result["ok"] is False
    assert result["samples"] == 1
    assert result["latest"]["storage"]["ok"] is True
    assert result["latest"]["diagnosticWriters"]["rust"]["ok"] is False
    assert result["latest"]["terminalFindings"] == [
        "rust-diagnostic-writer-unhealthy"
    ]
    assert result["latest"]["shutdown"]["launcherGraceful"] is True
    assert stop_requests == [manifest]


def test_watch_session_fails_closed_on_diagnostic_index_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    status = watch_status_payload()
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: status)
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
    )

    def reject_indexes(_status, _context):
        raise RuntimeError("index checkpoint failed")

    monkeypatch.setattr(controller, "advance_diagnostic_indexes", reject_indexes)
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024 * 1024,
        segments=2,
    )

    assert result["ok"] is False
    assert result["latest"]["storage"]["phase"] == "diagnosticIndexes"
    assert result["latest"]["diagnosticIndexes"] == {
        "required": False,
        "errorType": "RuntimeError",
        "error": "index checkpoint failed",
    }
    assert controller.STORAGE_FAILURE_FINDING in result["latest"]["findings"]
    assert stop_requests == [manifest]


def test_watch_session_restores_rest_failure_streak_and_stops_on_third_sample(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    controller.write_json_atomic(
        paths.watch_heartbeat,
        {
            "campaignId": manifest["campaignId"],
            "findingStreaks": {"rust-rest-unhealthy": 2},
        },
    )
    status = watch_status_payload()
    status.update(
        {
            "ok": False,
            "findings": [
                "rust-rest-unhealthy",
                "rust-diagnostic-writer-unavailable",
            ],
            "lastRun": {
                "campaignId": manifest["campaignId"],
                "status": "running",
            },
        }
    )
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: status)
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
    )
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024 * 1024,
        segments=2,
    )

    assert result["ok"] is False
    assert result["samples"] == 1
    assert result["latest"]["findingStreaks"] == {
        "rust-diagnostic-writer-unavailable": 1,
        "rust-rest-unhealthy": 3,
    }
    assert result["latest"]["terminalFindings"] == ["rust-rest-unhealthy"]
    assert stop_requests == [manifest]


def test_watch_session_fails_closed_on_raised_watch_loop_faults(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: (_ for _ in ()).throw(OSError("inventory failed")),
    )
    monkeypatch.setattr(controller, "session_status", lambda _paths: watch_status_payload())
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
    )

    assert result["ok"] is False
    assert result["latest"]["storage"]["phase"] == "enforcement"
    assert result["latest"]["shutdown"]["launcherGraceful"] is True
    assert stop_requests == [manifest]


def test_watch_session_streak_gates_status_read_failures(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
    )
    monkeypatch.setattr(
        controller,
        "session_status",
        lambda _paths: (_ for _ in ()).throw(OSError("WMI failed")),
    )
    monkeypatch.setattr(controller.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
    )

    assert result["ok"] is False
    assert result["samples"] == 3
    assert result["latest"]["campaignId"] == manifest["campaignId"]
    assert result["latest"]["storage"]["ok"] is True
    assert result["latest"]["statusError"] == {
        "type": "OSError",
        "message": "WMI failed",
    }
    assert result["latest"]["findingStreaks"] == {"watch-status-unavailable": 3}
    assert result["latest"]["terminalFindings"] == ["watch-status-unavailable"]
    assert stop_requests == [manifest]


def test_watch_session_recovers_from_transient_status_read_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    statuses = iter([OSError("observer snapshot changed"), watch_status_payload()])
    emitted: list[dict[str, object]] = []
    stop_requests: list[dict[str, object]] = []

    def next_status(_paths):
        value = next(statuses)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", next_status)
    monkeypatch.setattr(controller.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
    )
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024 * 1024,
        segments=2,
        max_samples=2,
        emit=emitted.append,
    )

    assert result["ok"] is True
    assert result["samples"] == 2
    assert emitted[0]["findings"] == ["watch-status-unavailable"]
    assert emitted[0]["findingStreaks"] == {"watch-status-unavailable": 1}
    assert emitted[1]["findings"] == []
    assert emitted[1]["findingStreaks"] == {}
    assert stop_requests == []


def test_watch_session_preserves_campaign_evidence_across_status_failure_streak(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    healthy = watch_status_payload()
    healthy["lastRun"]["status"] = "running"
    healthy["diagnosticWriters"] = {
        "required": True,
        "rust": {"ok": True, "health": diagnostic_writer_health(client="rust")},
        "mfc": {"ok": True, "health": diagnostic_writer_health(client="mfc")},
    }
    statuses = iter([healthy, OSError("snapshot"), OSError("snapshot"), OSError("snapshot")])
    stop_requests: list[dict[str, object]] = []

    def next_status(_paths):
        value = next(statuses)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", next_status)
    monkeypatch.setattr(controller.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
    )
    monkeypatch.setattr(
        controller,
        "advance_diagnostic_indexes",
        lambda _status, _context: {
            "required": True,
            "rust": {"ok": True},
            "mfc": {"ok": True},
        },
    )
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024 * 1024,
        segments=2,
    )

    assert result["samples"] == 4
    assert result["latest"]["campaignId"] == manifest["campaignId"]
    assert result["latest"]["diagnosticWriters"] == healthy["diagnosticWriters"]
    assert result["latest"]["diagnosticIndexes"] == {
        "required": True,
        "rust": {"ok": True},
        "mfc": {"ok": True},
    }
    assert result["latest"]["terminalFindings"] == ["watch-status-unavailable"]
    assert stop_requests == [manifest]


def test_watch_session_fails_closed_on_invalid_storage_context(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root = tmp_path / "output"
    manifest = {
        "schema": controller.MANIFEST_SCHEMA,
        "state": "running",
        "launcher": {"pid": 10, "creationDate": "launcher"},
    }
    controller.write_json_atomic(paths.manifest, manifest)
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: watch_status_payload())
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
    )

    assert result["ok"] is False
    assert result["latest"]["storage"]["phase"] == "context"
    assert "missing storage context" in result["latest"]["storage"]["error"]
    assert stop_requests == [manifest]


def test_watch_session_fails_closed_on_watch_evidence_write_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: watch_status_payload())
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
    )
    monkeypatch.setattr(
        controller,
        "persist_watch_sample",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
    )

    assert result["ok"] is False
    assert result["latest"]["storage"]["phase"] == "watchEvidence"
    assert result["latest"]["storage"]["error"] == "disk full"
    assert json.loads(paths.watch_heartbeat.read_text(encoding="utf-8"))["ok"] is False
    assert stop_requests == [manifest]


def test_watch_session_fails_closed_when_emit_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: watch_status_payload())
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
    )
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
        emit=lambda _sample: (_ for _ in ()).throw(BrokenPipeError("sink closed")),
    )

    assert result["ok"] is False
    assert result["latest"]["storage"]["phase"] == "watchEvidence"
    assert result["latest"]["storage"]["error"] == "sink closed"
    assert stop_requests == [manifest]


def test_watch_failure_stop_requests_both_paths_and_forces_exact_launcher(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    manifest = {
        "launcher": {"pid": 10, "creationDate": "launcher"},
        "observer": {"pid": 20, "creationDate": "observer"},
    }
    forced: list[tuple[dict[str, object], tuple[str, ...], float]] = []
    monkeypatch.setattr(controller, "capture_exact_process_tree", lambda _identity: ())
    monkeypatch.setattr(controller, "wait_exact_exit", lambda _identity, _timeout: False)

    def fake_stop(identity, *, markers, timeout_seconds):
        forced.append((identity, markers, timeout_seconds))
        return {"forced": True, "alreadyStopped": False, "verifiedStopped": True}

    monkeypatch.setattr(controller, "stop_exact_process", fake_stop)

    result = controller.request_watch_failure_stop(
        paths,
        manifest,
        graceful_timeout_seconds=0.1,
    )

    assert paths.stop_file.is_file()
    assert paths.watch_stop_file.is_file()
    assert result["launcherGraceful"] is False
    assert result["launcherForce"]["forced"] is True
    assert result["launcherStopped"] is True
    assert result["observerStop"]["graceful"] is False
    assert result["observerStop"]["force"]["forced"] is True
    assert forced == [
        (
            manifest["observer"],
            ("converged-soak-observer.py",),
            controller.WATCH_FAILURE_GRACE_SECONDS,
        ),
        (
            manifest["launcher"],
            ("launch-soak.py",),
            controller.WATCH_FAILURE_GRACE_SECONDS,
        )
    ]


def test_watch_failure_stop_uses_fallback_when_manifest_is_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    fallback = {"pid": 10, "creationDate": "launcher"}
    waited: list[dict[str, object]] = []
    captured = ({"pid": 10, "parentPid": 1, "creationDate": "launcher", "name": "python.exe"},)
    monkeypatch.setattr(controller, "capture_exact_process_tree", lambda _identity: captured)
    monkeypatch.setattr(controller, "remaining_exact_tree_rows", lambda _identities: [])
    monkeypatch.setattr(
        controller,
        "wait_exact_exit",
        lambda identity, _timeout: waited.append(identity) or True,
    )

    result = controller.request_watch_failure_stop(
        paths,
        {},
        launcher_fallback=fallback,
        graceful_timeout_seconds=0.1,
    )

    assert waited == [fallback]
    assert result["launcherIdentityAvailable"] is True
    assert result["launcherStopped"] is True


def test_watch_failure_stop_forces_captured_orphans_after_launcher_exit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    fallback = {"pid": 10, "creationDate": "launcher"}
    captured = (
        {"pid": 10, "parentPid": 1, "creationDate": "launcher", "name": "python.exe"},
        {"pid": 11, "parentPid": 10, "creationDate": "rust", "name": "rust.exe"},
    )
    orphan = WindowsProcessInfo(11, 10, "rust.exe", "rust", "rust")
    forced: list[tuple[dict[str, object], ...]] = []
    monkeypatch.setattr(controller, "capture_exact_process_tree", lambda _identity: captured)
    monkeypatch.setattr(controller, "wait_exact_exit", lambda _identity, _timeout: True)
    monkeypatch.setattr(controller, "remaining_exact_tree_rows", lambda _identities: [orphan])

    def fake_force(identities, *, timeout_seconds):
        del timeout_seconds
        forced.append(identities)
        return {"forced": True, "verifiedStopped": True}

    monkeypatch.setattr(controller, "stop_captured_process_tree", fake_force)

    result = controller.request_watch_failure_stop(
        paths,
        {},
        launcher_fallback=fallback,
        graceful_timeout_seconds=0.1,
    )

    assert result["launcherGraceful"] is False
    assert result["launcherForce"]["forced"] is True
    assert result["launcherStopped"] is True
    assert forced == [captured]


def test_watch_failure_stop_reports_unavailable_launcher_identity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    waited = False

    def reject_wait(*_args, **_kwargs):
        nonlocal waited
        waited = True
        raise AssertionError("wait must not run without an exact identity")

    monkeypatch.setattr(controller, "wait_exact_exit", reject_wait)

    result = controller.request_watch_failure_stop(paths, {}, graceful_timeout_seconds=0.1)

    assert waited is False
    assert result["launcherIdentityAvailable"] is False
    assert result["launcherStopped"] is False
    assert result["launcherForce"]["errorType"] == "LauncherIdentityUnavailable"


def test_stop_exact_process_reports_surviving_exact_launcher(
    monkeypatch,
) -> None:
    identity = {"pid": 10, "creationDate": "launcher"}
    row = WindowsProcessInfo(10, 1, "python.exe", "python launch-soak.py", "launcher")
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [row])
    monkeypatch.setattr(
        controller.windows_processes,
        "terminate_process_tree",
        lambda *_args, **_kwargs: {"return_code": 1, "remaining_pids": [10]},
    )

    result = controller.stop_exact_process(
        identity,
        markers=("launch-soak.py",),
        timeout_seconds=0.1,
    )

    assert result["forced"] is True
    assert result["verifiedStopped"] is False
    assert result["result"]["remaining_pids"] == [10]


def test_stop_exact_process_rejects_orphaned_owned_children(
    monkeypatch,
) -> None:
    identity = {"pid": 10, "creationDate": "launcher"}
    row = WindowsProcessInfo(10, 1, "python.exe", "python launch-soak.py", "launcher")
    process_snapshots = iter(([row], []))
    monkeypatch.setattr(
        controller.windows_processes,
        "collect_processes",
        lambda: list(next(process_snapshots)),
    )
    monkeypatch.setattr(
        controller.windows_processes,
        "terminate_process_tree",
        lambda *_args, **_kwargs: {"return_code": 1, "remaining_pids": [11]},
    )

    result = controller.stop_exact_process(
        identity,
        markers=("launch-soak.py",),
        timeout_seconds=0.1,
    )

    assert result["verifiedRootStopped"] is True
    assert result["verifiedStopped"] is False
    assert result["result"]["remaining_pids"] == [11]


def test_stop_captured_process_tree_terminates_orphaned_exact_child(
    monkeypatch,
) -> None:
    identities = (
        {"pid": 10, "parentPid": 1, "creationDate": "launcher", "name": "python.exe"},
        {"pid": 11, "parentPid": 10, "creationDate": "rust", "name": "rust.exe"},
    )
    orphan = WindowsProcessInfo(11, 10, "rust.exe", "rust", "rust")
    remaining_snapshots = iter(([orphan], []))
    terminated: list[tuple[int, str]] = []
    monkeypatch.setattr(
        controller,
        "remaining_exact_tree_rows",
        lambda _identities: list(next(remaining_snapshots)),
    )

    def fake_terminate(pid, **kwargs):
        terminated.append((pid, kwargs["expected_root_creation_date"]))
        return {"return_code": 0, "remaining_pids": []}

    monkeypatch.setattr(controller.windows_processes, "terminate_process_tree", fake_terminate)

    result = controller.stop_captured_process_tree(identities, timeout_seconds=0.1)

    assert result["verifiedStopped"] is True
    assert result["forcedRootPids"] == [11]
    assert terminated == [(11, "rust")]


def test_remaining_exact_tree_rows_discovers_post_capture_descendant(
    monkeypatch,
) -> None:
    identities = (
        {"pid": 10, "parentPid": 1, "creationDate": "launcher", "name": "python.exe"},
    )
    late_child = WindowsProcessInfo(11, 10, "rust.exe", "rust", "rust")
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [late_child])

    remaining = controller.remaining_exact_tree_rows(identities)

    assert remaining == [late_child]


def test_remaining_exact_tree_rows_fails_closed_on_parent_pid_reuse(
    monkeypatch,
) -> None:
    identities = (
        {"pid": 10, "parentPid": 1, "creationDate": "launcher", "name": "python.exe"},
    )
    reused_parent = WindowsProcessInfo(10, 1, "other.exe", "other", "replacement")
    ambiguous_child = WindowsProcessInfo(11, 10, "rust.exe", "rust", "rust")
    monkeypatch.setattr(
        controller.windows_processes,
        "collect_processes",
        lambda: [reused_parent, ambiguous_child],
    )

    with pytest.raises(RuntimeError, match="PID reuse made descendant ownership ambiguous: 11"):
        controller.remaining_exact_tree_rows(identities)


def test_stop_captured_process_tree_rejects_reported_late_survivors(
    monkeypatch,
) -> None:
    identities = (
        {"pid": 10, "parentPid": 1, "creationDate": "launcher", "name": "python.exe"},
        {"pid": 11, "parentPid": 10, "creationDate": "rust", "name": "rust.exe"},
    )
    orphan = WindowsProcessInfo(11, 10, "rust.exe", "rust", "rust")
    remaining_snapshots = iter(([orphan], []))
    monkeypatch.setattr(
        controller,
        "remaining_exact_tree_rows",
        lambda _identities: list(next(remaining_snapshots)),
    )
    monkeypatch.setattr(
        controller.windows_processes,
        "terminate_process_tree",
        lambda *_args, **_kwargs: {"return_code": 1, "remaining_pids": [12]},
    )

    result = controller.stop_captured_process_tree(identities, timeout_seconds=0.1)

    assert result["verifiedStopped"] is False
    assert result["results"][0]["remaining_pids"] == [12]
