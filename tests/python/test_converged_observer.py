from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from types import MappingProxyType

from emule_test_harness import converged_observer, converged_observer_state
from emule_test_harness import soak_run_layout, soak_storage


CAMPAIGN_ID = "20261025T120000Z"


def storage_policy() -> soak_storage.SoakStoragePolicy:
    return soak_storage.SoakStoragePolicy(
        max_total_bytes=10 * 1024 * 1024,
        max_age_seconds=10 * 24 * 60 * 60,
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
                "diagnostic_indexes": soak_storage.ArtifactStreamPolicy(1, 1),
                "diagnostic_pins": soak_storage.ArtifactStreamPolicy(1, 1),
                "diagnostic_segments": soak_storage.ArtifactStreamPolicy(1, 1),
                "observer_actions": soak_storage.ArtifactStreamPolicy(4_096, 2),
                "observer_checkpoints": soak_storage.ArtifactStreamPolicy(16_384, 2),
                "observer_summary": soak_storage.ArtifactStreamPolicy(16_384, 1),
            }
        ),
    )


def runtime(tmp_path: Path) -> converged_observer.ObserverRuntime:
    soak_root = tmp_path / "soak"
    run_paths = soak_run_layout.build_run_paths(soak_root, CAMPAIGN_ID)
    return converged_observer.ObserverRuntime(
        session_manifest=soak_root / "control" / "persisted-soak.latest.json",
        stop_file=soak_root / "control" / "persisted-soak.stop",
        last_run_manifest=run_paths.last_run_manifest,
        run_paths=run_paths,
        store=soak_storage.BoundedArtifactStore(
            run_paths.campaigns_root, storage_policy()
        ),
        launcher_identity={"pid": 100, "creationDate": "20261025120000.000000+000"},
        rust_base_url="http://127.0.0.1:4731/api/v1",
        mfc_base_url="http://127.0.0.1:4732/api/v1",
    )


def new_state() -> dict[str, object]:
    return converged_observer_state.new_state(
        CAMPAIGN_ID,
        recent_action_limit=4,
        recent_anomaly_limit=4,
    )


def test_capture_checkpoint_persists_full_health_and_cumulative_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    subject = runtime(tmp_path)
    health = {
        "rust": {"schema": "diag_event_v2", "recordsWritten": 31, "exact": "rust"},
        "mfc": {"schema": "diag_event_v2", "recordsWritten": 29, "exact": "mfc"},
    }
    monkeypatch.setattr(
        converged_observer,
        "diagnostic_writer_health",
        lambda base_url, _api_key: health[
            "rust" if base_url == subject.rust_base_url else "mfc"
        ],
    )

    updated = converged_observer.capture_checkpoint(
        subject,
        new_state(),
        observed_at=datetime(2026, 10, 25, 12, 5, tzinfo=UTC),
        now_ns=1_000_000_000,
    )

    checkpoint_path = next(subject.run_paths.checkpoints_dir.glob("*.json"))
    checkpoint = converged_observer.load_json_object(checkpoint_path)
    assert checkpoint["packetRecords"] == {"rust": 31, "mfc": 29}
    assert checkpoint["diagnosticWriters"] == health
    assert updated["checkpoints"]["count"] == 1
    assert updated["retention"]["checkpoints"]["retained"] == 1
    assert (
        converged_observer.load_json_object(
            subject.run_paths.report_dir / "summary.json"
        )
        == updated
    )


def test_run_observer_waits_for_existing_campaign_and_never_owns_clients(
    tmp_path: Path,
) -> None:
    subject = runtime(tmp_path)
    subject.last_run_manifest.parent.mkdir(parents=True)
    subject.last_run_manifest.write_text(
        json.dumps(
            {
                "campaignId": CAMPAIGN_ID,
                "campaignDir": str(subject.run_paths.campaign_dir),
                "status": "running",
            }
        ),
        encoding="utf-8",
    )
    captured: list[int] = []
    clock = [0.0]

    def capture(_runtime, state):
        captured.append(len(captured) + 1)
        return converged_observer_state.record_checkpoint(
            state,
            {
                "schema": "soak_checkpoint_v1",
                "ts_utc": f"2026-10-25T12:0{len(captured)}:00+00:00",
                "rustAlive": True,
                "packetRecords": {"rust": len(captured), "mfc": len(captured)},
                "totals": {"actions": 0},
            },
        )

    result = converged_observer.run_observer(
        subject,
        ready_timeout_seconds=30,
        poll_interval_seconds=1,
        checkpoint_interval_seconds=5,
        failure_threshold=3,
        max_checkpoints=2,
        monotonic=lambda: clock[0],
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        launcher_alive=lambda _identity: True,
        capture=capture,
    )

    assert captured == [1, 2]
    assert result["checkpoints"]["count"] == 2


def test_run_observer_honors_shared_stop_before_process_probe(tmp_path: Path) -> None:
    subject = runtime(tmp_path)
    subject.stop_file.parent.mkdir(parents=True)
    subject.stop_file.write_text("stop\n", encoding="utf-8")
    probed = False

    def launcher_alive(_identity):
        nonlocal probed
        probed = True
        return True

    result = converged_observer.run_observer(
        subject,
        ready_timeout_seconds=30,
        poll_interval_seconds=1,
        checkpoint_interval_seconds=5,
        failure_threshold=3,
        launcher_alive=launcher_alive,
    )

    assert probed is False
    assert result["campaignId"] == CAMPAIGN_ID
    assert result["checkpoints"]["count"] == 0


def test_attach_only_observer_source_has_no_client_lifecycle_calls() -> None:
    source = Path(converged_observer.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "prepare_clean_run(",
        "bring_up_rust(",
        "bring_up_mfc(",
        "stop_process_tree(",
        "close_app_cleanly(",
    ):
        assert forbidden not in source
