from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
import json
from pathlib import Path
from types import MappingProxyType

import pytest

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


def new_state(
    config: converged_observer.ObserverActionConfig = converged_observer.ObserverActionConfig(),
) -> dict[str, object]:
    return converged_observer_state.new_state(
        CAMPAIGN_ID,
        configuration_digest=converged_observer.action_configuration_digest(config),
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


def test_parse_action_config_requires_gentle_complete_schedule() -> None:
    config = converged_observer.parse_action_config(
        {
            "actionDriving": {
                "enabled": True,
                "sourceProfile": "generic_open",
                "terms": ["linux", "debian", "linux"],
                "method": "kad",
                "startDelaySeconds": 30,
                "searchIntervalSeconds": 900,
                "searchTimeoutSeconds": 120,
                "maxCycles": 12,
            }
        }
    )

    assert config == converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux", "debian"),
        method="kad",
        start_delay_seconds=30.0,
        search_interval_seconds=900.0,
        search_timeout_seconds=120.0,
        max_cycles=12,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("sourceProfile", None),
        ("startDelaySeconds", True),
        ("searchIntervalSeconds", float("inf")),
        ("searchTimeoutSeconds", float("nan")),
    ),
)
def test_parse_action_config_rejects_ambiguous_or_nonfinite_values(
    field: str,
    value: object,
) -> None:
    payload = {
        "enabled": True,
        "sourceProfile": "generic_open",
        "terms": ["linux"],
        "method": "server",
        "startDelaySeconds": 60,
        "searchIntervalSeconds": 900,
        "searchTimeoutSeconds": 120,
        "maxCycles": 0,
    }
    payload[field] = value

    with pytest.raises(RuntimeError):
        converged_observer.parse_action_config({"actionDriving": payload})


def test_load_state_binds_the_exact_action_configuration(tmp_path: Path) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="explicit",
        terms=("exact local term", "ünicode term"),
        method="kad",
        start_delay_seconds=30,
        search_interval_seconds=900,
        search_timeout_seconds=120,
        max_cycles=4,
    )
    subject = replace(runtime(tmp_path), action_config=config)

    state = converged_observer.load_state(subject)
    assert state[
        "configurationDigest"
    ] == converged_observer.action_configuration_digest(config)
    converged_observer.persist_state(subject, state)

    changed = replace(
        subject,
        action_config=replace(config, terms=("exact local term", "different")),
    )
    with pytest.raises(RuntimeError, match="configuration identity is invalid"):
        converged_observer.load_state(changed)


def test_capture_action_cycle_persists_exact_query_and_cumulative_driver_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    subject = runtime(tmp_path)
    observed: dict[str, object] = {}

    def drive(**kwargs):
        observed.update(kwargs)
        return {
            "cycle": kwargs["cycle_index"],
            "queryIndex": kwargs["cycle_index"] - 1,
            "method": kwargs["method"],
            "query": kwargs["query"],
            "downloadRequested": False,
            "searchIds": {"rust": "rust-search", "mfc": "mfc-search"},
            "resultCounts": {"rust": 4, "mfc": 3},
        }

    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "drive_automatic_cycle",
        drive,
    )
    timestamps = iter(
        (
            datetime(2026, 10, 25, 12, 1, tzinfo=UTC),
            datetime(2026, 10, 25, 12, 2, tzinfo=UTC),
        )
    )
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="explicit",
        terms=("Exact Local Search Term",),
        method="server",
        start_delay_seconds=0,
        search_interval_seconds=900,
        search_timeout_seconds=120,
    )
    subject = replace(subject, action_config=config)

    updated = converged_observer.capture_action_cycle(
        subject,
        new_state(config),
        config,
        now_utc=lambda: next(timestamps),
        now_ns=1_000_000_000,
    )

    assert observed["query"] == "Exact Local Search Term"
    assert observed["download"] is False
    assert observed["safety"] is None
    assert observed["rust"].base_url == subject.rust_base_url
    assert observed["mfc"].base_url == subject.mfc_base_url
    assert updated["driver"]["cycles"] == 1
    assert updated["driver"]["latestCycle"]["query"] == "Exact Local Search Term"
    assert (
        updated["driver"]["latestCycle"]["startedAtUtc"] == "2026-10-25T12:01:00+00:00"
    )
    assert (
        updated["driver"]["latestCycle"]["completedAtUtc"]
        == "2026-10-25T12:02:00+00:00"
    )
    assert (
        converged_observer.load_json_object(
            subject.run_paths.report_dir / "summary.json"
        )
        == updated
    )


def test_capture_action_cycle_records_rest_failure_without_stopping_soak(
    tmp_path: Path,
    monkeypatch,
) -> None:
    subject = runtime(tmp_path)
    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "drive_automatic_cycle",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("REST unavailable")),
    )
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        search_interval_seconds=900,
    )
    subject = replace(subject, action_config=config)

    updated = converged_observer.capture_action_cycle(
        subject,
        new_state(config),
        config,
        now_utc=lambda: datetime(2026, 10, 25, 12, 1, tzinfo=UTC),
    )

    assert updated["driver"]["cycles"] == 1
    assert updated["driver"]["cycleErrors"] == 1
    assert updated["driver"]["latestCycle"]["error"] == "RuntimeError: REST unavailable"


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


def test_run_observer_schedules_actions_without_owning_clients(tmp_path: Path) -> None:
    subject = replace(
        runtime(tmp_path),
        action_config=converged_observer.ObserverActionConfig(
            enabled=True,
            source_profile="generic_open",
            terms=("linux", "debian"),
            method="global",
            start_delay_seconds=0,
            search_interval_seconds=300,
            search_timeout_seconds=120,
            max_cycles=2,
        ),
    )
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
    clock = [0.0]
    action_cycles: list[int] = []

    def capture(_runtime, state):
        return converged_observer_state.record_checkpoint(
            state,
            {
                "schema": "soak_checkpoint_v1",
                "ts_utc": "2026-10-25T12:00:00+00:00",
                "rustAlive": True,
                "packetRecords": {"rust": 1, "mfc": 1},
                "totals": {"actions": 0},
            },
        )

    def drive_action(_runtime, state, config):
        cycle = int(state["driver"]["cycles"]) + 1
        action_cycles.append(cycle)
        assert config.method == "global"
        updated = converged_observer_state.record_driver_cycle(
            state,
            {
                "cycle": cycle,
                "query": config.terms[(cycle - 1) % len(config.terms)],
                "method": config.method,
            },
        )
        if cycle == 2:
            subject.stop_file.parent.mkdir(parents=True, exist_ok=True)
            subject.stop_file.write_text("stop\n", encoding="utf-8")
        return updated

    result = converged_observer.run_observer(
        subject,
        ready_timeout_seconds=30,
        poll_interval_seconds=60,
        checkpoint_interval_seconds=1_000,
        failure_threshold=3,
        monotonic=lambda: clock[0],
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        launcher_alive=lambda _identity: True,
        capture=capture,
        drive_action=drive_action,
    )

    assert action_cycles == [1, 2]
    assert result["driver"]["cycles"] == 2
    assert result["driver"]["latestCycle"]["query"] == "debian"


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
