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


def diagnostic_runs() -> dict[str, dict[str, object]]:
    return {
        "rust": {"processId": 4101, "runId": "rust-run"},
        "mfc": {"processId": 4201, "runId": "mfc-run"},
    }


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


def test_capture_action_cycle_persists_intents_before_posts_and_terminal_phases(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="explicit",
        terms=("Exact Local Search Term",),
        method="server",
        start_delay_seconds=0,
        search_interval_seconds=900,
        search_timeout_seconds=120,
    )
    subject = replace(runtime(tmp_path), action_config=config)
    events: list[tuple[str, str]] = []

    def health(base_url: str, _api_key: str) -> dict[str, object]:
        client = "rust" if base_url == subject.rust_base_url else "mfc"
        return diagnostic_runs()[client]

    def create_phase(client, *, query: str, method: str):
        summary = converged_observer.load_json_object(
            subject.run_paths.report_dir / "summary.json"
        )
        create_statuses = {
            name: summary["pendingAction"]["clients"][name]["create"]["status"]
            for name in ("rust", "mfc")
        }
        assert create_statuses[client.name] == "prepared"
        if client.name == "rust":
            assert create_statuses == {"rust": "prepared", "mfc": "prepared"}
        else:
            assert create_statuses == {"rust": "succeeded", "mfc": "prepared"}
        assert query == "Exact Local Search Term"
        assert method == "server"
        events.append(("create", client.name))
        return converged_observer.converged_action_driver.SearchCreatePhase(
            search_id=f"{client.name}-search",
            error=None,
        )

    def results_phase(client, search_id: str, *, timeout_seconds: float):
        assert search_id == f"{client.name}-search"
        assert timeout_seconds == 120
        events.append(("results", client.name))
        rows = tuple({"hash": str(index) * 32} for index in range(1, 3))
        return converged_observer.converged_action_driver.SearchResultsPhase(
            rows=rows,
            completed=client.name == "rust",
            error=None,
        )

    monkeypatch.setattr(converged_observer, "diagnostic_writer_health", health)
    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "run_search_create_phase",
        create_phase,
    )
    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "run_search_results_phase",
        results_phase,
    )

    updated = converged_observer.capture_action_cycle(
        subject,
        new_state(config),
        config,
        now_utc=lambda: datetime(2026, 10, 25, 12, 1, tzinfo=UTC),
        now_ns=1_000_000_000,
    )

    assert events == [
        ("create", "rust"),
        ("create", "mfc"),
        ("results", "rust"),
        ("results", "mfc"),
    ]
    assert updated["driver"]["cycles"] == 1
    assert updated["driver"]["latestCycle"]["query"] == "Exact Local Search Term"
    assert updated["driver"]["latestCycle"]["resultCounts"] == {
        "rust": 2,
        "mfc": 2,
    }
    assert updated["pendingAction"]["diagnosticRuns"] == diagnostic_runs()
    assert updated["pendingAction"]["clients"]["mfc"]["results"]["completed"] is False
    assert updated["pendingAction"]["evidence"] == {
        "status": "pending",
        "windowEndUtc": "2026-10-25T12:01:00+00:00",
    }
    assert (
        converged_observer.load_json_object(
            subject.run_paths.report_dir / "summary.json"
        )
        == updated
    )


def test_capture_action_cycle_fails_closed_on_restarted_prepared_posts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        search_interval_seconds=900,
    )
    subject = replace(runtime(tmp_path), action_config=config)
    state = converged_observer_state.reserve_driver_cycle(
        new_state(config),
        query="linux",
        method="server",
        reserved_at_utc="2026-10-25T12:00:00+00:00",
        diagnostic_runs=diagnostic_runs(),
    )
    for client in ("rust", "mfc"):
        state = converged_observer_state.prepare_search_create(
            state,
            client=client,
            prepared_at_utc="2026-10-25T12:00:01+00:00",
        )
    converged_observer.persist_state(subject, state)
    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "run_search_create_phase",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ambiguous POST must not be replayed")
        ),
    )

    updated = converged_observer.capture_action_cycle(
        subject,
        converged_observer.load_state(subject),
        config,
        now_utc=lambda: datetime(2026, 10, 25, 12, 1, tzinfo=UTC),
    )

    assert updated["driver"]["cycles"] == 1
    assert updated["driver"]["cycleErrors"] == 1
    for client in ("rust", "mfc"):
        create = updated["pendingAction"]["clients"][client]["create"]
        assert create["status"] == "failed"
        assert create["error"]["type"] == "AmbiguousSearchCreate"
        assert "the POST will not be replayed" in create["error"]["message"]


def test_capture_action_cycle_resumes_persisted_search_ids_without_post(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        search_interval_seconds=900,
    )
    subject = replace(runtime(tmp_path), action_config=config)
    state = converged_observer_state.reserve_driver_cycle(
        new_state(config),
        query="linux",
        method="server",
        reserved_at_utc="2026-10-25T12:00:00+00:00",
        diagnostic_runs=diagnostic_runs(),
    )
    for client in ("rust", "mfc"):
        state = converged_observer_state.prepare_search_create(
            state,
            client=client,
            prepared_at_utc="2026-10-25T12:00:01+00:00",
        )
        state = converged_observer_state.complete_search_create(
            state,
            client=client,
            completed_at_utc="2026-10-25T12:00:02+00:00",
            search_id=f"{client}-search-9",
            error=None,
        )
    converged_observer.persist_state(subject, state)
    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "run_search_create_phase",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("persisted search must not be created again")
        ),
    )
    polled: list[tuple[str, str]] = []

    def results_phase(client, search_id: str, *, timeout_seconds: float):
        assert timeout_seconds == config.search_timeout_seconds
        polled.append((client.name, search_id))
        return converged_observer.converged_action_driver.SearchResultsPhase(
            rows=({"hash": "a" * 32},),
            completed=False,
            error=None,
        )

    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "run_search_results_phase",
        results_phase,
    )

    updated = converged_observer.capture_action_cycle(
        subject,
        converged_observer.load_state(subject),
        config,
        now_utc=lambda: datetime(2026, 10, 25, 12, 1, tzinfo=UTC),
    )

    assert polled == [
        ("rust", "rust-search-9"),
        ("mfc", "mfc-search-9"),
    ]
    assert updated["driver"]["latestCycle"]["searchIds"] == {
        "rust": "rust-search-9",
        "mfc": "mfc-search-9",
    }


def test_capture_action_cycle_recovers_evidence_marker_after_driver_persist(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        search_interval_seconds=900,
    )
    subject = replace(runtime(tmp_path), action_config=config)
    state = converged_observer_state.reserve_driver_cycle(
        new_state(config),
        query="linux",
        method="server",
        reserved_at_utc="2026-10-25T12:00:00+00:00",
        diagnostic_runs=diagnostic_runs(),
    )
    for client in ("rust", "mfc"):
        state = converged_observer_state.prepare_search_create(
            state,
            client=client,
            prepared_at_utc="2026-10-25T12:00:01+00:00",
        )
        state = converged_observer_state.complete_search_create(
            state,
            client=client,
            completed_at_utc="2026-10-25T12:00:02+00:00",
            search_id=f"{client}-search-9",
            error=None,
        )
        state = converged_observer_state.record_search_results(
            state,
            client=client,
            completed_at_utc="2026-10-25T12:00:03+00:00",
            completed=True,
            result_count=1,
            error=None,
        )
    cycle = converged_observer.pending_cycle_payload(
        state["pendingAction"],
        completed_at_utc="2026-10-25T12:00:04+00:00",
    )
    state = converged_observer_state.record_driver_cycle(state, cycle)
    converged_observer.persist_state(subject, state)
    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "run_search_create_phase",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("completed driver must not issue another POST")
        ),
    )
    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "run_search_results_phase",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("completed driver must not poll again")
        ),
    )

    updated = converged_observer.capture_action_cycle(
        subject,
        converged_observer.load_state(subject),
        config,
        now_utc=lambda: datetime(2026, 10, 25, 12, 5, tzinfo=UTC),
    )

    assert updated["pendingAction"]["evidence"] == {
        "status": "pending",
        "windowEndUtc": "2026-10-25T12:00:04+00:00",
    }


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
