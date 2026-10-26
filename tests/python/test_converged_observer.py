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
    rust_profile = tmp_path / "rust-profile"
    mfc_profile = tmp_path / "mfc-profile"
    rust_profile.mkdir()
    mfc_profile.mkdir()
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
        diagnostic_directories=converged_observer.DiagnosticDirectories(
            rust=rust_profile / "packet-dump",
            mfc=mfc_profile / "logs",
        ),
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


def reportable_state(
    config: converged_observer.ObserverActionConfig,
) -> dict[str, object]:
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
            search_id=f"{client}-search-1",
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
    pending = state["pendingAction"]
    state = converged_observer_state.record_driver_cycle(
        state,
        converged_observer.pending_cycle_payload(
            pending,
            completed_at_utc="2026-10-25T12:00:04+00:00",
        ),
    )
    return converged_observer_state.mark_evidence_pending(
        state,
        window_end_utc="2026-10-25T12:00:04+00:00",
    )


def pending_action_report(pending: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "emulebb-build-tests.observer-action-report.v1",
        "campaignId": CAMPAIGN_ID,
        "seq": pending["reportSeq"],
        "actionId": pending["actionId"],
        "cycle": pending["cycle"],
        "kind": "search",
        "method": pending["method"],
        "key": pending["query"],
        "label": pending["query"],
        "window": {
            "t0": pending["reservedAtUtc"],
            "t1": pending["evidence"]["windowEndUtc"],
        },
        "observed": {
            "rust": pending["evidence"]["windowEndUtc"],
            "mfc": pending["evidence"]["windowEndUtc"],
        },
        "verdict": "no-traffic",
        "coverageOk": False,
        "byteMatch": False,
        "diagOk": True,
    }


def test_diagnostic_profile_directories_use_only_manifest_authority(
    tmp_path: Path,
) -> None:
    rust_profile = tmp_path / "operator-rust-profile"
    mfc_profile = tmp_path / "operator-mfc-profile"
    rust_profile.mkdir()
    mfc_profile.mkdir()

    directories = converged_observer.diagnostic_profile_directories(
        {
            "profiles": {
                "rust": str(rust_profile),
                "mfc": str(mfc_profile),
            }
        }
    )

    assert directories == converged_observer.DiagnosticDirectories(
        rust=(rust_profile / "packet-dump").resolve(),
        mfc=(mfc_profile / "logs").resolve(),
    )


@pytest.mark.parametrize(
    "profiles",
    [
        None,
        {"rust": "missing-mfc"},
        {"rust": "missing", "mfc": "missing", "other": "unexpected"},
        {"rust": "", "mfc": "missing"},
    ],
)
def test_diagnostic_profile_directories_reject_invalid_authority(
    profiles: object,
) -> None:
    with pytest.raises(RuntimeError, match="diagnostic profile"):
        converged_observer.diagnostic_profile_directories({"profiles": profiles})


def test_diagnostic_profile_directories_require_existing_profiles(
    tmp_path: Path,
) -> None:
    rust_profile = tmp_path / "rust-profile"
    rust_profile.mkdir()

    with pytest.raises(RuntimeError, match="mfc diagnostic profile does not exist"):
        converged_observer.diagnostic_profile_directories(
            {
                "profiles": {
                    "rust": str(rust_profile),
                    "mfc": str(tmp_path / "missing-mfc-profile"),
                }
            }
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

    def finalize_action(_runtime, state, *, now_ns):
        assert now_ns == 1_000_000_000
        assert state["pendingAction"]["evidence"] == {
            "status": "pending",
            "windowEndUtc": "2026-10-25T12:01:00+00:00",
        }
        assert (
            converged_observer.load_json_object(
                subject.run_paths.report_dir / "summary.json"
            )
            == state
        )
        events.append(("finalize", "report"))
        return state

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
        finalize_action=finalize_action,
    )

    assert events == [
        ("create", "rust"),
        ("create", "mfc"),
        ("results", "rust"),
        ("results", "mfc"),
        ("finalize", "report"),
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
        finalize_action=lambda _runtime, action_state, **_kwargs: action_state,
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
        finalize_action=lambda _runtime, action_state, **_kwargs: action_state,
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
    finalized_state = {"finalized": True}

    def finalize_action(_runtime, action_state, **_kwargs):
        assert action_state["pendingAction"]["evidence"] == {
            "status": "pending",
            "windowEndUtc": "2026-10-25T12:00:04+00:00",
        }
        assert (
            converged_observer.load_json_object(
                subject.run_paths.report_dir / "summary.json"
            )
            == action_state
        )
        return finalized_state

    updated = converged_observer.capture_action_cycle(
        subject,
        converged_observer.load_state(subject),
        config,
        now_utc=lambda: datetime(2026, 10, 25, 12, 5, tzinfo=UTC),
        finalize_action=finalize_action,
    )

    assert updated is finalized_state


def test_finalize_pending_action_is_report_first_and_uses_persisted_authority(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
    )
    subject = replace(runtime(tmp_path), action_config=config)
    subject.diagnostic_directories.rust.mkdir(parents=True)
    subject.diagnostic_directories.mfc.mkdir(parents=True)
    state = reportable_state(config)
    pending = state["pendingAction"]
    events: list[str] = []
    evidence_token = object()

    def capture_evidence(*, window, rust, mfc):
        events.append("capture")
        assert window.start_utc.isoformat() == pending["reservedAtUtc"]
        assert window.end_utc.isoformat() == pending["evidence"]["windowEndUtc"]
        assert rust.directory == subject.diagnostic_directories.rust.resolve()
        assert rust.process_id == 4101
        assert rust.run_id == "rust-run"
        assert mfc.directory == subject.diagnostic_directories.mfc.resolve()
        assert mfc.process_id == 4201
        assert mfc.run_id == "mfc-run"
        return evidence_token

    def build_report(*, campaign_id, pending_action, evidence):
        events.append("build")
        assert campaign_id == CAMPAIGN_ID
        assert pending_action == pending
        assert evidence is evidence_token
        return pending_action_report(pending_action)

    persisted = soak_storage.PersistedArtifact(
        path=subject.run_paths.actions_dir
        / f"action-00000001-{pending['actionId']}.json",
        byte_count=512,
        sha256="a" * 64,
        deleted_paths=(),
        retained_count=1,
        retained_bytes=512,
    )

    def persist_report(**kwargs):
        events.append("report")
        assert kwargs["report"]["actionId"] == pending["actionId"]
        assert kwargs["now_ns"] == 123
        return persisted

    original_commit = converged_observer_state.commit_action_report
    original_retention = converged_observer_state.record_stream_retention

    def commit_action(current_state, report):
        events.append("commit")
        return original_commit(current_state, report)

    def record_retention(current_state, *, stream, persisted):
        events.append("retention")
        return original_retention(
            current_state,
            stream=stream,
            persisted=persisted,
        )

    summaries = []

    def persist_summary(**kwargs):
        events.append("summary")
        summaries.append(kwargs["summary"])
        assert kwargs["now_ns"] == 123
        return persisted

    monkeypatch.setattr(
        converged_observer.observer_action_evidence,
        "capture_action_diagnostic_evidence",
        capture_evidence,
    )
    monkeypatch.setattr(
        converged_observer.observer_action_report,
        "build_observer_action_report",
        build_report,
    )
    monkeypatch.setattr(
        converged_observer.soak_run_layout,
        "persist_observer_action_report",
        persist_report,
    )
    monkeypatch.setattr(
        converged_observer.converged_observer_state,
        "commit_action_report",
        commit_action,
    )
    monkeypatch.setattr(
        converged_observer.converged_observer_state,
        "record_stream_retention",
        record_retention,
    )
    monkeypatch.setattr(
        converged_observer.soak_run_layout,
        "persist_observer_summary",
        persist_summary,
    )

    updated = converged_observer.finalize_pending_action(
        subject,
        state,
        now_ns=123,
    )

    assert events == ["capture", "build", "report", "commit", "retention", "summary"]
    assert updated["pendingAction"] is None
    assert updated["totals"]["actions"] == 1
    assert updated["retention"]["actions"] == {
        "seen": 1,
        "retained": 1,
        "omitted": 0,
        "retainedBytes": 512,
        "latestFile": persisted.path.name,
    }
    assert summaries == [updated]


def test_finalize_pending_action_does_not_commit_if_report_persistence_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
    )
    subject = replace(runtime(tmp_path), action_config=config)
    state = reportable_state(config)
    pending = state["pendingAction"]
    monkeypatch.setattr(
        converged_observer,
        "capture_pending_action_evidence",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        converged_observer.observer_action_report,
        "build_observer_action_report",
        lambda **_kwargs: pending_action_report(pending),
    )
    monkeypatch.setattr(
        converged_observer.soak_run_layout,
        "persist_observer_action_report",
        lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("synthetic write failure")
        ),
    )
    monkeypatch.setattr(
        converged_observer.converged_observer_state,
        "commit_action_report",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("state must not commit")
        ),
    )
    monkeypatch.setattr(
        converged_observer.soak_run_layout,
        "persist_observer_summary",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("summary must not persist")
        ),
    )

    with pytest.raises(RuntimeError, match="synthetic write failure"):
        converged_observer.finalize_pending_action(subject, state)

    assert state["pendingAction"] == pending


def test_finalize_pending_action_recovers_report_before_diagnostic_recapture(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
    )
    subject = replace(runtime(tmp_path), action_config=config)
    state = reportable_state(config)
    pending = state["pendingAction"]
    candidate = pending_action_report(pending)
    events = []
    persisted = soak_storage.PersistedArtifact(
        path=subject.run_paths.actions_dir
        / f"action-00000001-{pending['actionId']}.json",
        byte_count=512,
        sha256="a" * 64,
        deleted_paths=(),
        retained_count=1,
        retained_bytes=512,
    )

    def load_candidate(**kwargs):
        events.append("load")
        assert kwargs["pending_action"] == pending
        return candidate

    def validate_candidate(report, pending_action):
        events.append("validate")
        assert report is candidate
        assert pending_action == pending
        return report

    def persist_report(**kwargs):
        events.append("report")
        assert kwargs["report"] is candidate
        return persisted

    def persist_summary(**_kwargs):
        events.append("summary")
        return persisted

    monkeypatch.setattr(
        converged_observer.soak_run_layout,
        "load_observer_action_report_candidate",
        load_candidate,
    )
    monkeypatch.setattr(
        converged_observer.observer_action_report,
        "validate_observer_action_report_for_pending",
        validate_candidate,
    )
    monkeypatch.setattr(
        converged_observer,
        "capture_pending_action_evidence",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("recovered report must prevent diagnostic recapture")
        ),
    )
    monkeypatch.setattr(
        converged_observer.observer_action_report,
        "build_observer_action_report",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("recovered report must not be rebuilt")
        ),
    )
    monkeypatch.setattr(
        converged_observer.soak_run_layout,
        "persist_observer_action_report",
        persist_report,
    )
    monkeypatch.setattr(
        converged_observer.soak_run_layout,
        "persist_observer_summary",
        persist_summary,
    )

    updated = converged_observer.finalize_pending_action(subject, state)

    assert events == ["load", "validate", "report", "summary"]
    assert updated["pendingAction"] is None
    assert updated["retention"]["actions"]["latestFile"] == persisted.path.name


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


def test_run_observer_services_pending_action_before_delay_or_cycle_limit(
    tmp_path: Path,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        method="server",
        start_delay_seconds=3_600,
        search_interval_seconds=300,
        search_timeout_seconds=120,
        max_cycles=1,
    )
    subject = replace(runtime(tmp_path), action_config=config)
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
    converged_observer.persist_state(subject, reportable_state(config))
    clock = [0.0]
    action_times: list[float] = []

    def drive_action(_runtime, state, _config):
        action_times.append(clock[0])
        subject.stop_file.parent.mkdir(parents=True, exist_ok=True)
        subject.stop_file.write_text("stop\n", encoding="utf-8")
        return state

    def sleep(seconds: float) -> None:
        if not action_times:
            raise AssertionError(
                "persisted pending action was not serviced immediately"
            )
        clock[0] += seconds

    result = converged_observer.run_observer(
        subject,
        ready_timeout_seconds=30,
        poll_interval_seconds=60,
        checkpoint_interval_seconds=1_000,
        failure_threshold=3,
        monotonic=lambda: clock[0],
        sleep=sleep,
        launcher_alive=lambda _identity: True,
        capture=lambda _runtime, state: state,
        drive_action=drive_action,
    )

    assert action_times == [0.0]
    assert result["pendingAction"] is not None
    assert result["driver"]["cycles"] == config.max_cycles


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
