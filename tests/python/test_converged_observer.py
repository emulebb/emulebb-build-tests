from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from emule_test_harness import converged_observer, converged_observer_state
from emule_test_harness import soak_run_layout, soak_storage


CAMPAIGN_ID = "20261025T120000Z"


@pytest.fixture(autouse=True)
def connected_action_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        converged_observer,
        "action_network_readiness",
        lambda _clients, method: {
            "ok": True,
            "method": method,
            "requiredField": "kadConnected"
            if method == "kad"
            else "ed2kConnected",
            "clients": {
                "rust": {"ready": True},
                "mfc": {"ready": True},
            },
        },
    )


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
                "preflight_archive_manifest": soak_storage.ArtifactStreamPolicy(1, 1),
                "preflight_mfc_outputs": soak_storage.ArtifactStreamPolicy(1, 1),
                "preflight_rust_outputs": soak_storage.ArtifactStreamPolicy(1, 1),
                "process_metrics": soak_storage.ArtifactStreamPolicy(1, 1),
                "process_metrics_summary": soak_storage.ArtifactStreamPolicy(1, 1),
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
    (rust_profile / "packet-dump").mkdir()
    (mfc_profile / "logs").mkdir()
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
        state = converged_observer_state.start_search_results_poll(
            state,
            client=client,
            started_at_utc="2026-10-25T12:00:02+00:00",
            deadline_utc="2026-10-25T12:02:02+00:00",
        )
        state = converged_observer_state.record_search_results_poll_attempt(
            state,
            client=client,
            attempted_at_utc="2026-10-25T12:00:03+00:00",
            next_attempt_at_utc=None,
            completed=True,
            returned_count=1,
            total_count=4,
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


def test_diagnostic_profile_directories_allow_profiles_created_during_readiness(
    tmp_path: Path,
) -> None:
    rust_profile = tmp_path / "rust-profile"
    mfc_profile = tmp_path / "mfc-profile"

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


def test_load_runtime_accepts_profile_paths_before_first_import(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from emule_test_harness import persisted_soak_controller

    output_root = tmp_path / "output"
    soak_root = output_root / "soak"
    run_paths = soak_run_layout.build_run_paths(soak_root, CAMPAIGN_ID)
    rust_profile = tmp_path / "rust-profile"
    mfc_profile = tmp_path / "mfc-profile"
    session_manifest = output_root / "persisted-soak.latest.json"
    session_manifest.parent.mkdir(parents=True)
    session_manifest.write_text(
        json.dumps(
            {
                "schema": persisted_soak_controller.MANIFEST_SCHEMA,
                "state": "running",
                "campaignId": CAMPAIGN_ID,
                "launcher": {
                    "pid": 100,
                    "creationDate": "20261025120000.000000+000",
                },
                "observerConfig": {"enabled": True},
                "controlFiles": {
                    "stop": str(output_root / "persisted-soak.stop"),
                    "lastRunManifest": str(run_paths.last_run_manifest),
                },
                "preflight": {
                    "control": {
                        "rustBaseUrl": "http://127.0.0.1:4731/api/v1",
                        "mfcBaseUrl": "http://127.0.0.1:4732/api/v1",
                    },
                    "profiles": {
                        "rust": str(rust_profile),
                        "mfc": str(mfc_profile),
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    storage = persisted_soak_controller.SessionStorageContext(
        root=run_paths.campaigns_root,
        policy=storage_policy(),
        policy_sha256="a" * 64,
        active_campaign=run_paths.campaign_dir,
        previous_campaign=None,
    )
    monkeypatch.setattr(
        persisted_soak_controller,
        "parse_session_storage_context",
        lambda _manifest, _output_root: storage,
    )

    loaded = converged_observer.load_runtime(session_manifest, output_root)

    assert loaded.diagnostic_directories == converged_observer.DiagnosticDirectories(
        rust=(rust_profile / "packet-dump").resolve(),
        mfc=(mfc_profile / "logs").resolve(),
    )
    assert not rust_profile.exists()
    assert not mfc_profile.exists()


def test_load_ready_manifest_waits_for_diagnostic_directories(tmp_path: Path) -> None:
    subject = runtime(tmp_path)
    subject.diagnostic_directories.rust.rmdir()
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

    assert converged_observer.load_ready_manifest(subject) is None

    subject.diagnostic_directories.rust.mkdir()

    assert converged_observer.load_ready_manifest(subject) is not None


def test_run_observer_waits_for_first_import_diagnostic_directory(
    tmp_path: Path,
) -> None:
    subject = runtime(tmp_path)
    subject.diagnostic_directories.rust.rmdir()
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

    def sleep(seconds: float) -> None:
        subject.diagnostic_directories.rust.mkdir()
        clock[0] += seconds

    result = converged_observer.run_observer(
        subject,
        ready_timeout_seconds=30,
        poll_interval_seconds=1,
        checkpoint_interval_seconds=5,
        failure_threshold=3,
        max_checkpoints=1,
        monotonic=lambda: clock[0],
        sleep=sleep,
        launcher_alive=lambda _identity: True,
        capture=lambda _runtime, state: converged_observer_state.record_checkpoint(
            state,
            {
                "schema": "soak_checkpoint_v1",
                "ts_utc": "2026-10-25T12:01:00+00:00",
                "rustAlive": True,
                "packetRecords": {"rust": 1, "mfc": 1},
                "totals": {"actions": 0},
            },
        ),
    )

    assert clock == [1.0]
    assert result["checkpoints"]["count"] == 1


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
                "methods": ["server", "kad", "server"],
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
        methods=("server", "kad"),
        start_delay_seconds=30.0,
        search_interval_seconds=900.0,
        search_timeout_seconds=120.0,
        max_cycles=12,
    )


def test_parse_action_config_rejects_retired_single_method_shape() -> None:
    with pytest.raises(RuntimeError, match="config fields are invalid"):
        converged_observer.parse_action_config(
            {
                "actionDriving": {
                    "enabled": True,
                    "sourceProfile": "generic_open",
                    "terms": ["linux"],
                    "method": "server",
                    "startDelaySeconds": 30,
                    "searchIntervalSeconds": 900,
                    "searchTimeoutSeconds": 120,
                    "maxCycles": 0,
                }
            }
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
        "methods": ["server"],
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
        methods=("kad",),
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
        methods=("server",),
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
        assert timeout_seconds == 30.0
        events.append(("results", client.name))
        rows = tuple({"hash": str(index) * 32} for index in range(1, 3))
        return converged_observer.converged_action_driver.SearchResultsPhase(
            rows=rows,
            total=7,
            completed=True,
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
        "run_search_results_poll_phase",
        results_phase,
    )

    first = converged_observer.capture_action_cycle(
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
    ]
    assert first["pendingAction"]["clients"]["rust"]["results"] is not None
    assert first["pendingAction"]["clients"]["mfc"]["resultPoll"] is not None

    updated = converged_observer.capture_action_cycle(
        subject,
        first,
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
    assert updated["driver"]["latestCycle"]["returnedCounts"] == {
        "rust": 2,
        "mfc": 2,
    }
    assert updated["driver"]["latestCycle"]["resultTotals"] == {
        "rust": 7,
        "mfc": 7,
    }
    assert updated["driver"]["latestCycle"]["searches"]["rust"]["results"][
        "poll"
    ] == {
        "startedAtUtc": "2026-10-25T12:01:00+00:00",
        "deadlineUtc": "2026-10-25T12:03:00+00:00",
        "attempts": 1,
        "errorCount": 0,
        "latestAttemptAtUtc": "2026-10-25T12:01:00+00:00",
        "latestError": None,
        "termination": "completed",
    }
    assert updated["pendingAction"]["diagnosticRuns"] == diagnostic_runs()
    assert updated["pendingAction"]["clients"]["mfc"]["results"]["completed"] is True
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


def test_capture_action_cycle_records_diagnostic_connectivity_skip(
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
    monkeypatch.setattr(
        converged_observer,
        "diagnostic_writer_health",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            TimeoutError("diagnostics request timed out")
        ),
    )
    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "run_search_create_phase",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("search must not start without diagnostic identities")
        ),
    )

    updated = converged_observer.capture_action_cycle(
        subject,
        new_state(config),
        config,
        now_utc=lambda: datetime(2026, 10, 25, 12, 1, tzinfo=UTC),
        now_ns=1_000_000_000,
    )

    assert updated["pendingAction"] is None
    assert updated["driver"]["cycles"] == 0
    assert updated["driver"]["cycleErrors"] == 0
    assert updated["driver"]["connectivitySkips"] == 1
    assert updated["driver"]["latestConnectivitySkip"] == {
        "attemptedAtUtc": "2026-10-25T12:01:00+00:00",
        "phase": "diagnostic_run_identity",
        "error": {
            "type": "TimeoutError",
            "message": "diagnostics request timed out",
        },
        "scheduleSlot": 1,
    }
    assert (
        converged_observer.load_json_object(
            subject.run_paths.report_dir / "summary.json"
        )
        == updated
    )


def test_action_network_readiness_is_method_specific() -> None:
    stats = {
        "rust": {"ed2kConnected": True, "kadConnected": False},
        "mfc": {"ed2kConnected": True, "kadConnected": True},
    }

    server = converged_observer.classify_action_network_readiness("server", stats)
    kad = converged_observer.classify_action_network_readiness("kad", stats)

    assert server["ok"] is True
    assert server["requiredField"] == "ed2kConnected"
    assert kad["ok"] is False
    assert kad["requiredField"] == "kadConnected"
    assert kad["clients"]["rust"]["ready"] is False
    assert kad["clients"]["mfc"]["ready"] is True


def test_capture_action_cycle_skips_disconnected_selected_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        methods=("kad",),
        search_interval_seconds=900,
    )
    subject = replace(runtime(tmp_path), action_config=config)
    readiness = {
        "ok": False,
        "method": "kad",
        "requiredField": "kadConnected",
        "clients": {
            "rust": {
                "ed2kConnected": True,
                "kadConnected": False,
                "ready": False,
            },
            "mfc": {
                "ed2kConnected": True,
                "kadConnected": True,
                "ready": True,
            },
        },
    }
    monkeypatch.setattr(
        converged_observer,
        "diagnostic_writer_health",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("diagnostic identity must follow network readiness")
        ),
    )
    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "run_search_create_phase",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("search must not start on a disconnected network")
        ),
    )

    updated = converged_observer.capture_action_cycle(
        subject,
        new_state(config),
        config,
        now_utc=lambda: datetime(2026, 10, 25, 12, 1, tzinfo=UTC),
        now_ns=1_000_000_000,
        readiness_probe=lambda _clients, _method: readiness,
    )

    assert updated["pendingAction"] is None
    assert updated["driver"]["cycles"] == 0
    assert updated["driver"]["connectivitySkips"] == 1
    assert updated["driver"]["latestConnectivitySkip"] == {
        "attemptedAtUtc": "2026-10-25T12:01:00+00:00",
        "phase": "network_readiness",
        "method": "kad",
        "readiness": readiness,
        "scheduleSlot": 1,
    }


def test_connectivity_skip_advances_to_the_next_scheduled_method(
    tmp_path: Path,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        methods=("server", "kad"),
        search_interval_seconds=900,
    )
    subject = replace(runtime(tmp_path), action_config=config)
    observed_methods: list[str] = []

    def not_ready(_clients, method: str) -> dict[str, object]:
        observed_methods.append(method)
        required_field = "ed2kConnected" if method == "server" else "kadConnected"
        return {
            "ok": False,
            "method": method,
            "requiredField": required_field,
            "clients": {
                client: {required_field: False, "ready": False}
                for client in ("rust", "mfc")
            },
        }

    first = converged_observer.capture_action_cycle(
        subject,
        new_state(config),
        config,
        now_utc=lambda: datetime(2026, 10, 25, 12, 1, tzinfo=UTC),
        now_ns=1_000_000_000,
        readiness_probe=not_ready,
    )
    second = converged_observer.capture_action_cycle(
        subject,
        first,
        config,
        now_utc=lambda: datetime(2026, 10, 25, 12, 2, tzinfo=UTC),
        now_ns=2_000_000_000,
        readiness_probe=not_ready,
    )

    assert observed_methods == ["server", "kad"]
    assert second["driver"]["cycles"] == 0
    assert second["driver"]["connectivitySkips"] == 2
    assert second["driver"]["latestConnectivitySkip"]["scheduleSlot"] == 2
    assert second["scheduler"]["nextCycle"] == 1
    assert second["scheduler"]["nextScheduleSlot"] == 3


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
        assert timeout_seconds == 30.0
        polled.append((client.name, search_id))
        return converged_observer.converged_action_driver.SearchResultsPhase(
            rows=({"hash": "a" * 32},),
            total=5,
            completed=True,
            error=None,
        )

    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "run_search_results_poll_phase",
        results_phase,
    )

    first = converged_observer.capture_action_cycle(
        subject,
        converged_observer.load_state(subject),
        config,
        now_utc=lambda: datetime(2026, 10, 25, 12, 1, tzinfo=UTC),
        finalize_action=lambda _runtime, action_state, **_kwargs: action_state,
    )
    updated = converged_observer.capture_action_cycle(
        subject,
        first,
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


def test_capture_action_cycle_expires_one_overdue_poll_without_get(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        search_timeout_seconds=3,
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
        state = converged_observer_state.start_search_results_poll(
            state,
            client=client,
            started_at_utc="2026-10-25T12:00:02+00:00",
            deadline_utc="2026-10-25T12:00:05+00:00",
        )
    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "run_search_results_poll_phase",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("expired result poll must not issue a GET")
        ),
    )

    updated = converged_observer.capture_action_cycle(
        subject,
        state,
        config,
        now_utc=lambda: datetime(2026, 10, 25, 12, 1, tzinfo=UTC),
        finalize_action=lambda _runtime, action_state, **_kwargs: action_state,
    )

    rust = updated["pendingAction"]["clients"]["rust"]
    assert rust["resultPoll"] is None
    assert rust["results"]["error"]["type"] == "SearchResultsDeadlineElapsed"
    assert rust["results"]["poll"]["termination"] == "expired"
    assert updated["pendingAction"]["clients"]["mfc"]["resultPoll"] is not None
    assert updated["driver"]["cycles"] == 0


def test_capture_action_cycle_reclassifies_get_finishing_after_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        search_timeout_seconds=3,
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
    state = converged_observer_state.start_search_results_poll(
        state,
        client="rust",
        started_at_utc="2026-10-25T12:00:02+00:00",
        deadline_utc="2026-10-25T12:00:05+00:00",
    )
    current_time = {
        "value": datetime(2026, 10, 25, 12, 0, 4, 500_000, tzinfo=UTC)
    }

    def results_phase(client, search_id: str, *, timeout_seconds: float):
        assert client.name == "rust"
        assert search_id == "rust-search-9"
        assert timeout_seconds == pytest.approx(0.5)
        current_time["value"] = datetime(
            2026, 10, 25, 12, 0, 5, 250_000, tzinfo=UTC
        )
        return converged_observer.converged_action_driver.SearchResultsPhase(
            rows=({"hash": "a" * 32},),
            total=4,
            completed=True,
            error=None,
        )

    monkeypatch.setattr(
        converged_observer.converged_action_driver,
        "run_search_results_poll_phase",
        results_phase,
    )

    updated = converged_observer.capture_action_cycle(
        subject,
        state,
        config,
        now_utc=lambda: current_time["value"],
        finalize_action=lambda _runtime, action_state, **_kwargs: action_state,
    )

    rust_results = updated["pendingAction"]["clients"]["rust"]["results"]
    assert rust_results["completed"] is False
    assert rust_results["returnedCount"] == 1
    assert rust_results["totalCount"] == 4
    assert rust_results["completedAtUtc"] == "2026-10-25T12:00:05.250000+00:00"
    assert rust_results["poll"]["termination"] == "deadline"
    assert updated["pendingAction"]["clients"]["mfc"]["resultPoll"] is not None


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
        state = converged_observer_state.start_search_results_poll(
            state,
            client=client,
            started_at_utc="2026-10-25T12:00:02+00:00",
            deadline_utc="2026-10-25T12:02:02+00:00",
        )
        state = converged_observer_state.record_search_results_poll_attempt(
            state,
            client=client,
            attempted_at_utc="2026-10-25T12:00:03+00:00",
            next_attempt_at_utc=None,
            completed=True,
            returned_count=1,
            total_count=4,
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
        "run_search_results_poll_phase",
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


def test_run_observer_services_checkpoints_between_result_attempts(
    tmp_path: Path,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        start_delay_seconds=0,
        search_interval_seconds=300,
        search_timeout_seconds=120,
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
    started_at = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
    state = converged_observer_state.reserve_driver_cycle(
        new_state(config),
        query="linux",
        method="server",
        reserved_at_utc=started_at.isoformat(),
        diagnostic_runs=diagnostic_runs(),
    )
    state = converged_observer_state.prepare_search_create(
        state,
        client="rust",
        prepared_at_utc=started_at.isoformat(),
    )
    state = converged_observer_state.complete_search_create(
        state,
        client="rust",
        completed_at_utc=started_at.isoformat(),
        search_id="rust-search-1",
        error=None,
    )
    state = converged_observer_state.start_search_results_poll(
        state,
        client="rust",
        started_at_utc=started_at.isoformat(),
        deadline_utc=(started_at + timedelta(seconds=120)).isoformat(),
    )
    state = converged_observer_state.skip_search_create(
        state,
        client="mfc",
        completed_at_utc=started_at.isoformat(),
        error={"type": "SearchCreateSkipped", "message": "fixture"},
    )
    converged_observer.persist_state(subject, state)
    clock = [0.0]
    events: list[tuple[str, float]] = []
    attempts = [0]

    def capture(_runtime, action_state):
        events.append(("checkpoint", clock[0]))
        return converged_observer_state.record_checkpoint(
            action_state,
            {
                "schema": "soak_checkpoint_v1",
                "ts_utc": (started_at + timedelta(seconds=clock[0])).isoformat(),
                "rustAlive": True,
                "packetRecords": {"rust": 1, "mfc": 1},
                "totals": {"actions": 0},
            },
        )

    def drive_action(_runtime, action_state, _config):
        events.append(("action", clock[0]))
        attempts[0] += 1
        completed = attempts[0] == 2
        updated = converged_observer_state.record_search_results_poll_attempt(
            action_state,
            client="rust",
            attempted_at_utc=(
                started_at + timedelta(seconds=clock[0])
            ).isoformat(),
            next_attempt_at_utc=None
            if completed
            else (started_at + timedelta(seconds=2)).isoformat(),
            completed=completed,
            returned_count=attempts[0],
            total_count=attempts[0] + 4,
            error=None,
        )
        if completed:
            subject.stop_file.parent.mkdir(parents=True, exist_ok=True)
            subject.stop_file.write_text("stop\n", encoding="utf-8")
        return updated

    result = converged_observer.run_observer(
        subject,
        ready_timeout_seconds=30,
        poll_interval_seconds=10,
        checkpoint_interval_seconds=1,
        failure_threshold=3,
        monotonic=lambda: clock[0],
        now_utc=lambda: started_at + timedelta(seconds=clock[0]),
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        launcher_alive=lambda _identity: True,
        capture=capture,
        drive_action=drive_action,
    )

    assert events == [
        ("checkpoint", 0.0),
        ("action", 0.0),
        ("checkpoint", 1.0),
        ("checkpoint", 2.0),
        ("action", 2.0),
    ]
    assert result["checkpoints"]["count"] == 3
    assert result["pendingAction"]["clients"]["rust"]["results"] is not None


def test_run_observer_schedules_actions_without_owning_clients(tmp_path: Path) -> None:
    subject = replace(
        runtime(tmp_path),
        action_config=converged_observer.ObserverActionConfig(
            enabled=True,
            source_profile="generic_open",
            terms=("linux", "debian"),
            methods=("global", "kad"),
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
    started_at = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
    action_cycles: list[int] = []
    action_methods: list[str] = []
    action_queries: list[str] = []
    action_times: list[float] = []

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
        action_times.append(clock[0])
        query, method = converged_observer.scheduled_action(config, cycle)
        action_queries.append(query)
        action_methods.append(method)
        updated = converged_observer_state.record_driver_cycle(
            state,
            {
                "cycle": cycle,
                "query": query,
                "method": method,
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
        now_utc=lambda: started_at + timedelta(seconds=clock[0]),
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        launcher_alive=lambda _identity: True,
        capture=capture,
        drive_action=drive_action,
    )

    assert action_cycles == [1, 2]
    assert action_methods == ["global", "kad"]
    assert action_queries == ["linux", "linux"]
    assert action_times == [0.0, 300.0]
    assert result["driver"]["cycles"] == 2
    assert result["driver"]["latestCycle"]["query"] == "linux"
    assert result["driver"]["latestCycle"]["method"] == "kad"
    assert result["scheduler"]["nextActionAtUtc"] is None


def test_scheduled_action_runs_every_method_for_each_term() -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux", "debian"),
        methods=("server", "kad"),
    )

    assert [
        converged_observer.scheduled_action(config, cycle)
        for cycle in range(1, 6)
    ] == [
        ("linux", "server"),
        ("linux", "kad"),
        ("debian", "server"),
        ("debian", "kad"),
        ("linux", "server"),
    ]


def test_reconcile_action_deadline_persists_initial_and_post_action_schedule(
    tmp_path: Path,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        methods=("server",),
        start_delay_seconds=60,
        search_interval_seconds=300,
        search_timeout_seconds=120,
    )
    subject = replace(runtime(tmp_path), action_config=config)
    started_at = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)

    scheduled = converged_observer.reconcile_action_deadline(
        subject,
        new_state(config),
        now_utc=lambda: started_at,
    )

    assert (
        scheduled["scheduler"]["nextActionAtUtc"]
        == (started_at + timedelta(seconds=60)).isoformat()
    )
    assert (
        converged_observer.load_json_object(
            subject.run_paths.report_dir / "summary.json"
        )
        == scheduled
    )

    preserved = converged_observer.reconcile_action_deadline(
        subject,
        scheduled,
        now_utc=lambda: started_at + timedelta(seconds=30),
    )
    assert preserved == scheduled

    completed = converged_observer_state.record_driver_cycle(
        preserved,
        {"cycle": 1, "query": "linux", "method": "server"},
    )
    rescheduled = converged_observer.reconcile_action_deadline(
        subject,
        completed,
        now_utc=lambda: started_at + timedelta(seconds=90),
        after_action=True,
    )
    assert (
        rescheduled["scheduler"]["nextActionAtUtc"]
        == (started_at + timedelta(seconds=390)).isoformat()
    )


def test_run_observer_services_exact_persisted_utc_deadline_after_restart(
    tmp_path: Path,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        methods=("server",),
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
    started_at = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
    deadline = started_at + timedelta(seconds=120)
    state = converged_observer_state.set_next_action_deadline(
        new_state(config),
        deadline.isoformat(),
    )
    converged_observer.persist_state(subject, state)
    clock = [0.0]
    action_times: list[float] = []

    def drive_action(_runtime, action_state, _config):
        action_times.append(clock[0])
        assert action_state["scheduler"]["nextActionAtUtc"] == deadline.isoformat()
        subject.stop_file.parent.mkdir(parents=True, exist_ok=True)
        subject.stop_file.write_text("stop\n", encoding="utf-8")
        return converged_observer_state.record_driver_cycle(
            action_state,
            {"cycle": 1, "query": "linux", "method": "server"},
        )

    result = converged_observer.run_observer(
        subject,
        ready_timeout_seconds=30,
        poll_interval_seconds=60,
        checkpoint_interval_seconds=1_000,
        failure_threshold=3,
        monotonic=lambda: clock[0],
        now_utc=lambda: started_at + timedelta(seconds=clock[0]),
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        launcher_alive=lambda _identity: True,
        capture=lambda _runtime, action_state: action_state,
        drive_action=drive_action,
    )

    assert action_times == [120.0]
    assert result["scheduler"]["nextActionAtUtc"] is None


def test_run_observer_reconciles_missing_deadline_after_report_commit(
    tmp_path: Path,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        methods=("server",),
        start_delay_seconds=60,
        search_interval_seconds=300,
        search_timeout_seconds=120,
        max_cycles=2,
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
    state = reportable_state(config)
    state = converged_observer_state.commit_action_report(
        state,
        pending_action_report(state["pendingAction"]),
    )
    converged_observer.persist_state(subject, state)
    started_at = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
    first_deadline = started_at + timedelta(seconds=300)
    clock = [0.0]
    action_times: list[float] = []

    def drive_action(_runtime, action_state, _config):
        action_times.append(clock[0])
        assert action_state["scheduler"]["nextActionAtUtc"] == (
            first_deadline.isoformat()
        )
        subject.stop_file.parent.mkdir(parents=True, exist_ok=True)
        subject.stop_file.write_text("stop\n", encoding="utf-8")
        return action_state

    result = converged_observer.run_observer(
        subject,
        ready_timeout_seconds=30,
        poll_interval_seconds=60,
        checkpoint_interval_seconds=1_000,
        failure_threshold=3,
        monotonic=lambda: clock[0],
        now_utc=lambda: started_at + timedelta(seconds=clock[0]),
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        launcher_alive=lambda _identity: True,
        capture=lambda _runtime, action_state: action_state,
        drive_action=drive_action,
    )

    assert action_times == [300.0]
    assert (
        result["scheduler"]["nextActionAtUtc"]
        == (started_at + timedelta(seconds=600)).isoformat()
    )


def test_run_observer_services_pending_action_before_delay_or_cycle_limit(
    tmp_path: Path,
) -> None:
    config = converged_observer.ObserverActionConfig(
        enabled=True,
        source_profile="generic_open",
        terms=("linux",),
        methods=("server",),
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
