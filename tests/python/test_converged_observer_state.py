from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from emule_test_harness import converged_observer_state as observer_state
from emule_test_harness import soak_run_layout, soak_storage


CONFIGURATION_DIGEST = "a" * 64


def diagnostic_runs() -> dict[str, dict[str, object]]:
    return {
        "rust": {"processId": 4101, "runId": "rust-run"},
        "mfc": {"processId": 4201, "runId": "mfc-run"},
    }


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
                "observer_actions": soak_storage.ArtifactStreamPolicy(2_048, 7),
                "observer_checkpoints": soak_storage.ArtifactStreamPolicy(2_048, 11),
                "observer_summary": soak_storage.ArtifactStreamPolicy(8_192, 1),
            }
        ),
    )


def action_report(
    campaign_id: str, sequence: int, observed_utc: str
) -> dict[str, object]:
    divergent = sequence % 10 == 0
    return {
        "schema": "soak_action_diff_v1",
        "campaignId": campaign_id,
        "seq": sequence,
        "actionId": f"{campaign_id}-cycle-{sequence:08d}",
        "cycle": sequence,
        "kind": "search" if sequence % 2 else "download",
        "method": "server",
        "key": f"exact-local-key-{sequence}",
        "label": f"exact local label {sequence}",
        "window": {"t0": observed_utc, "t1": observed_utc},
        "observed": {"rust": observed_utc, "mfc": observed_utc},
        "verdict": "divergence" if divergent else "coverage-parity",
        "coverageOk": not divergent,
        "byteMatch": False,
        "diagOk": not divergent,
    }


def checkpoint(observed_utc: str, actions: int) -> dict[str, object]:
    return {
        "schema": "soak_checkpoint_v1",
        "ts_utc": observed_utc,
        "rustAlive": True,
        "packetRecords": {"rust": actions * 3, "mfc": actions * 2},
        "totals": {"actions": actions},
        "errorLogHits": [],
    }


def synthetic_persistence(
    path: Path,
    *,
    retained_count: int,
    retained_bytes: int,
) -> soak_storage.PersistedArtifact:
    return soak_storage.PersistedArtifact(
        path=path,
        byte_count=100,
        sha256="0" * 64,
        deleted_paths=(),
        retained_count=retained_count,
        retained_bytes=retained_bytes,
    )


def run_three_day_simulation(root: Path) -> tuple[bytes, dict[str, object]]:
    campaign_id = "20261001T000000Z"
    paths = soak_run_layout.build_run_paths(root / "soak", campaign_id)
    store = soak_storage.BoundedArtifactStore(paths.soak_root, storage_policy())
    state = observer_state.new_state(
        campaign_id,
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=5,
        recent_anomaly_limit=3,
    )
    start = datetime(2026, 10, 1, tzinfo=UTC)
    summary_result = None
    checkpoint_count = 3 * 24 * 12
    for index in range(checkpoint_count):
        observed = start + timedelta(minutes=index * 5)
        observed_utc = observed.isoformat()
        checkpoint_payload = checkpoint(observed_utc, state["totals"]["actions"])
        state = observer_state.record_checkpoint(state, checkpoint_payload)
        if index >= checkpoint_count - 24:
            checkpoint_result = soak_run_layout.persist_observer_checkpoint(
                paths=paths,
                store=store,
                checkpoint=checkpoint_payload,
                now_ns=index * 10 + 1,
            )
        else:
            checkpoint_result = synthetic_persistence(
                paths.checkpoints_dir / f"checkpoint-{index * 10 + 1:020d}.json",
                retained_count=min(index + 1, 11),
                retained_bytes=min(index + 1, 11) * 100,
            )
        state = observer_state.record_stream_retention(
            state,
            stream="checkpoints",
            persisted=checkpoint_result,
        )

        if index % 6 == 0:
            sequence = state["nextActionSeq"]
            report = action_report(campaign_id, sequence, observed_utc)
            if sequence > 128:
                action_result = soak_run_layout.persist_observer_action_report(
                    paths=paths,
                    store=store,
                    report=report,
                    now_ns=index * 10 + 2,
                )
            else:
                action_result = synthetic_persistence(
                    paths.actions_dir / f"action-{index * 10 + 2:020d}.json",
                    retained_count=min(sequence, 7),
                    retained_bytes=min(sequence, 7) * 100,
                )
            state = observer_state.record_action(state, report)
            state = observer_state.record_stream_retention(
                state,
                stream="actions",
                persisted=action_result,
            )

        if index in {checkpoint_count // 2, checkpoint_count - 1}:
            summary_result = soak_run_layout.persist_observer_summary(
                paths=paths,
                store=store,
                summary=state,
                now_ns=index * 10 + 3,
            )
        if index == checkpoint_count // 2 and summary_result is not None:
            state = observer_state.validate_state(
                json.loads(summary_result.path.read_text(encoding="utf-8")),
                campaign_id=campaign_id,
            )

    assert summary_result is not None
    assert summary_result.path.read_bytes() == observer_state.canonical_bytes(state)
    return summary_result.path.read_bytes(), state


def test_observer_state_rejects_discontinuous_action_sequence() -> None:
    state = observer_state.new_state(
        "20261001T000000Z",
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=2,
        recent_anomaly_limit=1,
    )
    report = action_report(
        "20261001T000000Z",
        2,
        "2026-10-01T00:00:00+00:00",
    )

    with pytest.raises(RuntimeError, match="sequence is discontinuous"):
        observer_state.record_action(state, report)


def test_observer_state_reduces_driver_activity_without_history_growth() -> None:
    state = observer_state.new_state(
        "20261001T000000Z",
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=2,
        recent_anomaly_limit=1,
    )

    state = observer_state.record_driver_cycle(
        state,
        {
            "cycle": 1,
            "error": "RuntimeError: unavailable",
            "download": {"scheduled": True},
        },
    )
    state = observer_state.record_connectivity_skip(
        state,
        {"ts": "2026-10-01T00:05:00+00:00", "reason": "server-disconnected"},
    )

    assert state["driver"] == {
        "cycles": 1,
        "cycleErrors": 1,
        "downloadsScheduled": 1,
        "connectivitySkips": 1,
        "latestCycle": {
            "cycle": 1,
            "error": "RuntimeError: unavailable",
            "download": {"scheduled": True},
        },
        "latestConnectivitySkip": {
            "ts": "2026-10-01T00:05:00+00:00",
            "reason": "server-disconnected",
        },
    }


def test_observer_state_counts_structured_cycle_failure() -> None:
    state = observer_state.new_state(
        "20261001T000000Z",
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=2,
        recent_anomaly_limit=1,
    )

    state = observer_state.record_driver_cycle(
        state,
        {
            "cycle": 1,
            "ok": False,
            "errors": [
                {
                    "client": "mfc",
                    "phase": "search-create",
                    "type": "RuntimeError",
                    "message": "exact failure",
                }
            ],
        },
    )

    assert state["driver"]["cycles"] == 1
    assert state["driver"]["cycleErrors"] == 1
    assert state["driver"]["latestCycle"]["errors"][0]["message"] == "exact failure"


def test_observer_state_rejects_configuration_digest_mismatch() -> None:
    state = observer_state.new_state(
        "20261001T000000Z",
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=2,
        recent_anomaly_limit=1,
    )

    with pytest.raises(RuntimeError, match="configuration identity is invalid"):
        observer_state.validate_state(state, configuration_digest="b" * 64)


@pytest.mark.parametrize(
    ("verdict", "total_field"),
    (
        ("not-assessable", "notAssessable"),
        ("evidence-incomplete", "evidenceIncomplete"),
    ),
)
def test_observer_state_counts_inconclusive_action_verdicts(
    verdict: str,
    total_field: str,
) -> None:
    state = observer_state.new_state(
        "20261001T000000Z",
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=2,
        recent_anomaly_limit=1,
    )
    report = action_report(
        state["campaignId"],
        1,
        "2026-10-01T00:00:00+00:00",
    )
    report["verdict"] = verdict

    updated = observer_state.record_action(state, report)

    assert updated["totals"][total_field] == 1
    assert updated["histograms"]["verdict"][verdict] == 1
    assert updated["recentAnomalies"][0]["verdict"] == verdict


@pytest.mark.parametrize("cycle", (1, 3))
def test_observer_state_rejects_duplicate_or_skipped_driver_cycle(cycle: int) -> None:
    state = observer_state.new_state(
        "20261001T000000Z",
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=2,
        recent_anomaly_limit=1,
    )
    state = observer_state.record_driver_cycle(state, {"cycle": 1})

    with pytest.raises(RuntimeError, match="driver cycle is discontinuous"):
        observer_state.record_driver_cycle(state, {"cycle": cycle})


def test_pending_action_round_trip_preserves_one_sided_exact_outcomes() -> None:
    state = observer_state.new_state(
        "20261001T000000Z",
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=2,
        recent_anomaly_limit=1,
    )
    state = observer_state.set_next_action_deadline(state, "2026-10-01T00:05:00+00:00")
    state = observer_state.reserve_driver_cycle(
        state,
        query="exact ünicode query",
        method="global",
        reserved_at_utc="2026-10-01T00:00:00+00:00",
        diagnostic_runs=diagnostic_runs(),
    )
    state = observer_state.prepare_search_create(
        state,
        client="rust",
        prepared_at_utc="2026-10-01T00:00:01+00:00",
    )
    state = observer_state.complete_search_create(
        state,
        client="rust",
        completed_at_utc="2026-10-01T00:00:02+00:00",
        search_id="rust-search-1",
        error=None,
    )
    exact_error = {
        "type": "RuntimeError",
        "message": "MFC exact create failure: ünicode",
    }
    state = observer_state.prepare_search_create(
        state,
        client="mfc",
        prepared_at_utc="2026-10-01T00:00:03+00:00",
    )
    state = observer_state.complete_search_create(
        state,
        client="mfc",
        completed_at_utc="2026-10-01T00:00:04+00:00",
        search_id=None,
        error=exact_error,
    )
    state = observer_state.record_search_results(
        state,
        client="rust",
        completed_at_utc="2026-10-01T00:02:00+00:00",
        completed=False,
        result_count=3,
        error=None,
    )
    state = observer_state.record_driver_cycle(
        state,
        {
            "cycle": 1,
            "actionId": "20261001T000000Z-cycle-00000001",
            "ok": False,
            "errors": [exact_error],
        },
    )
    state = observer_state.mark_evidence_pending(
        state, window_end_utc="2026-10-01T00:03:00+00:00"
    )

    reloaded = observer_state.validate_state(
        json.loads(observer_state.canonical_bytes(state)),
        campaign_id="20261001T000000Z",
        configuration_digest=CONFIGURATION_DIGEST,
    )

    assert reloaded["scheduler"] == {
        "nextCycle": 2,
        "nextActionAtUtc": "2026-10-01T00:05:00+00:00",
    }
    assert reloaded["pendingAction"]["reportSeq"] == 1
    assert reloaded["pendingAction"]["query"] == "exact ünicode query"
    assert reloaded["pendingAction"]["clients"]["mfc"]["create"]["error"] == exact_error
    assert reloaded["pendingAction"]["clients"]["rust"]["results"]["completed"] is False
    assert reloaded["pendingAction"]["evidence"] == {
        "status": "pending",
        "windowEndUtc": "2026-10-01T00:03:00+00:00",
    }


def test_pending_action_rejects_duplicate_reservation_and_create() -> None:
    state = observer_state.new_state(
        "20261001T000000Z",
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=2,
        recent_anomaly_limit=1,
    )
    state = observer_state.reserve_driver_cycle(
        state,
        query="linux",
        method="server",
        reserved_at_utc="2026-10-01T00:00:00+00:00",
        diagnostic_runs=diagnostic_runs(),
    )

    with pytest.raises(RuntimeError, match="already has a pending action"):
        observer_state.reserve_driver_cycle(
            state,
            query="debian",
            method="server",
            reserved_at_utc="2026-10-01T00:01:00+00:00",
            diagnostic_runs=diagnostic_runs(),
        )

    state = observer_state.prepare_search_create(
        state,
        client="rust",
        prepared_at_utc="2026-10-01T00:00:01+00:00",
    )
    with pytest.raises(RuntimeError, match="create is already prepared"):
        observer_state.prepare_search_create(
            state,
            client="rust",
            prepared_at_utc="2026-10-01T00:00:02+00:00",
        )


def test_prepared_create_survives_restart_and_can_fail_closed() -> None:
    state = observer_state.new_state(
        "20261001T000000Z",
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=2,
        recent_anomaly_limit=1,
    )
    state = observer_state.reserve_driver_cycle(
        state,
        query="debian",
        method="server",
        reserved_at_utc="2026-10-01T00:00:00+00:00",
        diagnostic_runs=diagnostic_runs(),
    )
    state = observer_state.prepare_search_create(
        state,
        client="rust",
        prepared_at_utc="2026-10-01T00:00:01+00:00",
    )
    state = observer_state.validate_state(
        json.loads(observer_state.canonical_bytes(state))
    )

    assert state["pendingAction"]["clients"]["rust"]["create"] == {
        "status": "prepared",
        "preparedAtUtc": "2026-10-01T00:00:01+00:00",
        "completedAtUtc": None,
        "searchId": None,
        "error": None,
    }
    with pytest.raises(RuntimeError, match="driver cycle is premature"):
        observer_state.record_driver_cycle(
            state,
            {
                "cycle": 1,
                "actionId": "20261001T000000Z-cycle-00000001",
            },
        )
    exact_error = {
        "type": "AmbiguousSearchCreate",
        "message": "restart observed a prepared POST without a terminal outcome",
    }
    state = observer_state.complete_search_create(
        state,
        client="rust",
        completed_at_utc="2026-10-01T00:00:02+00:00",
        search_id=None,
        error=exact_error,
    )
    state = observer_state.skip_search_create(
        state,
        client="mfc",
        completed_at_utc="2026-10-01T00:00:02+00:00",
        error={
            "type": "SearchCreateSkipped",
            "message": "peer create is ambiguous",
        },
    )

    assert state["pendingAction"]["clients"]["rust"]["create"]["error"] == exact_error
    assert state["pendingAction"]["clients"]["mfc"]["create"]["status"] == "skipped"
    state = observer_state.record_driver_cycle(
        state,
        {
            "cycle": 1,
            "actionId": "20261001T000000Z-cycle-00000001",
            "ok": False,
        },
    )
    assert state["driver"]["cycles"] == 1


def test_matching_action_report_is_the_only_commit_that_clears_pending() -> None:
    state = observer_state.new_state(
        "20261001T000000Z",
        configuration_digest=CONFIGURATION_DIGEST,
        recent_action_limit=2,
        recent_anomaly_limit=1,
    )
    state = observer_state.reserve_driver_cycle(
        state,
        query="linux",
        method="kad",
        reserved_at_utc="2026-10-01T00:00:00+00:00",
        diagnostic_runs=diagnostic_runs(),
    )
    for client in ("rust", "mfc"):
        state = observer_state.prepare_search_create(
            state,
            client=client,
            prepared_at_utc="2026-10-01T00:00:01+00:00",
        )
        state = observer_state.complete_search_create(
            state,
            client=client,
            completed_at_utc="2026-10-01T00:00:02+00:00",
            search_id=f"{client}-search-1",
            error=None,
        )
        state = observer_state.record_search_results(
            state,
            client=client,
            completed_at_utc="2026-10-01T00:01:00+00:00",
            completed=True,
            result_count=2,
            error=None,
        )
    state = observer_state.record_driver_cycle(
        state,
        {
            "cycle": 1,
            "actionId": "20261001T000000Z-cycle-00000001",
            "ok": True,
        },
    )
    state = observer_state.mark_evidence_pending(
        state, window_end_utc="2026-10-01T00:02:00+00:00"
    )
    report = action_report(
        "20261001T000000Z",
        1,
        "2026-10-01T00:02:00+00:00",
    )
    report.update({"actionId": "wrong", "cycle": 1})

    with pytest.raises(RuntimeError, match="require commit_action_report"):
        observer_state.record_action(state, report)
    with pytest.raises(RuntimeError, match="report identity is invalid"):
        observer_state.commit_action_report(state, report)

    report["actionId"] = "20261001T000000Z-cycle-00000001"
    committed = observer_state.commit_action_report(state, report)

    assert committed["pendingAction"] is None
    assert committed["nextActionSeq"] == 2
    assert committed["totals"]["actions"] == 1
    assert committed["driver"]["cycles"] == 1
    assert committed["scheduler"]["nextCycle"] == 2


def test_three_day_observer_simulation_is_restart_safe_and_bounded(
    tmp_path: Path,
) -> None:
    persisted_bytes, state = run_three_day_simulation(tmp_path)

    assert persisted_bytes == observer_state.canonical_bytes(state)
    assert state["checkpoints"]["count"] == 864
    assert state["totals"]["actions"] == 144
    assert state["nextActionSeq"] == 145
    assert state["totals"]["coverageParity"] == 130
    assert state["totals"]["divergence"] == 14
    assert state["retention"]["actions"] == {
        "seen": 144,
        "retained": 7,
        "omitted": 137,
        "retainedBytes": state["retention"]["actions"]["retainedBytes"],
        "latestFile": "action-00000144-20261001T000000Z-cycle-00000144.json",
    }
    assert state["retention"]["checkpoints"] == {
        "seen": 864,
        "retained": 11,
        "omitted": 853,
        "retainedBytes": state["retention"]["checkpoints"]["retainedBytes"],
        "latestFile": "checkpoint-00000000000000008631.json",
    }
    assert len(state["recentActions"]) == 5
    assert len(state["recentAnomalies"]) == 3
    report_dir = tmp_path / "soak" / "campaigns" / "20261001T000000Z" / "report"
    assert len(list((report_dir / "actions").glob("*.json"))) == 7
    assert len(list((report_dir / "checkpoints").glob("*.json"))) == 11
    assert (report_dir / "summary.json").stat().st_size < 8_192
