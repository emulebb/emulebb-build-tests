from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from emule_test_harness import converged_observer_state as observer_state
from emule_test_harness import soak_run_layout, soak_storage


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
        "latestFile": "action-00000000000000008582.json",
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
