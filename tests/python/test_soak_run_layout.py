from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from emule_test_harness import soak_run_layout, soak_storage
from emule_test_harness.windows_processes import WindowsProcessInfo


def artifact_store(
    paths: soak_run_layout.SoakRunPaths,
    *,
    segment_retained: int = 2,
) -> soak_storage.BoundedArtifactStore:
    policy = soak_storage.SoakStoragePolicy(
        max_total_bytes=10 * 1024 * 1024,
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
                "diagnostic_indexes": soak_storage.ArtifactStreamPolicy(1, 1),
                "diagnostic_pins": soak_storage.ArtifactStreamPolicy(1, 1),
                "diagnostic_segments": soak_storage.ArtifactStreamPolicy(
                    1_048_576, segment_retained
                ),
                "observer_actions": soak_storage.ArtifactStreamPolicy(1_024, 2),
                "observer_checkpoints": soak_storage.ArtifactStreamPolicy(1_024, 2),
                "observer_summary": soak_storage.ArtifactStreamPolicy(4_096, 1),
            }
        ),
    )
    return soak_storage.BoundedArtifactStore(paths.soak_root, policy)


def write_diag_segment(
    directory: Path,
    *,
    client: str,
    process_id: int,
    run_id: str,
    segment_id: int,
    sequence: int,
) -> Path:
    path = directory / (
        f"emulebb-{client}-diag-{process_id}-{run_id}-{segment_id:06d}.jsonl"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": "diag_event_v2",
                "client": client,
                "processId": process_id,
                "runId": run_id,
                "segmentId": segment_id,
                "seq": sequence,
                "streamSeq": sequence,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_persist_observer_artifacts_enforces_each_stream_budget(tmp_path: Path) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20261025T120000Z")
    store = artifact_store(paths)

    action_results = [
        soak_run_layout.persist_observer_action_report(
            paths=paths,
            store=store,
            report={
                "schema": "action",
                "campaignId": paths.campaign_id,
                "seq": sequence,
                "actionId": f"{paths.campaign_id}-cycle-{sequence:08d}",
            },
            now_ns=sequence,
        )
        for sequence in range(1, 4)
    ]
    checkpoint_results = [
        soak_run_layout.persist_observer_checkpoint(
            paths=paths,
            store=store,
            checkpoint={"schema": "checkpoint", "sequence": sequence},
            now_ns=sequence,
        )
        for sequence in range(1, 4)
    ]
    first_summary = soak_run_layout.persist_observer_summary(
        paths=paths,
        store=store,
        summary={"schema": "summary", "actions": 1},
        now_ns=1,
    )
    second_summary = soak_run_layout.persist_observer_summary(
        paths=paths,
        store=store,
        summary={"schema": "summary", "actions": 2},
        now_ns=2,
    )

    assert [path.name for path in sorted(paths.actions_dir.glob("*.json"))] == [
        "action-00000002-20261025T120000Z-cycle-00000002.json",
        "action-00000003-20261025T120000Z-cycle-00000003.json",
    ]
    assert action_results[-1].deleted_paths == (
        paths.actions_dir.resolve()
        / "action-00000001-20261025T120000Z-cycle-00000001.json",
    )
    assert [path.name for path in sorted(paths.checkpoints_dir.glob("*.json"))] == [
        "checkpoint-00000000000000000002.json",
        "checkpoint-00000000000000000003.json",
    ]
    assert checkpoint_results[-1].deleted_paths == (
        paths.checkpoints_dir.resolve() / "checkpoint-00000000000000000001.json",
    )
    assert (
        first_summary.path == second_summary.path == paths.report_dir / "summary.json"
    )
    assert json.loads(second_summary.path.read_text(encoding="utf-8"))["actions"] == 2


def test_persist_observer_action_report_reuses_exact_committed_identity(
    tmp_path: Path,
) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20261025T120000Z")
    store = artifact_store(paths)
    report = {
        "schema": "action",
        "campaignId": paths.campaign_id,
        "seq": 1,
        "actionId": f"{paths.campaign_id}-cycle-00000001",
        "exact": "unredacted local evidence",
    }

    first = soak_run_layout.persist_observer_action_report(
        paths=paths,
        store=store,
        report=report,
        now_ns=1,
    )
    replay = soak_run_layout.persist_observer_action_report(
        paths=paths,
        store=store,
        report=report,
        now_ns=2,
    )

    assert replay.path == first.path
    assert replay.sha256 == first.sha256
    assert replay.deleted_paths == ()
    assert list(paths.actions_dir.glob("*.json")) == [first.path]


def test_persist_observer_action_report_rejects_conflicting_replay(
    tmp_path: Path,
) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20261025T120000Z")
    store = artifact_store(paths)
    report = {
        "schema": "action",
        "campaignId": paths.campaign_id,
        "seq": 1,
        "actionId": f"{paths.campaign_id}-cycle-00000001",
        "exact": "first payload",
    }
    persisted = soak_run_layout.persist_observer_action_report(
        paths=paths,
        store=store,
        report=report,
        now_ns=1,
    )
    conflicting = {**report, "exact": "different payload"}

    with pytest.raises(RuntimeError, match="payload conflicts"):
        soak_run_layout.persist_observer_action_report(
            paths=paths,
            store=store,
            report=conflicting,
            now_ns=2,
        )

    assert json.loads(persisted.path.read_text(encoding="utf-8")) == report


def test_persist_observer_action_report_recovers_exact_temporary_payload(
    tmp_path: Path,
) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20261025T120000Z")
    store = artifact_store(paths)
    report = {
        "schema": "action",
        "campaignId": paths.campaign_id,
        "seq": 1,
        "actionId": f"{paths.campaign_id}-cycle-00000001",
        "exact": "prepared before an interrupted replace",
    }
    artifact_name = f"action-{report['seq']:08d}-{report['actionId']}.json"
    expected_path = paths.actions_dir / artifact_name
    temporary = expected_path.with_name(f".{artifact_name}.tmp")
    encoded = (
        json.dumps(
            report,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    paths.actions_dir.mkdir(parents=True, exist_ok=True)
    temporary.write_bytes(encoded)

    persisted = soak_run_layout.persist_observer_action_report(
        paths=paths,
        store=store,
        report=report,
        now_ns=1,
    )

    assert persisted.path == expected_path
    assert expected_path.read_bytes() == encoded
    assert not temporary.exists()


def test_persist_observer_action_report_rejects_conflicting_temporary_payload(
    tmp_path: Path,
) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20261025T120000Z")
    store = artifact_store(paths)
    report = {
        "schema": "action",
        "campaignId": paths.campaign_id,
        "seq": 1,
        "actionId": f"{paths.campaign_id}-cycle-00000001",
    }
    artifact_name = f"action-{report['seq']:08d}-{report['actionId']}.json"
    expected_path = paths.actions_dir / artifact_name
    temporary = expected_path.with_name(f".{artifact_name}.tmp")
    paths.actions_dir.mkdir(parents=True, exist_ok=True)
    temporary.write_text("{}\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="temporary payload conflicts"):
        soak_run_layout.persist_observer_action_report(
            paths=paths,
            store=store,
            report=report,
            now_ns=1,
        )

    assert not expected_path.exists()
    assert temporary.read_text(encoding="utf-8") == "{}\n"


def test_utc_campaign_id_uses_canonical_format() -> None:
    campaign_id = soak_run_layout.utc_campaign_id(
        datetime(2026, 7, 6, 7, 33, 13, tzinfo=timezone.utc)
    )

    assert campaign_id == "20260706T073313Z"
    assert soak_run_layout.validate_campaign_id(campaign_id) == campaign_id
    with pytest.raises(ValueError, match="YYYYMMDDTHHMMSSZ"):
        soak_run_layout.validate_campaign_id("2026-07-06")


def test_build_run_paths_uses_owned_campaign_and_stable_pointers(
    tmp_path: Path,
) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20260706T073313Z")

    assert paths.campaigns_root == tmp_path / "soak" / "campaigns"
    assert paths.campaign_dir == tmp_path / "soak" / "campaigns" / "20260706T073313Z"
    assert paths.report_dir == paths.campaign_dir / "report"
    assert paths.actions_dir == paths.report_dir / "actions"
    assert paths.checkpoints_dir == paths.report_dir / "checkpoints"
    assert paths.diagnostic_bundles_dir == paths.report_dir / "diagnostic-bundles"
    assert (
        paths.diagnostic_segments_dir
        == paths.preflight_archive_dir / "diagnostic-segments"
    )
    assert paths.daemon_output_dir == paths.campaign_dir / "daemon-output"
    assert paths.rust_daemon_output == paths.daemon_output_dir / "rust-daemon.out"
    assert paths.preflight_archive_dir == paths.campaign_dir / "archive" / "preflight"
    assert paths.last_run_manifest == tmp_path / "soak" / "last-run" / "manifest.json"
    assert (
        paths.latest_report_pointer
        == tmp_path / "soak" / "last-run" / "latest-report.json"
    )


def test_require_output_soak_root_rejects_non_output_report_tree(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "out"

    assert (
        soak_run_layout.require_output_soak_root(output_root / "soak", output_root)
        == (output_root / "soak").resolve()
    )
    with pytest.raises(RuntimeError, match="EMULEBB_WORKSPACE_OUTPUT_ROOT"):
        soak_run_layout.require_output_soak_root(
            tmp_path / "repo" / "reports", output_root
        )


def test_mfc_soak_log_dir_resolves_generated_and_direct_profiles(
    tmp_path: Path,
) -> None:
    assert (
        soak_run_layout.mfc_soak_log_dir(
            mfc_artifacts_dir=tmp_path / "mfc-profile",
            direct_profile_dir=None,
        )
        == tmp_path
        / "mfc-profile"
        / "profiles"
        / "converged-soak"
        / "profile-base"
        / "logs"
    )
    assert (
        soak_run_layout.mfc_soak_log_dir(
            mfc_artifacts_dir=tmp_path / "mfc-profile",
            direct_profile_dir=tmp_path / "direct-mfc",
        )
        == tmp_path / "direct-mfc" / "logs"
    )


def test_prepare_clean_run_archives_rust_outputs_and_keeps_state(
    tmp_path: Path,
) -> None:
    soak_root = tmp_path / "soak"
    paths = soak_run_layout.build_run_paths(soak_root, "20260706T073313Z")
    rust_profile_dir = soak_root / "rust-profile"
    rust_packet_dump = rust_profile_dir / "packet-dump"
    rust_packet_dump.mkdir(parents=True)
    (rust_profile_dir / "daemon.out").write_text("old daemon", encoding="utf-8")
    (rust_profile_dir / "emulebb-rust-metadata.db").write_text(
        "durable", encoding="utf-8"
    )
    (rust_packet_dump / "emulebb-rust-diag-1.jsonl").write_text("{}", encoding="utf-8")

    manifest = soak_run_layout.prepare_clean_run(
        paths=paths,
        rust_profile_dir=rust_profile_dir,
        rust_packet_dump_dir=rust_packet_dump,
        mfc_log_dir=None,
        artifact_store=artifact_store(paths),
        stop_process_cleanup=False,
    )

    assert manifest["preflightCleanup"]["rust"]["archivedCount"] == 1
    assert not (rust_profile_dir / "daemon.out").exists()
    assert (rust_packet_dump / "emulebb-rust-diag-1.jsonl").is_file()
    assert (rust_profile_dir / "emulebb-rust-metadata.db").read_text(
        encoding="utf-8"
    ) == "durable"
    assert (paths.preflight_archive_dir / "rust-profile" / "daemon.out").is_file()
    assert manifest["preflightCleanup"]["diagnosticSegments"] == {
        "enabled": False,
        "reason": "disabled",
        "promotedCount": 0,
        "clients": [],
    }
    assert paths.actions_dir.is_dir()
    assert paths.checkpoints_dir.is_dir()
    assert paths.diagnostic_bundles_dir.is_dir()


def test_prepare_clean_run_archives_only_known_mfc_logs(tmp_path: Path) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20260706T073313Z")
    rust_profile_dir = tmp_path / "soak" / "rust-profile"
    rust_packet_dump = rust_profile_dir / "packet-dump"
    mfc_logs = tmp_path / "mfc-logs"
    rust_packet_dump.mkdir(parents=True)
    mfc_logs.mkdir()
    (mfc_logs / "emulebb-diagnostics-diag.log").write_text("diag", encoding="utf-8")
    (mfc_logs / "emulebb-diagnostics-packet-20260706-090000.log").write_text(
        "packet", encoding="utf-8"
    )
    (mfc_logs / "emulebb-performance.csv").write_text("perf", encoding="utf-8")
    (mfc_logs / "operator-note.txt").write_text("keep", encoding="utf-8")

    manifest = soak_run_layout.prepare_clean_run(
        paths=paths,
        rust_profile_dir=rust_profile_dir,
        rust_packet_dump_dir=rust_packet_dump,
        mfc_log_dir=mfc_logs,
        artifact_store=artifact_store(paths),
        stop_process_cleanup=False,
    )

    archived = manifest["preflightCleanup"]["mfc"]
    assert archived["archivedCount"] == 3
    assert not (mfc_logs / "emulebb-diagnostics-diag.log").exists()
    assert not (mfc_logs / "emulebb-diagnostics-packet-20260706-090000.log").exists()
    assert not (mfc_logs / "emulebb-performance.csv").exists()
    assert (mfc_logs / "operator-note.txt").read_text(encoding="utf-8") == "keep"
    assert (
        paths.preflight_archive_dir / "mfc-logs" / "emulebb-diagnostics-diag.log"
    ).is_file()
    assert (
        paths.preflight_archive_dir
        / "mfc-logs"
        / "emulebb-diagnostics-packet-20260706-090000.log"
    ).is_file()
    assert (
        paths.preflight_archive_dir / "mfc-logs" / "emulebb-performance.csv"
    ).is_file()


def test_promote_latest_diagnostic_segments_copies_bounded_validated_suffixes(
    tmp_path: Path,
) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20260706T073313Z")
    rust_dir = tmp_path / "rust-profile" / "packet-dump"
    mfc_dir = tmp_path / "mfc-profile" / "logs"
    rust_sources = [
        write_diag_segment(
            rust_dir,
            client="rust",
            process_id=41,
            run_id="rust-run",
            segment_id=segment_id,
            sequence=segment_id + 1,
        )
        for segment_id in range(4)
    ]
    mfc_source = write_diag_segment(
        mfc_dir,
        client="mfc",
        process_id=42,
        run_id="mfc-run",
        segment_id=7,
        sequence=81,
    )

    result = soak_run_layout.promote_latest_diagnostic_segments(
        paths=paths,
        rust_packet_dump_dir=rust_dir,
        mfc_log_dir=mfc_dir,
        store=artifact_store(paths, segment_retained=2),
    )

    assert result["promotedCount"] == 3
    rust = result["clients"][0]
    assert rust["classification"] == "quiesced-immutable-retained-run-suffix"
    assert rust["runId"] == "rust-run"
    assert rust["retainedRunSegmentCount"] == 4
    assert rust["promotedSegmentCount"] == 2
    assert rust["recordCount"] == 2
    assert rust["retainedFirstSegmentId"] == 0
    assert rust["promotedFirstSegmentId"] == 2
    assert rust["promotedLastSegmentId"] == 3
    assert rust["omittedBeforeRetainedSuffix"] == 0
    assert rust["omittedByPromotionLimit"] == 2
    assert [row["segmentId"] for row in rust["files"]] == [2, 3]
    assert all(source.is_file() for source in rust_sources)
    assert mfc_source.is_file()
    for client in result["clients"]:
        for row in client.get("files", []):
            destination = Path(row["destination"])
            source = Path(row["source"])
            assert destination.read_bytes() == source.read_bytes()
    manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
    assert manifest["schema"] == soak_run_layout.DIAGNOSTIC_SEGMENT_PROMOTION_SCHEMA
    assert manifest["clients"] == result["clients"]


def test_promote_latest_diagnostic_segments_rejects_incomplete_tail(
    tmp_path: Path,
) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20260706T073313Z")
    rust_dir = tmp_path / "rust-profile" / "packet-dump"
    segment = write_diag_segment(
        rust_dir,
        client="rust",
        process_id=41,
        run_id="rust-run",
        segment_id=0,
        sequence=1,
    )
    with segment.open("a", encoding="utf-8") as handle:
        handle.write('{"schema":"diag_event_v2"')

    with pytest.raises(ValueError, match="malformed JSON"):
        soak_run_layout.promote_latest_diagnostic_segments(
            paths=paths,
            rust_packet_dump_dir=rust_dir,
            mfc_log_dir=None,
            store=artifact_store(paths),
        )

    assert not paths.diagnostic_segments_dir.exists()


def test_prepare_clean_run_rejects_processes_remaining_after_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20260706T073313Z")
    rust_profile_dir = tmp_path / "rust-profile"
    remaining = WindowsProcessInfo(
        pid=123,
        parent_pid=1,
        name="emulebb-rust-diagnostics.exe",
        command_line=f"emulebb-rust-diagnostics.exe --profile {rust_profile_dir}",
    )
    monkeypatch.setattr(
        soak_run_layout,
        "stop_stale_soak_processes",
        lambda **_kwargs: {"enabled": True, "targets": [], "results": []},
    )
    monkeypatch.setattr(
        soak_run_layout.windows_processes,
        "collect_processes",
        lambda: [remaining],
    )

    with pytest.raises(RuntimeError, match="not immutable"):
        soak_run_layout.prepare_clean_run(
            paths=paths,
            rust_profile_dir=rust_profile_dir,
            rust_packet_dump_dir=rust_profile_dir / "packet-dump",
            mfc_log_dir=None,
            artifact_store=artifact_store(paths),
        )


def test_prepare_clean_run_publishes_last_run_and_latest_pointers(
    tmp_path: Path,
) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20260706T073313Z")
    rust_profile_dir = tmp_path / "soak" / "rust-profile"
    rust_packet_dump = rust_profile_dir / "packet-dump"

    soak_run_layout.prepare_clean_run(
        paths=paths,
        rust_profile_dir=rust_profile_dir,
        rust_packet_dump_dir=rust_packet_dump,
        mfc_log_dir=None,
        artifact_store=artifact_store(paths),
        stop_process_cleanup=False,
    )

    manifest = paths.last_run_manifest.read_text(encoding="utf-8")
    latest = paths.latest_report_pointer.read_text(encoding="utf-8")
    assert '"campaignId": "20260706T073313Z"' in manifest
    assert '"status": "starting"' in manifest
    assert '"campaignDir"' in manifest
    assert '"campaignId": "20260706T073313Z"' in latest
    assert '"campaignDir"' in latest
    assert "summary.json" in latest


def test_mark_run_finished_retains_preflight_cleanup(tmp_path: Path) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20260706T073313Z")
    rust_profile_dir = tmp_path / "soak" / "rust-profile"
    rust_packet_dump = rust_profile_dir / "packet-dump"
    soak_run_layout.prepare_clean_run(
        paths=paths,
        rust_profile_dir=rust_profile_dir,
        rust_packet_dump_dir=rust_packet_dump,
        mfc_log_dir=None,
        artifact_store=artifact_store(paths),
        stop_process_cleanup=False,
    )

    soak_run_layout.mark_run_finished(paths, status="complete", extra={"summary": "ok"})

    manifest = paths.last_run_manifest.read_text(encoding="utf-8")
    assert '"status": "complete"' in manifest
    assert '"preflightCleanup"' in manifest
    assert '"summary": "ok"' in manifest


def test_mark_run_running_publishes_readiness_without_dropping_preflight(
    tmp_path: Path,
) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20260706T073313Z")
    rust_profile_dir = tmp_path / "soak" / "rust-profile"
    soak_run_layout.prepare_clean_run(
        paths=paths,
        rust_profile_dir=rust_profile_dir,
        rust_packet_dump_dir=rust_profile_dir / "packet-dump",
        mfc_log_dir=None,
        artifact_store=artifact_store(paths),
        stop_process_cleanup=False,
    )

    soak_run_layout.mark_run_running(paths, extra={"readyEvidence": "captured"})

    manifest = json.loads(paths.last_run_manifest.read_text(encoding="utf-8"))
    assert manifest["campaignId"] == "20260706T073313Z"
    assert manifest["status"] == "running"
    assert manifest["readyUtc"].endswith("+00:00")
    assert manifest["readyEvidence"] == "captured"
    assert "preflightCleanup" in manifest


def test_select_stale_soak_process_roots_is_command_line_scoped(tmp_path: Path) -> None:
    rust_profile_dir = tmp_path / "soak" / "rust-profile"
    mfc_profile = tmp_path / "mfc-profile"
    rows = [
        WindowsProcessInfo(
            pid=10,
            parent_pid=1,
            name="uv.exe",
            command_line="uv run python scripts\\converged-soak-live.py --duration 2h",
        ),
        WindowsProcessInfo(
            pid=11,
            parent_pid=10,
            name="python.exe",
            command_line="python scripts\\converged-soak-live.py --duration 2h",
        ),
        WindowsProcessInfo(
            pid=20,
            parent_pid=1,
            name="emulebb-rust-diagnostics.exe",
            command_line=f"emulebb-rust-diagnostics.exe --profile {rust_profile_dir}",
        ),
        WindowsProcessInfo(
            pid=30,
            parent_pid=1,
            name="emulebb-diagnostics.exe",
            command_line=f"emulebb-diagnostics.exe -ignoreinstances -c {mfc_profile}",
        ),
        WindowsProcessInfo(
            pid=40,
            parent_pid=1,
            name="emulebb-diagnostics.exe",
            command_line="emulebb-diagnostics.exe -ignoreinstances -c C:\\other-profile",
        ),
    ]

    selected = soak_run_layout.select_stale_soak_process_roots(
        rows,
        rust_profile_dir=rust_profile_dir,
        mfc_profile_base=mfc_profile,
        exclude_pids=set(),
    )

    assert [process.pid for process in selected] == [10, 20, 30]


def test_select_stale_soak_process_roots_excludes_current_family(
    tmp_path: Path,
) -> None:
    rust_profile_dir = tmp_path / "soak" / "rust-profile"
    rows = [
        WindowsProcessInfo(
            pid=10,
            parent_pid=1,
            name="uv.exe",
            command_line="uv run python scripts\\converged-soak-live.py --duration 2h",
        ),
        WindowsProcessInfo(
            pid=11,
            parent_pid=10,
            name="python.exe",
            command_line="python scripts\\converged-soak-live.py --duration 2h",
        ),
    ]

    selected = soak_run_layout.select_stale_soak_process_roots(
        rows,
        rust_profile_dir=rust_profile_dir,
        mfc_profile_base=None,
        exclude_pids={10, 11},
    )

    assert selected == []
