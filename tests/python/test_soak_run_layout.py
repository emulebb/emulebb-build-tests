from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from emule_test_harness import soak_run_layout


def test_utc_campaign_id_uses_canonical_format() -> None:
    campaign_id = soak_run_layout.utc_campaign_id(datetime(2026, 7, 6, 7, 33, 13, tzinfo=timezone.utc))

    assert campaign_id == "20260706T073313Z"
    assert soak_run_layout.validate_campaign_id(campaign_id) == campaign_id
    with pytest.raises(ValueError, match="YYYYMMDDTHHMMSSZ"):
        soak_run_layout.validate_campaign_id("2026-07-06")


def test_build_run_paths_uses_reports_archives_and_last_run(tmp_path: Path) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20260706T073313Z")

    assert paths.report_dir == tmp_path / "soak" / "reports" / "20260706T073313Z"
    assert paths.actions_dir == paths.report_dir / "actions"
    assert paths.checkpoints_dir == paths.report_dir / "checkpoints"
    assert paths.preflight_archive_dir == tmp_path / "soak" / "archives" / "20260706T073313Z" / "preflight"
    assert paths.last_run_manifest == tmp_path / "soak" / "last-run" / "manifest.json"
    assert paths.latest_report_pointer == tmp_path / "soak" / "reports" / "latest.json"


def test_mfc_soak_log_dir_resolves_generated_and_direct_profiles(tmp_path: Path) -> None:
    assert soak_run_layout.mfc_soak_log_dir(
        mfc_artifacts_dir=tmp_path / "mfc-profile",
        direct_profile_dir=None,
    ) == tmp_path / "mfc-profile" / "profiles" / "converged-soak" / "profile-base" / "logs"
    assert soak_run_layout.mfc_soak_log_dir(
        mfc_artifacts_dir=tmp_path / "mfc-profile",
        direct_profile_dir=tmp_path / "direct-mfc",
    ) == tmp_path / "direct-mfc" / "logs"


def test_prepare_clean_run_archives_rust_outputs_and_keeps_state(tmp_path: Path) -> None:
    soak_root = tmp_path / "soak"
    paths = soak_run_layout.build_run_paths(soak_root, "20260706T073313Z")
    rust_runtime = soak_root / "rust-runtime"
    rust_packet_dump = rust_runtime / "packet-dump"
    rust_packet_dump.mkdir(parents=True)
    (rust_runtime / "daemon.out").write_text("old daemon", encoding="utf-8")
    (rust_runtime / "metadata.sqlite").write_text("durable", encoding="utf-8")
    (rust_packet_dump / "emulebb-rust-diag-1.jsonl").write_text("{}", encoding="utf-8")

    manifest = soak_run_layout.prepare_clean_run(
        paths=paths,
        rust_runtime_dir=rust_runtime,
        rust_packet_dump_dir=rust_packet_dump,
        mfc_log_dir=None,
    )

    assert manifest["preflightCleanup"]["rust"]["archivedCount"] == 2
    assert not (rust_runtime / "daemon.out").exists()
    assert not (rust_packet_dump / "emulebb-rust-diag-1.jsonl").exists()
    assert (rust_runtime / "metadata.sqlite").read_text(encoding="utf-8") == "durable"
    assert (paths.preflight_archive_dir / "rust-runtime" / "daemon.out").is_file()
    assert (paths.preflight_archive_dir / "rust-packet-dump" / "emulebb-rust-diag-1.jsonl").is_file()
    assert paths.actions_dir.is_dir()
    assert paths.checkpoints_dir.is_dir()


def test_prepare_clean_run_archives_only_known_mfc_logs(tmp_path: Path) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20260706T073313Z")
    rust_runtime = tmp_path / "soak" / "rust-runtime"
    rust_packet_dump = rust_runtime / "packet-dump"
    mfc_logs = tmp_path / "mfc-logs"
    rust_packet_dump.mkdir(parents=True)
    mfc_logs.mkdir()
    (mfc_logs / "emulebb-diagnostics-diag.log").write_text("diag", encoding="utf-8")
    (mfc_logs / "emulebb-diagnostics-packet-20260706-090000.log").write_text("packet", encoding="utf-8")
    (mfc_logs / "emulebb-performance.csv").write_text("perf", encoding="utf-8")
    (mfc_logs / "operator-note.txt").write_text("keep", encoding="utf-8")

    manifest = soak_run_layout.prepare_clean_run(
        paths=paths,
        rust_runtime_dir=rust_runtime,
        rust_packet_dump_dir=rust_packet_dump,
        mfc_log_dir=mfc_logs,
    )

    archived = manifest["preflightCleanup"]["mfc"]
    assert archived["archivedCount"] == 3
    assert not (mfc_logs / "emulebb-diagnostics-diag.log").exists()
    assert not (mfc_logs / "emulebb-diagnostics-packet-20260706-090000.log").exists()
    assert not (mfc_logs / "emulebb-performance.csv").exists()
    assert (mfc_logs / "operator-note.txt").read_text(encoding="utf-8") == "keep"
    assert (paths.preflight_archive_dir / "mfc-logs" / "emulebb-diagnostics-diag.log").is_file()
    assert (paths.preflight_archive_dir / "mfc-logs" / "emulebb-diagnostics-packet-20260706-090000.log").is_file()
    assert (paths.preflight_archive_dir / "mfc-logs" / "emulebb-performance.csv").is_file()


def test_prepare_clean_run_publishes_last_run_and_latest_pointers(tmp_path: Path) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20260706T073313Z")
    rust_runtime = tmp_path / "soak" / "rust-runtime"
    rust_packet_dump = rust_runtime / "packet-dump"

    soak_run_layout.prepare_clean_run(
        paths=paths,
        rust_runtime_dir=rust_runtime,
        rust_packet_dump_dir=rust_packet_dump,
        mfc_log_dir=None,
    )

    manifest = paths.last_run_manifest.read_text(encoding="utf-8")
    latest = paths.latest_report_pointer.read_text(encoding="utf-8")
    assert '"campaignId": "20260706T073313Z"' in manifest
    assert '"status": "starting"' in manifest
    assert '"campaignId": "20260706T073313Z"' in latest
    assert "summary.json" in latest


def test_mark_run_finished_retains_preflight_cleanup(tmp_path: Path) -> None:
    paths = soak_run_layout.build_run_paths(tmp_path / "soak", "20260706T073313Z")
    rust_runtime = tmp_path / "soak" / "rust-runtime"
    rust_packet_dump = rust_runtime / "packet-dump"
    soak_run_layout.prepare_clean_run(
        paths=paths,
        rust_runtime_dir=rust_runtime,
        rust_packet_dump_dir=rust_packet_dump,
        mfc_log_dir=None,
    )

    soak_run_layout.mark_run_finished(paths, status="complete", extra={"summary": "ok"})

    manifest = paths.last_run_manifest.read_text(encoding="utf-8")
    assert '"status": "complete"' in manifest
    assert '"preflightCleanup"' in manifest
    assert '"summary": "ok"' in manifest
