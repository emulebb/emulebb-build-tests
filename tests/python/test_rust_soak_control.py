from __future__ import annotations

import importlib.util
import os
import time
from pathlib import Path
from types import ModuleType
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RUST_SOAK_CONTROL = REPO_ROOT / "scripts" / "rust-soak-control.py"


def _load_rust_soak_control() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rust_soak_control_script", RUST_SOAK_CONTROL)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shared_directory_summary_redacts_paths_and_keeps_flags() -> None:
    control = _load_rust_soak_control()

    summary = control.summarize_shared_directory_rows(
        [
            {
                "path": r"F:\Private\Library\\",
                "accessible": True,
                "shareable": True,
                "recursive": True,
                "monitorOwned": False,
            },
            {
                "path": r"F:\Private\Library",
                "accessible": True,
                "shareable": True,
                "recursive": False,
                "monitorOwned": True,
            },
        ]
    )

    assert summary["count"] == 2
    assert summary["duplicateCount"] == 1
    assert summary["counts"]["accessible"] == 2
    assert summary["counts"]["recursive"] == 1
    assert summary["counts"]["monitorOwned"] == 1
    assert "Private" not in repr(summary)
    assert "Library" not in repr(summary)


def test_shared_summary_compare_reports_root_and_count_delta() -> None:
    control = _load_rust_soak_control()

    shared = control.private_path_fingerprint(r"F:\Private\Library")
    rust_only = control.private_path_fingerprint(r"F:\Private\RustOnly")
    mfc_only = control.private_path_fingerprint(r"F:\Private\MfcOnly")
    comparison = control.compare_shared_summaries(
        {
            "sharedFilesTotal": 10,
            "roots": {"fingerprints": [shared, rust_only]},
        },
        {
            "sharedFilesTotal": 12,
            "roots": {"fingerprints": [shared, mfc_only]},
        },
    )

    assert comparison == {
        "enabled": True,
        "rootFingerprintsMatch": False,
        "rustOnlyRootFingerprintCount": 1,
        "mfcOnlyRootFingerprintCount": 1,
        "rustOnlyRootFingerprints": [rust_only],
        "mfcOnlyRootFingerprints": [mfc_only],
        "sharedFilesDeltaRustMinusMfc": -2,
    }


def test_private_path_fingerprint_normalizes_windows_verbatim_prefix() -> None:
    control = _load_rust_soak_control()

    assert control.private_path_fingerprint(r"\\?\F:\Private\Library") == control.private_path_fingerprint(
        r"F:\Private\Library\\"
    )
    assert control.private_path_fingerprint(r"\\?\UNC\server\share\Library") == control.private_path_fingerprint(
        r"\\server\share\Library"
    )


def test_shared_file_hash_comparison_reports_unique_and_duplicate_gaps() -> None:
    control = _load_rust_soak_control()

    comparison = control.compare_shared_file_hashes(
        {"rowCount": 2, "duplicateHashCount": 0, "hashes": {"a" * 32, "b" * 32}},
        {"rowCount": 3, "duplicateHashCount": 1, "hashes": {"b" * 32, "c" * 32}},
    )

    assert comparison["uniqueHashesMatch"] is False
    assert comparison["rustOnlyUniqueHashCount"] == 1
    assert comparison["mfcOnlyUniqueHashCount"] == 1
    assert comparison["rustDuplicateHashCount"] == 0
    assert comparison["mfcDuplicateHashCount"] == 1
    assert comparison["uniqueHashDeltaRustMinusMfc"] == 0
    assert comparison["rowCountDeltaRustMinusMfc"] == -1


def test_shared_file_catalog_comparison_reports_path_and_hash_gaps() -> None:
    control = _load_rust_soak_control()

    comparison = control.compare_shared_file_catalogs(
        {
            "byPath": {
                "shared": "a" * 32,
                "rust-only": "b" * 32,
                "changed": "c" * 32,
            }
        },
        {
            "byPath": {
                "shared": "a" * 32,
                "mfc-only": "d" * 32,
                "changed": "e" * 32,
            }
        },
    )

    assert comparison["pathFingerprintsMatch"] is False
    assert comparison["rustOnlyPathCount"] == 1
    assert comparison["mfcOnlyPathCount"] == 1
    assert comparison["changedHashForSamePathCount"] == 1
    assert comparison["rustOnlyPathFingerprints"] == ["rust-only"]
    assert comparison["mfcOnlyPathFingerprints"] == ["mfc-only"]
    assert comparison["changedPathFingerprints"] == ["changed"]


def test_shared_file_root_group_comparison_reports_largest_deltas() -> None:
    control = _load_rust_soak_control()

    comparison = control.compare_shared_file_root_groups(
        {
            "groups": [
                {"rootFingerprint": "root-a", "rowCount": 10, "uniqueHashCount": 10},
                {"rootFingerprint": "root-b", "rowCount": 3, "uniqueHashCount": 3},
            ]
        },
        {
            "groups": [
                {"rootFingerprint": "root-a", "rowCount": 12, "uniqueHashCount": 12},
                {"rootFingerprint": "root-c", "rowCount": 7, "uniqueHashCount": 7},
            ]
        },
    )

    assert comparison["rootGroupsMatch"] is False
    assert comparison["differingRootGroupCount"] == 3
    assert comparison["topDeltas"][0]["rootFingerprint"] == "root-c"
    assert comparison["topDeltas"][0]["rowDeltaRustMinusMfc"] == -7


def test_compact_shared_root_catalog_summary_keeps_bounded_top_groups() -> None:
    control = _load_rust_soak_control()

    compact = control.compact_shared_root_catalog_summary(
        {
            "total": 4,
            "rowCount": 4,
            "rootCount": 2,
            "groupCount": 3,
            "groups": [
                {"rootFingerprint": "root-a", "rowCount": 3},
                {"rootFingerprint": "root-b", "rowCount": 1},
                {"rootFingerprint": "root-c", "rowCount": 0},
            ],
        },
        sample_limit=2,
    )

    assert "groups" not in compact
    assert compact["topGroups"] == [
        {"rootFingerprint": "root-a", "rowCount": 3},
        {"rootFingerprint": "root-b", "rowCount": 1},
    ]


def test_unmatched_prefix_groups_are_sanitized_and_bounded() -> None:
    control = _load_rust_soak_control()
    groups = {}

    control.add_unmatched_prefix_groups(groups, r"f:\share\alpha\one.bin", "a" * 32)
    control.add_unmatched_prefix_groups(groups, r"f:\share\alpha\two.bin", "b" * 32)
    control.add_unmatched_prefix_groups(groups, r"g:\share\beta\three.bin", "c" * 32)

    compact = control.compact_unmatched_prefix_groups(groups, sample_limit=1)

    assert compact["depth2"] == [
        {
            "prefixFingerprint": control.private_path_prefix_fingerprint(r"f:\share\alpha\one.bin", 2),
            "rowCount": 2,
            "uniqueHashCount": 2,
        }
    ]
    assert "share" not in str(compact)
    assert "alpha" not in str(compact)


def test_shared_root_for_path_uses_longest_matching_root() -> None:
    control = _load_rust_soak_control()
    roots = [r"f:\share", r"f:\share\nested"]

    assert control.shared_root_for_path(r"f:\share\nested\file.bin", roots) == control.private_path_fingerprint(
        r"f:\share\nested"
    )
    assert control.shared_root_for_path(r"f:\other\file.bin", roots) == "unmatched"


def test_shared_directory_model_persistence_lists_preserve_mfc_semantics() -> None:
    control = _load_rust_soak_control()

    lists = control.shared_directory_model_persistence_lists(
        {
            "roots": [
                {"path": r"C:\Flat", "accessible": True, "shareable": True, "recursive": False},
                {"path": r"C:\Tree", "accessible": True, "shareable": True, "recursive": True},
            ],
            "items": [
                {"path": r"C:\Flat", "accessible": True, "shareable": True, "monitorOwned": False},
                {"path": r"C:\Tree", "accessible": True, "shareable": True, "monitorOwned": False},
                {"path": r"C:\Tree\Child", "accessible": True, "shareable": True, "monitorOwned": True},
                {"path": r"C:\Offline", "accessible": False, "shareable": True, "monitorOwned": False},
            ],
            "monitorOwned": [r"C:\Tree\Child", r"C:\Tree\Missing"],
        }
    )

    assert lists == {
        "shared": ["C:\\Flat\\", "C:\\Tree\\", "C:\\Tree\\Child\\"],
        "monitored": ["C:\\Tree\\"],
        "monitorOwned": ["C:\\Tree\\Child\\"],
    }


def test_write_mfc_shareddir_from_rest_writes_three_profile_files(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    profile_dir = tmp_path / "profile-base"
    config_dir = profile_dir / "config"
    config_dir.mkdir(parents=True)

    monkeypatch.setattr(
        control,
        "request_json",
        lambda *args, **kwargs: {
            "roots": [
                {"path": r"C:\Tree", "accessible": True, "shareable": True, "recursive": True},
            ],
            "items": [
                {"path": r"C:\Tree", "accessible": True, "shareable": True, "monitorOwned": False},
                {"path": r"C:\Tree\Child", "accessible": True, "shareable": True, "monitorOwned": True},
            ],
            "monitorOwned": [r"C:\Tree\Child"],
        },
    )

    result = control.write_mfc_shareddir_from_rest(
        SimpleNamespace(
            source_base_url="http://192.0.2.10:4731/api/v1",
            source_api_key="key",
            target_profile_dir=profile_dir,
            timeout_seconds=1.0,
            fingerprint_sample_limit=3,
            dry_run=False,
        )
    )

    assert result["written"] is True
    assert result["counts"] == {"shared": 2, "monitored": 1, "monitorOwned": 1}
    assert (config_dir / "shareddir.dat").read_text(encoding="utf-16").splitlines() == [
        "C:\\Tree\\",
        "C:\\Tree\\Child\\",
    ]
    assert (config_dir / "shareddir.monitored.dat").read_text(encoding="utf-16").splitlines() == ["C:\\Tree\\"]
    assert (config_dir / "shareddir.monitor-owned.dat").read_text(encoding="utf-16").splitlines() == [
        "C:\\Tree\\Child\\",
    ]


def test_resolve_mfc_start_profile_prefers_existing_persisted_profile(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    profile_dir = tmp_path / "profile-base"
    config_dir = profile_dir / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "preferences.ini").write_text("[eMule]\n", encoding="utf-8")
    monkeypatch.setattr(control, "default_mfc_profile_dir", lambda: profile_dir)

    resolved, mode = control.resolve_mfc_start_profile(
        SimpleNamespace(direct_profile_dir=None, rebuild_profile_from_inputs=False)
    )

    assert resolved == profile_dir
    assert mode == "default-direct"


def test_resolve_mfc_start_profile_allows_explicit_input_rebuild(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    profile_dir = tmp_path / "profile-base"
    config_dir = profile_dir / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "preferences.ini").write_text("[eMule]\n", encoding="utf-8")
    monkeypatch.setattr(control, "default_mfc_profile_dir", lambda: profile_dir)

    resolved, mode = control.resolve_mfc_start_profile(
        SimpleNamespace(direct_profile_dir=None, rebuild_profile_from_inputs=True)
    )

    assert resolved is None
    assert mode == "prepared-from-inputs"


def test_resolve_mfc_start_profile_honors_explicit_direct_profile(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    profile_dir = tmp_path / "explicit-profile"

    resolved, mode = control.resolve_mfc_start_profile(
        SimpleNamespace(direct_profile_dir=profile_dir, rebuild_profile_from_inputs=True)
    )

    assert resolved == profile_dir
    assert mode == "explicit-direct"


def test_mfc_upload_log_discovery_prefers_newest_fresh_candidate(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    stale = logs_dir / "emulebb-diagnostics-upload-slot-old.log"
    fresh = logs_dir / "emulebb-diagnostics-upload-slot.log"
    stale.write_text("old\n", encoding="utf-8")
    fresh.write_text("fresh\n", encoding="utf-8")
    now = time.time()
    os.utime(stale, (now - 3600, now - 3600))
    os.utime(fresh, (now, now))

    candidates = control.mfc_upload_log_candidates([tmp_path], limit=5)
    discovered = control.discover_mfc_upload_log([tmp_path], max_age_seconds=900.0)

    assert [Path(row["path"]).name for row in candidates] == [
        "emulebb-diagnostics-upload-slot.log",
        "emulebb-diagnostics-upload-slot-old.log",
    ]
    assert discovered == fresh.resolve()


def test_watch_findings_reports_mfc_status_gaps() -> None:
    control = _load_rust_soak_control()

    findings = control.watch_findings(
        {
            "sharedHashingActive": False,
            "sharedHashingCount": 0,
            "ed2kConnected": True,
            "ed2kHighId": True,
            "kadConnected": True,
            "kadFirewalled": False,
        },
        {"monitorAlive": True, "monitorStale": False, "latestRecord": {}},
        {
            "sharedHashingActive": True,
            "sharedHashingCount": 12,
            "ed2kConnected": True,
            "ed2kHighId": False,
            "kadConnected": True,
            "kadFirewalled": True,
        },
    )

    assert "mfc-hashing-active" in findings
    assert "mfc-ed2k-not-high-id" in findings
    assert "mfc-kad-firewalled" in findings


def test_watch_heartbeat_includes_optional_mfc_status(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    heartbeat = tmp_path / "heartbeat.txt"

    control.write_watch_heartbeat(
        heartbeat,
        {
            "timestampUtc": "2026-01-01T00:00:00+00:00",
            "findings": ["mfc-hashing-active"],
            "rust": {
                "uploadSpeedKiBps": 1.0,
                "activeUploads": 1,
                "waitingUploads": 0,
                "ed2kPublishedEntries": 2,
                "ed2kPendingEntries": 3,
                "ed2kVisibilityPercent": 4.0,
                "kadFirewalled": False,
            },
            "monitor": {"latestRecord": {"mfcLogStale": False}},
            "mfc": {
                "uploadSpeedKiBps": 0.5,
                "activeUploads": 1,
                "sharedFileCount": 100,
                "sharedHashingCount": 12,
                "ed2kHighId": False,
                "kadFirewalled": True,
            },
        },
    )

    text = heartbeat.read_text(encoding="utf-8")
    assert "mfcHashing=12" in text
    assert "mfcEd2kHighId=False" in text
    assert "mfcKadFirewalled=True" in text


def test_watch_trend_summarizes_retained_jsonl_progress(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    jsonl = tmp_path / "watch.jsonl"
    records = [
        {
            "timestampUtc": "2026-01-01T00:00:00+00:00",
            "findings": ["mfc-hashing-active"],
            "rust": {
                "uploadSpeedKiBps": 100.0,
                "activeUploads": 2,
                "ed2kPublishedEntries": 1000,
                "ed2kPendingEntries": 9000,
                "kadSourcePublishedTotal": 10,
            },
            "mfc": {
                "sharedFileCount": 100,
                "sharedHashingCount": 900,
                "uploadSpeedKiBps": 1.0,
                "activeUploads": 1,
            },
        },
        {
            "timestampUtc": "2026-01-01T00:10:00+00:00",
            "findings": ["mfc-hashing-active", "mfc-kad-firewalled"],
            "rust": {
                "uploadSpeedKiBps": 200.0,
                "activeUploads": 4,
                "ed2kPublishedEntries": 1200,
                "ed2kPendingEntries": 8800,
                "kadSourcePublishedTotal": 14,
            },
            "mfc": {
                "sharedFileCount": 160,
                "sharedHashingCount": 840,
                "uploadSpeedKiBps": 2.0,
                "activeUploads": 1,
            },
        },
    ]
    jsonl.write_text("\n".join(control.json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8")

    trend = control.watch_trend(SimpleNamespace(watch_jsonl=jsonl, limit=10))

    assert trend["sampleCount"] == 2
    assert trend["window"]["elapsedSeconds"] == 600.0
    assert trend["latestFindings"] == ["mfc-hashing-active", "mfc-kad-firewalled"]
    assert trend["counters"]["rustEd2kPublished"]["delta"] == 200.0
    assert trend["counters"]["rustEd2kPublished"]["perMinute"] == 20.0
    assert trend["counters"]["rustEd2kPending"]["perMinute"] == -20.0
    assert trend["counters"]["rustEd2kPending"]["remainingEtaMinutes"] == 440.0
    assert trend["counters"]["rustEd2kPending"]["remainingEtaHours"] == 7.33
    assert trend["counters"]["mfcSharedFiles"]["delta"] == 60.0
    assert trend["counters"]["mfcHashingRemaining"]["delta"] == -60.0
    assert trend["counters"]["mfcHashingRemaining"]["completedDelta"] == 60.0
    assert trend["counters"]["mfcHashingRemaining"]["completedPerMinute"] == 6.0
    assert trend["counters"]["mfcHashingRemaining"]["remainingEtaMinutes"] == 140.0
    assert trend["counters"]["mfcHashingRemaining"]["remainingEtaHours"] == 2.33


def test_watch_status_flags_stale_retained_sample(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    pid_file = tmp_path / "watch.pid"
    jsonl = tmp_path / "watch.jsonl"
    heartbeat = tmp_path / "watch.heartbeat.txt"
    stop_file = tmp_path / "watch.stop"
    pid_file.write_text("1234\n", encoding="utf-8")
    heartbeat.write_text("old heartbeat\n", encoding="utf-8")
    jsonl.write_text(
        control.json.dumps({"timestampUtc": "2026-01-01T00:00:00+00:00"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(control, "pid_exists", lambda pid: True)
    monkeypatch.setattr(control, "timestamp_age_seconds", lambda timestamp: 901.0)

    status = control.watch_status(
        SimpleNamespace(
            watch_pid_file=pid_file,
            watch_jsonl=jsonl,
            watch_heartbeat=heartbeat,
            watch_stop_file=stop_file,
            stale_seconds=900.0,
        )
    )

    assert status["watchAlive"] is True
    assert status["watchStale"] is True
    assert status["latestAgeSeconds"] == 901.0
    assert status["findings"] == ["watch-stale"]


def test_watch_once_can_append_retained_evidence(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    jsonl = tmp_path / "watch.jsonl"
    heartbeat = tmp_path / "watch.heartbeat.txt"

    def fake_sample(base_url: str, api_key: str) -> dict[str, object]:
        if "4732" in base_url:
            return {
                "activeUploads": 1,
                "ed2kConnected": True,
                "ed2kHighId": False,
                "kadConnected": True,
                "kadFirewalled": True,
                "sharedHashingActive": True,
                "sharedHashingCount": 10,
                "uploadSpeedKiBps": 0.5,
            }
        return {
            "activeUploads": 2,
            "ed2kConnected": True,
            "ed2kHighId": True,
            "ed2kPendingEntries": 100,
            "ed2kPublishedEntries": 20,
            "kadConnected": True,
            "kadFirewalled": False,
            "sharedHashingActive": False,
            "sharedHashingCount": 0,
            "uploadSpeedKiBps": 10.0,
            "waitingUploads": 0,
        }

    monkeypatch.setattr(control, "sample", fake_sample)
    monkeypatch.setattr(
        control,
        "upload_monitor_sample",
        lambda args: {
            "monitorAlive": True,
            "monitorStale": False,
            "latestRecord": {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "parityGap": False,
                "postVisibilityDemandGap": False,
                "mfcLogStale": False,
            },
        },
    )

    result = control.watch_once(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="rust",
            mfc_base_url="http://192.0.2.10:4732/api/v1",
            mfc_api_key="mfc",
            output_dir=tmp_path,
            stale_seconds=900.0,
            restart_stale_monitor=False,
            log_dir=tmp_path,
            rust_pid=None,
            rust_diag_log=None,
            mfc_upload_log=None,
            interval_seconds=300.0,
            mfc_log_stale_seconds=900.0,
            append_jsonl=True,
            watch_jsonl=jsonl,
            watch_heartbeat=heartbeat,
        )
    )

    assert "mfc-hashing-active" in result["findings"]
    retained = control.latest_jsonl_record(jsonl)
    assert retained is not None
    assert retained["findings"] == result["findings"]
    heartbeat_text = heartbeat.read_text(encoding="utf-8")
    assert "mfcHashing=10" in heartbeat_text
