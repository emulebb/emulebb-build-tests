from __future__ import annotations

import importlib.util
import json
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


def test_diagnostics_summary_redacts_live_log_content(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "emulebb-diagnostics-bad-peer.log"
    jsonl_file = logs_dir / "emulebb-rust-diag-123.jsonl"
    log_file.write_text(
        "\n".join(
            [
                (
                    '{"schema":"bad_peer_event_v1","marker":"BadPeerDiagnostics:",'
                    '"ts_utc":"2026-01-01T00:00:00.000Z","event":"fake_file_search_detected",'
                    '"severity":"medium","action":"warn",'
                    '"file":{"name":"Private Operator Title.mkv","path":"F:\\\\Private\\\\Library"}}'
                ),
                "UPnP mapped ED2K port and Kad port, High ID established",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    jsonl_file.write_text(
        '{"schema":"diag_event_v1","event":"capacity_snapshot","severity":"info"}\n',
        encoding="utf-8",
    )

    result = control.diagnostics_summary(
        SimpleNamespace(log_dir=logs_dir, log_file=None, limit=10, max_bytes=2048)
    )

    assert result["fileCount"] == 2
    assert result["aggregatePatternCounts"]["upnp"] == 1
    assert result["aggregatePatternCounts"]["ed2k"] == 1
    assert result["aggregatePatternCounts"]["kad"] == 1
    assert result["aggregateJsonCounts"]["event"] == {
        "fake_file_search_detected": 1,
        "capacity_snapshot": 1,
    }
    assert result["aggregateJsonCounts"]["severity"] == {"medium": 1, "info": 1}
    event_counts = {
        file_summary["name"]: file_summary["jsonCounts"]["event"]
        for file_summary in result["files"]
        if "jsonCounts" in file_summary
    }
    assert event_counts["emulebb-diagnostics-bad-peer.log"] == {"fake_file_search_detected": 1}
    assert event_counts["emulebb-rust-diag-123.jsonl"] == {"capacity_snapshot": 1}
    rendered = repr(result)
    assert "Private Operator Title" not in rendered
    assert "Private\\Library" not in rendered


def test_diagnostics_summary_combines_multiple_log_dirs(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    rust_logs = tmp_path / "rust"
    mfc_logs = tmp_path / "mfc"
    rust_logs.mkdir()
    mfc_logs.mkdir()
    (rust_logs / "emulebb-rust-diag-123.jsonl").write_text(
        '{"schema":"diag_event_v1","event":"routing_summary","severity":"info","network":"Kad"}\n',
        encoding="utf-8",
    )
    (mfc_logs / "emulebb-diagnostics-packet.log").write_text(
        '{"schema":"ed2k_packet_v1","direction":"out","network":"ED2K"}\n',
        encoding="utf-8",
    )

    result = control.diagnostics_summary(
        SimpleNamespace(log_dir=[rust_logs, mfc_logs], log_file=None, limit=10, max_bytes=2048)
    )

    assert result["fileCount"] == 2
    assert result["logDir"] is None
    assert len(result["logDirs"]) == 2
    assert result["aggregatePatternCounts"]["kad"] == 1
    assert result["aggregatePatternCounts"]["ed2k"] == 1
    assert result["aggregateJsonCounts"]["schema"] == {
        "diag_event_v1": 1,
        "ed2k_packet_v1": 1,
    }
    assert result["aggregateJsonCounts"]["event"] == {"routing_summary": 1}
    rendered = repr(result)
    assert str(rust_logs) not in rendered
    assert str(mfc_logs) not in rendered


def test_diagnostics_summary_reports_safe_body_buckets(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "emulebb-rust-diag-123.jsonl"
    log_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "upload_slot_recycled",
                        "body": {
                            "reason": "slowUnderfill",
                            "fileName": "Private Operator Title.mkv",
                        },
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "upload_request_outcome",
                        "body": {
                            "outcome": "served",
                            "peer": "192.0.2.10:4662",
                            "servedBytes": 184320,
                            "sentPayloadBytes": 184400,
                            "payloadReadMs": 3,
                            "throttleDelayMs": 0,
                        },
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "upload_request_outcome",
                        "body": {
                            "outcome": "served",
                            "servedBytes": 92160,
                            "payloadReadMs": 9,
                            "throttleDelayMs": 30,
                        },
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "capacity_snapshot",
                        "body": {"elasticUnderfill": True},
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = control.diagnostics_summary(
        SimpleNamespace(log_dir=logs_dir, log_file=None, limit=10, max_bytes=2048)
    )

    body_counts = result["files"][0]["jsonBodyCounts"]
    assert body_counts["upload_slot_recycled.reason"] == {"slowUnderfill": 1}
    assert body_counts["upload_request_outcome.outcome"] == {"served": 2}
    assert body_counts["capacity_snapshot.elasticUnderfill"] == {"true": 1}
    body_numeric = result["files"][0]["jsonBodyNumeric"]
    assert body_numeric["upload_request_outcome.servedBytes"] == {
        "count": 2,
        "sum": 276480.0,
        "min": 92160.0,
        "max": 184320.0,
        "average": 138240.0,
    }
    assert body_numeric["upload_request_outcome.payloadReadMs"]["average"] == 6.0
    assert body_numeric["upload_request_outcome.throttleDelayMs"]["sum"] == 30.0
    rendered = repr(result)
    assert "Private Operator Title" not in rendered
    assert "192.0.2.10" not in rendered


def test_diagnostics_summary_uses_rust_jsonl_ts_field(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "emulebb-rust-diag-123.jsonl"
    log_file.write_text(
        "\n".join(
            [
                json.dumps({"schema": "diag_event_v1", "event": "capacity_snapshot", "ts": "2026-01-01T00:00:00Z"}),
                json.dumps({"schema": "diag_event_v1", "event": "capacity_snapshot", "ts": "2026-01-01T00:01:00Z"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = control.diagnostics_summary(
        SimpleNamespace(log_dir=logs_dir, log_file=None, limit=10, max_bytes=2048)
    )

    assert result["files"][0]["jsonTimeRange"] == {
        "firstUtc": "2026-01-01T00:00:00+00:00",
        "lastUtc": "2026-01-01T00:01:00+00:00",
    }


def test_upload_efficiency_summary_reports_percentiles_and_redacts_rows(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "emulebb-rust-diag-123.jsonl"
    rows = [
        {
            "schema": "diag_event_v1",
            "event": "upload_request_outcome",
            "ts": "2026-01-01T00:00:00Z",
            "body": {
                "outcome": "served",
                "peer": "192.0.2.55:4662",
                "fileName": "Private Operator Title.mkv",
                "requestedBytes": 1000,
                "servedBytes": 1000,
                "payloadReadMs": 2,
                "throttleDelayMs": 10,
            },
        },
        {
            "schema": "diag_event_v1",
            "event": "upload_request_outcome",
            "ts": "2026-01-01T00:01:00Z",
            "body": {
                "outcome": "partial",
                "firstSkipReason": "duplicateDone",
                "requestedBytes": 1000,
                "servedBytes": 500,
                "payloadReadMs": 130,
                "throttleDelayMs": 20,
            },
        },
        {
            "schema": "diag_event_v1",
            "event": "upload_request_outcome",
            "ts": "2026-01-01T00:02:00Z",
            "body": {
                "outcome": "served",
                "requestedBytes": 1000,
                "servedBytes": 1000,
                "payloadReadMs": 10,
                "throttleDelayMs": 30,
            },
        },
        {
            "schema": "diag_event_v1",
            "event": "upload_request_outcome",
            "ts": "2026-01-01T00:03:00Z",
            "body": {
                "outcome": "served",
                "requestedBytes": 1000,
                "servedBytes": 1000,
                "payloadReadMs": 400,
                "throttleDelayMs": 40,
            },
        },
    ]
    log_file.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    result = control.upload_efficiency_summary(
        SimpleNamespace(
            log_dir=logs_dir,
            log_file=None,
            limit=10,
            max_bytes=4096,
            slow_read_ms=100.0,
            outlier_limit=2,
        )
    )

    assert result["rowCount"] == 4
    assert result["logDir"] is None
    assert result["logDirFingerprint"] == control.private_path_fingerprint(str(logs_dir))
    assert result["slowReadCount"] == 2
    assert result["slowReadRatio"] == 0.5
    assert result["servedToRequestedRatio"] == 0.875
    assert result["outcomes"] == {"served": 3, "partial": 1}
    assert result["firstSkipReasons"] == {"duplicateDone": 1}
    read_stats = result["numeric"]["payloadReadMs"]
    assert read_stats["average"] == 135.5
    assert read_stats["p50"] == 70.0
    assert read_stats["p90"] == 319.0
    assert [row["payloadReadMs"] for row in result["worstPayloadReads"]] == [400.0, 130.0]
    assert result["timeRange"] == {
        "firstUtc": "2026-01-01T00:00:00+00:00",
        "lastUtc": "2026-01-01T00:03:00+00:00",
    }
    rendered = repr(result)
    assert "Private Operator Title" not in rendered
    assert "192.0.2.55" not in rendered
    assert str(logs_dir) not in rendered


def test_anti_flood_summary_groups_sanitized_bursts(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "emulebb-rust-diag-123.jsonl"
    log_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "anti_flood_drop",
                        "severity": "medium",
                        "ts": "2026-01-01T00:00:00Z",
                        "keys": {"peer": "203.0.113.10:4662"},
                        "body": {"repeatCount": 3},
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "anti_flood_drop",
                        "severity": "medium",
                        "ts": "2026-01-01T00:00:00Z",
                        "keys": {"peer": "203.0.113.10:4662"},
                        "body": {"repeatCount": 3},
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "anti_flood_drop",
                        "severity": "medium",
                        "ts": "2026-01-01T00:00:05Z",
                        "keys": {"peer": "203.0.113.10:4662"},
                        "body": {"repeatCount": 4},
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "anti_flood_ban",
                        "severity": "high",
                        "ts": "2026-01-01T00:01:00Z",
                        "keys": {"peer": "203.0.113.11:4662"},
                        "body": {"repeatCount": 9},
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = control.anti_flood_summary(
        SimpleNamespace(
            log_dir=[logs_dir],
            log_file=None,
            limit=10,
            max_bytes=2048,
            peer_limit=10,
            event_limit=10,
        )
    )

    assert result["totalEvents"] == 3
    assert result["rawEventRows"] == 4
    assert result["duplicateEventRows"] == 1
    assert result["uniquePeers"] == 2
    assert result["maxRepeatCount"] == 9
    assert result["severityCounts"] == {"medium": 2, "high": 1}
    assert result["topPeers"][0]["events"] == 2
    assert result["topPeers"][0]["dropEvents"] == 2
    assert result["topPeers"][0]["maxRepeatCount"] == 4
    assert result["timeRange"] == {
        "firstUtc": "2026-01-01T00:00:00+00:00",
        "lastUtc": "2026-01-01T00:01:00+00:00",
    }
    rendered = repr(result)
    assert "203.0.113.10" not in rendered
    assert "203.0.113.11" not in rendered


def test_vpn_allowlist_status_reports_sanitized_executable_state(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    exe = tmp_path / "bin" / "emulebb-rust-diagnostics.exe"
    exe.parent.mkdir()
    exe.write_text("placeholder", encoding="utf-8")
    settings = tmp_path / "vpn.settings"
    settings.write_text(
        json.dumps({"SplitTunneling": {"Whitelisted": [{"Path": str(exe)}]}}),
        encoding="utf-8",
    )

    result = control.vpn_allowlist_status(
        SimpleNamespace(exe=[exe], settings_path=settings, check_adapter=False)
    )

    assert result["allWhitelisted"] is True
    assert result["adapterChecked"] is False
    assert result["executables"] == [
        {
            "name": "emulebb-rust-diagnostics.exe",
            "pathFingerprint": control.private_path_fingerprint(str(exe)),
            "exists": True,
            "whitelisted": True,
            "error": "",
        }
    ]
    rendered = repr(result)
    assert str(tmp_path) not in rendered


def test_optional_watch_diagnostics_keeps_per_source_summaries(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    rust_logs = tmp_path / "rust"
    mfc_logs = tmp_path / "mfc"
    rust_logs.mkdir()
    mfc_logs.mkdir()
    (rust_logs / "emulebb-rust-diag-1.jsonl").write_text(
        '{"schema":"diag_event_v1","event":"packet","severity":"info"} ED2K\n',
        encoding="utf-8",
    )
    (mfc_logs / "emulebb-diagnostics-kad.log").write_text(
        '{"schema":"kad_event_v1","event":"kad_contact_rejected","severity":"info"} Kad firewalled\n',
        encoding="utf-8",
    )

    result = control.optional_watch_diagnostics(
        SimpleNamespace(
            diagnostics_log_dir=[rust_logs, mfc_logs],
            diagnostics_log_file=[],
            diagnostics_limit=4,
            diagnostics_max_bytes=2048,
        )
    )

    assert result is not None
    assert result["fileCount"] == 2
    assert len(result["sources"]) == 2
    assert result["sources"][0]["fileCount"] == 1
    assert result["sources"][1]["fileCount"] == 1
    assert result["aggregatePatternCounts"]["ed2k"] == 1
    assert result["aggregatePatternCounts"]["firewall"] == 1
    assert result["aggregatePatternCounts"]["kad"] == 1
    rendered = repr(result)
    assert str(tmp_path) not in rendered


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


def test_watch_recommendations_preserve_mfc_hashing_before_restart() -> None:
    control = _load_rust_soak_control()

    assert control.watch_recommendations(
        ["mfc-hashing-active", "mfc-ed2k-not-high-id", "mfc-kad-firewalled"],
        {},
        {},
        {"sharedHashingCount": 12},
        {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
    ) == ["preserve-mfc-hashing-before-connectivity-restart"]
    assert control.watch_recommendations(
        ["mfc-ed2k-not-high-id", "mfc-kad-firewalled"],
        {},
        {},
        {"sharedHashingCount": 0},
        {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
    ) == ["restart-mfc-connectivity-path"]
    assert control.watch_recommendations(
        [],
        {},
        {},
        None,
        {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
    ) == ["continue-soak"]


def test_watch_heartbeat_includes_optional_mfc_status(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    heartbeat = tmp_path / "heartbeat.txt"

    control.write_watch_heartbeat(
        heartbeat,
        {
            "timestampUtc": "2026-01-01T00:00:00+00:00",
            "findings": ["mfc-hashing-active"],
            "recommendations": ["continue-mfc-hashing"],
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
            "vpn": {
                "allWhitelisted": True,
                "adapterUp": True,
                "bindIpPresent": True,
            },
            "diagnostics": {
                "fileCount": 2,
                "aggregatePatternCounts": {"ed2k": 3, "kad": 4},
            },
        },
    )

    text = heartbeat.read_text(encoding="utf-8")
    assert "mfcHashing=12" in text
    assert "mfcEd2kHighId=False" in text
    assert "mfcKadFirewalled=True" in text
    assert "recommendations=continue-mfc-hashing" in text
    assert "vpnAllWhitelisted=True" in text
    assert "vpnAdapterUp=True" in text
    assert "diagnosticsFiles=2" in text
    assert "diagnosticsPatterns=ed2k,kad" in text


def test_watch_trend_summarizes_retained_jsonl_progress(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    jsonl = tmp_path / "watch.jsonl"
    records = [
        {
            "timestampUtc": "2026-01-01T00:00:00+00:00",
            "findings": ["mfc-hashing-active"],
            "recommendations": ["continue-mfc-hashing"],
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
            "monitor": {
                "latestRecord": {
                    "rustKiBps": 90.0,
                    "mfcKiBps": 4.0,
                }
            },
        },
        {
            "timestampUtc": "2026-01-01T00:10:00+00:00",
            "findings": ["mfc-hashing-active", "mfc-kad-firewalled"],
            "recommendations": ["preserve-mfc-hashing-before-connectivity-restart"],
            "diagnostics": {
                "files": [
                    {
                        "jsonBodyCounts": {
                            "upload_request_outcome.firstSkipReason": {"duplicateDone": 2},
                            "upload_request_outcome.outcome": {"served": 3},
                            "upload_slot_recycled.reason": {"uploadTimeout": 1},
                        },
                        "jsonBodyNumeric": {
                            "upload_payload_accounting.sentFileBytes": {
                                "count": 3,
                                "sum": 300.0,
                                "min": 50.0,
                                "max": 150.0,
                                "average": 100.0,
                            },
                            "upload_payload_accounting.sentPayloadBytes": {
                                "count": 3,
                                "sum": 330.0,
                                "min": 60.0,
                                "max": 160.0,
                                "average": 110.0,
                            },
                            "upload_request_outcome.servedBytes": {
                                "count": 3,
                                "sum": 300.0,
                                "min": 50.0,
                                "max": 150.0,
                                "average": 100.0,
                            },
                            "upload_request_outcome.requestedBytes": {
                                "count": 3,
                                "sum": 600.0,
                                "min": 100.0,
                                "max": 300.0,
                                "average": 200.0,
                            },
                            "upload_request_outcome.payloadReadMs": {
                                "count": 3,
                                "sum": 12.0,
                                "min": 2.0,
                                "max": 6.0,
                                "average": 4.0,
                            },
                            "upload_request_outcome.throttleDelayMs": {
                                "count": 3,
                                "sum": 15.0,
                                "min": 3.0,
                                "max": 7.0,
                                "average": 5.0,
                            }
                        }
                    },
                    {
                        "jsonBodyCounts": {
                            "upload_request_outcome.firstSkipReason": {"duplicateDone": 1},
                            "upload_request_outcome.outcome": {"partial": 1, "served": 2}
                        },
                        "jsonBodyNumeric": {
                            "upload_payload_accounting.sentFileBytes": {
                                "count": 2,
                                "sum": 150.0,
                                "min": 25.0,
                                "max": 125.0,
                                "average": 75.0,
                            },
                            "upload_payload_accounting.sentPayloadBytes": {
                                "count": 2,
                                "sum": 165.0,
                                "min": 30.0,
                                "max": 135.0,
                                "average": 82.5,
                            },
                            "upload_request_outcome.servedBytes": {
                                "count": 2,
                                "sum": 150.0,
                                "min": 25.0,
                                "max": 125.0,
                                "average": 75.0,
                            },
                            "upload_request_outcome.requestedBytes": {
                                "count": 2,
                                "sum": 300.0,
                                "min": 75.0,
                                "max": 225.0,
                                "average": 150.0,
                            },
                            "upload_request_outcome.payloadReadMs": {
                                "count": 2,
                                "sum": 12.0,
                                "min": 4.0,
                                "max": 8.0,
                                "average": 6.0,
                            },
                            "upload_request_outcome.throttleDelayMs": {
                                "count": 2,
                                "sum": 20.0,
                                "min": 8.0,
                                "max": 12.0,
                                "average": 10.0,
                            }
                        }
                    },
                ]
            },
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
            "monitor": {
                "latestRecord": {
                    "rustKiBps": 180.0,
                    "mfcKiBps": 10.0,
                }
            },
        },
    ]
    jsonl.write_text("\n".join(control.json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8")

    trend = control.watch_trend(SimpleNamespace(watch_jsonl=jsonl, limit=10))

    assert trend["sampleCount"] == 2
    assert trend["window"]["elapsedSeconds"] == 600.0
    assert trend["latestFindings"] == ["mfc-hashing-active", "mfc-kad-firewalled"]
    assert trend["latestRecommendations"] == ["preserve-mfc-hashing-before-connectivity-restart"]
    assert trend["latestDiagnosticsBodyCounts"]["upload_request_outcome.outcome"] == {
        "served": 5,
        "partial": 1,
    }
    assert trend["latestDiagnosticsBodyCounts"]["upload_request_outcome.firstSkipReason"] == {
        "duplicateDone": 3
    }
    assert trend["latestDiagnosticsBodyCounts"]["upload_slot_recycled.reason"] == {"uploadTimeout": 1}
    assert trend["latestDiagnosticsBodyNumeric"]["upload_request_outcome.servedBytes"] == {
        "count": 5,
        "sum": 450.0,
        "min": 25.0,
        "max": 150.0,
        "average": 90.0,
    }
    assert trend["latestUploadEfficiency"]["servedToRequestedRatio"] == 0.5
    assert trend["latestUploadEfficiency"]["payloadOverheadBytes"] == 45.0
    assert trend["latestUploadEfficiency"]["payloadOverheadRatio"] == 0.1
    assert trend["latestUploadEfficiency"]["averagePayloadReadMs"] == 4.8
    assert trend["latestUploadEfficiency"]["averageThrottleDelayMs"] == 7.0
    assert trend["latestUploadEfficiency"]["duplicateDoneOutcomeRatio"] == 0.5
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
    assert trend["counters"]["monitorRustUploadKiBps"]["delta"] == 90.0
    assert trend["counters"]["monitorRustUploadKiBps"]["perMinute"] == 9.0
    assert trend["counters"]["monitorMfcUploadKiBps"]["last"] == 10.0
    assert trend["counters"]["monitorMfcUploadKiBps"]["perMinute"] == 0.6
    assert "remainingEtaMinutes" not in trend["counters"]["monitorMfcUploadKiBps"]


def test_watch_trend_segments_rust_publish_counters_after_restart(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    jsonl = tmp_path / "watch.jsonl"
    records = [
        {
            "timestampUtc": "2026-01-01T00:00:00+00:00",
            "rust": {
                "ed2kPublishedEntries": 30000,
                "ed2kPendingEntries": 34000,
                "kadSourcePublishedTotal": 320,
            },
        },
        {
            "timestampUtc": "2026-01-01T00:05:00+00:00",
            "rust": {
                "ed2kPublishedEntries": 400,
                "ed2kPendingEntries": 63600,
                "kadSourcePublishedTotal": 0,
            },
        },
        {
            "timestampUtc": "2026-01-01T00:10:00+00:00",
            "rust": {
                "ed2kPublishedEntries": 600,
                "ed2kPendingEntries": 63400,
                "kadSourcePublishedTotal": 3,
            },
        },
    ]
    jsonl.write_text("\n".join(control.json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8")

    trend = control.watch_trend(SimpleNamespace(watch_jsonl=jsonl, limit=10))

    published = trend["counters"]["rustEd2kPublished"]
    assert published["first"] == 400.0
    assert published["last"] == 600.0
    assert published["delta"] == 200.0
    assert published["perMinute"] == 40.0
    assert published["resetSegment"] is True
    assert published["droppedSamples"] == 1

    pending = trend["counters"]["rustEd2kPending"]
    assert pending["first"] == 63600.0
    assert pending["last"] == 63400.0
    assert pending["delta"] == -200.0
    assert pending["perMinute"] == -40.0
    assert pending["remainingEtaMinutes"] == 1585.0
    assert pending["resetSegment"] is True

    kad = trend["counters"]["rustKadSourcePublished"]
    assert kad["first"] == 0.0
    assert kad["last"] == 3.0
    assert kad["delta"] == 3.0
    assert kad["resetSegment"] is True


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


def test_watch_brief_keeps_regular_monitoring_output_compact(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    pid_file = tmp_path / "watch.pid"
    jsonl = tmp_path / "watch.jsonl"
    stop_file = tmp_path / "watch.stop"
    pid_file.write_text("1234\n", encoding="utf-8")
    records = [
        {
            "timestampUtc": "2026-01-01T00:00:00+00:00",
            "rust": {
                "uploadSpeedKiBps": 100.0,
                "activeUploads": 2,
                "waitingUploads": 1,
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
            "monitor": {"latestRecord": {"rustKiBps": 90.0, "mfcKiBps": 2.0}},
        },
        {
            "timestampUtc": "2026-01-01T00:10:00+00:00",
            "findings": ["mfc-hashing-active"],
            "recommendations": ["preserve-mfc-hashing-before-connectivity-restart"],
            "diagnostics": {
                "fileCount": 2,
                "aggregatePatternCounts": {"ed2k": 3},
                "aggregateJsonCounts": {
                    "event": {"upload_request_outcome": 2, "anti_flood_drop": 1},
                    "severity": {"info": 2, "medium": 1},
                },
                "files": [
                    {
                        "jsonBodyCounts": {
                            "upload_request_outcome.firstSkipReason": {"duplicateDone": 1},
                            "upload_request_outcome.outcome": {"partial": 1, "served": 1},
                        },
                        "jsonBodyNumeric": {
                            "upload_payload_accounting.sentFileBytes": {
                                "count": 2,
                                "sum": 200.0,
                                "min": 50.0,
                                "max": 150.0,
                                "average": 100.0,
                            },
                            "upload_payload_accounting.sentPayloadBytes": {
                                "count": 2,
                                "sum": 210.0,
                                "min": 55.0,
                                "max": 155.0,
                                "average": 105.0,
                            },
                            "upload_request_outcome.requestedBytes": {
                                "count": 2,
                                "sum": 400.0,
                                "min": 100.0,
                                "max": 300.0,
                                "average": 200.0,
                            },
                            "upload_request_outcome.servedBytes": {
                                "count": 2,
                                "sum": 200.0,
                                "min": 50.0,
                                "max": 150.0,
                                "average": 100.0,
                            },
                        },
                    }
                ],
            },
            "rust": {
                "uploadSpeedKiBps": 200.0,
                "activeUploads": 4,
                "waitingUploads": 0,
                "ed2kConnected": True,
                "ed2kHighId": True,
                "ed2kPublishedEntries": 1200,
                "ed2kPendingEntries": 8800,
                "ed2kVisibilityPercent": 12.0,
                "kadConnected": True,
                "kadFirewalled": False,
                "kadSourcePublishedTotal": 14,
            },
            "mfc": {
                "sharedFileCount": 160,
                "sharedHashingCount": 840,
                "uploadSpeedKiBps": 2.0,
                "activeUploads": 1,
                "ed2kConnected": True,
                "ed2kHighId": False,
                "kadConnected": True,
                "kadFirewalled": True,
            },
            "monitor": {
                "monitorAlive": True,
                "monitorStale": False,
                "latestAgeSeconds": 20.0,
                "latestRecord": {
                    "rustKiBps": 180.0,
                    "rustUploads": 4,
                    "mfcKiBps": 10.0,
                    "mfcWaiting": 0,
                    "parityGap": False,
                    "mfcLogStale": False,
                },
            },
            "vpn": {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
        },
    ]
    jsonl.write_text("\n".join(control.json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8")
    monkeypatch.setattr(control, "pid_exists", lambda pid: True)
    monkeypatch.setattr(control, "timestamp_age_seconds", lambda timestamp: 60.0)

    brief = control.watch_brief(
        SimpleNamespace(
            watch_pid_file=pid_file,
            watch_jsonl=jsonl,
            watch_stop_file=stop_file,
            stale_seconds=900.0,
            limit=10,
        )
    )

    assert brief["watch"]["alive"] is True
    assert brief["watch"]["stale"] is False
    assert brief["findings"] == ["mfc-hashing-active", "rust-anti-flood-drop-observed"]
    assert brief["rust"]["uploadSpeedKiBps"] == 200.0
    assert brief["rust"]["ed2kHighId"] is True
    assert brief["mfc"]["sharedHashingCount"] == 840
    assert brief["mfc"]["kadFirewalled"] is True
    assert brief["monitor"]["rustKiBps"] == 180.0
    assert brief["vpn"]["allWhitelisted"] is True
    assert brief["diagnostics"]["jsonCounts"]["event"]["anti_flood_drop"] == 1
    assert brief["diagnostics"]["uploadEfficiency"]["servedToRequestedRatio"] == 0.5
    assert brief["trend"]["rustEd2kPending"]["remainingEtaMinutes"] == 440.0
    assert "latestRecord" not in brief
    assert "files" not in brief["diagnostics"]


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
    monkeypatch.setattr(
        control,
        "optional_watch_diagnostics",
        lambda args: {
            "fileCount": 1,
            "aggregatePatternCounts": {"ed2k": 2},
            "aggregateJsonCounts": {
                "event": {"upload_request_outcome": 2, "anti_flood_drop": 1},
                "severity": {"info": 2, "medium": 1},
            },
            "files": [{"name": "emulebb-rust-diag-123.jsonl"}],
        },
    )
    monkeypatch.setattr(
        control,
        "optional_watch_vpn",
        lambda args: {
            "allWhitelisted": True,
            "adapterUp": True,
            "bindIpPresent": True,
            "executables": [],
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
            diagnostics_log_dir=[],
            diagnostics_log_file=[],
            include_vpn_status=True,
        )
    )

    assert "mfc-hashing-active" in result["findings"]
    assert "rust-anti-flood-drop-observed" in result["findings"]
    assert result["recommendations"] == [
        "review-rust-anti-flood-diagnostics",
        "preserve-mfc-hashing-before-connectivity-restart",
    ]
    assert result["diagnostics"]["aggregatePatternCounts"] == {"ed2k": 2}
    assert result["vpn"]["allWhitelisted"] is True
    retained = control.latest_jsonl_record(jsonl)
    assert retained is not None
    assert retained["findings"] == result["findings"]
    assert retained["recommendations"] == result["recommendations"]
    assert retained["diagnostics"]["fileCount"] == 1
    assert retained["diagnostics"]["aggregateJsonCounts"]["event"]["anti_flood_drop"] == 1
    assert retained["vpn"]["adapterUp"] is True
    heartbeat_text = heartbeat.read_text(encoding="utf-8")
    assert "mfcHashing=10" in heartbeat_text
    assert "preserve-mfc-hashing-before-connectivity-restart" in heartbeat_text
    assert "vpnAllWhitelisted=True" in heartbeat_text
    assert "diagnosticsFiles=1" in heartbeat_text


def test_watch_once_brief_report_keeps_retained_evidence_full(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    jsonl = tmp_path / "watch.jsonl"
    heartbeat = tmp_path / "watch.heartbeat.txt"
    pid_file = tmp_path / "watch.pid"
    stop_file = tmp_path / "watch.stop"
    pid_file.write_text("1234\n", encoding="utf-8")

    def fake_sample(base_url: str, api_key: str) -> dict[str, object]:
        if "4732" in base_url:
            return {
                "activeUploads": 1,
                "ed2kConnected": True,
                "ed2kHighId": False,
                "kadConnected": True,
                "kadFirewalled": True,
                "sharedHashingActive": True,
                "sharedHashingCount": 12,
                "uploadSpeedKiBps": 0.5,
            }
        return {
            "activeUploads": 4,
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
    monkeypatch.setattr(control, "pid_exists", lambda pid: True)
    monkeypatch.setattr(control, "timestamp_age_seconds", lambda timestamp: 30.0)
    monkeypatch.setattr(
        control,
        "upload_monitor_sample",
        lambda args: {
            "monitorAlive": True,
            "monitorStale": False,
            "latestAgeSeconds": 5.0,
            "latestRecord": {
                "rustKiBps": 9.0,
                "rustUploads": 4,
                "mfcKiBps": 0.5,
                "mfcWaiting": 0,
                "parityGap": False,
                "mfcLogStale": False,
            },
        },
    )
    monkeypatch.setattr(
        control,
        "optional_watch_diagnostics",
        lambda args: {
            "fileCount": 1,
            "aggregatePatternCounts": {"ed2k": 2},
            "aggregateJsonCounts": {"event": {"upload_request_outcome": 2}},
            "files": [{"name": "emulebb-rust-diag-123.jsonl", "jsonRowCount": 2}],
        },
    )
    monkeypatch.setattr(
        control,
        "optional_watch_vpn",
        lambda args: {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
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
            watch_pid_file=pid_file,
            watch_stop_file=stop_file,
            report="brief",
            report_limit=12,
            diagnostics_log_dir=[],
            diagnostics_log_file=[],
            include_vpn_status=True,
        )
    )

    assert result["watch"]["alive"] is True
    assert result["watch"]["stale"] is False
    assert result["findings"] == ["mfc-ed2k-not-high-id", "mfc-hashing-active", "mfc-kad-firewalled"]
    assert result["rust"]["activeUploads"] == 4
    assert result["monitor"]["rustKiBps"] == 9.0
    assert result["diagnostics"]["jsonCounts"]["event"]["upload_request_outcome"] == 2
    assert "latestRecord" not in result
    assert "files" not in result["diagnostics"]

    retained = control.latest_jsonl_record(jsonl)
    assert retained is not None
    assert retained["diagnostics"]["files"] == [{"name": "emulebb-rust-diag-123.jsonl", "jsonRowCount": 2}]
    assert retained["mfc"]["sharedHashingCount"] == 12
