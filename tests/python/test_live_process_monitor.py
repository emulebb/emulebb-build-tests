from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness import live_process_monitor


def test_parse_config_payload_normalizes_local_inputs() -> None:
    config = live_process_monitor.parse_config_payload(
        {
            "schema": live_process_monitor.SCHEMA,
            "profileDir": r"X:\live\profile",
            "baseUrl": "http://127.0.0.1:4711/",
            "apiKey": "secret",
            "durationSeconds": 1800,
            "sampleIntervalSeconds": 3.5,
            "procdumpPath": r"X:\tools\procdump64.exe",
            "cpuSpikeThresholdOneCore": 120,
            "maxSpikeDumps": 3,
        }
    )

    assert str(config.profile_dir) == r"X:\live\profile"
    assert config.base_url == "http://127.0.0.1:4711"
    assert config.api_key == "secret"
    assert config.duration_seconds == 1800
    assert config.sample_interval_seconds == 3.5
    assert config.cpu_spike_threshold_one_core == 120
    assert config.max_spike_dumps == 3


def test_parse_config_payload_rejects_wrong_schema() -> None:
    with pytest.raises(RuntimeError, match="schema"):
        live_process_monitor.parse_config_payload({"schema": "wrong", "profileDir": r"X:\profile"})


def test_build_launch_command_uses_real_profile_override() -> None:
    command = live_process_monitor.build_launch_command(
        Path(r"C:\build\emule.exe"),
        Path(r"X:\M\profile"),
        extra_args=("-foo",),
    )

    assert command == [
        r"C:\build\emule.exe",
        "-ignoreinstances",
        "-c",
        r"X:\M\profile",
        "-foo",
    ]


def test_summarize_metric_rows_reports_deltas() -> None:
    summary = live_process_monitor.summarize_metric_rows(
        [
            {
                "working_set_mb": 100.0,
                "private_mb": 90.0,
                "peak_working_set_mb": 110.0,
                "process_pct_one_core": 0.0,
                "handles": 10,
            },
            {
                "working_set_mb": 140.0,
                "private_mb": 120.0,
                "peak_working_set_mb": 145.0,
                "process_pct_one_core": 75.0,
                "handles": 14,
            },
        ]
    )

    assert summary["sample_count"] == 2
    assert summary["working_set_mb"] == {"min": 100.0, "max": 140.0, "delta": 40.0}
    assert summary["private_mb"] == {"min": 90.0, "max": 120.0, "delta": 30.0}
    assert summary["handles"] == {"min": 10.0, "max": 14.0, "delta": 4.0}
