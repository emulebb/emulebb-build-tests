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
            "spikeDumpDelaySeconds": 600,
        }
    )

    assert str(config.profile_dir) == r"X:\live\profile"
    assert config.base_url == "http://127.0.0.1:4711"
    assert config.api_key == "secret"
    assert config.duration_seconds == 1800
    assert config.sample_interval_seconds == 3.5
    assert config.cpu_spike_threshold_one_core == 120
    assert config.max_spike_dumps == 3
    assert config.spike_dump_delay_seconds == 600


def test_parse_config_payload_uses_less_intrusive_dump_defaults() -> None:
    config = live_process_monitor.parse_config_payload(
        {
            "schema": live_process_monitor.SCHEMA,
            "profileDir": r"X:\live\profile",
        }
    )

    assert config.max_spike_dumps == 2
    assert config.spike_dump_delay_seconds == 300.0


def test_parse_config_payload_rejects_wrong_schema() -> None:
    with pytest.raises(RuntimeError, match="schema"):
        live_process_monitor.parse_config_payload({"schema": "wrong", "profileDir": r"X:\profile"})


def test_build_launch_command_uses_real_profile_override() -> None:
    command = live_process_monitor.build_launch_command(
        Path(r"C:\build\emulebb.exe"),
        Path(r"X:\M\profile"),
        extra_args=("-foo",),
    )

    assert command == [
        r"C:\build\emulebb.exe",
        "-ignoreinstances",
        "-c",
        r"X:\M\profile",
        "-foo",
    ]


def test_validate_capture_mode_separates_umdh_from_cpu_and_full_dumps() -> None:
    with pytest.raises(RuntimeError, match="separate from ETW CPU profiling"):
        live_process_monitor.validate_capture_mode(
            cpu_profile_enabled=True,
            enable_umdh=True,
            capture_final_dump=False,
            spike_dumps_enabled=False,
            max_spike_dumps=0,
        )
    with pytest.raises(RuntimeError, match="final full ProcDump"):
        live_process_monitor.validate_capture_mode(
            cpu_profile_enabled=False,
            enable_umdh=True,
            capture_final_dump=True,
            spike_dumps_enabled=False,
            max_spike_dumps=0,
        )
    with pytest.raises(RuntimeError, match="full spike dumps"):
        live_process_monitor.validate_capture_mode(
            cpu_profile_enabled=False,
            enable_umdh=True,
            capture_final_dump=False,
            spike_dumps_enabled=True,
            max_spike_dumps=1,
        )

    live_process_monitor.validate_capture_mode(
        cpu_profile_enabled=False,
        enable_umdh=True,
        capture_final_dump=False,
        spike_dumps_enabled=False,
        max_spike_dumps=1,
    )


def test_should_capture_spike_dump_honors_delay_threshold_and_limit() -> None:
    common = {
        "max_spike_dumps": 2,
        "cpu_spike_threshold_one_core": 75.0,
        "spike_dump_delay_seconds": 300.0,
    }

    assert not live_process_monitor.should_capture_spike_dump(
        elapsed_seconds=299.0,
        process_pct_one_core=150.0,
        captured_count=0,
        **common,
    )
    assert not live_process_monitor.should_capture_spike_dump(
        elapsed_seconds=301.0,
        process_pct_one_core=74.9,
        captured_count=0,
        **common,
    )
    assert not live_process_monitor.should_capture_spike_dump(
        elapsed_seconds=301.0,
        process_pct_one_core=150.0,
        captured_count=2,
        **common,
    )
    assert live_process_monitor.should_capture_spike_dump(
        elapsed_seconds=301.0,
        process_pct_one_core=150.0,
        captured_count=1,
        **common,
    )


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
