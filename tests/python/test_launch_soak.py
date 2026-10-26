from __future__ import annotations

import importlib.util
import inspect
import json
import sys
from pathlib import Path

import pytest

from emule_test_harness import cpu_profile, soak_storage, vpn_guard_live
from emule_test_harness.live_wire_inputs import LiveWireInputs


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_launch_soak_module():
    script_path = REPO_ROOT / "scripts" / "launch-soak.py"
    spec = importlib.util.spec_from_file_location("launch_soak_script_under_test", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def inputs_with_profiles(profile_dir: Path | None, rust_profile_dir: Path | None = None) -> LiveWireInputs:
    return LiveWireInputs(
        path=REPO_ROOT / "live-wire-inputs.local.json",
        generic_open_terms=("ubuntu",),
        document_terms=("manual",),
        radarr_movie_terms=("movie",),
        sonarr_series_terms=("series",),
        video_roots=(),
        bootstrap_transfer_hashes=(),
        direct_bootstrap_transfers=(),
        mfc_profile_dir=profile_dir,
        rust_profile_dir=rust_profile_dir,
    )


def test_launch_soak_resolves_direct_mfc_profile_from_live_wire_inputs(tmp_path: Path) -> None:
    module = load_launch_soak_module()
    profile_dir = tmp_path / "EMULE_BIN"

    assert module.resolve_direct_mfc_profile(
        inputs_with_profiles(profile_dir),
        no_mfc=False,
    ) == profile_dir.resolve()
    assert module.resolve_direct_mfc_profile(
        inputs_with_profiles(profile_dir),
        no_mfc=True,
    ) is None
    assert module.resolve_direct_mfc_profile(
        inputs_with_profiles(None),
        no_mfc=False,
    ) is None


def test_launch_soak_resolves_direct_rust_profile_from_live_wire_inputs(tmp_path: Path) -> None:
    module = load_launch_soak_module()
    profile_dir = tmp_path / "rust-profile"

    assert module.resolve_direct_rust_profile(inputs_with_profiles(None, profile_dir)) == profile_dir.resolve()


def test_launch_soak_requires_direct_rust_profile_from_live_wire_inputs() -> None:
    module = load_launch_soak_module()

    try:
        module.resolve_direct_rust_profile(inputs_with_profiles(None, None))
    except RuntimeError as exc:
        assert "rust_profile.profile_dir" in str(exc)
    else:
        raise AssertionError("resolve_direct_rust_profile should reject missing rust_profile.profile_dir")


def test_launch_soak_parser_accepts_lan_bind_addr() -> None:
    module = load_launch_soak_module()
    args = module.build_parser().parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert args.lan_bind_addr == "192.0.2.10"


def test_launch_soak_parser_accepts_profile_and_vpn_guard_options() -> None:
    module = load_launch_soak_module()
    args = module.build_parser().parse_args(
        [
            "--lan-bind-addr",
            "127.0.0.1",
            "--campaign-id",
            "20261025T120000Z",
            "--rust-regular",
            "--no-mfc",
            "--cpu-profile",
            "--cpu-profile-seconds",
            "60",
            "--cpu-profile-stack",
            "--duration-seconds",
            "3600",
            "--stop-file",
            "C:/output/soak/control/stop.requested",
            "--rest-timeout-seconds",
            "30",
            "--connect-timeout-seconds",
            "90",
            "--rust-fallback-server",
            "176.123.5.89:4725",
            "--rust-profile-dir",
            "C:/profiles/imported",
            "--reuse-rust-shared-profile",
            "--rust-shutdown-trigger",
            "ctrl-c",
            "--vpn-guard-live-config",
            "vpn-guard-live.local.json",
            "--vpn-guard-scenario",
            "success",
            "--vpn-topology",
            "full-tunnel",
        ]
    )

    assert args.rust_regular is True
    assert args.campaign_id == "20261025T120000Z"
    assert args.no_mfc is True
    assert args.cpu_profile is True
    assert args.cpu_profile_seconds == 60
    assert args.cpu_profile_stack is True
    assert args.duration_seconds == 3600
    assert args.stop_file == Path("C:/output/soak/control/stop.requested")
    assert args.rest_timeout_seconds == 30
    assert args.connect_timeout_seconds == 90
    assert args.rust_fallback_server == ["176.123.5.89:4725"]
    assert args.rust_profile_dir == Path("C:/profiles/imported")
    assert args.reuse_rust_shared_profile is True
    assert args.rust_shutdown_trigger == "ctrl-c"
    assert args.vpn_guard_scenario == "success"
    assert args.vpn_topology == "full-tunnel"
    assert args.lan_bind_addr == "127.0.0.1"


def test_graceful_teardown_can_use_ctrl_c(monkeypatch) -> None:
    module = load_launch_soak_module()

    class FakeProcess:
        exit_code = None

        def poll(self):
            return self.exit_code

    class FakeLogHandle:
        closed = False

        def close(self) -> None:
            self.closed = True

    process = FakeProcess()
    log_handle = FakeLogHandle()

    def fake_request_ctrl_c(target) -> None:
        assert target is process
        target.exit_code = 0

    monkeypatch.setattr(module, "request_ctrl_c", fake_request_ctrl_c)

    result = module.graceful_teardown(
        rust_handles={"process": process, "logHandle": log_handle},
        mfc_handles=None,
        live_common=None,
        rust_base="http://192.0.2.10:4731",
        rust_shutdown_trigger="ctrl-c",
        wait_seconds=0.1,
    )

    assert result["trigger"] == "ctrl-c"
    assert result["requestSucceeded"] is True
    assert result["forced"] is False
    assert result["exitCode"] == 0
    assert result["clean"] is True
    assert log_handle.closed is True


def test_graceful_teardown_marks_output_capture_failure_unclean(monkeypatch) -> None:
    module = load_launch_soak_module()

    class FakeProcess:
        exit_code = None

        def poll(self):
            return self.exit_code

    class FailingCapture:
        closed = False

        def close(self) -> None:
            self.closed = True

        def raise_if_failed(self) -> None:
            raise RuntimeError("daemon output integrity lost")

    process = FakeProcess()
    capture = FailingCapture()

    def fake_request_ctrl_c(target) -> None:
        target.exit_code = 0

    monkeypatch.setattr(module, "request_ctrl_c", fake_request_ctrl_c)

    result = module.graceful_teardown(
        rust_handles={
            "process": process,
            "logHandle": None,
            "outputCapture": capture,
        },
        mfc_handles=None,
        live_common=None,
        rust_base="http://192.0.2.10:4731",
        rust_shutdown_trigger="ctrl-c",
        wait_seconds=0.1,
    )

    assert result["clean"] is False
    assert result["outputError"] == "RuntimeError: daemon output integrity lost"
    assert capture.closed is True


def test_required_daemon_output_policy_rejects_missing_storage(tmp_path: Path) -> None:
    module = load_launch_soak_module()
    inputs = LiveWireInputs(
        path=tmp_path / "inputs.json",
        generic_open_terms=(),
        document_terms=(),
        radarr_movie_terms=(),
        sonarr_series_terms=(),
        video_roots=(),
        bootstrap_transfer_hashes=(),
        direct_bootstrap_transfers=(),
        soak_storage=None,
    )

    with pytest.raises(RuntimeError, match="require soak_storage"):
        module.required_daemon_output_policy(inputs)


def test_required_daemon_output_policy_selects_daemon_stream(tmp_path: Path) -> None:
    module = load_launch_soak_module()
    daemon_policy = soak_storage.ArtifactStreamPolicy(64, 2)
    inputs = LiveWireInputs(
        path=tmp_path / "inputs.json",
        generic_open_terms=(),
        document_terms=(),
        radarr_movie_terms=(),
        sonarr_series_terms=(),
        video_roots=(),
        bootstrap_transfer_hashes=(),
        direct_bootstrap_transfers=(),
        soak_storage=soak_storage.SoakStoragePolicy(
            max_total_bytes=1_000,
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
            streams={
                "controller_output": soak_storage.ArtifactStreamPolicy(32, 2),
                "daemon_output": daemon_policy,
                "diagnostic_bundles": soak_storage.ArtifactStreamPolicy(16, 2),
                "diagnostic_indexes": soak_storage.ArtifactStreamPolicy(16, 1),
                "diagnostic_pins": soak_storage.ArtifactStreamPolicy(16, 2),
                "diagnostic_segments": soak_storage.ArtifactStreamPolicy(16, 2),
                "observer_actions": soak_storage.ArtifactStreamPolicy(16, 2),
                "observer_checkpoints": soak_storage.ArtifactStreamPolicy(16, 2),
                "observer_summary": soak_storage.ArtifactStreamPolicy(16, 1),
                "process_metrics": soak_storage.ArtifactStreamPolicy(1, 1),
                "process_metrics_summary": soak_storage.ArtifactStreamPolicy(1, 1),
            },
        ),
    )

    assert module.required_daemon_output_policy(inputs) is daemon_policy


def test_required_rust_diagnostic_writer_policy_selects_profile_writer(
    tmp_path: Path,
) -> None:
    module = load_launch_soak_module()
    rust_policy = soak_storage.RustDiagnosticWriterPolicy(
        max_segment_bytes=1_048_576,
        max_segment_seconds=60,
        retained_segments=2,
        max_total_bytes=2_097_152,
        max_retained_seconds=3_600,
        minimum_free_bytes=1,
    )
    inputs = LiveWireInputs(
        path=tmp_path / "inputs.json",
        generic_open_terms=(),
        document_terms=(),
        radarr_movie_terms=(),
        sonarr_series_terms=(),
        video_roots=(),
        bootstrap_transfer_hashes=(),
        direct_bootstrap_transfers=(),
        soak_storage=soak_storage.SoakStoragePolicy(
            max_total_bytes=1_000,
            max_age_seconds=3_600,
            minimum_free_bytes=1,
            bundle_interval_seconds=900,
            rust_diagnostics=rust_policy,
            streams={
                "controller_output": soak_storage.ArtifactStreamPolicy(32, 2),
                "daemon_output": soak_storage.ArtifactStreamPolicy(64, 2),
                "diagnostic_bundles": soak_storage.ArtifactStreamPolicy(16, 2),
                "diagnostic_indexes": soak_storage.ArtifactStreamPolicy(16, 1),
                "diagnostic_pins": soak_storage.ArtifactStreamPolicy(16, 2),
                "diagnostic_segments": soak_storage.ArtifactStreamPolicy(16, 2),
                "observer_actions": soak_storage.ArtifactStreamPolicy(16, 2),
                "observer_checkpoints": soak_storage.ArtifactStreamPolicy(16, 2),
                "observer_summary": soak_storage.ArtifactStreamPolicy(16, 1),
                "process_metrics": soak_storage.ArtifactStreamPolicy(1, 1),
                "process_metrics_summary": soak_storage.ArtifactStreamPolicy(1, 1),
            },
        ),
    )

    assert module.required_rust_diagnostic_writer_policy(inputs) is rust_policy


def test_daemon_output_manifest_records_exact_campaign_policy(tmp_path: Path) -> None:
    module = load_launch_soak_module()
    run_paths = module.soak_run_layout.build_run_paths(
        tmp_path / "soak",
        "20261025T120000Z",
    )

    result = module.daemon_output_manifest(
        run_paths,
        soak_storage.ArtifactStreamPolicy(64, 2),
    )

    assert result == {
        "path": str(run_paths.rust_daemon_output),
        "maxSegmentBytes": 64,
        "retainedSegments": 2,
        "exactBytes": True,
        "stderr": "merged",
    }


def test_capture_rust_diagnostic_bundle_persists_exact_campaign_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_launch_soak_module()
    run_paths = module.soak_run_layout.build_run_paths(
        tmp_path / "soak",
        "20261025T120000Z",
    )
    storage_policy = soak_storage.SoakStoragePolicy(
        max_total_bytes=1_000,
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
        streams={
            "controller_output": soak_storage.ArtifactStreamPolicy(32, 2),
            "daemon_output": soak_storage.ArtifactStreamPolicy(64, 2),
            "diagnostic_bundles": soak_storage.ArtifactStreamPolicy(4_096, 2),
            "diagnostic_indexes": soak_storage.ArtifactStreamPolicy(4_096, 1),
            "diagnostic_pins": soak_storage.ArtifactStreamPolicy(4_096, 2),
            "diagnostic_segments": soak_storage.ArtifactStreamPolicy(4_096, 2),
            "observer_actions": soak_storage.ArtifactStreamPolicy(4_096, 2),
            "observer_checkpoints": soak_storage.ArtifactStreamPolicy(4_096, 2),
            "observer_summary": soak_storage.ArtifactStreamPolicy(4_096, 1),
            "process_metrics": soak_storage.ArtifactStreamPolicy(1, 1),
            "process_metrics_summary": soak_storage.ArtifactStreamPolicy(1, 1),
        },
    )
    bundle = {
        "schema": "emulebb.diagnostic-bundle.v4",
        "capturedAt": "2026-10-25T12:00:00Z",
        "summary": {
            "artifactFileCount": 1,
            "missingArtifactFamilies": [],
            "issueCount": 0,
        },
        "settingsProvenance": {"sensitiveValues": "exact"},
    }
    old_campaign_artifact = (
        run_paths.campaigns_root
        / "20261024T120000Z"
        / "report"
        / "obsolete-evidence.json"
    )
    old_campaign_artifact.parent.mkdir(parents=True)
    old_campaign_artifact.write_bytes(b"o" * 2_048)
    adjacent_artifacts = [
        run_paths.soak_root / "control" / "persisted-soak.latest.json",
        run_paths.last_run_dir / "manifest.json",
        run_paths.soak_root / "transactions" / "mfc-preferences" / "journal.json",
        run_paths.soak_root / "mfc-profile" / "logs" / "emule.log",
    ]
    for path in adjacent_artifacts:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"a" * 512)
    requests: list[tuple] = []

    def fake_retry(*args, **kwargs):
        requests.append((args, kwargs))
        return {"data": bundle}

    monkeypatch.setattr(module, "retry_http_json", fake_retry)

    evidence = module.capture_rust_diagnostic_bundle(
        base_url="http://127.0.0.1:4711",
        run_paths=run_paths,
        storage_policy=storage_policy,
        phase="ready",
        now_ns=123,
    )

    assert requests == [
        (
            (
                "rust diagnostic bundle (ready)",
                3,
                "http://127.0.0.1:4711",
                "/api/v1/diagnostics/bundles",
            ),
            {
                "api_key": module.RUST_API_KEY,
                "method": "POST",
                "body": {"confirmCapture": True},
                "timeout_seconds": 30.0,
            },
        )
    ]
    artifact = Path(str(evidence["path"]))
    assert artifact.parent == run_paths.diagnostic_bundles_dir.resolve()
    assert json.loads(artifact.read_text(encoding="utf-8")) == bundle
    assert evidence["phase"] == "ready"
    assert evidence["bundleSchema"] == "emulebb.diagnostic-bundle.v4"
    assert evidence["bundleSummary"] == bundle["summary"]
    assert evidence["retainedCount"] == 1
    assert not old_campaign_artifact.exists()
    assert all(path.read_bytes() == b"a" * 512 for path in adjacent_artifacts)


def test_capture_rust_diagnostic_bundle_rejects_non_v4_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_launch_soak_module()
    run_paths = module.soak_run_layout.build_run_paths(
        tmp_path / "soak",
        "20261025T120000Z",
    )
    storage_policy = soak_storage.SoakStoragePolicy(
        max_total_bytes=1_000_000,
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
        streams={
            "controller_output": soak_storage.ArtifactStreamPolicy(32, 2),
            "daemon_output": soak_storage.ArtifactStreamPolicy(64, 2),
            "diagnostic_bundles": soak_storage.ArtifactStreamPolicy(4_096, 2),
            "diagnostic_indexes": soak_storage.ArtifactStreamPolicy(4_096, 1),
            "diagnostic_pins": soak_storage.ArtifactStreamPolicy(4_096, 2),
            "diagnostic_segments": soak_storage.ArtifactStreamPolicy(4_096, 2),
            "observer_actions": soak_storage.ArtifactStreamPolicy(4_096, 2),
            "observer_checkpoints": soak_storage.ArtifactStreamPolicy(4_096, 2),
            "observer_summary": soak_storage.ArtifactStreamPolicy(4_096, 1),
            "process_metrics": soak_storage.ArtifactStreamPolicy(1, 1),
            "process_metrics_summary": soak_storage.ArtifactStreamPolicy(1, 1),
        },
    )
    monkeypatch.setattr(
        module,
        "retry_http_json",
        lambda *_args, **_kwargs: {"data": {"schema": "emulebb.diagnostic-bundle.v3"}},
    )

    with pytest.raises(RuntimeError, match="must use emulebb.diagnostic-bundle.v4"):
        module.capture_rust_diagnostic_bundle(
            base_url="http://127.0.0.1:4711",
            run_paths=run_paths,
            storage_policy=storage_policy,
            phase="ready",
            now_ns=123,
        )

    assert not list(run_paths.diagnostic_bundles_dir.glob("*.json"))


def test_periodic_bundle_capture_schedule_waits_and_restarts_after_capture() -> None:
    module = load_launch_soak_module()

    schedule = module.PeriodicBundleCaptureSchedule.start(
        interval_seconds=900,
        now_monotonic=100.0,
    )

    assert not schedule.is_due(999.999)
    assert schedule.is_due(1_000.0)
    assert schedule.after_capture(1_025.0).next_capture_monotonic == 1_925.0


def test_record_diagnostic_bundle_capture_prunes_rotated_manifest_entries() -> None:
    module = load_launch_soak_module()
    captures = [
        {
            "path": "C:/soak/report/diagnostic-bundles/old.json",
            "deletedPaths": [],
            "retainedCount": 2,
        },
        {
            "path": "C:/soak/report/diagnostic-bundles/current.json",
            "deletedPaths": [],
            "retainedCount": 2,
        },
    ]

    module.record_diagnostic_bundle_capture(
        captures,
        {
            "path": "C:/soak/report/diagnostic-bundles/new.json",
            "deletedPaths": ["C:/soak/report/diagnostic-bundles/old.json"],
            "retainedCount": 2,
        },
    )

    assert [capture["path"] for capture in captures] == [
        "C:/soak/report/diagnostic-bundles/current.json",
        "C:/soak/report/diagnostic-bundles/new.json",
    ]


def test_launch_soak_resolves_vpn_guard_from_live_config(tmp_path: Path) -> None:
    module = load_launch_soak_module()
    config_path = tmp_path / "vpn-guard-live.local.json"
    vpn_guard_live.write_config(
        config_path,
        {
            "schema": vpn_guard_live.SCHEMA,
            "p2pBindInterfaceName": "hide.me",
            "allowedPublicIpCidrs": ",".join(vpn_guard_live.REQUIRED_HIDEME_PUBLIC_CIDRS),
            "commands": {},
        },
    )
    args = module.build_parser().parse_args(
        [
            "--lan-bind-addr",
            "192.0.2.10",
            "--vpn-guard-live-config",
            str(config_path),
            "--vpn-guard-scenario",
            "success",
        ]
    )

    resolved = module.resolve_vpn_guard_profile(args)

    assert resolved["mode"] == "block"
    assert resolved["allowed_public_ip_cidrs"] == ",".join(vpn_guard_live.REQUIRED_HIDEME_PUBLIC_CIDRS)
    assert resolved["config_path"] == str(config_path.resolve())


def test_launch_soak_rejects_full_tunnel_without_blocking_vpn_guard() -> None:
    module = load_launch_soak_module()
    args = module.build_parser().parse_args(
        [
            "--lan-bind-addr",
            "127.0.0.1",
            "--vpn-topology",
            "full-tunnel",
        ]
    )

    with pytest.raises(RuntimeError, match="both clients start in Block mode"):
        module.resolve_vpn_guard_profile(args)


def test_launch_soak_initializes_cpu_profile_with_staged_symbols(tmp_path: Path, monkeypatch) -> None:
    module = load_launch_soak_module()
    args = module.build_parser().parse_args(["--lan-bind-addr", "192.0.2.10", "--cpu-profile"])
    run_paths = module.soak_run_layout.build_run_paths(tmp_path / "soak", "20260712T010203Z")
    rust_exe = tmp_path / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
    rust_exe.parent.mkdir(parents=True)
    rust_exe.write_text("", encoding="utf-8")
    rust_exe.with_suffix(".pdb").write_text("", encoding="utf-8")

    monkeypatch.setattr(module.cpu_profile, "discover_cpu_profile_tools", lambda: cpu_profile.CpuProfileTools(xperf="xperf.exe"))
    monkeypatch.setattr(
        module.cpu_profile,
        "start_cpu_profile",
        lambda **_kwargs: {"return_code": 0},
    )

    _tools, paths, report = module.initialize_cpu_profile(args=args, run_paths=run_paths, rust_exe=rust_exe)

    assert paths is not None
    assert report is not None
    assert report["app_exe"] == str(rust_exe)
    assert report["profile_paths"]["summary"].endswith("cpu-profile-summary.json")
    assert report["symbols"]["app_pdb_exists"] is True


def test_rust_process_metrics_rotates_samples_and_keeps_cumulative_summary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = load_launch_soak_module()
    policy = soak_storage.SoakStoragePolicy(
        max_total_bytes=16_384,
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
        streams={
            "process_metrics": soak_storage.ArtifactStreamPolicy(320, 2),
            "process_metrics_summary": soak_storage.ArtifactStreamPolicy(8_192, 1),
        },
    )
    closed: list[int] = []
    monkeypatch.setattr(module.live_process_monitor, "open_process", lambda _pid: 99)
    monkeypatch.setattr(
        module.live_process_monitor,
        "close_handle",
        lambda handle: closed.append(handle),
    )
    metrics = module.RustProcessMetrics(
        process=type("Process", (), {"pid": 321})(),
        report_dir=tmp_path / "report",
        interval_seconds=2.0,
        storage_policy=policy,
    )

    for index in range(6):
        metrics.record_sample(
            {
                "utc_time": f"2026-10-26T12:00:0{index}Z",
                "elapsed_seconds": float(index * 2),
                "pid": 321,
                "cpu_seconds": float(index),
                "process_pct_one_core": float(index * 10),
                "working_set_mb": float(100 + index),
                "peak_working_set_mb": float(110 + index),
                "private_mb": float(90 + index),
                "pagefile_mb": float(95 + index),
                "handles": 200 + index,
                "exit_code": None,
            }
        )
    metrics.close()

    summary = json.loads(metrics.summary_path.read_text(encoding="utf-8"))
    assert summary["schema"] == "emulebb-build-tests.process-metrics-summary.v1"
    assert summary["summary"]["sample_count"] == 6
    assert summary["summary"]["first"]["working_set_mb"] == 100.0
    assert summary["summary"]["last"]["working_set_mb"] == 105.0
    assert summary["summary"]["working_set_mb"] == {
        "min": 100.0,
        "max": 105.0,
        "delta": 5.0,
    }
    assert not hasattr(metrics, "rows")
    retained = sorted(metrics.samples_path.parent.glob(f"{metrics.samples_path.name}*"))
    assert len(retained) == 2
    assert all(path.stat().st_size <= 320 for path in retained)
    retained_rows = [
        json.loads(line)
        for path in retained
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(retained_rows) < 6
    assert any(row["elapsed_seconds"] == 10.0 for row in retained_rows)
    assert closed == [99]


def test_rust_process_metrics_rejects_summary_over_its_reserved_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = load_launch_soak_module()
    policy = soak_storage.SoakStoragePolicy(
        max_total_bytes=16_384,
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
        streams={
            "process_metrics": soak_storage.ArtifactStreamPolicy(2_048, 2),
            "process_metrics_summary": soak_storage.ArtifactStreamPolicy(64, 1),
        },
    )
    closed: list[int] = []
    monkeypatch.setattr(module.live_process_monitor, "open_process", lambda _pid: 99)
    monkeypatch.setattr(
        module.live_process_monitor,
        "close_handle",
        lambda handle: closed.append(handle),
    )
    metrics = module.RustProcessMetrics(
        process=type("Process", (), {"pid": 321})(),
        report_dir=tmp_path / "report",
        interval_seconds=2.0,
        storage_policy=policy,
    )

    with pytest.raises(RuntimeError, match="process_metrics_summary requires"):
        metrics.record_sample(
            {
                "utc_time": "2026-10-26T12:00:00Z",
                "elapsed_seconds": 0.0,
                "pid": 321,
                "cpu_seconds": 0.0,
                "process_pct_one_core": 0.0,
                "working_set_mb": 100.0,
                "peak_working_set_mb": 110.0,
                "private_mb": 90.0,
                "pagefile_mb": 95.0,
                "handles": 200,
                "exit_code": None,
            }
        )
    metrics.close()

    assert not metrics.summary_path.exists()
    assert closed == [99]


def test_launch_soak_wires_direct_mfc_profile_to_cleanup_and_launch() -> None:
    module = load_launch_soak_module()
    source = inspect.getsource(module.main)

    assert "load_live_wire_inputs(inputs_path)" in source
    assert "artifact_store = campaign_artifact_store(run_paths, storage_policy)" in source
    assert "BoundedArtifactStore(soak_root" not in source
    assert "direct_mfc_profile = resolve_direct_mfc_profile(inputs, no_mfc=args.no_mfc)" in source
    assert "rust_profile_dir = resolve_direct_rust_profile(inputs)" in source
    assert "rust_profile_location = soak_launch.require_rust_profile_location(" in source
    assert "rust_profile_setup = mfc_profile_import.ensure_persisted_rust_profile(" in source
    assert source.index("soak_launch.prepare_hideme_routing(") < source.index(
        "mfc_profile_import.ensure_persisted_rust_profile("
    )
    assert source.index("mfc_profile_import.ensure_persisted_rust_profile(") < source.index(
        "soak_run_layout.prepare_clean_run("
    )
    assert source.index("soak_run_layout.prepare_clean_run(") < source.index(
        "profile_overlay.recover_file_overlay("
    )
    assert source.index("profile_overlay.recover_file_overlay(") < source.index(
        "profile_overlay.begin_file_overlay("
    )
    assert source.index("profile_overlay.begin_file_overlay(") < source.index("bring_up_mfc(")
    assert source.index('phase="ready"') < source.index('log("=" * 70)')
    assert source.index('phase="ready"') < source.index(
        "soak_run_layout.mark_run_running("
    )
    assert source.index("soak_run_layout.mark_run_running(") < source.index(
        'log("=" * 70)'
    )
    assert source.index('phase="periodic"') < source.index("time.sleep(2.0)")
    assert source.index('phase="final"') < source.index("graceful_teardown(")
    assert source.index("graceful_teardown(") < source.rindex("mfc_preferences_overlay.restore()")
    assert "resolve_rust_ui_exe" not in source
    assert "launch_rust_ui(" not in source
    assert "direct_profile_dir=direct_mfc_profile" in source
    assert "vpn_guard_mode=str(vpn_guard_profile[\"mode\"])" in source
    assert "duration_deadline = time.monotonic() + args.duration_seconds" in source
    assert "stop_file is not None and stop_file.exists()" in source
    assert "\"durationSeconds\": args.duration_seconds" in source
    assert "\"stopFile\": str(stop_file)" in source
    assert "apply_shared_directories=not args.reuse_rust_shared_profile" in source
    assert "fallback_server_endpoints=list(args.rust_fallback_server)" in source
    assert "\"reuseRustSharedProfile\": bool(args.reuse_rust_shared_profile)" in source
    assert "\"rustFallbackServers\": list(args.rust_fallback_server)" in source
    assert "\"rustProfileSetup\": rust_profile_setup" in source
    assert "\"rustDiagnosticBundles\": diagnostic_bundle_captures" in source
    assert '"intervalSeconds": storage_policy.bundle_interval_seconds' in source
    assert "\"mfcProfileOverlay\":" in source
    assert "except Exception as exc:" in source
    assert "\"error\": failure" in source
    assert "return 1 if status == \"failed\" else 0" in source
