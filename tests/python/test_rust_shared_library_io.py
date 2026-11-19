from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import rust_shared_library_io as subject
from emule_test_harness import rust_cgroup_budget as cgroup_budget
from emule_test_harness import rust_shared_library_storage as storage
from emule_test_harness import workspace_layout


def cgroup_files(tmp_path):
    import os

    root = tmp_path / "cgroup"
    root.mkdir()
    files = {"cgroup.procs": str(os.getpid()), "cpu.max": "100000 100000",
             "memory.max": str(cgroup_budget.MEMORY_BYTES), "memory.swap.max": "0",
             "memory.peak": "450000000", "memory.events": "oom 0\noom_kill 0\noom_group_kill 0\n"}
    for name, value in files.items():
        (root / name).write_text(value, encoding="ascii")
    membership = tmp_path / "membership"
    membership.write_text("0::/\n", encoding="ascii")
    return root, membership


def test_cgroup_budget_requires_kernel_membership_and_reads_the_actual_limits(tmp_path):
    root, membership = cgroup_files(tmp_path)
    value = cgroup_budget.sample_budget(root=root, membership=membership)
    assert cgroup_budget.matches_target(value)
    assert value["scope"] == "campaign-process-tree"
    assert value["memoryPeakBytes"] == 450000000
    (root / "cgroup.procs").write_text("", encoding="ascii")
    with pytest.raises(RuntimeError, match="does not cover"):
        cgroup_budget.sample_budget(root=root, membership=membership)


def test_cgroup_budget_does_not_claim_an_unobserved_namespace(tmp_path):
    root, membership = cgroup_files(tmp_path)
    membership.write_text("0::/other\n", encoding="ascii")
    assert cgroup_budget.sample_budget(root=root, membership=membership) is None
    assert cgroup_budget.sample_budget(root=root, membership=tmp_path / "absent") is None


@pytest.mark.parametrize("name,value", [("memory.max", "max"), ("memory.max", "1073741824"),
                                        ("memory.swap.max", "max"), ("memory.swap.max", "1"),
                                        ("cpu.max", "max 100000"), ("cpu.max", "200000 100000")])
def test_cgroup_budget_does_not_qualify_a_different_budget(tmp_path, name, value):
    root, membership = cgroup_files(tmp_path)
    (root / name).write_text(value, encoding="ascii")
    assert not cgroup_budget.matches_target(cgroup_budget.sample_budget(root=root, membership=membership))


@pytest.mark.parametrize("name,value", [("memory.max", "-1"), ("cpu.max", "100000 0"),
                                        ("memory.events", "oom -1\noom_kill 0\noom_group_kill 0")])
def test_cgroup_budget_rejects_invalid_kernel_numbers(tmp_path, name, value):
    root, membership = cgroup_files(tmp_path)
    (root / name).write_text(value, encoding="ascii")
    with pytest.raises(ValueError):
        cgroup_budget.sample_budget(root=root, membership=membership)


@pytest.mark.parametrize("changed", [None, "scopeIdentity", "memoryMaxBytes", "oom", "oomKill", "oomGroupKill", "missing"])
def test_cgroup_budget_checks_gate_success_and_keep_failed_campaigns_failed(tmp_path, monkeypatch, changed):
    root, membership = cgroup_files(tmp_path)
    before = cgroup_budget.sample_budget(root=root, membership=membership)
    after = dict(before)
    if changed == "scopeIdentity":
        after[changed] = [0, 0]
    elif changed == "missing":
        after = None
    elif changed:
        after[changed] += 1
    monkeypatch.setattr(cgroup_budget, "sample_budget", lambda: after)
    report = {"status": "passed", "qualificationScope": {"containerLimitsEnforced": False},
              "acceptance": {"ok": True}}
    cgroup_budget.finish_report(report, before)
    assert report["kernelResourceBudget"]["ok"] is (changed is None)
    assert report["acceptance"]["ok"] is (changed is None)
    assert report["status"] == ("passed" if changed is None else "failed")
    report["status"] = "failed"
    report["acceptance"]["ok"] = False
    cgroup_budget.finish_report(report, before)
    assert report["status"] == "failed" and report["acceptance"]["ok"] is False


def test_cgroup_budget_measurement_failure_retains_a_failed_report(tmp_path, monkeypatch):
    root, membership = cgroup_files(tmp_path)
    before = cgroup_budget.sample_budget(root=root, membership=membership)
    def fail():
        raise OSError("kernel read failed")
    monkeypatch.setattr(cgroup_budget, "sample_budget", fail)
    report = {"status": "passed", "qualificationScope": {"containerLimitsEnforced": False},
              "acceptance": {"ok": True}}
    cgroup_budget.finish_report(report, before)
    assert report["status"] == "failed"
    assert report["kernelResourceBudget"]["error"] == "OSError"
    assert report["qualificationScope"]["containerLimitsEnforced"] is False


def test_functional_success_does_not_qualify_an_unbounded_cgroup(tmp_path, monkeypatch):
    root, membership = cgroup_files(tmp_path)
    (root / "memory.max").write_text("max", encoding="ascii")
    before = cgroup_budget.sample_budget(root=root, membership=membership)
    monkeypatch.setattr(cgroup_budget, "sample_budget", lambda: dict(before))
    report = {"status": "passed", "qualificationScope": {"containerLimitsEnforced": False},
              "acceptance": {"ok": True}}
    cgroup_budget.finish_report(report, before)
    assert report["status"] == "passed"
    assert report["kernelResourceBudget"]["ok"] is True
    assert report["qualificationScope"]["containerLimitsEnforced"] is False


def tiny_spec() -> subject.FixtureSpec:
    return subject.FixtureSpec(
        top_directories=2,
        leaf_directories_per_top=2,
        files_per_leaf=2,
        small_count=4,
        small_size=8,
        medium_count=2,
        medium_size=16,
        large_count=2,
        large_size=32,
    )


@pytest.mark.parametrize("trace_metadata", [False, True])
def test_initial_profile_seeds_retained_jobs_before_the_daemon_launches(tmp_path, monkeypatch, trace_metadata):
    rust_repo = workspace_layout.resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-rust")
    profile = tmp_path / "profile"
    inherited = dict(subject.os.environ)
    def prepare(path, **kwargs):
        subject.rust_metadata.create_metadata_db(rust_repo, path / subject.rust_metadata.RUST_PROFILE_METADATA_FILE)
    def launch(paths, path, log, **kwargs):
        rows = subject.profile_storage_snapshot(path)["rowCounts"]
        assert rows["downloadJobs"] == 1000
        assert rows["unfinishedDownloads"] == 10
        assert rows["completedDownloads"] == 990
        if trace_metadata:
            env = kwargs["process_env"]
            assert "emulebb_metadata=debug" in env["RUST_LOG"]
            assert {key: value for key, value in env.items() if key != "RUST_LOG"} == {
                key: value for key, value in inherited.items() if key != "RUST_LOG"
            }
        else:
            assert kwargs["process_env"] is None
        return "launched"
    monkeypatch.setattr(subject.rust_client, "write_rust_profile", prepare)
    monkeypatch.setattr(subject, "start_configured_daemon", launch)
    assert subject.start_daemon(SimpleNamespace(rust_repo=rust_repo), profile, tmp_path / "log", 20017,
                                retained_downloads=1000, trace_metadata=trace_metadata) == "launched"
    assert dict(subject.os.environ) == inherited


@pytest.fixture
def replay_baseline(tmp_path, monkeypatch):
    rust_repo = workspace_layout.resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-rust")
    paths = SimpleNamespace(runs_root=tmp_path / "runs", reports_root=tmp_path / "reports",
                            fixture_root=tmp_path / "fixture", rust_repo=rust_repo)
    profile = paths.runs_root / "verified-run" / "profile"
    profile.mkdir(parents=True)
    paths.reports_root.mkdir()
    database = profile / subject.rust_metadata.RUST_PROFILE_METADATA_FILE
    subject.rust_metadata.create_metadata_db(rust_repo, database)
    subject.rust_metadata.seed_retained_download_scale(database, count=1000)
    monkeypatch.setattr(subject, "RETAINED_DOWNLOAD_EXPECTED", {
        "downloadJobs": 1000, "unfinishedDownloads": 10, "completedDownloads": 990,
        "startedDownloads": 1, "stoppedDownloads": 9,
    })
    report = {"schema": subject.REPORT_SCHEMA, "runId": "verified-run",
              "paths": {"fixtureFingerprint": subject.path_fingerprint(paths.fixture_root)},
              "phases": [{"acceptance": {"checks": {key: True for key in (
                  "databaseActiveBytes", "databaseActiveShares", "databaseHashIntegrity",
                  "databaseKnownFiles", "databaseLongPathShares", "databaseScanFailures",
              )}}}]}
    receipt = paths.reports_root / "rust-shared-library-io-verified-run.json"
    receipt.write_text(json.dumps(report), encoding="utf-8")
    return paths, database, receipt


def test_replay_copies_current_sqlite_snapshot_and_preserves_its_source(replay_baseline, tmp_path):
    paths, database, receipt = replay_baseline
    original = database.read_bytes()
    target = tmp_path / "replay"
    result = subject.copy_replay_database(paths, "verified-run", target)
    assert database.read_bytes() == original
    assert result["sourceRunId"] == "verified-run"
    assert result["sourceReportSha256"] == subject.hashlib.sha256(receipt.read_bytes()).hexdigest()
    assert subject.profile_storage_snapshot(target)["rowCounts"]["downloadJobs"] == 1000
    with pytest.raises(RuntimeError, match="already exists"):
        subject.copy_replay_database(paths, "verified-run", target)


def test_replay_refuses_an_unverified_baseline_before_copying(replay_baseline, tmp_path):
    paths, _, receipt = replay_baseline
    report = json.loads(receipt.read_text())
    report["phases"][0]["acceptance"]["checks"]["databaseHashIntegrity"] = False
    receipt.write_text(json.dumps(report), encoding="utf-8")
    target = tmp_path / "replay"
    with pytest.raises(RuntimeError, match="no verified complete library baseline"):
        subject.copy_replay_database(paths, "verified-run", target)
    assert not target.exists()


@pytest.mark.parametrize("run_id", ["..", "../outside", "", "one/two"])
def test_replay_refuses_paths_outside_owned_runs(tmp_path, run_id):
    with pytest.raises(RuntimeError, match="one path segment"):
        subject.copy_replay_database(SimpleNamespace(), run_id, tmp_path)


def test_retained_download_observation_requires_the_realistic_counts():
    class Client:
        def request(self, method, path):
            assert method == "GET"
            return {
                "/snapshot": {"downloads": {"unfinished": 1000, "completed": 99000}},
                "/stats": {"downloadCount": 100000, "activeDownloads": 100},
            }[path]
    assert subject.retained_download_observation(Client())["ok"] is True
    class IncompleteClient(Client):
        def request(self, method, path):
            value = super().request(method, path)
            if path == "/stats":
                value["downloadCount"] = 0
            return value
    assert subject.retained_download_observation(IncompleteClient())["ok"] is False


def test_process_summary_distinguishes_sampled_memory_from_lifetime_peak():
    sampler = object.__new__(subject.ProcessSampler)
    sampler.metric_errors = {}
    sampler.samples = [{"workingSetBytes": 100, "privateBytes": 90,
                        "lifetimePeakWorkingSetBytes": 500, "handleCount": 1,
                        "cpuSeconds": 1, "readBytes": 0, "writeBytes": 0,
                        "readCount": 0, "writeCount": 0}]
    value = sampler.summary()
    assert value["peakWorkingSetBytes"] == 100
    assert value["lifetimePeakWorkingSetBytes"] == 500
    assert value["lifetimeCpuSeconds"] == 1


@pytest.mark.parametrize("bad", [None, {"method": "forcedFallback", "exitCode": 0},
                                  {"method": "rest", "exitCode": 1},
                                  {"method": "rest", "exitCode": False}])
def test_every_process_lifetime_requires_graceful_zero_exit(bad):
    phases = ("initialShutdown", "preMutationShutdown", "mutationShutdown", "finalShutdown")
    report = {phase: {"method": "rest", "exitCode": 0} for phase in phases}
    assert subject.graceful_shutdowns(report, phases)
    for phase in phases:
        assert not subject.graceful_shutdowns(report | {phase: bad}, phases)


def completion_event(**overrides):
    fields = {field: 0 for field in subject.PROGRESS_FIELDS if field not in {
        "phase", "running", "pending", "readRateBytesPerSec",
    }}
    fields.update(scannedCount=100000, hashedCount=100000, startedAtMs=1, updatedAtMs=2)
    fields.update(overrides)
    return {"target": "emulebb_core::shared_directories",
            "fields": fields | {"message": "shared-directory reload completed"}}


def test_reload_keeps_completed_scan_evidence_until_queued_reconciliation_settles(monkeypatch, tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    path = logs / "emulebb-rust.test.jsonl"
    path.write_text(json.dumps(completion_event(hashedCount=5)) + "\n", encoding="utf-8")
    offsets = subject.reload_log_offsets(tmp_path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(completion_event()) + "\n")
        handle.write(json.dumps(completion_event(hashedCount=0, reusedCount=100000)) + "\n")
    def response(*, phase, running, pending, hashed, reused):
        return {"hashingCount": 0, "reloadProgress": {
            "phase": phase, "running": running, "pending": pending,
            "scannedCount": 100000, "activeHashCount": 0,
            "hashedCount": hashed, "reusedCount": reused, "disks": [],
        }}
    responses = [
        response(phase="hashing", running=True, pending=False, hashed=0, reused=100000),
        response(phase="idle", running=False, pending=False, hashed=0, reused=100000),
    ]
    def request(method, path, **kwargs):
        assert method == "GET"
        if path == "/shared-directories":
            return responses.pop(0)
        assert path == subject.SHARED_FILES_PROBE_PATH
        assert not responses, "catalog checked before the queued worker settled"
        return {"total": 100000}
    monkeypatch.setattr(subject, "disk_io_snapshot", lambda _: {})
    monkeypatch.setattr(subject.time, "sleep", lambda _: None)
    result = subject.wait_for_reload(
        label="initial", client=SimpleNamespace(request=request),
        process=SimpleNamespace(poll=lambda: None),
        sampler=SimpleNamespace(samples=[], maybe_sample=lambda **kwargs: None,
                                summary=lambda _: {}),
        disk_counter_key=None, expected_scanned=100000, timeout_seconds=1,
        poll_seconds=0,
        completion_logs=(tmp_path, offsets),
    )
    assert result["progress"]["hashedCount"] == 100000
    assert result["progress"]["reusedCount"] == 0
    assert result["settledProgress"]["hashedCount"] == 0
    assert result["settledProgress"]["reusedCount"] == 100000
    assert result["settledProgress"]["running"] is False
    assert result["completionSource"] == "structuredLog"


@pytest.mark.parametrize("value", [True, -1, "100000", None])
def test_reload_completion_refuses_invalid_counters(tmp_path, value):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "emulebb-rust.test.jsonl").write_text(
        json.dumps(completion_event(hashedCount=value)) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid counters"):
        subject.completed_reload_from_logs(tmp_path, {}, 100000)


def test_reload_completion_waits_for_terminated_record_and_matches_its_target(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    path = logs / "emulebb-rust.new.jsonl"
    wrong_target = completion_event()
    wrong_target["target"] = "unrelated"
    path.write_text(json.dumps(wrong_target) + "\n" + json.dumps(completion_event()), encoding="utf-8")
    assert subject.completed_reload_from_logs(tmp_path, {}, 100000) is None
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n")
    assert subject.completed_reload_from_logs(tmp_path, {}, 100000)["hashedCount"] == 100000


def test_reload_completion_skips_a_record_in_flight_before_the_phase(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    path = logs / "emulebb-rust.test.jsonl"
    old = json.dumps(completion_event(hashedCount=5)) + "\n"
    path.write_text(old[:40], encoding="utf-8")
    offsets = subject.reload_log_offsets(tmp_path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(old[40:] + json.dumps(completion_event()) + "\n")
    assert subject.completed_reload_from_logs(tmp_path, offsets, 100000)["hashedCount"] == 100000


def test_startup_failure_cleans_up_the_child_before_ownership_transfers(tmp_path, monkeypatch):
    process = object()
    stopped = []
    monkeypatch.setattr(subject.rust_client, "start_rust_client_executable", lambda *args: process)
    def failed(*args):
        raise RuntimeError("readiness fixture failed")
    monkeypatch.setattr(subject, "wait_for_rest", failed)
    monkeypatch.setattr(subject, "stop_daemon", lambda child, client: stopped.append(child))
    with pytest.raises(RuntimeError, match="readiness fixture failed"):
        subject.start_configured_daemon(SimpleNamespace(staged_executable=tmp_path / "daemon"),
            tmp_path / "profile", tmp_path / "log", rest_address="127.0.0.1", rest_port=20017)
    assert stopped == [process]


def harness_paths(tmp_path: Path) -> subject.HarnessPaths:
    scenario = tmp_path / "output/profiles/emulebb-rust-shared-library-io"
    return subject.HarnessPaths(
        workspace_root=tmp_path / "workspace",
        output_root=tmp_path / "output",
        rust_repo=tmp_path / "workspace/repos/emulebb-rust",
        scenario_root=scenario,
        fixture_root=scenario / "fixture/library",
        manifest_path=scenario / "fixture-manifest.json",
        owner_path=scenario / ".emulebb-rust-shared-library-io-owner.json",
        runs_root=scenario / "runs",
        reports_root=tmp_path / "output/reports",
        staged_executable=tmp_path / "output/tools/emulebb-rust/bin/emulebb-rust.exe",
    )


@pytest.mark.parametrize("runtime", [False, True])
def test_registered_paths_isolate_profiles_and_require_owned_runtime(tmp_path, monkeypatch, runtime):
    root, output = tmp_path / "workspace", tmp_path / "output"
    rust = root / "workspaces/agents/review/emulebb-rust"
    rust.mkdir(parents=True)
    monkeypatch.setattr(subject, "get_required_emule_workspace_root", lambda: root)
    monkeypatch.setattr(subject, "get_workspace_output_root", lambda: output)
    monkeypatch.setattr(workspace_layout, "resolve_selected_workspace_repo", lambda *args: rust)
    admitted = []
    executable = output / "tools/workstreams/review/emulebb-rust/host/bin/emulebb-rust.exe"

    def verify(source, destination):
        admitted.append((source, destination))
        return {"executable": str(executable)}

    monkeypatch.setattr(subject.rust_client, "verified_runtime_stage", verify)
    paths = subject.resolve_paths(rust_repo=rust, registered_stage=True, require_runtime=runtime)
    assert paths.rust_repo == rust
    assert paths.scenario_root == output / "profiles/workstreams/review/emulebb-rust-shared-library-io"
    assert paths.fixture_root == paths.scenario_root / "fixture/library"
    assert paths.runs_root == paths.scenario_root / "runs"
    assert paths.reports_root == output / "reports/workstreams/review/shared-library-io"
    assert paths.staged_executable == (executable if runtime else None)
    assert admitted == ([(rust, output)] if runtime else [])
    assert not output.exists()


def test_registered_runtime_failure_never_uses_operator_stage(tmp_path, monkeypatch):
    root, output = tmp_path / "workspace", tmp_path / "output"
    rust = root / "workspaces/agents/review/emulebb-rust"
    rust.mkdir(parents=True)
    operator = subject.rust_client.staged_executable(output)
    operator.parent.mkdir(parents=True)
    operator.write_bytes(b"operator runtime")
    monkeypatch.setattr(subject, "get_required_emule_workspace_root", lambda: root)
    monkeypatch.setattr(subject, "get_workspace_output_root", lambda: output)
    monkeypatch.setattr(workspace_layout, "resolve_selected_workspace_repo", lambda *args: rust)

    def reject(*args):
        raise RuntimeError("Registered runtime identity mismatch")

    monkeypatch.setattr(subject.rust_client, "verified_runtime_stage", reject)
    with pytest.raises(RuntimeError, match="identity mismatch"):
        subject.resolve_paths(rust_repo=rust, registered_stage=True, require_runtime=True)
    with pytest.raises(RuntimeError, match="--registered-stage"):
        subject.resolve_paths(rust_repo=rust, require_runtime=True)


def test_registered_paths_reject_another_workstreams_source(tmp_path, monkeypatch):
    root, output = tmp_path / "workspace", tmp_path / "output"
    rust = root / "workspaces/agents/other/emulebb-rust"
    monkeypatch.setattr(subject, "get_required_emule_workspace_root", lambda: root)
    monkeypatch.setattr(subject, "get_workspace_output_root", lambda: output)
    monkeypatch.setattr(workspace_layout, "resolve_selected_workspace_repo",
                        lambda *args: root / "workspaces/agents/selected/emulebb-rust")
    with pytest.raises(RuntimeError, match="registered companion"):
        subject.resolve_paths(rust_repo=rust, registered_stage=True)


def test_unselected_paths_preserve_operator_command_defaults(tmp_path, monkeypatch):
    root, output = tmp_path / "workspace", tmp_path / "output"
    (root / "repos/emulebb-rust").mkdir(parents=True)
    monkeypatch.setattr(subject, "get_required_emule_workspace_root", lambda: root)
    monkeypatch.setattr(subject, "get_workspace_output_root", lambda: output)
    paths = subject.resolve_paths()
    assert paths.scenario_root == output / "profiles/emulebb-rust-shared-library-io"
    assert paths.staged_executable == subject.rust_client.staged_executable(output)


def test_lan_startup_profile_seeds_only_local_sqlite_endpoints(tmp_path):
    from dataclasses import replace

    paths = replace(harness_paths(tmp_path), rust_repo=workspace_layout.resolve_selected_workspace_repo(
        Path(__file__).parents[2], "emulebb-rust"))
    own = SimpleNamespace(rest_port=24660, tcp_port=24662, udp_port=24672)
    peer = SimpleNamespace(tcp_port=24663, udp_port=24673)
    profile = tmp_path / "lan-profile"
    report = subject._configure_lan_startup_profile(
        paths=paths, profile_dir=profile, spec=own, peer_spec=peer, lan_bind_addr="127.0.0.1",
        server_endpoint="127.0.0.1:24661", initial_reload=False, shared_root=None,
    )
    assert report["discovery"]["kad"] == {"status": "initialized", "revision": 0,
                                           "contactCount": 0, "bootstrapEndpointCount": 1}
    with sqlite3.connect(profile / subject.rust_metadata.RUST_PROFILE_METADATA_FILE) as connection:
        assert connection.execute("SELECT endpoint FROM kad_bootstrap_endpoints").fetchall() == [("127.0.0.1:24673",)]
        assert connection.execute("SELECT value_json FROM settings WHERE section='core' AND key='networkKademlia'").fetchone() == ("true",)
    assert not (profile / "nodes.dat").exists()


def test_prepare_low_space_fails_before_creating_any_fixture_state(tmp_path, monkeypatch):
    paths = harness_paths(tmp_path)
    monkeypatch.setattr(subject, "physical_disk_inventory", lambda: [])
    monkeypatch.setattr(subject, "target_disk", lambda *args: {"mediaType": "SSD", "mountPath": str(tmp_path)})
    monkeypatch.setattr(subject.shutil, "disk_usage", lambda *args: SimpleNamespace(free=0))
    with pytest.raises(RuntimeError, match="Insufficient fixture space"):
        subject.prepare_fixture(paths, spec=tiny_spec())
    assert not paths.scenario_root.exists()


def test_fixture_space_preflight_only_reserves_remaining_payloads(tmp_path, monkeypatch):
    paths, spec = harness_paths(tmp_path), tiny_spec()
    index, first, size = next(iter(subject.iter_fixture_files(paths.fixture_root, spec)))
    first.parent.mkdir(parents=True)
    first.write_bytes(subject.deterministic_payload(index, size))
    target = {"mountPath": str(tmp_path)}
    required = spec.total_bytes - size + spec.large_size
    monkeypatch.setattr(subject.shutil, "disk_usage", lambda *args: SimpleNamespace(free=required))
    result = subject.fixture_space_preflight(paths, spec, target)
    assert result["remainingPayloadBytes"] == spec.total_bytes - size
    assert result["requiredFreeBytes"] == required


def test_prepare_refuses_unowned_or_invalid_owner_before_writing(tmp_path, monkeypatch):
    paths = harness_paths(tmp_path)
    paths.scenario_root.mkdir(parents=True)
    sentinel = paths.scenario_root / "operator-file"
    sentinel.write_text("preserve", encoding="utf-8")
    monkeypatch.setattr(subject, "physical_disk_inventory", lambda: [])
    monkeypatch.setattr(subject, "target_disk", lambda *args: {"mediaType": "SSD"})
    with pytest.raises(RuntimeError, match="unowned"):
        subject.prepare_fixture(paths, spec=tiny_spec())
    paths.owner_path.write_text('{"schema":"invalid"}', encoding="utf-8")
    with pytest.raises(RuntimeError, match="ownership marker"):
        subject.prepare_fixture(paths, spec=tiny_spec())
    assert sentinel.read_text() == "preserve"
    assert not paths.manifest_path.exists()


@pytest.mark.unit
def test_production_fixture_is_exactly_100k_and_ten_gib_decimal() -> None:
    assert len(subject.API_KEY.encode("utf-8")) >= 32
    assert subject.SHARED_FILES_PROBE_PATH == "/shared-files?limit=1"
    assert subject.PRODUCTION_SPEC.file_count == 100_000
    assert subject.PRODUCTION_SPEC.total_bytes == 10_485_760_000
    assert len(subject.mutation_indices()) == 1_000
    assert subject.expected_mutation_bytes() == 100 * subject.MIB


@pytest.mark.unit
def test_restart_accepts_validated_cohort_then_requires_full_hydration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not subject.startup_catalog_cohort_accepted(199, 100_000)
    assert subject.startup_catalog_cohort_accepted(200, 100_000)
    assert subject.startup_catalog_cohort_accepted(100_000, 100_000)
    assert not subject.startup_catalog_cohort_accepted(100_001, 100_000)

    totals = iter((200, 2_248, 100_000))
    client = SimpleNamespace(request=lambda *_args, **_kwargs: {"total": next(totals)})
    process = SimpleNamespace(poll=lambda: None)
    monkeypatch.setattr(subject.time, "sleep", lambda _seconds: None)
    hydrated = subject.wait_for_shared_catalog_hydration(
        client=client,
        process=process,
        expected=100_000,
        timeout_seconds=1,
        poll_seconds=0,
    )
    assert hydrated["sharedFilesTotal"] == 100_000


@pytest.mark.unit
def test_production_fixture_reserves_exactly_one_long_path_group() -> None:
    first_long = subject.relative_file_for_index(99_000)
    assert len(str(subject.relative_file_for_index(98_999))) < 300
    assert len(str(first_long)) >= 300
    assert len(str(subject.relative_file_for_index(99_999))) >= 300
    assert max(len(part) for part in first_long.parts) <= 60
    assert (
        sum(
            len(str(subject.relative_file_for_index(index))) >= 300
            for index in range(subject.PRODUCTION_SPEC.file_count)
        )
        == 1_000
    )


@pytest.mark.unit
def test_fixture_manifest_describes_native_lengths_and_unicode_cohort() -> None:
    manifest = subject.fixture_manifest(
        subject.PRODUCTION_SPEC, status="planned", disk_number=4
    )

    assert manifest["fileCount"] == 100_000
    assert manifest["longPaths"]["nativeLengthUnit"] == storage.native_length_unit()
    assert manifest["unicodeCohort"]["fileCount"] == 16
    assert manifest["unicodeCohort"]["longUnicodePathCount"] == 4


@pytest.mark.unit
def test_lan_startup_acceptance_requires_publication_during_partial_scan() -> None:
    observation = {
        "progress": {
            "running": True,
            "scannedCount": 100_000,
            "plannedHashCount": 99_800,
            "hashedCount": 4_096,
        },
        "sharedFilesTotal": 200,
        "ed2kConnected": True,
        "ed2kPublish": {"publishedEntries": 200},
        "serverTargetPublicationCount": 200,
        "targetKad": {"connected": True, "contactCount": 1},
        "seedKad": {"connected": True, "contactCount": 1},
        "kadPublish": {
            "phase": "publishing",
            "running": True,
            "keywordAttempted": 1,
            "sourceAttempted": 1,
        },
    }

    accepted = subject.lan_startup_overlap_acceptance(
        observation, expected_file_count=100_000
    )

    assert accepted["ok"] is True
    observation["progress"]["running"] = False
    assert (
        subject.lan_startup_overlap_acceptance(
            observation, expected_file_count=100_000
        )["ok"]
        is False
    )


@pytest.mark.unit
def test_shared_library_lanes_leave_canonical_server_builds_to_workspace_tooling() -> None:
    source = Path(subject.__file__).read_text(encoding="utf-8")

    assert 'else paths.workspace_root / "repos" / "ed2k-server"' not in source
    assert source.count(
        "repo_override=str(server_repo) if server_repo is not None else None"
    ) == 2


@pytest.mark.unit
def test_offerfiles_scale_cancellation_requires_quiescent_clean_shutdown() -> None:
    before = {
        "requested": 0,
        "sessions": 0,
        "batches": 0,
        "records": 0,
        "oversized": 0,
        "conn_waits": 0,
        "conn_wait_ms": 0,
        "global_waits": 0,
        "global_wait_ms": 0,
        "global_wait_max_ms": 0,
        "global_waiting_now": 0,
    }
    stopped = before | {
        "requested": 1,
        "sessions": 1,
        "batches": 3,
        "records": 600,
    }

    accepted = subject.offerfiles_scale_cancellation_acceptance(
        before=before,
        after_shutdown=stopped,
        after_settle=dict(stopped),
        shutdown={"method": "rest", "exitCode": 0},
        client_absent=True,
    )

    assert accepted["ok"] is True
    assert accepted["delta"]["records"] == 600
    assert accepted["checks"]["oneAdvertisedSession"] is True
    assert accepted["checks"]["sessionCounterSettled"] is True
    moving = dict(stopped)
    moving["records"] = 800
    assert (
        subject.offerfiles_scale_cancellation_acceptance(
            before=before,
            after_shutdown=stopped,
            after_settle=moving,
            shutdown={"method": "rest", "exitCode": 0},
            client_absent=True,
        )["ok"]
        is False
    )


@pytest.mark.unit
def test_offerfiles_scale_completion_requires_full_paced_reconnect() -> None:
    before = {
        "requested": 1,
        "sessions": 0,
        "batches": 3,
        "records": 600,
        "oversized": 0,
        "conn_waits": 0,
        "conn_wait_ms": 0,
        "global_waits": 0,
        "global_wait_ms": 0,
        "global_wait_max_ms": 0,
        "global_waiting_now": 0,
    }
    after = before | {
        "requested": 2,
        "sessions": 1,
        "batches": 503,
        "records": 100_600,
    }
    client_evidence = {
        "mode": "negotiatedV1",
        "batchMax": 200,
        "minIntervalMs": 500,
        "publishedEntries": 100_000,
        "pendingEntries": 0,
        "sessionPumpActive": False,
        "serverSharedFiles": 100_000,
    }
    process_summary = {
        "peakWorkingSetBytes": 256 * 1024 * 1024,
        "peakPrivateBytes": 300 * 1024 * 1024,
    }

    accepted = subject.offerfiles_scale_completion_acceptance(
        before=before,
        after=after,
        elapsed_seconds=249.5,
        client_evidence=client_evidence,
        process_summary=process_summary,
    )

    assert accepted["ok"] is True
    assert accepted["expectedBatches"] == 500
    assert accepted["minimumElapsedSeconds"] == 249.5
    after["batches"] = 507
    assert (
        subject.offerfiles_scale_completion_acceptance(
            before=before,
            after=after,
            elapsed_seconds=253.0,
            client_evidence=client_evidence,
            process_summary=process_summary,
        )["ok"]
        is True
    )
    too_fast = subject.offerfiles_scale_completion_acceptance(
        before=before,
        after=after,
        elapsed_seconds=200.0,
        client_evidence=client_evidence,
        process_summary=process_summary,
    )
    assert too_fast["ok"] is False
    assert too_fast["checks"]["minimumPacingElapsed"] is False


@pytest.mark.unit
def test_offerfiles_client_evidence_uses_nested_server_status() -> None:
    evidence = subject.offerfiles_client_evidence(
        {
            "servers": {
                "currentServer": {
                    "offerFilesMode": "negotiatedV1",
                    "offerFilesBatchMax": 200,
                    "offerFilesMinIntervalMs": 500,
                    "offerFilesPublishedEntries": 100_000,
                    "offerFilesPendingEntries": 0,
                }
            }
        },
        {
            "ed2kPublish": {
                "publishedEntries": 92_888,
                "pendingEntries": 7_112,
                "sessionPumpActive": True,
            }
        },
        server_shared_files=100_000,
    )

    assert evidence == {
        "mode": "negotiatedV1",
        "batchMax": 200,
        "minIntervalMs": 500,
        "publishedEntries": 100_000,
        "pendingEntries": 0,
        "sessionPumpActive": False,
        "serverSharedFiles": 100_000,
    }


@pytest.mark.unit
def test_offer_v1_counters_reject_missing_server_shape() -> None:
    with pytest.raises(RuntimeError, match="offer_v1"):
        subject.offer_v1_counters({"data": {}})


@pytest.mark.unit
def test_offerfiles_server_stats_uses_policy_and_counter_endpoint(monkeypatch) -> None:
    calls = []

    def fake_admin_request(base_url, api_key, path, *, timeout_seconds):
        calls.append((base_url, api_key, path, timeout_seconds))
        return {"data": {"offer_v1": {}}}

    monkeypatch.setattr(subject.ed2k_harness, "admin_request", fake_admin_request)

    result = subject.read_offerfiles_server_stats("http://127.0.0.1:8080")

    assert result == {"data": {"offer_v1": {}}}
    assert calls == [
        ("http://127.0.0.1:8080", subject.API_KEY, "/api/stats", 5.0)
    ]


@pytest.mark.unit
def test_offerfiles_campaign_uses_launcher_selected_server_endpoint(monkeypatch) -> None:
    server = SimpleNamespace(ed2k_host="172.20.0.2", ed2k_port=4661)
    route_calls = []

    def fake_resolve_route_bind_ip(host, port):
        route_calls.append((host, port))
        return "172.20.0.1"

    monkeypatch.setattr(subject.ed2k_harness, "resolve_route_bind_ip", fake_resolve_route_bind_ip)

    assert subject.launched_server_endpoint(server) == "172.20.0.2:4661"
    assert subject.launched_client_bind_address(server) == "172.20.0.1"
    assert route_calls == [("172.20.0.2", 4661)]

    forwarded = SimpleNamespace(ed2k_host="127.0.0.1", ed2k_port=4661)
    assert subject.launched_client_bind_address(forwarded) == "127.0.0.1"
    assert route_calls == [("172.20.0.2", 4661)]


@pytest.mark.unit
def test_offerfiles_scale_parser_uses_retained_campaign_defaults() -> None:
    args = subject.build_parser().parse_args(
        ["offerfiles-scale", "--lan-bind-addr", "192.0.2.10"]
    )

    assert args.timeout_seconds == 3 * 60 * 60
    assert args.poll_seconds == 0.25
    assert args.cancel_after_batches == 3
    assert args.settle_seconds == 2.0
    assert args.resume_run_id is None


@pytest.mark.unit
def test_offerfiles_scale_resume_requires_accepted_cold_scan(tmp_path: Path) -> None:
    paths = harness_paths(tmp_path)
    run_id = "20261021T204449Z-15648"
    run_root = paths.runs_root / f"offerfiles-scale-{run_id}"
    profile_dir = run_root / "profile"
    profile_dir.mkdir(parents=True)
    (profile_dir / subject.rust_metadata.RUST_PROFILE_METADATA_FILE).write_bytes(b"db")
    paths.reports_root.mkdir(parents=True)
    report_path = paths.reports_root / f"rust-offerfiles-scale-{run_id}.json"
    report_path.write_text(
        json.dumps(
            {
                "schema": subject.OFFERFILES_SCALE_REPORT_SCHEMA,
                "runId": run_id,
                "status": "failed",
                "startedAtUtc": "2026-10-21T20:44:49Z",
                "finishedAtUtc": "2026-10-21T21:32:43Z",
                "error": {"type": "TimeoutError"},
                "offlineScan": {"acceptance": {"ok": True}},
                "offlineShutdown": {"method": "rest", "exitCode": 0},
            }
        ),
        encoding="utf-8",
    )

    resolved = subject.load_offerfiles_scale_resume(paths, run_id)

    assert resolved[:3] == (run_root, profile_dir, report_path)
    resumed = resolved[3]
    assert resumed["status"] == "running"
    assert resumed["resumeCount"] == 1
    assert resumed["attempts"][0]["status"] == "failed"
    assert "error" not in resumed

    report_path.write_text(
        json.dumps(
            {
                "schema": subject.OFFERFILES_SCALE_REPORT_SCHEMA,
                "runId": run_id,
                "offlineScan": {"acceptance": {"ok": False}},
                "offlineShutdown": {"method": "rest", "exitCode": 0},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="cold-scan checkpoint"):
        subject.load_offerfiles_scale_resume(paths, run_id)


@pytest.mark.unit
def test_offerfiles_scale_policy_requires_enabled_100k_envelope() -> None:
    accepted = subject._offerfiles_scale_policy_acceptance(
        {
            "data": {
                "offerfiles_v1": True,
                "offerfiles_v1_error": None,
                "offerfiles_v1_policy": "200 files per batch",
                "soft_limit_files": 100_000,
                "hard_limit_files": 200_000,
            }
        },
        expected_files=100_000,
    )

    assert accepted["ok"] is True
    rejected = subject._offerfiles_scale_policy_acceptance(
        {
            "data": {
                "offerfiles_v1": False,
                "offerfiles_v1_error": None,
                "soft_limit_files": 5_000,
                "hard_limit_files": 200_000,
            }
        },
        expected_files=100_000,
    )
    assert rejected["ok"] is False


@pytest.mark.unit
def test_watcher_cohort_is_exactly_one_percent_with_balanced_path_classes() -> None:
    summary = subject.fixture.watcher_cohort_summary()
    paths = [
        subject.fixture.watcher_relative_file(index)
        for index in range(subject.fixture.WATCHER_FILE_COUNT)
    ]
    sizes = [
        subject.fixture.watcher_size_for_index(index)
        for index in range(subject.fixture.WATCHER_FILE_COUNT)
    ]
    assert summary == {
        "fileCount": 1_000,
        "totalBytes": 100 * subject.MIB,
        "normalPathFileCount": 500,
        "longPathFileCount": 500,
    }
    assert sum(size == 16 * 1024 for size in sizes) == 800
    assert sum(size == 256 * 1024 for size in sizes) == 150
    assert sum(size == subject.MIB for size in sizes) == 50
    assert sum(len(str(path)) >= 300 for path in paths) == 500


@pytest.mark.unit
def test_index_mapping_is_stable_across_tree_and_size_tiers() -> None:
    spec = tiny_spec()
    assert subject.relative_file_for_index(0, spec) == Path(
        "group-000/leaf-000/file-000000.bin"
    )
    assert subject.relative_file_for_index(7, spec) == Path(
        "group-001/leaf-001/file-000007.bin"
    )
    assert [subject.file_size_for_index(index, spec) for index in range(8)] == [
        8,
        8,
        8,
        8,
        16,
        16,
        32,
        32,
    ]


@pytest.mark.unit
def test_prepare_fixture_is_resumable_and_validates_without_deleting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = tiny_spec()
    paths = harness_paths(tmp_path)
    monkeypatch.setattr(
        subject,
        "physical_disk_inventory",
        lambda: [{"diskNumber": 6, "mediaType": "SSD"}],
    )
    monkeypatch.setattr(
        subject,
        "target_disk",
        lambda _paths, _inventory: {
            "diskNumber": 6,
            "mediaType": "SSD",
            "busType": "NVMe",
            "friendlyName": "test",
        },
    )
    first = subject.prepare_fixture(paths, spec=spec)
    second = subject.prepare_fixture(paths, spec=spec)
    assert first["createdCount"] == 8
    assert second["createdCount"] == 0
    assert second["reusedCount"] == 8
    validation = subject.validate_fixture(paths.fixture_root, spec)
    assert validation["ok"] is True
    assert validation["pathLengthUnit"] == storage.native_length_unit()
    assert validation["unicodePathFileCount"] == 0
    assert validation["nameCapabilities"]["caseCollisionDisposition"] in {
        "supported",
        "skipped-native-alias",
    }
    assert str(tmp_path) not in json.dumps(validation, ensure_ascii=False)
    manifest = json.loads(paths.manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "prepared"

    subject.mutate_fixture(paths.fixture_root, spec)
    subject.update_fixture_generation(paths, "mutation-v2")
    resumed = subject.prepare_fixture(paths, spec=spec)
    assert resumed["contentGeneration"] == "mutation-v2"
    restored = subject.restore_fixture_baseline(paths.fixture_root, spec)
    subject.update_fixture_generation(paths, "base-v2")
    assert restored["totalBytes"] == spec.total_bytes
    assert (
        json.loads(paths.manifest_path.read_text(encoding="utf-8"))["contentGeneration"]
        == "base-v2"
    )


@pytest.mark.unit
def test_cleanup_requires_exact_owned_target(tmp_path: Path) -> None:
    paths = harness_paths(tmp_path)
    paths.scenario_root.mkdir(parents=True)
    subject.write_json(paths.owner_path, {"schema": subject.OWNER_SCHEMA})
    with pytest.raises(RuntimeError, match="confirm"):
        subject.cleanup(paths, confirmed=False)
    result = subject.cleanup(paths, confirmed=True)
    assert result["status"] == "removed"
    assert not paths.scenario_root.exists()


@pytest.mark.unit
def test_v1_fixture_manifest_requires_explicit_cleanup(tmp_path: Path) -> None:
    paths = harness_paths(tmp_path)
    paths.scenario_root.mkdir(parents=True)
    subject.write_json(paths.owner_path, {"schema": subject.OWNER_SCHEMA})
    subject.write_json(
        paths.manifest_path,
        {"schema": "emulebb.rust-shared-library-fixture.v1", "status": "prepared"},
    )
    with pytest.raises(RuntimeError, match="not v2"):
        subject.load_prepared_manifest(paths)


@pytest.mark.unit
def test_phase_acceptance_checks_serial_io_and_exact_counters() -> None:
    phase = {
        "sharedFilesTotal": 8,
        "maxPerDiskActiveCount": 1,
        "progress": {
            "scannedCount": 8,
            "plannedHashCount": 2,
            "hashedCount": 2,
            "failedHashCount": 0,
            "statFailedCount": 0,
            "skippedFailedCount": 0,
            "skippedIntakeCount": 0,
            "reusedCount": 6,
            "plannedReadBytes": 64,
            "completedReadBytes": 64,
            "diskCount": 1,
            "changedCount": 2,
        },
    }
    result = subject.phase_acceptance(
        phase,
        {
            "sharedFilesTotal": 8,
            "scannedCount": 8,
            "plannedHashCount": 2,
            "hashedCount": 2,
            "reusedCount": 6,
            "plannedReadBytes": 64,
            "diskCount": 1,
            "changedCount": 2,
        },
    )
    assert result["ok"] is True


@pytest.mark.unit
def test_windows_verbatim_path_handles_drive_unc_and_existing_prefix() -> None:
    assert storage.windows_verbatim_path(r"C:\fixture\library") == (
        r"\\?\C:\fixture\library"
    )
    assert storage.windows_verbatim_path(r"\\server\share\library") == (
        r"\\?\UNC\server\share\library"
    )
    assert storage.windows_verbatim_path(r"\\?\C:\fixture") == r"\\?\C:\fixture"


@pytest.mark.unit
def test_long_path_adapter_reads_walks_and_removes(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    path = (
        root.joinpath(*(f"segment-{index}-" + "x" * 52 for index in range(5)))
        / "file.bin"
    )
    assert storage.absolute_path_length(path) > 260
    subject.fixture.write_payload(path, b"synthetic")
    assert storage.is_file(path)
    assert storage.stat(path).st_size == len(b"synthetic")
    walked = [
        directory / name for directory, _, files in storage.walk(root) for name in files
    ]
    assert walked == [path]
    storage.remove_tree(root)
    assert not storage.is_directory(root)


@pytest.mark.unit
def test_linux_lsblk_parser_maps_children_to_one_physical_disk() -> None:
    rows = storage.parse_linux_lsblk(
        {
            "blockdevices": [
                {
                    "name": "/dev/nvme0n1",
                    "kname": "nvme0n1",
                    "path": "/dev/nvme0n1",
                    "type": "disk",
                    "size": 2_000_000,
                    "model": "Synthetic SSD",
                    "rota": False,
                    "tran": "nvme",
                    "children": [
                        {
                            "name": "/dev/nvme0n1p1",
                            "kname": "nvme0n1p1",
                            "path": "/dev/nvme0n1p1",
                            "type": "part",
                        }
                    ],
                }
            ]
        }
    )
    assert len(rows) == 1
    assert rows[0]["mediaType"] == "SSD"
    assert rows[0]["counterKey"] == "nvme0n1"
    assert "/dev/nvme0n1p1" in rows[0]["devicePaths"]


@pytest.mark.unit
def test_watcher_evidence_is_exact_and_does_not_publish_paths(tmp_path: Path) -> None:
    normal = subject._normalized_path_key(tmp_path / "watch-probe-0000.bin")
    long = subject._normalized_path_key(tmp_path / "watch-probe-0500.bin")
    expected = {
        normal: {"sizeBytes": 16, "pathClass": "normal"},
        long: {"sizeBytes": 32, "pathClass": "long"},
    }
    rows = {
        normal: {
            "hash": "a" * 32,
            "sizeBytes": 16,
            "completed": 1,
            "md4Acquired": 1,
            "aichAcquired": 1,
            "aichRootBytes": 20,
            "sourceFingerprintBytes": 47,
        },
        long: {
            "hash": "b" * 32,
            "sizeBytes": 32,
            "completed": 1,
            "md4Acquired": 1,
            "aichAcquired": 1,
            "aichRootBytes": 20,
            "sourceFingerprintBytes": 47,
        },
    }
    evidence, ok = subject._watcher_row_evidence(rows, expected)
    assert ok is True
    assert evidence["normalPathCount"] == 1
    assert evidence["longPathCount"] == 1
    assert str(tmp_path) not in json.dumps(evidence)


@pytest.mark.unit
def test_watcher_rest_sample_uses_canonical_path_field(tmp_path: Path) -> None:
    path = tmp_path / "watch-probe-0000.bin"
    key = subject._normalized_path_key(path)
    rows = {key: {"hash": "a" * 32, "sizeBytes": 16}}
    expected = {key: {"sizeBytes": 16, "pathClass": "normal"}}

    class FakeClient:
        def request(
            self, method: str, route: str, **_kwargs: object
        ) -> dict[str, object]:
            assert method == "GET"
            assert route == f"/shared-files/{'a' * 32}"
            return {"hash": "a" * 32, "sizeBytes": 16, "path": str(path)}

    sample = subject._sample_watcher_rest(FakeClient(), rows, expected)
    assert sample["sampleCount"] == 1
    assert sample["failureCount"] == 0


@pytest.mark.unit
def test_watcher_database_query_returns_only_active_probe_rows(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    database = profile / subject.rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_repo = workspace_layout.resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-rust")
    subject.rust_metadata.create_metadata_db(rust_repo, database)
    for hash_value, name in (("11", "watch-probe-0000.bin"), ("33", "watch-probe-0001.bin")):
        subject.rust_metadata.seed_indexed_file(database, ed2k_hash=hash_value * 16,
            name=name, size_bytes=16, origin="local_share")
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        root_path = subject.rust_metadata._upsert_local_path(connection, str(tmp_path), 0)
        root = connection.execute("INSERT INTO shared_directory_roots(path_id,created_at_ms) VALUES(?,0)", (root_path,)).lastrowid
        connection.execute("INSERT INTO shared_directory_root_origins VALUES(?,'explicit',0,1,1)", (root,))
        for hash_value, name, removed in (("11", "watch-probe-0000.bin", None), ("33", "watch-probe-0001.bin", 123)):
            known = connection.execute("SELECT id FROM known_files WHERE ed2k_hash=?", (bytes.fromhex(hash_value * 16),)).fetchone()[0]
            path_id = subject.rust_metadata._upsert_local_path(connection, str(tmp_path / name), 0)
            connection.execute("INSERT INTO verified_local_content(known_file_id,display_name,part_size_bytes,part_count,aich_root) VALUES(?,?,16,1,?)", (known, name, bytes.fromhex("22" * 20)))
            connection.execute("INSERT INTO verified_local_md4_hashes VALUES(?,0,?)", (known, bytes(16)))
            connection.execute("INSERT INTO verified_local_aich_hashes VALUES(?,0,?)", (known, bytes(20)))
            connection.execute("INSERT INTO local_file_instances(path_id,known_file_id,size_bytes,native_identity,verified_fingerprint,verified_at_ms) VALUES(?,?,16,?,?,0)", (path_id, known, b"identity" + bytes([known]), bytes(47)))
            connection.execute("INSERT INTO shared_file_memberships(root_id,path_id,known_file_id,relative_path,first_seen_at_ms,last_seen_at_ms,removed_at_ms) VALUES(?,?,?,?,0,0,?)", (root, path_id, known, name, removed))
    rows = subject._watcher_database_rows(profile)
    assert len(rows) == 1
    assert next(iter(rows.values()))["hash"] == "11" * 16
    assert next(iter(rows.values()))["md4Acquired"] == 1
    assert next(iter(rows.values()))["aichAcquired"] == 1
    snapshot = subject.profile_storage_snapshot(profile)
    assert snapshot["rowCounts"]["activeShareSources"] == 1
    assert snapshot["rowCounts"]["activeShareBytes"] == 16
    assert snapshot["rowCounts"]["invalidActiveShareIntegrity"] == 0


@pytest.mark.unit
def test_storage_snapshot_distinguishes_verified_shares_and_download_jobs(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    database = profile / subject.rust_metadata.RUST_PROFILE_METADATA_FILE
    rust_repo = workspace_layout.resolve_selected_workspace_repo(Path(__file__).parents[2], "emulebb-rust")
    subject.rust_metadata.create_metadata_db(rust_repo, database)
    subject.rust_metadata.seed_retained_download_scale(database, count=1000)
    subject.rust_metadata.seed_indexed_file(database, ed2k_hash="ff" * 16,
        name="unverified.bin", size_bytes=16, origin="local_share")
    snapshot = subject.profile_storage_snapshot(profile)
    counts = snapshot["rowCounts"]
    assert counts["knownFiles"] == 1001
    assert counts["verifiedContentRows"] == 0
    assert counts["activeShareSources"] == 0
    assert counts["activeShareBytes"] == 0
    assert {key: counts[key] for key in subject.RETAINED_DOWNLOAD_EXPECTED} == {
        "downloadJobs": 1000, "unfinishedDownloads": 10, "completedDownloads": 990,
        "startedDownloads": 1, "stoppedDownloads": 9,
    }
    assert all(subject.storage_acceptance(snapshot, expected_active=0, expected_bytes=0,
        expected_minimum_long=0, expected_known=1001).values())
    assert not subject.storage_acceptance(snapshot, expected_active=0, expected_bytes=0,
        expected_minimum_long=0, expected_known=1000)["databaseKnownFiles"]


@pytest.mark.unit
def test_watcher_log_summary_reports_empty_logs_without_faking_registration(
    tmp_path: Path,
) -> None:
    empty = tmp_path / "empty.log"
    empty.write_bytes(b"")
    summary = subject.watcher_log_summary([empty])
    assert summary["logByteCount"] == 0
    assert summary["nonEmptyLogCount"] == 0
    assert summary["watcherRegistrations"] == 0


@pytest.mark.unit
def test_storage_target_report_fingerprints_local_roots(tmp_path: Path) -> None:
    target = storage.StorageTarget(
        role="ssdBaseline",
        root=tmp_path / "private-library",
        disk_number=6,
        counter_key="physicaldrive6",
        media_type="SSD",
        bus_type="NVMe",
        friendly_name="Synthetic SSD",
        mount_path=tmp_path,
        expected_file_count=100_000,
        expected_bytes=10_485_760_000,
    )
    report = target.sanitized(subject.path_fingerprint)
    assert str(tmp_path) not in json.dumps(report)
    assert report["expectedFileCount"] == 100_000


@pytest.mark.unit
def test_parser_exposes_independent_watcher_timing() -> None:
    args = subject.build_parser().parse_args(["run"])
    assert args.watcher_timeout_seconds == 600
    assert args.watcher_poll_seconds == 0.5


@pytest.mark.unit
def test_media_roots_file_is_private_absolute_and_non_overlapping(
    tmp_path: Path,
) -> None:
    first = tmp_path / "disk-a" / "library"
    second = tmp_path / "disk-b" / "library"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    roots_file = tmp_path / "roots.local.txt"
    roots_file.write_text(f"# private roots\n{first}\n\n{second}\n", encoding="utf-8")

    assert subject.load_media_roots(roots_file) == [
        first.resolve(),
        second.resolve(),
    ]

    roots_file.write_text(f"{first}\n{first / 'nested'}\n", encoding="utf-8")
    (first / "nested").mkdir()
    with pytest.raises(RuntimeError, match="overlap or nest"):
        subject.load_media_roots(roots_file)


@pytest.mark.unit
def test_media_targets_deduplicate_physical_counters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots = [tmp_path / name for name in ("one", "two", "three")]
    for root in roots:
        root.mkdir()
    rows = iter(
        [
            {
                "diskNumber": 1,
                "counterKey": "physicaldrive1",
                "mediaType": "HDD",
                "busType": "SATA",
                "friendlyName": "one",
                "mountPath": str(tmp_path),
            },
            {
                "diskNumber": 1,
                "counterKey": "physicaldrive1",
                "mediaType": "HDD",
                "busType": "SATA",
                "friendlyName": "one",
                "mountPath": str(tmp_path),
            },
            {
                "diskNumber": 2,
                "counterKey": "physicaldrive2",
                "mediaType": "HDD",
                "busType": "SATA",
                "friendlyName": "two",
                "mountPath": str(tmp_path),
            },
        ]
    )
    monkeypatch.setattr(storage, "target_disk", lambda *_args: next(rows))

    targets = subject.media_storage_targets(roots, [], allow_non_hdd=False)

    assert subject.distinct_counter_keys(targets) == [
        "physicaldrive1",
        "physicaldrive2",
    ]


@pytest.mark.unit
def test_media_initial_acceptance_requires_cross_disk_serial_hashing() -> None:
    phase = {
        "sharedFilesTotal": 90,
        "maxActiveHashCount": 3,
        "maxPerDiskActiveCount": 1,
        "progress": {
            "scannedCount": 100,
            "plannedHashCount": 100,
            "hashedCount": 100,
            "failedHashCount": 0,
            "statFailedCount": 0,
            "skippedFailedCount": 0,
            "skippedIntakeCount": 0,
            "diskCount": 3,
        },
        "physicalDiskIoDeltas": {
            f"physicaldrive{index}": {"read_count": 1} for index in range(3)
        },
        "storage": {
            "rowCounts": {
                "activeShareSources": 100,
                "invalidActiveShareIntegrity": 0,
                "scanFailures": 0,
                "downloadJobs": 0,
            }
        },
    }

    assert subject.media_initial_acceptance(phase, expected_disk_count=3)["ok"]
    del phase["storage"]["rowCounts"]["downloadJobs"]
    assert not subject.media_initial_acceptance(phase, expected_disk_count=3)["ok"]
    phase["storage"]["rowCounts"]["downloadJobs"] = 0
    phase["maxPerDiskActiveCount"] = 2
    assert not subject.media_initial_acceptance(phase, expected_disk_count=3)["ok"]


@pytest.mark.unit
def test_media_no_change_acceptance_requires_zero_payload_reads() -> None:
    initial = {
        "sharedFilesTotal": 90,
        "progress": {"scannedCount": 100},
    }
    phase = {
        "sharedFilesTotal": 90,
        "maxPerDiskActiveCount": 0,
        "progress": {
            "scannedCount": 100,
            "plannedHashCount": 0,
            "hashedCount": 0,
            "plannedReadBytes": 0,
            "completedReadBytes": 0,
            "reusedCount": 100,
            "diskCount": 0,
            "failedHashCount": 0,
            "statFailedCount": 0,
            "skippedFailedCount": 0,
            "skippedIntakeCount": 0,
        },
    }

    assert subject.media_no_change_acceptance(phase, initial=initial)["ok"]
    phase["progress"]["completedReadBytes"] = 1
    assert not subject.media_no_change_acceptance(phase, initial=initial)["ok"]


@pytest.mark.unit
def test_partial_media_inspector_accepts_duplicate_source_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = harness_paths(tmp_path)
    run = (
        paths.output_root
        / "profiles/emulebb-rust-shared-library-media-io/runs/20261003T000000Z-1"
    )
    profile = run / "profile"
    profile.mkdir(parents=True)
    database = profile / subject.rust_metadata.RUST_PROFILE_METADATA_FILE
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE known_files (
                size_bytes INTEGER, completed INTEGER,
                md4_hashset_acquired INTEGER, aich_hashset_acquired INTEGER,
                aich_root BLOB
            )
            """
        )
        connection.executemany(
            "INSERT INTO known_files VALUES (?, 1, 1, 1, ?)",
            [(10, bytes(20)), (20, bytes(20))],
        )
    (run / "initial.log").write_text(
        "timestamp ERROR probe: reached probe limit of 1048576 bytes\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        subject,
        "profile_storage_snapshot",
        lambda _profile: {
            "rowCounts": {
                "knownFiles": 2,
                "activeShareSources": 3,
                "invalidActiveShareIntegrity": 0,
                "scanFailures": 0,
                "downloadJobs": 0,
            }
        },
    )
    _, reports_root = subject.media_campaign_paths(paths)
    subject.write_json(
        reports_root / f"rust-shared-library-media-io-{run.name}.json",
        {
            "schema": subject.MEDIA_REPORT_SCHEMA,
            "runId": run.name,
            "status": "interrupted",
            "inProgressPhase": {
                "progress": {"hashedCount": 2},
                "physicalDiskIoDeltas": {"physicaldrive1": {"read_bytes": 30}},
            },
        },
    )

    result = subject.inspect_partial_media_run(paths, run.name)

    assert result["status"] == "healthyPartial"
    assert result["committedHashes"] == {"fileCount": 2, "totalBytes": 30}
    assert result["checks"]["activeSourcesCoverHashes"] is True
    assert result["logs"]["unexpectedErrorCount"] == 0
    assert result["retainedProgress"]["progress"]["hashedCount"] == 2
    assert result["limitations"] == {
        "cleanCompletion": False,
        "liveProgressCountersRetained": True,
        "perDiskIoDeltasRetained": True,
    }


@pytest.mark.unit
def test_dynamic_reload_checkpoints_running_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def response(*, running: bool, started: int, scanned: int) -> dict[str, object]:
        return {
            "hashingCount": int(running),
            "reloadProgress": {
                "running": running,
                "pending": False,
                "scannedCount": scanned,
                "startedAtMs": started,
                "activeHashCount": int(running),
                "disks": [{"activeCount": int(running)}],
            },
        }

    class FakeClient:
        def __init__(self) -> None:
            self.directories = [
                response(running=False, started=1, scanned=0),
                response(running=True, started=2, scanned=4),
                response(running=False, started=2, scanned=8),
            ]

        def request(self, _method: str, route: str, **_kwargs: object):
            if route == "/shared-directories":
                return self.directories.pop(0)
            return {"total": 8}

    class FakeProcess:
        returncode = None

        @staticmethod
        def poll():
            return None

    class FakeSampler:
        samples: list[dict[str, object]] = []

        @staticmethod
        def maybe_sample(*, force: bool = False) -> None:
            del force

        @staticmethod
        def summary(_start_index: int = 0) -> dict[str, object]:
            return {"sampleCount": 1}

    snapshots = iter(
        [
            {"physicaldrive1": {"read_count": 1}},
            {"physicaldrive1": {"read_count": 2}},
            {"physicaldrive1": {"read_count": 3}},
        ]
    )
    monkeypatch.setattr(subject, "disk_io_snapshots", lambda _keys: next(snapshots))
    checkpoints: list[dict[str, object]] = []

    phase = subject.run_dynamic_reload_phase(
        label="test",
        action=lambda: None,
        client=FakeClient(),
        process=FakeProcess(),
        sampler=FakeSampler(),
        counter_keys=["physicaldrive1"],
        timeout_seconds=1,
        poll_seconds=0.001,
        expected_scanned=8,
        checkpoint=checkpoints.append,
    )

    assert phase["progress"]["scannedCount"] == 8
    assert checkpoints[0]["status"] == "running"
    assert checkpoints[0]["progress"]["scannedCount"] == 4
    assert checkpoints[0]["physicalDiskIoDeltas"]["physicaldrive1"] == {"read_count": 1}


@pytest.mark.parametrize("fault", ["none", "missing-budget", "preparation-oom", "campaign-failure"])
def test_container_campaign_measures_preparation_and_requires_campaign_acceptance(tmp_path, monkeypatch, fault):
    from emule_test_harness import build_provenance

    output = tmp_path / "output"
    native = output / "native"
    (native / "tmp").mkdir(parents=True)
    archive = output / "candidate.tar.zst"
    archive.write_bytes(b"synthetic archive")
    source = tmp_path / "source"
    source.mkdir()
    args = SimpleNamespace(native_root=native, report_root=output / "reports", archive=archive,
                           rust_repo=source, source_sha="a" * 40, version="0.1.0-beta.2")
    monkeypatch.setattr(subject.sys, "platform", "linux")
    monkeypatch.setattr(subject, "get_workspace_output_root", lambda: output)
    monkeypatch.setattr(subject, "get_required_emule_workspace_root", lambda: tmp_path / "workspace")
    monkeypatch.setattr(build_provenance, "require_clean_git_source", lambda *a, **k: SimpleNamespace(revision="a" * 40))
    root, membership = cgroup_files(tmp_path)
    sample = cgroup_budget.sample_budget
    monkeypatch.setattr(cgroup_budget, "sample_budget", lambda: None if fault == "missing-budget" else sample(root=root, membership=membership))
    stages = []
    def verify(*arguments):
        stages.append("verify")
        assert arguments[1:] == ("a" * 40, "0.1.0-beta.2", "x86_64-unknown-linux-gnu")
        return {"sha256": "b" * 64}
    def extract(_stream, destination):
        stages.append("extract")
        executable = destination / "emulebb-rust/emulebb-rust"
        executable.parent.mkdir()
        executable.write_bytes(b"ELF fixture")
    package = SimpleNamespace(_verify_package_manifest=verify, _extract_portable_stream=extract)
    monkeypatch.setattr(subject, "load_script_module", lambda *a: package)
    class Process:
        stdout = None
        returncode = 0
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def communicate(self): return b"", b""
    monkeypatch.setattr(subject.subprocess, "Popen", lambda *a, **k: Process())
    def prepare(paths, *, allow_non_ssd):
        stages.append("prepare")
        assert allow_non_ssd and paths.staged_executable.is_file()
        assert paths.scenario_root.is_relative_to(native)
        if fault == "preparation-oom":
            (root / "memory.events").write_text("oom 1\noom_kill 1\noom_group_kill 0\n")
        return {"status": "prepared"}
    def campaign(paths, options):
        stages.append("campaign")
        assert options.command == "run" and options.allow_non_ssd and options.watcher_replay_from is None
        ok = fault != "campaign-failure"
        return paths.reports_root / "full.json", {"status": "passed" if ok else "failed", "acceptance": {"ok": ok}}
    controller = SimpleNamespace(memory_info=lambda: SimpleNamespace(rss=35_000_000))
    monkeypatch.setattr(subject, "_load_psutil", lambda: SimpleNamespace(Process=lambda _pid: controller))
    monkeypatch.setattr(subject, "prepare_fixture", prepare)
    monkeypatch.setattr(subject, "run_campaign", campaign)
    if fault == "missing-budget":
        with pytest.raises(RuntimeError, match="kernel limits"):
            subject.run_container_campaign(args)
        assert stages == []
    else:
        result = subject.run_container_campaign(args)
        assert result["status"] == ("passed" if fault == "none" else "failed")
        assert stages == ["verify", "extract", "prepare", "campaign"]
    retained = json.loads((args.report_root / "container-result.json").read_text())
    assert retained["status"] == ("passed" if fault == "none" else "failed")
    assert retained["acceptance"]["ok"] is (fault == "none")


@pytest.mark.parametrize("io_available", [True, False])
def test_process_sampler_preserves_rss_when_optional_metrics_are_unavailable(monkeypatch, io_available):
    class Process:
        def memory_info(self):
            return SimpleNamespace(rss=256_000_000, vms=900_000_000, peak_wset=None, private=None)
        def cpu_times(self): return SimpleNamespace(user=3.0, system=1.5)
        def io_counters(self):
            if not io_available: raise PermissionError("restricted process I/O")
            return SimpleNamespace(read_count=1, write_count=2, read_bytes=3, write_bytes=4)
        def num_handles(self): return 7
    controller = SimpleNamespace(memory_info=lambda: SimpleNamespace(rss=65_000_000))
    monkeypatch.setattr(subject, "_load_psutil", lambda: SimpleNamespace(
        Process=lambda pid: controller if pid == subject.os.getpid() else Process()))
    sampler = subject.ProcessSampler(SimpleNamespace(pid=subject.os.getpid() + 1), 1)
    sampler.maybe_sample(force=True)
    result = sampler.summary()
    assert result["sampleCount"] == 1
    assert result["peakWorkingSetBytes"] == 256_000_000
    assert result["peakControllerWorkingSetBytes"] == 65_000_000
    assert result["lifetimeCpuSeconds"] == 4.5
    assert result["lifetimePeakWorkingSetBytes"] is None
    assert result["peakPrivateBytes"] is None  # vms must never be labelled private.
    assert result["readBytesDelta"] == (0 if io_available else None)
    assert result["metricErrors"] == ({} if io_available else {"io": "PermissionError"})
