"""Verify heap diagnostics preserve ownership and cannot qualify workload."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import rust_library_heap_profile as subject
from emule_test_harness import rust_shared_library_io as library
from emule_test_harness import rust_client


def source_receipt(tmp_path):
    output = tmp_path / "output"
    run_id = "a" * 32
    root = output / "reports/linux-containers/library" / run_id
    (root / "campaign").mkdir(parents=True)
    receipt = root / "report.json"
    value = {"schema": "emulebb.rust-container-library-io.v1", "runId": run_id,
        "status": "failed", "container": {"absent": True},
        "volume": {"retained": True, "name": f"emulebb-library-{run_id}",
                   "labels": {"emulebb.scope": "shared-library-io", "emulebb.run": run_id}}}
    receipt.write_text(json.dumps(value), encoding="utf-8")
    report = root / "campaign/rust-shared-library-io-original.json"
    report.write_text(json.dumps({"schema": library.REPORT_SCHEMA, "runId": "original",
        "phases": [{"acceptance": {"ok": True}}]}), encoding="utf-8")
    return output, receipt, value, report


@pytest.mark.parametrize("fault", ["none", "running", "attached", "labels", "no-proof", "multiple"])
def test_replay_admits_only_inactive_owned_initial_proof(tmp_path, fault):
    output, receipt, value, report = source_receipt(tmp_path)
    if fault == "running": value["status"] = "running"
    if fault == "attached": value["container"]["absent"] = False
    if fault == "labels": value["volume"]["labels"]["emulebb.run"] = "b" * 32
    if fault == "no-proof": report.write_text(json.dumps({"schema": library.REPORT_SCHEMA, "phases": []}))
    if fault == "multiple": report.with_name("rust-shared-library-io-extra.json").write_text("{}")
    receipt.write_text(json.dumps(value), encoding="utf-8")
    before = receipt.read_bytes()
    if fault == "none":
        source, admitted, native = subject.replay_inputs(output, receipt)
        assert source == value and admitted == report and native == receipt.parent / "native"
    else:
        with pytest.raises(RuntimeError): subject.replay_inputs(output, receipt)
    assert receipt.read_bytes() == before


def test_replay_rejects_receipt_outside_owned_reports(tmp_path):
    with pytest.raises(RuntimeError, match="managed"):
        subject.replay_inputs(tmp_path, tmp_path / "unowned.json")


@pytest.mark.parametrize("code", [0, 1])
def test_trace_interpretation_retains_evidence_and_propagates_failure(tmp_path, monkeypatch, code):
    traces, reports = tmp_path / "native", tmp_path / "reports"
    traces.mkdir()
    reports.mkdir()
    trace = traces / "daemon.gz"
    trace.write_bytes(b"synthetic trace")
    (traces / "empty.gz").touch()
    def interpret(command, **options):
        assert command == ["heaptrack_print", "--file", str(trace)]
        options["stdout"].write("synthetic allocation stack\n")
        return SimpleNamespace(returncode=code)
    monkeypatch.setattr(subject.subprocess, "run", interpret)
    if code:
        with pytest.raises(RuntimeError, match="interpretation failed"):
            subject.collect_traces(traces, reports)
    else:
        result = subject.collect_traces(traces, reports)
        assert len(result) == 1 and result[0]["bytes"] == trace.stat().st_size
    assert (reports / "daemon.gz.analysis.txt").is_file()


def test_shared_launcher_keeps_product_argv_after_profiler_prefix(tmp_path, monkeypatch):
    captured = []
    monkeypatch.setattr(rust_client.subprocess, "Popen", lambda command, **kwargs: captured.append(command))
    executable, profile = tmp_path / "daemon", tmp_path / "profile"
    rust_client.spawn_rust_daemon(executable, profile, output_handle=None,
        command_prefix=("heaptrack", "-o", "trace"))
    assert captured == [["heaptrack", "-o", "trace", str(executable), "--profile", str(profile)]]


def test_profile_sampler_observes_daemon_child_not_wrapper(tmp_path, monkeypatch):
    executable = tmp_path / "daemon"
    executable.touch()
    process = SimpleNamespace(pid=11)
    calls = []
    monkeypatch.setattr(library.rust_client, "spawn_rust_daemon", lambda *a, **k: process)
    monkeypatch.setattr(library, "wait_for_rest", lambda *a: None)
    children = [SimpleNamespace(pid=22, exe=lambda: str(executable)),
                SimpleNamespace(pid=33, exe=lambda: str(tmp_path / "interpreter"))]
    monkeypatch.setattr(library, "_load_psutil", lambda: SimpleNamespace(
        Process=lambda _pid: SimpleNamespace(children=lambda **k: children)))
    def sampler(wrapper, interval, *, observed_pid):
        calls.append((wrapper.pid, observed_pid))
        return SimpleNamespace(maybe_sample=lambda **k: None)
    monkeypatch.setattr(library, "ProcessSampler", sampler)
    returned, _, _ = library.start_configured_daemon(SimpleNamespace(staged_executable=executable),
        tmp_path / "profile", tmp_path / "initial.log", rest_address="127.0.0.1", rest_port=1,
        heap_profile_dir=tmp_path / "trace")
    assert returned is process and calls == [(11, 22)]


@pytest.mark.parametrize("correct_budget", [True, False])
def test_heap_run_reuses_copy_replay_and_keeps_acceptance_false(tmp_path, monkeypatch, correct_budget):
    output, receipt, source, original_report = source_receipt(tmp_path)
    source.update(sourceRevisions={"rust": "d" * 40}, archiveSha256="e" * 64)
    receipt.write_text(json.dumps(source))
    before = receipt.read_bytes()
    args = SimpleNamespace(report_root=output / "reports/linux-containers/library-heap" / ("b" * 32),
        source_receipt=receipt, source_sha="d" * 40, archive=output / "archive.tar.zst",
        version="synthetic", rust_repo=tmp_path / "rust")
    monkeypatch.setattr(subject.sys, "platform", "linux")
    monkeypatch.setattr(subject.shutil, "which", lambda _tool: "/usr/bin/tool")
    monkeypatch.setattr(library, "get_workspace_output_root", lambda: output)
    monkeypatch.setattr(library, "get_required_emule_workspace_root", lambda: tmp_path)
    monkeypatch.setattr(subject, "require_clean_git_source", lambda *a, **k: SimpleNamespace(revision=args.source_sha))
    monkeypatch.setattr(library, "load_script_module", lambda *a: SimpleNamespace(
        _verify_package_manifest=lambda *a: {"sha256": "e" * 64}))
    monkeypatch.setattr(library.rust_cgroup_budget, "sample_budget", lambda: {
        "memoryMaxBytes": (1024 if correct_budget else 512) * 1024 * 1024,
        "swapMaxBytes": 0, "cpuQuotaMicros": 100000, "cpuPeriodMicros": 100000})
    monkeypatch.setattr(library.rust_cgroup_budget, "finish_report", lambda result, before:
        result.update(kernelResourceBudget={"ok": True}))
    calls = []
    def extract(archive, destination):
        calls.append("extract")
        destination.mkdir(parents=True)
        return destination / "daemon"
    monkeypatch.setattr(library, "extract_container_archive", extract)
    def campaign(paths, options, **kwargs):
        calls.append("replay")
        assert options.watcher_replay_from == "original"
        assert kwargs["replay_report"] == original_report
        assert kwargs["stop_after_watcher_create"] is True
        assert paths.fixture_root == receipt.parent / "native/scenario/fixture/library"
        return args.report_root / "campaign/replay.json", {"status": "diagnosticComplete"}
    monkeypatch.setattr(library, "run_campaign", campaign)
    monkeypatch.setattr(subject, "collect_traces", lambda *a: [{"bytes": 100}])
    if correct_budget:
        result = subject.run(args)
        assert result["status"] == "diagnosticComplete"
        assert result["workloadQualified"] is False and result["acceptance"]["ok"] is False
        assert result["qualificationScope"]["containerLimitsEnforced"] is False
        assert calls == ["extract", "replay"]
    else:
        with pytest.raises(RuntimeError, match="diagnostic 1 GiB"):
            subject.run(args)
        assert calls == []
    assert receipt.read_bytes() == before
