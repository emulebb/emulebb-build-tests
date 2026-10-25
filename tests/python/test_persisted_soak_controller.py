from __future__ import annotations

import json
import os
from pathlib import Path
from types import MappingProxyType

import pytest

from emule_test_harness import persisted_soak_controller as controller
from emule_test_harness import soak_storage
from emule_test_harness.live_wire_inputs import LiveWireInputs
from emule_test_harness.windows_processes import WindowsProcessInfo


def make_paths(tmp_path: Path) -> controller.ControlPaths:
    return controller.build_control_paths(tmp_path / "output")


def storage_policy(*, max_total_bytes: int = 1_000) -> soak_storage.SoakStoragePolicy:
    return soak_storage.SoakStoragePolicy(
        max_total_bytes=max_total_bytes,
        max_age_seconds=3_600,
        minimum_free_bytes=1,
        bundle_interval_seconds=900,
        streams=MappingProxyType(
            {
                "controller_output": soak_storage.ArtifactStreamPolicy(1, 1),
                "daemon_output": soak_storage.ArtifactStreamPolicy(1, 1),
            }
        ),
    )


def live_inputs(
    tmp_path: Path,
    *,
    policy: soak_storage.SoakStoragePolicy | None,
) -> LiveWireInputs:
    return LiveWireInputs(
        path=tmp_path / "inputs.json",
        generic_open_terms=("linux",),
        document_terms=("manual",),
        radarr_movie_terms=("movie",),
        sonarr_series_terms=("series",),
        video_roots=(),
        bootstrap_transfer_hashes=(),
        direct_bootstrap_transfers=(),
        soak_storage=policy,
    )


def test_control_paths_must_stay_under_output_root(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="must stay below"):
        controller.build_control_paths(tmp_path / "output", tmp_path / "elsewhere")


def test_persisted_storage_policy_is_mandatory(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="require soak_storage"):
        controller.required_storage_policy(live_inputs(tmp_path, policy=None))


def test_campaign_storage_preflight_is_read_only_and_protects_latest(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    campaigns = controller.campaign_storage_root(output_root)
    old_file = campaigns / "20261023T120000Z" / "report" / "old.json"
    latest_file = campaigns / "20261024T120000Z" / "report" / "latest.json"
    old_file.parent.mkdir(parents=True)
    latest_file.parent.mkdir(parents=True)
    old_file.write_bytes(b"o" * 60)
    latest_file.write_bytes(b"n" * 60)
    os.utime(old_file, ns=(100, 100))
    os.utime(latest_file, ns=(200, 200))

    summary = controller.preflight_campaign_storage(
        live_inputs(tmp_path, policy=storage_policy(max_total_bytes=70)),
        output_root,
        protected_campaigns=(latest_file.parents[1],),
    )

    assert summary["plan"]["deletionCount"] == 1
    assert summary["plan"]["deletionBytes"] == 60
    assert summary["plan"]["protectedFileCount"] == 1
    assert summary["plan"]["feasible"] is True
    assert old_file.is_file()
    assert latest_file.is_file()


def test_campaign_storage_enforcement_deletes_closed_and_preserves_latest(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    campaigns = controller.campaign_storage_root(output_root)
    old_file = campaigns / "20261023T120000Z" / "report" / "old.json"
    latest_campaign = campaigns / "20261024T120000Z"
    latest_file = latest_campaign / "report" / "latest.json"
    old_file.parent.mkdir(parents=True)
    latest_file.parent.mkdir(parents=True)
    old_file.write_bytes(b"o" * 60)
    latest_file.write_bytes(b"n" * 60)
    os.utime(old_file, ns=(100, 100))
    os.utime(latest_file, ns=(200, 200))
    inputs = live_inputs(tmp_path, policy=storage_policy(max_total_bytes=70))

    summary = controller.enforce_campaign_storage(
        inputs,
        output_root,
        protected_campaigns=(latest_campaign,),
    )

    assert summary["deletedCount"] == 1
    assert summary["deletedBytes"] == 60
    assert summary["verification"]["deletionCount"] == 0
    assert summary["withinLimits"] is True
    assert not old_file.exists()
    assert latest_file.read_bytes() == b"n" * 60


def test_latest_campaign_path_rejects_manifest_escape(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    controller.write_json_atomic(
        paths.last_run_manifest,
        {"campaignDir": str(tmp_path / "outside")},
    )

    with pytest.raises(RuntimeError, match="escaped"):
        controller.latest_campaign_path(
            paths,
            controller.campaign_storage_root(tmp_path / "output"),
        )


def preflight_payload(tmp_path: Path) -> dict[str, object]:
    return {
        "inputs": str(tmp_path / "inputs.json"),
        "profiles": {
            "mfc": str(tmp_path / "EMULE_BIN"),
            "rust": str(tmp_path / "EMULE_RUST_PROFILE_PERSISTED"),
        },
        "executables": {
            "mfc": str(tmp_path / "bin" / "emule.exe"),
            "rust": str(tmp_path / "bin" / "emulebb-rust-diagnostics.exe"),
        },
        "control": {
            "bindAddress": "127.0.0.1",
            "rustBaseUrl": "http://127.0.0.1:4731/api/v1",
            "mfcBaseUrl": "http://127.0.0.1:4732/api/v1",
        },
        "vpn": {
            "topology": "full-tunnel",
            "adapterUp": True,
            "routesThroughHideMe": True,
            "guardMode": "block",
            "guardConfig": str(tmp_path / "vpn.json"),
        },
    }


def test_build_launch_command_is_until_stopped_dual_diagnostics(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    config = controller.SessionConfig(
        inputs=tmp_path / "inputs.json",
        vpn_guard_config=tmp_path / "vpn.json",
    )

    command = controller.build_launch_command(
        config,
        paths,
        campaign_id="20261025T120000Z",
    )

    assert command[1].endswith("scripts\\launch-soak.py")
    assert command[command.index("--vpn-topology") + 1] == "full-tunnel"
    assert command[command.index("--lan-bind-addr") + 1] == "127.0.0.1"
    assert command[command.index("--duration-seconds") + 1] == "0"
    assert command[command.index("--campaign-id") + 1] == "20261025T120000Z"
    assert command[command.index("--stop-file") + 1] == str(paths.stop_file)
    assert "--vpn-guard-scenario" in command
    assert "success" in command
    assert "--reuse-rust-shared-profile" in command
    assert "--reuse-kad-bootstrap" in command
    assert "--no-mfc" not in command
    assert "--rust-regular" not in command
    assert "--cpu-profile" not in command


def test_bounded_process_command_preserves_policy_paths_and_target(tmp_path: Path) -> None:
    command = controller.build_bounded_process_command(
        ["python", "target.py", "--flag"],
        stdout_path=tmp_path / "stdout.log",
        stderr_path=tmp_path / "stderr.log",
        policy=soak_storage.ArtifactStreamPolicy(
            max_segment_bytes=128,
            retained_segments=3,
        ),
        stop_files=(tmp_path / "stop", tmp_path / "watch.stop"),
    )

    assert Path(command[1]).name == "run-bounded-process.py"
    assert command[command.index("--max-segment-bytes") + 1] == "128"
    assert command[command.index("--retained-segments") + 1] == "3"
    assert command.count("--stop-file") == 2
    assert command[-3:] == ["python", "target.py", "--flag"]


def test_exact_process_row_rejects_pid_reuse() -> None:
    rows = [
        WindowsProcessInfo(
            pid=123,
            parent_pid=1,
            name="python.exe",
            command_line="python launch-soak.py",
            creation_date="new",
        )
    ]

    assert controller.exact_process_row({"pid": 123, "creationDate": "old"}, rows) is None
    assert controller.exact_process_row({"pid": 123, "creationDate": "new"}, rows) == rows[0]
    assert controller.exact_process_row(None, rows) is None


def test_start_session_records_launcher_and_watcher_identities(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root = tmp_path / "output"
    output_root.mkdir()
    config = controller.SessionConfig(
        inputs=tmp_path / "inputs.json",
        vpn_guard_config=tmp_path / "vpn.json",
    )
    loaded_inputs = live_inputs(tmp_path, policy=storage_policy())
    input_loads: list[Path] = []
    observed_inputs: list[LiveWireInputs] = []
    spawned: list[list[str]] = []

    class FakeProcess:
        def __init__(self, pid: int) -> None:
            self.pid = pid
            self.terminated = False

        def poll(self):
            return None

        def terminate(self) -> None:
            self.terminated = True

    def fake_spawn(command: list[str], **_kwargs) -> FakeProcess:
        spawned.append(command)
        return FakeProcess(100 + len(spawned))

    def fake_identity(pid: int, *, markers: tuple[str, ...], timeout_seconds: float = 10.0):
        del timeout_seconds
        return WindowsProcessInfo(
            pid=pid,
            parent_pid=1,
            name="python.exe",
            command_line=" ".join(markers),
            creation_date=f"created-{pid}",
        )

    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(
        controller,
        "load_live_wire_inputs",
        lambda path: input_loads.append(path) or loaded_inputs,
    )

    def fake_preflight(_config, _root, *, inputs, **_kwargs):
        observed_inputs.append(inputs)
        return preflight_payload(tmp_path)

    def fake_enforcement(inputs, *_args, **_kwargs):
        observed_inputs.append(inputs)
        return {"withinLimits": True}

    monkeypatch.setattr(
        controller,
        "preflight_session",
        fake_preflight,
    )
    monkeypatch.setattr(
        controller,
        "enforce_campaign_storage",
        fake_enforcement,
    )
    monkeypatch.setattr(
        controller.soak_run_layout,
        "utc_campaign_id",
        lambda: "20261025T120000Z",
    )
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [])
    monkeypatch.setattr(controller, "spawn_detached", fake_spawn)
    monkeypatch.setattr(controller, "wait_process_identity", fake_identity)

    result = controller.start_session(config, paths, watch_interval_seconds=30.0)

    assert result["schema"] == controller.MANIFEST_SCHEMA
    assert result["launcher"]["pid"] == 101
    assert result["launcher"]["creationDate"] == "created-101"
    assert result["watcher"]["pid"] == 102
    assert result["watcher"]["creationDate"] == "created-102"
    assert result["campaignId"] == "20261025T120000Z"
    assert result["storageEnforcement"]["withinLimits"] is True
    assert input_loads == [config.inputs.resolve()]
    assert observed_inputs == [loaded_inputs, loaded_inputs]
    assert len(spawned) == 2
    assert Path(spawned[0][1]).name == "run-bounded-process.py"
    assert any(Path(value).name == "launch-soak.py" for value in spawned[0])
    assert Path(spawned[1][1]).name == "run-bounded-process.py"
    assert any(Path(value).name == "persisted-soak-control.py" for value in spawned[1])
    assert result["launcher"]["commandFingerprint"] == controller.command_fingerprint(spawned[0])
    assert result["watcher"]["commandFingerprint"] == controller.command_fingerprint(spawned[1])
    assert result["logs"]["root"] == str(
        output_root / "soak" / "campaigns" / "20261025T120000Z" / "controller-output"
    )
    assert result["logs"]["maxSegmentBytes"] == 1
    assert result["logs"]["retainedSegments"] == 1
    assert json.loads(paths.manifest.read_text(encoding="utf-8"))["watcher"]["pid"] == 102


def test_start_session_enforces_storage_before_control_mutation_or_spawn(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root = tmp_path / "output"
    config = controller.SessionConfig(
        inputs=tmp_path / "inputs.json",
        vpn_guard_config=tmp_path / "vpn.json",
    )
    spawned = False

    def reject_storage(*_args, **_kwargs):
        raise RuntimeError("reserve verification failed")

    def reject_spawn(*_args, **_kwargs):
        nonlocal spawned
        spawned = True
        raise AssertionError("spawn must not be reached")

    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(
        controller,
        "load_live_wire_inputs",
        lambda _path: live_inputs(tmp_path, policy=storage_policy()),
    )
    monkeypatch.setattr(
        controller,
        "preflight_session",
        lambda _config, _root, **_kwargs: preflight_payload(tmp_path),
    )
    monkeypatch.setattr(controller, "enforce_campaign_storage", reject_storage)
    monkeypatch.setattr(controller, "spawn_detached", reject_spawn)
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [])
    monkeypatch.setattr(
        controller.soak_run_layout,
        "utc_campaign_id",
        lambda: "20261025T120000Z",
    )

    with pytest.raises(RuntimeError, match="reserve verification failed"):
        controller.start_session(config, paths)

    assert spawned is False
    assert not paths.control_dir.exists()


def test_start_session_rejects_invalid_watch_budget_before_preflight(tmp_path: Path, monkeypatch) -> None:
    paths = make_paths(tmp_path)
    config = controller.SessionConfig(inputs=tmp_path / "inputs.json", vpn_guard_config=tmp_path / "vpn.json")
    preflight_called = False

    def fake_preflight(_config, _output_root):
        nonlocal preflight_called
        preflight_called = True

    monkeypatch.setattr(controller, "preflight_session", fake_preflight)

    with pytest.raises(ValueError, match="watch_max_bytes"):
        controller.start_session(config, paths, watch_max_bytes=0)

    assert preflight_called is False


def test_session_status_reports_exact_dual_process_tree(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    preflight = preflight_payload(tmp_path)
    controller.write_json_atomic(
        paths.manifest,
        {
            "schema": controller.MANIFEST_SCHEMA,
            "state": "running",
            "launcher": {"pid": 10, "creationDate": "launcher"},
            "watcher": {"pid": 20, "creationDate": "watcher"},
            "preflight": preflight,
        },
    )
    controller.write_json_atomic(paths.last_run_manifest, {"campaignId": "20261024T120000Z", "status": "starting"})
    processes = [
        WindowsProcessInfo(10, 1, "python.exe", "python run-bounded-process.py -- launch-soak.py", "launcher"),
        WindowsProcessInfo(13, 10, "python.exe", "python launch-soak.py", "launch-target"),
        WindowsProcessInfo(11, 13, "emulebb-rust-diagnostics.exe", "rust", "rust"),
        WindowsProcessInfo(12, 13, "emule.exe", "mfc", "mfc"),
        WindowsProcessInfo(
            20,
            1,
            "python.exe",
            "python run-bounded-process.py -- persisted-soak-control.py watch",
            "watcher",
        ),
    ]
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: processes)
    monkeypatch.setattr(controller, "rest_health", lambda _url, _key: {"ok": True})
    monkeypatch.setattr(controller, "full_tunnel_health", lambda: {"ok": True})

    result = controller.session_status(paths)

    assert result["ok"] is True
    assert result["launcher"]["alive"] is True
    assert result["watcher"]["alive"] is True
    assert result["clients"]["rustCount"] == 1
    assert result["clients"]["mfcCount"] == 1
    assert [row["role"] for row in result["clients"]["processes"]] == ["rust", "mfc"]
    assert all("commandLine" not in row for row in result["clients"]["processes"])
    assert result["findings"] == []


def test_stop_session_requests_graceful_teardown_without_force(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    controller.write_json_atomic(
        paths.manifest,
        {
            "schema": controller.MANIFEST_SCHEMA,
            "state": "running",
            "launcher": {"pid": 10, "creationDate": "launcher"},
            "watcher": {"pid": 20, "creationDate": "watcher"},
        },
    )
    waited: list[dict[str, object]] = []

    def fake_wait(identity: dict[str, object], _timeout: float) -> bool:
        waited.append(identity)
        return True

    monkeypatch.setattr(controller, "wait_exact_exit", fake_wait)
    monkeypatch.setattr(
        controller,
        "session_status",
        lambda *_args, **_kwargs: {"schema": controller.STATUS_SCHEMA, "ok": False},
    )

    result = controller.stop_session(paths, graceful_timeout_seconds=1.0)

    assert paths.stop_file.is_file()
    assert paths.watch_stop_file.is_file()
    assert [identity["pid"] for identity in waited] == [10, 20]
    assert result["launcherGraceful"] is True
    assert result["launcherForce"]["forced"] is False
    assert result["watcherGraceful"] is True
    assert json.loads(paths.manifest.read_text(encoding="utf-8"))["state"] == "stopped"


def test_stop_session_without_manifest_does_not_create_control_files(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)

    result = controller.stop_session(paths)

    assert result["noSession"] is True
    assert not paths.stop_file.exists()
    assert not paths.watch_stop_file.exists()


def test_append_bounded_jsonl_rotates_old_segments(tmp_path: Path) -> None:
    path = tmp_path / "watch.jsonl"

    controller.append_bounded_jsonl(path, {"sample": 1, "padding": "x" * 80}, max_bytes=100, segments=2)
    controller.append_bounded_jsonl(path, {"sample": 2, "padding": "x" * 80}, max_bytes=100, segments=2)
    controller.append_bounded_jsonl(path, {"sample": 3, "padding": "x" * 80}, max_bytes=100, segments=2)

    assert json.loads(path.read_text(encoding="utf-8"))["sample"] == 3
    assert json.loads(controller.rotated_path(path, 1).read_text(encoding="utf-8"))["sample"] == 2
    assert json.loads(controller.rotated_path(path, 2).read_text(encoding="utf-8"))["sample"] == 1
    assert not controller.rotated_path(path, 3).exists()


def test_watch_session_persists_one_bounded_health_sample(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    status = {
        "timestampUtc": "2026-10-24T12:00:00+00:00",
        "ok": True,
        "findings": [],
        "launcher": {"alive": True},
        "clients": {"rustCount": 1, "mfcCount": 1},
        "rest": {"rust": {"ok": True}, "mfc": {"ok": True}},
        "vpn": {"ok": True},
        "lastRun": {"status": "starting"},
    }
    monkeypatch.setattr(controller, "session_status", lambda _paths: status)

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
        max_samples=1,
    )

    assert result["samples"] == 1
    assert json.loads(paths.watch_heartbeat.read_text(encoding="utf-8"))["ok"] is True
    assert json.loads(paths.watch_jsonl.read_text(encoding="utf-8"))["rustProcessCount"] == 1
