from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
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

    assert summary["deletionCount"] == 1
    assert summary["deletionBytes"] == 60
    assert summary["protectedFileCount"] == 1
    assert summary["reservedBytes"] == 5
    assert summary["projectedTotalBytes"] == 65
    assert summary["reservation"] == {
        "totalBytes": 5,
        "streams": {
            "controller_output": {
                "instances": 4,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 4,
            },
            "daemon_output": {
                "instances": 1,
                "maxSegmentBytes": 1,
                "retainedSegments": 1,
                "capacityBytes": 1,
            },
        },
    }
    assert summary["feasible"] is True
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
    assert summary["planned"]["reservedBytes"] == 5
    assert summary["verification"]["reservedBytes"] == 5
    assert summary["verification"]["projectedTotalBytes"] == 65
    assert summary["reservation"]["totalBytes"] == 5
    assert summary["reservation"]["streams"]["controller_output"]["capacityBytes"] == 4
    assert summary["verification"]["deletionCount"] == 0
    assert summary["withinLimits"] is True
    assert not old_file.exists()
    assert latest_file.read_bytes() == b"n" * 60


def test_campaign_storage_preflight_rejects_unreservable_required_streams(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"

    with pytest.raises(RuntimeError, match="max_total_bytes"):
        controller.preflight_campaign_storage(
            live_inputs(tmp_path, policy=storage_policy(max_total_bytes=4)),
            output_root,
            protected_campaigns=(),
        )


def test_campaign_storage_preflight_reserves_minimum_free_space(
    tmp_path: Path,
    monkeypatch,
) -> None:
    output_root = tmp_path / "output"
    monkeypatch.setattr(
        soak_storage,
        "disk_space_snapshot",
        lambda root: soak_storage.DiskSpaceSnapshot(
            measured_path=root,
            total_bytes=100,
            used_bytes=95,
            free_bytes=5,
        ),
    )

    with pytest.raises(RuntimeError, match="minimum_free_bytes"):
        controller.preflight_campaign_storage(
            live_inputs(tmp_path, policy=storage_policy()),
            output_root,
            protected_campaigns=(),
        )


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
        "storage": {
            "feasible": True,
            "deletionCount": 0,
            "deletionBytes": 0,
            "protectedFileCount": 0,
        },
    }


def storage_context_manifest(
    tmp_path: Path,
    *,
    previous_campaign: Path | None = None,
) -> tuple[Path, dict[str, object]]:
    output_root = tmp_path / "output"
    root = controller.campaign_storage_root(output_root)
    active_campaign = root / "20261025T120000Z"
    policy = storage_policy()
    return output_root, {
        "campaignId": active_campaign.name,
        "storage": controller.session_storage_manifest(
            root=root,
            policy=policy,
            active_campaign=active_campaign,
            previous_campaign=previous_campaign,
            preflight_plan={"feasible": True},
            launch_enforcement={"withinLimits": True},
        ),
    }


def test_session_storage_context_round_trips_previous_campaign(tmp_path: Path) -> None:
    previous_campaign = (
        controller.campaign_storage_root(tmp_path / "output") / "20261024T120000Z"
    )
    output_root, manifest = storage_context_manifest(
        tmp_path,
        previous_campaign=previous_campaign,
    )

    context = controller.parse_session_storage_context(manifest, output_root)

    assert context.root == controller.campaign_storage_root(output_root)
    assert context.active_campaign.name == "20261025T120000Z"
    assert context.previous_campaign == previous_campaign
    assert context.policy_sha256 == soak_storage.storage_policy_sha256(context.policy)


def test_session_storage_context_rejects_policy_tampering(tmp_path: Path) -> None:
    output_root, manifest = storage_context_manifest(tmp_path)
    storage = manifest["storage"]
    assert isinstance(storage, dict)
    policy = storage["policy"]
    assert isinstance(policy, dict)
    policy["max_total_bytes"] = 2_000

    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        controller.parse_session_storage_context(manifest, output_root)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("root", "outside", "root mismatch"),
        ("activeCampaignDir", "outside", "escaped its storage root"),
        ("preflightPlan", [], "preflight plan is invalid"),
        ("launchEnforcement", [], "launch enforcement is invalid"),
    ],
)
def test_session_storage_context_rejects_invalid_authority(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    output_root, manifest = storage_context_manifest(tmp_path)
    storage = manifest["storage"]
    assert isinstance(storage, dict)
    storage[field] = str(tmp_path / value) if value == "outside" else value

    with pytest.raises(RuntimeError, match=message):
        controller.parse_session_storage_context(manifest, output_root)


def test_session_storage_context_rejects_missing_or_unknown_fields(tmp_path: Path) -> None:
    output_root, manifest = storage_context_manifest(tmp_path)
    storage = manifest["storage"]
    assert isinstance(storage, dict)
    del storage["launchEnforcement"]
    storage["unexpected"] = True

    with pytest.raises(RuntimeError, match=r"missing=launchEnforcement unknown=unexpected"):
        controller.parse_session_storage_context(manifest, output_root)


def test_session_storage_enforcement_protects_active_and_previous_campaigns(
    tmp_path: Path,
) -> None:
    root = controller.campaign_storage_root(tmp_path / "output")
    active_campaign = root / "20261025T120000Z"
    previous_campaign = root / "20261024T120000Z"
    old_campaign = root / "20261023T120000Z"
    active_file = active_campaign / "active.log"
    previous_file = previous_campaign / "previous.log"
    old_file = old_campaign / "old.log"
    for path, contents in (
        (active_file, b"active"),
        (previous_file, b"previous"),
        (old_file, b"old artifact"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
    policy = storage_policy(max_total_bytes=20)
    context = controller.SessionStorageContext(
        root=root,
        policy=policy,
        policy_sha256=soak_storage.storage_policy_sha256(policy),
        active_campaign=active_campaign,
        previous_campaign=previous_campaign,
    )

    result = controller.enforce_session_storage_context(context)

    assert result["ok"] is True
    assert result["enforcement"]["deletedCount"] == 1
    assert active_file.is_file()
    assert previous_file.is_file()
    assert not old_file.exists()


def test_session_storage_enforcement_reports_unprunable_active_growth(tmp_path: Path) -> None:
    root = controller.campaign_storage_root(tmp_path / "output")
    active_campaign = root / "20261025T120000Z"
    active_file = active_campaign / "active.log"
    active_file.parent.mkdir(parents=True)
    active_file.write_bytes(b"active")
    policy = storage_policy(max_total_bytes=5)
    context = controller.SessionStorageContext(
        root=root,
        policy=policy,
        policy_sha256=soak_storage.storage_policy_sha256(policy),
        active_campaign=active_campaign,
        previous_campaign=None,
    )

    result = controller.enforce_session_storage_context(context)

    assert result["ok"] is False
    assert result["errorType"] == "StoragePolicyUnsatisfied"
    assert result["error"] == "max_total_bytes"
    assert active_file.is_file()


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
    assert result["storage"]["launchEnforcement"]["withinLimits"] is True
    storage_context = controller.parse_session_storage_context(result, output_root)
    assert storage_context.active_campaign == (
        output_root / "soak" / "campaigns" / "20261025T120000Z"
    )
    assert storage_context.previous_campaign is None
    assert storage_context.policy == loaded_inputs.soak_storage
    assert input_loads == [config.inputs.resolve()]
    assert observed_inputs == [loaded_inputs, loaded_inputs]
    assert len(spawned) == 2
    assert Path(spawned[0][1]).name == "run-bounded-process.py"
    assert any(Path(value).name == "launch-soak.py" for value in spawned[0])
    assert Path(spawned[1][1]).name == "run-bounded-process.py"
    assert any(Path(value).name == "persisted-soak-control.py" for value in spawned[1])
    assert result["watchTargetCommand"][result["watchTargetCommand"].index("--launcher-pid") + 1] == "101"
    assert (
        result["watchTargetCommand"][
            result["watchTargetCommand"].index("--launcher-creation-date") + 1
        ]
        == "created-101"
    )
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


def test_session_status_reports_current_storage_failure_and_dead_watcher(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    campaign_id = "20261025T120000Z"
    output_root, manifest = storage_context_manifest(tmp_path)
    del output_root
    storage = manifest["storage"]
    assert isinstance(storage, dict)
    manifest.update(
        {
            "schema": controller.MANIFEST_SCHEMA,
            "state": "running",
            "startedUtc": datetime.now(UTC).isoformat(),
            "campaignId": campaign_id,
            "launcher": {"pid": 10, "creationDate": "launcher"},
            "watcher": {"pid": 20, "creationDate": "watcher"},
            "watchConfig": {
                "enabled": True,
                "intervalSeconds": 60.0,
                "heartbeatStaleSeconds": 180.0,
            },
        }
    )
    controller.write_json_atomic(
        paths.manifest,
        manifest,
    )
    controller.write_json_atomic(
        paths.watch_heartbeat,
        {
            "schema": controller.WATCH_SCHEMA,
            "campaignId": campaign_id,
            "timestampUtc": datetime.now(UTC).isoformat(),
            "storage": {
                "ok": False,
                "error": "minimum_free_bytes",
                "policySha256": storage["policySha256"],
                "activeCampaignDir": storage["activeCampaignDir"],
                "previousCampaignDir": storage["previousCampaignDir"],
            },
        },
    )
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [])

    result = controller.session_status(paths, check_rest=False, check_vpn=False)

    assert result["storage"]["error"] == "minimum_free_bytes"
    assert "watcher-not-running" in result["findings"]
    assert controller.STORAGE_FAILURE_FINDING in result["findings"]


def test_session_status_ignores_stale_watch_storage_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    controller.write_json_atomic(
        paths.manifest,
        {
            "schema": controller.MANIFEST_SCHEMA,
            "state": "running",
            "startedUtc": datetime.now(UTC).isoformat(),
            "campaignId": "20261025T120000Z",
            "launcher": {},
            "watcher": None,
            "watchConfig": {
                "enabled": True,
                "intervalSeconds": 60.0,
                "heartbeatStaleSeconds": 180.0,
            },
        },
    )
    controller.write_json_atomic(
        paths.watch_heartbeat,
        {
            "schema": controller.WATCH_SCHEMA,
            "campaignId": "20261024T120000Z",
            "timestampUtc": datetime.now(UTC).isoformat(),
            "storage": {"ok": False, "error": "stale"},
        },
    )
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [])

    result = controller.session_status(paths, check_rest=False, check_vpn=False)

    assert result["storage"] is None
    assert controller.STORAGE_FAILURE_FINDING not in result["findings"]
    assert result["watcher"]["heartbeatHealth"]["state"] == "pending"


@pytest.mark.parametrize(
    ("age_seconds", "policy_sha256", "expected_state"),
    [(10, "expected", "current"), (181, "expected", "stale"), (10, "tampered", "invalid")],
)
def test_watch_heartbeat_health_requires_fresh_manifest_authority(
    tmp_path: Path,
    age_seconds: int,
    policy_sha256: str,
    expected_state: str,
) -> None:
    now = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
    _output_root, manifest = storage_context_manifest(tmp_path)
    storage = manifest["storage"]
    assert isinstance(storage, dict)
    manifest.update(
        {
            "startedUtc": (now - timedelta(minutes=10)).isoformat(),
            "watchConfig": {
                "enabled": True,
                "intervalSeconds": 60.0,
                "heartbeatStaleSeconds": 180.0,
            },
        }
    )
    heartbeat = {
        "schema": controller.WATCH_SCHEMA,
        "campaignId": manifest["campaignId"],
        "timestampUtc": (now - timedelta(seconds=age_seconds)).isoformat(),
        "storage": {
            "ok": True,
            "policySha256": (
                storage["policySha256"] if policy_sha256 == "expected" else policy_sha256
            ),
            "activeCampaignDir": storage["activeCampaignDir"],
            "previousCampaignDir": storage["previousCampaignDir"],
        },
    }

    result = controller.watch_heartbeat_health(manifest, heartbeat, now=now)

    assert result["state"] == expected_state
    assert result["accepted"] is (expected_state == "current")


def test_watch_heartbeat_health_rejects_previous_campaign_pin_mismatch(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
    _output_root, manifest = storage_context_manifest(tmp_path)
    storage = manifest["storage"]
    assert isinstance(storage, dict)
    storage["previousCampaignDir"] = str(tmp_path / "expected-previous")
    manifest.update(
        {
            "startedUtc": (now - timedelta(minutes=10)).isoformat(),
            "watchConfig": {
                "enabled": True,
                "intervalSeconds": 60.0,
                "heartbeatStaleSeconds": 180.0,
            },
        }
    )
    heartbeat = {
        "schema": controller.WATCH_SCHEMA,
        "campaignId": manifest["campaignId"],
        "timestampUtc": now.isoformat(),
        "storage": {
            "ok": True,
            "policySha256": storage["policySha256"],
            "activeCampaignDir": storage["activeCampaignDir"],
            "previousCampaignDir": None,
        },
    }

    result = controller.watch_heartbeat_health(manifest, heartbeat, now=now)

    assert result == {"state": "invalid", "accepted": False, "reason": "previous-campaign"}


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


def watch_status_payload() -> dict[str, object]:
    return {
        "timestampUtc": "2026-10-24T12:00:00+00:00",
        "ok": True,
        "findings": [],
        "launcher": {"alive": True},
        "clients": {"rustCount": 1, "mfcCount": 1},
        "rest": {"rust": {"ok": True}, "mfc": {"ok": True}},
        "vpn": {"ok": True},
        "lastRun": {"status": "starting"},
    }


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_bytes": 0}, "max_bytes"),
        ({"segments": 0}, "segments"),
        ({"max_samples": -1}, "max_samples"),
    ],
)
def test_watch_session_rejects_invalid_limits_before_reading_manifest(
    tmp_path: Path,
    monkeypatch,
    kwargs: dict[str, int],
    message: str,
) -> None:
    paths = make_paths(tmp_path)
    manifest_read = False

    def fake_load(_path: Path) -> dict[str, object]:
        nonlocal manifest_read
        manifest_read = True
        return {}

    monkeypatch.setattr(controller, "load_json", fake_load)
    options = {"interval_seconds": 1.0, "max_bytes": 1024, "segments": 2, **kwargs}

    with pytest.raises(ValueError, match=message):
        controller.watch_session(paths, **options)

    assert manifest_read is False


def test_watch_session_persists_one_bounded_health_sample(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    status = watch_status_payload()
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: status)
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
        max_samples=1,
    )

    assert result["ok"] is True
    assert result["samples"] == 1
    assert json.loads(paths.watch_heartbeat.read_text(encoding="utf-8"))["ok"] is True
    sample = json.loads(paths.watch_jsonl.read_text(encoding="utf-8"))
    assert sample["rustProcessCount"] == 1
    assert sample["storage"]["policySha256"] == "abc"


def test_watch_session_fails_closed_on_storage_enforcement_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: watch_status_payload())
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {
            "ok": False,
            "policySha256": "abc",
            "errorType": "StoragePolicyUnsatisfied",
            "error": "minimum_free_bytes",
        },
    )
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
    )

    assert result["ok"] is False
    assert result["samples"] == 1
    assert result["latest"]["storage"]["error"] == "minimum_free_bytes"
    assert controller.STORAGE_FAILURE_FINDING in result["latest"]["findings"]
    assert result["latest"]["shutdown"]["launcherGraceful"] is True
    assert json.loads(paths.watch_heartbeat.read_text(encoding="utf-8"))["shutdown"] == {
        "launcherGraceful": True
    }
    assert stop_requests == [manifest]


@pytest.mark.parametrize(
    ("failure_source", "phase"),
    [("enforcement", "enforcement"), ("status", "watchStatus")],
)
def test_watch_session_fails_closed_on_raised_watch_loop_faults(
    tmp_path: Path,
    monkeypatch,
    failure_source: str,
    phase: str,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    if failure_source == "enforcement":
        monkeypatch.setattr(
            controller,
            "enforce_session_storage_context",
            lambda _context: (_ for _ in ()).throw(OSError("inventory failed")),
        )
        monkeypatch.setattr(controller, "session_status", lambda _paths: watch_status_payload())
    else:
        monkeypatch.setattr(
            controller,
            "enforce_session_storage_context",
            lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
        )
        monkeypatch.setattr(
            controller,
            "session_status",
            lambda _paths: (_ for _ in ()).throw(OSError("WMI failed")),
        )
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
    )

    assert result["ok"] is False
    assert result["latest"]["storage"]["phase"] == phase
    assert result["latest"]["shutdown"]["launcherGraceful"] is True
    assert stop_requests == [manifest]


def test_watch_session_fails_closed_on_invalid_storage_context(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root = tmp_path / "output"
    manifest = {
        "schema": controller.MANIFEST_SCHEMA,
        "state": "running",
        "launcher": {"pid": 10, "creationDate": "launcher"},
    }
    controller.write_json_atomic(paths.manifest, manifest)
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: watch_status_payload())
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
    )

    assert result["ok"] is False
    assert result["latest"]["storage"]["phase"] == "context"
    assert "missing storage context" in result["latest"]["storage"]["error"]
    assert stop_requests == [manifest]


def test_watch_session_fails_closed_on_watch_evidence_write_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: watch_status_payload())
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
    )
    monkeypatch.setattr(
        controller,
        "persist_watch_sample",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
    )

    assert result["ok"] is False
    assert result["latest"]["storage"]["phase"] == "watchEvidence"
    assert result["latest"]["storage"]["error"] == "disk full"
    assert json.loads(paths.watch_heartbeat.read_text(encoding="utf-8"))["ok"] is False
    assert stop_requests == [manifest]


def test_watch_session_fails_closed_when_emit_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    output_root, manifest = storage_context_manifest(tmp_path)
    controller.write_json_atomic(paths.manifest, manifest)
    stop_requests: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(controller, "session_status", lambda _paths: watch_status_payload())
    monkeypatch.setattr(
        controller,
        "enforce_session_storage_context",
        lambda _context: {"ok": True, "policySha256": "abc", "enforcement": {}},
    )
    monkeypatch.setattr(
        controller,
        "request_watch_failure_stop",
        lambda _paths, observed, **_kwargs: stop_requests.append(observed)
        or {"launcherGraceful": True},
    )

    result = controller.watch_session(
        paths,
        interval_seconds=1.0,
        max_bytes=1024,
        segments=2,
        emit=lambda _sample: (_ for _ in ()).throw(BrokenPipeError("sink closed")),
    )

    assert result["ok"] is False
    assert result["latest"]["storage"]["phase"] == "watchEvidence"
    assert result["latest"]["storage"]["error"] == "sink closed"
    assert stop_requests == [manifest]


def test_watch_failure_stop_requests_both_paths_and_forces_exact_launcher(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    manifest = {"launcher": {"pid": 10, "creationDate": "launcher"}}
    forced: list[tuple[dict[str, object], tuple[str, ...], float]] = []
    monkeypatch.setattr(controller, "capture_exact_process_tree", lambda _identity: ())
    monkeypatch.setattr(controller, "wait_exact_exit", lambda _identity, _timeout: False)

    def fake_stop(identity, *, markers, timeout_seconds):
        forced.append((identity, markers, timeout_seconds))
        return {"forced": True, "alreadyStopped": False, "verifiedStopped": True}

    monkeypatch.setattr(controller, "stop_exact_process", fake_stop)

    result = controller.request_watch_failure_stop(
        paths,
        manifest,
        graceful_timeout_seconds=0.1,
    )

    assert paths.stop_file.is_file()
    assert paths.watch_stop_file.is_file()
    assert result["launcherGraceful"] is False
    assert result["launcherForce"]["forced"] is True
    assert result["launcherStopped"] is True
    assert forced == [
        (
            manifest["launcher"],
            ("launch-soak.py",),
            controller.WATCH_FAILURE_GRACE_SECONDS,
        )
    ]


def test_watch_failure_stop_uses_fallback_when_manifest_is_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    fallback = {"pid": 10, "creationDate": "launcher"}
    waited: list[dict[str, object]] = []
    captured = ({"pid": 10, "parentPid": 1, "creationDate": "launcher", "name": "python.exe"},)
    monkeypatch.setattr(controller, "capture_exact_process_tree", lambda _identity: captured)
    monkeypatch.setattr(controller, "remaining_exact_tree_rows", lambda _identities: [])
    monkeypatch.setattr(
        controller,
        "wait_exact_exit",
        lambda identity, _timeout: waited.append(identity) or True,
    )

    result = controller.request_watch_failure_stop(
        paths,
        {},
        launcher_fallback=fallback,
        graceful_timeout_seconds=0.1,
    )

    assert waited == [fallback]
    assert result["launcherIdentityAvailable"] is True
    assert result["launcherStopped"] is True


def test_watch_failure_stop_forces_captured_orphans_after_launcher_exit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    fallback = {"pid": 10, "creationDate": "launcher"}
    captured = (
        {"pid": 10, "parentPid": 1, "creationDate": "launcher", "name": "python.exe"},
        {"pid": 11, "parentPid": 10, "creationDate": "rust", "name": "rust.exe"},
    )
    orphan = WindowsProcessInfo(11, 10, "rust.exe", "rust", "rust")
    forced: list[tuple[dict[str, object], ...]] = []
    monkeypatch.setattr(controller, "capture_exact_process_tree", lambda _identity: captured)
    monkeypatch.setattr(controller, "wait_exact_exit", lambda _identity, _timeout: True)
    monkeypatch.setattr(controller, "remaining_exact_tree_rows", lambda _identities: [orphan])

    def fake_force(identities, *, timeout_seconds):
        del timeout_seconds
        forced.append(identities)
        return {"forced": True, "verifiedStopped": True}

    monkeypatch.setattr(controller, "stop_captured_process_tree", fake_force)

    result = controller.request_watch_failure_stop(
        paths,
        {},
        launcher_fallback=fallback,
        graceful_timeout_seconds=0.1,
    )

    assert result["launcherGraceful"] is False
    assert result["launcherForce"]["forced"] is True
    assert result["launcherStopped"] is True
    assert forced == [captured]


def test_watch_failure_stop_reports_unavailable_launcher_identity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = make_paths(tmp_path)
    waited = False

    def reject_wait(*_args, **_kwargs):
        nonlocal waited
        waited = True
        raise AssertionError("wait must not run without an exact identity")

    monkeypatch.setattr(controller, "wait_exact_exit", reject_wait)

    result = controller.request_watch_failure_stop(paths, {}, graceful_timeout_seconds=0.1)

    assert waited is False
    assert result["launcherIdentityAvailable"] is False
    assert result["launcherStopped"] is False
    assert result["launcherForce"]["errorType"] == "LauncherIdentityUnavailable"


def test_stop_exact_process_reports_surviving_exact_launcher(
    monkeypatch,
) -> None:
    identity = {"pid": 10, "creationDate": "launcher"}
    row = WindowsProcessInfo(10, 1, "python.exe", "python launch-soak.py", "launcher")
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [row])
    monkeypatch.setattr(
        controller.windows_processes,
        "terminate_process_tree",
        lambda *_args, **_kwargs: {"return_code": 1, "remaining_pids": [10]},
    )

    result = controller.stop_exact_process(
        identity,
        markers=("launch-soak.py",),
        timeout_seconds=0.1,
    )

    assert result["forced"] is True
    assert result["verifiedStopped"] is False
    assert result["result"]["remaining_pids"] == [10]


def test_stop_exact_process_rejects_orphaned_owned_children(
    monkeypatch,
) -> None:
    identity = {"pid": 10, "creationDate": "launcher"}
    row = WindowsProcessInfo(10, 1, "python.exe", "python launch-soak.py", "launcher")
    process_snapshots = iter(([row], []))
    monkeypatch.setattr(
        controller.windows_processes,
        "collect_processes",
        lambda: list(next(process_snapshots)),
    )
    monkeypatch.setattr(
        controller.windows_processes,
        "terminate_process_tree",
        lambda *_args, **_kwargs: {"return_code": 1, "remaining_pids": [11]},
    )

    result = controller.stop_exact_process(
        identity,
        markers=("launch-soak.py",),
        timeout_seconds=0.1,
    )

    assert result["verifiedRootStopped"] is True
    assert result["verifiedStopped"] is False
    assert result["result"]["remaining_pids"] == [11]


def test_stop_captured_process_tree_terminates_orphaned_exact_child(
    monkeypatch,
) -> None:
    identities = (
        {"pid": 10, "parentPid": 1, "creationDate": "launcher", "name": "python.exe"},
        {"pid": 11, "parentPid": 10, "creationDate": "rust", "name": "rust.exe"},
    )
    orphan = WindowsProcessInfo(11, 10, "rust.exe", "rust", "rust")
    remaining_snapshots = iter(([orphan], []))
    terminated: list[tuple[int, str]] = []
    monkeypatch.setattr(
        controller,
        "remaining_exact_tree_rows",
        lambda _identities: list(next(remaining_snapshots)),
    )

    def fake_terminate(pid, **kwargs):
        terminated.append((pid, kwargs["expected_root_creation_date"]))
        return {"return_code": 0, "remaining_pids": []}

    monkeypatch.setattr(controller.windows_processes, "terminate_process_tree", fake_terminate)

    result = controller.stop_captured_process_tree(identities, timeout_seconds=0.1)

    assert result["verifiedStopped"] is True
    assert result["forcedRootPids"] == [11]
    assert terminated == [(11, "rust")]


def test_remaining_exact_tree_rows_discovers_post_capture_descendant(
    monkeypatch,
) -> None:
    identities = (
        {"pid": 10, "parentPid": 1, "creationDate": "launcher", "name": "python.exe"},
    )
    late_child = WindowsProcessInfo(11, 10, "rust.exe", "rust", "rust")
    monkeypatch.setattr(controller.windows_processes, "collect_processes", lambda: [late_child])

    remaining = controller.remaining_exact_tree_rows(identities)

    assert remaining == [late_child]


def test_remaining_exact_tree_rows_fails_closed_on_parent_pid_reuse(
    monkeypatch,
) -> None:
    identities = (
        {"pid": 10, "parentPid": 1, "creationDate": "launcher", "name": "python.exe"},
    )
    reused_parent = WindowsProcessInfo(10, 1, "other.exe", "other", "replacement")
    ambiguous_child = WindowsProcessInfo(11, 10, "rust.exe", "rust", "rust")
    monkeypatch.setattr(
        controller.windows_processes,
        "collect_processes",
        lambda: [reused_parent, ambiguous_child],
    )

    with pytest.raises(RuntimeError, match="PID reuse made descendant ownership ambiguous: 11"):
        controller.remaining_exact_tree_rows(identities)


def test_stop_captured_process_tree_rejects_reported_late_survivors(
    monkeypatch,
) -> None:
    identities = (
        {"pid": 10, "parentPid": 1, "creationDate": "launcher", "name": "python.exe"},
        {"pid": 11, "parentPid": 10, "creationDate": "rust", "name": "rust.exe"},
    )
    orphan = WindowsProcessInfo(11, 10, "rust.exe", "rust", "rust")
    remaining_snapshots = iter(([orphan], []))
    monkeypatch.setattr(
        controller,
        "remaining_exact_tree_rows",
        lambda _identities: list(next(remaining_snapshots)),
    )
    monkeypatch.setattr(
        controller.windows_processes,
        "terminate_process_tree",
        lambda *_args, **_kwargs: {"return_code": 1, "remaining_pids": [12]},
    )

    result = controller.stop_captured_process_tree(identities, timeout_seconds=0.1)

    assert result["verifiedStopped"] is False
    assert result["results"][0]["remaining_pids"] == [12]
