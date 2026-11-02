from __future__ import annotations

import importlib.util
import inspect
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.python.diagnostic_fixtures import current_diagnostic_writer_health


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "emulebb-rust-reask-cross-client.py"
FILE_HASH = "44556677889900112233aabbccddeeff"
SOURCE_TCP_ENDPOINT = "127.0.0.10:4662"
SOURCE_UDP_ENDPOINT = "127.0.0.10:4672"
SOURCE_USER_HASH = "11223344556677889900aabbccddeeff"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "emulebb_rust_reask_cross_client_test", SCRIPT
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_mfc_run(log_dir: Path) -> None:
    for segment_id, waiting_sessions in ((0, 1), (1, 3)):
        segment = log_dir / f"emulebb-mfc-diag-42-active-{segment_id:06}.jsonl"
        segment.write_text(
            json.dumps(
                {
                    "schema": "diag_event_v2",
                    "client": "mfc",
                    "processId": 42,
                    "runId": "active",
                    "segmentId": segment_id,
                    "seq": segment_id + 1,
                    "streamSeq": segment_id + 1,
                    "event": "capacity_snapshot",
                    "body": {
                        "effectiveSlotCap": 2,
                        "activeSlots": 2,
                        "waitingSessions": waiting_sessions,
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
    active = log_dir / "emulebb-mfc-diag-42-active-000001.jsonl"
    (log_dir / "emulebb-mfc-diag-health.json").write_text(
        json.dumps(
            current_diagnostic_writer_health(
                client="mfc",
                run_id="active",
                segment_id=1,
                active_file_name=active.name,
            )
        ),
        encoding="utf-8",
    )


def _registration_record() -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "family": "sched",
        "event": "udp_reask_source_registered",
        "keys": {
            "fileHash": FILE_HASH,
            "peer": SOURCE_TCP_ENDPOINT,
            "peerHash": SOURCE_USER_HASH,
        },
        "body": {
            "outcome": "accepted",
            "sourceUdpEndpoint": SOURCE_UDP_ENDPOINT,
            "sourceUdpVersion": 4,
            "lowId": False,
            "buddyEndpoint": None,
            "buddyId": None,
        },
    }


def _applied_record() -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "family": "sched",
        "event": "udp_reask_reply_applied",
        "keys": {
            "fileHash": FILE_HASH,
            "peer": SOURCE_TCP_ENDPOINT,
            "peerHash": SOURCE_USER_HASH,
        },
        "body": {
            "outcome": "applied",
            "replyOpcode": 0x91,
            "sourceUdpVersion": 4,
            "requestPendingAfter": False,
        },
    }


def test_runner_requires_one_explicit_supported_scenario() -> None:
    module = _load_module()

    with pytest.raises(SystemExit):
        module.parse_args(["--lan-bind-addr", "127.0.0.1"])

    args = module.parse_args(
        [
            "--scenario",
            "queue-full",
            "--lan-bind-addr",
            "127.0.0.1",
        ]
    )
    assert args.scenario == "queue-full"

    file_not_found = module.parse_args(
        [
            "--scenario",
            "file-not-found",
            "--lan-bind-addr",
            "127.0.0.1",
        ]
    )
    assert file_not_found.scenario == "file-not-found"
    assert module.SCENARIO_COVERAGE_IDS[file_not_found.scenario] == (
        "client-udp.file-not-found"
    )
    assert module.SCENARIO_REPLY_OPCODES[file_not_found.scenario] == 0x92

    clear = module.parse_args(
        [
            "--scenario",
            "clear",
            "--lan-bind-addr",
            "127.0.0.1",
        ]
    )
    assert clear.scenario == "clear"
    assert module.SCENARIO_COVERAGE_IDS[clear.scenario] == "client-udp.clear"
    assert module.SCENARIO_CAMPAIGN_SCHEMAS[clear.scenario] == (
        "emulebb-build-tests.client-udp-clear-campaign.v1"
    )
    assert module.SCENARIO_REPLY_OPCODES[clear.scenario] == 0x91
    assert module.SCENARIO_EVIDENCE_BUILDERS[clear.scenario] is (
        module.udp_evidence.build_client_udp_clear_diagnostic_evidence
    )
    assert module.SCENARIO_EVIDENCE_REQUIREMENTS[clear.scenario] is (
        module.udp_evidence.require_client_udp_clear_diagnostic_evidence
    )

    encrypted = module.parse_args(
        [
            "--scenario",
            "encrypted",
            "--lan-bind-addr",
            "127.0.0.1",
        ]
    )
    assert module.SCENARIO_COVERAGE_IDS[encrypted.scenario] == ("client-udp.encrypted")
    assert module.SCENARIO_CAMPAIGN_SCHEMAS[encrypted.scenario] == (
        "emulebb-build-tests.client-udp-encrypted-campaign.v1"
    )
    assert module.SCENARIO_OBFUSCATION[encrypted.scenario] is True
    assert module.SCENARIO_EVIDENCE_BUILDERS[encrypted.scenario] is (
        module.udp_evidence.build_client_udp_encrypted_diagnostic_evidence
    )
    assert module.SCENARIO_EVIDENCE_REQUIREMENTS[encrypted.scenario] is (
        module.udp_evidence.require_client_udp_encrypted_diagnostic_evidence
    )


def test_authoritative_builds_clean_build_and_hash_every_campaign_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    workspace_root = tmp_path / "workspace"
    output_root = tmp_path / "output"
    repos = {
        "build": workspace_root / "repos" / "emulebb-build",
        "emulebb_rust": workspace_root / "repos" / "emulebb-rust",
        "ed2k_server": workspace_root / "repos" / "ed2k-server",
    }
    mfc_repo = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main"
    for repo in (*repos.values(), mfc_repo):
        repo.mkdir(parents=True)
    rust_exe = output_root / "rust-diagnostics.exe"
    mfc_exe = output_root / "mfc-diagnostics.exe"
    server_exe = output_root / "ed2k-server"
    for executable, payload in (
        (rust_exe, b"rust"),
        (mfc_exe, b"mfc"),
        (server_exe, b"server"),
    ):
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(payload)

    calls: list[dict[str, object]] = []

    def build(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return {
            "schema": module.build_provenance.BUILD_RECEIPT_SCHEMA,
            "command": command,
            "returnCode": 0,
            "sourceRevision": str(len(calls)) * 40,
            "sourceCleanBefore": True,
            "sourceCleanAfter": True,
            "orchestratorRevision": "4" * 40,
            "orchestratorCleanBefore": True,
            "orchestratorCleanAfter": True,
        }

    monkeypatch.setattr(
        module,
        "resolve_manifest_repo",
        lambda _root, key: repos[key],
    )
    monkeypatch.setattr(
        module.build_provenance,
        "require_clean_git_source",
        lambda *_args, **_kwargs: SimpleNamespace(revision="5" * 40, clean=True),
    )
    monkeypatch.setattr(
        module.build_provenance,
        "run_canonical_source_build",
        build,
    )
    monkeypatch.setattr(module, "get_workspace_output_root", lambda: output_root)
    monkeypatch.setattr(
        module.converged_live_wire,
        "resolve_rust_diagnostics_exe",
        lambda _root: rust_exe,
    )
    monkeypatch.setattr(
        module.rust_ed2k, "resolve_server_exe", lambda _override: server_exe
    )

    result = module.prepare_authoritative_builds(
        SimpleNamespace(
            workspace_root=workspace_root,
            app_root=mfc_repo,
            app_exe=mfc_exe,
        )
    )

    assert len(calls) == 3
    assert [call["command"][-1] for call in calls] == ["--clean", "--clean", "--clean"]
    assert [call["source_repo"] for call in calls] == [
        repos["emulebb_rust"],
        mfc_repo,
        repos["ed2k_server"],
    ]
    assert calls[2]["timeout_seconds"] == 900.0
    assert result.rust_repo == repos["emulebb_rust"]
    assert result.server_exe == server_exe
    assert result.report["runner"] == {
        "sourceRevision": "5" * 40,
        "sourceClean": True,
    }
    assert result.report["rustDiagnostics"]["build"]["sourceRevision"] == "1" * 40
    assert result.report["mfcDiagnostics"]["build"]["sourceRevision"] == "2" * 40
    assert result.report["ed2kServer"]["build"]["sourceRevision"] == "3" * 40


def test_every_campaign_rust_process_uses_the_authoritative_diagnostics_binary() -> (
    None
):
    module = _load_module()
    source = inspect.getsource(module.start_rust)

    assert "resolve_rust_diagnostics_exe" in source
    assert "resolve_rust_regular_exe" not in source
    assert "EMULEBB_RUST_LOG_DIR" in source


def test_authoritative_runner_defers_mfc_executable_validation_until_clean_build() -> (
    None
):
    module = _load_module()
    source = inspect.getsource(module.main)

    assert "require_exists=False" in source
    assert "require_app_exe=False" in source
    assert source.index("prepare_authoritative_builds(paths)") > source.index(
        "prepare_run_paths("
    )


@pytest.mark.parametrize(
    "override",
    ("--app-root", "--app-exe", "--ed2k-server-repo", "--ed2k-server-exe"),
)
def test_authoritative_runner_has_no_binary_or_source_overrides(override: str) -> None:
    module = _load_module()

    with pytest.raises(SystemExit):
        module.parse_args(
            [
                "--scenario",
                "encrypted",
                "--lan-bind-addr",
                "127.0.0.1",
                override,
                "ignored",
            ]
        )


@pytest.mark.parametrize(
    ("scenario", "schema"),
    [
        ("clear", "CLEAR_RAW_EVIDENCE_SCHEMA"),
        ("encrypted", "ENCRYPTED_RAW_EVIDENCE_SCHEMA"),
    ],
)
def test_ack_raw_evidence_serializes_complete_reducer_inputs(
    scenario: str,
    schema: str,
) -> None:
    module = _load_module()
    transition = module.udp_evidence.ClientUdpV4Transition(
        requester="rust",
        responder="mfc",
        source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
        source_udp_endpoint=SOURCE_UDP_ENDPOINT,
        source_user_hash=bytes.fromhex(SOURCE_USER_HASH),
        requester_udp_endpoint="127.0.0.20:4772",
        control_receipt={"request": {}, "response": {}},
        requester_records=[{"seq": 1}],
        responder_records=[{"seq": 2}],
    )

    payload = module.build_ack_raw_evidence(
        scenario=scenario,
        file_hash=FILE_HASH,
        part_count=1,
        transitions=[transition],
    )

    assert payload == {
        "schema": getattr(module.udp_evidence, schema),
        "scenario": scenario,
        "fileHash": FILE_HASH,
        "partCount": 1,
        "transitions": [
            {
                "requester": "rust",
                "responder": "mfc",
                "sourceTcpEndpoint": SOURCE_TCP_ENDPOINT,
                "sourceUdpEndpoint": SOURCE_UDP_ENDPOINT,
                "sourceUserHash": SOURCE_USER_HASH,
                "requesterUdpEndpoint": "127.0.0.20:4772",
                "controlReceipt": {"request": {}, "response": {}},
                "requesterRecords": [{"seq": 1}],
                "responderRecords": [{"seq": 2}],
            }
        ],
    }


def test_capacity_precondition_reads_health_validated_segments(tmp_path: Path) -> None:
    module = _load_module()
    _write_mfc_run(tmp_path)

    assert (
        module.wait_for_upload_capacity(tmp_path, active_slots=2, timeout=0.1)[
            "waitingSessions"
        ]
        == 3
    )


def test_capacity_records_reject_missing_writer_health(tmp_path: Path) -> None:
    module = _load_module()
    _write_mfc_run(tmp_path)
    (tmp_path / "emulebb-mfc-diag-health.json").unlink()

    with pytest.raises(ValueError, match="missing MFC diagnostic writer health"):
        module._mfc_capacity_snapshots(tmp_path)


def test_rust_capacity_requires_one_exact_opened_production_slot(monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "current_diag_records",
        lambda *_args, **_kwargs: [
            {
                "schema": "diag_event_v2",
                "family": "sched",
                "event": "capacity_snapshot",
                "seq": 1,
                "body": {
                    "baseSlots": 1,
                    "elasticSlots": 0,
                    "effectiveSlotCap": 1,
                    "activeSlots": 1,
                    "waitingSessions": 0,
                },
            },
            {
                "schema": "diag_event_v2",
                "family": "sched",
                "event": "upload_slot_opened",
                "seq": 2,
                "keys": {
                    "fileHash": FILE_HASH,
                    "peer": SOURCE_TCP_ENDPOINT,
                },
                "body": {"outcome": "opened"},
            },
        ],
    )

    assert (
        module.wait_for_rust_occupied_upload_slot(
            Path("unused"),
            file_hash=FILE_HASH,
            peer_endpoint=SOURCE_TCP_ENDPOINT,
            timeout=0.1,
        )["slotOpenedSequence"]
        == 2
    )


def test_server_publication_uses_exact_named_client(monkeypatch) -> None:
    module = _load_module()

    class FakeControl:
        def wait_for_client_shared_files(self, nickname, minimum, timeout):
            assert (nickname, minimum, timeout) == ("rust-responder", 1, 1.0)
            return {
                "client_name": nickname,
                "ip": "192.0.2.241",
                "high_id": True,
                "shared_files": 1,
            }

    monkeypatch.setattr(
        module.ed2k_harness,
        "ed2k_server_control",
        lambda base_url, secret: FakeControl(),
    )

    assert module.wait_for_server_client_publication(
        "http://server.test",
        "secret",
        "rust-responder",
        1.0,
    ) == {
        "clientName": "rust-responder",
        "address": "192.0.2.241",
        "highId": True,
        "sharedFiles": 1,
    }


def test_server_publication_rejects_fragment_match(monkeypatch) -> None:
    module = _load_module()

    class FakeControl:
        def wait_for_client_shared_files(self, *_args):
            return {"client_name": "rust-responder-other", "shared_files": 1}

    monkeypatch.setattr(
        module.ed2k_harness,
        "ed2k_server_control",
        lambda base_url, secret: FakeControl(),
    )

    with pytest.raises(RuntimeError, match="expected 'rust-responder'"):
        module.wait_for_server_client_publication(
            "http://server.test",
            "secret",
            "rust-responder",
            1.0,
        )


def test_server_client_precondition_rejects_low_id() -> None:
    module = _load_module()

    with pytest.raises(RuntimeError, match="observed 'rust-requester' as LowID"):
        module.require_server_high_id_client(
            {
                "client_name": "rust-requester",
                "ip": "172.17.128.213",
                "high_id": False,
                "shared_files": 0,
            },
            nickname="rust-requester",
        )


def test_exact_direct_v4_registration_builds_control_identity() -> None:
    module = _load_module()

    identity = module.find_udp_reask_registration(
        [_registration_record()],
        file_hash=FILE_HASH.upper(),
        source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
        source_udp_endpoint=SOURCE_UDP_ENDPOINT,
    )

    assert identity == {
        "fileHash": FILE_HASH,
        "sourceTcpEndpoint": SOURCE_TCP_ENDPOINT,
        "sourceUdpEndpoint": SOURCE_UDP_ENDPOINT,
        "sourceUserHash": SOURCE_USER_HASH,
        "sourceUdpVersion": 4,
    }
    assert module.queued_source_reask_request(
        file_hash=FILE_HASH,
        source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
        source_udp_endpoint=SOURCE_UDP_ENDPOINT,
        source_user_hash=SOURCE_USER_HASH,
    ) == {
        "fileHash": FILE_HASH,
        "sourceIp": "127.0.0.10",
        "sourceTcpPort": 4662,
        "sourceUdpPort": 4672,
        "sourceUserHash": SOURCE_USER_HASH,
        "sourceUdpVersion": 4,
    }


def test_registration_rejects_duplicate_exact_identity() -> None:
    module = _load_module()

    with pytest.raises(RuntimeError, match="multiple exact direct V4"):
        module.find_udp_reask_registration(
            [_registration_record(), _registration_record()],
            file_hash=FILE_HASH,
            source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
            source_udp_endpoint=SOURCE_UDP_ENDPOINT,
        )


def test_mfc_queue_identity_requires_exact_onqueue_highid_source() -> None:
    module = _load_module()
    rows = {
        "data": {
            "items": [
                {
                    "address": "127.0.0.11",
                    "port": 4662,
                    "userHash": "ffeeddccbbaa00998877665544332211",
                    "downloadState": "onqueue",
                    "tcpConnected": False,
                    "lowId": False,
                    "queueRank": 1,
                },
                {
                    "address": "127.0.0.10",
                    "port": 4662,
                    "userHash": SOURCE_USER_HASH,
                    "downloadState": "onqueue",
                    "tcpConnected": False,
                    "lowId": False,
                    "queueRank": 1,
                },
            ]
        }
    }

    assert module.find_mfc_queued_source(
        rows, source_ip="127.0.0.10", source_tcp_port=4662
    ) == {
        "sourceIp": "127.0.0.10",
        "sourceTcpPort": 4662,
        "sourceUserHash": SOURCE_USER_HASH,
        "queueRank": 1,
    }

    rows["data"]["items"][1]["downloadState"] = "connected"
    assert (
        module.find_mfc_queued_source(
            rows, source_ip="127.0.0.10", source_tcp_port=4662
        )
        is None
    )

    rows["data"]["items"][1]["downloadState"] = "onqueue"
    rows["data"]["items"][1]["tcpConnected"] = True
    assert (
        module.find_mfc_queued_source(
            rows, source_ip="127.0.0.10", source_tcp_port=4662
        )
        is None
    )


def test_upload_waiter_identity_requires_exact_requester_and_file() -> None:
    module = _load_module()
    rows = {
        "data": {
            "items": [
                {
                    "clientId": "wrong-port",
                    "address": "127.0.0.20",
                    "port": 4663,
                    "requestedFileHash": FILE_HASH,
                    "waitingQueue": True,
                },
                {
                    "clientId": "exact-waiter",
                    "address": "127.0.0.20",
                    "port": 4662,
                    "requestedFileHash": FILE_HASH.upper(),
                    "waitingQueue": True,
                },
            ]
        }
    }

    assert module.find_upload_waiter(
        rows,
        file_hash=FILE_HASH,
        requester_tcp_endpoint="127.0.0.20:4662",
    ) == {
        "clientId": "exact-waiter",
        "address": "127.0.0.20",
        "requestedFileHash": FILE_HASH,
        "waitingQueue": True,
    }


def test_upload_waiter_removal_requires_confirmed_absence(monkeypatch) -> None:
    module = _load_module()
    calls: list[str] = []

    def retry(_base_url, path, **_kwargs):
        calls.append(path)
        return {
            "status": 200,
            "raw_json": {"data": {"ok": True, "removed": "queue"}},
        }

    monkeypatch.setattr(module.dtt, "retry_rest_request", retry)
    monkeypatch.setattr(
        module.cc,
        "request_json",
        lambda *_args, **_kwargs: {"data": {"items": []}},
    )
    waiter = {
        "clientId": "127.0.0.20:4662",
        "address": "127.0.0.20",
        "requestedFileHash": FILE_HASH,
        "waitingQueue": True,
    }

    assert module.remove_upload_waiter(
        "http://responder.test",
        "secret",
        waiter=waiter,
        file_hash=FILE_HASH,
        requester_tcp_endpoint="127.0.0.20:4662",
        timeout=0.1,
    ) == {
        "waiter": waiter,
        "response": {
            "status": 200,
            "json": {"ok": True, "removed": "queue"},
        },
        "verifiedAbsent": True,
    }
    assert calls == ["/api/v1/upload-queue/127.0.0.20%3A4662/operations/remove"]


def test_queue_pressure_receipt_uses_exact_requester_udp_endpoint(monkeypatch) -> None:
    module = _load_module()
    request = module.queue_pressure_request(
        file_hash=FILE_HASH.upper(),
        requester_udp_endpoint="127.0.0.20:4672",
    )
    payload = {
        "accepted": True,
        "fixtureId": 7,
        "fileHash": FILE_HASH,
        "sourceEndpoint": "127.0.0.20:4672",
        "actualWaitingUserCount": 0,
        "effectiveWaitingUserCount": 1951,
        "queueSize": 2000,
        "expiresAfterMillis": 30000,
        "state": "client-udp-queue-pressure-armed",
    }
    monkeypatch.setattr(
        module.dtt,
        "retry_rest_request",
        lambda *_args, **_kwargs: {
            "status": 200,
            "raw_json": {"data": payload},
        },
    )

    assert request == {
        "fileHash": FILE_HASH,
        "sourceIp": "127.0.0.20",
        "sourceUdpPort": 4672,
    }
    assert module.arm_queue_pressure(
        "http://responder.test",
        "secret",
        request,
    ) == {
        "request": request,
        "response": {"status": 200, "json": payload},
    }


def test_shared_catalog_identity_and_fixture_withdrawal(
    monkeypatch,
    tmp_path: Path,
) -> None:
    module = _load_module()
    fixture = tmp_path / "fixture" / "client-udp-file-not-found.bin"
    fixture.parent.mkdir()
    fixture.write_bytes(b"fixture")
    row = {"name": fixture.name, "hash": FILE_HASH.upper()}

    assert (
        module.find_shared_file_by_hash(
            {"data": {"items": [row]}},
            file_hash=FILE_HASH,
        )
        == row
    )

    observed_states: list[tuple[bool, str]] = []
    monkeypatch.setattr(
        module,
        "wait_for_shared_file_presence",
        lambda *_args, present, shared_files_path, **_kwargs: observed_states.append(
            (present, shared_files_path)
        ),
    )
    monkeypatch.setattr(
        module,
        "reload_shared_catalog",
        lambda *_args, **_kwargs: {"status": 200, "json": {"ok": True}},
    )

    receipt, withdrawn = module.withdraw_shared_fixture(
        "http://responder.test",
        "secret",
        fixture_path=fixture,
        file_hash=FILE_HASH,
        reload_path=module.MFC_SHARED_RELOAD_PATH,
        shared_files_path=module.MFC_SHARED_FILES_PATH,
        timeout=0.1,
    )

    assert observed_states == [
        (True, module.MFC_SHARED_FILES_PATH),
        (False, module.MFC_SHARED_FILES_PATH),
    ]
    assert not fixture.exists()
    assert withdrawn.read_bytes() == b"fixture"
    assert receipt == {
        "fileHash": FILE_HASH,
        "method": "file-move",
        "fixturePath": str(fixture.resolve()),
        "movedToPath": str(withdrawn),
        "presentBefore": True,
        "reloadResponse": {"status": 200, "json": {"ok": True}},
        "absentAfter": True,
    }

    module.restore_shared_fixture(fixture.resolve(), withdrawn)
    assert fixture.read_bytes() == b"fixture"
    assert not withdrawn.exists()


@pytest.mark.parametrize(
    "shared_files_path",
    [
        "/api/v1/shared-files?offset=0&limit=100",
        "/api/v1/shared-files",
    ],
)
def test_shared_catalog_presence_uses_selected_client_route(
    monkeypatch,
    shared_files_path: str,
) -> None:
    module = _load_module()
    calls: list[str] = []

    def request_json(_base_url, _method, path, _api_key):
        calls.append(path)
        return {"items": [{"hash": FILE_HASH.upper()}]}

    monkeypatch.setattr(module.cc, "request_json", request_json)

    assert module.wait_for_shared_file_presence(
        "http://responder.test",
        "secret",
        file_hash=FILE_HASH,
        present=True,
        shared_files_path=shared_files_path,
        timeout=0.1,
    ) == {"hash": FILE_HASH.upper()}
    assert calls == [shared_files_path]


def test_rust_shared_root_withdrawal_uses_production_configuration(
    monkeypatch,
    tmp_path: Path,
) -> None:
    module = _load_module()
    fixture = tmp_path / "fixture" / "client-udp-file-not-found.bin"
    fixture.parent.mkdir()
    fixture.write_bytes(b"fixture")
    observed_states: list[tuple[bool, str]] = []

    monkeypatch.setattr(
        module,
        "wait_for_shared_file_presence",
        lambda *_args, present, shared_files_path, **_kwargs: observed_states.append(
            (present, shared_files_path)
        ),
    )
    monkeypatch.setattr(
        module,
        "clear_shared_roots",
        lambda *_args, **_kwargs: {
            "request": {"roots": [], "confirmReplaceRoots": True},
            "response": {"status": 200, "json": {"roots": []}},
        },
    )
    monkeypatch.setattr(
        module,
        "reload_shared_catalog",
        lambda *_args, **_kwargs: {"status": 200, "json": {"ok": True}},
    )

    assert module.withdraw_rust_shared_root(
        "http://responder.test",
        "secret",
        fixture_path=fixture,
        file_hash=FILE_HASH,
        timeout=0.1,
    ) == {
        "fileHash": FILE_HASH,
        "method": "shared-roots-cleared",
        "fixturePath": str(fixture.resolve()),
        "sharedDirectories": {
            "request": {"roots": [], "confirmReplaceRoots": True},
            "response": {"status": 200, "json": {"roots": []}},
        },
        "presentBefore": True,
        "reloadResponse": {"status": 200, "json": {"ok": True}},
        "absentAfter": True,
    }
    assert fixture.read_bytes() == b"fixture"
    assert observed_states == [
        (True, module.RUST_SHARED_FILES_PATH),
        (False, module.RUST_SHARED_FILES_PATH),
    ]


def test_clear_shared_roots_uses_exact_production_patch(monkeypatch) -> None:
    module = _load_module()
    calls: list[tuple[str, str, object]] = []

    def retry_rest_request(_base_url, path, *, method, json_body, **_kwargs):
        calls.append((method, path, json_body))
        return {
            "status": 200,
            "raw_json": {"data": {"roots": []}},
        }

    monkeypatch.setattr(module.dtt, "retry_rest_request", retry_rest_request)

    assert module.clear_shared_roots("http://responder.test", "secret") == {
        "request": {"roots": [], "confirmReplaceRoots": True},
        "response": {"status": 200, "json": {"roots": []}},
    }
    assert calls == [
        (
            "PATCH",
            module.SHARED_DIRECTORIES_PATH,
            {"roots": [], "confirmReplaceRoots": True},
        )
    ]


def test_file_not_found_completion_requires_ordered_dead_list_and_drop() -> None:
    module = _load_module()
    applied = _applied_record()
    applied["seq"] = 7
    applied["body"]["replyOpcode"] = 0x92
    dead_listed = {
        "schema": "diag_event_v2",
        "seq": 8,
        "family": "sched",
        "event": "source_dead_listed",
        "keys": {
            "fileHash": FILE_HASH,
            "peer": SOURCE_TCP_ENDPOINT,
            "peerHash": SOURCE_USER_HASH,
        },
        "body": {
            "outcome": "dead_listed",
            "reason": "udp_fnf",
            "blockSecs": 2700,
        },
    }
    dropped = {
        "schema": "diag_event_v2",
        "seq": 9,
        "family": "sched",
        "event": "source_dropped",
        "keys": {
            "fileHash": FILE_HASH,
            "peer": SOURCE_TCP_ENDPOINT,
            "peerHash": SOURCE_USER_HASH,
        },
        "body": {"outcome": "dropped"},
    }

    completion = module.find_file_not_found_completion(
        [applied, dead_listed, dropped],
        file_hash=FILE_HASH,
        source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
        source_user_hash=SOURCE_USER_HASH,
    )

    assert completion == {
        "applied": applied,
        "deadListed": dead_listed,
        "dropped": dropped,
    }

    swapped = {
        **dropped,
        "event": "source_swapped",
        "body": {"outcome": "swapped"},
    }
    with pytest.raises(RuntimeError, match="swapped instead of dropped"):
        module.find_file_not_found_completion(
            [applied, dead_listed, dropped, swapped],
            file_hash=FILE_HASH,
            source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
            source_user_hash=SOURCE_USER_HASH,
        )


def test_transfer_source_absence_uses_exact_endpoint_and_hash(monkeypatch) -> None:
    module = _load_module()
    exact = {
        "address": "127.0.0.10",
        "port": 4662,
        "userHash": SOURCE_USER_HASH.upper(),
    }
    assert (
        module.find_transfer_source(
            {"data": {"items": [exact]}},
            source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
            source_user_hash=SOURCE_USER_HASH,
        )
        == exact
    )

    monkeypatch.setattr(
        module.cc,
        "request_json",
        lambda *_args, **_kwargs: {"data": {"items": []}},
    )
    assert module.wait_for_transfer_source_absent(
        "http://requester.test",
        "secret",
        file_hash=FILE_HASH,
        source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
        source_user_hash=SOURCE_USER_HASH,
        timeout=0.1,
    ) == {
        "fileHash": FILE_HASH,
        "sourceTcpEndpoint": SOURCE_TCP_ENDPOINT,
        "sourceUserHash": SOURCE_USER_HASH,
        "verifiedAbsent": True,
    }


def test_control_receipt_unwraps_only_the_api_data_envelope() -> None:
    module = _load_module()
    request = module.queued_source_reask_request(
        file_hash=FILE_HASH,
        source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
        source_udp_endpoint=SOURCE_UDP_ENDPOINT,
        source_user_hash=SOURCE_USER_HASH,
    )
    response_payload = {
        "accepted": True,
        "fileHash": FILE_HASH,
        "sourceEndpoint": SOURCE_UDP_ENDPOINT,
        "sourceTcpPort": 4662,
        "sourceUserHash": SOURCE_USER_HASH,
        "sourceUdpVersion": 4,
        "state": "queued-source-reask-pending",
    }

    assert module.queued_source_reask_receipt(
        request,
        {"status": 200, "raw_json": {"data": response_payload, "meta": {}}},
    ) == {
        "request": request,
        "response": {"status": 200, "json": response_payload},
    }


def test_exact_v4_application_is_required_once() -> None:
    module = _load_module()

    assert (
        module.find_udp_reask_applied(
            [_applied_record()],
            file_hash=FILE_HASH,
            source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
            source_user_hash=SOURCE_USER_HASH,
            reply_opcode=0x91,
        )
        == _applied_record()
    )

    assert (
        module.find_udp_reask_applied(
            [_applied_record()],
            file_hash=FILE_HASH,
            source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
            source_user_hash=SOURCE_USER_HASH,
            reply_opcode=0x93,
        )
        is None
    )

    with pytest.raises(RuntimeError, match="multiple exact client-UDP"):
        module.find_udp_reask_applied(
            [_applied_record(), _applied_record()],
            file_hash=FILE_HASH,
            source_tcp_endpoint=SOURCE_TCP_ENDPOINT,
            source_user_hash=SOURCE_USER_HASH,
            reply_opcode=0x91,
        )


def test_runner_loads_the_accepted_stock_client_udp_record() -> None:
    module = _load_module()

    record = module.load_stock_client_udp_record()

    assert record["recordId"] == "stock.client-udp.corpus"
    assert record["payloadDigest"] == (
        "sha256:89468db8e028268f21598216f5949ae11c2b1c3e1370b151d3d7136e8fda812b"
    )
