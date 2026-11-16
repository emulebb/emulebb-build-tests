from __future__ import annotations

import importlib.util
import os
import sys
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from emule_test_harness.workspace_layout import resolve_selected_workspace_repo


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_module():
    script_path = REPO_ROOT / "scripts" / "rust-rest-openapi-ci.py"
    spec = importlib.util.spec_from_file_location("rust_rest_openapi_ci_for_tests", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_staged_executable_uses_host_suffix(tmp_path: Path) -> None:
    module = load_module()

    expected = "emulebb-rust.exe" if os.name == "nt" else "emulebb-rust"
    assert module.staged_executable(tmp_path) == tmp_path / "tools" / "emulebb-rust" / "bin" / expected


def test_api_key_meets_daemon_production_validation() -> None:
    module = load_module()

    assert len(module.API_KEY.encode("utf-8")) >= 32
    assert module.API_KEY.isascii()
    assert module.API_KEY.isprintable()
    assert not any(character.isspace() for character in module.API_KEY)


def test_source_revision_prefers_ci_revision(tmp_path: Path, monkeypatch) -> None:
    module = load_module()
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)

    assert module.source_revision(tmp_path) == "a" * 40


def test_main_rejects_nonpositive_ready_timeout() -> None:
    module = load_module()

    try:
        module.main(["--ready-timeout-seconds", "0"])
    except ValueError as exc:
        assert "must be positive" in str(exc)
    else:
        raise AssertionError("expected nonpositive timeout rejection")


def test_main_passes_explicit_sources(tmp_path, monkeypatch):
    module = load_module()
    rust, contract = tmp_path / "emulebb-rust", tmp_path / "REST-API-OPENAPI.yaml"
    observed = {}
    def campaign(**kwargs):
        observed.update(kwargs)
        return {"status": "passed", "teardown": "not-started"}, tmp_path / "report.json"
    monkeypatch.setattr(module, "run_campaign", campaign)
    assert module.main(["--rust-repo", str(rust), "--openapi-contract", str(contract)]) == 0
    assert observed["rust_repo"] == rust
    assert observed["openapi_contract"] == contract


def test_explicit_source_outside_workspace_fails_before_launch(tmp_path, monkeypatch):
    import pytest
    module = load_module()
    monkeypatch.setattr(module, "get_required_emule_workspace_root", lambda: tmp_path / "workspace")
    monkeypatch.setattr(module, "get_workspace_output_root", lambda: tmp_path / "output")
    with pytest.raises(RuntimeError, match="workspace source boundaries"):
        module.run_campaign(rust_repo=tmp_path / "outside")


def test_registered_stage_failure_precedes_profile_creation_and_launch(tmp_path, monkeypatch):
    import pytest
    module = load_module()
    workspace, output = tmp_path / "workspace", tmp_path / "output"
    source = workspace / "workspaces/agents/sample/emulebb-rust"
    source.mkdir(parents=True)
    monkeypatch.setattr(module, "get_required_emule_workspace_root", lambda: workspace)
    monkeypatch.setattr(module, "get_workspace_output_root", lambda: output)

    def reject(*args):
        raise RuntimeError("runtime bundle bytes differ")

    def forbidden(*args, **kwargs):
        raise AssertionError("profile or daemon creation preceded source admission")

    monkeypatch.setattr(module.rust_client, "verified_runtime_stage", reject)
    monkeypatch.setattr(module.rust_client, "write_rust_profile", forbidden)
    monkeypatch.setattr(module.rust_client, "spawn_rust_daemon", forbidden)
    with pytest.raises(RuntimeError, match="bundle bytes differ"):
        module.run_campaign(rust_repo=source, registered_stage=True)
    assert not output.exists()


def test_fresh_category_fixture_allocates_stable_nonzero_ids_across_reopen(tmp_path):
    module = load_module()
    rust = resolve_selected_workspace_repo(REPO_ROOT, "emulebb-rust")
    database = tmp_path / "metadata.db"
    module.rust_metadata.create_metadata_db(rust, database)
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            first = connection.execute(
                "INSERT INTO categories(name,comment) VALUES ('First','')"
            ).lastrowid
            survivor = connection.execute(
                "INSERT INTO categories(name,comment) VALUES ('Second','')"
            ).lastrowid
            connection.execute("DELETE FROM categories WHERE id=?", (first,))
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            after_reopen = connection.execute(
                "INSERT INTO categories(name,comment) VALUES ('Third','')"
            ).lastrowid
        assert 0 < first < survivor < after_reopen
        assert connection.execute("SELECT id FROM categories ORDER BY id").fetchall() == [
            (survivor,), (after_reopen,)
        ]


def test_download_admission_keeps_allocated_job_id_separate_from_content_hash():
    module = load_module()
    hash_value = "00112233445566778899aabbccddeeff"
    assert module.require_download_id({"id": "27", "hash": hash_value}, hash_value=hash_value) == "27"
    for row in ({"id": 27, "hash": hash_value}, {"id": "0", "hash": hash_value},
                {"id": "027", "hash": hash_value}, {"id": "9223372036854775808", "hash": hash_value},
                {"id": "27", "hash": "f" * 32}):
        with pytest.raises(RuntimeError, match="invalid job identity"):
            module.require_download_id(row, hash_value=hash_value)


def test_download_action_requires_exact_successful_207_item():
    module = load_module()
    success = {"status": 207, "raw_json": {"data": [
        {"id": "27", "status": "accepted", "httpStatus": 202}]}}
    assert module.require_download_action_result(success, "27") == "accepted"
    unchanged = {"status": 207, "raw_json": {"data": [
        {"id": "27", "status": "unchanged", "httpStatus": 200}]}}
    assert module.require_download_action_result(unchanged, "27") == "unchanged"
    for response in (
        {"status": 200, "raw_json": success["raw_json"]},
        {"status": 207, "raw_json": {"data": [{"id": "28", "status": "accepted", "httpStatus": 202}]}},
        {"status": 207, "raw_json": {"data": [
            {"id": "27", "status": "failed", "httpStatus": 404,
             "error": {"code": "NOT_FOUND", "message": "Missing", "details": {}}}]}},
        {"status": 207, "raw_json": {"data": [
            {"id": "27", "status": "accepted", "httpStatus": 202, "error": {}}]}},
        {"status": 207, "raw_json": {"data": [
            {"id": "27", "status": "unchanged", "httpStatus": 202}]}},
    ):
        with pytest.raises(RuntimeError, match="did not succeed"):
            module.require_download_action_result(response, "27")


def test_main_forwards_registered_stage_selection(tmp_path, monkeypatch):
    module = load_module()
    observed = {}

    def campaign(**kwargs):
        observed.update(kwargs)
        return {"status": "passed", "teardown": "not-started"}, tmp_path / "report.json"

    monkeypatch.setattr(module, "run_campaign", campaign)
    assert module.main(["--registered-stage", "--rust-repo", str(tmp_path)]) == 0
    assert observed["registered_stage"] is True


@pytest.fixture
def friend_fixture(tmp_path):
    module = load_module()
    rust = resolve_selected_workspace_repo(REPO_ROOT, "emulebb-rust")
    tooling = resolve_selected_workspace_repo(REPO_ROOT, "emulebb-tooling")
    database = tmp_path / "metadata.db"
    module.rust_metadata.create_metadata_db(rust, database)
    document = module.load_openapi_document(tooling / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml")
    return module, database, document


@pytest.mark.parametrize("template", ["/uploads/{clientId}", "/upload-queue/{clientId}",
                                     "/downloads/{id}/sources/{clientId}"])
def test_frontdoor_evidence_requires_sql_failure_consistency_and_retry(friend_fixture, template):
    """Exercise evidence qualification with independent SQLite connections, not live peer coverage."""
    module, database, document = friend_fixture
    user_hash = "0123456789abcdef0123456789abcdef"
    ready_calls = []

    def request(method, path, *, expected=200):
        if method == "GET":
            rows = module.friend_database_rows(database)
            return {"json": {"data": {"items": [{"userHash": row[0]} for row in rows if row[6] is None]}}}
        try:
            with closing(sqlite3.connect(database)) as connection:
                with connection:
                    if path.endswith("add-friend"):
                        connection.execute("INSERT INTO friends(user_hash,name,first_seen_at_ms) VALUES (?, 'Peer', 1)",
                                           (bytes.fromhex(user_hash),))
                    else:
                        connection.execute("UPDATE friends SET deleted_at_ms=2 WHERE user_hash=?", (bytes.fromhex(user_hash),))
        except sqlite3.IntegrityError:
            assert expected == 500
            return {"status": 500, "json": {"error": {"code": "PERSISTENCE_FAILED", "message": "Injected write failure", "details": {}}}}
        assert expected == 200
        data = {"userHash": user_hash} if path.endswith("add-friend") else {"ok": True}
        return {"status": 200, "json": {"data": data, "meta": {"apiVersion": "v1"}}}

    result = module.prove_friend_frontdoor(
        request=request, database=database, prefix="/api/v1/peer-fixture", route_template=template,
        ready=lambda: ready_calls.append(True), user_hash=user_hash, document=document,
    )
    assert len(ready_calls) == 4
    assert result["retryAddAndRemove"] == "passed"
    assert len(result["failures"]) == 2
    assert all(row["code"] == "PERSISTENCE_FAILED" and row["reopenedDatabaseUnchanged"]
               and row["cacheUnchanged"] for row in result["failures"])
    assert module.friend_database_rows(database)[0][6] == 2
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE name LIKE 'harness_friend_failure_%'").fetchall() == []


def test_frontdoor_unexpected_response_still_removes_fixture_faults(friend_fixture):
    module, database, document = friend_fixture

    def request(method, path, **kwargs):
        if method == "GET":
            return {"json": {"data": {"items": []}}}
        raise RuntimeError("Peer vanished before mutation response")

    with pytest.raises(RuntimeError, match="Peer vanished"):
        module.prove_friend_frontdoor(
            request=request, database=database, prefix="/api/v1/uploads/peer", route_template="/uploads/{clientId}",
            ready=lambda: None, user_hash="0123456789abcdef0123456789abcdef", document=document,
        )
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE name LIKE 'harness_friend_failure_%'").fetchall() == []
        connection.execute("INSERT INTO friends(user_hash,name,first_seen_at_ms) VALUES (zeroblob(16),'Peer',1)")


def test_friend_fault_refuses_missing_database(tmp_path):
    module = load_module()
    database = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        module.friend_write_fault(database, enabled=True)
    assert not database.exists()


def test_peer_launch_failure_preserves_report_and_closes_owned_fixture(friend_fixture, tmp_path, monkeypatch):
    from types import SimpleNamespace

    module, database, document = friend_fixture
    fixture_root = tmp_path / "peer-phase"
    stopped = []
    ports = iter(range(24001, 24020))

    def write_profile(profile, **kwargs):
        profile.mkdir(parents=True)
        with closing(sqlite3.connect(database)) as source:
            with closing(sqlite3.connect(profile / module.rust_metadata.RUST_PROFILE_METADATA_FILE)) as target:
                source.backup(target)

    def fail_start(*args):
        raise RuntimeError("Daemon launch failed")

    package = SimpleNamespace(_available_unique_port=lambda *args, **kwargs: next(ports),
                              _write_profile=write_profile, _start_daemon=fail_start,
                              _shutdown_or_stop=lambda base, process: stopped.append(process))
    monkeypatch.setattr(module, "load_script_module", lambda *args: package)
    monkeypatch.setattr(module.rust_rest_conformance, "load_rest_smoke_module", lambda *args: None)
    monkeypatch.setattr(module, "load_openapi_document", lambda *args: document)
    with pytest.raises(RuntimeError, match="Local friend-peer proof failed"):
        module.run_friend_peer_phase(executable=tmp_path / "daemon", rust_repo=tmp_path / "rust",
                                     root=fixture_root, openapi_contract=tmp_path / "contract.yaml")
    import json
    report = json.loads((fixture_root / "report.json").read_text())
    assert report["status"] == "failed" and "Daemon launch failed" in report["error"]
    assert report["finalDatabases"][0]["reopenedAfterShutdown"]
    assert stopped == [None]


@pytest.mark.parametrize("initialization", ["pending", "initialized"])
def test_kad_import_evidence_requires_real_sql_rollback_and_retry(friend_fixture, initialization):
    """Qualify campaign evidence with real SQL; this is not live daemon coverage."""
    module, database, document = friend_fixture
    rust = resolve_selected_workspace_repo(REPO_ROOT, "emulebb-rust")
    node_id = "0123456789abcdef0123456789abcdef"
    display_id = "67452301efcdab8967452301efcdab89"
    assert display_id != node_id
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("UPDATE discovery_initialization SET status=? WHERE domain='kad'", (initialization,))

    def request(method, path, *, expected=200, body=None):
        if method == "GET":
            rows = module.kad_database_snapshot(rust, database)["contacts"]
            return {"json": {"data": {"items": [{"nodeId": display_id} for row in rows]}}}
        try:
            with closing(sqlite3.connect(database)) as connection:
                with connection:
                    connection.execute(
                        "INSERT INTO kad_routing_contacts VALUES (?,?,24001,24002,9,0,NULL,NULL,"
                        "0,0,0,0,1,'active',0,1,NULL,NULL,1,1)",
                        (bytes.fromhex(node_id), 2130706433))
                    connection.execute("UPDATE discovery_initialization SET status='initialized' WHERE domain='kad'")
                    connection.execute("UPDATE kad_routing_revision SET revision=revision+1 WHERE id=1")
        except sqlite3.IntegrityError:
            assert expected == 500
            return {"json": {"error": {"code": "PERSISTENCE_FAILED", "message": "Routing transaction failed", "details": {}}}}
        assert expected == 200
        return {"json": {"data": {"ok": True, "imported": True}, "meta": {"apiVersion": "v1"}}}

    evidence = module.prove_kad_import(
        request=request, rust_repo=rust, database=database, url="http://127.0.0.1:24003/nodes.dat",
        expected_node_id_wire_hex=node_id, document=document)
    assert evidence["before"]["initialization"] == initialization
    assert evidence["failure"]["routingSnapshotUnchanged"]
    assert evidence["failure"]["liveContactsUnchanged"]
    assert evidence["retry"] == "passed"
    assert len(evidence["after"]["contacts"]) == 1
    assert evidence["nodeIdWireHex"] == node_id
    assert evidence["nodeIdDisplay"] == display_id
    # The restart gate uses the same translation on its independently reopened DB.
    reopened = module.kad_database_snapshot(rust, database)
    assert module.kad_contact_display_ids(reopened) == [display_id]
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='harness_kad_revision_failure'").fetchall() == []


def test_kad_import_unexpected_response_removes_sql_fault(friend_fixture):
    module, database, document = friend_fixture
    rust = resolve_selected_workspace_repo(REPO_ROOT, "emulebb-rust")

    def request(method, path, **kwargs):
        if method == "GET":
            return {"json": {"data": {"items": []}}}
        raise RuntimeError("Import response transport failed")

    with pytest.raises(RuntimeError, match="transport failed"):
        module.prove_kad_import(request=request, rust_repo=rust, database=database,
                                url="http://127.0.0.1:24003/nodes.dat", expected_node_id_wire_hex="01" * 16,
                                document=document)
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE name='harness_kad_revision_failure'").fetchall() == []
        connection.execute("UPDATE kad_routing_revision SET revision=revision+1 WHERE id=1")


def test_kad_fault_refuses_missing_database(tmp_path):
    module = load_module()
    database = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        module.kad_import_fault(database, enabled=True)
    assert not database.exists()


def test_kad_launch_failure_retains_report_and_closes_local_peer(friend_fixture, tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace
    from emule_test_harness import local_kad_peer

    module, database, document = friend_fixture
    closed = []
    ports = iter(range(24001, 24020))
    fixture = SimpleNamespace(udp_port=24030, tcp_port=24031, start=lambda: None,
                              close=lambda: closed.append(True))
    monkeypatch.setattr(local_kad_peer, "LocalKadPeer", lambda *args: fixture)

    def write_profile(profile, **kwargs):
        profile.mkdir(parents=True)
        with closing(sqlite3.connect(database)) as source:
            with closing(sqlite3.connect(profile / module.rust_metadata.RUST_PROFILE_METADATA_FILE)) as target:
                source.backup(target)

    def fail_start(*args):
        raise RuntimeError("Kad daemon launch failed")

    package = SimpleNamespace(_available_unique_port=lambda *args, **kwargs: next(ports), _start_daemon=fail_start)
    monkeypatch.setattr(module, "load_script_module", lambda *args: package)
    monkeypatch.setattr(module.rust_client, "write_rust_profile", write_profile)
    monkeypatch.setattr(module.rust_rest_conformance, "load_rest_smoke_module", lambda *args: None)
    monkeypatch.setattr(module, "load_openapi_document", lambda *args: document)
    root = tmp_path / "kad-phase"
    with pytest.raises(RuntimeError, match="Kad persistence proof failed"):
        module.run_kad_persistence_phase(executable=tmp_path / "daemon", rust_repo=tmp_path / "rust",
                                         root=root, openapi_contract=tmp_path / "contract.yaml")
    report = json.loads((root / "report.json").read_text())
    assert report["status"] == "failed" and "Kad daemon launch failed" in report["error"]
    assert closed == [True]
