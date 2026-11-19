from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest

from emule_test_harness import ed2k_wire, rust_local_ed2k


def test_ed2k_link_with_source_appends_plain_source_hint() -> None:
    link = "ed2k://|file|payload.bin|4096|00112233445566778899aabbccddeeff|/"

    assert rust_local_ed2k.ed2k_link_with_source(link, "127.0.0.1", 41001) == (
        "ed2k://|file|payload.bin|4096|00112233445566778899aabbccddeeff|"
        "sources,127.0.0.1:41001|/"
    )


@pytest.mark.parametrize(
    "link",
    (
        "https://example.test/payload.bin",
        "ed2k://|file|payload.bin|4096|00112233445566778899aabbccddeeff",
    ),
)
def test_ed2k_link_with_source_rejects_malformed_link(link: str) -> None:
    with pytest.raises(RuntimeError, match="malformed ED2K link"):
        rust_local_ed2k.ed2k_link_with_source(link, "127.0.0.1", 41001)


def test_request_json_includes_http_error_body(monkeypatch) -> None:
    def fail_request(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "http://127.0.0.1/api/v1/test",
            400,
            "Bad Request",
            {},
            io.BytesIO(b'{"error":{"message":"exact failure"}}'),
        )

    monkeypatch.setattr(rust_local_ed2k.urllib.request, "urlopen", fail_request)

    with pytest.raises(RuntimeError, match="HTTP 400.*exact failure"):
        rust_local_ed2k.request_json("http://127.0.0.1", "POST", "/api/v1/test", "key")


@pytest.mark.parametrize("timeout_seconds", [None, 60.0])
def test_request_json_preserves_default_and_accepts_explicit_deadline(monkeypatch, timeout_seconds):
    calls = []
    def open_request(request, *, timeout):
        calls.append((timeout, request.data))
        return io.BytesIO(b'{"data":{"ok":true}}')
    monkeypatch.setattr(rust_local_ed2k.urllib.request, "urlopen", open_request)
    options = {} if timeout_seconds is None else {"timeout_seconds": timeout_seconds}
    # Existing positional request bodies remain valid after the keyword-only extension.
    result = rust_local_ed2k.request_json("http://127.0.0.1", "POST", "/api/v1/test", "key", {"value": 1}, **options)
    assert result == {"ok": True}
    assert calls == [(10.0 if timeout_seconds is None else timeout_seconds, b'{"value": 1}')]


@pytest.mark.parametrize("actual,accepted", [(207, True), (200, False), (201, False)])
def test_request_json_requires_exact_batch_http_status(monkeypatch, actual, accepted):
    class Response(io.BytesIO):
        status = actual

    monkeypatch.setattr(rust_local_ed2k.urllib.request, "urlopen",
        lambda request, *, timeout: Response(b'{"data":[{"id":"12","status":"accepted","httpStatus":200}]}'))
    if accepted:
        assert rust_local_ed2k.request_json("http://127.0.0.1", "POST", "/api/v1/downloads/stop",
            "key", {"ids": ["12"]}, expected_status=207)["data"][0]["id"] == "12"
    else:
        with pytest.raises(RuntimeError, match="expected 207"):
            rust_local_ed2k.request_json("http://127.0.0.1", "POST", "/api/v1/downloads/stop",
                "key", {"ids": ["12"]}, expected_status=207)


@pytest.mark.parametrize("code,message,expected", [
    ("INVALID_ARGUMENT", "failed to initialize Kad runtime for ED2K listener: /private/credential", "kad-listener-initialization"),
    ("EMULE_ERROR", "failed to bind eD2k TCP listener on 192.0.2.20:20029", "ed2k-listener-bind"),
    ("PRIVATE_SECRET", "private operator text", "unrecognized"),
    (["secret"], "private operator text", "unrecognized"),
])
def test_rest_failure_has_closed_status_code_and_core_context(code, message, expected):
    error = rust_local_ed2k.RustRestFailure("private raw message", status=400,
        detail=json.dumps({"error": {"code": code, "message": message}}))
    assert error.safe_failure == {"httpStatus": 400,
        "apiCode": code if code in ("INVALID_ARGUMENT", "EMULE_ERROR") else "unrecognized", "coreContext": expected}
    assert "private" not in json.dumps(error.safe_failure) and "192.0.2.20" not in json.dumps(error.safe_failure)


def test_wait_for_server_list_metadata_joins_active_server_to_distinct_entity(monkeypatch) -> None:
    status_responses = iter(
        [
            {
                "servers": {
                    "connected": True,
                    "currentServer": {
                        "current": True,
                        "address": "127.0.0.1",
                        "port": 4661,
                    },
                }
            },
            {
                "servers": {
                    "connected": True,
                    "currentServer": {
                        "current": True,
                        "address": "127.0.0.1",
                        "port": 4661,
                    },
                }
            },
        ]
    )
    entity_responses = iter(
        [
            {
                "address": "127.0.0.1",
                "port": 4761,
                "name": "seed-before-server-ident",
                "description": "seed",
                "users": 2,
                "files": 1,
            },
            {
                "address": "127.0.0.1",
                "port": 4761,
                "name": "emulebb-local-e2e",
                "description": "deterministic server",
                "users": 2,
                "files": 1,
            },
        ]
    )
    calls: list[tuple[str, str]] = []

    def request(_base_url, method, path, _api_key, _body=None):
        calls.append((method, path))
        return next(status_responses) if path == "/api/v1/status" else next(entity_responses)

    monkeypatch.setattr(rust_local_ed2k, "request_json", request)
    monkeypatch.setattr(rust_local_ed2k.time, "sleep", lambda _seconds: None)

    result = rust_local_ed2k.wait_for_server_list_metadata(
        "http://127.0.0.1:4711",
        "key",
        current_server_address="127.0.0.1",
        current_server_port=4661,
        metadata_server_address="127.0.0.1",
        metadata_server_port=4761,
        expected_name="emulebb-local-e2e",
        expected_description="deterministic server",
        expected_users=2,
        expected_files=1,
        timeout_seconds=1.0,
    )

    assert result["serverEntity"]["name"] == "emulebb-local-e2e"
    assert calls == [
        ("GET", "/api/v1/status"),
        ("GET", "/api/v1/servers/127.0.0.1:4761"),
        ("GET", "/api/v1/status"),
        ("GET", "/api/v1/servers/127.0.0.1:4761"),
    ]


def test_wait_for_server_search_result_reads_unwrapped_payload(monkeypatch) -> None:
    expected_hash = "00112233445566778899aabbccddeeff"
    monkeypatch.setattr(
        rust_local_ed2k,
        "request_json",
        lambda *_args, **_kwargs: {
            "id": "search-1",
            "status": "complete",
            "items": [{"hash": expected_hash.upper(), "name": "fixture.bin"}],
        },
    )

    result = rust_local_ed2k.wait_for_server_search_result(
        "http://192.0.2.10:4711",
        "key",
        query="fixture",
        transfer_hash=expected_hash,
        timeout_seconds=1.0,
    )

    assert result["search"]["id"] == "search-1"
    assert result["result"]["name"] == "fixture.bin"


def test_single_server_search_issues_only_one_exact_request(monkeypatch) -> None:
    expected_hash = "00112233445566778899aabbccddeeff"
    calls: list[tuple[str, str, object]] = []
    responses = iter(
        [
            {"id": "search-1", "status": "running", "items": []},
            {"id": "search-1", "status": "running", "items": []},
            {
                "id": "search-1",
                "status": "complete",
                "items": [
                    {
                        "hash": expected_hash.upper(),
                        "displayName": "fixture.bin",
                        "sizeBytes": 4096,
                    }
                ],
            },
        ]
    )

    def request(_base_url, method, path, _api_key, payload=None):
        calls.append((method, path, payload))
        return next(responses)

    monkeypatch.setattr(rust_local_ed2k, "request_json", request)
    monkeypatch.setattr(rust_local_ed2k.time, "sleep", lambda _seconds: None)

    result = rust_local_ed2k.run_single_server_search(
        "http://192.0.2.10:4711",
        "key",
        query="deterministicparitysearch",
        criteria=ed2k_wire.ServerSearchCriteria(),
        expected_hash=expected_hash,
        expected_name="fixture.bin",
        expected_size=4096,
        timeout_seconds=1.0,
    )

    assert result["searchId"] == "search-1"
    assert result["request"] == calls[0][2]
    assert result["result"]["hash"] == expected_hash.upper()
    assert [call[0] for call in calls].count("POST") == 1
    assert calls[0][2] == {
        "query": "deterministicparitysearch",
        "method": "server",
        "type": "",
    }


def test_single_server_search_sends_exact_size_criteria(monkeypatch) -> None:
    expected_hash = "00112233445566778899aabbccddeeff"
    result = {
        "hash": expected_hash,
        "displayName": "fixture.bin",
        "sizeBytes": 4096,
    }
    calls: list[object] = []
    responses = iter(
        [
            {"id": "search-1", "status": "running", "items": []},
            {"id": "search-1", "status": "complete", "items": [result]},
        ]
    )

    def request(_base_url, method, _path, _api_key, payload=None):
        if method == "POST":
            calls.append(payload)
        return next(responses)

    monkeypatch.setattr(rust_local_ed2k, "request_json", request)

    observed = rust_local_ed2k.run_single_server_search(
        "http://192.0.2.10:4711",
        "key",
        query="deterministicparitysearch",
        criteria=ed2k_wire.ServerSearchCriteria(
            min_size_bytes=4096,
            max_size_bytes=4096,
        ),
        expected_hash=expected_hash,
        expected_name="fixture.bin",
        expected_size=4096,
        timeout_seconds=1.0,
    )

    assert calls == [
        {
            "query": "deterministicparitysearch",
            "method": "server",
            "type": "",
            "minSizeBytes": 4096,
            "maxSizeBytes": 4096,
        }
    ]
    assert observed["request"] == calls[0]


def test_single_server_search_does_not_retry_empty_terminal_search(monkeypatch) -> None:
    calls: list[str] = []
    responses = iter(
        [
            {"id": "search-1", "status": "running", "items": []},
            {"id": "search-1", "status": "complete", "items": []},
        ]
    )

    def request(_base_url, method, _path, _api_key, _payload=None):
        calls.append(method)
        return next(responses)

    monkeypatch.setattr(rust_local_ed2k, "request_json", request)

    with pytest.raises(
        rust_local_ed2k.ServerSearchFailure,
        match="completed without the exact published file",
    ) as failure:
        rust_local_ed2k.run_single_server_search(
            "http://192.0.2.10:4711",
            "key",
            query="deterministicparitysearch",
            criteria=ed2k_wire.ServerSearchCriteria(),
            expected_hash="00112233445566778899aabbccddeeff",
            expected_name="fixture.bin",
            expected_size=4096,
            timeout_seconds=1.0,
        )

    assert calls.count("POST") == 1
    assert failure.value.evidence["searchId"] == "search-1"
    assert failure.value.evidence["search"]["status"] == "complete"
    assert failure.value.evidence["observations"][-1]["status"] == "complete"


def test_single_server_search_waits_for_terminal_state_after_exact_result(monkeypatch) -> None:
    expected_hash = "00112233445566778899aabbccddeeff"
    result = {
        "hash": expected_hash.upper(),
        "displayName": "fixture.bin",
        "sizeBytes": 4096,
    }
    responses = iter(
        [
            {"id": "search-1", "status": "running", "items": []},
            {"id": "search-1", "status": "running", "items": [result]},
            {"id": "search-1", "status": "completed", "items": [result]},
        ]
    )
    calls: list[str] = []

    def request(_base_url, method, _path, _api_key, _payload=None):
        calls.append(method)
        return next(responses)

    monkeypatch.setattr(rust_local_ed2k, "request_json", request)
    monkeypatch.setattr(rust_local_ed2k.time, "sleep", lambda _seconds: None)

    observed = rust_local_ed2k.run_single_server_search(
        "http://192.0.2.10:4711",
        "key",
        query="deterministicparitysearch",
        criteria=ed2k_wire.ServerSearchCriteria(),
        expected_hash=expected_hash,
        expected_name="fixture.bin",
        expected_size=4096,
        timeout_seconds=1.0,
    )

    assert observed["search"]["status"] == "completed"
    assert calls == ["POST", "GET", "GET"]


def test_single_server_search_preserves_missing_creation_id(monkeypatch) -> None:
    monkeypatch.setattr(rust_local_ed2k, "request_json", lambda *_args, **_kwargs: {"status": "running"})

    with pytest.raises(rust_local_ed2k.ServerSearchFailure, match="returned no search ID") as failure:
        rust_local_ed2k.run_single_server_search(
            "http://192.0.2.10:4711",
            "key",
            query="deterministicparitysearch",
            criteria=ed2k_wire.ServerSearchCriteria(),
            expected_hash="00112233445566778899aabbccddeeff",
            expected_name="fixture.bin",
            expected_size=4096,
            timeout_seconds=1.0,
        )

    assert failure.value.evidence["searchId"] is None
    assert failure.value.evidence["created"] == {"status": "running"}


def test_single_server_search_preserves_get_failure_after_creation(monkeypatch) -> None:
    calls = 0

    def request(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"id": "search-1", "status": "running", "items": []}
        raise RuntimeError("REST unavailable")

    monkeypatch.setattr(rust_local_ed2k, "request_json", request)

    with pytest.raises(rust_local_ed2k.ServerSearchFailure, match="result request failed") as failure:
        rust_local_ed2k.run_single_server_search(
            "http://192.0.2.10:4711",
            "key",
            query="deterministicparitysearch",
            criteria=ed2k_wire.ServerSearchCriteria(),
            expected_hash="00112233445566778899aabbccddeeff",
            expected_name="fixture.bin",
            expected_size=4096,
            timeout_seconds=1.0,
        )

    assert failure.value.evidence["searchId"] == "search-1"
    assert failure.value.evidence["created"]["id"] == "search-1"
    assert failure.value.evidence["observations"] == []


def test_start_client_prefers_staged_executable(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[str, Path, Path, Path]] = []

    class FakeProcess:
        pass

    def fake_executable(executable: Path, config_path: Path, log_path: Path):
        calls.append(("executable", executable, config_path, log_path))
        return FakeProcess()

    executable = tmp_path / "tools" / "emulebb-rust.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"exe")
    monkeypatch.setattr(rust_local_ed2k.rust_client, "start_rust_client_executable", fake_executable)

    process, mode, launch_path = rust_local_ed2k.start_client(
        repo=tmp_path / "repo",
        executable=executable,
        profile_dir=tmp_path / "profile",
        log_path=tmp_path / "rust.log",
    )

    assert isinstance(process, FakeProcess)
    assert mode == "executable"
    assert launch_path == executable
    assert calls == [("executable", executable, tmp_path / "profile", tmp_path / "rust.log")]


def test_start_client_falls_back_to_cargo(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[str, Path, Path, Path]] = []

    class FakeProcess:
        pass

    def fake_cargo(repo: Path, config_path: Path, log_path: Path):
        calls.append(("cargo", repo, config_path, log_path))
        return FakeProcess()

    monkeypatch.setattr(rust_local_ed2k.rust_client, "start_rust_client", fake_cargo)

    process, mode, launch_path = rust_local_ed2k.start_client(
        repo=tmp_path / "repo",
        executable=tmp_path / "missing.exe",
        profile_dir=tmp_path / "profile",
        log_path=tmp_path / "rust.log",
    )

    assert isinstance(process, FakeProcess)
    assert mode == "cargo"
    assert launch_path == tmp_path / "repo"
    assert calls == [("cargo", tmp_path / "repo", tmp_path / "profile", tmp_path / "rust.log")]


def test_publish_shared_tree_configures_current_root_and_returns_link(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[str, str, object]] = []

    def fake_request_json(_base_url, method, path, _api_key, body=None):
        calls.append((method, path, body))
        if path == "/api/v1/library/roots":
            return {"id": "1", **body}
        if path == "/api/v1/library/scan":
            return {"ok": True}
        if path == "/api/v1/shared-files":
            return {
                "items": [
                    {
                        "name": "Nested.bin",
                        "ed2kLink": "ed2k://|file|Nested.bin|1|00112233445566778899aabbccddeeff|/",
                    }
                ]
            }
        raise AssertionError(path)

    monkeypatch.setattr(rust_local_ed2k, "request_json", fake_request_json)

    result = rust_local_ed2k.publish_shared_tree(
        "http://192.0.2.10:4711",
        "key",
        root=tmp_path / "shared-tree",
        file_name="Nested.bin",
    )

    assert calls[0] == (
        "POST",
        "/api/v1/library/roots",
        {"path": str(tmp_path / "shared-tree"), "watchEnabled": False},
    )
    assert calls[1] == ("POST", "/api/v1/library/scan", None)
    assert calls[2] == ("GET", "/api/v1/shared-files", None)
    assert result["sharedFiles"]["matched"]["name"] == "Nested.bin"


@pytest.mark.parametrize("ownership", ["owned", "unowned"])
def test_download_completion_uses_retained_job_and_actual_delivery_path(monkeypatch, tmp_path: Path,
                                                                      ownership: str) -> None:
    delivered = tmp_path / "incoming" / "payload.bin"
    delivered.parent.mkdir()
    delivered.write_bytes(b"verified payload")
    file_hash = "00112233445566778899aabbccddeeff"
    calls = []
    def response(_base, method, path, _key):
        calls.append((method, path))
        return {"id": "17", "hash": file_hash, "sizeBytes": delivered.stat().st_size,
                "state": "completed", "completedAt": 123, "payloadVerified": True,
                "delivery": {"path": str(delivered), "state": "delivered", "ownership": ownership}}
    monkeypatch.setattr(rust_local_ed2k, "request_json", response)
    monkeypatch.setattr(rust_local_ed2k, "wait_for", lambda probe, **_kwargs: probe())
    row = rust_local_ed2k.wait_for_download_completed(
        "http://127.0.0.1:4711", "key", "17", expected_hash=file_hash,
        expected_size=delivered.stat().st_size,
        expected_sha256=rust_local_ed2k.file_sha256(delivered),
        expected_delivery_path=delivered, timeout_seconds=2.0,
    )
    assert row["delivered_file_exists"] is True
    assert row["delivered_file_size"] == delivered.stat().st_size
    assert row["deliveryOwnership"] == ownership
    assert calls == [("GET", "/api/v1/downloads/17")]
    assert rust_local_ed2k.wait_for_download_completed(
        "http://127.0.0.1:4711", "key", "17", expected_hash=file_hash,
        expected_size=delivered.stat().st_size,
        expected_sha256="0" * 64, expected_delivery_path=delivered,
        timeout_seconds=2.0,
    ) is None
    invalid = response("", "GET", "/api/v1/downloads/17", "key")
    invalid["delivery"]["ownership"] = "none"
    monkeypatch.setattr(rust_local_ed2k, "request_json", lambda *_args: invalid)
    assert rust_local_ed2k.wait_for_download_completed(
        "http://127.0.0.1:4711", "key", "17", expected_hash=file_hash,
        expected_size=delivered.stat().st_size,
        expected_sha256=rust_local_ed2k.file_sha256(delivered),
        expected_delivery_path=delivered, timeout_seconds=2.0,
    ) is None



def test_download_admission_retains_job_id_separate_from_hash():
    row = {"id": "9223372036854775807", "hash": "a" * 32}
    assert rust_local_ed2k.require_download_id(row, expected_hash="a" * 32) == row["id"]
    with pytest.raises(RuntimeError, match="job identity"):
        rust_local_ed2k.require_download_id({**row, "hash": "b" * 32}, expected_hash="a" * 32)


def test_download_batch_cannot_hide_a_failed_item():
    with pytest.raises(RuntimeError, match="did not accept captured job"):
        rust_local_ed2k.require_download_batch({"data": [{"id": "7", "status": "failed", "httpStatus": 409,
            "error": {"code": "DOWNLOAD_COMPLETED", "message": "Completed", "details": {}}}]}, "7")
    row = {"id": "7", "status": "unchanged", "httpStatus": 200}
    assert rust_local_ed2k.require_download_batch({"data": [row]}, "7") == row


def test_download_part_totals_stream_pages_and_separate_presence_from_verification(monkeypatch):
    calls = []
    def read(_base, method, path, _key):
        calls.append(path)
        assert method == "GET"
        if "cursor=" not in path:
            return {"data": [{"index": 0, "sizeBytes": 100, "presentBytes": 100, "complete": False}],
                    "meta": {"hasMore": True, "nextCursor": "next-page"}}
        return {"data": [{"index": 1, "sizeBytes": 50, "presentBytes": 50, "complete": True}],
                "meta": {"hasMore": False, "nextCursor": None}}
    monkeypatch.setattr(rust_local_ed2k, "request_json", read)
    assert rust_local_ed2k.download_part_totals("http://127.0.0.1", "key", "7") == {
        "partCount": 2, "presentBytes": 150, "verifiedBytes": 50,
    }
    assert calls == ["/api/v1/downloads/7/parts?limit=200", "/api/v1/downloads/7/parts?limit=200&cursor=next-page"]


def test_download_part_totals_refuse_repeated_parts(monkeypatch):
    monkeypatch.setattr(rust_local_ed2k, "request_json", lambda *_args: {
        "data": [{"index": 0, "sizeBytes": 10, "presentBytes": 0, "complete": False}],
        "meta": {"hasMore": True, "nextCursor": "next-page"},
    })
    with pytest.raises(RuntimeError, match="ordering"):
        rust_local_ed2k.download_part_totals("http://127.0.0.1", "key", "7")



def test_download_detail_refuses_a_same_hash_replacement(monkeypatch):
    monkeypatch.setattr(rust_local_ed2k, "request_json", lambda *_args: {"id": "8", "hash": "a" * 32})
    with pytest.raises(RuntimeError, match="substituted another job"):
        rust_local_ed2k.download_detail("http://127.0.0.1", "key", "7", expected_hash="a" * 32)
