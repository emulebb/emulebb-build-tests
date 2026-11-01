from __future__ import annotations

import io
import urllib.error
from pathlib import Path

import pytest

from emule_test_harness import rust_local_ed2k


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


def test_wait_for_current_server_metadata_requires_applied_identity_and_counters(monkeypatch) -> None:
    responses = iter(
        [
            {
                "servers": {
                    "connected": True,
                    "currentServer": {
                        "current": True,
                        "address": "127.0.0.1",
                        "port": 4661,
                        "name": "seed-before-server-ident",
                        "description": "seed",
                        "users": 2,
                        "files": 1,
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
                        "name": "emulebb-local-e2e",
                        "description": "deterministic server",
                        "users": 2,
                        "files": 1,
                    },
                }
            },
        ]
    )
    calls: list[tuple[str, str]] = []

    def request(_base_url, method, path, _api_key, _body=None):
        calls.append((method, path))
        return next(responses)

    monkeypatch.setattr(rust_local_ed2k, "request_json", request)
    monkeypatch.setattr(rust_local_ed2k.time, "sleep", lambda _seconds: None)

    result = rust_local_ed2k.wait_for_current_server_metadata(
        "http://127.0.0.1:4711",
        "key",
        expected_address="127.0.0.1",
        expected_port=4661,
        expected_name="emulebb-local-e2e",
        expected_description="deterministic server",
        timeout_seconds=1.0,
    )

    assert result["currentServer"]["name"] == "emulebb-local-e2e"
    assert calls == [
        ("GET", "/api/v1/status"),
        ("GET", "/api/v1/status"),
    ]


def test_wait_for_current_server_metadata_accepts_dedicated_mfc_status_route(monkeypatch) -> None:
    calls: list[str] = []

    def request(_base_url, _method, path, _api_key, _body=None):
        calls.append(path)
        return {
            "connected": True,
            "currentServer": {
                "current": True,
                "address": "127.0.0.1",
                "port": 4661,
                "name": "emulebb-local-e2e",
                "description": "deterministic server",
                "users": 2,
                "files": 1,
            },
        }

    monkeypatch.setattr(rust_local_ed2k, "request_json", request)

    result = rust_local_ed2k.wait_for_current_server_metadata(
        "http://127.0.0.1:4712",
        "key",
        expected_address="127.0.0.1",
        expected_port=4661,
        expected_name="emulebb-local-e2e",
        expected_description="deterministic server",
        timeout_seconds=1.0,
        status_path="/api/v1/servers/status",
    )

    assert result["currentServer"]["files"] == 1
    assert calls == ["/api/v1/servers/status"]


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
        expected_hash=expected_hash,
        expected_name="fixture.bin",
        expected_size=4096,
        timeout_seconds=1.0,
    )

    assert result["searchId"] == "search-1"
    assert result["result"]["hash"] == expected_hash.upper()
    assert [call[0] for call in calls].count("POST") == 1
    assert calls[0][2] == {
        "query": "deterministicparitysearch",
        "method": "server",
        "type": "",
    }


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
        if path == "/api/v1/shared-directories":
            return {"roots": [body["roots"][0]], "items": []}
        if path == "/api/v1/shared-directories/operations/reload":
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
        "PATCH",
        "/api/v1/shared-directories",
        {"roots": [{"path": str(tmp_path / "shared-tree")}], "confirmReplaceRoots": True},
    )
    assert calls[1] == ("POST", "/api/v1/shared-directories/operations/reload", None)
    assert calls[2] == ("GET", "/api/v1/shared-files", None)
    assert result["sharedFiles"]["matched"]["name"] == "Nested.bin"
