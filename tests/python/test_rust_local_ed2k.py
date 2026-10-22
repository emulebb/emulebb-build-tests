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
