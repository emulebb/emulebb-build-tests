from __future__ import annotations

from pathlib import Path

from emule_test_harness import rust_local_ed2k


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
        config_path=tmp_path / "rust.toml",
        log_path=tmp_path / "rust.log",
    )

    assert isinstance(process, FakeProcess)
    assert mode == "executable"
    assert launch_path == executable
    assert calls == [("executable", executable, tmp_path / "rust.toml", tmp_path / "rust.log")]


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
        config_path=tmp_path / "rust.toml",
        log_path=tmp_path / "rust.log",
    )

    assert isinstance(process, FakeProcess)
    assert mode == "cargo"
    assert launch_path == tmp_path / "repo"
    assert calls == [("cargo", tmp_path / "repo", tmp_path / "rust.toml", tmp_path / "rust.log")]


def test_publish_shared_tree_configures_recursive_root_and_returns_link(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[str, str, object]] = []

    def fake_request_json(_base_url, method, path, _api_key, body=None):
        calls.append((method, path, body))
        if path == "/api/v1/shared-directories":
            return {"roots": [{"path": body["roots"][0]["path"], "recursive": True}], "items": []}
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
        {"roots": [{"path": str(tmp_path / "shared-tree"), "recursive": True}], "confirmReplaceRoots": True},
    )
    assert calls[1] == ("POST", "/api/v1/shared-directories/operations/reload", None)
    assert calls[2] == ("GET", "/api/v1/shared-files", None)
    assert result["sharedFiles"]["matched"]["name"] == "Nested.bin"
