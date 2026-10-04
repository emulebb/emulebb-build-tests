from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_module():
    script = REPO_ROOT / "scripts" / "package-rust-docker-from-deb.py"
    spec = importlib.util.spec_from_file_location(
        "package_rust_docker_from_deb_under_test", script
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fixture_tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    workspace = tmp_path / "workspace"
    output = tmp_path / "output"
    docker = workspace / "repos" / "emulebb-rust" / "packaging" / "docker"
    (docker / "root").mkdir(parents=True)
    (docker / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    deb = output / "release" / "rust-v1.2.3" / "emulebb-rust-v1.2.3-linux-amd64.deb"
    deb.parent.mkdir(parents=True)
    deb.write_bytes(b"certified-deb")
    return workspace, output, deb


def test_packages_clean_commit_into_archive_and_override(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    module = load_module()
    workspace, output, deb = fixture_tree(tmp_path)
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output))
    calls: list[tuple[str, ...]] = []
    commit = "a" * 40

    def fake_command(*argv: str, cwd: Path | None = None):
        calls.append(argv)
        if argv[:3] == ("git", "status", "--porcelain"):
            return SimpleNamespace(stdout="")
        if argv[:3] == ("git", "rev-parse", "HEAD"):
            return SimpleNamespace(stdout=commit + "\n")
        if argv[:2] == ("docker", "save"):
            Path(argv[argv.index("--output") + 1]).write_bytes(b"oci-archive")
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(module, "command", fake_command)

    assert module.main(["--release-version", "1.2.3", "--native"]) == 0

    report = json.loads(capsys.readouterr().out)
    archive = Path(report["archive"])
    override = Path(report["composeOverride"])
    assert archive.read_bytes() == b"oci-archive"
    assert report["sourceCommit"] == commit
    assert report["deb"] == str(deb.resolve())
    assert "local/emulebb-rust:1.2.3-aaaaaaaa" in override.read_text(encoding="utf-8")
    assert any(call[:2] == ("docker", "build") for call in calls)
    assert any(call[:2] == ("docker", "save") for call in calls)


def test_rejects_dirty_rust_tree(monkeypatch, tmp_path: Path) -> None:
    module = load_module()
    workspace, output, _deb = fixture_tree(tmp_path)
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output))
    monkeypatch.setattr(
        module,
        "command",
        lambda *argv, **_kwargs: SimpleNamespace(stdout=" M source.rs\n"),
    )

    with pytest.raises(RuntimeError, match="must be clean"):
        module.main(["--release-version", "1.2.3", "--native"])


def test_windows_launcher_translates_inherited_operator_paths(
    monkeypatch, tmp_path: Path
) -> None:
    module = load_module()
    workspace, output, _deb = fixture_tree(tmp_path)
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output))
    monkeypatch.setattr(
        module,
        "wsl_path",
        lambda path, _distribution: "/wsl/" + path.name,
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda argv, **_kwargs: calls.append(argv) or SimpleNamespace(returncode=0),
    )

    assert module.main(["--release-version", "1.2.3"]) == 0

    argv = calls[0]
    assert "EMULEBB_WORKSPACE_ROOT=/wsl/workspace" in argv
    assert "EMULEBB_WORKSPACE_OUTPUT_ROOT=/wsl/output" in argv
    assert "GIT_CONFIG_KEY_0=core.autocrlf" in argv
    assert "scripts/package-rust-docker-from-deb.py" in argv
