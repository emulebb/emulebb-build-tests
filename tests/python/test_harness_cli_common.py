from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest


def load_harness_cli_common_module():
    """Loads the hyphenated harness CLI helper for focused unit tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "harness-cli-common.py"
    spec = importlib.util.spec_from_file_location("harness_cli_common_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["harness_cli_common_for_tests"] = module
    spec.loader.exec_module(module)
    return module


def test_publish_directory_snapshot_skips_generated_shared_hash_payloads(tmp_path: Path) -> None:
    module = load_harness_cli_common_module()
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    scenario = source / "scenario"
    payload_dir = scenario / "shared-hash-root" / "branch"
    payload_dir.mkdir(parents=True)
    (payload_dir / "large-payload.bin").write_bytes(b"x" * 1024)
    (scenario / "result.json").write_text("{}", encoding="utf-8")
    (source / "suite-result.json").write_text("{}", encoding="utf-8")

    module.publish_directory_snapshot(source, destination)

    assert (destination / "suite-result.json").is_file()
    assert (destination / "scenario" / "result.json").is_file()
    assert not (destination / "scenario" / "shared-hash-root").exists()


def test_write_json_file_recreates_parent_directory(tmp_path: Path) -> None:
    module = load_harness_cli_common_module()
    result_path = tmp_path / "missing" / "result.json"

    module.write_json_file(result_path, {"status": "failed"})

    assert result_path.is_file()
    assert json.loads(result_path.read_text(encoding="utf-8")) == {"status": "failed"}


def test_publish_directory_snapshot_preserves_exact_trailing_dot_space_names(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("exact Win32 trailing dot/space names require Windows extended-length paths")

    module = load_harness_cli_common_module()
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    exact_dir = Path(str(source / "exact-dir") + ". ")
    exact_file = exact_dir / "payload. "
    os.makedirs(module.to_windows_extended_path(exact_dir), exist_ok=True)
    with open(module.to_windows_extended_path(exact_file), "wb") as handle:
        handle.write(b"exact")

    module.publish_directory_snapshot(source, destination)

    copied_file = Path(str(destination / "exact-dir") + ". ") / "payload. "
    assert os.path.exists(module.to_windows_extended_path(copied_file))
    with open(module.to_windows_extended_path(copied_file), "rb") as handle:
        assert handle.read() == b"exact"


def test_cleanup_source_artifacts_leaves_locked_temp_payloads(monkeypatch, tmp_path: Path) -> None:
    module = load_harness_cli_common_module()
    source = tmp_path / "source"
    source.mkdir()

    attempts = {"count": 0}

    def fake_rmtree(_path: Path) -> None:
        attempts["count"] += 1
        raise PermissionError("locked")

    ticks = iter([0.0, 0.1, 10.1])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(module.shutil, "rmtree", fake_rmtree)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    paths = module.HarnessRunPaths(
        repo_root=tmp_path,
        workspace_root=tmp_path,
        app_root=tmp_path,
        app_exe=tmp_path / "emule.exe",
        seed_config_dir=tmp_path,
        configuration="Release",
        suite_name="locked-cleanup",
        source_artifacts_dir=source,
        run_report_dir=tmp_path / "reports" / "run",
        latest_report_dir=tmp_path / "reports" / "latest",
        keep_source_artifacts=False,
    )

    module.cleanup_source_artifacts(paths)

    assert attempts["count"] > 0


def test_resolve_profile_seed_dir_uses_default_or_override(tmp_path: Path) -> None:
    module = load_harness_cli_common_module()
    paths = module.HarnessRunPaths(
        repo_root=tmp_path,
        workspace_root=tmp_path,
        app_root=tmp_path,
        app_exe=tmp_path / "emule.exe",
        seed_config_dir=tmp_path / "default-seed",
        configuration="Release",
        suite_name="seed-resolution",
        source_artifacts_dir=tmp_path / "source",
        run_report_dir=tmp_path / "reports" / "run",
        latest_report_dir=tmp_path / "reports" / "latest",
        keep_source_artifacts=False,
    )

    assert module.resolve_profile_seed_dir(paths, None) == tmp_path / "default-seed"
    assert module.resolve_profile_seed_dir(paths, tmp_path / "override") == (tmp_path / "override").resolve()


def test_prepare_run_paths_defaults_to_workspace_state_roots(monkeypatch, tmp_path: Path) -> None:
    module = load_harness_cli_common_module()
    repo_root = tmp_path / "repos" / "eMule-build-tests"
    script_file = repo_root / "scripts" / "suite.py"
    seed_dir = repo_root / "manifests" / "live-profile-seed" / "config"
    app_root = tmp_path / "workspaces" / "workspace" / "app" / "eMule-main"
    app_exe = app_root / "srchybrid" / "x64" / "Release" / "emule.exe"
    seed_dir.mkdir(parents=True)
    app_exe.parent.mkdir(parents=True)
    app_exe.write_text("exe", encoding="utf-8")

    monkeypatch.setattr(module.time, "strftime", lambda _format: "20260521-120000")
    monkeypatch.setattr(module.os, "getpid", lambda: 4242)
    monkeypatch.setattr(module, "configure_local_dumps", lambda **_kwargs: {"enabled": False})
    monkeypatch.setenv("TEMP", r"C:\not-the-workspace-temp")
    monkeypatch.setenv("TMP", r"C:\not-the-workspace-temp")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\not-the-workspace-localappdata")

    paths = module.prepare_run_paths(
        script_file=script_file,
        suite_name="rest-api-live-e2e",
        configuration="Release",
        workspace_root=tmp_path / "workspaces" / "workspace",
        app_root=app_root,
    )

    label = "20260521-120000-eMule-main-release-4242"
    assert paths.source_artifacts_dir == (
        tmp_path / "workspaces" / "workspace" / "state" / "test-artifacts" / "rest-api-live-e2e" / label
    ).resolve()
    assert paths.run_report_dir == (
        tmp_path / "workspaces" / "workspace" / "state" / "test-reports" / "rest-api-live-e2e" / label
    ).resolve()
    assert paths.latest_report_dir == (
        tmp_path / "workspaces" / "workspace" / "state" / "test-reports" / "rest-api-live-e2e-latest"
    ).resolve()
    assert paths.keep_source_artifacts is False


def test_prepare_run_paths_rejects_explicit_windows_temp_artifacts(monkeypatch, tmp_path: Path) -> None:
    module = load_harness_cli_common_module()
    repo_root = tmp_path / "repos" / "eMule-build-tests"
    script_file = repo_root / "scripts" / "suite.py"
    seed_dir = repo_root / "manifests" / "live-profile-seed" / "config"
    app_root = tmp_path / "workspaces" / "workspace" / "app" / "eMule-main"
    app_exe = app_root / "srchybrid" / "x64" / "Release" / "emule.exe"
    local_temp = tmp_path / "Users" / "tester" / "AppData" / "Local" / "Temp"
    seed_dir.mkdir(parents=True)
    app_exe.parent.mkdir(parents=True)
    app_exe.write_text("exe", encoding="utf-8")
    local_temp.mkdir(parents=True)

    monkeypatch.setenv("LOCALAPPDATA", str(local_temp.parent))
    monkeypatch.setenv("TEMP", str(local_temp))
    monkeypatch.setattr(module, "configure_local_dumps", lambda **_kwargs: {"enabled": False})

    with pytest.raises(RuntimeError, match="not Windows temp"):
        module.prepare_run_paths(
            script_file=script_file,
            suite_name="rest-api-live-e2e",
            configuration="Release",
            workspace_root=tmp_path / "workspaces" / "workspace",
            app_root=app_root,
            artifacts_dir=local_temp / "bad-run",
        )


def test_configure_local_dumps_enables_full_dumps_for_emule_and_tools(monkeypatch, tmp_path: Path) -> None:
    module = load_harness_cli_common_module()
    registry: dict[str, dict[str, tuple[object, int]]] = {}

    class FakeKey:
        def __init__(self, subkey: str) -> None:
            self.subkey = subkey

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc, _tb) -> None:
            return None

    class FakeWinReg:
        HKEY_CURRENT_USER = object()
        HKEY_LOCAL_MACHINE = object()
        KEY_SET_VALUE = 0x0002
        REG_EXPAND_SZ = 2
        REG_DWORD = 4

        @staticmethod
        def key_name(root, subkey: str) -> str:
            return f"{id(root)}\\{subkey}"

        @staticmethod
        def OpenKey(root, subkey: str, *_args):
            subkey = FakeWinReg.key_name(root, subkey)
            if subkey not in registry:
                raise FileNotFoundError(subkey)
            return FakeKey(subkey)

        @staticmethod
        def CreateKeyEx(root, subkey: str, _reserved: int, _access: int):
            subkey = FakeWinReg.key_name(root, subkey)
            registry.setdefault(subkey, {})
            return FakeKey(subkey)

        @staticmethod
        def QueryValueEx(key: FakeKey, name: str):
            try:
                return registry[key.subkey][name]
            except KeyError as exc:
                raise FileNotFoundError(name) from exc

        @staticmethod
        def SetValueEx(key: FakeKey, name: str, _reserved: int, value_type: int, value) -> None:
            registry.setdefault(key.subkey, {})[name] = (value, value_type)

        @staticmethod
        def DeleteValue(key: FakeKey, name: str) -> None:
            try:
                del registry[key.subkey][name]
            except KeyError as exc:
                raise FileNotFoundError(name) from exc

        @staticmethod
        def DeleteKey(root, subkey: str) -> None:
            subkey = FakeWinReg.key_name(root, subkey)
            if registry.get(subkey):
                raise OSError("key is not empty")
            registry.pop(subkey, None)

    monkeypatch.setattr(module, "winreg", FakeWinReg)
    stale_dump_root = tmp_path / "state" / "live-e2e-artifacts" / "old-run" / "crash-dumps"
    for image_name in ("emule.exe", "umdh.exe", "procdump64.exe"):
        subkey = FakeWinReg.key_name(FakeWinReg.HKEY_CURRENT_USER, module.LOCAL_DUMPS_BASE_SUBKEY + "\\" + image_name)
        registry[subkey] = {
            "DumpFolder": (str(stale_dump_root), FakeWinReg.REG_EXPAND_SZ),
            "DumpType": (1, FakeWinReg.REG_DWORD),
        }

    result = module.configure_local_dumps(
        artifact_dir=tmp_path / "artifacts",
        app_exe=tmp_path / "emule.exe",
        tool_image_names=("umdh.exe", "procdump64.exe"),
    )

    assert result["enabled"] is True
    assert result["wer"]["enabled"] is True
    assert result["dump_count"] == 64
    assert result["dump_type"] == 2
    assert (tmp_path / "artifacts" / "crash-dumps").is_dir()
    assert result["image_names"] == ["emule.exe", "umdh.exe", "procdump64.exe"]
    for image_name in result["image_names"]:
        subkey = FakeWinReg.key_name(FakeWinReg.HKEY_CURRENT_USER, module.LOCAL_DUMPS_BASE_SUBKEY + "\\" + image_name)
        assert registry[subkey]["DumpFolder"][0] == str((tmp_path / "artifacts" / "crash-dumps").resolve())
        assert registry[subkey]["DumpFolder"][1] == FakeWinReg.REG_EXPAND_SZ
        assert registry[subkey]["DumpType"] == (2, FakeWinReg.REG_DWORD)
        assert registry[subkey]["DumpCount"] == (64, FakeWinReg.REG_DWORD)
    for entry in result["entries"]:
        assert entry["before"]["DumpFolder"] == {"present": True, "type": FakeWinReg.REG_EXPAND_SZ}
        assert str(stale_dump_root) not in json.dumps(entry["before"])
    wer_subkey = FakeWinReg.key_name(FakeWinReg.HKEY_CURRENT_USER, module.WER_BASE_SUBKEY)
    assert registry[wer_subkey]["Disabled"] == (0, FakeWinReg.REG_DWORD)


def test_cleanup_source_artifacts_restores_or_clears_local_dumps_registry(monkeypatch, tmp_path: Path) -> None:
    module = load_harness_cli_common_module()
    registry: dict[str, dict[str, tuple[object, int]]] = {}

    class FakeKey:
        def __init__(self, subkey: str) -> None:
            self.subkey = subkey

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc, _tb) -> None:
            return None

    class FakeWinReg:
        HKEY_CURRENT_USER = object()
        HKEY_LOCAL_MACHINE = object()
        KEY_SET_VALUE = 0x0002
        REG_EXPAND_SZ = 2
        REG_DWORD = 4

        @staticmethod
        def key_name(root, subkey: str) -> str:
            return f"{id(root)}\\{subkey}"

        @staticmethod
        def OpenKey(root, subkey: str, *_args):
            subkey = FakeWinReg.key_name(root, subkey)
            if subkey not in registry:
                raise FileNotFoundError(subkey)
            return FakeKey(subkey)

        @staticmethod
        def CreateKeyEx(root, subkey: str, _reserved: int, _access: int):
            subkey = FakeWinReg.key_name(root, subkey)
            registry.setdefault(subkey, {})
            return FakeKey(subkey)

        @staticmethod
        def QueryValueEx(key: FakeKey, name: str):
            try:
                return registry[key.subkey][name]
            except KeyError as exc:
                raise FileNotFoundError(name) from exc

        @staticmethod
        def SetValueEx(key: FakeKey, name: str, _reserved: int, value_type: int, value) -> None:
            registry.setdefault(key.subkey, {})[name] = (value, value_type)

        @staticmethod
        def DeleteValue(key: FakeKey, name: str) -> None:
            try:
                del registry[key.subkey][name]
            except KeyError as exc:
                raise FileNotFoundError(name) from exc

        @staticmethod
        def DeleteKey(root, subkey: str) -> None:
            subkey = FakeWinReg.key_name(root, subkey)
            if registry.get(subkey):
                raise OSError("key is not empty")
            registry.pop(subkey, None)

    monkeypatch.setattr(module, "winreg", FakeWinReg)
    artifact_dir = tmp_path / "state" / "test-artifacts" / "suite" / "run"
    artifact_dir.mkdir(parents=True)
    previous_external_dump = tmp_path / "operator-dumps"
    previous_harness_dump = tmp_path / "state" / "live-e2e-artifacts" / "old-run" / "crash-dumps"
    emule_subkey = FakeWinReg.key_name(FakeWinReg.HKEY_CURRENT_USER, module.LOCAL_DUMPS_BASE_SUBKEY + "\\emule.exe")
    tool_subkey = FakeWinReg.key_name(FakeWinReg.HKEY_CURRENT_USER, module.LOCAL_DUMPS_BASE_SUBKEY + "\\umdh.exe")
    registry[emule_subkey] = {
        "DumpFolder": (str(previous_external_dump), FakeWinReg.REG_EXPAND_SZ),
        "DumpType": (1, FakeWinReg.REG_DWORD),
    }
    registry[tool_subkey] = {
        "DumpFolder": (str(previous_harness_dump), FakeWinReg.REG_EXPAND_SZ),
        "DumpType": (1, FakeWinReg.REG_DWORD),
    }

    local_dumps = module.configure_local_dumps(
        artifact_dir=artifact_dir,
        app_exe=tmp_path / "emule.exe",
        tool_image_names=("umdh.exe",),
    )
    paths = module.HarnessRunPaths(
        repo_root=tmp_path,
        workspace_root=tmp_path,
        app_root=tmp_path,
        app_exe=tmp_path / "emule.exe",
        seed_config_dir=tmp_path,
        configuration="Release",
        suite_name="suite",
        source_artifacts_dir=artifact_dir,
        run_report_dir=tmp_path / "reports" / "suite" / "run",
        latest_report_dir=tmp_path / "reports" / "suite-latest",
        keep_source_artifacts=False,
        local_dumps=local_dumps,
    )

    module.cleanup_source_artifacts(paths)

    assert not artifact_dir.exists()
    assert registry[emule_subkey]["DumpFolder"] == (str(previous_external_dump), FakeWinReg.REG_EXPAND_SZ)
    assert registry[emule_subkey]["DumpType"] == (1, FakeWinReg.REG_DWORD)
    assert tool_subkey not in registry


def test_publish_run_artifacts_rewrites_json_paths_to_report_dir(tmp_path: Path) -> None:
    module = load_harness_cli_common_module()
    source_dir = tmp_path / "state" / "test-artifacts" / "suite" / "run"
    report_dir = tmp_path / "state" / "test-reports" / "suite" / "run"
    source_dir.mkdir(parents=True)
    (source_dir / "result.json").write_text(
        json.dumps(
            {
                "artifact_dir": str(report_dir),
                "source_artifact_dir": str(source_dir),
                "local_dumps": {
                    "dump_folder": str(source_dir / "crash-dumps"),
                    "entries": [
                        {
                            "after": {
                                "DumpFolder": {
                                    "value": str(source_dir / "crash-dumps"),
                                }
                            }
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    paths = module.HarnessRunPaths(
        repo_root=tmp_path,
        workspace_root=tmp_path / "workspaces" / "workspace",
        app_root=tmp_path / "app",
        app_exe=tmp_path / "app" / "emule.exe",
        seed_config_dir=tmp_path / "seed",
        configuration="Release",
        suite_name="suite",
        source_artifacts_dir=source_dir,
        run_report_dir=report_dir,
        latest_report_dir=tmp_path / "state" / "test-reports" / "suite-latest",
        keep_source_artifacts=False,
        local_dumps={},
    )

    module.publish_run_artifacts(paths)

    published = json.loads((report_dir / "result.json").read_text(encoding="utf-8"))
    assert published["source_artifact_dir"] == str(report_dir)
    assert published["local_dumps"]["dump_folder"] == str(report_dir / "crash-dumps")
    assert published["local_dumps"]["entries"][0]["after"]["DumpFolder"]["value"] == str(report_dir / "crash-dumps")
    assert str(source_dir) not in json.dumps(published)


def test_collect_local_dump_files_filters_configured_images(tmp_path: Path) -> None:
    module = load_harness_cli_common_module()
    dump_dir = tmp_path / "crash-dumps"
    dump_dir.mkdir()
    (dump_dir / "emule.exe.1234.dmp").write_bytes(b"product")
    (dump_dir / "umdh.exe.2222.dmp").write_bytes(b"tool")
    (dump_dir / "other.exe.3333.dmp").write_bytes(b"noise")

    summary = module.collect_local_dump_files(
        {
            "dump_folder": str(dump_dir),
            "image_names": ["emule.exe", "umdh.exe"],
        }
    )

    assert summary["count"] == 2
    assert [row["name"] for row in summary["files"]] == ["emule.exe.1234.dmp", "umdh.exe.2222.dmp"]
    assert [row["image_name"] for row in summary["files"]] == ["emule.exe", "umdh.exe"]
    assert summary["image_counts"] == {"emule.exe": 1, "umdh.exe": 1}
    assert summary["non_empty_image_counts"] == {"emule.exe": 1, "umdh.exe": 1}
    assert [row["name"] for row in module.local_dump_files_for_image(summary, "emule.exe")] == ["emule.exe.1234.dmp"]


def test_process_exited_with_access_violation_matches_windows_code() -> None:
    module = load_harness_cli_common_module()

    assert module.process_exited_with_access_violation({"exit_code": 0xC0000005})
    assert module.process_exited_with_access_violation({"exit_code": -1073741819})
    assert not module.process_exited_with_access_violation({"exit_code": 0})
