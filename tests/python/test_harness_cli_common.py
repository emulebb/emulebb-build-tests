from __future__ import annotations

import importlib.util
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
        def OpenKey(root, subkey: str):
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

    monkeypatch.setattr(module, "winreg", FakeWinReg)

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
    wer_subkey = FakeWinReg.key_name(FakeWinReg.HKEY_CURRENT_USER, module.WER_BASE_SUBKEY)
    assert registry[wer_subkey]["Disabled"] == (0, FakeWinReg.REG_DWORD)


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
    assert [row["name"] for row in module.local_dump_files_for_image(summary, "emule.exe")] == ["emule.exe.1234.dmp"]


def test_process_exited_with_access_violation_matches_windows_code() -> None:
    module = load_harness_cli_common_module()

    assert module.process_exited_with_access_violation({"exit_code": 0xC0000005})
    assert not module.process_exited_with_access_violation({"exit_code": 0})
