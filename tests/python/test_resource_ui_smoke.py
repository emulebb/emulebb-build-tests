from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


def load_resource_ui_smoke():
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "resource-ui-smoke.py"
    spec = importlib.util.spec_from_file_location("resource_ui_smoke", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["resource_ui_smoke"] = module
    spec.loader.exec_module(module)
    return module


def write_manifest(path: Path, languages: list[dict[str, str]]) -> Path:
    path.write_text(json.dumps({"languages": languages}), encoding="utf-8")
    return path


def test_release_language_manifest_uses_historical_dll_stems(tmp_path: Path) -> None:
    smoke = load_resource_ui_smoke()
    manifest = write_manifest(
        tmp_path / "rc-release-languages.json",
        [
            {"code": "cs_CZ", "name": "Czech", "rc": "cz_CZ.rc"},
            {"code": "ja_JP", "name": "Japanese", "rc": "jp_JP.rc"},
            {"code": "uk_UA", "name": "Ukrainian", "rc": "ua_UA.rc"},
        ],
    )

    languages = smoke.load_release_languages(manifest)

    assert [row["dll_stem"] for row in languages] == ["cz_CZ", "jp_JP", "ua_UA"]
    assert [row["language_id"] for row in languages] == [0x0405, 0x0411, 0x0422]


def test_language_id_table_covers_canonical_release_manifest() -> None:
    smoke = load_resource_ui_smoke()
    workspace_root = Path(__file__).resolve().parents[3]
    manifest = workspace_root / "eMule-tooling" / "helpers" / "rc-release-languages.json"

    languages = smoke.load_release_languages(manifest)

    assert len(languages) >= 40
    assert not [row for row in languages if row["dll_stem"] not in smoke.LANGUAGE_ID_BY_DLL_STEM]


def test_default_manifest_path_accepts_variant_workspace_root(tmp_path: Path) -> None:
    smoke = load_resource_ui_smoke()
    workspace_root = tmp_path / "workspaces" / "workspace"
    manifest = tmp_path / "repos" / "eMule-tooling" / "helpers" / "rc-release-languages.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"languages": []}', encoding="utf-8")

    assert smoke.default_release_languages_path(workspace_root, tmp_path / "repos" / "eMule-build-tests") == manifest


def test_release_scope_marks_missing_language_dlls_as_failed(tmp_path: Path) -> None:
    smoke = load_resource_ui_smoke()
    app_exe = tmp_path / "emule.exe"
    app_exe.write_text("", encoding="utf-8")
    languages = smoke.attach_language_dlls(
        [{"code": "it_IT", "name": "Italian", "rc": "it_IT.rc", "dll_stem": "it_IT", "language_id": 0x0410}],
        app_exe,
    )

    selected, missing = smoke.select_languages_for_scope(languages, "release")
    status = smoke.build_report_status(language_scope="release", missing_dlls=missing, language_results=[])

    assert selected == languages
    assert missing[0]["dll_stem"] == "it_IT"
    assert status == "failed"


def test_available_scope_filters_missing_language_dlls(tmp_path: Path) -> None:
    smoke = load_resource_ui_smoke()
    app_exe = tmp_path / "emule.exe"
    app_exe.write_text("", encoding="utf-8")
    (tmp_path / "it_IT.dll").write_text("", encoding="utf-8")
    languages = smoke.attach_language_dlls(
        [
            {"code": "it_IT", "name": "Italian", "rc": "it_IT.rc", "dll_stem": "it_IT", "language_id": 0x0410},
            {"code": "de_DE", "name": "German", "rc": "de_DE.rc", "dll_stem": "de_DE", "language_id": 0x0407},
        ],
        app_exe,
    )

    selected, missing = smoke.select_languages_for_scope(languages, "available")

    assert [row["dll_stem"] for row in selected] == ["it_IT"]
    assert [row["dll_stem"] for row in missing] == ["de_DE"]


def test_resource_report_fails_before_launching_when_release_dlls_are_missing(tmp_path: Path, monkeypatch) -> None:
    smoke = load_resource_ui_smoke()
    manifest = write_manifest(
        tmp_path / "rc-release-languages.json",
        [{"code": "it_IT", "name": "Italian", "rc": "it_IT.rc"}],
    )
    app_exe = tmp_path / "bin" / "emule.exe"
    app_exe.parent.mkdir()
    app_exe.write_text("", encoding="utf-8")
    paths = SimpleNamespace(
        configuration="Release",
        app_exe=app_exe,
        workspace_root=tmp_path,
        repo_root=tmp_path / "repo",
        source_artifacts_dir=tmp_path / "artifacts",
    )
    args = SimpleNamespace(
        profile_seed_dir=None,
        release_languages_json=str(manifest),
        language_scope="release",
        max_languages=None,
        skip_screenshots=True,
        language_timeout_seconds=30.0,
    )
    monkeypatch.setattr(smoke.harness_cli_common, "resolve_profile_seed_dir", lambda _paths, _value: tmp_path / "seed")

    report = smoke.run_resource_ui_smoke(paths, args)

    assert report["status"] == "failed"
    assert report["selected_language_count"] == 1
    assert report["missing_language_dlls"][0]["dll_stem"] == "it_IT"
    assert report["languages"] == []


def test_language_child_command_carries_isolated_language_contract(tmp_path: Path) -> None:
    smoke = load_resource_ui_smoke()
    app_root = tmp_path / "app"
    app_root.mkdir()
    app_exe = app_root / "emule.exe"
    app_exe.write_text("", encoding="utf-8")
    paths = SimpleNamespace(
        workspace_root=tmp_path / "workspaces" / "workspace",
        app_root=app_root,
        app_exe=app_exe,
        source_artifacts_dir=tmp_path / "artifacts",
        configuration="Release",
    )
    args = SimpleNamespace(
        profile_seed_dir=tmp_path / "seed",
        language_scope="release",
        skip_screenshots=True,
    )
    result_path = tmp_path / "artifacts" / "languages" / "de_DE" / "language-result.json"

    command = smoke.build_language_child_command(
        paths=paths,
        args=args,
        manifest_path=tmp_path / "rc-release-languages.json",
        language={"dll_stem": "de_DE"},
        result_path=result_path,
    )

    assert command[0] == sys.executable
    assert "--single-language-dll-stem" in command
    assert command[command.index("--single-language-dll-stem") + 1] == "de_DE"
    assert command[command.index("--single-language-output-json") + 1] == str(result_path)
    assert "--profile-seed-dir" in command
    assert "--skip-screenshots" in command


def test_language_subprocess_timeout_records_failure_and_kills_process_tree(tmp_path: Path, monkeypatch) -> None:
    smoke = load_resource_ui_smoke()
    language = {
        "code": "ar_AE",
        "name": "Arabic",
        "rc": "ar_AE.rc",
        "dll_stem": "ar_AE",
        "language_id": 0x3801,
        "dll_path": str(tmp_path / "ar_AE.dll"),
    }
    paths = SimpleNamespace(
        workspace_root=tmp_path,
        app_root=tmp_path / "app",
        app_exe=tmp_path / "app" / "emule.exe",
        source_artifacts_dir=tmp_path / "artifacts",
        configuration="Release",
    )
    args = SimpleNamespace(
        profile_seed_dir=None,
        language_scope="release",
        skip_screenshots=True,
        language_timeout_seconds=1.0,
    )
    kill_commands: list[list[str]] = []

    class FakeProcess:
        pid = 1234
        returncode: int | None = None

        def __init__(self) -> None:
            self.calls = 0

        def communicate(self, timeout: float | None = None):
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired(cmd=["resource-ui-smoke.py"], timeout=timeout or 0.0, output="before", stderr="blocked")
            self.returncode = -9
            return "after", "terminated"

    def fake_run(command, **_kwargs):
        kill_commands.append(command)
        return SimpleNamespace(returncode=0, stdout="killed", stderr="")

    monkeypatch.setattr(smoke.sys, "platform", "win32")
    monkeypatch.setattr(smoke.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(smoke.subprocess, "run", fake_run)

    result = smoke.run_language_subprocess(
        language=language,
        paths=paths,
        args=args,
        manifest_path=tmp_path / "rc-release-languages.json",
        output_root=tmp_path / "artifacts" / "languages",
    )

    assert result["status"] == "failed"
    assert result["error"]["type"] == "LanguageSmokeTimeout"
    assert result["child_process"]["returncode"] == -9
    assert kill_commands == [["taskkill", "/PID", "1234", "/T", "/F"]]
    result_file = tmp_path / "artifacts" / "languages" / "ar_AE" / "language-result.json"
    assert json.loads(result_file.read_text(encoding="utf-8"))["error"]["type"] == "LanguageSmokeTimeout"
