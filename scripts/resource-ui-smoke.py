"""Resource and language UI smoke coverage for release builds."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import win32con
import win32gui
import win32process

try:
    from pywinauto import Application
except ModuleNotFoundError:  # pragma: no cover - checked by live_common at runtime
    Application = object  # type: ignore[assignment]


def load_local_module(module_name: str, filename: str):
    """Loads one sibling helper module from a hyphenated script filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


live_common = load_local_module("emule_live_profile_common", "emule-live-profile-common.py")
harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")
preference_ui = load_local_module("preference_ui_e2e", "preference-ui-e2e.py")

WM_COMMAND = 0x0111
MP_HM_TRANSFER = 10211
MP_HM_SEARCH = 10212
MP_HM_FILES = 10213
MP_HM_STATS = 10216
MP_HM_PREFS = 10217
MP_HM_KAD = 10229
IDCANCEL = 2
PAGE_TREE_ID = 0x7EEE

MIN_PREFERENCE_TREE_ITEMS = 8
DEFAULT_LANGUAGE_TIMEOUT_SECONDS = 120.0
PROCESS_OUTPUT_TAIL_CHARS = 4000
VIEW_COMMANDS = (
    ("transfer", MP_HM_TRANSFER),
    ("search", MP_HM_SEARCH),
    ("shared_files", MP_HM_FILES),
    ("statistics", MP_HM_STATS),
    ("kad", MP_HM_KAD),
)

LANGUAGE_ID_BY_DLL_STEM = {
    "ar_AE": 0x3801,
    "ba_BA": 0x042D,
    "bg_BG": 0x0402,
    "ca_ES": 0x0403,
    "cz_CZ": 0x0405,
    "da_DK": 0x0406,
    "de_DE": 0x0407,
    "el_GR": 0x0408,
    "es_AS": 0x0901,
    "es_ES_T": 0x040A,
    "et_EE": 0x0425,
    "fa_IR": 0x0429,
    "fi_FI": 0x040B,
    "fr_BR": 0x047E,
    "fr_FR": 0x040C,
    "gl_ES": 0x0456,
    "he_IL": 0x040D,
    "hu_HU": 0x040E,
    "it_IT": 0x0410,
    "jp_JP": 0x0411,
    "ko_KR": 0x0412,
    "lt_LT": 0x0427,
    "lv_LV": 0x0426,
    "mt_MT": 0x043A,
    "nb_NO": 0x0414,
    "nl_NL": 0x0413,
    "nn_NO": 0x0814,
    "pl_PL": 0x0415,
    "pt_BR": 0x0416,
    "pt_PT": 0x0816,
    "ro_RO": 0x0418,
    "ru_RU": 0x0419,
    "sl_SI": 0x0424,
    "sq_AL": 0x041C,
    "sv_SE": 0x041D,
    "tr_TR": 0x041F,
    "ua_UA": 0x0422,
    "ug_CN": 0x0480,
    "va_ES": 0x0902,
    "va_ES_RACV": 0x0903,
    "vi_VN": 0x042A,
    "zh_CN": 0x0804,
    "zh_TW": 0x0404,
}


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def tail_process_output(value: str | bytes | None) -> str:
    """Returns a bounded text tail for child process diagnostic fields."""

    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if len(value) <= PROCESS_OUTPUT_TAIL_CHARS:
        return value
    return value[-PROCESS_OUTPUT_TAIL_CHARS:]


def canonical_workspace_root(workspace_root: Path) -> Path:
    if workspace_root.name == "workspace" and workspace_root.parent.name == "workspaces":
        return workspace_root.parent.parent
    return workspace_root


def default_release_languages_path(workspace_root: Path, repo_root: Path) -> Path:
    workspace_candidate = canonical_workspace_root(workspace_root) / "repos" / "emulebb-tooling" / "helpers" / "rc-release-languages.json"
    if workspace_candidate.is_file():
        return workspace_candidate
    return (repo_root.parent / "emulebb-tooling" / "helpers" / "rc-release-languages.json").resolve()


def load_release_languages(manifest_path: Path) -> list[dict[str, object]]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    languages = payload.get("languages")
    if not isinstance(languages, list) or not languages:
        raise ValueError(f"Release language manifest has no languages array: {manifest_path}")

    normalized: list[dict[str, object]] = []
    missing_ids: list[str] = []
    for row in languages:
        if not isinstance(row, dict):
            raise ValueError(f"Invalid language row in {manifest_path}: {row!r}")
        rc_name = str(row.get("rc") or "").strip()
        code = str(row.get("code") or "").strip()
        name = str(row.get("name") or code).strip()
        if not rc_name.endswith(".rc"):
            raise ValueError(f"Language {code!r} has invalid rc name {rc_name!r}.")
        dll_stem = rc_name[:-3]
        language_id = LANGUAGE_ID_BY_DLL_STEM.get(dll_stem)
        if language_id is None:
            missing_ids.append(dll_stem)
            continue
        normalized.append(
            {
                "code": code,
                "name": name,
                "rc": rc_name,
                "dll_stem": dll_stem,
                "language_id": language_id,
            }
        )
    if missing_ids:
        raise ValueError(f"Missing language ID mappings for release language DLLs: {missing_ids!r}")
    return normalized


def resolve_language_dll(app_exe: Path, dll_stem: str) -> Path | None:
    dll_name = f"{dll_stem}.dll"
    candidates = (
        app_exe.parent / dll_name,
        app_exe.parent / "lang" / dll_name,
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def attach_language_dlls(languages: list[dict[str, object]], app_exe: Path) -> list[dict[str, object]]:
    enriched: list[dict[str, object]] = []
    for language in languages:
        row = dict(language)
        dll_path = resolve_language_dll(app_exe, str(row["dll_stem"]))
        row["dll_path"] = str(dll_path) if dll_path is not None else None
        row["dll_present"] = dll_path is not None
        enriched.append(row)
    return enriched


def select_languages_for_scope(languages: list[dict[str, object]], language_scope: str) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    missing = [row for row in languages if not row.get("dll_present")]
    if language_scope == "available":
        return [row for row in languages if row.get("dll_present")], missing
    return languages, missing


def configure_language_profile(config_dir: Path, language_id: int) -> None:
    live_common.apply_emule_preferences(
        config_dir,
        (
            ("Language", str(language_id)),
            ("ConfirmExit", "0"),
            ("Autoconnect", "0"),
            ("Reconnect", "0"),
            ("NetworkED2K", "0"),
            ("NetworkKademlia", "0"),
            ("StartupMinimized", "0"),
            ("MinToTray", "0"),
            ("AlwaysShowTrayIcon", "0"),
            ("IPFilterEnabled", "0"),
            ("IPFilterUpdateEnabled", "0"),
        ),
    )


def read_top_menu_labels(main_hwnd: int) -> list[str]:
    menu = win32gui.GetMenu(main_hwnd)
    if not menu:
        return []
    labels: list[str] = []
    count = win32gui.GetMenuItemCount(menu)
    for index in range(count):
        labels.append(win32gui.GetMenuString(menu, index, win32con.MF_BYPOSITION))
    return labels


def send_view_command(main_hwnd: int, command_id: int) -> None:
    win32gui.PostMessage(main_hwnd, WM_COMMAND, command_id, 0)
    time.sleep(0.25)


def get_process_id(main_hwnd: int) -> int:
    return int(win32process.GetWindowThreadProcessId(main_hwnd)[1])


def smoke_one_language(
    *,
    language: dict[str, object],
    paths,
    seed_config_dir: Path,
    output_root: Path,
    capture_screenshots: bool,
) -> dict[str, object]:
    dll_stem = str(language["dll_stem"])
    language_dir = output_root / dll_stem
    language_dir.mkdir(parents=True, exist_ok=True)
    profile = live_common.prepare_scenario_profile(
        seed_config_dir=seed_config_dir,
        artifacts_dir=output_root.parent,
        shared_dirs=[],
        scenario_id=dll_stem,
    )
    config_dir = Path(str(profile["config_dir"]))
    configure_language_profile(config_dir, int(language["language_id"]))

    result: dict[str, object] = {
        "code": language["code"],
        "name": language["name"],
        "rc": language["rc"],
        "dll_stem": dll_stem,
        "language_id": language["language_id"],
        "dll_path": language.get("dll_path"),
        "profile_base": str(profile["profile_base"]),
        "status": "failed",
    }
    app: Application | None = None
    dialog_hwnd: int | None = None
    main_hwnd: int | None = None
    try:
        app = live_common.launch_app(
            paths.app_exe,
            Path(str(profile["profile_base"])),
            minimized_to_tray=False,
            requires_interactive_ui=True,
        )
        main_window = live_common.wait_for_main_window(app, timeout=90.0, require_visible=True)
        live_common.bring_window_to_front(main_window)
        main_hwnd = int(main_window.handle)
        result["main_window_title"] = win32gui.GetWindowText(main_hwnd)
        result["main_window_class"] = win32gui.GetClassName(main_hwnd)

        menu_labels = [label for label in read_top_menu_labels(main_hwnd) if label]
        result["top_menu_labels"] = menu_labels
        result["top_menu_handle_available"] = bool(menu_labels)

        command_results: list[dict[str, object]] = []
        for label, command_id in VIEW_COMMANDS:
            send_view_command(main_hwnd, command_id)
            command_results.append({"name": label, "command_id": command_id, "sent": True})
        result["view_commands"] = command_results

        process_id = get_process_id(main_hwnd)
        send_view_command(main_hwnd, MP_HM_PREFS)
        dialog_hwnd = preference_ui.wait_for_preferences_dialog(process_id, main_hwnd)
        page_tree = preference_ui.find_control(dialog_hwnd, PAGE_TREE_ID, "SysTreeView32")
        tree_texts = [text for text in preference_ui.collect_tree_texts(page_tree) if text]
        result["preference_tree_count"] = len(tree_texts)
        result["preference_tree_sample"] = tree_texts[:12]
        if len(tree_texts) < MIN_PREFERENCE_TREE_ITEMS:
            raise AssertionError(f"Expected at least {MIN_PREFERENCE_TREE_ITEMS} Preferences tree entries, got {tree_texts!r}.")
        if capture_screenshots:
            try:
                result["preferences_screenshot"] = preference_ui.capture_dialog_screenshot(
                    app,
                    dialog_hwnd,
                    language_dir / "screenshots" / "preferences.png",
                )
            except Exception as capture_exc:
                result["preferences_screenshot_error"] = repr(capture_exc)
        preference_ui.click_button(preference_ui.find_control(dialog_hwnd, IDCANCEL, "Button"))
        live_common.wait_for(
            lambda: not win32gui.IsWindow(dialog_hwnd),
            timeout=15.0,
            interval=0.2,
            description=f"{dll_stem} Preferences close",
        )
        dialog_hwnd = None
        result["status"] = "passed"
    except Exception as exc:
        result["status"] = "failed"
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
        if main_hwnd and win32gui.IsWindow(main_hwnd):
            tree_path = language_dir / "window-tree.json"
            try:
                live_common.dump_window_tree(main_hwnd, tree_path)
                result["window_tree"] = str(tree_path)
            except Exception as dump_exc:
                result["window_tree_error"] = repr(dump_exc)
        if capture_screenshots and app is not None:
            screenshot_path = language_dir / "screenshots" / "failure.png"
            try:
                app.top_window().capture_as_image().save(screenshot_path)
                result["failure_screenshot"] = str(screenshot_path)
            except Exception as capture_exc:
                result["failure_screenshot_error"] = repr(capture_exc)
    finally:
        if dialog_hwnd is not None and win32gui.IsWindow(dialog_hwnd):
            try:
                preference_ui.click_button(preference_ui.find_control(dialog_hwnd, IDCANCEL, "Button"))
            except Exception:
                pass
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
                result["app_closed"] = True
            except Exception as close_exc:
                result["app_closed"] = False
                result["app_close_error"] = repr(close_exc)
                if result.get("status") == "passed":
                    result["status"] = "failed"
                    result["error"] = {"type": type(close_exc).__name__, "message": str(close_exc)}
    return result


def build_language_failure_result(
    language: dict[str, object],
    *,
    error_type: str,
    message: str,
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    """Builds one failed language row without requiring an in-process app launch."""

    result: dict[str, object] = {
        "code": language.get("code"),
        "name": language.get("name"),
        "rc": language.get("rc"),
        "dll_stem": language.get("dll_stem"),
        "language_id": language.get("language_id"),
        "dll_path": language.get("dll_path"),
        "status": "failed",
        "error": {
            "type": error_type,
            "message": message,
        },
    }
    if extra:
        result.update(extra)
    return result


def build_language_child_command(
    *,
    paths,
    args: argparse.Namespace,
    manifest_path: Path,
    language: dict[str, object],
    result_path: Path,
) -> list[str]:
    """Builds the isolated subprocess command for one resource language row."""

    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--app-root",
        str(paths.app_root),
        "--app-exe",
        str(paths.app_exe),
        "--artifacts-dir",
        str(paths.source_artifacts_dir),
        "--configuration",
        str(paths.configuration),
        "--release-languages-json",
        str(manifest_path),
        "--language-scope",
        str(args.language_scope),
        "--single-language-dll-stem",
        str(language["dll_stem"]),
        "--single-language-output-json",
        str(result_path),
    ]
    if args.profile_seed_dir:
        command.extend(["--profile-seed-dir", str(args.profile_seed_dir)])
    if args.skip_screenshots:
        command.append("--skip-screenshots")
    return command


def kill_process_tree(process_id: int) -> dict[str, object]:
    """Terminates one child process tree after a language timeout."""

    if sys.platform == "win32":
        completed = subprocess.run(
            ["taskkill", "/PID", str(process_id), "/T", "/F"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return {
            "command": "taskkill",
            "returncode": completed.returncode,
            "stdout_tail": tail_process_output(completed.stdout),
            "stderr_tail": tail_process_output(completed.stderr),
        }
    return {"command": "unsupported", "message": "Process-tree cleanup is only implemented for Windows live UI runs."}


def run_language_subprocess(
    *,
    language: dict[str, object],
    paths,
    args: argparse.Namespace,
    manifest_path: Path,
    output_root: Path,
) -> dict[str, object]:
    """Runs one language smoke row in an isolated child process with a hard timeout."""

    dll_stem = str(language["dll_stem"])
    result_path = output_root / dll_stem / "language-result.json"
    command = build_language_child_command(
        paths=paths,
        args=args,
        manifest_path=manifest_path,
        language=language,
        result_path=result_path,
    )
    timeout_seconds = float(args.language_timeout_seconds)
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        timed_out = False
        kill_result: dict[str, object] | None = None
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        kill_result = kill_process_tree(int(process.pid))
        try:
            stdout, stderr = process.communicate(timeout=10.0)
        except subprocess.TimeoutExpired:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""

    child_process = {
        "returncode": process.returncode,
        "timeout_seconds": timeout_seconds,
        "stdout_tail": tail_process_output(stdout),
        "stderr_tail": tail_process_output(stderr),
    }
    if timed_out:
        child_process["termination"] = kill_result
        result = build_language_failure_result(
            language,
            error_type="LanguageSmokeTimeout",
            message=f"{dll_stem} resource UI smoke exceeded {timeout_seconds:.1f} seconds.",
            extra={"child_process": child_process},
        )
        write_json(result_path, result)
        return result

    if result_path.is_file():
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["child_process"] = child_process
        write_json(result_path, result)
        return result

    result = build_language_failure_result(
        language,
        error_type="LanguageSmokeChildProcessFailure",
        message=f"{dll_stem} child process exited without writing a language result.",
        extra={"child_process": child_process},
    )
    write_json(result_path, result)
    return result


def make_child_run_paths(args: argparse.Namespace):
    """Resolves the minimal run-path contract for one single-language child."""

    repo_root = harness_cli_common.get_repo_root(__file__)
    workspace_root, app_root, app_exe = harness_cli_common.resolve_app_executable(
        repo_root=repo_root,
        configuration=args.configuration,
        workspace_root=Path(args.workspace_root).resolve() if args.workspace_root else None,
        app_root=args.app_root,
        app_exe=args.app_exe,
    )
    seed_config_dir = (repo_root / "manifests" / "live-profile-seed" / "config").resolve()
    if not seed_config_dir.is_dir():
        raise RuntimeError(f"Seed config directory was not found at '{seed_config_dir}'.")
    if not args.artifacts_dir:
        raise RuntimeError("--artifacts-dir is required for isolated resource UI language children.")
    source_artifacts_dir = Path(args.artifacts_dir).resolve()
    return harness_cli_common.HarnessRunPaths(
        repo_root=repo_root,
        workspace_root=workspace_root,
        app_root=app_root,
        app_exe=app_exe,
        seed_config_dir=seed_config_dir,
        configuration=args.configuration,
        suite_name="resource-ui-smoke",
        source_artifacts_dir=source_artifacts_dir,
        run_report_dir=source_artifacts_dir,
        latest_report_dir=source_artifacts_dir,
        keep_source_artifacts=True,
        local_dumps={},
    )


def run_single_language_child(args: argparse.Namespace) -> int:
    """Runs and writes the result for one isolated resource language child."""

    if not args.single_language_output_json:
        raise RuntimeError("--single-language-output-json is required with --single-language-dll-stem.")
    paths = make_child_run_paths(args)
    manifest_path = (
        Path(args.release_languages_json).resolve()
        if args.release_languages_json
        else default_release_languages_path(paths.workspace_root, paths.repo_root)
    )
    languages = attach_language_dlls(load_release_languages(manifest_path), paths.app_exe)
    matches = [row for row in languages if row.get("dll_stem") == args.single_language_dll_stem]
    if not matches:
        raise RuntimeError(f"Release language DLL stem was not found in manifest: {args.single_language_dll_stem!r}")
    language = matches[0]
    if not language.get("dll_present"):
        result = build_language_failure_result(
            language,
            error_type="MissingLanguageDll",
            message=f"{args.single_language_dll_stem} DLL is missing next to the app executable.",
        )
    else:
        seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
        result = smoke_one_language(
            language=language,
            paths=paths,
            seed_config_dir=seed_config_dir,
            output_root=paths.source_artifacts_dir / "languages",
            capture_screenshots=not args.skip_screenshots,
        )
    write_json(Path(args.single_language_output_json).resolve(), result)
    return 0 if result.get("status") == "passed" else 1


def build_report_status(
    *,
    language_scope: str,
    missing_dlls: list[dict[str, object]],
    language_results: list[dict[str, object]],
) -> str:
    if language_scope == "release" and missing_dlls:
        return "failed"
    if not language_results:
        return "failed"
    if any(row.get("status") != "passed" for row in language_results):
        return "failed"
    return "passed"


def run_resource_ui_smoke(paths, args: argparse.Namespace) -> dict[str, object]:
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    manifest_path = (
        Path(args.release_languages_json).resolve()
        if args.release_languages_json
        else default_release_languages_path(paths.workspace_root, paths.repo_root)
    )
    languages = attach_language_dlls(load_release_languages(manifest_path), paths.app_exe)
    selected_languages, missing_dlls = select_languages_for_scope(languages, args.language_scope)
    if args.max_languages is not None:
        selected_languages = selected_languages[: args.max_languages]

    report: dict[str, object] = {
        "suite": "resource-ui-smoke",
        "status": "failed",
        "configuration": paths.configuration,
        "app_exe": str(paths.app_exe),
        "release_languages_json": str(manifest_path),
        "language_scope": args.language_scope,
        "language_count": len(languages),
        "selected_language_count": len(selected_languages),
        "missing_language_dlls": [
            {
                "code": row["code"],
                "name": row["name"],
                "rc": row["rc"],
                "dll_stem": row["dll_stem"],
            }
            for row in missing_dlls
        ],
        "checks": {
            "release_manifest_loaded": True,
            "language_id_mapping_complete": True,
            "ui_resource_failures_are_hard_failures": True,
            "language_rows_are_process_isolated": True,
        },
        "language_timeout_seconds": float(args.language_timeout_seconds),
        "languages": [],
    }
    if args.language_scope == "release" and missing_dlls:
        report["status"] = "failed"
        report["error"] = {
            "type": "MissingLanguageDlls",
            "message": f"{len(missing_dlls)} release language DLLs are missing next to the app executable.",
        }
        return report

    output_root = paths.source_artifacts_dir / "languages"
    for language in selected_languages:
        language_result = run_language_subprocess(
            language=language,
            paths=paths,
            args=args,
            manifest_path=manifest_path,
            output_root=output_root,
        )
        report["languages"].append(language_result)  # type: ignore[index]
        if args.fail_fast_languages and language_result.get("status") != "passed":
            break

    report["status"] = build_report_status(
        language_scope=args.language_scope,
        missing_dlls=missing_dlls,
        language_results=list(report["languages"]),  # type: ignore[arg-type]
    )
    if report["status"] != "passed":
        failures = [row for row in report["languages"] if row.get("status") != "passed"]  # type: ignore[union-attr]
        report["error"] = {
            "type": "ResourceUiSmokeFailure",
            "message": f"{len(failures)} language UI smoke rows failed.",
        }
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--release-languages-json")
    parser.add_argument("--language-scope", choices=["release", "available"], default="release")
    parser.add_argument("--max-languages", type=int)
    parser.add_argument("--skip-screenshots", action="store_true")
    parser.add_argument("--language-timeout-seconds", type=float, default=DEFAULT_LANGUAGE_TIMEOUT_SECONDS)
    parser.add_argument("--fail-fast-languages", action="store_true")
    parser.add_argument("--single-language-dll-stem", help=argparse.SUPPRESS)
    parser.add_argument("--single-language-output-json", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.single_language_dll_stem:
        return run_single_language_child(args)

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="resource-ui-smoke",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )

    report_path = paths.source_artifacts_dir / "resource-ui-smoke-summary.json"
    report: dict[str, object] | None = None
    try:
        report = run_resource_ui_smoke(paths, args)
        write_json(report_path, report)
        if report.get("status") != "passed":
            raise RuntimeError(f"Resource UI smoke failed: {report.get('error')!r}")
    except Exception as exc:
        if report is None:
            report = {"suite": "resource-ui-smoke", "status": "failed"}
        report.setdefault("error", {"type": type(exc).__name__, "message": str(exc)})
        write_json(report_path, report)
        raise
    finally:
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        if not paths.keep_source_artifacts:
            shutil.rmtree(paths.source_artifacts_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
