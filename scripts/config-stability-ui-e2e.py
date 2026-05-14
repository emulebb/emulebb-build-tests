"""Real Win32 UI regression for long `-c` config paths, settings save, and relaunch stability."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

import win32con
import win32gui
import win32process

try:
    from pywinauto import Application
    _PYWINAUTO_IMPORT_ERROR = None
except ModuleNotFoundError as exc:  # pragma: no cover - environment dependent
    Application = object  # type: ignore[assignment]
    _PYWINAUTO_IMPORT_ERROR = exc


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
generated_fixture = load_local_module("create_long_paths_tree", "create-long-paths-tree.py")

WM_COMMAND = 0x0111
BM_CLICK = 0x00F5
BM_GETCHECK = 0x00F0
BST_CHECKED = 0x0001

MP_HM_PREFS = 10217
MP_HM_FILES = 10213

IDOK = 1
IDCANCEL = 2
IDC_APPLY_NOW = 0x3021
IDC_ONLINESIG = 2447


def parse_ini_values(text: str) -> dict[str, str]:
    """Parses one simple INI text blob into key/value pairs."""

    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("[") or line.startswith(";") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def get_ini_value(path: Path, key: str) -> str | None:
    """Reads one key from the persisted preferences.ini file."""

    if not path.exists():
        return None
    return parse_ini_values(live_common.read_ini_text(path)).get(key)


def build_long_artifacts_root(root: Path, scenario_name: str) -> Path:
    """Returns one deterministically deep artifacts root whose profile base exceeds MAX_PATH."""

    current = root / "long-config-root"
    index = 0
    target_length = 320
    while len(str((current / "profile-base" / "config" / "preferences.ini").resolve())) < target_length:
        current = current / f"{scenario_name}-segment-{index:02d}-abcdefghij-klmnopqrst-uvwxyz"
        index += 1
    current.mkdir(parents=True, exist_ok=True)
    return current


def build_small_shared_fixture(root: Path) -> list[str]:
    """Creates a deterministic small shared fixture for the settings roundtrip scenario."""

    shared_a_dir = root / "shared-a"
    shared_b_dir = root / "shared-b"
    shared_a_dir.mkdir(parents=True, exist_ok=True)
    shared_b_dir.mkdir(parents=True, exist_ok=True)
    (shared_a_dir / "middle_small.txt").write_bytes(b"small\n")
    (shared_a_dir / "zeta_large.bin").write_bytes(b"z" * 4096)
    (shared_b_dir / "alpha_medium.txt").write_bytes(b"a" * 600)
    return [
        live_common.win_path(shared_a_dir, trailing_slash=True),
        live_common.win_path(shared_b_dir, trailing_slash=True),
    ]


def write_json(path: Path, payload) -> None:
    """Writes one UTF-8 JSON artifact with stable formatting."""

    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def get_main_process_id(app: Application) -> int:
    """Resolves the current main-window process id."""

    main_window = live_common.wait_for_main_window(app)
    return int(win32process.GetWindowThreadProcessId(main_window.handle)[1])


def enum_descendants(root_hwnd: int) -> list[int]:
    """Collects one flat list of descendant HWNDs."""

    results: list[int] = []

    def callback(hwnd: int, _lparam: int) -> bool:
        results.append(hwnd)
        return True

    win32gui.EnumChildWindows(root_hwnd, callback, 0)
    return results


def find_control(root_hwnd: int, control_id: int, class_name: str | None = None) -> int:
    """Finds one descendant control by dialog id and optional Win32 class name."""

    for hwnd in enum_descendants(root_hwnd):
        try:
            if win32gui.GetDlgCtrlID(hwnd) != control_id:
                continue
        except win32gui.error:
            continue
        if class_name and win32gui.GetClassName(hwnd) != class_name:
            continue
        return hwnd
    raise RuntimeError(f"Control id {control_id} was not found under hwnd={root_hwnd}.")


def wait_for_preferences_dialog(process_id: int, main_hwnd: int) -> int:
    """Waits for the visible top-level Preferences dialog created by the running app."""

    def resolve() -> int | None:
        matches: list[int] = []

        def callback(hwnd: int, _lparam: int) -> bool:
            if hwnd == main_hwnd or not win32gui.IsWindowVisible(hwnd):
                return True
            if win32gui.GetClassName(hwnd) != "#32770":
                return True
            if int(win32process.GetWindowThreadProcessId(hwnd)[1]) != process_id:
                return True
            matches.append(hwnd)
            return True

        win32gui.EnumWindows(callback, 0)
        if not matches:
            return None
        for hwnd in matches:
            title = win32gui.GetWindowText(hwnd)
            if "Preferences" in title:
                return hwnd
        for hwnd in matches:
            try:
                find_control(hwnd, IDC_ONLINESIG, "Button")
                return hwnd
            except RuntimeError:
                continue
        return matches[0]

    return live_common.wait_for(resolve, timeout=20.0, interval=0.2, description="Preferences dialog")


def wait_for_dialog_close(dialog_hwnd: int) -> None:
    """Waits until one top-level dialog handle is destroyed."""

    live_common.wait_for(
        lambda: not win32gui.IsWindow(dialog_hwnd),
        timeout=20.0,
        interval=0.2,
        description="Preferences dialog close",
    )


def open_preferences(main_hwnd: int, process_id: int) -> int:
    """Opens the Preferences dialog from the main window and returns its handle."""

    win32gui.PostMessage(main_hwnd, WM_COMMAND, MP_HM_PREFS, 0)
    return wait_for_preferences_dialog(process_id, main_hwnd)


def get_checkbox_state(checkbox_hwnd: int) -> bool:
    """Returns one Win32 checkbox state."""

    return bool(win32gui.SendMessage(checkbox_hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED)


def click_button(button_hwnd: int) -> None:
    """Clicks one Win32 pushbutton/checkbox and yields briefly for message processing."""

    win32gui.PostMessage(button_hwnd, BM_CLICK, 0, 0)
    time.sleep(0.2)


def wait_for_ini_value(path: Path, key: str, expected: str) -> None:
    """Polls until one persisted INI key reaches the expected value."""

    live_common.wait_for(
        lambda: get_ini_value(path, key) == expected,
        timeout=20.0,
        interval=0.2,
        description=f"{path.name} {key}={expected}",
    )


def set_online_signature(dialog_hwnd: int, desired: bool) -> bool:
    """Sets the OnlineSignature checkbox to the requested state and returns the prior state."""

    checkbox_hwnd = find_control(dialog_hwnd, IDC_ONLINESIG, "Button")
    prior = get_checkbox_state(checkbox_hwnd)
    if prior != desired:
        click_button(checkbox_hwnd)
    current = get_checkbox_state(checkbox_hwnd)
    if current != desired:
        raise RuntimeError(f"OnlineSignature checkbox expected {desired}, got {current}.")
    return prior


def save_preferences(dialog_hwnd: int) -> None:
    """Saves the active Preferences page through the real dialog buttons."""

    ok_button_hwnd = find_control(dialog_hwnd, IDOK, "Button")
    click_button(ok_button_hwnd)
    wait_for_dialog_close(dialog_hwnd)


def cancel_preferences(dialog_hwnd: int) -> None:
    """Cancels the Preferences dialog without saving new edits."""

    cancel_button_hwnd = find_control(dialog_hwnd, IDCANCEL, "Button")
    click_button(cancel_button_hwnd)
    wait_for_dialog_close(dialog_hwnd)


def verify_preferences_value(main_hwnd: int, process_id: int, expected: bool) -> None:
    """Reopens Preferences and asserts the OnlineSignature checkbox state."""

    dialog_hwnd = open_preferences(main_hwnd, process_id)
    checkbox_hwnd = find_control(dialog_hwnd, IDC_ONLINESIG, "Button")
    current = get_checkbox_state(checkbox_hwnd)
    if current != expected:
        raise RuntimeError(f"Expected OnlineSignature checkbox state {expected}, got {current}.")
    cancel_preferences(dialog_hwnd)


def build_fixture(
    *,
    seed_config_dir: Path,
    scenario_dir: Path,
    shared_dirs: list[str],
) -> dict[str, object]:
    """Creates one isolated profile base under a deliberately long config-root path."""

    long_root = build_long_artifacts_root(scenario_dir, scenario_dir.name)
    fixture = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=long_root,
        shared_dirs=shared_dirs,
    )
    preferences_path = Path(str(fixture["config_dir"])) / "preferences.ini"
    return {
        **fixture,
        "long_root": long_root,
        "preferences_path": preferences_path,
        "profile_base_length": len(str(Path(str(fixture["profile_base"])).resolve())),
        "config_dir_length": len(str(Path(str(fixture["config_dir"])).resolve())),
        "preferences_ini_length": len(str(preferences_path.resolve())),
    }


def prepare_roundtrip_fixture(seed_config_dir: Path, scenario_dir: Path) -> dict[str, object]:
    """Builds the small deterministic roundtrip fixture under a long config path."""

    shared_dirs = build_small_shared_fixture(scenario_dir / "data")
    return build_fixture(seed_config_dir=seed_config_dir, scenario_dir=scenario_dir, shared_dirs=shared_dirs)


def prepare_stress_fixture(seed_config_dir: Path, scenario_dir: Path, shared_root: Path) -> dict[str, object]:
    """Builds the recursive stress fixture under a long config path."""

    manifest = generated_fixture.ensure_fixture(shared_root)
    subtree = manifest["subtrees"]["shared_files_robustness"]
    subtree_root = Path(str(subtree["root"])).resolve()
    shared_dirs = live_common.enumerate_recursive_directories(subtree_root)
    fixture = build_fixture(seed_config_dir=seed_config_dir, scenario_dir=scenario_dir, shared_dirs=shared_dirs)
    fixture.update(
        {
            "generated_fixture_manifest_path": str(Path(str(manifest["manifest_path"])).resolve()),
            "shared_root": live_common.win_path(shared_root.resolve(), trailing_slash=True),
            "subtree_root": live_common.win_path(subtree_root, trailing_slash=True),
            "shared_directory_count": len(shared_dirs),
        }
    )
    return fixture


def collect_startup_profile_summary(
    startup_profile_path: Path,
    *,
    require_startup_profile: bool,
) -> dict[str, object]:
    """Collects startup-profile diagnostics or records an expected omission for baseline runs."""

    try:
        startup_profile_text = live_common.wait_for_startup_profile_complete(
            startup_profile_path,
            timeout=120.0 if require_startup_profile else 5.0,
        )
    except Exception as exc:
        if require_startup_profile:
            raise
        return {
            "startup_profile_path": str(startup_profile_path),
            "startup_profile_status": "missing",
            "startup_profile_error": str(exc),
            "startup_profile_phase_count": 0,
            "startup_profile_counter_count": 0,
            "startup_profile_counters": {},
        }

    phases = live_common.parse_startup_profile(startup_profile_text)
    counters = live_common.parse_startup_profile_counters(startup_profile_text)
    return {
        "startup_profile_path": str(startup_profile_path),
        "startup_profile_status": "present",
        "startup_profile_phase_count": len(phases),
        "startup_profile_counter_count": len(counters),
        "startup_profile_counters": live_common.summarize_startup_profile_counters(counters),
        "startup_profile_readiness": live_common.summarize_shared_files_readiness(phases, counters),
        "startup_profile_highlights": live_common.summarize_startup_profile(
            phases,
            [
                "CemuleDlg::OnInitDialog total",
                "Construct CSharedFileList (share cache/scan)",
                "shared.scan.complete",
                "ui.shared_files_ready",
                "StartupTimer complete",
            ],
        ),
        "startup_profile_top_slowest_phases": live_common.get_top_slowest_phases(phases, limit=8),
    }


def launch_and_capture_startup(
    app_exe: Path,
    fixture: dict[str, object],
    *,
    require_startup_profile: bool,
) -> tuple[Application, int, int, dict[str, object]]:
    """Launches the app, waits for readiness, and returns startup diagnostics."""

    app = live_common.launch_app(app_exe, Path(str(fixture["profile_base"])), minimized_to_tray=False)
    main_window = live_common.wait_for_main_window(app)
    main_hwnd = int(main_window.handle)
    live_common.bring_window_to_front(main_window)
    process_id = get_main_process_id(app)
    startup_summary = collect_startup_profile_summary(
        Path(str(fixture["startup_profile_path"])),
        require_startup_profile=require_startup_profile,
    )
    return app, main_hwnd, process_id, startup_summary


def run_roundtrip_scenario(
    app_exe: Path,
    seed_config_dir: Path,
    scenario_dir: Path,
    *,
    require_startup_profile: bool,
) -> dict[str, object]:
    """Runs one long-config settings roundtrip and relaunch persistence regression."""

    fixture = prepare_roundtrip_fixture(seed_config_dir, scenario_dir)
    summary = {
        "name": "long-config-settings-roundtrip",
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(fixture["profile_base"]),
        "config_dir": str(fixture["config_dir"]),
        "preferences_path": str(fixture["preferences_path"]),
        "profile_base_length": fixture["profile_base_length"],
        "config_dir_length": fixture["config_dir_length"],
        "preferences_ini_length": fixture["preferences_ini_length"],
        "command_line": live_common.win_path(app_exe),
    }

    app = None
    try:
        app, main_hwnd, process_id, startup_summary = launch_and_capture_startup(
            app_exe,
            fixture,
            require_startup_profile=require_startup_profile,
        )
        summary.update(startup_summary)
        initial_ini_value = get_ini_value(Path(str(fixture["preferences_path"])), "OnlineSignature")
        summary["initial_online_signature_ini"] = initial_ini_value

        dialog_hwnd = open_preferences(main_hwnd, process_id)
        prior_state = set_online_signature(dialog_hwnd, True)
        summary["online_signature_prior_state"] = prior_state
        save_preferences(dialog_hwnd)
        wait_for_ini_value(Path(str(fixture["preferences_path"])), "OnlineSignature", "1")
        verify_preferences_value(main_hwnd, process_id, True)
        close_started = time.perf_counter()
        live_common.close_app_cleanly(app)
        summary["close_duration_ms"] = round((time.perf_counter() - close_started) * 1000.0, 3)
        app = None

        app, main_hwnd, process_id, relaunch_startup_summary = launch_and_capture_startup(
            app_exe,
            fixture,
            require_startup_profile=require_startup_profile,
        )
        summary["relaunch_startup_profile"] = relaunch_startup_summary
        verify_preferences_value(main_hwnd, process_id, True)

        dialog_hwnd = open_preferences(main_hwnd, process_id)
        set_online_signature(dialog_hwnd, False)
        save_preferences(dialog_hwnd)
        wait_for_ini_value(Path(str(fixture["preferences_path"])), "OnlineSignature", "0")
        summary["final_online_signature_ini"] = get_ini_value(Path(str(fixture["preferences_path"])), "OnlineSignature")
        summary["status"] = "passed"
        summary["error"] = None
        return summary
    except Exception as exc:
        summary["error"] = str(exc)
        try:
            if app is not None:
                main_window = app.top_window()
                live_common.dump_window_tree(main_window.handle, scenario_dir / "window-tree-failure.json")
                try:
                    image = main_window.capture_as_image()
                    image.save(scenario_dir / "failure.png")
                except Exception:
                    pass
        except Exception:
            pass
        return summary
    finally:
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
            except Exception:
                try:
                    app.kill()
                except Exception:
                    pass
        write_json(scenario_dir / "result.json", summary)


def run_stress_scenario(
    app_exe: Path,
    seed_config_dir: Path,
    scenario_dir: Path,
    shared_root: Path,
    *,
    require_startup_profile: bool,
) -> dict[str, object]:
    """Runs repeated long-config startup/save/shutdown cycles against a heavier shared tree."""

    fixture = prepare_stress_fixture(seed_config_dir, scenario_dir, shared_root)
    summary = {
        "name": "long-config-shared-stress",
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(fixture["profile_base"]),
        "config_dir": str(fixture["config_dir"]),
        "preferences_path": str(fixture["preferences_path"]),
        "profile_base_length": fixture["profile_base_length"],
        "config_dir_length": fixture["config_dir_length"],
        "preferences_ini_length": fixture["preferences_ini_length"],
        "shared_root": fixture["shared_root"],
        "subtree_root": fixture["subtree_root"],
        "generated_fixture_manifest_path": fixture["generated_fixture_manifest_path"],
        "shared_directory_count": fixture["shared_directory_count"],
        "cycles": [],
    }

    desired_state = False
    app = None
    cycle: dict[str, object] | None = None
    try:
        for cycle_index in range(1, 4):
            summary["active_cycle_index"] = cycle_index
            app, main_hwnd, process_id, startup_summary = launch_and_capture_startup(
                app_exe,
                fixture,
                require_startup_profile=require_startup_profile,
            )
            desired_state = not desired_state
            cycle = {
                "cycle_index": cycle_index,
                "desired_online_signature": desired_state,
                "startup": startup_summary,
                "last_step": "startup_complete",
            }

            cycle["last_step"] = "open_preferences"
            dialog_hwnd = open_preferences(main_hwnd, process_id)
            cycle["last_step"] = "set_online_signature"
            set_online_signature(dialog_hwnd, desired_state)
            cycle["last_step"] = "save_preferences"
            save_preferences(dialog_hwnd)
            cycle["last_step"] = "wait_for_ini_value"
            wait_for_ini_value(
                Path(str(fixture["preferences_path"])),
                "OnlineSignature",
                "1" if desired_state else "0",
            )
            cycle["last_step"] = "verify_preferences_value"
            verify_preferences_value(main_hwnd, process_id, desired_state)

            cycle["last_step"] = "activate_shared_files"
            win32gui.SendMessage(main_hwnd, WM_COMMAND, MP_HM_FILES, 0)
            cycle["persisted_online_signature_ini"] = get_ini_value(Path(str(fixture["preferences_path"])), "OnlineSignature")
            summary["cycles"].append(cycle)

            cycle["last_step"] = "close_app"
            close_started = time.perf_counter()
            live_common.close_app_cleanly(app, window_timeout=90.0, process_timeout=90.0)
            cycle["close_duration_ms"] = round((time.perf_counter() - close_started) * 1000.0, 3)
            cycle["last_step"] = "closed"
            app = None

        summary["active_cycle_index"] = "final_relaunch"
        app, main_hwnd, process_id, final_startup_summary = launch_and_capture_startup(
            app_exe,
            fixture,
            require_startup_profile=require_startup_profile,
        )
        summary["final_relaunch_startup"] = final_startup_summary
        summary["final_last_step"] = "verify_preferences_value"
        verify_preferences_value(main_hwnd, process_id, desired_state)
        summary["final_online_signature_ini"] = get_ini_value(Path(str(fixture["preferences_path"])), "OnlineSignature")
        summary["final_last_step"] = "close_app"
        close_started = time.perf_counter()
        live_common.close_app_cleanly(app, window_timeout=90.0, process_timeout=90.0)
        summary["final_close_duration_ms"] = round((time.perf_counter() - close_started) * 1000.0, 3)
        summary["final_last_step"] = "closed"
        app = None
        summary["status"] = "passed"
        summary["error"] = None
        return summary
    except Exception as exc:
        summary["error"] = str(exc)
        if cycle is not None:
            summary["failed_cycle"] = cycle
        try:
            if app is not None:
                main_window = app.top_window()
                live_common.dump_window_tree(main_window.handle, scenario_dir / "window-tree-failure.json")
                try:
                    image = main_window.capture_as_image()
                    image.save(scenario_dir / "failure.png")
                except Exception:
                    pass
        except Exception:
            pass
        return summary
    finally:
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
            except Exception:
                try:
                    app.kill()
                except Exception:
                    pass
        write_json(scenario_dir / "result.json", summary)


def run_scenario(
    *,
    app_exe: Path,
    seed_config_dir: Path,
    scenario_dir: Path,
    shared_root: Path,
    name: str,
    require_startup_profile: bool,
) -> dict[str, object]:
    """Dispatches one named config-stability scenario."""

    if name == "long-config-settings-roundtrip":
        return run_roundtrip_scenario(
            app_exe,
            seed_config_dir,
            scenario_dir,
            require_startup_profile=require_startup_profile,
        )
    if name == "long-config-shared-stress":
        return run_stress_scenario(
            app_exe,
            seed_config_dir,
            scenario_dir,
            shared_root,
            require_startup_profile=require_startup_profile,
        )
    raise RuntimeError(f"Unknown config-stability scenario '{name}'.")


def main(argv: list[str]) -> int:
    """Runs the requested config-stability UI scenarios."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--startup-trace-mode", choices=["required", "optional"], default="required")
    parser.add_argument("--shared-root", default=r"C:\tmp\00_long_paths")
    parser.add_argument(
        "--scenario",
        dest="scenarios",
        action="append",
        choices=[
            "long-config-settings-roundtrip",
            "long-config-shared-stress",
        ],
    )
    args = parser.parse_args(argv)

    if _PYWINAUTO_IMPORT_ERROR is not None:
        live_common.require_pywinauto()

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="config-stability-ui-e2e",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    artifacts_dir = paths.source_artifacts_dir
    shared_root = Path(args.shared_root).resolve()
    scenario_names = args.scenarios or [
        "long-config-settings-roundtrip",
        "long-config-shared-stress",
    ]
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)

    combined = {
        "generated_at": None,
        "status": "passed",
        "app_exe": str(paths.app_exe),
        "seed_config_dir": str(seed_config_dir),
        "artifact_dir": str(artifacts_dir),
        "shared_root": live_common.win_path(shared_root, trailing_slash=True),
        "startup_trace_mode": args.startup_trace_mode,
        "scenarios": [],
    }

    failures: list[str] = []
    for name in scenario_names:
        scenario_dir = artifacts_dir / name
        scenario_dir.mkdir(parents=True, exist_ok=True)
        result = run_scenario(
            app_exe=paths.app_exe,
            seed_config_dir=seed_config_dir,
            scenario_dir=scenario_dir,
            shared_root=shared_root,
            name=name,
            require_startup_profile=(args.startup_trace_mode == "required"),
        )
        combined["scenarios"].append(result)
        if result["status"] != "passed":
            failures.append(name)

    combined["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    if failures:
        combined["status"] = "failed"

    write_json(artifacts_dir / "result.json", combined)
    harness_cli_common.publish_run_artifacts(paths)
    summary_payload = harness_cli_common.build_live_ui_summary(
        status=str(combined["status"]),
        paths=paths,
        error_message="" if not failures else "Config-stability UI scenarios failed: " + ", ".join(failures),
    )
    summary_path = paths.run_report_dir / "ui-summary.json"
    harness_cli_common.write_json_file(summary_path, summary_payload)
    harness_cli_common.publish_latest_report(paths)
    harness_cli_common.update_harness_summary(paths.repo_root, live_ui_summary_path=summary_path)
    harness_cli_common.cleanup_source_artifacts(paths)
    if failures:
        raise RuntimeError("Config-stability UI scenarios failed: " + ", ".join(failures))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
