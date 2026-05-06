"""Exercises REST shared-directory mutation persistence against a live eMule."""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time
from pathlib import Path
from typing import Any


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


harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")
live_common = load_local_module("emule_live_profile_common", "emule-live-profile-common.py")
rest_api_smoke = load_local_module("rest_api_smoke_helpers", "rest-api-smoke.py")

close_app_cleanly = live_common.close_app_cleanly
launch_app = live_common.launch_app
patch_ini_value = live_common.patch_ini_value
prepare_profile_base = live_common.prepare_profile_base
upsert_ini_section_value = live_common.upsert_ini_section_value
wait_for = live_common.wait_for
wait_for_main_window = live_common.wait_for_main_window
write_json = live_common.write_json

choose_listen_port = rest_api_smoke.choose_listen_port
compact_http_result = rest_api_smoke.compact_http_result
get_app_process_id = rest_api_smoke.get_app_process_id
http_request = rest_api_smoke.http_request
require_json_array = rest_api_smoke.require_json_array
require_json_object = rest_api_smoke.require_json_object
wait_for_rest_ready = rest_api_smoke.wait_for_rest_ready

SUITE_NAME = "shared-directories-rest-e2e"
SHARED_DIRECTORIES_ROUTE = "/api/v1/shared-directories"
SHARED_FILES_ROUTE = "/api/v1/shared-files"
PATH_LIST_FILES = {
    "shared": "shareddir.dat",
    "monitored": "shareddir.monitored.dat",
    "monitor_owned": "shareddir.monitor-owned.dat",
}


def configure_rest_only_profile(
    config_dir: Path,
    app_exe: Path,
    api_key: str,
    port: int,
    bind_addr: str,
) -> None:
    """Enables localhost REST while keeping P2P networks disabled."""

    preferences_path = config_dir / "preferences.ini"
    text = live_common.read_ini_text(preferences_path)
    for key, value in (
        ("ConfirmExit", "0"),
        ("Autoconnect", "0"),
        ("Reconnect", "0"),
        ("NetworkED2K", "0"),
        ("NetworkKademlia", "0"),
        ("CloseUPnPOnExit", "0"),
    ):
        text = patch_ini_value(text, key, value)

    template_path = app_exe.parent.parent.parent / "webinterface" / "eMule.tmpl"
    text = patch_ini_value(text, "WebTemplateFile", str(template_path))
    for key, value in (
        ("Password", ""),
        ("PasswordLow", ""),
        ("ApiKey", api_key),
        ("BindAddr", bind_addr),
        ("Port", str(port)),
        ("WebUseUPnP", "0"),
        ("Enabled", "1"),
        ("UseGzip", "0"),
        ("PageRefreshTime", "120"),
        ("UseLowRightsUser", "0"),
        ("AllowAdminHiLevelFunc", "1"),
        ("WebTimeoutMins", "5"),
        ("UseHTTPS", "0"),
        ("HTTPSCertificate", ""),
        ("HTTPSKey", ""),
    ):
        text = upsert_ini_section_value(text, "WebServer", key, value)
    text = upsert_ini_section_value(text, "UPnP", "EnableUPnP", "0")
    live_common.write_utf16_ini_text(preferences_path, text)


def normalize_path_text(path: str) -> str:
    """Normalizes one Windows path enough for cross-source set comparisons."""

    normalized = path.strip().replace("/", "\\")
    while len(normalized) > 3 and normalized.endswith("\\"):
        normalized = normalized[:-1]
    return normalized.casefold()


def normalized_path_set(paths: list[str] | tuple[str, ...]) -> set[str]:
    """Returns the normalized set representation for path-list assertions."""

    return {normalize_path_text(path) for path in paths}


def assert_equivalent_path_sets(actual: list[str], expected: list[str], label: str) -> None:
    """Asserts that two path collections contain equivalent Windows paths."""

    actual_set = normalized_path_set(actual)
    expected_set = normalized_path_set(expected)
    if actual_set != expected_set:
        raise AssertionError(
            f"{label} mismatch. "
            f"Expected {sorted(expected_set)!r}, got {sorted(actual_set)!r}. "
            f"Raw actual: {actual!r}"
        )


def to_windows_long_path(path: Path) -> str:
    """Returns a Windows extended-length spelling for fixture filesystem calls."""

    text = str(path.resolve())
    if os.name != "nt" or text.startswith("\\\\?\\"):
        return text
    if text.startswith("\\\\"):
        return "\\\\?\\UNC\\" + text[2:]
    return "\\\\?\\" + text


def mkdir_long_path(path: Path) -> None:
    """Creates a directory tree without relying on legacy MAX_PATH limits."""

    os.makedirs(to_windows_long_path(path), exist_ok=True)


def write_text_long_path(path: Path, text: str) -> None:
    """Writes one text fixture without relying on legacy MAX_PATH limits."""

    with open(to_windows_long_path(path), "w", encoding="utf-8") as handle:
        handle.write(text)


def read_persisted_path_list(path: Path) -> list[str]:
    """Reads one persisted eMule path-list file, accepting absent empty lists."""

    if not path.exists():
        return []
    data = path.read_bytes()
    if not data:
        return []
    try:
        text = data.decode("utf-16")
    except UnicodeError:
        text = data.decode("utf-8-sig")
    return [line.strip() for line in text.splitlines() if line.strip()]


def build_shared_directory_patch_payload(flat_roots: list[Path], recursive_roots: list[Path]) -> dict[str, object]:
    """Builds the public PATCH payload for flat and recursive shared roots."""

    roots: list[object] = [
        live_common.win_path(root, trailing_slash=True)
        for root in flat_roots
    ]
    roots.extend(
        {
            "path": live_common.win_path(root, trailing_slash=True),
            "recursive": True,
        }
        for root in recursive_roots
    )
    return {"roots": roots}


def get_shared_directory_model(base_url: str, api_key: str) -> dict[str, Any]:
    """Returns the current shared-directory REST model."""

    return require_json_object(http_request(base_url, SHARED_DIRECTORIES_ROUTE, api_key=api_key), 200)


def get_shared_file_names(base_url: str, api_key: str) -> list[str]:
    """Returns the currently visible shared file names from REST."""

    rows = require_json_array(http_request(base_url, SHARED_FILES_ROUTE, api_key=api_key), 200)
    names: list[str] = []
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("name"), str):
            names.append(row["name"])
    return sorted(names)


def extract_directory_paths(model: dict[str, Any]) -> dict[str, list[str]]:
    """Extracts comparable path lists from the shared-directory REST model."""

    def row_paths(key: str) -> list[str]:
        rows = model.get(key)
        if not isinstance(rows, list):
            raise AssertionError(f"shared-directory model field '{key}' is not a list: {model!r}")
        paths: list[str] = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str):
                raise AssertionError(f"shared-directory row in '{key}' has no path: {row!r}")
            paths.append(row["path"])
        return paths

    monitor_owned = model.get("monitorOwned")
    if not isinstance(monitor_owned, list) or not all(isinstance(path, str) for path in monitor_owned):
        raise AssertionError(f"shared-directory model field 'monitorOwned' is not a string list: {model!r}")
    return {
        "roots": row_paths("roots"),
        "items": row_paths("items"),
        "monitor_owned": list(monitor_owned),
    }


def wait_for_shared_directory_paths(
    base_url: str,
    api_key: str,
    *,
    expected_roots: list[str],
    expected_items: list[str],
    expected_monitor_owned: list[str],
    description: str,
    timeout_seconds: float = 60.0,
) -> dict[str, object]:
    """Polls until the REST directory model matches all expected path sets."""

    def resolve():
        model = get_shared_directory_model(base_url, api_key)
        paths = extract_directory_paths(model)
        try:
            assert_equivalent_path_sets(paths["roots"], expected_roots, f"{description} roots")
            assert_equivalent_path_sets(paths["items"], expected_items, f"{description} items")
            assert_equivalent_path_sets(paths["monitor_owned"], expected_monitor_owned, f"{description} monitor-owned")
        except AssertionError:
            return None
        return {
            "model": model,
            "paths": paths,
        }

    return wait_for(resolve, timeout=timeout_seconds, interval=1.0, description=description)


def wait_for_shared_file_names(
    base_url: str,
    api_key: str,
    expected_names: list[str],
    description: str,
    timeout_seconds: float = 90.0,
) -> dict[str, object]:
    """Polls until REST exposes exactly the expected shared file names."""

    expected_set = set(expected_names)

    def resolve():
        names = get_shared_file_names(base_url, api_key)
        if set(names) == expected_set:
            return {
                "names": names,
                "count": len(names),
            }
        return None

    return wait_for(resolve, timeout=timeout_seconds, interval=1.0, description=description)


def assert_persisted_lists(
    config_dir: Path,
    *,
    expected_shared_dirs: list[str],
    expected_monitored_roots: list[str],
    expected_monitor_owned: list[str],
) -> dict[str, list[str]]:
    """Asserts all shared-directory persistence files match expected paths."""

    actual = {
        "shared": read_persisted_path_list(config_dir / PATH_LIST_FILES["shared"]),
        "monitored": read_persisted_path_list(config_dir / PATH_LIST_FILES["monitored"]),
        "monitor_owned": read_persisted_path_list(config_dir / PATH_LIST_FILES["monitor_owned"]),
    }
    assert_equivalent_path_sets(actual["shared"], expected_shared_dirs, "persisted shared directories")
    assert_equivalent_path_sets(actual["monitored"], expected_monitored_roots, "persisted monitored roots")
    assert_equivalent_path_sets(actual["monitor_owned"], expected_monitor_owned, "persisted monitor-owned directories")
    return actual


def create_fixture_tree(artifacts_dir: Path) -> dict[str, Path]:
    """Creates a deterministic shared-directory fixture tree for REST mutation."""

    flat = artifacts_dir / "shared-rest-flat"
    recursive = artifacts_dir / "shared-rest-recursive"
    recursive_child = recursive / "child"
    replacement = artifacts_dir / "shared-rest-replacement"
    long_unicode = artifacts_dir / "shared-rest-long-unicode"
    while len(str(long_unicode.resolve())) < 285:
        long_unicode = long_unicode / "segment-abcdefghijklmnopqrstuvwxyz"
    long_unicode = long_unicode / f"unicode-{chr(0x00DF)}-{chr(0x6F22)}"
    for directory in (flat, recursive_child, replacement, long_unicode):
        mkdir_long_path(directory)
    write_text_long_path(flat / "flat_file.txt", "flat share fixture\r\n")
    write_text_long_path(recursive / "recursive_root_file.txt", "recursive root fixture\r\n")
    write_text_long_path(recursive_child / "recursive_child_file.txt", "recursive child fixture\r\n")
    write_text_long_path(replacement / "replacement_file.txt", "replacement fixture\r\n")
    write_text_long_path(long_unicode / f"unicode-{chr(0x00DF)}-{chr(0x6F22)}.txt", "unicode long-path fixture\r\n")
    return {
        "flat": flat,
        "recursive": recursive,
        "recursive_child": recursive_child,
        "replacement": replacement,
        "long_unicode": long_unicode,
    }


def set_phase(report: dict[str, object], phase: str) -> str:
    """Records the current execution phase in the live report."""

    report["current_phase"] = phase
    phase_history = report.setdefault("phase_history", [])
    assert isinstance(phase_history, list)
    phase_history.append({"phase": phase, "entered_at": round(time.time(), 3)})
    return phase


def launch_and_wait(app_exe: Path, profile_base: Path, base_url: str, api_key: str, timeout_seconds: float):
    """Launches eMule and waits for both the UI shell and REST listener."""

    app = launch_app(app_exe, profile_base)
    main_window = wait_for_main_window(app)
    ready = wait_for_rest_ready(base_url, api_key, timeout_seconds)
    return app, main_window.window_text(), compact_http_result(ready)


def patch_shared_directories(base_url: str, api_key: str, payload: dict[str, object]) -> dict[str, object]:
    """Applies one shared-directory PATCH and returns a compact response."""

    result = http_request(
        base_url,
        SHARED_DIRECTORIES_ROUTE,
        method="PATCH",
        api_key=api_key,
        json_body=payload,
    )
    body = require_json_object(result, 200)
    shared_directories = body.get("sharedDirectories") if isinstance(body.get("sharedDirectories"), dict) else body
    assert isinstance(shared_directories, dict), compact_http_result(result)
    assert isinstance(shared_directories.get("roots"), list), compact_http_result(result)
    assert isinstance(shared_directories.get("items"), list), compact_http_result(result)
    return compact_http_result(result)


def main() -> int:
    """Runs the shared-directory REST persistence scenario."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default="shared-directories-rest-test-key")
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=45.0)
    args = parser.parse_args()

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="shared-directories-rest",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    app_exe = paths.app_exe
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    artifacts_dir = paths.source_artifacts_dir

    port = choose_listen_port()
    base_url = f"http://127.0.0.1:{port}"
    fixtures = create_fixture_tree(artifacts_dir)
    profile = prepare_profile_base(
        seed_config_dir,
        artifacts_dir,
        shared_dirs=[],
        incoming_dir=artifacts_dir / "incoming",
        temp_dir=artifacts_dir / "temp",
    )
    config_dir = Path(profile["config_dir"])
    profile_base = Path(profile["profile_base"])
    configure_rest_only_profile(config_dir, app_exe, args.api_key, port, args.bind_addr)

    flat_path = live_common.win_path(fixtures["flat"], trailing_slash=True)
    recursive_path = live_common.win_path(fixtures["recursive"], trailing_slash=True)
    recursive_child_path = live_common.win_path(fixtures["recursive_child"], trailing_slash=True)
    replacement_path = live_common.win_path(fixtures["replacement"], trailing_slash=True)
    long_unicode_path = live_common.win_path(fixtures["long_unicode"], trailing_slash=True)
    unicode_file_name = f"unicode-{chr(0x00DF)}-{chr(0x6F22)}.txt"
    first_shared_dirs = [flat_path, recursive_path, recursive_child_path, long_unicode_path]
    first_roots = [flat_path, recursive_path, long_unicode_path]
    first_monitor_owned = [recursive_child_path]
    replacement_dirs = [replacement_path]

    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "failed",
        "base_url": base_url,
        "port": port,
        "launch_inputs": {
            "app_exe": str(app_exe),
            "seed_config_dir": str(seed_config_dir),
            "artifacts_dir": str(artifacts_dir),
            "profile_base": str(profile_base),
            "config_dir": str(config_dir),
            "api_key_length": len(args.api_key),
            "bind_addr": args.bind_addr,
            "rest_ready_timeout_seconds": args.rest_ready_timeout_seconds,
        },
        "fixtures": {key: str(value) for key, value in fixtures.items()},
        "long_path_unicode": {
            "path": long_unicode_path,
            "path_length": len(long_unicode_path),
            "file_name": unicode_file_name,
            "over_max_path": len(long_unicode_path) > 260,
        },
        "checks": {},
        "cleanup": {},
    }
    current_phase = set_phase(report, "launch_initial")
    pending_error: Exception | None = None
    app = None

    try:
        app, title, ready = launch_and_wait(app_exe, profile_base, base_url, args.api_key, args.rest_ready_timeout_seconds)
        report["launched_process_id"] = get_app_process_id(app)
        report["main_window_title"] = title
        checks = report["checks"]
        assert isinstance(checks, dict)
        checks["initial_ready"] = ready

        current_phase = set_phase(report, "initial_empty_state")
        checks["initial_directories"] = wait_for_shared_directory_paths(
            base_url,
            args.api_key,
            expected_roots=[],
            expected_items=[],
            expected_monitor_owned=[],
            description="initial empty shared-directory model",
            timeout_seconds=15.0,
        )
        checks["initial_files"] = wait_for_shared_file_names(
            base_url,
            args.api_key,
            [],
            "initial empty shared-file list",
            timeout_seconds=15.0,
        )

        current_phase = set_phase(report, "patch_flat_recursive")
        first_payload = build_shared_directory_patch_payload([fixtures["flat"], fixtures["long_unicode"]], [fixtures["recursive"]])
        checks["patch_flat_recursive"] = {
            "payload": first_payload,
            "response": patch_shared_directories(base_url, args.api_key, first_payload),
        }
        checks["flat_recursive_directories"] = wait_for_shared_directory_paths(
            base_url,
            args.api_key,
            expected_roots=first_roots,
            expected_items=first_shared_dirs,
            expected_monitor_owned=first_monitor_owned,
            description="flat plus recursive shared-directory model",
        )
        checks["flat_recursive_files"] = wait_for_shared_file_names(
            base_url,
            args.api_key,
            ["flat_file.txt", "recursive_root_file.txt", "recursive_child_file.txt", unicode_file_name],
            "flat plus recursive plus long-unicode shared files",
        )

        current_phase = set_phase(report, "shutdown_after_first_patch")
        close_app_cleanly(app)
        app = None
        checks["persisted_after_first_shutdown"] = assert_persisted_lists(
            config_dir,
            expected_shared_dirs=first_shared_dirs,
            expected_monitored_roots=[recursive_path],
            expected_monitor_owned=first_monitor_owned,
        )

        current_phase = set_phase(report, "relaunch_first_state")
        app, title, ready = launch_and_wait(app_exe, profile_base, base_url, args.api_key, args.rest_ready_timeout_seconds)
        checks["first_relaunch"] = {
            "process_id": get_app_process_id(app),
            "main_window_title": title,
            "ready": ready,
        }
        checks["first_relaunch_directories"] = wait_for_shared_directory_paths(
            base_url,
            args.api_key,
            expected_roots=first_roots,
            expected_items=first_shared_dirs,
            expected_monitor_owned=first_monitor_owned,
            description="reloaded flat plus recursive shared-directory model",
        )
        checks["first_relaunch_files"] = wait_for_shared_file_names(
            base_url,
            args.api_key,
            ["flat_file.txt", "recursive_root_file.txt", "recursive_child_file.txt", unicode_file_name],
            "reloaded flat plus recursive plus long-unicode shared files",
        )

        current_phase = set_phase(report, "patch_replacement")
        replacement_payload = build_shared_directory_patch_payload([fixtures["replacement"]], [])
        checks["patch_replacement"] = {
            "payload": replacement_payload,
            "response": patch_shared_directories(base_url, args.api_key, replacement_payload),
        }
        checks["replacement_directories"] = wait_for_shared_directory_paths(
            base_url,
            args.api_key,
            expected_roots=replacement_dirs,
            expected_items=replacement_dirs,
            expected_monitor_owned=[],
            description="replacement shared-directory model",
        )
        checks["replacement_files"] = wait_for_shared_file_names(
            base_url,
            args.api_key,
            ["replacement_file.txt"],
            "replacement shared files",
        )

        current_phase = set_phase(report, "shutdown_after_replacement")
        close_app_cleanly(app)
        app = None
        checks["persisted_after_replacement_shutdown"] = assert_persisted_lists(
            config_dir,
            expected_shared_dirs=replacement_dirs,
            expected_monitored_roots=[],
            expected_monitor_owned=[],
        )

        current_phase = set_phase(report, "relaunch_replacement_state")
        app, title, ready = launch_and_wait(app_exe, profile_base, base_url, args.api_key, args.rest_ready_timeout_seconds)
        checks["replacement_relaunch"] = {
            "process_id": get_app_process_id(app),
            "main_window_title": title,
            "ready": ready,
        }
        checks["replacement_relaunch_directories"] = wait_for_shared_directory_paths(
            base_url,
            args.api_key,
            expected_roots=replacement_dirs,
            expected_items=replacement_dirs,
            expected_monitor_owned=[],
            description="reloaded replacement shared-directory model",
        )
        checks["replacement_relaunch_files"] = wait_for_shared_file_names(
            base_url,
            args.api_key,
            ["replacement_file.txt"],
            "reloaded replacement shared files",
        )

        current_phase = set_phase(report, "completed")
        report["status"] = "passed"
    except Exception as exc:
        pending_error = exc
        report["status"] = "failed"
        report["failed_phase"] = current_phase
        report["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
    finally:
        cleanup = report["cleanup"]
        assert isinstance(cleanup, dict)
        if app is not None:
            cleanup["process_id"] = get_app_process_id(app)
            cleanup["profile_base"] = str(profile_base)
            try:
                close_app_cleanly(app)
                cleanup["app_closed"] = True
            except Exception as exc:  # pragma: no cover - best-effort live cleanup
                cleanup["app_closed"] = False
                cleanup["app_close_error"] = repr(exc)
                if pending_error is None:
                    pending_error = exc
                    report["status"] = "failed"
                    report["failed_phase"] = "cleanup"
                    report["error"] = {
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
        write_json(artifacts_dir / "result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)

    if pending_error is not None:
        raise pending_error

    print(f"Shared-directories REST E2E passed. Report directory: {paths.run_report_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
