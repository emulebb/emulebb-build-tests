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
prepare_profile_base = live_common.prepare_profile_base
wait_for = live_common.wait_for
wait_for_main_window = live_common.wait_for_main_window
write_json = live_common.write_json

choose_listen_port = rest_api_smoke.choose_listen_port
compact_http_result = rest_api_smoke.compact_http_result
get_app_process_id = rest_api_smoke.get_app_process_id
http_request = rest_api_smoke.http_request
require_json_array = rest_api_smoke.require_json_array
require_json_object = rest_api_smoke.require_json_object
require_error_response = rest_api_smoke.require_error_response
wait_for_rest_ready = rest_api_smoke.wait_for_rest_ready

SUITE_NAME = "shared-directories-rest-e2e"
SHARED_DIRECTORIES_ROUTE = "/api/v1/shared-directories"
SHARED_FILES_ROUTE = "/api/v1/shared-files"
CATEGORIES_ROUTE = "/api/v1/categories"
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

    live_common.apply_emule_preferences(
        config_dir,
        (
            ("ConfirmExit", "0"),
            ("Autoconnect", "0"),
            ("Reconnect", "0"),
            ("NetworkED2K", "0"),
            ("NetworkKademlia", "0"),
            ("CloseUPnPOnExit", "0"),
        ),
    )
    live_common.apply_webserver_profile(
        config_dir,
        live_common.WebServerProfileSpec(
            app_exe=app_exe,
            api_key=api_key,
            port=port,
            bind_addr=bind_addr,
            use_gzip=False,
            allow_admin_high_level_func=True,
        ),
    )
    live_common.apply_live_network_policy(config_dir)


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


def to_windows_exact_long_path(path: Path) -> str:
    """Returns an extended-length path spelling without normalizing exact names."""

    text = str(path if path.is_absolute() else Path.cwd() / path)
    if os.name != "nt" or text.startswith("\\\\?\\"):
        return text
    if text.startswith("\\\\"):
        return "\\\\?\\UNC\\" + text[2:]
    return "\\\\?\\" + text


def exact_win_path(path: Path, trailing_slash: bool = False) -> str:
    """Formats an absolute Windows path while preserving exact final text."""

    text = str(path if path.is_absolute() else Path.cwd() / path)
    return text + ("\\" if trailing_slash and not text.endswith("\\") else "")


def mkdir_long_path(path: Path) -> None:
    """Creates a directory tree without relying on legacy MAX_PATH limits."""

    os.makedirs(to_windows_long_path(path), exist_ok=True)


def mkdir_exact_long_path(path: Path) -> None:
    """Creates an exact-name directory tree without trimming dot/space suffixes."""

    os.makedirs(to_windows_exact_long_path(path), exist_ok=True)


def write_text_long_path(path: Path, text: str) -> None:
    """Writes one text fixture without relying on legacy MAX_PATH limits."""

    with open(to_windows_long_path(path), "w", encoding="utf-8") as handle:
        handle.write(text)


def write_text_exact_long_path(path: Path, text: str) -> None:
    """Writes one exact-name text fixture without legacy path normalization."""

    with open(to_windows_exact_long_path(path), "w", encoding="utf-8") as handle:
        handle.write(text)


def file_exists_long_path(path: Path) -> bool:
    """Returns whether one long-path-capable fixture file still exists."""

    return os.path.isfile(to_windows_long_path(path))


def file_exists_exact_long_path(path: Path) -> bool:
    """Returns whether one exact-name fixture file still exists."""

    return os.path.isfile(to_windows_exact_long_path(path))


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
    return {"confirmReplaceRoots": True, "roots": roots}


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


def get_shared_file_row_by_name(base_url: str, api_key: str, name: str) -> dict[str, object]:
    """Returns one shared-file REST row by display name."""

    rows = require_json_array(http_request(base_url, SHARED_FILES_ROUTE, api_key=api_key), 200)
    for row in rows:
        if isinstance(row, dict) and row.get("name") == name:
            return row
    raise AssertionError(f"Shared file named {name!r} not found in {rows!r}.")


def delete_shared_file_by_hash(base_url: str, api_key: str, file_hash: str, *, delete_files: bool) -> dict[str, object]:
    """Deletes one shared file through native REST and validates the response."""

    result = http_request(
        base_url,
        f"{SHARED_FILES_ROUTE}/{file_hash}",
        method="DELETE",
        api_key=api_key,
        json_body={"deleteFiles": delete_files},
    )
    body = require_json_object(result, 200)
    assert body.get("ok") is True, compact_http_result(result)
    assert body.get("deletedFiles") is delete_files, compact_http_result(result)
    compact = compact_http_result(result)
    compact["response"] = body
    return compact


def assert_replaced_shared_files_preserved(fixtures: dict[str, Path], unicode_file_name: str, exact_file_name: str) -> dict[str, bool]:
    """Asserts shared-directory replacement unshares old files without deleting them."""

    old_files = {
        "flat_file": file_exists_long_path(fixtures["flat"] / "flat_file.txt"),
        "recursive_root_file": file_exists_long_path(fixtures["recursive"] / "recursive_root_file.txt"),
        "recursive_child_file": file_exists_long_path(fixtures["recursive_child"] / "recursive_child_file.txt"),
        "unicode_file": file_exists_long_path(fixtures["long_unicode"] / unicode_file_name),
        "exact_name_file": file_exists_exact_long_path(fixtures["exact_names"] / exact_file_name),
    }
    missing = [name for name, exists in old_files.items() if not exists]
    if missing:
        raise AssertionError(f"Shared-directory replacement deleted old fixture files: {missing!r}")
    return old_files


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


def assert_directory_accessibility(check: dict[str, object], path: str, expected_accessible: bool) -> None:
    """Asserts one reported shared-directory row has the expected accessibility."""

    model = check.get("model")
    assert isinstance(model, dict), check
    items = model.get("items")
    assert isinstance(items, list), check
    expected_path = normalize_path_text(path)
    for item in items:
        if not isinstance(item, dict):
            continue
        item_path = item.get("path")
        if isinstance(item_path, str) and normalize_path_text(item_path) == expected_path:
            if item.get("accessible") != expected_accessible:
                raise AssertionError(f"Expected {path!r} accessible={expected_accessible}, got {item!r}")
            return
    raise AssertionError(f"Shared directory {path!r} not found in {items!r}")


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
    exact_names = Path(str(artifacts_dir / "shared-rest-exact-names") + ". ")
    long_unicode = artifacts_dir / "shared-rest-long-unicode"
    while len(str(long_unicode.resolve())) < 285:
        long_unicode = long_unicode / "segment-abcdefghijklmnopqrstuvwxyz"
    long_unicode = long_unicode / f"unicode-{chr(0x00DF)}-{chr(0x6F22)}"
    for directory in (flat, recursive_child, replacement, long_unicode):
        mkdir_long_path(directory)
    mkdir_exact_long_path(exact_names)
    write_text_long_path(flat / "flat_file.txt", "flat share fixture\r\n")
    write_text_long_path(recursive / "recursive_root_file.txt", "recursive root fixture\r\n")
    write_text_long_path(recursive_child / "recursive_child_file.txt", "recursive child fixture\r\n")
    write_text_long_path(replacement / "replacement_file.txt", "replacement fixture\r\n")
    write_text_long_path(long_unicode / f"unicode-{chr(0x00DF)}-{chr(0x6F22)}.txt", "unicode long-path fixture\r\n")
    write_text_exact_long_path(exact_names / "shared-file. ", "exact trailing dot and space fixture\r\n")
    return {
        "flat": flat,
        "recursive": recursive,
        "recursive_child": recursive_child,
        "replacement": replacement,
        "long_unicode": long_unicode,
        "exact_names": exact_names,
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


def patch_shared_directories_error(
    base_url: str,
    api_key: str,
    payload: dict[str, object],
    message_contains: str,
) -> dict[str, object]:
    """Asserts one invalid shared-directory PATCH fails as native REST JSON."""

    result = http_request(
        base_url,
        SHARED_DIRECTORIES_ROUTE,
        method="PATCH",
        api_key=api_key,
        json_body=payload,
    )
    require_error_response(
        result,
        400,
        "INVALID_ARGUMENT",
        message_contains=message_contains,
    )
    return compact_http_result(result)


def create_category(base_url: str, api_key: str, name: str, path: str) -> dict[str, object]:
    """Creates one category and returns the compact response plus parsed id."""

    result = http_request(
        base_url,
        CATEGORIES_ROUTE,
        method="POST",
        api_key=api_key,
        json_body={"name": name, "path": path},
    )
    body = require_json_object(result, 200)
    assert isinstance(body.get("id"), int), compact_http_result(result)
    assert body.get("name") == name, compact_http_result(result)
    assert body.get("path") == path, compact_http_result(result)
    compact = compact_http_result(result)
    compact["category_id"] = body["id"]
    return compact


def delete_category(base_url: str, api_key: str, category_id: int) -> dict[str, object]:
    """Deletes one non-default category created during the live scenario."""

    result = http_request(
        base_url,
        f"{CATEGORIES_ROUTE}/{category_id}",
        method="DELETE",
        api_key=api_key,
    )
    body = require_json_object(result, 200)
    assert body.get("ok") is True, compact_http_result(result)
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
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
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
    exact_names_path = exact_win_path(fixtures["exact_names"], trailing_slash=True)
    unicode_file_name = f"unicode-{chr(0x00DF)}-{chr(0x6F22)}.txt"
    exact_file_name = "shared-file. "
    first_shared_dirs = [flat_path, recursive_path, recursive_child_path, long_unicode_path, exact_names_path]
    first_roots = [flat_path, recursive_path, long_unicode_path, exact_names_path]
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
        "exact_names": {
            "path": exact_names_path,
            "directory_leaf": fixtures["exact_names"].name,
            "file_name": exact_file_name,
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

        current_phase = set_phase(report, "invalid_patch_checks")
        missing_parent_path = live_common.win_path(artifacts_dir / "missing-parent" / "child", trailing_slash=True)
        checks["invalid_patch_blank_path"] = {
            "payload": {"confirmReplaceRoots": True, "roots": ["   "]},
            "response": patch_shared_directories_error(
                base_url,
                args.api_key,
                {"confirmReplaceRoots": True, "roots": ["   "]},
                "path must not be empty",
            ),
        }
        checks["invalid_patch_recursive_type"] = {
            "payload": {"confirmReplaceRoots": True, "roots": [{"path": flat_path, "recursive": "true"}]},
            "response": patch_shared_directories_error(
                base_url,
                args.api_key,
                {"confirmReplaceRoots": True, "roots": [{"path": flat_path, "recursive": "true"}]},
                "recursive must be a boolean",
            ),
        }
        checks["invalid_patch_missing_confirmation"] = {
            "payload": {"roots": []},
            "response": patch_shared_directories_error(
                base_url,
                args.api_key,
                {"roots": []},
                "confirmReplaceRoots must be true",
            ),
        }
        checks["invalid_patch_state"] = wait_for_shared_directory_paths(
            base_url,
            args.api_key,
            expected_roots=[],
            expected_items=[],
            expected_monitor_owned=[],
            description="empty shared-directory model after invalid patches",
            timeout_seconds=15.0,
        )

        current_phase = set_phase(report, "missing_parent_patch")
        missing_parent_payload = {"confirmReplaceRoots": True, "roots": [missing_parent_path]}
        checks["patch_missing_parent"] = {
            "payload": missing_parent_payload,
            "response": patch_shared_directories(base_url, args.api_key, missing_parent_payload),
        }
        checks["missing_parent_directories"] = wait_for_shared_directory_paths(
            base_url,
            args.api_key,
            expected_roots=[missing_parent_path],
            expected_items=[missing_parent_path],
            expected_monitor_owned=[],
            description="missing-parent shared-directory model",
            timeout_seconds=15.0,
        )
        assert_directory_accessibility(checks["missing_parent_directories"], missing_parent_path, False)
        checks["missing_parent_files"] = wait_for_shared_file_names(
            base_url,
            args.api_key,
            [],
            "missing-parent shared-file list",
            timeout_seconds=15.0,
        )
        clear_missing_parent_payload: dict[str, object] = {"confirmReplaceRoots": True, "roots": []}
        checks["patch_clear_missing_parent"] = {
            "payload": clear_missing_parent_payload,
            "response": patch_shared_directories(base_url, args.api_key, clear_missing_parent_payload),
        }
        checks["after_missing_parent_clear"] = wait_for_shared_directory_paths(
            base_url,
            args.api_key,
            expected_roots=[],
            expected_items=[],
            expected_monitor_owned=[],
            description="empty shared-directory model after missing-parent clear",
            timeout_seconds=15.0,
        )

        current_phase = set_phase(report, "category_long_unicode_path")
        category_name = "REST long Unicode path"
        category_create = create_category(base_url, args.api_key, category_name, long_unicode_path)
        checks["category_long_unicode_create"] = category_create
        category_id = category_create["category_id"]
        assert isinstance(category_id, int), category_create
        checks["category_long_unicode_delete"] = delete_category(base_url, args.api_key, category_id)

        current_phase = set_phase(report, "patch_flat_recursive")
        first_payload = build_shared_directory_patch_payload([fixtures["flat"], fixtures["long_unicode"]], [fixtures["recursive"]])
        first_payload["roots"].append(exact_names_path)
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
            ["flat_file.txt", "recursive_root_file.txt", "recursive_child_file.txt", unicode_file_name, exact_file_name],
            "flat plus recursive plus long-unicode plus exact-name shared files",
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
            ["flat_file.txt", "recursive_root_file.txt", "recursive_child_file.txt", unicode_file_name, exact_file_name],
            "reloaded flat plus recursive plus long-unicode plus exact-name shared files",
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
        checks["replaced_shared_files_preserved"] = assert_replaced_shared_files_preserved(
            fixtures,
            unicode_file_name,
            exact_file_name,
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

        current_phase = set_phase(report, "delete_replacement_shared_file")
        replacement_row = get_shared_file_row_by_name(base_url, args.api_key, "replacement_file.txt")
        replacement_hash = replacement_row.get("hash")
        if not isinstance(replacement_hash, str) or not replacement_hash:
            raise AssertionError(f"Replacement shared-file row has no hash: {replacement_row!r}")
        replacement_file_path = fixtures["replacement"] / "replacement_file.txt"
        checks["delete_replacement_shared_file"] = {
            "row": replacement_row,
            "response": delete_shared_file_by_hash(
                base_url,
                args.api_key,
                replacement_hash,
                delete_files=True,
            ),
        }
        if replacement_file_path.exists():
            raise AssertionError(f"Expected shared-file delete to remove {replacement_file_path}.")
        checks["after_replacement_shared_file_delete_directories"] = wait_for_shared_directory_paths(
            base_url,
            args.api_key,
            expected_roots=replacement_dirs,
            expected_items=replacement_dirs,
            expected_monitor_owned=[],
            description="replacement shared-directory model after shared-file delete",
        )
        checks["after_replacement_shared_file_delete_files"] = wait_for_shared_file_names(
            base_url,
            args.api_key,
            [],
            "replacement shared files after native REST delete",
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
