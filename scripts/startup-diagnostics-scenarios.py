"""Builds startup-diagnostics artifacts for deterministic live-profile scenarios."""

from __future__ import annotations

import argparse
import importlib.util
import json
import struct
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import win32con
import win32gui
import win32process


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

HIGHLIGHTED_PHASES = [
    "Construct CSharedFileList (share cache/scan)",
    "CSharedFilesWnd::OnInitDialog total",
    "BuildSharedDirectoryTree done",
    "shared.scan.complete",
    "shared.tree.populated",
    "shared.model.populated",
    "ui.shared_files_ready",
    "StartupTimer complete",
]
WARM_RELAUNCH_SHARED_CACHE_TIMEOUT_SECONDS = 45.0
PERSISTED_STRESS_FIXTURE_PREFIXES = ("shared_files_tree_stress",)


def create_fixture_shared_dirs(artifacts_dir: Path) -> tuple[list[str], dict[str, object]]:
    """Creates the small deterministic shared-files fixture used by the UI regression."""

    shared_a_dir = artifacts_dir / "shared-a"
    shared_b_dir = artifacts_dir / "shared-b"
    shared_a_dir.mkdir(parents=True, exist_ok=True)
    shared_b_dir.mkdir(parents=True, exist_ok=True)

    files = [
        (shared_a_dir / "middle_small.txt", b"small\n"),
        (shared_a_dir / "zeta_large.bin", b"z" * 4096),
        (shared_b_dir / "alpha_medium.txt", b"a" * 600),
    ]
    for file_path, content in files:
        file_path.write_bytes(content)

    shared_dirs = [
        live_common.win_path(shared_a_dir, trailing_slash=True),
        live_common.win_path(shared_b_dir, trailing_slash=True),
    ]
    return shared_dirs, {
        "directory_count_including_root": 2,
        "file_count": len(files),
        "shared_directory_count": len(shared_dirs),
    }


def build_scenario_definition(name: str, artifacts_dir: Path, shared_root: Path) -> dict[str, object]:
    """Resolves one named startup-diagnostics scenario into concrete shared roots and metadata."""

    resolved_root = shared_root.resolve()
    emule_fixture_root = resolved_root / "emule-longpath-tests"
    long_path_output_root = resolved_root / "long_path_output"
    shared_files_robustness_root = resolved_root / "shared_files_robustness"
    if name == "baseline-no-shares":
        return {
            "name": name,
            "description": "Seeded profile with no shared directories.",
            "shared_dirs": [],
            "tree_summary": {
                "directory_count_including_root": 0,
                "file_count": 0,
                "shared_directory_count": 0,
            },
        }
    if name == "fixture-three-files":
        shared_dirs, tree_summary = create_fixture_shared_dirs(artifacts_dir)
        return {
            "name": name,
            "description": "Two deterministic shared roots with three visible fixture files.",
            "shared_dirs": shared_dirs,
            "tree_summary": tree_summary,
        }
    if name == "long-paths-root-only":
        tree_summary = live_common.summarize_existing_tree(
            resolved_root,
            excluded_dir_prefixes=PERSISTED_STRESS_FIXTURE_PREFIXES,
        )
        tree_summary["shared_directory_count"] = 1
        return {
            "name": name,
            "description": "Shares only the long-path root without expanding child directories into shareddir.dat; persisted stress fixtures are excluded from harness metrics.",
            "shared_dirs": [live_common.win_path(resolved_root, trailing_slash=True)],
            "tree_summary": tree_summary,
        }
    if name == "long-paths-recursive":
        shared_dirs = live_common.enumerate_recursive_directories(
            resolved_root,
            excluded_dir_prefixes=PERSISTED_STRESS_FIXTURE_PREFIXES,
        )
        tree_summary = live_common.summarize_existing_tree(
            resolved_root,
            excluded_dir_prefixes=PERSISTED_STRESS_FIXTURE_PREFIXES,
        )
        tree_summary["shared_directory_count"] = len(shared_dirs)
        return {
            "name": name,
            "description": "Expands the long-path root recursively into shareddir.dat before launch while excluding persisted stress fixtures.",
            "shared_dirs": shared_dirs,
            "tree_summary": tree_summary,
        }
    if name == "long-path-output-recursive":
        shared_dirs = live_common.enumerate_recursive_directories(long_path_output_root)
        tree_summary = live_common.summarize_existing_tree(long_path_output_root)
        tree_summary["shared_directory_count"] = len(shared_dirs)
        return {
            "name": name,
            "description": "Recursively shares only the generated long_path_output subtree.",
            "shared_dirs": shared_dirs,
            "tree_summary": tree_summary,
        }
    if name == "long-path-output-root-only":
        tree_summary = live_common.summarize_existing_tree(long_path_output_root)
        tree_summary["shared_directory_count"] = 1
        return {
            "name": name,
            "description": "Shares only the long_path_output root without expanding child directories into shareddir.dat.",
            "shared_dirs": [live_common.win_path(long_path_output_root, trailing_slash=True)],
            "tree_summary": tree_summary,
        }
    if name == "long-path-emule-fixture-recursive":
        shared_dirs = live_common.enumerate_recursive_directories(emule_fixture_root)
        tree_summary = live_common.summarize_existing_tree(emule_fixture_root)
        tree_summary["shared_directory_count"] = len(shared_dirs)
        return {
            "name": name,
            "description": "Recursively shares only the emule-longpath-tests subtree.",
            "shared_dirs": shared_dirs,
            "tree_summary": tree_summary,
        }
    if name == "long-path-emule-fixture-root-only":
        tree_summary = live_common.summarize_existing_tree(emule_fixture_root)
        tree_summary["shared_directory_count"] = 1
        return {
            "name": name,
            "description": "Shares only the emule-longpath-tests root without expanding child directories into shareddir.dat.",
            "shared_dirs": [live_common.win_path(emule_fixture_root, trailing_slash=True)],
            "tree_summary": tree_summary,
        }
    if name == "shared-files-robustness-root-only":
        tree_summary = live_common.summarize_existing_tree(shared_files_robustness_root)
        tree_summary["shared_directory_count"] = 1
        return {
            "name": name,
            "description": "Shares only the generated Shared Files robustness root without expanding child directories into shareddir.dat.",
            "shared_dirs": [live_common.win_path(shared_files_robustness_root, trailing_slash=True)],
            "tree_summary": tree_summary,
        }
    if name == "shared-files-robustness-recursive":
        shared_dirs = live_common.enumerate_recursive_directories(shared_files_robustness_root)
        tree_summary = live_common.summarize_existing_tree(shared_files_robustness_root)
        tree_summary["shared_directory_count"] = len(shared_dirs)
        return {
            "name": name,
            "description": "Recursively shares the generated Shared Files robustness subtree.",
            "shared_dirs": shared_dirs,
            "tree_summary": tree_summary,
        }
    raise RuntimeError(f"Unknown startup-diagnostics scenario: {name}")


def get_highlight_metric(summary: dict[str, object], name: str, field: str) -> float | None:
    """Returns one highlighted startup metric from a scenario result when present."""

    highlights = summary.get("startup_diagnostics_highlights")
    if not isinstance(highlights, dict):
        return None
    phase = highlights.get(name)
    if not isinstance(phase, dict):
        return None
    value = phase.get(field)
    return float(value) if value is not None else None


def get_derived_metric(summary: dict[str, object], key: str) -> float | int | None:
    """Returns one derived startup-diagnostics metric from a scenario result when present."""

    metrics = summary.get("startup_diagnostics_derived_metrics")
    if not isinstance(metrics, dict):
        return None
    value = metrics.get(key)
    if isinstance(value, (int, float)):
        return value
    return None


def get_counter_metric(summary: dict[str, object], counter_id: str, field: str = "value") -> float | int | None:
    """Returns one summarized startup-diagnostics counter value from a scenario result when present."""

    counters = summary.get("startup_diagnostics_counters")
    if not isinstance(counters, dict):
        return None
    counter = counters.get(counter_id)
    if not isinstance(counter, dict):
        return None
    value = counter.get(field)
    if isinstance(value, (int, float)):
        return value
    return None


def build_derived_metrics(summary: dict[str, object]) -> dict[str, object]:
    """Adds normalized startup-diagnostics metrics that are easier to compare between scenarios."""

    metrics: dict[str, object] = {}
    tree_summary = summary.get("tree_summary")
    file_count = 0
    directory_count = 0
    if isinstance(tree_summary, dict):
        file_count = int(tree_summary.get("file_count", 0) or 0)
        directory_count = int(tree_summary.get("directory_count_including_root", 0) or 0)
    shared_directory_count = int(summary.get("shared_directory_count", 0) or 0)

    startup_complete_absolute_ms = get_highlight_metric(summary, "StartupTimer complete", "absolute_ms")
    if startup_complete_absolute_ms is not None:
        metrics["startup_complete_absolute_ms"] = round(startup_complete_absolute_ms, 3)

    shared_file_scan_duration_ms = get_highlight_metric(summary, "Construct CSharedFileList (share cache/scan)", "duration_ms")
    if shared_file_scan_duration_ms is not None:
        metrics["shared_file_scan_duration_ms"] = round(shared_file_scan_duration_ms, 3)
        if shared_directory_count > 0:
            metrics["shared_file_scan_ms_per_shared_directory"] = round(shared_file_scan_duration_ms / shared_directory_count, 2)
        if directory_count > 0:
            metrics["shared_file_scan_ms_per_tree_directory"] = round(shared_file_scan_duration_ms / directory_count, 2)
        if file_count > 0:
            metrics["shared_file_scan_ms_per_file"] = round(shared_file_scan_duration_ms / file_count, 2)

    shared_tree_build_duration_ms = get_highlight_metric(summary, "BuildSharedDirectoryTree done", "duration_ms")
    if shared_tree_build_duration_ms is not None:
        metrics["shared_tree_build_duration_ms"] = round(shared_tree_build_duration_ms, 3)
        if shared_directory_count > 0:
            metrics["shared_tree_build_ms_per_shared_directory"] = round(shared_tree_build_duration_ms / shared_directory_count, 2)
        if directory_count > 0:
            metrics["shared_tree_build_ms_per_tree_directory"] = round(shared_tree_build_duration_ms / directory_count, 2)

    visible_rows = get_counter_metric(summary, "shared.list.visible_rows")
    if visible_rows is not None:
        metrics["shared_visible_rows"] = int(visible_rows)

    broadband_budget = get_counter_metric(summary, "broadband.configured_upload_budget_bytes_per_sec")
    if broadband_budget is not None:
        metrics["broadband_upload_budget_bytes_per_sec"] = int(broadband_budget)

    readiness = summary.get("startup_diagnostics_readiness")
    if isinstance(readiness, dict):
        readiness_metrics = readiness.get("metrics")
        if isinstance(readiness_metrics, dict):
            for key, value in readiness_metrics.items():
                if isinstance(value, (int, float)):
                    metrics[key] = value

    return metrics


def build_comparison(left: dict[str, object], right: dict[str, object]) -> dict[str, object]:
    """Builds a compact comparison between two scenario summaries."""

    result = {
        "left": left["name"],
        "right": right["name"],
    }
    for metric_name, token in (
        ("shared_file_scan_duration_ms", "shared_file_scan_duration_delta_ms"),
        ("shared_tree_build_duration_ms", "shared_tree_build_duration_delta_ms"),
        ("startup_complete_absolute_ms", "startup_complete_absolute_delta_ms"),
        ("shared_files_ready_absolute_ms", "shared_files_ready_absolute_delta_ms"),
        ("shared_files_ready_after_startup_complete_ms", "shared_files_ready_after_startup_complete_delta_ms"),
        ("shared_scan_to_ready_ms", "shared_scan_to_ready_delta_ms"),
        ("shared_file_scan_ms_per_shared_directory", "shared_file_scan_per_shared_directory_delta_ms"),
        ("shared_file_scan_ms_per_file", "shared_file_scan_per_file_delta_ms"),
    ):
        left_value = get_derived_metric(left, metric_name)
        right_value = get_derived_metric(right, metric_name)
        if left_value is None or right_value is None:
            continue
        delta = left_value - right_value
        result[token] = round(delta, 3) if isinstance(delta, float) else delta

    for left_key, right_key, token in (
        ("shared_directory_count", "shared_directory_count", "shared_directory_count_delta"),
        ("file_count", "file_count", "tree_file_count_delta"),
        ("directory_count_including_root", "directory_count_including_root", "tree_directory_count_delta"),
        ("max_directory_path_length", "max_directory_path_length", "max_directory_path_length_delta"),
        ("max_file_path_length", "max_file_path_length", "max_file_path_length_delta"),
    ):
        if left_key == "shared_directory_count":
            left_value = int(left.get(left_key, 0) or 0)
            right_value = int(right.get(right_key, 0) or 0)
        else:
            left_tree = left.get("tree_summary")
            right_tree = right.get("tree_summary")
            if not isinstance(left_tree, dict) or not isinstance(right_tree, dict):
                continue
            left_value = int(left_tree.get(left_key, 0) or 0)
            right_value = int(right_tree.get(right_key, 0) or 0)
        result[token] = left_value - right_value
    return result


def get_file_state(path: Path) -> dict[str, object]:
    """Returns a compact state snapshot for a profile sidecar file."""

    if not path.exists():
        return {"exists": False}
    stat = path.stat()
    return {
        "exists": True,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "mtime": stat.st_mtime,
    }


def read_known_met_record_count(path: Path) -> int | None:
    """Reads the known.met record-count header without parsing file records."""

    if not path.exists() or path.stat().st_size < 5:
        return None
    with path.open("rb") as handle:
        handle.read(1)
        return struct.unpack("<I", handle.read(4))[0]


def unwrap_rest_payload(payload: object) -> object:
    """Returns the payload body inside the public REST envelope."""

    if isinstance(payload, dict) and "data" in payload and "meta" in payload:
        return payload["data"]
    return payload


def get_rest_status_model(base_url: str, api_key: str, *, timeout_seconds: float = 5.0) -> dict[str, object]:
    """Reads the status REST model from a live eMule process."""

    request = urllib.request.Request(base_url + "/api/v1/status", headers={"X-API-Key": api_key}, method="GET")
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8", errors="replace")
        payload = json.loads(body)
    model = unwrap_rest_payload(payload)
    if not isinstance(model, dict):
        raise RuntimeError(f"Expected status JSON object, got {model!r}.")
    return model


def get_rest_shared_startup_cache_status(base_url: str, api_key: str) -> dict[str, object]:
    """Reads shared startup-cache diagnostics from the status REST model."""

    status_model = get_rest_status_model(base_url, api_key)
    status = status_model.get("sharedStartupCache")
    if not isinstance(status, dict):
        raise RuntimeError(f"Expected sharedStartupCache JSON object, got {status!r}.")
    return status


def is_shared_startup_cache_idle_clean(status: dict[str, object]) -> bool:
    """Reports whether the live app says shared startup-cache persistence is settled."""

    save = status.get("save")
    if not isinstance(save, dict):
        return False
    return (
        status.get("available") is True
        and status.get("ready") is True
        and status.get("hashingCount") == 0
        and status.get("deferredHashingActive") is False
        and status.get("interruptedHashingInvalidatedCache") is False
        and save.get("running") is False
        and save.get("dirty") is False
        and save.get("phase") == "idle"
    )


def wait_for_shared_cache(
    path: Path,
    *,
    expected_known_records: int | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    require_rest_status: bool = False,
    timeout: float = WARM_RELAUNCH_SHARED_CACHE_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Waits until warm shared-cache dependencies are ready for relaunch reuse."""

    known_met_path = path.parent / "known.met"
    last_state: dict[str, object] = {}

    def resolve() -> dict[str, object] | None:
        nonlocal last_state
        cache_state = get_file_state(path)
        known_state = get_file_state(known_met_path)
        known_records = read_known_met_record_count(known_met_path)
        rest_status = None
        if base_url is not None and api_key is not None:
            rest_status = get_rest_shared_startup_cache_status(base_url, api_key)

        expected_records = 0 if expected_known_records is None else expected_known_records
        cache_ready = cache_state.get("exists") is True and int(cache_state.get("size", 0)) > 0
        known_ready = expected_records <= 0 or (known_records is not None and known_records >= expected_records)
        rest_ready = (
            is_shared_startup_cache_idle_clean(rest_status)
            if rest_status is not None
            else not require_rest_status
        )
        last_state = {
            "shared_cache": cache_state,
            "known_met": known_state,
            "known_met_record_count": known_records,
            "expected_known_records": expected_known_records,
            "shared_startup_cache": rest_status,
        }
        if cache_ready and known_ready and rest_ready:
            return dict(last_state)
        return None

    try:
        return live_common.wait_for(
            resolve,
            timeout=timeout,
            interval=0.25,
            description="shared startup cache dependency persistence",
        )
    except RuntimeError as exc:
        raise RuntimeError(f"{exc} Last shared cache dependency state: {last_state!r}") from exc


def collect_startup_diagnostics_metrics(
    startup_diagnostics_path: Path,
    summary: dict[str, object],
    *,
    require_startup_diagnostics: bool,
    wait_for_shared_hashing_done: bool,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Reads startup diagnostics metrics or records a missing trace for non-instrumented baselines."""

    try:
        startup_diagnostics_text = live_common.wait_for_startup_diagnostics_complete(
            startup_diagnostics_path,
            timeout=120.0 if require_startup_diagnostics else 5.0,
        )
    except Exception as exc:
        if require_startup_diagnostics:
            raise
        summary["startup_diagnostics_status"] = "missing"
        summary["startup_diagnostics_error"] = str(exc)
        summary["startup_diagnostics_phase_count"] = 0
        summary["startup_diagnostics_counter_count"] = 0
        summary["startup_diagnostics_counters"] = {}
        summary["startup_diagnostics_readiness"] = {}
        summary["startup_diagnostics_highlights"] = {}
        summary["startup_diagnostics_top_slowest_phases"] = []
        summary["startup_diagnostics_derived_metrics"] = {}
        return [], []

    startup_diagnostics_phases = live_common.parse_startup_diagnostics(startup_diagnostics_text)
    startup_diagnostics_counters = live_common.parse_startup_diagnostics_counters(startup_diagnostics_text)
    if wait_for_shared_hashing_done:
        pending_hashes_at_readiness = live_common.get_counter_by_id(
            startup_diagnostics_counters,
            "shared.model.pending_hashes",
        )
        pending_hash_count = int(pending_hashes_at_readiness["value"]) if pending_hashes_at_readiness is not None else 0
        shared_files_hashing_done = live_common.get_phase_by_id(
            startup_diagnostics_phases,
            live_common.STARTUP_DIAGNOSTICS_SHARED_FILES_HASHING_DONE_PHASE_ID,
        )
        if pending_hash_count > 0 and shared_files_hashing_done is None:
            startup_diagnostics_text = live_common.wait_for_startup_diagnostics_phase(
                startup_diagnostics_path,
                live_common.STARTUP_DIAGNOSTICS_SHARED_FILES_HASHING_DONE_PHASE_ID,
                timeout=120.0,
            )
            startup_diagnostics_phases = live_common.parse_startup_diagnostics(startup_diagnostics_text)
            startup_diagnostics_counters = live_common.parse_startup_diagnostics_counters(startup_diagnostics_text)

    summary["startup_diagnostics_status"] = "present"
    summary["startup_diagnostics_phase_count"] = len(startup_diagnostics_phases)
    summary["startup_diagnostics_counter_count"] = len(startup_diagnostics_counters)
    summary["startup_diagnostics_counters"] = live_common.summarize_startup_diagnostics_counters(startup_diagnostics_counters)
    summary["startup_diagnostics_readiness"] = live_common.summarize_shared_files_readiness(
        startup_diagnostics_phases,
        startup_diagnostics_counters,
    )
    summary["startup_diagnostics_highlights"] = live_common.summarize_startup_diagnostics(
        startup_diagnostics_phases,
        HIGHLIGHTED_PHASES,
    )
    summary["startup_diagnostics_top_slowest_phases"] = live_common.get_top_slowest_phases(startup_diagnostics_phases, limit=8)
    summary["startup_diagnostics_derived_metrics"] = build_derived_metrics(summary)
    return startup_diagnostics_phases, startup_diagnostics_counters


def run_scenario(
    app_exe: Path,
    seed_config_dir: Path,
    scenario_dir: Path,
    shared_root: Path,
    name: str,
    *,
    require_startup_diagnostics: bool,
    warm_relaunch: bool,
) -> dict[str, object]:
    """Executes one startup-diagnostics scenario and returns its machine-readable result."""

    scenario = build_scenario_definition(name=name, artifacts_dir=scenario_dir, shared_root=shared_root)
    fixture = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=scenario_dir,
        shared_dirs=list(scenario["shared_dirs"]),
        scenario_id=name,
    )

    summary = {
        "name": scenario["name"],
        "description": scenario["description"],
        "status": "failed",
        "artifact_dir": str(scenario_dir),
        "profile_base": str(fixture["profile_base"]),
        "startup_diagnostics_path": str(fixture["startup_diagnostics_path"]),
        "command_line": subprocess.list2cmdline(
            [str(app_exe), "-ignoreinstances", "-c", str(fixture["profile_base"])]
        ),
        "shared_directory_count": len(list(scenario["shared_dirs"])),
        "shared_directory_metrics": live_common.summarize_shared_directories(list(scenario["shared_dirs"])),
        "shared_directories_preview": list(scenario["shared_dirs"])[:3],
        "shared_directories_tail": list(scenario["shared_dirs"])[-3:],
        "tree_summary": scenario["tree_summary"],
    }

    app = None
    try:
        app = live_common.launch_app(
            app_exe,
            fixture["profile_base"],
            minimized_to_tray=False,
            requires_interactive_ui=True,
        )
        main_window = live_common.wait_for_main_window(app)
        main_hwnd = main_window.handle
        live_common.bring_window_to_front(main_window)

        summary["process_id"] = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        summary["main_window_rect"] = list(win32gui.GetWindowRect(main_hwnd))
        summary["main_window_show_cmd"] = live_common.get_window_show_cmd(main_hwnd)
        summary["main_window_is_maximized"] = summary["main_window_show_cmd"] == win32con.SW_SHOWMAXIMIZED
        if not summary["main_window_is_maximized"]:
            raise RuntimeError(f"Expected scenario '{name}' to start maximized, got showCmd={summary['main_window_show_cmd']}.")

        startup_diagnostics_phases, _startup_diagnostics_counters = collect_startup_diagnostics_metrics(
            fixture["startup_diagnostics_path"],
            summary,
            require_startup_diagnostics=require_startup_diagnostics,
            wait_for_shared_hashing_done=require_startup_diagnostics,
        )
        if startup_diagnostics_phases:
            live_common.enforce_deferred_shared_hashing_boundary(startup_diagnostics_phases, scenario["name"])

        if warm_relaunch:
            shared_cache_path = Path(str(fixture["config_dir"])) / "sharedcache.dat"
            summary["shared_cache_path"] = str(shared_cache_path)
            summary["shared_cache_ready_before_relaunch"] = wait_for_shared_cache(
                shared_cache_path,
                expected_known_records=int(scenario["tree_summary"].get("file_count", 0) or 0),
            )

            first_launch_trace_artifact = scenario_dir / "startup-diagnostics-first-launch.trace.json"
            first_launch_trace_artifact.write_bytes(Path(str(fixture["startup_diagnostics_path"])).read_bytes())
            summary["first_launch_trace_artifact"] = str(first_launch_trace_artifact)
            Path(str(fixture["startup_diagnostics_path"])).unlink(missing_ok=True)

            live_common.close_app_cleanly(app)
            app = None

            relaunch_summary = {
                "name": scenario["name"] + ".warm-relaunch",
                "shared_directory_count": summary["shared_directory_count"],
                "tree_summary": summary["tree_summary"],
            }
            app = live_common.launch_app(
                app_exe,
                fixture["profile_base"],
                minimized_to_tray=False,
                requires_interactive_ui=True,
            )
            main_window = live_common.wait_for_main_window(app)
            main_hwnd = main_window.handle
            live_common.bring_window_to_front(main_window)

            relaunch_summary["process_id"] = win32process.GetWindowThreadProcessId(main_hwnd)[1]
            relaunch_summary["main_window_rect"] = list(win32gui.GetWindowRect(main_hwnd))
            relaunch_summary["main_window_show_cmd"] = live_common.get_window_show_cmd(main_hwnd)
            relaunch_summary["main_window_is_maximized"] = relaunch_summary["main_window_show_cmd"] == win32con.SW_SHOWMAXIMIZED
            if not relaunch_summary["main_window_is_maximized"]:
                raise RuntimeError(
                    f"Expected warm relaunch for scenario '{name}' to start maximized, "
                    f"got showCmd={relaunch_summary['main_window_show_cmd']}."
                )

            relaunch_diagnostics_phases, _relaunch_diagnostics_counters = collect_startup_diagnostics_metrics(
                fixture["startup_diagnostics_path"],
                relaunch_summary,
                require_startup_diagnostics=require_startup_diagnostics,
                wait_for_shared_hashing_done=require_startup_diagnostics,
            )
            if relaunch_diagnostics_phases:
                live_common.enforce_deferred_shared_hashing_boundary(
                    relaunch_diagnostics_phases,
                    scenario["name"] + ".warm-relaunch",
                )

            relaunch_trace_artifact = scenario_dir / "startup-diagnostics-warm-relaunch.trace.json"
            relaunch_trace_artifact.write_bytes(Path(str(fixture["startup_diagnostics_path"])).read_bytes())
            relaunch_summary["trace_artifact"] = str(relaunch_trace_artifact)
            summary["warm_relaunch"] = relaunch_summary
            summary["warm_relaunch_comparison"] = build_comparison(summary, relaunch_summary)

        summary["status"] = "passed"
        summary["error"] = None
        live_common.write_json(scenario_dir / "startup-diagnostics-scenarios-result.json", summary)
        return summary
    except Exception as exc:
        summary["error"] = str(exc)
        if app is not None:
            try:
                main_window = app.top_window()
                live_common.dump_window_tree(main_window.handle, scenario_dir / "window-tree-failure.json")
                try:
                    image = main_window.capture_as_image()
                    image.save(scenario_dir / "failure.png")
                except Exception:
                    pass
            except Exception:
                pass
        live_common.write_json(scenario_dir / "startup-diagnostics-scenarios-result.json", summary)
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


def main(argv: list[str]) -> int:
    """Parses arguments, runs the requested scenarios, and writes a combined summary."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--startup-trace-mode", choices=["required", "optional"], default="required")
    parser.add_argument("--warm-relaunch", action="store_true")
    parser.add_argument("--shared-root", default=r"C:\tmp\00_long_paths")
    parser.add_argument(
        "--scenario",
        dest="scenarios",
        action="append",
        choices=[
            "baseline-no-shares",
            "fixture-three-files",
            "long-paths-root-only",
            "long-paths-recursive",
            "long-path-output-root-only",
            "long-path-output-recursive",
            "long-path-emule-fixture-root-only",
            "long-path-emule-fixture-recursive",
            "shared-files-robustness-root-only",
            "shared-files-robustness-recursive",
        ],
    )
    args = parser.parse_args(argv)

    live_common.require_pywinauto()
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="startup-diagnostics-scenarios",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    artifacts_dir = paths.source_artifacts_dir
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)

    scenario_names = args.scenarios or [
        "baseline-no-shares",
        "fixture-three-files",
        "long-paths-root-only",
        "long-paths-recursive",
        "long-path-output-root-only",
        "long-path-output-recursive",
        "long-path-emule-fixture-root-only",
        "long-path-emule-fixture-recursive",
        "shared-files-robustness-root-only",
        "shared-files-robustness-recursive",
    ]
    shared_root = Path(args.shared_root).resolve()
    generated_fixture_manifest = None
    if any(
        name in {
            "long-paths-root-only",
            "long-paths-recursive",
            "long-path-output-root-only",
            "long-path-output-recursive",
            "shared-files-robustness-root-only",
            "shared-files-robustness-recursive",
        }
        for name in scenario_names
    ):
        generated_fixture_manifest = generated_fixture.ensure_fixture(shared_root)

    combined = {
        "generated_at": None,
        "status": "passed",
        "app_exe": str(paths.app_exe),
        "seed_config_dir": str(seed_config_dir),
        "artifact_dir": str(artifacts_dir),
        "shared_root": live_common.win_path(shared_root, trailing_slash=True),
        "generated_fixture_manifest_path": (
            str(Path(str(generated_fixture_manifest["manifest_path"])).resolve())
            if generated_fixture_manifest is not None
            else None
        ),
        "startup_trace_mode": args.startup_trace_mode,
        "scenarios": [],
    }

    failures = []
    for name in scenario_names:
        scenario_dir = artifacts_dir / name
        scenario_dir.mkdir(parents=True, exist_ok=True)
        result = run_scenario(
            app_exe=paths.app_exe,
            seed_config_dir=seed_config_dir,
            scenario_dir=scenario_dir,
            shared_root=shared_root,
            name=name,
            require_startup_diagnostics=(args.startup_trace_mode == "required"),
            warm_relaunch=args.warm_relaunch,
        )
        combined["scenarios"].append(result)
        if result["status"] != "passed":
            failures.append(name)

    results_by_name = {str(result["name"]): result for result in combined["scenarios"]}
    comparisons = []
    for left_name, right_name in (
        ("long-paths-recursive", "long-paths-root-only"),
        ("long-path-output-recursive", "long-path-output-root-only"),
        ("long-path-emule-fixture-recursive", "long-path-emule-fixture-root-only"),
        ("shared-files-robustness-recursive", "shared-files-robustness-root-only"),
        ("long-path-output-recursive", "long-path-emule-fixture-recursive"),
        ("shared-files-robustness-recursive", "long-path-output-recursive"),
        ("long-paths-recursive", "baseline-no-shares"),
    ):
        left = results_by_name.get(left_name)
        right = results_by_name.get(right_name)
        if left is None or right is None:
            continue
        comparisons.append(build_comparison(left, right))
    combined["comparisons"] = comparisons

    combined["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    if failures:
        combined["status"] = "failed"

    live_common.write_json(artifacts_dir / "startup-diagnostics-scenarios-result.json", combined)
    harness_cli_common.publish_run_artifacts(paths)
    summary_payload = harness_cli_common.build_startup_diagnostics_summary(
        status=str(combined["status"]),
        paths=paths,
        shared_root=shared_root,
        error_message="" if not failures else "Startup-profile scenarios failed: " + ", ".join(failures),
    )
    summary_path = paths.run_report_dir / "startup-diagnostics-scenarios-summary.json"
    harness_cli_common.write_json_file(summary_path, summary_payload)
    harness_cli_common.publish_latest_report(paths)
    harness_cli_common.update_harness_summary(paths.repo_root, startup_diagnostics_summary_path=summary_path)
    harness_cli_common.cleanup_source_artifacts(paths)
    if failures:
        raise RuntimeError("Startup-profile scenarios failed: " + ", ".join(failures))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
