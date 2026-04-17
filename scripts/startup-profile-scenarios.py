"""Builds startup-profile artifacts for deterministic live-profile scenarios."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import win32con
import win32gui
import win32process

import emule_live_profile_common as live_common
import test_create_long_paths_tree as generated_fixture

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
    """Resolves one named startup-profile scenario into concrete shared roots and metadata."""

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
        tree_summary = live_common.summarize_existing_tree(resolved_root)
        tree_summary["shared_directory_count"] = 1
        return {
            "name": name,
            "description": "Shares only the long-path root without expanding child directories into shareddir.dat.",
            "shared_dirs": [live_common.win_path(resolved_root, trailing_slash=True)],
            "tree_summary": tree_summary,
        }
    if name == "long-paths-recursive":
        shared_dirs = live_common.enumerate_recursive_directories(resolved_root)
        tree_summary = live_common.summarize_existing_tree(resolved_root)
        tree_summary["shared_directory_count"] = len(shared_dirs)
        return {
            "name": name,
            "description": "Expands the long-path root recursively into shareddir.dat before launch.",
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
    raise RuntimeError(f"Unknown startup-profile scenario: {name}")


def get_highlight_metric(summary: dict[str, object], name: str, field: str) -> float | None:
    """Returns one highlighted startup metric from a scenario result when present."""

    highlights = summary.get("startup_profile_highlights")
    if not isinstance(highlights, dict):
        return None
    phase = highlights.get(name)
    if not isinstance(phase, dict):
        return None
    value = phase.get(field)
    return float(value) if value is not None else None


def get_derived_metric(summary: dict[str, object], key: str) -> float | int | None:
    """Returns one derived startup-profile metric from a scenario result when present."""

    metrics = summary.get("startup_profile_derived_metrics")
    if not isinstance(metrics, dict):
        return None
    value = metrics.get(key)
    if isinstance(value, (int, float)):
        return value
    return None


def get_counter_metric(summary: dict[str, object], counter_id: str, field: str = "value") -> float | int | None:
    """Returns one summarized startup-profile counter value from a scenario result when present."""

    counters = summary.get("startup_profile_counters")
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
    """Adds normalized startup-profile metrics that are easier to compare between scenarios."""

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

    readiness = summary.get("startup_profile_readiness")
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


def run_scenario(app_exe: Path, seed_config_dir: Path, scenario_dir: Path, shared_root: Path, name: str) -> dict[str, object]:
    """Executes one startup-profile scenario and returns its machine-readable result."""

    scenario = build_scenario_definition(name=name, artifacts_dir=scenario_dir, shared_root=shared_root)
    fixture = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=scenario_dir,
        shared_dirs=list(scenario["shared_dirs"]),
    )

    summary = {
        "name": scenario["name"],
        "description": scenario["description"],
        "status": "failed",
        "artifact_dir": str(scenario_dir),
        "profile_base": str(fixture["profile_base"]),
        "startup_profile_path": str(fixture["startup_profile_path"]),
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
        app = live_common.launch_app(app_exe, fixture["profile_base"])
        main_window = live_common.wait_for_main_window(app)
        main_hwnd = main_window.handle
        main_window.set_focus()

        summary["process_id"] = win32process.GetWindowThreadProcessId(main_hwnd)[1]
        summary["main_window_rect"] = list(win32gui.GetWindowRect(main_hwnd))
        summary["main_window_show_cmd"] = live_common.get_window_show_cmd(main_hwnd)
        summary["main_window_is_maximized"] = summary["main_window_show_cmd"] == win32con.SW_SHOWMAXIMIZED
        if not summary["main_window_is_maximized"]:
            raise RuntimeError(f"Expected scenario '{name}' to start maximized, got showCmd={summary['main_window_show_cmd']}.")

        startup_profile_text = live_common.wait_for_startup_profile_complete(fixture["startup_profile_path"])
        startup_profile_phases = live_common.parse_startup_profile(startup_profile_text)
        startup_profile_counters = live_common.parse_startup_profile_counters(startup_profile_text)
        summary["startup_profile_phase_count"] = len(startup_profile_phases)
        summary["startup_profile_counter_count"] = len(startup_profile_counters)
        summary["startup_profile_counters"] = live_common.summarize_startup_profile_counters(startup_profile_counters)
        summary["startup_profile_readiness"] = live_common.summarize_shared_files_readiness(
            startup_profile_phases,
            startup_profile_counters,
        )
        summary["startup_profile_highlights"] = live_common.summarize_startup_profile(
            startup_profile_phases,
            HIGHLIGHTED_PHASES,
        )
        summary["startup_profile_top_slowest_phases"] = live_common.get_top_slowest_phases(startup_profile_phases, limit=8)
        summary["startup_profile_derived_metrics"] = build_derived_metrics(summary)
        live_common.enforce_deferred_shared_hashing_boundary(startup_profile_phases, scenario["name"])
        summary["status"] = "passed"
        summary["error"] = None
        live_common.write_json(scenario_dir / "result.json", summary)
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
        live_common.write_json(scenario_dir / "result.json", summary)
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
    parser.add_argument("--app-exe", required=True)
    parser.add_argument("--seed-config-dir", required=True)
    parser.add_argument("--artifacts-dir", required=True)
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

    artifacts_dir = Path(args.artifacts_dir).resolve()
    artifacts_dir.mkdir(parents=True, exist_ok=True)

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
        "app_exe": str(Path(args.app_exe).resolve()),
        "seed_config_dir": str(Path(args.seed_config_dir).resolve()),
        "artifact_dir": str(artifacts_dir),
        "shared_root": live_common.win_path(shared_root, trailing_slash=True),
        "generated_fixture_manifest_path": (
            str(Path(str(generated_fixture_manifest["manifest_path"])).resolve())
            if generated_fixture_manifest is not None
            else None
        ),
        "scenarios": [],
    }

    failures = []
    for name in scenario_names:
        scenario_dir = artifacts_dir / name
        scenario_dir.mkdir(parents=True, exist_ok=True)
        result = run_scenario(
            app_exe=Path(args.app_exe).resolve(),
            seed_config_dir=Path(args.seed_config_dir).resolve(),
            scenario_dir=scenario_dir,
            shared_root=shared_root,
            name=name,
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

    live_common.write_json(artifacts_dir / "startup-profiles-summary.json", combined)
    if failures:
        raise RuntimeError("Startup-profile scenarios failed: " + ", ".join(failures))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
