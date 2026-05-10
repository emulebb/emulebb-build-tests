"""Real Win32 UI regression for shared-hash shutdown and interruption scenarios."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import win32api
import win32con
import win32event
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
shared_files_ui = load_local_module("shared_files_ui_e2e", "shared-files-ui-e2e.py")

SCENARIO_NAMES = [
    "clean-close-during-hash-startup",
    "clean-close-during-hash-files-page",
    "clean-close-during-hash-files-page-warm-relaunch",
    "clean-close-during-hash-files-page-warm-relaunch-many-files",
    "clean-close-during-hash-partial-results",
    "clean-close-during-hash-partial-results-many-files",
    "hard-kill-during-hash-startup",
    "hard-kill-during-hash-startup-warm-relaunch",
    "hard-kill-during-hash-startup-warm-relaunch-many-files",
    "hard-kill-during-hash-files-page",
    "hard-kill-during-hash-files-page-warm-relaunch",
    "hard-kill-during-hash-files-page-warm-relaunch-many-files",
    "hard-kill-during-hash-partial-results",
    "hard-kill-during-hash-partial-results-many-files",
    "reload-during-hash-files-page",
    "reload-during-hash-files-page-many-files",
    "reload-then-clean-close-during-hash-files-page",
    "reload-then-clean-close-during-hash-files-page-many-files",
    "reload-then-hard-kill-during-hash-files-page",
    "reload-then-hard-kill-during-hash-files-page-many-files",
    "clean-close-during-hash-startup-warm-relaunch",
    "clean-close-during-hash-startup-warm-relaunch-many-files",
    "clean-close-during-hash-repeated-cycle",
    "clean-close-during-hash-repeated-cycle-many-files",
    "hard-kill-during-hash-repeated-cycle",
    "hard-kill-during-hash-repeated-cycle-many-files",
]
MAX_CLEAN_SHUTDOWN_DURATION_MS = 20000.0
SHARED_HASH_DRAIN_TIMEOUT_SECONDS = 300.0
STARTUP_CACHE_FILE_NAME = "sharedcache.dat"
DUPLICATE_PATH_CACHE_FILE_NAME = "shareddups.dat"
HASH_STRESS_FILE_SPECS = [
    ("alpha_hash_payload.bin", 96 * 1024 * 1024, 0x61),
    ("beta_hash_payload.bin", 96 * 1024 * 1024, 0x62),
    ("gamma_hash_payload.bin", 96 * 1024 * 1024, 0x63),
]
HASH_STRESS_FILE_SPECS_MANY = [
    ("alpha_hash_payload.bin", 64 * 1024 * 1024, 0x61),
    ("beta_hash_payload.bin", 64 * 1024 * 1024, 0x62),
    ("gamma_hash_payload.bin", 64 * 1024 * 1024, 0x63),
    ("delta_hash_payload.bin", 64 * 1024 * 1024, 0x64),
    ("epsilon_hash_payload.bin", 64 * 1024 * 1024, 0x65),
    ("zeta_hash_payload.bin", 64 * 1024 * 1024, 0x66),
]
HASH_STRESS_NESTED_SEGMENTS = [
    "segment-00-shared-hash-startup",
    "segment-01-shared-hash-recursive",
    "segment-02-shared-hash-drain",
    "segment-03-shared-hash-timeout",
    "segment-04-shared-hash-recovery",
]


def write_json(path: Path, payload) -> None:
    """Writes one UTF-8 JSON artifact with stable formatting."""

    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def write_pattern_file(path: Path, size_bytes: int, fill_byte: int) -> None:
    """Writes one deterministic large file without building the full payload in memory."""

    path.parent.mkdir(parents=True, exist_ok=True)
    chunk = bytes([fill_byte]) * (1024 * 1024)
    remaining = size_bytes
    with path.open("wb") as handle:
        while remaining > 0:
            current = chunk if remaining >= len(chunk) else chunk[:remaining]
            handle.write(current)
            remaining -= len(current)


def get_hash_stress_file_specs_for_scenario(name: str) -> list[tuple[str, int, int]]:
    """Returns the shared-hash fixture file layout for one scenario."""

    return list(HASH_STRESS_FILE_SPECS_MANY if "many-files" in name else HASH_STRESS_FILE_SPECS)


def prepare_hash_interruption_fixture(
    seed_config_dir: Path,
    scenario_dir: Path,
    *,
    file_specs: list[tuple[str, int, int]] | None = None,
) -> dict[str, object]:
    """Creates one recursive shared-tree fixture that keeps shared hashing active after startup."""

    shared_root = scenario_dir / "shared-hash-root"
    expected_visible_names: list[str] = []
    for index, (file_name, size_bytes, fill_byte) in enumerate(file_specs or HASH_STRESS_FILE_SPECS):
        branch_root = shared_root / f"branch-{index:02d}-shared-hash-interruption"
        current = branch_root
        for segment in HASH_STRESS_NESTED_SEGMENTS:
            current = current / f"{segment}-{index:02d}"
        file_path = current / file_name
        write_pattern_file(file_path, size_bytes, fill_byte)
        expected_visible_names.append(file_name)

    fixture = live_common.prepare_profile_base(
        seed_config_dir=seed_config_dir,
        artifacts_dir=scenario_dir,
        shared_dirs=live_common.enumerate_recursive_directories(shared_root),
    )
    live_common.apply_live_network_policy(Path(str(fixture["config_dir"])))
    fixture.update(
        {
            "shared_root": live_common.win_path(shared_root.resolve(), trailing_slash=True),
            "expected_row_count": len(expected_visible_names),
            "expected_visible_names": sorted(expected_visible_names, key=str.lower),
        }
    )
    return fixture


def archive_trace_if_present(source_path: Path, destination_path: Path) -> None:
    """Copies one startup trace when it exists."""

    if source_path.exists():
        shutil.copy2(source_path, destination_path)


def launch_app_with_fresh_startup_trace(app_exe: Path, fixture: dict[str, object]) -> Application:
    """Starts eMule after removing any trace left by an earlier launch on the same profile."""

    startup_profile_path = Path(str(fixture["startup_profile_path"]))
    startup_profile_path.unlink(missing_ok=True)
    return live_common.launch_app(app_exe, Path(str(fixture["profile_base"])))


def capture_sidecar_state(config_dir: Path) -> dict[str, dict[str, object]]:
    """Captures the persisted shared startup-cache sidecar state for one profile config dir."""

    state: dict[str, dict[str, object]] = {}
    for file_name in (STARTUP_CACHE_FILE_NAME, DUPLICATE_PATH_CACHE_FILE_NAME):
        path = config_dir / file_name
        state[file_name] = {
            "exists": path.exists(),
            "size_bytes": path.stat().st_size if path.exists() else 0,
        }
    return state


def ensure_sidecars_absent(sidecar_state: dict[str, dict[str, object]], *, description: str) -> None:
    """Fails when an interrupted hashing path leaves warm-cache sidecars behind."""

    unexpected = [
        f"{name} ({entry['size_bytes']} bytes)"
        for name, entry in sidecar_state.items()
        if bool(entry.get("exists"))
    ]
    if unexpected:
        raise RuntimeError(f"{description} unexpectedly left startup-cache sidecars behind: {', '.join(unexpected)}")


def ensure_startup_cache_present(sidecar_state: dict[str, dict[str, object]], *, description: str) -> None:
    """Fails when a successful clean shutdown did not leave behind the warm shared startup cache."""

    shared_cache = sidecar_state.get(STARTUP_CACHE_FILE_NAME, {})
    if not bool(shared_cache.get("exists")) or int(shared_cache.get("size_bytes", 0)) <= 0:
        raise RuntimeError(f"{description} did not persist {STARTUP_CACHE_FILE_NAME}.")


def get_readiness_metric(summary: dict[str, object], metric_name: str) -> float | int | None:
    """Returns one shared readiness metric from the summarized startup-profile bundle."""

    readiness = summary.get("startup_profile_readiness")
    if not isinstance(readiness, dict):
        return None
    metrics = readiness.get("metrics")
    if not isinstance(metrics, dict):
        return None
    value = metrics.get(metric_name)
    if isinstance(value, (int, float)):
        return value
    return None


def wait_for_hashing_active(startup_profile_path: Path, *, timeout: float = 90.0) -> dict[str, object]:
    """Waits until startup reached Shared Files readiness with queued hashing still in flight."""

    def resolve() -> dict[str, object] | None:
        if not startup_profile_path.exists():
            return None
        try:
            text = startup_profile_path.read_text(encoding="utf-8", errors="ignore")
            phases = live_common.parse_startup_profile(text)
            counters = live_common.parse_startup_profile_counters(text)
        except Exception:
            return None

        ready_phase = live_common.get_phase_by_id(
            phases,
            live_common.STARTUP_PROFILE_SHARED_FILES_READY_PHASE_ID,
        )
        if ready_phase is None:
            return None

        hashing_done_phase = live_common.get_phase_by_id(
            phases,
            live_common.STARTUP_PROFILE_SHARED_FILES_HASHING_DONE_PHASE_ID,
        )
        if hashing_done_phase is not None:
            raise RuntimeError("Hashing completed before the interruption target was reached.")

        pending_hashes = live_common.get_counter_by_id(counters, "shared.model.pending_hashes")
        pending_hash_count = int(pending_hashes["value"]) if pending_hashes is not None else 0
        if pending_hash_count <= 0:
            return None

        return {
            "shared_files_ready_absolute_ms": float(ready_phase["absolute_ms"]),
            "pending_hashes_at_readiness": pending_hash_count,
        }

    return live_common.wait_for(resolve, timeout=timeout, interval=0.25, description="shared hashing active after readiness")


def wait_for_expected_shared_files(
    main_hwnd: int,
    process_id: int,
    expected_names: list[str],
    *,
    startup_profile_path: Path | None = None,
) -> dict[str, object]:
    """Opens the Shared Files page and waits until the expected visible rows converge."""

    hash_drain_state: dict[str, object] | None = None
    if startup_profile_path is not None:
        hash_drain_state = wait_for_shared_hash_drain(
            startup_profile_path,
            expected_count=len(expected_names),
        )

    list_hwnd = shared_files_ui.open_shared_files_list_page(main_hwnd)
    row_count = shared_files_ui.wait_for_exact_list_count(list_hwnd, len(expected_names))
    process_handle = shared_files_ui.open_process(process_id)
    try:
        visible_names = shared_files_ui.get_list_names(process_handle, list_hwnd, row_count)
    finally:
        shared_files_ui.close_process(process_handle)

    if sorted(visible_names, key=str.lower) != expected_names:
        raise RuntimeError(f"Unexpected Shared Files rows: {visible_names!r}")
    return {
        "row_count": row_count,
        "visible_names": visible_names,
        "hash_drain": hash_drain_state,
    }


def open_shared_files_page_snapshot(main_hwnd: int) -> dict[str, object]:
    """Opens the Shared Files page and records the immediate visible row count."""

    list_hwnd = shared_files_ui.open_shared_files_list_page(main_hwnd)
    time.sleep(0.2)
    return {
        "row_count": int(win32gui.SendMessage(list_hwnd, shared_files_ui.LVM_GETITEMCOUNT, 0, 0)),
    }


def get_counter_int(counters: list[dict[str, object]], counter_id: str) -> int:
    """Returns the latest integer value for one startup-profile counter."""

    counter = live_common.get_counter_by_id(counters, counter_id)
    return int(counter["value"]) if counter is not None else 0


def read_shared_hash_drain_state(startup_profile_path: Path, *, expected_count: int) -> dict[str, object] | None:
    """Reads the current startup-profile counters needed to judge shared-hash drain."""

    if not startup_profile_path.exists():
        return None

    text = startup_profile_path.read_text(encoding="utf-8", errors="ignore")
    phases = live_common.parse_startup_profile(text)
    counters = live_common.parse_startup_profile_counters(text)
    hashing_done_phase = live_common.get_phase_by_id(
        phases,
        live_common.STARTUP_PROFILE_SHARED_FILES_HASHING_DONE_PHASE_ID,
    )
    state: dict[str, object] = {
        "expected_count": expected_count,
        "completed_files": get_counter_int(counters, "shared.hash.completed_files"),
        "waiting_queue_depth": get_counter_int(counters, "shared.hash.waiting_queue_depth"),
        "currently_hashing": get_counter_int(counters, "shared.hash.currently_hashing"),
        "hashing_done_observed": hashing_done_phase is not None,
        "hashing_done_shared_files": get_counter_int(counters, "shared.model.hashing_done_shared_files"),
        "hashing_done_visible_rows": get_counter_int(counters, "shared.model.hashing_done_visible_rows"),
        "model_shared_files": get_counter_int(counters, "shared.model.shared_files"),
        "model_visible_rows": get_counter_int(counters, "shared.model.visible_rows"),
    }
    if hashing_done_phase is not None:
        state["hashing_done_absolute_ms"] = float(hashing_done_phase["absolute_ms"])
    return state


def wait_for_shared_hash_drain(
    startup_profile_path: Path,
    *,
    expected_count: int,
    timeout: float = SHARED_HASH_DRAIN_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Waits until startup profiling shows shared hashing drained for the expected files."""

    deadline = time.time() + timeout
    last_state: dict[str, object] | str | None = None
    while time.time() < deadline:
        try:
            state = read_shared_hash_drain_state(startup_profile_path, expected_count=expected_count)
        except Exception as exc:
            last_state = f"{type(exc).__name__}: {exc}"
            time.sleep(0.5)
            continue

        if state is None:
            last_state = "startup profile not created yet"
            time.sleep(0.5)
            continue

        last_state = state
        hashing_done_observed = bool(state["hashing_done_observed"])
        completed_files = int(state["completed_files"])
        waiting_queue_depth = int(state["waiting_queue_depth"])
        currently_hashing = int(state["currently_hashing"])
        hashing_done_shared_files = int(state["hashing_done_shared_files"])
        hashing_done_visible_rows = int(state["hashing_done_visible_rows"])

        if hashing_done_observed:
            if hashing_done_shared_files >= expected_count and hashing_done_visible_rows >= expected_count:
                return state
            raise RuntimeError(
                "Shared hashing reported completion before the expected rows were present. "
                f"Last value: {state!r}"
            )
        if completed_files >= expected_count and waiting_queue_depth == 0 and currently_hashing == 0:
            return state

        time.sleep(0.5)

    raise RuntimeError(f"Timed out waiting for shared hashing to drain. Last value: {last_state!r}")


def wait_for_partial_hash_progress(
    startup_profile_path: Path,
    *,
    expected_count: int,
    timeout: float = 90.0,
) -> dict[str, object]:
    """Waits until shared hashing has completed some files while more work remains."""

    deadline = time.time() + timeout
    last_state: dict[str, object] | str | None = None
    while time.time() < deadline:
        if not startup_profile_path.exists():
            last_state = "startup profile not created yet"
            time.sleep(0.25)
            continue

        try:
            text = startup_profile_path.read_text(encoding="utf-8", errors="ignore")
            phases = live_common.parse_startup_profile(text)
            counters = live_common.parse_startup_profile_counters(text)
        except Exception as exc:
            last_state = f"{type(exc).__name__}: {exc}"
            time.sleep(0.25)
            continue

        hashing_done_phase = live_common.get_phase_by_id(
            phases,
            live_common.STARTUP_PROFILE_SHARED_FILES_HASHING_DONE_PHASE_ID,
        )
        completed_count = get_counter_int(counters, "shared.hash.completed_files")
        waiting_queue_depth = get_counter_int(counters, "shared.hash.waiting_queue_depth")
        currently_hashing = get_counter_int(counters, "shared.hash.currently_hashing")
        last_state = {
            "completed_files": completed_count,
            "expected_count": expected_count,
            "waiting_queue_depth": waiting_queue_depth,
            "currently_hashing": currently_hashing,
            "hashing_done_observed": hashing_done_phase is not None,
        }

        if 0 < completed_count < expected_count and hashing_done_phase is None:
            return last_state
        if completed_count >= expected_count or hashing_done_phase is not None:
            raise RuntimeError("Hashing completed before the partial-results interruption target was reached.")

        time.sleep(0.25)

    raise RuntimeError(f"Timed out waiting for partial shared-hash progress. Last value: {last_state!r}")


def wait_for_process_exit(process_id: int, *, timeout: float = 15.0) -> None:
    """Waits until the target process exits."""

    try:
        process_handle = win32api.OpenProcess(win32con.SYNCHRONIZE, False, int(process_id))
    except Exception:
        return
    try:
        wait_result = win32event.WaitForSingleObject(process_handle, int(timeout * 1000))
        if wait_result != win32event.WAIT_OBJECT_0:
            raise RuntimeError(f"Timed out waiting for process {process_id} to exit.")
    finally:
        win32api.CloseHandle(process_handle)


def hard_kill_app(app: Application) -> int:
    """Forcefully terminates the running app process."""

    process_id = int(getattr(app, "process", 0) or 0)
    if process_id <= 0:
        raise RuntimeError("Unable to resolve the running process id for hard-kill.")
    completed = subprocess.run(
        ["taskkill", "/F", "/PID", str(process_id), "/T"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "taskkill failed for process "
            f"{process_id}: stdout={completed.stdout!r} stderr={completed.stderr!r}"
        )
    wait_for_process_exit(process_id, timeout=15.0)
    return process_id


def validate_clean_shutdown_duration(duration_ms: float) -> None:
    """Fails when the bounded shutdown regression reappears."""

    if duration_ms > MAX_CLEAN_SHUTDOWN_DURATION_MS:
        raise RuntimeError(
            f"Clean shutdown took {duration_ms:.3f} ms, expected <= {MAX_CLEAN_SHUTDOWN_DURATION_MS:.3f} ms."
        )


def wait_for_expected_shared_files_with_summary(
    fixture: dict[str, object],
    app: Application,
    scenario_dir: Path,
    *,
    summary_prefix: str,
    require_startup_profile: bool,
) -> tuple[int, dict[str, object], dict[str, object]]:
    """Waits until the Shared Files page converges and returns the process id, visible rows, and startup bundle."""

    main_window = live_common.wait_for_main_window(app)
    main_hwnd = main_window.handle
    process_id = int(win32process.GetWindowThreadProcessId(main_hwnd)[1])
    visible_shared_files = wait_for_expected_shared_files(
        main_hwnd,
        process_id,
        list(fixture["expected_visible_names"]),
        startup_profile_path=Path(str(fixture["startup_profile_path"])),
    )
    archive_trace_if_present(
        Path(str(fixture["startup_profile_path"])),
        scenario_dir / f"startup-profile-{summary_prefix}.trace.json",
    )
    startup_summary, startup_phases, _startup_counters = shared_files_ui.collect_startup_profile_bundle(
        Path(str(fixture["startup_profile_path"])),
        require_startup_profile=require_startup_profile,
    )
    if startup_phases:
        live_common.enforce_deferred_shared_hashing_boundary(startup_phases, f"{summary_prefix}.startup_profile")
    return process_id, visible_shared_files, startup_summary


def run_interruption_scenario(
    app_exe: Path,
    seed_config_dir: Path,
    scenario_dir: Path,
    *,
    name: str,
    open_shared_files_before_interrupt: bool,
    interrupt_mode: str,
    require_startup_profile: bool,
    perform_warm_relaunch_after_recovery: bool = False,
    wait_for_partial_hash_progress_before_interrupt: bool = False,
) -> dict[str, object]:
    """Runs one shutdown or hard-kill interruption scenario plus a recovery relaunch."""

    fixture = prepare_hash_interruption_fixture(
        seed_config_dir,
        scenario_dir,
        file_specs=get_hash_stress_file_specs_for_scenario(name),
    )
    summary = {
        "name": name,
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(fixture["profile_base"]),
        "shared_root": fixture["shared_root"],
        "expected_row_count": fixture["expected_row_count"],
        "expected_visible_names": fixture["expected_visible_names"],
        "interrupt_mode": interrupt_mode,
        "open_shared_files_before_interrupt": open_shared_files_before_interrupt,
        "command_line": subprocess.list2cmdline(
            [str(app_exe), "-ignoreinstances", "-c", str(fixture["profile_base"])]
        ),
    }

    app = None
    try:
        app = launch_app_with_fresh_startup_trace(app_exe, fixture)
        main_window = live_common.wait_for_main_window(app)
        main_hwnd = main_window.handle
        process_id = int(win32process.GetWindowThreadProcessId(main_hwnd)[1])
        summary["first_launch_process_id"] = process_id

        if open_shared_files_before_interrupt:
            summary["first_launch_visible_before_interrupt"] = open_shared_files_page_snapshot(main_hwnd)

        hashing_active = wait_for_hashing_active(Path(str(fixture["startup_profile_path"])))
        summary["first_launch_hashing_active"] = hashing_active
        if wait_for_partial_hash_progress_before_interrupt:
            summary["first_launch_partial_hash_progress_before_interrupt"] = wait_for_partial_hash_progress(
                Path(str(fixture["startup_profile_path"])),
                expected_count=int(fixture["expected_row_count"]),
            )

        if interrupt_mode == "clean-close":
            close_started = time.perf_counter()
            live_common.close_app_cleanly(app, window_timeout=30.0, process_timeout=30.0)
            close_duration_ms = round((time.perf_counter() - close_started) * 1000.0, 3)
            validate_clean_shutdown_duration(close_duration_ms)
            summary["first_launch_close_duration_ms"] = close_duration_ms
            app = None
            archive_trace_if_present(
                Path(str(fixture["startup_profile_path"])),
                scenario_dir / "startup-profile-first-launch.trace.json",
            )
            startup_summary, startup_phases, _startup_counters = shared_files_ui.collect_startup_profile_bundle(
                Path(str(fixture["startup_profile_path"])),
                require_startup_profile=require_startup_profile,
            )
            if startup_phases:
                live_common.enforce_deferred_shared_hashing_boundary(startup_phases, name + ".first_launch")
            summary["first_launch_startup_profile"] = startup_summary
        else:
            summary["first_launch_hard_kill_process_id"] = hard_kill_app(app)
            app = None
            archive_trace_if_present(
                Path(str(fixture["startup_profile_path"])),
                scenario_dir / "startup-profile-first-launch.partial.trace.json",
            )

        summary["post_interrupt_sidecar_state"] = capture_sidecar_state(Path(str(fixture["config_dir"])))
        ensure_sidecars_absent(
            summary["post_interrupt_sidecar_state"],
            description=f"{name} interruption",
        )

        app = launch_app_with_fresh_startup_trace(app_exe, fixture)
        (
            summary["relaunch_process_id"],
            summary["relaunch_visible_shared_files"],
            summary["relaunch_startup_profile"],
        ) = wait_for_expected_shared_files_with_summary(
            fixture,
            app,
            scenario_dir,
            summary_prefix="relaunch",
            require_startup_profile=require_startup_profile,
        )

        close_started = time.perf_counter()
        live_common.close_app_cleanly(app, window_timeout=45.0, process_timeout=45.0)
        relaunch_close_duration_ms = round((time.perf_counter() - close_started) * 1000.0, 3)
        validate_clean_shutdown_duration(relaunch_close_duration_ms)
        summary["relaunch_close_duration_ms"] = relaunch_close_duration_ms
        app = None

        if perform_warm_relaunch_after_recovery:
            summary["post_recovery_clean_close_sidecar_state"] = capture_sidecar_state(Path(str(fixture["config_dir"])))
            ensure_startup_cache_present(
                summary["post_recovery_clean_close_sidecar_state"],
                description=f"{name} recovery clean close",
            )

            app = launch_app_with_fresh_startup_trace(app_exe, fixture)
            (
                summary["warm_relaunch_process_id"],
                summary["warm_relaunch_visible_shared_files"],
                summary["warm_relaunch_startup_profile"],
            ) = wait_for_expected_shared_files_with_summary(
                fixture,
                app,
                scenario_dir,
                summary_prefix="warm-relaunch",
                require_startup_profile=require_startup_profile,
            )
            warm_dirs_from_cache = shared_files_ui.get_profile_counter_value(
                summary["warm_relaunch_startup_profile"],
                "shared.scan.directories_from_cache",
                "directories",
            )
            warm_files_queued = shared_files_ui.get_profile_counter_value(
                summary["warm_relaunch_startup_profile"],
                "shared.scan.files_queued_for_hash",
                "files",
            )
            summary["warm_relaunch_directories_from_cache"] = warm_dirs_from_cache
            summary["warm_relaunch_files_queued_for_hash"] = warm_files_queued
            if warm_dirs_from_cache is None or warm_dirs_from_cache <= 0:
                raise RuntimeError(f"Expected warm recovery relaunch to reuse the startup cache, got directories_from_cache={warm_dirs_from_cache!r}.")
            if warm_files_queued != 0:
                raise RuntimeError(f"Expected warm recovery relaunch to queue no hash work, got files_queued_for_hash={warm_files_queued!r}.")

            close_started = time.perf_counter()
            live_common.close_app_cleanly(app, window_timeout=45.0, process_timeout=45.0)
            warm_relaunch_close_duration_ms = round((time.perf_counter() - close_started) * 1000.0, 3)
            validate_clean_shutdown_duration(warm_relaunch_close_duration_ms)
            summary["warm_relaunch_close_duration_ms"] = warm_relaunch_close_duration_ms
            app = None

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
                    hard_kill_app(app)
                except Exception:
                    pass
        write_json(scenario_dir / "result.json", summary)


def run_repeated_interruption_cycle_scenario(
    app_exe: Path,
    seed_config_dir: Path,
    scenario_dir: Path,
    *,
    name: str,
    require_startup_profile: bool,
    interrupt_mode: str,
) -> dict[str, object]:
    """Runs two interrupted cycles on the same profile, then verifies warm recovery."""

    fixture = prepare_hash_interruption_fixture(
        seed_config_dir,
        scenario_dir,
        file_specs=get_hash_stress_file_specs_for_scenario(name),
    )
    summary = {
        "name": name,
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(fixture["profile_base"]),
        "shared_root": fixture["shared_root"],
        "expected_row_count": fixture["expected_row_count"],
        "expected_visible_names": fixture["expected_visible_names"],
        "command_line": subprocess.list2cmdline(
            [str(app_exe), "-ignoreinstances", "-c", str(fixture["profile_base"])]
        ),
        "interrupt_mode": interrupt_mode,
    }

    app = None
    try:
        for cycle_index in (1, 2):
            app = launch_app_with_fresh_startup_trace(app_exe, fixture)
            main_window = live_common.wait_for_main_window(app)
            main_hwnd = main_window.handle
            process_id = int(win32process.GetWindowThreadProcessId(main_hwnd)[1])
            summary[f"cycle_{cycle_index}_process_id"] = process_id
            summary[f"cycle_{cycle_index}_hashing_active"] = wait_for_hashing_active(Path(str(fixture["startup_profile_path"])))
            if interrupt_mode == "clean-close":
                close_started = time.perf_counter()
                live_common.close_app_cleanly(app, window_timeout=30.0, process_timeout=30.0)
                close_duration_ms = round((time.perf_counter() - close_started) * 1000.0, 3)
                validate_clean_shutdown_duration(close_duration_ms)
                summary[f"cycle_{cycle_index}_close_duration_ms"] = close_duration_ms
            else:
                summary[f"cycle_{cycle_index}_hard_kill_process_id"] = hard_kill_app(app)
            app = None

            archive_trace_if_present(
                Path(str(fixture["startup_profile_path"])),
                scenario_dir / f"startup-profile-cycle-{cycle_index}.trace.json",
            )
            startup_summary, startup_phases, _startup_counters = shared_files_ui.collect_startup_profile_bundle(
                Path(str(fixture["startup_profile_path"])),
                require_startup_profile=require_startup_profile,
            )
            if startup_phases:
                live_common.enforce_deferred_shared_hashing_boundary(startup_phases, f"{name}.cycle_{cycle_index}")
            summary[f"cycle_{cycle_index}_startup_profile"] = startup_summary

            sidecar_state = capture_sidecar_state(Path(str(fixture["config_dir"])))
            summary[f"cycle_{cycle_index}_post_interrupt_sidecar_state"] = sidecar_state
            ensure_sidecars_absent(sidecar_state, description=f"{name} cycle {cycle_index}")

        app = launch_app_with_fresh_startup_trace(app_exe, fixture)
        (
            summary["recovery_relaunch_process_id"],
            summary["recovery_relaunch_visible_shared_files"],
            summary["recovery_relaunch_startup_profile"],
        ) = wait_for_expected_shared_files_with_summary(
            fixture,
            app,
            scenario_dir,
            summary_prefix="recovery-relaunch",
            require_startup_profile=require_startup_profile,
        )
        close_started = time.perf_counter()
        live_common.close_app_cleanly(app, window_timeout=45.0, process_timeout=45.0)
        recovery_close_duration_ms = round((time.perf_counter() - close_started) * 1000.0, 3)
        validate_clean_shutdown_duration(recovery_close_duration_ms)
        summary["recovery_relaunch_close_duration_ms"] = recovery_close_duration_ms
        app = None

        summary["post_recovery_clean_close_sidecar_state"] = capture_sidecar_state(Path(str(fixture["config_dir"])))
        ensure_startup_cache_present(
            summary["post_recovery_clean_close_sidecar_state"],
            description=f"{name} recovery clean close",
        )

        app = launch_app_with_fresh_startup_trace(app_exe, fixture)
        (
            summary["warm_recovery_relaunch_process_id"],
            summary["warm_recovery_relaunch_visible_shared_files"],
            summary["warm_recovery_relaunch_startup_profile"],
        ) = wait_for_expected_shared_files_with_summary(
            fixture,
            app,
            scenario_dir,
            summary_prefix="warm-recovery-relaunch",
            require_startup_profile=require_startup_profile,
        )
        warm_dirs_from_cache = shared_files_ui.get_profile_counter_value(
            summary["warm_recovery_relaunch_startup_profile"],
            "shared.scan.directories_from_cache",
            "directories",
        )
        warm_files_queued = shared_files_ui.get_profile_counter_value(
            summary["warm_recovery_relaunch_startup_profile"],
            "shared.scan.files_queued_for_hash",
            "files",
        )
        summary["warm_recovery_relaunch_directories_from_cache"] = warm_dirs_from_cache
        summary["warm_recovery_relaunch_files_queued_for_hash"] = warm_files_queued
        if warm_dirs_from_cache is None or warm_dirs_from_cache <= 0:
            raise RuntimeError(
                "Expected repeated-cycle warm relaunch to reuse the startup cache, "
                f"got directories_from_cache={warm_dirs_from_cache!r}."
            )
        if warm_files_queued != 0:
            raise RuntimeError(
                "Expected repeated-cycle warm relaunch to queue no hash work, "
                f"got files_queued_for_hash={warm_files_queued!r}."
            )

        close_started = time.perf_counter()
        live_common.close_app_cleanly(app, window_timeout=45.0, process_timeout=45.0)
        warm_close_duration_ms = round((time.perf_counter() - close_started) * 1000.0, 3)
        validate_clean_shutdown_duration(warm_close_duration_ms)
        summary["warm_recovery_relaunch_close_duration_ms"] = warm_close_duration_ms
        app = None

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
                    hard_kill_app(app)
                except Exception:
                    pass
        write_json(scenario_dir / "result.json", summary)


def run_reload_then_interrupt_scenario(
    app_exe: Path,
    seed_config_dir: Path,
    scenario_dir: Path,
    *,
    name: str,
    require_startup_profile: bool,
    interrupt_mode: str,
) -> dict[str, object]:
    """Triggers Reload during hash drain, then interrupts before the deferred reload can complete."""

    fixture = prepare_hash_interruption_fixture(
        seed_config_dir,
        scenario_dir,
        file_specs=get_hash_stress_file_specs_for_scenario(name),
    )
    summary = {
        "name": name,
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(fixture["profile_base"]),
        "shared_root": fixture["shared_root"],
        "expected_row_count": fixture["expected_row_count"],
        "expected_visible_names": fixture["expected_visible_names"],
        "interrupt_mode": interrupt_mode,
        "command_line": subprocess.list2cmdline(
            [str(app_exe), "-ignoreinstances", "-c", str(fixture["profile_base"])]
        ),
    }

    app = None
    try:
        app = launch_app_with_fresh_startup_trace(app_exe, fixture)
        main_window = live_common.wait_for_main_window(app)
        main_hwnd = main_window.handle
        process_id = int(win32process.GetWindowThreadProcessId(main_hwnd)[1])
        summary["first_launch_process_id"] = process_id
        summary["visible_before_reload"] = open_shared_files_page_snapshot(main_hwnd)
        summary["hashing_active"] = wait_for_hashing_active(Path(str(fixture["startup_profile_path"])))

        shared_files_ui.click_reload_button(main_hwnd)
        summary["visible_immediately_after_reload"] = open_shared_files_page_snapshot(main_hwnd)
        immediate_row_count = int(summary["visible_immediately_after_reload"]["row_count"])
        if immediate_row_count >= int(fixture["expected_row_count"]):
            raise RuntimeError(
                "Reload while hashing should not fully converge before hash drain, "
                f"got immediate row count {immediate_row_count} for expected {fixture['expected_row_count']}."
            )

        if interrupt_mode == "clean-close":
            close_started = time.perf_counter()
            live_common.close_app_cleanly(app, window_timeout=30.0, process_timeout=30.0)
            close_duration_ms = round((time.perf_counter() - close_started) * 1000.0, 3)
            validate_clean_shutdown_duration(close_duration_ms)
            summary["first_launch_close_duration_ms"] = close_duration_ms
            archive_trace_if_present(
                Path(str(fixture["startup_profile_path"])),
                scenario_dir / "startup-profile-first-launch.trace.json",
            )
            startup_summary, startup_phases, _startup_counters = shared_files_ui.collect_startup_profile_bundle(
                Path(str(fixture["startup_profile_path"])),
                require_startup_profile=require_startup_profile,
            )
            if startup_phases:
                live_common.enforce_deferred_shared_hashing_boundary(startup_phases, name + ".first_launch")
            summary["first_launch_startup_profile"] = startup_summary
        else:
            summary["first_launch_hard_kill_process_id"] = hard_kill_app(app)
            archive_trace_if_present(
                Path(str(fixture["startup_profile_path"])),
                scenario_dir / "startup-profile-first-launch.partial.trace.json",
            )
        app = None

        summary["post_interrupt_sidecar_state"] = capture_sidecar_state(Path(str(fixture["config_dir"])))
        ensure_sidecars_absent(
            summary["post_interrupt_sidecar_state"],
            description=f"{name} interruption after deferred reload",
        )

        app = launch_app_with_fresh_startup_trace(app_exe, fixture)
        (
            summary["relaunch_process_id"],
            summary["relaunch_visible_shared_files"],
            summary["relaunch_startup_profile"],
        ) = wait_for_expected_shared_files_with_summary(
            fixture,
            app,
            scenario_dir,
            summary_prefix="relaunch",
            require_startup_profile=require_startup_profile,
        )

        close_started = time.perf_counter()
        live_common.close_app_cleanly(app, window_timeout=45.0, process_timeout=45.0)
        relaunch_close_duration_ms = round((time.perf_counter() - close_started) * 1000.0, 3)
        validate_clean_shutdown_duration(relaunch_close_duration_ms)
        summary["relaunch_close_duration_ms"] = relaunch_close_duration_ms
        app = None

        summary["post_recovery_clean_close_sidecar_state"] = capture_sidecar_state(Path(str(fixture["config_dir"])))
        ensure_startup_cache_present(
            summary["post_recovery_clean_close_sidecar_state"],
            description=f"{name} recovery clean close",
        )

        app = launch_app_with_fresh_startup_trace(app_exe, fixture)
        (
            summary["warm_relaunch_process_id"],
            summary["warm_relaunch_visible_shared_files"],
            summary["warm_relaunch_startup_profile"],
        ) = wait_for_expected_shared_files_with_summary(
            fixture,
            app,
            scenario_dir,
            summary_prefix="warm-relaunch",
            require_startup_profile=require_startup_profile,
        )
        warm_dirs_from_cache = shared_files_ui.get_profile_counter_value(
            summary["warm_relaunch_startup_profile"],
            "shared.scan.directories_from_cache",
            "directories",
        )
        warm_files_queued = shared_files_ui.get_profile_counter_value(
            summary["warm_relaunch_startup_profile"],
            "shared.scan.files_queued_for_hash",
            "files",
        )
        summary["warm_relaunch_directories_from_cache"] = warm_dirs_from_cache
        summary["warm_relaunch_files_queued_for_hash"] = warm_files_queued
        if warm_dirs_from_cache is None or warm_dirs_from_cache <= 0:
            raise RuntimeError(
                "Expected deferred-reload warm relaunch to reuse the startup cache, "
                f"got directories_from_cache={warm_dirs_from_cache!r}."
            )
        if warm_files_queued != 0:
            raise RuntimeError(
                "Expected deferred-reload warm relaunch to queue no hash work, "
                f"got files_queued_for_hash={warm_files_queued!r}."
            )

        close_started = time.perf_counter()
        live_common.close_app_cleanly(app, window_timeout=45.0, process_timeout=45.0)
        warm_relaunch_close_duration_ms = round((time.perf_counter() - close_started) * 1000.0, 3)
        validate_clean_shutdown_duration(warm_relaunch_close_duration_ms)
        summary["warm_relaunch_close_duration_ms"] = warm_relaunch_close_duration_ms
        app = None

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
                    hard_kill_app(app)
                except Exception:
                    pass
        write_json(scenario_dir / "result.json", summary)


def run_reload_during_hash_scenario(
    app_exe: Path,
    seed_config_dir: Path,
    scenario_dir: Path,
    *,
    name: str,
    require_startup_profile: bool,
) -> dict[str, object]:
    """Runs the Shared Files reload button while startup hashing is still draining."""

    fixture = prepare_hash_interruption_fixture(
        seed_config_dir,
        scenario_dir,
        file_specs=get_hash_stress_file_specs_for_scenario(name),
    )
    summary = {
        "name": name,
        "status": "failed",
        "app_exe": str(app_exe),
        "profile_base": str(fixture["profile_base"]),
        "shared_root": fixture["shared_root"],
        "expected_row_count": fixture["expected_row_count"],
        "expected_visible_names": fixture["expected_visible_names"],
        "command_line": subprocess.list2cmdline(
            [str(app_exe), "-ignoreinstances", "-c", str(fixture["profile_base"])]
        ),
    }

    app = None
    try:
        app = launch_app_with_fresh_startup_trace(app_exe, fixture)
        main_window = live_common.wait_for_main_window(app)
        main_hwnd = main_window.handle
        process_id = int(win32process.GetWindowThreadProcessId(main_hwnd)[1])
        summary["process_id"] = process_id
        summary["visible_before_reload"] = open_shared_files_page_snapshot(main_hwnd)
        summary["hashing_active"] = wait_for_hashing_active(Path(str(fixture["startup_profile_path"])))

        shared_files_ui.click_reload_button(main_hwnd)
        summary["visible_immediately_after_reload"] = open_shared_files_page_snapshot(main_hwnd)
        immediate_row_count = int(summary["visible_immediately_after_reload"]["row_count"])
        if immediate_row_count >= int(fixture["expected_row_count"]):
            raise RuntimeError(
                "Reload while hashing should not fully converge before hash drain, "
                f"got immediate row count {immediate_row_count} for expected {fixture['expected_row_count']}."
            )

        summary["visible_after_hash_drain"] = wait_for_expected_shared_files(
            main_hwnd,
            process_id,
            list(fixture["expected_visible_names"]),
            startup_profile_path=Path(str(fixture["startup_profile_path"])),
        )

        close_started = time.perf_counter()
        live_common.close_app_cleanly(app, window_timeout=45.0, process_timeout=45.0)
        close_duration_ms = round((time.perf_counter() - close_started) * 1000.0, 3)
        validate_clean_shutdown_duration(close_duration_ms)
        summary["close_duration_ms"] = close_duration_ms
        app = None

        archive_trace_if_present(
            Path(str(fixture["startup_profile_path"])),
            scenario_dir / "startup-profile-reload.trace.json",
        )
        startup_summary, startup_phases, _startup_counters = shared_files_ui.collect_startup_profile_bundle(
            Path(str(fixture["startup_profile_path"])),
            require_startup_profile=require_startup_profile,
        )
        if startup_phases:
            live_common.enforce_deferred_shared_hashing_boundary(startup_phases, name)
        summary["startup_profile"] = startup_summary
        reloads_during_hash_drain = get_readiness_metric(startup_summary, "shared_list_reloads_during_hash_drain")
        summary["shared_list_reloads_during_hash_drain"] = reloads_during_hash_drain
        if reloads_during_hash_drain is None or float(reloads_during_hash_drain) < 1.0:
            raise RuntimeError(
                "Expected the reload-during-hash scenario to observe at least one deferred Shared Files reload "
                f"during hash drain, got {reloads_during_hash_drain!r}."
            )

        summary["post_clean_close_sidecar_state"] = capture_sidecar_state(Path(str(fixture["config_dir"])))
        ensure_startup_cache_present(
            summary["post_clean_close_sidecar_state"],
            description=f"{name} final clean close",
        )
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
                    hard_kill_app(app)
                except Exception:
                    pass
        write_json(scenario_dir / "result.json", summary)


def run_shared_hash_ui_suite(
    app_exe: Path,
    seed_config_dir: Path,
    artifacts_dir: Path,
    *,
    scenario_names: list[str],
    require_startup_profile: bool,
) -> None:
    """Runs the requested shared-hash interruption scenarios."""

    combined = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": "passed",
        "app_exe": str(app_exe),
        "seed_config_dir": str(seed_config_dir),
        "artifact_dir": str(artifacts_dir),
        "scenario_names": scenario_names,
        "scenarios": [],
    }
    failures: list[str] = []

    for name in scenario_names:
        scenario_dir = artifacts_dir / name
        scenario_dir.mkdir(parents=True, exist_ok=True)
        if name.startswith("reload-during-hash-files-page"):
            result = run_reload_during_hash_scenario(
                app_exe,
                seed_config_dir,
                scenario_dir,
                name=name,
                require_startup_profile=require_startup_profile,
            )
        elif name.startswith("reload-then-clean-close-during-hash-files-page") or name.startswith("reload-then-hard-kill-during-hash-files-page"):
            result = run_reload_then_interrupt_scenario(
                app_exe,
                seed_config_dir,
                scenario_dir,
                name=name,
                require_startup_profile=require_startup_profile,
                interrupt_mode="hard-kill" if name.startswith("reload-then-hard-kill") else "clean-close",
            )
        elif name.startswith("clean-close-during-hash-repeated-cycle") or name.startswith("hard-kill-during-hash-repeated-cycle"):
            result = run_repeated_interruption_cycle_scenario(
                app_exe,
                seed_config_dir,
                scenario_dir,
                name=name,
                require_startup_profile=require_startup_profile,
                interrupt_mode="hard-kill" if name.startswith("hard-kill") else "clean-close",
            )
        else:
            open_shared_files_before_interrupt = "files-page" in name
            interrupt_mode = "hard-kill" if name.startswith("hard-kill") else "clean-close"
            result = run_interruption_scenario(
                app_exe,
                seed_config_dir,
                scenario_dir,
                name=name,
                open_shared_files_before_interrupt=open_shared_files_before_interrupt,
                interrupt_mode=interrupt_mode,
                require_startup_profile=require_startup_profile,
                perform_warm_relaunch_after_recovery="warm-relaunch" in name,
                wait_for_partial_hash_progress_before_interrupt="partial-results" in name,
            )
        combined["scenarios"].append(result)
        if result.get("status") != "passed":
            failures.append(name)

    if failures:
        combined["status"] = "failed"
    write_json(artifacts_dir / "result.json", combined)
    if failures:
        raise RuntimeError("Shared hash UI scenarios failed: " + ", ".join(failures))


def main(argv: list[str]) -> int:
    """Parses arguments, runs the interruption suite, and publishes the report artifacts."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--startup-trace-mode", choices=["required", "optional"], default="required")
    parser.add_argument("--scenario", dest="scenarios", action="append", choices=SCENARIO_NAMES)
    args = parser.parse_args(argv)

    if _PYWINAUTO_IMPORT_ERROR is not None:
        live_common.require_pywinauto()

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="shared-hash-ui-e2e",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    artifacts_dir = paths.source_artifacts_dir
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    scenario_names = args.scenarios or list(SCENARIO_NAMES)

    try:
        run_shared_hash_ui_suite(
            app_exe=paths.app_exe,
            seed_config_dir=seed_config_dir,
            artifacts_dir=artifacts_dir,
            scenario_names=scenario_names,
            require_startup_profile=(args.startup_trace_mode == "required"),
        )
        harness_cli_common.publish_run_artifacts(paths)
        summary_payload = harness_cli_common.build_live_ui_summary(status="passed", paths=paths)
        summary_path = paths.run_report_dir / "ui-summary.json"
        harness_cli_common.write_json_file(summary_path, summary_payload)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.update_harness_summary(paths.repo_root, live_ui_summary_path=summary_path)
        harness_cli_common.cleanup_source_artifacts(paths)
        return 0
    except Exception as exc:
        harness_cli_common.publish_run_artifacts(paths)
        summary_payload = harness_cli_common.build_live_ui_summary(status="failed", paths=paths, error_message=str(exc))
        summary_path = paths.run_report_dir / "ui-summary.json"
        harness_cli_common.write_json_file(summary_path, summary_payload)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.update_harness_summary(paths.repo_root, live_ui_summary_path=summary_path)
        if not paths.keep_source_artifacts:
            print(f"Shared-hash UI suite failed; preserving artifacts at {paths.source_artifacts_dir}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
