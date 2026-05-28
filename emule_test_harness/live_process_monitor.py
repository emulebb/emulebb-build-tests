"""Long-running live eMule process CPU and memory monitor helpers."""

from __future__ import annotations

import csv
import ctypes
import json
import os
import re
from dataclasses import dataclass, replace
from pathlib import Path
import shutil
import subprocess
import time
import urllib.error
import urllib.request

SCHEMA = "emule-live-process-monitor.v1"
DEFAULT_DURATION_SECONDS = 30 * 60
DEFAULT_SAMPLE_INTERVAL_SECONDS = 2.0
DEFAULT_CPU_SPIKE_THRESHOLD_ONE_CORE = 75.0
DEFAULT_MAX_SPIKE_DUMPS = 2
DEFAULT_SPIKE_DUMP_DELAY_SECONDS = 300.0
DEFAULT_PROCDUMP_PATH: str | None = None
STILL_ACTIVE = 259
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
WM_CLOSE = 0x0010

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_TERMINATE = 0x0001
SYNCHRONIZE = 0x00100000


@dataclass(frozen=True)
class LiveProcessMonitorConfig:
    """Configuration for one real-profile live process monitor run."""

    profile_dir: Path
    app_exe: Path | None = None
    base_url: str | None = None
    api_key: str | None = None
    duration_seconds: float = DEFAULT_DURATION_SECONDS
    sample_interval_seconds: float = DEFAULT_SAMPLE_INTERVAL_SECONDS
    procdump_path: Path | None = None
    cpu_spike_threshold_one_core: float = DEFAULT_CPU_SPIKE_THRESHOLD_ONE_CORE
    max_spike_dumps: int = DEFAULT_MAX_SPIKE_DUMPS
    spike_dump_delay_seconds: float = DEFAULT_SPIKE_DUMP_DELAY_SECONDS
    restart_on_failure: bool = False
    assertion_window_check: bool = True
    scan_logs: bool = True


@dataclass(frozen=True)
class ProcessTimes:
    """One process CPU-time sample in seconds."""

    kernel_seconds: float
    user_seconds: float

    @property
    def total_seconds(self) -> float:
        return self.kernel_seconds + self.user_seconds


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("PageFaultCount", ctypes.c_uint32),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = ctypes.c_int
kernel32.GetProcessTimes.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(FILETIME),
    ctypes.POINTER(FILETIME),
    ctypes.POINTER(FILETIME),
    ctypes.POINTER(FILETIME),
]
kernel32.GetProcessTimes.restype = ctypes.c_int
kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
kernel32.GetExitCodeProcess.restype = ctypes.c_int
kernel32.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
kernel32.GetProcessHandleCount.restype = ctypes.c_int
kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
kernel32.WaitForSingleObject.restype = ctypes.c_uint32

user32.EnumWindows.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
user32.EnumWindows.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
user32.GetWindowThreadProcessId.restype = ctypes.c_uint32
user32.IsWindowVisible.argtypes = [ctypes.c_void_p]
user32.IsWindowVisible.restype = ctypes.c_int
user32.PostMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
user32.PostMessageW.restype = ctypes.c_int

psapi.GetProcessMemoryInfo.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
    ctypes.c_uint32,
]
psapi.GetProcessMemoryInfo.restype = ctypes.c_int


def parse_config_payload(payload: dict[str, object], *, path: Path | None = None) -> LiveProcessMonitorConfig:
    """Parses one ignored local live-process monitor JSON payload."""

    if payload.get("schema") != SCHEMA:
        label = f" in '{path}'" if path else ""
        raise RuntimeError(f"Invalid live process monitor schema{label}; expected {SCHEMA!r}.")

    profile_dir = Path(str(payload.get("profileDir") or "")).expanduser()
    if not str(profile_dir):
        raise RuntimeError("live process monitor config requires profileDir.")

    app_exe_raw = payload.get("appExe")
    procdump_raw = payload.get("procdumpPath", DEFAULT_PROCDUMP_PATH)
    return LiveProcessMonitorConfig(
        profile_dir=profile_dir,
        app_exe=Path(str(app_exe_raw)).expanduser() if app_exe_raw else None,
        base_url=str(payload["baseUrl"]).rstrip("/") if payload.get("baseUrl") else None,
        api_key=str(payload["apiKey"]) if payload.get("apiKey") else None,
        duration_seconds=float(payload.get("durationSeconds", DEFAULT_DURATION_SECONDS)),
        sample_interval_seconds=float(payload.get("sampleIntervalSeconds", DEFAULT_SAMPLE_INTERVAL_SECONDS)),
        procdump_path=Path(str(procdump_raw)).expanduser() if procdump_raw else discover_procdump_path(),
        cpu_spike_threshold_one_core=float(payload.get("cpuSpikeThresholdOneCore", DEFAULT_CPU_SPIKE_THRESHOLD_ONE_CORE)),
        max_spike_dumps=int(payload.get("maxSpikeDumps", DEFAULT_MAX_SPIKE_DUMPS)),
        spike_dump_delay_seconds=float(payload.get("spikeDumpDelaySeconds", DEFAULT_SPIKE_DUMP_DELAY_SECONDS)),
        restart_on_failure=bool(payload.get("restartOnFailure", False)),
        assertion_window_check=bool(payload.get("assertionWindowCheck", True)),
        scan_logs=bool(payload.get("scanLogs", True)),
    )


def load_config(path: Path) -> LiveProcessMonitorConfig:
    """Loads one ignored local live-process monitor configuration file."""

    return parse_config_payload(json.loads(path.read_text(encoding="utf-8")), path=path)


def merge_config(config: LiveProcessMonitorConfig, **overrides: object) -> LiveProcessMonitorConfig:
    """Applies non-null command-line overrides to a parsed config object."""

    clean = {key: value for key, value in overrides.items() if value is not None}
    return replace(config, **clean)


def validate_config(config: LiveProcessMonitorConfig, *, app_exe: Path) -> None:
    """Raises actionable errors for missing live process monitor inputs."""

    if not config.profile_dir.is_dir():
        raise RuntimeError(f"Live eMule profile directory does not exist: {config.profile_dir}")
    if config.duration_seconds < DEFAULT_DURATION_SECONDS:
        raise RuntimeError("Live process monitor duration must be at least 1800 seconds.")
    if config.sample_interval_seconds <= 0:
        raise RuntimeError("Live process monitor sample interval must be greater than zero.")
    if config.max_spike_dumps < 0:
        raise RuntimeError("Live process monitor max spike dumps must not be negative.")
    if config.spike_dump_delay_seconds < 0:
        raise RuntimeError("Live process monitor spike dump delay must not be negative.")
    if not app_exe.is_file():
        raise RuntimeError(f"eMule executable does not exist: {app_exe}")


def validate_capture_mode(
    *,
    cpu_profile_enabled: bool,
    enable_umdh: bool,
    capture_final_dump: bool,
    spike_dumps_enabled: bool,
    max_spike_dumps: int,
) -> None:
    """Rejects diagnostic mode combinations that distort CPU or heap evidence."""

    if not enable_umdh:
        return
    if cpu_profile_enabled:
        raise RuntimeError("UMDH memory runs must be separate from ETW CPU profiling; pass --no-cpu-profile.")
    if capture_final_dump:
        raise RuntimeError("UMDH memory runs must not also capture a final full ProcDump dump.")
    if spike_dumps_enabled and max_spike_dumps > 0:
        raise RuntimeError("UMDH memory runs must not also capture full spike dumps; pass --skip-spike-dumps.")


def should_capture_spike_dump(
    *,
    elapsed_seconds: float,
    process_pct_one_core: float,
    captured_count: int,
    max_spike_dumps: int,
    cpu_spike_threshold_one_core: float,
    spike_dump_delay_seconds: float,
) -> bool:
    """Returns whether one sampled CPU spike should trigger a full ProcDump dump."""

    return (
        captured_count < max_spike_dumps
        and elapsed_seconds >= spike_dump_delay_seconds
        and process_pct_one_core >= cpu_spike_threshold_one_core
    )


def build_launch_command(app_exe: Path, profile_dir: Path, extra_args: tuple[str, ...] = ()) -> list[str]:
    """Builds the real-profile eMule launch command."""

    return [str(app_exe), "-ignoreinstances", "-c", str(profile_dir), *extra_args]


def runtime_log_paths(profile_dir: Path) -> list[Path]:
    """Returns current eMuleBB runtime logs for a real-profile launch."""

    candidates = [profile_dir, profile_dir / "config", profile_dir / "logs"]
    paths: list[Path] = []
    seen: set[Path] = set()
    for root in candidates:
        if not root.is_dir():
            continue
        for path in sorted(root.glob("emulebb*.log")):
            resolved = path.resolve()
            if resolved not in seen and path.is_file():
                paths.append(path)
                seen.add(resolved)
    return paths


def scan_log_markers(
    log_paths: list[Path],
    offsets: dict[str, int],
    patterns: list[re.Pattern[str]],
    *,
    max_matches: int = 100,
) -> list[dict[str, object]]:
    """Scans appended log text for failure markers without rereading old lines."""

    matches: list[dict[str, object]] = []
    for path in log_paths:
        key = str(path.resolve())
        previous_offset = int(offsets.get(key, 0))
        try:
            current_size = path.stat().st_size
        except OSError:
            continue
        if current_size < previous_offset:
            previous_offset = 0
        if current_size == previous_offset:
            continue
        try:
            with path.open("rb") as handle:
                handle.seek(previous_offset)
                data = handle.read()
                offsets[key] = handle.tell()
        except OSError:
            continue
        text = data.decode("utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for pattern in patterns:
                if pattern.search(line):
                    matches.append(
                        {
                            "path": key,
                            "line_number_after_offset": line_number,
                            "pattern": pattern.pattern,
                            "line": line,
                        }
                    )
                    break
            if len(matches) >= max_matches:
                return matches
    return matches


def current_profile_dumps(profile_dir: Path) -> list[Path]:
    """Returns dump files currently present in the live profile."""

    candidates = [profile_dir, profile_dir / "config"]
    dumps: list[Path] = []
    seen: set[Path] = set()
    for root in candidates:
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*.dmp")):
            resolved = path.resolve()
            if resolved not in seen and path.is_file():
                dumps.append(path)
                seen.add(resolved)
    return dumps


def collect_new_profile_dumps(profile_dir: Path, known_paths: set[str]) -> list[dict[str, object]]:
    """Records profile dump files created after monitoring started."""

    rows: list[dict[str, object]] = []
    for path in current_profile_dumps(profile_dir):
        key = str(path.resolve())
        if key in known_paths:
            continue
        known_paths.add(key)
        try:
            stat = path.stat()
            rows.append(
                {
                    "path": key,
                    "size_bytes": stat.st_size,
                    "mtime_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
                }
            )
        except OSError:
            rows.append({"path": key, "stat_error": True})
    return rows


def assertion_window_title(title: str) -> bool:
    """Returns whether a top-level window title looks like a debug assertion."""

    return bool(re.search(r"Microsoft Visual C\+\+ Runtime Library|Debug Assertion Failed", title, re.IGNORECASE))


def find_assertion_windows(process_id: int) -> list[dict[str, object]]:
    """Finds visible debug assertion/runtime-library windows owned by a process."""

    windows: list[dict[str, object]] = []

    @ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    def enum_callback(hwnd: int, _lparam: int) -> int:
        owner = ctypes.c_uint32()
        user32.GetWindowThreadProcessId(ctypes.c_void_p(hwnd), ctypes.byref(owner))
        if int(owner.value) != int(process_id) or not user32.IsWindowVisible(ctypes.c_void_p(hwnd)):
            return 1
        buffer = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(ctypes.c_void_p(hwnd), buffer, len(buffer))
        title = buffer.value
        if assertion_window_title(title):
            windows.append({"hwnd": int(hwnd), "title": title})
        return 1

    if not user32.EnumWindows(enum_callback, None):
        raise OSError(ctypes.get_last_error(), "EnumWindows failed")
    return windows


def filetime_to_seconds(value: FILETIME) -> float:
    """Converts a Windows FILETIME interval to seconds."""

    ticks = (int(value.dwHighDateTime) << 32) + int(value.dwLowDateTime)
    return ticks / 10_000_000.0


def open_process(process_id: int) -> int:
    """Opens a process handle suitable for resource sampling."""

    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE | SYNCHRONIZE,
        False,
        int(process_id),
    )
    if not handle:
        raise OSError(ctypes.get_last_error(), f"OpenProcess failed for pid {process_id}")
    return int(handle)


def close_handle(handle: int) -> None:
    """Closes a native Windows handle."""

    if handle:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def get_process_exit_code(handle: int) -> int:
    """Returns the process exit code or STILL_ACTIVE."""

    code = ctypes.c_uint32()
    if not kernel32.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code)):
        raise OSError(ctypes.get_last_error(), "GetExitCodeProcess failed")
    return int(code.value)


def post_close_to_process_windows(process_id: int) -> int:
    """Posts WM_CLOSE to visible top-level windows owned by a process."""

    closed = 0

    @ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    def enum_callback(hwnd: int, _lparam: int) -> int:
        nonlocal closed
        owner = ctypes.c_uint32()
        user32.GetWindowThreadProcessId(ctypes.c_void_p(hwnd), ctypes.byref(owner))
        if int(owner.value) == int(process_id) and user32.IsWindowVisible(ctypes.c_void_p(hwnd)):
            if user32.PostMessageW(ctypes.c_void_p(hwnd), WM_CLOSE, None, None):
                closed += 1
        return 1

    if not user32.EnumWindows(enum_callback, None):
        raise OSError(ctypes.get_last_error(), "EnumWindows failed")
    return closed


def wait_for_process_exit(handle: int, timeout_seconds: float) -> bool:
    """Waits for process exit using an existing process handle."""

    result = kernel32.WaitForSingleObject(ctypes.c_void_p(handle), int(max(timeout_seconds, 0.0) * 1000))
    if result == WAIT_OBJECT_0:
        return True
    if result == WAIT_TIMEOUT:
        return False
    raise OSError(ctypes.get_last_error(), "WaitForSingleObject failed")


def close_process_gracefully(process: subprocess.Popen[str], handle: int, *, timeout_seconds: float = 60.0) -> dict[str, object]:
    """Closes a launched GUI process gracefully before using a hard fallback."""

    if get_process_exit_code(handle) != STILL_ACTIVE:
        return {"app_closed": True, "method": "already_exited", "exit_code": process.poll()}

    windows_closed = post_close_to_process_windows(process.pid)
    if windows_closed > 0 and wait_for_process_exit(handle, timeout_seconds):
        return {"app_closed": True, "method": "wm_close", "windows_closed": windows_closed, "exit_code": process.poll()}

    process.terminate()
    try:
        process.wait(timeout=timeout_seconds)
        return {
            "app_closed": True,
            "method": "terminate",
            "windows_closed": windows_closed,
            "exit_code": process.returncode,
        }
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=30.0)
        return {
            "app_closed": True,
            "method": "kill",
            "windows_closed": windows_closed,
            "exit_code": process.returncode,
        }


def get_process_times(handle: int) -> ProcessTimes:
    """Returns kernel and user CPU seconds for one process handle."""

    creation = FILETIME()
    exit_time = FILETIME()
    kernel = FILETIME()
    user = FILETIME()
    if not kernel32.GetProcessTimes(
        ctypes.c_void_p(handle),
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")
    return ProcessTimes(kernel_seconds=filetime_to_seconds(kernel), user_seconds=filetime_to_seconds(user))


def sample_process_metrics(
    *,
    handle: int,
    started_monotonic: float,
    last_sample_monotonic: float | None,
    last_cpu_seconds: float | None,
) -> dict[str, object]:
    """Samples process CPU, memory, handle count, and exit state."""

    now = time.monotonic()
    times = get_process_times(handle)
    counters = PROCESS_MEMORY_COUNTERS_EX()
    counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
    if not psapi.GetProcessMemoryInfo(ctypes.c_void_p(handle), ctypes.byref(counters), counters.cb):
        raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo failed")

    handle_count = ctypes.c_uint32()
    kernel32.GetProcessHandleCount(ctypes.c_void_p(handle), ctypes.byref(handle_count))

    process_pct_one_core = 0.0
    if last_sample_monotonic is not None and last_cpu_seconds is not None:
        elapsed = max(now - last_sample_monotonic, 0.001)
        process_pct_one_core = max(0.0, (times.total_seconds - last_cpu_seconds) * 100.0 / elapsed)

    return {
        "utc_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_seconds": round(now - started_monotonic, 3),
        "cpu_seconds": round(times.total_seconds, 3),
        "process_pct_one_core": round(process_pct_one_core, 1),
        "working_set_mb": round(int(counters.WorkingSetSize) / 1024 / 1024, 1),
        "peak_working_set_mb": round(int(counters.PeakWorkingSetSize) / 1024 / 1024, 1),
        "private_mb": round(int(counters.PrivateUsage) / 1024 / 1024, 1),
        "pagefile_mb": round(int(counters.PagefileUsage) / 1024 / 1024, 1),
        "handles": int(handle_count.value),
        "exit_code": get_process_exit_code(handle),
    }


def summarize_metric_rows(rows: list[dict[str, object]]) -> dict[str, object]:
    """Builds a compact resource summary from sampled metric rows."""

    if not rows:
        return {"sample_count": 0}

    def values(name: str) -> list[float]:
        return [float(row[name]) for row in rows if row.get(name) is not None]

    summary: dict[str, object] = {
        "sample_count": len(rows),
        "first": rows[0],
        "last": rows[-1],
    }
    for name in ("working_set_mb", "private_mb", "peak_working_set_mb", "process_pct_one_core", "handles"):
        series = values(name)
        if series:
            summary[name] = {
                "min": min(series),
                "max": max(series),
                "delta": round(series[-1] - series[0], 3),
            }
    return summary


def write_metric_csv(path: Path, rows: list[dict[str, object]]) -> None:
    """Writes process samples as a stable CSV file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "utc_time",
        "elapsed_seconds",
        "cpu_seconds",
        "process_pct_one_core",
        "working_set_mb",
        "peak_working_set_mb",
        "private_mb",
        "pagefile_mb",
        "handles",
        "exit_code",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def http_json(base_url: str, path: str, api_key: str, timeout_seconds: float = 5.0) -> dict[str, object]:
    """Reads one authenticated local REST JSON endpoint."""

    request = urllib.request.Request(base_url.rstrip("/") + path)
    request.add_header("X-API-Key", api_key)
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def sample_runtime_counters(base_url: str | None, api_key: str | None) -> dict[str, object]:
    """Samples app-provided runtime counters when a local API is configured."""

    if not base_url or not api_key:
        return {"skipped": True, "reason": "base_url or api_key not configured"}
    try:
        return {
            "ok": True,
            "status": http_json(base_url, "/api/v1/status", api_key),
        }
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
            },
        }


def find_tool(*names: str) -> str | None:
    """Returns the first available executable path for one of the supplied names."""

    for name in names:
        resolved = shutil.which(name)
        if resolved:
            return resolved
    return None


def discover_procdump_path() -> Path | None:
    """Finds ProcDump on PATH when the ignored local config does not pin it."""

    resolved = find_tool("procdump64.exe", "procdump.exe")
    return Path(resolved) if resolved else None


def run_tool(command: list[str], output_path: Path, timeout_seconds: float) -> dict[str, object]:
    """Runs one external diagnostic command and records its output."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
        output_path.write_text(
            "\n".join(
                [
                    f"command: {subprocess.list2cmdline(command)}",
                    f"return_code: {completed.returncode}",
                    f"duration_seconds: {round(time.monotonic() - started, 3)}",
                    "",
                    completed.stdout,
                    completed.stderr,
                ]
            ),
            encoding="utf-8",
        )
        return {
            "command": command,
            "output_path": str(output_path),
            "return_code": completed.returncode,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        output_path.write_text(
            "\n".join(
                [
                    f"command: {subprocess.list2cmdline(command)}",
                    "timed_out: true",
                    "",
                    exc.stdout or "",
                    exc.stderr or "",
                ]
            ),
            encoding="utf-8",
        )
        return {
            "command": command,
            "output_path": str(output_path),
            "return_code": None,
            "timed_out": True,
        }


def capture_procdump(procdump_path: Path | None, process_id: int, dump_path: Path, log_path: Path) -> dict[str, object]:
    """Captures a full-memory ProcDump dump when the tool is available."""

    if procdump_path is None or not procdump_path.is_file():
        return {"skipped": True, "reason": "procdump was not found", "path": str(procdump_path) if procdump_path else None}
    dump_path.parent.mkdir(parents=True, exist_ok=True)
    result = run_tool(
        [str(procdump_path), "-accepteula", "-ma", str(process_id), str(dump_path)],
        log_path,
        timeout_seconds=180.0,
    )
    result["dump_path"] = str(dump_path)
    result["dump_exists"] = dump_path.is_file()
    result["dump_size_bytes"] = dump_path.stat().st_size if dump_path.is_file() else 0
    return result


def set_umdh_stack_tracing(gflags_path: str, app_exe: Path, *, enabled: bool, output_path: Path) -> dict[str, object]:
    """Enables or disables user-stack-trace database collection for the app image."""

    return run_tool(
        [gflags_path, "/i", app_exe.name, "+ust" if enabled else "-ust"],
        output_path,
        timeout_seconds=30.0,
    )


def capture_umdh_snapshot(umdh_path: str | None, process_id: int, snapshot_path: Path) -> dict[str, object]:
    """Captures one UMDH heap stack snapshot."""

    if not umdh_path:
        return {"skipped": True, "reason": "umdh was not found"}
    result = run_tool([umdh_path, f"-p:{process_id}", f"-f:{snapshot_path}"], snapshot_path.with_suffix(".stdout.txt"), 120.0)
    result["snapshot_path"] = str(snapshot_path)
    result["snapshot_exists"] = snapshot_path.is_file()
    return result


def diff_umdh_snapshots(umdh_path: str | None, before: Path, after: Path, output_path: Path) -> dict[str, object]:
    """Diffs two UMDH snapshots."""

    if not umdh_path:
        return {"skipped": True, "reason": "umdh was not found"}
    if not before.is_file() or not after.is_file():
        return {"skipped": True, "reason": "umdh snapshots are incomplete"}
    return run_tool([umdh_path, "-d", str(before), str(after)], output_path, 120.0)


def analyze_dump_with_cdb(dump_path: Path, output_path: Path) -> dict[str, object]:
    """Runs a compact CDB heap/address summary against a full-memory dump."""

    cdb = find_tool("cdb.exe", "cdb")
    if not cdb:
        return {"skipped": True, "reason": "cdb was not found"}
    if not dump_path.is_file():
        return {"skipped": True, "reason": "dump file was not found"}
    return run_tool(
        [
            cdb,
            "-z",
            str(dump_path),
            "-logo",
            str(output_path),
            "-c",
            ".reload; !address -summary; !heap -s; !heap -stat; !handle 0 1; ~* k 8; q",
        ],
        output_path.with_suffix(".runner.txt"),
        180.0,
    )
