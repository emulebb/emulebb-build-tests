"""Runs cold-start REST search/download stress with dump and heap diagnostics."""

from __future__ import annotations

import argparse
import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import cpu_profile, live_wire_inputs
from emule_test_harness.live_seed_sources import EMULE_SECURITY_HOME_URL, refresh_seed_files


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


rest_smoke = load_local_module("rest_api_smoke_for_cold_start_dump_stress", "rest-api-smoke.py")
harness_cli_common = rest_smoke.harness_cli_common
live_common = rest_smoke.live_common


class FILETIME(ctypes.Structure):
    """Windows FILETIME used for best-effort process CPU telemetry."""

    _fields_ = [
        ("dwLowDateTime", ctypes.c_uint32),
        ("dwHighDateTime", ctypes.c_uint32),
    ]


rest_smoke.kernel32.GetProcessTimes.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(FILETIME),
    ctypes.POINTER(FILETIME),
    ctypes.POINTER(FILETIME),
    ctypes.POINTER(FILETIME),
]
rest_smoke.kernel32.GetProcessTimes.restype = ctypes.c_int

SUITE_NAME = "rest-cold-start-dump-stress"
SUITE_INCONCLUSIVE_RETURN_CODE = 2
DIAGNOSTIC_LABELS = ("baseline", "peak", "post_drain")
UMDH_TOP_DELTA_LIMIT = 10
DEFAULT_MAX_POST_DRAIN_UMDH_POSITIVE_BYTES = 16 * 1024 * 1024
ACCESS_VIOLATION_EXIT_CODE = 0xC0000005
UMDH_DIFF_ENTRY_RE = re.compile(
    r"^\s*([+-]?)\s*([0-9][0-9,]*)\s+\(\s*([0-9,]+)\s*-\s*([0-9,]+)\s*\)\s+([0-9,]+)\s+allocs\s+(BackTrace[0-9A-Fa-f]+)\b"
)
CDB_HEAP_ROW_RE = re.compile(
    r"^\s*[0-9A-Fa-f`]+\s+[0-9A-Fa-f`]+\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\b"
)
CDB_ADDRESS_SUMMARY_RE = re.compile(
    r"^\s*([A-Za-z_<>\-]+)\s+([0-9]+)\s+[0-9A-Fa-f`]+\s+\(\s*([0-9.]+)\s+([KMGT]B)\)"
)
UMDH_ALLOCATOR_FRAME_PREFIXES = (
    "ntdll!",
    "emule!_malloc",
    "emule!operator new",
    "emule!CAfxStringMgr::Allocate",
)
VIDEO_ACTIVE_DOWNLOAD_SUFFIXES = (
    ".3gp",
    ".avi",
    ".divx",
    ".flv",
    ".m4v",
    ".mkv",
    ".mov",
    ".mp4",
    ".mpeg",
    ".mpg",
    ".msi",
    ".ogv",
    ".ps1",
    ".rm",
    ".rmvb",
    ".ts",
    ".vob",
    ".webm",
    ".wmv",
    ".xvid",
)
BLOCKED_ACTIVE_DOWNLOAD_SUFFIXES = VIDEO_ACTIVE_DOWNLOAD_SUFFIXES + (
    ".bat",
    ".cmd",
    ".com",
    ".exe",
    ".msi",
    ".ps1",
    ".scr",
    ".vbs",
)
VIDEO_ACTIVE_DOWNLOAD_TYPES = frozenset(("movie", "video"))
BLOCKED_ACTIVE_DOWNLOAD_TYPES = frozenset(("program", "executable", "movie", "video"))
OPEN_SOURCE_STRESS_TERMS = (
    "linux",
    "ubuntu",
    "debian",
    "gnu",
    "python",
    "rust",
    "mozilla",
    "firefox",
    "libreoffice",
    "gimp",
    "blender",
    "inkscape",
    "vlc",
    "kodi",
    "apache",
    "nginx",
    "postgresql",
    "mysql",
    "mariadb",
    "sqlite",
    "openjdk",
    "eclipse",
    "gcc",
    "llvm",
    "clang",
    "git",
    "kubernetes",
    "docker",
    "podman",
    "ansible",
    "terraform",
    "prometheus",
    "grafana",
    "jupyter",
    "numpy",
    "pandas",
    "scipy",
    "tensorflow",
    "pytorch",
    "raspberry",
    "arduino",
    "freecad",
    "krita",
    "audacity",
    "obs",
    "ffmpeg",
    "qemu",
    "virtualbox",
    "openwrt",
    "openstreetmap",
    "wikipedia",
    "wiktionary",
    "creative commons",
    "public domain",
    "open source",
    "fedora",
    "freebsd",
    "openbsd",
    "netbsd",
    "arch linux",
    "linux mint",
    "opensuse",
    "alpine linux",
    "raspberry pi os",
    "gentoo",
    "slackware",
    "centos",
    "rocky linux",
    "alma linux",
    "kernel",
    "busybox",
    "openoffice",
    "thunderbird",
    "filezilla",
    "wireshark",
    "notepad++",
    "putty",
    "winscp",
    "cygwin",
    "mingw",
)
MUST_RETURN_RESULT_TERMS = frozenset(
    (
        "linux",
        "ubuntu",
        "debian",
        "fedora",
        "gnu",
        "python",
        "rust",
    )
)


class DownloadTriggerCoordinator:
    """Coordinates per-run download hash de-duplication across search workers."""

    def __init__(self) -> None:
        self._claimed_hashes: set[str] = set()
        self._lock = threading.Lock()

    def claim(self, transfer_hash: str) -> bool:
        """Returns true when this run has not already claimed the transfer."""

        normalized = transfer_hash.lower()
        with self._lock:
            if normalized in self._claimed_hashes:
                return False
            self._claimed_hashes.add(normalized)
            return True


class StressTransferRegistry:
    """Tracks stress-triggered transfers for completion, churn, and telemetry."""

    def __init__(self) -> None:
        self._triggered: set[str] = set()
        self._completed: set[str] = set()
        self._deleted: set[str] = set()
        self._lock = threading.Lock()

    def record_triggered(self, transfer_hash: str) -> None:
        """Records one transfer hash after REST confirms materialization."""

        normalized = transfer_hash.lower()
        if not rest_smoke.is_lowercase_md4_hash(normalized):
            return
        with self._lock:
            self._triggered.add(normalized)
            self._deleted.discard(normalized)

    def record_completed(self, transfer_hash: str) -> None:
        """Records one stress transfer that reached native completed state."""

        normalized = transfer_hash.lower()
        if not rest_smoke.is_lowercase_md4_hash(normalized):
            return
        with self._lock:
            if normalized in self._triggered:
                self._completed.add(normalized)

    def record_deleted(self, transfer_hash: str) -> None:
        """Records one stress transfer deleted by churn or final cleanup."""

        normalized = transfer_hash.lower()
        if not rest_smoke.is_lowercase_md4_hash(normalized):
            return
        with self._lock:
            if normalized in self._triggered:
                self._deleted.add(normalized)

    def hashes(self) -> list[str]:
        """Returns all stress transfer hashes in stable order."""

        with self._lock:
            return sorted(self._triggered)

    def active_hashes(self) -> set[str]:
        """Returns hashes still counted as active for stress telemetry."""

        with self._lock:
            return set(self._triggered - self._completed - self._deleted)

    def counts(self) -> dict[str, int]:
        """Returns compact stress transfer counters."""

        with self._lock:
            active = self._triggered - self._completed - self._deleted
            return {
                "triggered_stress_transfer_count": len(self._triggered),
                "active_stress_transfer_count": len(active),
                "completed_stress_transfer_count": len(self._completed),
                "deleted_stress_transfer_count": len(self._deleted),
            }


def filetime_to_100ns(value: FILETIME) -> int:
    """Converts a FILETIME structure to 100ns ticks."""

    return (int(value.dwHighDateTime) << 32) + int(value.dwLowDateTime)


def get_process_cpu_time_100ns(process_id: int | None) -> int | None:
    """Returns process user+kernel CPU time in 100ns ticks when available."""

    if process_id is None:
        return None
    process_handle = rest_smoke.kernel32.OpenProcess(rest_smoke.PROCESS_QUERY_LIMITED_INFORMATION, False, process_id)
    if not process_handle:
        return None
    try:
        create_time = FILETIME()
        exit_time = FILETIME()
        kernel_time = FILETIME()
        user_time = FILETIME()
        if not rest_smoke.kernel32.GetProcessTimes(
            process_handle,
            ctypes.byref(create_time),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            return None
        return filetime_to_100ns(kernel_time) + filetime_to_100ns(user_time)
    finally:
        rest_smoke.kernel32.CloseHandle(process_handle)


def compute_cpu_percent(
    before_cpu_100ns: int | None,
    after_cpu_100ns: int | None,
    elapsed_seconds: float,
    logical_cpu_count: int | None,
) -> float | None:
    """Computes process CPU percent normalized across logical CPUs."""

    if before_cpu_100ns is None or after_cpu_100ns is None:
        return None
    if elapsed_seconds <= 0:
        return None
    if logical_cpu_count is None or logical_cpu_count <= 0:
        return None
    delta_seconds = max(0.0, (after_cpu_100ns - before_cpu_100ns) / 10_000_000.0)
    return round((delta_seconds / elapsed_seconds) * 100.0 / logical_cpu_count, 3)


def percentile_value(values: list[float], percentile: int) -> float | None:
    """Returns a compact nearest-rank percentile for telemetry summaries."""

    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, min(len(ordered), (len(ordered) * percentile + 99) // 100))
    return ordered[rank - 1]


def summarize_resource_monitor_samples(samples: list[dict[str, object]]) -> dict[str, object]:
    """Summarizes continuous resource telemetry samples."""

    cpu_values = [float(row["cpu_percent"]) for row in samples if isinstance(row.get("cpu_percent"), (int, float))]
    thread_values = [int(row["thread_count"]) for row in samples if isinstance(row.get("thread_count"), int)]
    handle_values = [int(row["handles"]) for row in samples if isinstance(row.get("handles"), int)]
    private_values = [int(row["private_bytes"]) for row in samples if isinstance(row.get("private_bytes"), int)]
    working_set_values = [int(row["working_set_bytes"]) for row in samples if isinstance(row.get("working_set_bytes"), int)]
    return {
        "sample_count": len(samples),
        "cpu_percent_avg": round(sum(cpu_values) / len(cpu_values), 3) if cpu_values else None,
        "cpu_percent_p95": percentile_value(cpu_values, 95),
        "cpu_percent_max": max(cpu_values) if cpu_values else None,
        "thread_count_max": max(thread_values) if thread_values else None,
        "handles_max": max(handle_values) if handle_values else None,
        "private_bytes_max": max(private_values) if private_values else None,
        "working_set_bytes_max": max(working_set_values) if working_set_values else None,
    }


class ProcessResourceMonitor:
    """Samples process resources in the background while live stress runs."""

    def __init__(
        self,
        *,
        process_id: int | None,
        interval_seconds: float,
        counts_provider,
    ) -> None:
        self.process_id = process_id
        self.interval_seconds = interval_seconds
        self.counts_provider = counts_provider
        self.samples: list[dict[str, object]] = []
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._previous_cpu_100ns: int | None = None
        self._previous_monotonic: float | None = None
        self._logical_cpu_count = os.cpu_count() or 1

    def start(self) -> None:
        """Starts the monitor thread when sampling is enabled."""

        if self.interval_seconds <= 0 or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="rest-cold-start-resource-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> dict[str, object]:
        """Stops the monitor and returns a summary plus retained samples."""

        if self._thread is not None:
            self._stop_event.set()
            self._thread.join(timeout=max(2.0, self.interval_seconds + 1.0))
        return {
            "samples": self.samples,
            "summary": summarize_resource_monitor_samples(self.samples),
        }

    def sample_once(self) -> dict[str, object]:
        """Collects one telemetry sample."""

        observed_at_monotonic = time.monotonic()
        observed_at = round(time.time(), 3)
        cpu_100ns = get_process_cpu_time_100ns(self.process_id)
        cpu_percent = compute_cpu_percent(
            self._previous_cpu_100ns,
            cpu_100ns,
            observed_at_monotonic - self._previous_monotonic if self._previous_monotonic is not None else 0.0,
            self._logical_cpu_count,
        )
        self._previous_cpu_100ns = cpu_100ns
        self._previous_monotonic = observed_at_monotonic

        sample: dict[str, object] = {
            "observed_at": observed_at,
            "cpu_percent": cpu_percent,
        }
        resources = rest_smoke.get_process_resource_snapshot(self.process_id)
        sample.update(resources)
        try:
            counts = self.counts_provider()
        except Exception as exc:
            counts = {
                "stress_transfer_count_error": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            }
        sample.update(counts)
        self.samples.append(sample)
        return sample

    def _run(self) -> None:
        self.sample_once()
        while not self._stop_event.wait(self.interval_seconds):
            self.sample_once()


def build_parser() -> argparse.ArgumentParser:
    """Builds the cold-start diagnostic stress CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default="rest-cold-start-dump-stress-key")
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--enable-upnp", action="store_true", default=True)
    parser.add_argument("--p2p-bind-interface-name", default="hide.me")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--network-ready-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--kad-running-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--search-observation-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--seed-download-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument("--live-wire-inputs-file", default=str(live_wire_inputs.get_default_inputs_path(REPO_ROOT)))
    parser.add_argument("--waves", type=int, default=4)
    parser.add_argument("--searches-per-wave", type=int, default=12)
    parser.add_argument("--max-concurrent-searches", type=int, default=8)
    parser.add_argument("--downloads-per-wave", type=int, default=12)
    parser.add_argument("--downloads-per-search", type=int)
    parser.add_argument("--max-missing-download-triggers", type=int, default=0)
    parser.add_argument("--target-completed-downloads", type=int, default=0)
    parser.add_argument("--completion-timeout-seconds", type=float, default=1800.0)
    parser.add_argument("--max-active-downloads", type=int, default=128)
    parser.add_argument("--download-churn-interval-seconds", type=float, default=0.0)
    parser.add_argument("--download-remove-count-per-churn", type=int, default=0)
    parser.add_argument("--resource-monitor-interval-seconds", type=float, default=5.0)
    parser.add_argument("--post-drain-seconds", type=float, default=30.0)
    parser.add_argument("--tool-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--enable-umdh", action="store_true")
    parser.add_argument("--max-post-drain-umdh-positive-bytes", type=int, default=DEFAULT_MAX_POST_DRAIN_UMDH_POSITIVE_BYTES)
    parser.add_argument("--cpu-profile", action="store_true")
    parser.add_argument("--cpu-profile-max-file-mb", type=int, default=cpu_profile.DEFAULT_CPU_PROFILE_MAX_FILE_MB)
    parser.add_argument("--cpu-profile-symbols-required", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--skip-dumps", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validates stress and diagnostic CLI arguments."""

    if args.waves <= 0:
        raise ValueError("waves must be greater than zero.")
    if args.searches_per_wave <= 0:
        raise ValueError("searches per wave must be greater than zero.")
    if args.max_concurrent_searches <= 0:
        raise ValueError("max concurrent searches must be greater than zero.")
    if args.downloads_per_wave < 0:
        raise ValueError("downloads per wave must be zero or greater.")
    if args.downloads_per_search is not None and args.downloads_per_search < 0:
        raise ValueError("downloads per search must be zero or greater.")
    if args.max_missing_download_triggers < 0:
        raise ValueError("max missing download triggers must be zero or greater.")
    if args.target_completed_downloads < 0:
        raise ValueError("target completed downloads must be zero or greater.")
    if args.completion_timeout_seconds <= 0:
        raise ValueError("completion timeout seconds must be greater than zero.")
    if args.max_active_downloads <= 0:
        raise ValueError("max active downloads must be greater than zero.")
    if args.download_churn_interval_seconds < 0:
        raise ValueError("download churn interval seconds must be zero or greater.")
    if args.download_remove_count_per_churn < 0:
        raise ValueError("download remove count per churn must be zero or greater.")
    if args.resource_monitor_interval_seconds < 0:
        raise ValueError("resource monitor interval seconds must be zero or greater.")
    if args.post_drain_seconds < 0:
        raise ValueError("post-drain seconds must be zero or greater.")
    if args.tool_timeout_seconds <= 0:
        raise ValueError("tool timeout seconds must be greater than zero.")
    if args.max_post_drain_umdh_positive_bytes < 0:
        raise ValueError("max post-drain UMDH positive bytes must be zero or greater.")
    if args.cpu_profile_max_file_mb <= 0:
        raise ValueError("CPU profile max file MB must be greater than zero.")


def resolve_downloads_per_search(args: argparse.Namespace) -> int:
    """Resolves the per-search trigger budget while preserving legacy defaults."""

    explicit = getattr(args, "downloads_per_search", None)
    if explicit is not None:
        return int(explicit)
    searches_per_wave = max(1, int(args.searches_per_wave))
    return max(0, int(args.downloads_per_wave) // searches_per_wave)


def build_open_source_stress_terms(configured_terms: tuple[str, ...]) -> tuple[str, ...]:
    """Combines operator terms with built-in open-source stress terms."""

    terms: list[str] = []
    seen: set[str] = set()
    for term in (*configured_terms, *OPEN_SOURCE_STRESS_TERMS):
        normalized = " ".join(str(term).split()).strip()
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            terms.append(normalized)
    return tuple(terms)


def public_search_term_label(query: object) -> str:
    """Returns a report-safe label for built-in public OSS terms and redacts custom terms."""

    normalized = " ".join(str(query).split()).strip().lower()
    return normalized if normalized in OPEN_SOURCE_STRESS_TERMS else "<custom>"


def candidate_tool_paths(tool_name: str) -> list[Path]:
    """Returns deterministic fallback locations for Windows diagnostic tools."""

    candidates: list[Path] = []
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(env_name)
        if root:
            candidates.append(Path(root) / "Windows Kits" / "10" / "Debuggers" / "x64" / tool_name)
    program_data = os.environ.get("ProgramData")
    if program_data:
        candidates.append(Path(program_data) / "chocolatey" / "lib" / "sysinternals" / "tools" / tool_name)
        candidates.append(Path(program_data) / "chocolatey" / "bin" / tool_name)
    system_root = os.environ.get("SystemRoot")
    if system_root:
        candidates.append(Path(system_root) / "System32" / tool_name)
    return candidates


def is_known_broken_chocolatey_sysinternals_shim(path: str) -> bool:
    """Returns true for Chocolatey Sysinternals shims whose package payload is missing."""

    program_data = os.environ.get("ProgramData")
    if not program_data:
        return False
    candidate = Path(path)
    shim_dir = Path(program_data) / "chocolatey" / "bin"
    try:
        if candidate.resolve().parent != shim_dir.resolve():
            return False
    except OSError:
        return False
    backing_tool = Path(program_data) / "chocolatey" / "lib" / "sysinternals" / "tools" / candidate.name
    return not backing_tool.is_file()


def find_tool(*names: str) -> str | None:
    """Finds the first available executable from PATH or known Windows tool roots."""

    for name in names:
        for candidate in candidate_tool_paths(name):
            if candidate.is_file():
                if is_known_broken_chocolatey_sysinternals_shim(str(candidate)):
                    continue
                return str(candidate)
        resolved = shutil.which(name)
        if resolved and not is_known_broken_chocolatey_sysinternals_shim(resolved):
            return resolved
    return None


def discover_diagnostic_tools() -> dict[str, str | None]:
    """Discovers Sysinternals and Windows SDK tools used by the diagnostic lane."""

    return {
        "procdump": find_tool("procdump64.exe", "procdump64", "procdump.exe", "procdump"),
        "cdb": find_tool("cdb.exe", "cdb"),
        "handle": find_tool("handle64.exe", "handle64", "handle.exe", "handle"),
        "listdlls": find_tool("listdlls64.exe", "listdlls64", "listdlls.exe", "listdlls"),
        "gflags": find_tool("gflags.exe", "gflags"),
        "umdh": find_tool("umdh.exe", "umdh"),
    }


def cpu_profile_tools_to_report(tools: cpu_profile.CpuProfileTools) -> dict[str, str | None]:
    """Returns a JSON-safe CPU profiling tool discovery payload."""

    return {
        "xperf": tools.xperf,
        "wpaexporter": tools.wpaexporter,
    }


def cpu_profile_paths_to_report(paths: cpu_profile.CpuProfilePaths) -> dict[str, str]:
    """Returns a JSON-safe CPU profiling artifact path payload."""

    return {
        "etl_path": str(paths.etl_path),
        "raw_etl_path": str(paths.raw_etl_path),
        "detail_path": str(paths.detail_path),
        "summary_path": str(paths.summary_path),
        "symbol_cache_dir": str(paths.symbol_cache_dir),
    }


def build_cpu_profile_symbol_status(app_exe: Path) -> dict[str, object]:
    """Returns whether the app-local PDB needed for useful attribution exists."""

    pdb_path = cpu_profile.resolve_app_pdb_path(app_exe)
    return {
        "app_pdb_path": str(pdb_path),
        "app_pdb_exists": pdb_path.is_file(),
    }


def initialize_cpu_profile_report(
    *,
    app_exe: Path,
    artifacts_dir: Path,
) -> tuple[cpu_profile.CpuProfileTools, cpu_profile.CpuProfilePaths, dict[str, object]]:
    """Discovers CPU profiling tools and builds the initial report payload."""

    tools = cpu_profile.discover_cpu_profile_tools()
    paths = cpu_profile.build_cpu_profile_paths(artifacts_dir)
    report = {
        "enabled": True,
        "tools": cpu_profile_tools_to_report(tools),
        "paths": cpu_profile_paths_to_report(paths),
        "symbols": build_cpu_profile_symbol_status(app_exe),
    }
    return tools, paths, report


def export_cpu_profile_summary(
    *,
    tools: cpu_profile.CpuProfileTools,
    paths: cpu_profile.CpuProfilePaths,
    app_exe: Path,
    timeout_seconds: float,
) -> dict[str, object]:
    """Exports the ETW profile and writes the compact top-function summary."""

    export = cpu_profile.export_cpu_profile(
        tools=tools,
        paths=paths,
        app_exe=app_exe,
        timeout_seconds=timeout_seconds,
    )
    summary = cpu_profile.parse_xperf_profile_detail_file(paths.detail_path)
    harness_cli_common.write_json_file(paths.summary_path, summary)
    return {
        "export": export,
        "summary": summary,
    }


def run_tool_to_file(
    command: list[str],
    output_path: Path,
    timeout_seconds: float,
    *,
    env: dict[str, str] | None = None,
) -> dict[str, object]:
    """Runs one diagnostic tool and writes stdout/stderr plus metadata to a file."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    command_line = subprocess.list2cmdline(command)
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            env=env,
        )
        duration = round(time.monotonic() - started, 3)
        output_path.write_text(
            "\n".join(
                [
                    f"command: {command_line}",
                    f"return_code: {completed.returncode}",
                    f"duration_seconds: {duration}",
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
            "duration_seconds": duration,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        duration = round(time.monotonic() - started, 3)
        output_path.write_text(
            "\n".join(
                [
                    f"command: {command_line}",
                    f"timed_out: true",
                    f"duration_seconds: {duration}",
                    "",
                    str(exc.stdout or ""),
                    str(exc.stderr or ""),
                ]
            ),
            encoding="utf-8",
        )
        return {
            "command": command,
            "output_path": str(output_path),
            "return_code": None,
            "duration_seconds": duration,
            "timed_out": True,
        }


def build_symbol_environment(app_exe: Path, artifacts_dir: Path) -> dict[str, str]:
    """Builds a symbol environment for UMDH/CDB without changing the parent process."""

    env = dict(os.environ)
    symbol_cache = artifacts_dir / "symbols"
    symbol_cache.mkdir(parents=True, exist_ok=True)
    app_symbol_dir = app_exe.parent
    env["_NT_SYMBOL_PATH"] = f"{app_symbol_dir};srv*{symbol_cache}*https://msdl.microsoft.com/download/symbols"
    return env


def set_umdh_stack_tracing(
    gflags_path: str,
    app_exe: Path,
    enabled: bool,
    output_path: Path,
    timeout_seconds: float,
) -> dict[str, object]:
    """Enables or disables UST for the app image with gflags."""

    flag = "+ust" if enabled else "-ust"
    return run_tool_to_file(
        [gflags_path, "/i", app_exe.name, flag],
        output_path,
        timeout_seconds,
    )


def cdb_size_to_bytes(value: str, unit: str) -> int:
    """Converts a CDB human-size pair to bytes."""

    multiplier_by_unit = {
        "KB": 1024,
        "MB": 1024 * 1024,
        "GB": 1024 * 1024 * 1024,
        "TB": 1024 * 1024 * 1024 * 1024,
    }
    return int(float(value) * multiplier_by_unit[unit])


def parse_cdb_summary_text(text: str) -> dict[str, object]:
    """Extracts heap and address summary metrics from CDB diagnostic output."""

    heap_totals = {
        "heap_count": 0,
        "reserve_bytes": 0,
        "commit_bytes": 0,
        "virtual_bytes": 0,
        "free_bytes": 0,
        "free_block_count": 0,
        "ucr_count": 0,
        "virtual_alloc_count": 0,
    }
    address_usage: dict[str, dict[str, int]] = {}
    in_heap_table = False
    in_usage_summary = False
    for line in text.splitlines():
        if "Heap     Flags   Reserv  Commit" in line:
            in_heap_table = True
            continue
        if in_heap_table and line.startswith("-----"):
            continue
        if in_heap_table:
            heap_match = CDB_HEAP_ROW_RE.match(line)
            if heap_match:
                reserve_kb, commit_kb, virtual_kb, free_kb, free_blocks, ucr_count, virtual_alloc_count, _lock_count = (
                    int(group) for group in heap_match.groups()
                )
                heap_totals["heap_count"] += 1
                heap_totals["reserve_bytes"] += reserve_kb * 1024
                heap_totals["commit_bytes"] += commit_kb * 1024
                heap_totals["virtual_bytes"] += virtual_kb * 1024
                heap_totals["free_bytes"] += free_kb * 1024
                heap_totals["free_block_count"] += free_blocks
                heap_totals["ucr_count"] += ucr_count
                heap_totals["virtual_alloc_count"] += virtual_alloc_count
                continue
            if line.startswith("---- Usage Summary"):
                in_heap_table = False
                in_usage_summary = True
                continue
            if line.startswith("0:") or line.startswith("--- "):
                in_heap_table = False

        if line.startswith("--- Usage Summary"):
            in_usage_summary = True
            continue
        if in_usage_summary:
            if line.startswith("--- ") and not line.startswith("--- Usage Summary"):
                in_usage_summary = False
                continue
            address_match = CDB_ADDRESS_SUMMARY_RE.match(line)
            if address_match:
                name, region_count, size_value, size_unit = address_match.groups()
                address_usage[name] = {
                    "region_count": int(region_count),
                    "total_bytes": cdb_size_to_bytes(size_value, size_unit),
                }

    summary: dict[str, object] = {}
    if heap_totals["heap_count"]:
        summary["heap"] = heap_totals
    if address_usage:
        summary["address_usage"] = address_usage
    return summary


def parse_cdb_summary_file(cdb_log: Path) -> dict[str, object]:
    """Reads one CDB log and returns structured heap/address metrics."""

    if not cdb_log.is_file():
        return {"available": False, "reason": "CDB log was not written"}
    try:
        summary = parse_cdb_summary_text(cdb_log.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        return {
            "available": False,
            "reason": f"{type(exc).__name__}: {exc}",
        }
    summary["available"] = True
    return summary


def capture_dump_and_analysis(
    *,
    label: str,
    process_id: int,
    tools: dict[str, str | None],
    diagnostics_dir: Path,
    timeout_seconds: float,
    skip_dumps: bool,
    symbol_env: dict[str, str],
) -> dict[str, object]:
    """Captures a full dump and runs CDB summary analysis when available."""

    result: dict[str, object] = {
        "label": label,
        "skipped": bool(skip_dumps),
        "dump": None,
        "cdb": None,
    }
    if skip_dumps:
        return result

    procdump = tools.get("procdump")
    if not procdump:
        result["error"] = "procdump was not found"
        return result

    dump_path = diagnostics_dir / "dumps" / f"{label}.dmp"
    dump_path.parent.mkdir(parents=True, exist_ok=True)
    procdump_log = diagnostics_dir / "analysis" / f"{label}-procdump.txt"
    dump_run = run_tool_to_file(
        [procdump, "-accepteula", "-ma", str(process_id), str(dump_path)],
        procdump_log,
        timeout_seconds,
    )
    dump_run["dump_path"] = str(dump_path)
    dump_run["dump_exists"] = dump_path.is_file()
    result["dump"] = dump_run

    cdb = tools.get("cdb")
    if cdb and dump_path.is_file():
        cdb_log = diagnostics_dir / "analysis" / f"{label}-cdb.txt"
        cdb_run = run_tool_to_file(
            [
                cdb,
                "-z",
                str(dump_path),
                "-c",
                ".symfix; .reload; |; lm; ~*k; !handle 0 0; !heap -s; !address -summary; q",
            ],
            cdb_log,
            timeout_seconds,
            env=symbol_env,
        )
        cdb_run["summary"] = parse_cdb_summary_file(cdb_log)
        result["cdb"] = cdb_run
    elif not cdb:
        result["cdb"] = {"skipped": True, "reason": "cdb was not found"}
    return result


def redact_sensitive_search_value(value: object) -> object:
    """Redacts exact live search terms from persisted stress artifacts."""

    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            if key == "query":
                redacted["query_present"] = bool(item)
            elif key == "message":
                redacted["message_redacted"] = True
            elif key == "body_text":
                redacted["body_text_redacted"] = True
            else:
                redacted[key] = redact_sensitive_search_value(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive_search_value(item) for item in value]
    return value


def capture_text_snapshot(
    *,
    tool_path: str | None,
    command_suffix: list[str],
    output_path: Path,
    timeout_seconds: float,
    missing_reason: str,
) -> dict[str, object]:
    """Captures a text diagnostic snapshot from one Sysinternals-style tool."""

    if not tool_path:
        return {"skipped": True, "reason": missing_reason}
    return run_tool_to_file([tool_path, *command_suffix], output_path, timeout_seconds)


def capture_umdh_snapshot(
    *,
    label: str,
    process_id: int,
    tools: dict[str, str | None],
    diagnostics_dir: Path,
    timeout_seconds: float,
    symbol_env: dict[str, str],
) -> dict[str, object]:
    """Captures one UMDH snapshot for the current process."""

    umdh = tools.get("umdh")
    if not umdh:
        return {"skipped": True, "reason": "umdh was not found"}
    snapshot_path = diagnostics_dir / "analysis" / f"umdh-{label}.txt"
    run = run_tool_to_file(
        [umdh, f"-p:{process_id}", f"-f:{snapshot_path}"],
        diagnostics_dir / "analysis" / f"umdh-{label}-stdout.txt",
        timeout_seconds,
        env=symbol_env,
    )
    run["snapshot_path"] = str(snapshot_path)
    run["snapshot_exists"] = snapshot_path.is_file()
    return run


def parse_umdh_int(value: str) -> int:
    """Parses comma-formatted UMDH integers."""

    return int(value.replace(",", ""))


def umdh_frame_symbol(frame: object) -> str:
    """Normalizes a UMDH frame to a stable module/function symbol."""

    text = str(frame).strip()
    if not text:
        return "<unknown>"
    symbol = text.split(" ", 1)[0]
    if "+" in symbol:
        symbol = symbol.split("+", 1)[0]
    return symbol or "<unknown>"


def umdh_app_allocation_frame(stack: object) -> str:
    """Returns the first non-allocator eMule frame from one UMDH stack."""

    if not isinstance(stack, list):
        return "<unknown>"
    for frame in stack:
        text = str(frame).strip()
        if not text:
            continue
        if any(text.startswith(prefix) for prefix in UMDH_ALLOCATOR_FRAME_PREFIXES):
            continue
        if text.startswith("emule!"):
            return umdh_frame_symbol(text)
    return "<allocator-only>" if stack else "<unknown>"


def summarize_umdh_app_frames(entries: list[dict[str, object]], *, limit: int = UMDH_TOP_DELTA_LIMIT) -> list[dict[str, object]]:
    """Groups UMDH positive deltas by the first relevant eMule allocation frame."""

    grouped: dict[str, dict[str, object]] = {}
    for entry in entries:
        frame = umdh_app_allocation_frame(entry.get("stack"))
        row = grouped.setdefault(
            frame,
            {
                "frame": frame,
                "delta_bytes": 0,
                "allocation_count": 0,
                "trace_count": 0,
            },
        )
        row["delta_bytes"] = int(row["delta_bytes"]) + int(entry.get("delta_bytes", 0))
        row["allocation_count"] = int(row["allocation_count"]) + int(entry.get("allocation_count", 0))
        row["trace_count"] = int(row["trace_count"]) + 1
    rows = list(grouped.values())
    rows.sort(key=lambda row: int(row["delta_bytes"]), reverse=True)
    return rows[:limit]


def parse_umdh_diff_text(text: str, *, limit: int = UMDH_TOP_DELTA_LIMIT) -> dict[str, object]:
    """Extracts the largest positive allocation deltas from UMDH diff output."""

    entries: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for line in text.splitlines():
        match = UMDH_DIFF_ENTRY_RE.match(line)
        if match:
            sign, delta_text, after_text, before_text, alloc_text, trace_id = match.groups()
            delta_bytes = parse_umdh_int(delta_text)
            if sign == "-":
                current = None
                continue
            entry = {
                "delta_bytes": delta_bytes,
                "after_bytes": parse_umdh_int(after_text),
                "before_bytes": parse_umdh_int(before_text),
                "allocation_count": parse_umdh_int(alloc_text),
                "trace_id": trace_id,
                "stack": [],
            }
            entries.append(entry)
            current = entry
            continue
        if current is None:
            continue
        frame = line.strip()
        if not frame or "BackTrace" in frame:
            continue
        stack = current["stack"]
        assert isinstance(stack, list)
        if len(stack) < 8:
            stack.append(frame)

    positive_entries = [entry for entry in entries if int(entry["delta_bytes"]) > 0]
    positive_entries.sort(key=lambda entry: int(entry["delta_bytes"]), reverse=True)
    return {
        "positive_delta_count": len(positive_entries),
        "positive_delta_bytes": sum(int(entry["delta_bytes"]) for entry in positive_entries),
        "top_positive_deltas": positive_entries[:limit],
        "top_positive_app_frames": summarize_umdh_app_frames(positive_entries, limit=limit),
    }


def parse_umdh_diff_file(diff_path: Path, *, limit: int = UMDH_TOP_DELTA_LIMIT) -> dict[str, object]:
    """Reads one UMDH diff log and returns a compact allocation-delta summary."""

    if not diff_path.is_file():
        return {"available": False, "reason": "UMDH diff log was not written"}
    try:
        summary = parse_umdh_diff_text(diff_path.read_text(encoding="utf-8", errors="replace"), limit=limit)
    except OSError as exc:
        return {
            "available": False,
            "reason": f"{type(exc).__name__}: {exc}",
        }
    summary["available"] = True
    return summary


def diff_umdh_snapshots(
    *,
    before: Path,
    after: Path,
    diff_name: str,
    tools: dict[str, str | None],
    diagnostics_dir: Path,
    timeout_seconds: float,
    symbol_env: dict[str, str],
) -> dict[str, object]:
    """Runs UMDH diff mode for two completed snapshots."""

    umdh = tools.get("umdh")
    if not umdh:
        return {"skipped": True, "reason": "umdh was not found"}
    if not before.is_file() or not after.is_file():
        return {"skipped": True, "reason": "one or both UMDH snapshots are missing"}
    output_path = diagnostics_dir / "analysis" / f"umdh-diff-{diff_name}.txt"
    run = run_tool_to_file(
        [umdh, "-d", str(before), str(after)],
        output_path,
        timeout_seconds,
        env=symbol_env,
    )
    run["summary"] = parse_umdh_diff_file(output_path)
    return run


def summarize_umdh_diffs(diagnostics: dict[str, object]) -> dict[str, object]:
    """Builds a compact report-level summary from parsed UMDH diff results."""

    diffs = diagnostics.get("umdh_diffs")
    if not isinstance(diffs, dict):
        return {}
    summary: dict[str, object] = {}
    for diff_name, diff_result in diffs.items():
        if not isinstance(diff_result, dict):
            continue
        diff_summary = diff_result.get("summary")
        if isinstance(diff_summary, dict):
            summary[str(diff_name)] = diff_summary
    return summary


def summarize_resource_deltas(diagnostics: dict[str, object]) -> dict[str, object]:
    """Summarizes resource deltas between baseline, peak, and post-drain snapshots."""

    resources_by_label: dict[str, dict[str, object]] = {}
    for label in DIAGNOSTIC_LABELS:
        entry = diagnostics.get(label)
        if not isinstance(entry, dict):
            continue
        resources = entry.get("resources")
        if isinstance(resources, dict):
            resources_by_label[label] = resources
    baseline = resources_by_label.get("baseline")
    if not baseline:
        return {}

    def numeric_deltas(left: dict[str, object], right: dict[str, object]) -> dict[str, int]:
        deltas: dict[str, int] = {}
        for key, right_value in right.items():
            if key == "process_id":
                continue
            left_value = left.get(key)
            if isinstance(left_value, int) and not isinstance(left_value, bool) and isinstance(right_value, int) and not isinstance(right_value, bool):
                deltas[key] = right_value - left_value
        return deltas

    summary: dict[str, object] = {}
    for label in ("peak", "post_drain"):
        resources = resources_by_label.get(label)
        if resources:
            summary[f"{label}_minus_baseline"] = numeric_deltas(baseline, resources)
    peak = resources_by_label.get("peak")
    post_drain = resources_by_label.get("post_drain")
    if peak and post_drain:
        summary["post_drain_minus_peak"] = numeric_deltas(peak, post_drain)
    return summary


def summarize_cdb_deltas(diagnostics: dict[str, object]) -> dict[str, object]:
    """Summarizes CDB heap/address deltas between diagnostic snapshots."""

    summaries_by_label: dict[str, dict[str, object]] = {}
    for label in DIAGNOSTIC_LABELS:
        entry = diagnostics.get(label)
        if not isinstance(entry, dict):
            continue
        tools = entry.get("tools")
        if not isinstance(tools, dict):
            continue
        dump_analysis = tools.get("dump_analysis")
        if not isinstance(dump_analysis, dict):
            continue
        cdb = dump_analysis.get("cdb")
        if not isinstance(cdb, dict):
            continue
        cdb_summary = cdb.get("summary")
        if isinstance(cdb_summary, dict):
            summaries_by_label[label] = cdb_summary

    baseline = summaries_by_label.get("baseline")
    if not baseline:
        return {}

    def numeric_deltas(left: dict[str, object], right: dict[str, object]) -> dict[str, int]:
        deltas: dict[str, int] = {}
        for key, right_value in right.items():
            left_value = left.get(key)
            if isinstance(left_value, int) and not isinstance(left_value, bool) and isinstance(right_value, int) and not isinstance(right_value, bool):
                deltas[key] = right_value - left_value
        return deltas

    def summary_delta(left: dict[str, object], right: dict[str, object]) -> dict[str, object]:
        delta: dict[str, object] = {}
        left_heap = left.get("heap")
        right_heap = right.get("heap")
        if isinstance(left_heap, dict) and isinstance(right_heap, dict):
            delta["heap"] = numeric_deltas(left_heap, right_heap)
        left_usage = left.get("address_usage")
        right_usage = right.get("address_usage")
        if isinstance(left_usage, dict) and isinstance(right_usage, dict):
            address_deltas: dict[str, dict[str, int]] = {}
            for name, right_row in right_usage.items():
                left_row = left_usage.get(name)
                if isinstance(left_row, dict) and isinstance(right_row, dict):
                    address_deltas[str(name)] = numeric_deltas(left_row, right_row)
            if address_deltas:
                delta["address_usage"] = address_deltas
        return delta

    summary: dict[str, object] = {}
    for label in ("peak", "post_drain"):
        cdb_summary = summaries_by_label.get(label)
        if cdb_summary:
            summary[f"{label}_minus_baseline"] = summary_delta(baseline, cdb_summary)
    peak = summaries_by_label.get("peak")
    post_drain = summaries_by_label.get("post_drain")
    if peak and post_drain:
        summary["post_drain_minus_peak"] = summary_delta(peak, post_drain)
    return summary


def collect_diagnostics(
    *,
    label: str,
    process_id: int | None,
    tools: dict[str, str | None],
    diagnostics_dir: Path,
    timeout_seconds: float,
    skip_dumps: bool,
    enable_umdh: bool,
    symbol_env: dict[str, str],
) -> dict[str, object]:
    """Collects resources, dumps, handles, loaded modules, and optional UMDH."""

    result: dict[str, object] = {
        "label": label,
        "process_id": process_id,
        "resources": rest_smoke.get_process_resource_snapshot(process_id),
        "tools": {},
    }
    harness_cli_common.write_json_file(diagnostics_dir / f"resources-{label}.json", result["resources"])
    if process_id is None:
        result["error"] = "process id is unavailable"
        return result

    result["tools"]["dump_analysis"] = capture_dump_and_analysis(
        label=label,
        process_id=process_id,
        tools=tools,
        diagnostics_dir=diagnostics_dir,
        timeout_seconds=timeout_seconds,
        skip_dumps=skip_dumps,
        symbol_env=symbol_env,
    )
    result["tools"]["handle"] = capture_text_snapshot(
        tool_path=tools.get("handle"),
        command_suffix=["-accepteula", "-p", str(process_id), "-a"],
        output_path=diagnostics_dir / "analysis" / f"handle-{label}.txt",
        timeout_seconds=timeout_seconds,
        missing_reason="handle was not found",
    )
    if label == "baseline":
        result["tools"]["listdlls"] = capture_text_snapshot(
            tool_path=tools.get("listdlls"),
            command_suffix=["-accepteula", "-v", str(process_id)],
            output_path=diagnostics_dir / "analysis" / "listdlls.txt",
            timeout_seconds=timeout_seconds,
            missing_reason="listdlls was not found",
        )
    if enable_umdh:
        result["tools"]["umdh"] = capture_umdh_snapshot(
            label=label,
            process_id=process_id,
            tools=tools,
            diagnostics_dir=diagnostics_dir,
            timeout_seconds=timeout_seconds,
            symbol_env=symbol_env,
        )
    return result


def build_wave_search_plan(
    *,
    wave_index: int,
    searches_per_wave: int,
    search_terms: tuple[str, ...],
    network_mode: str,
) -> list[dict[str, object]]:
    """Builds one phased-ramp wave with mixed methods when live networks allow it."""

    if not search_terms:
        raise RuntimeError("Cold-start stress requires at least one live search term.")
    method_cycle = (("server", "server"), ("server", "global"), ("kad", "kad"), ("server", "automatic"))
    rows: list[dict[str, object]] = []
    for index in range(searches_per_wave):
        network, method = method_cycle[index % len(method_cycle)]
        term_index = ((wave_index - 1) * searches_per_wave + index) % len(search_terms)
        query = search_terms[term_index]
        rows.append(
            {
                "wave": wave_index,
                "ordinal": index + 1,
                "network": network,
                "method": method,
                "query": query,
                "query_index": term_index,
            }
        )
    return rows


def is_stress_download_candidate(result_row: object) -> bool:
    """Returns whether one live result is acceptable for active stress download."""

    if not isinstance(result_row, dict):
        return False
    file_name = str(result_row.get("name") or "").strip().lower()
    file_type = str(result_row.get("fileType") or "").strip().lower()
    size_bytes = result_row.get("sizeBytes", result_row.get("size"))
    sources = result_row.get("sources")
    if not file_name or file_name.endswith(BLOCKED_ACTIVE_DOWNLOAD_SUFFIXES) or file_type in BLOCKED_ACTIVE_DOWNLOAD_TYPES:
        return False
    if not isinstance(sources, int) or isinstance(sources, bool) or sources < rest_smoke.MIN_SAFE_LIVE_DOWNLOAD_SOURCES:
        return False
    if not rest_smoke.is_lowercase_md4_hash(result_row.get("hash")):
        return False
    return (
        isinstance(size_bytes, int)
        and not isinstance(size_bytes, bool)
        and 0 < size_bytes <= rest_smoke.MAX_SAFE_LIVE_DOWNLOAD_BYTES
    )


def stress_candidate_extension(result_row: object) -> str:
    """Returns the lowercase file extension recorded for stress download summaries."""

    if not isinstance(result_row, dict):
        return ""
    file_name = str(result_row.get("name") or "").strip().lower()
    return Path(file_name).suffix if file_name else ""


def find_stress_download_candidates(search_payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Returns safe active-download candidates while excluding executables and video media."""

    results = search_payload.get("results")
    if not isinstance(results, list):
        return []
    candidates: list[dict[str, Any]] = []
    for result_row in results:
        if is_stress_download_candidate(result_row):
            assert isinstance(result_row, dict)
            candidates.append(result_row)
    return sort_stress_download_candidates(candidates)


def stress_candidate_size(candidate: dict[str, Any]) -> int:
    """Returns a safe integer size used for completion-oriented candidate ordering."""

    size_bytes = candidate.get("sizeBytes", candidate.get("size"))
    return int(size_bytes) if isinstance(size_bytes, int) and not isinstance(size_bytes, bool) else 0


def sort_stress_download_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prefers smaller safe files and then better complete-source counts."""

    return sorted(
        candidates,
        key=lambda candidate: (
            stress_candidate_size(candidate),
            -int(candidate.get("completeSources") or 0),
            -int(candidate.get("sources") or 0),
            str(candidate.get("hash") or ""),
        ),
    )


def trigger_active_downloads_from_search_result(
    base_url: str,
    api_key: str,
    search_id: str,
    timeout_seconds: float,
    downloads_per_search: int,
    trigger_coordinator: DownloadTriggerCoordinator,
    transfer_registry: StressTransferRegistry,
    max_active_downloads: int,
) -> dict[str, object]:
    """Triggers active real downloads from safe live search results."""

    observations: list[dict[str, object]] = []
    triggered: list[dict[str, object]] = []

    def resolve():
        if downloads_per_search <= 0:
            return {
                "ok": bool(triggered),
                "reason": "per-search download trigger budget is zero",
                "triggers": triggered,
                "observations": observations,
            }
        if len(triggered) >= downloads_per_search:
            return {
                "ok": True,
                "reason": "per-search download trigger budget exhausted",
                "triggers": triggered,
                "observations": observations,
            }
        active_count = transfer_registry.counts()["active_stress_transfer_count"]
        if active_count >= max_active_downloads:
            return {
                "ok": bool(triggered),
                "reason": "max active download cap reached",
                "active_stress_transfer_count": active_count,
                "triggers": triggered,
                "observations": observations,
            }
        result = rest_smoke.http_request(base_url, f"/api/v1/searches/{search_id}", api_key=api_key)
        if int(result["status"]) != 200 or not isinstance(result["json"], dict):
            return None
        payload = rest_smoke.require_json_object(result, 200)
        candidates = find_stress_download_candidates(payload)
        observations.append(
            {
                "observed_at": round(time.time(), 3),
                "status": payload.get("status"),
                "result_count": len(payload.get("results") or []),
                "candidate_count": len(candidates),
                "search_trigger_count": len(triggered),
                "downloads_per_search": downloads_per_search,
                "active_stress_transfer_count": active_count,
                "max_active_downloads": max_active_downloads,
            }
        )
        for candidate in candidates:
            transfer_hash = str(candidate["hash"])
            if len(triggered) >= downloads_per_search:
                break
            if transfer_registry.counts()["active_stress_transfer_count"] >= max_active_downloads:
                break
            if not trigger_coordinator.claim(transfer_hash):
                continue
            download = rest_smoke.http_request(
                base_url,
                f"/api/v1/searches/{search_id}/results/{transfer_hash}/operations/download",
                method="POST",
                api_key=api_key,
                json_body={"paused": False, "categoryId": 0},
                request_timeout_seconds=timeout_seconds,
            )
            rest_smoke.require_json_object(download, 200)
            transfer = rest_smoke.wait_for_triggered_transfer(
                base_url,
                api_key,
                transfer_hash,
                timeout_seconds,
            )
            transfer_registry.record_triggered(transfer_hash)
            triggered.append(
                {
                    "hash_present": True,
                    "candidate": {
                        "name_present": bool(candidate.get("name")),
                        "extension": stress_candidate_extension(candidate),
                        "sizeBytes": candidate.get("sizeBytes", candidate.get("size")),
                        "fileType": candidate.get("fileType"),
                        "sources": candidate.get("sources"),
                        "completeSources": candidate.get("completeSources"),
                    },
                    "download": {"status": download.get("status")},
                    "transfer": transfer,
                }
            )
            if len(triggered) >= downloads_per_search:
                break
        if triggered:
            return {
                "ok": True,
                "searchId": search_id,
                "active": True,
                "triggers": triggered,
                "observations": observations,
            }
        return None

    try:
        result = rest_smoke.wait_for(resolve, timeout=timeout_seconds, interval=2.0, description="active live download candidates")
    except Exception:
        return {
            "ok": False,
            "reason": "timed out without active download candidates",
            "active": True,
            "triggers": triggered,
            "observations": observations,
        }
    assert isinstance(result, dict)
    return result


def wait_for_stress_search_observation(
    base_url: str,
    api_key: str,
    search_id: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Observes a queued live search until results arrive or the full timeout expires."""

    observations: list[dict[str, object]] = []
    max_results = 0
    last_payload: dict[str, Any] | None = None
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        response = rest_smoke.http_request(base_url, f"/api/v1/searches/{search_id}", api_key=api_key)
        observed_at = round(time.time(), 3)
        if int(response.get("status", 0)) == 200 and isinstance(response.get("json"), dict):
            payload = rest_smoke.require_json_object(response, 200)
            results = payload.get("results")
            result_count = len(results) if isinstance(results, list) else 0
            max_results = max(max_results, result_count)
            last_payload = payload
            observations.append(
                {
                    "observed_at": observed_at,
                    "status": payload.get("status"),
                    "result_count": result_count,
                    "max_result_count": max_results,
                }
            )
            if result_count > 0:
                return {
                    "ok": True,
                    "searchId": search_id,
                    "terminal": "results",
                    "maxResults": max_results,
                    "last": payload,
                    "observations": observations,
                }
        else:
            observations.append(
                {
                    "observed_at": observed_at,
                    "status_code": response.get("status"),
                    "max_result_count": max_results,
                }
            )
        time.sleep(2.0)

    return {
        "ok": False,
        "searchId": search_id,
        "terminal": "timeout_zero_results",
        "maxResults": max_results,
        "last": last_payload,
        "observations": observations,
    }


def search_requires_nonzero_results(query: object) -> bool:
    """Returns true for common live-network terms that should not finish at zero."""

    return " ".join(str(query).split()).strip().lower() in MUST_RETURN_RESULT_TERMS


def fallback_search_methods(primary_method: object, resolved_method: object) -> tuple[str, ...]:
    """Returns fallback methods to try after a sentinel term observes zero results."""

    seen = {
        str(primary_method or "").strip().lower(),
        str(resolved_method or "").strip().lower(),
    }
    methods: list[str] = []
    for method in ("server", "global", "kad"):
        if method not in seen:
            methods.append(method)
    for method in (str(resolved_method or "").strip().lower(), str(primary_method or "").strip().lower()):
        if method in {"server", "global", "kad"} and method not in methods:
            methods.append(method)
    return tuple(methods)


def run_search_fallbacks(
    *,
    base_url: str,
    api_key: str,
    plan_row: dict[str, object],
    resolved_method: str,
    observation_timeout_seconds: float,
) -> dict[str, object]:
    """Retries sentinel searches on alternate backends before accepting zero results."""

    attempts: list[dict[str, object]] = []
    for method in fallback_search_methods(plan_row.get("method"), resolved_method):
        network = "kad" if method == "kad" else "server"
        attempt: dict[str, object] = {
            "method": method,
            "network": network,
        }
        try:
            started = rest_smoke.start_live_search(
                base_url,
                api_key,
                network,
                str(plan_row["query"]),
                forced_method=method,
            )
            attempt["start"] = redact_sensitive_search_value(started)
            if not bool(started.get("ok")):
                attempt["ok"] = False
                attempt["error"] = "fallback search start failed"
                attempts.append(attempt)
                continue
            response = started.get("response")
            assert isinstance(response, dict)
            payload = rest_smoke.require_json_object(response, 200)
            search_id = str(payload["id"])
            attempt["searchId"] = search_id
            attempt["activity"] = redact_sensitive_search_value(
                wait_for_stress_search_observation(
                    base_url,
                    api_key,
                    search_id,
                    observation_timeout_seconds,
                )
            )
            attempt["ok"] = int(attempt["activity"].get("maxResults", 0)) > 0 if isinstance(attempt.get("activity"), dict) else False
            attempts.append(attempt)
            if bool(attempt["ok"]):
                return {
                    "recovered": True,
                    "searchId": search_id,
                    "method": method,
                    "activity": attempt["activity"],
                    "attempts": attempts,
                }
        except Exception as exc:
            attempt["ok"] = False
            attempt["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
            attempts.append(attempt)
    return {
        "recovered": False,
        "attempts": attempts,
    }


def count_download_triggers(search_report: dict[str, object]) -> int:
    """Counts active downloads triggered by one search task."""

    trigger = search_report.get("download_trigger")
    if not isinstance(trigger, dict):
        return 0
    triggers = trigger.get("triggers")
    if not isinstance(triggers, list):
        return 1 if bool(trigger.get("ok")) else 0
    return len(triggers)


def summarize_download_triggers(stress_report: dict[str, object]) -> dict[str, object]:
    """Summarizes triggered file metadata so blocked media classes become a release gate."""

    file_type_counts: dict[str, int] = {}
    extension_counts: dict[str, int] = {}
    video_trigger_count = 0
    total_trigger_count = 0
    waves = stress_report.get("waves")
    if not isinstance(waves, list):
        return {
            "total": 0,
            "file_type_counts": file_type_counts,
            "extension_counts": extension_counts,
            "video_download_trigger_count": 0,
        }
    for wave in waves:
        if not isinstance(wave, dict):
            continue
        searches = wave.get("searches")
        if not isinstance(searches, list):
            continue
        for search in searches:
            if not isinstance(search, dict):
                continue
            trigger = search.get("download_trigger")
            if not isinstance(trigger, dict):
                continue
            triggers = trigger.get("triggers")
            if not isinstance(triggers, list):
                continue
            for trigger_row in triggers:
                if not isinstance(trigger_row, dict):
                    continue
                candidate = trigger_row.get("candidate")
                if not isinstance(candidate, dict):
                    continue
                total_trigger_count += 1
                file_type = str(candidate.get("fileType") or "").strip().lower()
                extension = str(candidate.get("extension") or "").strip().lower()
                if file_type:
                    file_type_counts[file_type] = file_type_counts.get(file_type, 0) + 1
                if extension:
                    extension_counts[extension] = extension_counts.get(extension, 0) + 1
                if file_type in VIDEO_ACTIVE_DOWNLOAD_TYPES or extension in VIDEO_ACTIVE_DOWNLOAD_SUFFIXES:
                    video_trigger_count += 1
    return {
        "total": total_trigger_count,
        "file_type_counts": dict(sorted(file_type_counts.items())),
        "extension_counts": dict(sorted(extension_counts.items())),
        "video_download_trigger_count": video_trigger_count,
    }


def collect_zero_result_searches(stress_report: dict[str, object], *, required_only: bool = False) -> list[dict[str, object]]:
    """Returns searches that completed observation without ever seeing a result."""

    zero_result_searches: list[dict[str, object]] = []
    waves = stress_report.get("waves")
    if not isinstance(waves, list):
        return zero_result_searches
    for wave in waves:
        if not isinstance(wave, dict):
            continue
        searches = wave.get("searches")
        if not isinstance(searches, list):
            continue
        for row in searches:
            if not isinstance(row, dict):
                continue
            activity = row.get("activity")
            if not isinstance(activity, dict):
                continue
            if required_only and not bool(row.get("must_return_results")):
                continue
            max_results = activity.get("maxResults")
            if isinstance(max_results, int) and not isinstance(max_results, bool) and max_results == 0:
                fallback = row.get("fallback")
                if isinstance(fallback, dict) and bool(fallback.get("recovered")):
                    continue
                zero_result_searches.append(
                    {
                        "wave": row.get("wave"),
                        "ordinal": row.get("ordinal"),
                        "searchId": row.get("searchId"),
                        "method": row.get("method"),
                        "network": row.get("network"),
                        "query_index": row.get("query_index"),
                        "query_label": row.get("query_label"),
                        "terminal": activity.get("terminal"),
                        "maxResults": activity.get("maxResults"),
                        "observation_count": len(activity.get("observations") or []),
                        "last_status": (activity.get("last") or {}).get("status") if isinstance(activity.get("last"), dict) else None,
                        "must_return_results": bool(row.get("must_return_results")),
                    }
                )
    return zero_result_searches


def summarize_zero_result_searches(zero_result_searches: list[dict[str, object]]) -> dict[str, int]:
    """Groups zero-result searches by report-safe query label for release diagnostics."""

    counts: dict[str, int] = {}
    for row in zero_result_searches:
        label = str(row.get("query_label") or "<unknown>")
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def get_search_network_mode(
    *,
    base_url: str,
    api_key: str,
    server_rows: list[dict[str, object]],
    timeout_seconds: float,
) -> dict[str, object]:
    """Returns the best currently available live search transport for one wave."""

    try:
        ready = rest_smoke.wait_for_requested_networks(
            base_url,
            api_key,
            min(timeout_seconds, 10.0),
            require_server_connected=False,
            require_kad_connected=False,
        )
        if bool(ready.get("ready")):
            return {
                "ok": True,
                "mode": ready["mode"],
                "source": "already_ready",
                "ready": ready,
            }
    except Exception as exc:
        last_error = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
    else:
        last_error = None

    try:
        reconnect = rest_smoke.connect_to_live_server(
            base_url,
            api_key=api_key,
            server_rows=server_rows,
            timeout_seconds=timeout_seconds,
        )
        return {
            "ok": True,
            "mode": "server",
            "source": "server_reconnect",
            "reconnect": reconnect,
        }
    except Exception as exc:
        return {
            "ok": False,
            "mode": None,
            "source": "unavailable",
            "last_ready_error": last_error,
            "reconnect_error": {
                "type": type(exc).__name__,
                "message": str(exc),
            },
        }


def run_search_task(
    *,
    base_url: str,
    api_key: str,
    plan_row: dict[str, object],
    observation_timeout_seconds: float,
    downloads_per_search: int,
    trigger_coordinator: DownloadTriggerCoordinator,
    transfer_registry: StressTransferRegistry,
    max_active_downloads: int,
) -> dict[str, object]:
    """Starts one live search, observes it, and optionally triggers active downloads."""

    report: dict[str, object] = {
        "wave": plan_row["wave"],
        "ordinal": plan_row["ordinal"],
        "network": plan_row["network"],
        "method": plan_row["method"],
        "query_index": plan_row["query_index"],
        "query_label": public_search_term_label(plan_row["query"]),
        "must_return_results": search_requires_nonzero_results(plan_row["query"]),
    }
    try:
        started = rest_smoke.start_live_search(
            base_url,
            api_key,
            str(plan_row["network"]),
            str(plan_row["query"]),
            forced_method=str(plan_row["method"]),
        )
        report["start"] = redact_sensitive_search_value(started)
        if not bool(started.get("ok")):
            report["ok"] = False
            report["error"] = "search start failed"
            return report
        response = started.get("response")
        assert isinstance(response, dict)
        payload = rest_smoke.require_json_object(response, 200)
        search_id = str(payload["id"])
        report["searchId"] = search_id
        report["searchIds"] = [search_id]
        activity = wait_for_stress_search_observation(
            base_url,
            api_key,
            search_id,
            observation_timeout_seconds,
        )
        report["activity"] = redact_sensitive_search_value(activity)
        resolved_method = str(payload.get("method") or plan_row["method"])
        trigger_search_id = search_id
        if int(activity.get("maxResults", 0)) == 0 and bool(report["must_return_results"]):
            fallback = run_search_fallbacks(
                base_url=base_url,
                api_key=api_key,
                plan_row=plan_row,
                resolved_method=resolved_method,
                observation_timeout_seconds=observation_timeout_seconds,
            )
            report["fallback"] = fallback
            for attempt in fallback.get("attempts", []):
                if isinstance(attempt, dict) and isinstance(attempt.get("searchId"), str):
                    report["searchIds"].append(str(attempt["searchId"]))
            if bool(fallback.get("recovered")) and isinstance(fallback.get("searchId"), str):
                trigger_search_id = str(fallback["searchId"])
        if downloads_per_search > 0:
            report["download_trigger"] = trigger_active_downloads_from_search_result(
                base_url,
                api_key,
                trigger_search_id,
                observation_timeout_seconds,
                downloads_per_search,
                trigger_coordinator,
                transfer_registry,
                max_active_downloads,
            )
        report["ok"] = True
    except Exception as exc:
        report["ok"] = False
        report["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
    return report


def run_stress_waves(
    *,
    base_url: str,
    api_key: str,
    process_id: int | None,
    server_rows: list[dict[str, object]],
    search_terms: tuple[str, ...],
    waves: int,
    searches_per_wave: int,
    max_concurrent_searches: int,
    downloads_per_search: int,
    max_active_downloads: int,
    download_churn_interval_seconds: float,
    download_remove_count_per_churn: int,
    transfer_registry: StressTransferRegistry,
    observation_timeout_seconds: float,
    network_ready_timeout_seconds: float,
) -> dict[str, object]:
    """Runs phased live search/download stress while keeping searches active until cleanup."""

    wave_reports: list[dict[str, object]] = []
    all_search_ids: list[str] = []
    completed_download_triggers = 0
    transport_checks: list[dict[str, object]] = []
    trigger_coordinator = DownloadTriggerCoordinator()
    churn_reports: list[dict[str, object]] = []
    last_churn_at = time.monotonic()
    for wave_index in range(1, waves + 1):
        transport = get_search_network_mode(
            base_url=base_url,
            api_key=api_key,
            server_rows=server_rows,
            timeout_seconds=network_ready_timeout_seconds,
        )
        transport_checks.append({"wave": wave_index, **transport})
        if not bool(transport.get("ok")):
            wave_reports.append(
                {
                    "wave": wave_index,
                    "planned_searches": searches_per_wave,
                    "completed_searches": 0,
                    "failed_searches": searches_per_wave,
                    "requested_download_triggers": searches_per_wave * downloads_per_search,
                    "completed_download_triggers": 0,
                    "transport": transport,
                    "searches": [],
                }
            )
            continue
        plan = build_wave_search_plan(
            wave_index=wave_index,
            searches_per_wave=searches_per_wave,
            search_terms=search_terms,
            network_mode=str(transport["mode"]),
        )
        wave_rows: list[dict[str, object]] = []
        with ThreadPoolExecutor(max_workers=max_concurrent_searches) as executor:
            futures = [
                executor.submit(
                    run_search_task,
                    base_url=base_url,
                    api_key=api_key,
                    plan_row=row,
                    observation_timeout_seconds=observation_timeout_seconds,
                    downloads_per_search=downloads_per_search,
                    trigger_coordinator=trigger_coordinator,
                    transfer_registry=transfer_registry,
                    max_active_downloads=max_active_downloads,
                )
                for row in plan
            ]
            for future in as_completed(futures):
                row = future.result()
                wave_rows.append(row)
                if isinstance(row.get("searchId"), str):
                    all_search_ids.append(str(row["searchId"]))
                for search_id in row.get("searchIds", []):
                    if isinstance(search_id, str) and search_id not in all_search_ids:
                        all_search_ids.append(search_id)
                completed_download_triggers += count_download_triggers(row)

        ready_probe = rest_smoke.http_request(base_url, "/api/v1/app", api_key=api_key)
        churn_report: dict[str, object] | None = None
        if (
            download_churn_interval_seconds > 0
            and download_remove_count_per_churn > 0
            and time.monotonic() - last_churn_at >= download_churn_interval_seconds
        ):
            churn_report = delete_non_completed_stress_transfers(
                base_url,
                api_key,
                transfer_registry,
                download_remove_count_per_churn,
            )
            churn_report["wave"] = wave_index
            churn_reports.append(churn_report)
            last_churn_at = time.monotonic()
        wave_reports.append(
            {
                "wave": wave_index,
                "planned_searches": len(plan),
                "completed_searches": sum(1 for row in wave_rows if bool(row.get("ok"))),
                "failed_searches": sum(1 for row in wave_rows if not bool(row.get("ok"))),
                "requested_download_triggers": len(plan) * downloads_per_search,
                "completed_download_triggers": sum(count_download_triggers(row) for row in wave_rows),
                "churn": churn_report,
                "rest_ready_probe": rest_smoke.compact_http_result(ready_probe),
                "resource_snapshot": rest_smoke.get_process_resource_snapshot(process_id),
                "transport": transport,
                "searches": sorted(wave_rows, key=lambda row: int(row.get("ordinal", 0))),
            }
        )
        if int(ready_probe["status"]) != 200:
            raise RuntimeError(f"REST readiness probe failed after wave {wave_index}: {ready_probe!r}")

    stress_report = {
        "waves": wave_reports,
        "search_ids": all_search_ids,
        "planned_searches": waves * searches_per_wave,
        "completed_searches": sum(wave["completed_searches"] for wave in wave_reports),
        "failed_searches": sum(wave["failed_searches"] for wave in wave_reports),
        "requested_download_triggers": waves * searches_per_wave * downloads_per_search,
        "completed_download_triggers": completed_download_triggers,
        "transport_checks": transport_checks,
        "churn": churn_reports,
        "transfer_registry": transfer_registry.counts(),
    }
    zero_result_searches = collect_zero_result_searches(stress_report)
    required_zero_result_searches = collect_zero_result_searches(stress_report, required_only=True)
    stress_report["zero_result_searches"] = zero_result_searches
    stress_report["zero_result_search_count"] = len(zero_result_searches)
    stress_report["zero_result_query_counts"] = summarize_zero_result_searches(zero_result_searches)
    stress_report["required_zero_result_searches"] = required_zero_result_searches
    stress_report["required_zero_result_search_count"] = len(required_zero_result_searches)
    stress_report["required_zero_result_query_counts"] = summarize_zero_result_searches(required_zero_result_searches)
    download_trigger_summary = summarize_download_triggers(stress_report)
    stress_report["download_trigger_summary"] = download_trigger_summary
    stress_report["download_file_type_counts"] = download_trigger_summary["file_type_counts"]
    stress_report["download_extension_counts"] = download_trigger_summary["extension_counts"]
    stress_report["video_download_trigger_count"] = download_trigger_summary["video_download_trigger_count"]
    return stress_report


def list_stress_transfer_rows(
    base_url: str,
    api_key: str,
    transfer_hashes: set[str],
) -> list[dict[str, Any]]:
    """Returns currently visible transfer rows for the requested stress hashes."""

    result = rest_smoke.http_request(base_url, "/api/v1/transfers", api_key=api_key)
    rows = rest_smoke.require_json_array(result, 200)
    stress_rows: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        transfer_hash = str(row.get("hash") or "").lower()
        if transfer_hash in transfer_hashes:
            stress_rows.append(row)
    return stress_rows


def delete_non_completed_stress_transfers(
    base_url: str,
    api_key: str,
    transfer_registry: StressTransferRegistry,
    remove_count: int,
) -> dict[str, object]:
    """Deletes a bounded set of non-completed stress transfers for churn."""

    if remove_count <= 0:
        return {"requested_count": 0, "deleted_count": 0, "deletes": []}
    rows = list_stress_transfer_rows(base_url, api_key, transfer_registry.active_hashes())
    candidates = [
        row
        for row in rows
        if str(row.get("state") or "").lower() != "completed" and rest_smoke.is_lowercase_md4_hash(str(row.get("hash") or "").lower())
    ]
    candidates.sort(
        key=lambda row: (
            str(row.get("state") or ""),
            -int(row.get("completedBytes") or 0),
            str(row.get("hash") or ""),
        )
    )
    selected_hashes = [str(row["hash"]).lower() for row in candidates[:remove_count]]
    active_before = transfer_registry.counts()
    result = delete_stress_transfers(base_url, api_key, selected_hashes)
    for row in result.get("deletes", []):
        if not isinstance(row, dict):
            continue
        response = row.get("response")
        if isinstance(response, dict) and int(response.get("status", 0)) in {200, 404}:
            transfer_registry.record_deleted(str(row.get("hash") or ""))
    result["visible_candidate_count"] = len(candidates)
    result["active_before"] = active_before
    result["active_after"] = transfer_registry.counts()
    return result


def wait_for_completed_stress_downloads(
    base_url: str,
    api_key: str,
    transfer_registry: StressTransferRegistry,
    target_completed_downloads: int,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits for the configured number of stress transfers to complete."""

    observations: list[dict[str, object]] = []
    if target_completed_downloads <= 0:
        return {
            "ok": True,
            "target_completed_downloads": target_completed_downloads,
            "completed_count": 0,
            "observations": observations,
            "skipped": True,
        }

    def resolve():
        stress_hashes = set(transfer_registry.hashes())
        rows = list_stress_transfer_rows(base_url, api_key, stress_hashes)
        completed_hashes: list[str] = []
        completed_bytes = 0
        for row in rows:
            transfer_hash = str(row.get("hash") or "").lower()
            if str(row.get("state") or "").lower() == "completed":
                transfer_registry.record_completed(transfer_hash)
                completed_hashes.append(transfer_hash)
            completed_bytes += int(row.get("completedBytes") or 0)
        counts = transfer_registry.counts()
        observation = {
            "observed_at": round(time.time(), 3),
            "target_completed_downloads": target_completed_downloads,
            "visible_stress_transfer_count": len(rows),
            "completed_count": counts["completed_stress_transfer_count"],
            "active_stress_transfer_count": counts["active_stress_transfer_count"],
            "triggered_stress_transfer_count": counts["triggered_stress_transfer_count"],
            "completed_bytes": completed_bytes,
        }
        observations.append(observation)
        if counts["completed_stress_transfer_count"] >= target_completed_downloads:
            return {
                "ok": True,
                "target_completed_downloads": target_completed_downloads,
                "completed_count": counts["completed_stress_transfer_count"],
                "completed_hashes": sorted(set(completed_hashes)),
                "observations": observations,
            }
        return None

    try:
        result = rest_smoke.wait_for(
            resolve,
            timeout=timeout_seconds,
            interval=5.0,
            description="stress download completions",
        )
    except Exception:
        counts = transfer_registry.counts()
        return {
            "ok": False,
            "target_completed_downloads": target_completed_downloads,
            "completed_count": counts["completed_stress_transfer_count"],
            "observations": observations,
        }
    assert isinstance(result, dict)
    return result


def cleanup_searches_and_transfers(
    *,
    base_url: str,
    api_key: str,
    search_ids: list[str],
    transfer_hashes: list[str],
    transfer_cleanup_timeout_seconds: float,
    transfer_registry: StressTransferRegistry | None = None,
) -> dict[str, object]:
    """Deletes active stress searches/transfers and records cleanup state."""

    cleanup: dict[str, object] = {
        "search_ids": search_ids,
        "transfer_hashes": transfer_hashes,
    }
    delete_result = rest_smoke.delete_all_searches(base_url, api_key)
    cleanup["delete_all_searches"] = rest_smoke.compact_http_result(delete_result)
    if int(delete_result["status"]) == 200:
        cleanup["post_delete"] = rest_smoke.verify_searches_deleted(base_url, api_key, search_ids)
    cleanup["delete_stress_transfers"] = delete_stress_transfers(base_url, api_key, transfer_hashes)
    if transfer_registry is not None:
        for row in cleanup["delete_stress_transfers"].get("deletes", []):
            if not isinstance(row, dict):
                continue
            response = row.get("response")
            if isinstance(response, dict) and int(response.get("status", 0)) in {200, 404}:
                transfer_registry.record_deleted(str(row.get("hash") or ""))
    cleanup["post_transfer_delete"] = wait_for_stress_transfers_absent(
        base_url,
        api_key,
        transfer_hashes,
        transfer_cleanup_timeout_seconds,
    )
    clear_result = rest_smoke.clear_completed_transfers(base_url, api_key)
    cleanup["clear_completed_transfers"] = rest_smoke.compact_http_result(clear_result)
    clear_logs_result = rest_smoke.clear_logs(base_url, api_key)
    cleanup["clear_logs"] = rest_smoke.compact_http_result(clear_logs_result)
    return cleanup


def extract_stress_transfer_hashes(stress_report: dict[str, object]) -> list[str]:
    """Extracts unique transfer hashes triggered during the stress run."""

    transfer_hashes: list[str] = []
    seen: set[str] = set()
    waves = stress_report.get("waves")
    if not isinstance(waves, list):
        return transfer_hashes
    for wave in waves:
        if not isinstance(wave, dict):
            continue
        searches = wave.get("searches")
        if not isinstance(searches, list):
            continue
        for search in searches:
            if not isinstance(search, dict):
                continue
            trigger = search.get("download_trigger")
            if not isinstance(trigger, dict):
                continue
            triggers = trigger.get("triggers")
            if not isinstance(triggers, list):
                continue
            for trigger_row in triggers:
                if not isinstance(trigger_row, dict):
                    continue
                transfer = trigger_row.get("transfer")
                if not isinstance(transfer, dict):
                    continue
                transfer_json = transfer.get("json")
                if not isinstance(transfer_json, dict):
                    continue
                transfer_hash = str(transfer_json.get("hash") or "").lower()
                if rest_smoke.is_lowercase_md4_hash(transfer_hash) and transfer_hash not in seen:
                    seen.add(transfer_hash)
                    transfer_hashes.append(transfer_hash)
    return transfer_hashes


def delete_stress_transfers(base_url: str, api_key: str, transfer_hashes: list[str]) -> dict[str, object]:
    """Deletes stress-triggered transfers so post-drain diagnostics measure cleanup recovery."""

    deletes: list[dict[str, object]] = []
    for transfer_hash in transfer_hashes:
        result = rest_smoke.http_request(
            base_url,
            f"/api/v1/transfers/{transfer_hash}",
            method="DELETE",
            api_key=api_key,
            json_body={"deleteFiles": True},
            request_timeout_seconds=30.0,
        )
        deletes.append(
            {
                "hash": transfer_hash,
                "response": rest_smoke.compact_http_result(result),
            }
        )
    return {
        "requested_count": len(transfer_hashes),
        "deleted_count": sum(1 for row in deletes if int(row["response"]["status"]) in {200, 404}),
        "deletes": deletes,
    }


def wait_for_stress_transfers_absent(
    base_url: str,
    api_key: str,
    transfer_hashes: list[str],
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until stress-triggered transfers no longer appear in the REST transfer list."""

    expected = {transfer_hash.lower() for transfer_hash in transfer_hashes if rest_smoke.is_lowercase_md4_hash(transfer_hash)}
    observations: list[dict[str, object]] = []
    if not expected:
        return {
            "absent": True,
            "expected_count": 0,
            "observations": observations,
        }

    def resolve():
        result = rest_smoke.http_request(base_url, "/api/v1/transfers", api_key=api_key)
        rows = rest_smoke.require_json_array(result, 200)
        present = sorted(
            str(row.get("hash") or "").lower()
            for row in rows
            if isinstance(row, dict) and str(row.get("hash") or "").lower() in expected
        )
        observations.append(
            {
                "observed_at": round(time.time(), 3),
                "transfer_count": len(rows),
                "present_count": len(present),
            }
        )
        if not present:
            return {
                "absent": True,
                "expected_count": len(expected),
                "observations": observations,
            }
        return None

    try:
        result = rest_smoke.wait_for(
            resolve,
            timeout=timeout_seconds,
            interval=1.0,
            description="stress transfer deletion",
        )
    except Exception:
        last_present_count = observations[-1]["present_count"] if observations else None
        return {
            "absent": False,
            "expected_count": len(expected),
            "last_present_count": last_present_count,
            "observations": observations,
        }
    assert isinstance(result, dict)
    return result


def stress_cleanup_is_complete(report: dict[str, object]) -> bool:
    """Returns true when stress transfer cleanup completed before post-drain diagnostics."""

    cleanup = report.get("cleanup")
    if not isinstance(cleanup, dict):
        return False
    searches_and_transfers = cleanup.get("searches_and_transfers")
    if not isinstance(searches_and_transfers, dict):
        return False
    delete_stress_transfers = searches_and_transfers.get("delete_stress_transfers")
    post_transfer_delete = searches_and_transfers.get("post_transfer_delete")
    if not isinstance(delete_stress_transfers, dict) or not isinstance(post_transfer_delete, dict):
        return False
    return int(delete_stress_transfers.get("deleted_count", 0)) >= int(delete_stress_transfers.get("requested_count", 0)) and bool(
        post_transfer_delete.get("absent")
    )


def diagnostics_are_complete(report: dict[str, object], *, skip_dumps: bool) -> bool:
    """Returns true when mandatory dump artifacts exist for the completed labels."""

    if skip_dumps:
        return True
    diagnostics = report.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return False
    for label in DIAGNOSTIC_LABELS:
        entry = diagnostics.get(label)
        if not isinstance(entry, dict):
            return False
        tools = entry.get("tools")
        if not isinstance(tools, dict):
            return False
        dump_analysis = tools.get("dump_analysis")
        if not isinstance(dump_analysis, dict):
            return False
        dump = dump_analysis.get("dump")
        if not isinstance(dump, dict) or not bool(dump.get("dump_exists")):
            return False
    return True


def umdh_diagnostics_are_complete(report: dict[str, object]) -> bool:
    """Returns true when UMDH snapshots and mandatory post-drain diff completed."""

    diagnostics = report.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return False
    for label in DIAGNOSTIC_LABELS:
        entry = diagnostics.get(label)
        if not isinstance(entry, dict):
            return False
        tools = entry.get("tools")
        if not isinstance(tools, dict):
            return False
        umdh = tools.get("umdh")
        if not isinstance(umdh, dict) or bool(umdh.get("timed_out")) or not bool(umdh.get("snapshot_exists")):
            return False
    diffs = diagnostics.get("umdh_diffs")
    if not isinstance(diffs, dict):
        return False
    post_drain = diffs.get("baseline_to_post_drain")
    return isinstance(post_drain, dict) and not bool(post_drain.get("timed_out")) and post_drain.get("return_code") == 0


def cpu_profile_diagnostics_are_complete(report: dict[str, object], *, symbols_required: bool) -> bool:
    """Returns true when requested ETW CPU profile artifacts were captured and exported."""

    diagnostics = report.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return False
    profile = diagnostics.get("cpu_profile")
    if not isinstance(profile, dict) or not bool(profile.get("enabled")):
        return True
    symbols = profile.get("symbols")
    if symbols_required and (not isinstance(symbols, dict) or not bool(symbols.get("app_pdb_exists"))):
        return False
    stop = profile.get("stop")
    if not isinstance(stop, dict) or bool(stop.get("timed_out")) or stop.get("return_code") != 0 or not bool(stop.get("etl_exists")):
        return False
    export = profile.get("export")
    if not isinstance(export, dict) or bool(export.get("timed_out")) or export.get("return_code") != 0 or not bool(export.get("detail_exists")):
        return False
    return True


def post_drain_umdh_delta_within_budget(report: dict[str, object], max_positive_bytes: int) -> bool:
    """Returns true when post-drain UMDH growth stays within the configured leak budget."""

    diagnostics = report.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return False
    umdh_summary = diagnostics.get("umdh_summary")
    if not isinstance(umdh_summary, dict):
        return False
    post_drain = umdh_summary.get("baseline_to_post_drain")
    if not isinstance(post_drain, dict) or not bool(post_drain.get("available")):
        return False
    return int(post_drain.get("positive_delta_bytes", 0)) <= max_positive_bytes


def diagnostic_tool_crashes(report: dict[str, object]) -> list[dict[str, object]]:
    """Returns diagnostic tool invocations that crashed with access violations."""

    diagnostics = report.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return []
    crashes: list[dict[str, object]] = []
    for label, diagnostic in diagnostics.items():
        if not isinstance(diagnostic, dict):
            continue
        tools = diagnostic.get("tools")
        if not isinstance(tools, dict):
            continue
        for tool_name, tool_result in tools.items():
            if not isinstance(tool_result, dict):
                continue
            return_code = tool_result.get("return_code")
            if return_code is None and tool_name == "dump_analysis":
                dump_result = tool_result.get("dump")
                if isinstance(dump_result, dict):
                    return_code = dump_result.get("return_code")
            try:
                crashed = int(return_code) == ACCESS_VIOLATION_EXIT_CODE
            except (TypeError, ValueError):
                crashed = False
            if crashed:
                crashes.append(
                    {
                        "label": label,
                        "tool": tool_name,
                        "return_code": int(return_code),
                    }
                )
    return crashes


def access_violation_without_emule_dump(report: dict[str, object]) -> bool:
    """Returns true when eMule crashed with AV but no WER LocalDump was captured."""

    if not harness_cli_common.process_exited_with_access_violation(report.get("failure_process_state")):
        return False
    return not harness_cli_common.local_dump_files_for_image(report.get("local_dump_files"), "emule.exe")


def main(argv: list[str] | None = None) -> int:
    """Runs the cold-start dump stress suite and returns a process exit code."""

    args = build_parser().parse_args(argv)
    validate_args(args)
    inputs = live_wire_inputs.load_live_wire_inputs(
        live_wire_inputs.resolve_inputs_path(REPO_ROOT, args.live_wire_inputs_file)
    )
    search_terms = build_open_source_stress_terms(inputs.generic_open_terms)
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts or args.keep_running,
    )
    artifacts_dir = paths.source_artifacts_dir
    diagnostics_dir = artifacts_dir
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    port = rest_smoke.choose_listen_port()
    base_url = f"http://127.0.0.1:{port}"
    tools = discover_diagnostic_tools()
    symbol_env = build_symbol_environment(paths.app_exe, artifacts_dir)
    downloads_per_search = resolve_downloads_per_search(args)
    transfer_registry = StressTransferRegistry()
    resource_monitor: ProcessResourceMonitor | None = None
    cpu_profile_tools: cpu_profile.CpuProfileTools | None = None
    cpu_profile_paths: cpu_profile.CpuProfilePaths | None = None
    cpu_profile_active = False
    report: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "suite": SUITE_NAME,
        "status": "failed",
        "base_url": base_url,
        "app_exe": str(paths.app_exe),
        "configuration": args.configuration,
        "artifact_dir": str(paths.run_report_dir),
        "latest_report_dir": str(paths.latest_report_dir),
        "source_artifact_dir": str(paths.source_artifacts_dir),
        "local_dumps": paths.local_dumps,
        "live_seed_source_url": EMULE_SECURITY_HOME_URL,
        "live_wire_inputs_file": str(inputs.path),
        "live_wire_search_terms": live_wire_inputs.summarize_terms(search_terms),
        "diagnostic_tools": tools,
        "settings": {
            "waves": args.waves,
            "searches_per_wave": args.searches_per_wave,
            "max_concurrent_searches": args.max_concurrent_searches,
            "downloads_per_wave": args.downloads_per_wave,
            "downloads_per_search": downloads_per_search,
            "max_missing_download_triggers": args.max_missing_download_triggers,
            "target_completed_downloads": args.target_completed_downloads,
            "completion_timeout_seconds": args.completion_timeout_seconds,
            "max_active_downloads": args.max_active_downloads,
            "download_churn_interval_seconds": args.download_churn_interval_seconds,
            "download_remove_count_per_churn": args.download_remove_count_per_churn,
            "resource_monitor_interval_seconds": args.resource_monitor_interval_seconds,
            "post_drain_seconds": args.post_drain_seconds,
            "tool_timeout_seconds": args.tool_timeout_seconds,
            "enable_umdh": bool(args.enable_umdh),
            "max_post_drain_umdh_positive_bytes": args.max_post_drain_umdh_positive_bytes,
            "cpu_profile": bool(args.cpu_profile),
            "cpu_profile_max_file_mb": args.cpu_profile_max_file_mb,
            "cpu_profile_symbols_required": bool(args.cpu_profile_symbols_required),
            "skip_dumps": bool(args.skip_dumps),
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
        },
        "checks": {},
        "diagnostics": {},
        "cleanup": {},
    }
    app = None
    process_id: int | None = None
    gflags_enabled = False

    try:
        if args.cpu_profile:
            cpu_profile_tools, cpu_profile_paths, profile_report = initialize_cpu_profile_report(
                app_exe=paths.app_exe,
                artifacts_dir=artifacts_dir,
            )
            report["diagnostics"]["cpu_profile"] = profile_report
            if not cpu_profile_tools.xperf:
                raise RuntimeError("CPU profiling was requested but xperf was not found.")
            symbols = profile_report["symbols"]
            if args.cpu_profile_symbols_required and not bool(symbols.get("app_pdb_exists")):
                raise RuntimeError(f"CPU profiling requires app symbols, but '{symbols.get('app_pdb_path')}' was not found.")

        if args.enable_umdh:
            if not tools.get("gflags") or not tools.get("umdh"):
                raise RuntimeError("UMDH was requested but gflags or umdh was not found.")
            report["checks"]["gflags_enable_ust"] = set_umdh_stack_tracing(
                str(tools["gflags"]),
                paths.app_exe,
                True,
                diagnostics_dir / "analysis" / "gflags-enable-ust.txt",
                args.tool_timeout_seconds,
            )
            gflags_enabled = True

        profile = rest_smoke.prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[])
        seed_refresh = None
        if not args.skip_live_seed_refresh:
            seed_refresh = refresh_seed_files(
                Path(profile["config_dir"]),
                timeout_seconds=args.seed_download_timeout_seconds,
            )
        report["launch_inputs"] = {
            "seed_config_dir": str(seed_config_dir),
            "live_seed_refresh": seed_refresh,
            "profile_base": str(profile["profile_base"]),
            "config_dir": str(profile["config_dir"]),
            "api_key_length": len(args.api_key),
            "bind_addr": args.bind_addr,
            "enable_upnp": True,
        }
        rest_smoke.configure_webserver_profile(
            Path(profile["config_dir"]),
            paths.app_exe,
            args.api_key,
            port,
            args.bind_addr,
        )
        if args.p2p_bind_interface_name:
            rest_smoke.apply_p2p_bind_interface_override(Path(profile["config_dir"]), args.p2p_bind_interface_name)

        app = rest_smoke.launch_app(paths.app_exe, Path(profile["profile_base"]))
        process_id = rest_smoke.get_app_process_id(app)
        report["launched_process_id"] = process_id
        main_window = rest_smoke.wait_for_main_window(app)
        report["main_window_title"] = main_window.window_text()
        ready = rest_smoke.wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        report["checks"]["ready"] = rest_smoke.compact_http_result(ready)

        report["diagnostics"]["baseline"] = collect_diagnostics(
            label="baseline",
            process_id=process_id,
            tools=tools,
            diagnostics_dir=diagnostics_dir,
            timeout_seconds=args.tool_timeout_seconds,
            skip_dumps=args.skip_dumps,
            enable_umdh=args.enable_umdh,
            symbol_env=symbol_env,
        )

        servers = rest_smoke.http_request(base_url, "/api/v1/servers", api_key=args.api_key)
        server_rows = rest_smoke.require_json_array(servers, 200)
        report["checks"]["servers_list"] = {
            "count": len(server_rows),
        }
        try:
            report["checks"]["servers_connect"] = rest_smoke.connect_to_live_server(
                base_url,
                api_key=args.api_key,
                server_rows=server_rows,
                timeout_seconds=args.network_ready_timeout_seconds,
            )
        except rest_smoke.LiveNetworkUnavailableError as exc:
            report["checks"]["servers_connect"] = {
                "ok": False,
                "reason": str(exc),
            }

        kad_connect = rest_smoke.http_request(
            base_url,
            "/api/v1/kad/operations/start",
            method="POST",
            api_key=args.api_key,
            json_body={},
        )
        report["checks"]["kad_connect"] = rest_smoke.compact_http_result(kad_connect)
        if int(kad_connect["status"]) == 200:
            try:
                report["checks"]["kad_running"] = rest_smoke.wait_for_kad_running(
                    base_url,
                    args.api_key,
                    args.kad_running_timeout_seconds,
                )
            except Exception as exc:
                report["checks"]["kad_running"] = {
                    "ok": False,
                    "error": {
                        "type": type(exc).__name__,
                        "message": str(exc),
                    },
                }

        live_network = rest_smoke.wait_for_requested_networks(
            base_url,
            args.api_key,
            args.network_ready_timeout_seconds,
            require_server_connected=False,
            require_kad_connected=False,
        )
        report["checks"]["network_ready"] = live_network

        if args.cpu_profile:
            assert cpu_profile_tools is not None
            assert cpu_profile_paths is not None
            profile_report = report["diagnostics"]["cpu_profile"]
            assert isinstance(profile_report, dict)
            profile_report["start"] = cpu_profile.start_cpu_profile(
                tools=cpu_profile_tools,
                paths=cpu_profile_paths,
                max_file_mb=args.cpu_profile_max_file_mb,
                timeout_seconds=args.tool_timeout_seconds,
            )
            if profile_report["start"].get("return_code") != 0:
                raise RuntimeError("CPU profile ETW start failed.")
            cpu_profile_active = True

        resource_monitor = ProcessResourceMonitor(
            process_id=process_id,
            interval_seconds=args.resource_monitor_interval_seconds,
            counts_provider=transfer_registry.counts,
        )
        resource_monitor.start()
        stress = run_stress_waves(
            base_url=base_url,
            api_key=args.api_key,
            process_id=process_id,
            server_rows=server_rows,
            search_terms=search_terms,
            waves=args.waves,
            searches_per_wave=args.searches_per_wave,
            max_concurrent_searches=args.max_concurrent_searches,
            downloads_per_search=downloads_per_search,
            max_active_downloads=args.max_active_downloads,
            download_churn_interval_seconds=args.download_churn_interval_seconds,
            download_remove_count_per_churn=args.download_remove_count_per_churn,
            transfer_registry=transfer_registry,
            observation_timeout_seconds=args.search_observation_timeout_seconds,
            network_ready_timeout_seconds=args.network_ready_timeout_seconds,
        )
        report["checks"]["stress"] = stress
        report["checks"]["download_completion"] = wait_for_completed_stress_downloads(
            base_url,
            args.api_key,
            transfer_registry,
            args.target_completed_downloads,
            args.completion_timeout_seconds,
        )
        if cpu_profile_active:
            assert cpu_profile_tools is not None
            assert cpu_profile_paths is not None
            profile_report = report["diagnostics"]["cpu_profile"]
            assert isinstance(profile_report, dict)
            profile_report["stop"] = cpu_profile.stop_cpu_profile(
                tools=cpu_profile_tools,
                paths=cpu_profile_paths,
                timeout_seconds=args.tool_timeout_seconds,
            )
            cpu_profile_active = False
            profile_report.update(
                export_cpu_profile_summary(
                    tools=cpu_profile_tools,
                    paths=cpu_profile_paths,
                    app_exe=paths.app_exe,
                    timeout_seconds=args.tool_timeout_seconds,
                )
            )
        report["diagnostics"]["peak"] = collect_diagnostics(
            label="peak",
            process_id=process_id,
            tools=tools,
            diagnostics_dir=diagnostics_dir,
            timeout_seconds=args.tool_timeout_seconds,
            skip_dumps=args.skip_dumps,
            enable_umdh=args.enable_umdh,
            symbol_env=symbol_env,
        )

        report["cleanup"]["searches_and_transfers"] = cleanup_searches_and_transfers(
            base_url=base_url,
            api_key=args.api_key,
            search_ids=[str(search_id) for search_id in stress["search_ids"]],
            transfer_hashes=transfer_registry.hashes(),
            transfer_cleanup_timeout_seconds=max(30.0, args.post_drain_seconds),
            transfer_registry=transfer_registry,
        )
        if args.post_drain_seconds:
            time.sleep(args.post_drain_seconds)
        report["diagnostics"]["post_drain"] = collect_diagnostics(
            label="post_drain",
            process_id=process_id,
            tools=tools,
            diagnostics_dir=diagnostics_dir,
            timeout_seconds=args.tool_timeout_seconds,
            skip_dumps=args.skip_dumps,
            enable_umdh=args.enable_umdh,
            symbol_env=symbol_env,
        )
        report["diagnostics"]["resource_deltas"] = summarize_resource_deltas(report["diagnostics"])
        report["diagnostics"]["cdb_deltas"] = summarize_cdb_deltas(report["diagnostics"])
        if resource_monitor is not None:
            report["diagnostics"]["resource_monitor"] = resource_monitor.stop()
            resource_monitor = None

        if args.enable_umdh:
            report["diagnostics"]["umdh_diffs"] = {
                "baseline_to_peak": diff_umdh_snapshots(
                    before=diagnostics_dir / "analysis" / "umdh-baseline.txt",
                    after=diagnostics_dir / "analysis" / "umdh-peak.txt",
                    diff_name="baseline-to-peak",
                    tools=tools,
                    diagnostics_dir=diagnostics_dir,
                    timeout_seconds=args.tool_timeout_seconds,
                    symbol_env=symbol_env,
                ),
                "baseline_to_post_drain": diff_umdh_snapshots(
                    before=diagnostics_dir / "analysis" / "umdh-baseline.txt",
                    after=diagnostics_dir / "analysis" / "umdh-post_drain.txt",
                    diff_name="baseline-to-post_drain",
                    tools=tools,
                    diagnostics_dir=diagnostics_dir,
                    timeout_seconds=args.tool_timeout_seconds,
                    symbol_env=symbol_env,
                ),
            }
            report["diagnostics"]["umdh_summary"] = summarize_umdh_diffs(report["diagnostics"])

        stress_summary = report["checks"]["stress"]
        assert isinstance(stress_summary, dict)
        if int(stress_summary.get("failed_searches", 0)) > 0:
            report["status"] = "failed"
            report["failure_reason"] = "one or more live searches failed"
        elif int(stress_summary.get("required_zero_result_search_count", 0)) > 0:
            report["status"] = "failed"
            report["failure_reason"] = "one or more required live searches returned zero results"
        elif diagnostic_tool_crashes(report):
            report["status"] = "failed"
            report["failure_reason"] = "one or more diagnostic tools crashed"
        elif not diagnostics_are_complete(report, skip_dumps=args.skip_dumps):
            report["status"] = "failed"
            report["failure_reason"] = "required dump diagnostics were not captured"
        elif not stress_cleanup_is_complete(report):
            report["status"] = "failed"
            report["failure_reason"] = "stress transfer cleanup did not settle before post-drain diagnostics"
        elif int(stress_summary.get("video_download_trigger_count", 0)) > 0:
            report["status"] = "failed"
            report["failure_reason"] = "video downloads were triggered during dump stress"
        elif not bool(report["checks"]["download_completion"].get("ok")):
            report["status"] = "failed"
            report["failure_reason"] = (
                "target completed downloads were not reached: "
                f"{report['checks']['download_completion'].get('completed_count')} < {args.target_completed_downloads}"
            )
        elif args.enable_umdh and not umdh_diagnostics_are_complete(report):
            report["status"] = "failed"
            report["failure_reason"] = "required UMDH diagnostics did not complete"
        elif args.enable_umdh and not post_drain_umdh_delta_within_budget(report, args.max_post_drain_umdh_positive_bytes):
            post_drain = report["diagnostics"]["umdh_summary"]["baseline_to_post_drain"]
            report["status"] = "failed"
            report["failure_reason"] = (
                "post-drain UMDH positive delta exceeded budget: "
                f"{int(post_drain.get('positive_delta_bytes', 0))} > {args.max_post_drain_umdh_positive_bytes}"
            )
        elif args.cpu_profile and not cpu_profile_diagnostics_are_complete(report, symbols_required=args.cpu_profile_symbols_required):
            report["status"] = "failed"
            report["failure_reason"] = "required CPU profile diagnostics did not complete"
        elif (
            int(stress_summary.get("requested_download_triggers", 0)) - int(stress_summary.get("completed_download_triggers", 0))
        ) > args.max_missing_download_triggers:
            report["status"] = "inconclusive"
            report["failure_reason"] = (
                "live network did not expose enough safe active-download candidates: "
                f"{int(stress_summary.get('completed_download_triggers', 0))}/"
                f"{int(stress_summary.get('requested_download_triggers', 0))} triggers completed"
            )
        else:
            report["status"] = "passed"
    except rest_smoke.LiveNetworkUnavailableError as exc:
        report["status"] = "inconclusive"
        report["failure_reason"] = str(exc)
    except Exception as exc:
        report["status"] = "failed"
        report["failure_reason"] = f"{type(exc).__name__}: {exc}"
        if process_id is not None:
            report["failure_process_state"] = rest_smoke.get_process_exit_state(process_id)
        if process_id is not None and "failure" not in report["diagnostics"]:
            report["diagnostics"]["failure"] = collect_diagnostics(
                label="failure",
                process_id=process_id,
                tools=tools,
                diagnostics_dir=diagnostics_dir,
                timeout_seconds=args.tool_timeout_seconds,
                skip_dumps=args.skip_dumps,
                enable_umdh=args.enable_umdh,
                symbol_env=symbol_env,
            )
    finally:
        if cpu_profile_active and cpu_profile_tools is not None and cpu_profile_paths is not None:
            profile_report = report["diagnostics"].setdefault("cpu_profile", {"enabled": True})
            assert isinstance(profile_report, dict)
            try:
                profile_report["stop"] = cpu_profile.stop_cpu_profile(
                    tools=cpu_profile_tools,
                    paths=cpu_profile_paths,
                    timeout_seconds=args.tool_timeout_seconds,
                )
                profile_report.update(
                    export_cpu_profile_summary(
                        tools=cpu_profile_tools,
                        paths=cpu_profile_paths,
                        app_exe=paths.app_exe,
                        timeout_seconds=args.tool_timeout_seconds,
                    )
                )
            except Exception as exc:
                profile_report["stop_error"] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
        if resource_monitor is not None:
            try:
                report["diagnostics"]["resource_monitor"] = resource_monitor.stop()
            except Exception as exc:
                report["diagnostics"]["resource_monitor_error"] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
        if app is not None and not args.keep_running:
            try:
                report["cleanup"]["app_shutdown"] = rest_smoke.close_app_cleanly(app)
            except Exception as exc:
                report["cleanup"]["app_shutdown_error"] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
                if report.get("status") == "passed":
                    report["status"] = "failed"
        if gflags_enabled and tools.get("gflags"):
            try:
                report["checks"]["gflags_disable_ust"] = set_umdh_stack_tracing(
                    str(tools["gflags"]),
                    paths.app_exe,
                    False,
                    diagnostics_dir / "analysis" / "gflags-disable-ust.txt",
                    args.tool_timeout_seconds,
                )
            except Exception as exc:
                report["checks"]["gflags_disable_ust_error"] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
        report["local_dump_files"] = harness_cli_common.collect_local_dump_files(paths.local_dumps)
        if access_violation_without_emule_dump(report):
            report["status"] = "failed"
            report["failure_reason"] = "eMule exited with access violation but no WER LocalDump was captured"
        crashes = diagnostic_tool_crashes(report)
        if crashes:
            report["diagnostic_tool_crashes"] = crashes
            report["status"] = "failed"
            report["failure_reason"] = "one or more diagnostic tools crashed"
        harness_cli_common.write_json_file(artifacts_dir / "result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)

    if report["status"] == "passed":
        return 0
    if report["status"] == "inconclusive":
        return SUITE_INCONCLUSIVE_RETURN_CODE
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
