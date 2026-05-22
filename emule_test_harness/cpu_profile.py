"""ETW CPU stack attribution helpers for live eMule diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from html import unescape
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

DEFAULT_CPU_PROFILE_MAX_FILE_MB = 512
DEFAULT_CPU_PROFILE_INTERVAL_100NS = 80_000
DEFAULT_CPU_PROFILE_TOP_LIMIT = 25
CPU_PROFILE_KERNEL_FLAGS = "PROC_THREAD+LOADER+PROFILE"
CPU_PROFILE_STACKWALK_FLAGS = "Profile"
XPERF_ERROR_ALREADY_EXISTS = 2147942583
EMULE_SYMBOL_PREFIXES = ("emulebb!", "emulebb.exe!", "emule!", "emule.exe!")
EMULE_SYMBOL_PREFIX = EMULE_SYMBOL_PREFIXES[0]

_PERCENT_RE = re.compile(r"(?P<value>[0-9]+(?:\.[0-9]+)?)\s*%")
_XPERF_CSV_ROW_RE = re.compile(
    r"^\s*(?P<process>[^,]+),\s*(?P<count>[0-9][0-9,]*),\s*(?P<weight>[0-9]+(?:\.[0-9]+)?),\s*(?P<function>.+?)\s*$"
)
_SAMPLE_COUNT_RE = re.compile(r"(?<![A-Za-z0-9_.])([0-9][0-9,]*)(?![A-Za-z0-9_.])")
_SYMBOL_RE = re.compile(r"\bemulebb(?:\.exe)?![^\s,;|]+|\bemule(?:\.exe)?![^\s,;|]+", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_STACK_ROW_RE = re.compile(
    r"<tr><td>(?P<function>.*?)</td><td>(?P<hits>[0-9][0-9,]*)</td><td>(?P<percent>[0-9]+(?:\.[0-9]+)?)%</td><td>(?P<exclusive>[0-9][0-9,]*)</td>",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CpuProfileTools:
    """Resolved Windows Performance Toolkit tools used for CPU profiling."""

    xperf: str | None
    wpaexporter: str | None = None


@dataclass(frozen=True)
class CpuProfilePaths:
    """Filesystem paths for one ETW CPU profile capture."""

    etl_path: Path
    raw_etl_path: Path
    detail_path: Path
    summary_path: Path
    stack_path: Path
    symbol_cache_dir: Path


def discover_cpu_profile_tools() -> CpuProfileTools:
    """Finds Windows Performance Toolkit commands needed for CPU profile capture."""

    return CpuProfileTools(
        xperf=find_tool("xperf.exe", "xperf"),
        wpaexporter=find_tool("wpaexporter.exe", "wpaexporter"),
    )


def find_tool(*names: str) -> str | None:
    """Resolves the first command available on PATH."""

    for name in names:
        resolved = shutil.which(name)
        if resolved:
            return resolved
    return None


def build_cpu_profile_paths(artifacts_dir: Path) -> CpuProfilePaths:
    """Returns the conventional artifact paths for one CPU profile run."""

    analysis_dir = artifacts_dir / "analysis"
    return CpuProfilePaths(
        etl_path=analysis_dir / "cpu-profile.etl",
        raw_etl_path=analysis_dir / "cpu-profile.raw.etl",
        detail_path=analysis_dir / "cpu-profile-detail.txt",
        summary_path=analysis_dir / "cpu-profile-summary.json",
        stack_path=analysis_dir / "cpu-profile-stack.html",
        symbol_cache_dir=artifacts_dir / "symbols",
    )


def resolve_app_pdb_path(app_exe: Path) -> Path:
    """Returns the expected app-local PDB path for an eMule executable."""

    return app_exe.with_suffix(".pdb")


def build_symbol_environment(
    app_exe: Path,
    symbol_cache_dir: Path,
    base_env: dict[str, str] | None = None,
    *,
    include_microsoft_symbols: bool = False,
) -> dict[str, str]:
    """Builds an environment that resolves app symbols without slow public symbol downloads."""

    env = dict(base_env or os.environ)
    symbol_cache_dir.mkdir(parents=True, exist_ok=True)
    app_symbol_dir = app_exe.parent
    symbol_paths = [str(app_symbol_dir)]
    if include_microsoft_symbols:
        symbol_paths.append(f"srv*{symbol_cache_dir}*https://msdl.microsoft.com/download/symbols")
    env["_NT_SYMBOL_PATH"] = ";".join(symbol_paths)
    env["_NT_SYMCACHE_PATH"] = str(symbol_cache_dir)
    return env


def build_xperf_start_command(
    tools: CpuProfileTools,
    paths: CpuProfilePaths,
    *,
    max_file_mb: int = DEFAULT_CPU_PROFILE_MAX_FILE_MB,
    profile_interval_100ns: int = DEFAULT_CPU_PROFILE_INTERVAL_100NS,
) -> list[str]:
    """Builds the xperf command that starts bounded sampled CPU capture."""

    if not tools.xperf:
        raise ValueError("xperf was not found.")
    return [
        tools.xperf,
        "-on",
        CPU_PROFILE_KERNEL_FLAGS,
        "-stackwalk",
        CPU_PROFILE_STACKWALK_FLAGS,
        "-SetProfInt",
        str(profile_interval_100ns),
        "-BufferSize",
        "1024",
        "-MinBuffers",
        "64",
        "-MaxBuffers",
        "256",
        "-MaxFile",
        str(max_file_mb),
        "-FileMode",
        "Circular",
        "-f",
        str(paths.raw_etl_path),
    ]


def build_xperf_stop_command(tools: CpuProfileTools, paths: CpuProfilePaths) -> list[str]:
    """Builds the xperf command that stops and merges the active kernel capture."""

    if not tools.xperf:
        raise ValueError("xperf was not found.")
    return [tools.xperf, "-d", str(paths.etl_path)]


def build_xperf_cancel_command(tools: CpuProfileTools) -> list[str]:
    """Builds the xperf command that stops a stale kernel capture without merging it."""

    if not tools.xperf:
        raise ValueError("xperf was not found.")
    return [tools.xperf, "-stop"]


def build_xperf_profile_export_command(tools: CpuProfileTools, paths: CpuProfilePaths) -> list[str]:
    """Builds the xperf command that exports symbolized sampled CPU detail."""

    if not tools.xperf:
        raise ValueError("xperf was not found.")
    return [
        tools.xperf,
        "-i",
        str(paths.etl_path),
        "-symbols",
        "-target",
        "human",
        "-o",
        str(paths.detail_path),
        "-a",
        "profile",
        "-detail",
    ]


def build_xperf_stack_export_command(
    tools: CpuProfileTools,
    paths: CpuProfilePaths,
    *,
    process_image: str = "emulebb.exe",
    min_hits: int = 10,
) -> list[str]:
    """Builds the xperf command that exports a caller/callee stack report."""

    if not tools.xperf:
        raise ValueError("xperf was not found.")
    return [
        tools.xperf,
        "-i",
        str(paths.etl_path),
        "-symbols",
        "-target",
        "human",
        "-o",
        str(paths.stack_path),
        "-a",
        "stack",
        "-process",
        process_image,
        "-event",
        "Profile",
        "-butterfly",
        str(min_hits),
    ]


def run_tool_to_file(
    command: list[str],
    output_path: Path,
    timeout_seconds: float,
    *,
    env: dict[str, str] | None = None,
) -> dict[str, object]:
    """Runs one profiling tool command and records stdout/stderr metadata."""

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
                    "timed_out: true",
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


def start_cpu_profile(
    *,
    tools: CpuProfileTools,
    paths: CpuProfilePaths,
    max_file_mb: int,
    timeout_seconds: float,
) -> dict[str, object]:
    """Starts ETW sampled CPU capture and returns command metadata."""

    paths.raw_etl_path.parent.mkdir(parents=True, exist_ok=True)
    command = build_xperf_start_command(tools, paths, max_file_mb=max_file_mb)
    result = run_tool_to_file(command, paths.raw_etl_path.with_suffix(".start.txt"), timeout_seconds)
    if result.get("return_code") != XPERF_ERROR_ALREADY_EXISTS:
        return result

    stale_stop = run_tool_to_file(
        build_xperf_cancel_command(tools),
        paths.raw_etl_path.with_suffix(".stale-stop.txt"),
        timeout_seconds,
    )
    retry = run_tool_to_file(command, paths.raw_etl_path.with_suffix(".start-retry.txt"), timeout_seconds)
    retry["stale_stop"] = stale_stop
    retry["retried_after_existing_logger"] = True
    return retry


def stop_cpu_profile(
    *,
    tools: CpuProfileTools,
    paths: CpuProfilePaths,
    timeout_seconds: float,
) -> dict[str, object]:
    """Stops ETW sampled CPU capture and merges the trace."""

    command = build_xperf_stop_command(tools, paths)
    result = run_tool_to_file(command, paths.etl_path.with_suffix(".stop.txt"), timeout_seconds)
    result["etl_path"] = str(paths.etl_path)
    result["etl_exists"] = paths.etl_path.is_file()
    return result


def export_cpu_profile(
    *,
    tools: CpuProfileTools,
    paths: CpuProfilePaths,
    app_exe: Path,
    timeout_seconds: float,
    include_stack: bool = False,
    stack_min_hits: int = 10,
) -> dict[str, object]:
    """Exports xperf sampled CPU detail with the required app symbols."""

    symbol_env = build_symbol_environment(app_exe, paths.symbol_cache_dir)
    command = build_xperf_profile_export_command(tools, paths)
    result = run_tool_to_file(command, paths.detail_path.with_suffix(".export.txt"), timeout_seconds, env=symbol_env)
    result["detail_path"] = str(paths.detail_path)
    result["detail_exists"] = paths.detail_path.is_file()
    result["symbol_path"] = symbol_env["_NT_SYMBOL_PATH"]
    result["symcache_path"] = symbol_env["_NT_SYMCACHE_PATH"]
    if include_stack:
        stack_command = build_xperf_stack_export_command(tools, paths, min_hits=stack_min_hits)
        stack_result = run_tool_to_file(stack_command, paths.stack_path.with_suffix(".export.txt"), timeout_seconds, env=symbol_env)
        stack_result["stack_path"] = str(paths.stack_path)
        stack_result["stack_exists"] = paths.stack_path.is_file()
        result["stack"] = stack_result
    return result


def parse_xperf_profile_detail(
    text: str,
    *,
    process_image: str = "emulebb.exe",
    symbol_prefix: str = EMULE_SYMBOL_PREFIX,
    limit: int = DEFAULT_CPU_PROFILE_TOP_LIMIT,
) -> dict[str, object]:
    """Extracts top eMule CPU attribution rows from xperf profile detail text."""

    rows: list[dict[str, object]] = []
    image_token = process_image.casefold()
    symbol_token = symbol_prefix.casefold()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        folded = line.casefold()
        if not line or (image_token not in folded and symbol_token not in folded and not any(prefix in folded for prefix in EMULE_SYMBOL_PREFIXES)):
            continue
        percent_match = _PERCENT_RE.search(line)
        csv_match = _XPERF_CSV_ROW_RE.match(line)
        symbol_text = None
        if csv_match:
            csv_function = csv_match.group("function").strip()
            if csv_function.casefold().startswith(EMULE_SYMBOL_PREFIXES):
                symbol_text = csv_function
        if symbol_text is None:
            symbol_match = _SYMBOL_RE.search(line)
            symbol_text = symbol_match.group(0) if symbol_match else None
        function = normalize_emule_symbol(symbol_text) if symbol_text else "<unresolved>"
        if percent_match:
            weight = float(percent_match.group("value"))
            sample_count = parse_sample_count(line, percent_match.start())
        elif csv_match:
            weight = float(csv_match.group("weight"))
            sample_count = int(csv_match.group("count").replace(",", ""))
        else:
            weight = None
            sample_count = parse_sample_count(line, None)
        rows.append(
            {
                "function": function,
                "sample_count": sample_count,
                "weight_percent": weight,
                "raw": line,
            }
        )

    rows.sort(
        key=lambda row: (
            float(row["weight_percent"]) if isinstance(row.get("weight_percent"), (float, int)) else -1.0,
            int(row["sample_count"]) if isinstance(row.get("sample_count"), int) else -1,
        ),
        reverse=True,
    )
    top_rows = rows[:limit]
    app_rows = [row for row in rows if isinstance(row.get("function"), str) and str(row["function"]).casefold().startswith(EMULE_SYMBOL_PREFIX)]
    return {
        "available": bool(top_rows),
        "app_row_count": len(app_rows),
        "process_image": process_image,
        "row_count": len(rows),
        "top": top_rows,
        "top_app_functions": app_rows[:limit],
        "unresolved_row_count": sum(1 for row in rows if row["function"] == "<unresolved>"),
    }


def normalize_emule_symbol(symbol: str) -> str:
    """Normalizes xperf's app module spellings to the current emulebb! prefix."""

    if symbol.casefold().startswith("emulebb.exe!"):
        return f"emulebb!{symbol[len('emulebb.exe!'):]}"
    if symbol.casefold().startswith("emule.exe!"):
        return f"emulebb!{symbol[len('emule.exe!'):]}"
    if symbol.casefold().startswith("emule!"):
        return f"emulebb!{symbol[len('emule!'):]}"
    return symbol


def parse_sample_count(line: str, percent_start: int | None) -> int | None:
    """Returns the nearest integer sample count before the percentage column."""

    prefix = line[:percent_start] if percent_start is not None else line
    matches = list(_SAMPLE_COUNT_RE.finditer(prefix))
    if not matches:
        return None
    return int(matches[-1].group(1).replace(",", ""))


def parse_xperf_profile_detail_file(path: Path, *, limit: int = DEFAULT_CPU_PROFILE_TOP_LIMIT) -> dict[str, object]:
    """Reads an exported xperf profile report and returns a compact summary."""

    if not path.is_file():
        return {"available": False, "reason": "xperf profile detail output was not written"}
    try:
        return parse_xperf_profile_detail(path.read_text(encoding="utf-8", errors="replace"), limit=limit)
    except OSError as exc:
        return {
            "available": False,
            "reason": f"{type(exc).__name__}: {exc}",
        }


def parse_xperf_stack_report(
    text: str,
    *,
    limit: int = DEFAULT_CPU_PROFILE_TOP_LIMIT,
) -> dict[str, object]:
    """Extracts top app functions from xperf's stack butterfly HTML report."""

    start = text.find("id='TblSI'")
    if start < 0:
        start = text.find('id="TblSI"')
    if start < 0:
        start = text.find("Functions by UniInclusive Hits")
    end = text.find("id='TblSN'", start)
    if end < 0:
        end = text.find('id="TblSN"', start)
    if end < 0:
        end = text.find("Functions by Multi-Inclusive Hits", start)
    section = text[start:end] if start >= 0 and end > start else text
    rows: list[dict[str, object]] = []
    for match in _STACK_ROW_RE.finditer(section):
        function = strip_html_cell(match.group("function"))
        folded = function.casefold()
        if not folded.startswith(EMULE_SYMBOL_PREFIXES):
            continue
        rows.append(
            {
                "function": normalize_emule_symbol(function),
                "inclusive_hits": int(match.group("hits").replace(",", "")),
                "total_percent": float(match.group("percent")),
                "exclusive_hits": int(match.group("exclusive").replace(",", "")),
            }
        )

    rows.sort(key=lambda row: (float(row["total_percent"]), int(row["inclusive_hits"])), reverse=True)
    return {
        "available": bool(rows),
        "app_row_count": len(rows),
        "top_app_inclusive_functions": rows[:limit],
    }


def strip_html_cell(value: str) -> str:
    """Returns display text from one xperf stack-report HTML cell."""

    stripped = _HTML_TAG_RE.sub("", value)
    return unescape(stripped).replace("\xa0", " ").strip()


def parse_xperf_stack_report_file(path: Path, *, limit: int = DEFAULT_CPU_PROFILE_TOP_LIMIT) -> dict[str, object]:
    """Reads an exported xperf stack report and returns a compact summary."""

    if not path.is_file():
        return {"available": False, "reason": "xperf stack output was not written"}
    try:
        return parse_xperf_stack_report(path.read_text(encoding="utf-8", errors="replace"), limit=limit)
    except OSError as exc:
        return {
            "available": False,
            "reason": f"{type(exc).__name__}: {exc}",
        }
