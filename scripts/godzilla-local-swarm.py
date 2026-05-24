"""Large local eMuleBB, tracing-harness, and aMule swarm stress campaign."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import random
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import amule as amule_harness  # noqa: E402
from emule_test_harness import live_process_monitor  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES, resolve_amule_client  # noqa: E402


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


dtt = load_local_module("deterministic_two_client_transfer_godzilla", "deterministic-two-client-transfer.py")
amule_seed = load_local_module("deterministic_amule_transfer_godzilla", "deterministic-amule-transfer.py")
harness_cli_common = dtt.harness_cli_common
live_common = dtt.live_common
rest_smoke = dtt.rest_smoke

SUITE_NAME = "godzilla-local-swarm"
API_KEY = "godzilla-local-swarm-key"
CLIENT01 = CLIENT_IDENTITIES["emulebb"]
CLIENT02 = CLIENT_IDENTITIES["harness"]
CLIENT04 = CLIENT_IDENTITIES["amule"]
DEFAULT_EMULEBB_FILES = 10_000
DEFAULT_EXTRA_EMULEBB_CLIENTS = 3
DEFAULT_EXTRA_EMULEBB_FILES = 1_000
DEFAULT_HARNESS_FILES = 1_000
DEFAULT_AMULE_FILES = 1_000
DEFAULT_TRANSFER_COUNT = 300
DEFAULT_OBSERVATION_SECONDS = 600.0
DEFAULT_PUBLISH_TIMEOUT_SECONDS = 1800.0
DEFAULT_CLIENT_ROTATION_CYCLES = 8
DEFAULT_CLIENT_ROTATION_INTERVAL_SECONDS = 45.0
DEFAULT_UI_CYCLE_CYCLES = 16
DEFAULT_UI_CYCLE_INTERVAL_SECONDS = 0.75
DEFAULT_FILE_BASE_SIZE_BYTES = 4096
DEFAULT_FILE_MEDIUM_SIZE_BYTES = 64 * 1024
DEFAULT_FILE_LARGE_SIZE_BYTES = 1024 * 1024
SHARED_FILES_ROUTE = "/api/v1/shared-files"
OWNER_SEEDS = {
    "emulebb": 0xE001,
    "emulebbx": 0xE100,
    "harness": 0xE002,
    "amule": 0xE004,
}


@dataclass(frozen=True)
class GeneratedFile:
    """One generated deterministic shared file."""

    owner_key: str
    path: Path
    name: str
    size: int
    sha256: str
    ed2k_hash: str | None = None

    def as_report(self) -> dict[str, object]:
        return {
            "owner_key": self.owner_key,
            "path": str(self.path),
            "name": self.name,
            "size": self.size,
            "sha256": self.sha256,
            "ed2k_hash": self.ed2k_hash,
        }

    def with_hash(self, ed2k_hash: str) -> "GeneratedFile":
        return GeneratedFile(self.owner_key, self.path, self.name, self.size, self.sha256, ed2k_hash.lower())


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses the standalone Godzilla local swarm arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--client2-app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--visible-ui", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--p2p-bind-interface-name", default="")
    parser.add_argument("--p2p-bind-interface-address")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--publish-timeout-seconds", type=float, default=DEFAULT_PUBLISH_TIMEOUT_SECONDS)
    parser.add_argument("--observation-seconds", type=float, default=DEFAULT_OBSERVATION_SECONDS)
    parser.add_argument("--resource-sample-interval-seconds", type=float, default=2.0)
    parser.add_argument("--client-rotation-cycles", type=int, default=DEFAULT_CLIENT_ROTATION_CYCLES)
    parser.add_argument("--client-rotation-interval-seconds", type=float, default=DEFAULT_CLIENT_ROTATION_INTERVAL_SECONDS)
    parser.add_argument("--ui-cycle-cycles", type=int, default=DEFAULT_UI_CYCLE_CYCLES)
    parser.add_argument("--ui-cycle-interval-seconds", type=float, default=DEFAULT_UI_CYCLE_INTERVAL_SECONDS)
    parser.add_argument("--emulebb-files", type=int, default=DEFAULT_EMULEBB_FILES)
    parser.add_argument("--extra-emulebb-clients", type=int, default=DEFAULT_EXTRA_EMULEBB_CLIENTS)
    parser.add_argument("--extra-emulebb-files", type=int, default=DEFAULT_EXTRA_EMULEBB_FILES)
    parser.add_argument("--harness-files", type=int, default=DEFAULT_HARNESS_FILES)
    parser.add_argument("--amule-files", type=int, default=DEFAULT_AMULE_FILES)
    parser.add_argument("--transfer-count", type=int, default=DEFAULT_TRANSFER_COUNT)
    parser.add_argument("--file-base-size-bytes", type=int, default=DEFAULT_FILE_BASE_SIZE_BYTES)
    parser.add_argument("--file-medium-size-bytes", type=int, default=DEFAULT_FILE_MEDIUM_SIZE_BYTES)
    parser.add_argument("--file-large-size-bytes", type=int, default=DEFAULT_FILE_LARGE_SIZE_BYTES)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    parser.add_argument("--amule-daemon-exe")
    parser.add_argument("--amule-control-exe")
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> None:
    """Rejects impossible or too-ambiguous stress arguments early."""

    for name in (
        "emulebb_files",
        "extra_emulebb_clients",
        "extra_emulebb_files",
        "harness_files",
        "amule_files",
        "transfer_count",
        "client_rotation_cycles",
        "ui_cycle_cycles",
    ):
        if int(getattr(args, name)) < 0:
            raise ValueError(f"{name.replace('_', '-')} must not be negative.")
    if args.harness_files <= 0 or args.amule_files <= 0:
        raise ValueError("harness-files and amule-files must be greater than zero.")
    if args.transfer_count <= 0:
        raise ValueError("transfer-count must be greater than zero.")
    if min(args.file_base_size_bytes, args.file_medium_size_bytes, args.file_large_size_bytes) <= 0:
        raise ValueError("file sizes must be greater than zero.")
    if args.resource_sample_interval_seconds <= 0:
        raise ValueError("resource sample interval must be greater than zero.")
    if args.observation_seconds <= 0:
        raise ValueError("observation seconds must be greater than zero.")
    if args.client_rotation_interval_seconds <= 0:
        raise ValueError("client rotation interval must be greater than zero.")
    if args.ui_cycle_interval_seconds <= 0:
        raise ValueError("UI cycle interval must be greater than zero.")


def write_generated_file(path: Path, *, size_bytes: int, seed: int) -> str:
    """Writes deterministic bytes and returns a SHA-256 digest."""

    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    rng = random.Random(seed)
    remaining = size_bytes
    with path.open("wb") as handle:
        while remaining > 0:
            chunk = bytes(rng.getrandbits(8) for _ in range(min(16 * 1024, remaining)))
            handle.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def generated_size(index: int, args: argparse.Namespace) -> int:
    """Returns a mixed file size for one generated index."""

    if index > 0 and index % 200 == 0:
        return int(args.file_large_size_bytes)
    if index > 0 and index % 50 == 0:
        return int(args.file_medium_size_bytes)
    return int(args.file_base_size_bytes)


def generate_library(root: Path, *, owner_key: str, count: int, args: argparse.Namespace) -> list[GeneratedFile]:
    """Generates one deterministic shared-file library."""

    rows: list[GeneratedFile] = []
    owner_seed = OWNER_SEEDS.get(owner_key, int.from_bytes(hashlib.sha256(owner_key.encode("utf-8")).digest()[:4], "big"))
    for index in range(count):
        bucket = index // 250
        size = generated_size(index, args)
        name = f"{owner_key}-godzilla-{index:05d}-{size}.bin"
        path = root / f"{bucket:03d}" / name
        sha256 = write_generated_file(path, size_bytes=size, seed=owner_seed * 1_000_003 + index)
        rows.append(GeneratedFile(owner_key=owner_key, path=path, name=name, size=size, sha256=sha256))
    return rows


def choose_ports(extra_emulebb_clients: int = 0) -> dict[str, int]:
    """Allocates local ports for all clients and the ED2K server."""

    ports = amule_seed.choose_amule_ports(dtt.choose_distinct_ports())
    used = set(ports.values())
    for index in range(extra_emulebb_clients):
        for suffix in ("tcp", "udp", "rest"):
            key = f"extra_emulebb_{index}_{suffix}"
            udp = suffix == "udp"
            for _ in range(100):
                candidate = rest_smoke.choose_listen_port()
                if candidate not in used and dtt.is_port_available(candidate, udp=udp):
                    ports[key] = candidate
                    used.add(candidate)
                    break
            else:
                raise RuntimeError(f"Could not allocate port for {key}.")
    return ports


def discover_local_lan_ipv4() -> str:
    """Finds a LAN IPv4 address for local multi-client tests, preferring 192.* over VPNs."""

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            "Get-NetIPAddress -AddressFamily IPv4 "
            "| Where-Object { "
            "$_.IPAddress -and $_.IPAddress -ne '127.0.0.1' "
            "-and $_.IPAddress -notlike '169.254.*' "
            "-and $_.PrefixOrigin -ne 'WellKnown' "
            "} "
            "| Sort-Object @{Expression={if ($_.IPAddress -like '192.*') { 0 } else { 1 }}}, "
            "@{Expression={if ($_.IPAddress -like '10.*') { 1 } else { 0 }}}, InterfaceMetric "
            "| Select-Object -First 1 -ExpandProperty IPAddress"
        ),
    ]
    completed = subprocess.run(command, text=True, capture_output=True, timeout=15, check=False)
    candidate = completed.stdout.strip().splitlines()[0].strip() if completed.stdout.strip() else ""
    if not candidate:
        raise RuntimeError("Could not discover a local LAN IPv4 address. Pass --p2p-bind-interface-address explicitly.")
    return candidate


def resolve_local_p2p_address(args: argparse.Namespace) -> str:
    """Resolves the advertised local P2P address for the Godzilla local stack."""

    if args.p2p_bind_interface_address:
        return str(args.p2p_bind_interface_address)
    if args.p2p_bind_interface_name.strip():
        return dtt.discover_interface_ipv4(args.p2p_bind_interface_name)
    return discover_local_lan_ipv4()


def resolve_required_amule(paths, args: argparse.Namespace):
    """Resolves the staged aMule daemon/control pair or raises an actionable error."""

    availability = resolve_amule_client(paths.workspace_root, args.amule_daemon_exe, args.amule_control_exe)
    if not availability.available or availability.executable is None or availability.control_executable is None:
        raise RuntimeError(f"aMule is unavailable for Godzilla swarm: {availability.reason}")
    return availability


def admin_files_page(admin_base_url: str, api_key: str, *, search: str, page: int = 1) -> dict[str, object]:
    """Reads one ED2K server admin file page."""

    encoded = quote(search)
    return dtt.admin_request(admin_base_url, api_key, f"/api/files?search={encoded}&page={page}&per_page=500&sort=name")


def server_file_count(admin_base_url: str, api_key: str, *, search: str) -> int:
    """Returns the server-side published file count matching one prefix."""

    payload = admin_files_page(admin_base_url, api_key, search=search, page=1)
    meta = payload.get("meta")
    if not isinstance(meta, dict) or "total" not in meta:
        data = payload.get("data")
        return len(data) if isinstance(data, list) else 0
    return int(meta["total"])


def wait_for_server_file_count(
    admin_base_url: str,
    api_key: str,
    *,
    search: str,
    expected_count: int,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until the local ED2K server has observed enough published files."""

    observations: list[dict[str, object]] = []

    def resolve():
        count = server_file_count(admin_base_url, api_key, search=search)
        observations.append({"count": count, "observed_at": round(time.time(), 3)})
        return {"count": count, "observations": observations} if count >= expected_count else None

    return live_common.wait_for(resolve, timeout_seconds, 5.0, f"server published files for {search}")


def collect_server_files(admin_base_url: str, api_key: str, *, search: str, limit: int) -> list[GeneratedFile]:
    """Collects published file rows from the local ED2K server."""

    rows: list[GeneratedFile] = []
    page = 1
    while len(rows) < limit:
        payload = admin_files_page(admin_base_url, api_key, search=search, page=page)
        data = payload.get("data")
        if not isinstance(data, list) or not data:
            break
        for item in data:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            ed2k_hash = str(item.get("hash") or "").lower()
            size = int(item.get("size") or 0)
            if name and dtt.ED2K_HASH_PATTERN.match(ed2k_hash) and size > 0:
                owner_key = name.split("-godzilla-", 1)[0]
                rows.append(GeneratedFile(owner_key=owner_key, path=Path(name), name=name, size=size, sha256="", ed2k_hash=ed2k_hash))
            if len(rows) >= limit:
                break
        page += 1
    return rows


def wait_for_rest_shared_count(base_url: str, api_key: str, expected_count: int, timeout_seconds: float) -> dict[str, object]:
    """Waits until eMuleBB REST exposes the expected shared-file count."""

    observations: list[dict[str, object]] = []

    def resolve():
        result = rest_smoke.http_request(base_url, SHARED_FILES_ROUTE, api_key=api_key, request_timeout_seconds=20.0)
        rows = rest_smoke.require_json_array(result, 200)
        observations.append({"count": len(rows), "observed_at": round(time.time(), 3)})
        return {"count": len(rows), "observations": observations} if len(rows) >= expected_count else None

    return live_common.wait_for(resolve, timeout_seconds, 5.0, "eMuleBB REST shared-file count")


def build_file_link(row: GeneratedFile, *, source_ip: str, source_port: int) -> str:
    """Builds an ED2K file link with a deterministic local source hint."""

    if not row.ed2k_hash:
        raise ValueError(f"Missing ED2K hash for generated row: {row!r}")
    base = f"ed2k://|file|{row.name}|{row.size}|{row.ed2k_hash}|/"
    return f"{base}|sources,{source_ip}:{source_port}|/"


def write_download_link_file(path: Path, links: list[str]) -> dict[str, object]:
    """Writes newline-delimited ED2K links for the tracing harness."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{link}\n" for link in links), encoding="utf-8", newline="\n")
    return {"path": str(path), "count": len(links)}


def amule_command_summary(completed: subprocess.CompletedProcess) -> dict[str, object]:
    """Returns a bounded diagnostic summary for one `amulecmd` invocation."""

    return {
        "return_code": completed.returncode,
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-1000:],
    }


def queue_emulebb_downloads(base_url: str, api_key: str, links: list[str]) -> list[dict[str, object]]:
    """Queues ED2K links through eMuleBB REST."""

    rows: list[dict[str, object]] = []
    for link in links:
        result = rest_smoke.http_request(
            base_url,
            "/api/v1/transfers",
            method="POST",
            api_key=api_key,
            json_body={"link": link},
            request_timeout_seconds=20.0,
        )
        rows.append(rest_smoke.compact_http_result(result))
    return rows


def queue_amule_downloads(control_exe: Path, profile: amule_harness.AmuleRuntimeProfile, links: list[str]) -> list[dict[str, object]]:
    """Queues ED2K links through aMule external control."""

    rows: list[dict[str, object]] = []
    for link in links:
        rows.append(amule_command_summary(amule_harness.run_amulecmd(control_exe, profile, f"Add {link}", timeout_seconds=30.0, check=False)))
    return rows


def churn_emulebb_transfers(base_url: str, api_key: str, hashes: list[str]) -> list[dict[str, object]]:
    """Runs pause/resume/stop/delete churn against a deterministic subset."""

    operations = ("pause", "resume", "stop", "resume")
    rows: list[dict[str, object]] = []
    for index, transfer_hash in enumerate(hashes[: min(len(hashes), 80)]):
        if index % 10 == 9:
            result = rest_smoke.http_request(
                base_url,
                f"/api/v1/transfers/{transfer_hash}",
                method="DELETE",
                api_key=api_key,
                json_body={"deleteFiles": False},
                request_timeout_seconds=10.0,
            )
            rows.append({"hash": transfer_hash, "operation": "delete", **rest_smoke.compact_http_result(result)})
            continue
        operation = operations[index % len(operations)]
        result = rest_smoke.http_request(
            base_url,
            f"/api/v1/transfers/{transfer_hash}/operations/{operation}",
            method="POST",
            api_key=api_key,
            json_body={},
            request_timeout_seconds=10.0,
        )
        rows.append({"hash": transfer_hash, "operation": operation, **rest_smoke.compact_http_result(result)})
    return rows


def sample_emulebb_metrics(
    *,
    app,
    base_url: str,
    api_key: str,
    duration_seconds: float,
    interval_seconds: float,
    output_csv: Path,
) -> dict[str, object]:
    """Samples eMuleBB resource usage while the stress workload drains."""

    rows: list[dict[str, object]] = []
    handle = live_process_monitor.open_process(app_process_id(app))
    started = time.monotonic()
    last_sample = None
    last_cpu = None
    try:
        deadline = started + duration_seconds
        while time.monotonic() < deadline:
            row = live_process_monitor.sample_process_metrics(
                handle=handle,
                started_monotonic=started,
                last_sample_monotonic=last_sample,
                last_cpu_seconds=last_cpu,
            )
            row["runtime"] = live_process_monitor.sample_runtime_counters(base_url, api_key)
            rows.append(row)
            last_sample = time.monotonic()
            last_cpu = float(row["cpu_seconds"])
            if int(row.get("exit_code", live_process_monitor.STILL_ACTIVE)) != live_process_monitor.STILL_ACTIVE:
                break
            time.sleep(interval_seconds)
    finally:
        live_process_monitor.kernel32.CloseHandle(live_process_monitor.ctypes.c_void_p(handle))
    live_process_monitor.write_metric_csv(output_csv, rows)
    return live_process_monitor.summarize_metric_rows(rows)


def shutdown_amule(control_exe: Path | None, profile: amule_harness.AmuleRuntimeProfile | None) -> dict[str, object]:
    """Requests graceful aMule daemon shutdown through EC when possible."""

    if control_exe is None or profile is None:
        return {"skipped": True}
    return amule_command_summary(amule_harness.run_amulecmd(control_exe, profile, "Shutdown", timeout_seconds=30.0, check=False))


def app_process_id(app) -> int:
    """Returns the process id for a pywinauto Application object."""

    process_attr = getattr(app, "process", None)
    if callable(process_attr):
        process_attr = process_attr()
    if isinstance(process_attr, int):
        return process_attr
    pid = getattr(process_attr, "pid", None)
    if pid is None:
        raise RuntimeError(f"Could not resolve pywinauto application process id from {app!r}.")
    return int(pid)


def extra_emulebb_identity(index: int) -> dict[str, str]:
    """Returns stable labels for one extra eMuleBB source client."""

    ordinal = index + 1
    profile_id = f"cl-emulebb-extra-{ordinal:03d}"
    key = f"emulebbx{ordinal:02d}"
    return {"key": key, "profile_id": profile_id, "nick": profile_id}


def interleave_rows(groups: list[list[GeneratedFile]], limit: int) -> list[GeneratedFile]:
    """Interleaves generated rows from several sources without starving later groups."""

    selected: list[GeneratedFile] = []
    offset = 0
    while len(selected) < limit:
        appended = False
        for group in groups:
            if offset < len(group):
                selected.append(group[offset])
                appended = True
                if len(selected) >= limit:
                    break
        if not appended:
            break
        offset += 1
    return selected


def post_key(hwnd: int, virtual_key: int) -> None:
    """Posts one key press to a top-level eMule window."""

    live_common.win32gui.PostMessage(hwnd, live_common.win32con.WM_KEYDOWN, virtual_key, 0)
    live_common.win32gui.PostMessage(hwnd, live_common.win32con.WM_KEYUP, virtual_key, 0)


def post_ctrl_key(hwnd: int, virtual_key: int) -> None:
    """Posts one Ctrl-modified key press to a top-level eMule window."""

    live_common.win32gui.PostMessage(hwnd, live_common.win32con.WM_KEYDOWN, live_common.win32con.VK_CONTROL, 0)
    live_common.win32gui.PostMessage(hwnd, live_common.win32con.WM_KEYDOWN, virtual_key, 0)
    live_common.win32gui.PostMessage(hwnd, live_common.win32con.WM_KEYUP, virtual_key, 0)
    live_common.win32gui.PostMessage(hwnd, live_common.win32con.WM_KEYUP, live_common.win32con.VK_CONTROL, 0)


def ui_cycle_hammer(*, args: argparse.Namespace, apps: list[tuple[str, object]]) -> list[dict[str, object]]:
    """Exercises visible eMule-family windows with explicit refresh and tab cycling."""

    if args.ui_cycle_cycles <= 0:
        return []
    events: list[dict[str, object]] = []
    vk_f5 = 0x74
    vk_tab = 0x09
    for cycle in range(args.ui_cycle_cycles):
        for label, app in apps:
            event: dict[str, object] = {"cycle": cycle + 1, "client": label, "observed_at": round(time.time(), 3)}
            try:
                window = live_common.wait_for_main_window(app, timeout=8.0, require_visible=False)
                hwnd = int(window.handle)
                event["hwnd"] = hwnd
                event["pid"] = app_process_id(app)
                event["visible_before"] = bool(live_common.win32gui.IsWindowVisible(hwnd))
                event["show_cmd_before"] = live_common.get_window_show_cmd(hwnd)
                live_common.bring_window_to_front(window)
                post_key(hwnd, vk_f5)
                post_ctrl_key(hwnd, vk_tab)
                post_key(hwnd, vk_f5)
                event["visible_after"] = bool(live_common.win32gui.IsWindowVisible(hwnd))
                event["show_cmd_after"] = live_common.get_window_show_cmd(hwnd)
                event["status"] = "posted"
            except Exception as exc:  # pragma: no cover - diagnostic path for live UI churn
                event["status"] = "failed"
                event["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
            events.append(event)
        time.sleep(args.ui_cycle_interval_seconds)
    return events


def build_harness_args(download_link_file: Path, download_report_file: Path) -> list[str]:
    """Builds tracing-harness arguments for later link-file driven downloads."""

    return ["-downloadlinkfile", str(download_link_file), "-downloadreportfile", str(download_report_file)]


def restart_tracing_harness_client(
    *,
    app,
    app_exe: Path,
    profile_base: Path,
    extra_args: list[str],
    admin_base_url: str,
    api_key: str,
    timeout_seconds: float,
    visible_ui: bool,
) -> tuple[object, dict[str, object]]:
    """Restarts the tracing harness client and waits for server visibility."""

    event: dict[str, object] = {"client": CLIENT02.profile_id, "operation": "restart", "started_at": round(time.time(), 3)}
    if app is not None:
        live_common.close_app_cleanly(app)
        event["terminate"] = {"ok": True}
    restarted = live_common.launch_app(app_exe, profile_base, minimized_to_tray=not visible_ui, extra_args=extra_args)
    event["pid"] = app_process_id(restarted)
    event["server_client"] = dtt.wait_for_server_client(admin_base_url, api_key, CLIENT02.nick, timeout_seconds)
    event["finished_at"] = round(time.time(), 3)
    return restarted, event


def restart_extra_emulebb_client(
    *,
    client: dict[str, object],
    admin_base_url: str,
    api_key: str,
    timeout_seconds: float,
    visible_ui: bool,
) -> dict[str, object]:
    """Restarts one extra REST-controlled eMuleBB source client."""

    event: dict[str, object] = {
        "client": client["profile_id"],
        "operation": "restart",
        "started_at": round(time.time(), 3),
    }
    app = client.get("app")
    if app is not None:
        live_common.close_app_cleanly(app)
        event["terminate"] = {"ok": True}
    restarted = live_common.launch_app(
        Path(str(client["app_exe"])),
        Path(str(client["profile_base"])),
        minimized_to_tray=not visible_ui,
    )
    client["app"] = restarted
    event["pid"] = app_process_id(restarted)
    event["rest_ready"] = rest_smoke.compact_http_result(
        rest_smoke.wait_for_rest_ready(str(client["base_url"]), api_key, timeout_seconds)
    )
    event["server_connect"] = dtt.add_and_connect_server(
        str(client["base_url"]),
        api_key,
        address=str(client["p2p_address"]),
        port=int(client["server_port"]),
        timeout_seconds=timeout_seconds,
    )
    event["server_client"] = dtt.wait_for_server_client(admin_base_url, api_key, str(client["nick"]), timeout_seconds)
    event["finished_at"] = round(time.time(), 3)
    return event


def restart_amule_client(
    *,
    process: subprocess.Popen | None,
    daemon_exe: Path,
    control_exe: Path,
    profile: amule_harness.AmuleRuntimeProfile,
    admin_base_url: str,
    api_key: str,
    p2p_address: str,
    ed2k_port: int,
    timeout_seconds: float,
) -> tuple[subprocess.Popen, dict[str, object]]:
    """Restarts aMule and reconnects it to the deterministic ED2K server."""

    event: dict[str, object] = {"client": CLIENT04.profile_id, "operation": "restart", "started_at": round(time.time(), 3)}
    if process is not None and process.poll() is None:
        event["shutdown"] = shutdown_amule(control_exe, profile)
        try:
            process.wait(timeout=30.0)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=30.0)
            event["forced_terminate"] = True
    restarted = amule_harness.start_amuled(daemon_exe, profile)
    event["pid"] = restarted.pid
    event["ec_ready"] = amule_harness.wait_for_ec_ready(control_exe, profile, timeout_seconds)
    event["reload_shared"] = amule_command_summary(
        amule_harness.run_amulecmd(control_exe, profile, "Reload Shared", timeout_seconds=60.0, check=False)
    )
    event["add_server"] = amule_command_summary(
        amule_harness.run_amulecmd(control_exe, profile, f"Add {amule_harness.build_server_link(p2p_address, ed2k_port)}", timeout_seconds=30.0, check=False)
    )
    event["connect_server"] = amule_command_summary(
        amule_harness.run_amulecmd(control_exe, profile, "Connect ed2k", timeout_seconds=30.0, check=False)
    )
    event["server_client"] = dtt.wait_for_server_client(admin_base_url, api_key, CLIENT04.nick, timeout_seconds)
    event["finished_at"] = round(time.time(), 3)
    return restarted, event


def rotate_source_clients(
    *,
    args: argparse.Namespace,
    client2_app,
    client2_app_exe: Path,
    client2_profile_base: Path,
    client2_extra_args: list[str],
    extra_emulebb_clients: list[dict[str, object]],
    amule_process: subprocess.Popen | None,
    amule_daemon_exe: Path,
    amule_control_exe: Path,
    amule_profile: amule_harness.AmuleRuntimeProfile,
    admin_base_url: str,
    api_key: str,
    p2p_address: str,
    ed2k_port: int,
    primary_base_url: str,
    primary_source_links: list[str],
) -> tuple[object, subprocess.Popen | None, list[dict[str, object]]]:
    """Rotates controlled source clients and trickles new links into eMuleBB."""

    if args.client_rotation_cycles <= 0:
        return client2_app, amule_process, []

    events: list[dict[str, object]] = []
    targets: list[str] = ["harness", "amule"]
    targets.extend(str(client["profile_id"]) for client in extra_emulebb_clients)
    for cycle in range(args.client_rotation_cycles):
        time.sleep(args.client_rotation_interval_seconds)
        target = targets[cycle % len(targets)]
        if target == "harness":
            client2_app, event = restart_tracing_harness_client(
                app=client2_app,
                app_exe=client2_app_exe,
                profile_base=client2_profile_base,
                extra_args=client2_extra_args,
                admin_base_url=admin_base_url,
                api_key=api_key,
                timeout_seconds=args.server_connect_timeout_seconds,
                visible_ui=args.visible_ui,
            )
        elif target == "amule":
            amule_process, event = restart_amule_client(
                process=amule_process,
                daemon_exe=amule_daemon_exe,
                control_exe=amule_control_exe,
                profile=amule_profile,
                admin_base_url=admin_base_url,
                api_key=api_key,
                p2p_address=p2p_address,
                ed2k_port=ed2k_port,
                timeout_seconds=args.server_connect_timeout_seconds,
            )
        else:
            client = next(item for item in extra_emulebb_clients if item["profile_id"] == target)
            event = restart_extra_emulebb_client(
                client=client,
                admin_base_url=admin_base_url,
                api_key=api_key,
                timeout_seconds=args.server_connect_timeout_seconds,
                visible_ui=args.visible_ui,
            )
        if primary_source_links:
            start = (cycle * 3) % len(primary_source_links)
            event["post_rotation_download_add"] = queue_emulebb_downloads(
                primary_base_url,
                api_key,
                primary_source_links[start : start + min(3, len(primary_source_links))],
            )
        event["cycle"] = cycle + 1
        events.append(event)
    return client2_app, amule_process, events


def write_reports(paths, report: dict[str, object]) -> None:
    """Writes suite-specific JSON evidence."""

    harness_cli_common.write_json_file(paths.source_artifacts_dir / "godzilla-local-swarm-result.json", report)


def main(argv: list[str] | None = None) -> int:
    """Runs the Godzilla local swarm campaign."""

    args = parse_args(argv)
    validate_args(args)
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    profile_seed_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "parameters": vars(args),
        "checks": {},
    }
    server_process: subprocess.Popen | None = None
    client1_app = None
    client2_app = None
    extra_emulebb_clients: list[dict[str, object]] = []
    amule_process: subprocess.Popen | None = None
    amule_profile: amule_harness.AmuleRuntimeProfile | None = None
    amule_control_exe: Path | None = None
    current_phase = "initializing"

    try:
        amule_client = resolve_required_amule(paths, args)
        amule_daemon_exe = amule_client.executable
        amule_control_exe = amule_client.control_executable
        client2_app_exe = dtt.resolve_client2_app_exe(paths.workspace_root, args.configuration, args.client2_app_exe)
        p2p_address = resolve_local_p2p_address(args)
        ports = choose_ports(args.extra_emulebb_clients)
        base_url = f"http://{args.bind_addr}:{ports['client1_rest']}"
        admin_base_url = f"http://127.0.0.1:{ports['ed2k_admin']}"
        for index in range(args.extra_emulebb_clients):
            identity = extra_emulebb_identity(index)
            extra_emulebb_clients.append(
                {
                    **identity,
                    "app_exe": str(paths.app_exe),
                    "tcp_port": ports[f"extra_emulebb_{index}_tcp"],
                    "udp_port": ports[f"extra_emulebb_{index}_udp"],
                    "rest_port": ports[f"extra_emulebb_{index}_rest"],
                    "base_url": f"http://{args.bind_addr}:{ports[f'extra_emulebb_{index}_rest']}",
                    "p2p_address": p2p_address,
                    "server_port": ports["ed2k_tcp"],
                }
            )
        report["client_inventory"] = {
            CLIENT01.profile_id: {"app_exe": str(paths.app_exe), "role": "primary REST-controlled eMuleBB target"},
            CLIENT02.profile_id: {"app_exe": str(client2_app_exe)},
            CLIENT04.profile_id: amule_client.as_report(),
            "extra_emulebb": [
                {
                    "profile_id": client["profile_id"],
                    "nick": client["nick"],
                    "app_exe": client["app_exe"],
                    "base_url": client["base_url"],
                }
                for client in extra_emulebb_clients
            ],
        }
        report["network"] = {"p2p_bind_interface_address": p2p_address, "ports": ports}

        current_phase = "build_ed2k_server"
        ed2k_repo = dtt.resolve_ed2k_server_repo(paths.workspace_root, args.ed2k_server_repo)
        ed2k_exe = dtt.resolve_ed2k_server_exe(paths.workspace_root, args.ed2k_server_exe)
        report["checks"]["server_build"] = dtt.build_ed2k_server_binary(ed2k_repo, ed2k_exe)
        server_dir = paths.source_artifacts_dir / "ed2k-server"
        catalog_path = server_dir / "catalog.json"
        config_path = server_dir / "config.json"
        dtt.write_empty_catalog(catalog_path)
        report["ed2k_server"] = dtt.build_server_config(
            config_path,
            ed2k_port=ports["ed2k_tcp"],
            admin_port=ports["ed2k_admin"],
            catalog_path=catalog_path,
            token=args.api_key,
        )
        server_process = dtt.start_ed2k_server(ed2k_exe, config_path, server_dir / "server.log")
        report["checks"]["ed2k_server_health"] = dtt.wait_for_admin_health(admin_base_url, 30.0)

        current_phase = "generate_libraries"
        library_root = paths.source_artifacts_dir / "generated-libraries"
        emulebb_library = generate_library(library_root / CLIENT01.profile_id, owner_key=CLIENT01.key, count=args.emulebb_files, args=args)
        extra_emulebb_libraries: dict[str, list[GeneratedFile]] = {}
        for client in extra_emulebb_clients:
            client_library_root = library_root / str(client["profile_id"])
            client["library_root"] = str(client_library_root)
            extra_emulebb_libraries[str(client["profile_id"])] = generate_library(
                client_library_root,
                owner_key=str(client["key"]),
                count=args.extra_emulebb_files,
                args=args,
            )
        harness_library = generate_library(library_root / CLIENT02.profile_id, owner_key=CLIENT02.key, count=args.harness_files, args=args)
        amule_library = generate_library(library_root / CLIENT04.profile_id, owner_key=CLIENT04.key, count=args.amule_files, args=args)
        report["libraries"] = {
            CLIENT01.profile_id: {"root": str(library_root / CLIENT01.profile_id), "count": len(emulebb_library)},
            **{
                profile_id: {"root": str(library_root / profile_id), "count": len(rows)}
                for profile_id, rows in extra_emulebb_libraries.items()
            },
            CLIENT02.profile_id: {"root": str(library_root / CLIENT02.profile_id), "count": len(harness_library)},
            CLIENT04.profile_id: {"root": str(library_root / CLIENT04.profile_id), "count": len(amule_library)},
        }

        current_phase = "prepare_profiles"
        client1 = live_common.prepare_scenario_profile(
            profile_seed_dir,
            paths.source_artifacts_dir,
            [live_common.win_path(library_root / CLIENT01.profile_id, trailing_slash=True)],
            CLIENT01.profile_id,
        )
        client2 = live_common.prepare_scenario_profile(
            profile_seed_dir,
            paths.source_artifacts_dir,
            [live_common.win_path(library_root / CLIENT02.profile_id, trailing_slash=True)],
            CLIENT02.profile_id,
        )
        for client in extra_emulebb_clients:
            profile = live_common.prepare_scenario_profile(
                profile_seed_dir,
                paths.source_artifacts_dir,
                [live_common.win_path(Path(str(client["library_root"])), trailing_slash=True)],
                str(client["profile_id"]),
            )
            client["profile_base"] = str(profile["profile_base"])
            client["config_dir"] = str(profile["config_dir"])
        amule_profile = amule_harness.prepare_amule_profile(
            root_dir=paths.source_artifacts_dir / "clients" / CLIENT04.profile_id,
            profile_id=CLIENT04.profile_id,
            nick=CLIENT04.nick,
            tcp_port=ports["amule_tcp"],
            udp_port=ports["amule_udp"],
            ec_port=ports["amule_ec"],
            advertised_address=p2p_address,
        )
        for item in amule_library:
            destination = amule_profile.incoming_dir / item.path.relative_to(library_root / CLIENT04.profile_id)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item.path, destination)
        dtt.configure_client_profile(
            config_dir=Path(client1["config_dir"]),
            app_exe=paths.app_exe,
            nick=CLIENT01.nick,
            tcp_port=ports["client1_tcp"],
            udp_port=ports["client1_udp"],
            ed2k_enabled=True,
            autoconnect=False,
            rest_api_key=args.api_key,
            rest_port=ports["client1_rest"],
            rest_bind_addr=args.bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
            p2p_bind_addr=p2p_address,
        )
        dtt.configure_client_profile(
            config_dir=Path(client2["config_dir"]),
            app_exe=client2_app_exe,
            nick=CLIENT02.nick,
            tcp_port=ports["client2_tcp"],
            udp_port=ports["client2_udp"],
            ed2k_enabled=True,
            autoconnect=True,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
            p2p_bind_addr=p2p_address,
        )
        for client in extra_emulebb_clients:
            dtt.configure_client_profile(
                config_dir=Path(str(client["config_dir"])),
                app_exe=paths.app_exe,
                nick=str(client["nick"]),
                tcp_port=int(client["tcp_port"]),
                udp_port=int(client["udp_port"]),
                ed2k_enabled=True,
                autoconnect=False,
                rest_api_key=args.api_key,
                rest_port=int(client["rest_port"]),
                rest_bind_addr=args.bind_addr,
                p2p_bind_interface_name=args.p2p_bind_interface_name,
                p2p_bind_addr=p2p_address,
            )
        for config_dir in (
            Path(client1["config_dir"]),
            Path(client2["config_dir"]),
            amule_profile.config_dir,
            *(Path(str(client["config_dir"])) for client in extra_emulebb_clients),
        ):
            dtt.write_server_met(config_dir / "server.met", address=p2p_address, port=ports["ed2k_tcp"], name="emulebb-local-godzilla")

        current_phase = "launch_amule"
        amule_process = amule_harness.start_amuled(amule_daemon_exe, amule_profile)
        report["checks"]["amule_ec_ready"] = amule_harness.wait_for_ec_ready(amule_control_exe, amule_profile, args.rest_ready_timeout_seconds)
        report["checks"]["amule_reload_shared"] = amule_command_summary(
            amule_harness.run_amulecmd(amule_control_exe, amule_profile, "Reload Shared", timeout_seconds=60.0, check=False)
        )
        report["checks"]["amule_add_server"] = amule_command_summary(
            amule_harness.run_amulecmd(amule_control_exe, amule_profile, f"Add {amule_harness.build_server_link(p2p_address, ports['ed2k_tcp'])}", timeout_seconds=30.0, check=False)
        )
        report["checks"]["amule_connect_server"] = amule_command_summary(
            amule_harness.run_amulecmd(amule_control_exe, amule_profile, "Connect ed2k", timeout_seconds=30.0, check=False)
        )

        current_phase = "launch_extra_emulebb_sources"
        report["checks"]["extra_emulebb_sources"] = {}
        for client in extra_emulebb_clients:
            client["app"] = live_common.launch_app(paths.app_exe, Path(str(client["profile_base"])), minimized_to_tray=not args.visible_ui)
            report["checks"]["extra_emulebb_sources"][str(client["profile_id"])] = {
                "pid": app_process_id(client["app"]),
                "rest_ready": rest_smoke.compact_http_result(
                    rest_smoke.wait_for_rest_ready(str(client["base_url"]), args.api_key, args.rest_ready_timeout_seconds)
                ),
                "server_connect": dtt.add_and_connect_server(
                    str(client["base_url"]),
                    args.api_key,
                    address=p2p_address,
                    port=ports["ed2k_tcp"],
                    timeout_seconds=args.server_connect_timeout_seconds,
                ),
            }

        current_phase = "launch_harness"
        harness_dir = paths.source_artifacts_dir / "harness-control"
        harness_download_links_path = harness_dir / "downloads.ed2k.txt"
        harness_download_report_path = harness_dir / "download-report.json"
        client2_app = live_common.launch_app(
            client2_app_exe,
            Path(client2["profile_base"]),
            minimized_to_tray=not args.visible_ui,
            extra_args=build_harness_args(harness_download_links_path, harness_download_report_path),
        )

        current_phase = "launch_emulebb"
        client1_app = live_common.launch_app(paths.app_exe, Path(client1["profile_base"]), minimized_to_tray=not args.visible_ui)
        report["checks"]["emulebb_rest_ready"] = rest_smoke.compact_http_result(
            rest_smoke.wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        )
        report["checks"]["emulebb_server_connect"] = dtt.add_and_connect_server(
            base_url,
            args.api_key,
            address=p2p_address,
            port=ports["ed2k_tcp"],
            timeout_seconds=args.server_connect_timeout_seconds,
        )

        current_phase = "wait_for_publish"
        report["checks"]["server_clients"] = {
            CLIENT01.profile_id: dtt.wait_for_server_client(admin_base_url, args.api_key, CLIENT01.nick, args.server_connect_timeout_seconds),
            CLIENT02.profile_id: dtt.wait_for_server_client(admin_base_url, args.api_key, CLIENT02.nick, args.server_connect_timeout_seconds),
            CLIENT04.profile_id: dtt.wait_for_server_client(admin_base_url, args.api_key, CLIENT04.nick, args.server_connect_timeout_seconds),
            **{
                str(client["profile_id"]): dtt.wait_for_server_client(
                    admin_base_url,
                    args.api_key,
                    str(client["nick"]),
                    args.server_connect_timeout_seconds,
                )
                for client in extra_emulebb_clients
            },
        }
        if args.emulebb_files:
            report["checks"]["emulebb_rest_shared_count"] = wait_for_rest_shared_count(base_url, args.api_key, args.emulebb_files, args.publish_timeout_seconds)
            report["checks"]["emulebb_server_file_count"] = wait_for_server_file_count(
                admin_base_url,
                args.api_key,
                search=f"{CLIENT01.key}-godzilla-",
                expected_count=args.emulebb_files,
                timeout_seconds=args.publish_timeout_seconds,
            )
        report["checks"]["harness_server_file_count"] = wait_for_server_file_count(
            admin_base_url,
            args.api_key,
            search=f"{CLIENT02.key}-godzilla-",
            expected_count=args.harness_files,
            timeout_seconds=args.publish_timeout_seconds,
        )
        report["checks"]["amule_server_file_count"] = wait_for_server_file_count(
            admin_base_url,
            args.api_key,
            search=f"{CLIENT04.key}-godzilla-",
            expected_count=args.amule_files,
            timeout_seconds=args.publish_timeout_seconds,
        )
        for client in extra_emulebb_clients:
            report["checks"][f"{client['profile_id']}_rest_shared_count"] = wait_for_rest_shared_count(
                str(client["base_url"]),
                args.api_key,
                args.extra_emulebb_files,
                args.publish_timeout_seconds,
            )
            report["checks"][f"{client['profile_id']}_server_file_count"] = wait_for_server_file_count(
                admin_base_url,
                args.api_key,
                search=f"{client['key']}-godzilla-",
                expected_count=args.extra_emulebb_files,
                timeout_seconds=args.publish_timeout_seconds,
            )

        current_phase = "queue_transfer_waves"
        harness_rows = collect_server_files(admin_base_url, args.api_key, search=f"{CLIENT02.key}-godzilla-", limit=max(args.transfer_count, 1))
        amule_rows = collect_server_files(admin_base_url, args.api_key, search=f"{CLIENT04.key}-godzilla-", limit=max(args.transfer_count, 1))
        emulebb_rows = collect_server_files(admin_base_url, args.api_key, search=f"{CLIENT01.key}-godzilla-", limit=max(args.transfer_count, 1))
        extra_rows_by_profile = {
            str(client["profile_id"]): collect_server_files(
                admin_base_url,
                args.api_key,
                search=f"{client['key']}-godzilla-",
                limit=max(args.transfer_count, 1),
            )
            for client in extra_emulebb_clients
        }
        source_port_by_key = {
            CLIENT02.key: ports["client2_tcp"],
            CLIENT04.key: ports["amule_tcp"],
            **{str(client["key"]): int(client["tcp_port"]) for client in extra_emulebb_clients},
        }
        emulebb_source_rows = interleave_rows([harness_rows, amule_rows, *extra_rows_by_profile.values()], args.transfer_count)
        emulebb_links = [
            build_file_link(row, source_ip=p2p_address, source_port=source_port_by_key[row.owner_key])
            for row in emulebb_source_rows
        ]
        amule_links = [
            build_file_link(row, source_ip=p2p_address, source_port=ports["client1_tcp"])
            for row in emulebb_rows[: max(1, min(50, args.transfer_count // 4))]
        ]
        harness_links = [
            build_file_link(row, source_ip=p2p_address, source_port=ports["client1_tcp"])
            for row in emulebb_rows[max(1, min(50, args.transfer_count // 4)) : max(2, min(100, args.transfer_count // 2))]
        ]
        report["checks"]["emulebb_download_add"] = queue_emulebb_downloads(base_url, args.api_key, emulebb_links)
        report["checks"]["amule_download_add"] = queue_amule_downloads(amule_control_exe, amule_profile, amule_links)
        report["checks"]["harness_download_links"] = write_download_link_file(harness_download_links_path, harness_links)
        extra_download_counts: dict[str, int] = {}
        extra_download_checks: dict[str, list[dict[str, object]]] = {}
        if extra_emulebb_clients and emulebb_rows:
            per_extra_count = max(1, min(50, args.transfer_count // max(1, len(extra_emulebb_clients) * 4)))
            for index, client in enumerate(extra_emulebb_clients):
                rows = emulebb_rows[index * per_extra_count : (index + 1) * per_extra_count]
                links = [build_file_link(row, source_ip=p2p_address, source_port=ports["client1_tcp"]) for row in rows]
                extra_download_counts[str(client["profile_id"])] = len(links)
                extra_download_checks[str(client["profile_id"])] = queue_emulebb_downloads(str(client["base_url"]), args.api_key, links)
        report["checks"]["extra_emulebb_download_add"] = extra_download_checks
        report["queued_transfer_counts"] = {
            "emulebb": len(emulebb_links),
            "amule": len(amule_links),
            "harness": len(harness_links),
            "extra_emulebb": extra_download_counts,
        }

        current_phase = "transfer_churn"
        queued_hashes = [str(row.ed2k_hash) for row in emulebb_source_rows if row.ed2k_hash]
        report["checks"]["emulebb_transfer_churn"] = churn_emulebb_transfers(base_url, args.api_key, queued_hashes)
        report["checks"]["transfer_list_after_churn"] = rest_smoke.compact_http_result(
            rest_smoke.http_request(base_url, "/api/v1/transfers", api_key=args.api_key, request_timeout_seconds=20.0)
        )

        current_phase = "client_rotation"
        client2_extra_args = build_harness_args(harness_download_links_path, harness_download_report_path)
        client2_app, amule_process, report["checks"]["client_rotation"] = rotate_source_clients(
            args=args,
            client2_app=client2_app,
            client2_app_exe=client2_app_exe,
            client2_profile_base=Path(client2["profile_base"]),
            client2_extra_args=client2_extra_args,
            extra_emulebb_clients=extra_emulebb_clients,
            amule_process=amule_process,
            amule_daemon_exe=amule_daemon_exe,
            amule_control_exe=amule_control_exe,
            amule_profile=amule_profile,
            admin_base_url=admin_base_url,
            api_key=args.api_key,
            p2p_address=p2p_address,
            ed2k_port=ports["ed2k_tcp"],
            primary_base_url=base_url,
            primary_source_links=emulebb_links,
        )

        current_phase = "ui_cycle_hammer"
        report["checks"]["ui_cycle_hammer"] = ui_cycle_hammer(
            args=args,
            apps=[
                (CLIENT01.profile_id, client1_app),
                (CLIENT02.profile_id, client2_app),
                *[(str(client["profile_id"]), client["app"]) for client in extra_emulebb_clients if client.get("app") is not None],
            ],
        )

        current_phase = "resource_observation"
        report["checks"]["resource_summary"] = sample_emulebb_metrics(
            app=client1_app,
            base_url=base_url,
            api_key=args.api_key,
            duration_seconds=args.observation_seconds,
            interval_seconds=args.resource_sample_interval_seconds,
            output_csv=paths.source_artifacts_dir / "resource-samples.csv",
        )
        final_transfers = rest_smoke.http_request(base_url, "/api/v1/transfers", api_key=args.api_key, request_timeout_seconds=20.0)
        final_rows = rest_smoke.require_json_array(final_transfers, 200)
        report["checks"]["final_transfer_count"] = len(final_rows)
        report["checks"]["ed2k_server_stats_final"] = dtt.admin_request(admin_base_url, args.api_key, "/api/stats")
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["current_phase"] = current_phase
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        return 1
    finally:
        cleanup: dict[str, object] = {}
        for identity, app in ((CLIENT01, client1_app), (CLIENT02, client2_app)):
            if app is None:
                continue
            try:
                live_common.close_app_cleanly(app)
                cleanup[identity.profile_id] = {"ok": True}
            except Exception as exc:  # pragma: no cover - cleanup diagnostics only
                cleanup[identity.profile_id] = {"error": str(exc)}
        for client in extra_emulebb_clients:
            app = client.get("app")
            if app is None:
                continue
            try:
                live_common.close_app_cleanly(app)
                cleanup[str(client["profile_id"])] = {"ok": True}
            except Exception as exc:  # pragma: no cover - cleanup diagnostics only
                cleanup[str(client["profile_id"])] = {"error": str(exc)}
        try:
            cleanup[CLIENT04.profile_id] = shutdown_amule(amule_control_exe, amule_profile)
        except Exception as exc:  # pragma: no cover - cleanup diagnostics only
            cleanup[CLIENT04.profile_id] = {"error": str(exc)}
        if amule_process is not None and amule_process.poll() is None:
            try:
                amule_process.terminate()
                amule_process.wait(timeout=30.0)
            except Exception as exc:  # pragma: no cover - cleanup diagnostics only
                cleanup["amule_process_terminate_error"] = str(exc)
        if server_process is not None:
            try:
                dtt.stop_process(server_process)
                cleanup["ed2k_server"] = {"ok": True}
            except Exception as exc:  # pragma: no cover - cleanup diagnostics only
                cleanup["ed2k_server"] = {"error": str(exc)}
        report["cleanup"] = cleanup
        write_reports(paths, report)


if __name__ == "__main__":
    raise SystemExit(main())
