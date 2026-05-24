"""Large local eMuleBB, tracing-harness, and aMule swarm stress campaign."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
import random
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote
import urllib.request

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import amule as amule_harness  # noqa: E402
from emule_test_harness import cpu_profile  # noqa: E402
from emule_test_harness.admin_volume_fixtures import (  # noqa: E402
    AdminVolumeFixtureConfig,
    build_storage_topology,
    create_admin_volume_fixture,
)
from emule_test_harness import live_process_monitor  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES, long_path_capability_report, resolve_amule_client  # noqa: E402
from emule_test_harness.paths import reject_windows_temp_path  # noqa: E402


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
protocol_matrix = load_local_module("local_ed2k_protocol_combinations_godzilla", "local-ed2k-protocol-combinations.py")
amutorrent_smoke = load_local_module("amutorrent_browser_smoke_godzilla", "amutorrent-browser-smoke.py")
amutorrent_local = load_local_module("amutorrent_local_ed2k_ui_godzilla", "amutorrent-local-ed2k-ui-live.py")
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
DEFAULT_PROTOCOL_CASE = "obfuscated-preferred"
DEFAULT_VHD_SIZE_MB = 8192
DEFAULT_REST_SEARCH_ROUNDS = 12
DEFAULT_AMULE_COMMAND_ROUNDS = 12
DEFAULT_AMUTORRENT_API_ROUNDS = 8
DEFAULT_MIN_PUBLISHED_FILES_TO_START = 1
DEFAULT_HAMMER_WAVES = 6
DEFAULT_HAMMER_WAVE_SLEEP_SECONDS = 1.0
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
    parser.add_argument("--admin-volume-fixtures", action="store_true")
    parser.add_argument("--vhd-size-mb", type=int, default=DEFAULT_VHD_SIZE_MB)
    parser.add_argument("--mount-root")
    parser.add_argument("--keep-admin-fixtures", action="store_true")
    parser.add_argument(
        "--vhd-runtime-root",
        choices=["drive-letter"],
        default="drive-letter",
        help="Runtime root for generated Godzilla profiles. Mixed aMule/tracing-harness runs must stay on the short VHD drive-letter root.",
    )
    parser.add_argument("--capture-final-dump", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--procdump-path")
    parser.add_argument("--cpu-profile", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--cpu-profile-max-file-mb", type=int, default=cpu_profile.DEFAULT_CPU_PROFILE_MAX_FILE_MB)
    parser.add_argument("--cpu-profile-stack", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--cpu-profile-stack-min-hits", type=int, default=10)
    parser.add_argument("--enable-umdh", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--require-umdh", action="store_true")
    parser.add_argument("--enable-pageheap", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--crash-monitor", action=argparse.BooleanOptionalAction, default=True)
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
    parser.add_argument("--rest-search-rounds", type=int, default=DEFAULT_REST_SEARCH_ROUNDS)
    parser.add_argument("--amule-command-rounds", type=int, default=DEFAULT_AMULE_COMMAND_ROUNDS)
    parser.add_argument("--amutorrent-controller", action="store_true")
    parser.add_argument("--amutorrent-api-rounds", type=int, default=DEFAULT_AMUTORRENT_API_ROUNDS)
    parser.add_argument("--min-published-files-to-start", type=int, default=DEFAULT_MIN_PUBLISHED_FILES_TO_START)
    parser.add_argument("--hammer-waves", type=int, default=DEFAULT_HAMMER_WAVES)
    parser.add_argument("--hammer-wave-sleep-seconds", type=float, default=DEFAULT_HAMMER_WAVE_SLEEP_SECONDS)
    parser.add_argument("--emulebb-files", type=int, default=DEFAULT_EMULEBB_FILES)
    parser.add_argument("--extra-emulebb-clients", type=int, default=DEFAULT_EXTRA_EMULEBB_CLIENTS)
    parser.add_argument("--extra-emulebb-files", type=int, default=DEFAULT_EXTRA_EMULEBB_FILES)
    parser.add_argument("--harness-files", type=int, default=DEFAULT_HARNESS_FILES)
    parser.add_argument("--amule-files", type=int, default=DEFAULT_AMULE_FILES)
    parser.add_argument("--transfer-count", type=int, default=DEFAULT_TRANSFER_COUNT)
    parser.add_argument("--file-base-size-bytes", type=int, default=DEFAULT_FILE_BASE_SIZE_BYTES)
    parser.add_argument("--file-medium-size-bytes", type=int, default=DEFAULT_FILE_MEDIUM_SIZE_BYTES)
    parser.add_argument("--file-large-size-bytes", type=int, default=DEFAULT_FILE_LARGE_SIZE_BYTES)
    parser.add_argument("--protocol-case", choices=tuple(protocol_matrix.PROTOCOL_CASE_MAP.keys()), default=DEFAULT_PROTOCOL_CASE)
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
        "rest_search_rounds",
        "amule_command_rounds",
        "amutorrent_api_rounds",
        "min_published_files_to_start",
        "hammer_waves",
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
    if args.vhd_size_mb <= 0:
        raise ValueError("VHD size must be greater than zero.")
    if args.hammer_wave_sleep_seconds < 0:
        raise ValueError("Hammer wave sleep seconds must not be negative.")
    if args.cpu_profile_max_file_mb <= 0:
        raise ValueError("CPU profile max file MB must be greater than zero.")
    if args.cpu_profile_stack_min_hits <= 0:
        raise ValueError("CPU profile stack min hits must be greater than zero.")


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


def generated_library_shared_dirs(root: Path) -> list[str]:
    """Returns recursive eMule share entries for a generated bucketed library."""

    return live_common.enumerate_recursive_directories(root)


def allocate_free_tcp_port(used: set[int]) -> int:
    """Allocates one additional unique local TCP port."""

    for _ in range(100):
        candidate = rest_smoke.choose_listen_port()
        if candidate not in used and dtt.is_port_available(candidate):
            used.add(candidate)
            return candidate
    raise RuntimeError("Could not allocate an additional TCP port.")


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


def build_admin_fixture_config(paths, args: argparse.Namespace) -> AdminVolumeFixtureConfig:
    """Builds the optional throwaway VHD fixture for Godzilla runtime state."""

    mount_parent = (
        Path(args.mount_root).resolve()
        if args.mount_root
        else paths.source_artifacts_dir / "admin-mounts"
    )
    reject_windows_temp_path(mount_parent, "Godzilla admin fixture mount root")
    return AdminVolumeFixtureConfig(
        vhd_path=paths.source_artifacts_dir / "admin-volumes" / f"{SUITE_NAME}.vhdx",
        mount_root=mount_parent / SUITE_NAME,
        local_control_root=paths.source_artifacts_dir / "local-control-volume",
        size_mb=args.vhd_size_mb,
        keep=args.keep_admin_fixtures,
    )


@contextmanager
def godzilla_runtime_storage(paths, args: argparse.Namespace):
    """Yields the runtime root used for generated libraries and throwaway profiles."""

    if not args.admin_volume_fixtures:
        raise RuntimeError("godzilla-local-swarm requires --admin-volume-fixtures so legacy clients run from a short throwaway VHD profile root.")

    config = build_admin_fixture_config(paths, args)
    with create_admin_volume_fixture(config) as fixture:
        topology = build_storage_topology(fixture, SUITE_NAME)
        runtime_root = topology.vhd_drive_root
        runtime_root.mkdir(parents=True, exist_ok=True)
        yield {
            "enabled": True,
            "root": runtime_root,
            "mode": args.vhd_runtime_root,
            "vhd_path": str(fixture.vhd_path),
            "drive_root": str(fixture.drive_root),
            "mount_root": str(fixture.mount_root),
            "local_control_root": str(fixture.local_control_root),
            "drive_identity": fixture.drive_identity.__dict__,
            "mount_identity": fixture.mount_identity.__dict__,
            "local_control_identity": fixture.local_control_identity.__dict__,
        }


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


def protocol_preferences(case) -> dict[str, object]:
    """Returns the client preference values for one protocol-obfuscation case."""

    return {
        "crypt_layer_supported": bool(case.client_crypt_supported),
        "crypt_layer_requested": bool(case.client_crypt_requested),
        "crypt_layer_required": bool(case.client_crypt_required),
        "crypt_tcp_padding_length": int(protocol_matrix.PROTOCOL_PADDING_LENGTH),
    }


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


def server_total_file_count(admin_base_url: str, api_key: str) -> int:
    """Returns the current dynamic/shared file count from the local ED2K server."""

    stats = dtt.admin_request(admin_base_url, api_key, "/api/stats")
    data = stats.get("data") if isinstance(stats, dict) else None
    if not isinstance(data, dict):
        return 0
    return int(data.get("current_files") or 0)


def wait_for_server_min_file_count(
    admin_base_url: str,
    api_key: str,
    *,
    minimum_count: int,
    timeout_seconds: float,
) -> dict[str, object]:
    """Starts the hammer as soon as any requested minimum publication exists."""

    observations: list[dict[str, object]] = []

    def resolve():
        count = server_total_file_count(admin_base_url, api_key)
        observations.append({"count": count, "minimum": minimum_count, "observed_at": round(time.time(), 3)})
        return {"count": count, "minimum": minimum_count, "observations": observations} if count >= minimum_count else None

    return live_common.wait_for(resolve, timeout_seconds, 1.0, f"minimum published file count {minimum_count}")


def snapshot_publication_counts(
    admin_base_url: str,
    api_key: str,
    *,
    owner_keys: list[str],
) -> dict[str, object]:
    """Records current publication coverage without blocking the hammer."""

    counts = {"total": server_total_file_count(admin_base_url, api_key)}
    for owner_key in owner_keys:
        counts[owner_key] = server_file_count(admin_base_url, api_key, search=f"{owner_key}-godzilla-")
    return counts


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


def wait_for_known_met_size(config_dir: Path, expected_files: int, timeout_seconds: float) -> dict[str, object]:
    """Waits until a generated eMule profile has persisted a plausible known.met."""

    if expected_files <= 0:
        return {"skipped": True, "reason": "no expected files"}
    known_path = config_dir / "known.met"
    min_size = max(128, expected_files * 64)
    observations: list[dict[str, object]] = []

    def resolve():
        size = known_path.stat().st_size if known_path.exists() else 0
        observations.append({"size": size, "minimum": min_size, "observed_at": round(time.time(), 3)})
        return {"path": str(known_path), "size": size, "minimum": min_size, "observations": observations} if size >= min_size else None

    return live_common.wait_for(resolve, timeout_seconds, 5.0, f"known.met hash persistence in {config_dir}")


def try_wait_for_known_met_size(config_dir: Path, expected_files: int, timeout_seconds: float) -> dict[str, object]:
    """Records known.met readiness without blocking the hammer campaign."""

    try:
        result = wait_for_known_met_size(config_dir, expected_files, timeout_seconds)
        result["ok"] = True
        return result
    except Exception as exc:
        known_path = config_dir / "known.met"
        return {
            "ok": False,
            "type": type(exc).__name__,
            "message": str(exc),
            "path": str(known_path),
            "size": known_path.stat().st_size if known_path.exists() else 0,
        }


def force_emulebb_publish(base_url: str, api_key: str, *, address: str, port: int, timeout_seconds: float) -> dict[str, object]:
    """Forces shared-file reload and reconnect for one REST-controlled eMuleBB client."""

    reload_result = rest_smoke.http_request(
        base_url,
        "/api/v1/shared-files/operations/reload",
        method="POST",
        api_key=api_key,
        json_body={},
        request_timeout_seconds=30.0,
    )
    return {
        "reload_shared_files": rest_smoke.compact_http_result(reload_result),
        "server_reconnect": dtt.add_and_connect_server(
            base_url,
            api_key,
            address=address,
            port=port,
            timeout_seconds=timeout_seconds,
        ),
    }


def run_emulebb_search_hammer(base_url: str, api_key: str, *, queries: list[str], rounds: int) -> dict[str, object]:
    """Starts local-server search rounds through native eMuleBB REST."""

    if rounds <= 0:
        return {"skipped": True, "reason": "rounds disabled"}
    rows: list[dict[str, object]] = []
    for index in range(rounds):
        query = queries[index % len(queries)]
        row: dict[str, object] = {"round": index + 1, "query": query}
        start = rest_smoke.start_live_search(base_url, api_key, "server", query, forced_method="server")
        row["start"] = rest_smoke.compact_http_result(start["response"]) if start.get("response") else start
        search_id = None
        response = start.get("response")
        if isinstance(response, dict) and isinstance(response.get("json"), dict):
            search_id = response["json"].get("id")
        if search_id:
            row["observation"] = rest_smoke.wait_for_search_observation(base_url, api_key, str(search_id), 20.0)
        rows.append(row)
    cleanup = rest_smoke.compact_http_result(rest_smoke.delete_all_searches(base_url, api_key))
    return {"rounds": rows, "cleanup": cleanup}


def run_amule_command_hammer(
    control_exe: Path,
    profile: amule_harness.AmuleRuntimeProfile,
    *,
    links: list[str],
    queries: list[str],
    rounds: int,
) -> dict[str, object]:
    """Runs non-fatal aMule external-control commands to stress EC and ED2K paths."""

    if rounds <= 0:
        return {"skipped": True, "reason": "rounds disabled"}
    command_templates = [
        "Status",
        "Show DL",
        "Show UL",
        "Show Shared",
        "Reload Shared",
        "Connect ed2k",
        "Search global {query}",
        "Search local {query}",
    ]
    rows: list[dict[str, object]] = []
    for index in range(rounds):
        template = command_templates[index % len(command_templates)]
        command = template.format(query=queries[index % len(queries)])
        rows.append({"round": index + 1, "command": command, **amule_command_summary(amule_harness.run_amulecmd(control_exe, profile, command, timeout_seconds=30.0, check=False))})
        if links and index % 4 == 3:
            link = links[(index // 4) % len(links)]
            rows.append({"round": index + 1, "command": "Add <ed2k-link>", **amule_command_summary(amule_harness.run_amulecmd(control_exe, profile, f"Add {link}", timeout_seconds=30.0, check=False))})
    return {"rounds": rows}


def amutorrent_http_json(base_url: str, path: str, *, method: str = "GET", body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Runs one JSON aMuTorrent controller request."""

    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"{base_url}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=20.0) as response:
        payload_text = response.read().decode("utf-8", errors="replace")
        payload = json.loads(payload_text) if payload_text else None
        return {"status": response.status, "payload": payload}


def run_amutorrent_api_hammer(base_url: str, *, links: list[str], rounds: int) -> dict[str, object]:
    """Runs optional aMuTorrent controller API traffic against eMuleBB and aMule."""

    if rounds <= 0:
        return {"skipped": True, "reason": "rounds disabled"}
    rows: list[dict[str, object]] = []
    instance_cycle = [CLIENT01.profile_id, CLIENT04.profile_id]
    for index in range(rounds):
        instance_id = instance_cycle[index % len(instance_cycle)]
        row: dict[str, object] = {
            "round": index + 1,
            "instance_id": instance_id,
            "health": amutorrent_http_json(base_url, "/health"),
            "snapshot_before": amutorrent_http_json(base_url, "/api/v1/data/snapshot"),
        }
        if links:
            link = links[index % len(links)]
            row["add_ed2k"] = amutorrent_http_json(
                base_url,
                "/api/v1/downloads/ed2k",
                method="POST",
                body={"links": [link], "instanceId": instance_id},
            )
        query = "linux" if index % 2 == 0 else "debian"
        row["search"] = amutorrent_http_json(
            base_url,
            "/api/v1/search?wait=false",
            method="POST",
            body={"query": query, "type": "server", "instanceId": instance_id},
        )
        row["search_results"] = amutorrent_http_json(base_url, f"/api/v1/search/results?type=server&instanceId={instance_id}")
        row["snapshot_after"] = amutorrent_http_json(base_url, "/api/v1/data/snapshot")
        rows.append(row)
    return {"rounds": rows}


def server_telemetry_snapshot(admin_base_url: str, api_key: str) -> dict[str, object]:
    """Captures a compact Go ED2K server telemetry snapshot through the admin API."""

    snapshot: dict[str, object] = {"observed_at": round(time.time(), 3)}
    endpoints = {
        "stats": "/api/stats",
        "clients": "/api/clients?page=1&per_page=100&sort=last_seen",
        "audit": "/api/audit?page=1&per_page=25",
    }
    for name, endpoint in endpoints.items():
        try:
            snapshot[name] = dtt.admin_request(admin_base_url, api_key, endpoint)
        except Exception as exc:  # noqa: BLE001 - telemetry must not abort the hammer
            snapshot[name] = {"error_type": type(exc).__name__, "error_message": str(exc) or repr(exc)}
    return snapshot


def run_spiral_hammer(
    *,
    base_url: str,
    api_key: str,
    admin_base_url: str,
    amule_control_exe: Path,
    amule_profile: amule_harness.AmuleRuntimeProfile,
    links: list[str],
    queries: list[str],
    waves: int,
    sleep_seconds: float,
) -> dict[str, object]:
    """Runs increasing search/download/churn/EC waves after first publication."""

    if waves <= 0:
        return {"skipped": True, "reason": "waves disabled"}
    rows: list[dict[str, object]] = []
    link_count = len(links)
    for wave in range(1, waves + 1):
        wave_row: dict[str, object] = {
            "wave": wave,
            "started_at": round(time.time(), 3),
            "actions": [],
        }
        wave_row["server_before"] = server_telemetry_snapshot(admin_base_url, api_key)
        actions = wave_row["actions"]
        assert isinstance(actions, list)
        for index in range(wave * 3):
            query = queries[(wave + index) % len(queries)]
            start = rest_smoke.start_live_search(base_url, api_key, "server", query, forced_method="server")
            actions.append(
                {
                    "kind": "rest-search",
                    "query": query,
                    "response": rest_smoke.compact_http_result(start["response"]) if start.get("response") else start,
                }
            )
        if link_count:
            start = ((wave - 1) * 3) % link_count
            wave_links = [links[(start + offset) % link_count] for offset in range(min(link_count, wave * 6))]
            add_results = queue_emulebb_downloads(base_url, api_key, wave_links)
            actions.extend({"kind": "rest-add", "response": result} for result in add_results)
            hashes = []
            for link in wave_links[: min(len(wave_links), wave * 4)]:
                try:
                    hashes.append(str(dtt.parse_ed2k_file_link(link)["hash"]).lower())
                except Exception:
                    continue
            for transfer_hash in hashes:
                operations = ("pause", "resume", "stop", "resume")[: 1 + (wave % 4)]
                for operation in operations:
                    result = rest_smoke.http_request(
                        base_url,
                        f"/api/v1/transfers/{transfer_hash}/operations/{operation}",
                        method="POST",
                        api_key=api_key,
                        json_body={},
                        request_timeout_seconds=10.0,
                    )
                    actions.append(
                        {
                            "kind": "rest-churn",
                            "hash": transfer_hash,
                            "operation": operation,
                            "response": rest_smoke.compact_http_result(result),
                        }
                    )
        amule_commands = [
            "Status",
            "Show DL",
            "Show UL",
            "Show Shared",
            "Reload Shared",
            "Connect ed2k",
            f"Search global {queries[wave % len(queries)]}",
            f"Search local {queries[(wave + 1) % len(queries)]}",
        ][: 2 + wave]
        for command in amule_commands:
            actions.append(
                {
                    "kind": "amulecmd",
                    "command": command,
                    "response": amule_command_summary(
                        amule_harness.run_amulecmd(amule_control_exe, amule_profile, command, timeout_seconds=30.0, check=False)
                    ),
                }
            )
        wave_row["server_after"] = server_telemetry_snapshot(admin_base_url, api_key)
        wave_row["finished_at"] = round(time.time(), 3)
        rows.append(wave_row)
        if sleep_seconds:
            time.sleep(sleep_seconds)
    return {"waves": rows}


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
    runtime_rows: list[dict[str, object]] = []
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
            runtime_rows.append(
                {
                    "utc_time": row.get("utc_time"),
                    "elapsed_seconds": row.get("elapsed_seconds"),
                    "runtime": live_process_monitor.sample_runtime_counters(base_url, api_key),
                }
            )
            rows.append(row)
            last_sample = time.monotonic()
            last_cpu = float(row["cpu_seconds"])
            if int(row.get("exit_code", live_process_monitor.STILL_ACTIVE)) != live_process_monitor.STILL_ACTIVE:
                break
            time.sleep(interval_seconds)
    finally:
        live_process_monitor.kernel32.CloseHandle(live_process_monitor.ctypes.c_void_p(handle))
    live_process_monitor.write_metric_csv(output_csv, rows)
    runtime_jsonl = output_csv.with_name(output_csv.stem + "-runtime-counters.jsonl")
    runtime_jsonl.write_text(
        "".join(json.dumps(json_safe(row), sort_keys=True) + "\n" for row in runtime_rows),
        encoding="utf-8",
    )
    summary = live_process_monitor.summarize_metric_rows(rows)
    summary["runtime_counters_jsonl"] = str(runtime_jsonl)
    summary["runtime_sample_count"] = len(runtime_rows)
    if runtime_rows:
        summary["last_runtime_sample"] = runtime_rows[-1]
    return summary


def cpu_profile_paths_to_report(paths: cpu_profile.CpuProfilePaths) -> dict[str, str]:
    """Returns stable CPU profile artifact paths for the Godzilla result report."""

    return {
        "raw_etl": str(paths.raw_etl_path),
        "etl": str(paths.etl_path),
        "detail": str(paths.detail_path),
        "summary": str(paths.summary_path),
        "stack": str(paths.stack_path),
    }


def finalize_cpu_profile_capture(
    *,
    report: dict[str, object],
    tools: cpu_profile.CpuProfileTools,
    paths: cpu_profile.CpuProfilePaths,
    app_exe: Path,
    include_stack: bool,
    stack_min_hits: int,
) -> None:
    """Stops, exports, and summarizes the active Godzilla CPU ETW profile."""

    diagnostics = report.setdefault("diagnostics", {})
    assert isinstance(diagnostics, dict)
    cpu_report = diagnostics.setdefault("cpu_profile", {})
    assert isinstance(cpu_report, dict)
    cpu_report["stop"] = cpu_profile.stop_cpu_profile(tools=tools, paths=paths, timeout_seconds=60.0)
    if (
        isinstance(cpu_report.get("start"), dict)
        and cpu_report["start"].get("return_code") == 0
        and isinstance(cpu_report.get("stop"), dict)
        and cpu_report["stop"].get("return_code") == 0
        and paths.etl_path.is_file()
    ):
        cpu_report["export"] = cpu_profile.export_cpu_profile(
            tools=tools,
            paths=paths,
            app_exe=app_exe,
            timeout_seconds=90.0,
            include_stack=include_stack,
            stack_min_hits=stack_min_hits,
        )
        summary = {
            "detail": cpu_profile.parse_xperf_profile_detail_file(paths.detail_path),
            "stack": cpu_profile.parse_xperf_stack_report_file(paths.stack_path)
            if include_stack
            else {"available": False, "reason": "stack export disabled"},
        }
        paths.summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        cpu_report["summary"] = summary
        cpu_report["status"] = "passed" if summary["detail"].get("available") else "failed"
    else:
        cpu_report["status"] = "failed"


def capture_primary_memory_diagnostics(
    *,
    report: dict[str, object],
    app,
    procdump_path: Path | None,
    umdh_path: str | None,
    analysis_dir: Path,
    diagnostics_dir: Path,
) -> None:
    """Captures final dump and UMDH heap evidence for the primary eMuleBB client."""

    if app is None:
        return
    process_id = app_process_id(app)
    process_handle = live_process_monitor.open_process(process_id)
    try:
        if live_process_monitor.get_process_exit_code(process_handle) != live_process_monitor.STILL_ACTIVE:
            return
        diagnostics = report.setdefault("diagnostics", {})
        assert isinstance(diagnostics, dict)
        if diagnostics.get("capture_final_dump_enabled"):
            final_dump = live_process_monitor.capture_procdump(
                procdump_path,
                process_id,
                diagnostics_dir / "primary-final-memory.dmp",
                analysis_dir / "procdump-primary-final-memory.txt",
            )
            diagnostics["final_dump"] = final_dump
            if isinstance(final_dump, dict) and final_dump.get("dump_exists"):
                diagnostics["cdb_final_dump"] = live_process_monitor.analyze_dump_with_cdb(
                    Path(str(final_dump["dump_path"])),
                    analysis_dir / "cdb-primary-final-memory-summary.txt",
                )
        umdh_report = diagnostics.get("umdh")
        if isinstance(umdh_report, dict) and umdh_report.get("enabled"):
            final_path = analysis_dir / "umdh-primary-final.txt"
            umdh_report["final"] = live_process_monitor.capture_umdh_snapshot(umdh_path, process_id, final_path)
            umdh_report["diff"] = live_process_monitor.diff_umdh_snapshots(
                umdh_path,
                analysis_dir / "umdh-primary-baseline.txt",
                final_path,
                analysis_dir / "umdh-primary-baseline-final.diff.txt",
            )
    finally:
        live_process_monitor.close_handle(process_handle)


def run_diagnostic_tool(command: list[str], output_path: Path, timeout_seconds: float) -> dict[str, object]:
    """Runs one diagnostic tool from the artifact folder so stray logs stay contained."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=str(output_path.parent),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
        duration = round(time.monotonic() - started, 3)
        output_path.write_text(
            "\n".join(
                [
                    "command: " + subprocess.list2cmdline(command),
                    f"return_code: {completed.returncode}",
                    f"duration_seconds: {duration}",
                    "",
                    completed.stdout,
                    completed.stderr,
                ]
            ),
            encoding="utf-8",
        )
        return {"command": command, "output_path": str(output_path), "return_code": completed.returncode, "duration_seconds": duration, "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        output_path.write_text(
            "\n".join(["command: " + subprocess.list2cmdline(command), "timed_out: true", "", str(exc.stdout or ""), str(exc.stderr or "")]),
            encoding="utf-8",
        )
        return {"command": command, "output_path": str(output_path), "return_code": None, "timed_out": True}


def set_pageheap(gflags_path: str | None, app_exe: Path, *, enabled: bool, output_path: Path) -> dict[str, object]:
    """Enables or disables full page heap for the eMuleBB image."""

    if not gflags_path:
        return {"skipped": True, "reason": "gflags was not found"}
    command = [gflags_path, "/p", "/enable" if enabled else "/disable", app_exe.name]
    if enabled:
        command.append("/full")
    return run_diagnostic_tool(command, output_path, 30.0)


def start_procdump_crash_monitor(
    *,
    procdump_path: Path | None,
    process_id: int,
    dump_dir: Path,
) -> tuple[dict[str, object], subprocess.Popen | None]:
    """Starts ProcDump in crash-monitor mode for the primary eMuleBB process."""

    result: dict[str, object] = {
        "started": False,
        "procdump": str(procdump_path) if procdump_path else None,
        "process_id": process_id,
        "dump_dir": str(dump_dir),
    }
    if procdump_path is None or not procdump_path.is_file():
        result["error"] = "procdump was not found"
        return result, None
    dump_dir.mkdir(parents=True, exist_ok=True)
    log_path = dump_dir / "procdump-crash-monitor.txt"
    command = [str(procdump_path), "-accepteula", "-ma", "-e", "1", "-o", str(process_id), str(dump_dir)]
    log_handle = log_path.open("w", encoding="utf-8", errors="replace")
    log_handle.write("command: " + subprocess.list2cmdline(command) + "\n\n")
    log_handle.flush()
    try:
        process = subprocess.Popen(command, stdout=log_handle, stderr=subprocess.STDOUT, cwd=str(dump_dir))
    except OSError as exc:
        log_handle.close()
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
        return result, None
    setattr(process, "_emulebb_log_handle", log_handle)
    result.update({"started": True, "pid": process.pid, "log_path": str(log_path), "command": command})
    return result, process


def finish_procdump_crash_monitor(process: subprocess.Popen | None, timeout_seconds: float) -> dict[str, object]:
    """Stops the ProcDump crash monitor and records its exit state."""

    result: dict[str, object] = {"started": process is not None, "return_code": None, "timed_out": False}
    if process is None:
        return result
    try:
        result["return_code"] = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        result["timed_out"] = True
        process.terminate()
        try:
            result["return_code"] = process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            result["return_code"] = process.wait(timeout=5.0)
    finally:
        log_handle = getattr(process, "_emulebb_log_handle", None)
        if log_handle is not None:
            log_handle.close()
    return result


def collect_crash_monitor_dumps(dump_dir: Path) -> dict[str, object]:
    """Returns ProcDump crash-monitor dump files."""

    files = []
    if dump_dir.is_dir():
        for dump_path in sorted(dump_dir.glob("*.dmp"), key=lambda item: item.stat().st_mtime):
            stat = dump_path.stat()
            files.append({"name": dump_path.name, "path": str(dump_path), "size_bytes": stat.st_size, "mtime": round(stat.st_mtime, 3)})
    return {"dump_folder": str(dump_dir), "files": files, "count": len(files)}


def cleanup_external_tool_logs(*roots: Path) -> list[str]:
    """Deletes known stray diagnostic-tool logs from workspace roots."""

    deleted: list[str] = []
    for root in roots:
        path = root / "myeasylog.log"
        try:
            if path.exists():
                path.unlink()
                deleted.append(str(path))
        except OSError:
            pass
    return deleted


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


def restart_primary_emulebb_client(
    *,
    app,
    app_exe: Path,
    profile_base: Path,
    base_url: str,
    admin_base_url: str,
    api_key: str,
    p2p_address: str,
    ed2k_port: int,
    timeout_seconds: float,
    visible_ui: bool,
) -> tuple[object, dict[str, object]]:
    """Restarts the primary REST-controlled eMuleBB client after hashing settles."""

    event: dict[str, object] = {
        "client": CLIENT01.profile_id,
        "operation": "restart-after-hash",
        "started_at": round(time.time(), 3),
    }
    if app is not None:
        live_common.close_app_cleanly(app)
        event["terminate"] = {"ok": True}
    restarted = live_common.launch_app(app_exe, profile_base, minimized_to_tray=not visible_ui)
    event["pid"] = app_process_id(restarted)
    event["rest_ready"] = rest_smoke.compact_http_result(rest_smoke.wait_for_rest_ready(base_url, api_key, timeout_seconds))
    event["server_connect"] = dtt.add_and_connect_server(
        base_url,
        api_key,
        address=p2p_address,
        port=ed2k_port,
        timeout_seconds=timeout_seconds,
    )
    event["server_client"] = dtt.wait_for_server_client(admin_base_url, api_key, CLIENT01.nick, timeout_seconds)
    event["finished_at"] = round(time.time(), 3)
    return restarted, event


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

    harness_cli_common.write_json_file(paths.source_artifacts_dir / "godzilla-local-swarm-result.json", json_safe(report))


def json_safe(value):
    """Returns a JSON-safe copy of diagnostic values collected from live helpers."""

    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


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
        "client_path_capabilities": long_path_capability_report([CLIENT01.key, CLIENT02.key, CLIENT04.key]),
        "checks": {},
    }
    server_process: subprocess.Popen | None = None
    client1_app = None
    client2_app = None
    extra_emulebb_clients: list[dict[str, object]] = []
    amule_process: subprocess.Popen | None = None
    amule_profile: amule_harness.AmuleRuntimeProfile | None = None
    amule_control_exe: Path | None = None
    amutorrent_process: subprocess.Popen[str] | None = None
    amutorrent_output = None
    amutorrent_log_path: Path | None = None
    runtime_storage_context = None
    analysis_dir = paths.source_artifacts_dir / "analysis"
    diagnostics_dir = paths.source_artifacts_dir / "diagnostics"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    diagnostics_dir.mkdir(parents=True, exist_ok=True)
    procdump_path = Path(args.procdump_path).resolve() if args.procdump_path else live_process_monitor.discover_procdump_path()
    gflags_path = live_process_monitor.find_tool("gflags.exe", "gflags")
    umdh_path = live_process_monitor.find_tool("umdh.exe", "umdh")
    cpu_profile_tools = cpu_profile.discover_cpu_profile_tools()
    cpu_profile_paths = cpu_profile.build_cpu_profile_paths(paths.source_artifacts_dir)
    cpu_profile_active = False
    cpu_profile_stopped = False
    gflags_enabled = False
    pageheap_enabled = False
    procdump_crash_monitor_process: subprocess.Popen | None = None
    procdump_crash_dump_dir = diagnostics_dir / "procdump-crash-monitor"
    current_phase = "initializing"

    try:
        report["diagnostics"] = {
            "tools": {
                "procdump": str(procdump_path) if procdump_path else None,
                "gflags": gflags_path,
                "umdh": umdh_path,
                "xperf": cpu_profile_tools.xperf,
                "wpaexporter": cpu_profile_tools.wpaexporter,
            },
            "capture_final_dump_enabled": bool(args.capture_final_dump),
            "pageheap": {
                "enabled": bool(args.enable_pageheap),
            },
            "crash_monitor": {
                "enabled": bool(args.crash_monitor),
                "dump_dir": str(procdump_crash_dump_dir),
            },
            "cpu_profile": {
                "enabled": bool(args.cpu_profile),
                "paths": cpu_profile_paths_to_report(cpu_profile_paths),
                "max_file_mb": args.cpu_profile_max_file_mb,
                "stack": bool(args.cpu_profile_stack),
                "stack_min_hits": args.cpu_profile_stack_min_hits,
            },
            "umdh": {
                "enabled": bool(args.enable_umdh),
            },
        }
        diagnostics = report["diagnostics"]
        assert isinstance(diagnostics, dict)
        if args.enable_umdh:
            umdh_report = diagnostics["umdh"]
            assert isinstance(umdh_report, dict)
            if not gflags_path or not umdh_path:
                message = "UMDH requested but gflags or umdh was not found."
                if args.require_umdh:
                    raise RuntimeError(message)
                umdh_report["status"] = "skipped"
                umdh_report["reason"] = message
            else:
                umdh_report["gflags_enable_ust"] = live_process_monitor.set_umdh_stack_tracing(
                    gflags_path,
                    paths.app_exe,
                    enabled=True,
                    output_path=analysis_dir / "gflags-enable-ust.txt",
                )
                gflags_enabled = True
                umdh_report["status"] = "active"
        if args.enable_pageheap:
            pageheap_report = diagnostics["pageheap"]
            assert isinstance(pageheap_report, dict)
            pageheap_report["enable"] = set_pageheap(
                gflags_path,
                paths.app_exe,
                enabled=True,
                output_path=analysis_dir / "gflags-enable-pageheap.txt",
            )
            pageheap_enabled = isinstance(pageheap_report["enable"], dict) and pageheap_report["enable"].get("return_code") == 0
            pageheap_report["status"] = "active" if pageheap_enabled else "failed"
        if args.cpu_profile:
            cpu_report = diagnostics["cpu_profile"]
            assert isinstance(cpu_report, dict)
            if not cpu_profile_tools.xperf:
                cpu_report["status"] = "skipped"
                cpu_report["reason"] = "xperf was not found"
            else:
                cpu_report["start"] = cpu_profile.start_cpu_profile(
                    tools=cpu_profile_tools,
                    paths=cpu_profile_paths,
                    max_file_mb=args.cpu_profile_max_file_mb,
                    timeout_seconds=30.0,
                )
                cpu_profile_active = cpu_report["start"].get("return_code") == 0
                if not cpu_profile_active:
                    cpu_report["status"] = "failed"
        runtime_storage_context = godzilla_runtime_storage(paths, args)
        runtime_storage = runtime_storage_context.__enter__()
        runtime_root = Path(str(runtime_storage["root"]))
        report["runtime_storage"] = runtime_storage
        amule_client = resolve_required_amule(paths, args)
        amule_daemon_exe = amule_client.executable
        amule_control_exe = amule_client.control_executable
        client2_app_exe = dtt.resolve_client2_app_exe(paths.workspace_root, args.configuration, args.client2_app_exe)
        protocol_case = protocol_matrix.PROTOCOL_CASE_MAP[args.protocol_case]
        client_protocol_preferences = protocol_preferences(protocol_case)
        p2p_address = resolve_local_p2p_address(args)
        ports = choose_ports(args.extra_emulebb_clients)
        if args.amutorrent_controller:
            ports["amutorrent"] = allocate_free_tcp_port(set(ports.values()))
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
        report["protocol_case"] = {
            "name": protocol_case.name,
            "server_protocol_obfuscation": protocol_case.server_protocol_obfuscation,
            "server_udp": protocol_case.server_udp,
            "client_crypt_supported": protocol_case.client_crypt_supported,
            "client_crypt_requested": protocol_case.client_crypt_requested,
            "client_crypt_required": protocol_case.client_crypt_required,
            "crypt_tcp_padding_length": protocol_matrix.PROTOCOL_PADDING_LENGTH,
        }

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
            protocol_obfuscation=protocol_case.server_protocol_obfuscation,
            server_udp=protocol_case.server_udp,
        )
        server_process = dtt.start_ed2k_server(ed2k_exe, config_path, server_dir / "server.log")
        report["checks"]["ed2k_server_health"] = dtt.wait_for_admin_health(admin_base_url, 30.0)

        current_phase = "generate_libraries"
        library_root = runtime_root / "generated-libraries"
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
            runtime_root,
            generated_library_shared_dirs(library_root / CLIENT01.profile_id),
            CLIENT01.profile_id,
        )
        client2 = live_common.prepare_scenario_profile(
            profile_seed_dir,
            runtime_root,
            generated_library_shared_dirs(library_root / CLIENT02.profile_id),
            CLIENT02.profile_id,
        )
        for client in extra_emulebb_clients:
            profile = live_common.prepare_scenario_profile(
                profile_seed_dir,
                runtime_root,
                generated_library_shared_dirs(Path(str(client["library_root"]))),
                str(client["profile_id"]),
            )
            client["profile_base"] = str(profile["profile_base"])
            client["config_dir"] = str(profile["config_dir"])
        amule_profile = amule_harness.prepare_amule_profile(
            root_dir=runtime_root / "clients" / CLIENT04.profile_id,
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
            **client_protocol_preferences,
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
            **client_protocol_preferences,
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
                **client_protocol_preferences,
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
        diagnostics = report.get("diagnostics")
        if isinstance(diagnostics, dict):
            diagnostics["primary_pid"] = app_process_id(client1_app)
            crash_report = diagnostics.get("crash_monitor")
            if isinstance(crash_report, dict) and crash_report.get("enabled"):
                crash_report["start"], procdump_crash_monitor_process = start_procdump_crash_monitor(
                    procdump_path=procdump_path,
                    process_id=app_process_id(client1_app),
                    dump_dir=procdump_crash_dump_dir,
                )
            umdh_report = diagnostics.get("umdh")
            if isinstance(umdh_report, dict) and umdh_report.get("status") == "active":
                umdh_report["baseline"] = live_process_monitor.capture_umdh_snapshot(
                    umdh_path,
                    app_process_id(client1_app),
                    analysis_dir / "umdh-primary-baseline.txt",
                )

        if args.amutorrent_controller:
            current_phase = "launch_amutorrent_controller"
            workspace_repo_root = amutorrent_smoke.find_workspace_repo_root(paths.workspace_root)
            amutorrent_root = workspace_repo_root / "repos" / "amutorrent"
            node_info = amutorrent_smoke.resolve_amutorrent_node()
            node_path = Path(str(node_info["path"]))
            amutorrent_smoke.require_amutorrent_server_dependencies(amutorrent_root, node_info)
            amutorrent_data_dir = runtime_root / "amutorrent-data"
            amutorrent_log_path = paths.source_artifacts_dir / "amutorrent-server.log"
            env = amutorrent_local.build_local_amutorrent_environment(
                base_env=os.environ,
                amutorrent_port=ports["amutorrent"],
                node_path=node_path,
                data_dir=amutorrent_data_dir,
                emulebb_rest_port=ports["client1_rest"],
                emulebb_api_key=args.api_key,
                amule_ec_port=ports["amule_ec"],
                amule_password=amule_profile.ec_password,
            )
            amutorrent_output = amutorrent_log_path.open("w", encoding="utf-8", errors="replace")
            amutorrent_process = subprocess.Popen(
                [str(node_path), "server/server.js"],
                cwd=str(amutorrent_root),
                env=env,
                stdout=amutorrent_output,
                stderr=subprocess.STDOUT,
                text=True,
            )
            amutorrent_base_url = f"http://127.0.0.1:{ports['amutorrent']}"
            amutorrent_smoke.wait_for_http_ok(f"{amutorrent_base_url}/api/config/status", args.rest_ready_timeout_seconds)
            report["amutorrent"] = {
                "base_url": amutorrent_base_url,
                "data_dir": str(amutorrent_data_dir),
                "process_id": amutorrent_process.pid,
                "node": node_info,
            }
            report["checks"]["amutorrent_clients_connected"] = amutorrent_local.wait_for_amutorrent_clients(
                base_url=amutorrent_base_url,
                expected={CLIENT01.profile_id: "emulebb", CLIENT04.profile_id: "amule"},
                timeout_seconds=args.rest_ready_timeout_seconds,
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
        current_phase = "force_publish_after_hash"
        primary_known_met = try_wait_for_known_met_size(Path(client1["config_dir"]), args.emulebb_files, args.publish_timeout_seconds)
        if args.emulebb_files:
            client1_app, primary_republish = restart_primary_emulebb_client(
                app=client1_app,
                app_exe=paths.app_exe,
                profile_base=Path(client1["profile_base"]),
                base_url=base_url,
                admin_base_url=admin_base_url,
                api_key=args.api_key,
                p2p_address=p2p_address,
                ed2k_port=ports["ed2k_tcp"],
                timeout_seconds=args.server_connect_timeout_seconds,
                visible_ui=args.visible_ui,
            )
        else:
            primary_republish = {"skipped": True}
        report["checks"]["post_hash_publication"] = {
            CLIENT01.profile_id: {
                "known_met": primary_known_met,
                "restart": primary_republish,
            },
            CLIENT04.profile_id: {
                "reload_shared": amule_command_summary(
                    amule_harness.run_amulecmd(amule_control_exe, amule_profile, "Reload Shared", timeout_seconds=60.0, check=False)
                ),
                "connect_server": amule_command_summary(
                    amule_harness.run_amulecmd(amule_control_exe, amule_profile, "Connect ed2k", timeout_seconds=30.0, check=False)
                ),
            },
            "extra_emulebb": {},
        }
        for client in extra_emulebb_clients:
            report["checks"]["post_hash_publication"]["extra_emulebb"][str(client["profile_id"])] = {
                "known_met": try_wait_for_known_met_size(Path(str(client["config_dir"])), args.extra_emulebb_files, args.publish_timeout_seconds),
                "restart": restart_extra_emulebb_client(
                    client=client,
                    admin_base_url=admin_base_url,
                    api_key=args.api_key,
                    timeout_seconds=args.server_connect_timeout_seconds,
                    visible_ui=args.visible_ui,
                ),
            }
        harness_known_met = try_wait_for_known_met_size(Path(client2["config_dir"]), args.harness_files, min(args.publish_timeout_seconds, 20.0))
        client2_app, harness_republish = restart_tracing_harness_client(
            app=client2_app,
            app_exe=client2_app_exe,
            profile_base=Path(client2["profile_base"]),
            extra_args=build_harness_args(harness_download_links_path, harness_download_report_path),
            admin_base_url=admin_base_url,
            api_key=args.api_key,
            timeout_seconds=args.server_connect_timeout_seconds,
            visible_ui=args.visible_ui,
        )
        report["checks"]["post_hash_publication"][CLIENT02.profile_id] = {
            "known_met": harness_known_met,
            "restart": harness_republish,
        }
        current_phase = "wait_for_first_publication"
        owner_keys = [
            CLIENT01.key,
            CLIENT02.key,
            CLIENT04.key,
            *(str(client["key"]) for client in extra_emulebb_clients),
        ]
        report["checks"]["first_publication_gate"] = wait_for_server_min_file_count(
            admin_base_url,
            args.api_key,
            minimum_count=max(1, args.min_published_files_to_start),
            timeout_seconds=args.publish_timeout_seconds,
        )
        report["checks"]["publication_counts_at_hammer_start"] = snapshot_publication_counts(
            admin_base_url,
            args.api_key,
            owner_keys=owner_keys,
        )
        if args.emulebb_files:
            try:
                report["checks"]["emulebb_rest_shared_count"] = wait_for_rest_shared_count(base_url, args.api_key, args.emulebb_files, 20.0)
            except Exception as exc:
                report["checks"]["emulebb_rest_shared_count"] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        for client in extra_emulebb_clients:
            try:
                report["checks"][f"{client['profile_id']}_rest_shared_count"] = wait_for_rest_shared_count(
                    str(client["base_url"]),
                    args.api_key,
                    args.extra_emulebb_files,
                    20.0,
                )
            except Exception as exc:
                report["checks"][f"{client['profile_id']}_rest_shared_count"] = {
                    "ok": False,
                    "type": type(exc).__name__,
                    "message": str(exc),
                }

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
        local_search_queries = [
            f"{CLIENT01.key}-godzilla-",
            f"{CLIENT02.key}-godzilla-",
            f"{CLIENT04.key}-godzilla-",
            *(f"{client['key']}-godzilla-" for client in extra_emulebb_clients),
            "linux",
            "debian",
            "ubuntu",
        ]
        current_phase = "spiral_hammer"
        spiral_links = emulebb_links or amule_links or harness_links
        report["checks"]["spiral_hammer"] = run_spiral_hammer(
            base_url=base_url,
            api_key=args.api_key,
            admin_base_url=admin_base_url,
            amule_control_exe=amule_control_exe,
            amule_profile=amule_profile,
            links=spiral_links,
            queries=local_search_queries,
            waves=args.hammer_waves,
            sleep_seconds=args.hammer_wave_sleep_seconds,
        )
        report["checks"]["publication_counts_after_spiral"] = snapshot_publication_counts(
            admin_base_url,
            args.api_key,
            owner_keys=owner_keys,
        )
        current_phase = "control_plane_hammer"
        report["checks"]["emulebb_rest_search_hammer"] = run_emulebb_search_hammer(
            base_url,
            args.api_key,
            queries=local_search_queries,
            rounds=args.rest_search_rounds,
        )
        report["checks"]["amule_command_hammer"] = run_amule_command_hammer(
            amule_control_exe,
            amule_profile,
            links=amule_links,
            queries=local_search_queries,
            rounds=args.amule_command_rounds,
        )
        if args.amutorrent_controller:
            report["checks"]["amutorrent_api_hammer"] = run_amutorrent_api_hammer(
                str(report["amutorrent"]["base_url"]),
                links=(emulebb_links[: max(1, min(len(emulebb_links), 20))] if emulebb_links else amule_links),
                rounds=args.amutorrent_api_rounds,
            )

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
        current_phase = "diagnostic_capture"
        capture_primary_memory_diagnostics(
            report=report,
            app=client1_app,
            procdump_path=procdump_path,
            umdh_path=umdh_path,
            analysis_dir=analysis_dir,
            diagnostics_dir=diagnostics_dir,
        )
        if cpu_profile_active:
            finalize_cpu_profile_capture(
                report=report,
                tools=cpu_profile_tools,
                paths=cpu_profile_paths,
                app_exe=paths.app_exe,
                include_stack=bool(args.cpu_profile_stack),
                stack_min_hits=args.cpu_profile_stack_min_hits,
            )
            cpu_profile_stopped = True
        diagnostics = report.get("diagnostics")
        if isinstance(diagnostics, dict):
            crash_report = diagnostics.get("crash_monitor")
            if isinstance(crash_report, dict):
                crash_report["finish"] = finish_procdump_crash_monitor(procdump_crash_monitor_process, 5.0)
                procdump_crash_monitor_process = None
                crash_report["dump_files"] = collect_crash_monitor_dumps(procdump_crash_dump_dir)
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["current_phase"] = current_phase
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        return 1
    finally:
        cleanup: dict[str, object] = {}
        if procdump_crash_monitor_process is not None:
            try:
                diagnostics = report.setdefault("diagnostics", {})
                assert isinstance(diagnostics, dict)
                crash_report = diagnostics.setdefault("crash_monitor", {})
                assert isinstance(crash_report, dict)
                crash_report["finish"] = finish_procdump_crash_monitor(procdump_crash_monitor_process, 5.0)
                crash_report["dump_files"] = collect_crash_monitor_dumps(procdump_crash_dump_dir)
                cleanup["crash_monitor"] = {"stopped": True}
            except Exception as exc:  # pragma: no cover - diagnostics best effort during cleanup
                cleanup["crash_monitor"] = {"error": str(exc) or repr(exc)}
        if client1_app is not None:
            diagnostics = report.get("diagnostics")
            already_dumped = isinstance(diagnostics, dict) and "final_dump" in diagnostics
            if not already_dumped and (args.capture_final_dump or args.enable_umdh):
                try:
                    capture_primary_memory_diagnostics(
                        report=report,
                        app=client1_app,
                        procdump_path=procdump_path,
                        umdh_path=umdh_path,
                        analysis_dir=analysis_dir,
                        diagnostics_dir=diagnostics_dir,
                    )
                except Exception as exc:  # pragma: no cover - diagnostics best effort during cleanup
                    cleanup["primary_diagnostics"] = {"error": str(exc) or repr(exc)}
        if cpu_profile_active and not cpu_profile_stopped:
            try:
                finalize_cpu_profile_capture(
                    report=report,
                    tools=cpu_profile_tools,
                    paths=cpu_profile_paths,
                    app_exe=paths.app_exe,
                    include_stack=bool(args.cpu_profile_stack),
                    stack_min_hits=args.cpu_profile_stack_min_hits,
                )
                cleanup["cpu_profile"] = {"stopped": True}
            except Exception as exc:  # pragma: no cover - diagnostics best effort during cleanup
                cleanup["cpu_profile"] = {"error": str(exc) or repr(exc)}
        if amutorrent_process is not None:
            try:
                amutorrent_local.stop_amutorrent(amutorrent_process)
                cleanup["amutorrent"] = {"ok": True}
            except Exception as exc:  # pragma: no cover - cleanup diagnostics only
                cleanup["amutorrent"] = {"error": str(exc)}
        if amutorrent_output is not None:
            amutorrent_output.close()
            if amutorrent_log_path is not None and amutorrent_log_path.exists():
                cleanup["amutorrent_log"] = str(amutorrent_log_path)
                cleanup["amutorrent_output_tail"] = amutorrent_log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
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
        if gflags_enabled and gflags_path:
            try:
                diagnostics = report.setdefault("diagnostics", {})
                assert isinstance(diagnostics, dict)
                umdh_report = diagnostics.setdefault("umdh", {})
                assert isinstance(umdh_report, dict)
                umdh_report["gflags_disable_ust"] = live_process_monitor.set_umdh_stack_tracing(
                    gflags_path,
                    paths.app_exe,
                    enabled=False,
                    output_path=analysis_dir / "gflags-disable-ust.txt",
                )
            except Exception as exc:  # pragma: no cover - cleanup diagnostics only
                cleanup["gflags_disable_ust"] = {"error": str(exc) or repr(exc)}
        if pageheap_enabled:
            try:
                diagnostics = report.setdefault("diagnostics", {})
                assert isinstance(diagnostics, dict)
                pageheap_report = diagnostics.setdefault("pageheap", {})
                assert isinstance(pageheap_report, dict)
                pageheap_report["disable"] = set_pageheap(
                    gflags_path,
                    paths.app_exe,
                    enabled=False,
                    output_path=analysis_dir / "gflags-disable-pageheap.txt",
                )
            except Exception as exc:  # pragma: no cover - cleanup diagnostics only
                cleanup["pageheap_disable"] = {"error": str(exc) or repr(exc)}
        cleanup["external_tool_logs_deleted"] = cleanup_external_tool_logs(
            paths.workspace_root,
            Path.cwd(),
            REPO_ROOT,
            paths.source_artifacts_dir,
            analysis_dir,
            diagnostics_dir,
            procdump_crash_dump_dir,
        )
        report["cleanup"] = cleanup
        write_reports(paths, report)
        if runtime_storage_context is not None:
            try:
                runtime_storage_context.__exit__(None, None, None)
            except Exception as exc:  # pragma: no cover - cleanup diagnostics only
                report["runtime_storage_cleanup_error"] = str(exc)
                write_reports(paths, report)


if __name__ == "__main__":
    raise SystemExit(main())
