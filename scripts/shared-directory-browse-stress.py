"""Direct eD2K shared-directory browse stress against a bucketed fake share tree."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.live_profiles import WebServerProfileSpec  # noqa: E402


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


harness_cli_common = load_local_module("harness_cli_common_shared_browse", "harness-cli-common.py")
live_common = load_local_module("emule_live_profile_common_shared_browse", "emule-live-profile-common.py")
rest_smoke = load_local_module("rest_api_smoke_shared_browse", "rest-api-smoke.py")
generated_fixture = load_local_module("create_long_paths_tree_shared_browse", "create-long-paths-tree.py")

SUITE_NAME = "shared-directory-browse-stress"
API_KEY = "shared-directory-browse-stress-key"
ED2K_PROTOCOL = 0xE3
EMULE_PROTOCOL = 0xC5
OP_HELLO = 0x01
OP_HELLOANSWER = 0x4C
OP_ASKSHAREDDIRS = 0x5D
OP_ASKSHAREDFILESDIR = 0x5E
OP_ASKSHAREDDIRSANS = 0x5F
OP_ASKSHAREDFILESDIRANS = 0x60
DEFAULT_REQUEST_COUNT = 1000
DEFAULT_MAX_AVG_MS = 50.0
DEFAULT_MAX_P95_MS = 150.0
DEFAULT_MAX_ONE_CORE_PERCENT = 35.0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses the standalone shared-directory browse stress arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--shared-root")
    parser.add_argument("--fixture-size", choices=["full", "smoke"], default="full")
    parser.add_argument("--request-count", type=int, default=DEFAULT_REQUEST_COUNT)
    parser.add_argument("--directory-sample-count", type=int, default=0)
    parser.add_argument("--startup-timeout-seconds", type=float, default=600.0)
    parser.add_argument("--request-timeout-seconds", type=float, default=20.0)
    parser.add_argument("--max-avg-ms", type=float, default=DEFAULT_MAX_AVG_MS)
    parser.add_argument("--max-p95-ms", type=float, default=DEFAULT_MAX_P95_MS)
    parser.add_argument("--max-one-core-percent", type=float, default=DEFAULT_MAX_ONE_CORE_PERCENT)
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> None:
    """Rejects invalid stress settings before launching the app."""

    if args.request_count <= 0:
        raise ValueError("request-count must be greater than zero.")
    if args.directory_sample_count < 0:
        raise ValueError("directory-sample-count must be zero or greater.")
    if args.startup_timeout_seconds <= 0 or args.request_timeout_seconds <= 0:
        raise ValueError("timeouts must be greater than zero.")
    if min(args.max_avg_ms, args.max_p95_ms, args.max_one_core_percent) <= 0:
        raise ValueError("thresholds must be greater than zero.")


def choose_listen_port(lan_bind_addr: str) -> int:
    """Chooses a local TCP port available on the explicit LAN bind address."""

    for _ in range(100):
        port = rest_smoke.choose_listen_port(lan_bind_addr)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind((lan_bind_addr, port))
            except OSError:
                continue
            return port
    raise RuntimeError("Could not allocate an eD2K listen port.")


def configure_profile(config_dir: Path, app_exe: Path, *, lan_bind_addr: str, tcp_port: int, rest_port: int) -> None:
    """Applies deterministic LAN-only preferences for the browse stress target."""

    live_common.apply_emule_preferences(
        config_dir,
        (
            ("Nick", "eMuleBB shared browse stress"),
            ("Port", str(tcp_port)),
            ("UDPPort", str(tcp_port + 4 if tcp_port <= 65531 else tcp_port - 4)),
            ("BindInterface", ""),
            ("BindAddr", lan_bind_addr),
            ("AllowLocalHostIP", "1"),
            ("BlockNetworkWhenBindUnavailableAtStartup", "0"),
            ("Autoconnect", "0"),
            ("NetworkED2K", "1"),
            ("NetworkKademlia", "0"),
            ("Serverlist", "0"),
            ("AddServersFromServer", "0"),
            ("AddServersFromClient", "0"),
            ("OpenPortsOnStartUp", "0"),
            ("VpnGuardMode", "Off"),
            ("SeeShare", "0"),
            ("CryptLayerSupported", "0"),
            ("CryptLayerRequested", "0"),
            ("CryptLayerRequired", "0"),
        ),
    )
    live_common.apply_section_preferences(config_dir, "UPnP", (("EnableUPnP", "0"),))
    live_common.apply_webserver_profile(
        config_dir,
        WebServerProfileSpec(app_exe=app_exe, api_key=API_KEY, port=rest_port, lan_bind_addr=lan_bind_addr),
    )


def build_packet(opcode: int, payload: bytes = b"") -> bytes:
    """Builds one eD2K TCP packet."""

    return struct.pack("<BI", ED2K_PROTOCOL, len(payload) + 1) + bytes([opcode]) + payload


def read_packet(sock: socket.socket) -> tuple[int, bytes]:
    """Reads one eD2K TCP packet and returns opcode plus payload."""

    header = read_exact(sock, 5)
    protocol, size = struct.unpack("<BI", header)
    if protocol not in {ED2K_PROTOCOL, EMULE_PROTOCOL}:
        raise RuntimeError(f"Unexpected eD2K protocol byte: {protocol:#x}.")
    if size < 1 or size > 16 * 1024 * 1024:
        raise RuntimeError(f"Unexpected eD2K packet size: {size}.")
    body = read_exact(sock, size)
    return body[0], body[1:]


def read_exact(sock: socket.socket, size: int) -> bytes:
    """Reads exactly size bytes or raises when the socket closes early."""

    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("Socket closed while reading eD2K packet.")
        chunks.extend(chunk)
    return bytes(chunks)


def encode_ed2k_string(value: str) -> bytes:
    """Encodes one non-UTF8 eD2K string."""

    encoded = value.encode("mbcs" if os.name == "nt" else "utf-8", errors="replace")
    if len(encoded) > 0xFFFF:
        raise ValueError("eD2K string is too long.")
    return struct.pack("<H", len(encoded)) + encoded


def decode_ed2k_string(payload: bytes, offset: int) -> tuple[str, int]:
    """Decodes one non-UTF8 eD2K string."""

    if offset + 2 > len(payload):
        raise RuntimeError("Short eD2K string length.")
    length = struct.unpack_from("<H", payload, offset)[0]
    offset += 2
    if offset + length > len(payload):
        raise RuntimeError("Short eD2K string payload.")
    encoding = "mbcs" if os.name == "nt" else "utf-8"
    return payload[offset:offset + length].decode(encoding, errors="replace"), offset + length


def build_hello_payload() -> bytes:
    """Builds the minimal old-style eD2K hello accepted by eMule clients."""

    userhash = bytearray(range(16))
    userhash[5] = 14
    userhash[14] = 111
    return bytes([16]) + bytes(userhash) + struct.pack("<IHIIH", 0, 4662, 0, 0, 0)


def wait_for_opcode(sock: socket.socket, expected_opcode: int, *, timeout_seconds: float) -> bytes:
    """Reads packets until the expected opcode arrives or the timeout expires."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        sock.settimeout(max(0.1, min(1.0, deadline - time.monotonic())))
        try:
            opcode, payload = read_packet(sock)
        except socket.timeout:
            continue
        if opcode == expected_opcode:
            return payload
    raise RuntimeError(f"Timed out waiting for eD2K opcode {expected_opcode:#x}.")


def request_shared_directories(sock: socket.socket, *, timeout_seconds: float) -> list[str]:
    """Requests and decodes the remote shared pseudo-directory list."""

    sock.sendall(build_packet(OP_ASKSHAREDDIRS))
    payload = wait_for_opcode(sock, OP_ASKSHAREDDIRSANS, timeout_seconds=timeout_seconds)
    if len(payload) < 4:
        raise RuntimeError("Short OP_ASKSHAREDDIRSANS payload.")
    count = struct.unpack_from("<I", payload, 0)[0]
    offset = 4
    directories: list[str] = []
    for _ in range(count):
        directory, offset = decode_ed2k_string(payload, offset)
        directories.append(directory)
    return directories


def request_directory_files(sock: socket.socket, directory: str, *, timeout_seconds: float) -> dict[str, object]:
    """Requests one shared-directory file list and returns response timing and count."""

    started = time.perf_counter()
    sock.sendall(build_packet(OP_ASKSHAREDFILESDIR, encode_ed2k_string(directory)))
    payload = wait_for_opcode(sock, OP_ASKSHAREDFILESDIRANS, timeout_seconds=timeout_seconds)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    response_dir, offset = decode_ed2k_string(payload, 0)
    if len(payload) < offset + 4:
        raise RuntimeError("Short OP_ASKSHAREDFILESDIRANS file count.")
    file_count = struct.unpack_from("<I", payload, offset)[0]
    return {"directory": response_dir, "elapsed_ms": elapsed_ms, "file_count": file_count, "payload_bytes": len(payload)}


def percentile(values: list[float], pct: float) -> float:
    """Returns one nearest-rank percentile from a non-empty value list."""

    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return ordered[index]


def process_cpu_seconds(process_id: int) -> float | None:
    """Returns total process CPU seconds on Windows, or none when unavailable."""

    if os.name != "nt":
        return None
    import ctypes

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(0x0400, False, int(process_id))
    if not handle:
        return None
    try:
        creation = FILETIME()
        exit_time = FILETIME()
        kernel = FILETIME()
        user = FILETIME()
        if not kernel32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel), ctypes.byref(user)):
            return None
        ticks = (
            ((kernel.dwHighDateTime << 32) + kernel.dwLowDateTime)
            + ((user.dwHighDateTime << 32) + user.dwLowDateTime)
        )
        return ticks / 10_000_000.0
    finally:
        kernel32.CloseHandle(handle)


def run_browse_probe(host: str, port: int, directories_to_request: int, request_count: int, timeout_seconds: float) -> dict[str, object]:
    """Runs the direct eD2K browse-directory stress probe."""

    with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
        sock.settimeout(timeout_seconds)
        sock.sendall(build_packet(OP_HELLO, build_hello_payload()))
        wait_for_opcode(sock, OP_HELLOANSWER, timeout_seconds=timeout_seconds)
        directories = request_shared_directories(sock, timeout_seconds=timeout_seconds)
        if not directories:
            raise RuntimeError("Target returned no shared directories.")
        candidates = directories if directories_to_request <= 0 else directories[:directories_to_request]
        rng = random.Random(0xED2B144)
        requested = [candidates[index % len(candidates)] for index in range(request_count)]
        rng.shuffle(requested)
        responses = [request_directory_files(sock, directory, timeout_seconds=timeout_seconds) for directory in requested]

    elapsed_values = [float(row["elapsed_ms"]) for row in responses]
    total_file_rows = sum(int(row["file_count"]) for row in responses)
    return {
        "directory_count": len(directories),
        "candidate_directory_count": len(candidates),
        "request_count": len(responses),
        "total_file_rows": total_file_rows,
        "latency_ms": {
            "min": round(min(elapsed_values), 3),
            "avg": round(sum(elapsed_values) / len(elapsed_values), 3),
            "p95": round(percentile(elapsed_values, 95), 3),
            "p99": round(percentile(elapsed_values, 99), 3),
            "max": round(max(elapsed_values), 3),
        },
        "sample_responses": [
            {**row, "elapsed_ms": round(float(row["elapsed_ms"]), 3)}
            for row in responses[:10]
        ],
    }


def get_rest_shared_file_count(base_url: str, api_key: str) -> int | None:
    """Returns the REST shared-files total when the API is ready."""

    result = rest_smoke.http_request(
        base_url,
        "/api/v1/shared-files?offset=0&limit=1",
        api_key=api_key,
        request_timeout_seconds=5.0,
    )
    if int(result.get("status", 0)) != 200:
        return None
    payload = result.get("json")
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, dict) and isinstance(data.get("total"), int):
            return int(data["total"])
        if isinstance(payload.get("total"), int):
            return int(payload["total"])
    if isinstance(payload, list):
        return len(payload)
    return None


def wait_for_shared_file_count(base_url: str, api_key: str, expected_count: int, timeout_seconds: float) -> dict[str, object]:
    """Waits until REST reports that the generated shared model is populated."""

    observations: list[dict[str, object]] = []

    def resolve():
        count = get_rest_shared_file_count(base_url, api_key)
        observations.append({"count": count, "observed_at": round(time.time(), 3)})
        if count is not None and count >= expected_count:
            return {"count": count, "expected_count": expected_count, "observations": observations[-10:]}
        return None

    return live_common.wait_for(resolve, timeout_seconds, 1.0, "REST shared-files count")


def build_fixture(shared_root: Path, fixture_size: str) -> dict[str, object]:
    """Materializes and returns the requested generated browse-stress subtree."""

    manifest = generated_fixture.ensure_fixture(
        shared_root,
        include_browse_stress=fixture_size == "full",
        include_browse_stress_smoke=fixture_size == "smoke",
    )
    key = "shared_directory_browse_stress" if fixture_size == "full" else "shared_directory_browse_stress_smoke"
    return {"manifest": manifest, "subtree": manifest["subtrees"][key], "subtree_key": key}


def assert_thresholds(probe: dict[str, object], cpu: dict[str, object]) -> list[str]:
    """Returns threshold failure messages for the completed stress probe."""

    latency = probe["latency_ms"]
    assert isinstance(latency, dict)
    failures: list[str] = []
    if float(latency["avg"]) > float(probe["max_avg_ms"]):
        failures.append(f"avg latency {latency['avg']}ms exceeded {probe['max_avg_ms']}ms")
    if float(latency["p95"]) > float(probe["max_p95_ms"]):
        failures.append(f"p95 latency {latency['p95']}ms exceeded {probe['max_p95_ms']}ms")
    cpu_pct = cpu.get("process_pct_one_core")
    max_cpu = cpu.get("max_one_core_percent")
    if cpu_pct is not None and max_cpu is not None and float(cpu_pct) > float(max_cpu):
        failures.append(f"CPU {cpu_pct}% of one core exceeded {max_cpu}%")
    return failures


def main(argv: list[str] | None = None) -> int:
    """Runs the direct shared-directory browse stress suite."""

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
    shared_root = Path(args.shared_root).resolve() if args.shared_root else paths.source_artifacts_dir / "generated-shared-root"
    report: dict[str, Any] = {
        "suite": SUITE_NAME,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "checks": {},
    }
    app = None
    try:
        fixture = build_fixture(shared_root, args.fixture_size)
        subtree = fixture["subtree"]
        shared_dir = Path(str(subtree["root"]))
        shared_dirs = live_common.enumerate_recursive_directories(shared_dir)
        tcp_port = choose_listen_port(args.lan_bind_addr)
        rest_port = choose_listen_port(args.lan_bind_addr)
        profile = live_common.prepare_scenario_profile(
            profile_seed_dir,
            paths.source_artifacts_dir,
            shared_dirs,
            SUITE_NAME,
        )
        configure_profile(
            Path(profile["config_dir"]),
            paths.app_exe,
            lan_bind_addr=args.lan_bind_addr,
            tcp_port=tcp_port,
            rest_port=rest_port,
        )
        report["fixture"] = {
            "shared_root": str(shared_root),
            "subtree_key": fixture["subtree_key"],
            "subtree": subtree,
            "shared_directory_entries": len(shared_dirs),
        }
        report["profile"] = {
            "profile_base": str(profile["profile_base"]),
            "config_dir": str(profile["config_dir"]),
            "tcp_port": tcp_port,
            "rest_port": rest_port,
            "lan_bind_addr": args.lan_bind_addr,
        }

        app = live_common.launch_app(paths.app_exe, Path(profile["profile_base"]), minimized_to_tray=True)
        base_url = f"http://{args.lan_bind_addr}:{rest_port}"
        report["checks"]["rest_ready"] = rest_smoke.compact_http_result(
            rest_smoke.wait_for_rest_ready(base_url, API_KEY, args.startup_timeout_seconds)
        )
        report["checks"]["shared_file_count_ready"] = wait_for_shared_file_count(
            base_url,
            API_KEY,
            int(subtree["expected_visible_file_count"]),
            args.startup_timeout_seconds,
        )
        live_common.wait_for(
            lambda: socket.create_connection((args.lan_bind_addr, tcp_port), timeout=1.0).close() or True,
            timeout=30.0,
            interval=0.5,
            description="eD2K TCP listener",
        )

        process_id = live_common.resolve_app_process_id(app)
        cpu_start = process_cpu_seconds(process_id) if process_id is not None else None
        wall_start = time.perf_counter()
        probe = run_browse_probe(
            args.lan_bind_addr,
            tcp_port,
            args.directory_sample_count,
            args.request_count,
            args.request_timeout_seconds,
        )
        wall_elapsed = time.perf_counter() - wall_start
        cpu_end = process_cpu_seconds(process_id) if process_id is not None else None
        cpu_delta = None if cpu_start is None or cpu_end is None else max(0.0, cpu_end - cpu_start)
        cpu = {
            "process_id": process_id,
            "cpu_seconds": round(cpu_delta, 3) if cpu_delta is not None else None,
            "wall_seconds": round(wall_elapsed, 3),
            "process_pct_one_core": round((cpu_delta * 100.0 / wall_elapsed), 3) if cpu_delta is not None and wall_elapsed > 0 else None,
            "max_one_core_percent": args.max_one_core_percent,
        }
        probe["max_avg_ms"] = args.max_avg_ms
        probe["max_p95_ms"] = args.max_p95_ms
        report["checks"]["browse_probe"] = probe
        report["checks"]["cpu"] = cpu
        failures = assert_thresholds(probe, cpu)
        report["threshold_failures"] = failures
        report["status"] = "failed" if failures else "passed"
        return 1 if failures else 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        return 1
    finally:
        if app is not None:
            try:
                live_common.close_app_cleanly(app)
            except Exception as exc:
                report.setdefault("cleanup", {})["close_error"] = str(exc)
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        report_path = paths.source_artifacts_dir / f"{SUITE_NAME}-result.json"
        harness_cli_common.write_json_file(report_path, report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
