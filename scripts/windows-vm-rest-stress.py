"""Runs existing REST search/download stress waves against a Windows VM eMuleBB endpoint."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import time
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def load_script_module(module_name: str, filename: str):
    """Loads one sibling stress script module with a hyphenated filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


rest_stress = load_script_module("rest_cold_start_dump_stress_for_windows_vm", "rest-cold-start-dump-stress.py")
rest_smoke = rest_stress.rest_smoke


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Existing VM eMuleBB REST base URL.")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument("--waves", type=int, default=2)
    parser.add_argument("--searches-per-wave", type=int, default=8)
    parser.add_argument("--max-concurrent-searches", type=int, default=4)
    parser.add_argument("--downloads-per-search", type=int, default=0)
    parser.add_argument("--max-active-downloads", type=int, default=64)
    parser.add_argument("--synthetic-queue-fill-count", type=int, default=64)
    parser.add_argument("--synthetic-queue-fill-size-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--synthetic-queue-fill-batch-size", type=int, default=16)
    parser.add_argument("--search-observation-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--network-ready-timeout-seconds", type=float, default=45.0)
    parser.add_argument("--tool-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--term", action="append", default=[], help="Additional operator-provided live search term.")
    parser.add_argument("--cleanup", action="store_true", help="Delete stress-created searches/transfers after the run.")
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> None:
    if args.waves <= 0:
        raise ValueError("--waves must be greater than zero.")
    if args.searches_per_wave <= 0:
        raise ValueError("--searches-per-wave must be greater than zero.")
    if args.max_concurrent_searches <= 0:
        raise ValueError("--max-concurrent-searches must be greater than zero.")
    if args.downloads_per_search < 0:
        raise ValueError("--downloads-per-search must be zero or greater.")
    if args.max_active_downloads <= 0:
        raise ValueError("--max-active-downloads must be greater than zero.")
    if args.synthetic_queue_fill_count < 0:
        raise ValueError("--synthetic-queue-fill-count must be zero or greater.")
    if args.synthetic_queue_fill_size_bytes <= 0:
        raise ValueError("--synthetic-queue-fill-size-bytes must be greater than zero.")
    if args.synthetic_queue_fill_batch_size <= 0:
        raise ValueError("--synthetic-queue-fill-batch-size must be greater than zero.")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def fetch_array(base_url: str, api_key: str, path: str) -> list[Any]:
    result = rest_smoke.http_request(base_url, path, api_key=api_key, request_timeout_seconds=20.0)
    return rest_smoke.require_json_array(result, 200)


def fetch_object(base_url: str, api_key: str, path: str) -> dict[str, Any]:
    result = rest_smoke.http_request(base_url, path, api_key=api_key, request_timeout_seconds=20.0)
    return rest_smoke.require_json_object(result, 200)


def compact_status(payload: dict[str, Any]) -> dict[str, Any]:
    stats = payload.get("stats") if isinstance(payload.get("stats"), dict) else {}
    network = payload.get("network") if isinstance(payload.get("network"), dict) else {}
    servers = payload.get("servers") if isinstance(payload.get("servers"), dict) else {}
    binding = network.get("binding") if isinstance(network.get("binding"), dict) else {}
    vpn_guard = network.get("vpnGuard") if isinstance(network.get("vpnGuard"), dict) else {}
    current_server = servers.get("currentServer") if isinstance(servers.get("currentServer"), dict) else {}
    return {
        "connected": stats.get("connected"),
        "ed2kConnected": stats.get("ed2kConnected"),
        "downloadCount": stats.get("downloadCount"),
        "downloadSpeedKiBps": stats.get("downloadSpeedKiBps"),
        "sessionDownloadedBytes": stats.get("sessionDownloadedBytes"),
        "activeInterfaceName": binding.get("activeInterfaceName"),
        "vpnGuardMode": vpn_guard.get("mode"),
        "serverConnected": servers.get("connected"),
        "serverName": current_server.get("name"),
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    artifacts_dir = Path(args.artifacts_dir).resolve()
    started = time.time()
    status_before = fetch_object(args.base_url, args.api_key, "/api/v1/status")
    server_rows = [row for row in fetch_array(args.base_url, args.api_key, "/api/v1/servers") if isinstance(row, dict)]
    terms = rest_stress.build_open_source_stress_terms(tuple(args.term))
    transfer_registry = rest_stress.StressTransferRegistry()
    report: dict[str, Any] = {
        "schema": "emulebb.windows-vm-rest-stress.v1",
        "startedAt": started,
        "baseUrl": args.base_url,
        "inputs": {
            "waves": args.waves,
            "searchesPerWave": args.searches_per_wave,
            "maxConcurrentSearches": args.max_concurrent_searches,
            "downloadsPerSearch": args.downloads_per_search,
            "maxActiveDownloads": args.max_active_downloads,
            "syntheticQueueFillCount": args.synthetic_queue_fill_count,
            "syntheticQueueFillSizeBytes": args.synthetic_queue_fill_size_bytes,
            "syntheticQueueFillBatchSize": args.synthetic_queue_fill_batch_size,
            "cleanup": bool(args.cleanup),
        },
        "statusBefore": compact_status(status_before),
        "checks": {},
        "cleanup": {},
    }
    write_json(artifacts_dir / "windows-vm-rest-stress-result.partial.json", report)

    stress = rest_stress.run_stress_waves(
        base_url=args.base_url,
        api_key=args.api_key,
        process_id=None,
        server_rows=server_rows,
        search_terms=terms,
        waves=args.waves,
        searches_per_wave=args.searches_per_wave,
        max_concurrent_searches=args.max_concurrent_searches,
        downloads_per_search=args.downloads_per_search,
        max_active_downloads=args.max_active_downloads,
        download_churn_interval_seconds=0.0,
        download_remove_count_per_churn=0,
        synthetic_queue_fill_count=args.synthetic_queue_fill_count,
        synthetic_queue_fill_size_bytes=args.synthetic_queue_fill_size_bytes,
        synthetic_queue_fill_batch_size=args.synthetic_queue_fill_batch_size,
        transfer_registry=transfer_registry,
        observation_timeout_seconds=args.search_observation_timeout_seconds,
        synthetic_queue_timeout_seconds=args.tool_timeout_seconds,
        network_ready_timeout_seconds=args.network_ready_timeout_seconds,
    )
    report["checks"]["stress"] = stress
    report["checks"]["transfersAfterStress"] = rest_smoke.compact_http_result(
        rest_smoke.http_request(args.base_url, "/api/v1/transfers", api_key=args.api_key, request_timeout_seconds=20.0)
    )
    if args.cleanup:
        report["cleanup"]["searchesAndTransfers"] = rest_stress.cleanup_searches_and_transfers(
            base_url=args.base_url,
            api_key=args.api_key,
            search_ids=[str(search_id) for search_id in stress.get("search_ids", [])],
            transfer_hashes=transfer_registry.hashes(),
            transfer_cleanup_timeout_seconds=max(30.0, args.tool_timeout_seconds),
            transfer_registry=transfer_registry,
        )
    else:
        report["cleanup"]["searchesAndTransfers"] = {
            "skipped": True,
            "reason": "cleanup disabled to preserve the VM live soak queue",
            "searchIds": [str(search_id) for search_id in stress.get("search_ids", [])],
            "transferHashes": transfer_registry.hashes(),
        }
    status_after = fetch_object(args.base_url, args.api_key, "/api/v1/status")
    report["statusAfter"] = compact_status(status_after)
    report["finishedAt"] = time.time()
    report["durationSeconds"] = round(float(report["finishedAt"]) - started, 3)
    missing_downloads = int(stress.get("requested_download_triggers", 0)) - int(stress.get("completed_download_triggers", 0))
    failures = []
    if int(stress.get("failed_searches", 0)) > 0:
        failures.append("one or more stress searches failed")
    if missing_downloads > 0 and args.downloads_per_search > 0:
        failures.append("one or more requested live download triggers were not created")
    if bool(report["statusAfter"].get("ed2kConnected")) is not True:
        failures.append("VM endpoint was not ED2K-connected after stress")
    report["status"] = "passed" if not failures else "failed"
    report["failureReasons"] = failures
    write_json(artifacts_dir / "windows-vm-rest-stress-result.json", report)
    return report


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    validate_args(args)
    report = run(args)
    print(json.dumps(
        {
            "status": report["status"],
            "result": str(Path(args.artifacts_dir).resolve() / "windows-vm-rest-stress-result.json"),
            "durationSeconds": report["durationSeconds"],
            "stress": {
                "plannedSearches": report["checks"]["stress"].get("planned_searches"),
                "completedSearches": report["checks"]["stress"].get("completed_searches"),
                "syntheticQueued": report["checks"]["stress"].get("synthetic_completed_download_triggers"),
            },
        },
        indent=2,
        sort_keys=True,
    ))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
