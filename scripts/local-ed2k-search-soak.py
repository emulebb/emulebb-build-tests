"""Local ED2K search and deterministic download soak through the workspace server."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import importlib.util
import json
import subprocess
import sys
import time
import urllib.error
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import goed2k  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES  # noqa: E402


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


dtt = load_local_module("deterministic_two_client_transfer_local_soak", "deterministic-two-client-transfer.py")
harness_cli_common = dtt.harness_cli_common
live_common = dtt.live_common
rest_smoke = dtt.rest_smoke

SUITE_NAME = "local-ed2k-search-soak"
API_KEY = "local-ed2k-search-soak-key"
CLIENT01 = CLIENT_IDENTITIES["emulebb"]
CLIENT02 = CLIENT_IDENTITIES["harness"]
SOAK_DOWNLOAD_NAME = "local-ed2k-soak-download.bin"
DEFAULT_SYNTHETIC_CATALOG_FILES = 240
DEFAULT_SEARCH_WAVES = 3
DEFAULT_SEARCHES_PER_WAVE = 12
DEFAULT_MAX_CONCURRENT_SEARCHES = 6
DEFAULT_SEARCH_TIMEOUT_SECONDS = 45.0
DEFAULT_DOWNLOAD_TIMEOUT_SECONDS = 900.0
DEFAULT_SEARCH_ATTEMPTS = 3
SOAK_TERMS = (
    "local-soak-linux",
    "local-soak-ubuntu",
    "local-soak-debian",
    "local-soak-fedora",
    "local-soak-python",
    "local-soak-rust",
    "local-soak-kernel",
    "local-soak-docs",
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses standalone local ED2K soak arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--client2-app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--p2p-bind-interface-name", default="")
    parser.add_argument("--p2p-bind-interface-address")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--search-waves", type=int, default=DEFAULT_SEARCH_WAVES)
    parser.add_argument("--searches-per-wave", type=int, default=DEFAULT_SEARCHES_PER_WAVE)
    parser.add_argument("--max-concurrent-searches", type=int, default=DEFAULT_MAX_CONCURRENT_SEARCHES)
    parser.add_argument("--search-timeout-seconds", type=float, default=DEFAULT_SEARCH_TIMEOUT_SECONDS)
    parser.add_argument("--download-timeout-seconds", type=float, default=DEFAULT_DOWNLOAD_TIMEOUT_SECONDS)
    parser.add_argument("--synthetic-catalog-files", type=int, default=DEFAULT_SYNTHETIC_CATALOG_FILES)
    parser.add_argument("--fixture-size-bytes", type=int, default=dtt.DEFAULT_FIXTURE_SIZE_BYTES)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    return parser.parse_args(argv)


def synthetic_hash(seed: str) -> str:
    """Returns a deterministic 32-hex ED2K-shaped hash for search-only rows."""

    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32].upper()


def build_synthetic_catalog_records(count: int, *, source_host: str, source_port: int) -> list[dict[str, object]]:
    """Builds deterministic search-only catalog rows for local ED2K query stress."""

    if count <= 0:
        raise ValueError("synthetic catalog file count must be greater than zero.")
    records: list[dict[str, object]] = []
    for index in range(count):
        term = SOAK_TERMS[index % len(SOAK_TERMS)]
        extension = "bin" if index % 3 else "txt"
        records.append(
            {
                "hash": synthetic_hash(f"{term}:{index}"),
                "name": f"{term}-{index:05d}.{extension}",
                "size": 1024 * (64 + index),
                "file_type": "Pro" if extension == "bin" else "Doc",
                "extension": extension,
                "sources": 1,
                "complete_sources": 1,
                "endpoints": [{"host": source_host, "port": source_port}],
            }
        )
    return records


def write_catalog(path: Path, records: list[dict[str, object]]) -> dict[str, object]:
    """Writes a local server catalog file and returns a compact summary."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"files": records}, indent=2), encoding="utf-8")
    return {"path": str(path), "file_count": len(records)}


def start_server_search(base_url: str, api_key: str, query: str) -> dict[str, object]:
    """Starts one server-only REST search and returns its id."""

    response = rest_smoke.http_request(
        base_url,
        "/api/v1/searches",
        method="POST",
        api_key=api_key,
        json_body={"query": query, "method": "server", "type": ""},
        request_timeout_seconds=15.0,
    )
    body = rest_smoke.require_json_object(response, 200)
    search_id = body.get("id")
    if not isinstance(search_id, str) or not search_id:
        raise RuntimeError(f"Local ED2K search did not return an id: {rest_smoke.compact_http_result(response)!r}")
    return {"id": search_id, "response": rest_smoke.compact_http_result(response)}


def wait_for_search_results(base_url: str, api_key: str, search_id: str, timeout_seconds: float) -> dict[str, object]:
    """Waits until one local search exposes at least one result."""

    observations: list[dict[str, object]] = []

    def resolve():
        response = rest_smoke.http_request(base_url, f"/api/v1/searches/{search_id}", api_key=api_key)
        if int(response.get("status", 0)) != 200:
            return None
        body = rest_smoke.require_json_object(response, 200)
        results = body.get("results")
        if not isinstance(results, list):
            results = []
        observations.append(
            {
                "observed_at": round(time.time(), 3),
                "status": body.get("status"),
                "result_count": len(results),
            }
        )
        if results:
            return {"search": body, "observations": observations}
        if body.get("status") == "complete":
            return {"search": body, "observations": observations}
        return None

    return live_common.wait_for(resolve, timeout_seconds, 1.0, f"local ED2K search {search_id}")


def run_one_search(
    base_url: str,
    api_key: str,
    query: str,
    timeout_seconds: float,
    attempts: int = DEFAULT_SEARCH_ATTEMPTS,
) -> dict[str, object]:
    """Runs one complete local server search and returns a bounded result summary."""

    if attempts <= 0:
        raise ValueError("search attempts must be greater than zero.")
    failures: list[dict[str, object]] = []
    for attempt in range(1, attempts + 1):
        started = time.monotonic()
        try:
            created = start_server_search(base_url, api_key, query)
            observed = wait_for_search_results(base_url, api_key, str(created["id"]), timeout_seconds)
            results = observed["search"].get("results") if isinstance(observed.get("search"), dict) else []
            result_count = len(results) if isinstance(results, list) else 0
            return {
                "query": query,
                "search_id": created["id"],
                "result_count": result_count,
                "duration_seconds": round(time.monotonic() - started, 3),
                "attempts": attempt,
                "retry_failures": failures,
                "observations": observed.get("observations", [])[-5:],
            }
        except (urllib.error.URLError, ConnectionResetError, TimeoutError) as exc:
            failures.append({"attempt": attempt, "type": type(exc).__name__, "message": str(exc)})
            if attempt >= attempts:
                raise
            time.sleep(min(2.0, 0.25 * attempt))
    raise RuntimeError("unreachable local ED2K search retry state")


def run_search_waves(
    *,
    base_url: str,
    api_key: str,
    waves: int,
    searches_per_wave: int,
    max_concurrent_searches: int,
    timeout_seconds: float,
) -> dict[str, object]:
    """Runs concurrent deterministic local ED2K searches in bounded waves."""

    if waves <= 0 or searches_per_wave <= 0 or max_concurrent_searches <= 0:
        raise ValueError("search waves, searches per wave, and concurrency must be greater than zero.")
    wave_reports: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []
    ordinal = 0
    for wave in range(waves):
        queries = [SOAK_TERMS[(ordinal + offset) % len(SOAK_TERMS)] for offset in range(searches_per_wave)]
        ordinal += searches_per_wave
        rows: list[dict[str, object]] = []
        with ThreadPoolExecutor(max_workers=max_concurrent_searches) as executor:
            futures = [executor.submit(run_one_search, base_url, api_key, query, timeout_seconds) for query in queries]
            for future in as_completed(futures):
                try:
                    row = future.result()
                    rows.append(row)
                    if int(row.get("result_count") or 0) <= 0:
                        failures.append({"wave": wave, "query": row.get("query"), "reason": "zero results"})
                except Exception as exc:
                    failures.append({"wave": wave, "type": type(exc).__name__, "message": str(exc)})
        wave_reports.append(
            {
                "wave": wave,
                "search_count": len(rows),
                "result_count_total": sum(int(row.get("result_count") or 0) for row in rows),
                "max_duration_seconds": max((float(row.get("duration_seconds") or 0) for row in rows), default=0.0),
                "samples": rows[:5],
            }
        )
    if failures:
        raise RuntimeError(f"Local ED2K search soak had failures: {failures[:10]!r}")
    return {
        "waves": wave_reports,
        "total_searches": waves * searches_per_wave,
        "failures": failures,
    }


def trigger_download_from_search_result(
    *,
    base_url: str,
    api_key: str,
    query: str,
    expected_hash: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Finds a deterministic search result and starts it as an active download."""

    created = start_server_search(base_url, api_key, query)
    observed = wait_for_search_results(base_url, api_key, str(created["id"]), timeout_seconds)
    results = observed["search"].get("results") if isinstance(observed.get("search"), dict) else []
    if not isinstance(results, list):
        results = []
    expected = expected_hash.lower()
    candidate = next((row for row in results if isinstance(row, dict) and str(row.get("hash") or "").lower() == expected), None)
    if candidate is None:
        raise RuntimeError(f"Deterministic download result {expected_hash} was not present in search results.")
    response = rest_smoke.http_request(
        base_url,
        f"/api/v1/searches/{created['id']}/results/{expected}/operations/download",
        method="POST",
        api_key=api_key,
        json_body={"paused": False, "categoryId": 0},
        request_timeout_seconds=30.0,
    )
    transfer = rest_smoke.require_json_object(response, 200)
    return {
        "search_id": created["id"],
        "candidate": {
            "hash": candidate.get("hash"),
            "name": candidate.get("name"),
            "sizeBytes": candidate.get("sizeBytes", candidate.get("size")),
            "sources": candidate.get("sources"),
            "completeSources": candidate.get("completeSources"),
        },
        "download": rest_smoke.compact_http_result(response),
        "transfer": transfer,
        "observations": observed.get("observations", [])[-5:],
    }


def main(argv: list[str] | None = None) -> int:
    """Runs the local ED2K search/download soak suite."""

    args = parse_args(argv)
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration=args.configuration,
        workspace_root=None,
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
        "checks": {},
    }
    server_process: subprocess.Popen | None = None
    client1_app = None
    client2_app = None
    current_phase = "initializing"

    try:
        p2p_address = args.p2p_bind_interface_address or dtt.discover_interface_ipv4(args.p2p_bind_interface_name)
        ports = dtt.choose_distinct_ports(args.lan_bind_addr)
        report["network"] = {
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
            "ports": ports,
        }

        current_phase = "prepare_catalog"
        server_dir = paths.source_artifacts_dir / "ed2k-server"
        synthetic_records = build_synthetic_catalog_records(
            args.synthetic_catalog_files,
            source_host=p2p_address,
            source_port=ports["client2_tcp"],
        )
        report["checks"]["synthetic_catalog"] = {
            "path": str(server_dir / "catalog.json"),
            "file_count": len(synthetic_records),
        }

        current_phase = "start_ed2k_server"
        ed2k_server = goed2k.launch_ed2k_server(
            workspace_root=paths.workspace_root,
            server_dir=server_dir,
            ed2k_port=ports["ed2k_tcp"],
            admin_port=ports["ed2k_admin"],
            token=args.api_key,
            admin_address=args.lan_bind_addr,
            catalog_files=synthetic_records,
            repo_override=args.ed2k_server_repo,
            exe_override=args.ed2k_server_exe,
        )
        server_process = ed2k_server.process
        admin_base_url = ed2k_server.admin_base_url
        report["checks"]["server_build"] = ed2k_server.build
        report["checks"]["ed2k_server_health"] = ed2k_server.health
        report["ed2k_server"] = ed2k_server.config

        current_phase = "prepare_profiles"
        client1 = live_common.prepare_scenario_profile(profile_seed_dir, paths.source_artifacts_dir, [], CLIENT01.profile_id)
        client2 = live_common.prepare_scenario_profile(profile_seed_dir, paths.source_artifacts_dir, [], CLIENT02.profile_id)
        client2_app_exe = dtt.resolve_client2_app_exe(paths.workspace_root, args.configuration, args.client2_app_exe)
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
            lan_bind_addr=args.lan_bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
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
        )
        for profile in (client1, client2):
            dtt.write_server_met(
                Path(profile["config_dir"]) / "server.met",
                address=p2p_address,
                port=ports["ed2k_tcp"],
                name="emulebb-local-e2e",
            )
        fixture_file = paths.source_artifacts_dir / "client2-shared" / SOAK_DOWNLOAD_NAME
        fixture_sha256 = dtt.write_fixture_file(fixture_file, args.fixture_size_bytes)
        report["fixture"] = {
            "path": str(fixture_file),
            "name": fixture_file.name,
            "size": args.fixture_size_bytes,
            "sha256": fixture_sha256,
        }

        current_phase = "launch_harness_seed"
        harness_export_dir = paths.source_artifacts_dir / "client2-export"
        harness_export_dir.mkdir(parents=True, exist_ok=True)
        harness_ready_path = harness_export_dir / "ready.txt"
        harness_export_link_path = harness_export_dir / "fixture.ed2k.txt"
        client2_app = live_common.launch_app(
            client2_app_exe,
            Path(client2["profile_base"]),
            minimized_to_tray=True,
            extra_args=dtt.build_client2_harness_args(
                ready_path=harness_ready_path,
                fixture_file=fixture_file,
                export_link_path=harness_export_link_path,
                source_ip=p2p_address,
            ),
        )
        exported_link = dtt.wait_for_exported_link(harness_export_link_path, args.link_export_timeout_seconds)
        link_info = dtt.parse_ed2k_file_link(exported_link)
        transfer_hash = str(link_info["hash"])
        report["checks"]["harness_exported_link"] = {
            "path": str(harness_export_link_path),
            "link": exported_link,
            "parsed": link_info,
        }
        report["checks"]["harness_ready"] = dtt.wait_for_file(harness_ready_path, 30.0, "tracing harness ready file")
        report["checks"]["harness_server_client"] = goed2k.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT02.nick,
            args.server_connect_timeout_seconds,
        )
        report["checks"]["harness_server_file"] = goed2k.wait_for_server_file(
            admin_base_url,
            args.api_key,
            transfer_hash,
            args.server_publish_timeout_seconds,
        )

        current_phase = "launch_emulebb"
        client1_app = live_common.launch_app(paths.app_exe, Path(client1["profile_base"]))
        base_url = f"http://{args.lan_bind_addr}:{ports['client1_rest']}"
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
        report["checks"]["emulebb_server_client"] = goed2k.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT01.nick,
            args.server_connect_timeout_seconds,
        )

        current_phase = "run_search_waves"
        report["checks"]["search_soak"] = run_search_waves(
            base_url=base_url,
            api_key=args.api_key,
            waves=args.search_waves,
            searches_per_wave=args.searches_per_wave,
            max_concurrent_searches=args.max_concurrent_searches,
            timeout_seconds=args.search_timeout_seconds,
        )

        current_phase = "trigger_deterministic_download"
        report["checks"]["download_trigger"] = trigger_download_from_search_result(
            base_url=base_url,
            api_key=args.api_key,
            query=SOAK_DOWNLOAD_NAME,
            expected_hash=transfer_hash,
            timeout_seconds=args.search_timeout_seconds,
        )
        completed_path = Path(client1["incoming_dir"]) / SOAK_DOWNLOAD_NAME
        report["checks"]["download_completion"] = dtt.wait_for_completed_file(
            completed_path,
            expected_size=args.fixture_size_bytes,
            expected_sha256=fixture_sha256,
            timeout_seconds=args.download_timeout_seconds,
        )
        report["checks"]["delete_all_searches"] = rest_smoke.delete_all_searches(base_url, args.api_key)
        report["checks"]["ed2k_server_stats_final"] = goed2k.admin_request(admin_base_url, args.api_key, "/api/stats")
        report["profiles"] = {
            CLIENT01.profile_id: {
                "profile_base": str(client1["profile_base"]),
                "config_dir": str(client1["config_dir"]),
                "incoming_dir": str(client1["incoming_dir"]),
                "temp_dir": str(client1["temp_dir"]),
                "preferences": dtt.read_preferences_snapshot(Path(client1["config_dir"])),
            },
            CLIENT02.profile_id: {
                "profile_base": str(client2["profile_base"]),
                "config_dir": str(client2["config_dir"]),
                "incoming_dir": str(client2["incoming_dir"]),
                "temp_dir": str(client2["temp_dir"]),
                "preferences": dtt.read_preferences_snapshot(Path(client2["config_dir"])),
            },
        }
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["current_phase"] = current_phase
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        if isinstance(exc, dtt.TransferCompletionTimeout):
            report["checks"]["download_completion_timeout"] = {"observations": exc.observations}
        return 1
    finally:
        cleanup: dict[str, object] = {}
        for identity, app in ((CLIENT01, client1_app), (CLIENT02, client2_app)):
            if app is None:
                continue
            try:
                live_common.close_app_cleanly(app)
                cleanup[identity.profile_id] = {"ok": True}
            except Exception as exc:
                cleanup[identity.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        goed2k.stop_process(server_process)
        report["cleanup"] = cleanup
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        report_path = paths.source_artifacts_dir / "local-ed2k-search-soak-result.json"
        harness_cli_common.write_json_file(report_path, report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
