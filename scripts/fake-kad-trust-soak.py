"""Runs a focused live soak for fake-file risk evidence and Kad trust telemetry."""

from __future__ import annotations

import argparse
from collections import Counter
import ctypes
import importlib.util
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import live_wire_inputs
from emule_test_harness.live_seed_sources import EMULE_SECURITY_HOME_URL, refresh_seed_files


def load_local_module(module_name: str, filename: str):
    module_path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


rest_smoke = load_local_module("rest_api_smoke_for_fake_kad_trust_soak", "rest-api-smoke.py")
harness_cli_common = rest_smoke.harness_cli_common
live_common = rest_smoke.live_common

SUITE_NAME = "fake-kad-trust-soak"
LIVE_NETWORK_UNAVAILABLE_EXIT_CODE = 2
DEFAULT_DURATION_SECONDS = 3 * 60 * 60
DEFAULT_SEARCH_OBSERVATION_TIMEOUT_SECONDS = 90.0
DEFAULT_CYCLE_PAUSE_SECONDS = 10.0
DEFAULT_RESOURCE_SAMPLE_INTERVAL_SECONDS = 60.0
KNOWN_FAKE_SEVERITIES = frozenset(("none", "low", "medium", "high", "critical"))


class FILETIME(ctypes.Structure):
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


def filetime_to_seconds(value: FILETIME) -> float:
    ticks = (int(value.dwHighDateTime) << 32) + int(value.dwLowDateTime)
    return ticks / 10_000_000.0


def get_process_cpu_times(process_id: int | None) -> dict[str, object]:
    if not process_id:
        return {"available": False, "reason": "missing process id"}
    handle = rest_smoke.kernel32.OpenProcess(
        rest_smoke.PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        int(process_id),
    )
    if not handle:
        return {"available": False, "reason": "OpenProcess failed"}
    try:
        create_time = FILETIME()
        exit_time = FILETIME()
        kernel_time = FILETIME()
        user_time = FILETIME()
        if not rest_smoke.kernel32.GetProcessTimes(
            handle,
            ctypes.byref(create_time),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            return {"available": False, "reason": "GetProcessTimes failed"}
        kernel_seconds = filetime_to_seconds(kernel_time)
        user_seconds = filetime_to_seconds(user_time)
        return {
            "available": True,
            "kernel_seconds": round(kernel_seconds, 3),
            "user_seconds": round(user_seconds, 3),
            "total_seconds": round(kernel_seconds + user_seconds, 3),
        }
    finally:
        rest_smoke.kernel32.CloseHandle(handle)


def build_kad_trust_hint(kad_publish_info: object) -> dict[str, object]:
    if not isinstance(kad_publish_info, int) or isinstance(kad_publish_info, bool) or kad_publish_info < 0:
        return {
            "valid": False,
            "kind": "invalid",
            "raw": kad_publish_info,
            "publishers": 0,
            "differentNames": 0,
            "trustValueCent": 0,
        }
    different_names = (kad_publish_info >> 24) & 0xFF
    publishers = (kad_publish_info >> 16) & 0xFF
    trust_value_cent = kad_publish_info & 0xFFFF
    if kad_publish_info == 0 or publishers == 0:
        kind = "unknown"
    elif trust_value_cent < 100:
        kind = "low"
    elif trust_value_cent < 300:
        kind = "normal"
    else:
        kind = "high"
    return {
        "valid": True,
        "kind": kind,
        "raw": kad_publish_info,
        "publishers": publishers,
        "differentNames": different_names,
        "trustValueCent": trust_value_cent,
    }


def _list_of_strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def validate_fake_report(row: dict[str, Any]) -> tuple[list[str], dict[str, object]]:
    errors: list[str] = []
    fake = row.get("fakeFile")
    if not isinstance(fake, dict):
        return ["missing fakeFile object"], {"score": None, "severity": "missing", "reasons": []}

    score = fake.get("score")
    severity = str(fake.get("severity") or "")
    reasons = _list_of_strings(fake.get("reasons"))
    canonical_names = _list_of_strings(fake.get("canonicalNames"))
    ignored_tokens = _list_of_strings(fake.get("ignoredNameTokens"))
    divergence_groups = _list_of_strings(fake.get("nameDivergenceGroups"))

    if not isinstance(score, int) or isinstance(score, bool) or score < 0 or score > 100:
        errors.append(f"invalid fake score {score!r}")
    if severity not in KNOWN_FAKE_SEVERITIES:
        errors.append(f"invalid fake severity {severity!r}")
    if isinstance(score, int) and not isinstance(score, bool):
        if score == 0 and severity != "none":
            errors.append(f"zero score has non-none severity {severity!r}")
        if score > 0 and severity == "none":
            errors.append("positive score has none severity")
        if score > 0 and not reasons and not bool(fake.get("pendingHeaderCheck")):
            errors.append("positive score has no reasons")
    if "multiple_names" in reasons and len(divergence_groups) < 2:
        errors.append("multiple_names reason has fewer than two divergence groups")
    if fake.get("canonicalNames") is None:
        errors.append("missing canonicalNames")
    if fake.get("ignoredNameTokens") is None:
        errors.append("missing ignoredNameTokens")
    if fake.get("nameDivergenceGroups") is None:
        errors.append("missing nameDivergenceGroups")
    for token in ignored_tokens:
        if token != token.lower():
            errors.append(f"ignored token is not normalized: {token!r}")
            break

    return errors, {
        "score": score,
        "severity": severity,
        "reasons": reasons,
        "pendingHeaderCheck": bool(fake.get("pendingHeaderCheck")),
        "canonicalNames": canonical_names,
        "ignoredNameTokens": ignored_tokens,
        "nameDivergenceGroups": divergence_groups,
    }


def summarize_result_rows(rows: list[Any]) -> dict[str, object]:
    metrics: dict[str, object] = {
        "row_count": 0,
        "unique_hash_count": 0,
        "missing_hash_count": 0,
        "invalid_rows": [],
        "fake_score_buckets": Counter(),
        "fake_severity_counts": Counter(),
        "fake_reason_counts": Counter(),
        "fake_pending_header_count": 0,
        "canonical_name_rows": 0,
        "ignored_token_rows": 0,
        "name_divergence_rows": 0,
        "kad_trust_counts": Counter(),
        "kad_publish_info_rows": 0,
        "kad_publishers_max": 0,
        "kad_different_names_max": 0,
        "kad_trust_value_cent_max": 0,
        "sample_risky_rows": [],
        "sample_invalid_rows": [],
    }
    hashes: set[str] = set()
    invalid_rows: list[dict[str, object]] = []
    risky_samples: list[dict[str, object]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            invalid_rows.append({"index": index, "errors": ["row is not an object"]})
            continue
        metrics["row_count"] = int(metrics["row_count"]) + 1
        row_hash = row.get("hash")
        if isinstance(row_hash, str) and row_hash:
            hashes.add(row_hash.lower())
        else:
            metrics["missing_hash_count"] = int(metrics["missing_hash_count"]) + 1

        fake_errors, fake = validate_fake_report(row)
        if fake_errors:
            invalid_rows.append(
                {
                    "index": index,
                    "hash": row_hash,
                    "name": row.get("name"),
                    "errors": fake_errors,
                }
            )
        score = fake.get("score")
        if isinstance(score, int) and not isinstance(score, bool):
            if score == 0:
                bucket = "0"
            elif score < 25:
                bucket = "1-24"
            elif score < 50:
                bucket = "25-49"
            elif score < 75:
                bucket = "50-74"
            else:
                bucket = "75-100"
            metrics["fake_score_buckets"][bucket] += 1
            if score > 0 and len(risky_samples) < 10:
                risky_samples.append(
                    {
                        "hash": row_hash,
                        "name": row.get("name"),
                        "score": score,
                        "severity": fake.get("severity"),
                        "reasons": fake.get("reasons"),
                        "canonicalNames": fake.get("canonicalNames"),
                        "nameDivergenceGroups": fake.get("nameDivergenceGroups"),
                    }
                )
        metrics["fake_severity_counts"][str(fake.get("severity"))] += 1
        for reason in fake.get("reasons") or []:
            metrics["fake_reason_counts"][str(reason)] += 1
        if bool(fake.get("pendingHeaderCheck")):
            metrics["fake_pending_header_count"] = int(metrics["fake_pending_header_count"]) + 1
        if fake.get("canonicalNames"):
            metrics["canonical_name_rows"] = int(metrics["canonical_name_rows"]) + 1
        if fake.get("ignoredNameTokens"):
            metrics["ignored_token_rows"] = int(metrics["ignored_token_rows"]) + 1
        if fake.get("nameDivergenceGroups"):
            metrics["name_divergence_rows"] = int(metrics["name_divergence_rows"]) + 1

        kad_hint = build_kad_trust_hint(row.get("kadPublishInfo"))
        metrics["kad_trust_counts"][str(kad_hint["kind"])] += 1
        if bool(kad_hint["valid"]) and int(kad_hint["raw"]) != 0:
            metrics["kad_publish_info_rows"] = int(metrics["kad_publish_info_rows"]) + 1
            metrics["kad_publishers_max"] = max(int(metrics["kad_publishers_max"]), int(kad_hint["publishers"]))
            metrics["kad_different_names_max"] = max(int(metrics["kad_different_names_max"]), int(kad_hint["differentNames"]))
            metrics["kad_trust_value_cent_max"] = max(int(metrics["kad_trust_value_cent_max"]), int(kad_hint["trustValueCent"]))
    metrics["unique_hash_count"] = len(hashes)
    metrics["invalid_rows"] = invalid_rows
    metrics["invalid_row_count"] = len(invalid_rows)
    metrics["sample_invalid_rows"] = invalid_rows[:10]
    metrics["sample_risky_rows"] = risky_samples
    for key in ("fake_score_buckets", "fake_severity_counts", "fake_reason_counts", "kad_trust_counts"):
        metrics[key] = dict(sorted(metrics[key].items()))
    return metrics


def merge_result_metrics(total: dict[str, object], increment: dict[str, object]) -> None:
    for scalar_key in (
        "row_count",
        "unique_hash_count",
        "missing_hash_count",
        "fake_pending_header_count",
        "canonical_name_rows",
        "ignored_token_rows",
        "name_divergence_rows",
        "kad_publish_info_rows",
    ):
        total[scalar_key] = int(total.get(scalar_key, 0)) + int(increment.get(scalar_key, 0))
    for max_key in ("kad_publishers_max", "kad_different_names_max", "kad_trust_value_cent_max"):
        total[max_key] = max(int(total.get(max_key, 0)), int(increment.get(max_key, 0)))
    for counter_key in ("fake_score_buckets", "fake_severity_counts", "fake_reason_counts", "kad_trust_counts"):
        counter = Counter(total.get(counter_key, {}))
        counter.update(Counter(increment.get(counter_key, {})))
        total[counter_key] = dict(sorted(counter.items()))
    invalid = list(total.get("invalid_rows", []))
    invalid.extend(increment.get("invalid_rows", []))
    total["invalid_rows"] = invalid
    total["invalid_row_count"] = len(invalid)
    risky = list(total.get("sample_risky_rows", []))
    risky.extend(increment.get("sample_risky_rows", []))
    total["sample_risky_rows"] = risky[:10]


def observe_search_until_terminal(
    base_url: str,
    api_key: str,
    search_id: str,
    timeout_seconds: float,
    poll_interval_seconds: float,
) -> dict[str, object]:
    observations: list[dict[str, object]] = []
    deadline = time.time() + timeout_seconds
    last_payload: dict[str, Any] | None = None
    while time.time() < deadline:
        result = rest_smoke.http_request(base_url, f"/api/v1/searches/{search_id}", api_key=api_key)
        if int(result["status"]) == 200 and isinstance(result.get("json"), dict):
            payload = rest_smoke.require_json_object(result, 200)
            rows = payload.get("results")
            if not isinstance(rows, list):
                rows = []
            last_payload = payload
            observations.append(
                {
                    "observed_at": round(time.time(), 3),
                    "status": payload.get("status"),
                    "result_count": len(rows),
                }
            )
            if payload.get("status") == "complete":
                break
        time.sleep(poll_interval_seconds)
    if last_payload is None:
        raise RuntimeError(f"Search {search_id} did not return a readable payload.")
    rows = last_payload.get("results")
    if not isinstance(rows, list):
        rows = []
    return {
        "payload": last_payload,
        "rows": rows,
        "observations": observations,
        "terminal_state": last_payload.get("status"),
    }


def collect_resource_sample(process_id: int | None, label: str) -> dict[str, object]:
    return {
        "label": label,
        "observed_at": round(time.time(), 3),
        "resources": rest_smoke.get_process_resource_snapshot(process_id),
        "cpu": get_process_cpu_times(process_id),
    }


def run_soak(args: argparse.Namespace) -> int:
    if args.duration_seconds <= 0:
        raise ValueError("--duration-seconds must be greater than zero.")
    if args.cycle_pause_seconds < 0:
        raise ValueError("--cycle-pause-seconds must be zero or greater.")
    if args.search_observation_timeout_seconds <= 0:
        raise ValueError("--search-observation-timeout-seconds must be greater than zero.")
    if args.resource_sample_interval_seconds <= 0:
        raise ValueError("--resource-sample-interval-seconds must be greater than zero.")

    inputs = live_wire_inputs.load_live_wire_inputs(
        live_wire_inputs.resolve_inputs_path(REPO_ROOT, args.live_wire_inputs_file)
    )
    search_terms = inputs.generic_open_terms
    if not search_terms:
        raise RuntimeError("Fake/Kad trust soak requires at least one generic_open live search term.")

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
    seed_config_dir = harness_cli_common.resolve_profile_seed_dir(paths, args.profile_seed_dir)
    artifacts_dir = paths.source_artifacts_dir
    port = rest_smoke.choose_listen_port()
    base_url = f"http://127.0.0.1:{port}"
    profile = live_common.prepare_profile_base(seed_config_dir, artifacts_dir, shared_dirs=[])
    seed_refresh = None
    if not args.skip_live_seed_refresh:
        seed_refresh = refresh_seed_files(
            Path(profile["config_dir"]),
            timeout_seconds=args.seed_download_timeout_seconds,
        )
    rest_smoke.configure_webserver_profile(
        Path(profile["config_dir"]),
        paths.app_exe,
        args.api_key,
        port,
        "127.0.0.1",
    )
    if args.p2p_bind_interface_name:
        rest_smoke.apply_p2p_bind_interface_override(Path(profile["config_dir"]), args.p2p_bind_interface_name)

    app = None
    process_id = None
    active_search_id: str | None = None
    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "failed",
        "base_url": base_url,
        "launch_inputs": {
            "app_exe": str(paths.app_exe),
            "profile_base": str(profile["profile_base"]),
            "config_dir": str(profile["config_dir"]),
            "seed_config_dir": str(seed_config_dir),
            "live_seed_source_url": EMULE_SECURITY_HOME_URL,
            "live_seed_refresh": seed_refresh,
            "duration_seconds": args.duration_seconds,
            "cycle_pause_seconds": args.cycle_pause_seconds,
            "search_observation_timeout_seconds": args.search_observation_timeout_seconds,
            "resource_sample_interval_seconds": args.resource_sample_interval_seconds,
            "min_result_rows": args.min_result_rows,
            "min_kad_publish_info_rows": args.min_kad_publish_info_rows,
            "require_kad_connected": bool(args.require_kad_connected),
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "live_wire_inputs_file": str(inputs.path),
            "live_wire_search_terms": live_wire_inputs.summarize_terms(search_terms),
        },
        "checks": {},
        "cycles": [],
        "resource_samples": [],
        "aggregate": {
            "row_count": 0,
            "unique_hash_count": 0,
            "missing_hash_count": 0,
            "fake_pending_header_count": 0,
            "canonical_name_rows": 0,
            "ignored_token_rows": 0,
            "name_divergence_rows": 0,
            "kad_publish_info_rows": 0,
            "kad_publishers_max": 0,
            "kad_different_names_max": 0,
            "kad_trust_value_cent_max": 0,
            "fake_score_buckets": {},
            "fake_severity_counts": {},
            "fake_reason_counts": {},
            "kad_trust_counts": {},
            "invalid_rows": [],
            "invalid_row_count": 0,
            "sample_risky_rows": [],
        },
        "cleanup": {},
    }
    pending_error: Exception | None = None
    start_time = time.time()
    next_resource_sample_at = start_time

    try:
        app = live_common.launch_app(paths.app_exe, Path(profile["profile_base"]))
        process_id = rest_smoke.get_app_process_id(app)
        report["launched_process_id"] = process_id
        report["resource_samples"].append(collect_resource_sample(process_id, "after_launch"))

        ready = rest_smoke.wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        report["checks"]["ready"] = rest_smoke.compact_http_result(ready)

        kad_connect = rest_smoke.http_request(
            base_url,
            "/api/v1/kad/operations/start",
            method="POST",
            api_key=args.api_key,
            json_body={},
        )
        report["checks"]["kad_connect"] = rest_smoke.compact_http_result(kad_connect)
        rest_smoke.require_json_object(kad_connect, 200)
        report["checks"]["kad_running"] = rest_smoke.wait_for_kad_running(
            base_url,
            args.api_key,
            args.kad_running_timeout_seconds,
        )
        if args.require_kad_connected:
            report["checks"]["kad_connected"] = rest_smoke.wait_for_requested_networks(
                base_url,
                args.api_key,
                args.network_ready_timeout_seconds,
                require_server_connected=False,
                require_kad_connected=True,
            )

        end_time = start_time + args.duration_seconds
        cycle_index = 0
        completed_cycles = 0
        failed_cycles = 0
        zero_result_cycles = 0
        while time.time() < end_time:
            cycle_index += 1
            cycle_start = time.time()
            query_index = (cycle_index - 1) % len(search_terms)
            query = search_terms[query_index]
            cycle: dict[str, object] = {
                "cycle": cycle_index,
                "query_index": query_index,
                "started_at": round(cycle_start, 3),
                "status": "failed",
            }
            try:
                start = rest_smoke.start_live_search(
                    base_url,
                    args.api_key,
                    mode="kad",
                    query=query,
                    forced_method="kad",
                )
                cycle["start"] = {
                    "ok": bool(start.get("ok")),
                    "selected_method": start.get("selected_method"),
                    "response": rest_smoke.compact_http_result(start.get("response")),
                }
                if not bool(start.get("ok")):
                    failed_cycles += 1
                    cycle["failure_reason"] = "search start failed"
                    continue
                response = start.get("response")
                assert isinstance(response, dict)
                payload = rest_smoke.require_json_object(response, 200)
                active_search_id = str(payload["id"])
                cycle["searchId"] = active_search_id

                remaining = max(1.0, end_time - time.time())
                observed = observe_search_until_terminal(
                    base_url,
                    args.api_key,
                    active_search_id,
                    min(args.search_observation_timeout_seconds, remaining),
                    args.search_poll_interval_seconds,
                )
                rows = observed["rows"]
                assert isinstance(rows, list)
                result_metrics = summarize_result_rows(rows)
                merge_result_metrics(report["aggregate"], result_metrics)
                if int(result_metrics["row_count"]) == 0:
                    zero_result_cycles += 1
                completed_cycles += 1
                cycle.update(
                    {
                        "status": "passed",
                        "duration_seconds": round(time.time() - cycle_start, 3),
                        "terminal_state": observed.get("terminal_state"),
                        "observations": observed.get("observations"),
                        "result_metrics": {
                            key: value
                            for key, value in result_metrics.items()
                            if key not in {"invalid_rows", "sample_risky_rows"}
                        },
                    }
                )
            except Exception as exc:
                failed_cycles += 1
                cycle["status"] = "failed"
                cycle["error"] = {"type": type(exc).__name__, "message": str(exc)}
            finally:
                if active_search_id is not None:
                    try:
                        stop = rest_smoke.stop_live_search(base_url, args.api_key, active_search_id)
                        cycle["stop"] = rest_smoke.compact_http_result(stop)
                    except Exception as exc:
                        cycle["stop_error"] = {"type": type(exc).__name__, "message": str(exc)}
                    active_search_id = None
                try:
                    delete_all = rest_smoke.delete_all_searches(base_url, args.api_key)
                    cycle["delete_all_searches"] = rest_smoke.compact_http_result(delete_all)
                except Exception as exc:
                    cycle["delete_all_searches_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["cycles"].append(cycle)

            if time.time() >= next_resource_sample_at:
                report["resource_samples"].append(collect_resource_sample(process_id, f"cycle_{cycle_index}"))
                next_resource_sample_at = time.time() + args.resource_sample_interval_seconds

            remaining = end_time - time.time()
            if remaining <= 0:
                break
            time.sleep(min(args.cycle_pause_seconds, remaining))

        report["summary"] = {
            "duration_seconds": round(time.time() - start_time, 3),
            "attempted_cycles": cycle_index,
            "completed_cycles": completed_cycles,
            "failed_cycles": failed_cycles,
            "zero_result_cycles": zero_result_cycles,
        }
        aggregate = report["aggregate"]
        failure_reasons: list[str] = []
        if completed_cycles <= 0:
            failure_reasons.append("no completed Kad search cycles")
        if failed_cycles > args.max_failed_cycles:
            failure_reasons.append(f"failed cycles exceeded limit: {failed_cycles} > {args.max_failed_cycles}")
        if int(aggregate.get("row_count", 0)) < args.min_result_rows:
            failure_reasons.append(
                f"result rows below minimum: {aggregate.get('row_count')} < {args.min_result_rows}"
            )
        if int(aggregate.get("kad_publish_info_rows", 0)) < args.min_kad_publish_info_rows:
            failure_reasons.append(
                "Kad publish-info rows below minimum: "
                f"{aggregate.get('kad_publish_info_rows')} < {args.min_kad_publish_info_rows}"
            )
        if int(aggregate.get("invalid_row_count", 0)) > 0:
            failure_reasons.append(f"invalid result rows observed: {aggregate.get('invalid_row_count')}")
        report["failure_reasons"] = failure_reasons
        report["status"] = "passed" if not failure_reasons else "failed"
    except Exception as exc:
        pending_error = exc
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        cleanup = report["cleanup"]
        assert isinstance(cleanup, dict)
        if active_search_id is not None:
            try:
                cleanup["active_search_stop"] = rest_smoke.compact_http_result(
                    rest_smoke.stop_live_search(base_url, args.api_key, active_search_id)
                )
            except Exception as exc:
                cleanup["active_search_stop_error"] = {"type": type(exc).__name__, "message": str(exc)}
        if app is not None:
            try:
                cleanup["delete_all_searches"] = rest_smoke.compact_http_result(
                    rest_smoke.delete_all_searches(base_url, args.api_key)
                )
            except Exception as exc:
                cleanup["delete_all_searches_error"] = {"type": type(exc).__name__, "message": str(exc)}
            try:
                cleanup["kad_disconnect"] = rest_smoke.compact_http_result(
                    rest_smoke.http_request(
                        base_url,
                        "/api/v1/kad/operations/stop",
                        method="POST",
                        api_key=args.api_key,
                        json_body={},
                    )
                )
            except Exception as exc:
                cleanup["kad_disconnect_error"] = {"type": type(exc).__name__, "message": str(exc)}
            report["resource_samples"].append(collect_resource_sample(process_id, "before_close"))
            if args.keep_running and report["status"] == "passed":
                cleanup["app_closed"] = False
                cleanup["app_left_running"] = True
            else:
                try:
                    cleanup.update(rest_smoke.close_app_cleanly_with_timing(app))
                except Exception as exc:
                    cleanup["app_closed"] = False
                    cleanup["app_close_error"] = {"type": type(exc).__name__, "message": str(exc)}
                    if pending_error is None:
                        pending_error = exc
                        report["status"] = "failed"
                        report["error"] = {"type": type(exc).__name__, "message": str(exc)}

        live_common.write_json(artifacts_dir / "result.json", report)
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)

    print(f"Fake/Kad trust soak {report['status']}. Report directory: {paths.run_report_dir}")
    if pending_error is not None:
        raise pending_error
    return 0 if report["status"] == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--configuration", default="Release", choices=("Debug", "Release"))
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--api-key", default="emule-bb-rest-test-key")
    parser.add_argument("--duration-seconds", type=float, default=DEFAULT_DURATION_SECONDS)
    parser.add_argument("--cycle-pause-seconds", type=float, default=DEFAULT_CYCLE_PAUSE_SECONDS)
    parser.add_argument("--search-observation-timeout-seconds", type=float, default=DEFAULT_SEARCH_OBSERVATION_TIMEOUT_SECONDS)
    parser.add_argument("--search-poll-interval-seconds", type=float, default=5.0)
    parser.add_argument("--resource-sample-interval-seconds", type=float, default=DEFAULT_RESOURCE_SAMPLE_INTERVAL_SECONDS)
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--kad-running-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--network-ready-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--seed-download-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--live-wire-inputs-file")
    parser.add_argument("--p2p-bind-interface-name", default="hide.me")
    parser.add_argument("--min-result-rows", type=int, default=1)
    parser.add_argument("--min-kad-publish-info-rows", type=int, default=1)
    parser.add_argument("--max-failed-cycles", type=int, default=0)
    parser.add_argument("--require-kad-connected", action="store_true")
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    return parser


def main() -> int:
    return run_soak(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
