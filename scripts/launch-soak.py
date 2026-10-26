"""Launch the rust<->MFC soak environment against the persistent profiles.

A pure launcher: it brings up emulebb-rust (diagnostics) and the MFC diagnostics
GUI on selected persistent profiles (same operator eD2K server, same nodes.dat
bootstrap, same shared library roots), then idles until Ctrl-C. Drive the clients
through their REST APIs; both diagnostics builds write segmented
``diag_event_v2`` runs continuously into the persistent profile dirs, while
bounded Rust diagnostic bundles are captured into the campaign evidence store.

No test/diff logic lives here. Analysis runs separately from this repo
(``analyze-packet-coverage.py``, ``diag_event_diff``, or the live observer
``converged-soak-live.py``) over the captured dumps when you ask for it.

REST control binds X_LOCAL_IP for split-tunnel or loopback for full-tunnel;
P2P binds the hide.me tunnel. The Rust
diagnostics binary is the distinctly-named ``emulebb-rust-diagnostics.exe`` (build
it with ``python -m emule_workspace build clients --client emulebb-rust
--diagnostics``).

GENTLE LIVE DISCIPLINE: you drive the pace by hand; keep searches few and widely
spaced, and confirm before starting a live campaign.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import converged_live_wire as clw
from emule_test_harness import bounded_process_output, cpu_profile, live_process_monitor
from emule_test_harness import mfc_profile_import, profile_overlay
from emule_test_harness import persisted_soak_controller
from emule_test_harness import soak_launch, soak_run_layout, soak_storage
from emule_test_harness.kad_nodes import DEFAULT_NODES_DAT_URL, fetch_bootstrap_endpoints
from emule_test_harness.live_wire_inputs import LiveWireInputs, load_live_wire_inputs
from emule_test_harness.paths import get_workspace_output_root
from emule_test_harness.rust_client import request_ctrl_c, stop_process_tree
from emule_test_harness.soak_launch import (
    DEFAULT_MFC_SEED_CONFIG_DIR,
    DEFAULT_SERVER_MET_URL,
    MFC_ED2K_PORT,
    MFC_API_KEY,
    MFC_KAD_PORT,
    MFC_SERVER_UDP_PORT,
    OPERATOR_SERVER,
    RUST_ED2K_PORT,
    RUST_API_KEY,
    RUST_KAD_PORT,
    bring_up_mfc,
    bring_up_rust,
    log,
)
from emule_test_harness.vm_guest_profiles import api_data, retry_http_json

DEFAULT_PROFILE_SECONDS = 300.0
DEFAULT_PROCESS_SAMPLE_INTERVAL_SECONDS = 2.0


@dataclass(frozen=True)
class PeriodicBundleCaptureSchedule:
    """Monotonic low-cadence schedule for campaign-owned diagnostic bundles."""

    interval_seconds: float
    next_capture_monotonic: float

    @classmethod
    def start(
        cls,
        *,
        interval_seconds: float,
        now_monotonic: float,
    ) -> PeriodicBundleCaptureSchedule:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive.")
        return cls(
            interval_seconds=interval_seconds,
            next_capture_monotonic=now_monotonic + interval_seconds,
        )

    def is_due(self, now_monotonic: float) -> bool:
        return now_monotonic >= self.next_capture_monotonic

    def after_capture(self, now_monotonic: float) -> PeriodicBundleCaptureSchedule:
        return type(self).start(
            interval_seconds=self.interval_seconds,
            now_monotonic=now_monotonic,
        )


def required_storage_policy(inputs: LiveWireInputs) -> soak_storage.SoakStoragePolicy:
    """Returns the mandatory aggregate persisted-soak storage policy."""

    if inputs.soak_storage is None:
        raise RuntimeError("Persisted soaks require soak_storage in the live-wire inputs.")
    return inputs.soak_storage


def required_daemon_output_policy(inputs: LiveWireInputs) -> soak_storage.ArtifactStreamPolicy:
    """Returns the mandatory bounded Rust daemon-output policy."""

    return required_storage_policy(inputs).stream("daemon_output")


def required_rust_diagnostic_writer_policy(
    inputs: LiveWireInputs,
) -> soak_storage.RustDiagnosticWriterPolicy:
    """Returns the mandatory bounded Rust profile-writer policy."""

    return required_storage_policy(inputs).rust_diagnostics


def campaign_artifact_store(
    run_paths: soak_run_layout.SoakRunPaths,
    storage_policy: soak_storage.SoakStoragePolicy,
) -> soak_storage.BoundedArtifactStore:
    """Returns the store whose exclusive deletion authority is campaigns/."""

    return soak_storage.BoundedArtifactStore(
        run_paths.campaigns_root,
        storage_policy,
    )


def capture_rust_diagnostic_bundle(
    *,
    base_url: str,
    run_paths: soak_run_layout.SoakRunPaths,
    storage_policy: soak_storage.SoakStoragePolicy,
    phase: str,
    now_ns: int | None = None,
) -> dict[str, object]:
    """Captures one inline Rust bundle into the bounded campaign-owned stream."""

    response = retry_http_json(
        f"rust diagnostic bundle ({phase})",
        3,
        base_url,
        "/api/v1/diagnostics/bundles",
        api_key=RUST_API_KEY,
        method="POST",
        body={"confirmCapture": True},
        timeout_seconds=30.0,
    )
    bundle = api_data(response)
    if not isinstance(bundle, dict):
        raise RuntimeError("Rust diagnostic bundle response data must be an object.")
    if bundle.get("schema") != "emulebb.diagnostic-bundle.v4":
        raise RuntimeError(
            "Rust diagnostic bundle response must use emulebb.diagnostic-bundle.v4."
        )
    summary = bundle.get("summary")
    if not isinstance(summary, dict):
        raise RuntimeError("Rust diagnostic bundle response is missing its summary.")

    persisted = soak_storage.persist_bounded_json_artifact(
        store=campaign_artifact_store(run_paths, storage_policy),
        active_campaign=run_paths.campaign_dir,
        directory=run_paths.diagnostic_bundles_dir,
        stream_name="diagnostic_bundles",
        stem="rust-diagnostic-bundle",
        payload=bundle,
        now_ns=now_ns,
    )
    return {
        "phase": phase,
        "bundleSchema": bundle["schema"],
        "bundleCapturedAt": bundle.get("capturedAt"),
        "bundleSummary": summary,
        "path": str(persisted.path),
        "byteCount": persisted.byte_count,
        "sha256": persisted.sha256,
        "deletedPaths": [str(path) for path in persisted.deleted_paths],
        "retainedCount": persisted.retained_count,
        "retainedBytes": persisted.retained_bytes,
    }


def record_diagnostic_bundle_capture(
    captures: list[dict[str, object]],
    capture: dict[str, object],
) -> None:
    """Keeps manifest evidence aligned with the retained bundle ring."""

    deleted_paths = capture.get("deletedPaths")
    if not isinstance(deleted_paths, list) or any(
        not isinstance(path, str) for path in deleted_paths
    ):
        raise RuntimeError("Diagnostic bundle capture deletedPaths must be a string list.")
    deleted = set(deleted_paths)
    captures[:] = [item for item in captures if item.get("path") not in deleted]
    captures.append(capture)

    retained_count = capture.get("retainedCount")
    if (
        isinstance(retained_count, bool)
        or not isinstance(retained_count, int)
        or retained_count < 1
    ):
        raise RuntimeError("Diagnostic bundle capture retainedCount must be positive.")
    if len(captures) > retained_count:
        raise RuntimeError(
            "Diagnostic bundle manifest inventory exceeds the retained bundle count."
        )


def raise_rust_output_failure(rust_handles: dict | None) -> None:
    """Fails the launch loop when asynchronous Rust output capture failed."""

    if rust_handles is None:
        return
    capture = rust_handles.get("outputCapture")
    if capture is not None:
        capture.raise_if_failed()


def daemon_output_manifest(
    run_paths: soak_run_layout.SoakRunPaths,
    policy: soak_storage.ArtifactStreamPolicy,
) -> dict[str, object]:
    """Returns exact bounded Rust daemon-output evidence for the run manifest."""

    return {
        "path": str(run_paths.rust_daemon_output),
        "maxSegmentBytes": policy.max_segment_bytes,
        "retainedSegments": policy.retained_segments,
        "exactBytes": True,
        "stderr": "merged",
    }


def resolve_direct_mfc_profile(inputs: LiveWireInputs, *, no_mfc: bool) -> Path | None:
    """Returns the operator-owned MFC profile used for the soak launcher."""

    if no_mfc or inputs.mfc_profile_dir is None:
        return None
    return inputs.mfc_profile_dir.resolve()


def resolve_direct_rust_profile(inputs: LiveWireInputs) -> Path:
    """Returns the operator-owned Rust profile used for the soak launcher."""

    if inputs.rust_profile_dir is None:
        raise RuntimeError("live-wire inputs must define rust_profile.profile_dir for live soak runs.")
    return inputs.rust_profile_dir.resolve()


def enforce_post_import_profile_storage_guard(
    *,
    args: argparse.Namespace,
    inputs: LiveWireInputs,
    profile_dir: Path,
    storage_policy: soak_storage.SoakStoragePolicy,
) -> dict[str, object] | None:
    """Checks persisted profile authority after import and before either client starts."""

    authority_values = (
        args.rust_profile_storage_baseline_file_count,
        args.rust_profile_storage_baseline_bytes,
        args.rust_profile_storage_baseline_free_bytes,
        args.rust_profile_storage_baseline_measured_path,
        args.rust_profile_storage_volume_identity,
    )
    if all(value is None for value in authority_values):
        return None
    if any(value is None for value in authority_values):
        raise RuntimeError("Persisted Rust profile storage authority is incomplete.")
    integer_values = authority_values[:3]
    if any(not isinstance(value, int) or value < 0 for value in integer_values):
        raise RuntimeError("Persisted Rust profile storage authority values are invalid.")
    if not isinstance(args.rust_profile_storage_baseline_measured_path, Path):
        raise RuntimeError("Persisted Rust profile storage measured path is invalid.")
    if not isinstance(args.rust_profile_storage_volume_identity, str) or not args.rust_profile_storage_volume_identity:
        raise RuntimeError("Persisted Rust profile storage volume identity is invalid.")
    policy = persisted_soak_controller.required_rust_profile_guard(inputs)
    persisted_soak_controller.validate_rust_profile_guard_capacity(policy, storage_policy)
    context = persisted_soak_controller.RustProfileGuardContext(
        profile_dir=profile_dir.resolve(),
        policy=policy,
        baseline_file_count=args.rust_profile_storage_baseline_file_count,
        baseline_total_bytes=args.rust_profile_storage_baseline_bytes,
        baseline_free_bytes=args.rust_profile_storage_baseline_free_bytes,
        baseline_measured_path=args.rust_profile_storage_baseline_measured_path.resolve(),
        volume_identity=args.rust_profile_storage_volume_identity,
    )
    result = persisted_soak_controller.enforce_rust_profile_guard(context)
    if result["ok"] is not True:
        violations = ", ".join(result["violations"])
        raise RuntimeError(
            "Persisted Rust profile storage guard failed after profile import: "
            f"{violations}. Imported profile state was preserved."
        )
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--inputs",
        help="live-wire-inputs.local.json (shared roots). Default: repo-root copy.",
    )
    parser.add_argument(
        "--campaign-id",
        help="Controller-assigned UTC YYYYMMDDTHHMMSSZ campaign identity; generated when omitted.",
    )
    parser.add_argument(
        "--lan-bind-addr",
        required=True,
        help="REST/control bind IP: X_LOCAL_IP for split-tunnel, 127.0.0.1 for full-tunnel.",
    )
    parser.add_argument(
        "--vpn-topology",
        choices=soak_launch.VPN_TOPOLOGIES,
        default="split-tunnel",
        help="hide.me routing topology; full-tunnel is read-only and requires split tunneling disabled.",
    )
    parser.add_argument("--rust-rest-port", type=int, default=4731)
    parser.add_argument(
        "--rust-profile-dir",
        type=Path,
        help="Override rust_profile.profile_dir with an existing profile below the workspace output root.",
    )
    parser.add_argument("--mfc-rest-port", type=int, default=4732)
    parser.add_argument("--rust-ed2k-port", type=int, default=RUST_ED2K_PORT)
    parser.add_argument("--rust-kad-port", type=int, default=RUST_KAD_PORT)
    parser.add_argument("--mfc-ed2k-port", type=int, default=MFC_ED2K_PORT)
    parser.add_argument("--mfc-kad-port", type=int, default=MFC_KAD_PORT)
    parser.add_argument("--mfc-server-udp-port", type=int, default=MFC_SERVER_UDP_PORT)
    parser.add_argument("--rust-server", default=OPERATOR_SERVER, help="eD2K server endpoint for Rust, host:port.")
    parser.add_argument(
        "--rust-fallback-server",
        action="append",
        default=[],
        help="Explicit Rust-only fallback eD2K server endpoint, host:port. May be repeated.",
    )
    parser.add_argument("--mfc-server", default=OPERATOR_SERVER, help="eD2K server endpoint for MFC, host:port.")
    parser.add_argument("--no-mfc", action="store_true", help="Do not launch the MFC diagnostics GUI.")
    parser.add_argument(
        "--rust-regular",
        action="store_true",
        help=(
            "Run the plain-release emulebb-rust.exe (no packet-diagnostics feature, "
            "no packet/diag dumps) instead of the diagnostics flavor. Build it with "
            "'python -m emule_workspace build clients --client emulebb-rust'."
        ),
    )
    parser.add_argument("--no-obfuscation", action="store_true", help="Disable protocol obfuscation on both clients.")
    parser.add_argument("--nodes-url", default=DEFAULT_NODES_DAT_URL, help="Kad nodes.dat URL (same source for both).")
    parser.add_argument(
        "--reuse-kad-bootstrap",
        action="store_true",
        help="Reuse existing Rust profile Kad bootstrap endpoints instead of downloading nodes.dat.",
    )
    parser.add_argument("--server-met-url", default=DEFAULT_SERVER_MET_URL, help="server.met URL for rust import (empty to skip).")
    parser.add_argument(
        "--single-rust-server",
        action="store_true",
        help="Replace the Rust profile server list with only --rust-server before launch.",
    )
    parser.add_argument("--bootstrap-limit", type=int, default=40)
    parser.add_argument("--rest-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--connect-timeout-seconds", type=float, default=240.0)
    parser.add_argument(
        "--reuse-rust-shared-profile",
        action="store_true",
        help="Do not PATCH Rust shared directories; reuse the existing persistent Rust profile state.",
    )
    parser.add_argument("--rust-profile-storage-baseline-file-count", type=int)
    parser.add_argument("--rust-profile-storage-baseline-bytes", type=int)
    parser.add_argument("--rust-profile-storage-baseline-free-bytes", type=int)
    parser.add_argument("--rust-profile-storage-baseline-measured-path", type=Path)
    parser.add_argument("--rust-profile-storage-volume-identity")
    parser.add_argument(
        "--vpn-guard-live-config",
        help="Ignored local VPN Guard config; required when --vpn-guard-scenario is not off.",
    )
    parser.add_argument(
        "--vpn-guard-allowed-public-ip-cidrs",
        default="",
        help="Approved public VPN CIDR allowlist; defaults to the VPN Guard live config value.",
    )
    parser.add_argument(
        "--vpn-guard-scenario",
        choices=("off", "success"),
        default="off",
        help="Set to success for public live-wire runs; off is only for explicit guard-off scenarios.",
    )
    parser.add_argument("--cpu-profile", action="store_true", help="Run the soak under bounded ETW sampled CPU profiling.")
    parser.add_argument("--cpu-profile-seconds", type=float, default=DEFAULT_PROFILE_SECONDS)
    parser.add_argument("--cpu-profile-max-file-mb", type=int, default=cpu_profile.DEFAULT_CPU_PROFILE_MAX_FILE_MB)
    parser.add_argument("--cpu-profile-stack", action="store_true", help="Export a symbolized xperf stack butterfly report.")
    parser.add_argument("--cpu-profile-stack-min-hits", type=int, default=10)
    parser.add_argument(
        "--cpu-profile-symbols-optional",
        action="store_true",
        help="Continue when the staged app-local PDB is absent.",
    )
    parser.add_argument(
        "--process-metrics",
        action="store_true",
        help="Sample Rust process CPU and memory metrics even when ETW CPU profiling is disabled.",
    )
    parser.add_argument("--process-sample-interval", type=float, default=DEFAULT_PROCESS_SAMPLE_INTERVAL_SECONDS)
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=0.0,
        help="Stop the soak after this many seconds with the same graceful teardown path as Ctrl-C.",
    )
    parser.add_argument(
        "--stop-file",
        type=Path,
        help="Stop an until-stopped soak gracefully when this output-root control file appears.",
    )
    parser.add_argument(
        "--rust-shutdown-trigger",
        choices=("rest", "ctrl-c"),
        default="rest",
        help="Graceful Rust shutdown trigger used at the end of the soak.",
    )
    parser.add_argument("--profile-seed-dir", help="MFC profile seed config directory.")
    parser.add_argument("--mfc-variant", default=clw.DEFAULT_MFC_VARIANT)
    parser.add_argument("--mfc-arch", default=clw.DEFAULT_MFC_ARCH)
    parser.add_argument("--mfc-configuration", default=clw.DEFAULT_MFC_CONFIGURATION)
    return parser


def resolve_vpn_guard_profile(args: argparse.Namespace) -> dict[str, str | None]:
    """Resolves the VPN Guard mode and approved CIDRs for one launcher run."""

    if args.vpn_guard_scenario == "off":
        if args.vpn_topology == "full-tunnel":
            raise RuntimeError(
                "Full-tunnel soaks require --vpn-guard-scenario success so both clients start in Block mode."
            )
        return {"mode": "off", "allowed_public_ip_cidrs": "", "config_path": None}

    config_path = Path(args.vpn_guard_live_config).resolve() if args.vpn_guard_live_config else None
    if config_path is None:
        raise RuntimeError("--vpn-guard-live-config is required for --vpn-guard-scenario success.")
    return soak_launch.require_blocking_vpn_guard_config(
        config_path,
        allowed_public_ip_cidrs=args.vpn_guard_allowed_public_ip_cidrs,
    )


def initialize_cpu_profile(
    *,
    args: argparse.Namespace,
    run_paths: soak_run_layout.SoakRunPaths,
    rust_exe: Path,
) -> tuple[cpu_profile.CpuProfileTools | None, cpu_profile.CpuProfilePaths | None, dict[str, object] | None]:
    """Starts ETW CPU profiling when requested and returns the mutable report."""

    if not args.cpu_profile:
        return None, None, None
    if args.cpu_profile_seconds <= 0:
        raise RuntimeError("--cpu-profile-seconds must be greater than zero.")
    if args.cpu_profile_max_file_mb <= 0:
        raise RuntimeError("--cpu-profile-max-file-mb must be greater than zero.")
    if args.cpu_profile_stack_min_hits <= 0:
        raise RuntimeError("--cpu-profile-stack-min-hits must be greater than zero.")

    profile_paths = cpu_profile.build_cpu_profile_paths(run_paths.report_dir)
    profile_report: dict[str, object] = {
        "enabled": True,
        "tool": "xperf",
        "app_exe": str(rust_exe),
        "profile_paths": {
            "etl": str(profile_paths.etl_path),
            "detail": str(profile_paths.detail_path),
            "summary": str(profile_paths.summary_path),
            "stack": str(profile_paths.stack_path),
        },
        "max_file_mb": args.cpu_profile_max_file_mb,
        "seconds": args.cpu_profile_seconds,
        "stack": bool(args.cpu_profile_stack),
        "stack_min_hits": args.cpu_profile_stack_min_hits,
    }
    tools = cpu_profile.discover_cpu_profile_tools()
    if not tools.xperf:
        profile_report["status"] = "failed"
        profile_report["error"] = "xperf was not found."
        return tools, profile_paths, profile_report

    pdb_path = cpu_profile.resolve_app_pdb_path(rust_exe)
    profile_report["symbols"] = {"app_pdb": str(pdb_path), "app_pdb_exists": pdb_path.is_file()}
    if not args.cpu_profile_symbols_optional and not pdb_path.is_file():
        profile_report["status"] = "failed"
        profile_report["error"] = f"Required app symbols were not found: {pdb_path}"
        return tools, profile_paths, profile_report

    start = cpu_profile.start_cpu_profile(
        tools=tools,
        paths=profile_paths,
        max_file_mb=args.cpu_profile_max_file_mb,
        timeout_seconds=30.0,
    )
    profile_report["start"] = start
    return tools, profile_paths, profile_report


def finalize_cpu_profile(
    *,
    tools: cpu_profile.CpuProfileTools | None,
    paths: cpu_profile.CpuProfilePaths | None,
    report: dict[str, object] | None,
    rust_exe: Path,
    extra_process_images: list[str] | None = None,
    include_stack: bool,
    stack_min_hits: int,
) -> dict[str, object] | None:
    """Stops and exports ETW CPU profiling when it was started."""

    if tools is None or paths is None or report is None:
        return report
    if not tools.xperf:
        return report
    if report.get("status") == "failed" and "start" not in report:
        return report

    stop = cpu_profile.stop_cpu_profile(tools=tools, paths=paths, timeout_seconds=60.0)
    report["stop"] = stop
    if report.get("start", {}).get("return_code") == 0 and stop.get("return_code") == 0 and paths.etl_path.is_file():
        export = cpu_profile.export_cpu_profile(
            tools=tools,
            paths=paths,
            app_exe=rust_exe,
            timeout_seconds=90.0,
            include_stack=include_stack,
            stack_min_hits=stack_min_hits,
        )
        detail_summary = cpu_profile.parse_xperf_profile_detail_file(paths.detail_path, process_image=rust_exe.name)
        details_by_process = {rust_exe.name: detail_summary}
        for process_image in extra_process_images or []:
            details_by_process[process_image] = cpu_profile.parse_xperf_profile_detail_file(
                paths.detail_path,
                process_image=process_image,
            )
        stack_summary = (
            cpu_profile.parse_xperf_stack_report_file(paths.stack_path)
            if include_stack
            else {"available": False, "reason": "stack export disabled"}
        )
        combined_summary = {"detail": detail_summary, "detail_by_process": details_by_process, "stack": stack_summary}
        paths.summary_path.parent.mkdir(parents=True, exist_ok=True)
        paths.summary_path.write_text(json.dumps(combined_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        report["export"] = export
        report["summary"] = combined_summary
        report["status"] = "passed" if detail_summary.get("available") or stack_summary.get("available") else "failed"
    else:
        report["status"] = "failed"
    return report


class RustProcessMetrics:
    """Persists bounded samples and an O(1)-memory cumulative summary."""

    SUMMARY_FIELDS = (
        "working_set_mb",
        "private_mb",
        "peak_working_set_mb",
        "process_pct_one_core",
        "handles",
    )

    def __init__(
        self,
        *,
        process,
        report_dir: Path,
        interval_seconds: float,
        storage_policy: soak_storage.SoakStoragePolicy,
        label: str = "rust",
    ) -> None:
        self.process = process
        self.report_dir = report_dir
        self.interval_seconds = interval_seconds
        self.label = label
        self.started = time.monotonic()
        self.last_sample_monotonic: float | None = None
        self.last_cpu_seconds: float | None = None
        self.next_sample = 0.0
        self.sample_count = 0
        self.first: dict[str, object] | None = None
        self.last: dict[str, object] | None = None
        self.minimums: dict[str, float] = {}
        self.maximums: dict[str, float] = {}
        self.handle: int | None = None
        self.samples_path = report_dir / "analysis" / f"{label}-process-metrics.jsonl"
        self.summary_path = report_dir / "analysis" / f"{label}-process-metrics-summary.json"
        stream_policy = storage_policy.stream("process_metrics")
        self.summary_policy = storage_policy.stream("process_metrics_summary")
        if self.summary_policy.retained_segments != 1:
            raise RuntimeError(
                "process_metrics_summary must retain exactly one artifact."
            )
        self.samples = bounded_process_output.RotatingBinaryLog(
            self.samples_path,
            max_segment_bytes=stream_policy.max_segment_bytes,
            retained_segments=stream_policy.retained_segments,
        )
        self.handle = live_process_monitor.open_process(process.pid)

    def maybe_sample(self) -> dict[str, object] | None:
        now = time.monotonic()
        if self.handle is None or now < self.next_sample:
            return None
        row = live_process_monitor.sample_process_metrics(
            handle=self.handle,
            started_monotonic=self.started,
            last_sample_monotonic=self.last_sample_monotonic,
            last_cpu_seconds=self.last_cpu_seconds,
        )
        row["pid"] = self.process.pid
        self.record_sample(row)
        self.last_sample_monotonic = time.monotonic()
        self.last_cpu_seconds = float(row["cpu_seconds"])
        self.next_sample = now + self.interval_seconds
        return row

    def record_sample(self, row: dict[str, object]) -> None:
        """Persists one complete sample and advances cumulative aggregates."""

        encoded = (
            json.dumps(
                row,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        self.samples.write_record(encoded)
        copied = dict(row)
        if self.first is None:
            self.first = copied
        self.last = copied
        self.sample_count += 1
        for name in self.SUMMARY_FIELDS:
            value = row.get(name)
            if value is None:
                continue
            numeric = float(value)
            self.minimums[name] = min(self.minimums.get(name, numeric), numeric)
            self.maximums[name] = max(self.maximums.get(name, numeric), numeric)
        self.write_summary()

    def metric_summary(self) -> dict[str, object]:
        """Returns the cumulative summary without retaining individual rows."""

        if self.first is None or self.last is None:
            return {"sample_count": 0}
        summary: dict[str, object] = {
            "sample_count": self.sample_count,
            "first": self.first,
            "last": self.last,
        }
        for name in self.SUMMARY_FIELDS:
            if (
                name not in self.minimums
                or self.first.get(name) is None
                or self.last.get(name) is None
            ):
                continue
            summary[name] = {
                "min": self.minimums[name],
                "max": self.maximums[name],
                "delta": round(
                    float(self.last[name]) - float(self.first[name]),
                    3,
                ),
            }
        return summary

    def write_summary(self) -> dict[str, object]:
        summary = self.metric_summary()
        payload = {
            "schema": "emulebb-build-tests.process-metrics-summary.v1",
            "enabled": True,
            "label": self.label,
            "pid": self.process.pid,
            "samplesPath": str(self.samples_path),
            "retention": {
                "maxSegmentBytes": self.samples.max_segment_bytes,
                "retainedSegments": self.samples.retained_segments,
            },
            "summary": summary,
        }
        encoded = (
            json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        if len(encoded) > self.summary_policy.max_segment_bytes:
            raise RuntimeError(
                f"process_metrics_summary requires {len(encoded)} bytes, exceeding "
                f"its {self.summary_policy.max_segment_bytes}-byte limit."
            )
        self.summary_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.summary_path.with_name(f".{self.summary_path.name}.tmp")
        for candidate in (self.summary_path, temporary):
            if candidate.is_symlink():
                raise RuntimeError(
                    f"Process metrics summary path must not be a symlink: {candidate}"
                )
            if candidate.exists() and not candidate.is_file():
                raise RuntimeError(
                    f"Process metrics summary path must be a file: {candidate}"
                )
        temporary.unlink(missing_ok=True)
        try:
            with temporary.open("xb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            if temporary.stat().st_size != len(encoded):
                raise OSError(
                    f"Short process metrics summary write: expected {len(encoded)} bytes, "
                    f"wrote {temporary.stat().st_size}."
                )
            temporary.replace(self.summary_path)
        finally:
            temporary.unlink(missing_ok=True)
        return payload

    def close(self) -> None:
        try:
            self.samples.close()
        finally:
            if self.handle is not None:
                live_process_monitor.close_handle(self.handle)
                self.handle = None


def graceful_teardown(
    *,
    rust_handles: dict | None,
    mfc_handles: dict | None,
    live_common,
    rust_base: str,
    rust_shutdown_trigger: str = "rest",
    wait_seconds: float = 15.0,
) -> dict[str, object]:
    """Stops everything the launcher started, gracefully, with a bounded fallback.

    Asks each component to stop cleanly (rust via ``POST /api/v1/app/shutdown`` →
    its graceful network teardown; the MFC GUI via ``close_app_cleanly`` → the
    eMule save-and-exit path that persists known.met), then waits up to
    ``wait_seconds`` for the processes to exit before force-killing any straggler.
    A second Ctrl-C during the wait jumps straight to the kill.
    """

    started = time.monotonic()
    summary: dict[str, object] = {
        "trigger": rust_shutdown_trigger,
        "requestAttempted": False,
        "requestSucceeded": False,
        "forced": False,
        "exitCode": None,
    }
    if rust_handles is not None and rust_handles["process"].poll() is None:
        summary["requestAttempted"] = True
        try:
            if rust_shutdown_trigger == "ctrl-c":
                log("rust: requesting graceful shutdown via Ctrl-C...")
                request_ctrl_c(rust_handles["process"])
            else:
                log("rust: requesting graceful shutdown (POST /api/v1/app/shutdown)...")
                retry_http_json(
                    "rust shutdown", 1, rust_base, "/api/v1/app/shutdown",
                    api_key=RUST_API_KEY, method="POST", body={"confirmShutdown": True}, timeout_seconds=5.0,
                )
            summary["requestSucceeded"] = True
        except Exception as error:  # noqa: BLE001 - cleanup must continue to the bounded fallback
            summary["requestError"] = f"{type(error).__name__}: {error}"
    if mfc_handles is not None and mfc_handles.get("app") is not None:
        log("MFC: closing the diagnostics GUI cleanly...")
        try:
            live_common.close_app_cleanly(mfc_handles["app"])
        except Exception:  # noqa: BLE001
            try:
                mfc_handles["app"].kill()
            except Exception:  # noqa: BLE001
                pass
    watched = [
        proc
        for proc in (rust_handles["process"] if rust_handles is not None else None,)
        if proc is not None
    ]
    deadline = time.monotonic() + wait_seconds
    try:
        while time.monotonic() < deadline and any(proc.poll() is None for proc in watched):
            time.sleep(0.5)
    except KeyboardInterrupt:
        log("second interrupt - force-killing now.")

    if rust_handles is not None:
        if rust_handles["process"].poll() is None:
            log("rust did not exit in time - force-killing.")
            summary["forced"] = True
            stop_process_tree(rust_handles["process"])
        summary["exitCode"] = rust_handles["process"].poll()
        log_handle = rust_handles.get("logHandle")
        if log_handle is not None:
            try:
                log_handle.close()
            except Exception:  # noqa: BLE001
                pass
        output_capture = rust_handles.get("outputCapture")
        if output_capture is not None:
            try:
                output_capture.close()
                output_capture.raise_if_failed()
            except Exception as error:  # noqa: BLE001 - output integrity participates in teardown health
                summary["outputError"] = f"{type(error).__name__}: {error}"
    summary["elapsedSeconds"] = round(time.monotonic() - started, 3)
    summary["clean"] = bool(
        summary["requestSucceeded"]
        and not summary["forced"]
        and summary["exitCode"] == 0
        and "outputError" not in summary
    )
    return summary

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.duration_seconds < 0:
        raise RuntimeError("--duration-seconds must not be negative.")
    if args.rest_timeout_seconds <= 0:
        raise RuntimeError("--rest-timeout-seconds must be greater than zero.")
    if args.connect_timeout_seconds <= 0:
        raise RuntimeError("--connect-timeout-seconds must be greater than zero.")
    obfuscation = not args.no_obfuscation
    endpoint_ports = soak_launch.require_distinct_endpoint_ports(
        rust_ed2k_port=args.rust_ed2k_port,
        rust_kad_port=args.rust_kad_port,
        mfc_ed2k_port=args.mfc_ed2k_port,
        mfc_kad_port=args.mfc_kad_port,
        mfc_server_udp_port=args.mfc_server_udp_port,
    )
    soak_launch.require_operator_server_endpoint(args.rust_server, label="--rust-server")
    soak_launch.require_operator_server_endpoint(args.mfc_server, label="--mfc-server")
    for index, endpoint in enumerate(args.rust_fallback_server, start=1):
        soak_launch.require_live_server_endpoint(endpoint, label=f"--rust-fallback-server #{index}")
    if args.rust_fallback_server and not args.no_mfc:
        raise RuntimeError("--rust-fallback-server is Rust-only; pass --no-mfc for fallback server probes.")
    vpn_guard_profile = resolve_vpn_guard_profile(args)

    rest_addr = soak_launch.resolve_lan_rest_bind_addr(
        args.lan_bind_addr,
        vpn_topology=args.vpn_topology,
    )
    output_root = get_workspace_output_root()
    stop_file = args.stop_file.resolve() if args.stop_file is not None else None
    if stop_file is not None:
        try:
            stop_file.relative_to(output_root)
        except ValueError as error:
            raise RuntimeError(f"--stop-file must be below EMULEBB_WORKSPACE_OUTPUT_ROOT: {stop_file}") from error
        if stop_file.exists():
            raise RuntimeError(f"--stop-file already exists; remove the stale stop request before launch: {stop_file}")

    rust_exe = (
        clw.resolve_rust_regular_exe(output_root)
        if args.rust_regular
        else clw.resolve_rust_diagnostics_exe(output_root)
    )
    mfc_exe = None
    if not args.no_mfc:
        mfc_exe = clw.resolve_mfc_diagnostics_exe(
            output_root, variant=args.mfc_variant, arch=args.mfc_arch, configuration=args.mfc_configuration
        )

    mods = soak_launch.load_helper_modules("launcher")
    rust_mod = mods["rust"]

    inputs_path = Path(args.inputs).resolve() if args.inputs else REPO_ROOT / "live-wire-inputs.local.json"
    if not inputs_path.is_file():
        raise RuntimeError(f"live-wire inputs not found: {inputs_path} (pass --inputs).")
    inputs = load_live_wire_inputs(inputs_path)
    storage_policy = required_storage_policy(inputs)
    daemon_output_policy = required_daemon_output_policy(inputs)
    rust_diagnostic_writer_policy = required_rust_diagnostic_writer_policy(inputs)
    direct_mfc_profile = resolve_direct_mfc_profile(inputs, no_mfc=args.no_mfc)
    if args.rust_profile_dir is not None:
        rust_profile_dir = args.rust_profile_dir.resolve()
    else:
        rust_profile_dir = resolve_direct_rust_profile(inputs)
    rust_profile_location = soak_launch.require_rust_profile_location(
        rust_profile_dir,
        output_root=output_root,
        vpn_topology=args.vpn_topology,
    )
    vpn_clients = [("rust", "eMuleBB Rust", rust_exe)]
    if not args.no_mfc:
        vpn_clients.append(("mfc", "eMuleBB MFC", mfc_exe))
    log(f"preparing hide.me {args.vpn_topology} routing...")
    vpn_routing = soak_launch.prepare_hideme_routing(args.vpn_topology, vpn_clients)
    bind_ip = str(vpn_routing["bindIp"])
    log(f"hide.me {args.vpn_topology} routing ready")

    source_mfc_profile = inputs.mfc_profile_dir.resolve() if inputs.mfc_profile_dir is not None else None
    rust_profile_setup = mfc_profile_import.ensure_persisted_rust_profile(
        rust_repo=REPO_ROOT.parent / "emulebb-rust",
        mfc_profile_dir=source_mfc_profile,
        rust_profile_dir=rust_profile_dir,
        kad_bootstrap_limit=args.bootstrap_limit,
        rest_addr=rest_addr,
        rest_port=args.rust_rest_port,
        api_key=RUST_API_KEY,
        p2p_bind_interface="hide.me",
        ed2k_port=args.rust_ed2k_port,
        kad_port=args.rust_kad_port,
    )
    post_import_profile_guard = enforce_post_import_profile_storage_guard(
        args=args,
        inputs=inputs,
        profile_dir=rust_profile_dir,
        storage_policy=storage_policy,
    )
    shared_roots = rust_mod.load_shared_roots(inputs_path)
    if not shared_roots:
        raise RuntimeError("No shared_directories.roots in the live-wire inputs - nothing to share.")

    soak_root = output_root / "soak"
    campaign_id = (
        soak_run_layout.validate_campaign_id(args.campaign_id)
        if args.campaign_id
        else soak_run_layout.utc_campaign_id()
    )
    mfc_artifacts = soak_root / "mfc-profile"
    mfc_log_dir = None if args.no_mfc else soak_run_layout.mfc_soak_log_dir(
        mfc_artifacts_dir=mfc_artifacts,
        direct_profile_dir=direct_mfc_profile,
    )
    run_paths = soak_run_layout.build_run_paths(soak_root, campaign_id)
    artifact_store = campaign_artifact_store(run_paths, storage_policy)
    preflight_manifest = soak_run_layout.prepare_clean_run(
        paths=run_paths,
        rust_profile_dir=rust_profile_dir,
        rust_packet_dump_dir=rust_profile_dir / "packet-dump",
        mfc_log_dir=mfc_log_dir,
        artifact_store=artifact_store,
    )
    preflight_manifest["daemonOutput"] = daemon_output_manifest(run_paths, daemon_output_policy)
    diagnostic_bundle_policy = storage_policy.stream("diagnostic_bundles")
    preflight_manifest["rustDiagnosticBundles"] = {
        "path": str(run_paths.diagnostic_bundles_dir.resolve()),
        "intervalSeconds": storage_policy.bundle_interval_seconds,
        "policy": {
            "maxSegmentBytes": diagnostic_bundle_policy.max_segment_bytes,
            "retainedSegments": diagnostic_bundle_policy.retained_segments,
        },
    }
    preflight_manifest["rustDiagnosticWriter"] = {
        "enabled": not args.rust_regular,
        "path": str((rust_profile_dir / "packet-dump").resolve()),
        "policy": (
            soak_storage.rust_diagnostic_writer_policy_payload(
                rust_diagnostic_writer_policy
            )
            if not args.rust_regular
            else None
        ),
    }
    preflight_manifest["rustProfileStorageGuard"] = post_import_profile_guard
    soak_run_layout.write_last_run_manifest(run_paths, preflight_manifest)
    mfc_overlay_journal = soak_root / "transactions" / "mfc-preferences"
    mfc_preferences_path = (
        direct_mfc_profile / "config" / "preferences.ini"
        if direct_mfc_profile is not None
        else None
    )
    mfc_overlay_recovery = (
        profile_overlay.recover_file_overlay(
            target=mfc_preferences_path,
            journal_dir=mfc_overlay_journal,
        )
        if mfc_preferences_path is not None
        else {"enabled": False, "status": "not-operator-profile"}
    )
    log(
        "preflight cleanup archived "
        f"{preflight_manifest['preflightCleanup']['rust']['archivedCount']} rust file(s) and "
        f"{preflight_manifest['preflightCleanup']['mfc']['archivedCount']} MFC log file(s); "
        "promoted "
        f"{preflight_manifest['preflightCleanup']['diagnosticSegments']['promotedCount']} "
        "diagnostic segment(s)"
    )
    if direct_mfc_profile is not None:
        log(f"MFC direct profile from live-wire inputs: {direct_mfc_profile}")
    log(
        f"rust profile {rust_profile_setup['mode']}: {rust_profile_dir} - "
        f"sharing {len(shared_roots)} library root(s)"
    )
    if vpn_guard_profile["mode"] == "block":
        log(
            "VPN Guard enabled for hide.me with CIDRs: "
            + str(vpn_guard_profile["allowed_public_ip_cidrs"])
        )
    log(
        "P2P endpoint ports: "
        f"rust TCP {endpoint_ports['rust']['ed2kTcpPort']}/UDP {endpoint_ports['rust']['kadUdpPort']}; "
        f"MFC TCP {endpoint_ports['mfc']['ed2kTcpPort']}/UDP {endpoint_ports['mfc']['kadUdpPort']}"
    )

    if args.reuse_kad_bootstrap:
        bootstrap_nodes = []
        log("Kad bootstrap: reusing existing Rust profile endpoints")
    else:
        bootstrap_nodes = fetch_bootstrap_endpoints(args.nodes_url, limit=args.bootstrap_limit)
        log(f"Kad bootstrap from {args.nodes_url}: {len(bootstrap_nodes)} contacts")

    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else DEFAULT_MFC_SEED_CONFIG_DIR
    timeouts = {"rest": args.rest_timeout_seconds, "connect": args.connect_timeout_seconds}

    rust_handles: dict | None = None
    mfc_handles: dict | None = None
    rust_base = ""
    profile_tools: cpu_profile.CpuProfileTools | None = None
    profile_paths: cpu_profile.CpuProfilePaths | None = None
    profile_report: dict[str, object] | None = None
    process_metrics: RustProcessMetrics | None = None
    status = "stopped"
    failure: dict[str, object] | None = None
    shutdown_report: dict[str, object] | None = None
    diagnostic_bundle_captures: list[dict[str, object]] = []
    mfc_preferences_overlay: profile_overlay.FileOverlay | None = None
    mfc_overlay_restore: dict[str, object] | None = None
    try:
        if mfc_preferences_path is not None:
            mfc_preferences_overlay = profile_overlay.begin_file_overlay(
                target=mfc_preferences_path,
                journal_dir=mfc_overlay_journal,
            )
        profile_tools, profile_paths, profile_report = initialize_cpu_profile(
            args=args,
            run_paths=run_paths,
            rust_exe=rust_exe,
        )
        rust_handles = bring_up_rust(
            rust_mod=rust_mod, exe_path=rust_exe, bind_ip=bind_ip, rest_addr=rest_addr,
            rest_port=args.rust_rest_port, profile_dir=rust_profile_dir,
            packet_dump_dir=rust_profile_dir / "packet-dump", incoming_dir=rust_profile_dir / "incoming",
            bootstrap_nodes=bootstrap_nodes,
            shared_roots=shared_roots, server_met_url=args.server_met_url,
            server_endpoint=args.rust_server, obfuscation=obfuscation, timeouts=timeouts,
            ed2k_port=args.rust_ed2k_port, kad_port=args.rust_kad_port,
            enable_packet_dump=not args.rust_regular,
            apply_shared_directories=not args.reuse_rust_shared_profile,
            ctrl_c_shutdown=args.rust_shutdown_trigger == "ctrl-c",
            replace_servers=args.single_rust_server,
            fallback_server_endpoints=list(args.rust_fallback_server),
            vpn_guard_mode=str(vpn_guard_profile["mode"]),
            vpn_guard_allowed_public_ip_cidrs=str(vpn_guard_profile["allowed_public_ip_cidrs"] or ""),
            daemon_output_path=run_paths.rust_daemon_output,
            daemon_output_policy=daemon_output_policy,
            diagnostic_writer_policy=(
                rust_diagnostic_writer_policy if not args.rust_regular else None
            ),
        )
        rust_proc = rust_handles["process"]
        rust_base = rust_handles["baseUrl"]
        if args.cpu_profile or args.process_metrics:
            process_metrics = RustProcessMetrics(
                process=rust_proc,
                report_dir=run_paths.report_dir,
                interval_seconds=args.process_sample_interval,
                storage_policy=storage_policy,
                label="rust",
            )

        mfc_base = ""
        if not args.no_mfc:
            mfc_handles = bring_up_mfc(
                live_common=mods["live_common"], rest_smoke=mods["rest_smoke"],
                shared_dirs_mod=mods["shared_dirs"], exe_path=mfc_exe,
                seed_config_dir=seed_config_dir, artifacts_dir=mfc_artifacts,
                direct_profile_dir=direct_mfc_profile,
                rest_host=rest_addr, rest_port=args.mfc_rest_port, shared_roots=shared_roots,
                server_endpoint=args.mfc_server, obfuscation=obfuscation, timeouts=timeouts,
                ed2k_port=args.mfc_ed2k_port, kad_port=args.mfc_kad_port,
                server_udp_port=args.mfc_server_udp_port,
                vpn_guard_mode=str(vpn_guard_profile["mode"]),
                vpn_guard_allowed_public_ip_cidrs=str(vpn_guard_profile["allowed_public_ip_cidrs"] or ""),
            )
            mfc_base = mfc_handles["baseUrl"]

        record_diagnostic_bundle_capture(
            diagnostic_bundle_captures,
            capture_rust_diagnostic_bundle(
                base_url=rust_base,
                run_paths=run_paths,
                storage_policy=storage_policy,
                phase="ready",
            ),
        )
        bundle_capture_schedule = PeriodicBundleCaptureSchedule.start(
            interval_seconds=storage_policy.bundle_interval_seconds,
            now_monotonic=time.monotonic(),
        )
        soak_run_layout.mark_run_running(
            run_paths,
            extra={
                "rustDiagnosticWriterHealth": rust_handles.get(
                    "diagnosticWriterHealth"
                ),
                "rustDiagnosticBundles": diagnostic_bundle_captures,
            },
        )

        log("=" * 70)
        log("SOAK ENVIRONMENT UP. Drive searches/downloads through REST automation:")
        log(f"  emulebb-rust REST : {rust_base}   (X-API-Key: {RUST_API_KEY})")
        if not args.no_mfc:
            log(f"  MFC diagnostics   : {mfc_base}   (X-API-Key: {MFC_API_KEY}) + its GUI window")
        log(f"  operator server   : {OPERATOR_SERVER}")
        log(
            "Bounded event rings remain under the persistent profiles; "
            "bounded diagnostic bundles are campaign-owned."
        )
        if args.cpu_profile:
            log(f"Profiling for {args.cpu_profile_seconds:.0f}s; artifacts: {run_paths.report_dir / 'analysis'}")
        log("Press Ctrl-C to stop everything (profiles + bounded campaign evidence are kept).")
        log("=" * 70)

        duration_deadline = time.monotonic() + args.duration_seconds if args.duration_seconds > 0 else None
        profile_deadline = time.monotonic() + args.cpu_profile_seconds if args.cpu_profile and duration_deadline is None else None
        last_metrics_log = 0.0
        while True:
            raise_rust_output_failure(rust_handles)
            if rust_proc.poll() is not None:
                log("rust daemon exited - stopping.")
                status = "rust-exited"
                break
            if stop_file is not None and stop_file.exists():
                log("stop file observed - stopping all launched apps gracefully...")
                status = "stop-requested"
                break
            row = process_metrics.maybe_sample() if process_metrics is not None else None
            if row is not None and time.monotonic() - last_metrics_log >= 30.0:
                log(
                    "rust metrics: "
                    f"cpu_one_core={row['process_pct_one_core']}% "
                    f"private={row['private_mb']}MiB ws={row['working_set_mb']}MiB "
                    f"handles={row['handles']}"
                )
                last_metrics_log = time.monotonic()
            loop_now = time.monotonic()
            if profile_deadline is not None and loop_now >= profile_deadline:
                log("CPU profile window complete - stopping.")
                status = "profile-complete"
                break
            if duration_deadline is not None and loop_now >= duration_deadline:
                log("duration window complete - stopping.")
                status = "duration-complete"
                break
            if bundle_capture_schedule.is_due(loop_now):
                periodic_capture = capture_rust_diagnostic_bundle(
                    base_url=rust_base,
                    run_paths=run_paths,
                    storage_policy=storage_policy,
                    phase="periodic",
                )
                record_diagnostic_bundle_capture(
                    diagnostic_bundle_captures,
                    periodic_capture,
                )
                log(f"captured periodic Rust diagnostic bundle: {periodic_capture['path']}")
                bundle_capture_schedule = bundle_capture_schedule.after_capture(
                    time.monotonic()
                )
            time.sleep(2.0)
    except KeyboardInterrupt:
        log("Ctrl-C - stopping all launched apps gracefully...")
    except Exception as exc:
        status = "failed"
        failure = {
            "type": type(exc).__name__,
            "message": str(exc) or repr(exc),
            "traceback": traceback.format_exc(),
        }
        log(f"soak launch failed: {failure['type']}: {failure['message']}")
    finally:
        if (
            rust_handles is not None
            and rust_base
            and rust_handles["process"].poll() is None
        ):
            try:
                record_diagnostic_bundle_capture(
                    diagnostic_bundle_captures,
                    capture_rust_diagnostic_bundle(
                        base_url=rust_base,
                        run_paths=run_paths,
                        storage_policy=storage_policy,
                        phase="final",
                    ),
                )
            except Exception as exc:  # noqa: BLE001 - teardown and evidence must continue
                status = "failed"
                bundle_failure = {
                    "type": type(exc).__name__,
                    "message": f"Final Rust diagnostic bundle capture failed: {exc}",
                }
                if failure is None:
                    failure = bundle_failure
                else:
                    failure["diagnosticBundleCapture"] = bundle_failure
        profile_report = finalize_cpu_profile(
            tools=profile_tools,
            paths=profile_paths,
            report=profile_report,
            rust_exe=rust_exe,
            include_stack=args.cpu_profile_stack,
            stack_min_hits=args.cpu_profile_stack_min_hits,
        )
        process_metrics_summary = None
        if process_metrics is not None:
            try:
                process_metrics_summary = process_metrics.write_summary()
            finally:
                process_metrics.close()
        shutdown_report = graceful_teardown(
            rust_handles=rust_handles,
            mfc_handles=mfc_handles,
            live_common=mods["live_common"],
            rust_base=rust_base,
            rust_shutdown_trigger=args.rust_shutdown_trigger,
        )
        if mfc_preferences_overlay is not None:
            try:
                mfc_overlay_restore = mfc_preferences_overlay.restore()
            except Exception as exc:  # noqa: BLE001 - report restore failure after process cleanup
                status = "failed"
                failure = {
                    "type": type(exc).__name__,
                    "message": f"MFC preferences restore failed: {exc}",
                    "traceback": traceback.format_exc(),
                }
        if args.rust_shutdown_trigger == "ctrl-c" and not shutdown_report.get("clean"):
            status = "failed"
            if failure is None:
                failure = {
                    "type": "CtrlCShutdownError",
                    "message": f"Ctrl-C shutdown was not clean: {shutdown_report}",
                }
    soak_run_layout.mark_run_finished(
        run_paths,
        status=status,
        extra={
            "rustProfileDir": str(rust_profile_dir),
            "rustProfileLocation": rust_profile_location,
            "rustProfileSetup": rust_profile_setup,
            "rustProfileStorageGuard": post_import_profile_guard,
            "mfcProfileOverlay": {
                "enabled": mfc_preferences_path is not None,
                "target": str(mfc_preferences_path) if mfc_preferences_path is not None else None,
                "journalDir": str(mfc_overlay_journal) if mfc_preferences_path is not None else None,
                "recovery": mfc_overlay_recovery,
                "restore": mfc_overlay_restore,
            },
            "mfcArtifactsDir": str(mfc_artifacts),
            "rustExe": str(rust_exe),
            "rustServer": args.rust_server,
            "rustFallbackServers": list(args.rust_fallback_server),
            "durationSeconds": args.duration_seconds,
            "stopFile": str(stop_file) if stop_file is not None else None,
            "reuseRustSharedProfile": bool(args.reuse_rust_shared_profile),
            "shutdown": shutdown_report,
            "error": failure,
            "vpnRouting": vpn_routing,
            "vpnGuard": vpn_guard_profile,
            "cpuProfile": profile_report,
            "processMetrics": process_metrics_summary,
            "rustDiagnosticWriterHealth": (
                rust_handles.get("diagnosticWriterHealth")
                if rust_handles is not None
                else None
            ),
            "rustDiagnosticBundles": diagnostic_bundle_captures,
        },
    )
    log("soak environment stopped; bounded campaign evidence preserved under " + str(soak_root))
    return 1 if status == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
