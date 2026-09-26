"""Launch a local Rust daemon and gate its live responses against OpenAPI.

This is the CI-owned counterpart to ``check-rust-rest-openapi-responses.py``.
It creates a fresh external profile, keeps ED2K/Kad disabled, binds REST only to
loopback, runs the shared live response + SSE conformance checks, and always
tears the daemon down while retaining a machine-readable report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import rust_client, rust_metadata, rust_rest_conformance  # noqa: E402
from emule_test_harness.paths import get_required_emule_workspace_root, get_workspace_output_root  # noqa: E402
from emule_test_harness.vm_guest_profiles import http_json, wait_until  # noqa: E402

API_KEY = "rust-rest-openapi-ci"
REST_ADDR = "127.0.0.1"


def staged_executable(output_root: Path) -> Path:
    """Returns the orchestrator-staged regular daemon for this host OS."""

    suffix = ".exe" if os.name == "nt" else ""
    return output_root / "tools" / "emulebb-rust" / "bin" / f"emulebb-rust{suffix}"


def choose_loopback_port() -> int:
    """Reserves an ephemeral loopback port long enough to select its number."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((REST_ADDR, 0))
        return int(listener.getsockname()[1])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_revision(rust_repo: Path) -> str:
    """Returns the CI revision, falling back to the checked-out Rust HEAD."""

    ci_revision = os.environ.get("GITHUB_SHA", "").strip()
    if ci_revision:
        return ci_revision
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=rust_repo,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def run_campaign(*, ready_timeout_seconds: float = 60.0) -> tuple[dict[str, Any], Path]:
    workspace_root = get_required_emule_workspace_root()
    output_root = get_workspace_output_root()
    rust_repo = workspace_root / "repos" / "emulebb-rust"
    executable = staged_executable(output_root)
    if not rust_repo.is_dir():
        raise RuntimeError(f"emulebb-rust source is missing: {rust_repo}")
    if not executable.is_file():
        raise RuntimeError(f"staged emulebb-rust daemon is missing: {executable}")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_root = output_root / "reports" / "rust-rest-openapi-ci" / run_id
    profile_dir = output_root / "profiles" / "rust-rest-openapi-ci" / run_id
    contract_shared_root = profile_dir / "contract-shared-root"
    report_path = run_root / "report.json"
    daemon_log = run_root / "daemon.log"
    port = choose_loopback_port()
    base_url = f"http://{REST_ADDR}:{port}"

    rust_client.write_rust_profile(
        profile_dir,
        rust_repo=rust_repo,
        incoming_dir=profile_dir / "incoming",
        rest_addr=REST_ADDR,
        rest_port=port,
        api_key=API_KEY,
        nat_enabled=False,
        initial_shared_directory_reload=False,
        local_only_discovery=True,
        vpn_guard_mode="off",
    )
    rust_metadata.replace_settings_section(
        profile_dir / rust_metadata.RUST_PROFILE_METADATA_FILE,
        "core",
        {
            "autoConnect": False,
            "networkEd2k": False,
            "networkKademlia": False,
            "reconnect": False,
        },
    )

    report: dict[str, Any] = {
        "schema": "emulebb.rust-rest-openapi-ci.v1",
        "runId": run_id,
        "status": "failed",
        "networkMode": "local-disabled",
        "restLoopback": True,
        "sourceRevision": source_revision(rust_repo),
        "executableSha256": sha256_file(executable),
    }
    run_root.mkdir(parents=True, exist_ok=True)
    handle = daemon_log.open("w", encoding="utf-8", newline="\n")
    process = None
    try:
        process = rust_client.spawn_rust_daemon(executable, profile_dir, output_handle=handle)

        def rest_ready() -> object | None:
            if process is not None and process.poll() is not None:
                raise RuntimeError(f"Rust daemon exited before REST readiness (code {process.returncode}).")
            try:
                return http_json(base_url, "/api/v1/status", api_key=API_KEY, timeout_seconds=2.0)
            except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError):
                return None

        wait_until("Rust REST ready", ready_timeout_seconds, rest_ready)
        previous_contract_shared_root = os.environ.get("EMULEBB_REST_CONTRACT_SHARED_ROOT")
        os.environ["EMULEBB_REST_CONTRACT_SHARED_ROOT"] = str(contract_shared_root)
        try:
            report["conformance"] = rust_rest_conformance.run_response_conformance(
                base_url,
                API_KEY,
                budget="contract",
            )
        finally:
            if previous_contract_shared_root is None:
                os.environ.pop("EMULEBB_REST_CONTRACT_SHARED_ROOT", None)
            else:
                os.environ["EMULEBB_REST_CONTRACT_SHARED_ROOT"] = previous_contract_shared_root
        report["status"] = "passed"
    except rust_rest_conformance.RestConformanceError as exc:
        report["conformance"] = exc.summary
        report["error"] = "live REST/OpenAPI response conformance failed"
    except Exception as exc:  # noqa: BLE001 - retain CI launch failures in the report
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if process is not None and process.poll() is None:
            try:
                http_json(
                    base_url,
                    "/api/v1/app/shutdown",
                    api_key=API_KEY,
                    method="POST",
                    body={"confirmShutdown": True},
                    timeout_seconds=5.0,
                )
                process.wait(timeout=20.0)
                report["teardown"] = "graceful"
            except Exception as exc:  # noqa: BLE001 - teardown evidence must survive
                report["teardown"] = f"forced: {type(exc).__name__}: {exc}"
                rust_client.stop_process_tree(process)
        elif process is not None:
            report["teardown"] = f"already-exited: {process.returncode}"
        else:
            report["teardown"] = "not-started"
        handle.close()
        write_report(report_path, report)
    return report, report_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ready-timeout-seconds", type=float, default=60.0)
    args = parser.parse_args(argv)
    if args.ready_timeout_seconds <= 0:
        raise ValueError("--ready-timeout-seconds must be positive.")
    report, report_path = run_campaign(ready_timeout_seconds=args.ready_timeout_seconds)
    print(json.dumps({"report": str(report_path), "status": report["status"], "teardown": report["teardown"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
