"""Start the regular Rust live soak profile run in the background.

This is a thin persisted Python launcher for operator monitoring sessions. The
actual soak behavior stays in ``scripts/launch-soak.py``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.live_wire_inputs import load_live_wire_inputs
from emule_test_harness.paths import get_workspace_output_root
from emule_test_harness.soak_launch import OPERATOR_SERVER

REQUIRED_ENV_DIRS = ("EMULEBB_WORKSPACE_ROOT", "EMULEBB_WORKSPACE_OUTPUT_ROOT", "CARGO_TARGET_DIR")
REQUIRED_ENV_VALUES = ("X_LOCAL_IP",)


def require_env_dir(name: str) -> Path:
    """Returns a required environment directory without mutating the environment."""

    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must already be set in the environment.")
    path = Path(value)
    if not path.is_dir():
        raise RuntimeError(f"{name} points to a missing directory: {path}")
    return path


def require_env_value(name: str) -> str:
    """Returns a required non-empty environment value."""

    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must already be set in the environment.")
    return value


def require_operator_environment() -> dict[str, Path | str]:
    """Returns the inherited operator environment, or raises before launch."""

    workspace_root = require_env_dir("EMULEBB_WORKSPACE_ROOT")
    output_root = require_env_dir("EMULEBB_WORKSPACE_OUTPUT_ROOT")
    cargo_target_dir = require_env_dir("CARGO_TARGET_DIR")
    expected_cargo_target_dir = output_root / "builds" / "rust" / "target"
    if cargo_target_dir.resolve() != expected_cargo_target_dir.resolve():
        raise RuntimeError(
            "CARGO_TARGET_DIR must already point to "
            f"{expected_cargo_target_dir}; got {cargo_target_dir}."
        )
    return {
        "EMULEBB_WORKSPACE_ROOT": workspace_root,
        "EMULEBB_WORKSPACE_OUTPUT_ROOT": output_root,
        "CARGO_TARGET_DIR": cargo_target_dir,
        "X_LOCAL_IP": require_env_value("X_LOCAL_IP"),
    }


def default_inputs_path() -> Path:
    """Returns the checked-in operator live-wire input path."""

    return (REPO_ROOT / "live-wire-inputs.local.json").resolve()


def default_vpn_guard_path() -> Path:
    """Returns the checked-in operator VPN Guard config path."""

    return (REPO_ROOT / "vpn-guard-live.local.json").resolve()


def regular_rust_exe(output_root: Path) -> Path:
    """Returns the staged regular Rust executable path used by --rust-regular."""

    return output_root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"


def diagnostics_rust_exe(output_root: Path) -> Path:
    """Returns the staged diagnostics Rust executable path."""

    return output_root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust-diagnostics.exe"


def build_effective_profile(args: argparse.Namespace, env: dict[str, Path | str]) -> dict[str, Any]:
    """Builds the self-describing operator run profile without starting it."""

    inputs_path = default_inputs_path()
    inputs = load_live_wire_inputs(inputs_path)
    output_root = Path(env["EMULEBB_WORKSPACE_OUTPUT_ROOT"])
    lan_bind_addr = args.lan_bind_addr.strip() or str(env["X_LOCAL_IP"])
    rust_rest_base_url = f"http://{lan_bind_addr}:4731"
    rust_api_key = "converged-soak"
    return {
        "schema": "emulebb.rust-soak-profile.describe.v1",
        "mode": "rust-diagnostics-live-profile" if args.diagnostics else "rust-regular-live-profile",
        "seconds": args.seconds,
        "lanBindAddr": lan_bind_addr,
        "requiredEnvironment": {
            name: str(env[name])
            for name in (*REQUIRED_ENV_DIRS, *REQUIRED_ENV_VALUES)
        },
        "inputs": str(inputs_path),
        "vpnGuardConfig": str(default_vpn_guard_path()),
        "rustProfileDir": str(inputs.rust_profile_dir) if inputs.rust_profile_dir is not None else None,
        "rustExe": str(diagnostics_rust_exe(output_root) if args.diagnostics else regular_rust_exe(output_root)),
        "rustRest": f"{rust_rest_base_url}/api/v1",
        "rustRestBaseUrl": rust_rest_base_url,
        "rustApiKey": rust_api_key,
        "p2pBindInterface": "hide.me",
        "p2pPorts": {"ed2kTcp": 42662, "kadUdp": 42672},
        "operatorServer": OPERATOR_SERVER,
        "sharedRootCount": len(inputs.video_roots),
        "bootstrapHashCount": len(inputs.bootstrap_transfer_hashes),
        "directBootstrapTransferCount": len(inputs.direct_bootstrap_transfers),
        "singleServer": bool(args.single_server),
        "diagnostics": bool(args.diagnostics),
        "rustFallbackServers": list(args.rust_fallback_server),
        "restTimeoutSeconds": args.rest_timeout_seconds,
        "launchCommand": build_launch_command(
            argparse.Namespace(
                seconds=args.seconds,
                lan_bind_addr=lan_bind_addr,
                single_server=args.single_server,
                diagnostics=args.diagnostics,
                rust_fallback_server=list(args.rust_fallback_server),
                rest_timeout_seconds=args.rest_timeout_seconds,
            )
        ),
        "restOpenApiConformanceCommand": build_rest_conformance_command(
            rust_rest_base_url,
            rust_api_key,
            output_root,
        ),
        "stopCommand": [
            sys.executable,
            str(REPO_ROOT / "scripts" / "rust-soak-control.py"),
            "stop-profile-launch",
            "--manifest",
            str(output_root / "logs" / "soak-launch" / "rust-regular-soak.latest.json"),
        ],
    }


def build_rest_conformance_command(base_url: str, api_key: str, output_root: Path) -> list[str]:
    """Builds the already-running daemon REST/OpenAPI conformance command."""

    report_path = (
        output_root
        / "reports"
        / "rust-rest-openapi-conformance"
        / "rust-rest-openapi-conformance.latest.json"
    )
    return [
        sys.executable,
        str(REPO_ROOT / "scripts" / "check-rust-rest-openapi-responses.py"),
        "--base-url",
        base_url,
        "--api-key",
        api_key,
        "--rest-coverage-budget",
        "contract",
        "--json-output",
        str(report_path),
    ]


def build_launch_command(args: argparse.Namespace) -> list[str]:
    """Builds the background launch-soak command."""

    command = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "launch-soak.py"),
        "--inputs",
        str(default_inputs_path()),
        "--lan-bind-addr",
        args.lan_bind_addr,
        "--no-mfc",
        "--rust-server",
        OPERATOR_SERVER,
        "--vpn-guard-live-config",
        str(default_vpn_guard_path()),
        "--vpn-guard-scenario",
        "success",
        "--cpu-profile",
        "--cpu-profile-seconds",
        str(args.seconds),
        "--cpu-profile-stack",
        "--process-metrics",
        "--rest-timeout-seconds",
        str(args.rest_timeout_seconds),
    ]
    if not args.diagnostics:
        command.append("--rust-regular")
    if args.single_server:
        command.extend(["--reuse-kad-bootstrap", "--server-met-url", "", "--single-rust-server"])
    for endpoint in args.rust_fallback_server:
        command.extend(["--rust-fallback-server", endpoint])
    return command


def build_parser() -> argparse.ArgumentParser:
    epilog = (
        "Required inherited environment: "
        "EMULEBB_WORKSPACE_ROOT, EMULEBB_WORKSPACE_OUTPUT_ROOT, CARGO_TARGET_DIR, X_LOCAL_IP. "
        "This launcher never sets or repairs those values. Use --describe to print the "
        "effective profile, paths, binding, command, and stop command without starting anything."
    )
    parser = argparse.ArgumentParser(description=__doc__, epilog=epilog)
    parser.add_argument("--seconds", type=int, default=3600, help="CPU profile/run window; minimum 3600.")
    parser.add_argument("--lan-bind-addr", default="", help="REST LAN bind address; defaults to inherited X_LOCAL_IP.")
    parser.add_argument(
        "--single-server",
        action="store_true",
        help="Use only the fixed Rust operator ED2K server and skip server.met import.",
    )
    parser.add_argument(
        "--diagnostics",
        action="store_true",
        help="Run emulebb-rust-diagnostics.exe instead of the regular Rust executable.",
    )
    parser.add_argument(
        "--rust-fallback-server",
        action="append",
        default=[],
        help="Explicit Rust-only fallback eD2K server endpoint, host:port. May be repeated.",
    )
    parser.add_argument(
        "--rest-timeout-seconds",
        type=float,
        default=60.0,
        help="Timeout for the launcher's Rust REST readiness checks.",
    )
    parser.add_argument("--describe", action="store_true", help="Print effective paths and commands without launching.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.seconds < 3600:
        raise RuntimeError("--seconds must be at least 3600 for the operator soak profile run.")
    if args.rest_timeout_seconds <= 0:
        raise RuntimeError("--rest-timeout-seconds must be greater than zero.")

    env = require_operator_environment()
    if args.describe:
        print(json.dumps(build_effective_profile(args, env), indent=2, sort_keys=True))
        return 0

    lan_bind_addr = args.lan_bind_addr.strip() or str(env["X_LOCAL_IP"])
    args.lan_bind_addr = lan_bind_addr

    output_root = get_workspace_output_root()
    log_dir = output_root / "logs" / "soak-launch"
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    stdout_path = log_dir / f"rust-regular-soak-{stamp}.out.log"
    stderr_path = log_dir / f"rust-regular-soak-{stamp}.err.log"
    manifest_path = log_dir / "rust-regular-soak.latest.json"
    command = build_launch_command(args)

    stdout = stdout_path.open("w", encoding="utf-8", newline="\n")
    stderr = stderr_path.open("w", encoding="utf-8", newline="\n")
    try:
        process = subprocess.Popen(
            command,
            cwd=str(REPO_ROOT),
            stdout=stdout,
            stderr=stderr,
            text=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )
    finally:
        stdout.close()
        stderr.close()

    manifest = {
        "schema": "emulebb.rust-soak-profile-background.v1",
        "pid": process.pid,
        "command": command,
        "cwd": str(REPO_ROOT),
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
        "seconds": args.seconds,
        "lanBindAddr": lan_bind_addr,
        "startedUtc": stamp,
        "describe": build_effective_profile(args, env),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
