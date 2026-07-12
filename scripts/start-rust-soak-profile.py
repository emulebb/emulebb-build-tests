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

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.paths import get_workspace_output_root


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


def build_launch_command(args: argparse.Namespace) -> list[str]:
    """Builds the background launch-soak command."""

    command = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "launch-soak.py"),
        "--inputs",
        str((REPO_ROOT / "live-wire-inputs.local.json").resolve()),
        "--lan-bind-addr",
        args.lan_bind_addr,
        "--rust-regular",
        "--no-mfc",
        "--vpn-guard-live-config",
        str((REPO_ROOT / "vpn-guard-live.local.json").resolve()),
        "--vpn-guard-scenario",
        "success",
        "--cpu-profile",
        "--cpu-profile-seconds",
        str(args.seconds),
        "--cpu-profile-stack",
        "--process-metrics",
    ]
    return command


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=3600)
    parser.add_argument("--lan-bind-addr", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.seconds < 3600:
        raise RuntimeError("--seconds must be at least 3600 for the operator soak profile run.")

    require_env_dir("EMULEBB_WORKSPACE_ROOT")
    require_env_dir("EMULEBB_WORKSPACE_OUTPUT_ROOT")
    require_env_dir("CARGO_TARGET_DIR")
    lan_bind_addr = args.lan_bind_addr.strip() or require_env_value("X_LOCAL_IP")
    args.lan_bind_addr = lan_bind_addr

    output_root = get_workspace_output_root()
    log_dir = output_root / "logs" / "soak-launch"
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    stdout_path = log_dir / f"rust-regular-1h-soak-{stamp}.out.log"
    stderr_path = log_dir / f"rust-regular-1h-soak-{stamp}.err.log"
    manifest_path = log_dir / "rust-regular-1h-soak.latest.json"
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
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
