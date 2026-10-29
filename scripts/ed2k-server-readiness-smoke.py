#!/usr/bin/env python3
"""Prove a staged Linux ED2K server starts, responds, and stops through WSL."""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import ed2k_server  # noqa: E402
from emule_test_harness.paths import (  # noqa: E402
    get_required_emule_workspace_root,
    get_workspace_output_root,
    path_is_relative_to,
)

SUITE_NAME = "ed2k-server-readiness-smoke"


def utc_now() -> str:
    """Return a compact UTC timestamp."""

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse standalone readiness-smoke arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ed2k-server-exe", required=True)
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--health-timeout-seconds", type=float, default=30.0)
    return parser.parse_args(argv)


def resolve_artifacts_dir(raw_value: str | None, output_root: Path) -> Path:
    """Resolve one report directory and require output-root ownership."""

    if raw_value:
        candidate = Path(raw_value)
        artifacts_dir = candidate.resolve() if candidate.is_absolute() else (output_root / candidate).resolve()
    else:
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + f"-pid{os.getpid()}"
        artifacts_dir = (output_root / "reports" / SUITE_NAME / run_id).resolve()
    if not path_is_relative_to(artifacts_dir, output_root):
        raise RuntimeError(f"Readiness artifacts must stay under EMULEBB_WORKSPACE_OUTPUT_ROOT: {artifacts_dir}")
    return artifacts_dir


def allocate_port(*, udp_offset: int | None = None, used: set[int] | None = None) -> int:
    """Choose a local port with any required UDP companion free."""

    reserved = used if used is not None else set()
    for _ in range(200):
        port = random.randrange(20000, 45000)
        if port in reserved or (udp_offset is not None and port + udp_offset in reserved):
            continue
        probes: list[socket.socket] = []
        try:
            tcp_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_probe.bind(("127.0.0.1", port))
            probes.append(tcp_probe)
            if udp_offset is not None:
                udp_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_probe.bind(("127.0.0.1", port + udp_offset))
                probes.append(udp_probe)
            reserved.add(port)
            if udp_offset is not None:
                reserved.add(port + udp_offset)
            return port
        except OSError:
            pass
        finally:
            for probe in probes:
                probe.close()
    raise RuntimeError("Could not allocate local ED2K readiness ports.")


def run_readiness_smoke(
    *,
    workspace_root: Path,
    server_exe: Path,
    artifacts_dir: Path,
    health_timeout_seconds: float,
) -> dict[str, Any]:
    """Run one real WSL launch/readiness/cleanup proof."""

    result: dict[str, Any] = {
        "suite": SUITE_NAME,
        "status": "failed",
        "current_phase": "validate",
        "started_at": utc_now(),
        "workspace_root": str(workspace_root),
        "server_exe": str(server_exe),
        "artifacts_dir": str(artifacts_dir),
        "checks": {},
        "cleanup": {},
    }
    launch = None
    try:
        if os.name != "nt":
            raise RuntimeError("The WSL ED2K readiness smoke requires a Windows host.")
        if not server_exe.is_file():
            raise RuntimeError(f"Staged ED2K server executable was not found: {server_exe}")
        if health_timeout_seconds <= 0:
            raise RuntimeError("--health-timeout-seconds must be positive")

        artifacts_dir.mkdir(parents=True, exist_ok=True)
        server_dir = artifacts_dir / "ed2k-server"
        used_ports: set[int] = set()
        ed2k_port = allocate_port(udp_offset=4, used=used_ports)
        admin_port = allocate_port(used=used_ports)
        result["ports"] = {"ed2k_tcp": ed2k_port, "ed2k_udp": ed2k_port + 4, "admin": admin_port}

        result["current_phase"] = "launch"
        launch = ed2k_server.launch_ed2k_server(
            workspace_root=workspace_root,
            server_dir=server_dir,
            ed2k_port=ed2k_port,
            admin_port=admin_port,
            token="readiness-smoke",
            admin_address="127.0.0.1",
            ed2k_address="127.0.0.1",
            exe_override=str(server_exe),
            health_timeout_seconds=health_timeout_seconds,
        )

        result["current_phase"] = "verify"
        pid_path = server_dir / "server.pid"
        pid_text = pid_path.read_text(encoding="ascii").strip()
        if not pid_text.isdigit():
            raise RuntimeError(f"WSL ED2K server PID evidence is invalid: {pid_text!r}")
        if launch.process.poll() is not None:
            raise RuntimeError(f"WSL ED2K server exited after readiness with code {launch.process.returncode}.")
        control = ed2k_server.ed2k_server_control(launch.admin_base_url, "readiness-smoke")
        result["checks"] = {
            "health": launch.health,
            "pid": int(pid_text),
            "stats": control.stats(),
        }
        result["status"] = "passed"
        result["current_phase"] = "cleanup"
    except Exception as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if launch is not None:
            try:
                ed2k_server.stop_process(launch.process)
                return_code = launch.process.poll()
                result["cleanup"] = {"return_code": return_code, "stopped": return_code is not None}
                if return_code is None:
                    raise RuntimeError("WSL ED2K server remained active after cleanup.")
            except Exception as exc:
                result["status"] = "failed"
                result["cleanup"] = {"stopped": False, "error": str(exc)}
                result["error"] = {"type": type(exc).__name__, "message": str(exc)}
        result["current_phase"] = "complete"
        result["finished_at"] = utc_now()
    return result


def main(argv: list[str] | None = None) -> int:
    """Run the smoke and persist its compact result."""

    try:
        args = parse_args(argv)
        workspace_root = get_required_emule_workspace_root()
        output_root = get_workspace_output_root()
        artifacts_dir = resolve_artifacts_dir(args.artifacts_dir, output_root)
        result = run_readiness_smoke(
            workspace_root=workspace_root,
            server_exe=Path(args.ed2k_server_exe).resolve(),
            artifacts_dir=artifacts_dir,
            health_timeout_seconds=args.health_timeout_seconds,
        )
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        result_path = artifacts_dir / f"{SUITE_NAME}-result.json"
        result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"{SUITE_NAME}: {result['status']} ({result_path})")
        return 0 if result["status"] == "passed" else 1
    except Exception as exc:
        print(f"{SUITE_NAME}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
