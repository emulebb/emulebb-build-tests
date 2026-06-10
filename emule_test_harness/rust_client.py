"""Shared eMuleBB Rust launch and configuration helpers for harness scenarios."""

from __future__ import annotations

import os
import subprocess
import json
from pathlib import Path

from .paths import get_workspace_output_root


def rust_cargo_env() -> dict[str, str]:
    """Returns a Cargo environment that keeps Rust build output under the workspace output root."""

    env = os.environ.copy()
    target_dir = Path(env.get("CARGO_TARGET_DIR") or get_workspace_output_root() / "builds" / "rust" / "target")
    target_dir.mkdir(parents=True, exist_ok=True)
    env["CARGO_TARGET_DIR"] = str(target_dir)
    return env


def write_rust_config(
    path: Path,
    *,
    runtime_dir: Path,
    rest_addr: str,
    rest_port: int,
    api_key: str,
    p2p_bind_ip: str | None = None,
    ed2k_port: int | None = None,
    kad_port: int | None = None,
    server_endpoint: str | None = None,
    connect_timeout_secs: int = 10,
    kad_bootstrap_nodes: list[str] | None = None,
    kad_bootstrap_min_routing_contacts: int = 10,
) -> None:
    """Writes a minimal eMuleBB Rust config for local harness runs."""

    lines = [
        f'runtimeDir = "{runtime_dir.as_posix()}"',
    ]
    if server_endpoint is not None:
        if p2p_bind_ip is None or ed2k_port is None or kad_port is None:
            raise ValueError("ED2K Rust configs require p2p_bind_ip, ed2k_port, and kad_port.")
        lines.extend(
            [
                f'p2pBindIp = "{p2p_bind_ip}"',
                "",
            ]
        )
    lines.extend(
        [
            "[rest]",
            f'bindAddr = "{rest_addr}:{rest_port}"',
            f'apiKey = "{api_key}"',
            "",
        ]
    )
    if server_endpoint is not None:
        lines.extend(
            [
                "[kad]",
                f"listenPort = {kad_port}",
                f"bootstrapNodes = {json.dumps(kad_bootstrap_nodes or [])}",
                f"bootstrapMinRoutingContacts = {kad_bootstrap_min_routing_contacts}",
                "",
                "[ed2k]",
                f"listenPort = {ed2k_port}",
                f'serverEndpoints = ["{server_endpoint}"]',
                f"connectTimeoutSecs = {connect_timeout_secs}",
                "reconnectIntervalSecs = 60",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def start_rust_client(repo: Path, config_path: Path, output_path: Path) -> subprocess.Popen[str]:
    """Starts `emulebb-rust` through Cargo using the shared workspace target directory."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("w", encoding="utf-8")
    return start_rust_client_with_output(repo, config_path, output_handle)


def start_rust_client_append(repo: Path, config_path: Path, output_path: Path) -> subprocess.Popen[str]:
    """Restarts `emulebb-rust` while appending to an existing harness log."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("a", encoding="utf-8")
    return start_rust_client_with_output(repo, config_path, output_handle)


def start_rust_client_with_output(repo: Path, config_path: Path, output_handle) -> subprocess.Popen[str]:
    """Starts `emulebb-rust` with an already-open output handle."""

    return subprocess.Popen(
        [
            "cargo",
            "run",
            "-p",
            "emulebb-daemon",
            "--bin",
            "emulebb-rust",
            "--",
            "--config",
            str(config_path),
        ],
        cwd=repo,
        env=rust_cargo_env(),
        stdout=output_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )


def stop_process_tree(process: subprocess.Popen | None, *, timeout_seconds: float = 10.0) -> None:
    """Stops a launched process and its children."""

    if process is None or process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        process.terminate()
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout_seconds)
