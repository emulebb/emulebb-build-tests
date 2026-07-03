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
    incoming_dir: Path | None = None,
    rest_addr: str,
    rest_port: int,
    api_key: str,
    p2p_bind_ip: str | None = None,
    p2p_bind_interface: str | None = None,
    ed2k_port: int | None = None,
    kad_port: int | None = None,
    server_endpoint: str | None = None,
    server_entry: dict[str, object] | None = None,
    obfuscation_enabled: bool = True,
    connect_timeout_secs: int = 10,
    reconnect_interval_secs: int = 60,
    kad_bootstrap_nodes: list[str] | None = None,
    kad_bootstrap_min_routing_contacts: int = 10,
    kad_hello_intro_interval_secs: int = 1,
    kad_hello_intro_fanout: int = 4,
    enable_udp_reask: bool = False,
    publish_emule_rust_identity: bool = False,
    upload_active_slots: int | None = None,
) -> None:
    """Writes a minimal eMuleBB Rust config for local harness runs."""

    lines = [
        f'runtimeDir = "{runtime_dir.as_posix()}"',
    ]
    if incoming_dir is not None:
        lines.append(f'incomingDir = "{incoming_dir.as_posix()}"')
    if server_endpoint is not None:
        if (p2p_bind_ip is None and p2p_bind_interface is None) or ed2k_port is None or kad_port is None:
            raise ValueError(
                "ED2K Rust configs require p2p_bind_ip and/or p2p_bind_interface, ed2k_port, and kad_port."
            )
        if p2p_bind_ip is not None:
            lines.append(f'p2pBindIp = "{p2p_bind_ip}"')
        if p2p_bind_interface is not None:
            lines.append(f'p2pBindInterface = "{p2p_bind_interface}"')
        lines.append("")
    if server_entry is not None:
        if server_endpoint is None:
            raise ValueError("ED2K Rust serverEntry requires server_endpoint.")
        if "host" not in server_entry or "port" not in server_entry:
            raise ValueError("ED2K Rust serverEntry requires host and port.")
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
                f"helloIntroIntervalSecs = {kad_hello_intro_interval_secs}",
                f"helloIntroFanout = {kad_hello_intro_fanout}",
                "",
                "[ed2k]",
                f"listenPort = {ed2k_port}",
                f"obfuscationEnabled = {str(obfuscation_enabled).lower()}",
                f"connectTimeoutSecs = {connect_timeout_secs}",
                f"reconnectIntervalSecs = {reconnect_interval_secs}",
                f"enableUdpReask = {str(enable_udp_reask).lower()}",
                # Client identity on the wire: false (default) impersonates a stock
                # eMule Community 0.7-series client (6-tag hello, no CT_MOD_VERSION);
                # true publishes the emulebb-rust mod identity. Kept explicit so the
                # impersonation choice is visible + flippable per soak run.
                f"publishEmuleRustIdentity = {str(publish_emule_rust_identity).lower()}",
                "",
            ]
        )
        if server_entry is None:
            lines.append(f'serverEndpoints = ["{server_endpoint}"]')
        else:
            lines.append("[[ed2k.serverEntries]]")
            lines.extend(toml_line(key, value) for key, value in server_entry.items())
        lines.append("")
        # Optional upload-queue policy override. activeSlots=0 forces every
        # requester into the waiting queue (used to make a peer UDP-reask us).
        if upload_active_slots is not None:
            lines.extend(
                [
                    "[ed2k.uploadQueue]",
                    f"activeSlots = {upload_active_slots}",
                    "",
                ]
            )
    path.write_text("\n".join(lines), encoding="utf-8")


def toml_line(key: str, value: object) -> str:
    """Formats a simple TOML scalar line for generated harness configs."""

    if isinstance(value, bool):
        rendered = str(value).lower()
    elif isinstance(value, int):
        rendered = str(value)
    elif isinstance(value, str):
        rendered = json.dumps(value)
    else:
        raise TypeError(f"unsupported TOML scalar for {key}: {value!r}")
    return f"{key} = {rendered}"


def start_rust_client(
    repo: Path, config_path: Path, output_path: Path, features: str | None = None
) -> subprocess.Popen[str]:
    """Starts `emulebb-rust` through Cargo using the shared workspace target directory.

    ``features`` forwards a Cargo feature list (e.g. ``packet-diagnostics``) so a
    harness can compile in the ed2k_packet_v1 / Kad udp_packet_v1 dumps; default
    None keeps the plain build for existing callers.
    """

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("w", encoding="utf-8")
    return start_rust_client_with_output(repo, config_path, output_handle, features=features)


def start_rust_client_append(repo: Path, config_path: Path, output_path: Path) -> subprocess.Popen[str]:
    """Restarts `emulebb-rust` while appending to an existing harness log."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("a", encoding="utf-8")
    return start_rust_client_with_output(repo, config_path, output_handle)


def start_rust_client_executable(executable: Path, config_path: Path, output_path: Path) -> subprocess.Popen[str]:
    """Starts a staged `emulebb-rust` executable with a generated harness config."""

    if not executable.is_file():
        raise RuntimeError(f"eMuleBB Rust executable was not found at '{executable}'.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("w", encoding="utf-8")
    return start_rust_client_executable_with_output(executable, config_path, output_handle)


def spawn_rust_daemon(
    executable: Path,
    config_path: Path,
    *,
    output_handle,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    detached: bool = False,
    text: bool = True,
) -> subprocess.Popen:
    """Spawns the `emulebb-rust` daemon with the shared argv/stdio wiring.

    ``detached=True`` adds the Windows CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
    flags so the daemon outlives the launcher (used by the persistent soak restart
    controller); the default keeps it a managed child the launcher tears down.
    """

    creationflags = 0
    if detached and os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
    return subprocess.Popen(
        [str(executable), "--config", str(config_path)],
        cwd=cwd if cwd is not None else executable.parent,
        env=env if env is not None else os.environ.copy(),
        stdout=output_handle,
        stderr=subprocess.STDOUT,
        text=text,
        creationflags=creationflags,
    )


def start_rust_client_executable_with_output(
    executable: Path,
    config_path: Path,
    output_handle,
) -> subprocess.Popen[str]:
    """Starts a staged `emulebb-rust` executable with an already-open output handle."""

    return spawn_rust_daemon(executable, config_path, output_handle=output_handle)


def start_rust_client_with_output(
    repo: Path, config_path: Path, output_handle, features: str | None = None
) -> subprocess.Popen[str]:
    """Starts `emulebb-rust` with an already-open output handle.

    ``features`` forwards a Cargo feature list (e.g. ``packet-diagnostics``);
    default None keeps the plain build.
    """

    feature_args = ["--features", features] if features else []
    return subprocess.Popen(
        [
            "cargo",
            "run",
            "-p",
            "emulebb-daemon",
            "--bin",
            "emulebb-rust",
            *feature_args,
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
