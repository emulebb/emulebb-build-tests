"""Shared eMuleBB Rust launch and profile helpers for harness scenarios."""

from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import sys
from pathlib import Path

from . import kad_nodes
from .paths import get_required_emule_workspace_root, get_workspace_output_root
from . import rust_metadata

CARGO_TARGET_DIR_ENV = "CARGO_TARGET_DIR"
RUST_PROFILE_SETTINGS_FILE = "emulebb-rust-settings.toml"
RUST_PROFILE_METADATA_FILE = rust_metadata.RUST_PROFILE_METADATA_FILE
STOCK_SERVER_KEEPALIVE_MINUTES = 20


def container_profile_setup_script(settings: dict[str, str], *, uid: int = 1000, gid: int = 1000) -> str:
    """Prepare a fresh campaign-owned volume through the packaged offline owners.

    Existing final profiles are refused. These explicit fixture writes finish
    before any daemon or P2P process starts; they are not runtime overrides.
    """
    if type(uid) is not int or type(gid) is not int or uid < 0 or gid < 0:
        raise ValueError("Container fixture ownership requires nonnegative numeric IDs")
    binary = "/usr/lib/emulebb-rust/emulebb-rust"
    profile = "/config/emulebb-rust"
    lines = [f"test ! -e {profile}", "mkdir -p /config /data/incoming /data/temp",
             "/usr/lib/emulebb-rust/emulebb-profile-init"]
    lines.extend(shlex.join([binary, "--profile", profile, "settings", "set", key, value])
                 for key, value in settings.items())
    lines.extend([f"chown -R {uid}:{gid} /config", f"chown {uid}:{gid} /data/incoming /data/temp"])
    return "\n".join(lines)


def prepare_container_profile(run, compose: tuple[str, ...], *, env: dict[str, str], settings: dict[str, str]) -> None:
    """Use the existing Compose owner and its unique campaign volumes for setup."""
    run(*compose, "run", "--rm", "--no-deps", "--entrypoint", "/bin/sh", "emulebb-rust", "-ec",
        container_profile_setup_script(settings), env=env, timeout=120)


def staged_executable(output_root: Path) -> Path:
    """Return the explicitly prebuilt regular daemon for this host; never build it."""

    suffix = ".exe" if os.name == "nt" else ""
    return output_root / "tools" / "emulebb-rust" / "bin" / f"emulebb-rust{suffix}"


def verified_runtime_stage(rust_repo: Path, output_root: Path) -> dict:
    """Admit a registered source's complete runtime bundle through its persisted owner."""
    workspace = get_required_emule_workspace_root()
    source = rust_repo.resolve()
    boundary = workspace / "workspaces" / "agents"
    if not source.is_relative_to(boundary):
        raise RuntimeError("Registered runtime admission requires a managed Rust checkout")
    parts = source.relative_to(boundary).parts
    if len(parts) != 2 or parts[1] != "emulebb-rust":
        raise RuntimeError("Registered runtime source must identify the Rust checkout root")
    completed = subprocess.run(
        [sys.executable, "-B", str(source / "tools/fresh_rust_build.py"), "--verify-stage"],
        cwd=source, env=os.environ.copy(), capture_output=True, text=True,
    )
    if completed.returncode:
        raise RuntimeError(f"Registered runtime admission failed: {completed.stderr[-4096:].strip()}")
    data = json.loads(completed.stdout)
    if not isinstance(data, dict):
        raise RuntimeError("Registered runtime owner returned an invalid description")
    target = data.get("target", "")
    if not isinstance(target, str) or re.fullmatch(r"[A-Za-z0-9_-]+", target) is None:
        raise RuntimeError("Registered runtime owner returned an invalid target identity")
    root = output_root / "tools" / "workstreams" / parts[0] / "emulebb-rust" / target
    name = "emulebb-rust.exe" if os.name == "nt" else "emulebb-rust"
    expected = root / "bin" / name
    if (data.get("schema") != "emulebb.rust-runtime-stage/1" or data.get("workstream") != parts[0]
            or data.get("source", {}).get("path") != str(source)
            or data.get("stageRoot") != str(root) or data.get("executable") != str(expected)
            or data.get("receipt") != str(root / "stage.json") or not expected.is_file()):
        raise RuntimeError("Registered runtime identity does not match its source and owned stage")
    return data


def write_private_text(path: Path, contents: str) -> None:
    """Write credential-bearing text with owner-only POSIX permissions."""

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        os.ftruncate(descriptor, 0)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            descriptor = -1
            handle.write(contents)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def get_required_cargo_target_dir() -> Path:
    """Returns the caller-provided canonical Cargo target directory."""

    raw_target_dir = os.environ.get(CARGO_TARGET_DIR_ENV, "").strip()
    if not raw_target_dir:
        raise RuntimeError(f"{CARGO_TARGET_DIR_ENV} must be set before running Rust harness commands.")
    target_dir = Path(raw_target_dir).resolve()
    if not target_dir.exists():
        raise RuntimeError(f"{CARGO_TARGET_DIR_ENV} must point to an existing directory: {target_dir}")
    expected = (get_workspace_output_root() / "builds" / "rust" / "target").resolve()
    if os.path.normcase(str(target_dir)) != os.path.normcase(str(expected)):
        raise RuntimeError(f"{CARGO_TARGET_DIR_ENV} must be {expected}, got {target_dir}.")
    return target_dir


def rust_cargo_env() -> dict[str, str]:
    """Returns the process environment after validating the canonical Cargo target dir."""

    env = os.environ.copy()
    get_required_cargo_target_dir()
    return env


def write_rust_profile(
    profile_dir: Path, *, rust_repo: Path, rest_addr: str, rest_port: int,
    api_key: str, settings: dict[str, object] | None = None,
    reset: tuple[str, ...] = (), server_endpoint: str | None = None,
    server_entry: dict[str, object] | None = None, replace_servers: bool = False,
    kad_bootstrap_nodes: list[str] | None = None, local_only_discovery: bool = False,
    local_kad_seed: kad_nodes.BootstrapContact | None = None,
) -> None:
    """Prepare current canonical settings and separately owned discovery resources.

    Test profiles default to manual connection and disabled NAT. Explicit resets
    select product defaults. All supplied settings use current dotted product keys.
    """
    from .rust_openapi_responses import validate_openapi_schema_component_payload
    from .workspace_layout import resolve_selected_workspace_repo
    import jsonschema

    if set(settings or {}).intersection(reset):
        raise ValueError("Settings fixture cannot set and reset the same key")
    values: dict[str, object] = {"network.autoConnect": False, "network.nat.enabled": False}
    values.update(settings or {})
    for key in reset:
        values.pop(key, None)
    if local_only_discovery:
        if local_kad_seed is not None:
            if values.get("network.kadEnabled") is not True:
                raise ValueError("local_kad_seed requires explicit network.kadEnabled=true")
            if kad_bootstrap_nodes:
                raise ValueError("Choose a local Kad seed or explicit bootstrap endpoints")
            kad_bootstrap_nodes = [local_kad_seed.endpoint]
        else:
            values["network.kadEnabled"] = False
    if server_endpoint is not None:
        bound = values.get("network.p2p.bindIp") or values.get("network.p2p.bindInterface")
        if not bound or not values.get("network.p2p.tcpPort") or not values.get("network.p2p.udpPort"):
            raise ValueError("ED2K fixture requires explicit binding and shared TCP/UDP ports")
    if server_entry is not None:
        if server_endpoint is None or "host" not in server_entry or "port" not in server_entry:
            raise ValueError("Server fixture requires its endpoint, host and port")

    partial: dict[str, object] = {}
    for key, value in values.items():
        branch = partial
        *groups, leaf = key.split(".")
        for group in groups:
            branch = branch.setdefault(group, {})
        branch[leaf] = value
    tooling = resolve_selected_workspace_repo(Path(__file__).resolve().parents[1], "emulebb-tooling")
    contract = tooling / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml"
    try:
        validate_openapi_schema_component_payload("SettingsPartial", partial, contract)
    except jsonschema.ValidationError as error:
        path = ".".join(map(str, error.absolute_path))
        raise ValueError(f"Invalid canonical profile setting at {path}") from None

    profile_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = profile_dir / RUST_PROFILE_METADATA_FILE
    if not metadata_path.exists():
        rust_metadata.create_metadata_db(rust_repo, metadata_path)
    rust_metadata.edit_app_settings(rust_repo, metadata_path, values, reset=reset)
    lines = ["[rest]", f"bind_addr = {json.dumps(f'{rest_addr}:{rest_port}', ensure_ascii=False)}",
             f"api_key = {json.dumps(api_key, ensure_ascii=False)}", ""]
    write_private_text(profile_dir / RUST_PROFILE_SETTINGS_FILE, "\n".join(lines))
    if kad_bootstrap_nodes is not None:
        rust_metadata.replace_kad_bootstrap_endpoints(metadata_path, kad_bootstrap_nodes)
    if replace_servers:
        rust_metadata.clear_servers(metadata_path)
    if server_entry is not None:
        rust_metadata.seed_server(metadata_path, server_entry)
    elif server_endpoint is not None:
        rust_metadata.seed_server(metadata_path, server_from_endpoint(server_endpoint))
    if local_only_discovery:
        rust_metadata.initialize_local_discovery(rust_repo, metadata_path)


def server_from_endpoint(endpoint: str) -> dict[str, object]:
    """Returns a SQLite server seed row from a ``host:port`` endpoint."""

    host, separator, raw_port = endpoint.rpartition(":")
    if not separator or not host:
        raise ValueError(f"ED2K Rust server endpoint must be host:port, got {endpoint!r}.")
    return {"host": host, "port": int(raw_port), "name": endpoint}


def start_rust_client(
    repo: Path, profile_dir: Path, output_path: Path, features: str | None = None
) -> subprocess.Popen[str]:
    """Starts `emulebb-rust` through Cargo using the shared workspace target directory.

    ``features`` forwards a Cargo feature list (e.g. ``packet-diagnostics``) so a
    harness can compile in exact packet events within the unified diagnostic
    stream; default None keeps the plain build for existing callers.
    """

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("w", encoding="utf-8")
    return start_rust_client_with_output(repo, profile_dir, output_handle, features=features)


def start_rust_client_append(repo: Path, profile_dir: Path, output_path: Path) -> subprocess.Popen[str]:
    """Restarts `emulebb-rust` while appending to an existing harness log."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("a", encoding="utf-8")
    return start_rust_client_with_output(repo, profile_dir, output_handle)


def start_rust_client_executable(
    executable: Path,
    profile_dir: Path,
    output_path: Path,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.Popen[str]:
    """Starts a staged `emulebb-rust` executable with a generated harness profile."""

    if not executable.is_file():
        raise RuntimeError(f"eMuleBB Rust executable was not found at '{executable}'.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("w", encoding="utf-8")
    return start_rust_client_executable_with_output(
        executable,
        profile_dir,
        output_handle,
        env=env,
    )


def start_rust_client_executable_append(
    executable: Path,
    profile_dir: Path,
    output_path: Path,
) -> subprocess.Popen[str]:
    """Restarts a staged `emulebb-rust` executable while preserving its harness log."""

    if not executable.is_file():
        raise RuntimeError(f"eMuleBB Rust executable was not found at '{executable}'.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("a", encoding="utf-8")
    return start_rust_client_executable_with_output(executable, profile_dir, output_handle)


def spawn_rust_daemon(
    executable: Path,
    profile_dir: Path,
    *,
    output_handle,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    detached: bool = False,
    new_process_group: bool = False,
    text: bool = True,
    command_prefix: tuple[str, ...] = (),
) -> subprocess.Popen:
    """Spawns the `emulebb-rust` daemon with the shared argv/stdio wiring.

    ``detached=True`` adds the Windows CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
    flags so the daemon outlives the launcher (used by the persistent soak restart
    controller); the default keeps it a managed child the launcher tears down.
    """

    creationflags = 0
    if os.name == "nt" and (detached or new_process_group):
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        if detached:
            creationflags |= subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
    return subprocess.Popen(
        [*command_prefix, str(executable), "--profile", str(profile_dir)],
        cwd=cwd if cwd is not None else executable.parent,
        env=env if env is not None else os.environ.copy(),
        stdout=output_handle,
        stderr=subprocess.STDOUT,
        text=text,
        creationflags=creationflags,
    )


def start_rust_client_executable_with_output(
    executable: Path,
    profile_dir: Path,
    output_handle,
    *,
    env: dict[str, str] | None = None,
    new_process_group: bool = False,
    text: bool = True,
) -> subprocess.Popen:
    """Starts a staged `emulebb-rust` executable with an already-open output handle."""

    return spawn_rust_daemon(
        executable,
        profile_dir,
        output_handle=output_handle,
        env=env,
        new_process_group=new_process_group,
        text=text,
    )


def request_ctrl_c(process: subprocess.Popen) -> None:
    """Send the platform Ctrl-C signal to one managed Rust daemon."""

    if process.poll() is not None:
        return
    if os.name == "nt":
        process.send_signal(signal.CTRL_C_EVENT)
    else:
        process.send_signal(signal.SIGINT)


def start_rust_client_with_output(
    repo: Path, profile_dir: Path, output_handle, features: str | None = None
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
            "--profile",
            str(profile_dir),
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
