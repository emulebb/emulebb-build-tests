"""Shared bring-up for the rust<->MFC soak (launcher + observer reuse this).

Both `scripts/launch-soak.py` (the pure launcher) and `scripts/converged-soak-live.py`
(the live observer/analysis) stand up the SAME persistent, isolated profiles under
`$EMULEBB_WORKSPACE_OUTPUT_ROOT/soak/`, connected to the SAME operator eD2K server,
bootstrapped from the SAME nodes.dat, sharing the SAME library roots. This module
holds that common bring-up so the two entry points cannot drift apart.

REST control plane binds X_LOCAL_IP; P2P binds the hide.me tunnel. Nothing
machine-specific is baked in.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from .rust_client import start_rust_client_executable_with_output, write_rust_config
from .ini import read_ini_text
from .vm_guest_profiles import retry_http_json, wait_until

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

# Same lab wiring as the converged single-pass orchestrator so both campaigns are
# like-for-like (operator server, high ports, REST api keys, server.met source).
OPERATOR_SERVER = "45.82.80.155:5687"
OPERATOR_SERVER_NAME = "operator-parity"
DEFAULT_SERVER_MET_URL = "https://upd.emule-security.org/server.met"
DEFAULT_MFC_SEED_CONFIG_DIR = REPO_ROOT / "manifests" / "live-profile-seed" / "config"
RUST_ED2K_PORT = 42662
RUST_KAD_PORT = 42672
MFC_ED2K_PORT = 43662
MFC_KAD_PORT = 43672
MFC_SERVER_UDP_PORT = 43673
# Compatibility aliases for older helper imports.
ED2K_PORT = RUST_ED2K_PORT
KAD_PORT = RUST_KAD_PORT
RUST_API_KEY = "converged-soak"
MFC_API_KEY = "converged-soak-mfc"
DEFAULT_UPLOAD_LIMIT_KIBPS = 3072
DEFAULT_LOG_TRIM_BYTES = 64 * 1024 * 1024


def log(message: str) -> None:
    print(f"[soak] {message}", flush=True)


def require_same_vpn_bind_ip(rust_vpn: dict[str, Any], mfc_vpn: dict[str, Any]) -> str:
    """Returns the common hide.me bind IP or raises when client routing diverges."""

    rust_bind_ip = str(rust_vpn.get("bindIp") or "").strip()
    mfc_bind_ip = str(mfc_vpn.get("bindIp") or "").strip()
    if not rust_bind_ip or not mfc_bind_ip:
        raise RuntimeError(f"hide.me split-tunnel bind IP missing: rust={rust_bind_ip!r}, mfc={mfc_bind_ip!r}.")
    if rust_bind_ip != mfc_bind_ip:
        raise RuntimeError(
            "hide.me split-tunnel bind IP mismatch: "
            f"rust={rust_bind_ip!r}, mfc={mfc_bind_ip!r}. Both clients must use the same VPN adapter."
        )
    return rust_bind_ip


def require_distinct_endpoint_ports(
    *,
    rust_ed2k_port: int,
    rust_kad_port: int,
    mfc_ed2k_port: int,
    mfc_kad_port: int,
    mfc_server_udp_port: int,
) -> dict[str, dict[str, int]]:
    """Validates and reports the public P2P endpoint ports used by both clients."""

    ports = {
        "rust": {
            "ed2kTcpPort": rust_ed2k_port,
            "kadUdpPort": rust_kad_port,
        },
        "mfc": {
            "ed2kTcpPort": mfc_ed2k_port,
            "kadUdpPort": mfc_kad_port,
            "serverUdpPort": mfc_server_udp_port,
        },
    }
    flattened: list[tuple[str, int]] = [
        (f"{client}.{name}", int(port))
        for client, values in ports.items()
        for name, port in values.items()
    ]
    for name, port in flattened:
        if port < 1 or port > 65535:
            raise ValueError(f"{name} must be in the range 1..65535, got {port}.")
    seen: dict[int, str] = {}
    duplicates: list[str] = []
    for name, port in flattened:
        existing = seen.get(port)
        if existing is not None:
            duplicates.append(f"{existing} and {name} both use {port}")
        seen[port] = name
    if duplicates:
        raise ValueError("Soak client P2P ports must be distinct: " + "; ".join(duplicates))
    return ports


def normalize_shared_root(path: str) -> str:
    """Returns a REST shared-root path with one trailing Windows separator."""

    root = path.strip().replace("/", "\\")
    while root.endswith(("\\", "/")):
        root = root[:-1]
    return f"{root}\\"


def shared_root_path(root: object) -> str:
    """Returns the path component from a shared-root entry."""

    if isinstance(root, dict):
        return str(root.get("path") or "")
    return str(root or "")


def shared_root_is_recursive(root: object) -> bool:
    """Returns whether a shared-root entry is recursive."""

    return bool(root.get("recursive")) if isinstance(root, dict) else False


def normalize_shared_root_entry(root: object) -> object:
    """Returns one REST shared-root payload entry with normalized path spelling."""

    path = normalize_shared_root(shared_root_path(root))
    if shared_root_is_recursive(root):
        return {"path": path, "recursive": True}
    return path


def dedupe_shared_roots(roots: list[object]) -> list[object]:
    """Deduplicates shared roots case-insensitively while preserving order."""

    positions: dict[str, int] = {}
    unique: list[object] = []
    for root in roots:
        normalized = normalize_shared_root_entry(root)
        path = shared_root_path(normalized)
        recursive = shared_root_is_recursive(normalized)
        key = path.casefold()
        if not path.strip("\\"):
            continue
        existing = positions.get(key)
        if existing is not None:
            if recursive and not shared_root_is_recursive(unique[existing]):
                unique[existing] = normalized
            continue
        positions[key] = len(unique)
        unique.append(normalized)
    return unique


def load_shareddir_roots(path: Path, *, extra_roots: list[Path] | None = None) -> list[str]:
    """Loads MFC ``shareddir.dat`` roots plus optional operator content roots."""

    roots = [
        line.strip()
        for line in read_ini_text(path).splitlines()
        if line.strip()
    ]
    for extra_root in extra_roots or []:
        roots.append(str(extra_root))
    return [shared_root_path(root) for root in dedupe_shared_roots(roots)]


def load_shareddir_root_entries(path: Path, *, extra_roots: list[Path] | None = None) -> list[object]:
    """Loads MFC shared roots while preserving monitored recursive-root intent."""

    shared = load_shareddir_roots(path)
    monitored_file = path.with_name("shareddir.monitored.dat")
    monitor_owned_file = path.with_name("shareddir.monitor-owned.dat")
    monitored_text = read_ini_text(monitored_file) if monitored_file.is_file() else ""
    monitor_owned_text = read_ini_text(monitor_owned_file) if monitor_owned_file.is_file() else ""
    monitored = {normalize_shared_root(line).casefold() for line in monitored_text.splitlines() if line.strip()}
    monitor_owned = {
        normalize_shared_root(line).casefold()
        for line in monitor_owned_text.splitlines()
        if line.strip()
    }
    roots: list[object] = []
    for root in shared:
        key = normalize_shared_root(root).casefold()
        if key in monitor_owned:
            continue
        if key in monitored:
            roots.append({"path": root, "recursive": True})
        else:
            roots.append(root)
    for extra_root in extra_roots or []:
        roots.append(str(extra_root))
    return dedupe_shared_roots(roots)


def shared_root_paths(roots: list[object]) -> list[str]:
    """Returns only the path component for shared-root entries."""

    return [shared_root_path(root) for root in roots]


def existing_shared_roots(roots: list[object]) -> tuple[list[object], int]:
    """Returns existing directory roots plus the number skipped as inaccessible."""

    existing: list[object] = []
    skipped = 0
    for root in roots:
        if Path(shared_root_path(root)).is_dir():
            existing.append(root)
        else:
            skipped += 1
    return existing, skipped


def patch_upload_limit(base_url: str, api_key: str, upload_limit_kibps: int) -> dict[str, Any]:
    """Applies the shared REST upload cap preference to one live client."""

    return retry_http_json(
        "soak upload limit",
        2,
        base_url,
        "/api/v1/app/preferences",
        api_key=api_key,
        method="PATCH",
        body={"uploadLimitKiBps": upload_limit_kibps},
        timeout_seconds=15.0,
    )


def api_items(payload: Any, key: str) -> list[Any]:
    """Extracts list rows from common eMuleBB REST envelope shapes."""

    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return items
        keyed_items = data.get(key)
        if isinstance(keyed_items, list):
            return keyed_items
    items = payload.get("items")
    if isinstance(items, list):
        return items
    keyed_items = payload.get(key)
    return keyed_items if isinstance(keyed_items, list) else []


def server_endpoint_parts(endpoint: str) -> tuple[str, int]:
    """Returns one live eD2K server endpoint as address and port."""

    address, port_text = endpoint.rsplit(":", 1)
    return address, int(port_text)


def operator_server_parts() -> tuple[str, int]:
    """Returns the default live eD2K operator server as address and port."""

    return server_endpoint_parts(OPERATOR_SERVER)


def ensure_operator_server(
    base_url: str,
    api_key: str,
    *,
    endpoint: str = OPERATOR_SERVER,
    name: str = OPERATOR_SERVER_NAME,
) -> dict[str, Any]:
    """Ensures one configured live eD2K server is present before connect."""

    address, port = server_endpoint_parts(endpoint)
    server = {"address": address, "port": port, "name": name, "static": True}
    servers = retry_http_json(
        "operator server list",
        3,
        base_url,
        "/api/v1/servers",
        api_key=api_key,
        timeout_seconds=15.0,
    )
    rows = api_items(servers, "servers")
    matching = [
        row
        for row in rows
        if isinstance(row, dict)
        and str(row.get("address") or "").casefold() == address.casefold()
        and int(row.get("port") or 0) == port
    ]
    if matching:
        server_info = dict(matching[0])
        if not bool(server_info.get("static")):
            update_result = retry_http_json(
                "operator server static",
                3,
                base_url,
                f"/api/v1/servers/{endpoint}",
                api_key=api_key,
                method="PATCH",
                body={"static": True},
                timeout_seconds=15.0,
            )
            return {
                "preloaded": True,
                "server": server_info,
                "staticUpdated": True,
                "update": update_result,
            }
        return {"preloaded": True, "server": server_info, "staticUpdated": False}
    add_result = retry_http_json(
        "operator server add",
        3,
        base_url,
        "/api/v1/servers",
        api_key=api_key,
        method="POST",
        body=server,
        timeout_seconds=15.0,
    )
    return {"preloaded": False, "server": server, "add": add_result}


def connect_operator_server(
    base_url: str,
    api_key: str,
    *,
    description: str,
    endpoint: str = OPERATOR_SERVER,
    name: str = OPERATOR_SERVER_NAME,
) -> dict[str, Any]:
    """Connects one client to the configured live eD2K server."""

    ensured = ensure_operator_server(base_url, api_key, endpoint=endpoint, name=name)
    connected = retry_http_json(
        description,
        3,
        base_url,
        f"/api/v1/servers/{endpoint}/operations/connect",
        api_key=api_key,
        method="POST",
        body={},
        timeout_seconds=15.0,
    )
    return {"ensure": ensured, "connect": connected}


def wait_for_mfc_core_rest_ready(base_url: str, api_key: str, timeout_seconds: float) -> dict[str, Any]:
    """Waits for MFC REST surfaces that lag behind the listener on large profiles."""

    def core_ready() -> dict[str, Any] | None:
        status = retry_http_json(
            "MFC status readiness",
            1,
            base_url,
            "/api/v1/status",
            api_key=api_key,
            timeout_seconds=15.0,
        )
        servers = retry_http_json(
            "MFC server-list readiness",
            1,
            base_url,
            "/api/v1/servers",
            api_key=api_key,
            timeout_seconds=15.0,
        )
        return {"status": status, "servers": servers}

    return wait_until("MFC core REST readiness", timeout_seconds, core_ready)


def apply_mfc_soak_preferences(
    *,
    live_common: ModuleType,
    config_dir: Path,
    upload_limit_kibps: int,
    log_trim_bytes: int,
) -> None:
    """Persists MFC live-soak preferences that must be true before launch."""

    live_common.apply_emule_preferences(
        config_dir,
        (
            ("MaxUpload", str(upload_limit_kibps)),
            ("SaveLogToDisk", "1"),
            ("SaveDebugToDisk", "1"),
            ("VerboseOptions", "1"),
            ("Verbose", "1"),
            ("FullVerbose", "1"),
            ("MaxLogFileSize", str(log_trim_bytes)),
            ("MaxLogBuff", "256"),
            ("LogFileFormat", "0"),
        ),
    )


def apply_mfc_endpoint_ports(
    *,
    live_common: ModuleType,
    config_dir: Path,
    ed2k_port: int,
    kad_port: int,
    server_udp_port: int,
) -> None:
    """Persists the MFC P2P endpoint ports before launch."""

    live_common.apply_emule_preferences(
        config_dir,
        (
            ("Port", str(ed2k_port)),
            ("UDPPort", str(kad_port)),
            ("ServerUDPPort", str(server_udp_port)),
        ),
    )


def load_scripts_module(module_name: str, filename: str) -> ModuleType:
    """Loads one hyphenated helper script from ``scripts/`` as an importable module."""

    module_path = SCRIPTS_DIR / filename
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def load_helper_modules(suffix: str) -> dict[str, ModuleType]:
    """Loads the reused live-driver scripts and pins the rust REST api key.

    ``suffix`` disambiguates the synthetic module names so the launcher and the
    observer can each load their own copies without colliding in ``sys.modules``.
    Returns a dict with ``rust``, ``live_common``, ``rest_smoke``, ``shared_dirs``.
    """

    rust_mod = load_scripts_module(f"rust_live_wire_{suffix}", "rust-live-wire-hideme.py")
    setattr(rust_mod, "API_KEY", RUST_API_KEY)  # noqa: B010 - reused helpers auth with this
    return {
        "rust": rust_mod,
        "live_common": load_scripts_module(f"emule_live_profile_common_{suffix}", "emule-live-profile-common.py"),
        "rest_smoke": load_scripts_module(f"rest_api_smoke_{suffix}", "rest-api-smoke.py"),
        "shared_dirs": load_scripts_module(f"shared_directories_rest_e2e_{suffix}", "shared-directories-rest-e2e.py"),
    }


def bring_up_rust(
    *,
    rust_mod: ModuleType,
    exe_path: Path,
    bind_ip: str,
    rest_addr: str,
    rest_port: int,
    runtime_dir: Path,
    packet_dump_dir: Path,
    incoming_dir: Path | None,
    bootstrap_nodes: list[str],
    shared_roots: list[object],
    server_met_url: str,
    server_endpoint: str,
    obfuscation: bool,
    timeouts: dict[str, float],
    upload_limit_kibps: int = DEFAULT_UPLOAD_LIMIT_KIBPS,
    ed2k_port: int = RUST_ED2K_PORT,
    kad_port: int = RUST_KAD_PORT,
) -> dict[str, Any]:
    """Starts the rust daemon on the persistent runtime and returns live handles."""

    runtime_dir.mkdir(parents=True, exist_ok=True)
    packet_dump_dir.mkdir(parents=True, exist_ok=True)
    config_path = runtime_dir / "emulebb-rust.toml"
    base_url = f"http://{rest_addr}:{rest_port}"

    write_rust_config(
        config_path,
        runtime_dir=runtime_dir,
        incoming_dir=incoming_dir,
        rest_addr=rest_addr,
        rest_port=rest_port,
        api_key=RUST_API_KEY,
        p2p_bind_ip=bind_ip,
        p2p_bind_interface="hide.me",
        ed2k_port=ed2k_port,
        kad_port=kad_port,
        server_endpoint=server_endpoint,
        obfuscation_enabled=obfuscation,
        kad_bootstrap_nodes=bootstrap_nodes,
        kad_bootstrap_min_routing_contacts=2,
    )
    with config_path.open("a", encoding="utf-8") as cfg:
        cfg.write("\n[nat]\nenabled = true\n")

    os.environ["EMULEBB_RUST_LOG_DIR"] = str(packet_dump_dir)
    handle = (runtime_dir / "daemon.out").open("a", encoding="utf-8")
    process = start_rust_client_executable_with_output(exe_path, config_path, handle)

    wait_until("rust REST ready", timeouts["rest"], lambda: rust_mod.get_stats(base_url) or None)
    patch_upload_limit(base_url, RUST_API_KEY, upload_limit_kibps)
    if server_met_url:
        rust_mod.import_server_met(base_url, server_met_url)
    retry_http_json(
        "rust kad start", 3, base_url, "/api/v1/kad/operations/start",
        api_key=RUST_API_KEY, method="POST", body={},
    )
    connect_operator_server(
        base_url,
        RUST_API_KEY,
        description="rust server connect",
        endpoint=server_endpoint,
    )
    rust_mod.share_directories(base_url, shared_roots)
    connect_operator_server(
        base_url,
        RUST_API_KEY,
        description="rust server reconnect after share import",
        endpoint=server_endpoint,
    )

    def connected() -> dict[str, Any] | None:
        stats = rust_mod.get_stats(base_url)
        return stats if stats.get("ed2kConnected") else None

    stats = wait_until("rust ED2K connected", timeouts["connect"], connected)
    log(f"rust connected (highId={bool(stats.get('ed2kHighId'))}) - REST {base_url}")
    return {
        "process": process,
        "logHandle": handle,
        "baseUrl": base_url,
        "packetDumpDir": packet_dump_dir,
    }


def bring_up_mfc(
    *,
    live_common: ModuleType,
    rest_smoke: ModuleType,
    shared_dirs_mod: ModuleType,
    exe_path: Path,
    artifacts_dir: Path,
    seed_config_dir: Path,
    direct_profile_dir: Path | None = None,
    rest_host: str,
    rest_port: int,
    shared_roots: list[object],
    server_endpoint: str,
    obfuscation: bool,
    timeouts: dict[str, float],
    upload_limit_kibps: int = DEFAULT_UPLOAD_LIMIT_KIBPS,
    log_trim_bytes: int = DEFAULT_LOG_TRIM_BYTES,
    ed2k_port: int = MFC_ED2K_PORT,
    kad_port: int = MFC_KAD_PORT,
    server_udp_port: int = MFC_SERVER_UDP_PORT,
) -> dict[str, Any]:
    """Launches the MFC diagnostics GUI on the persistent profile (left open)."""

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{rest_host}:{rest_port}"
    if direct_profile_dir is None:
        profile = live_common.prepare_profile_base(
            seed_config_dir,
            artifacts_dir,
            shared_dirs=shared_root_paths(shared_roots),
            scenario_id="converged-soak",
            reuse_existing=True,
        )
        config_dir = Path(str(profile["config_dir"]))
        profile_base = Path(str(profile["profile_base"]))
        packet_dump_dir = Path(str(profile["log_dir"]))
        replace_shared_roots = True
    else:
        profile_base = direct_profile_dir
        config_dir = profile_base / "config"
        if not (config_dir / "preferences.ini").is_file():
            raise RuntimeError(f"Direct MFC profile is missing config/preferences.ini: {config_dir}")
        packet_dump_dir = profile_base / "logs"
        packet_dump_dir.mkdir(parents=True, exist_ok=True)
        replace_shared_roots = False

    rest_smoke.configure_webserver_profile(
        config_dir,
        exe_path,
        MFC_API_KEY,
        rest_port,
        rest_host,
        enable_crash_test_endpoint=True,
    )
    apply_mfc_endpoint_ports(
        live_common=live_common,
        config_dir=config_dir,
        ed2k_port=ed2k_port,
        kad_port=kad_port,
        server_udp_port=server_udp_port,
    )
    rest_smoke.apply_p2p_bind_interface_override(config_dir, "hide.me")
    live_common.apply_private_harness_obfuscation(config_dir, obfuscation)
    apply_mfc_soak_preferences(
        live_common=live_common,
        config_dir=config_dir,
        upload_limit_kibps=upload_limit_kibps,
        log_trim_bytes=log_trim_bytes,
    )

    app = live_common.launch_app(exe_path, profile_base)
    rest_smoke.wait_for_rest_ready(base_url, MFC_API_KEY, timeouts["rest"])
    wait_for_mfc_core_rest_ready(base_url, MFC_API_KEY, timeouts["rest"])
    try:
        patch_upload_limit(base_url, MFC_API_KEY, upload_limit_kibps)
    except RuntimeError as exc:
        log(f"MFC upload cap REST patch skipped after persisted profile cap: {type(exc).__name__}")

    connect_operator_server(
        base_url,
        MFC_API_KEY,
        description="MFC server connect",
        endpoint=server_endpoint,
    )
    rest_smoke.observe_server_connect_attempt(base_url, MFC_API_KEY, min(timeouts["connect"], 120.0))
    rest_smoke.http_request(
        base_url, "/api/v1/kad/operations/start", method="POST", api_key=MFC_API_KEY, json_body={}
    )
    if replace_shared_roots:
        roots_payload = {
            "confirmReplaceRoots": True,
            "roots": [normalize_shared_root_entry(root) for root in shared_roots],
        }
        shared_dirs_mod.patch_shared_directories(base_url, MFC_API_KEY, roots_payload)
    log(f"MFC diagnostics GUI up - REST {base_url}, profile {profile_base}")
    return {"app": app, "baseUrl": base_url, "packetDumpDir": packet_dump_dir}
