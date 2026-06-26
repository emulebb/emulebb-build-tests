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
from .vm_guest_profiles import retry_http_json, wait_until

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

# Same lab wiring as the converged single-pass orchestrator so both campaigns are
# like-for-like (operator server, high ports, REST api keys, server.met source).
OPERATOR_SERVER = "45.82.80.155:5687"
DEFAULT_SERVER_MET_URL = "https://upd.emule-security.org/server.met"
DEFAULT_MFC_SEED_CONFIG_DIR = REPO_ROOT / "manifests" / "live-profile-seed" / "config"
ED2K_PORT = 42662
KAD_PORT = 42672
RUST_API_KEY = "converged-soak"
MFC_API_KEY = "converged-soak-mfc"


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
    bootstrap_nodes: list[str],
    shared_roots: list[str],
    server_met_url: str,
    obfuscation: bool,
    timeouts: dict[str, float],
) -> dict[str, Any]:
    """Starts the rust daemon on the persistent runtime and returns live handles."""

    runtime_dir.mkdir(parents=True, exist_ok=True)
    packet_dump_dir.mkdir(parents=True, exist_ok=True)
    config_path = runtime_dir / "emulebb-rust.toml"
    base_url = f"http://{rest_addr}:{rest_port}"

    write_rust_config(
        config_path,
        runtime_dir=runtime_dir,
        rest_addr=rest_addr,
        rest_port=rest_port,
        api_key=RUST_API_KEY,
        p2p_bind_ip=bind_ip,
        p2p_bind_interface="hide.me",
        ed2k_port=ED2K_PORT,
        kad_port=KAD_PORT,
        server_endpoint=OPERATOR_SERVER,
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
    if server_met_url:
        rust_mod.import_server_met(base_url, server_met_url)
    retry_http_json(
        "rust kad start", 3, base_url, "/api/v1/kad/operations/start",
        api_key=RUST_API_KEY, method="POST", body={},
    )
    retry_http_json(
        "rust server connect", 3, base_url,
        f"/api/v1/servers/{OPERATOR_SERVER}/operations/connect",
        api_key=RUST_API_KEY, method="POST", body={}, timeout_seconds=15.0,
    )
    rust_mod.share_directories(base_url, shared_roots)

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
    seed_config_dir: Path,
    artifacts_dir: Path,
    rest_host: str,
    rest_port: int,
    shared_roots: list[str],
    obfuscation: bool,
    timeouts: dict[str, float],
) -> dict[str, Any]:
    """Launches the MFC diagnostics GUI on the persistent profile (left open)."""

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://{rest_host}:{rest_port}"
    profile = live_common.prepare_profile_base(
        seed_config_dir,
        artifacts_dir,
        shared_dirs=list(shared_roots),
        scenario_id="converged-soak",
        reuse_existing=True,
    )
    config_dir = Path(str(profile["config_dir"]))
    packet_dump_dir = Path(str(profile["log_dir"]))

    rest_smoke.configure_webserver_profile(config_dir, exe_path, MFC_API_KEY, rest_port, rest_host)
    rest_smoke.apply_p2p_bind_interface_override(config_dir, "hide.me")
    live_common.apply_private_harness_obfuscation(config_dir, obfuscation)

    app = live_common.launch_app(exe_path, Path(str(profile["profile_base"])))
    rest_smoke.wait_for_rest_ready(base_url, MFC_API_KEY, timeouts["rest"])

    rest_smoke.http_request(
        base_url, f"/api/v1/servers/{OPERATOR_SERVER}/operations/connect",
        method="POST", api_key=MFC_API_KEY, json_body={}, request_timeout_seconds=15.0,
    )
    rest_smoke.observe_server_connect_attempt(base_url, MFC_API_KEY, min(timeouts["connect"], 120.0))
    rest_smoke.http_request(
        base_url, "/api/v1/kad/operations/start", method="POST", api_key=MFC_API_KEY, json_body={}
    )
    roots_payload = {
        "confirmReplaceRoots": True,
        "roots": [r if r.endswith(("\\", "/")) else r + "\\" for r in shared_roots],
    }
    shared_dirs_mod.patch_shared_directories(base_url, MFC_API_KEY, roots_payload)
    log(f"MFC diagnostics GUI up - REST {base_url}, profile {profile['profile_base']}")
    return {"app": app, "baseUrl": base_url, "packetDumpDir": packet_dump_dir}
