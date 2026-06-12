"""Bidirectional cross-client eD2K transfer between eMuleBB Rust and eMuleBB via REST."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import goed2k  # noqa: E402
from emule_test_harness import rust_client  # noqa: E402
from emule_test_harness.script_modules import load_script_module  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES, resolve_manifest_repo  # noqa: E402


harness_cli_common = load_script_module("harness_cli_common", "harness-cli-common.py")
live_common = load_script_module("emule_live_profile_common", "emule-live-profile-common.py")
dtt = load_script_module("deterministic_two_client_transfer", "deterministic-two-client-transfer.py")

SUITE_NAME = "emulebb-rust-emulebb-cross-client"
API_KEY = "emulebb-rust-emulebb-cross-client-key"
CLIENT_EMULEBB = CLIENT_IDENTITIES["emulebb"]
CLIENT_RUST = CLIENT_IDENTITIES["emulebb_rust"]
ED2K_PART_SIZE_BYTES = 9_728_000
UNICODE_FIXTURE_SUFFIX = "Unicode-\u00e9-\u6f22"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses the Rust/eMuleBB cross-client suite arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--p2p-bind-interface-name", default="")
    parser.add_argument("--p2p-bind-interface-address")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--transfer-completion-timeout-seconds", type=float, default=900.0)
    parser.add_argument("--fixture-size-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    return parser.parse_args(argv)


def choose_extra_port(lan_bind_addr: str, used_ports: set[int], *, udp: bool = False) -> int:
    for _ in range(100):
        candidate = dtt.rest_smoke.choose_listen_port(lan_bind_addr)
        if candidate not in used_ports and dtt.is_port_available(candidate, host=lan_bind_addr, udp=udp):
            used_ports.add(candidate)
            return candidate
    raise RuntimeError("Could not allocate an extra LAN port.")


def request_json(base_url: str, method: str, path: str, api_key: str, body: dict[str, object] | None = None) -> dict[str, object]:
    result = dtt.retry_rest_request(
        base_url,
        path,
        method=method,
        api_key=api_key,
        json_body=body,
        timeout_seconds=30.0,
    )
    if int(result.get("status", 0)) != 200:
        raise RuntimeError(f"REST request failed: {method} {path} {dtt.rest_smoke.compact_http_result(result)!r}")
    return dtt.rest_smoke.require_json_object(result, 200)


def wait_for_rust_rest(
    base_url: str,
    process: subprocess.Popen[str],
    output_path: Path,
    api_key: str,
    timeout_seconds: float,
) -> dict[str, object]:
    def resolve():
        if process.poll() is not None:
            raise RuntimeError(f"emulebb-rust exited early with code {process.returncode}: {output_path.read_text(encoding='utf-8', errors='replace')[-2000:]}")
        try:
            payload = request_json(base_url, "GET", "/api/v1/app", api_key)
        except (OSError, RuntimeError):
            return None
        return payload

    return live_common.wait_for(resolve, timeout_seconds, 0.5, "emulebb-rust REST ready")


def wait_for_rust_ed2k_connected(base_url: str, api_key: str, timeout_seconds: float) -> dict[str, object]:
    def resolve():
        data = request_json(base_url, "GET", "/api/v1/status", api_key)
        stats = data.get("stats") if isinstance(data, dict) else None
        if isinstance(stats, dict) and stats.get("ed2kConnected"):
            return data
        return None

    return live_common.wait_for(resolve, timeout_seconds, 0.5, "emulebb-rust ED2K connected")


def wait_for_rust_transfer_completed(
    base_url: str,
    api_key: str,
    transfer_hash: str,
    runtime_dir: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until Rust completes one transfer and verifies the persisted bytes."""

    observations: list[dict[str, object]] = []
    pieces_path = runtime_dir / "transfers" / transfer_hash.lower() / "pieces.bin"

    def resolve():
        data = request_json(base_url, "GET", f"/api/v1/transfers/{transfer_hash}", api_key)
        row = dict(data) if isinstance(data, dict) else {"payload": data}
        row["observed_at"] = round(time.time(), 3)
        row["pieces_file"] = dtt.snapshot_file(pieces_path, hash_limit_bytes=expected_size)
        observations.append(row)
        if (
            isinstance(data, dict)
            and data.get("state") == "completed"
            and int(data.get("completedBytes") or 0) == expected_size
            and pieces_path.is_file()
            and pieces_path.stat().st_size == expected_size
            and dtt.file_sha256(pieces_path) == expected_sha256
        ):
            result = dict(row)
            result["observations"] = observations[-20:]
            return result
        return None

    return live_common.wait_for(resolve, timeout_seconds, 1.0, f"emulebb-rust transfer {transfer_hash} completion")


def wait_for_rust_search_result(
    base_url: str,
    api_key: str,
    *,
    query: str,
    transfer_hash: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until Rust server search returns the expected file hash."""

    observations: list[dict[str, object]] = []
    normalized_hash = transfer_hash.lower()

    def resolve():
        search = request_json(
            base_url,
            "POST",
            "/api/v1/searches",
            api_key,
            {"query": query, "method": "server", "type": ""},
        )
        results = search.get("results") if isinstance(search, dict) else None
        result_count = len(results) if isinstance(results, list) else 0
        observations.append({"result_count": result_count, "observed_at": round(time.time(), 3)})
        if not isinstance(results, list):
            return None
        for result in results:
            if isinstance(result, dict) and str(result.get("hash") or "").lower() == normalized_hash:
                return {
                    "search": search,
                    "result": result,
                    "observations": observations[-20:],
                }
        return None

    return live_common.wait_for(resolve, timeout_seconds, 1.0, f"emulebb-rust server search result {normalized_hash}")


def require_rust_download_manifest_metadata(
    runtime_dir: Path,
    *,
    transfer_hash: str,
    expected_name: str,
    expected_size: int,
    require_aich_hashset: bool,
) -> dict[str, object]:
    """Requires Rust to persist stock metadata learned from a cross-client source."""

    manifest_path = runtime_dir / "transfers" / transfer_hash.lower() / "resume-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_part_count = max(1, (expected_size + ED2K_PART_SIZE_BYTES - 1) // ED2K_PART_SIZE_BYTES)
    md4_hashset = manifest.get("md4_hashset")
    aich_hashset = manifest.get("aich_hashset")
    sources = manifest.get("sources")
    if str(manifest.get("file_hash") or "").lower() != transfer_hash.lower():
        raise RuntimeError("Rust cross-client manifest has the wrong file hash.")
    if manifest.get("canonical_name") != expected_name:
        raise RuntimeError("Rust cross-client manifest did not preserve the canonical file name.")
    if int(manifest.get("file_size") or 0) != expected_size:
        raise RuntimeError("Rust cross-client manifest did not preserve the file size.")
    if manifest.get("md4_hashset_acquired") is not True or not isinstance(md4_hashset, list):
        raise RuntimeError("Rust did not acquire the MD4 hashset from the cross-client source.")
    if len(md4_hashset) != expected_part_count:
        raise RuntimeError(
            f"Rust acquired {len(md4_hashset)} MD4 parts from the cross-client source, expected {expected_part_count}."
        )
    if require_aich_hashset:
        if manifest.get("aich_hashset_acquired") is not True or not isinstance(aich_hashset, list):
            raise RuntimeError("Rust did not acquire the AICH hashset from the cross-client source.")
        if len(aich_hashset) != expected_part_count:
            raise RuntimeError(
                f"Rust acquired {len(aich_hashset)} AICH parts from the cross-client source, expected {expected_part_count}."
            )
    if not isinstance(sources, list) or not sources:
        raise RuntimeError("Rust cross-client manifest did not persist any transfer source.")
    source_user_hashes = [
        str(source.get("user_hash") or "")
        for source in sources
        if isinstance(source, dict) and is_lower_hex_32(str(source.get("user_hash") or ""))
    ]
    if not source_user_hashes:
        raise RuntimeError("Rust cross-client manifest did not persist the peer user hash.")
    return {
        "manifestPath": str(manifest_path),
        "fileHash": str(manifest.get("file_hash") or "").lower(),
        "canonicalName": manifest.get("canonical_name"),
        "fileSize": int(manifest.get("file_size") or 0),
        "expectedPartCount": expected_part_count,
        "md4HashsetAcquired": bool(manifest.get("md4_hashset_acquired")),
        "md4HashsetCount": len(md4_hashset),
        "aichRoot": str(manifest.get("aich_root") or ""),
        "aichHashsetAcquired": bool(manifest.get("aich_hashset_acquired")),
        "aichHashsetCount": len(aich_hashset) if isinstance(aich_hashset, list) else 0,
        "sourceCount": len(sources),
        "sourceUserHashCount": len(source_user_hashes),
    }


def is_lower_hex_32(value: str) -> bool:
    """Returns whether a persisted peer hash has the REST manifest shape."""

    return len(value) == 32 and all(char in "0123456789abcdef" for char in value)


def rust_to_emulebb_fixture_name() -> str:
    """Returns the Rust-seeded cross-client Unicode fixture name."""

    return f"emulebb-rust-to-emulebb-{UNICODE_FIXTURE_SUFFIX}.bin"


def emulebb_to_rust_fixture_name() -> str:
    """Returns the eMuleBB-seeded cross-client Unicode fixture name."""

    return f"emulebb-to-emulebb-rust-{UNICODE_FIXTURE_SUFFIX}.bin"


def decoded_ed2k_link_name(link_info: dict[str, object]) -> str:
    """Returns the display filename from a parsed ED2K link."""

    return unquote(str(link_info.get("name") or ""))


def require_cross_client_requirements(report: dict[str, object]) -> dict[str, object]:
    """Checks the high-level Rust/eMuleBB ED2K parity surfaces proven by the report."""

    fixture = report.get("fixture")
    emulebb_fixture = report.get("emulebb_fixture")
    checks = report.get("checks")
    if not isinstance(fixture, dict) or not isinstance(emulebb_fixture, dict) or not isinstance(checks, dict):
        raise RuntimeError("Rust/eMuleBB cross-client report is missing fixture or check sections.")
    rust_fixture_name = str(fixture.get("name") or "")
    emulebb_fixture_name = str(emulebb_fixture.get("name") or "")
    if rust_fixture_name.isascii() or emulebb_fixture_name.isascii():
        raise RuntimeError("Rust/eMuleBB cross-client fixtures did not use Unicode filenames.")
    manifest_metadata = checks.get("rust_emulebb_manifest_metadata")
    if not isinstance(manifest_metadata, dict):
        raise RuntimeError("Rust/eMuleBB cross-client report is missing Rust manifest metadata.")
    if manifest_metadata.get("canonicalName") != emulebb_fixture_name:
        raise RuntimeError("Rust/eMuleBB cross-client manifest did not preserve the Unicode canonical name.")
    if int(manifest_metadata.get("sourceUserHashCount") or 0) < 1:
        raise RuntimeError("Rust/eMuleBB cross-client manifest did not persist source userHash metadata.")
    if int(manifest_metadata.get("md4HashsetCount") or 0) < 1 or int(manifest_metadata.get("aichHashsetCount") or 0) < 1:
        raise RuntimeError("Rust/eMuleBB cross-client manifest did not persist MD4/AICH hashset metadata.")
    return {
        "bidirectionalTransfers": True,
        "unicodeFixtureNames": True,
        "rustToEmulebbUnicodeName": rust_fixture_name,
        "emulebbToRustUnicodeName": emulebb_fixture_name,
        "rustPersistedSourceUserHash": True,
        "rustPersistedMd4Hashset": True,
        "rustPersistedAichHashset": True,
    }


def main(argv: list[str] | None = None) -> int:
    """Runs the bidirectional Rust/eMuleBB cross-client transfer scenario."""

    args = parse_args(argv)
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration=args.configuration,
        workspace_root=None,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    profile_seed_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "clients": [CLIENT_RUST.profile_id, CLIENT_EMULEBB.profile_id],
        "checks": {},
    }
    server_process: subprocess.Popen | None = None
    rust_process: subprocess.Popen[str] | None = None
    emulebb_app = None
    current_phase = "initializing"
    try:
        p2p_address = args.p2p_bind_interface_address or dtt.discover_interface_ipv4(args.p2p_bind_interface_name)
        ports = dtt.choose_distinct_ports(args.lan_bind_addr)
        used_ports = set(ports.values())
        rust_rest_port = choose_extra_port(args.lan_bind_addr, used_ports)
        rust_ed2k_port = choose_extra_port(args.lan_bind_addr, used_ports)
        rust_kad_port = choose_extra_port(args.lan_bind_addr, used_ports)
        server_endpoint = f"{p2p_address}:{ports['ed2k_tcp']}"
        report["network"] = {
            "lan_bind_addr": args.lan_bind_addr,
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
            "server_endpoint": server_endpoint,
            "ports": {**ports, "rust_rest": rust_rest_port, "rust_ed2k": rust_ed2k_port, "rust_kad": rust_kad_port},
        }

        rust_repo = resolve_manifest_repo(paths.workspace_root, "emulebb_rust")
        if not (rust_repo / "Cargo.toml").is_file():
            raise RuntimeError(f"emulebb-rust repo is missing Cargo.toml: {rust_repo}")

        server_dir = paths.source_artifacts_dir / "ed2k-server"
        current_phase = "start_ed2k_server"
        ed2k_server = goed2k.launch_ed2k_server(
            workspace_root=paths.workspace_root,
            server_dir=server_dir,
            ed2k_port=ports["ed2k_tcp"],
            admin_port=ports["ed2k_admin"],
            token=args.api_key,
            admin_address=args.lan_bind_addr,
            ed2k_address=p2p_address,
            repo_override=args.ed2k_server_repo,
            exe_override=args.ed2k_server_exe,
        )
        server_process = ed2k_server.process
        admin_base_url = ed2k_server.admin_base_url
        report["checks"]["server_build"] = ed2k_server.build
        report["checks"]["ed2k_server_health"] = ed2k_server.health
        report["ed2k_server"] = ed2k_server.config

        fixture_path = paths.source_artifacts_dir / "rust-shared" / rust_to_emulebb_fixture_name()
        fixture_sha256 = dtt.write_fixture_file(fixture_path, args.fixture_size_bytes)
        report["fixture"] = {
            "path": str(fixture_path),
            "name": fixture_path.name,
            "size": args.fixture_size_bytes,
            "sha256": fixture_sha256,
            "unicode_name": True,
        }

        rust_runtime = paths.source_artifacts_dir / "rust-runtime"
        rust_config = paths.source_artifacts_dir / "rust.toml"
        rust_client.write_rust_config(
            rust_config,
            runtime_dir=rust_runtime,
            rest_addr=args.lan_bind_addr,
            rest_port=rust_rest_port,
            api_key=args.api_key,
            p2p_bind_ip=p2p_address,
            ed2k_port=rust_ed2k_port,
            kad_port=rust_kad_port,
            server_endpoint=server_endpoint,
        )
        current_phase = "launch_rust"
        rust_process = rust_client.start_rust_client(rust_repo, rust_config, paths.source_artifacts_dir / "rust.out")
        rust_base_url = f"http://{args.lan_bind_addr}:{rust_rest_port}"
        report["checks"]["rust_rest_ready"] = wait_for_rust_rest(
            rust_base_url,
            rust_process,
            paths.source_artifacts_dir / "rust.out",
            args.api_key,
            args.rest_ready_timeout_seconds,
        )
        report["checks"]["rust_connect"] = request_json(rust_base_url, "POST", "/api/v1/servers/operations/connect", args.api_key)
        report["checks"]["rust_ed2k_connected"] = wait_for_rust_ed2k_connected(rust_base_url, args.api_key, args.server_connect_timeout_seconds)
        shared = request_json(rust_base_url, "POST", "/api/v1/shared-files", args.api_key, {"path": str(fixture_path)})
        rust_file = shared["file"]
        link = str(rust_file["ed2kLink"])
        link_info = dtt.parse_ed2k_file_link(link)
        transfer_hash = str(link_info["hash"])
        report["checks"]["rust_shared_file"] = rust_file
        report["checks"]["rust_server_file"] = goed2k.wait_for_server_file(admin_base_url, args.api_key, transfer_hash, args.server_publish_timeout_seconds)

        emulebb = live_common.prepare_scenario_profile(profile_seed_dir, paths.source_artifacts_dir, [], CLIENT_EMULEBB.profile_id)
        dtt.configure_client_profile(
            config_dir=Path(emulebb["config_dir"]),
            app_exe=paths.app_exe,
            nick=CLIENT_EMULEBB.nick,
            tcp_port=ports["client1_tcp"],
            udp_port=ports["client1_udp"],
            ed2k_enabled=True,
            autoconnect=False,
            rest_api_key=args.api_key,
            rest_port=ports["client1_rest"],
            lan_bind_addr=args.lan_bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
            p2p_bind_addr=p2p_address,
        )
        dtt.write_server_met(Path(emulebb["config_dir"]) / "server.met", address=p2p_address, port=ports["ed2k_tcp"], name="emulebb-local-e2e")
        current_phase = "launch_emulebb"
        emulebb_app = live_common.launch_app(paths.app_exe, Path(emulebb["profile_base"]), minimized_to_tray=True)
        emulebb_base_url = f"http://{args.lan_bind_addr}:{ports['client1_rest']}"
        report["checks"]["emulebb_rest_ready"] = dtt.rest_smoke.compact_http_result(
            dtt.rest_smoke.wait_for_rest_ready(emulebb_base_url, args.api_key, args.rest_ready_timeout_seconds)
        )
        report["checks"]["emulebb_server_connect"] = dtt.add_and_connect_server(
            emulebb_base_url,
            args.api_key,
            address=p2p_address,
            port=ports["ed2k_tcp"],
            timeout_seconds=args.server_connect_timeout_seconds,
        )
        report["checks"]["emulebb_transfer_add"] = dtt.add_transfer(emulebb_base_url, args.api_key, link, transfer_hash)
        completed_path = Path(emulebb["incoming_dir"]) / str(link_info["name"])
        report["checks"]["emulebb_completed_file"] = dtt.wait_for_completed_file(
            completed_path,
            expected_size=int(link_info["size"]),
            expected_sha256=fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
            snapshot_callback=lambda: dtt.collect_client1_transfer_snapshot(
                base_url=emulebb_base_url,
                api_key=args.api_key,
                transfer_hash=transfer_hash,
                incoming_path=completed_path,
                temp_dir=Path(emulebb["temp_dir"]),
                hash_limit_bytes=max(int(link_info["size"]), args.fixture_size_bytes),
            ),
        )
        emulebb_fixture_path = paths.source_artifacts_dir / "emulebb-shared" / emulebb_to_rust_fixture_name()
        emulebb_fixture_sha256 = dtt.write_fixture_file(emulebb_fixture_path, args.fixture_size_bytes, seed=0xE1BB2026)
        report["emulebb_fixture"] = {
            "path": str(emulebb_fixture_path),
            "name": emulebb_fixture_path.name,
            "size": args.fixture_size_bytes,
            "sha256": emulebb_fixture_sha256,
            "unicode_name": True,
        }
        report["checks"]["emulebb_shared_file_add"] = dtt.add_emule_shared_file(
            emulebb_base_url,
            args.api_key,
            emulebb_fixture_path,
        )
        report["checks"]["emulebb_shared_file_reload"] = dtt.reload_emule_shared_files(emulebb_base_url, args.api_key)
        emulebb_shared_link = dtt.wait_for_emule_shared_file_link(
            emulebb_base_url,
            args.api_key,
            file_name=emulebb_fixture_path.name,
            timeout_seconds=args.link_export_timeout_seconds,
        )
        report["checks"]["emulebb_shared_file_link"] = emulebb_shared_link
        emulebb_link = str(emulebb_shared_link["link"])
        emulebb_link_info = dtt.parse_ed2k_file_link(emulebb_link)
        emulebb_transfer_hash = str(emulebb_link_info["hash"])
        report["checks"]["emulebb_server_file"] = goed2k.wait_for_server_file(
            admin_base_url,
            args.api_key,
            emulebb_transfer_hash,
            args.server_publish_timeout_seconds,
        )
        rust_reverse_search = wait_for_rust_search_result(
            rust_base_url,
            args.api_key,
            query="emulebb-to-emulebb-rust",
            transfer_hash=emulebb_transfer_hash,
            timeout_seconds=args.server_publish_timeout_seconds,
        )
        report["checks"]["rust_reverse_search"] = rust_reverse_search
        rust_search = rust_reverse_search["search"]
        report["checks"]["rust_reverse_download"] = request_json(
            rust_base_url,
            "POST",
            f"/api/v1/searches/{rust_search['id']}/results/{emulebb_transfer_hash}/operations/download",
            args.api_key,
            {"paused": False},
        )
        report["checks"]["rust_reverse_resume"] = request_json(
            rust_base_url,
            "POST",
            f"/api/v1/transfers/{emulebb_transfer_hash}/operations/resume",
            args.api_key,
        )
        report["checks"]["rust_completed_reverse_file"] = wait_for_rust_transfer_completed(
            rust_base_url,
            args.api_key,
            emulebb_transfer_hash,
            rust_runtime,
            expected_size=int(emulebb_link_info["size"]),
            expected_sha256=emulebb_fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
        )
        report["checks"]["rust_emulebb_manifest_metadata"] = require_rust_download_manifest_metadata(
            rust_runtime,
            transfer_hash=emulebb_transfer_hash,
            expected_name=decoded_ed2k_link_name(emulebb_link_info),
            expected_size=int(emulebb_link_info["size"]),
            require_aich_hashset=True,
        )
        report["checks"]["rust_emulebb_cross_client_requirements"] = require_cross_client_requirements(report)
        report["checks"]["ed2k_server_stats_final"] = goed2k.admin_request(admin_base_url, args.api_key, "/api/stats")
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["current_phase"] = current_phase
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        if isinstance(exc, dtt.TransferCompletionTimeout):
            report["checks"]["transfer_completion_timeout"] = {"observations": exc.observations}
        return 1
    finally:
        cleanup: dict[str, object] = {}
        if emulebb_app is not None:
            try:
                live_common.close_app_cleanly(emulebb_app)
                cleanup[CLIENT_EMULEBB.profile_id] = {"ok": True}
            except Exception as exc:
                cleanup[CLIENT_EMULEBB.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        rust_client.stop_process_tree(rust_process)
        goed2k.stop_process(server_process)
        report["cleanup"] = cleanup
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "emulebb-rust-emulebb-cross-client-result.json", report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
