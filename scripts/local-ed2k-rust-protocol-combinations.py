"""Local ED2K protocol-combination matrix for the eMuleBB Rust client."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from urllib.parse import unquote
from dataclasses import asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import goed2k  # noqa: E402
from emule_test_harness import rust_client  # noqa: E402
from emule_test_harness import rust_metadata  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES, resolve_manifest_repo  # noqa: E402
from emule_test_harness.script_modules import load_script_module  # noqa: E402


protocol_matrix = load_script_module("local_ed2k_protocol_combinations_for_rust", "local-ed2k-protocol-combinations.py")
rust_emulebb = load_script_module("emulebb_rust_emulebb_cross_client_for_protocol_matrix", "emulebb-rust-emulebb-cross-client.py")
dtt = protocol_matrix.dtt
harness_cli_common = protocol_matrix.harness_cli_common
live_common = protocol_matrix.live_common
rest_smoke = protocol_matrix.rest_smoke

SUITE_NAME = "local-ed2k-rust-protocol-combinations"
API_KEY = "local-ed2k-rust-protocol-combinations-key"
CLIENT_RUST = CLIENT_IDENTITIES["emulebb_rust"]
CLIENT_HARNESS = CLIENT_IDENTITIES["harness"]
SERVER_UDP_FLAG_EXT_GETSOURCES = 0x0000_0001
SERVER_UDP_FLAG_EXT_GETFILES = 0x0000_0002
SERVER_UDP_FLAG_EXT_GETSOURCES2 = 0x0000_0020
SERVER_UDP_FLAG_LARGEFILES = 0x0000_0100
SERVER_UDP_FLAG_UDPOBFUSCATION = 0x0000_0200
SERVER_UDP_FLAG_TCPOBFUSCATION = 0x0000_0400
ED2K_PART_SIZE_BYTES = 9_728_000
SECONDARY_FIXTURE_SIZE_BYTES = ED2K_PART_SIZE_BYTES + 1
HASH_ONLY_FIXTURE_SIZE_BYTES = (ED2K_PART_SIZE_BYTES * 2) + 1
UNICODE_FIXTURE_SUFFIX = "Unicode-\u00e9-\u6f22"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses standalone Rust protocol-combination matrix arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--client2-app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--p2p-bind-interface-name", default="")
    parser.add_argument("--p2p-bind-interface-address")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=90.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--transfer-completion-timeout-seconds", type=float, default=900.0)
    parser.add_argument("--fixture-size-bytes", type=int, default=dtt.DEFAULT_FIXTURE_SIZE_BYTES)
    parser.add_argument("--case", action="append", choices=tuple(protocol_matrix.PROTOCOL_CASE_MAP.keys()))
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    return parser.parse_args(argv)


def server_udp_flags(case: protocol_matrix.ProtocolCase) -> int:
    """Returns the stock capability flags advertised to Rust for one server case."""

    flags = (
        SERVER_UDP_FLAG_EXT_GETSOURCES
        | SERVER_UDP_FLAG_EXT_GETFILES
        | SERVER_UDP_FLAG_EXT_GETSOURCES2
        | SERVER_UDP_FLAG_LARGEFILES
    )
    if case.server_protocol_obfuscation:
        flags |= SERVER_UDP_FLAG_TCPOBFUSCATION
    if case.server_protocol_obfuscation and case.server_udp:
        flags |= SERVER_UDP_FLAG_UDPOBFUSCATION
    return flags


def rust_server_entry(case: protocol_matrix.ProtocolCase, host: str, tcp_port: int) -> dict[str, object]:
    """Builds the ED2K server-entry metadata Rust needs for obfuscated sessions."""

    udp_key = 0x11223344 if case.server_protocol_obfuscation and case.server_udp else 0
    return {
        "host": host,
        "port": tcp_port,
        "name": "emulebb-local-e2e",
        "description": "Workspace deterministic eMuleBB Rust protocol matrix server",
        "udpFlags": server_udp_flags(case),
        "udpKey": udp_key,
        "udpKeyIp": 0,
        "obfuscationPortTcp": tcp_port if case.server_protocol_obfuscation else 0,
        "obfuscationPortUdp": tcp_port + 4 if case.server_protocol_obfuscation and case.server_udp else 0,
    }


def rust_protocol_surface(case: protocol_matrix.ProtocolCase) -> dict[str, object]:
    """Returns the protocol surface covered by one Rust matrix case."""

    surface = protocol_matrix.protocol_surface(case)
    surface["rust_client_crypt"] = {
        "obfuscation_enabled": case.client_crypt_supported,
        "required_preference_supported": False,
        "evidence": "emulebb-rust currently exposes one ED2K obfuscation boolean, not separate supported/requested/required bits.",
    }
    return surface


def protocol_fixture_name(case: protocol_matrix.ProtocolCase) -> str:
    """Returns the synthetic Unicode fixture filename used by every Rust protocol case."""

    return f"rust-{case.artifact_id}-{UNICODE_FIXTURE_SUFFIX}.bin"


def secondary_protocol_fixture_name(case: protocol_matrix.ProtocolCase) -> str:
    """Returns the second synthetic Unicode fixture filename for multi-transfer coverage."""

    return f"rust-{case.artifact_id}-multi-{UNICODE_FIXTURE_SUFFIX}.bin"


def hash_only_protocol_fixture_name(case: protocol_matrix.ProtocolCase) -> str:
    """Returns the synthetic Unicode fixture filename used for hash-only metadata recovery."""

    return f"rust-{case.artifact_id}-hash-only-{UNICODE_FIXTURE_SUFFIX}.bin"


def decoded_ed2k_link_name(link_info: dict[str, object]) -> str:
    """Returns the stock percent-decoded filename component from an ED2K link parse."""

    return unquote(str(link_info["name"]))


def ed2k_link_with_source(link: str, source_ip: str, source_port: int, user_hash: str | None = None) -> str:
    """Appends a stock ED2K link source hint for deterministic local handoff."""

    if not link.endswith("|/"):
        raise RuntimeError(f"Cannot append source hint to malformed ED2K link: {link!r}")
    source = f"{source_ip}:{source_port}"
    if user_hash:
        source = f"{source}:{user_hash}"
    return f"{link[:-2]}|sources,{source}|/"


def require_protocol_coverage(
    cases: list[protocol_matrix.ProtocolCase],
    *,
    require_full_matrix: bool,
) -> dict[str, object]:
    """Summarizes and, for full runs, enforces the Rust ED2K protocol coverage contract."""

    selected_names = {case.name for case in cases}
    required_names = {case.name for case in protocol_matrix.PROTOCOL_CASES}
    missing_names = sorted(required_names - selected_names)
    coverage = {
        "caseCount": len(cases),
        "selectedCaseNames": [case.name for case in cases],
        "requiredCaseNames": [case.name for case in protocol_matrix.PROTOCOL_CASES],
        "fullMatrixRequired": require_full_matrix,
        "missingRequiredCaseNames": missing_names,
        "plainServerPlainClients": any(
            not case.server_protocol_obfuscation
            and not case.client_crypt_supported
            and not case.client_crypt_requested
            and not case.client_crypt_required
            for case in cases
        ),
        "obfuscatedPreferred": any(
            case.server_protocol_obfuscation
            and case.client_crypt_supported
            and case.client_crypt_requested
            and not case.client_crypt_required
            for case in cases
        ),
        "obfuscatedRequired": any(
            case.server_protocol_obfuscation
            and case.client_crypt_supported
            and case.client_crypt_requested
            and case.client_crypt_required
            for case in cases
        ),
        "serverUdpDisabled": any(not case.server_udp for case in cases),
        "compressibleFixture": any(case.fixture_pattern == "compressible" for case in cases),
        "lowCompressibilityFixture": any(case.fixture_pattern == "low-compressibility" for case in cases),
        "unicodeFixtureNames": all(protocol_fixture_name(case).isascii() is False for case in cases),
        "multiTransferFixtureNames": all(secondary_protocol_fixture_name(case).isascii() is False for case in cases),
        "hashOnlyFixtureNames": all(hash_only_protocol_fixture_name(case).isascii() is False for case in cases),
    }
    if not require_full_matrix:
        return coverage
    missing_surfaces = [
        key
        for key in (
            "plainServerPlainClients",
            "obfuscatedPreferred",
            "obfuscatedRequired",
            "serverUdpDisabled",
            "compressibleFixture",
            "lowCompressibilityFixture",
            "unicodeFixtureNames",
            "multiTransferFixtureNames",
            "hashOnlyFixtureNames",
        )
        if not coverage[key]
    ]
    if missing_names or missing_surfaces:
        raise RuntimeError(
            "Rust ED2K protocol matrix coverage is incomplete: "
            f"missing cases={missing_names}, missing surfaces={missing_surfaces}."
        )
    return coverage


def require_rust_source_metadata(
    case: protocol_matrix.ProtocolCase,
    sources: list[dict[str, object]],
    *,
    expected_ip: str,
    expected_tcp_port: int,
) -> dict[str, object]:
    """Checks Rust's remembered ED2K source identity for one completed transfer."""

    endpoint = f"{expected_ip}:{expected_tcp_port}"
    matching_sources = [
        source
        for source in sources
        if source.get("endpoint") == endpoint
        or (source.get("ip") == expected_ip and int(source.get("tcpPort") or 0) == expected_tcp_port)
        or (source.get("address") == expected_ip and int(source.get("port") or 0) == expected_tcp_port)
    ]
    if not matching_sources:
        raise RuntimeError(f"Rust transfer sources did not include harness endpoint {endpoint}.")
    source = matching_sources[0]
    user_hash = source.get("userHash")
    has_user_hash = isinstance(user_hash, str) and len(user_hash) == 32 and user_hash.lower() == user_hash
    if case.server_protocol_obfuscation and case.client_crypt_supported and not has_user_hash:
        raise RuntimeError(f"Rust obfuscated transfer source {endpoint} did not expose a peer userHash.")
    return {
        "endpoint": endpoint,
        "clientId": source.get("clientId"),
        "userHash": user_hash,
        "hasUserHash": has_user_hash,
        "sourceCount": len(sources),
        "obfuscatedSourceIdentityRequired": bool(case.server_protocol_obfuscation and case.client_crypt_supported),
    }


def require_rust_hashset_metadata(
    metadata_path: Path,
    *,
    expected_hash: str,
    expected_name: str,
    expected_size: int,
) -> dict[str, object]:
    """Checks Rust's persisted ED2K hashset and AICH metadata for one completed transfer."""

    manifest = rust_metadata.read_transfer_manifest(metadata_path, expected_hash)
    if manifest is None:
        raise RuntimeError(f"Rust transfer manifest is missing for {expected_hash} in {metadata_path}")
    normalized_hash = expected_hash.lower()
    if str(manifest.get("file_hash") or "").lower() != normalized_hash:
        raise RuntimeError(f"Rust manifest file_hash did not match {normalized_hash}.")
    if manifest.get("canonical_name") != expected_name:
        raise RuntimeError(f"Rust manifest canonical_name did not match {expected_name!r}.")
    if int(manifest.get("file_size") or 0) != expected_size:
        raise RuntimeError(f"Rust manifest file_size did not match {expected_size}.")

    expected_part_count = max(1, (expected_size + ED2K_PART_SIZE_BYTES - 1) // ED2K_PART_SIZE_BYTES)
    md4_hashset = manifest.get("md4_hashset")
    aich_hashset = manifest.get("aich_hashset")
    aich_root = manifest.get("aich_root")
    if expected_part_count > 1:
        if manifest.get("md4_hashset_acquired") is not True:
            raise RuntimeError("Rust transfer manifest did not mark the ED2K MD4 hashset as acquired.")
        if not isinstance(md4_hashset, list) or len(md4_hashset) != expected_part_count:
            raise RuntimeError("Rust transfer manifest has an unexpected ED2K MD4 hashset length.")
        if manifest.get("aich_hashset_acquired") is not True:
            raise RuntimeError("Rust transfer manifest did not mark the AICH hashset as acquired.")
        if not isinstance(aich_hashset, list) or len(aich_hashset) != expected_part_count:
            raise RuntimeError("Rust transfer manifest has an unexpected AICH hashset length.")
        if not isinstance(aich_root, str) or len(aich_root) != 40:
            raise RuntimeError("Rust transfer manifest did not persist a 20-byte AICH root.")

    return {
        "metadataPath": str(metadata_path),
        "fileHash": str(manifest.get("file_hash") or ""),
        "canonicalName": manifest.get("canonical_name"),
        "fileSize": manifest.get("file_size"),
        "expectedPartCount": expected_part_count,
        "md4HashsetAcquired": manifest.get("md4_hashset_acquired") is True,
        "md4HashsetCount": len(md4_hashset) if isinstance(md4_hashset, list) else 0,
        "aichHashsetAcquired": manifest.get("aich_hashset_acquired") is True,
        "aichHashsetCount": len(aich_hashset) if isinstance(aich_hashset, list) else 0,
        "aichRoot": aich_root,
    }


def wait_for_rust_search_result_by_name(
    base_url: str,
    api_key: str,
    *,
    query: str,
    expected_name: str,
    expected_size: int,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until Rust server search returns one exact filename and size match."""

    observations: list[dict[str, object]] = []

    def resolve():
        # eMuleBB search is asynchronous: POST /searches creates the search
        # (empty first page, status "running"); results are polled from GET
        # /searches/{id} under the canonical "items" key. A single server
        # search can race server-side publish propagation, so each attempt
        # issues a fresh search and polls it to a terminal status, and the
        # outer wait_for re-issues until the result appears or it times out.
        created = rust_emulebb.request_json(
            base_url,
            "POST",
            "/api/v1/searches",
            api_key,
            {"query": query, "method": "server", "type": ""},
        )
        search_id = str(created.get("id") or "") if isinstance(created, dict) else ""
        if not search_id:
            return None
        search: dict[str, object] = created
        item_count = 0
        deadline = time.time() + 35.0
        while True:
            search = rust_emulebb.request_json(
                base_url,
                "GET",
                f"/api/v1/searches/{search_id}?limit=200&offset=0",
                api_key,
            )
            items = search.get("items") if isinstance(search, dict) else None
            item_count = len(items) if isinstance(items, list) else 0
            if isinstance(items, list):
                for result in items:
                    if not isinstance(result, dict):
                        continue
                    result_name = str(result.get("name") or "")
                    result_size = int(result.get("size") or result.get("sizeBytes") or 0)
                    result_hash = str(result.get("hash") or "").lower()
                    if result_name == expected_name and result_size == expected_size and len(result_hash) == 32:
                        observations.append({"result_count": item_count, "observed_at": round(time.time(), 3)})
                        return {
                            "search": search,
                            "result": result,
                            "transfer_hash": result_hash,
                            "observations": observations[-20:],
                        }
            status = str(search.get("status") or "") if isinstance(search, dict) else ""
            if status in ("complete", "completed", "error") or time.time() >= deadline:
                break
            time.sleep(0.5)
        observations.append({"result_count": item_count, "observed_at": round(time.time(), 3)})
        return None

    return live_common.wait_for(
        resolve,
        timeout_seconds,
        1.0,
        f"emulebb-rust server search result for {expected_name}",
    )


def require_case_result_coverage(cases: list[dict[str, object]]) -> dict[str, object]:
    """Checks the post-run per-case Rust ED2K parity evidence surfaces."""

    missing: list[str] = []
    for case_report in cases:
        name = str(case_report.get("name") or "<unknown>")
        checks = case_report.get("checks")
        if not isinstance(checks, dict):
            missing.append(f"{name}:checks")
            continue

        sequence = checks.get("rust_multi_transfer_sequence")
        if not isinstance(sequence, dict) or int(sequence.get("transferCount") or 0) != 3:
            missing.append(f"{name}:threeTransfers")
        if not isinstance(sequence, dict) or sequence.get("hashOnlyMetadataRecovery") is not True:
            missing.append(f"{name}:hashOnlyMetadataRecovery")

        hash_only_transfer = checks.get("rust_hash_only_transfer_metadata")
        if not isinstance(hash_only_transfer, dict):
            missing.append(f"{name}:hashOnlyTransferMetadata")
        else:
            hash_only_name = str(hash_only_transfer.get("name") or "")
            if hash_only_name.isascii() or int(hash_only_transfer.get("sizeBytes") or 0) != HASH_ONLY_FIXTURE_SIZE_BYTES:
                missing.append(f"{name}:hashOnlyUnicodeNameAndSize")

        for key in ("rust_hashset_metadata", "rust_secondary_hashset_metadata"):
            metadata = checks.get(key)
            if not isinstance(metadata, dict):
                missing.append(f"{name}:{key}")
                continue
            if int(metadata.get("md4HashsetCount") or 0) < 1:
                missing.append(f"{name}:{key}:md4")
            if int(metadata.get("aichHashsetCount") or 0) < 1:
                missing.append(f"{name}:{key}:aich")

        source_metadata = checks.get("rust_source_metadata")
        secondary_source_metadata = checks.get("rust_secondary_source_metadata")
        hash_only_source_metadata = checks.get("rust_hash_only_source_metadata")
        for key, metadata in (
            ("rust_source_metadata", source_metadata),
            ("rust_secondary_source_metadata", secondary_source_metadata),
            ("rust_hash_only_source_metadata", hash_only_source_metadata),
        ):
            if not isinstance(metadata, dict):
                missing.append(f"{name}:{key}")

        if (
            name.startswith("obfuscated-")
            and isinstance(source_metadata, dict)
            and isinstance(secondary_source_metadata, dict)
            and isinstance(hash_only_source_metadata, dict)
            and (
                source_metadata.get("hasUserHash") is not True
                or secondary_source_metadata.get("hasUserHash") is not True
                or hash_only_source_metadata.get("hasUserHash") is not True
            )
        ):
            missing.append(f"{name}:obfuscatedSourceUserHash")

    if missing:
        raise RuntimeError("Rust ED2K protocol matrix case evidence is incomplete: " + ", ".join(missing))
    return {
        "caseCount": len(cases),
        "allCasesPassed": all(case.get("status") == "passed" for case in cases),
        "threeTransfersPerCase": True,
        "hashOnlyMetadataRecoveryPerCase": True,
        "unicodeHashOnlyMetadataPerCase": True,
        "namedTransferHashsetsPerCase": True,
        "obfuscatedSourceUserHashPerCase": True,
    }


def run_protocol_case(
    *,
    case: protocol_matrix.ProtocolCase,
    args: argparse.Namespace,
    paths,
    profile_seed_dir: Path,
    p2p_address: str,
    ed2k_exe: Path,
    client2_app_exe: Path,
) -> dict[str, object]:
    """Runs one deterministic Rust download under a concrete local ED2K protocol configuration."""

    case_dir = paths.source_artifacts_dir / case.artifact_id
    report: dict[str, object] = {
        "name": case.name,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "protocol_surface": rust_protocol_surface(case),
        "clients": [CLIENT_RUST.profile_id, CLIENT_HARNESS.profile_id],
        "checks": {},
    }
    server_process: subprocess.Popen | None = None
    rust_process: subprocess.Popen[str] | None = None
    client2_app = None
    current_phase = "initializing"

    try:
        ports = dtt.choose_distinct_ports(args.lan_bind_addr)
        used_ports = set(ports.values())
        rust_rest_port = rust_emulebb.choose_extra_port(args.lan_bind_addr, used_ports)
        rust_ed2k_port = rust_emulebb.choose_extra_port(args.lan_bind_addr, used_ports)
        rust_kad_port = rust_emulebb.choose_extra_port(args.lan_bind_addr, used_ports)
        server_endpoint = f"{p2p_address}:{ports['ed2k_tcp']}"
        report["network"] = {
            "lan_bind_addr": args.lan_bind_addr,
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
            "server_endpoint": server_endpoint,
            "ports": {**ports, "rust_rest": rust_rest_port, "rust_ed2k": rust_ed2k_port, "rust_kad": rust_kad_port},
        }

        current_phase = "start_ed2k_server"
        ed2k_server = goed2k.launch_ed2k_server(
            workspace_root=paths.workspace_root,
            server_dir=case_dir / "ed2k-server",
            ed2k_port=ports["ed2k_tcp"],
            admin_port=ports["ed2k_admin"],
            token=args.api_key,
            admin_address=args.lan_bind_addr,
            ed2k_address=p2p_address,
            exe_override=str(ed2k_exe),
            protocol_obfuscation=case.server_protocol_obfuscation,
            server_udp=case.server_udp,
        )
        server_process = ed2k_server.process
        admin_base_url = ed2k_server.admin_base_url
        report["checks"]["ed2k_server_health"] = ed2k_server.health
        report["ed2k_server"] = ed2k_server.config

        shared_dir = case_dir / "client2-shared"
        fixture_file = shared_dir / protocol_fixture_name(case)
        fixture_sha256 = protocol_matrix.write_protocol_fixture_file(
            fixture_file,
            args.fixture_size_bytes,
            case.fixture_pattern,
        )
        secondary_fixture_file = shared_dir / secondary_protocol_fixture_name(case)
        secondary_fixture_sha256 = protocol_matrix.write_protocol_fixture_file(
            secondary_fixture_file,
            SECONDARY_FIXTURE_SIZE_BYTES,
            case.fixture_pattern,
        )
        hash_only_fixture_file = shared_dir / hash_only_protocol_fixture_name(case)
        hash_only_fixture_sha256 = protocol_matrix.write_protocol_fixture_file(
            hash_only_fixture_file,
            HASH_ONLY_FIXTURE_SIZE_BYTES,
            case.fixture_pattern,
        )
        report["fixture"] = {
            "path": str(fixture_file),
            "name": fixture_file.name,
            "size": args.fixture_size_bytes,
            "sha256": fixture_sha256,
            "pattern": case.fixture_pattern,
            "unicode_name": True,
        }
        report["hash_only_fixture"] = {
            "path": str(hash_only_fixture_file),
            "name": hash_only_fixture_file.name,
            "size": HASH_ONLY_FIXTURE_SIZE_BYTES,
            "sha256": hash_only_fixture_sha256,
            "pattern": case.fixture_pattern,
            "unicode_name": True,
        }
        report["secondary_fixture"] = {
            "path": str(secondary_fixture_file),
            "name": secondary_fixture_file.name,
            "size": SECONDARY_FIXTURE_SIZE_BYTES,
            "sha256": secondary_fixture_sha256,
            "pattern": case.fixture_pattern,
            "unicode_name": True,
        }

        current_phase = "prepare_harness_profile"
        harness = live_common.prepare_scenario_profile(
            profile_seed_dir,
            case_dir,
            [live_common.win_path(shared_dir, trailing_slash=True)],
            CLIENT_HARNESS.profile_id,
        )
        dtt.configure_client_profile(
            config_dir=Path(harness["config_dir"]),
            app_exe=client2_app_exe,
            nick=CLIENT_HARNESS.nick,
            tcp_port=ports["client2_tcp"],
            udp_port=ports["client2_udp"],
            ed2k_enabled=True,
            autoconnect=True,
            rest_api_key=args.api_key,
            rest_port=ports["client2_rest"],
            lan_bind_addr=args.lan_bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
            p2p_bind_addr=p2p_address,
        )
        report["checks"]["harness_protocol_preferences"] = protocol_matrix.apply_protocol_preferences(
            Path(harness["config_dir"]),
            case,
        )
        dtt.write_server_met(
            Path(harness["config_dir"]) / "server.met",
            address=p2p_address,
            port=ports["ed2k_tcp"],
            name="emulebb-local-e2e",
        )

        current_phase = "launch_harness_seed"
        client2_app = live_common.launch_app(
            client2_app_exe,
            Path(harness["profile_base"]),
            minimized_to_tray=True,
        )
        client2_base_url = f"http://{args.lan_bind_addr}:{ports['client2_rest']}"
        report["checks"]["harness_rest_ready"] = rest_smoke.compact_http_result(
            rest_smoke.wait_for_rest_ready(client2_base_url, args.api_key, args.rest_ready_timeout_seconds)
        )
        report["checks"]["harness_shared_file_add"] = dtt.add_emule_shared_file(client2_base_url, args.api_key, fixture_file)
        report["checks"]["harness_shared_files_reload"] = dtt.reload_emule_shared_files(client2_base_url, args.api_key)
        shared_link = dtt.wait_for_emule_shared_file_link(
            client2_base_url,
            args.api_key,
            file_name=fixture_file.name,
            timeout_seconds=args.link_export_timeout_seconds,
        )
        exported_link = str(shared_link["link"])
        link_info = dtt.parse_ed2k_file_link(exported_link)
        decoded_link_name = decoded_ed2k_link_name(link_info)
        if decoded_link_name != fixture_file.name:
            raise RuntimeError(
                f"MFC parity peer exported ED2K link name {decoded_link_name!r}, expected {fixture_file.name!r}."
            )
        transfer_hash = str(link_info["hash"])
        report["checks"]["harness_shared_file_link"] = {
            **shared_link,
            "parsed": link_info,
            "decodedName": decoded_link_name,
        }
        report["checks"]["harness_server_client"] = goed2k.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT_HARNESS.nick,
            args.server_connect_timeout_seconds,
        )
        report["checks"]["harness_server_file"] = goed2k.wait_for_server_file(
            admin_base_url,
            args.api_key,
            transfer_hash,
            args.server_publish_timeout_seconds,
        )
        secondary_shared_link = dtt.wait_for_emule_shared_file_link(
            client2_base_url,
            args.api_key,
            file_name=secondary_fixture_file.name,
            timeout_seconds=args.link_export_timeout_seconds,
        )
        secondary_link_info = dtt.parse_ed2k_file_link(str(secondary_shared_link["link"]))
        secondary_decoded_name = decoded_ed2k_link_name(secondary_link_info)
        if secondary_decoded_name != secondary_fixture_file.name:
            raise RuntimeError(
                "MFC parity peer exported secondary ED2K link name "
                f"{secondary_decoded_name!r}, expected {secondary_fixture_file.name!r}."
            )
        secondary_expected_hash = str(secondary_link_info["hash"]).lower()
        report["checks"]["harness_secondary_shared_file_link"] = {
            **secondary_shared_link,
            "parsed": secondary_link_info,
            "decodedName": secondary_decoded_name,
        }
        report["checks"]["harness_secondary_server_file"] = goed2k.wait_for_server_file(
            admin_base_url,
            args.api_key,
            secondary_expected_hash,
            args.server_publish_timeout_seconds,
        )
        hash_only_shared_link = dtt.wait_for_emule_shared_file_link(
            client2_base_url,
            args.api_key,
            file_name=hash_only_fixture_file.name,
            timeout_seconds=args.link_export_timeout_seconds,
        )
        hash_only_link_info = dtt.parse_ed2k_file_link(str(hash_only_shared_link["link"]))
        hash_only_decoded_name = decoded_ed2k_link_name(hash_only_link_info)
        if hash_only_decoded_name != hash_only_fixture_file.name:
            raise RuntimeError(
                "MFC parity peer exported hash-only ED2K link name "
                f"{hash_only_decoded_name!r}, expected {hash_only_fixture_file.name!r}."
            )
        hash_only_hash = str(hash_only_link_info["hash"]).lower()
        report["checks"]["harness_hash_only_shared_file_link"] = {
            **hash_only_shared_link,
            "parsed": hash_only_link_info,
            "decodedName": hash_only_decoded_name,
        }
        report["checks"]["harness_hash_only_server_file"] = goed2k.wait_for_server_file(
            admin_base_url,
            args.api_key,
            hash_only_hash,
            args.server_publish_timeout_seconds,
        )

        current_phase = "launch_rust"
        rust_repo = resolve_manifest_repo(paths.workspace_root, "emulebb_rust")
        rust_profile = case_dir / "rust-profile"
        entry = rust_server_entry(case, p2p_address, ports["ed2k_tcp"])
        rust_client.write_rust_profile(
            rust_profile,
            rust_repo=rust_repo,
            rest_addr=args.lan_bind_addr,
            rest_port=rust_rest_port,
            api_key=args.api_key,
            p2p_bind_ip=p2p_address,
            ed2k_port=rust_ed2k_port,
            kad_port=rust_kad_port,
            server_endpoint=server_endpoint,
            server_entry=entry,
            obfuscation_enabled=case.client_crypt_supported,
        )
        report["checks"]["rust_server_entry"] = entry
        rust_process = rust_client.start_rust_client(rust_repo, rust_profile, case_dir / "rust.out")
        rust_base_url = f"http://{args.lan_bind_addr}:{rust_rest_port}"
        report["checks"]["rust_rest_ready"] = rust_emulebb.wait_for_rust_rest(
            rust_base_url,
            rust_process,
            case_dir / "rust.out",
            args.api_key,
            args.rest_ready_timeout_seconds,
        )
        report["checks"]["rust_connect"] = rust_emulebb.request_json(
            rust_base_url,
            "POST",
            "/api/v1/servers/operations/connect",
            args.api_key,
        )
        report["checks"]["rust_ed2k_connected"] = rust_emulebb.wait_for_rust_ed2k_connected(
            rust_base_url,
            args.api_key,
            args.server_connect_timeout_seconds,
        )

        current_phase = "rust_search_and_download"
        rust_search = rust_emulebb.wait_for_rust_search_result(
            rust_base_url,
            args.api_key,
            query=decoded_link_name,
            transfer_hash=transfer_hash,
            timeout_seconds=args.server_publish_timeout_seconds,
        )
        report["checks"]["rust_search"] = rust_search
        search = rust_search["search"]
        report["checks"]["rust_download"] = rust_emulebb.request_json(
            rust_base_url,
            "POST",
            f"/api/v1/searches/{search['id']}/results/{transfer_hash}/operations/download",
            args.api_key,
            {"paused": False},
        )
        report["checks"]["rust_resume"] = rust_emulebb.request_json(
            rust_base_url,
            "POST",
            f"/api/v1/transfers/{transfer_hash}/operations/resume",
            args.api_key,
        )
        report["checks"]["rust_completed_file"] = rust_emulebb.wait_for_rust_transfer_completed(
            rust_base_url,
            args.api_key,
            transfer_hash,
            rust_profile,
            expected_size=int(link_info["size"]),
            expected_sha256=fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
        )
        rust_sources = rust_emulebb.request_json(
            rust_base_url,
            "GET",
            f"/api/v1/transfers/{transfer_hash}/sources",
            args.api_key,
        )["items"]
        report["checks"]["rust_source_metadata"] = require_rust_source_metadata(
            case,
            rust_sources,
            expected_ip=p2p_address,
            expected_tcp_port=ports["client2_tcp"],
        )
        source_user_hash = (
            str(report["checks"]["rust_source_metadata"]["userHash"])
            if case.client_crypt_supported
            else None
        )
        report["checks"]["rust_hashset_metadata"] = require_rust_hashset_metadata(
            rust_profile / rust_client.RUST_PROFILE_METADATA_FILE,
            expected_hash=transfer_hash,
            expected_name=decoded_link_name,
            expected_size=int(link_info["size"]),
        )

        secondary_search = wait_for_rust_search_result_by_name(
            rust_base_url,
            args.api_key,
            query=secondary_fixture_file.name,
            expected_name=secondary_fixture_file.name,
            expected_size=SECONDARY_FIXTURE_SIZE_BYTES,
            timeout_seconds=args.server_publish_timeout_seconds,
        )
        secondary_transfer_hash = str(secondary_search["transfer_hash"])
        report["checks"]["rust_secondary_search"] = secondary_search
        if secondary_transfer_hash.lower() != secondary_expected_hash:
            raise RuntimeError(
                "Rust secondary search returned hash "
                f"{secondary_transfer_hash}, expected {secondary_expected_hash}."
            )
        secondary_source_link = ed2k_link_with_source(
            str(secondary_shared_link["link"]),
            p2p_address,
            ports["client2_tcp"],
            source_user_hash,
        )
        report["checks"]["rust_secondary_create"] = rust_emulebb.request_json(
            rust_base_url,
            "POST",
            "/api/v1/transfers",
            args.api_key,
            {"link": secondary_source_link, "paused": False},
        )
        report["checks"]["rust_secondary_resume"] = rust_emulebb.request_json(
            rust_base_url,
            "POST",
            f"/api/v1/transfers/{secondary_transfer_hash}/operations/resume",
            args.api_key,
        )
        report["checks"]["rust_secondary_completed_file"] = rust_emulebb.wait_for_rust_transfer_completed(
            rust_base_url,
            args.api_key,
            secondary_transfer_hash,
            rust_profile,
            expected_size=SECONDARY_FIXTURE_SIZE_BYTES,
            expected_sha256=secondary_fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
        )
        secondary_rust_sources = rust_emulebb.request_json(
            rust_base_url,
            "GET",
            f"/api/v1/transfers/{secondary_transfer_hash}/sources",
            args.api_key,
        )["items"]
        report["checks"]["rust_secondary_source_metadata"] = require_rust_source_metadata(
            case,
            secondary_rust_sources,
            expected_ip=p2p_address,
            expected_tcp_port=ports["client2_tcp"],
        )
        report["checks"]["rust_secondary_hashset_metadata"] = require_rust_hashset_metadata(
            rust_profile / rust_client.RUST_PROFILE_METADATA_FILE,
            expected_hash=secondary_transfer_hash,
            expected_name=secondary_fixture_file.name,
            expected_size=SECONDARY_FIXTURE_SIZE_BYTES,
        )

        hash_only_link = ed2k_link_with_source(
            f"ed2k://|file|{hash_only_hash}|0|{hash_only_hash}|/",
            p2p_address,
            ports["client2_tcp"],
            source_user_hash,
        )
        report["checks"]["rust_hash_only_input"] = {
            "hashOnlyLink": hash_only_link,
            "hash": hash_only_hash,
            "sourceLinkName": hash_only_decoded_name,
            "sourceLinkSize": hash_only_link_info["size"],
        }
        report["checks"]["rust_hash_only_create"] = rust_emulebb.request_json(
            rust_base_url,
            "POST",
            "/api/v1/transfers",
            args.api_key,
            {"link": hash_only_link, "paused": False},
        )
        report["checks"]["rust_hash_only_resume"] = rust_emulebb.request_json(
            rust_base_url,
            "POST",
            f"/api/v1/transfers/{hash_only_hash}/operations/resume",
            args.api_key,
        )
        report["checks"]["rust_hash_only_completed_file"] = rust_emulebb.wait_for_rust_transfer_completed(
            rust_base_url,
            args.api_key,
            hash_only_hash,
            rust_profile,
            expected_size=HASH_ONLY_FIXTURE_SIZE_BYTES,
            expected_sha256=hash_only_fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
        )
        hash_only_transfer = rust_emulebb.request_json(
            rust_base_url,
            "GET",
            f"/api/v1/transfers/{hash_only_hash}",
            args.api_key,
        )
        if hash_only_transfer.get("name") != hash_only_fixture_file.name:
            raise RuntimeError("Rust hash-only transfer did not recover the canonical file name.")
        if int(hash_only_transfer.get("sizeBytes") or 0) != HASH_ONLY_FIXTURE_SIZE_BYTES:
            raise RuntimeError("Rust hash-only transfer did not recover the canonical file size.")
        report["checks"]["rust_hash_only_transfer_metadata"] = {
            "hashOnlyLink": hash_only_link,
            "hash": hash_only_hash,
            "name": hash_only_transfer.get("name"),
            "sizeBytes": hash_only_transfer.get("sizeBytes"),
            "state": hash_only_transfer.get("state"),
        }
        hash_only_sources = rust_emulebb.request_json(
            rust_base_url,
            "GET",
            f"/api/v1/transfers/{hash_only_hash}/sources",
            args.api_key,
        )["items"]
        report["checks"]["rust_hash_only_source_metadata"] = require_rust_source_metadata(
            case,
            hash_only_sources,
            expected_ip=p2p_address,
            expected_tcp_port=ports["client2_tcp"],
        )
        report["checks"]["rust_hash_only_manifest_metadata"] = require_rust_hashset_metadata(
            rust_profile / rust_client.RUST_PROFILE_METADATA_FILE,
            expected_hash=hash_only_hash,
            expected_name=hash_only_fixture_file.name,
            expected_size=HASH_ONLY_FIXTURE_SIZE_BYTES,
        )
        report["checks"]["rust_multi_transfer_sequence"] = {
            "singleProtocolSession": True,
            "transferHashes": [transfer_hash.lower(), secondary_transfer_hash.lower(), hash_only_hash],
            "transferCount": 3,
            "hashOnlyMetadataRecovery": True,
        }
        report["checks"]["ed2k_server_stats_final"] = goed2k.admin_request(admin_base_url, args.api_key, "/api/stats")
        report["profiles"] = {
            CLIENT_HARNESS.profile_id: {
                "profile_base": str(harness["profile_base"]),
                "config_dir": str(harness["config_dir"]),
                "preferences": dtt.read_preferences_snapshot(Path(harness["config_dir"])),
            },
            CLIENT_RUST.profile_id: {
                "profile_dir": str(rust_profile),
            },
        }
        report["status"] = "passed"
    except Exception as exc:
        report["status"] = "failed"
        report["current_phase"] = current_phase
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
    finally:
        cleanup: dict[str, object] = {}
        if client2_app is not None:
            try:
                live_common.close_app_cleanly(client2_app)
                cleanup[CLIENT_HARNESS.profile_id] = {"ok": True}
            except Exception as exc:
                cleanup[CLIENT_HARNESS.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        rust_client.stop_process_tree(rust_process)
        goed2k.stop_process(server_process)
        report["cleanup"] = cleanup
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    return report


def main(argv: list[str] | None = None) -> int:
    """Runs all requested Rust protocol-combination transfer cases."""

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
        "checks": {},
        "cases": [],
    }
    try:
        p2p_address = dtt.resolve_lan_p2p_bind_address(
            lan_bind_addr=args.lan_bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
            p2p_bind_interface_address=args.p2p_bind_interface_address,
        )
        report["network"] = {
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
        }
        ed2k_binary = goed2k.prepare_ed2k_server_binary(
            paths.workspace_root,
            repo_override=args.ed2k_server_repo,
            exe_override=args.ed2k_server_exe,
        )
        report["checks"]["server_build"] = ed2k_binary.build
        client2_app_exe = dtt.resolve_client2_app_exe(paths.workspace_root, args.configuration, args.client2_app_exe)
        report["clients"] = [asdict(CLIENT_RUST), asdict(CLIENT_HARNESS)]

        selected_cases = protocol_matrix.selected_cases(args.case)
        report["checks"]["protocol_matrix_coverage"] = require_protocol_coverage(
            selected_cases,
            require_full_matrix=not args.case,
        )

        for case in selected_cases:
            case_report = run_protocol_case(
                case=case,
                args=args,
                paths=paths,
                profile_seed_dir=profile_seed_dir,
                p2p_address=p2p_address,
                ed2k_exe=ed2k_binary.server_exe,
                client2_app_exe=client2_app_exe,
            )
            report["cases"].append(case_report)
            if case_report["status"] != "passed":
                raise RuntimeError(f"Rust protocol case {case.name!r} failed.")
        report["checks"]["rust_protocol_case_requirements"] = require_case_result_coverage(report["cases"])
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        return 1
    finally:
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "local-ed2k-rust-protocol-combinations-result.json", report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
