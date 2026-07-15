"""Bidirectional cross-client eD2K transfer between eMuleBB Rust and eMuleBB via REST."""

from __future__ import annotations

import argparse
import os
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
from emule_test_harness import rust_metadata  # noqa: E402
from emule_test_harness import rust_upload_soak  # noqa: E402
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
    parser.add_argument(
        "--diagnostics", action="store_true",
        help="Capture converged packet dumps on both clients for upload-path parity: build/run rust "
        "with the packet-diagnostics feature + EMULEBB_RUST_LOG_DIR, and use the MFC diagnostics exe "
        "(pass --app-exe pointing at emulebb-diagnostics.exe).",
    )
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
    parser.add_argument("--attach-rust-ui", action="store_true")
    parser.add_argument("--rust-ui-exe", type=Path)
    parser.add_argument("--ui-poll-interval-ms", type=int, default=1000)
    parser.add_argument("--rust-upload-limit-kibps", type=int)
    parser.add_argument("--emulebb-upload-limit-kibps", type=int)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    return parser.parse_args(argv)


def resolve_rust_ui_exe(override: Path | None) -> Path:
    """Resolves the native Rust UI executable used by cross-client evidence runs."""

    path = override if override is not None else rust_upload_soak.staged_rust_bin("emulebb-rust-ui.exe")
    return path.resolve()


def validate_optional_soak_args(args: argparse.Namespace) -> None:
    """Rejects invalid optional cross-client soak and UI arguments."""

    if args.attach_rust_ui:
        rust_ui_exe = resolve_rust_ui_exe(args.rust_ui_exe)
        if not rust_ui_exe.is_file():
            raise ValueError(f"Rust UI executable was not found: {rust_ui_exe}")
        if args.ui_poll_interval_ms < 1000:
            raise ValueError("--ui-poll-interval-ms must be at least 1000.")
    for name in ("rust_upload_limit_kibps", "emulebb_upload_limit_kibps"):
        value = getattr(args, name)
        if value is not None and value <= 0:
            raise ValueError(f"--{name.replace('_', '-')} must be greater than zero.")


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
    snapshot_callback=None,
) -> dict[str, object]:
    """Waits until Rust completes one transfer and verifies the persisted bytes."""

    observations: list[dict[str, object]] = []
    pieces_path = runtime_dir / "transfers" / transfer_hash.lower() / "pieces.bin"

    def resolve():
        data = request_json(base_url, "GET", f"/api/v1/transfers/{transfer_hash}", api_key)
        row = dict(data) if isinstance(data, dict) else {"payload": data}
        row["observed_at"] = round(time.time(), 3)
        row["pieces_file"] = dtt.snapshot_file(pieces_path, hash_limit_bytes=expected_size)
        if snapshot_callback is not None:
            row["snapshot"] = snapshot_callback()
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
        # eMuleBB search is asynchronous: POST /searches creates the search
        # (empty first page, status "running"); results are polled from GET
        # /searches/{id} under the canonical "items" key. A single server
        # search can race server-side publish propagation, so each attempt
        # issues a fresh search and polls it to a terminal status, and the
        # outer wait_for re-issues until the result appears or it times out.
        created = request_json(
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
        result_count = 0
        deadline = time.time() + 35.0
        while True:
            search = request_json(
                base_url,
                "GET",
                f"/api/v1/searches/{search_id}?limit=200&offset=0",
                api_key,
            )
            items = search.get("items") if isinstance(search, dict) else None
            result_count = len(items) if isinstance(items, list) else 0
            if isinstance(items, list):
                for result in items:
                    if isinstance(result, dict) and str(result.get("hash") or "").lower() == normalized_hash:
                        observations.append({"result_count": result_count, "observed_at": round(time.time(), 3)})
                        return {
                            "search": search,
                            "result": result,
                            "observations": observations[-20:],
                        }
            status = str(search.get("status") or "") if isinstance(search, dict) else ""
            if status in ("complete", "completed", "error") or time.time() >= deadline:
                break
            time.sleep(0.5)
        observations.append({"result_count": result_count, "observed_at": round(time.time(), 3)})
        return None

    return live_common.wait_for(resolve, timeout_seconds, 1.0, f"emulebb-rust server search result {normalized_hash}")


def require_rust_download_manifest_metadata(
    profile_dir: Path,
    *,
    transfer_hash: str,
    expected_name: str,
    expected_size: int,
    require_aich_hashset: bool,
) -> dict[str, object]:
    """Requires Rust to persist stock metadata learned from a cross-client source."""

    metadata_path = profile_dir / rust_client.RUST_PROFILE_METADATA_FILE
    manifest = rust_metadata.read_transfer_manifest(metadata_path, transfer_hash)
    if manifest is None:
        raise RuntimeError(f"Rust cross-client manifest is missing for {transfer_hash}.")
    expected_part_count = max(1, (expected_size + ED2K_PART_SIZE_BYTES - 1) // ED2K_PART_SIZE_BYTES)
    expected_hashset_count = expected_part_count if expected_part_count > 1 else 0
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
    # WHY: an eD2K single-part file carries an optional MD4 part-hash list. Some clients
    # omit it (the file hash IS that single part hash) while others surface the one part
    # hash. Accept 0 or 1 for a single-part file; require the exact
    # part count for multi-part files. expectedHashsetCount stays 0 for single-part (part
    # hashes beyond the file hash), which the REST manifest contract asserts.
    if expected_part_count > 1:
        if len(md4_hashset) != expected_part_count:
            raise RuntimeError(
                f"Rust acquired {len(md4_hashset)} MD4 parts from the cross-client source, expected {expected_part_count}."
            )
    elif len(md4_hashset) > 1:
        raise RuntimeError(
            f"Rust acquired {len(md4_hashset)} MD4 parts for a single-part file, expected 0 or 1."
        )
    if require_aich_hashset:
        if manifest.get("aich_hashset_acquired") is not True or not isinstance(aich_hashset, list):
            raise RuntimeError("Rust did not acquire the AICH hashset from the cross-client source.")
        if expected_part_count > 1:
            if len(aich_hashset) != expected_part_count:
                raise RuntimeError(
                    f"Rust acquired {len(aich_hashset)} AICH parts from the cross-client source, expected {expected_part_count}."
                )
        elif len(aich_hashset) > 1:
            raise RuntimeError(
                f"Rust acquired {len(aich_hashset)} AICH parts for a single-part file, expected 0 or 1."
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
        "metadataPath": str(metadata_path),
        "fileHash": str(manifest.get("file_hash") or "").lower(),
        "canonicalName": manifest.get("canonical_name"),
        "fileSize": int(manifest.get("file_size") or 0),
        "expectedPartCount": expected_part_count,
        "expectedHashsetCount": expected_hashset_count,
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


def rust_shared_tree_fixture_name() -> str:
    """Returns the nested Rust shared-tree fixture name."""

    return f"emulebb-rust-shared-tree-{UNICODE_FIXTURE_SUFFIX}.bin"


def emulebb_to_rust_fixture_name() -> str:
    """Returns the eMuleBB-seeded cross-client Unicode fixture name."""

    return f"emulebb-to-emulebb-rust-{UNICODE_FIXTURE_SUFFIX}.bin"


def decoded_ed2k_link_name(link_info: dict[str, object]) -> str:
    """Returns the display filename from a parsed ED2K link."""

    return unquote(str(link_info.get("name") or ""))


def write_rust_shared_tree_fixture(root: Path, size_bytes: int) -> dict[str, object]:
    """Writes a throw-away recursive shared tree fixture for Rust upload proof."""

    nested_dir = root / "alpha" / "beta"
    fixture_path = nested_dir / rust_shared_tree_fixture_name()
    fixture_sha256 = dtt.write_fixture_file(fixture_path, size_bytes, seed=0x52555354)
    return {
        "root": str(root),
        "nested_dir": str(nested_dir),
        "path": str(fixture_path),
        "name": fixture_path.name,
        "size": size_bytes,
        "sha256": fixture_sha256,
        "unicode_name": True,
        "recursive": True,
    }


def require_shared_file_item(shared_files: dict[str, object], file_name: str) -> dict[str, object]:
    """Returns one shared-file row from a paged Rust REST shared-files payload."""

    items = shared_files.get("items")
    if not isinstance(items, list):
        raise RuntimeError("Rust shared-files response did not expose an items list.")
    item = find_shared_file_item(items, file_name)
    if item is not None:
        return item
    raise RuntimeError(f"Rust shared-files response did not include {file_name}.")


def find_shared_file_item(items: list[object], file_name: str) -> dict[str, object] | None:
    """Returns a matching Rust shared-file row without treating a miss as fatal."""

    for item in items:
        if isinstance(item, dict) and item.get("name") == file_name:
            link = str(item.get("ed2kLink") or "")
            if not link.startswith("ed2k://|file|"):
                raise RuntimeError(f"Rust shared-file row for {file_name} did not expose an ED2K link.")
            return item
    return None


def wait_for_rust_shared_file(
    base_url: str,
    api_key: str,
    *,
    file_name: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits for detached Rust shared-directory hashing to expose one file row."""

    observations: list[dict[str, object]] = []

    def resolve():
        shared_files = request_json(base_url, "GET", "/api/v1/shared-files", api_key)
        items = shared_files.get("items")
        if not isinstance(items, list):
            raise RuntimeError("Rust shared-files response did not expose an items list.")
        status = request_json(base_url, "GET", "/api/v1/status", api_key)
        stats = status.get("stats") if isinstance(status, dict) else None
        matched = find_shared_file_item(items, file_name)
        observations.append(
            {
                "count": len(items),
                "hashingCount": stats.get("sharedHashingCount") if isinstance(stats, dict) else None,
                "observed_at": round(time.time(), 3),
            }
        )
        if matched is None:
            return None
        return {
            "count": len(items),
            "matched": matched,
            "observations": observations[-20:],
        }

    return live_common.wait_for(resolve, timeout_seconds, 1.0, f"Rust shared-file {file_name!r}")


def publish_rust_shared_tree(
    base_url: str,
    api_key: str,
    *,
    root: Path,
    file_name: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Configures and reloads one recursive Rust shared directory root."""

    directories = request_json(
        base_url,
        "PATCH",
        "/api/v1/shared-directories",
        api_key,
        {
            "roots": [{"path": str(root), "recursive": True}],
            "confirmReplaceRoots": True,
        },
    )
    reload_result = request_json(
        base_url,
        "POST",
        "/api/v1/shared-directories/operations/reload",
        api_key,
    )
    shared_files = wait_for_rust_shared_file(
        base_url,
        api_key,
        file_name=file_name,
        timeout_seconds=timeout_seconds,
    )
    return {
        "directories": directories,
        "reload": reload_result,
        "sharedFiles": shared_files,
    }


def require_process_alive(process: subprocess.Popen, output_path: Path, label: str) -> dict[str, object]:
    """Returns process liveness evidence or raises with the captured output tail."""

    if process.poll() is None:
        return {"pid": process.pid, "alive": True, "output": str(output_path)}
    tail = ""
    if output_path.is_file():
        tail = output_path.read_text(encoding="utf-8", errors="replace")[-2000:]
    raise RuntimeError(f"{label} exited early with code {process.returncode}: {tail}")


def require_cross_client_requirements(report: dict[str, object]) -> dict[str, object]:
    """Checks the high-level Rust/eMuleBB ED2K parity surfaces proven by the report."""

    fixture = report.get("fixture")
    emulebb_fixture = report.get("emulebb_fixture")
    shared_tree = report.get("rust_shared_tree")
    checks = report.get("checks")
    if (
        not isinstance(fixture, dict)
        or not isinstance(emulebb_fixture, dict)
        or not isinstance(shared_tree, dict)
        or not isinstance(checks, dict)
    ):
        raise RuntimeError("Rust/eMuleBB cross-client report is missing fixture or check sections.")
    rust_fixture_name = str(fixture.get("name") or "")
    emulebb_fixture_name = str(emulebb_fixture.get("name") or "")
    if rust_fixture_name.isascii() or emulebb_fixture_name.isascii():
        raise RuntimeError("Rust/eMuleBB cross-client fixtures did not use Unicode filenames.")
    if shared_tree.get("recursive") is not True or str(shared_tree.get("name") or "").isascii():
        raise RuntimeError("Rust/eMuleBB cross-client report did not prove a recursive Unicode shared-tree fixture.")
    tree_publish = checks.get("rust_shared_tree_publish")
    if not isinstance(tree_publish, dict):
        raise RuntimeError("Rust/eMuleBB cross-client report is missing Rust shared-tree publish evidence.")
    matched = tree_publish.get("sharedFiles", {}).get("matched") if isinstance(tree_publish.get("sharedFiles"), dict) else None
    if not isinstance(matched, dict) or matched.get("name") != shared_tree.get("name"):
        raise RuntimeError("Rust/eMuleBB cross-client report did not match the shared-tree fixture in Rust shared files.")
    manifest_metadata = checks.get("rust_emulebb_manifest_metadata")
    if not isinstance(manifest_metadata, dict):
        raise RuntimeError("Rust/eMuleBB cross-client report is missing Rust manifest metadata.")
    if manifest_metadata.get("canonicalName") != emulebb_fixture_name:
        raise RuntimeError("Rust/eMuleBB cross-client manifest did not preserve the Unicode canonical name.")
    if int(manifest_metadata.get("sourceUserHashCount") or 0) < 1:
        raise RuntimeError("Rust/eMuleBB cross-client manifest did not persist source userHash metadata.")
    expected_hashset_count = int(manifest_metadata.get("expectedHashsetCount") or 0)
    if (
        manifest_metadata.get("md4HashsetAcquired") is not True
        or int(manifest_metadata.get("md4HashsetCount") or 0) != expected_hashset_count
        or manifest_metadata.get("aichHashsetAcquired") is not True
        or int(manifest_metadata.get("aichHashsetCount") or 0) != expected_hashset_count
    ):
        raise RuntimeError("Rust/eMuleBB cross-client manifest did not persist MD4/AICH hashset metadata.")
    return {
        "bidirectionalTransfers": True,
        "unicodeFixtureNames": True,
        "recursiveSharedTreeUpload": True,
        "rustToEmulebbUnicodeName": rust_fixture_name,
        "emulebbToRustUnicodeName": emulebb_fixture_name,
        "rustPersistedSourceUserHash": True,
        "rustPersistedMd4Hashset": True,
        "rustPersistedAichHashset": True,
    }


def main(argv: list[str] | None = None) -> int:
    """Runs the bidirectional Rust/eMuleBB cross-client transfer scenario."""

    args = parse_args(argv)
    validate_optional_soak_args(args)
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
    rust_ui_process: subprocess.Popen[str] | None = None
    rust_ui_log = None
    rust_ui_metrics: dict[str, object] | None = None
    rust_ui_output_path = paths.source_artifacts_dir / "rust-ui.out"
    emulebb_app = None
    current_phase = "initializing"

    def sample_rust_ui(label: str) -> dict[str, object] | None:
        if rust_ui_process is None:
            return None
        row: dict[str, object] = {
            "label": label,
            "process": require_process_alive(rust_ui_process, rust_ui_output_path, "emulebb-rust-ui"),
        }
        if rust_ui_metrics is not None:
            row["metrics"] = rust_upload_soak.sample_process_metrics(rust_ui_metrics, 1.0)
        return row

    try:
        p2p_address = dtt.resolve_lan_p2p_bind_address(
            lan_bind_addr=args.lan_bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
            p2p_bind_interface_address=args.p2p_bind_interface_address,
        )
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
        report["limits"] = {
            "rust_upload_limit_kibps": args.rust_upload_limit_kibps,
            "emulebb_upload_limit_kibps": args.emulebb_upload_limit_kibps,
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

        rust_shared_tree = write_rust_shared_tree_fixture(
            paths.source_artifacts_dir / "rust-shared-tree",
            args.fixture_size_bytes,
        )
        fixture_path = Path(str(rust_shared_tree["path"]))
        fixture_sha256 = str(rust_shared_tree["sha256"])
        report["fixture"] = dict(rust_shared_tree)
        report["rust_shared_tree"] = dict(rust_shared_tree)

        rust_profile = paths.source_artifacts_dir / "rust-profile"
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
        )
        current_phase = "launch_rust"
        rust_features: str | None = None
        if args.diagnostics:
            # Capture both clients' converged packet dumps for upload-path parity:
            # rust writes ed2k_packet_v1 / Kad udp_packet_v1 when EMULEBB_RUST_LOG_DIR
            # is set AND it is built with the packet-diagnostics feature; the MFC side
            # must be the diagnostics exe (--app-exe ...emulebb-diagnostics.exe), which
            # emits its packet log from the EMULEBB_ENABLE_PACKET_DIAGNOSTICS build.
            rust_packet_dir = paths.source_artifacts_dir / "rust-packet-dump"
            rust_packet_dir.mkdir(parents=True, exist_ok=True)
            os.environ["EMULEBB_RUST_LOG_DIR"] = str(rust_packet_dir)
            rust_features = "packet-diagnostics"
            report["rust_packet_dump_dir"] = str(rust_packet_dir)
        rust_process = rust_client.start_rust_client(
            rust_repo, rust_profile, paths.source_artifacts_dir / "rust.out", features=rust_features
        )
        rust_base_url = f"http://{args.lan_bind_addr}:{rust_rest_port}"
        report["checks"]["rust_rest_ready"] = wait_for_rust_rest(
            rust_base_url,
            rust_process,
            paths.source_artifacts_dir / "rust.out",
            args.api_key,
            args.rest_ready_timeout_seconds,
        )
        if args.rust_upload_limit_kibps is not None:
            report["checks"]["rust_upload_limit"] = rust_upload_soak.patch_upload_limit(
                rust_base_url,
                args.api_key,
                args.rust_upload_limit_kibps,
            )
        if args.attach_rust_ui:
            current_phase = "launch_rust_ui"
            rust_ui_exe = resolve_rust_ui_exe(args.rust_ui_exe)
            rust_ui_process, rust_ui_log = rust_upload_soak.launch_rust_ui(
                ui_exe=rust_ui_exe,
                base_url=rust_base_url,
                api_key=args.api_key,
                poll_interval_ms=args.ui_poll_interval_ms,
                output_path=rust_ui_output_path,
            )
            report["rust_ui"] = {
                "exe": str(rust_ui_exe),
                "output": str(rust_ui_output_path),
                "poll_interval_ms": args.ui_poll_interval_ms,
                "pid": rust_ui_process.pid,
            }
            report["checks"]["rust_ui_attached"] = require_process_alive(
                rust_ui_process,
                rust_ui_output_path,
                "emulebb-rust-ui",
            )
            rust_ui_metrics = rust_upload_soak.open_process_metrics(
                rust_ui_process,
                "rust-ui",
                paths.source_artifacts_dir / "analysis",
                1.0,
            )
            report["checks"]["rust_ui_sample_after_launch"] = sample_rust_ui("after_launch")
        report["checks"]["rust_connect"] = request_json(rust_base_url, "POST", "/api/v1/servers/operations/connect", args.api_key)
        report["checks"]["rust_ed2k_connected"] = wait_for_rust_ed2k_connected(rust_base_url, args.api_key, args.server_connect_timeout_seconds)
        report["checks"]["rust_shared_tree_publish"] = publish_rust_shared_tree(
            rust_base_url,
            args.api_key,
            root=Path(str(rust_shared_tree["root"])),
            file_name=str(rust_shared_tree["name"]),
            timeout_seconds=args.link_export_timeout_seconds,
        )
        rust_file = report["checks"]["rust_shared_tree_publish"]["sharedFiles"]["matched"]
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
        if args.emulebb_upload_limit_kibps is not None:
            live_common.apply_emule_preferences(
                Path(emulebb["config_dir"]),
                (("MaxUpload", str(args.emulebb_upload_limit_kibps)),),
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
            )
            | {"rustUi": sample_rust_ui("rust_to_emulebb_transfer_wait")},
        )
        report["checks"]["rust_ui_sample_after_rust_upload"] = sample_rust_ui("after_rust_upload")
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
            rust_profile,
            expected_size=int(emulebb_link_info["size"]),
            expected_sha256=emulebb_fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
            snapshot_callback=lambda: {"rustUi": sample_rust_ui("emulebb_to_rust_transfer_wait")},
        )
        report["checks"]["rust_ui_sample_after_emulebb_upload"] = sample_rust_ui("after_emulebb_upload")
        report["checks"]["rust_emulebb_manifest_metadata"] = require_rust_download_manifest_metadata(
            rust_profile,
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
        report["rust_ui_process_metrics"] = rust_upload_soak.close_process_metrics(rust_ui_metrics)
        if emulebb_app is not None:
            try:
                live_common.close_app_cleanly(emulebb_app)
                cleanup[CLIENT_EMULEBB.profile_id] = {"ok": True}
            except Exception as exc:
                cleanup[CLIENT_EMULEBB.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        rust_client.stop_process_tree(rust_ui_process)
        rust_client.stop_process_tree(rust_process)
        if rust_ui_log is not None:
            rust_ui_log.close()
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
