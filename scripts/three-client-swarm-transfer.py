"""Deterministic three-client eD2K swarm transfer through the local server."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import random
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import amule as amule_harness  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES, resolve_amule_client  # noqa: E402


def load_local_module(module_name: str, filename: str):
    """Loads one sibling helper module from a hyphenated script filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


dtt = load_local_module("deterministic_two_client_transfer_swarm", "deterministic-two-client-transfer.py")
amule_seed = load_local_module("deterministic_amule_transfer_swarm", "deterministic-amule-transfer.py")
harness_cli_common = dtt.harness_cli_common
live_common = dtt.live_common
rest_smoke = dtt.rest_smoke

SUITE_NAME = "three-client-swarm-transfer"
API_KEY = "three-client-swarm-transfer-key"
CLIENT01 = CLIENT_IDENTITIES["emulebb"]
CLIENT02 = CLIENT_IDENTITIES["harness"]
CLIENT04 = CLIENT_IDENTITIES["amule"]
CLIENT_KEYS = (CLIENT01.key, CLIENT02.key, CLIENT04.key)
SHARED_FILES_ROUTE = "/api/v1/shared-files"
SEED_SPECS = {
    CLIENT01.key: ("seed-from-cl-emulebb-001.bin", 0xE001),
    CLIENT02.key: ("seed-from-cl-harness-002.bin", 0xE002),
    CLIENT04.key: ("seed-from-cl-amule-004.bin", 0xE004),
}


@dataclass(frozen=True)
class SeedFile:
    """One deterministic file seeded by one client in the swarm."""

    client_key: str
    profile_id: str
    path: Path
    name: str
    size: int
    sha256: str
    link: str | None = None
    file_hash: str | None = None

    def with_link(self, link: str) -> "SeedFile":
        """Returns a copy with ED2K link metadata attached."""

        link_info = dtt.parse_ed2k_file_link(link)
        return SeedFile(
            client_key=self.client_key,
            profile_id=self.profile_id,
            path=self.path,
            name=self.name,
            size=self.size,
            sha256=self.sha256,
            link=link,
            file_hash=str(link_info["hash"]),
        )

    def as_report(self) -> dict[str, object]:
        """Returns a JSON-safe seed summary."""

        return {
            "client_key": self.client_key,
            "profile_id": self.profile_id,
            "path": str(self.path),
            "name": self.name,
            "size": self.size,
            "sha256": self.sha256,
            "ed2k_hash": self.file_hash,
            "link": self.link,
        }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses the standalone three-client swarm arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--client2-app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--bind-addr", default="127.0.0.1")
    parser.add_argument("--p2p-bind-interface-name", default="")
    parser.add_argument("--p2p-bind-interface-address")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--transfer-completion-timeout-seconds", type=float, default=1800.0)
    parser.add_argument("--fixture-size-bytes", type=int, default=dtt.DEFAULT_FIXTURE_SIZE_BYTES)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    parser.add_argument("--amule-daemon-exe")
    parser.add_argument("--amule-control-exe")
    return parser.parse_args(argv)


def write_seed_file(path: Path, *, size_bytes: int, rng_seed: int) -> str:
    """Writes deterministic low-compressibility bytes and returns SHA-256."""

    if size_bytes <= 0:
        raise ValueError("Fixture size must be greater than zero.")
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    rng = random.Random(rng_seed)
    remaining = size_bytes
    with path.open("wb") as handle:
        while remaining > 0:
            chunk_size = min(64 * 1024, remaining)
            chunk = bytes(rng.getrandbits(8) for _ in range(chunk_size))
            handle.write(chunk)
            digest.update(chunk)
            remaining -= chunk_size
    return digest.hexdigest()


def create_seed_file(root_dir: Path, client_key: str, profile_id: str, size_bytes: int) -> SeedFile:
    """Creates one client's unique deterministic seed file."""

    name, rng_seed = SEED_SPECS[client_key]
    path = root_dir / profile_id / name
    sha256 = write_seed_file(path, size_bytes=size_bytes, rng_seed=rng_seed)
    return SeedFile(client_key=client_key, profile_id=profile_id, path=path, name=name, size=size_bytes, sha256=sha256)


def choose_swarm_ports() -> dict[str, int]:
    """Allocates ports for eMule BB, tracing harness, aMule, and ED2K server."""

    return amule_seed.choose_amule_ports(dtt.choose_distinct_ports())


def resolve_required_amule(paths, args: argparse.Namespace):
    """Resolves the staged aMule daemon/control pair or raises an actionable error."""

    availability = resolve_amule_client(paths.workspace_root, args.amule_daemon_exe, args.amule_control_exe)
    if not availability.available or availability.executable is None or availability.control_executable is None:
        raise RuntimeError(f"aMule is unavailable for three-client E2E: {availability.reason}")
    return availability


def build_harness_args(
    *,
    ready_path: Path,
    fixture_file: Path,
    export_link_path: Path,
    source_ip: str,
    download_link_file: Path,
    download_report_file: Path,
) -> list[str]:
    """Builds tracing-harness CLI args for simultaneous seed and download roles."""

    return [
        *dtt.build_client2_harness_args(
            ready_path=ready_path,
            fixture_file=fixture_file,
            export_link_path=export_link_path,
            source_ip=source_ip,
        ),
        "-downloadlinkfile",
        str(download_link_file),
        "-downloadreportfile",
        str(download_report_file),
    ]


def write_download_link_file(path: Path, links: list[str]) -> dict[str, object]:
    """Writes one newline-delimited download-link file for the tracing harness."""

    if not links:
        raise ValueError("At least one download link is required.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{link.strip()}\n" for link in links), encoding="utf-8", newline="\n")
    return {"path": str(path), "count": len(links), "links": links}


def ed2k_link_with_source(link: str, *, source_ip: str, source_port: int) -> str:
    """Adds a deterministic local source hint to an ED2K file link."""

    if "|sources," in link:
        return link
    if not link.endswith("|/"):
        raise ValueError(f"Unsupported ED2K file link terminator: {link!r}")
    return f"{link}|sources,{source_ip}:{source_port}|/"


def amule_command_summary(completed: subprocess.CompletedProcess) -> dict[str, object]:
    """Returns a bounded diagnostic summary for one `amulecmd` invocation."""

    return {
        "return_code": completed.returncode,
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-2000:],
    }


def add_amule_downloads(control_exe: Path, profile: amule_harness.AmuleRuntimeProfile, links: list[str]) -> list[dict[str, object]]:
    """Queues multiple ED2K file links through aMule external control."""

    rows = []
    for link in links:
        rows.append(
            {
                "link": link,
                "result": amule_command_summary(
                    amule_harness.run_amulecmd(control_exe, profile, f"Add {link}", timeout_seconds=30.0)
                ),
            }
        )
    return rows


def add_emule_downloads(base_url: str, api_key: str, seeds: list[SeedFile]) -> list[dict[str, object]]:
    """Queues multiple ED2K file links through eMule BB REST."""

    rows = []
    for seed in seeds:
        if seed.link is None or seed.file_hash is None:
            raise RuntimeError(f"Seed has no ED2K link: {seed!r}")
        rows.append(
            {
                "source_profile_id": seed.profile_id,
                "link": seed.link,
                "result": dtt.add_transfer(base_url, api_key, seed.link, seed.file_hash),
            }
        )
    return rows


def require_shared_file_hash(row: dict[str, object], expected_name: str) -> str:
    """Extracts and validates the lowercase ED2K hash from one shared-file row."""

    if row.get("name") != expected_name:
        raise AssertionError(f"Expected shared-file row for {expected_name!r}, got {row!r}")
    file_hash = row.get("hash")
    if not isinstance(file_hash, str) or not dtt.ED2K_HASH_PATTERN.match(file_hash):
        raise AssertionError(f"Shared-file row has no ED2K hash: {row!r}")
    return file_hash.lower()


def add_emule_shared_file(base_url: str, api_key: str, file_path: Path) -> dict[str, object]:
    """Adds one eMule BB seed file to the shared-file model."""

    result = rest_smoke.http_request(
        base_url,
        SHARED_FILES_ROUTE,
        method="POST",
        api_key=api_key,
        json_body={"path": str(file_path.resolve())},
        request_timeout_seconds=30.0,
    )
    if int(result.get("status", 0)) != 200:
        raise RuntimeError(f"Adding eMule BB shared file failed: {rest_smoke.compact_http_result(result)!r}")
    return rest_smoke.compact_http_result(result)


def reload_emule_shared_files(base_url: str, api_key: str) -> dict[str, object]:
    """Requests a native shared-files reload through REST."""

    result = rest_smoke.http_request(
        base_url,
        f"{SHARED_FILES_ROUTE}/operations/reload",
        method="POST",
        api_key=api_key,
        json_body={},
        request_timeout_seconds=30.0,
    )
    if int(result.get("status", 0)) != 200:
        raise RuntimeError(f"Reloading eMule BB shared files failed: {rest_smoke.compact_http_result(result)!r}")
    return rest_smoke.compact_http_result(result)


def wait_for_emule_shared_file_link(
    base_url: str,
    api_key: str,
    seed: SeedFile,
    timeout_seconds: float,
) -> SeedFile:
    """Waits until eMule BB exposes a shared-file row and ED2K link."""

    observations: list[dict[str, object]] = []

    def resolve():
        rows_result = rest_smoke.http_request(base_url, SHARED_FILES_ROUTE, api_key=api_key, request_timeout_seconds=10.0)
        rows = rest_smoke.require_json_array(rows_result, 200)
        observations.append({"count": len(rows), "observed_at": round(time.time(), 3)})
        for row in rows:
            if isinstance(row, dict) and row.get("name") == seed.name:
                file_hash = require_shared_file_hash(row, seed.name)
                link_result = rest_smoke.http_request(
                    base_url,
                    f"{SHARED_FILES_ROUTE}/{file_hash}/ed2k-link",
                    api_key=api_key,
                    request_timeout_seconds=10.0,
                )
                body = rest_smoke.require_json_object(link_result, 200)
                link = body.get("link")
                if isinstance(link, str) and link.startswith("ed2k://|file|"):
                    return seed.with_link(link)
        return None

    try:
        return live_common.wait_for(resolve, timeout_seconds, 1.0, f"eMule BB shared link for {seed.name}")
    except Exception as exc:
        raise RuntimeError(f"Timed out waiting for eMule BB shared link. Observations: {observations[-20:]!r}") from exc


def wait_for_harness_download_report(path: Path, timeout_seconds: float) -> dict[str, object]:
    """Waits for the tracing harness to report all requested downloads complete."""

    observations: list[dict[str, object]] = []

    def resolve():
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if isinstance(payload, dict):
            observations.append(
                {
                    "complete": payload.get("complete"),
                    "download_count": payload.get("download_count"),
                    "observed_at": round(time.time(), 3),
                }
            )
            if payload.get("complete") is True:
                return payload
        return None

    try:
        return live_common.wait_for(resolve, timeout_seconds, 1.0, "tracing harness download report completion")
    except Exception as exc:
        raise RuntimeError(f"Timed out waiting for tracing harness download report. Observations: {observations[-20:]!r}") from exc


def wait_for_seed_completed_at(
    *,
    destination_profile_id: str,
    destination_dir: Path,
    seed: SeedFile,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until one destination client has completed one source seed file."""

    completed_path = destination_dir / seed.name
    result = dtt.wait_for_completed_file(
        completed_path,
        expected_size=seed.size,
        expected_sha256=seed.sha256,
        timeout_seconds=timeout_seconds,
    )
    result["destination_profile_id"] = destination_profile_id
    result["source_profile_id"] = seed.profile_id
    result["path"] = str(completed_path)
    return result


def wait_for_completed_matrix(
    *,
    incoming_dirs: dict[str, Path],
    seeds: dict[str, SeedFile],
    timeout_seconds: float,
) -> list[dict[str, object]]:
    """Validates all six directed transfers across the three-client swarm."""

    completions: list[dict[str, object]] = []
    for destination_key in CLIENT_KEYS:
        for source_key in CLIENT_KEYS:
            if destination_key == source_key:
                continue
            completions.append(
                wait_for_seed_completed_at(
                    destination_profile_id=CLIENT_IDENTITIES[destination_key].profile_id,
                    destination_dir=incoming_dirs[destination_key],
                    seed=seeds[source_key],
                    timeout_seconds=timeout_seconds,
                )
            )
    return completions


def build_role_proofs(completions: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    """Summarizes whether every client both uploaded and downloaded at least once."""

    proofs: dict[str, dict[str, object]] = {}
    for identity in (CLIENT01, CLIENT02, CLIENT04):
        profile_id = identity.profile_id
        downloaded = [row for row in completions if row.get("destination_profile_id") == profile_id]
        uploaded = [row for row in completions if row.get("source_profile_id") == profile_id]
        proofs[profile_id] = {
            "completed_downloads": len(downloaded),
            "completed_upload_targets": sorted({str(row.get("destination_profile_id")) for row in uploaded}),
            "has_download_proof": bool(downloaded),
            "has_upload_proof": bool(uploaded),
        }
    return proofs


def shutdown_amule(control_exe: Path | None, profile: amule_harness.AmuleRuntimeProfile | None) -> dict[str, object]:
    """Requests graceful aMule daemon shutdown through EC when possible."""

    if control_exe is None or profile is None:
        return {"skipped": True}
    completed = amule_harness.run_amulecmd(control_exe, profile, "Shutdown", timeout_seconds=30.0, check=False)
    return amule_command_summary(completed)


def write_reports(paths, report: dict[str, object]) -> None:
    """Writes suite-specific and generic JSON reports for matrix callers."""

    harness_cli_common.write_json_file(paths.source_artifacts_dir / "three-client-swarm-transfer.json", report)
    harness_cli_common.write_json_file(paths.source_artifacts_dir / "result.json", report)


def main(argv: list[str] | None = None) -> int:
    """Runs the deterministic three-client swarm suite."""

    args = parse_args(argv)
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration=args.configuration,
        workspace_root=args.workspace_root,
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
    }
    server_process: subprocess.Popen | None = None
    client1_app = None
    client2_app = None
    amule_process: subprocess.Popen | None = None
    amule_profile: amule_harness.AmuleRuntimeProfile | None = None
    amule_control_exe: Path | None = None
    current_phase = "initializing"

    try:
        amule_client = resolve_required_amule(paths, args)
        amule_daemon_exe = amule_client.executable
        amule_control_exe = amule_client.control_executable
        client2_app_exe = dtt.resolve_client2_app_exe(paths.workspace_root, args.configuration, args.client2_app_exe)
        report["client_inventory"] = {
            CLIENT02.profile_id: {"app_exe": str(client2_app_exe)},
            CLIENT04.profile_id: amule_client.as_report(),
        }

        p2p_address = args.p2p_bind_interface_address or dtt.discover_interface_ipv4(args.p2p_bind_interface_name)
        ports = choose_swarm_ports()
        report["network"] = {
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
            "ports": ports,
        }

        ed2k_repo = dtt.resolve_ed2k_server_repo(paths.workspace_root, args.ed2k_server_repo)
        ed2k_exe = dtt.resolve_ed2k_server_exe(paths.workspace_root, args.ed2k_server_exe)
        report["checks"]["server_build"] = dtt.build_ed2k_server_binary(ed2k_repo, ed2k_exe)

        server_dir = paths.source_artifacts_dir / "ed2k-server"
        catalog_path = server_dir / "catalog.json"
        config_path = server_dir / "config.json"
        dtt.write_empty_catalog(catalog_path)
        report["ed2k_server"] = dtt.build_server_config(
            config_path,
            ed2k_port=ports["ed2k_tcp"],
            admin_port=ports["ed2k_admin"],
            catalog_path=catalog_path,
            token=args.api_key,
        )
        current_phase = "start_ed2k_server"
        server_process = dtt.start_ed2k_server(ed2k_exe, config_path, server_dir / "server.log")
        admin_base_url = f"http://127.0.0.1:{ports['ed2k_admin']}"
        report["checks"]["ed2k_server_health"] = dtt.wait_for_admin_health(admin_base_url, 30.0)

        current_phase = "create_seed_files"
        seed_root = paths.source_artifacts_dir / "seeds"
        seeds = {
            CLIENT01.key: create_seed_file(seed_root, CLIENT01.key, CLIENT01.profile_id, args.fixture_size_bytes),
            CLIENT02.key: create_seed_file(seed_root, CLIENT02.key, CLIENT02.profile_id, args.fixture_size_bytes),
            CLIENT04.key: create_seed_file(seed_root, CLIENT04.key, CLIENT04.profile_id, args.fixture_size_bytes),
        }

        current_phase = "prepare_profiles"
        client1 = live_common.prepare_scenario_profile(profile_seed_dir, paths.source_artifacts_dir, [], CLIENT01.profile_id)
        client2 = live_common.prepare_scenario_profile(profile_seed_dir, paths.source_artifacts_dir, [], CLIENT02.profile_id)
        amule_profile = amule_harness.prepare_amule_profile(
            root_dir=paths.source_artifacts_dir / "clients" / CLIENT04.profile_id,
            profile_id=CLIENT04.profile_id,
            nick=CLIENT04.nick,
            tcp_port=ports["amule_tcp"],
            udp_port=ports["amule_udp"],
            ec_port=ports["amule_ec"],
            advertised_address=p2p_address,
        )
        amule_seed_file = amule_profile.incoming_dir / seeds[CLIENT04.key].name
        shutil.copyfile(seeds[CLIENT04.key].path, amule_seed_file)
        seeds[CLIENT04.key] = SeedFile(
            client_key=CLIENT04.key,
            profile_id=CLIENT04.profile_id,
            path=amule_seed_file,
            name=seeds[CLIENT04.key].name,
            size=seeds[CLIENT04.key].size,
            sha256=seeds[CLIENT04.key].sha256,
        )

        dtt.configure_client_profile(
            config_dir=Path(client1["config_dir"]),
            app_exe=paths.app_exe,
            nick=CLIENT01.nick,
            tcp_port=ports["client1_tcp"],
            udp_port=ports["client1_udp"],
            ed2k_enabled=True,
            autoconnect=False,
            rest_api_key=args.api_key,
            rest_port=ports["client1_rest"],
            rest_bind_addr=args.bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
        )
        dtt.configure_client_profile(
            config_dir=Path(client2["config_dir"]),
            app_exe=client2_app_exe,
            nick=CLIENT02.nick,
            tcp_port=ports["client2_tcp"],
            udp_port=ports["client2_udp"],
            ed2k_enabled=True,
            autoconnect=True,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
        )
        for config_dir in (Path(client1["config_dir"]), Path(client2["config_dir"]), amule_profile.config_dir):
            dtt.write_server_met(config_dir / "server.met", address=p2p_address, port=ports["ed2k_tcp"], name="emulebb-local-e2e")

        report["profiles"] = {
            CLIENT01.profile_id: {
                "profile_base": str(client1["profile_base"]),
                "config_dir": str(client1["config_dir"]),
                "incoming_dir": str(client1["incoming_dir"]),
                "temp_dir": str(client1["temp_dir"]),
                "preferences": dtt.read_preferences_snapshot(Path(client1["config_dir"])),
            },
            CLIENT02.profile_id: {
                "profile_base": str(client2["profile_base"]),
                "config_dir": str(client2["config_dir"]),
                "incoming_dir": str(client2["incoming_dir"]),
                "temp_dir": str(client2["temp_dir"]),
                "preferences": dtt.read_preferences_snapshot(Path(client2["config_dir"])),
            },
            CLIENT04.profile_id: amule_profile.as_report(),
        }

        current_phase = "launch_amule"
        amule_process = amule_harness.start_amuled(amule_daemon_exe, amule_profile)
        report["checks"]["amule_ec_ready"] = amule_harness.wait_for_ec_ready(
            amule_control_exe,
            amule_profile,
            args.rest_ready_timeout_seconds,
        )
        report["checks"]["amule_reload_shared"] = amule_command_summary(
            amule_harness.run_amulecmd(amule_control_exe, amule_profile, "Reload Shared", timeout_seconds=30.0)
        )
        amule_shared = amule_harness.wait_for_shared_file_hash(
            amule_control_exe,
            amule_profile,
            seeds[CLIENT04.key].name,
            args.link_export_timeout_seconds,
        )
        seeds[CLIENT04.key] = seeds[CLIENT04.key].with_link(
            amule_harness.build_file_link(seeds[CLIENT04.key].name, seeds[CLIENT04.key].size, str(amule_shared["hash"]))
        )
        report["checks"]["amule_shared_file"] = {"shared": amule_shared, "seed": seeds[CLIENT04.key].as_report()}
        report["checks"]["amule_add_server"] = amule_command_summary(
            amule_harness.run_amulecmd(
                amule_control_exe,
                amule_profile,
                f"Add {amule_harness.build_server_link(p2p_address, ports['ed2k_tcp'])}",
                timeout_seconds=30.0,
            )
        )
        report["checks"]["amule_connect_server"] = amule_command_summary(
            amule_harness.run_amulecmd(amule_control_exe, amule_profile, "Connect ed2k", timeout_seconds=30.0)
        )
        report["checks"]["amule_server_client"] = dtt.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT04.nick,
            args.server_connect_timeout_seconds,
        )
        report["checks"]["amule_server_file"] = dtt.wait_for_server_file(
            admin_base_url,
            args.api_key,
            str(seeds[CLIENT04.key].file_hash),
            args.server_publish_timeout_seconds,
        )

        current_phase = "launch_harness"
        harness_dir = paths.source_artifacts_dir / "harness-control"
        harness_ready_path = harness_dir / "ready.txt"
        harness_export_link_path = harness_dir / "seed.ed2k.txt"
        harness_download_links_path = harness_dir / "downloads.ed2k.txt"
        harness_download_report_path = harness_dir / "download-report.json"
        harness_dir.mkdir(parents=True, exist_ok=True)
        client2_app = live_common.launch_app(
            client2_app_exe,
            Path(client2["profile_base"]),
            minimized_to_tray=True,
            extra_args=build_harness_args(
                ready_path=harness_ready_path,
                fixture_file=seeds[CLIENT02.key].path,
                export_link_path=harness_export_link_path,
                source_ip=p2p_address,
                download_link_file=harness_download_links_path,
                download_report_file=harness_download_report_path,
            ),
        )
        seeds[CLIENT02.key] = seeds[CLIENT02.key].with_link(
            dtt.wait_for_exported_link(harness_export_link_path, args.link_export_timeout_seconds)
        )
        report["checks"]["harness_exported_link"] = seeds[CLIENT02.key].as_report()
        report["checks"]["harness_server_client"] = dtt.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT02.nick,
            args.server_connect_timeout_seconds,
        )
        report["checks"]["harness_server_file"] = dtt.wait_for_server_file(
            admin_base_url,
            args.api_key,
            str(seeds[CLIENT02.key].file_hash),
            args.server_publish_timeout_seconds,
        )

        current_phase = "launch_emulebb"
        client1_app = live_common.launch_app(paths.app_exe, Path(client1["profile_base"]), minimized_to_tray=True)
        base_url = f"http://{args.bind_addr}:{ports['client1_rest']}"
        report["checks"]["emulebb_rest_ready"] = rest_smoke.compact_http_result(
            rest_smoke.wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        )
        report["checks"]["emulebb_server_connect"] = dtt.add_and_connect_server(
            base_url,
            args.api_key,
            address=p2p_address,
            port=ports["ed2k_tcp"],
            timeout_seconds=args.server_connect_timeout_seconds,
        )
        report["checks"]["emulebb_shared_add"] = add_emule_shared_file(base_url, args.api_key, seeds[CLIENT01.key].path)
        report["checks"]["emulebb_shared_reload"] = reload_emule_shared_files(base_url, args.api_key)
        seeds[CLIENT01.key] = wait_for_emule_shared_file_link(
            base_url,
            args.api_key,
            seeds[CLIENT01.key],
            args.link_export_timeout_seconds,
        )
        report["checks"]["emulebb_server_client"] = dtt.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT01.nick,
            args.server_connect_timeout_seconds,
        )
        report["checks"]["emulebb_server_file"] = dtt.wait_for_server_file(
            admin_base_url,
            args.api_key,
            str(seeds[CLIENT01.key].file_hash),
            args.server_publish_timeout_seconds,
        )

        current_phase = "queue_concurrent_downloads"
        report["seeds"] = {key: seed.as_report() for key, seed in seeds.items()}
        source_links = {
            CLIENT01.key: ed2k_link_with_source(
                str(seeds[CLIENT01.key].link),
                source_ip=p2p_address,
                source_port=ports["client1_tcp"],
            ),
            CLIENT02.key: ed2k_link_with_source(
                str(seeds[CLIENT02.key].link),
                source_ip=p2p_address,
                source_port=ports["client2_tcp"],
            ),
            CLIENT04.key: ed2k_link_with_source(
                str(seeds[CLIENT04.key].link),
                source_ip=p2p_address,
                source_port=ports["amule_tcp"],
            ),
        }
        report["checks"]["source_annotated_links"] = source_links
        report["checks"]["harness_download_links"] = write_download_link_file(
            harness_download_links_path,
            [source_links[CLIENT01.key], source_links[CLIENT04.key]],
        )
        report["checks"]["emulebb_download_add"] = add_emule_downloads(
            base_url,
            args.api_key,
            [
                seeds[CLIENT02.key].with_link(source_links[CLIENT02.key]),
                seeds[CLIENT04.key].with_link(source_links[CLIENT04.key]),
            ],
        )
        report["checks"]["amule_download_add"] = add_amule_downloads(
            amule_control_exe,
            amule_profile,
            [source_links[CLIENT01.key], source_links[CLIENT02.key]],
        )
        report["checks"]["all_downloads_queued_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")

        current_phase = "wait_for_transfer_matrix"
        incoming_dirs = {
            CLIENT01.key: Path(client1["incoming_dir"]),
            CLIENT02.key: Path(client2["incoming_dir"]),
            CLIENT04.key: amule_profile.incoming_dir,
        }
        completions = wait_for_completed_matrix(
            incoming_dirs=incoming_dirs,
            seeds=seeds,
            timeout_seconds=args.transfer_completion_timeout_seconds,
        )
        report["checks"]["harness_download_report"] = wait_for_harness_download_report(
            harness_download_report_path,
            args.transfer_completion_timeout_seconds,
        )
        report["checks"]["harness_ready_after_completion"] = dtt.wait_for_file(
            harness_ready_path,
            30.0,
            "tracing harness ready file after download completion",
        )
        report["checks"]["transfer_completions"] = completions
        report["checks"]["role_proofs"] = build_role_proofs(completions)
        report["checks"]["ed2k_server_stats_final"] = dtt.admin_request(admin_base_url, args.api_key, "/api/stats")
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
        for identity, app in ((CLIENT01, client1_app), (CLIENT02, client2_app)):
            if app is None:
                continue
            try:
                live_common.close_app_cleanly(app)
                cleanup[identity.profile_id] = {"ok": True}
            except Exception as exc:
                cleanup[identity.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        try:
            cleanup[CLIENT04.profile_id] = shutdown_amule(amule_control_exe, amule_profile)
        except Exception as exc:
            cleanup[CLIENT04.profile_id] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        dtt.stop_process(amule_process)
        dtt.stop_process(server_process)
        report["cleanup"] = cleanup
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        write_reports(paths, report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
