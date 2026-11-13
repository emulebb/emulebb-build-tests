"""Same-guest, source-bound production CLI peer for APK transfer qualification."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import sys
import time
from urllib.parse import quote
from uuid import uuid4

from .rust_local_ed2k import ed2k_link_with_source, publish_shared_tree, request_json
from .rust_shared_library_fixture import deterministic_payload

PREFIX = ("-s", "emulator-5554")
PEER_KEY = "synthetic-apk-peer-only-0000000000000000"


def start_local_listener(base: str, key: str) -> None:
    """Start the real peer runtime with no public discovery/server endpoints."""
    servers = request_json(base, "GET", "/api/v1/servers", key).get("items")
    if not isinstance(servers, list):
        raise RuntimeError("APK transfer peer returned an invalid server collection")
    for server in servers:
        address, port = server.get("address"), server.get("port")
        if not isinstance(address, str) or not address or type(port) is not int or not 0 < port <= 65535:
            raise RuntimeError("APK transfer peer returned an invalid server endpoint")
        endpoint = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
        request_json(base, "DELETE", "/api/v1/servers/" + quote(endpoint, safe=""), key)
    request_json(base, "POST", "/api/v1/servers", key,
                 {"address": "127.0.0.1", "port": 20031, "name": "Local qualification endpoint", "connect": False})
    servers = request_json(base, "GET", "/api/v1/servers", key).get("items")
    if (not isinstance(servers, list) or len(servers) != 1
            or servers[0].get("address") != "127.0.0.1" or servers[0].get("port") != 20031):
        raise RuntimeError("APK transfer peer retained a nonlocal server endpoint")
    # WHY: Core binds the peer listener before its asynchronous server-login
    # worker; a closed local server endpoint deliberately supplies no discovery.
    # Actual transfer bytes below, rather than this acknowledgement, prove P2P.
    acknowledgement = request_json(base, "POST", "/api/v1/servers/operations/connect", key)
    if acknowledgement.get("operationQueued") is not True:
        raise RuntimeError("APK transfer peer did not accept its eD2K start operation")


def guest_sha256(command, path: str) -> str:
    """Preserve spaces/metacharacters through ADB shell's extra command parser."""
    result = command(*PREFIX, "shell", "sha256sum", shlex.quote(path)).split()
    if not result or re.fullmatch(r"[0-9a-f]{64}", result[0]) is None:
        raise RuntimeError("Owned guest file has no valid SHA-256 result")
    return result[0]


def admit_peer(root: Path, *, manifest_sha256: str, identity: dict) -> dict:
    """Admit only a producer-verified native archive's exact CLI/runtime subset."""
    if re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is None:
        raise ValueError("APK peer requires an immutable manifest hash")
    manifest = root / "manifest.json"
    if root.is_symlink() or manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 65536:
        raise RuntimeError("APK peer manifest must be a bounded regular file")
    raw = manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest_sha256:
        raise RuntimeError("APK peer manifest hash differs")
    value = json.loads(raw)
    if (not isinstance(value, dict) or value.get("schema") != "emulebb.android.apk-peer/1"
            or value.get("sourceRevision") != identity["sourceRevision"] or value.get("buildIdentity") != identity
            or not isinstance(value.get("files"), dict) or "emulebb-rust" not in value["files"]
            or set(value["files"]) - {"emulebb-rust", "libc++_shared.so"}):
        raise RuntimeError("APK peer must match the application's exact source and distribution identity")
    for name, record in value["files"].items():
        path = root / name
        if (not isinstance(record, dict) or type(record.get("sizeBytes")) is not int
                or not 0 < record["sizeBytes"] <= 512 * 1024**2
                or not isinstance(record.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
                or path.is_symlink() or not path.is_file() or path.stat().st_size != record["sizeBytes"]):
            raise RuntimeError("APK peer file is missing, redirected or inconsistent")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != record["sha256"]:
                raise RuntimeError("APK peer file hash differs")
    return {**value, "payloadRoot": str(root)}


@contextmanager
def production_peer(command, peer: dict, *, adb: str, child: dict, report_dir: Path, rust_source: Path, bind_ip: str):
    """Own a disjoint CLI profile and verify kernel process identity before signals."""
    from .android_emulator import _app_identity, _daemon_identity, _rest_app, _start_production_daemon, _stop_group
    from .rust_client import write_rust_profile

    home = "/data/local/tmp/emulebb-apk-peer-" + uuid4().hex
    profile = report_dir / "peer-profile"
    write_rust_profile(profile, rust_repo=rust_source, incoming_dir=Path(home) / "incoming",
                       rest_addr="127.0.0.1", rest_port=20027, api_key=PEER_KEY,
                       auto_connect=False, network_kademlia=False, p2p_bind_ip=bind_ip,
                       ed2k_port=20029, kad_port=20030, server_endpoint="127.0.0.1:20031",
                       nat_enabled=False, replace_servers=True, initial_shared_directory_reload=False,
                       local_only_discovery=True)
    command(*PREFIX, "shell", "mkdir", "-m", "700", home)
    process = capture = None
    forward = pid = identity = None
    executable = home + "/emulebb-rust"
    digest = peer["files"]["emulebb-rust"]["sha256"]
    try:
        command(*PREFIX, "push", str(profile) + "/.", home, timeout=60)
        command(*PREFIX, "shell", "chmod", "600", home + "/emulebb-rust-settings.toml")
        for name, record in peer["files"].items():
            target = home + "/" + name
            command(*PREFIX, "push", str(Path(peer["payloadRoot"]) / name), target, timeout=120)
            if command(*PREFIX, "shell", "sha256sum", target).split() != [record["sha256"], target]:
                raise RuntimeError("Guest APK peer file differs from its source-bound bytes")
            command(*PREFIX, "shell", "chmod", "500", target)
        process, capture = _start_production_daemon(adb, child, executable, home, home, report_dir)
        raw_forward = command(*PREFIX, "forward", "--no-rebind", "tcp:0", "tcp:20027")
        if re.fullmatch(r"[1-9][0-9]*", raw_forward) is None or int(raw_forward) > 65535:
            raise RuntimeError("APK peer must allocate a private REST forward")
        forward = int(raw_forward)
        deadline = time.monotonic() + 90
        while True:
            capture.raise_if_failed()
            if process.poll() is not None:
                raise RuntimeError("APK peer exited before REST readiness")
            try:
                status, document = _rest_app(forward, PEER_KEY)
            except (OSError, TimeoutError):
                status = None
            if status == 200:
                pid = command(*PREFIX, "shell", "cat", home + "/owned-daemon.pid")
                identity = _daemon_identity(command, pid, executable, digest, home)
                _app_identity(document, peer["buildIdentity"])
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("APK peer REST readiness timed out")
            time.sleep(0.5)
        yield home, forward
        request_json(f"http://127.0.0.1:{forward}", "POST", "/api/v1/app/shutdown", PEER_KEY, {"confirmShutdown": True})
        if process.wait(timeout=30) != 0:
            raise RuntimeError("APK qualification peer did not exit gracefully")
    finally:
        active_failure = sys.exc_info()[0] is not None
        cleanup_errors = []
        try:
            if process is not None and process.poll() is None:
                if identity is None:
                    # The outer owned guest teardown is the fail-safe until the
                    # process is admitted. Retain its files; do not claim cleanup.
                    raise RuntimeError("APK peer failed before guest process admission")
                if _daemon_identity(command, pid, executable, digest, home) != identity:
                    raise RuntimeError("APK peer process identity changed; refusing to signal it")
                command(*PREFIX, "shell", "kill", "-TERM", pid)
                process.wait(timeout=30)
        except Exception as error:
            cleanup_errors.append(type(error).__name__)
        finally:
            actions = [lambda: _stop_group(process)]
            if capture is not None:
                actions.extend([capture.close, capture.raise_if_failed])
            if forward is not None:
                actions.append(lambda: command(*PREFIX, "forward", "--remove", "tcp:" + str(forward)))
            if not cleanup_errors:
                actions.append(lambda: command(*PREFIX, "shell", "rm", "-rf", home))
            for action in actions:
                try:
                    action()
                except Exception as error:
                    cleanup_errors.append(type(error).__name__)
            if cleanup_errors:
                (report_dir / "peer-cleanup.json").write_text(json.dumps({"status": "failed", "errorTypes": cleanup_errors}) + "\n", encoding="utf-8")
                if not active_failure:
                    raise RuntimeError("APK qualification peer cleanup failed")


def transfer_proof(command, peer: dict, *, apk_port: int, api_key: str, adb: str,
                   child: dict, report_dir: Path, rust_source: Path) -> dict:
    """Transfer real deterministic bytes to shared storage and preserve a foreign collision."""
    base = f"http://127.0.0.1:{apk_port}"
    network = request_json(base, "GET", "/api/v1/network", api_key)
    bind_ip = network.get("binding", {}).get("activeConfiguredAddress")
    address = ipaddress.ip_address(bind_ip)
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_unspecified:
        raise RuntimeError("APK local transfer requires a private guest IPv4 binding")
    incoming = "/sdcard/Download/emulebb-apk-proof-" + uuid4().hex
    name = "Android Sample.bin"
    occupant = b"synthetic foreign occupant"
    content = deterministic_payload(0, 256 * 1024, generation="android-apk")
    expected_sha = hashlib.sha256(content).hexdigest()
    fixture = report_dir / name
    fixture.write_bytes(content)
    foreign = report_dir / "foreign.bin"
    foreign.write_bytes(occupant)
    command(*PREFIX, "shell", "mkdir", "-m", "700", incoming)
    canonical = command(*PREFIX, "shell", "readlink", "-f", incoming)
    if not PurePosixPath(canonical).is_absolute() or PurePosixPath(canonical).name != PurePosixPath(incoming).name:
        raise RuntimeError("APK incoming fixture did not resolve to its owned directory")
    incoming = canonical
    command(*PREFIX, "push", str(foreign), incoming + "/" + name)
    request_json(base, "PATCH", "/api/v1/app/settings", api_key,
                 {"daemon": {"incomingDir": incoming}, "core": {"autoConnect": False, "networkKademlia": False},
                  "ed2k": {"enableUdpReask": False, "addServersFromServer": False}, "nat": {"enabled": False}})
    with production_peer(command, peer, adb=adb, child=child, report_dir=report_dir,
                         rust_source=rust_source, bind_ip=bind_ip) as (home, port):
        shared = home + "/shared"
        command(*PREFIX, "shell", "mkdir", "-m", "700", shared)
        command(*PREFIX, "push", str(fixture), shared + "/" + name)
        peer_base = f"http://127.0.0.1:{port}"
        tree = publish_shared_tree(peer_base, PEER_KEY, root=shared, file_name=name)
        item = tree["sharedFiles"]["matched"]
        source_link = ed2k_link_with_source(item["ed2kLink"], bind_ip, 20029)
        for endpoint, key in ((peer_base, PEER_KEY), (base, api_key)):
            start_local_listener(endpoint, key)
        request_json(base, "POST", "/api/v1/transfers", api_key, {"link": source_link, "paused": False})
        deadline = time.monotonic() + 120
        while True:
            files = request_json(base, "GET", "/api/v1/shared-files", api_key).get("items", [])
            result = next((file for file in files if file.get("hash", "").lower() == item["hash"].lower()
                           and file.get("complete") is True and file.get("partFile") is False), None)
            if result is not None:
                path = PurePosixPath(result.get("path", ""))
                if path.parent != PurePosixPath(incoming) or path.name == name or result.get("sizeBytes") != len(content):
                    raise RuntimeError("APK delivered file has invalid size, location or collision handling")
                if guest_sha256(command, str(path)) != expected_sha:
                    raise RuntimeError("APK delivered bytes differ from the deterministic peer payload")
                if guest_sha256(command, incoming + "/" + name) != hashlib.sha256(occupant).hexdigest():
                    raise RuntimeError("APK delivery replaced the foreign destination occupant")
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("APK local transfer did not register a completed delivery within its bound")
            time.sleep(1)
    return {"status": "passed", "sizeBytes": len(content), "sha256": expected_sha,
            "deliveredPath": str(path), "collisionPreserved": True,
            "deliveredInSharedStorage": True, "peerSourceRevision": peer["sourceRevision"]}
