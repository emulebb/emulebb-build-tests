"""Same-guest, source-bound production CLI peer for APK transfer qualification."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import sys
import time
from urllib.parse import quote
from uuid import uuid4

from .rust_local_ed2k import RustRestFailure, ed2k_link_with_source, publish_shared_tree, request_json
from .rust_shared_library_fixture import deterministic_payload
from .android_adb_failure import AdbOperationFailure
from .android_apk_cleanup import COLLISION_OCCUPANT, OwnedFixtureFailure, remove_owned_fixture

PREFIX = ("-s", "emulator-5554")
PEER_KEY = "synthetic-apk-peer-only-0000000000000000"


class CampaignFailure(RuntimeError):
    """Expose only a fixed stage code and exception type, never native output."""
    def __init__(self, failure):
        self.failure = failure
        super().__init__("APK transfer campaign failed: " + failure["code"])


class _Campaign:
    def __init__(self, path, peer, prefix):
        self.path = path
        self.value = {"schema": "emulebb.android.transfer-campaign/1", "status": "running",
                      "phase": "admit-original-settings", "peerSourceRevision": peer["sourceRevision"],
                      "deviceSerialSha256": hashlib.sha256(prefix[1].encode()).hexdigest(), "cleanup": []}
        self.save()

    def save(self):
        # No UI, exception text, operator paths, endpoints or credential values.
        temporary = self.path.with_name(self.path.name + ".tmp")
        with temporary.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(self.value, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.path)

    def mark(self, phase):
        self.value["phase"] = phase
        self.save()

    def fail(self, error):
        self.value["status"] = "failed"
        self.value.setdefault("failure", {"phase": self.value["phase"],
            "code": self.value["phase"] + "-failed", "errorType": type(error).__name__,
            **({"adb": error.safe_failure} if isinstance(error, AdbOperationFailure) else {}),
            **({"rest": error.safe_failure} if isinstance(error, RustRestFailure) else {}),
            **({"ownedFixture": {"code": error.code, "filesRemoved": error.files_removed}} if isinstance(error, OwnedFixtureFailure) else {})})
        self.save()

    def record(self, **values):
        self.value.update(values)
        self.save()

    def cleaned(self, action, error=None):
        self.value["cleanup"].append({"action": action, "status": "passed" if error is None else "failed",
            **({"errorType": type(error).__name__} if error is not None else {}),
            **({"adb": error.safe_failure} if isinstance(error, AdbOperationFailure) else {}),
            **({"ownedFixture": {"code": error.code, "filesRemoved": error.files_removed}} if isinstance(error, OwnedFixtureFailure) else {})})
        self.save()


def _server_configuration(base, key):
    rows = request_json(base, "GET", "/api/v1/servers", key).get("items")
    if (not isinstance(rows, list) or any(not isinstance(row, dict)
            or not isinstance(row.get("address"), str) or not row["address"]
            or type(row.get("port")) is not int or not 0 < row["port"] <= 65535 for row in rows)):
        raise RuntimeError("APK transfer peer returned an invalid server collection")
    # Complete ServerCreate/ServerUpdate configuration, excluding live counters.
    fields = ("address", "port", "name", "priority", "static", "enabled")
    return sorted(({name: row.get(name) for name in fields} for row in rows),
                  key=lambda row: (str(row["address"]), str(row["port"])))


@contextmanager
def local_listener(base: str, key: str, *, role="app", campaign=None):
    """Direct listener startup to loopback without replacing operator servers."""
    if role not in {"peer", "app"}:
        raise ValueError("Local listener diagnostics require a known participant role")
    def stage(name):
        if campaign is not None:
            campaign.mark(role + "-listener-" + name)
    stage("server-inventory")
    before = _server_configuration(base, key)
    stage("allocate-owned-loopback-endpoint")
    for _attempt in range(32):
        nonce = uuid4().hex
        host = 1 + int(nonce[:6], 16) % (2**24 - 2)
        address = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("127.0.0.0")) + host))
        if not any(row["address"] == address and row["port"] == 20031 for row in before):
            break
    else:
        raise RuntimeError("Cannot allocate an absent owned loopback endpoint")
    name = "Owned APK qualification " + nonce
    route = "/api/v1/servers/" + quote(address + ":20031", safe="")
    if campaign is not None:
        ownership = dict(campaign.value.get("listenerOwnership", {}))
        ownership[role] = {"nonce": nonce, "port": 20031}
        campaign.record(listenerOwnership=ownership)
    created = False
    try:
        stage("server-create")
        request_json(base, "POST", "/api/v1/servers", key,
                     {"address": address, "port": 20031, "name": name, "connect": False})
        created = True
        # Directed mode excludes fallback to the preserved public server rows.
        # A real byte transfer below, not this acknowledgement, proves P2P.
        stage("directed-connect")
        acknowledgement = request_json(base, "POST", route + "/operations/connect", key)
        if acknowledgement.get("operationQueued") is not True:
            stage("connect-acknowledgement")
            raise RuntimeError("APK transfer peer did not accept its eD2K start operation")
        stage("ready")
        yield
    except Exception as error:
        if campaign is not None:
            campaign.fail(error)
        raise
    finally:
        if created:
            if campaign is not None:
                stage("owned-server-removal-precondition")
            current = _server_configuration(base, key)
            owned = [row for row in current if row["address"] == address and row["port"] == 20031]
            if len(owned) != 1 or owned[0]["name"] != name:
                raise RuntimeError("Qualification server ownership changed; refusing removal")
            stage("owned-server-remove")
            request_json(base, "DELETE", route, key)
        stage("server-configuration-restoration")
        if _server_configuration(base, key) != before:
            raise RuntimeError("Qualification altered preexisting server configuration")


def guest_sha256(command, path: str, *, prefix=PREFIX) -> str:
    """Preserve spaces/metacharacters through ADB shell's extra command parser."""
    result = command(*prefix, "shell", "sha256sum", shlex.quote(path)).split()
    if not result or re.fullmatch(r"[0-9a-f]{64}", result[0]) is None:
        raise RuntimeError("Owned guest file has no valid SHA-256 result")
    return result[0]


def admit_peer(root: Path, *, manifest_sha256: str, identity: dict, expected_abi: str) -> dict:
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
    targets = {"arm64-v8a": "aarch64-linux-android", "x86_64": "x86_64-linux-android"}
    if (not isinstance(value, dict) or value.get("schema") != "emulebb.android.apk-peer/1"
            or expected_abi not in targets or value.get("abi") != expected_abi or value.get("target") != targets[expected_abi]
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
def production_peer(command, peer: dict, *, adb: str, child: dict, report_dir: Path, rust_source: Path, bind_ip: str,
                    prefix=PREFIX, bind_interface: str | None = None, spawn_daemon=None, stop_client=None, campaign=None):
    """Own a disjoint CLI profile and verify kernel process identity before signals."""
    from .android_emulator import _app_identity, _daemon_identity, _rest_app, _start_production_daemon, _stop_group
    from .rust_client import write_rust_profile

    if prefix != PREFIX and (spawn_daemon is None or stop_client is None):
        raise ValueError("Selected-device peer requires its explicit owned launcher and client cleanup")
    spawn = spawn_daemon or _start_production_daemon
    stop = stop_client or _stop_group

    home = "/data/local/tmp/emulebb-apk-peer-" + uuid4().hex
    profile = report_dir / "peer-profile"
    process = capture = None
    forward = pid = identity = None
    home_created = False
    executable = home + "/emulebb-rust"
    digest = peer["files"]["emulebb-rust"]["sha256"]
    def stage(name):
        if campaign is not None:
            campaign.mark(name)
    try:
        if campaign is not None:
            campaign.record(peerOwnership={"nonce": PurePosixPath(home).name.removeprefix("emulebb-apk-peer-"),
                                           "executableSha256": digest, "creationVerified": False})
        stage("peer-profile-seed")
        write_rust_profile(profile, rust_repo=rust_source, incoming_dir=Path(home) / "incoming",
                           rest_addr="127.0.0.1", rest_port=20027, api_key=PEER_KEY,
                           auto_connect=False, network_kademlia=False,
                           p2p_bind_ip=bind_ip if bind_interface is None else None, p2p_bind_interface=bind_interface,
                           ed2k_port=20029, kad_port=20030, server_endpoint="127.0.0.1:20031",
                           nat_enabled=False, replace_servers=True, initial_shared_directory_reload=False,
                           local_only_discovery=True)
        stage("peer-home-create")
        command(*prefix, "shell", "mkdir", "-m", "700", home)
        home_created = True
        if campaign is not None:
            campaign.value["peerOwnership"]["creationVerified"] = True
            campaign.save()
        stage("peer-profile-push")
        command(*prefix, "push", str(profile) + "/.", home, timeout=60)
        command(*prefix, "shell", "chmod", "600", home + "/emulebb-rust-settings.toml")
        for name, record in peer["files"].items():
            stage("peer-binary-push-and-hash")
            target = home + "/" + name
            command(*prefix, "push", str(Path(peer["payloadRoot"]) / name), target, timeout=120)
            if command(*prefix, "shell", "sha256sum", target).split() != [record["sha256"], target]:
                raise RuntimeError("Guest APK peer file differs from its source-bound bytes")
            command(*prefix, "shell", "chmod", "500", target)
        stage("peer-process-spawn")
        process, capture = spawn(adb, child, executable, home, home, report_dir)
        # Admit the real process immediately: a physical phone has no disposable
        # outer guest teardown to clean up an unverified long-running peer.
        deadline = time.monotonic() + 10
        stage("peer-process-admission")
        while True:
            if process.poll() is not None:
                if campaign is not None:
                    if capture is not None:
                        capture.close()
                    campaign.record(peerProcess={"returnCode": process.returncode,
                        **({"startup": capture.summary()} if callable(getattr(capture, "summary", None)) else {})})
                raise RuntimeError("APK peer exited before guest process admission")
            pid = command(*prefix, "shell", "cat", home + "/owned-daemon.pid", check=False)
            try:
                identity = _daemon_identity(command, pid, executable, digest, home, prefix=prefix)
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("APK peer guest process admission timed out") from None
                time.sleep(0.25)
        stage("peer-rest-forward")
        raw_forward = command(*prefix, "forward", "--no-rebind", "tcp:0", "tcp:20027")
        if re.fullmatch(r"[1-9][0-9]*", raw_forward) is None or int(raw_forward) > 65535:
            raise RuntimeError("APK peer must allocate a private REST forward")
        forward = int(raw_forward)
        deadline = time.monotonic() + 90
        stage("peer-source-bound-readiness")
        while True:
            if capture is not None:
                capture.raise_if_failed()
            if process.poll() is not None:
                if campaign is not None:
                    if capture is not None:
                        capture.close()
                    campaign.record(peerProcess={"returnCode": process.returncode,
                        **({"startup": capture.summary()} if callable(getattr(capture, "summary", None)) else {})})
                raise RuntimeError("APK peer exited before REST readiness")
            try:
                status, document = _rest_app(forward, PEER_KEY)
            except (OSError, TimeoutError):
                status = None
            if status == 200:
                _app_identity(document, peer["buildIdentity"])
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("APK peer REST readiness timed out")
            time.sleep(0.5)
        stage("peer-ready")
        yield home, forward
        stage("peer-graceful-shutdown")
        if _daemon_identity(command, pid, executable, digest, home, prefix=prefix) != identity:
            raise RuntimeError("APK peer process identity changed before graceful shutdown")
        request_json(f"http://127.0.0.1:{forward}", "POST", "/api/v1/app/shutdown", PEER_KEY, {"confirmShutdown": True})
        if process.wait(timeout=30) != 0:
            raise RuntimeError("APK qualification peer did not exit gracefully")
    except Exception as error:
        if campaign is not None:
            campaign.fail(error)
        raise
    finally:
        active_failure = sys.exc_info()[0] is not None
        cleanup_errors = []
        try:
            if process is not None and process.poll() is None:
                if identity is None:
                    # No guest signal is safe before admission. Retain its files
                    # and emit failure evidence rather than claim cleanup.
                    raise RuntimeError("APK peer failed before guest process admission")
                if _daemon_identity(command, pid, executable, digest, home, prefix=prefix) != identity:
                    raise RuntimeError("APK peer process identity changed; refusing to signal it")
                command(*prefix, "shell", "kill", "-TERM", pid)
                process.wait(timeout=30)
        except Exception as error:
            cleanup_errors.append(type(error).__name__)
        finally:
            actions = [lambda: stop(process)] if process is not None else []
            if capture is not None:
                actions.extend([capture.close, capture.raise_if_failed])
            if forward is not None:
                def remove_forward():
                    rows = [row.split() for row in command(*prefix, "forward", "--list").splitlines()]
                    existing = [row for row in rows if len(row) == 3 and row[1] == f"tcp:{forward}"]
                    if existing and existing != [[prefix[1], f"tcp:{forward}", "tcp:20027"]]:
                        raise RuntimeError("APK peer forward ownership changed")
                    if existing:
                        command(*prefix, "forward", "--remove", "tcp:" + str(forward))
                actions.append(remove_forward)
            if not cleanup_errors and home_created:
                def remove_home():
                    if command(*prefix, "shell", "readlink", "-f", home) != home:
                        raise RuntimeError("APK peer home was redirected; refusing cleanup")
                    command(*prefix, "shell", "test", "!", "-L", home)
                    if guest_sha256(command, executable, prefix=prefix) != digest:
                        raise RuntimeError("APK peer bytes changed before owned cleanup")
                    command(*prefix, "shell", "rm", "-rf", home)
                actions.append(remove_home)
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
                   child: dict, report_dir: Path, rust_source: Path, restart_service,
                   prefix=PREFIX, spawn_daemon=None, stop_client=None) -> dict:
    campaign = _Campaign(report_dir / "transfer-campaign.json", peer, prefix)
    try:
        result = _transfer_proof(command, peer, apk_port=apk_port, api_key=api_key, adb=adb,
            child=child, report_dir=report_dir, rust_source=rust_source, restart_service=restart_service,
            prefix=prefix, spawn_daemon=spawn_daemon, stop_client=stop_client, campaign=campaign)
    except Exception as error:
        campaign.fail(error)
        campaign.record(phase=campaign.value["failure"]["phase"])
        raise CampaignFailure(campaign.value["failure"]) from None
    campaign.record(status="passed", phase="complete")
    return result


def probe_local_listeners(command, peer: dict, *, apk_port: int, api_key: str, adb: str,
                          child: dict, report_dir: Path, rust_source: Path, restart_service,
                          prefix=PREFIX, spawn_daemon=None, stop_client=None) -> dict:
    """Isolate real listener-control rejection without publishing or enqueueing bytes."""
    campaign = _Campaign(report_dir / "listener-probe.json", peer, prefix)
    base = f"http://127.0.0.1:{apk_port}"
    request = lambda method, route: request_json(base, method, route, api_key)
    app_attempted = False
    try:
        original = request("GET", "/api/v1/app/settings")
        roots = {row["path"] for row in request("GET", "/api/v1/shared-directories")["roots"]}
        campaign.mark("admit-prior-downloads")
        if any(row.get("state") != "completed" for row in request("GET", "/api/v1/transfers")["items"]):
            raise RuntimeError("Listener probe refuses to interrupt unfinished downloads")
        campaign.mark("admit-network-binding")
        binding = request("GET", "/api/v1/network")["binding"]
        address = ipaddress.ip_address(binding["activeConfiguredAddress"])
        if address.version != 4 or not address.is_private or address.is_loopback or address.is_unspecified:
            raise RuntimeError("Listener probe requires its actual private IPv4 binding")
        try:
            with production_peer(command, peer, adb=adb, child=child, report_dir=report_dir,
                    rust_source=rust_source, bind_ip=str(address), prefix=prefix,
                    bind_interface=binding.get("activeInterfaceId") or None,
                    spawn_daemon=spawn_daemon, stop_client=stop_client, campaign=campaign) as (_home, peer_port):
                with local_listener(f"http://127.0.0.1:{peer_port}", PEER_KEY, role="peer", campaign=campaign):
                    app_attempted = True
                    with local_listener(base, api_key, campaign=campaign):
                        campaign.record(listenerControl={"peer": "acknowledged", "app": "acknowledged"})
        except Exception as error:
            campaign.fail(error)
            raise
        finally:
            active_failure = sys.exc_info()[0] is not None
            if app_attempted:
                campaign.mark("cleanup-restore-app-listener-state")
                try:
                    restart_service()
                    if (request("GET", "/api/v1/app/settings") != original
                            or {row["path"] for row in request("GET", "/api/v1/shared-directories")["roots"]} != roots):
                        raise RuntimeError("Listener probe changed prior configuration")
                    campaign.cleaned("restore-app-listener-state")
                except Exception as error:
                    campaign.fail(error)
                    campaign.cleaned("restore-app-listener-state", error)
                    if not active_failure:
                        raise
    except Exception as error:
        campaign.fail(error)
        campaign.record(phase=campaign.value["failure"]["phase"])
        raise CampaignFailure(campaign.value["failure"]) from None
    campaign.record(status="passed", phase="complete")
    return {"status": "passed", "scope": "listener-control-only", "transfer": "not-run"}


def _transfer_proof(command, peer: dict, *, apk_port: int, api_key: str, adb: str,
                    child: dict, report_dir: Path, rust_source: Path, restart_service,
                    prefix, spawn_daemon, stop_client, campaign) -> dict:
    """Own a real transfer, collision and restart campaign; restore operator state."""
    base = f"http://127.0.0.1:{apk_port}"
    def request(method, route, body=None):
        return request_json(base, method, route, api_key, body)

    def shell(*args):
        return command(*prefix, "shell", *args)

    def shared_roots():
        roots = request("GET", "/api/v1/shared-directories").get("roots")
        if not isinstance(roots, list) or any(not isinstance(row, dict) or not isinstance(row.get("path"), str) for row in roots):
            raise RuntimeError("APK transfer returned invalid sharing roots")
        return {row["path"] for row in roots}

    selection = {"daemon": ("incomingDir",), "core": ("autoConnect", "networkKademlia", "networkEd2k"),
                 "ed2k": ("enableUdpReask", "addServersFromServer"), "nat": ("enabled",)}
    settings = request("GET", "/api/v1/app/settings")
    if any(not isinstance(settings.get(group), dict) or any(name not in settings[group] for name in names)
           for group, names in selection.items()):
        raise RuntimeError("APK transfer cannot preserve its prior settings")
    original = {group: {name: settings[group][name] for name in names} for group, names in selection.items()}
    if not isinstance(original["daemon"]["incomingDir"], str) or not original["daemon"]["incomingDir"].startswith("/"):
        raise RuntimeError("APK transfer requires its explicit prepared incoming configuration")
    campaign.mark("admit-prior-downloads-and-roots")
    original_roots = shared_roots()
    rows = request("GET", "/api/v1/transfers").get("items")
    if not isinstance(rows, list) or any(row.get("state") != "completed" for row in rows):
        raise RuntimeError("APK transfer refuses to interrupt preexisting unfinished downloads")
    prior_hashes = {row.get("hash", "").lower() for row in rows}
    shared = request("GET", "/api/v1/shared-files").get("items")
    if not isinstance(shared, list):
        raise RuntimeError("APK transfer returned invalid preexisting shared files")
    prior_hashes.update(row.get("hash", "").lower() for row in shared)
    campaign.mark("admit-network-binding")
    network = request_json(base, "GET", "/api/v1/network", api_key)
    bind_ip = network.get("binding", {}).get("activeConfiguredAddress")
    address = ipaddress.ip_address(bind_ip)
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_unspecified:
        raise RuntimeError("APK local transfer requires a private guest IPv4 binding")
    nonce = uuid4().hex
    incoming = "/sdcard/Download/emulebb-apk-proof-" + nonce
    name = "Android Sample.bin"
    occupant = COLLISION_OCCUPANT
    content = deterministic_payload(0, 256 * 1024, generation="android-apk-" + nonce)
    expected_sha = hashlib.sha256(content).hexdigest()
    campaign.record(fixtureOwnership={"nonce": nonce, "payloadSha256": expected_sha,
        "occupantSha256": hashlib.sha256(occupant).hexdigest(), "sizeBytes": len(content), "creationVerified": False},
        originalSettingsSha256=hashlib.sha256(json.dumps(original, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    fixture = report_dir / name
    fixture.write_bytes(content)
    foreign = report_dir / "foreign.bin"
    foreign.write_bytes(occupant)
    campaign.mark("fixture-directory-create")
    shell("mkdir", "-m", "700", incoming)
    campaign.value["fixtureOwnership"]["creationVerified"] = True
    campaign.save()
    canonical = shell("readlink", "-f", incoming)
    if canonical != "/storage/emulated/0/Download/" + PurePosixPath(incoming).name:
        raise RuntimeError("APK incoming fixture did not resolve to its owned directory")
    incoming = canonical
    file_hash = path = None
    changed = False
    cleanup_errors = []
    try:
        campaign.mark("fixture-occupant-push")
        command(*prefix, "push", str(foreign), incoming + "/" + name)
        changed = True
        campaign.mark("persist-fixture-settings")
        request("PATCH", "/api/v1/app/settings",
                {"daemon": {"incomingDir": incoming},
                 "core": {"autoConnect": False, "networkKademlia": False, "networkEd2k": True},
                 "ed2k": {"enableUdpReask": False, "addServersFromServer": False}, "nat": {"enabled": False}})
        campaign.mark("restart-fixture-destination")
        restart_service()
        campaign.mark("verify-fixture-destination")
        if request("GET", "/api/v1/app/settings").get("daemon", {}).get("incomingDir") != incoming:
            raise RuntimeError("APK qualification destination did not survive service restart")
        interface = network.get("binding", {}).get("activeInterfaceId") or None
        with production_peer(command, peer, adb=adb, child=child, report_dir=report_dir,
                rust_source=rust_source, bind_ip=bind_ip, prefix=prefix, bind_interface=interface,
                spawn_daemon=spawn_daemon, stop_client=stop_client, campaign=campaign) as (home, port):
            campaign.mark("peer-shared-fixture-push")
            shared = home + "/shared"
            shell("mkdir", "-m", "700", shared)
            command(*prefix, "push", str(fixture), shared + "/" + name)
            peer_base = f"http://127.0.0.1:{port}"
            campaign.mark("peer-shared-file-hash")
            item = publish_shared_tree(peer_base, PEER_KEY, root=shared, file_name=name)["sharedFiles"]["matched"]
            file_hash = item["hash"].lower()
            if re.fullmatch(r"[0-9a-f]{32}", file_hash) is None or file_hash in prior_hashes:
                file_hash = None
                raise RuntimeError("APK qualification payload already belongs to the operator")
            source_link = ed2k_link_with_source(item["ed2kLink"], bind_ip, 20029)
            campaign.record(transferHash=file_hash)
            campaign.mark("directed-local-listener-start")
            with local_listener(peer_base, PEER_KEY, role="peer", campaign=campaign), local_listener(base, api_key, campaign=campaign):
                campaign.mark("enqueue-owned-transfer")
                request("POST", "/api/v1/transfers", {"link": source_link, "paused": False})
                deadline = time.monotonic() + 120
                campaign.mark("await-completed-delivery")
                while True:
                    files = request("GET", "/api/v1/shared-files").get("items", [])
                    result = next((row for row in files if row.get("hash", "").lower() == file_hash
                                   and row.get("complete") is True and row.get("partFile") is False), None)
                    if result is not None:
                        path = PurePosixPath(result.get("path", ""))
                        campaign.mark("verify-delivered-path-and-size")
                        if path.parent != PurePosixPath(incoming) or path.name == name or result.get("sizeBytes") != len(content):
                            raise RuntimeError("APK delivered file has invalid size, location or collision handling")
                        campaign.mark("verify-delivered-bytes")
                        if guest_sha256(command, str(path), prefix=prefix) != expected_sha:
                            raise RuntimeError("APK delivered bytes differ from the deterministic peer payload")
                        campaign.mark("verify-collision-preserved")
                        if guest_sha256(command, incoming + "/" + name, prefix=prefix) != hashlib.sha256(occupant).hexdigest():
                            raise RuntimeError("APK delivery replaced the foreign destination occupant")
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("APK local transfer did not register a completed delivery within its bound")
                    time.sleep(1)
        campaign.mark("restart-completed-delivery")
        restart_service()
        campaign.mark("verify-completed-delivery-metadata")
        completed = request("GET", "/api/v1/transfers").get("items", [])
        if not any(row.get("hash", "").lower() == file_hash and row.get("state") == "completed"
                   and row.get("deliveredPath") == str(path) for row in completed):
            raise RuntimeError("APK completed delivery metadata did not survive restart")
        campaign.mark("verify-completed-delivery-bytes")
        if guest_sha256(command, str(path), prefix=prefix) != expected_sha:
            raise RuntimeError("APK delivered bytes changed across service restart")
        return {"status": "passed", "sizeBytes": len(content), "sha256": expected_sha,
                "collisionPreserved": True, "completedDeliverySurvivesRestart": True,
                "deliveredInSharedStorage": True, "peerSourceRevision": peer["sourceRevision"],
                "transport": "same-device-p2p", "wifiDataPlane": "not-claimed"}
    except Exception as error:
        campaign.fail(error)
        raise
    finally:
        active_failure = sys.exc_info()[0] is not None
        def remove_transfer():
            if file_hash is not None:
                # Only a hash absent before this nonce-owned campaign is ours.
                if path is not None and (path.parent != PurePosixPath(incoming)
                        or guest_sha256(command, str(path), prefix=prefix) != expected_sha):
                    raise RuntimeError("Owned delivery changed; refusing file deletion")
                request("DELETE", f"/api/v1/transfers/{file_hash}/files?confirm=true")
        def restore_settings():
            if changed:
                request("PATCH", "/api/v1/app/settings", original)
                restart_service()
                restored = request("GET", "/api/v1/app/settings")
                if any(restored.get(group, {}).get(name) != value for group, names in original.items() for name, value in names.items()):
                    raise RuntimeError("APK transfer did not restore prior settings")
                if shared_roots() != original_roots:
                    raise RuntimeError("APK transfer changed prior sharing roots")
        def remove_fixture():
            if cleanup_errors:
                return
            removed = remove_owned_fixture(command, prefix=prefix, nonce=nonce,
                protected_roots=original_roots | {original["daemon"]["incomingDir"]}, payload_sha256=expected_sha)
            campaign.record(fixtureCleanup=removed)
        for action_name, action in (("remove-owned-transfer", remove_transfer), ("restore-original-settings", restore_settings),
                                    ("remove-owned-fixture", remove_fixture)):
            campaign.mark("cleanup-" + action_name)
            try:
                action()
                campaign.cleaned(action_name)
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
                campaign.cleaned(action_name, error)
                campaign.fail(error)
        if cleanup_errors:
            (report_dir / "transfer-cleanup.json").write_text(json.dumps({"status": "failed", "errorTypes": cleanup_errors}) + "\n", encoding="utf-8")
            if not active_failure:
                raise RuntimeError("APK transfer cleanup failed; owned evidence retained")
