"""Bounded Docker-backed HighID eD2K source publisher fixture.

The public entry point runs on Windows and controls the WSL Docker engine with
argument-vector subprocess calls.  The same persisted module is invoked inside
the pinned container through the ``child`` CLI mode; no generated shell or
Python program participates in the fixture.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from emule_test_harness import ed2k_wire


DOCKER_IMAGE = (
    "python@sha256:7712cfd23e0501f5cb58faa5e6e0d515c9939bdbce866921799b31e696a1d13c"
)
DOCKER_PLATFORM = "linux/amd64"
BENCHMARK_SUBNET = "198.18.240.0/28"
PUBLISHER_IP = "198.18.240.2"
PUBLISHER_HIGH_ID = int.from_bytes(ipaddress.IPv4Address(PUBLISHER_IP).packed, "little")
WINDOWS_HOST_ROUTE_NETMASK = "255.255.255.255"
PLAIN_SERVER_FLAGS = 0x0119
OBFUSCATED_SOURCE_SERVER_FLAGS = PLAIN_SERVER_FLAGS | ed2k_wire.SRVCAP_SUPPORTCRYPT
DEFAULT_NICKNAME = "emulebb-harness-source-publisher"
RECEIPT_SCHEMA = "emulebb.docker-ed2k-source-publisher/1"
CALLBACK_COMMAND_SCHEMA = "emulebb.docker-ed2k-source-publisher.callback-command/1"
CALLBACK_RESULT_SCHEMA = "emulebb.docker-ed2k-source-publisher.callback-result/1"

OP_HELLO = 0x01
OP_HELLOANSWER = 0x4C

_LABEL_FIXTURE = "org.emulebb.harness.fixture"
_LABEL_RUN_ID = "org.emulebb.harness.run-id"
_FIXTURE_LABEL_VALUE = "docker-ed2k-source-publisher"
_CONTAINER_REPO = "/workspace"
_CONTAINER_RUN_DIR = "/run"


class DockerEd2kSourcePublisherError(RuntimeError):
    """Raised when the bounded publisher cannot be started or cleaned up."""


def _is_windows_host() -> bool:
    return os.name == "nt"


def _wsl_command(distribution: str | None, *arguments: str) -> list[str]:
    command = ["wsl.exe"]
    if distribution:
        command.extend(("--distribution", distribution))
    command.extend(("--", *arguments))
    return command


def _run(
    command: Sequence[str],
    *,
    timeout_seconds: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )


def _command_failure(action: str, completed: subprocess.CompletedProcess[str]) -> str:
    detail = (completed.stderr or completed.stdout).strip()
    suffix = f": {detail}" if detail else ""
    return f"{action} failed with exit code {completed.returncode}{suffix}"


def _wsl_path(path: Path, distribution: str | None) -> str:
    completed = _run(
        _wsl_command(distribution, "wslpath", "-a", "-u", path.resolve().as_posix())
    )
    if completed.returncode != 0:
        raise DockerEd2kSourcePublisherError(
            _command_failure(f"WSL path translation for {path}", completed)
        )
    translated = completed.stdout.strip()
    if not translated.startswith("/") or "\n" in translated or "," in translated:
        raise DockerEd2kSourcePublisherError(
            f"WSL returned an unsafe Docker bind path for {path}: {translated!r}"
        )
    return translated


def _parse_hash(value: bytes | str, field_name: str) -> bytes:
    if isinstance(value, bytes):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError(
                f"{field_name} must be exactly 32 hexadecimal characters"
            ) from exc
    else:
        raise TypeError(f"{field_name} must be bytes or hexadecimal text")
    if len(parsed) != 16:
        raise ValueError(f"{field_name} must be exactly 16 bytes")
    return parsed


def _validate_port(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 0xFFFF:
        raise ValueError(f"{field_name} must be an integer in 1..65535")
    return value


def _validate_server_flags(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF_FFFF:
        raise ValueError("server_flags must be an integer in 0..2^32-1")
    return value


def _new_run_id() -> str:
    return uuid.uuid4().hex


def _docker_result(
    distribution: str | None,
    arguments: Sequence[str],
    *,
    timeout_seconds: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    return _run(
        _wsl_command(distribution, "docker", *arguments),
        timeout_seconds=timeout_seconds,
    )


def _preflight_image(distribution: str | None) -> None:
    completed = _docker_result(
        distribution,
        ("image", "inspect", "--format", "{{.Id}}", DOCKER_IMAGE),
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise DockerEd2kSourcePublisherError(
            "Pinned Docker publisher image is absent from the selected WSL Docker engine: "
            f"{DOCKER_IMAGE}. Load it explicitly before the deterministic run; "
            "the harness will not pull it."
        )


def _resource_absent(completed: subprocess.CompletedProcess[str]) -> bool:
    detail = f"{completed.stdout}\n{completed.stderr}".lower()
    return (
        "no such container" in detail
        or "no such network" in detail
        or "route specified was not found" in detail
        or "element not found" in detail
        or "not found" in detail
    )


def _add_windows_host_route(gateway: str) -> None:
    """Routes the fixture's exact HighID address through the managed WSL host."""

    try:
        gateway_ip = ipaddress.ip_address(gateway)
    except ValueError as exc:
        raise DockerEd2kSourcePublisherError(
            f"Docker publisher route gateway is not an IP address: {gateway!r}"
        ) from exc
    if not isinstance(gateway_ip, ipaddress.IPv4Address) or gateway_ip.is_unspecified:
        raise DockerEd2kSourcePublisherError(
            f"Docker publisher route gateway must be a concrete IPv4 address: {gateway!r}"
        )
    completed = _run(
        (
            "route.exe",
            "ADD",
            PUBLISHER_IP,
            "MASK",
            WINDOWS_HOST_ROUTE_NETMASK,
            str(gateway_ip),
            "METRIC",
            "1",
        )
    )
    if completed.returncode != 0:
        raise DockerEd2kSourcePublisherError(
            _command_failure("Docker publisher Windows callback route creation", completed)
        )


def _remove_windows_host_route(gateway: str) -> str | None:
    """Removes the exact callback route owned by this fixture, if still present."""

    completed = _run(
        (
            "route.exe",
            "DELETE",
            PUBLISHER_IP,
            "MASK",
            WINDOWS_HOST_ROUTE_NETMASK,
            gateway,
        )
    )
    if completed.returncode == 0 or _resource_absent(completed):
        return None
    return _command_failure("Docker publisher Windows callback route removal", completed)


def _remove_resources(
    distribution: str | None,
    container_name: str,
    network_name: str,
) -> list[str]:
    errors: list[str] = []
    for action, arguments in (
        (
            "Docker publisher container removal",
            ("container", "rm", "--force", container_name),
        ),
        ("Docker publisher network removal", ("network", "rm", network_name)),
    ):
        completed = _docker_result(distribution, arguments)
        if completed.returncode != 0 and not _resource_absent(completed):
            errors.append(_command_failure(action, completed))
    return errors


@dataclass
class DockerEd2kSourcePublisherHandle:
    """Live publisher ownership plus its independently checked readiness receipt."""

    run_id: str
    container_name: str
    network_name: str
    receipt_path: Path
    receipt: dict[str, Any]
    wsl_distribution: str | None = None
    windows_route_gateway: str | None = None
    windows_route: dict[str, object] | None = None
    _cleaned: bool = field(default=False, init=False, repr=False)

    def cleanup(self) -> None:
        """Removes the owned container first and its isolated network second."""

        if self._cleaned:
            return
        errors = _remove_resources(
            self.wsl_distribution,
            self.container_name,
            self.network_name,
        )
        if self.windows_route_gateway is not None:
            route_error = _remove_windows_host_route(self.windows_route_gateway)
            if route_error is not None:
                errors.append(route_error)
        if errors:
            raise DockerEd2kSourcePublisherError("; ".join(errors))
        self._cleaned = True

    def request_callback(
        self,
        *,
        target_client_id: int,
        target_label: str,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """Issues one callback command through the already authenticated HighID peer."""

        payload = ed2k_wire.encode_callback_request(target_client_id)
        if not target_label:
            raise ValueError("target_label must be non-empty")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        command_id = uuid.uuid4().hex
        control_dir = self.receipt_path.parent / "callback-control"
        request_path = control_dir / f"{command_id}.request.json"
        result_path = control_dir / f"{command_id}.result.json"
        write_json_atomic(
            request_path,
            {
                "schema": CALLBACK_COMMAND_SCHEMA,
                "commandId": command_id,
                "runId": self.run_id,
                "targetClientId": target_client_id,
                "targetLabel": target_label,
                "timeoutSeconds": timeout_seconds,
                "requestPayloadHex": payload.hex().upper(),
            },
        )
        result = _wait_for_receipt(result_path, timeout_seconds + 2.0)
        expected = {
            "schema": CALLBACK_RESULT_SCHEMA,
            "status": "completed",
            "commandId": command_id,
            "runId": self.run_id,
            "targetClientId": target_client_id,
            "targetLabel": target_label,
        }
        for key, value in expected.items():
            if result.get(key) != value:
                raise DockerEd2kSourcePublisherError(
                    f"Docker callback result field {key!r} is not {value!r}: {result!r}"
                )
        if result.get("requestPayloadHex") != payload.hex().upper():
            raise DockerEd2kSourcePublisherError(
                f"Docker callback result changed the request payload: {result!r}"
            )
        return result

    def __enter__(self) -> "DockerEd2kSourcePublisherHandle":
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self.cleanup()


def _wait_for_receipt(path: Path, timeout_seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if path.is_file():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise DockerEd2kSourcePublisherError(
                    f"Docker publisher readiness receipt is unreadable: {path}"
                ) from exc
            if not isinstance(value, dict):
                raise DockerEd2kSourcePublisherError(
                    "Docker publisher readiness receipt must be a JSON object"
                )
            return value
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DockerEd2kSourcePublisherError(
                f"Timed out waiting for Docker publisher readiness receipt: {path}"
            )
        time.sleep(min(0.05, remaining))


def _validate_receipt(
    receipt: dict[str, Any],
    *,
    run_id: str,
    server_host: str,
    server_port: int,
    publisher_port: int,
    server_flags: int,
    user_hash: bytes,
    nickname: str,
    file_hash: bytes,
    file_name: str,
    file_size: int,
) -> None:
    expected = {
        "schema": RECEIPT_SCHEMA,
        "status": "ready",
        "runId": run_id,
        "publisherIp": PUBLISHER_IP,
        "expectedHighId": PUBLISHER_HIGH_ID,
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise DockerEd2kSourcePublisherError(
                f"Docker publisher receipt field {key!r} is not {value!r}"
            )

    login = receipt.get("login")
    if not isinstance(login, dict):
        raise DockerEd2kSourcePublisherError(
            "Docker publisher receipt has no login object"
        )
    if (
        login.get("assigned_id") != PUBLISHER_HIGH_ID
        or login.get("id_kind") != "high-id"
    ):
        raise DockerEd2kSourcePublisherError(
            "Docker publisher was not assigned the IPv4 little-endian HighID "
            f"{PUBLISHER_HIGH_ID} for {PUBLISHER_IP}: {login!r}"
        )

    expected_sections = {
        "server": {"host": server_host, "port": server_port},
        "publisher": {
            "nickname": nickname,
            "tcpPort": publisher_port,
            "userHash": user_hash.hex().upper(),
            "serverFlags": server_flags,
        },
        "file": {
            "hash": file_hash.hex().upper(),
            "name": file_name,
            "size": file_size,
        },
    }
    for key, value in expected_sections.items():
        if receipt.get(key) != value:
            raise DockerEd2kSourcePublisherError(
                f"Docker publisher receipt {key!r} provenance does not match the request"
            )


def start_docker_ed2k_source_publisher(
    *,
    server_host: str,
    server_port: int,
    publisher_port: int,
    server_flags: int,
    user_hash: bytes | str,
    file_hash: bytes | str,
    file_name: str,
    file_size: int,
    run_dir: Path,
    repo_root: Path | None = None,
    nickname: str = DEFAULT_NICKNAME,
    wsl_distribution: str | None = None,
    readiness_timeout_seconds: float = 20.0,
    windows_routable: bool = False,
) -> DockerEd2kSourcePublisherHandle:
    """Starts one pinned publisher and returns ownership after a verified receipt."""

    if not _is_windows_host():
        raise DockerEd2kSourcePublisherError(
            "The Docker eD2K publisher parent must run on Windows through wsl.exe"
        )
    if not server_host.strip():
        raise ValueError("server_host must be non-empty")
    server_port = _validate_port(server_port, "server_port")
    publisher_port = _validate_port(publisher_port, "publisher_port")
    server_flags = _validate_server_flags(server_flags)
    user_hash_bytes = _parse_hash(user_hash, "user_hash")
    file_hash_bytes = _parse_hash(file_hash, "file_hash")
    if not nickname:
        raise ValueError("nickname must be non-empty")
    if not file_name:
        raise ValueError("file_name must be non-empty")
    if (
        isinstance(file_size, bool)
        or not isinstance(file_size, int)
        or not 0 <= file_size <= 0xFFFF_FFFF_FFFF_FFFF
    ):
        raise ValueError("file_size must be an integer in 0..2^64-1")
    if readiness_timeout_seconds <= 0:
        raise ValueError("readiness_timeout_seconds must be positive")

    root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    module_path = root / "emule_test_harness" / "docker_ed2k_source_publisher.py"
    if not module_path.is_file():
        raise DockerEd2kSourcePublisherError(
            f"Persisted Docker publisher module is missing below the repo root: {module_path}"
        )

    output_dir = run_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    _preflight_image(wsl_distribution)
    linux_repo = _wsl_path(root, wsl_distribution)
    linux_run_dir = _wsl_path(output_dir, wsl_distribution)

    run_id = _new_run_id()
    resource_prefix = f"emulebb-ed2k-src-{run_id}"
    network_name = f"{resource_prefix}-net"
    container_name = f"{resource_prefix}-publisher"
    receipt_path = output_dir / f"{run_id}.publisher-ready.json"
    if receipt_path.exists():
        raise DockerEd2kSourcePublisherError(
            f"Refusing to reuse a Docker publisher receipt path: {receipt_path}"
        )

    labels = (
        ("--label", f"{_LABEL_FIXTURE}={_FIXTURE_LABEL_VALUE}"),
        ("--label", f"{_LABEL_RUN_ID}={run_id}"),
    )
    network_arguments = [
        "network",
        "create",
        "--driver",
        "bridge",
        "--subnet",
        BENCHMARK_SUBNET,
    ]
    for option in labels:
        network_arguments.extend(option)
    network_arguments.append(network_name)

    completed = _docker_result(wsl_distribution, network_arguments)
    if completed.returncode != 0:
        raise DockerEd2kSourcePublisherError(
            _command_failure("Docker publisher network creation", completed)
        )

    child_receipt = f"{_CONTAINER_RUN_DIR}/{receipt_path.name}"
    container_arguments = [
        "run",
        "--detach",
        "--pull=never",
        f"--platform={DOCKER_PLATFORM}",
        "--name",
        container_name,
    ]
    for option in labels:
        container_arguments.extend(option)
    container_arguments.extend(
        (
            "--network",
            network_name,
            "--ip",
            PUBLISHER_IP,
            "--mount",
            f"type=bind,src={linux_repo},dst={_CONTAINER_REPO},readonly",
            "--mount",
            f"type=bind,src={linux_run_dir},dst={_CONTAINER_RUN_DIR}",
            "--workdir",
            _CONTAINER_REPO,
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            DOCKER_IMAGE,
            "python",
            "-m",
            "emule_test_harness.docker_ed2k_source_publisher",
            "child",
            "--run-id",
            run_id,
            "--server-host",
            server_host,
            "--server-port",
            str(server_port),
            "--publisher-port",
            str(publisher_port),
            "--server-flags",
            str(server_flags),
            "--user-hash",
            user_hash_bytes.hex().upper(),
            "--nickname",
            nickname,
            "--file-hash",
            file_hash_bytes.hex().upper(),
            "--file-name",
            file_name,
            "--file-size",
            str(file_size),
            "--receipt-path",
            child_receipt,
            "--timeout-seconds",
            str(readiness_timeout_seconds),
        )
    )

    windows_route_gateway: str | None = None
    windows_route: dict[str, object] | None = None

    try:
        if windows_routable:
            _add_windows_host_route(server_host)
            windows_route_gateway = server_host
            windows_route = {
                "destination": f"{PUBLISHER_IP}/32",
                "gateway": server_host,
                "publishedTcpPort": publisher_port,
            }
            image_index = container_arguments.index(DOCKER_IMAGE)
            container_arguments[image_index:image_index] = (
                "--publish",
                f"{publisher_port}:{publisher_port}/tcp",
            )
        completed = _docker_result(
            wsl_distribution,
            container_arguments,
            timeout_seconds=max(30.0, readiness_timeout_seconds),
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            raise DockerEd2kSourcePublisherError(
                _command_failure("Docker publisher container start", completed)
            )
        receipt = _wait_for_receipt(receipt_path, readiness_timeout_seconds)
        _validate_receipt(
            receipt,
            run_id=run_id,
            server_host=server_host,
            server_port=server_port,
            publisher_port=publisher_port,
            server_flags=server_flags,
            user_hash=user_hash_bytes,
            nickname=nickname,
            file_hash=file_hash_bytes,
            file_name=file_name,
            file_size=file_size,
        )
    except Exception as exc:
        cleanup_errors = _remove_resources(
            wsl_distribution,
            container_name,
            network_name,
        )
        if windows_route_gateway is not None:
            route_error = _remove_windows_host_route(windows_route_gateway)
            if route_error is not None:
                cleanup_errors.append(route_error)
        if cleanup_errors:
            raise DockerEd2kSourcePublisherError(
                f"Docker publisher startup failed ({exc}); cleanup also failed: "
                + "; ".join(cleanup_errors)
            ) from exc
        raise

    return DockerEd2kSourcePublisherHandle(
        run_id=run_id,
        container_name=container_name,
        network_name=network_name,
        receipt_path=receipt_path,
        receipt=receipt,
        wsl_distribution=wsl_distribution,
        windows_route_gateway=windows_route_gateway,
        windows_route=windows_route,
    )


def _recv_exact(stream: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise ed2k_wire.Ed2kWireError(
                f"Identity-probe connection closed with {size - len(data)} bytes outstanding"
            )
        data.extend(chunk)
    return bytes(data)


def encode_hello_answer(
    *,
    user_hash: bytes,
    client_id: int,
    tcp_port: int,
) -> bytes:
    """Encodes the plain OP_HELLOANSWER shape used by stock eD2K clients."""

    user_hash = _parse_hash(user_hash, "user_hash")
    _validate_port(tcp_port, "tcp_port")
    if not 0 <= client_id <= 0xFFFF_FFFF:
        raise ValueError("client_id must fit in u32")
    payload = (
        user_hash
        + struct.pack("<IH", client_id, tcp_port)
        + struct.pack("<I", 0)  # tag count
        + struct.pack("<IH", 0, 0)  # server IPv4 and port
    )
    return ed2k_wire.encode_frame(OP_HELLOANSWER, payload)


def _answer_identity_probe(
    stream: socket.socket,
    *,
    user_hash: bytes,
    client_id: int,
    tcp_port: int,
) -> dict[str, object] | None:
    """Answers one complete plain OP_HELLO and returns its peer identity."""

    header = _recv_exact(stream, 6)
    declared = int.from_bytes(header[1:5], "little")
    if declared < 1 or declared > ed2k_wire.MAX_FRAME_BYTES:
        raise ed2k_wire.Ed2kWireError(
            f"Identity-probe frame has invalid declared length {declared}"
        )
    frame = ed2k_wire.decode_frame_bytes(header + _recv_exact(stream, declared - 1))
    if (
        frame.marker != ed2k_wire.PROTO_EDONKEY
        or frame.opcode != OP_HELLO
        or len(frame.payload) < 17
        or frame.payload[0] != 16
    ):
        return None
    peer_user_hash = frame.payload[1:17]
    peer_client_id = int.from_bytes(frame.payload[17:21], "little")
    peer_tcp_port = int.from_bytes(frame.payload[21:23], "little")
    hello_answer_sent = True
    hello_answer_error: str | None = None
    try:
        stream.sendall(
            encode_hello_answer(
                user_hash=user_hash,
                client_id=client_id,
                tcp_port=tcp_port,
            )
        )
    except (OSError, TimeoutError) as exc:
        # The callback proof is the complete peer HELLO. Preserve that causal
        # observation even when the peer closes before consuming our answer.
        hello_answer_sent = False
        hello_answer_error = f"{type(exc).__name__}: {exc}"
    return {
        "userHash": peer_user_hash.hex().upper(),
        "clientId": peer_client_id,
        "tcpPort": peer_tcp_port,
        "payloadLength": len(frame.payload),
        "payloadHex": frame.payload.hex().upper(),
        "helloAnswerSent": hello_answer_sent,
        "helloAnswerError": hello_answer_error,
    }


def answer_identity_probe(
    stream: socket.socket,
    *,
    user_hash: bytes,
    client_id: int,
    tcp_port: int,
) -> bool:
    """Answers one complete plain OP_HELLO and rejects unrelated traffic."""

    return (
        _answer_identity_probe(
            stream,
            user_hash=user_hash,
            client_id=client_id,
            tcp_port=tcp_port,
        )
        is not None
    )


class PlainEd2kIdentityProbeListener:
    """Small multi-connection listener for bare and identity HighID probes."""

    def __init__(self, tcp_port: int, user_hash: bytes) -> None:
        self.tcp_port = _validate_port(tcp_port, "tcp_port")
        self.user_hash = _parse_hash(user_hash, "user_hash")
        self.probe_answers = 0
        self._observations: list[dict[str, object]] = []
        self._connection_attempts: list[dict[str, object]] = []
        self._observation_condition = threading.Condition()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._listener is not None:
            raise RuntimeError("Identity-probe listener is already started")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", self.tcp_port))
            listener.listen(8)
            listener.settimeout(0.2)
        except Exception:
            listener.close()
            raise
        self._listener = listener
        self._thread = threading.Thread(
            target=self._serve,
            name="ed2k-identity-probe",
            daemon=True,
        )
        self._thread.start()

    def _serve(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stop.is_set():
            try:
                stream, peer = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            attempt: dict[str, object] = {
                "peerHost": str(peer[0]),
                "peerPort": int(peer[1]),
                "acceptedAt": time.time(),
            }
            try:
                stream.settimeout(2.0)
                observation = _answer_identity_probe(
                    stream,
                    user_hash=self.user_hash,
                    client_id=PUBLISHER_HIGH_ID,
                    tcp_port=self.tcp_port,
                )
                if observation is not None:
                    attempt.update({"status": "hello", **observation})
                    self.probe_answers += 1
                    observation = {
                        **observation,
                        "peerHost": str(peer[0]),
                        "peerPort": int(peer[1]),
                        "observedAt": time.time(),
                    }
                    with self._observation_condition:
                        self._observations.append(observation)
                        self._observation_condition.notify_all()
                else:
                    attempt["status"] = "unrelated-frame"
            except (OSError, TimeoutError, ed2k_wire.Ed2kWireError) as exc:
                # A normal HighID decision first performs a bare connect and
                # closes it without sending bytes.  That is expected traffic.
                attempt.update(
                    {
                        "status": "error",
                        "errorType": type(exc).__name__,
                        "errorMessage": str(exc) or repr(exc),
                    }
                )
            finally:
                with self._observation_condition:
                    self._connection_attempts.append(attempt)
                    self._observation_condition.notify_all()
                stream.close()

    def observation_count(self) -> int:
        """Returns the number of complete peer HELLO observations."""

        with self._observation_condition:
            return len(self._observations)

    def connection_attempt_count(self) -> int:
        """Returns the number of accepted sockets, including bare HighID probes."""

        with self._observation_condition:
            return len(self._connection_attempts)

    def connection_attempts_after(self, start_index: int) -> list[dict[str, object]]:
        """Returns immutable diagnostic copies of accepted sockets after an index."""

        with self._observation_condition:
            return [dict(value) for value in self._connection_attempts[start_index:]]

    def wait_for_observation_after(
        self,
        start_index: int,
        timeout_seconds: float,
    ) -> dict[str, object]:
        """Waits for the first complete peer HELLO after one callback request."""

        deadline = time.monotonic() + timeout_seconds
        with self._observation_condition:
            while len(self._observations) <= start_index:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Timed out waiting for callback peer HELLO.")
                self._observation_condition.wait(remaining)
            return dict(self._observations[start_index])

    def close(self) -> None:
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None


@dataclass(frozen=True)
class ChildConfiguration:
    run_id: str
    server_host: str
    server_port: int
    publisher_port: int
    server_flags: int
    user_hash: bytes
    nickname: str
    file_hash: bytes
    file_name: str
    file_size: int
    receipt_path: Path
    timeout_seconds: float


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    """Publishes one complete JSON object with a same-directory atomic replace."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as stream:
            temporary_name = stream.name
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def _install_stop_handlers(stop_event: threading.Event) -> dict[int, Any]:
    previous: dict[int, Any] = {}

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, request_stop)
    return previous


def _restore_stop_handlers(previous: dict[int, Any]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _execute_callback_command(
    command: dict[str, Any],
    *,
    config: ChildConfiguration,
    client: ed2k_wire.Ed2kWireClient,
    listener: PlainEd2kIdentityProbeListener,
) -> dict[str, Any]:
    """Executes one immutable parent command and returns causal callback evidence."""

    if command.get("schema") != CALLBACK_COMMAND_SCHEMA:
        raise DockerEd2kSourcePublisherError("Docker callback command schema is invalid")
    command_id = command.get("commandId")
    target_label = command.get("targetLabel")
    target_client_id = command.get("targetClientId")
    timeout_seconds = command.get("timeoutSeconds")
    if not isinstance(command_id, str) or not command_id:
        raise DockerEd2kSourcePublisherError("Docker callback command has no commandId")
    if command.get("runId") != config.run_id:
        raise DockerEd2kSourcePublisherError("Docker callback command runId does not match")
    if not isinstance(target_label, str) or not target_label:
        raise DockerEd2kSourcePublisherError("Docker callback command has no targetLabel")
    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
        raise DockerEd2kSourcePublisherError("Docker callback command timeout is invalid")
    try:
        request_payload = ed2k_wire.encode_callback_request(target_client_id)
    except (TypeError, ValueError) as exc:
        raise DockerEd2kSourcePublisherError("Docker callback command targetClientId is invalid") from exc
    if command.get("requestPayloadHex") != request_payload.hex().upper():
        raise DockerEd2kSourcePublisherError("Docker callback command request payload does not match")

    observation_index = listener.observation_count()
    connection_attempt_index = listener.connection_attempt_count()
    transcript_index = len(client.transcript)
    client.send(ed2k_wire.OP_CALLBACKREQUEST, request_payload)
    try:
        callback_connection = listener.wait_for_observation_after(
            observation_index,
            float(timeout_seconds),
        )
    except TimeoutError as exc:
        attempts = listener.connection_attempts_after(connection_attempt_index)
        raise DockerEd2kSourcePublisherError(
            "Timed out waiting for callback peer HELLO; "
            f"connectionAttempts={json.dumps(attempts, sort_keys=True)}"
        ) from exc
    transcript_delta = list(client.transcript[transcript_index:])
    if len(transcript_delta) != 1:
        raise DockerEd2kSourcePublisherError(
            f"Docker callback command produced {len(transcript_delta)} wire records"
        )
    return {
        "schema": CALLBACK_RESULT_SCHEMA,
        "status": "completed",
        "commandId": command_id,
        "runId": config.run_id,
        "targetClientId": target_client_id,
        "targetLabel": target_label,
        "requestOpcode": ed2k_wire.OP_CALLBACKREQUEST,
        "requestPayloadHex": request_payload.hex().upper(),
        "requestTranscript": transcript_delta[0],
        "callbackConnection": callback_connection,
    }


def _process_callback_commands(
    config: ChildConfiguration,
    *,
    client: ed2k_wire.Ed2kWireClient,
    listener: PlainEd2kIdentityProbeListener,
) -> None:
    """Processes every new command exactly once, retaining request and result files."""

    control_dir = config.receipt_path.parent / "callback-control"
    control_dir.mkdir(parents=True, exist_ok=True)
    for request_path in sorted(control_dir.glob("*.request.json")):
        result_path = request_path.with_name(
            request_path.name.removesuffix(".request.json") + ".result.json"
        )
        if result_path.exists():
            continue
        try:
            command = json.loads(request_path.read_text(encoding="utf-8"))
            if not isinstance(command, dict):
                raise DockerEd2kSourcePublisherError(
                    "Docker callback command must be a JSON object"
                )
            result = _execute_callback_command(
                command,
                config=config,
                client=client,
                listener=listener,
            )
        except Exception as exc:
            result = {
                "schema": CALLBACK_RESULT_SCHEMA,
                "status": "failed",
                "commandId": request_path.name.removesuffix(".request.json"),
                "runId": config.run_id,
                "failure": {"type": type(exc).__name__, "message": str(exc)},
            }
        write_json_atomic(result_path, result)


def run_child(
    config: ChildConfiguration,
    *,
    stop_event: threading.Event | None = None,
    listener_factory: Callable[[int, bytes], PlainEd2kIdentityProbeListener]
    | None = None,
    client_factory: Callable[[str, int, float], ed2k_wire.Ed2kWireClient] | None = None,
) -> dict[str, Any]:
    """Runs the persisted container child until a termination signal is received."""

    event = stop_event or threading.Event()
    make_listener = listener_factory or PlainEd2kIdentityProbeListener
    make_client = client_factory or ed2k_wire.Ed2kWireClient
    listener = make_listener(config.publisher_port, config.user_hash)
    client = make_client(config.server_host, config.server_port, config.timeout_seconds)
    handlers = _install_stop_handlers(event)
    try:
        # The server's login path performs the callback synchronously, so the
        # identity endpoint must already be listening before LOGINREQUEST.
        listener.start()
        client.connect()
        login = client.login(
            user_hash=config.user_hash,
            tcp_port=config.publisher_port,
            nickname=config.nickname,
            server_flags=config.server_flags,
        )
        if (
            login.get("assigned_id") != PUBLISHER_HIGH_ID
            or login.get("id_kind") != "high-id"
        ):
            raise DockerEd2kSourcePublisherError(
                "eD2K server did not assign the publisher's IPv4 little-endian HighID: "
                f"expected {PUBLISHER_HIGH_ID}, got {login!r}"
            )
        client.offer_file(
            file_hash=config.file_hash,
            name=config.file_name,
            size=config.file_size,
        )
        receipt: dict[str, Any] = {
            "schema": RECEIPT_SCHEMA,
            "status": "ready",
            "runId": config.run_id,
            "publisherIp": PUBLISHER_IP,
            "expectedHighId": PUBLISHER_HIGH_ID,
            "server": {"host": config.server_host, "port": config.server_port},
            "publisher": {
                "nickname": config.nickname,
                "tcpPort": config.publisher_port,
                "userHash": config.user_hash.hex().upper(),
                "serverFlags": config.server_flags,
            },
            "file": {
                "hash": config.file_hash.hex().upper(),
                "name": config.file_name,
                "size": config.file_size,
            },
            "login": login,
            "identityProbeAnswers": listener.probe_answers,
            "transcript": list(client.transcript),
        }
        write_json_atomic(config.receipt_path, receipt)
        while not event.wait(0.05):
            _process_callback_commands(config, client=client, listener=listener)
        return receipt
    finally:
        client.close()
        listener.close()
        _restore_stop_handlers(handlers)


def _child_parser(subparsers: Any) -> None:
    child = subparsers.add_parser("child")
    child.add_argument("--run-id", required=True)
    child.add_argument("--server-host", required=True)
    child.add_argument("--server-port", required=True, type=int)
    child.add_argument("--publisher-port", required=True, type=int)
    child.add_argument("--server-flags", required=True, type=int)
    child.add_argument("--user-hash", required=True)
    child.add_argument("--nickname", required=True)
    child.add_argument("--file-hash", required=True)
    child.add_argument("--file-name", required=True)
    child.add_argument("--file-size", required=True, type=int)
    child.add_argument("--receipt-path", required=True, type=Path)
    child.add_argument("--timeout-seconds", required=True, type=float)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    _child_parser(subparsers)
    args = parser.parse_args(argv)
    if args.mode != "child":
        parser.error("only the persisted child mode is supported")
    config = ChildConfiguration(
        run_id=args.run_id,
        server_host=args.server_host,
        server_port=_validate_port(args.server_port, "server_port"),
        publisher_port=_validate_port(args.publisher_port, "publisher_port"),
        server_flags=_validate_server_flags(args.server_flags),
        user_hash=_parse_hash(args.user_hash, "user_hash"),
        nickname=args.nickname,
        file_hash=_parse_hash(args.file_hash, "file_hash"),
        file_name=args.file_name,
        file_size=args.file_size,
        receipt_path=args.receipt_path,
        timeout_seconds=args.timeout_seconds,
    )
    if not config.nickname:
        raise ValueError("nickname must be non-empty")
    if not config.file_name:
        raise ValueError("file_name must be non-empty")
    if not 0 <= config.file_size <= 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("file_size must be in 0..2^64-1")
    if config.timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    run_child(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
