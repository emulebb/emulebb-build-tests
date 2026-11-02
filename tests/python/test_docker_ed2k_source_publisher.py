from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path

import pytest

from emule_test_harness import docker_ed2k_source_publisher as publisher
from emule_test_harness import ed2k_wire


USER_HASH = bytes.fromhex("32547698BADCFE1021436587A9CBED0F")
FILE_HASH = bytes.fromhex("22334455667788990011AABBCCDDEEFF")
FILE_NAME = "deterministic-server-source.bin"
FILE_SIZE = 67_890
SERVER_HOST = "172.17.142.32"
SERVER_PORT = 46_611
PUBLISHER_PORT = 20_118
RUN_ID = "0123456789abcdef0123456789abcdef"


def completed(
    command: list[str],
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def create_repo_fixture(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    module = repo / "emule_test_harness" / "docker_ed2k_source_publisher.py"
    module.parent.mkdir(parents=True)
    module.write_text("# persisted fixture module\n", encoding="utf-8")
    return repo


def ready_receipt(
    *,
    assigned_id: int = publisher.PUBLISHER_HIGH_ID,
    server_flags: int = publisher.PLAIN_SERVER_FLAGS,
) -> dict[str, object]:
    return {
        "schema": publisher.RECEIPT_SCHEMA,
        "status": "ready",
        "runId": RUN_ID,
        "publisherIp": publisher.PUBLISHER_IP,
        "expectedHighId": publisher.PUBLISHER_HIGH_ID,
        "server": {"host": SERVER_HOST, "port": SERVER_PORT},
        "publisher": {
            "nickname": publisher.DEFAULT_NICKNAME,
            "tcpPort": PUBLISHER_PORT,
            "userHash": USER_HASH.hex().upper(),
            "serverFlags": server_flags,
        },
        "file": {
            "hash": FILE_HASH.hex().upper(),
            "name": FILE_NAME,
            "size": FILE_SIZE,
        },
        "login": {
            "assigned_id": assigned_id,
            "id_kind": "high-id"
            if assigned_id == publisher.PUBLISHER_HIGH_ID
            else "low-id",
            "welcome_opcodes": [0x40, 0x34],
        },
        "identityProbeAnswers": 1,
        "transcript": [],
    }


@pytest.mark.unit
def test_constants_pin_isolated_amd64_fixture_identity() -> None:
    assert publisher.DOCKER_IMAGE == (
        "python@sha256:7712cfd23e0501f5cb58faa5e6e0d515c9939bdbce866921799b31e696a1d13c"
    )
    assert publisher.DOCKER_PLATFORM == "linux/amd64"
    assert publisher.BENCHMARK_SUBNET == "198.18.240.0/28"
    assert publisher.PUBLISHER_IP == "198.18.240.2"
    assert publisher.PUBLISHER_HIGH_ID == 0x02F012C6
    assert publisher.PLAIN_SERVER_FLAGS == 0x0119
    assert publisher.OBFUSCATED_SOURCE_SERVER_FLAGS == 0x0319


class FakeStream:
    def __init__(self, incoming: bytes) -> None:
        self.incoming = bytearray(incoming)
        self.sent = bytearray()

    def recv(self, size: int) -> bytes:
        if not self.incoming:
            return b""
        value = bytes(self.incoming[:size])
        del self.incoming[:size]
        return value

    def sendall(self, value: bytes) -> None:
        self.sent.extend(value)


@pytest.mark.unit
def test_identity_probe_answers_plain_hello_with_exact_publisher_hash() -> None:
    probe_hash = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    hello_payload = (
        b"\x10"
        + probe_hash
        + (0).to_bytes(4, "little")
        + (4661).to_bytes(2, "little")
        + (0).to_bytes(4, "little")
    )
    stream = FakeStream(ed2k_wire.encode_frame(publisher.OP_HELLO, hello_payload))

    answered = publisher.answer_identity_probe(
        stream,  # type: ignore[arg-type]
        user_hash=USER_HASH,
        client_id=publisher.PUBLISHER_HIGH_ID,
        tcp_port=PUBLISHER_PORT,
    )

    assert answered is True
    frame = ed2k_wire.decode_frame_bytes(bytes(stream.sent))
    assert frame.marker == ed2k_wire.PROTO_EDONKEY
    assert frame.opcode == publisher.OP_HELLOANSWER
    assert frame.payload[:16] == USER_HASH
    assert int.from_bytes(frame.payload[16:20], "little") == publisher.PUBLISHER_HIGH_ID
    assert int.from_bytes(frame.payload[20:22], "little") == PUBLISHER_PORT
    assert frame.payload[22:] == b"\x00" * 10


@pytest.mark.unit
def test_identity_probe_does_not_answer_unrelated_frame() -> None:
    stream = FakeStream(ed2k_wire.encode_frame(ed2k_wire.OP_SERVERSTATUS, b"\x00" * 8))

    answered = publisher.answer_identity_probe(
        stream,  # type: ignore[arg-type]
        user_hash=USER_HASH,
        client_id=publisher.PUBLISHER_HIGH_ID,
        tcp_port=PUBLISHER_PORT,
    )

    assert answered is False
    assert stream.sent == b""


@pytest.mark.unit
def test_child_listens_before_login_offers_file_and_publishes_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[object] = []

    class FakeListener:
        probe_answers = 2

        def __init__(self, port: int, user_hash: bytes) -> None:
            assert (port, user_hash) == (PUBLISHER_PORT, USER_HASH)

        def start(self) -> None:
            events.append("listener.start")

        def close(self) -> None:
            events.append("listener.close")

    class FakeClient:
        transcript = [{"direction": "send", "opcode": ed2k_wire.OP_LOGINREQUEST}]

        def __init__(self, host: str, port: int, timeout: float) -> None:
            assert (host, port, timeout) == (SERVER_HOST, SERVER_PORT, 3.0)

        def connect(self) -> None:
            events.append("client.connect")

        def login(self, **kwargs: object) -> dict[str, object]:
            events.append(("client.login", kwargs))
            return {
                "assigned_id": publisher.PUBLISHER_HIGH_ID,
                "id_kind": "high-id",
                "welcome_opcodes": [0x40, 0x34],
            }

        def offer_file(self, **kwargs: object) -> None:
            events.append(("client.offer_file", kwargs))

        def close(self) -> None:
            events.append("client.close")

    monkeypatch.setattr(publisher, "_install_stop_handlers", lambda _event: {})
    monkeypatch.setattr(publisher, "_restore_stop_handlers", lambda _handlers: None)
    receipt_path = tmp_path / "ready.json"
    config = publisher.ChildConfiguration(
        run_id=RUN_ID,
        server_host=SERVER_HOST,
        server_port=SERVER_PORT,
        publisher_port=PUBLISHER_PORT,
        server_flags=publisher.OBFUSCATED_SOURCE_SERVER_FLAGS,
        user_hash=USER_HASH,
        nickname=publisher.DEFAULT_NICKNAME,
        file_hash=FILE_HASH,
        file_name=FILE_NAME,
        file_size=FILE_SIZE,
        receipt_path=receipt_path,
        timeout_seconds=3.0,
    )
    stop = threading.Event()
    stop.set()

    receipt = publisher.run_child(
        config,
        stop_event=stop,
        listener_factory=FakeListener,  # type: ignore[arg-type]
        client_factory=FakeClient,  # type: ignore[arg-type]
    )

    assert events[:3] == [
        "listener.start",
        "client.connect",
        (
            "client.login",
            {
                "user_hash": USER_HASH,
                "tcp_port": PUBLISHER_PORT,
                "nickname": publisher.DEFAULT_NICKNAME,
                "server_flags": publisher.OBFUSCATED_SOURCE_SERVER_FLAGS,
            },
        ),
    ]
    assert events[3] == (
        "client.offer_file",
        {"file_hash": FILE_HASH, "name": FILE_NAME, "size": FILE_SIZE},
    )
    assert events[-2:] == ["client.close", "listener.close"]
    assert receipt["login"] == {
        "assigned_id": publisher.PUBLISHER_HIGH_ID,
        "id_kind": "high-id",
        "welcome_opcodes": [0x40, 0x34],
    }
    assert receipt["identityProbeAnswers"] == 2
    assert receipt["publisher"]["serverFlags"] == publisher.OBFUSCATED_SOURCE_SERVER_FLAGS
    assert json.loads(receipt_path.read_text(encoding="utf-8")) == receipt
    assert list(tmp_path.glob("*.tmp")) == []


@pytest.mark.unit
def test_child_rejects_noncanonical_assigned_id_before_offer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []

    class FakeListener:
        probe_answers = 0

        def __init__(self, _port: int, _user_hash: bytes) -> None:
            pass

        def start(self) -> None:
            events.append("listener.start")

        def close(self) -> None:
            events.append("listener.close")

    class FakeClient:
        transcript: list[dict[str, object]] = []

        def __init__(self, _host: str, _port: int, _timeout: float) -> None:
            pass

        def connect(self) -> None:
            events.append("client.connect")

        def login(self, **_kwargs: object) -> dict[str, object]:
            return {"assigned_id": 1, "id_kind": "low-id"}

        def offer_file(self, **_kwargs: object) -> None:
            events.append("client.offer_file")

        def close(self) -> None:
            events.append("client.close")

    monkeypatch.setattr(publisher, "_install_stop_handlers", lambda _event: {})
    monkeypatch.setattr(publisher, "_restore_stop_handlers", lambda _handlers: None)
    config = publisher.ChildConfiguration(
        run_id=RUN_ID,
        server_host=SERVER_HOST,
        server_port=SERVER_PORT,
        publisher_port=PUBLISHER_PORT,
        server_flags=publisher.PLAIN_SERVER_FLAGS,
        user_hash=USER_HASH,
        nickname=publisher.DEFAULT_NICKNAME,
        file_hash=FILE_HASH,
        file_name=FILE_NAME,
        file_size=FILE_SIZE,
        receipt_path=tmp_path / "ready.json",
        timeout_seconds=3.0,
    )

    with pytest.raises(
        publisher.DockerEd2kSourcePublisherError, match="did not assign"
    ):
        publisher.run_child(
            config,
            stop_event=threading.Event(),
            listener_factory=FakeListener,  # type: ignore[arg-type]
            client_factory=FakeClient,  # type: ignore[arg-type]
        )

    assert "client.offer_file" not in events
    assert events[-2:] == ["client.close", "listener.close"]
    assert not config.receipt_path.exists()


@pytest.mark.unit
def test_atomic_receipt_replace_uses_same_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "run" / "ready.json"
    replacements: list[tuple[Path, Path]] = []
    actual_replace = publisher.os.replace

    def recording_replace(source: str | Path, destination: str | Path) -> None:
        replacements.append((Path(source), Path(destination)))
        actual_replace(source, destination)

    monkeypatch.setattr(publisher.os, "replace", recording_replace)

    publisher.write_json_atomic(target, {"status": "ready"})

    assert json.loads(target.read_text(encoding="utf-8")) == {"status": "ready"}
    assert len(replacements) == 1
    assert replacements[0][0].parent == target.parent
    assert replacements[0][1] == target


class FakeDockerRun:
    def __init__(
        self, *, run_dir: Path, receipt_id: int = publisher.PUBLISHER_HIGH_ID
    ) -> None:
        self.run_dir = run_dir
        self.receipt_id = receipt_id
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(
        self, command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((command, kwargs))
        assert isinstance(command, list)
        assert "shell" not in kwargs
        if "wslpath" in command:
            suffix = "repo" if command[-1].endswith("repo") else "run"
            return completed(command, stdout=f"/mnt/c/{suffix}\n")
        if command[-6:-4] == ["image", "inspect"] or (
            "image" in command and "inspect" in command
        ):
            return completed(command, stdout="sha256:local-image\n")
        if "network" in command and "create" in command:
            return completed(command, stdout="network-id\n")
        if "run" in command:
            (self.run_dir / f"{RUN_ID}.publisher-ready.json").write_text(
                json.dumps(ready_receipt(assigned_id=self.receipt_id)),
                encoding="utf-8",
            )
            return completed(command, stdout="container-id\n")
        if "container" in command and "rm" in command:
            return completed(command, stdout="removed-container\n")
        if "network" in command and "rm" in command:
            return completed(command, stdout="removed-network\n")
        raise AssertionError(f"unexpected subprocess command: {command!r}")


def start_with_fake_docker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    receipt_id: int = publisher.PUBLISHER_HIGH_ID,
) -> tuple[publisher.DockerEd2kSourcePublisherHandle, FakeDockerRun]:
    repo = create_repo_fixture(tmp_path)
    run_dir = tmp_path / "run"
    fake = FakeDockerRun(run_dir=run_dir, receipt_id=receipt_id)
    monkeypatch.setattr(publisher, "_is_windows_host", lambda: True)
    monkeypatch.setattr(publisher, "_new_run_id", lambda: RUN_ID)
    monkeypatch.setattr(publisher.subprocess, "run", fake)
    handle = publisher.start_docker_ed2k_source_publisher(
        server_host=SERVER_HOST,
        server_port=SERVER_PORT,
        publisher_port=PUBLISHER_PORT,
        server_flags=publisher.PLAIN_SERVER_FLAGS,
        user_hash=USER_HASH,
        file_hash=FILE_HASH,
        file_name=FILE_NAME,
        file_size=FILE_SIZE,
        run_dir=run_dir,
        repo_root=repo,
        wsl_distribution="Ubuntu-Test",
        readiness_timeout_seconds=3.0,
    )
    return handle, fake


@pytest.mark.unit
def test_parent_uses_only_wsl_argv_and_pinned_bounded_docker_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    handle, fake = start_with_fake_docker(monkeypatch, tmp_path)

    commands = [row[0] for row in fake.calls]
    assert len(commands) == 5
    assert all(
        command[:3] == ["wsl.exe", "--distribution", "Ubuntu-Test"]
        for command in commands
    )
    assert all(command[3] == "--" for command in commands)
    assert all(row[1]["check"] is False for row in fake.calls)
    assert all(row[1]["capture_output"] is True for row in fake.calls)
    assert all(row[1]["text"] is True for row in fake.calls)
    assert not any("sh" in command or "-c" in command for command in commands)

    image_preflight = commands[0]
    assert image_preflight[-5:] == [
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        publisher.DOCKER_IMAGE,
    ]
    network = commands[3]
    assert ["--driver", "bridge"] == network[
        network.index("--driver") : network.index("--driver") + 2
    ]
    assert network[network.index("--subnet") + 1] == "198.18.240.0/28"
    assert "org.emulebb.harness.fixture=docker-ed2k-source-publisher" in network
    assert f"org.emulebb.harness.run-id={RUN_ID}" in network

    container = commands[4]
    assert "--pull=never" in container
    assert "--platform=linux/amd64" in container
    assert container[container.index("--ip") + 1] == "198.18.240.2"
    assert "type=bind,src=/mnt/c/repo,dst=/workspace,readonly" in container
    assert "type=bind,src=/mnt/c/run,dst=/run" in container
    assert container[container.index(publisher.DOCKER_IMAGE) :] == [
        publisher.DOCKER_IMAGE,
        "python",
        "-m",
        "emule_test_harness.docker_ed2k_source_publisher",
        "child",
        "--run-id",
        RUN_ID,
        "--server-host",
        SERVER_HOST,
        "--server-port",
        str(SERVER_PORT),
        "--publisher-port",
        str(PUBLISHER_PORT),
        "--server-flags",
        str(publisher.PLAIN_SERVER_FLAGS),
        "--user-hash",
        USER_HASH.hex().upper(),
        "--nickname",
        publisher.DEFAULT_NICKNAME,
        "--file-hash",
        FILE_HASH.hex().upper(),
        "--file-name",
        FILE_NAME,
        "--file-size",
        str(FILE_SIZE),
        "--receipt-path",
        f"/run/{RUN_ID}.publisher-ready.json",
        "--timeout-seconds",
        "3.0",
    ]
    assert handle.receipt["login"] == {
        "assigned_id": publisher.PUBLISHER_HIGH_ID,
        "id_kind": "high-id",
        "welcome_opcodes": [0x40, 0x34],
    }

    handle.cleanup()
    cleanup_commands = [row[0] for row in fake.calls[-2:]]
    assert cleanup_commands[0][-4:] == [
        "container",
        "rm",
        "--force",
        handle.container_name,
    ]
    assert cleanup_commands[1][-3:] == ["network", "rm", handle.network_name]
    count = len(fake.calls)
    handle.cleanup()
    assert len(fake.calls) == count


@pytest.mark.unit
def test_missing_pinned_image_fails_before_network_without_pull(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = create_repo_fixture(tmp_path)
    calls: list[list[str]] = []

    def absent(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return completed(command, returncode=1, stderr="No such image")

    monkeypatch.setattr(publisher, "_is_windows_host", lambda: True)
    monkeypatch.setattr(publisher.subprocess, "run", absent)

    with pytest.raises(
        publisher.DockerEd2kSourcePublisherError,
        match="image is absent.*will not pull",
    ):
        publisher.start_docker_ed2k_source_publisher(
            server_host=SERVER_HOST,
            server_port=SERVER_PORT,
            publisher_port=PUBLISHER_PORT,
            server_flags=publisher.PLAIN_SERVER_FLAGS,
            user_hash=USER_HASH,
            file_hash=FILE_HASH,
            file_name=FILE_NAME,
            file_size=FILE_SIZE,
            run_dir=tmp_path / "run",
            repo_root=repo,
        )

    assert len(calls) == 1
    assert calls[0][-5:] == [
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        publisher.DOCKER_IMAGE,
    ]
    assert "pull" not in calls[0]


@pytest.mark.unit
def test_wrong_assigned_id_rejects_receipt_and_cleans_container_then_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = create_repo_fixture(tmp_path)
    run_dir = tmp_path / "run"
    fake = FakeDockerRun(run_dir=run_dir, receipt_id=7)
    monkeypatch.setattr(publisher, "_is_windows_host", lambda: True)
    monkeypatch.setattr(publisher, "_new_run_id", lambda: RUN_ID)
    monkeypatch.setattr(publisher.subprocess, "run", fake)

    with pytest.raises(
        publisher.DockerEd2kSourcePublisherError,
        match="IPv4 little-endian HighID",
    ):
        publisher.start_docker_ed2k_source_publisher(
            server_host=SERVER_HOST,
            server_port=SERVER_PORT,
            publisher_port=PUBLISHER_PORT,
            server_flags=publisher.PLAIN_SERVER_FLAGS,
            user_hash=USER_HASH,
            file_hash=FILE_HASH,
            file_name=FILE_NAME,
            file_size=FILE_SIZE,
            run_dir=run_dir,
            repo_root=repo,
            readiness_timeout_seconds=3.0,
        )

    assert fake.calls[-2][0][-4:-2] == ["container", "rm"]
    assert fake.calls[-1][0][-3:-1] == ["network", "rm"]


@pytest.mark.unit
def test_cleanup_attempts_network_after_container_removal_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[list[str]] = []

    def failing_cleanup(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "container" in command:
            return completed(command, returncode=1, stderr="daemon unavailable")
        return completed(command, stdout="removed-network")

    monkeypatch.setattr(publisher.subprocess, "run", failing_cleanup)
    handle = publisher.DockerEd2kSourcePublisherHandle(
        run_id=RUN_ID,
        container_name="publisher-container",
        network_name="publisher-network",
        receipt_path=tmp_path / "ready.json",
        receipt=ready_receipt(),
    )

    with pytest.raises(
        publisher.DockerEd2kSourcePublisherError,
        match="container removal",
    ):
        handle.cleanup()

    assert calls[0][-4:] == ["container", "rm", "--force", "publisher-container"]
    assert calls[1][-3:] == ["network", "rm", "publisher-network"]


@pytest.mark.unit
def test_child_cli_builds_configuration_for_persisted_module(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[publisher.ChildConfiguration] = []
    monkeypatch.setattr(
        publisher, "run_child", lambda config: observed.append(config) or {}
    )
    receipt = tmp_path / "ready.json"

    result = publisher.main(
        [
            "child",
            "--run-id",
            RUN_ID,
            "--server-host",
            SERVER_HOST,
            "--server-port",
            str(SERVER_PORT),
            "--publisher-port",
            str(PUBLISHER_PORT),
            "--server-flags",
            str(publisher.PLAIN_SERVER_FLAGS),
            "--user-hash",
            USER_HASH.hex(),
            "--nickname",
            publisher.DEFAULT_NICKNAME,
            "--file-hash",
            FILE_HASH.hex(),
            "--file-name",
            FILE_NAME,
            "--file-size",
            str(FILE_SIZE),
            "--receipt-path",
            str(receipt),
            "--timeout-seconds",
            "4.5",
        ]
    )

    assert result == 0
    assert observed == [
        publisher.ChildConfiguration(
            run_id=RUN_ID,
            server_host=SERVER_HOST,
            server_port=SERVER_PORT,
            publisher_port=PUBLISHER_PORT,
            server_flags=publisher.PLAIN_SERVER_FLAGS,
            user_hash=USER_HASH,
            nickname=publisher.DEFAULT_NICKNAME,
            file_hash=FILE_HASH,
            file_name=FILE_NAME,
            file_size=FILE_SIZE,
            receipt_path=receipt,
            timeout_seconds=4.5,
        )
    ]
