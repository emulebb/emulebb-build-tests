from __future__ import annotations

import json
import signal
import subprocess
from pathlib import Path
from typing import Sequence

import pytest

from emule_test_harness.native_windows_network import (
    CaptureFrameStats,
    CaptureInterfaceHints,
    CaptureSizeLimitReachedError,
    ManagedDumpcapCapture,
    UpnpMappingAuditError,
    WindowsInboundBlockRules,
    discover_capture_interfaces,
    make_tshark_frame_inspection_hook,
    make_tshark_protocol_summary_hook,
    parse_dumpcap_interfaces,
    resolve_capture_interface,
    resolve_windows_adapter_hints,
    validate_capture,
    verify_upnp_port_mappings,
)


class FakeCaptureProcess:
    def __init__(self) -> None:
        self.returncode: int | None = None
        self.signals: list[int] = []
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def send_signal(self, value: int) -> None:
        self.signals.append(value)
        self.returncode = 0

    def wait(self, timeout: float) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired("dumpcap", timeout)
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 1

    def kill(self) -> None:
        self.killed = True
        self.returncode = 1


class FakeUpnpClient:
    def __init__(self, mappings: dict[tuple[int, str], object], *, discovered_count: int = 1) -> None:
        self.mappings = mappings
        self.discovered_count = discovered_count
        self.discoverdelay = 0
        self.multicastif = ""
        self.selected = False
        self.queries: list[tuple[int, str]] = []

    def discover(self) -> int:
        return self.discovered_count

    def selectigd(self) -> None:
        self.selected = True

    def getspecificportmapping(self, external_port: int, protocol: str) -> object:
        self.queries.append((external_port, protocol))
        return self.mappings.get((external_port, protocol))


def completed(command: Sequence[str], *, stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(tuple(command), 0, stdout=stdout, stderr="")


def test_discovers_and_resolves_dumpcap_interface_from_route_hints() -> None:
    inventory = """
1. \\Device\\NPF_{11111111-1111-1111-1111-111111111111} (OpenVPN Data Channel Offload)
2. \\Device\\NPF_{22222222-2222-2222-2222-222222222222} (Intel(R) Ethernet Adapter)
"""
    commands: list[tuple[str, ...]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(tuple(command))
        return completed(command, stdout=inventory)

    interfaces = discover_capture_interfaces(dumpcap_path="C:/Tools/dumpcap.exe", run_command=runner)
    selected = resolve_capture_interface(
        interfaces,
        CaptureInterfaceHints(guid="22222222-2222-2222-2222-222222222222", alias="Ethernet"),
    )

    assert commands == [("C:/Tools/dumpcap.exe", "-D")]
    assert selected.index == 2
    assert selected.description == "Intel(R) Ethernet Adapter"


def test_resolves_windows_adapter_hints_from_local_address() -> None:
    commands: list[tuple[str, ...]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(tuple(command))
        return completed(
            command,
            stdout=json.dumps(
                {
                    "guid": "22222222-2222-2222-2222-222222222222",
                    "alias": "Ethernet",
                    "description": "Intel(R) Ethernet Adapter",
                }
            ),
        )

    hints = resolve_windows_adapter_hints(
        "192.0.2.18",
        powershell_path="pwsh.exe",
        run_command=runner,
    )

    assert commands[0][:5] == (
        "pwsh.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
    )
    assert "192.0.2.18" in commands[0][5]
    assert hints == CaptureInterfaceHints(
        guid="22222222-2222-2222-2222-222222222222",
        alias="Ethernet",
        description="Intel(R) Ethernet Adapter",
    )


def test_windows_adapter_resolution_rejects_invalid_local_address_without_command() -> None:
    called = False

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        return completed(command)

    with pytest.raises(ValueError, match="X_LOCAL_IP"):
        resolve_windows_adapter_hints("192.0.2.18'; Remove-Item", run_command=runner)

    assert not called


def test_windows_adapter_resolution_requires_complete_adapter_identity() -> None:
    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return completed(command, stdout='{"guid":"abc","alias":"Ethernet"}')

    with pytest.raises(RuntimeError, match="omitted description"):
        resolve_windows_adapter_hints("192.0.2.18", run_command=runner)


def test_interface_resolution_rejects_ambiguous_alias() -> None:
    interfaces = parse_dumpcap_interfaces("1. eth0 (Ethernet A)\n2. eth1 (Ethernet B)\n")

    with pytest.raises(ValueError, match="ambiguous"):
        resolve_capture_interface(interfaces, CaptureInterfaceHints(alias="Ethernet"))


def test_interface_resolution_accepts_exact_npcap_device() -> None:
    interfaces = parse_dumpcap_interfaces(
        r"1. \Device\NPF_{22222222-2222-2222-2222-222222222222} (Ethernet)"
    )

    selected = resolve_capture_interface(
        interfaces,
        CaptureInterfaceHints(device=r"\Device\NPF_{22222222-2222-2222-2222-222222222222}"),
    )

    assert selected.index == 1


def test_managed_capture_starts_stops_validates_and_summarizes(tmp_path: Path) -> None:
    capture_path = tmp_path / "case.pcapng"
    process = FakeCaptureProcess()
    launched: list[tuple[str, ...]] = []
    summarized: list[Path] = []

    def factory(command: Sequence[str]) -> FakeCaptureProcess:
        launched.append(tuple(command))
        capture_path.write_bytes(b"x" * 64)
        return process

    def summary(path: Path) -> str:
        summarized.append(path)
        return "protocol hierarchy"

    capture = ManagedDumpcapCapture(
        output_path=capture_path,
        capture_filter="tcp port 4662 or udp port 4672",
        interface=r"\Device\NPF_{22222222-2222-2222-2222-222222222222}",
        dumpcap_path="dumpcap.exe",
        maximum_size_kib=8192,
        process_factory=factory,
        inspection_hook=lambda path: CaptureFrameStats(
            frame_count=3, relevant_frame_count=2, captured_byte_count=144
        ),
        summary_hook=summary,
    )

    with capture:
        assert capture.is_running

    result = capture.stop()

    assert launched[0][:4] == (
        "dumpcap.exe",
        "-q",
        "-i",
        r"\Device\NPF_{22222222-2222-2222-2222-222222222222}",
    )
    assert launched[0][-2:] == ("-a", "filesize:8192")
    assert process.signals == [getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM)]
    assert not process.terminated
    assert result.byte_count == 64
    assert result.frame_count == 3
    assert result.relevant_frame_count == 2
    assert result.captured_byte_count == 144
    assert result.sanitized_counts() == {
        "fileByteCount": 64,
        "frameCount": 3,
        "relevantFrameCount": 2,
        "capturedByteCount": 144,
        "sizeLimitReached": False,
    }
    assert result.tshark_summary == "protocol hierarchy"
    assert summarized == [capture_path.resolve()]


def test_managed_capture_stops_child_when_body_raises(tmp_path: Path) -> None:
    capture_path = tmp_path / "case.pcapng"
    process = FakeCaptureProcess()

    def factory(command: Sequence[str]) -> FakeCaptureProcess:
        capture_path.write_bytes(b"x" * 28)
        return process

    with pytest.raises(RuntimeError, match="campaign failed"):
        with ManagedDumpcapCapture(
            output_path=capture_path,
            capture_filter="udp",
            interface="2",
            process_factory=factory,
            inspection_hook=lambda path: CaptureFrameStats(
                frame_count=1, relevant_frame_count=1, captured_byte_count=60
            ),
        ):
            raise RuntimeError("campaign failed")

    assert process.returncode == 0


def test_managed_capture_cleans_up_after_readiness_timeout(tmp_path: Path) -> None:
    process = FakeCaptureProcess()
    ticks = iter((0.0, 0.0, 0.5, 1.1))

    with pytest.raises(TimeoutError, match="did not become ready"):
        ManagedDumpcapCapture(
            output_path=tmp_path / "never-created.pcapng",
            capture_filter="udp",
            interface="2",
            readiness_timeout_seconds=1.0,
            process_factory=lambda command: process,
            monotonic=lambda: next(ticks),
            sleep=lambda seconds: None,
        ).start()

    assert process.returncode == 0


def test_capture_validation_rejects_missing_and_empty_files(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="was not created"):
        validate_capture(tmp_path / "missing.pcapng")

    empty = tmp_path / "empty.pcapng"
    empty.write_bytes(b"")
    with pytest.raises(RuntimeError, match="too small"):
        validate_capture(empty)


def test_tshark_summary_hook_uses_injected_command(tmp_path: Path) -> None:
    commands: list[tuple[str, ...]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(tuple(command))
        return completed(command, stdout="protocol hierarchy")

    capture_path = tmp_path / "capture.pcapng"
    hook = make_tshark_protocol_summary_hook(tshark_path="tshark.exe", run_command=runner)

    assert hook(capture_path) == "protocol hierarchy"
    assert commands == [("tshark.exe", "-r", str(capture_path), "-q", "-z", "io,phs")]


def test_tshark_frame_inspection_returns_sanitized_counts(tmp_path: Path) -> None:
    commands: list[tuple[str, ...]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(tuple(command))
        return completed(command, stdout="60\n128\n72\n")

    capture_path = tmp_path / "capture.pcapng"
    hook = make_tshark_frame_inspection_hook(tshark_path="tshark.exe", run_command=runner)

    assert hook(capture_path) == CaptureFrameStats(
        frame_count=3, relevant_frame_count=3, captured_byte_count=260
    )
    assert commands == [
        (
            "tshark.exe",
            "-n",
            "-r",
            str(capture_path),
            "-T",
            "fields",
            "-e",
            "frame.cap_len",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
            "-E",
            "separator=,",
        )
    ]


def test_tshark_frame_inspection_rejects_header_only_capture(tmp_path: Path) -> None:
    hook = make_tshark_frame_inspection_hook(
        run_command=lambda command: completed(command, stdout=""),
    )

    with pytest.raises(RuntimeError, match="contains no frames"):
        hook(tmp_path / "header-only.pcapng")


def test_tshark_frame_inspection_counts_only_campaign_ports(tmp_path: Path) -> None:
    hook = make_tshark_frame_inspection_hook(
        relevant_tcp_ports=(4661, 4662),
        relevant_udp_ports=(1900, 4672),
        run_command=lambda command: completed(
            command,
            stdout="60,50000,443,,\n72,,,4672,53\n80,50001,80,,\n",
        ),
    )

    assert hook(tmp_path / "capture.pcapng") == CaptureFrameStats(
        frame_count=3,
        relevant_frame_count=1,
        captured_byte_count=212,
    )


def test_tshark_frame_inspection_propagates_truncated_capture_failure(tmp_path: Path) -> None:
    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(2, tuple(command), stderr="appears to have been cut short")

    hook = make_tshark_frame_inspection_hook(run_command=runner)

    with pytest.raises(subprocess.CalledProcessError):
        hook(tmp_path / "truncated.pcapng")


def test_managed_capture_rejects_size_limit_autostop_with_counts(tmp_path: Path) -> None:
    capture_path = tmp_path / "limited.pcapng"
    process = FakeCaptureProcess()

    def factory(command: Sequence[str]) -> FakeCaptureProcess:
        capture_path.write_bytes(b"x" * 64)
        return process

    capture = ManagedDumpcapCapture(
        output_path=capture_path,
        capture_filter="udp",
        interface="2",
        maximum_size_kib=8,
        process_factory=factory,
        inspection_hook=lambda path: CaptureFrameStats(
            frame_count=2, relevant_frame_count=2, captured_byte_count=120
        ),
    ).start()
    process.returncode = 0

    with pytest.raises(CaptureSizeLimitReachedError) as raised:
        capture.stop()

    assert raised.value.result.sanitized_counts() == {
        "fileByteCount": 64,
        "frameCount": 2,
        "relevantFrameCount": 2,
        "capturedByteCount": 120,
        "sizeLimitReached": True,
    }


def test_upnp_mapping_audit_verifies_tcp_and_udp_target_local_address() -> None:
    client = FakeUpnpClient(
        {
            (4662, "TCP"): ("192.0.2.18", 4662, "private description", True, "", 0),
            (4672, "UDP"): ("192.0.2.18", 4672, "private description", True, "", 0),
        }
    )

    def factory(address: str) -> FakeUpnpClient:
        client.multicastif = address
        return client

    audit = verify_upnp_port_mappings(
        "192.0.2.18",
        tcp_ports=(4662,),
        udp_ports=(4672,),
        expected_mapped=True,
        client_factory=factory,
        discovery_delay_ms=350,
    )

    assert client.discoverdelay == 350
    assert client.multicastif == "192.0.2.18"
    assert client.selected
    assert client.queries == [(4662, "TCP"), (4672, "UDP")]
    assert audit.sanitized_counts() == {
        "expectedMapped": True,
        "expectedCount": 2,
        "presentCount": 2,
        "matchingLocalCount": 2,
        "foreignTargetCount": 0,
        "missingCount": 0,
        "observedStatus": "mapped",
        "passed": True,
    }
    assert "192.0.2.18" not in str(audit.sanitized_counts())
    assert "private description" not in str(audit.sanitized_counts())


@pytest.mark.parametrize("case_name", ["after-shutdown", "firewalled"])
def test_upnp_mapping_audit_requires_exact_ports_absent(case_name: str) -> None:
    client = FakeUpnpClient({})

    audit = verify_upnp_port_mappings(
        "192.0.2.18",
        tcp_ports=(4662,),
        udp_ports=(4672,),
        expected_mapped=False,
        client_factory=lambda _address: client,
    )

    assert case_name
    assert audit.observed_status == "absent"
    assert audit.present_count == 0
    assert audit.passed


def test_upnp_mapping_audit_rejects_missing_or_foreign_mapping_without_leaking_target() -> None:
    client = FakeUpnpClient(
        {
            (4662, "TCP"): ("198.51.100.9", 4662, "foreign private description", True, "", 0),
        }
    )

    with pytest.raises(UpnpMappingAuditError) as raised:
        verify_upnp_port_mappings(
            "192.0.2.18",
            tcp_ports=(4662,),
            udp_ports=(4672,),
            expected_mapped=True,
            client_factory=lambda _address: client,
        )

    assert raised.value.audit.observed_status == "mismatched"
    assert raised.value.audit.foreign_target_count == 1
    assert raised.value.audit.missing_count == 1
    assert "198.51.100.9" not in str(raised.value)
    assert "foreign private description" not in str(raised.value)
    assert "198.51.100.9" not in str(raised.value.audit.sanitized_counts())


def test_upnp_mapping_audit_rejects_wrong_internal_port_without_leaking_target() -> None:
    client = FakeUpnpClient(
        {
            (4662, "TCP"): ("192.0.2.18", 54321, "private description", True, "", 0),
        }
    )

    with pytest.raises(UpnpMappingAuditError) as raised:
        verify_upnp_port_mappings(
            "192.0.2.18",
            tcp_ports=(4662,),
            expected_mapped=True,
            client_factory=lambda _address: client,
        )

    assert raised.value.audit.observed_status == "mismatched"
    assert raised.value.audit.matching_local_count == 0
    assert raised.value.audit.foreign_target_count == 1
    assert "54321" not in str(raised.value)
    assert "54321" not in str(raised.value.audit.sanitized_counts())
    assert "private description" not in str(raised.value.audit.sanitized_counts())


def test_upnp_mapping_audit_rejects_any_mapping_when_absence_is_required() -> None:
    client = FakeUpnpClient({(4662, "TCP"): ("192.0.2.18", 4662, "description", True, "", 0)})

    with pytest.raises(UpnpMappingAuditError) as raised:
        verify_upnp_port_mappings(
            "192.0.2.18",
            tcp_ports=(4662,),
            udp_ports=(4672,),
            expected_mapped=False,
            client_factory=lambda _address: client,
        )

    assert raised.value.audit.present_count == 1
    assert not raised.value.audit.passed


def test_upnp_mapping_audit_requires_gateway_and_valid_inputs() -> None:
    with pytest.raises(RuntimeError, match="did not discover"):
        verify_upnp_port_mappings(
            "192.0.2.18",
            tcp_ports=(4662,),
            expected_mapped=True,
            client_factory=lambda _address: FakeUpnpClient({}, discovered_count=0),
        )
    with pytest.raises(ValueError, match="X_LOCAL_IP"):
        verify_upnp_port_mappings(
            "not-an-address",
            tcp_ports=(4662,),
            expected_mapped=True,
            client_factory=lambda _address: FakeUpnpClient({}),
        )
    with pytest.raises(ValueError, match="at least one"):
        verify_upnp_port_mappings(
            "192.0.2.18",
            expected_mapped=False,
            client_factory=lambda _address: FakeUpnpClient({}),
        )


def test_firewall_owner_adds_unique_blocks_and_always_cleans_up() -> None:
    commands: list[tuple[str, ...]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        commands.append(tuple(command))
        return completed(command)

    rules = WindowsInboundBlockRules(
        case_id="rust-firewalled",
        tcp_ports=(4662,),
        udp_ports=(4672, 4665),
        unique_token="test123",
        run_command=runner,
    )

    with pytest.raises(RuntimeError, match="scenario failed"):
        with rules:
            assert rules.installed
            raise RuntimeError("scenario failed")

    adds = [command for command in commands if "add" in command]
    deletes = [command for command in commands if "delete" in command]
    assert len(adds) == 2
    assert len(deletes) == 2
    assert rules.rule_names == (
        "eMuleBB-CI-054-rust-firewalled-test123-TCP",
        "eMuleBB-CI-054-rust-firewalled-test123-UDP",
    )
    assert "localport=4665,4672" in adds[1]
    assert all("dir=in" in command and "action=block" in command for command in adds)
    assert not rules.installed


def test_firewall_owner_rolls_back_partial_install() -> None:
    commands: list[tuple[str, ...]] = []

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        command_tuple = tuple(command)
        commands.append(command_tuple)
        if "add" in command_tuple and "protocol=UDP" in command_tuple:
            raise subprocess.CalledProcessError(1, command_tuple)
        return completed(command)

    rules = WindowsInboundBlockRules(
        case_id="mfc-firewalled",
        tcp_ports=(4662,),
        udp_ports=(4672,),
        unique_token="partial",
        run_command=runner,
    )

    with pytest.raises(subprocess.CalledProcessError):
        rules.install()

    deletes = [command for command in commands if "delete" in command]
    assert {command[5] for command in deletes} == {f"name={name}" for name in rules.rule_names}
    assert not rules.installed


def test_firewall_cleanup_attempts_every_rule_and_can_retry_failures() -> None:
    commands: list[tuple[str, ...]] = []
    fail_tcp_delete = True

    def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        nonlocal fail_tcp_delete
        command_tuple = tuple(command)
        commands.append(command_tuple)
        if "delete" in command_tuple and command_tuple[5].endswith("-TCP") and fail_tcp_delete:
            fail_tcp_delete = False
            raise subprocess.CalledProcessError(1, command_tuple)
        return completed(command)

    rules = WindowsInboundBlockRules(
        case_id="cleanup-retry",
        tcp_ports=(4662,),
        udp_ports=(4672,),
        unique_token="retry",
        run_command=runner,
    ).install()

    with pytest.raises(RuntimeError, match="failed to remove"):
        rules.cleanup()

    assert rules.installed
    assert len([command for command in commands if "delete" in command]) == 2

    rules.cleanup()

    assert not rules.installed
    assert len([command for command in commands if "delete" in command]) == 3


def test_firewall_inputs_reject_invalid_or_empty_ports() -> None:
    with pytest.raises(ValueError, match="at least one"):
        WindowsInboundBlockRules(case_id="empty")
    with pytest.raises(ValueError, match="invalid TCP/UDP port"):
        WindowsInboundBlockRules(case_id="bad-port", tcp_ports=(0,))
    with pytest.raises(ValueError, match="case_id"):
        WindowsInboundBlockRules(case_id="contains spaces", tcp_ports=(4662,))
