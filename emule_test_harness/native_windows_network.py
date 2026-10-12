"""Managed native-Windows capture and firewall helpers for live campaigns."""

from __future__ import annotations

import ipaddress
import json
import re
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, Sequence

Command = tuple[str, ...]
CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
ProcessFactory = Callable[[Sequence[str]], subprocess.Popen[bytes]]
CaptureSummaryHook = Callable[[Path], str]
CaptureInspectionHook = Callable[[Path], "CaptureFrameStats"]


class MiniupnpcClient(Protocol):
    """Subset of miniupnpc used for read-only mapping audits."""

    discoverdelay: int
    multicastif: str

    def discover(self) -> int: ...

    def selectigd(self) -> None: ...

    def getspecificportmapping(self, external_port: int, protocol: str) -> object: ...


MiniupnpcFactory = Callable[[str], MiniupnpcClient]

PCAPNG_MINIMUM_BYTES = 28
_DUMPCAP_INTERFACE_RE = re.compile(r"^\s*(?P<index>\d+)\.\s+(?P<device>\S+)(?:\s+\((?P<description>.*)\))?\s*$")
_FIREWALL_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,47}$")


@dataclass(frozen=True)
class CaptureInterface:
    """One interface reported by ``dumpcap -D``."""

    index: int
    device: str
    description: str


@dataclass(frozen=True)
class CaptureInterfaceHints:
    """Inputs supplied by the caller's direct-route interface resolution."""

    device: str | None = None
    guid: str | None = None
    alias: str | None = None
    description: str | None = None

    def values(self) -> tuple[str, ...]:
        """Returns non-empty matching hints in priority order."""

        return tuple(value.strip() for value in (self.device, self.guid, self.alias, self.description) if value and value.strip())


@dataclass(frozen=True)
class CaptureResult:
    """Validated output from one managed capture session."""

    output_path: Path
    byte_count: int
    frame_count: int
    relevant_frame_count: int
    captured_byte_count: int
    size_limit_reached: bool
    tshark_summary: str | None

    def sanitized_counts(self) -> dict[str, int | bool]:
        """Returns endpoint-free metrics suitable for retained diff evidence."""

        return {
            "fileByteCount": self.byte_count,
            "frameCount": self.frame_count,
            "relevantFrameCount": self.relevant_frame_count,
            "capturedByteCount": self.captured_byte_count,
            "sizeLimitReached": self.size_limit_reached,
        }


@dataclass(frozen=True)
class CaptureFrameStats:
    """Sanitized frame totals parsed from a completed capture."""

    frame_count: int
    relevant_frame_count: int
    captured_byte_count: int


class CaptureSizeLimitReachedError(RuntimeError):
    """Reports a capture stopped by or at its configured size boundary."""

    def __init__(self, result: CaptureResult) -> None:
        super().__init__("capture reached its configured size limit before managed teardown")
        self.result = result


@dataclass(frozen=True)
class UpnpMappingAudit:
    """Endpoint-free result for exact-port UPnP mapping verification."""

    expected_mapped: bool
    expected_count: int
    present_count: int
    matching_local_count: int
    foreign_target_count: int
    missing_count: int
    observed_status: str
    passed: bool

    def sanitized_counts(self) -> dict[str, int | bool | str]:
        """Returns only counts and status suitable for retained evidence."""

        return {
            "expectedMapped": self.expected_mapped,
            "expectedCount": self.expected_count,
            "presentCount": self.present_count,
            "matchingLocalCount": self.matching_local_count,
            "foreignTargetCount": self.foreign_target_count,
            "missingCount": self.missing_count,
            "observedStatus": self.observed_status,
            "passed": self.passed,
        }


class UpnpMappingAuditError(RuntimeError):
    """Carries sanitized mapping counts when an expected state is not met."""

    def __init__(self, audit: UpnpMappingAudit) -> None:
        expected = "mapped" if audit.expected_mapped else "absent"
        super().__init__(
            "UPnP mapping audit failed: "
            f"expected={expected} observed={audit.observed_status} "
            f"present={audit.present_count}/{audit.expected_count}"
        )
        self.audit = audit


def run_checked(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Runs one external command and raises when it fails."""

    return subprocess.run(tuple(command), check=True, capture_output=True, text=True)


def create_miniupnpc_client(local_address: str) -> MiniupnpcClient:
    """Creates the optional miniupnpc client with a clear missing-tool error."""

    try:
        import miniupnpc
    except ImportError as error:
        raise RuntimeError("miniupnpc is required for native UPnP mapping audits") from error
    return miniupnpc.UPnP(localport=0, multicastif=local_address)


def start_background_process(command: Sequence[str]) -> subprocess.Popen[bytes]:
    """Starts one quiet child process in a group suitable for managed teardown."""

    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    return subprocess.Popen(
        tuple(command),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )


def parse_dumpcap_interfaces(output: str) -> tuple[CaptureInterface, ...]:
    """Parses the stable numbered interface inventory emitted by ``dumpcap -D``."""

    interfaces: list[CaptureInterface] = []
    for line in output.splitlines():
        match = _DUMPCAP_INTERFACE_RE.match(line)
        if match is None:
            continue
        interfaces.append(
            CaptureInterface(
                index=int(match.group("index")),
                device=match.group("device"),
                description=(match.group("description") or "").strip(),
            )
        )
    return tuple(interfaces)


def discover_capture_interfaces(
    *,
    dumpcap_path: str = "dumpcap",
    run_command: CommandRunner = run_checked,
) -> tuple[CaptureInterface, ...]:
    """Queries dumpcap for the interfaces visible to the native capture driver."""

    result = run_command((dumpcap_path, "-D"))
    interfaces = parse_dumpcap_interfaces(result.stdout)
    if not interfaces:
        raise RuntimeError("dumpcap did not report any capture interfaces")
    return interfaces


def resolve_windows_adapter_hints(
    local_address: str,
    *,
    powershell_path: str = "powershell.exe",
    run_command: CommandRunner = run_checked,
) -> CaptureInterfaceHints:
    """Maps the inherited ``X_LOCAL_IP`` IPv4 address to Windows adapter hints."""

    try:
        normalized_address = str(ipaddress.IPv4Address(local_address))
    except ipaddress.AddressValueError as error:
        raise ValueError("X_LOCAL_IP must be a valid IPv4 address") from error

    # The address is normalized before interpolation, so the PowerShell command
    # cannot inherit script syntax from operator-controlled environment text.
    script = (
        f"$ip = Get-NetIPAddress -IPAddress '{normalized_address}' -AddressFamily IPv4 -ErrorAction Stop "
        "| Select-Object -First 1; "
        "if ($null -eq $ip) { throw 'No matching IP adapter' }; "
        "$adapter = Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex -ErrorAction Stop; "
        "[PSCustomObject]@{ "
        "guid = [string]$adapter.InterfaceGuid; "
        "alias = [string]$adapter.Name; "
        "description = [string]$adapter.InterfaceDescription "
        "} | ConvertTo-Json -Compress"
    )
    result = run_command(
        (
            powershell_path,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        )
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Windows adapter query returned invalid JSON") from error
    if not isinstance(payload, dict):
        raise RuntimeError("Windows adapter query did not return one adapter")

    values: dict[str, str] = {}
    for key in ("guid", "alias", "description"):
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"Windows adapter query omitted {key}")
        values[key] = value.strip()
    return CaptureInterfaceHints(
        guid=values["guid"],
        alias=values["alias"],
        description=values["description"],
    )


def resolve_capture_interface(
    interfaces: Sequence[CaptureInterface],
    hints: CaptureInterfaceHints,
) -> CaptureInterface:
    """Matches route-derived Windows identity hints to exactly one Npcap device."""

    candidates = tuple(interfaces)
    if not candidates:
        raise ValueError("capture interface inventory is empty")
    values = hints.values()
    if not values:
        if len(candidates) == 1:
            return candidates[0]
        raise ValueError("capture interface hints are required when more than one interface is available")

    for index, value in enumerate(values):
        exact_device = bool(hints.device and hints.device.strip()) and index == 0
        needle = value.casefold() if exact_device else value.casefold().strip("{}")
        matches = [
            interface
            for interface in candidates
            if _interface_matches(interface, needle, exact_device=exact_device)
        ]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError(f"capture interface hint {value!r} is ambiguous")
    raise ValueError("no dumpcap interface matched the supplied direct-route identity")


def build_dumpcap_command(
    *,
    output_path: Path,
    capture_filter: str,
    interface: CaptureInterface | str,
    dumpcap_path: str = "dumpcap",
    maximum_size_kib: int | None = None,
) -> Command:
    """Builds a bounded native dumpcap command for a resolved interface."""

    interface_name = interface.device if isinstance(interface, CaptureInterface) else str(interface).strip()
    if not interface_name:
        raise ValueError("capture interface must not be empty")
    if not capture_filter.strip():
        raise ValueError("capture filter must not be empty")
    if maximum_size_kib is not None and maximum_size_kib <= 0:
        raise ValueError("maximum_size_kib must be positive")

    command = [
        dumpcap_path,
        "-q",
        "-i",
        interface_name,
        "-f",
        capture_filter,
        "-w",
        str(output_path),
    ]
    if maximum_size_kib is not None:
        command.extend(("-a", f"filesize:{maximum_size_kib}"))
    return tuple(command)


def validate_capture(path: Path, *, minimum_bytes: int = PCAPNG_MINIMUM_BYTES) -> int:
    """Requires an existing capture large enough to contain a pcapng header."""

    if minimum_bytes <= 0:
        raise ValueError("minimum_bytes must be positive")
    try:
        byte_count = path.stat().st_size
    except FileNotFoundError as error:
        raise RuntimeError(f"capture file was not created: {path}") from error
    if byte_count < minimum_bytes:
        raise RuntimeError(f"capture file is too small: {path} ({byte_count} bytes)")
    return byte_count


def make_tshark_protocol_summary_hook(
    *,
    tshark_path: str = "tshark",
    run_command: CommandRunner = run_checked,
) -> CaptureSummaryHook:
    """Returns a hook that renders Tshark's protocol-hierarchy summary."""

    def summarize(capture_path: Path) -> str:
        result = run_command((tshark_path, "-r", str(capture_path), "-q", "-z", "io,phs"))
        return result.stdout

    return summarize


def make_tshark_frame_inspection_hook(
    *,
    tshark_path: str = "tshark",
    run_command: CommandRunner = run_checked,
    relevant_tcp_ports: Sequence[int] = (),
    relevant_udp_ports: Sequence[int] = (),
) -> CaptureInspectionHook:
    """Returns a strict parser/count hook that also validates pcap readability."""

    tcp_ports = set(_normalize_ports(relevant_tcp_ports))
    udp_ports = set(_normalize_ports(relevant_udp_ports))

    def inspect(capture_path: Path) -> CaptureFrameStats:
        result = run_command(
            (
                tshark_path,
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
        )
        captured_lengths: list[int] = []
        relevant_frame_count = 0
        for line_number, line in enumerate(result.stdout.splitlines(), start=1):
            value = line.strip()
            if not value:
                continue
            fields = value.split(",")
            try:
                captured_length = int(fields[0], 10)
            except ValueError as error:
                raise RuntimeError(f"tshark returned an invalid frame length on line {line_number}") from error
            if captured_length < 0:
                raise RuntimeError(f"tshark returned a negative frame length on line {line_number}")
            captured_lengths.append(captured_length)
            if not tcp_ports and not udp_ports:
                relevant_frame_count += 1
                continue
            port_fields = fields[1:5] + [""] * max(0, 5 - len(fields))
            try:
                observed_tcp = {int(value) for value in port_fields[:2] if value}
                observed_udp = {int(value) for value in port_fields[2:4] if value}
            except ValueError as error:
                raise RuntimeError(f"tshark returned an invalid port on line {line_number}") from error
            if observed_tcp & tcp_ports or observed_udp & udp_ports:
                relevant_frame_count += 1
        if not captured_lengths:
            raise RuntimeError("capture contains no frames")
        return CaptureFrameStats(
            frame_count=len(captured_lengths),
            relevant_frame_count=relevant_frame_count,
            captured_byte_count=sum(captured_lengths),
        )

    return inspect


def verify_upnp_port_mappings(
    local_address: str,
    *,
    tcp_ports: Sequence[int] = (),
    udp_ports: Sequence[int] = (),
    expected_mapped: bool,
    client_factory: MiniupnpcFactory = create_miniupnpc_client,
    discovery_delay_ms: int = 200,
) -> UpnpMappingAudit:
    """Verifies exact TCP/UDP mappings without retaining endpoint details.

    Use ``expected_mapped=True`` while the UPnP client is active. Use
    ``expected_mapped=False`` after shutdown and throughout firewalled cases.
    """

    try:
        normalized_address = str(ipaddress.IPv4Address(local_address))
    except ipaddress.AddressValueError as error:
        raise ValueError("X_LOCAL_IP must be a valid IPv4 address") from error
    if discovery_delay_ms <= 0:
        raise ValueError("discovery_delay_ms must be positive")
    expected = tuple(("TCP", port) for port in _normalize_ports(tcp_ports)) + tuple(
        ("UDP", port) for port in _normalize_ports(udp_ports)
    )
    if not expected:
        raise ValueError("at least one TCP or UDP port is required")

    client = client_factory(normalized_address)
    client.discoverdelay = discovery_delay_ms
    discovered_count = client.discover()
    if discovered_count <= 0:
        raise RuntimeError("miniupnpc did not discover a UPnP gateway")
    client.selectigd()

    present_count = 0
    matching_local_count = 0
    foreign_target_count = 0
    for protocol, port in expected:
        mapping = client.getspecificportmapping(port, protocol)
        if mapping is None:
            continue
        present_count += 1
        target = mapping[0] if isinstance(mapping, (tuple, list)) and mapping else None
        if isinstance(target, str) and target.strip() == normalized_address:
            matching_local_count += 1
        else:
            foreign_target_count += 1

    missing_count = len(expected) - present_count
    if present_count == 0:
        observed_status = "absent"
    elif matching_local_count == len(expected) and foreign_target_count == 0:
        observed_status = "mapped"
    elif foreign_target_count:
        observed_status = "mismatched"
    else:
        observed_status = "partial"
    passed = observed_status == ("mapped" if expected_mapped else "absent")
    audit = UpnpMappingAudit(
        expected_mapped=expected_mapped,
        expected_count=len(expected),
        present_count=present_count,
        matching_local_count=matching_local_count,
        foreign_target_count=foreign_target_count,
        missing_count=missing_count,
        observed_status=observed_status,
        passed=passed,
    )
    if not passed:
        raise UpnpMappingAuditError(audit)
    return audit


class ManagedDumpcapCapture:
    """Owns dumpcap readiness, graceful teardown, validation, and summarization."""

    def __init__(
        self,
        *,
        output_path: Path,
        capture_filter: str,
        interface: CaptureInterface | str,
        dumpcap_path: str = "dumpcap",
        maximum_size_kib: int | None = None,
        readiness_timeout_seconds: float = 10.0,
        stop_timeout_seconds: float = 10.0,
        minimum_bytes: int = PCAPNG_MINIMUM_BYTES,
        process_factory: ProcessFactory = start_background_process,
        inspection_hook: CaptureInspectionHook | None = None,
        summary_hook: CaptureSummaryHook | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if readiness_timeout_seconds <= 0:
            raise ValueError("readiness_timeout_seconds must be positive")
        if stop_timeout_seconds <= 0:
            raise ValueError("stop_timeout_seconds must be positive")
        self.output_path = output_path.resolve()
        self.command = build_dumpcap_command(
            output_path=self.output_path,
            capture_filter=capture_filter,
            interface=interface,
            dumpcap_path=dumpcap_path,
            maximum_size_kib=maximum_size_kib,
        )
        self.readiness_timeout_seconds = readiness_timeout_seconds
        self.stop_timeout_seconds = stop_timeout_seconds
        self.minimum_bytes = minimum_bytes
        self.maximum_size_kib = maximum_size_kib
        self._process_factory = process_factory
        self._inspection_hook = inspection_hook or make_tshark_frame_inspection_hook()
        self._summary_hook = summary_hook
        self._monotonic = monotonic
        self._sleep = sleep
        self._process: subprocess.Popen[bytes] | None = None
        self._result: CaptureResult | None = None

    @property
    def is_running(self) -> bool:
        """Reports whether the managed child is still active."""

        return self._process is not None and self._process.poll() is None

    def start(self) -> "ManagedDumpcapCapture":
        """Starts dumpcap and waits until it has written a pcapng header."""

        if self._process is not None or self._result is not None:
            raise RuntimeError("capture session has already been started")
        if self.output_path.exists():
            raise FileExistsError(f"capture output already exists: {self.output_path}")
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._process = self._process_factory(self.command)
        deadline = self._monotonic() + self.readiness_timeout_seconds
        try:
            while self._monotonic() < deadline:
                return_code = self._process.poll()
                if return_code is not None:
                    raise RuntimeError(f"dumpcap exited before becoming ready (exit code {return_code})")
                try:
                    validate_capture(self.output_path, minimum_bytes=self.minimum_bytes)
                except RuntimeError:
                    self._sleep(0.05)
                    continue
                return self
            raise TimeoutError(f"dumpcap did not become ready within {self.readiness_timeout_seconds:g} seconds")
        except BaseException:
            self._stop_process()
            raise

    def stop(self) -> CaptureResult:
        """Stops dumpcap, validates its output, and runs the optional summary hook."""

        if self._result is not None:
            return self._result
        if self._process is None:
            raise RuntimeError("capture session has not been started")
        return_code_before_stop = self._process.poll()
        self._stop_process()
        byte_count = validate_capture(self.output_path, minimum_bytes=self.minimum_bytes)
        frame_stats = self._inspection_hook(self.output_path)
        if frame_stats.frame_count <= 0:
            raise RuntimeError("capture contains no frames")
        if frame_stats.relevant_frame_count <= 0:
            raise RuntimeError("capture contains no campaign-relevant frames")
        if frame_stats.captured_byte_count < 0:
            raise RuntimeError("capture has an invalid captured-byte count")
        summary = self._summary_hook(self.output_path) if self._summary_hook is not None else None
        configured_size_bytes = self.maximum_size_kib * 1024 if self.maximum_size_kib is not None else None
        size_limit_reached = bool(
            configured_size_bytes is not None
            and (return_code_before_stop == 0 or byte_count >= configured_size_bytes)
        )
        result = CaptureResult(
            output_path=self.output_path,
            byte_count=byte_count,
            frame_count=frame_stats.frame_count,
            relevant_frame_count=frame_stats.relevant_frame_count,
            captured_byte_count=frame_stats.captured_byte_count,
            size_limit_reached=size_limit_reached,
            tshark_summary=summary,
        )
        if return_code_before_stop is not None and return_code_before_stop != 0:
            raise RuntimeError(f"dumpcap exited before managed teardown (exit code {return_code_before_stop})")
        if return_code_before_stop == 0 and self.maximum_size_kib is None:
            raise RuntimeError("dumpcap exited before managed teardown")
        if size_limit_reached:
            raise CaptureSizeLimitReachedError(result)
        self._result = result
        return self._result

    def _stop_process(self) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            return
        stop_signal = getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM)
        try:
            process.send_signal(stop_signal)
            process.wait(timeout=self.stop_timeout_seconds)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            process.terminate()
            process.wait(timeout=self.stop_timeout_seconds)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        process.kill()
        process.wait(timeout=self.stop_timeout_seconds)

    def __enter__(self) -> "ManagedDumpcapCapture":
        return self.start()

    def __exit__(self, exc_type: object, exc: BaseException | None, traceback: object) -> bool:
        try:
            self.stop()
        except BaseException as cleanup_error:
            if exc is None:
                raise
            _add_exception_note(exc, f"capture cleanup failed: {cleanup_error}")
        return False


class WindowsInboundBlockRules:
    """Owns uniquely named inbound TCP/UDP block rules for one campaign case."""

    def __init__(
        self,
        *,
        case_id: str,
        tcp_ports: Sequence[int] = (),
        udp_ports: Sequence[int] = (),
        name_prefix: str = "eMuleBB-CI-054",
        netsh_path: str = "netsh.exe",
        run_command: CommandRunner = run_checked,
        unique_token: str | None = None,
    ) -> None:
        if _FIREWALL_CASE_ID_RE.fullmatch(case_id) is None:
            raise ValueError("case_id must contain only short ASCII identifier characters")
        self.tcp_ports = _normalize_ports(tcp_ports)
        self.udp_ports = _normalize_ports(udp_ports)
        if not self.tcp_ports and not self.udp_ports:
            raise ValueError("at least one TCP or UDP port is required")
        token = (unique_token or uuid.uuid4().hex[:12]).strip()
        if not token or re.fullmatch(r"[A-Za-z0-9-]+", token) is None:
            raise ValueError("unique_token must contain only ASCII letters, digits, or hyphens")
        self.name_prefix = name_prefix.strip()
        if not self.name_prefix:
            raise ValueError("name_prefix must not be empty")
        self.case_id = case_id
        self.netsh_path = netsh_path
        self._run_command = run_command
        self._rule_specs = tuple(
            (f"{self.name_prefix}-{case_id}-{token}-{protocol}", protocol, ports)
            for protocol, ports in (("TCP", self.tcp_ports), ("UDP", self.udp_ports))
            if ports
        )
        self._owned_rule_names: list[str] = []
        self._installed = False

    @property
    def rule_names(self) -> tuple[str, ...]:
        """Returns the unique names reserved for this owner."""

        return tuple(name for name, _, _ in self._rule_specs)

    @property
    def installed(self) -> bool:
        """Reports whether installation completed successfully."""

        return self._installed

    def install(self) -> "WindowsInboundBlockRules":
        """Adds all owned rules and rolls back every attempted name on failure."""

        if self._owned_rule_names or self._installed:
            raise RuntimeError("firewall rules have already been installed")
        try:
            for name, protocol, ports in self._rule_specs:
                # WHY: an interrupted netsh call can create a rule before reporting
                # failure, so ownership is recorded before the command is attempted.
                self._owned_rule_names.append(name)
                self._run_command(self._add_command(name=name, protocol=protocol, ports=ports))
        except BaseException as install_error:
            try:
                self.cleanup()
            except BaseException as cleanup_error:
                _add_exception_note(install_error, f"firewall rollback failed: {cleanup_error}")
            raise
        self._installed = True
        return self

    def cleanup(self) -> None:
        """Attempts deletion of every owned rule, including partial installs."""

        failures: list[tuple[str, BaseException]] = []
        while self._owned_rule_names:
            name = self._owned_rule_names.pop()
            try:
                self._run_command(self._delete_command(name))
            except BaseException as error:
                failures.append((name, error))
        self._owned_rule_names.extend(name for name, _ in reversed(failures))
        self._installed = bool(self._owned_rule_names)
        if failures:
            details = "; ".join(f"{name}: {error}" for name, error in failures)
            raise RuntimeError("failed to remove campaign firewall rules: " + details)

    def _add_command(self, *, name: str, protocol: str, ports: tuple[int, ...]) -> Command:
        return (
            self.netsh_path,
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={name}",
            "dir=in",
            "action=block",
            f"protocol={protocol}",
            f"localport={','.join(str(port) for port in ports)}",
            "profile=any",
            "enable=yes",
        )

    def _delete_command(self, name: str) -> Command:
        return (
            self.netsh_path,
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={name}",
            "dir=in",
        )

    def __enter__(self) -> "WindowsInboundBlockRules":
        return self.install()

    def __exit__(self, exc_type: object, exc: BaseException | None, traceback: object) -> bool:
        try:
            self.cleanup()
        except BaseException as cleanup_error:
            if exc is None:
                raise
            _add_exception_note(exc, f"firewall cleanup failed: {cleanup_error}")
        return False


def _interface_matches(interface: CaptureInterface, needle: str, *, exact_device: bool) -> bool:
    device = interface.device.casefold()
    description = interface.description.casefold()
    if exact_device:
        return device == needle.casefold()
    normalized_device = device.replace("{", "").replace("}", "")
    return needle in normalized_device or needle in description


def _normalize_ports(ports: Sequence[int]) -> tuple[int, ...]:
    normalized: set[int] = set()
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"invalid TCP/UDP port: {port!r}")
        normalized.add(port)
    return tuple(sorted(normalized))


def _add_exception_note(error: BaseException, note: str) -> None:
    """Attaches cleanup context when supported without dropping Python 3.10."""

    add_note = getattr(error, "add_note", None)
    if add_note is not None:
        add_note(note)
