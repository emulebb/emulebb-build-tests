"""aMule runtime helpers for deterministic Windows multi-client tests."""

from __future__ import annotations

import hashlib
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from emule_test_harness.paths import reject_windows_temp_path


SHARED_FILE_PATTERN = re.compile(r"(?im)^\s*(?:>\s*)?([0-9a-f]{32})\s+(.+)$")
KAD_STATUS_PATTERN = re.compile(r"(?im)^\s*(?:>\s*)?Kad\s*:\s*(.+?)\s*$")
UNLIMITED_THROTTLE = "0"


@dataclass(frozen=True)
class AmuleRuntimeProfile:
    """Describes one isolated aMule daemon profile owned by a test run."""

    profile_id: str
    nick: str
    root_dir: Path
    config_dir: Path
    incoming_dir: Path
    temp_dir: Path
    logs_dir: Path
    tcp_port: int
    udp_port: int
    ec_port: int
    ec_password: str
    ec_password_hash: str
    advertised_address: str

    def as_report(self) -> dict[str, object]:
        """Returns a JSON-safe profile summary without exposing the EC password."""

        return {
            "profile_id": self.profile_id,
            "nick": self.nick,
            "root_dir": str(self.root_dir),
            "config_dir": str(self.config_dir),
            "incoming_dir": str(self.incoming_dir),
            "temp_dir": str(self.temp_dir),
            "logs_dir": str(self.logs_dir),
            "tcp_port": self.tcp_port,
            "udp_port": self.udp_port,
            "ec_port": self.ec_port,
            "ec_password_hash": self.ec_password_hash,
            "advertised_address": self.advertised_address,
        }


def md5_hex(value: str) -> str:
    """Returns the lowercase MD5 hex string used by aMule EC config."""

    return hashlib.md5(value.encode("utf-8")).hexdigest()


def win_path_text(path: Path) -> str:
    """Returns a resolved Windows path string for aMule config files."""

    return str(path.resolve()).replace("\\", "\\\\")


def build_amule_conf(
    profile: AmuleRuntimeProfile,
    *,
    connect_to_kad: bool = False,
    connect_to_ed2k: bool = True,
) -> str:
    """Builds a deterministic `amule.conf` for a headless daemon profile."""

    return "\n".join(
        [
            "[eMule]",
            f"Nick={profile.nick}",
            f"Port={profile.tcp_port}",
            f"UDPPort={profile.udp_port}",
            "UDPEnable=1",
            f"Address={profile.advertised_address}",
            "Autoconnect=0",
            "Reconnect=0",
            "Serverlist=0",
            "AddServerListFromServer=0",
            "AddServerListFromClient=0",
            "SafeServerConnect=0",
            "AutoConnectStaticOnly=0",
            f"MaxUpload={UNLIMITED_THROTTLE}",
            f"MaxDownload={UNLIMITED_THROTTLE}",
            "SlotAllocation=16",
            "MaxConnections=1000",
            "MaxConnectionsPerFiveSeconds=100",
            "UPnPEnabled=0",
            f"ConnectToKad={1 if connect_to_kad else 0}",
            f"ConnectToED2K={1 if connect_to_ed2k else 0}",
            f"TempDir={win_path_text(profile.temp_dir)}",
            f"IncomingDir={win_path_text(profile.incoming_dir)}",
            "CheckDiskspace=1",
            "MinFreeDiskSpace=1",
            "AddNewFilesPaused=0",
            "AllocateFullFile=0",
            "FilterLanIPs=0",
            "IPFilterAutoLoad=0",
            "IPFilterURL=",
            "FilterLevel=0",
            "OnlineSignature=0",
            "ConfirmExit=0",
            "",
            "[ExternalConnect]",
            "AcceptExternalConnections=1",
            "ECAddress=127.0.0.1",
            f"ECPort={profile.ec_port}",
            f"ECPassword={profile.ec_password_hash}",
            "UPnPECEnabled=0",
            "IpFilterClients=0",
            "IpFilterServers=0",
            "UseSrcSeeds=0",
            "ShowProgressBar=1",
            "ShowPercent=1",
            "",
            "[WebServer]",
            "Enabled=0",
            "",
            "[Obfuscation]",
            "IsClientCryptLayerSupported=1",
            "IsCryptLayerRequested=1",
            "IsClientCryptLayerRequired=0",
            "",
        ]
    )


def prepare_amule_profile(
    *,
    root_dir: Path,
    profile_id: str,
    nick: str,
    tcp_port: int,
    udp_port: int,
    ec_port: int,
    advertised_address: str,
    connect_to_kad: bool = False,
    connect_to_ed2k: bool = True,
) -> AmuleRuntimeProfile:
    """Creates one isolated aMule profile under the suite artifact tree."""

    reject_windows_temp_path(root_dir, "aMule profile root")
    profile = AmuleRuntimeProfile(
        profile_id=profile_id,
        nick=nick,
        root_dir=root_dir.resolve(),
        config_dir=(root_dir / "config").resolve(),
        incoming_dir=(root_dir / "incoming").resolve(),
        temp_dir=(root_dir / "temp").resolve(),
        logs_dir=(root_dir / "logs").resolve(),
        tcp_port=tcp_port,
        udp_port=udp_port,
        ec_port=ec_port,
        ec_password=f"{profile_id}-ec-password",
        ec_password_hash=md5_hex(f"{profile_id}-ec-password"),
        advertised_address=advertised_address,
    )
    for directory in (profile.config_dir, profile.incoming_dir, profile.temp_dir, profile.logs_dir):
        reject_windows_temp_path(directory, f"aMule {directory.name} directory")
        directory.mkdir(parents=True, exist_ok=True)
    (profile.config_dir / "amule.conf").write_text(
        build_amule_conf(profile, connect_to_kad=connect_to_kad, connect_to_ed2k=connect_to_ed2k),
        encoding="utf-8",
        newline="\n",
    )
    return profile


def build_amuled_command(daemon_exe: Path, profile: AmuleRuntimeProfile) -> list[str]:
    """Builds the `amuled` launch command with explicit profile isolation."""

    return [
        str(daemon_exe.resolve()),
        f"--config-dir={profile.config_dir}",
        "--log-stdout",
    ]


def build_amulecmd_command(control_exe: Path, profile: AmuleRuntimeProfile, command: str) -> list[str]:
    """Builds one non-interactive `amulecmd` command for the isolated daemon."""

    return [
        str(control_exe.resolve()),
        "--host=127.0.0.1",
        f"--port={profile.ec_port}",
        f"--password={profile.ec_password}",
        f"--command={command}",
    ]


def start_amuled(daemon_exe: Path, profile: AmuleRuntimeProfile) -> subprocess.Popen:
    """Starts `amuled` with stdout/stderr captured below the profile log root."""

    log_path = profile.logs_dir / "amuled.log"
    handle = log_path.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            build_amuled_command(daemon_exe, profile),
            stdout=handle,
            stderr=subprocess.STDOUT,
            cwd=daemon_exe.resolve().parent,
            text=True,
        )
    finally:
        handle.close()
    return process


def run_amulecmd(
    control_exe: Path,
    profile: AmuleRuntimeProfile,
    command: str,
    *,
    timeout_seconds: float = 30.0,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Runs one `amulecmd` command and optionally raises on command failure."""

    completed = subprocess.run(
        build_amulecmd_command(control_exe, profile, command),
        cwd=control_exe.resolve().parent,
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            "amulecmd command failed: "
            f"command={command!r} return_code={completed.returncode} "
            f"stdout={completed.stdout[-2000:]!r} stderr={completed.stderr[-2000:]!r}"
        )
    return completed


def wait_for_ec_ready(control_exe: Path, profile: AmuleRuntimeProfile, timeout_seconds: float) -> dict[str, object]:
    """Waits until `amulecmd Status` can talk to the daemon."""

    deadline = time.monotonic() + timeout_seconds
    observations: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        completed = run_amulecmd(control_exe, profile, "Status", timeout_seconds=10.0, check=False)
        observations.append(
            {
                "return_code": completed.returncode,
                "stdout_tail": completed.stdout[-1000:],
                "stderr_tail": completed.stderr[-1000:],
                "observed_at": round(time.time(), 3),
            }
        )
        if completed.returncode == 0 and "eD2k" in completed.stdout:
            return {"ready": True, "observations": observations[-5:]}
        time.sleep(1.0)
    raise RuntimeError(f"Timed out waiting for aMule EC readiness. Observations: {observations[-5:]!r}")


def parse_kad_status(stdout: str) -> dict[str, object]:
    """Parses the `Kad:` line from `amulecmd Status` output."""

    match = KAD_STATUS_PATTERN.search(stdout)
    state = match.group(1).strip() if match else ""
    state_lower = state.lower()
    return {
        "present": bool(match),
        "state": state,
        "running": bool(match) and state_lower != "not running",
        "connected": state_lower.startswith("connected"),
        "firewalled": "firewalled" in state_lower,
    }


def wait_for_kad_status(
    control_exe: Path,
    profile: AmuleRuntimeProfile,
    timeout_seconds: float,
    *,
    require_connected: bool = False,
) -> dict[str, object]:
    """Waits until aMule reports Kad running, optionally connected, through EC."""

    deadline = time.monotonic() + timeout_seconds
    observations: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        completed = run_amulecmd(control_exe, profile, "Status", timeout_seconds=10.0, check=False)
        status = parse_kad_status(completed.stdout)
        observations.append(
            {
                "return_code": completed.returncode,
                "kad": status,
                "stdout_tail": completed.stdout[-1000:],
                "stderr_tail": completed.stderr[-1000:],
                "observed_at": round(time.time(), 3),
            }
        )
        if completed.returncode == 0 and status["running"] and (not require_connected or status["connected"]):
            return {
                "ready": True,
                "require_connected": require_connected,
                "kad": status,
                "observations": observations[-5:],
            }
        time.sleep(1.0)
    raise RuntimeError(f"Timed out waiting for aMule Kad readiness. Observations: {observations[-5:]!r}")


def wait_for_shared_file_hash(
    control_exe: Path,
    profile: AmuleRuntimeProfile,
    file_name: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until `Show Shared` exposes the named file and returns its ED2K hash."""

    deadline = time.monotonic() + timeout_seconds
    observations: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        completed = run_amulecmd(control_exe, profile, "Show Shared", timeout_seconds=30.0, check=False)
        observations.append(
            {
                "return_code": completed.returncode,
                "stdout_tail": completed.stdout[-2000:],
                "stderr_tail": completed.stderr[-1000:],
                "observed_at": round(time.time(), 3),
            }
        )
        if completed.returncode == 0:
            for match in SHARED_FILE_PATTERN.finditer(completed.stdout):
                if file_name.lower() in match.group(2).lower():
                    return {
                        "hash": match.group(1).lower(),
                        "file_name": file_name,
                        "stdout_tail": completed.stdout[-4000:],
                        "observations": observations[-5:],
                    }
        time.sleep(1.0)
    raise RuntimeError(f"Timed out waiting for aMule to share {file_name!r}. Observations: {observations[-5:]!r}")


def build_file_link(file_name: str, size: int, file_hash: str) -> str:
    """Builds the deterministic ED2K file link consumed by eMule BB."""

    return f"ed2k://|file|{file_name}|{size}|{file_hash.lower()}|/"


def build_server_link(address: str, port: int) -> str:
    """Builds an ED2K server link accepted by `amulecmd Add`."""

    normalized_address = address.strip()
    if not normalized_address:
        raise ValueError("ED2K server address must not be empty.")
    if port < 1 or port > 65535:
        raise ValueError(f"ED2K server port is out of range: {port}")
    return f"ed2k://|server|{normalized_address}|{port}|/"
