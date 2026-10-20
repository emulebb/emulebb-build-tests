"""Official aMule daemon profile and EC control helpers for local live tests."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time
import urllib.parse
from pathlib import Path


SHARED_FILE_PATTERN = re.compile(r"^(?:>\s*)?([0-9a-fA-F]{32})\s+(.+)$")


def _config_path(path: Path) -> str:
    """Returns a Windows path escaped for wxFileConfig."""

    return str(path.resolve()).replace("\\", "\\\\")


def configure_profile(
    *,
    config_dir: Path,
    incoming_dir: Path,
    temp_dir: Path,
    shared_dir: Path,
    nick: str,
    tcp_port: int,
    udp_port: int,
    ec_port: int,
    ec_password: str,
) -> None:
    """Writes the minimal deterministic profile consumed by official `amuled`."""

    for directory in (config_dir, incoming_dir, temp_dir, shared_dir):
        directory.mkdir(parents=True, exist_ok=True)
    password_hash = hashlib.md5(ec_password.encode("utf-8"), usedforsecurity=False).hexdigest()
    config = f"""[eMule]
Nick={nick}
MaxUpload=0
MaxDownload=0
Port={tcp_port}
UDPPort={udp_port}
UDPEnable=1
Address=
NetworkInterface=
Autoconnect=1
Reconnect=0
Serverlist=0
AddServerListFromServer=0
AddServerListFromClient=0
SafeServerConnect=0
AutoConnectStaticOnly=0
UPnPEnabled=0
ConnectToKad=0
ConnectToED2K=1
TempDir={_config_path(temp_dir)}
IncomingDir={_config_path(incoming_dir)}
CheckDiskspace=0
FirstRunWizardDone=1
GeoIPEnabled=0
GeoIPAutoUpdate=0
FilterLanIPs=0
ParanoidFiltering=0
IPFilterAutoLoad=0
IPFilterSystem=0
AutoRescanSharedDirs=0
[ExternalConnect]
AcceptExternalConnections=1
RequireEncryption=0
ECAddress=127.0.0.1
ECNetworkInterface=
ECPort={ec_port}
ECPassword={password_hash}
UPnPECEnabled=0
AuthFailureWindowSeconds=60
AuthFailureThreshold=10
AuthLockoutSeconds=30
[Obfuscation]
IsClientCryptLayerSupported=1
IsCryptLayerRequested=1
IsClientCryptLayerRequired=0
CryptoPaddingLenght=254
"""
    (config_dir / "amule.conf").write_text(config, encoding="utf-8", newline="\n")
    shared_path = f"{shared_dir.resolve()}\n"
    for name in ("shareddir.dat", "shareddir-explicit.dat"):
        (config_dir / name).write_text(shared_path, encoding="utf-8", newline="\n")
    (config_dir / "shareddir-recursive.dat").write_text("", encoding="utf-8")


def profile_snapshot(config_dir: Path) -> dict[str, object]:
    """Returns non-secret aMule profile settings for retained evidence."""

    values: dict[str, str] = {}
    section = ""
    for raw_line in (config_dir / "amule.conf").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if (section, key) in {
            ("eMule", "Nick"),
            ("eMule", "Port"),
            ("eMule", "UDPPort"),
            ("eMule", "Address"),
            ("eMule", "Autoconnect"),
            ("eMule", "ConnectToKad"),
            ("eMule", "ConnectToED2K"),
            ("eMule", "IncomingDir"),
            ("eMule", "TempDir"),
            ("ExternalConnect", "ECAddress"),
            ("ExternalConnect", "ECPort"),
        }:
            values[f"{section}.{key}"] = value
    return values


def launch_daemon(daemon_exe: Path, config_dir: Path) -> subprocess.Popen:
    """Launches `amuled` in the foreground with an isolated config directory."""

    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    return subprocess.Popen(
        [str(daemon_exe), f"--config-dir={config_dir.resolve()}"],
        cwd=daemon_exe.parent,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )


def run_command(
    control_exe: Path,
    *,
    ec_port: int,
    ec_password: str,
    command: str,
    timeout_seconds: float = 15.0,
) -> str:
    """Runs one non-interactive `amulecmd` command and returns its output."""

    completed = subprocess.run(
        [
            str(control_exe),
            "--host=127.0.0.1",
            f"--port={ec_port}",
            f"--password={ec_password}",
            f"--command={command}",
        ],
        cwd=control_exe.parent,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        output = (completed.stdout + completed.stderr).strip()
        raise RuntimeError(f"amulecmd {command!r} failed with exit code {completed.returncode}: {output}")
    return completed.stdout


def wait_for_control(
    control_exe: Path,
    *,
    ec_port: int,
    ec_password: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until the daemon accepts authenticated EC commands."""

    deadline = time.monotonic() + timeout_seconds
    observations: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        try:
            output = run_command(control_exe, ec_port=ec_port, ec_password=ec_password, command="status")
            return {"ready": True, "output": output, "observations": observations[-20:]}
        except Exception as exc:
            observations.append({"type": type(exc).__name__, "message": str(exc), "observed_at": round(time.time(), 3)})
            time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for aMule EC control. Observations: {observations[-20:]!r}")


def shared_file_hash(output: str, file_name: str) -> str | None:
    """Extracts one exact shared-file hash from `amulecmd show shared` output."""

    matches = []
    for line in output.splitlines():
        match = SHARED_FILE_PATTERN.match(line.strip())
        reported_name = match.group(2).strip().replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] if match else ""
        if match and reported_name.casefold() == file_name.casefold():
            matches.append(match.group(1).lower())
    if len(matches) > 1:
        raise RuntimeError(f"aMule reported duplicate shared rows for {file_name!r}: {matches!r}")
    return matches[0] if matches else None


def wait_for_shared_file_hash(
    control_exe: Path,
    *,
    ec_port: int,
    ec_password: str,
    file_name: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until aMule's EC shared-file view contains the fixture."""

    deadline = time.monotonic() + timeout_seconds
    observations: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        try:
            output = run_command(control_exe, ec_port=ec_port, ec_password=ec_password, command="show shared")
            file_hash = shared_file_hash(output, file_name)
            observations.append({"hash": file_hash, "observed_at": round(time.time(), 3)})
            if file_hash:
                return {"hash": file_hash, "observations": observations[-20:]}
        except Exception as exc:
            observations.append({"type": type(exc).__name__, "message": str(exc), "observed_at": round(time.time(), 3)})
        time.sleep(1.0)
    raise RuntimeError(f"Timed out waiting for aMule shared file {file_name!r}. Observations: {observations[-20:]!r}")


def shutdown_daemon(
    process: subprocess.Popen,
    control_exe: Path,
    *,
    ec_port: int,
    ec_password: str,
    timeout_seconds: float = 30.0,
) -> dict[str, object]:
    """Requests a clean EC shutdown and bounds the process teardown."""

    if process.poll() is not None:
        return {"already_exited": True, "return_code": process.returncode}
    output = run_command(control_exe, ec_port=ec_port, ec_password=ec_password, command="shutdown")
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            return_code = process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            return_code = process.wait(timeout=5.0)
        raise RuntimeError(f"aMule did not exit after EC shutdown; forced return code {return_code}")
    return {"already_exited": False, "return_code": return_code, "output": output}


def file_link(file_name: str, size_bytes: int, ed2k_hash: str) -> str:
    """Builds a canonical eD2K file link from aMule's EC hash observation."""

    encoded_name = urllib.parse.quote(file_name, safe="")
    return f"ed2k://|file|{encoded_name}|{size_bytes}|{ed2k_hash.upper()}|/"
