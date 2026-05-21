"""Admin-only Windows volume fixtures for live E2E storage proofs."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import ctypes
import os
from pathlib import Path
import shutil
import subprocess
import time


class AdminVolumeFixtureError(RuntimeError):
    """Raised when an admin volume fixture cannot be provisioned safely."""


@dataclass(frozen=True)
class CommandResult:
    """Captured result from one fixture provisioning command."""

    command: list[str]
    return_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class VolumeIdentity:
    """Stable identity details for one mounted Windows volume root."""

    root: str
    volume_name: str | None
    serial_hex: str | None
    file_system: str | None
    label: str | None
    total_bytes: int
    free_bytes: int


@dataclass(frozen=True)
class AdminVolumeFixtureConfig:
    """Inputs used to create one VHD-backed drive and folder mount fixture."""

    vhd_path: Path
    mount_root: Path
    local_control_root: Path
    size_mb: int
    drive_letter: str | None = None
    keep: bool = False


@dataclass(frozen=True)
class AdminVolumeFixture:
    """Resolved roots and identities for one admin storage fixture."""

    vhd_path: Path
    drive_root: Path
    mount_root: Path
    local_control_root: Path
    drive_identity: VolumeIdentity
    mount_identity: VolumeIdentity
    local_control_identity: VolumeIdentity
    create_result: CommandResult


def require_windows_admin() -> None:
    """Raises when the current process cannot create Windows volume fixtures."""

    if os.name != "nt":
        raise AdminVolumeFixtureError("Admin volume fixtures require Windows.")
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as exc:  # pragma: no cover - platform dependent
        raise AdminVolumeFixtureError(f"Unable to determine whether the process is elevated: {exc}") from exc
    if not is_admin:
        raise AdminVolumeFixtureError("Admin volume fixtures require an elevated shell.")


def normalize_drive_letter(letter: str) -> str:
    """Returns an uppercase bare drive letter."""

    normalized = letter.strip().rstrip(":\\/")
    if len(normalized) != 1 or not normalized.isalpha():
        raise ValueError(f"Invalid drive letter: {letter!r}")
    return normalized.upper()


def find_available_drive_letter(preferred: str | None = None) -> str:
    """Returns an available Windows drive letter, honoring a preferred letter when possible."""

    candidates = [normalize_drive_letter(preferred)] if preferred else []
    candidates.extend(letter for letter in "ZYXWVUTSRQPONMLKJIHGFED" if letter not in candidates)
    for letter in candidates:
        if not Path(f"{letter}:\\").exists():
            return letter
    raise AdminVolumeFixtureError("No available drive letter was found for the admin volume fixture.")


def quote_diskpart_path(path: Path) -> str:
    """Returns a diskpart-safe quoted path token."""

    return f'"{path.resolve()}"'


def build_create_vhd_diskpart_script(*, vhd_path: Path, size_mb: int, drive_letter: str, mount_root: Path) -> str:
    """Builds the diskpart script that creates and mounts one test VHD."""

    if size_mb <= 0:
        raise ValueError("VHD size must be greater than zero.")
    letter = normalize_drive_letter(drive_letter)
    return "\n".join(
        [
            f"create vdisk file={quote_diskpart_path(vhd_path)} maximum={size_mb} type=expandable",
            f"select vdisk file={quote_diskpart_path(vhd_path)}",
            "attach vdisk",
            "create partition primary",
            'format fs=ntfs label="EMULEBB_TEST" quick',
            f"assign letter={letter}",
            f"assign mount={quote_diskpart_path(mount_root)}",
            "",
        ]
    )


def build_cleanup_vhd_diskpart_script(*, vhd_path: Path, drive_letter: str, mount_root: Path, delete_vdisk: bool) -> str:
    """Builds a best-effort diskpart cleanup script for one test VHD."""

    letter = normalize_drive_letter(drive_letter)
    lines = [
        f"select volume {letter}",
        f"remove mount={quote_diskpart_path(mount_root)} noerr",
        f"remove letter={letter} noerr",
        f"select vdisk file={quote_diskpart_path(vhd_path)}",
        "detach vdisk noerr",
    ]
    if delete_vdisk:
        lines.append("delete vdisk noerr")
    lines.append("")
    return "\n".join(lines)


def run_diskpart_script(script_text: str, script_dir: Path) -> CommandResult:
    """Runs one generated diskpart script from a workspace-owned artifact directory."""

    script_dir.mkdir(parents=True, exist_ok=True)
    script_path = script_dir / f"diskpart-{os.getpid()}-{time.time_ns()}.txt"
    script_path.write_text(script_text, encoding="utf-8")
    try:
        command = ["diskpart.exe", "/s", str(script_path)]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return CommandResult(command=command, return_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)
    finally:
        script_path.unlink(missing_ok=True)


def get_volume_identity(root: Path) -> VolumeIdentity:
    """Reads stable identity and capacity details for a mounted volume root."""

    usage = shutil.disk_usage(root)
    if os.name != "nt":
        return VolumeIdentity(
            root=str(root),
            volume_name=None,
            serial_hex=None,
            file_system=None,
            label=None,
            total_bytes=usage.total,
            free_bytes=usage.free,
        )

    root_text = str(root.resolve())
    if not root_text.endswith("\\"):
        root_text += "\\"
    volume_name_buffer = ctypes.create_unicode_buffer(256)
    label_buffer = ctypes.create_unicode_buffer(256)
    fs_buffer = ctypes.create_unicode_buffer(256)
    serial = ctypes.c_uint32()
    max_component = ctypes.c_uint32()
    flags = ctypes.c_uint32()
    volume_name = None
    serial_hex = None
    file_system = None
    label = None
    if ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(root_text, volume_name_buffer, len(volume_name_buffer)):
        volume_name = volume_name_buffer.value
    if ctypes.windll.kernel32.GetVolumeInformationW(
        root_text,
        label_buffer,
        len(label_buffer),
        ctypes.byref(serial),
        ctypes.byref(max_component),
        ctypes.byref(flags),
        fs_buffer,
        len(fs_buffer),
    ):
        serial_hex = f"{serial.value:08X}"
        file_system = fs_buffer.value
        label = label_buffer.value
    return VolumeIdentity(
        root=root_text,
        volume_name=volume_name,
        serial_hex=serial_hex,
        file_system=file_system,
        label=label,
        total_bytes=usage.total,
        free_bytes=usage.free,
    )


@contextmanager
def create_admin_volume_fixture(config: AdminVolumeFixtureConfig):
    """Creates one VHD drive-letter plus folder-mount fixture and cleans it up."""

    require_windows_admin()
    drive_letter = find_available_drive_letter(config.drive_letter)
    mount_root_preexisting = config.mount_root.exists()
    config.vhd_path.parent.mkdir(parents=True, exist_ok=True)
    config.mount_root.mkdir(parents=True, exist_ok=True)
    config.local_control_root.mkdir(parents=True, exist_ok=True)
    if config.vhd_path.exists():
        raise AdminVolumeFixtureError(f"Refusing to overwrite existing VHD: {config.vhd_path}")
    create_script = build_create_vhd_diskpart_script(
        vhd_path=config.vhd_path,
        size_mb=config.size_mb,
        drive_letter=drive_letter,
        mount_root=config.mount_root,
    )
    script_dir = config.vhd_path.parent / "diskpart-scripts"
    create_result = run_diskpart_script(create_script, script_dir)
    if create_result.return_code != 0:
        raise AdminVolumeFixtureError(f"diskpart failed while creating the test VHD: {create_result.stderr or create_result.stdout}")

    drive_root = Path(f"{drive_letter}:\\")
    try:
        fixture = AdminVolumeFixture(
            vhd_path=config.vhd_path,
            drive_root=drive_root,
            mount_root=config.mount_root,
            local_control_root=config.local_control_root,
            drive_identity=get_volume_identity(drive_root),
            mount_identity=get_volume_identity(config.mount_root),
            local_control_identity=get_volume_identity(config.local_control_root),
            create_result=create_result,
        )
        yield fixture
    finally:
        cleanup_script = build_cleanup_vhd_diskpart_script(
            vhd_path=config.vhd_path,
            drive_letter=drive_letter,
            mount_root=config.mount_root,
            delete_vdisk=not config.keep,
        )
        run_diskpart_script(cleanup_script, script_dir)
        if not config.keep:
            try:
                config.vhd_path.unlink(missing_ok=True)
            except OSError:
                pass
            if not mount_root_preexisting:
                try:
                    config.mount_root.rmdir()
                except OSError:
                    pass
