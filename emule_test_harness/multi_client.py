"""Windows multi-client descriptors for deterministic P2P live tests."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


CLIENT01_EMULEBB = "client01-emulebb"
CLIENT02_HARNESS = "client02-harness"
CLIENT03_EMULEAI = "client03-emuleai"
CLIENT04_AMULE = "client04-amule"

NICK_CLIENT01_EMULEBB = "cl-emulebb-001"
NICK_CLIENT02_HARNESS = "cl-harness-002"
NICK_CLIENT03_EMULEAI = "cl-emuleai-003"
NICK_CLIENT04_AMULE = "cl-amule-004"


@dataclass(frozen=True)
class ClientIdentity:
    """Stable identity used for profile names, reports, and P2P-visible nicknames."""

    key: str
    profile_id: str
    nick: str
    product: str
    role: str


@dataclass(frozen=True)
class ClientAvailability:
    """Describes whether one optional client can be used by a live scenario."""

    identity: ClientIdentity
    available: bool
    executable: Path | None
    reason: str
    control_executable: Path | None = None

    def as_report(self) -> dict[str, object]:
        """Returns a JSON-serializable availability row."""

        row: dict[str, object] = {
            "key": self.identity.key,
            "profile_id": self.identity.profile_id,
            "nick": self.identity.nick,
            "product": self.identity.product,
            "role": self.identity.role,
            "available": self.available,
            "reason": self.reason,
            "executable": str(self.executable) if self.executable is not None else None,
        }
        if self.control_executable is not None:
            row["control_executable"] = str(self.control_executable)
        return row


CLIENT_IDENTITIES = {
    "emulebb": ClientIdentity(
        key="emulebb",
        profile_id=CLIENT01_EMULEBB,
        nick=NICK_CLIENT01_EMULEBB,
        product="eMule BB",
        role="primary eMule BB client",
    ),
    "harness": ClientIdentity(
        key="harness",
        profile_id=CLIENT02_HARNESS,
        nick=NICK_CLIENT02_HARNESS,
        product="eMule community tracing harness",
        role="deterministic parity seed client",
    ),
    "emuleai": ClientIdentity(
        key="emuleai",
        profile_id=CLIENT03_EMULEAI,
        nick=NICK_CLIENT03_EMULEAI,
        product="eMuleAI",
        role="optional Windows eMule-family comparison client",
    ),
    "amule": ClientIdentity(
        key="amule",
        profile_id=CLIENT04_AMULE,
        nick=NICK_CLIENT04_AMULE,
        product="aMule",
        role="optional Windows aMule daemon/control comparison client",
    ),
}


def workspace_parent_root(workspace_root: Path) -> Path:
    """Returns the root that owns `repos`, `workspaces`, `analysis`, and `state`."""

    override = os.environ.get("EMULE_WORKSPACE_ROOT")
    if override:
        return Path(override).resolve()
    resolved = workspace_root.resolve()
    if resolved.name.lower() == "workspace" and resolved.parent.name.lower() == "workspaces":
        return resolved.parent.parent
    return resolved


def analysis_root(workspace_root: Path, name: str) -> Path:
    """Returns the materialized analysis checkout path for one optional client."""

    return workspace_parent_root(workspace_root) / "analysis" / name


def first_existing_file(candidates: list[Path]) -> Path | None:
    """Returns the first existing candidate file in priority order."""

    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_file():
            return resolved
    return None


def resolve_emulebb_client(app_exe: Path) -> ClientAvailability:
    """Builds the mandatory eMule BB client descriptor from the active app executable."""

    identity = CLIENT_IDENTITIES["emulebb"]
    resolved = app_exe.resolve()
    return ClientAvailability(
        identity=identity,
        available=resolved.is_file(),
        executable=resolved if resolved.is_file() else None,
        reason="available" if resolved.is_file() else f"missing executable: {resolved}",
    )


def resolve_harness_client(workspace_root: Path, configuration: str, override: str | None = None) -> ClientAvailability:
    """Resolves the mandatory tracing-harness executable used as the deterministic seed."""

    identity = CLIENT_IDENTITIES["harness"]
    if override:
        candidate = Path(override).resolve()
    else:
        candidate = (
            workspace_root
            / "app"
            / "eMule-community-tracing-harness"
            / "srchybrid"
            / "x64"
            / configuration
            / "emule.exe"
        ).resolve()
    return ClientAvailability(
        identity=identity,
        available=candidate.is_file(),
        executable=candidate if candidate.is_file() else None,
        reason="available" if candidate.is_file() else f"missing executable: {candidate}",
    )


def resolve_emuleai_client(workspace_root: Path, configuration: str, override: str | None = None) -> ClientAvailability:
    """Resolves an optional Windows eMuleAI executable if it has already been built."""

    identity = CLIENT_IDENTITIES["emuleai"]
    root = analysis_root(workspace_root, "emuleai")
    candidates = [Path(override)] if override else [
        root / "x64" / configuration / "eMuleAI.exe",
        root / "srchybrid" / "x64" / configuration / "eMuleAI.exe",
        root / "srchybrid" / "x64" / configuration / "emule.exe",
        root / configuration / "eMuleAI.exe",
    ]
    executable = first_existing_file(candidates)
    return ClientAvailability(
        identity=identity,
        available=executable is not None,
        executable=executable,
        reason="available" if executable is not None else f"no built eMuleAI executable found under {root}",
    )


def resolve_amule_client(
    workspace_root: Path,
    override_daemon: str | None = None,
    override_control: str | None = None,
) -> ClientAvailability:
    """Resolves optional Windows aMule daemon and command binaries when present."""

    identity = CLIENT_IDENTITIES["amule"]
    root = analysis_root(workspace_root, "amule")
    daemon_candidates = [Path(override_daemon)] if override_daemon else [
        workspace_parent_root(workspace_root) / "state" / "tools" / "amule" / "bin" / "amuled.exe",
        root / "packaging" / "windows" / "dist" / "bin" / "amuled.exe",
        root / "build" / "bin" / "amuled.exe",
        root / "bin" / "amuled.exe",
    ]
    control_candidates = [Path(override_control)] if override_control else [
        workspace_parent_root(workspace_root) / "state" / "tools" / "amule" / "bin" / "amulecmd.exe",
        root / "packaging" / "windows" / "dist" / "bin" / "amulecmd.exe",
        root / "build" / "bin" / "amulecmd.exe",
        root / "bin" / "amulecmd.exe",
    ]
    daemon = first_existing_file(daemon_candidates)
    control = first_existing_file(control_candidates)
    available = daemon is not None and control is not None
    if available:
        reason = "available"
    elif daemon is None and control is None:
        reason = f"no built aMule daemon/control binaries found under {root} or workspace state"
    elif daemon is None:
        reason = "missing amuled.exe"
    else:
        reason = "missing amulecmd.exe"
    return ClientAvailability(
        identity=identity,
        available=available,
        executable=daemon,
        control_executable=control,
        reason=reason,
    )


def resolve_windows_client_inventory(
    *,
    workspace_root: Path,
    app_exe: Path,
    configuration: str,
    harness_exe: str | None = None,
    emuleai_exe: str | None = None,
    amule_daemon_exe: str | None = None,
    amule_control_exe: str | None = None,
) -> dict[str, ClientAvailability]:
    """Resolves the current Windows multi-client inventory for live E2E scenarios."""

    return {
        "emulebb": resolve_emulebb_client(app_exe),
        "harness": resolve_harness_client(workspace_root, configuration, harness_exe),
        "emuleai": resolve_emuleai_client(workspace_root, configuration, emuleai_exe),
        "amule": resolve_amule_client(workspace_root, amule_daemon_exe, amule_control_exe),
    }
