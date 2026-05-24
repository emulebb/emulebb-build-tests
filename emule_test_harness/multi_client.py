"""Windows multi-client descriptors for deterministic P2P live tests."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


CLIENT01_EMULEBB = "cl-emulebb-001"
CLIENT02_HARNESS = "cl-harness-002"
CLIENT03_EMULEAI = "cl-emuleai-003"
CLIENT04_AMULE = "cl-amule-004"

NICK_CLIENT01_EMULEBB = "cl-emulebb-001"
NICK_CLIENT02_HARNESS = "cl-harness-002"
NICK_CLIENT03_EMULEAI = "cl-emuleai-003"
NICK_CLIENT04_AMULE = "cl-amule-004"


@dataclass(frozen=True)
class ClientIdentity:
    """Stable identity used for profile directories, reports, and P2P-visible nicknames."""

    key: str
    profile_id: str
    nick: str
    product: str
    role: str
    supports_long_paths: bool


@dataclass(frozen=True)
class ClientAvailability:
    """Describes whether one optional client can be used by a live scenario."""

    identity: ClientIdentity
    available: bool
    executable: Path | None
    reason: str
    launch_adapter: str = ""
    deterministic_transfer_adapter: bool = False
    control_executable: Path | None = None

    def as_report(self) -> dict[str, object]:
        """Returns a JSON-serializable availability row."""

        row: dict[str, object] = {
            "key": self.identity.key,
            "profile_id": self.identity.profile_id,
            "nick": self.identity.nick,
            "product": self.identity.product,
            "role": self.identity.role,
            "supports_long_paths": self.identity.supports_long_paths,
            "available": self.available,
            "reason": self.reason,
            "executable": str(self.executable) if self.executable is not None else None,
            "launch_adapter": self.launch_adapter,
            "deterministic_transfer_adapter": self.deterministic_transfer_adapter,
        }
        if self.control_executable is not None:
            row["control_executable"] = str(self.control_executable)
        return row


CLIENT_IDENTITIES = {
    "emulebb": ClientIdentity(
        key="emulebb",
        profile_id=CLIENT01_EMULEBB,
        nick=NICK_CLIENT01_EMULEBB,
        product="eMuleBB",
        role="primary eMuleBB client",
        supports_long_paths=True,
    ),
    "harness": ClientIdentity(
        key="harness",
        profile_id=CLIENT02_HARNESS,
        nick=NICK_CLIENT02_HARNESS,
        product="eMule community tracing harness",
        role="deterministic parity seed client",
        supports_long_paths=False,
    ),
    "emuleai": ClientIdentity(
        key="emuleai",
        profile_id=CLIENT03_EMULEAI,
        nick=NICK_CLIENT03_EMULEAI,
        product="eMuleAI",
        role="optional Windows eMule-family comparison client",
        supports_long_paths=False,
    ),
    "amule": ClientIdentity(
        key="amule",
        profile_id=CLIENT04_AMULE,
        nick=NICK_CLIENT04_AMULE,
        product="aMule",
        role="optional Windows aMule daemon/control comparison client",
        supports_long_paths=False,
    ),
}


def long_path_capability_report(client_keys: tuple[str, ...] | list[str]) -> dict[str, dict[str, object]]:
    """Returns long-path capability metadata for the selected deterministic clients."""

    report: dict[str, dict[str, object]] = {}
    for key in client_keys:
        identity = CLIENT_IDENTITIES[key]
        report[key] = {
            "profile_id": identity.profile_id,
            "product": identity.product,
            "supports_long_paths": identity.supports_long_paths,
        }
    return report


def workspace_parent_root(workspace_root: Path) -> Path:
    """Returns the root that owns `repos`, `workspaces`, `analysis`, and `state`."""

    override = os.environ.get("EMULE_WORKSPACE_ROOT")
    if override:
        return Path(override).resolve()
    resolved = workspace_root.resolve()
    if resolved.name.lower() == "workspace" and resolved.parent.name.lower() == "workspaces":
        return resolved.parent.parent
    return resolved


def workspace_manifest_path(workspace_root: Path) -> Path:
    """Returns the generated workspace manifest path."""

    return workspace_root.resolve() / "deps.json"


def resolve_manifest_repo(workspace_root: Path, repo_key: str) -> Path:
    """Resolves one repo path from the generated workspace manifest."""

    manifest_path = workspace_manifest_path(workspace_root)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    repos = payload.get("workspace", {}).get("repos", {})
    value = repos.get(repo_key)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"Workspace manifest does not define workspace.repos.{repo_key}.")
    return (manifest_path.parent / value).resolve()


def unavailable_manifest_client(
    identity: ClientIdentity,
    repo_key: str,
    adapter: str,
    exc: Exception,
) -> ClientAvailability:
    """Builds an unavailable optional-client row when the workspace manifest cannot resolve it."""

    return ClientAvailability(
        identity=identity,
        available=False,
        executable=None,
        reason=f"workspace manifest repo '{repo_key}' is unavailable: {exc}",
        launch_adapter=adapter,
        deterministic_transfer_adapter=False,
    )


def first_existing_file(candidates: list[Path]) -> Path | None:
    """Returns the first existing candidate file in priority order."""

    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_file():
            return resolved
    return None


def resolve_emulebb_client(app_exe: Path) -> ClientAvailability:
    """Builds the mandatory eMuleBB client descriptor from the active app executable."""

    identity = CLIENT_IDENTITIES["emulebb"]
    resolved = app_exe.resolve()
    return ClientAvailability(
        identity=identity,
        available=resolved.is_file(),
        executable=resolved if resolved.is_file() else None,
        reason="available" if resolved.is_file() else f"missing executable: {resolved}",
        launch_adapter="emule-gui-profile",
        deterministic_transfer_adapter=True,
    )


def resolve_harness_client(workspace_root: Path, configuration: str, override: str | None = None) -> ClientAvailability:
    """Resolves the mandatory tracing-harness executable used as the deterministic seed."""

    identity = CLIENT_IDENTITIES["harness"]
    if override:
        executable = first_existing_file([Path(override)])
    else:
        base_dir = (
            workspace_root
            / "app"
            / "emulebb-community-tracing-harness"
            / "srchybrid"
            / "x64"
            / configuration
        )
        executable = first_existing_file([base_dir / "emule.exe", base_dir / "emulebb.exe"])
    reason = "available" if executable is not None else "missing tracing-harness executable"
    return ClientAvailability(
        identity=identity,
        available=executable is not None,
        executable=executable,
        reason=reason if executable is not None else f"{reason} under {workspace_root / 'app' / 'emulebb-community-tracing-harness'}",
        launch_adapter="tracing-harness-gui-profile",
        deterministic_transfer_adapter=True,
    )


def resolve_emuleai_client(workspace_root: Path, configuration: str, override: str | None = None) -> ClientAvailability:
    """Resolves an optional Windows eMuleAI executable if it has already been built."""

    identity = CLIENT_IDENTITIES["emuleai"]
    try:
        root = resolve_manifest_repo(workspace_root, "emuleai")
    except (OSError, json.JSONDecodeError, RuntimeError) as exc:
        return unavailable_manifest_client(identity, "emuleai", "emuleai-gui-profile", exc)
    candidates = [Path(override)] if override else [
        root / "_Build" / "eMuleAI" / configuration / "x64" / "eMuleAI.exe",
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
        launch_adapter="emuleai-gui-profile",
        deterministic_transfer_adapter=False,
    )


def resolve_amule_client(
    workspace_root: Path,
    override_daemon: str | None = None,
    override_control: str | None = None,
) -> ClientAvailability:
    """Resolves optional Windows aMule daemon and command binaries when present."""

    identity = CLIENT_IDENTITIES["amule"]
    try:
        root = resolve_manifest_repo(workspace_root, "amule")
    except (OSError, json.JSONDecodeError, RuntimeError) as exc:
        return unavailable_manifest_client(identity, "amule", "amuled-amulecmd", exc)
    daemon_candidates = [Path(override_daemon)] if override_daemon else [
        workspace_root.resolve() / "state" / "tools" / "amule" / "bin" / "amuled.exe",
        root / "packaging" / "windows" / "dist" / "bin" / "amuled.exe",
        root / "build" / "bin" / "amuled.exe",
        root / "bin" / "amuled.exe",
    ]
    control_candidates = [Path(override_control)] if override_control else [
        workspace_root.resolve() / "state" / "tools" / "amule" / "bin" / "amulecmd.exe",
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
        launch_adapter="amuled-amulecmd",
        deterministic_transfer_adapter=available,
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
