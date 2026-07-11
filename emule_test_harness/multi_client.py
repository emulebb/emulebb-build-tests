"""Windows multi-client descriptors for deterministic P2P live tests."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

CLIENT01_EMULEBB = "cl-emulebb-001"
CLIENT02_HARNESS = "cl-harness-002"
CLIENT03_EMULEAI = "cl-emuleai-003"
CLIENT05_EMULEBB_RUST_A = "cl-emulebb-rust-005"
CLIENT06_EMULEBB_RUST_B = "cl-emulebb-rust-006"

NICK_CLIENT01_EMULEBB = "cl-emulebb-001"
NICK_CLIENT02_HARNESS = "cl-harness-002"
NICK_CLIENT03_EMULEAI = "cl-emuleai-003"
NICK_CLIENT05_EMULEBB_RUST_A = "cl-emulebb-rust-005"
NICK_CLIENT06_EMULEBB_RUST_B = "cl-emulebb-rust-006"


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
        product="eMuleBB MFC",
        role="MFC parity peer client",
        supports_long_paths=True,
    ),
    "emuleai": ClientIdentity(
        key="emuleai",
        profile_id=CLIENT03_EMULEAI,
        nick=NICK_CLIENT03_EMULEAI,
        product="eMuleAI",
        role="optional Windows eMule-family comparison client",
        supports_long_paths=False,
    ),
    "emulebb_rust": ClientIdentity(
        key="emulebb_rust",
        profile_id=CLIENT05_EMULEBB_RUST_A,
        nick=NICK_CLIENT05_EMULEBB_RUST_A,
        product="eMuleBB Rust",
        role="headless Rust eMuleBB-compatible client",
        # Long-path capable, scoped to operator content path classes only:
        # shared-directory trees, incoming downloads, and category paths
        # (longPathAware manifest + verbatim \\?\ helper). Config/logs/DB and
        # the internal hash-named piece store stay short-path by design.
        supports_long_paths=True,
    ),
    "emulebb_rust_peer": ClientIdentity(
        key="emulebb_rust_peer",
        profile_id=CLIENT06_EMULEBB_RUST_B,
        nick=NICK_CLIENT06_EMULEBB_RUST_B,
        product="eMuleBB Rust",
        role="second headless Rust eMuleBB-compatible client",
        # Long-path capable (scoped, see emulebb_rust above).
        supports_long_paths=True,
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
    """Returns the root that owns `repos`, `workspaces`, and `analysis`."""

    override = os.environ.get("EMULEBB_WORKSPACE_ROOT")
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
    """Resolves the MFC parity peer executable.

    The historical key stays `harness` for report/profile compatibility, but
    current parity tests use the active emulebb-main worktree instead of the
    retired tracing-harness worktree.
    """

    identity = CLIENT_IDENTITIES["harness"]
    if override:
        executable = first_existing_file([Path(override)])
    else:
        base_dir = (
            workspace_root
            / "app"
            / "emulebb-main"
            / "srchybrid"
            / "x64"
            / configuration
        )
        executable = first_existing_file([base_dir / "emulebb.exe", base_dir / "emule.exe"])
    reason = "available" if executable is not None else "missing eMuleBB main executable"
    return ClientAvailability(
        identity=identity,
        available=executable is not None,
        executable=executable,
        reason=reason if executable is not None else f"{reason} under {workspace_root / 'app' / 'emulebb-main'}",
        launch_adapter="emulebb-main-rest-profile",
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


def resolve_emulebb_rust_client(
    workspace_root: Path,
    repo_key: str = "emulebb_rust",
    identity_key: str = "emulebb_rust",
) -> ClientAvailability:
    """Resolves the Rust client repository used by the orchestrated local swarm adapter."""

    identity = CLIENT_IDENTITIES[identity_key]
    try:
        root = resolve_manifest_repo(workspace_root, repo_key)
    except (OSError, json.JSONDecodeError, RuntimeError) as exc:
        return unavailable_manifest_client(identity, repo_key, "emule-workspace-python-test", exc)
    manifest = root / "Cargo.toml"
    available = manifest.is_file()
    return ClientAvailability(
        identity=identity,
        available=available,
        executable=manifest if available else None,
        reason="available" if available else f"missing Cargo.toml under {root}",
        launch_adapter="emule-workspace-python-test",
        deterministic_transfer_adapter=available,
    )


def resolve_windows_client_inventory(
    *,
    workspace_root: Path,
    app_exe: Path,
    configuration: str,
    harness_exe: str | None = None,
    emuleai_exe: str | None = None,
) -> dict[str, ClientAvailability]:
    """Resolves the current Windows multi-client inventory for live E2E scenarios."""

    return {
        "emulebb": resolve_emulebb_client(app_exe),
        "harness": resolve_harness_client(workspace_root, configuration, harness_exe),
        "emuleai": resolve_emuleai_client(workspace_root, configuration, emuleai_exe),
        "emulebb_rust": resolve_emulebb_rust_client(workspace_root),
        "emulebb_rust_peer": resolve_emulebb_rust_client(workspace_root, identity_key="emulebb_rust_peer"),
    }
