"""Canonical workspace-layout helpers for the shared test harness."""

from __future__ import annotations

import os
import json
import sys
from dataclasses import dataclass
from functools import cache
from pathlib import Path

WORKSPACE_NAME = "workspace"
DEFAULT_APP_VARIANTS = ("community", "main")


@dataclass(frozen=True)
class AppVariant:
    """One app worktree entry parsed from a workspace manifest."""

    name: str
    path: Path


@dataclass(frozen=True)
class WorkspaceManifest:
    """Minimal app-root data consumed from `deps.json`."""

    seed_repo_path: Path | None
    variants: tuple[AppVariant, ...]
    repos: dict[str, Path]


def get_emule_workspace_root(test_repo_root: Path) -> Path:
    """Returns the canonical eMule workspace root that owns `repos` and `workspaces`."""

    override = os.environ.get("EMULEBB_WORKSPACE_ROOT")
    if override:
        return Path(override).resolve()
    return (test_repo_root.resolve() / ".." / "..").resolve()


def get_default_workspace_root(test_repo_root: Path, workspace_name: str = WORKSPACE_NAME) -> Path:
    """Returns the default workspace root for a shared tests checkout."""

    return (get_emule_workspace_root(test_repo_root) / "workspaces" / workspace_name).resolve()


def load_workspace_manifest(workspace_root: Path) -> WorkspaceManifest:
    """Parses the app-root subset of the generated workspace `deps.json` file."""

    manifest_path = workspace_root.resolve() / "deps.json"
    if not manifest_path.is_file():
        return WorkspaceManifest(seed_repo_path=None, variants=(), repos={})

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    workspace = payload.get("workspace", {})
    app_repo = workspace.get("app_repo", {})
    seed_repo = app_repo.get("seed_repo", {})
    seed_repo_path = seed_repo.get("path")
    variants = tuple(
        AppVariant(name=str(raw["name"]), path=Path(str(raw["path"])))
        for raw in app_repo.get("variants", [])
    )
    repos = {
        str(key): Path(str(value))
        for key, value in workspace.get("repos", {}).items()
        if isinstance(value, str) and value
    }
    return WorkspaceManifest(seed_repo_path=Path(seed_repo_path) if seed_repo_path else None, variants=variants, repos=repos)


def resolve_workspace_repo(workspace_root: Path, repo_key: str) -> Path:
    """Resolves one repository path from the generated workspace manifest."""

    resolved_workspace_root = workspace_root.resolve()
    manifest = load_workspace_manifest(resolved_workspace_root)
    repo_path = manifest.repos.get(repo_key)
    if repo_path is None:
        raise RuntimeError(f"Workspace manifest does not define workspace.repos.{repo_key}.")
    return (resolved_workspace_root / repo_path).resolve()


def resolve_rust_openapi_contract() -> Path:
    """Select the explicit standalone contract or the verified workspace source."""
    explicit = os.environ.get("EMULEBB_REST_OPENAPI_CONTRACT_PATH")
    if explicit:
        return Path(explicit).resolve()
    tooling = resolve_selected_workspace_repo(Path(__file__).resolve().parents[1], "emulebb-tooling")
    return tooling / "docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml"


def resolve_selected_workspace_repo(test_repo_root: Path, repository: str) -> Path:
    """Resolve a companion through Builder topology and verified registration.

    Validation freezes these sources for one Python process. Cache by explicit
    workspace, output and caller identity, never by a global repository name.
    """
    from .paths import get_required_emule_workspace_root, get_workspace_output_root

    return _selected_workspace_repo(
        get_required_emule_workspace_root(), get_workspace_output_root(),
        test_repo_root.resolve(), repository,
    )


@cache
def _selected_workspace_repo(root: Path, output: Path, caller: Path, repository: str) -> Path:
    """Use the maintained Builder selector once for each frozen source identity."""
    builder = resolve_workspace_repo(root / "workspaces" / WORKSPACE_NAME, "build")
    # WHY: pytest runs from the harness checkout, so the topology-owned Builder
    # package is not on its import path. Import its API instead of duplicating
    # registration parsing or invoking another Python interpreter per fixture.
    sys.path.insert(0, str(builder))
    try:
        from emule_workspace import layout as builder_layout, workstreams
    finally:
        sys.path.pop(0)
    registration = workstreams.resolve_workstream(root, output, repo=caller)
    allowed_builders = {builder}
    if registration is not None:
        entry = registration.get("repositories", {}).get("emulebb-build")
        if entry is not None:
            allowed_builders.add(Path(entry["path"]).resolve())
    if not any(all(Path(module.__file__).resolve().is_relative_to(candidate)
                   for module in (builder_layout, workstreams)) for candidate in allowed_builders):
        raise RuntimeError("Loaded Builder API differs from workspace topology and registration")
    selected = builder_layout.load_layout(root, output_root=output)
    if registration is not None:
        selected = workstreams.apply_workstream_layout(selected, registration)
    if repository not in workstreams.REPOSITORY_FIELDS:
        raise ValueError(f"Unsupported workspace repository: {repository}")
    companion = getattr(selected, workstreams.REPOSITORY_FIELDS[repository])
    if companion is None:
        raise RuntimeError(f"Selected workspace does not define {repository}")
    return Path(companion).resolve()


def resolve_workspace_app_root(
    workspace_root: Path,
    *,
    preferred_variant_names: tuple[str, ...] = DEFAULT_APP_VARIANTS,
) -> Path:
    """Resolves the canonical app root from the generated workspace manifest."""

    resolved_workspace_root = workspace_root.resolve()
    manifest = load_workspace_manifest(resolved_workspace_root)
    candidates: list[Path] = []

    variants_by_name: dict[str, list[AppVariant]] = {}
    for variant in manifest.variants:
        variants_by_name.setdefault(variant.name, []).append(variant)

    for preferred_name in preferred_variant_names:
        for variant in variants_by_name.get(preferred_name, []):
            candidates.append(resolved_workspace_root / variant.path)

    for variant in manifest.variants:
        candidates.append(resolved_workspace_root / variant.path)

    if manifest.seed_repo_path is not None:
        candidates.append(resolved_workspace_root / manifest.seed_repo_path)

    # Fast hosted CI checks out only the app worktree, not the generated
    # workspace manifest. Keep that minimal layout usable for source-only tests.
    if not manifest.variants and manifest.seed_repo_path is None:
        candidates.append(resolved_workspace_root / "app" / "emulebb-main")

    seen: set[Path] = set()
    for candidate in candidates:
        resolved_candidate = candidate.resolve()
        if resolved_candidate in seen:
            continue
        seen.add(resolved_candidate)
        if resolved_candidate.is_dir():
            return resolved_candidate

    raise RuntimeError(f"Unable to resolve a canonical app root from '{resolved_workspace_root / 'deps.json'}'.")
