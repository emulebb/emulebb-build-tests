"""Canonical workspace-layout helpers for the shared test harness."""

from __future__ import annotations

import os
import json
from dataclasses import dataclass
from pathlib import Path

WORKSPACE_NAME = "workspace"
DEFAULT_APP_VARIANTS = ("community", "main", "tracing-harness")


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


def get_emule_workspace_root(test_repo_root: Path) -> Path:
    """Returns the canonical eMule workspace root that owns `repos` and `workspaces`."""

    override = os.environ.get("EMULE_WORKSPACE_ROOT")
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
        return WorkspaceManifest(seed_repo_path=None, variants=())

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    workspace = payload.get("workspace", {})
    app_repo = workspace.get("app_repo", {})
    seed_repo = app_repo.get("seed_repo", {})
    seed_repo_path = seed_repo.get("path")
    variants = tuple(
        AppVariant(name=str(raw["name"]), path=Path(str(raw["path"])))
        for raw in app_repo.get("variants", [])
    )
    return WorkspaceManifest(seed_repo_path=Path(seed_repo_path) if seed_repo_path else None, variants=variants)


def resolve_workspace_app_root(
    workspace_root: Path,
    *,
    preferred_variant_names: tuple[str, ...] = DEFAULT_APP_VARIANTS,
) -> Path:
    """Resolves the canonical app root from the generated workspace manifest."""

    resolved_workspace_root = workspace_root.resolve()
    manifest = load_workspace_manifest(resolved_workspace_root)
    candidates: list[Path] = []
    if manifest.seed_repo_path is not None:
        candidates.append(resolved_workspace_root / manifest.seed_repo_path)

    variants_by_name: dict[str, list[AppVariant]] = {}
    for variant in manifest.variants:
        variants_by_name.setdefault(variant.name, []).append(variant)

    for preferred_name in preferred_variant_names:
        for variant in variants_by_name.get(preferred_name, []):
            candidates.append(resolved_workspace_root / variant.path)

    for variant in manifest.variants:
        candidates.append(resolved_workspace_root / variant.path)

    seen: set[Path] = set()
    for candidate in candidates:
        resolved_candidate = candidate.resolve()
        if resolved_candidate in seen:
            continue
        seen.add(resolved_candidate)
        if resolved_candidate.is_dir():
            return resolved_candidate

    raise RuntimeError(f"Unable to resolve a canonical app root from '{resolved_workspace_root / 'deps.json'}'.")
