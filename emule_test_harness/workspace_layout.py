"""Canonical workspace-layout helpers for the shared test harness."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

WORKSPACE_NAME = "v0.72a"
DEFAULT_APP_VARIANTS = ("community", "main", "broadband")


@dataclass(frozen=True)
class AppVariant:
    """One app worktree entry parsed from a workspace manifest."""

    name: str
    path: Path


@dataclass(frozen=True)
class WorkspaceManifest:
    """Minimal app-root data consumed from `deps.psd1`."""

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
    """Parses the app-root subset of the generated workspace `deps.psd1` file."""

    manifest_path = workspace_root.resolve() / "deps.psd1"
    if not manifest_path.is_file():
        return WorkspaceManifest(seed_repo_path=None, variants=())

    text = manifest_path.read_text(encoding="utf-8")
    seed_repo_path = _parse_seed_repo_path(text)
    variants = tuple(
        AppVariant(name=name, path=Path(raw_path))
        for name, raw_path in _parse_variant_entries(text)
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

    raise RuntimeError(f"Unable to resolve a canonical app root from '{resolved_workspace_root / 'deps.psd1'}'.")


def _parse_seed_repo_path(text: str) -> str | None:
    """Extracts `Workspace.AppRepo.SeedRepo.Path` from the generated manifest text."""

    seed_match = re.search(r"SeedRepo\s*=\s*@\{(?P<body>.*?)^\s*\}", text, flags=re.DOTALL | re.MULTILINE)
    if not seed_match:
        return None
    path_match = re.search(r"\bPath\s*=\s*(['\"])(?P<path>.*?)\1", seed_match.group("body"))
    return path_match.group("path") if path_match else None


def _parse_variant_entries(text: str) -> list[tuple[str, str]]:
    """Extracts one-line variant `Name` and `Path` entries from the manifest text."""

    entries: list[tuple[str, str]] = []
    pattern = re.compile(
        r"@\{\s*Name\s*=\s*(['\"])(?P<name>.*?)\1\s*;\s*Path\s*=\s*(['\"])(?P<path>.*?)\3\s*;",
        flags=re.DOTALL,
    )
    for match in pattern.finditer(text):
        entries.append((match.group("name"), match.group("path")))
    return entries
