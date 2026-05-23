"""Shared product-family helpers for eMuleBB-adjacent repos."""

from __future__ import annotations

from pathlib import Path

from emule_test_harness.workspace_layout import resolve_workspace_repo

P2P_OVERLORD_REPO_KEYS = ("p2p_overlord_agents", "p2p_overlord_be")
REST_OPENAPI_RELATIVE_PATH = Path("docs") / "rest" / "REST-API-OPENAPI.yaml"


def resolve_p2p_overlord_repos(workspace_root: Path) -> dict[str, Path]:
    """Resolves first-class p2p-overlord product-family repo roots."""

    return {repo_key: resolve_workspace_repo(workspace_root, repo_key) for repo_key in P2P_OVERLORD_REPO_KEYS}


def resolve_canonical_rest_openapi(workspace_root: Path) -> Path:
    """Resolves the canonical eMuleBB REST OpenAPI contract path."""

    return resolve_workspace_repo(workspace_root, "tooling") / REST_OPENAPI_RELATIVE_PATH
