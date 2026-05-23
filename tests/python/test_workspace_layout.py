from __future__ import annotations

from pathlib import Path

from emule_test_harness.workspace_layout import (
    get_default_workspace_root,
    load_workspace_manifest,
    resolve_workspace_repo,
    resolve_workspace_app_root,
)


def test_default_roots_use_canonical_repo_layout(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("EMULE_WORKSPACE_ROOT", raising=False)
    test_repo_root = tmp_path / "repos" / "emulebb-build-tests"

    assert get_default_workspace_root(test_repo_root) == tmp_path / "workspaces" / "workspace"


def test_workspace_manifest_parser_reads_seed_and_variants(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces" / "workspace"
    workspace_root.mkdir(parents=True)
    (workspace_root / "deps.json").write_text(
        """{
  "workspace": {
    "app_repo": {
      "seed_repo": {
        "name": "emulebb",
        "path": "..\\\\..\\\\repos\\\\emulebb"
      },
      "variants": [
        { "name": "main", "path": "app\\\\eMule-main", "branch": "main" },
        { "name": "community", "path": "app\\\\eMule-community-baseline", "branch": "baseline/community-0.72a" }
      ]
    },
    "repos": {
      "tooling": "..\\\\..\\\\repos\\\\emulebb-tooling",
      "p2p_overlord_agents": "..\\\\..\\\\repos\\\\p2p-overlord-agents"
    }
  }
}
""",
        encoding="utf-8",
    )

    manifest = load_workspace_manifest(workspace_root)

    assert manifest.seed_repo_path == Path("..\\..\\repos\\emulebb")
    assert [(variant.name, variant.path) for variant in manifest.variants] == [
        ("main", Path("app\\eMule-main")),
        ("community", Path("app\\eMule-community-baseline")),
    ]
    assert manifest.repos["tooling"] == Path("..\\..\\repos\\emulebb-tooling")
    assert manifest.repos["p2p_overlord_agents"] == Path("..\\..\\repos\\p2p-overlord-agents")


def test_resolve_workspace_repo_uses_manifest_repo_map(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces" / "workspace"
    workspace_root.mkdir(parents=True)
    (workspace_root / "deps.json").write_text(
        """{
  "workspace": {
    "repos": {
      "p2p_overlord_be": "..\\\\..\\\\repos\\\\p2p-overlord-be"
    }
  }
}
""",
        encoding="utf-8",
    )

    assert resolve_workspace_repo(workspace_root, "p2p_overlord_be") == (
        tmp_path / "repos" / "p2p-overlord-be"
    ).resolve()


def test_resolve_workspace_app_root_prefers_existing_seed_then_variants(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces" / "workspace"
    community_root = workspace_root / "app" / "eMule-community-baseline"
    community_root.mkdir(parents=True)
    (workspace_root / "deps.json").write_text(
        """{
  "workspace": {
    "app_repo": {
      "seed_repo": { "name": "emulebb", "path": "..\\\\..\\\\repos\\\\emulebb" },
      "variants": [
        { "name": "main", "path": "app\\\\eMule-main", "branch": "main" },
        { "name": "community", "path": "app\\\\eMule-community-baseline", "branch": "baseline/community-0.72a" }
      ]
    }
  }
}
""",
        encoding="utf-8",
    )

    assert resolve_workspace_app_root(workspace_root) == community_root.resolve()
