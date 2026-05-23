from __future__ import annotations

from pathlib import Path

from emule_test_harness import product_family


def test_product_family_resolves_p2p_overlord_repos_and_openapi(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces" / "workspace"
    workspace_root.mkdir(parents=True)
    (workspace_root / "deps.json").write_text(
        """{
  "workspace": {
    "repos": {
      "tooling": "..\\\\..\\\\repos\\\\eMule-tooling",
      "p2p_overlord_agents": "..\\\\..\\\\repos\\\\p2p-overlord-agents",
      "p2p_overlord_be": "..\\\\..\\\\repos\\\\p2p-overlord-be"
    }
  }
}
""",
        encoding="utf-8",
    )

    repos = product_family.resolve_p2p_overlord_repos(workspace_root)

    assert repos["p2p_overlord_agents"] == (tmp_path / "repos" / "p2p-overlord-agents").resolve()
    assert repos["p2p_overlord_be"] == (tmp_path / "repos" / "p2p-overlord-be").resolve()
    assert product_family.resolve_canonical_rest_openapi(workspace_root) == (
        tmp_path / "repos" / "eMule-tooling" / "docs" / "rest" / "REST-API-OPENAPI.yaml"
    ).resolve()
