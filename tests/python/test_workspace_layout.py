from __future__ import annotations

from pathlib import Path

from emule_test_harness.workspace_layout import (
    get_default_workspace_root,
    load_workspace_manifest,
    resolve_workspace_app_root,
)


def test_default_roots_use_canonical_repo_layout(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("EMULE_WORKSPACE_ROOT", raising=False)
    test_repo_root = tmp_path / "repos" / "eMule-build-tests"

    assert get_default_workspace_root(test_repo_root) == tmp_path / "workspaces" / "v0.72a"


def test_workspace_manifest_parser_reads_seed_and_variants(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces" / "v0.72a"
    workspace_root.mkdir(parents=True)
    (workspace_root / "deps.psd1").write_text(
        """@{
    Workspace = @{
        AppRepo = @{
            SeedRepo = @{
                Path = '..\\..\\repos\\eMule'
            }
            Variants = @(
                @{ Name = 'main'; Path = 'app\\eMule-main'; Branch = 'main' }
                @{ Name = 'community'; Path = 'app\\eMule-v0.72a-community'; Branch = 'release/v0.72a-community' }
            )
        }
    }
}
""",
        encoding="utf-8",
    )

    manifest = load_workspace_manifest(workspace_root)

    assert manifest.seed_repo_path == Path("..\\..\\repos\\eMule")
    assert [(variant.name, variant.path) for variant in manifest.variants] == [
        ("main", Path("app\\eMule-main")),
        ("community", Path("app\\eMule-v0.72a-community")),
    ]


def test_resolve_workspace_app_root_prefers_existing_seed_then_variants(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces" / "v0.72a"
    community_root = workspace_root / "app" / "eMule-v0.72a-community"
    community_root.mkdir(parents=True)
    (workspace_root / "deps.psd1").write_text(
        """@{
    Workspace = @{
        AppRepo = @{
            SeedRepo = @{ Path = '..\\..\\repos\\eMule' }
            Variants = @(
                @{ Name = 'main'; Path = 'app\\eMule-main'; Branch = 'main' }
                @{ Name = 'community'; Path = 'app\\eMule-v0.72a-community'; Branch = 'release/v0.72a-community' }
            )
        }
    }
}
""",
        encoding="utf-8",
    )

    assert resolve_workspace_app_root(workspace_root) == community_root.resolve()
