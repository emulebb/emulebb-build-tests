from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import workspace_layout

from emule_test_harness.workspace_layout import (
    get_default_workspace_root,
    load_workspace_manifest,
    resolve_workspace_repo,
    resolve_workspace_app_root,
)


@pytest.mark.parametrize("explicit", [False, True])
def test_contract_selection_resolves_workspace_only_without_explicit_input(tmp_path, monkeypatch, explicit):
    calls = []
    def selected(_caller, repository):
        calls.append(repository)
        return tmp_path / "tooling"
    monkeypatch.setattr(workspace_layout, "resolve_selected_workspace_repo", selected)
    if explicit:
        expected = tmp_path / "selected.yaml"
        monkeypatch.setenv("EMULEBB_REST_OPENAPI_CONTRACT_PATH", str(expected))
    else:
        monkeypatch.delenv("EMULEBB_REST_OPENAPI_CONTRACT_PATH", raising=False)
        expected = tmp_path / "tooling/docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml"
    assert workspace_layout.resolve_rust_openapi_contract() == expected
    assert calls == ([] if explicit else ["emulebb-tooling"])


@pytest.mark.parametrize("module", ["rust_openapi_responses", "rust_rest_conformance"])
def test_contract_consumers_import_without_materialized_workspace(tmp_path, monkeypatch, module):
    import runpy

    selected = tmp_path / "selected.yaml"
    monkeypatch.setenv("EMULEBB_REST_OPENAPI_CONTRACT_PATH", str(selected))
    def unexpected_resolution(*_args):
        raise AssertionError("Explicit contract must not inspect workspace topology")
    monkeypatch.setattr(workspace_layout, "resolve_selected_workspace_repo", unexpected_resolution)
    source = Path(workspace_layout.__file__).with_name(f"{module}.py")
    loaded = runpy.run_path(str(source))
    key = "RUST_OPENAPI_CONTRACT_PATH" if module == "rust_rest_conformance" else "OPENAPI_CONTRACT_PATH"
    assert loaded[key] == selected


@pytest.mark.parametrize("managed", [False, True])
def test_selected_companion_uses_builder_registration(tmp_path, monkeypatch, managed):
    builder = tmp_path / "repos/emulebb-build"
    canonical = tmp_path / "repos/emulebb-rust"
    selected = tmp_path / "workspaces/agents/review/emulebb-rust"
    for source, version in ((canonical, 69), (selected, 70)):
        source.mkdir(parents=True)
        (source / "schema.sql").write_text(f"PRAGMA user_version = {version};", encoding="utf-8")
    caller = (selected.parent if managed else canonical.parent) / "emulebb-build-tests"
    calls = []

    def registration(root, output, *, repo):
        calls.append(repo)
        return {"id": "review"} if managed else None

    api = SimpleNamespace(
        __file__=str(builder / "emule_workspace/workstreams.py"),
        resolve_workstream=registration,
        apply_workstream_layout=lambda layout, record: SimpleNamespace(rust=selected),
        REPOSITORY_FIELDS={"emulebb-rust": "rust"},
    )
    layout = SimpleNamespace(
        __file__=str(builder / "emule_workspace/layout.py"),
        load_layout=lambda root, **kwargs: SimpleNamespace(rust=canonical),
    )
    monkeypatch.setattr(workspace_layout, "resolve_workspace_repo", lambda *args: builder)
    monkeypatch.setitem(__import__("sys").modules, "emule_workspace", SimpleNamespace(layout=layout, workstreams=api))
    result = workspace_layout._selected_workspace_repo(tmp_path, tmp_path / "output", caller, "emulebb-rust")
    expected = selected if managed else canonical
    assert result == expected
    assert result.joinpath("schema.sql").read_text() == f"PRAGMA user_version = {70 if managed else 69};"
    assert calls == [caller]


def test_selected_companion_never_falls_back_from_invalid_registration(tmp_path, monkeypatch):
    builder = tmp_path / "repos/emulebb-build"

    def invalid(*args, **kwargs):
        raise RuntimeError("Workstream branch changed")

    api = SimpleNamespace(__file__=str(builder / "emule_workspace/workstreams.py"), resolve_workstream=invalid)
    layout = SimpleNamespace(__file__=str(builder / "emule_workspace/layout.py"), load_layout=lambda *args, **kwargs: object())
    monkeypatch.setattr(workspace_layout, "resolve_workspace_repo", lambda *args: builder)
    monkeypatch.setitem(__import__("sys").modules, "emule_workspace", SimpleNamespace(layout=layout, workstreams=api))
    with pytest.raises(RuntimeError, match="Workstream branch changed"):
        workspace_layout._selected_workspace_repo(
            tmp_path, tmp_path / "output", tmp_path / "workspaces/agents/review/emulebb-build-tests", "emulebb-rust"
        )


@pytest.mark.parametrize("registered_origin", [True, False])
def test_loaded_builder_origin_must_match_verified_registration(tmp_path, monkeypatch, registered_origin):
    canonical = tmp_path / "repos/emulebb-build"
    selected = tmp_path / "workspaces/agents/review/emulebb-build"
    loaded = selected if registered_origin else tmp_path / "unregistered-builder"
    rust = selected.parent / "emulebb-rust"
    registration = {"id": "review", "repositories": {"emulebb-build": {"path": str(selected)}}}
    api = SimpleNamespace(
        __file__=str(loaded / "emule_workspace/workstreams.py"),
        resolve_workstream=lambda *args, **kwargs: registration,
        apply_workstream_layout=lambda *args: SimpleNamespace(rust=rust),
        REPOSITORY_FIELDS={"emulebb-rust": "rust"},
    )
    layout = SimpleNamespace(__file__=str(loaded / "emule_workspace/layout.py"),
                             load_layout=lambda *args, **kwargs: object())
    monkeypatch.setattr(workspace_layout, "resolve_workspace_repo", lambda *args: canonical)
    monkeypatch.setitem(__import__("sys").modules, "emule_workspace", SimpleNamespace(layout=layout, workstreams=api))
    arguments = (tmp_path, tmp_path / "output", selected.parent / "emulebb-build-tests", "emulebb-rust")
    if registered_origin:
        assert workspace_layout._selected_workspace_repo(*arguments) == rust
    else:
        with pytest.raises(RuntimeError, match="Builder API differs"):
            workspace_layout._selected_workspace_repo(*arguments)


def test_default_roots_use_canonical_repo_layout(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("EMULEBB_WORKSPACE_ROOT", raising=False)
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
        { "name": "main", "path": "app\\\\emulebb-main", "branch": "main" },
        { "name": "community", "path": "app\\\\emulebb-community-baseline", "branch": "baseline/community-0.72a" }
      ]
    },
    "repos": {
      "tooling": "..\\\\..\\\\repos\\\\emulebb-tooling",
      "example_service": "..\\\\..\\\\repos\\\\example-service"
    }
  }
}
""",
        encoding="utf-8",
    )

    manifest = load_workspace_manifest(workspace_root)

    assert manifest.seed_repo_path == Path("..\\..\\repos\\emulebb")
    assert [(variant.name, variant.path) for variant in manifest.variants] == [
        ("main", Path("app\\emulebb-main")),
        ("community", Path("app\\emulebb-community-baseline")),
    ]
    assert manifest.repos["tooling"] == Path("..\\..\\repos\\emulebb-tooling")
    assert manifest.repos["example_service"] == Path("..\\..\\repos\\example-service")


def test_resolve_workspace_repo_uses_manifest_repo_map(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces" / "workspace"
    workspace_root.mkdir(parents=True)
    (workspace_root / "deps.json").write_text(
        """{
  "workspace": {
    "repos": {
      "example_worker": "..\\\\..\\\\repos\\\\example-worker"
    }
  }
}
""",
        encoding="utf-8",
    )

    assert resolve_workspace_repo(workspace_root, "example_worker") == (
        tmp_path / "repos" / "example-worker"
    ).resolve()


def test_resolve_workspace_app_root_prefers_existing_seed_then_variants(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces" / "workspace"
    community_root = workspace_root / "app" / "emulebb-community-baseline"
    community_root.mkdir(parents=True)
    (workspace_root / "deps.json").write_text(
        """{
  "workspace": {
    "app_repo": {
      "seed_repo": { "name": "emulebb", "path": "..\\\\..\\\\repos\\\\emulebb" },
      "variants": [
        { "name": "main", "path": "app\\\\emulebb-main", "branch": "main" },
        { "name": "community", "path": "app\\\\emulebb-community-baseline", "branch": "baseline/community-0.72a" }
      ]
    }
  }
}
""",
        encoding="utf-8",
    )

    assert resolve_workspace_app_root(workspace_root) == community_root.resolve()


def test_resolve_workspace_app_root_accepts_minimal_fast_ci_checkout(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces" / "workspace"
    app_root = workspace_root / "app" / "emulebb-main"
    app_root.mkdir(parents=True)

    assert resolve_workspace_app_root(workspace_root, preferred_variant_names=("main",)) == app_root.resolve()
