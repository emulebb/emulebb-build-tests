from __future__ import annotations

import json
import os
from pathlib import Path

from emule_test_harness import multi_client


def test_client_identities_use_stable_workspace_names() -> None:
    assert multi_client.CLIENT_IDENTITIES["emulebb"].profile_id == "cl-emulebb-001"
    assert multi_client.CLIENT_IDENTITIES["emulebb"].nick == "cl-emulebb-001"
    assert multi_client.CLIENT_IDENTITIES["mfc_oracle"].profile_id == "cl-mfc-oracle-002"
    assert multi_client.CLIENT_IDENTITIES["mfc_oracle"].nick == "cl-mfc-oracle-002"
    assert multi_client.CLIENT_IDENTITIES["emuleai"].profile_id == "cl-emuleai-003"
    assert multi_client.CLIENT_IDENTITIES["stock_emule"].profile_id == "cl-stock-emule-004"
    assert multi_client.CLIENT_IDENTITIES["emulebb_rust"].profile_id == "cl-emulebb-rust-005"
    assert multi_client.CLIENT_IDENTITIES["emulebb_rust_peer"].profile_id == "cl-emulebb-rust-006"
    assert multi_client.CLIENT_IDENTITIES["amule"].profile_id == "cl-amule-007"


def test_client_long_path_capabilities_are_explicit() -> None:
    report = multi_client.long_path_capability_report(
        ["emulebb", "emulebb_rust", "emulebb_rust_peer", "mfc_oracle"]
    )

    # The eMuleBB family (MFC master + the Rust client) is long-path capable.
    # The Rust client's support is scoped to operator content path classes
    # (shared trees / incoming / categories) via a longPathAware manifest + a
    # verbatim \\?\ helper.
    assert report["emulebb"]["supports_long_paths"] is True
    assert report["emulebb_rust"]["supports_long_paths"] is True
    assert report["emulebb_rust_peer"]["supports_long_paths"] is True
    assert report["mfc_oracle"]["supports_long_paths"] is True


def test_workspace_parent_root_derives_canonical_root(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("EMULEBB_WORKSPACE_ROOT", raising=False)
    workspace = tmp_path / "workspaces" / "workspace"

    assert multi_client.workspace_parent_root(workspace) == tmp_path


def test_workspace_parent_root_honors_env_override(tmp_path: Path, monkeypatch) -> None:
    override = tmp_path / "custom-root"
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(override))

    assert multi_client.workspace_parent_root(tmp_path / "workspaces" / "workspace") == override.resolve()


def test_resolve_windows_inventory_reports_missing_optional_clients(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "root"
    output_root = tmp_path / "output"
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))
    workspace = root / "workspaces" / "workspace"
    app_exe = workspace / "app" / "emulebb-main" / "srchybrid" / "x64" / "Release" / "emulebb.exe"
    oracle_exe = output_root / "builds" / "app" / "main" / "x64" / "Release" / "standard" / "bin" / "emulebb.exe"
    app_exe.parent.mkdir(parents=True)
    oracle_exe.parent.mkdir(parents=True)
    write_workspace_manifest(workspace, root)
    app_exe.write_bytes(b"")
    oracle_exe.write_bytes(b"")

    inventory = multi_client.resolve_windows_client_inventory(
        workspace_root=workspace,
        app_exe=app_exe,
        configuration="Release",
    )

    assert inventory["emulebb"].available is True
    assert inventory["mfc_oracle"].available is True
    assert inventory["emuleai"].available is False
    assert inventory["stock_emule"].available is False
    assert inventory["emulebb_rust"].available is False
    assert inventory["emulebb_rust_peer"].available is False
    assert inventory["amule"].available is False
    assert "no built eMuleAI executable" in inventory["emuleai"].reason
    assert "no staged stock baseline executable" in inventory["stock_emule"].reason
    assert "missing Cargo.toml" in inventory["emulebb_rust"].reason
    assert "no staged aMule executable" in inventory["amule"].reason
    assert inventory["emuleai"].launch_adapter == "emuleai-gui-profile"
    assert inventory["emulebb_rust"].launch_adapter == "emule-workspace-python-test"
    assert inventory["amule"].launch_adapter == "amule-ec"


def test_resolve_mfc_oracle_client_uses_canonical_external_build(tmp_path: Path) -> None:
    workspace = tmp_path / "workspaces" / "workspace"
    source_repo = workspace / "app" / "emulebb-main"
    source_repo.mkdir(parents=True)
    output_root = tmp_path / "output"
    oracle_dir = output_root / "builds" / "app" / "main" / "x64" / "Release" / "standard" / "bin"
    oracle_dir.mkdir(parents=True)
    oracle_exe = oracle_dir / "emulebb.exe"

    oracle_exe.write_bytes(b"")
    availability = multi_client.resolve_mfc_oracle_client(
        workspace,
        "Release",
        output_root=output_root,
    )

    assert availability.executable == oracle_exe.resolve()
    assert availability.source_repo == source_repo.resolve()


def test_resolve_mfc_oracle_client_selects_diagnostics_flavor(tmp_path: Path) -> None:
    workspace = tmp_path / "workspaces" / "workspace"
    source_repo = workspace / "app" / "emulebb-main"
    source_repo.mkdir(parents=True)
    output_root = tmp_path / "output"
    oracle_exe = (
        output_root
        / "builds"
        / "app"
        / "main"
        / "x64"
        / "Release"
        / "diagnostics"
        / "bin"
        / "emulebb-diagnostics.exe"
    )
    oracle_exe.parent.mkdir(parents=True)
    oracle_exe.write_bytes(b"")

    availability = multi_client.resolve_mfc_oracle_client(
        workspace,
        "Release",
        output_root=output_root,
        flavor="diagnostics",
    )

    assert availability.executable == oracle_exe.resolve()
    assert availability.launch_adapter == "emulebb-main-diagnostics-rest-profile"
    assert availability.source_repo == source_repo.resolve()


def test_resolve_optional_emuleai_client_accepts_manifest_build(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "root"
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(root))
    workspace = root / "workspaces" / "workspace"
    write_workspace_manifest(workspace, root)
    emuleai_exe = root / "repos" / "eMuleAI" / "_Build" / "eMuleAI" / "Release" / "x64" / "eMuleAI.exe"
    emuleai_exe.parent.mkdir(parents=True, exist_ok=True)
    emuleai_exe.write_bytes(b"")

    emuleai = multi_client.resolve_emuleai_client(workspace, "Release")

    assert emuleai.available is True
    assert emuleai.executable == emuleai_exe.resolve()


def test_resolve_stock_emule_client_accepts_fixed_baseline_build(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspaces" / "workspace"
    baseline_root = workspace / "app" / "emulebb-community-baseline"
    output_root = tmp_path / "output"
    stock_exe = output_root / "builds" / "app" / "community" / "x64" / "Release" / "standard" / "bin" / "emule.exe"
    stock_exe.parent.mkdir(parents=True)
    stock_exe.write_bytes(b"")
    baseline_root.mkdir(parents=True)
    monkeypatch.setattr(multi_client, "git_head_revision", lambda root: "a" * 40 if root == baseline_root else None)

    stock = multi_client.resolve_stock_emule_client(workspace, "Release", output_root=output_root)

    assert stock.available is True
    assert stock.executable == stock_exe.resolve()
    assert stock.deterministic_transfer_adapter is True
    assert stock.source_repo == baseline_root.resolve()
    assert stock.source_revision == "a" * 40


def test_resolve_amule_stable_client_requires_staged_runtime_and_control(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "root"
    workspace = root / "workspaces" / "workspace"
    output_root = tmp_path / "output"
    write_workspace_manifest(workspace, root)
    amule_repo = root / "repos" / "amule-stable"
    amule_repo.mkdir(parents=True)
    amuled_exe = output_root / "tools" / "amule" / "bin" / "amuled.exe"
    amulecmd_exe = amuled_exe.with_name("amulecmd.exe")
    amuled_exe.parent.mkdir(parents=True)
    amuled_exe.write_bytes(b"")
    monkeypatch.setattr(multi_client, "git_head_revision", lambda repo: "b" * 40 if repo == amule_repo else None)

    missing_control = multi_client.resolve_amule_stable_client(workspace, output_root=output_root)
    amulecmd_exe.write_bytes(b"")
    available = multi_client.resolve_amule_stable_client(workspace, output_root=output_root)

    assert missing_control.available is False
    assert "EC control executable is missing" in missing_control.reason
    assert available.available is True
    assert available.executable == amuled_exe.resolve()
    assert available.control_executable == amulecmd_exe.resolve()
    assert available.deterministic_transfer_adapter is True
    assert available.source_repo == amule_repo.resolve()
    assert available.source_revision == "b" * 40
    assert available.as_report()["source_revision"] == "b" * 40


def test_resolve_emulebb_rust_client_accepts_manifest_repo(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "root"
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(root))
    workspace = root / "workspaces" / "workspace"
    write_workspace_manifest(workspace, root)
    cargo_manifest = root / "repos" / "emulebb-rust" / "Cargo.toml"
    cargo_manifest.parent.mkdir(parents=True)
    cargo_manifest.write_text("[workspace]\n", encoding="utf-8")

    rust = multi_client.resolve_emulebb_rust_client(workspace)
    rust_peer = multi_client.resolve_emulebb_rust_client(workspace, identity_key="emulebb_rust_peer")

    assert rust.available is True
    assert rust.executable == cargo_manifest.resolve()
    assert rust.deterministic_transfer_adapter is True
    assert rust_peer.available is True
    assert rust_peer.identity.profile_id == "cl-emulebb-rust-006"


def test_optional_clients_report_unavailable_when_manifest_is_missing(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "root"
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(tmp_path / "output"))
    workspace = root / "workspaces" / "workspace"

    emuleai = multi_client.resolve_emuleai_client(workspace, "Release")
    rust = multi_client.resolve_emulebb_rust_client(workspace)

    assert emuleai.available is False
    assert rust.available is False
    assert "workspace manifest repo 'emuleai' is unavailable" in emuleai.reason
    assert "workspace manifest repo 'emulebb_rust' is unavailable" in rust.reason


def write_workspace_manifest(workspace: Path, root: Path) -> None:
    """Writes the manifest repo keys consumed by multi-client discovery."""

    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "deps.json").write_text(
        json.dumps(
            {
                "workspace": {
                    "repos": {
                        "emuleai": os.path.relpath(root / "repos" / "eMuleAI", workspace),
                        "amule_stable": os.path.relpath(root / "repos" / "amule-stable", workspace),
                        "emulebb_rust": os.path.relpath(root / "repos" / "emulebb-rust", workspace),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
