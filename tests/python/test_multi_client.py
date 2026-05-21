from __future__ import annotations

import json
import os
from pathlib import Path

from emule_test_harness import multi_client


def test_client_identities_use_stable_workspace_names() -> None:
    assert multi_client.CLIENT_IDENTITIES["emulebb"].profile_id == "cl-emulebb-001"
    assert multi_client.CLIENT_IDENTITIES["emulebb"].nick == "cl-emulebb-001"
    assert multi_client.CLIENT_IDENTITIES["harness"].profile_id == "cl-harness-002"
    assert multi_client.CLIENT_IDENTITIES["harness"].nick == "cl-harness-002"
    assert multi_client.CLIENT_IDENTITIES["emuleai"].profile_id == "cl-emuleai-003"
    assert multi_client.CLIENT_IDENTITIES["amule"].profile_id == "cl-amule-004"


def test_workspace_parent_root_derives_canonical_root(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("EMULE_WORKSPACE_ROOT", raising=False)
    workspace = tmp_path / "workspaces" / "workspace"

    assert multi_client.workspace_parent_root(workspace) == tmp_path


def test_workspace_parent_root_honors_env_override(tmp_path: Path, monkeypatch) -> None:
    override = tmp_path / "custom-root"
    monkeypatch.setenv("EMULE_WORKSPACE_ROOT", str(override))

    assert multi_client.workspace_parent_root(tmp_path / "workspaces" / "workspace") == override.resolve()


def test_resolve_windows_inventory_reports_missing_optional_clients(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("EMULE_WORKSPACE_ROOT", raising=False)
    workspace = tmp_path / "workspaces" / "workspace"
    app_exe = workspace / "app" / "eMule-main" / "srchybrid" / "x64" / "Release" / "emule.exe"
    harness_exe = workspace / "app" / "eMule-community-tracing-harness" / "srchybrid" / "x64" / "Release" / "emule.exe"
    app_exe.parent.mkdir(parents=True)
    harness_exe.parent.mkdir(parents=True)
    write_workspace_manifest(workspace, tmp_path)
    app_exe.write_bytes(b"")
    harness_exe.write_bytes(b"")

    inventory = multi_client.resolve_windows_client_inventory(
        workspace_root=workspace,
        app_exe=app_exe,
        configuration="Release",
    )

    assert inventory["emulebb"].available is True
    assert inventory["harness"].available is True
    assert inventory["emuleai"].available is False
    assert inventory["amule"].available is False
    assert "no built eMuleAI executable" in inventory["emuleai"].reason
    assert "no built aMule daemon/control binaries" in inventory["amule"].reason
    assert inventory["emuleai"].launch_adapter == "emuleai-gui-profile"
    assert inventory["amule"].launch_adapter == "amuled-amulecmd"


def test_resolve_optional_clients_accepts_workspace_state_artifacts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("EMULE_WORKSPACE_ROOT", raising=False)
    workspace = tmp_path / "workspaces" / "workspace"
    write_workspace_manifest(workspace, tmp_path)
    emuleai_exe = tmp_path / "repos" / "eMuleAI" / "_Build" / "eMuleAI" / "Release" / "x64" / "eMuleAI.exe"
    amule_daemon = workspace / "state" / "tools" / "amule" / "bin" / "amuled.exe"
    amule_control = workspace / "state" / "tools" / "amule" / "bin" / "amulecmd.exe"
    for executable in (emuleai_exe, amule_daemon, amule_control):
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"")

    emuleai = multi_client.resolve_emuleai_client(workspace, "Release")
    amule = multi_client.resolve_amule_client(workspace)

    assert emuleai.available is True
    assert emuleai.executable == emuleai_exe.resolve()
    assert amule.available is True
    assert amule.executable == amule_daemon.resolve()
    assert amule.control_executable == amule_control.resolve()
    assert amule.deterministic_transfer_adapter is True


def test_optional_clients_report_unavailable_when_manifest_is_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("EMULE_WORKSPACE_ROOT", raising=False)
    workspace = tmp_path / "workspaces" / "workspace"

    emuleai = multi_client.resolve_emuleai_client(workspace, "Release")
    amule = multi_client.resolve_amule_client(workspace)

    assert emuleai.available is False
    assert amule.available is False
    assert "workspace manifest repo 'emuleai' is unavailable" in emuleai.reason
    assert "workspace manifest repo 'amule' is unavailable" in amule.reason


def write_workspace_manifest(workspace: Path, root: Path) -> None:
    """Writes the manifest repo keys consumed by multi-client discovery."""

    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "deps.json").write_text(
        json.dumps(
            {
                "workspace": {
                    "repos": {
                        "amule": os.path.relpath(root / "repos" / "amule", workspace),
                        "emuleai": os.path.relpath(root / "repos" / "eMuleAI", workspace),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
