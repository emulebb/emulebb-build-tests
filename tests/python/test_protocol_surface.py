from __future__ import annotations

import json
from pathlib import Path

from emule_test_harness.protocol_surface import (
    check_protocol_surface,
    load_manifest,
    render_report_lines,
    write_report,
)


def test_manifest_requires_tracked_item_ids(tmp_path: Path) -> None:
    manifest_path = tmp_path / "surface.json"
    manifest_path.write_text(
        json.dumps(
            {
                "protocol_path_globs": ["srchybrid/kademlia/**"],
                "allowlist": [
                    {
                        "path_glob": "srchybrid/kademlia/**",
                        "item_id": "CI-028",
                        "reason": "covered by protocol parity",
                        "proof_command": "python -m emule_workspace test protocol-parity",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    manifest = load_manifest(manifest_path)

    assert manifest.protocol_path_globs == ("srchybrid/kademlia/**",)
    assert manifest.allowlist[0].item_id == "CI-028"


def test_protocol_surface_reports_unallowlisted_diff(tmp_path: Path, monkeypatch) -> None:
    commands: list[tuple[str, ...]] = []

    def fake_git_stdout(repo_root: Path, *args: str) -> str:
        commands.append(args)
        if args == ("rev-parse", "HEAD"):
            return "main-ref" if repo_root.name == "main" else "baseline-ref"
        return "srchybrid/kademlia/net/KademliaUDPListener.cpp\nsrchybrid/WebServer.cpp\n"

    monkeypatch.setattr("emule_test_harness.protocol_surface._git_stdout", fake_git_stdout)
    manifest_path = tmp_path / "surface.json"
    manifest_path.write_text(
        json.dumps(
            {
                "protocol_path_globs": ["srchybrid/kademlia/**"],
                "allowlist": [],
            }
        ),
        encoding="utf-8",
    )

    report = check_protocol_surface(
        manifest=load_manifest(manifest_path),
        test_run_app_root=tmp_path / "main",
        baseline_app_root=tmp_path / "baseline",
    )

    assert report.passed is False
    assert [violation.path for violation in report.violations] == [
        "srchybrid/kademlia/net/KademliaUDPListener.cpp"
    ]
    assert any(command[0] == "diff" for command in commands)


def test_protocol_surface_accepts_allowlisted_diff_and_writes_report(tmp_path: Path, monkeypatch) -> None:
    def fake_git_stdout(repo_root: Path, *args: str) -> str:
        if args == ("rev-parse", "HEAD"):
            return "main-ref" if repo_root.name == "main" else "baseline-ref"
        return "srchybrid/ClientUDPSocket.cpp\n"

    monkeypatch.setattr("emule_test_harness.protocol_surface._git_stdout", fake_git_stdout)
    manifest_path = tmp_path / "surface.json"
    manifest_path.write_text(
        json.dumps(
            {
                "protocol_path_globs": ["srchybrid/ClientUDPSocket*"],
                "allowlist": [
                    {
                        "path_glob": "srchybrid/ClientUDPSocket*",
                        "item_id": "BUG-085",
                        "reason": "UDP encryption gate compatibility proof",
                        "proof_command": "python -m emule_workspace test protocol-parity",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.json"

    report = check_protocol_surface(
        manifest=load_manifest(manifest_path),
        test_run_app_root=tmp_path / "main",
        baseline_app_root=tmp_path / "baseline",
    )
    write_report(report, report_path)

    assert report.passed is True
    assert report.allowed_paths == ("srchybrid/ClientUDPSocket.cpp",)
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert render_report_lines(report)[2] == "Protocol surface violations: 0"
