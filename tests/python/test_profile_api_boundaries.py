from pathlib import Path


def test_win32_profile_api_usage_stays_at_legacy_boundaries() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    app_root = workspace_root / "workspaces" / "workspace" / "app" / "eMule-main" / "srchybrid"
    allowed = {
        app_root / "Ini2.cpp",
        app_root / "ShellUiHelpers.h",
    }

    offenders: list[str] = []
    for path in app_root.rglob("*"):
        if path.suffix.lower() not in {".cpp", ".h"}:
            continue
        text = path.read_text(encoding="utf-8")
        if (
            "::GetPrivateProfileString" in text
            or "WritePrivateProfileString(" in text
            or "GetPrivateProfileInt(" in text
        ) and path not in allowed:
            offenders.append(str(path.relative_to(app_root)))

    assert offenders == []
