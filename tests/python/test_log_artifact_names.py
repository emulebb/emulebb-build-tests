from __future__ import annotations

from pathlib import Path

from emule_test_harness.workspace_layout import get_default_workspace_root, load_workspace_manifest


OLD_APP_LOG_TOKENS = (
    "eMule.log",
    "eMule_Verbose.log",
    "eMule CRT Debug Log.log",
    "perflog.csv",
    "perflog.mrtg",
    "_data.mrtg",
    "_overhead.mrtg",
)


def _app_root() -> Path:
    test_repo_root = Path(__file__).resolve().parents[2]
    workspace_root = get_default_workspace_root(test_repo_root)
    manifest = load_workspace_manifest(workspace_root)
    for variant in manifest.variants:
        if variant.name == "main":
            return (workspace_root / variant.path).resolve()
    raise RuntimeError("Workspace manifest does not define the main app variant.")


def test_runtime_log_artifact_names_are_strictly_renamed() -> None:
    app_root = _app_root()
    targets = [
        app_root / "srchybrid" / "Emule.cpp",
        app_root / "srchybrid" / "PerfLog.cpp",
        app_root / "srchybrid" / "Log.cpp",
        app_root / "srchybrid" / "Mdump.cpp",
        app_root / "srchybrid" / "emule.rc",
    ]
    targets.extend((app_root / "srchybrid" / "lang").glob("*.rc"))

    for path in targets:
        text = path.read_text(encoding="utf-8-sig", errors="ignore")
        for token in OLD_APP_LOG_TOKENS:
            assert token not in text, f"{token!r} is still referenced by {path}"


def test_harness_log_readers_use_current_app_log_names() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    this_file = Path(__file__).resolve()
    targets = [
        path
        for root_name in ("scripts", "tests")
        for path in (repo_root / root_name).rglob("*.py")
        if path.resolve() != this_file
    ]

    for path in targets:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for token in OLD_APP_LOG_TOKENS:
            assert token not in text, f"{token!r} is still referenced by {path}"
