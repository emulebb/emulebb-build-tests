from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from emule_test_harness import live_dependencies


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def zip_payload(name: str, content: bytes = b"exe") -> bytes:
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr(name, content)
    return data.getvalue()


@pytest.fixture(autouse=True)
def isolated_workspace_output_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(tmp_path / "workspace-root"))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(tmp_path / "workspace-output"))


def test_select_release_asset_uses_windows_x64_zip() -> None:
    asset = live_dependencies.select_release_asset(
        {
            "assets": [
                {"name": "Prowlarr.develop.1.0.linux-x64.tar.gz", "browser_download_url": "https://example.invalid/linux"},
                {"name": "Prowlarr.master.1.0.windows-core-x64.zip", "browser_download_url": "https://example.invalid/win"},
            ]
        },
        r"(?i)windows(?:-core)?-x64\.zip$",
    )

    assert asset["browser_download_url"] == "https://example.invalid/win"


def test_sonarr_pinned_asset_pattern_accepts_win_x64_zip() -> None:
    asset = live_dependencies.select_release_asset(
        {
            "assets": [
                {"name": "Sonarr.main.4.0.17.2952.win-x64-installer.exe", "browser_download_url": "https://example.invalid/installer"},
                {"name": "Sonarr.main.4.0.17.2952.win-x64.zip", "browser_download_url": "https://example.invalid/zip"},
            ]
        },
        live_dependencies.ARR_PORTABLE_DEPENDENCIES["sonarr"]["asset_pattern"],
    )

    assert asset["browser_download_url"] == "https://example.invalid/zip"


def test_safe_extract_zip_rejects_path_escape(tmp_path: Path) -> None:
    archive_path = tmp_path / "bad.zip"
    archive_path.write_bytes(zip_payload("../escape.txt"))

    with pytest.raises(live_dependencies.DependencyUnavailableError):
        live_dependencies.safe_extract_zip(archive_path, tmp_path / "extract")


def test_resolve_portable_dependency_accepts_override(tmp_path: Path) -> None:
    exe = tmp_path / "Radarr.exe"
    exe.write_text("placeholder", encoding="utf-8")

    resolved = live_dependencies.resolve_portable_dependency(
        "radarr",
        workspace_root=tmp_path,
        mode="off",
        override_exe=exe,
    )

    assert resolved.exe_path == exe.resolve()
    assert resolved.source == "override"


def test_resolve_portable_dependency_downloads_and_caches(tmp_path: Path) -> None:
    release = {
        "tag_name": "v1.2.3",
        "assets": [
            {
                "name": "Radarr.master.1.2.3.windows-core-x64.zip",
                "browser_download_url": "https://example.invalid/radarr.zip",
            }
        ],
    }
    archive = zip_payload("Radarr/Radarr.exe")
    calls: list[str] = []

    def opener(request, timeout=0):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        calls.append(url)
        if url.endswith("/releases/latest"):
            return FakeResponse(json.dumps(release).encode("utf-8"))
        if url == "https://example.invalid/radarr.zip":
            return FakeResponse(archive)
        raise AssertionError(url)

    resolved = live_dependencies.resolve_portable_dependency(
        "radarr",
        workspace_root=tmp_path,
        mode="auto-download",
        channel="latest",
        opener=opener,
    )

    assert resolved.exe_path is not None
    assert resolved.exe_path.name == "Radarr.exe"
    assert resolved.archive_sha256 == live_dependencies.sha256_file(resolved.archive_path)  # type: ignore[arg-type]
    assert calls == [
        "https://api.github.com/repos/Radarr/Radarr/releases/latest",
        "https://example.invalid/radarr.zip",
    ]

    cached = live_dependencies.resolve_portable_dependency("radarr", workspace_root=tmp_path, mode="cache-only")
    assert cached.exe_path == resolved.exe_path


def test_default_urlopen_receives_trusted_https_context(monkeypatch: pytest.MonkeyPatch) -> None:
    context = object()
    calls = []

    def fake_urlopen(request, *, timeout=0, context=None):
        calls.append({"request": request, "timeout": timeout, "context": context})
        return FakeResponse(b"{}")

    monkeypatch.setattr(live_dependencies, "trusted_https_context", lambda: context)
    monkeypatch.setattr(live_dependencies.urllib.request, "urlopen", fake_urlopen)

    with live_dependencies.open_https_url("https://example.invalid", timeout=17, opener=live_dependencies.urllib.request.urlopen):
        pass

    assert calls == [{"request": "https://example.invalid", "timeout": 17, "context": context}]


def test_resolve_portable_dependency_pinned_uses_manifest_tag(tmp_path: Path) -> None:
    release = {
        "tag_name": live_dependencies.ARR_PORTABLE_DEPENDENCIES["radarr"]["tag"],
        "assets": [
            {
                "name": "Radarr.master.pinned.windows-core-x64.zip",
                "browser_download_url": "https://example.invalid/radarr-pinned.zip",
            }
        ],
    }
    archive = zip_payload("Radarr/Radarr.exe")
    calls: list[str] = []

    def opener(request, timeout=0):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        calls.append(url)
        if "/releases/tags/" in url:
            return FakeResponse(json.dumps(release).encode("utf-8"))
        if url == "https://example.invalid/radarr-pinned.zip":
            return FakeResponse(archive)
        raise AssertionError(url)

    resolved = live_dependencies.resolve_portable_dependency(
        "radarr",
        workspace_root=tmp_path,
        mode="auto-download",
        channel="pinned",
        opener=opener,
    )

    assert resolved.exe_path is not None
    assert calls[0] == (
        "https://api.github.com/repos/Radarr/Radarr/releases/tags/"
        f"{live_dependencies.ARR_PORTABLE_DEPENDENCIES['radarr']['tag']}"
    )


def test_cache_only_missing_dependency_is_unavailable(tmp_path: Path) -> None:
    with pytest.raises(live_dependencies.DependencyUnavailableError):
        live_dependencies.resolve_portable_dependency("sonarr", workspace_root=tmp_path, mode="cache-only")
