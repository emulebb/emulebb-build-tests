"""Reusable external runtime resolution for live and E2E harnesses."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEPENDENCY_MODES = ("cache-only", "auto-download", "off")
DEPENDENCY_CHANNELS = ("pinned", "latest")
DEFAULT_CACHE_DIRNAME = "test-tools-cache"

ARR_PORTABLE_DEPENDENCIES: dict[str, dict[str, str]] = {
    # The default "pinned" channel is intentionally explicit. Live and E2E
    # suites need reproducible tool behavior by default; operators can opt into
    # GitHub's moving latest release with --dependency-channel latest.
    "prowlarr": {
        "repo": "Prowlarr/Prowlarr",
        "tag": "v2.3.5.5327",
        "asset_pattern": r"(?i)windows(?:-core)?-x64\.zip$",
        "exe_name": "Prowlarr.exe",
    },
    "radarr": {
        "repo": "Radarr/Radarr",
        "tag": "v6.1.1.10360",
        "asset_pattern": r"(?i)windows(?:-core)?-x64\.zip$",
        "exe_name": "Radarr.exe",
    },
    "sonarr": {
        "repo": "Sonarr/Sonarr",
        "tag": "v4.0.17.2952",
        "asset_pattern": r"(?i)windows(?:-core)?-x64\.zip$",
        "exe_name": "Sonarr.exe",
    },
}


class DependencyUnavailableError(RuntimeError):
    """Raised when a live dependency cannot be resolved in the selected mode."""


@dataclass(frozen=True)
class PortableDependency:
    """Resolved portable runtime metadata recorded by live-suite reports."""

    name: str
    status: str
    exe_path: Path | None
    source: str
    version: str
    cache_dir: Path
    archive_path: Path | None = None
    archive_sha256: str | None = None
    asset_url: str | None = None
    detail: str = ""

    def to_report(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": self.status,
            "exe_path": str(self.exe_path) if self.exe_path is not None else None,
            "source": self.source,
            "version": self.version,
            "cache_dir": str(self.cache_dir),
            "archive_path": str(self.archive_path) if self.archive_path is not None else None,
            "archive_sha256": self.archive_sha256,
            "asset_url": self.asset_url,
            "detail": self.detail,
        }


def default_dependency_cache_root(workspace_root: Path) -> Path:
    """Returns the workspace-owned cache used by reusable live dependencies."""

    return workspace_root / "state" / DEFAULT_CACHE_DIRNAME


def sha256_file(path: Path) -> str:
    """Returns the SHA-256 digest for one local file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_github_release(repo: str, tag: str, *, opener=urllib.request.urlopen) -> dict[str, Any]:
    """Loads GitHub release JSON for an explicit tag or for the latest release."""

    endpoint = "latest" if tag == "latest" else f"tags/{tag}"
    url = f"https://api.github.com/repos/{repo}/releases/{endpoint}"
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "emulebb-live-tests"})
    with opener(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def select_release_asset(release: dict[str, Any], asset_pattern: str) -> dict[str, Any]:
    """Returns the first release asset matching the dependency manifest regex."""

    pattern = re.compile(asset_pattern)
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise DependencyUnavailableError("release payload did not contain an assets list")
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name") or "")
        if pattern.search(name):
            url = str(asset.get("browser_download_url") or "")
            if not url:
                raise DependencyUnavailableError(f"asset {name!r} had no browser_download_url")
            return asset
    names = [str(asset.get("name") or "") for asset in assets if isinstance(asset, dict)]
    raise DependencyUnavailableError(f"no release asset matched {asset_pattern!r}; assets={names!r}")


def safe_extract_zip(archive_path: Path, destination: Path) -> None:
    """Extracts a ZIP archive while rejecting entries that escape the destination."""

    destination.mkdir(parents=True, exist_ok=True)
    destination_resolved = destination.resolve()
    with zipfile.ZipFile(archive_path, "r") as archive:
        for member in archive.infolist():
            target = (destination / member.filename).resolve()
            if destination_resolved != target and destination_resolved not in target.parents:
                raise DependencyUnavailableError(f"unsafe zip member escapes extraction root: {member.filename}")
        # Dependency archives are downloaded at test time, so every member is
        # validated before extraction to avoid ZIP path traversal into the
        # workspace, user profile, or another test run's cache.
        archive.extractall(destination)


def find_executable(root: Path, exe_name: str) -> Path | None:
    """Finds a portable runtime executable under an extracted dependency root."""

    direct = root / exe_name
    if direct.is_file():
        return direct
    matches = sorted(path for path in root.rglob(exe_name) if path.is_file())
    return matches[0] if matches else None


def download_file(url: str, destination: Path, *, opener=urllib.request.urlopen) -> None:
    """Downloads one dependency archive to a temporary file and promotes it atomically."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    try:
        with opener(url, timeout=180) as response, temporary.open("wb") as handle:
            shutil.copyfileobj(response, handle)
        # Promote only a completed archive so cache-only follow-up runs never
        # observe a partially downloaded ZIP after interruption or timeout.
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _cache_key(name: str, version: str) -> str:
    safe_version = re.sub(r"[^A-Za-z0-9._-]+", "_", version)
    return f"{name}-{safe_version}"


def resolve_portable_dependency(
    name: str,
    *,
    workspace_root: Path,
    cache_root: Path | None = None,
    mode: str = "cache-only",
    channel: str = "pinned",
    override_exe: str | Path | None = None,
    refresh: bool = False,
    opener=urllib.request.urlopen,
) -> PortableDependency:
    """Resolves a portable live-test runtime from override, cache, or official download."""

    if mode not in DEPENDENCY_MODES:
        raise ValueError(f"dependency mode must be one of {DEPENDENCY_MODES}, not {mode!r}")
    if channel not in DEPENDENCY_CHANNELS:
        raise ValueError(f"dependency channel must be one of {DEPENDENCY_CHANNELS}, not {channel!r}")
    manifest = ARR_PORTABLE_DEPENDENCIES.get(name)
    if manifest is None:
        raise ValueError(f"unknown portable dependency: {name}")

    root = (cache_root or default_dependency_cache_root(workspace_root)).resolve()
    if override_exe:
        exe_path = Path(override_exe).resolve()
        if not exe_path.is_file():
            raise DependencyUnavailableError(f"{name} executable override does not exist: {exe_path}")
        return PortableDependency(name=name, status="available", exe_path=exe_path, source="override", version="override", cache_dir=root)

    if mode == "off":
        raise DependencyUnavailableError(f"{name} dependency resolution is disabled")

    requested_tag = manifest["tag"] if channel == "pinned" else "latest"
    metadata_root = root / name
    metadata_path = metadata_root / "resolved.json"
    if metadata_path.is_file() and not refresh:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        exe_path = Path(str(metadata.get("exe_path") or ""))
        if exe_path.is_file():
            return PortableDependency(
                name=name,
                status="available",
                exe_path=exe_path,
                source=str(metadata.get("source") or "cache"),
                version=str(metadata.get("version") or requested_tag),
                cache_dir=root,
                archive_path=Path(str(metadata["archive_path"])) if metadata.get("archive_path") else None,
                archive_sha256=str(metadata.get("archive_sha256") or ""),
                asset_url=str(metadata.get("asset_url") or ""),
            )

    if mode != "auto-download":
        raise DependencyUnavailableError(f"{name} is not cached and dependency mode is {mode}")

    release = load_github_release(manifest["repo"], requested_tag, opener=opener)
    version = str(release.get("tag_name") or requested_tag)
    asset = select_release_asset(release, manifest["asset_pattern"])
    asset_name = str(asset.get("name") or f"{name}.zip")
    asset_url = str(asset["browser_download_url"])
    cache_dir = root / _cache_key(name, version)
    archive_path = cache_dir / "archive" / asset_name
    extract_root = cache_dir / "extract"
    if refresh and cache_dir.exists():
        shutil.rmtree(cache_dir)
    if not archive_path.is_file():
        download_file(asset_url, archive_path, opener=opener)
    if not extract_root.exists():
        safe_extract_zip(archive_path, extract_root)
    exe_path = find_executable(extract_root, manifest["exe_name"])
    if exe_path is None:
        raise DependencyUnavailableError(f"{name} archive did not contain {manifest['exe_name']}")
    archive_sha256 = sha256_file(archive_path)
    metadata = {
        "name": name,
        "source": "download",
        "version": version,
        "repo": manifest["repo"],
        "asset_url": asset_url,
        "archive_path": str(archive_path),
        "archive_sha256": archive_sha256,
        "exe_path": str(exe_path),
    }
    metadata_root.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2) + os.linesep, encoding="utf-8")
    return PortableDependency(
        name=name,
        status="available",
        exe_path=exe_path,
        source="download",
        version=version,
        cache_dir=root,
        archive_path=archive_path,
        archive_sha256=archive_sha256,
        asset_url=asset_url,
    )
