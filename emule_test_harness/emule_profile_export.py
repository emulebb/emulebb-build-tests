"""Export stock-compatible eMule profile hashes into a portable Rust manifest."""

from __future__ import annotations

import argparse
import json
import ntpath
import os
import posixpath
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

from . import mfc_known_met, mfc_profile_import
from .ini import parse_ini_values, read_ini_text

JOB_SCHEMA_VERSION = 1
MANIFEST_SCHEMA = "emulebb-rust.profile-import.v1"
SUPPORTED_FLAVORS = {"auto", "stock", "mfc"}
SUPPORTED_TARGET_PLATFORMS = {"windows", "unix", "linux", "macos"}


@dataclass(frozen=True)
class PathMapping:
    source: str
    target: str


@dataclass(frozen=True)
class ExportJob:
    config_path: Path
    source_profile: Path
    flavor: str
    target_platform: str
    output_manifest: Path
    path_mappings: tuple[PathMapping, ...]


@dataclass(frozen=True)
class DiscoveredRoot:
    path: str
    origin: str


def load_export_job(path: Path) -> ExportJob:
    """Load and validate one profile-export TOML job."""

    config_path = path.resolve()
    with config_path.open("rb") as handle:
        payload = tomllib.load(handle)
    _require_keys(payload, {"schema_version", "source", "target", "output", "path_mappings"}, "root")
    if payload.get("schema_version") != JOB_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {JOB_SCHEMA_VERSION}")

    source = _require_table(payload, "source")
    target = _require_table(payload, "target")
    output = _require_table(payload, "output")
    _require_keys(source, {"profile", "flavor"}, "source")
    _require_keys(target, {"platform"}, "target")
    _require_keys(output, {"manifest"}, "output")

    source_profile = _resolve_job_path(config_path, _require_string(source, "profile"))
    flavor = str(source.get("flavor", "auto")).strip().lower()
    if flavor not in SUPPORTED_FLAVORS:
        raise ValueError(f"source.flavor must be one of {sorted(SUPPORTED_FLAVORS)}")
    target_platform = _canonical_target_platform(_require_string(target, "platform"))
    output_manifest = _resolve_job_path(config_path, _require_string(output, "manifest"))

    raw_mappings = payload.get("path_mappings", [])
    if not isinstance(raw_mappings, list):
        raise ValueError("path_mappings must be an array of tables")
    mappings: list[PathMapping] = []
    seen_sources: set[str] = set()
    for index, raw_mapping in enumerate(raw_mappings):
        if not isinstance(raw_mapping, dict):
            raise ValueError(f"path_mappings[{index}] must be a table")
        _require_keys(raw_mapping, {"source", "target"}, f"path_mappings[{index}]")
        source_path = _normalize_windows_absolute(_require_string(raw_mapping, "source"))
        target_path = _normalize_target_absolute(
            _require_string(raw_mapping, "target"),
            target_platform,
        )
        source_key = ntpath.normcase(source_path)
        if source_key in seen_sources:
            raise ValueError(f"duplicate path mapping source: {source_path}")
        seen_sources.add(source_key)
        mappings.append(PathMapping(source=source_path, target=target_path))

    mappings.sort(key=lambda mapping: len(ntpath.normcase(mapping.source)), reverse=True)
    return ExportJob(
        config_path=config_path,
        source_profile=source_profile,
        flavor=flavor,
        target_platform=target_platform,
        output_manifest=output_manifest,
        path_mappings=tuple(mappings),
    )


def build_export_manifest(job: ExportJob) -> dict[str, Any]:
    """Build one validated portable import manifest without writing it."""

    config_dir = resolve_emule_config_dir(job.source_profile)
    detected_flavor = detect_profile_flavor(config_dir)
    if job.flavor != "auto" and job.flavor != detected_flavor:
        raise ValueError(
            f"source.flavor is {job.flavor!r}, but profile files identify {detected_flavor!r}"
        )

    known_met = config_dir / "known.met"
    if not known_met.is_file():
        raise ValueError(f"eMule profile is missing known.met under {config_dir}")
    known2_met = next(
        (candidate for candidate in (config_dir / "known2_64.met", config_dir / "known2.met") if candidate.is_file()),
        None,
    )
    known_rows, known_summary = mfc_known_met.build_imported_known_rows(
        known_met=known_met,
        known2_met=known2_met,
    )
    if not known_rows:
        raise ValueError("known.met did not contain any reusable hash records")

    discovered_roots = discover_shared_roots(config_dir, detected_flavor)
    if not discovered_roots:
        raise ValueError("profile did not contain any shared-directory roots")
    mapped_roots = [
        {
            "path": map_shared_root(root.path, job),
            "origin": root.origin,
        }
        for root in discovered_roots
    ]
    mapped_roots = _dedupe_mapped_roots(mapped_roots, job.target_platform)

    return {
        "schema": MANIFEST_SCHEMA,
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "targetPlatform": job.target_platform,
        "source": {
            "flavor": detected_flavor,
            "knownMet": known_met.name,
            "known2Met": known2_met.name if known2_met is not None else None,
        },
        "sharedRoots": mapped_roots,
        "knownFiles": [_manifest_known_file(row) for row in known_rows],
        "summary": {
            **known_summary,
            "discoveredSharedRoots": len(discovered_roots),
            "mappedSharedRoots": len(mapped_roots),
        },
    }


def discover_shared_roots(config_dir: Path, flavor: str) -> list[DiscoveredRoot]:
    """Discover the Incoming directory and explicit/monitored shared roots."""

    roots: list[DiscoveredRoot] = []
    preferences = config_dir / "preferences.ini"
    if preferences.is_file():
        incoming = parse_ini_values(read_ini_text(preferences)).get("IncomingDir", "").strip()
        if incoming:
            roots.append(DiscoveredRoot(_normalize_windows_absolute(incoming), "incoming"))

    shareddir = config_dir / "shareddir.dat"
    if not shareddir.is_file():
        return _dedupe_discovered_roots(roots)
    shared = _load_profile_paths(shareddir)
    monitored_file = config_dir / "shareddir.monitored.dat"
    monitored = (
        _load_profile_paths(monitored_file)
        if flavor == "mfc" and monitored_file.is_file()
        else []
    )
    monitor_owned_file = config_dir / "shareddir.monitor-owned.dat"
    monitor_owned = (
        {
            ntpath.normcase(path)
            for path in _load_profile_paths(monitor_owned_file)
        }
        if flavor == "mfc" and monitor_owned_file.is_file()
        else set()
    )

    if monitored:
        roots.extend(DiscoveredRoot(path, "mfc-monitored") for path in monitored)
        monitored_keys = [ntpath.normcase(path) for path in monitored]
        explicit_shared: list[str] = []
        for path in shared:
            key = ntpath.normcase(path)
            if key in monitor_owned or any(_windows_path_is_under(key, root) for root in monitored_keys):
                continue
            explicit_shared.append(path)
        collapsed = mfc_profile_import._collapse_stock_shareddir_roots(explicit_shared)
        roots.extend(DiscoveredRoot(_normalize_windows_absolute(path), "shareddir") for path in collapsed)
    else:
        collapsed = mfc_profile_import._collapse_stock_shareddir_roots(shared)
        roots.extend(DiscoveredRoot(_normalize_windows_absolute(path), "shareddir") for path in collapsed)
    return _dedupe_discovered_roots(roots)


def detect_profile_flavor(config_dir: Path) -> str:
    """Return ``mfc`` when eMuleBB monitored-root sidecars are present."""

    if any(
        (config_dir / name).is_file()
        for name in ("shareddir.monitored.dat", "shareddir.monitor-owned.dat")
    ):
        return "mfc"
    return "stock"


def resolve_emule_config_dir(profile: Path) -> Path:
    """Accept either an eMule profile root or its config directory."""

    resolved = profile.expanduser().resolve()
    if (resolved / "known.met").is_file():
        return resolved
    nested = resolved / "config"
    if (nested / "known.met").is_file():
        return nested
    raise ValueError(f"no eMule config directory with known.met found under {resolved}")


def map_shared_root(source_root: str, job: ExportJob) -> str:
    """Map one Windows root with longest-prefix, path-boundary semantics."""

    normalized = _normalize_windows_absolute(source_root)
    normalized_key = ntpath.normcase(normalized)
    for mapping in job.path_mappings:
        mapping_key = ntpath.normcase(mapping.source)
        if not _windows_path_is_under(normalized_key, mapping_key):
            continue
        relative = ntpath.relpath(normalized, mapping.source)
        if relative == ".":
            return mapping.target
        relative_parts = [part for part in relative.replace("/", "\\").split("\\") if part]
        if job.target_platform == "windows":
            return ntpath.normpath(ntpath.join(mapping.target, *relative_parts))
        return posixpath.normpath(posixpath.join(mapping.target, *relative_parts))
    if job.target_platform == "windows":
        return normalized
    raise ValueError(f"shared root requires a path mapping for {job.target_platform}: {source_root}")


def export_manifest(job: ExportJob, manifest: dict[str, Any]) -> Path:
    """Write a manifest atomically to the configured output path."""

    output = job.output_manifest
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f"{output.name}.tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, output)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("check", "export"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)

    job = load_export_job(args.config)
    manifest = build_export_manifest(job)
    if args.command == "export":
        export_manifest(job, manifest)
    print(
        json.dumps(
            {
                "schema": manifest["schema"],
                "targetPlatform": manifest["targetPlatform"],
                "outputManifest": str(job.output_manifest),
                "summary": manifest["summary"],
                "sharedRoots": manifest["sharedRoots"],
                "written": args.command == "export",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _manifest_known_file(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "fileHash": row["ed2k_hash"],
        "displayName": row["name"],
        "fileSize": row["size_bytes"],
        "modifiedS": row["modified_s"],
        "md4Hashset": row["md4_hashset"],
        "aichRoot": row["aich_root"],
        "aichHashset": row["aich_hashset"],
        "uploadPriority": row["upload_priority"],
        "autoUploadPriority": row["auto_upload_priority"],
        "allTimeUploadedBytes": row["all_time_uploaded_bytes"],
        "allTimeUploadRequests": row["all_time_upload_requests"],
        "allTimeUploadAccepts": row["all_time_upload_accepts"],
        "lastUploadRequestMs": row["last_upload_request_ms"],
    }


def _load_profile_paths(path: Path) -> list[str]:
    return [
        _normalize_windows_absolute(line)
        for line in read_ini_text(path).splitlines()
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    ]


def _dedupe_discovered_roots(roots: list[DiscoveredRoot]) -> list[DiscoveredRoot]:
    unique: dict[str, DiscoveredRoot] = {}
    for root in roots:
        unique.setdefault(ntpath.normcase(root.path), root)
    return list(unique.values())


def _dedupe_mapped_roots(roots: list[dict[str, str]], platform: str) -> list[dict[str, str]]:
    unique: dict[str, dict[str, str]] = {}
    for root in roots:
        key = ntpath.normcase(root["path"]) if platform == "windows" else root["path"]
        unique.setdefault(key, root)
    return list(unique.values())


def _windows_path_is_under(candidate_key: str, root_key: str) -> bool:
    if candidate_key == root_key:
        return True
    separator = "" if root_key.endswith(("\\", "/")) else "\\"
    return candidate_key.startswith(f"{root_key}{separator}")


def _normalize_windows_absolute(value: str) -> str:
    clean = mfc_known_met.normal_windows_display_path(value.strip())
    if any(part == ".." for part in clean.replace("/", "\\").split("\\")):
        raise ValueError(f"Windows path must not contain traversal: {value}")
    normalized = ntpath.normpath(clean)
    if not ntpath.isabs(normalized):
        raise ValueError(f"Windows path must be absolute: {value}")
    return normalized


def _normalize_target_absolute(value: str, platform: str) -> str:
    clean = value.strip()
    if platform == "windows":
        return _normalize_windows_absolute(clean)
    clean = clean.replace("\\", "/")
    if any(part == ".." for part in clean.split("/")):
        raise ValueError(f"{platform} path must not contain traversal: {value}")
    normalized = posixpath.normpath(clean)
    if not normalized.startswith("/"):
        raise ValueError(f"{platform} path must be absolute: {value}")
    return normalized


def _canonical_target_platform(value: str) -> str:
    platform = value.strip().lower()
    if platform not in SUPPORTED_TARGET_PLATFORMS:
        raise ValueError(f"target.platform must be one of {sorted(SUPPORTED_TARGET_PLATFORMS)}")
    return "unix" if platform in {"linux", "macos"} else platform


def _resolve_job_path(config_path: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else (config_path.parent / path).resolve()


def _require_table(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be a table")
    return value


def _require_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _require_keys(payload: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValueError(f"{label} contains unknown field(s): {', '.join(unknown)}")
