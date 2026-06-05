"""Deterministic media inputs for local-swarm Arr acquisition tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from emule_test_harness import live_wire_inputs

SCHEMA = "emulebb-build-tests.local-swarm-media.v1"
GENERATED_INPUTS_FILE_NAME = "local-swarm-live-wire-inputs.generated.json"
ARCHIVE_INPUTS_FILE_NAME = live_wire_inputs.DEFAULT_INPUTS_FILE_NAME
DEFAULT_RADARR_MOVIE_TITLE = "Night of the Living Dead"
DEFAULT_SONARR_SERIES_TITLE = "Dragnet"
DEFAULT_SONARR_SERIES_YEAR = 1951


def build_local_swarm_live_wire_payload(
    *,
    local_package_install: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Builds a live-wire-compatible payload for offline local-swarm Arr lanes."""

    payload: dict[str, Any] = {
        "schema": live_wire_inputs.SCHEMA,
        "search_terms": {
            "generic_open": ["emulebb local swarm generated fixture"],
            "documents": ["emulebb local swarm generated document"],
            "radarr_movies": [DEFAULT_RADARR_MOVIE_TITLE],
            "sonarr_series": [DEFAULT_SONARR_SERIES_TITLE],
        },
        "auto_browse": {
            "bootstrap_transfer_hashes": [live_wire_inputs.PLACEHOLDER_HASH],
            "direct_bootstrap_transfers": [
                {
                    "hash": live_wire_inputs.PLACEHOLDER_HASH,
                    "name": "emulebb-local-swarm-placeholder.txt",
                    "size": 1,
                    "method": "direct_ed2k",
                }
            ],
        },
        "media_corpus": {
            "video_roots": [],
        },
        "local_swarm_media_fixture": {
            "schema": SCHEMA,
            "radarr_movie": {
                "title": DEFAULT_RADARR_MOVIE_TITLE,
                "public_domain": True,
            },
            "sonarr_series": {
                "title": DEFAULT_SONARR_SERIES_TITLE,
                "year": DEFAULT_SONARR_SERIES_YEAR,
            },
        },
    }
    if local_package_install is not None:
        payload["local_package_install"] = local_package_install
    return payload


def load_local_package_install_from_live_wire(path: Path) -> dict[str, Any] | None:
    """Reads only local dependency package settings from an operator input file."""

    if not path.is_file():
        return None
    payload = live_wire_inputs.load_live_wire_inputs_payload(path)
    value = payload.get("local_package_install")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RuntimeError(f"Live-wire inputs field 'local_package_install' must be an object: {path}")
    return value


def write_generated_local_swarm_inputs(
    path: Path,
    *,
    local_package_install: dict[str, Any] | None = None,
) -> Path:
    """Writes the deterministic local-swarm payload and returns the resolved path."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_local_swarm_live_wire_payload(local_package_install=local_package_install)
    live_wire_inputs.parse_live_wire_inputs(payload, path=path)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path.resolve()
