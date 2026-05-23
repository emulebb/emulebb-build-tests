from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA = "emulebb-build-tests.release-live-wire-golden.v1"


def get_release_live_wire_golden_path(test_repo_root: Path) -> Path:
    """Returns the tracked release live-wire golden-vector manifest path."""

    return test_repo_root.resolve() / "manifests" / "release-live-wire-golden.v1.json"


def load_release_live_wire_golden(test_repo_root: Path) -> dict[str, Any]:
    """Loads the release live-wire golden-vector manifest."""

    path = get_release_live_wire_golden_path(test_repo_root)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != SCHEMA:
        raise ValueError(f"Unexpected release live-wire golden schema in '{path}'.")
    return payload
