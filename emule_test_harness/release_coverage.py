"""Release coverage ownership manifest loading and validation."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "emulebb-build-tests.release-coverage.v1"
DEFAULT_MANIFEST_PATH = Path("manifests") / "release-coverage" / "ownership.v1.json"
OWNER_LANES = {
    "native",
    "python-harness",
    "live-e2e",
    "campaign",
    "packaging",
    "deferred",
}
RELEASE_PHASES = {
    "preflight",
    "protocol-parity",
    "controller-surface",
    "live-wire-release",
    "ui-resource-depth",
    "stabilization-stress",
    "packaging-provenance",
}
STATUSES = {"covered", "planned", "deferred"}


@dataclass(frozen=True)
class ReleaseCoverageValidation:
    """Result from validating a release coverage ownership manifest."""

    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        """Returns whether the manifest is valid."""

        return not self.errors


def default_manifest_path(tests_repo_root: Path) -> Path:
    """Returns the canonical release coverage ownership manifest path."""

    return tests_repo_root / DEFAULT_MANIFEST_PATH


def load_release_coverage_manifest(tests_repo_root: Path, manifest_path: Path | None = None) -> dict[str, Any]:
    """Loads the release coverage ownership manifest."""

    path = manifest_path or default_manifest_path(tests_repo_root)
    return json.loads(path.read_text(encoding="utf-8"))


def validate_release_coverage_manifest(
    manifest: dict[str, Any],
    *,
    campaign_scenario_ids: set[str] | None = None,
) -> ReleaseCoverageValidation:
    """Validates release ownership metadata without reading live evidence."""

    errors: list[str] = []
    if manifest.get("schemaVersion") != SCHEMA_VERSION:
        errors.append(f"schemaVersion must be {SCHEMA_VERSION!r}.")

    areas = manifest.get("areas")
    if not isinstance(areas, list) or not areas:
        errors.append("areas must be a non-empty list.")
        return ReleaseCoverageValidation(tuple(errors))

    seen_ids: set[str] = set()
    for index, area in enumerate(areas):
        if not isinstance(area, dict):
            errors.append(f"areas[{index}] must be an object.")
            continue
        area_id = str(area.get("id") or "")
        if not area_id:
            errors.append(f"areas[{index}] is missing id.")
        elif area_id in seen_ids:
            errors.append(f"duplicate area id: {area_id}")
        seen_ids.add(area_id)

        owner_lane = area.get("ownerLane")
        status = area.get("status")
        phase = area.get("releasePhase")
        blocking = bool(area.get("blocking", False))
        coverage = area.get("coverage")
        deferred_reason = str(area.get("deferredReason") or "")
        campaign_ids = area.get("campaignScenarioIds", [])
        globs = area.get("appPathGlobs", [])

        if owner_lane not in OWNER_LANES:
            errors.append(f"{area_id}: unsupported ownerLane {owner_lane!r}.")
        if status not in STATUSES:
            errors.append(f"{area_id}: unsupported status {status!r}.")
        if phase not in RELEASE_PHASES:
            errors.append(f"{area_id}: unsupported releasePhase {phase!r}.")
        if not isinstance(globs, list) or not globs:
            errors.append(f"{area_id}: appPathGlobs must be non-empty.")
        else:
            for glob in globs:
                if not isinstance(glob, str) or not glob.startswith("srchybrid/") or ":" in glob:
                    errors.append(f"{area_id}: appPathGlob must be a relative srchybrid path: {glob!r}.")

        if status == "covered":
            if not isinstance(coverage, list) or not coverage:
                errors.append(f"{area_id}: covered areas must list concrete coverage.")
            if deferred_reason:
                errors.append(f"{area_id}: covered areas must not carry deferredReason.")
        if status == "deferred":
            if not deferred_reason:
                errors.append(f"{area_id}: deferred areas must carry deferredReason.")
            if blocking:
                errors.append(f"{area_id}: deferred areas cannot be blocking release gates.")
        if blocking and not campaign_ids:
            errors.append(f"{area_id}: blocking areas must map to a campaign scenario.")
        if campaign_ids and not isinstance(campaign_ids, list):
            errors.append(f"{area_id}: campaignScenarioIds must be a list.")
        elif campaign_scenario_ids is not None:
            for scenario_id in campaign_ids:
                if scenario_id not in campaign_scenario_ids:
                    errors.append(f"{area_id}: unknown campaign scenario {scenario_id!r}.")

    return ReleaseCoverageValidation(tuple(errors))


def release_candidate_area_ids(manifest: dict[str, Any]) -> set[str]:
    """Returns area ids considered in scope for release ownership."""

    areas = manifest.get("areas", [])
    return {str(area["id"]) for area in areas if isinstance(area, dict) and area.get("releaseOwned", True)}


def clone_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Returns a mutable deep copy for tests and tooling transforms."""

    return copy.deepcopy(manifest)
