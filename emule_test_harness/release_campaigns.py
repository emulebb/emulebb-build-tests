"""Release campaign manifest loading, validation, and status reporting."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from emule_test_harness import live_e2e_suite

SCHEMA_VERSION = "emulebb-build-tests.release-campaign.v1"
DEFAULT_TEMPLATE_ID = "emulebb.release.template.default.v1"
DEFAULT_CAMPAIGN_ID = "emulebb-0.7.3"
PROOF_TIERS = (
    "rc-blocking-quick",
    "overnight-full",
    "future",
)
STRICT_PHASE_TAXONOMY = (
    "preflight",
    "protocol-parity",
    "controller-surface",
    "live-wire-release",
    "ui-resource-depth",
    "stabilization-stress",
    "packaging-provenance",
)
TERMINAL_STATUS_VALUES = (
    "passed",
    "failed",
    "inconclusive",
    "present",
    "missing-evidence",
    "stale-evidence",
    "manual",
    "unknown",
)


class ReleaseCampaignError(ValueError):
    """Raised when release campaign manifests are malformed."""


@dataclass(frozen=True)
class ReleaseCampaignPaths:
    """Filesystem roots used when resolving release campaign evidence."""

    tests_repo_root: Path
    emule_workspace_root: Path | None = None
    workspace_state_root: Path | None = None

    def base_path(self, base: str) -> Path:
        """Returns the filesystem base for one manifest evidence entry."""

        if base == "tests-repo":
            return self.tests_repo_root
        if base == "emule-workspace-root":
            if self.emule_workspace_root is None:
                raise ReleaseCampaignError("Evidence requires an eMule workspace root.")
            return self.emule_workspace_root
        if base == "workspace-state":
            if self.workspace_state_root is not None:
                return self.workspace_state_root
            if self.emule_workspace_root is None:
                raise ReleaseCampaignError("Evidence requires a workspace state root.")
            return self.emule_workspace_root / "workspaces" / "workspace" / "state"
        raise ReleaseCampaignError(f"Unsupported release campaign evidence base: {base}")


def release_campaign_manifest_root(tests_repo_root: Path) -> Path:
    """Returns the manifest directory for release campaign definitions."""

    return tests_repo_root / "manifests" / "release-campaigns"


def load_release_campaign_template(tests_repo_root: Path, template_id: str = DEFAULT_TEMPLATE_ID) -> dict[str, Any]:
    """Loads one release campaign template manifest by id."""

    for manifest in _load_manifests(tests_repo_root):
        if manifest.get("kind") == "template" and manifest.get("templateId") == template_id:
            return manifest
    raise ReleaseCampaignError(f"Release campaign template not found: {template_id}")


def load_release_campaign(tests_repo_root: Path, campaign_id: str = DEFAULT_CAMPAIGN_ID) -> dict[str, Any]:
    """Loads one release campaign instance manifest by id."""

    for manifest in _load_manifests(tests_repo_root):
        if manifest.get("kind") == "instance" and manifest.get("campaignId") == campaign_id:
            return manifest
    raise ReleaseCampaignError(f"Release campaign not found: {campaign_id}")


def validate_release_campaign_template(template: dict[str, Any]) -> list[str]:
    """Validates the generic release campaign template and returns warnings."""

    _require_schema(template)
    if template.get("kind") != "template":
        raise ReleaseCampaignError("Release campaign template kind must be 'template'.")
    if template.get("templateId") != DEFAULT_TEMPLATE_ID:
        raise ReleaseCampaignError(f"Release campaign template id must be {DEFAULT_TEMPLATE_ID!r}.")
    taxonomy = _required_dict(template, "taxonomy")
    phase_ids = tuple(str(phase.get("id")) for phase in _required_list(taxonomy, "phases"))
    if phase_ids != STRICT_PHASE_TAXONOMY:
        raise ReleaseCampaignError(
            "Release campaign phase taxonomy must be "
            + ", ".join(STRICT_PHASE_TAXONOMY)
            + f"; got {', '.join(phase_ids)}."
        )
    return []


def validate_release_campaign(campaign: dict[str, Any], template: dict[str, Any]) -> list[str]:
    """Validates one release campaign instance and returns warn-only coverage gaps."""

    validate_release_campaign_template(template)
    _require_schema(campaign)
    if campaign.get("kind") != "instance":
        raise ReleaseCampaignError("Release campaign instance kind must be 'instance'.")
    if campaign.get("templateId") != template.get("templateId"):
        raise ReleaseCampaignError("Release campaign instance references the wrong template id.")
    _required_str(campaign, "campaignId")
    _required_str(campaign, "releaseVersion")
    _required_str(campaign, "title")
    _required_str(campaign, "description")
    proof_tier = _required_str(campaign, "proofTier")
    if proof_tier not in PROOF_TIERS:
        raise ReleaseCampaignError(f"Release campaign proofTier must be one of: {', '.join(PROOF_TIERS)}.")
    phases = _required_list(campaign, "phases")
    phase_ids = tuple(str(phase.get("id")) for phase in phases)
    if phase_ids != STRICT_PHASE_TAXONOMY:
        raise ReleaseCampaignError(
            "Release campaign instance phases must match the strict taxonomy: "
            + ", ".join(STRICT_PHASE_TAXONOMY)
        )

    warnings: list[str] = []
    scenario_ids: set[str] = set()
    for phase in phases:
        phase_id = str(phase["id"])
        for scenario in _required_list(phase, "scenarios"):
            scenario_id = _required_str(scenario, "id")
            if scenario_id in scenario_ids:
                raise ReleaseCampaignError(f"Duplicate release campaign scenario id: {scenario_id}")
            scenario_ids.add(scenario_id)
            if scenario.get("phase") != phase_id:
                raise ReleaseCampaignError(f"Scenario {scenario_id} must declare phase {phase_id}.")
            _validate_scenario_mapping(scenario)

    gate_ids: set[str] = set()
    for gate in _required_list(campaign, "releaseGates"):
        gate_id = _required_str(gate, "id")
        if gate_id in gate_ids:
            raise ReleaseCampaignError(f"Duplicate release gate id: {gate_id}")
        gate_ids.add(gate_id)
        covered_by = tuple(str(value) for value in gate.get("coveredBy", ()))
        if not covered_by:
            warnings.append(f"Release gate {gate_id} is not mapped to any feature-flow scenario.")
            continue
        for scenario_id in covered_by:
            if scenario_id not in scenario_ids:
                warnings.append(f"Release gate {gate_id} references unknown scenario {scenario_id}.")
    return warnings


def build_release_campaign_report(
    paths: ReleaseCampaignPaths,
    *,
    campaign_id: str = DEFAULT_CAMPAIGN_ID,
    phase_id: str | None = None,
    show_template: bool = False,
) -> dict[str, Any]:
    """Builds a warn-only release campaign matrix and latest-evidence status report."""

    template = load_release_campaign_template(paths.tests_repo_root)
    template_warnings = validate_release_campaign_template(template)
    if show_template:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "kind": "template-report",
            "templateId": template["templateId"],
            "taxonomy": template["taxonomy"],
            "warnings": template_warnings,
        }

    campaign = load_release_campaign(paths.tests_repo_root, campaign_id)
    warnings = validate_release_campaign(campaign, template)
    scenario_reports: list[dict[str, Any]] = []
    for phase in campaign["phases"]:
        if phase_id is not None and phase["id"] != phase_id:
            continue
        for scenario in phase["scenarios"]:
            scenario_reports.append(_build_scenario_report(paths, phase, scenario))

    if phase_id is not None and not any(phase["id"] == phase_id for phase in campaign["phases"]):
        raise ReleaseCampaignError(f"Unknown release campaign phase: {phase_id}")

    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "campaign-report",
        "campaignId": campaign["campaignId"],
        "templateId": campaign["templateId"],
        "releaseVersion": campaign.get("releaseVersion", ""),
        "title": campaign.get("title", ""),
        "description": campaign.get("description", ""),
        "proofTier": campaign.get("proofTier", ""),
        "phase": phase_id or "",
        "statusPolicy": "warn-only",
        "warnings": warnings,
        "scenarios": scenario_reports,
    }


def format_release_campaign_report(report: dict[str, Any]) -> str:
    """Formats a release campaign report as a compact terminal table."""

    if report.get("kind") == "template-report":
        phases = report["taxonomy"]["phases"]
        lines = [
            f"Template: {report['templateId']}",
            "",
            "Phase                  Description",
            "---------------------  ----------------------------------------",
        ]
        for phase in phases:
            lines.append(f"{phase['id']:<21}  {phase['title']}")
        return "\n".join(lines)

    lines = [
        f"Campaign: {report['campaignId']}",
        f"Title: {report.get('title') or report['campaignId']}",
        f"Release: {report.get('releaseVersion') or 'generic'}",
        f"Proof tier: {report.get('proofTier') or 'unspecified'}",
        f"Status policy: {report['statusPolicy']}",
        "",
        "Phase                  Req  Status            Scenario",
        "---------------------  ---  ----------------  ----------------------------------------",
    ]
    for scenario in report["scenarios"]:
        req = "yes" if scenario["required"] else "no"
        lines.append(
            f"{scenario['phase']:<21}  {req:<3}  {scenario['status']:<16}  {scenario['id']}"
        )
        lines.append(f"{'':<21}       command: {scenario['command']}")
        for warning in scenario["warnings"]:
            lines.append(f"{'':<21}       warning: {warning}")
    if report["warnings"]:
        lines.extend(["", "Warnings:"])
        lines.extend(f"- {warning}" for warning in report["warnings"])
    return "\n".join(lines)


def _load_manifests(tests_repo_root: Path) -> list[dict[str, Any]]:
    manifest_dir = release_campaign_manifest_root(tests_repo_root)
    if not manifest_dir.is_dir():
        raise ReleaseCampaignError(f"Release campaign manifest directory is missing: {manifest_dir}")
    manifests: list[dict[str, Any]] = []
    for path in sorted(manifest_dir.glob("*.json")):
        if path.name.endswith(".schema.json"):
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            manifests.append(payload)
    return manifests


def _build_scenario_report(paths: ReleaseCampaignPaths, phase: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
    evidence_reports = [_build_evidence_report(paths, evidence) for evidence in scenario.get("evidence", ())]
    warnings = _scenario_warnings(evidence_reports)
    return {
        "id": scenario["id"],
        "title": scenario["title"],
        "phase": phase["id"],
        "phaseTitle": phase["title"],
        "flowCategory": scenario["flowCategory"],
        "required": bool(scenario.get("required", True)),
        "blocking": bool(scenario.get("blocking", True)),
        "command": scenario.get("command", "manual"),
        "status": _aggregate_evidence_status(evidence_reports),
        "warnings": warnings,
        "evidence": evidence_reports,
        "localInputs": scenario.get("localInputs", []),
    }


def _build_evidence_report(paths: ReleaseCampaignPaths, evidence: dict[str, Any]) -> dict[str, Any]:
    required = bool(evidence.get("required", True))
    if evidence.get("kind") == "manual":
        return {
            "kind": "manual",
            "required": required,
            "status": "manual",
            "description": evidence.get("description", ""),
        }

    base = paths.base_path(str(evidence.get("base", "tests-repo")))
    expected = str(evidence.get("path") or evidence.get("glob") or "")
    resolved = _resolve_evidence_path(base, evidence)
    if resolved is None:
        return {
            "kind": evidence.get("kind", "artifact"),
            "required": required,
            "status": "missing-evidence",
            "expected": expected,
        }

    status = _read_evidence_status(resolved, evidence)
    return {
        "kind": evidence.get("kind", "artifact"),
        "required": required,
        "status": status,
        "path": str(resolved),
        "expected": expected,
    }


def _resolve_evidence_path(base: Path, evidence: dict[str, Any]) -> Path | None:
    relative_path = evidence.get("path")
    if isinstance(relative_path, str) and relative_path:
        path = (base / relative_path).resolve()
        return path if path.exists() else None
    glob_pattern = evidence.get("glob")
    if isinstance(glob_pattern, str) and glob_pattern:
        matches = sorted(
            (path for path in base.glob(glob_pattern) if path.exists()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if not matches:
            return None
        if isinstance(evidence.get("matches"), dict):
            matching_path = next((path for path in matches if _evidence_matches(path, evidence)), None)
            if matching_path is not None:
                return matching_path.resolve()
        return matches[0].resolve()
    return None


def _evidence_matches(path: Path, evidence: dict[str, Any]) -> bool:
    matches = evidence.get("matches")
    if not isinstance(matches, dict):
        return True
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return all(_json_pointer(payload, str(pointer)) == expected for pointer, expected in matches.items())


def _read_evidence_status(path: Path, evidence: dict[str, Any]) -> str:
    status_pointer = evidence.get("statusPointer")
    matches = evidence.get("matches")
    if not status_pointer and not matches:
        return "present"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "unknown"
    if isinstance(matches, dict):
        for pointer, expected in matches.items():
            if _json_pointer(payload, str(pointer)) != expected:
                return "stale-evidence"
    if not status_pointer:
        return "present"
    value = _json_pointer(payload, str(status_pointer))
    if isinstance(value, str) and value in TERMINAL_STATUS_VALUES:
        return value
    return "present"


def _json_pointer(payload: Any, pointer: str) -> Any:
    if pointer in ("", "/"):
        return payload
    current = payload
    for raw_part in pointer.strip("/").split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        else:
            return None
    return current


def _aggregate_evidence_status(evidence_reports: list[dict[str, Any]]) -> str:
    if not evidence_reports:
        return "unknown"
    required_reports = [report for report in evidence_reports if report["required"]]
    status_reports = required_reports or evidence_reports
    statuses = [str(report["status"]) for report in status_reports]
    if "failed" in statuses:
        return "failed"
    if any(report["required"] and report["status"] in {"missing-evidence", "stale-evidence"} for report in evidence_reports):
        return "missing-evidence"
    if "inconclusive" in statuses:
        return "inconclusive"
    if all(status in {"passed", "present", "manual"} for status in statuses):
        return "passed" if any(status == "passed" for status in statuses) else statuses[0]
    return "unknown"


def _scenario_warnings(evidence_reports: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    for report in evidence_reports:
        if report["required"] and report["status"] == "missing-evidence":
            warnings.append(f"missing required evidence: {report.get('expected', '')}")
        if report["required"] and report["status"] == "stale-evidence":
            warnings.append(f"latest evidence does not match this scenario: {report.get('expected', '')}")
    return warnings


def _validate_scenario_mapping(scenario: dict[str, Any]) -> None:
    scenario_id = _required_str(scenario, "id")
    command = _required_str(scenario, "command")
    _required_str(scenario, "title")
    _required_str(scenario, "flowCategory")
    if command.startswith("python -m emule_workspace test live-e2e"):
        profile = scenario.get("liveE2eProfile")
        suite = scenario.get("liveE2eSuite")
        if profile and profile not in live_e2e_suite.LIVE_E2E_PROFILES:
            raise ReleaseCampaignError(f"Scenario {scenario_id} references unknown live E2E profile: {profile}")
        if suite and suite not in live_e2e_suite.SUITE_NAMES:
            raise ReleaseCampaignError(f"Scenario {scenario_id} references unknown live E2E suite: {suite}")


def _require_schema(payload: dict[str, Any]) -> None:
    if payload.get("schemaVersion") != SCHEMA_VERSION:
        raise ReleaseCampaignError(f"Release campaign schemaVersion must be {SCHEMA_VERSION!r}.")


def _required_dict(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ReleaseCampaignError(f"Release campaign manifest field {key!r} must be an object.")
    return value


def _required_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = payload.get(key)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ReleaseCampaignError(f"Release campaign manifest field {key!r} must be an object list.")
    return value


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ReleaseCampaignError(f"Release campaign manifest field {key!r} must be a non-empty string.")
    return value
