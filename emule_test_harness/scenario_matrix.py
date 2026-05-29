"""Generated live E2E scenario matrix from the maintained suite registry."""

from __future__ import annotations

from typing import Any

from emule_test_harness import live_e2e_suite

SCHEMA = "emulebb-build-tests.live-e2e-scenario-matrix.v1"


def build_live_e2e_scenario_matrix() -> dict[str, Any]:
    """Returns a machine-readable matrix for live E2E suite consistency audits."""

    profile_membership = suite_profile_membership()
    suites = [
        {
            "name": spec.name,
            "script": spec.script_name,
            "category": spec.category,
            "networkScope": spec.network_scope,
            "profiles": profile_membership.get(spec.name, ()),
            "profileStages": classify_profile_stages(spec),
            "defaultEnabled": spec.default_enabled,
            "topology": classify_topology(spec),
            "stressClass": classify_stress(spec),
            "fixtureScope": classify_fixture_scope(spec),
            "adminVolumePolicy": classify_admin_volume_policy(spec),
            "optionalClientPolicy": classify_optional_client_policy(spec),
            "diagnostics": classify_diagnostics(spec),
        }
        for spec in live_e2e_suite.SUITE_SPECS
    ]
    return {
        "schema": SCHEMA,
        "suiteCount": len(suites),
        "profiles": {name: list(suites) for name, suites in live_e2e_suite.PROFILE_SUITE_NAMES.items()},
        "suites": suites,
        "gaps": summarize_matrix_gaps(suites),
    }


def suite_profile_membership() -> dict[str, tuple[str, ...]]:
    """Maps each suite to the explicit live E2E profiles that include it."""

    membership: dict[str, list[str]] = {name: [] for name in live_e2e_suite.SUITE_NAMES}
    for profile, suite_names in live_e2e_suite.PROFILE_SUITE_NAMES.items():
        for suite_name in suite_names:
            membership.setdefault(suite_name, []).append(profile)
    return {name: tuple(profiles) for name, profiles in membership.items()}


def classify_topology(spec: live_e2e_suite.SuiteSpec) -> str:
    """Classifies the client/process topology exercised by one suite."""

    if spec.name == "godzilla-local-swarm":
        return "large-local-swarm"
    if spec.name in {"local-kad-swarm", "local-kad-mixed-client-swarm", "multi-client-p2p-matrix"}:
        return "local-swarm"
    if spec.name in {"deterministic-two-client-transfer", "local-ed2k-search-soak", "local-ed2k-chaos-mode", "local-ed2k-protocol-combinations"}:
        return "local-two-client"
    if spec.is_arr_emulebb or spec.is_prowlarr_emulebb or spec.is_amutorrent_browser or spec.name.startswith("amutorrent-"):
        return "controller-stack"
    if spec.category == "storage":
        return "single-client-storage"
    if spec.category == "ui":
        return "single-client-ui"
    if spec.category == "rest":
        return "single-client-rest"
    return "single-client"


def classify_stress(spec: live_e2e_suite.SuiteSpec) -> str:
    """Classifies the primary load/adversity tier for one suite."""

    name = spec.name
    if name == "godzilla-local-swarm":
        return "hammer"
    if "chaos" in name:
        return "chaos"
    if "soak" in name or name == "live-process-monitor":
        return "soak"
    if "stress" in name or spec.is_rest_cold_start_dump_stress:
        return "stress"
    if name in {"multi-client-p2p-matrix", "local-ed2k-protocol-combinations", "category-incoming-path-matrix"}:
        return "matrix"
    if name in {"local-dumps-crash-smoke", "resource-ui-smoke", "command-line-smoke"}:
        return "smoke"
    return "scenario"


def classify_fixture_scope(spec: live_e2e_suite.SuiteSpec) -> str:
    """Classifies the main fixture or runtime state scope."""

    if spec.requires_admin_volume_fixtures or spec.accepts_admin_volume_fixtures:
        return "admin-volume"
    if spec.uses_live_seed_refresh:
        return "live-wire-profile"
    if spec.network_scope == "lan":
        return "local-stack"
    if spec.category == "storage":
        return "filesystem"
    return "isolated-profile"


def classify_admin_volume_policy(spec: live_e2e_suite.SuiteSpec) -> str:
    """Returns whether admin volume fixtures are required, accepted, or unused."""

    if spec.requires_admin_volume_fixtures:
        return "required"
    if spec.accepts_admin_volume_fixtures:
        return "accepted"
    return "unused"


def classify_optional_client_policy(spec: live_e2e_suite.SuiteSpec) -> str:
    """Classifies whether optional third-party clients affect evidence strength."""

    if spec.name == "multi-client-p2p-matrix":
        return "mixed-clients-optional-with-required-control"
    if spec.name == "godzilla-local-swarm":
        return "mixed-clients-runtime-optional"
    if spec.name == "local-kad-mixed-client-swarm":
        return "mixed-clients-required"
    if spec.name in {"deterministic-two-client-transfer", "local-ed2k-search-soak", "local-ed2k-chaos-mode", "local-ed2k-protocol-combinations", "local-kad-swarm"}:
        return "emulebb-and-harness-required"
    if spec.is_arr_emulebb or spec.is_prowlarr_emulebb or spec.is_amutorrent_browser or spec.name.startswith("amutorrent-"):
        return "controller-dependencies-required"
    return "none"


def classify_profile_stages(spec: live_e2e_suite.SuiteSpec) -> dict[str, str]:
    """Returns profile-specific child-stage defaults for suites that are staged."""

    if spec.name == "godzilla-local-swarm":
        return {"release-expanded": live_e2e_suite.RELEASE_EXPANDED_GODZILLA_STAGE}
    return {}


def classify_diagnostics(spec: live_e2e_suite.SuiteSpec) -> tuple[str, ...]:
    """Returns the diagnostic evidence families expected from one suite."""

    diagnostics: list[str] = []
    if spec.name in live_e2e_suite.CPU_PROFILED_SUITE_NAMES or spec.name == "godzilla-local-swarm":
        diagnostics.append("cpu-profile-optional")
    if spec.is_rest_cold_start_dump_stress or spec.name in {"local-dumps-crash-smoke", "live-process-monitor", "godzilla-local-swarm"}:
        diagnostics.append("dump-or-resource-evidence")
    if spec.accepts_startup_trace_mode:
        diagnostics.append("startup-trace")
    return tuple(diagnostics)


def summarize_matrix_gaps(suites: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Identifies consistency gaps that should be resolved by later scenario work."""

    gaps: list[dict[str, str]] = []
    for suite in suites:
        if suite["name"] == "godzilla-local-swarm" and "release-expanded" not in suite["profiles"]:
            gaps.append(
                {
                    "suite": suite["name"],
                    "gap": "large local swarm hammer is not RC-profile-visible",
                }
            )
        if suite["optionalClientPolicy"] == "mixed-clients-optional-with-required-control":
            gaps.append(
                {
                    "suite": suite["name"],
                    "gap": "mixed-client optional policy weakens evidence unless --multi-client-require-optional-clients is enabled",
                }
            )
        if suite["optionalClientPolicy"] == "mixed-clients-runtime-optional":
            gaps.append(
                {
                    "suite": suite["name"],
                    "gap": "mixed-client runtime readiness can downgrade aMule evidence inside the hammer",
                }
            )
    return gaps
