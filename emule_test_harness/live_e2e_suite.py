"""Aggregate live UI, REST, and live-wire E2E suite orchestration."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from emule_test_harness.live_seed_sources import EMULE_SECURITY_HOME_URL
from emule_test_harness import cpu_profile, live_wire_inputs

SHARED_FILES_UI_CORE_SCENARIOS = (
    "fixture-three-files",
    "generated-robustness-recursive",
    "duplicate-startup-reuse",
    "dynamic-folder-lifecycle",
    "monitored-folder-events",
)
SHARED_FILES_UI_STRESS_SCENARIOS = (
    "tree-refresh-stress-50k",
)
SHARED_FILES_UI_ADMIN_SCENARIOS = (
    "monitored-folder-events-vhd",
)
SHARED_FILES_UI_SCENARIOS = SHARED_FILES_UI_CORE_SCENARIOS + SHARED_FILES_UI_STRESS_SCENARIOS + SHARED_FILES_UI_ADMIN_SCENARIOS
CONFIG_STABILITY_UI_SCENARIOS = (
    "long-config-settings-roundtrip",
    "long-config-shared-stress",
)
STARTUP_PROFILE_SCENARIOS = (
    "baseline-no-shares",
    "fixture-three-files",
    "long-paths-root-only",
    "long-paths-recursive",
    "long-path-output-root-only",
    "long-path-output-recursive",
    "long-path-emule-fixture-root-only",
    "long-path-emule-fixture-recursive",
    "shared-files-robustness-root-only",
    "shared-files-robustness-recursive",
)
DEFAULT_REST_SEARCH_COUNT = 6
DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT = 1
DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT = 6
DEFAULT_ARR_PROWLARR_SEARCH_STRESS_COUNT = 4
BETA_GREEN_ARR_DIRECT_SEARCH_STRESS_COUNT = 2
BETA_GREEN_ARR_PROWLARR_SEARCH_STRESS_COUNT = 1
DEFAULT_EMULE_CONNECTION_TIMEOUT_SECONDS = 60.0
DEFAULT_ARR_SEARCH_TIMEOUT_SECONDS = 90.0
DEFAULT_DOCUMENT_DOWNLOAD_TIMEOUT_SECONDS = 300.0
DEFAULT_MEDIA_ACQUISITION_TIMEOUT_MINUTES = 30.0
DEFAULT_ARR_DOWNLOAD_PROOF_MODE = "complete"
DEFAULT_REST_COLD_START_DUMP_STRESS_WAVES = 4
DEFAULT_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE = 12
DEFAULT_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES = 8
DEFAULT_REST_COLD_START_DUMP_STRESS_SEARCH_OBSERVATION_TIMEOUT_SECONDS = 60.0
DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE = 600
DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_SEARCH = 50
DEFAULT_REST_COLD_START_DUMP_STRESS_MAX_MISSING_DOWNLOAD_TRIGGERS = 0
DEFAULT_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_COUNT = 0
DEFAULT_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_SIZE_BYTES = 1024 * 1024
DEFAULT_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_BATCH_SIZE = 50
DEFAULT_REST_COLD_START_DUMP_STRESS_TARGET_COMPLETED_DOWNLOADS = 0
DEFAULT_REST_COLD_START_DUMP_STRESS_COMPLETION_TIMEOUT_SECONDS = 1800.0
DEFAULT_REST_COLD_START_DUMP_STRESS_MAX_ACTIVE_DOWNLOADS = 512
DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOAD_CHURN_INTERVAL_SECONDS = 0.0
DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOAD_REMOVE_COUNT_PER_CHURN = 0
DEFAULT_REST_COLD_START_DUMP_STRESS_RESOURCE_MONITOR_INTERVAL_SECONDS = 5.0
DEFAULT_REST_COLD_START_DUMP_STRESS_POST_DRAIN_SECONDS = 30.0
DEFAULT_REST_COLD_START_DUMP_STRESS_TOOL_TIMEOUT_SECONDS = 60.0
DEFAULT_REST_COLD_START_DUMP_STRESS_CPU_PROFILE_MAX_FILE_MB = cpu_profile.DEFAULT_CPU_PROFILE_MAX_FILE_MB
DEFAULT_REST_COLD_START_DUMP_STRESS_CPU_PROFILE_STACK_MIN_HITS = 10
DEFAULT_SHARED_FILES_UI_CPU_PROFILE_MAX_FILE_MB = cpu_profile.DEFAULT_CPU_PROFILE_MAX_FILE_MB
DEFAULT_SHARED_FILES_UI_CPU_PROFILE_STACK_MIN_HITS = 10
DEFAULT_PROFILE_CPU_MAX_FILE_MB = cpu_profile.DEFAULT_CPU_PROFILE_MAX_FILE_MB
DEFAULT_PROFILE_CPU_STACK_MIN_HITS = 10
DEFAULT_PROFILE_RESOURCE_MONITOR_INTERVAL_SECONDS = 2.0
DEFAULT_SEARCH_UI_SEARCH_ROUNDS = 1
DEFAULT_SEARCH_UI_DOWNLOAD_LIFECYCLE_COUNT = 1
DEFAULT_RESOURCE_UI_LANGUAGE_TIMEOUT_SECONDS = 120.0
DEFAULT_CHILD_SUITE_TIMEOUT_SECONDS = 2.0 * 60.0 * 60.0
DEFAULT_CONTROLLER_STORAGE_VHD_SIZE_MB = 6144
DEFAULT_ARR_CONTROLLER_STORAGE_VHD_SIZE_MB = 32768
SUITE_TIMEOUT_RETURN_CODE = 124
RELEASE_EXPANDED_REST_SEARCH_COUNT_PER_NETWORK = 50
RELEASE_EXPANDED_REST_DOWNLOAD_TRIGGER_COUNT = 100
RELEASE_EXPANDED_REST_STRESS_DURATION_SECONDS = 45.0
RELEASE_EXPANDED_REST_STRESS_CONCURRENCY = 8
RELEASE_EXPANDED_REST_STRESS_MAX_FAILURES = 0
RELEASE_EXPANDED_REST_LEAK_CHURN_CYCLES = 4
RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_WAVES = 1
RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE = 3
RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES = 2
RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE = 0
RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_POST_DRAIN_SECONDS = 5.0
RELEASE_EXPANDED_SEARCH_UI_SEARCH_ROUNDS = 2
RELEASE_EXPANDED_SEARCH_UI_DOWNLOAD_LIFECYCLE_COUNT = 2
BETA_RELEASE_REST_COLD_START_DUMP_STRESS_WAVES = 1
BETA_RELEASE_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE = 3
BETA_RELEASE_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES = 2
BETA_RELEASE_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE = 0
BETA_RELEASE_REST_COLD_START_DUMP_STRESS_POST_DRAIN_SECONDS = 5.0
STABILIZATION_REST_STRESS_DURATION_SECONDS = 120.0
STABILIZATION_REST_STRESS_CONCURRENCY = 16
STABILIZATION_REST_STRESS_MAX_FAILURES = 0
STABILIZATION_REST_LEAK_CHURN_CYCLES = 8
STABILIZATION_REST_COLD_START_DUMP_STRESS_WAVES = 2
STABILIZATION_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE = 6
STABILIZATION_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES = 4
STABILIZATION_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE = 150
STABILIZATION_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_SEARCH = 25
STABILIZATION_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_COUNT = 300
STABILIZATION_REST_COLD_START_DUMP_STRESS_POST_DRAIN_SECONDS = 15.0
STABILIZATION_REST_COLD_START_DUMP_STRESS_DOWNLOAD_CHURN_INTERVAL_SECONDS = 10.0
STABILIZATION_REST_COLD_START_DUMP_STRESS_DOWNLOAD_REMOVE_COUNT_PER_CHURN = 20
STABILIZATION_SEARCH_UI_SEARCH_ROUNDS = 3
STABILIZATION_SEARCH_UI_DOWNLOAD_LIFECYCLE_COUNT = 2
CONTROLLER_SURFACE_ARR_DOWNLOAD_PROOF_MODE = "handoff"


@dataclass(frozen=True)
class SuiteSpec:
    """One child live E2E suite invoked by the aggregate runner."""

    name: str
    script_name: str
    category: str
    scenarios: tuple[str, ...] = ()
    accepts_startup_trace_mode: bool = False
    accepts_shared_root: bool = False
    uses_live_seed_refresh: bool = False
    is_rest_api: bool = False
    is_auto_browse: bool = False
    is_amutorrent_browser: bool = False
    is_prowlarr_emulebb: bool = False
    is_arr_emulebb: bool = False
    is_rest_cold_start_dump_stress: bool = False
    is_search_ui_live: bool = False
    is_resource_ui_smoke: bool = False
    accepts_mounted_shared_root: bool = False
    requires_admin_volume_fixtures: bool = False
    accepts_admin_volume_fixtures: bool = False
    default_enabled: bool = True


SUITE_SPECS = (
    SuiteSpec(
        name="resource-ui-smoke",
        script_name="resource-ui-smoke.py",
        category="ui",
        is_resource_ui_smoke=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="command-line-smoke",
        script_name="command-line-smoke.py",
        category="startup",
        default_enabled=False,
    ),
    SuiteSpec(name="preference-ui", script_name="preference-ui-e2e.py", category="ui"),
    SuiteSpec(
        name="shared-files-ui",
        script_name="shared-files-ui-e2e.py",
        category="ui",
        scenarios=SHARED_FILES_UI_CORE_SCENARIOS,
        accepts_startup_trace_mode=True,
        accepts_shared_root=True,
        accepts_admin_volume_fixtures=True,
    ),
    SuiteSpec(
        name="config-stability-ui",
        script_name="config-stability-ui-e2e.py",
        category="ui",
        scenarios=CONFIG_STABILITY_UI_SCENARIOS,
        accepts_startup_trace_mode=True,
        accepts_shared_root=True,
    ),
    SuiteSpec(
        name="search-ui-live",
        script_name="search-ui-live.py",
        category="ui",
        uses_live_seed_refresh=True,
        is_search_ui_live=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="shared-hash-ui",
        script_name="shared-hash-ui-e2e.py",
        category="ui",
        accepts_startup_trace_mode=True,
    ),
    SuiteSpec(
        name="startup-profile",
        script_name="startup-profile-scenarios.py",
        category="ui",
        scenarios=STARTUP_PROFILE_SCENARIOS,
        accepts_startup_trace_mode=True,
        accepts_shared_root=True,
    ),
    SuiteSpec(
        name="shared-directories-rest",
        script_name="shared-directories-rest-e2e.py",
        category="rest",
        accepts_mounted_shared_root=True,
        accepts_admin_volume_fixtures=True,
    ),
    SuiteSpec(
        name="shared-cache-volume-identity",
        script_name="shared-cache-volume-identity.py",
        category="storage",
        requires_admin_volume_fixtures=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="shared-cache-invalidation",
        script_name="shared-cache-invalidation.py",
        category="storage",
        requires_admin_volume_fixtures=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="unc-mapped-drive-identity",
        script_name="unc-mapped-drive-identity.py",
        category="storage",
        requires_admin_volume_fixtures=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="vhd-long-path-special-names",
        script_name="vhd-long-path-special-names.py",
        category="storage",
        requires_admin_volume_fixtures=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="rest-api",
        script_name="rest-api-smoke.py",
        category="rest",
        uses_live_seed_refresh=True,
        is_rest_api=True,
    ),
    SuiteSpec(
        name="disk-space-guard-live",
        script_name="disk-space-guard-live.py",
        category="storage",
        requires_admin_volume_fixtures=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="vhd-profile-isolation",
        script_name="vhd-profile-isolation.py",
        category="storage",
        requires_admin_volume_fixtures=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="vhd-profile-durability",
        script_name="vhd-profile-durability.py",
        category="storage",
        requires_admin_volume_fixtures=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="category-incoming-path-matrix",
        script_name="category-incoming-path-matrix.py",
        category="storage",
        requires_admin_volume_fixtures=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="vhd-partfile-recovery",
        script_name="vhd-partfile-recovery.py",
        category="storage",
        requires_admin_volume_fixtures=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="admin-volume-cleanup-audit",
        script_name="admin-volume-cleanup-audit.py",
        category="storage",
        requires_admin_volume_fixtures=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="rest-cold-start-dump-stress",
        script_name="rest-cold-start-dump-stress.py",
        category="rest",
        uses_live_seed_refresh=True,
        is_rest_cold_start_dump_stress=True,
        default_enabled=False,
    ),
    SuiteSpec(
        name="local-dumps-crash-smoke",
        script_name="local-dumps-crash-smoke.py",
        category="rest",
        default_enabled=False,
    ),
    SuiteSpec(
        name="amutorrent-browser-smoke",
        script_name="amutorrent-browser-smoke.py",
        category="rest",
        is_amutorrent_browser=True,
        accepts_admin_volume_fixtures=True,
    ),
    SuiteSpec(
        name="prowlarr-emulebb",
        script_name="prowlarr-emulebb-live.py",
        category="rest",
        uses_live_seed_refresh=True,
        is_prowlarr_emulebb=True,
    ),
    SuiteSpec(
        name="radarr-emulebb",
        script_name="radarr-emulebb-live.py",
        category="live-wire",
        uses_live_seed_refresh=True,
        is_arr_emulebb=True,
        accepts_admin_volume_fixtures=True,
    ),
    SuiteSpec(
        name="sonarr-emulebb",
        script_name="sonarr-emulebb-live.py",
        category="live-wire",
        uses_live_seed_refresh=True,
        is_arr_emulebb=True,
        accepts_admin_volume_fixtures=True,
    ),
    SuiteSpec(
        name="auto-browse-live",
        script_name="auto-browse-live.py",
        category="live-wire",
        uses_live_seed_refresh=True,
        is_auto_browse=True,
    ),
)
SUITE_NAMES = tuple(spec.name for spec in SUITE_SPECS)
SUITE_INCONCLUSIVE_RETURN_CODE = 2
PROFILE_SUITE_NAMES = {
    "protocol-parity": (
        "rest-api",
    ),
    "beta-green": (
        "shared-directories-rest",
        "rest-api",
        "prowlarr-emulebb",
    ),
    "controller-surface": (
        "rest-api",
        "prowlarr-emulebb",
        "radarr-emulebb",
        "sonarr-emulebb",
        "amutorrent-browser-smoke",
    ),
    "beta-release": (
        "command-line-smoke",
        "shared-directories-rest",
        "rest-api",
        "prowlarr-emulebb",
        "radarr-emulebb",
        "sonarr-emulebb",
        "rest-cold-start-dump-stress",
    ),
    "release-expanded": (
        "command-line-smoke",
        "preference-ui",
        "shared-files-ui",
        "shared-hash-ui",
        "search-ui-live",
        "shared-directories-rest",
        "shared-cache-volume-identity",
        "shared-cache-invalidation",
        "unc-mapped-drive-identity",
        "vhd-long-path-special-names",
        "rest-api",
        "disk-space-guard-live",
        "vhd-profile-isolation",
        "vhd-profile-durability",
        "category-incoming-path-matrix",
        "vhd-partfile-recovery",
        "admin-volume-cleanup-audit",
        "rest-cold-start-dump-stress",
        "local-dumps-crash-smoke",
        "amutorrent-browser-smoke",
    ),
    "stabilization-stress": (
        "shared-files-ui",
        "search-ui-live",
        "shared-directories-rest",
        "rest-api",
        "rest-cold-start-dump-stress",
        "local-dumps-crash-smoke",
    ),
    "cpu-heavy": (
        "shared-files-ui",
    ),
    "ui-resource-depth": (
        "resource-ui-smoke",
        "preference-ui",
    ),
}
LIVE_E2E_PROFILES = ("default", *PROFILE_SUITE_NAMES.keys())
BROAD_DIAGNOSTIC_PROFILE_NAMES = {"release-expanded", "stabilization-stress", "cpu-heavy"}
CPU_PROFILED_SUITE_NAMES = {
    "preference-ui",
    "shared-files-ui",
    "shared-hash-ui",
    "search-ui-live",
    "resource-ui-smoke",
    "rest-api",
    "rest-cold-start-dump-stress",
}


def resolve_suite_specs(selected_names: list[str] | None) -> tuple[SuiteSpec, ...]:
    """Resolves selected suite names while preserving the canonical order."""

    if not selected_names:
        return tuple(spec for spec in SUITE_SPECS if spec.default_enabled)

    requested = set(selected_names)
    return tuple(spec for spec in SUITE_SPECS if spec.name in requested)


def apply_profile_defaults(args: argparse.Namespace) -> None:
    """Applies named live E2E profile defaults before validation and command building."""

    if args.profile == "default":
        return

    if not args.suite:
        args.suite = list(PROFILE_SUITE_NAMES[args.profile])

    if args.profile in BROAD_DIAGNOSTIC_PROFILE_NAMES:
        args.profile_cpu = True
        args.profile_cpu_stack = True
        args.profile_memory = True
        if (
            args.rest_cold_start_dump_stress_resource_monitor_interval_seconds
            == DEFAULT_REST_COLD_START_DUMP_STRESS_RESOURCE_MONITOR_INTERVAL_SECONDS
        ):
            args.rest_cold_start_dump_stress_resource_monitor_interval_seconds = DEFAULT_PROFILE_RESOURCE_MONITOR_INTERVAL_SECONDS
        if not args.rest_cold_start_dump_stress_cpu_profile:
            args.rest_cold_start_dump_stress_cpu_profile = True
        if not args.rest_cold_start_dump_stress_cpu_profile_stack:
            args.rest_cold_start_dump_stress_cpu_profile_stack = True

    if args.arr_direct_search_stress_count == DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT:
        args.arr_direct_search_stress_count = BETA_GREEN_ARR_DIRECT_SEARCH_STRESS_COUNT
    if args.arr_prowlarr_search_stress_count == DEFAULT_ARR_PROWLARR_SEARCH_STRESS_COUNT:
        args.arr_prowlarr_search_stress_count = BETA_GREEN_ARR_PROWLARR_SEARCH_STRESS_COUNT

    if args.profile == "controller-surface" and args.arr_download_proof_mode == DEFAULT_ARR_DOWNLOAD_PROOF_MODE:
        args.arr_download_proof_mode = CONTROLLER_SURFACE_ARR_DOWNLOAD_PROOF_MODE

    if args.profile == "release-expanded":
        args.admin_volume_fixtures = True
        if not args.preference_ui_directories_tree_stress:
            args.preference_ui_directories_tree_stress = True
        if args.rest_server_search_count == DEFAULT_REST_SEARCH_COUNT:
            args.rest_server_search_count = RELEASE_EXPANDED_REST_SEARCH_COUNT_PER_NETWORK
        if args.rest_kad_search_count == DEFAULT_REST_SEARCH_COUNT:
            args.rest_kad_search_count = RELEASE_EXPANDED_REST_SEARCH_COUNT_PER_NETWORK
        if args.rest_download_trigger_count == DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT:
            args.rest_download_trigger_count = RELEASE_EXPANDED_REST_DOWNLOAD_TRIGGER_COUNT
        if args.rest_coverage_budget == "contract":
            args.rest_coverage_budget = "contract-stress"
        if args.rest_stress_duration_seconds == 30.0:
            args.rest_stress_duration_seconds = RELEASE_EXPANDED_REST_STRESS_DURATION_SECONDS
        if args.rest_stress_concurrency == 4:
            args.rest_stress_concurrency = RELEASE_EXPANDED_REST_STRESS_CONCURRENCY
        if args.rest_stress_max_failures == 1:
            args.rest_stress_max_failures = RELEASE_EXPANDED_REST_STRESS_MAX_FAILURES
        if args.rest_socket_adversity_budget == "off":
            args.rest_socket_adversity_budget = "smoke"
        if args.rest_webserver_scheme == "https" and args.rest_tls_handshake_adversity_budget == "off":
            args.rest_tls_handshake_adversity_budget = "smoke"
        if args.rest_leak_churn_budget == "off":
            args.rest_leak_churn_budget = "smoke"
        if args.rest_leak_churn_cycles is None:
            args.rest_leak_churn_cycles = RELEASE_EXPANDED_REST_LEAK_CHURN_CYCLES
        if not args.rest_stop_start_after_churn:
            args.rest_stop_start_after_churn = True
        if args.rest_cold_start_dump_stress_waves == DEFAULT_REST_COLD_START_DUMP_STRESS_WAVES:
            args.rest_cold_start_dump_stress_waves = RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_WAVES
        if args.rest_cold_start_dump_stress_searches_per_wave == DEFAULT_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE:
            args.rest_cold_start_dump_stress_searches_per_wave = RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE
        if args.rest_cold_start_dump_stress_max_concurrent_searches == DEFAULT_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES:
            args.rest_cold_start_dump_stress_max_concurrent_searches = (
                RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES
            )
        if args.rest_cold_start_dump_stress_downloads_per_wave == DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE:
            args.rest_cold_start_dump_stress_downloads_per_wave = RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE
        if args.rest_cold_start_dump_stress_post_drain_seconds == DEFAULT_REST_COLD_START_DUMP_STRESS_POST_DRAIN_SECONDS:
            args.rest_cold_start_dump_stress_post_drain_seconds = RELEASE_EXPANDED_REST_COLD_START_DUMP_STRESS_POST_DRAIN_SECONDS
        if args.search_ui_search_rounds == DEFAULT_SEARCH_UI_SEARCH_ROUNDS:
            args.search_ui_search_rounds = RELEASE_EXPANDED_SEARCH_UI_SEARCH_ROUNDS
        if args.search_ui_download_lifecycle_count == DEFAULT_SEARCH_UI_DOWNLOAD_LIFECYCLE_COUNT:
            args.search_ui_download_lifecycle_count = RELEASE_EXPANDED_SEARCH_UI_DOWNLOAD_LIFECYCLE_COUNT

    if args.profile == "stabilization-stress":
        if "shared-files-ui" in (args.suite or ()) and not args.shared_files_ui_scenario:
            args.shared_files_ui_scenario = list(SHARED_FILES_UI_STRESS_SCENARIOS)
        if args.rest_coverage_budget == "contract":
            args.rest_coverage_budget = "contract-stress"
        if args.rest_stress_budget == "smoke":
            args.rest_stress_budget = "soak"
        if args.rest_stress_duration_seconds == 30.0:
            args.rest_stress_duration_seconds = STABILIZATION_REST_STRESS_DURATION_SECONDS
        if args.rest_stress_concurrency == 4:
            args.rest_stress_concurrency = STABILIZATION_REST_STRESS_CONCURRENCY
        if args.rest_stress_max_failures == 1:
            args.rest_stress_max_failures = STABILIZATION_REST_STRESS_MAX_FAILURES
        if args.rest_socket_adversity_budget == "off":
            args.rest_socket_adversity_budget = "smoke"
        if args.rest_webserver_scheme == "https" and args.rest_tls_handshake_adversity_budget == "off":
            args.rest_tls_handshake_adversity_budget = "smoke"
        if args.rest_leak_churn_budget == "off":
            args.rest_leak_churn_budget = "smoke"
        if args.rest_leak_churn_cycles is None:
            args.rest_leak_churn_cycles = STABILIZATION_REST_LEAK_CHURN_CYCLES
        if not args.rest_stop_start_after_churn:
            args.rest_stop_start_after_churn = True
        if args.rest_cold_start_dump_stress_waves == DEFAULT_REST_COLD_START_DUMP_STRESS_WAVES:
            args.rest_cold_start_dump_stress_waves = STABILIZATION_REST_COLD_START_DUMP_STRESS_WAVES
        if args.rest_cold_start_dump_stress_searches_per_wave == DEFAULT_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE:
            args.rest_cold_start_dump_stress_searches_per_wave = STABILIZATION_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE
        if args.rest_cold_start_dump_stress_max_concurrent_searches == DEFAULT_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES:
            args.rest_cold_start_dump_stress_max_concurrent_searches = STABILIZATION_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES
        if args.rest_cold_start_dump_stress_downloads_per_wave == DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE:
            args.rest_cold_start_dump_stress_downloads_per_wave = STABILIZATION_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE
        if args.rest_cold_start_dump_stress_downloads_per_search == DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_SEARCH:
            args.rest_cold_start_dump_stress_downloads_per_search = STABILIZATION_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_SEARCH
        if args.rest_cold_start_dump_stress_synthetic_queue_fill_count == DEFAULT_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_COUNT:
            args.rest_cold_start_dump_stress_synthetic_queue_fill_count = (
                STABILIZATION_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_COUNT
            )
        if args.rest_cold_start_dump_stress_download_churn_interval_seconds == DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOAD_CHURN_INTERVAL_SECONDS:
            args.rest_cold_start_dump_stress_download_churn_interval_seconds = (
                STABILIZATION_REST_COLD_START_DUMP_STRESS_DOWNLOAD_CHURN_INTERVAL_SECONDS
            )
        if args.rest_cold_start_dump_stress_download_remove_count_per_churn == DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOAD_REMOVE_COUNT_PER_CHURN:
            args.rest_cold_start_dump_stress_download_remove_count_per_churn = (
                STABILIZATION_REST_COLD_START_DUMP_STRESS_DOWNLOAD_REMOVE_COUNT_PER_CHURN
            )
        if args.rest_cold_start_dump_stress_post_drain_seconds == DEFAULT_REST_COLD_START_DUMP_STRESS_POST_DRAIN_SECONDS:
            args.rest_cold_start_dump_stress_post_drain_seconds = STABILIZATION_REST_COLD_START_DUMP_STRESS_POST_DRAIN_SECONDS
        if args.search_ui_search_rounds == DEFAULT_SEARCH_UI_SEARCH_ROUNDS:
            args.search_ui_search_rounds = STABILIZATION_SEARCH_UI_SEARCH_ROUNDS
        if args.search_ui_download_lifecycle_count == DEFAULT_SEARCH_UI_DOWNLOAD_LIFECYCLE_COUNT:
            args.search_ui_download_lifecycle_count = STABILIZATION_SEARCH_UI_DOWNLOAD_LIFECYCLE_COUNT

    if args.profile == "cpu-heavy":
        if "shared-files-ui" in (args.suite or ()) and not args.shared_files_ui_scenario:
            args.shared_files_ui_scenario = list(SHARED_FILES_UI_STRESS_SCENARIOS)
        if args.shared_files_tree_stress_churn_cycles is None:
            args.shared_files_tree_stress_churn_cycles = 80
        args.shared_files_ui_cpu_profile = True
        args.shared_files_ui_cpu_profile_stack = True

    if args.profile == "beta-release":
        if args.rest_cold_start_dump_stress_waves == DEFAULT_REST_COLD_START_DUMP_STRESS_WAVES:
            args.rest_cold_start_dump_stress_waves = BETA_RELEASE_REST_COLD_START_DUMP_STRESS_WAVES
        if args.rest_cold_start_dump_stress_searches_per_wave == DEFAULT_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE:
            args.rest_cold_start_dump_stress_searches_per_wave = BETA_RELEASE_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE
        if args.rest_cold_start_dump_stress_max_concurrent_searches == DEFAULT_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES:
            args.rest_cold_start_dump_stress_max_concurrent_searches = BETA_RELEASE_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES
        if args.rest_cold_start_dump_stress_downloads_per_wave == DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE:
            args.rest_cold_start_dump_stress_downloads_per_wave = BETA_RELEASE_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE
        if args.rest_cold_start_dump_stress_post_drain_seconds == DEFAULT_REST_COLD_START_DUMP_STRESS_POST_DRAIN_SECONDS:
            args.rest_cold_start_dump_stress_post_drain_seconds = BETA_RELEASE_REST_COLD_START_DUMP_STRESS_POST_DRAIN_SECONDS


def build_python_command(python_executable: str) -> list[str]:
    """Builds the Python executable prefix, including `py -3` when needed."""

    command = [python_executable]
    if Path(python_executable).stem.lower() == "py":
        command.append("-3")
    return command


def build_suite_command(
    *,
    spec: SuiteSpec,
    scripts_dir: Path,
    python_executable: str,
    workspace_root: Path,
    configuration: str,
    artifacts_dir: Path,
    app_root: Path | None = None,
    app_exe: Path | None = None,
    seed_config_dir: Path | None = None,
    startup_trace_mode: str = "required",
    shared_root: Path | None = None,
    preference_ui_directories_tree_stress: bool = False,
    shared_files_ui_scenarios: tuple[str, ...] | None = None,
    shared_files_tree_stress_churn_cycles: int | None = None,
    skip_live_seed_refresh: bool = False,
    rest_server_search_count: int = DEFAULT_REST_SEARCH_COUNT,
    rest_kad_search_count: int = DEFAULT_REST_SEARCH_COUNT,
    rest_download_trigger_count: int = DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT,
    rest_search_method_override: str | None = None,
    rest_webserver_scheme: str = "http",
    rest_coverage_budget: str = "contract",
    rest_stress_budget: str = "smoke",
    rest_stress_duration_seconds: float = 30.0,
    rest_stress_concurrency: int = 4,
    rest_stress_max_failures: int = 1,
    rest_stress_request_timeout_seconds: float = 5.0,
    rest_socket_adversity_budget: str = "off",
    rest_tls_handshake_adversity_budget: str = "off",
    rest_leak_churn_budget: str = "off",
    rest_leak_churn_cycles: int | None = None,
    rest_stop_start_after_churn: bool = False,
    p2p_bind_interface_name: str = "hide.me",
    live_wire_inputs_file: Path | None = None,
    search_ui_search_rounds: int = DEFAULT_SEARCH_UI_SEARCH_ROUNDS,
    search_ui_download_lifecycle_count: int = DEFAULT_SEARCH_UI_DOWNLOAD_LIFECYCLE_COUNT,
    arr_direct_search_stress_count: int = DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT,
    arr_prowlarr_search_stress_count: int = DEFAULT_ARR_PROWLARR_SEARCH_STRESS_COUNT,
    emule_connection_timeout_seconds: float = DEFAULT_EMULE_CONNECTION_TIMEOUT_SECONDS,
    arr_search_timeout_seconds: float = DEFAULT_ARR_SEARCH_TIMEOUT_SECONDS,
    document_download_timeout_seconds: float = DEFAULT_DOCUMENT_DOWNLOAD_TIMEOUT_SECONDS,
    media_acquisition_timeout_minutes: float = DEFAULT_MEDIA_ACQUISITION_TIMEOUT_MINUTES,
    arr_download_proof_mode: str = DEFAULT_ARR_DOWNLOAD_PROOF_MODE,
    radarr_movie_root: str | None = None,
    sonarr_series_root: str | None = None,
    rest_cold_start_dump_stress_waves: int = DEFAULT_REST_COLD_START_DUMP_STRESS_WAVES,
    rest_cold_start_dump_stress_searches_per_wave: int = DEFAULT_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE,
    rest_cold_start_dump_stress_max_concurrent_searches: int = DEFAULT_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES,
    rest_cold_start_dump_stress_search_observation_timeout_seconds: float = DEFAULT_REST_COLD_START_DUMP_STRESS_SEARCH_OBSERVATION_TIMEOUT_SECONDS,
    rest_cold_start_dump_stress_downloads_per_wave: int = DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE,
    rest_cold_start_dump_stress_downloads_per_search: int = DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_SEARCH,
    rest_cold_start_dump_stress_max_missing_download_triggers: int = DEFAULT_REST_COLD_START_DUMP_STRESS_MAX_MISSING_DOWNLOAD_TRIGGERS,
    rest_cold_start_dump_stress_synthetic_queue_fill_count: int = DEFAULT_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_COUNT,
    rest_cold_start_dump_stress_synthetic_queue_fill_size_bytes: int = DEFAULT_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_SIZE_BYTES,
    rest_cold_start_dump_stress_synthetic_queue_fill_batch_size: int = DEFAULT_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_BATCH_SIZE,
    rest_cold_start_dump_stress_target_completed_downloads: int = DEFAULT_REST_COLD_START_DUMP_STRESS_TARGET_COMPLETED_DOWNLOADS,
    rest_cold_start_dump_stress_completion_timeout_seconds: float = DEFAULT_REST_COLD_START_DUMP_STRESS_COMPLETION_TIMEOUT_SECONDS,
    rest_cold_start_dump_stress_max_active_downloads: int = DEFAULT_REST_COLD_START_DUMP_STRESS_MAX_ACTIVE_DOWNLOADS,
    rest_cold_start_dump_stress_allow_required_zero_result_searches: bool = False,
    rest_cold_start_dump_stress_skip_transfer_cleanup: bool = False,
    rest_cold_start_dump_stress_download_churn_interval_seconds: float = DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOAD_CHURN_INTERVAL_SECONDS,
    rest_cold_start_dump_stress_download_remove_count_per_churn: int = DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOAD_REMOVE_COUNT_PER_CHURN,
    rest_cold_start_dump_stress_resource_monitor_interval_seconds: float = DEFAULT_REST_COLD_START_DUMP_STRESS_RESOURCE_MONITOR_INTERVAL_SECONDS,
    rest_cold_start_dump_stress_post_drain_seconds: float = DEFAULT_REST_COLD_START_DUMP_STRESS_POST_DRAIN_SECONDS,
    rest_cold_start_dump_stress_tool_timeout_seconds: float = DEFAULT_REST_COLD_START_DUMP_STRESS_TOOL_TIMEOUT_SECONDS,
    rest_cold_start_dump_stress_enable_umdh: bool = False,
    rest_cold_start_dump_stress_skip_umdh_diffs: bool = False,
    rest_cold_start_dump_stress_cpu_profile: bool = False,
    rest_cold_start_dump_stress_cpu_profile_max_file_mb: int = DEFAULT_REST_COLD_START_DUMP_STRESS_CPU_PROFILE_MAX_FILE_MB,
    rest_cold_start_dump_stress_cpu_profile_stack: bool = False,
    rest_cold_start_dump_stress_cpu_profile_stack_min_hits: int = DEFAULT_REST_COLD_START_DUMP_STRESS_CPU_PROFILE_STACK_MIN_HITS,
    rest_cold_start_dump_stress_cpu_profile_symbols_required: bool = True,
    rest_cold_start_dump_stress_skip_dumps: bool = False,
    resource_ui_language_timeout_seconds: float = DEFAULT_RESOURCE_UI_LANGUAGE_TIMEOUT_SECONDS,
    mounted_shared_root: Path | None = None,
    admin_volume_fixtures: bool = False,
    vhd_size_mb: int = 256,
    mount_root: Path | None = None,
    keep_admin_fixtures: bool = False,
    fail_fast: bool = False,
) -> list[str]:
    """Builds one child suite command line."""

    command = build_python_command(python_executable)
    command.extend(
        [
            str((scripts_dir / spec.script_name).resolve()),
            "--configuration",
            configuration,
            "--artifacts-dir",
            str((artifacts_dir / spec.name).resolve()),
        ]
    )
    if not env_workspace_root_matches(workspace_root):
        command.extend(["--workspace-root", str(workspace_root.resolve())])
    if app_root is not None:
        command.extend(["--app-root", str(app_root.resolve())])
    if app_exe is not None:
        command.extend(["--app-exe", str(app_exe.resolve())])
    if seed_config_dir is not None:
        command.extend(["--profile-seed-dir", str(seed_config_dir.resolve())])
    if spec.accepts_startup_trace_mode:
        command.extend(["--startup-trace-mode", startup_trace_mode])
    if spec.accepts_shared_root and shared_root is not None:
        command.extend(["--shared-root", str(shared_root.resolve())])
    if spec.accepts_mounted_shared_root and mounted_shared_root is not None:
        command.extend(["--mounted-shared-root", str(mounted_shared_root.resolve())])
    if spec.requires_admin_volume_fixtures or spec.accepts_admin_volume_fixtures:
        if admin_volume_fixtures:
            command.append("--admin-volume-fixtures")
        if spec.is_arr_emulebb:
            suite_vhd_size_mb = max(vhd_size_mb, DEFAULT_ARR_CONTROLLER_STORAGE_VHD_SIZE_MB)
        elif spec.is_amutorrent_browser:
            suite_vhd_size_mb = max(vhd_size_mb, DEFAULT_CONTROLLER_STORAGE_VHD_SIZE_MB)
        else:
            suite_vhd_size_mb = vhd_size_mb
        command.extend(["--vhd-size-mb", str(suite_vhd_size_mb)])
        if mount_root is not None:
            command.extend(["--mount-root", str(mount_root.resolve())])
        if keep_admin_fixtures:
            command.append("--keep-admin-fixtures")
    if spec.name == "preference-ui" and preference_ui_directories_tree_stress:
        command.append("--directories-tree-stress")
        if shared_root is not None:
            command.extend(["--shared-root", str(shared_root.resolve())])
    if spec.is_resource_ui_smoke:
        release_languages_json = workspace_root.parent.parent / "repos" / "eMule-tooling" / "helpers" / "rc-release-languages.json"
        command.extend(["--release-languages-json", str(release_languages_json.resolve())])
        command.extend(["--language-scope", "release"])
        command.extend(["--language-timeout-seconds", str(resource_ui_language_timeout_seconds)])
        if fail_fast:
            command.append("--fail-fast-languages")
    if spec.name == "shared-files-ui" and shared_files_tree_stress_churn_cycles is not None:
        command.extend(["--tree-stress-churn-cycles", str(shared_files_tree_stress_churn_cycles)])
    scenario_names = shared_files_ui_scenarios if spec.name == "shared-files-ui" and shared_files_ui_scenarios else spec.scenarios
    if spec.name == "shared-files-ui" and admin_volume_fixtures and not shared_files_ui_scenarios:
        scenario_names = tuple(dict.fromkeys((*scenario_names, *SHARED_FILES_UI_ADMIN_SCENARIOS)))
    for scenario in scenario_names:
        command.extend(["--scenario", scenario])
    if spec.uses_live_seed_refresh and skip_live_seed_refresh:
        command.append("--skip-live-seed-refresh")
    if spec.is_rest_api:
        if live_wire_inputs_file is not None:
            command.extend(["--live-wire-inputs-file", str(live_wire_inputs_file.resolve())])
        command.extend(["--server-search-count", str(rest_server_search_count)])
        command.extend(["--kad-search-count", str(rest_kad_search_count)])
        command.extend(["--live-download-trigger-count", str(rest_download_trigger_count)])
        if rest_search_method_override:
            command.extend(["--search-method-override", rest_search_method_override])
        command.extend(["--webserver-scheme", rest_webserver_scheme])
        command.extend(["--rest-coverage-budget", rest_coverage_budget])
        command.extend(["--rest-stress-budget", rest_stress_budget])
        command.extend(["--rest-stress-duration-seconds", str(rest_stress_duration_seconds)])
        command.extend(["--rest-stress-concurrency", str(rest_stress_concurrency)])
        command.extend(["--rest-stress-max-failures", str(rest_stress_max_failures)])
        command.extend(["--rest-stress-request-timeout-seconds", str(rest_stress_request_timeout_seconds)])
        command.extend(["--rest-socket-adversity-budget", rest_socket_adversity_budget])
        command.extend(["--rest-tls-handshake-adversity-budget", rest_tls_handshake_adversity_budget])
        command.extend(["--rest-leak-churn-budget", rest_leak_churn_budget])
        if rest_leak_churn_cycles is not None:
            command.extend(["--rest-leak-churn-cycles", str(rest_leak_churn_cycles)])
        if rest_stop_start_after_churn:
            command.append("--rest-stop-start-after-churn")
        command.append("--enable-upnp")
        if p2p_bind_interface_name:
            command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
    if spec.is_auto_browse:
        if live_wire_inputs_file is not None:
            command.extend(["--live-wire-inputs-file", str(live_wire_inputs_file.resolve())])
    if spec.is_auto_browse and p2p_bind_interface_name:
        command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
    if spec.is_amutorrent_browser and p2p_bind_interface_name:
        command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
    if spec.is_search_ui_live:
        if live_wire_inputs_file is not None:
            command.extend(["--live-wire-inputs-file", str(live_wire_inputs_file.resolve())])
        if p2p_bind_interface_name:
            command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
        command.extend(["--ui-search-rounds", str(search_ui_search_rounds)])
        command.extend(["--ui-download-lifecycle-count", str(search_ui_download_lifecycle_count)])
    if spec.is_prowlarr_emulebb:
        if live_wire_inputs_file is not None:
            command.extend(["--live-wire-inputs-file", str(live_wire_inputs_file.resolve())])
        command.extend(["--rest-ready-timeout-seconds", str(emule_connection_timeout_seconds)])
        command.extend(["--emule-connection-timeout-seconds", str(emule_connection_timeout_seconds)])
        command.extend(["--result-timeout-seconds", str(arr_search_timeout_seconds)])
        command.extend(["--document-download-timeout-seconds", str(document_download_timeout_seconds)])
        command.extend(["--direct-search-stress-count", str(arr_direct_search_stress_count)])
        command.extend(["--prowlarr-search-stress-count", str(arr_prowlarr_search_stress_count)])
        command.append("--enable-upnp")
        if p2p_bind_interface_name:
            command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
    if spec.is_arr_emulebb:
        if live_wire_inputs_file is not None:
            command.extend(["--live-wire-inputs-file", str(live_wire_inputs_file.resolve())])
        command.extend(["--rest-ready-timeout-seconds", str(emule_connection_timeout_seconds)])
        command.extend(["--emule-connection-timeout-seconds", str(emule_connection_timeout_seconds)])
        command.extend(["--result-timeout-seconds", str(arr_search_timeout_seconds)])
        command.extend(["--radarr-release-timeout-seconds", str(arr_search_timeout_seconds)])
        command.extend(["--acquisition-timeout-minutes", str(media_acquisition_timeout_minutes)])
        command.extend(["--download-proof-mode", arr_download_proof_mode])
        if spec.name == "radarr-emulebb" and radarr_movie_root is not None:
            command.extend(["--radarr-movie-root", str(radarr_movie_root)])
        if spec.name == "sonarr-emulebb" and sonarr_series_root is not None:
            command.extend(["--sonarr-series-root", str(sonarr_series_root)])
        command.append("--enable-upnp")
        if p2p_bind_interface_name:
            command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
    if spec.is_rest_cold_start_dump_stress:
        if live_wire_inputs_file is not None:
            command.extend(["--live-wire-inputs-file", str(live_wire_inputs_file.resolve())])
        command.append("--enable-upnp")
        if p2p_bind_interface_name:
            command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
        command.extend(["--waves", str(rest_cold_start_dump_stress_waves)])
        command.extend(["--searches-per-wave", str(rest_cold_start_dump_stress_searches_per_wave)])
        command.extend(["--max-concurrent-searches", str(rest_cold_start_dump_stress_max_concurrent_searches)])
        command.extend(["--search-observation-timeout-seconds", str(rest_cold_start_dump_stress_search_observation_timeout_seconds)])
        command.extend(["--downloads-per-wave", str(rest_cold_start_dump_stress_downloads_per_wave)])
        command.extend(["--downloads-per-search", str(rest_cold_start_dump_stress_downloads_per_search)])
        command.extend(["--max-missing-download-triggers", str(rest_cold_start_dump_stress_max_missing_download_triggers)])
        command.extend(["--synthetic-queue-fill-count", str(rest_cold_start_dump_stress_synthetic_queue_fill_count)])
        command.extend(["--synthetic-queue-fill-size-bytes", str(rest_cold_start_dump_stress_synthetic_queue_fill_size_bytes)])
        command.extend(["--synthetic-queue-fill-batch-size", str(rest_cold_start_dump_stress_synthetic_queue_fill_batch_size)])
        command.extend(["--target-completed-downloads", str(rest_cold_start_dump_stress_target_completed_downloads)])
        command.extend(["--completion-timeout-seconds", str(rest_cold_start_dump_stress_completion_timeout_seconds)])
        command.extend(["--max-active-downloads", str(rest_cold_start_dump_stress_max_active_downloads)])
        if rest_cold_start_dump_stress_allow_required_zero_result_searches:
            command.append("--allow-required-zero-result-searches")
        if rest_cold_start_dump_stress_skip_transfer_cleanup:
            command.append("--skip-transfer-cleanup")
        command.extend(["--download-churn-interval-seconds", str(rest_cold_start_dump_stress_download_churn_interval_seconds)])
        command.extend(["--download-remove-count-per-churn", str(rest_cold_start_dump_stress_download_remove_count_per_churn)])
        command.extend(["--resource-monitor-interval-seconds", str(rest_cold_start_dump_stress_resource_monitor_interval_seconds)])
        command.extend(["--post-drain-seconds", str(rest_cold_start_dump_stress_post_drain_seconds)])
        command.extend(["--tool-timeout-seconds", str(rest_cold_start_dump_stress_tool_timeout_seconds)])
        if rest_cold_start_dump_stress_enable_umdh:
            command.append("--enable-umdh")
        if rest_cold_start_dump_stress_skip_umdh_diffs:
            command.append("--skip-umdh-diffs")
        if rest_cold_start_dump_stress_cpu_profile:
            command.append("--cpu-profile")
        command.extend(["--cpu-profile-max-file-mb", str(rest_cold_start_dump_stress_cpu_profile_max_file_mb)])
        if rest_cold_start_dump_stress_cpu_profile_stack:
            command.append("--cpu-profile-stack")
        command.extend(["--cpu-profile-stack-min-hits", str(rest_cold_start_dump_stress_cpu_profile_stack_min_hits)])
        if not rest_cold_start_dump_stress_cpu_profile_symbols_required:
            command.append("--no-cpu-profile-symbols-required")
        if rest_cold_start_dump_stress_skip_dumps:
            command.append("--skip-dumps")
    if spec.name == "local-dumps-crash-smoke" and p2p_bind_interface_name:
        command.extend(["--p2p-bind-interface-name", p2p_bind_interface_name])
    return command


def run_suite_command(command: list[str]) -> int:
    """Runs one child suite command with a hard wall-clock timeout."""

    process = subprocess.Popen(command)
    try:
        return process.wait(timeout=DEFAULT_CHILD_SUITE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        terminate_process_tree(process.pid)
        try:
            process.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            pass
        return SUITE_TIMEOUT_RETURN_CODE


def terminate_process_tree(process_id: int) -> dict[str, object]:
    """Terminates one child process tree after a suite-level timeout."""

    if os.name == "nt":
        completed = subprocess.run(
            ["taskkill", "/PID", str(process_id), "/T", "/F"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return {
            "command": "taskkill",
            "return_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    try:
        os.kill(process_id, 9)
        return {"command": "kill", "return_code": 0}
    except OSError as exc:
        return {"command": "kill", "return_code": 1, "error": str(exc)}


@dataclass(frozen=True)
class SuiteCpuProfileOptions:
    """Resolved CPU profiling settings for one aggregate child suite."""

    enabled: bool
    source: str
    max_file_mb: int
    stack: bool
    stack_min_hits: int
    symbols_required: bool


def resolve_suite_cpu_profile_options(spec: SuiteSpec, args: argparse.Namespace) -> SuiteCpuProfileOptions:
    """Returns the effective CPU profiling settings for one child suite."""

    if bool(args.profile_cpu) and spec.name in CPU_PROFILED_SUITE_NAMES:
        return SuiteCpuProfileOptions(
            enabled=True,
            source="profile-cpu",
            max_file_mb=args.profile_cpu_max_file_mb,
            stack=bool(args.profile_cpu_stack),
            stack_min_hits=args.profile_cpu_stack_min_hits,
            symbols_required=bool(args.profile_symbols_required),
        )
    if spec.name == "shared-files-ui" and bool(args.shared_files_ui_cpu_profile):
        return SuiteCpuProfileOptions(
            enabled=True,
            source="shared-files-ui-cpu-profile",
            max_file_mb=args.shared_files_ui_cpu_profile_max_file_mb,
            stack=bool(args.shared_files_ui_cpu_profile_stack),
            stack_min_hits=args.shared_files_ui_cpu_profile_stack_min_hits,
            symbols_required=bool(args.shared_files_ui_cpu_profile_symbols_required),
        )
    return SuiteCpuProfileOptions(
        enabled=False,
        source="disabled",
        max_file_mb=args.profile_cpu_max_file_mb,
        stack=False,
        stack_min_hits=args.profile_cpu_stack_min_hits,
        symbols_required=True,
    )


def should_profile_shared_files_ui_suite(spec: SuiteSpec, args: argparse.Namespace) -> bool:
    """Returns whether the shared-files UI child suite should run under ETW CPU profiling."""

    return spec.name == "shared-files-ui" and resolve_suite_cpu_profile_options(spec, args).enabled


def run_suite_command_with_optional_cpu_profile(
    command: list[str],
    *,
    spec: SuiteSpec,
    args: argparse.Namespace,
    child_artifacts_dir: Path,
    app_exe: Path,
) -> tuple[int, dict[str, object] | None]:
    """Runs one child suite, optionally wrapped in a bounded xperf CPU profile."""

    profile_options = resolve_suite_cpu_profile_options(spec, args)
    if not profile_options.enabled:
        return run_suite_command(command), None

    profile_paths = cpu_profile.build_cpu_profile_paths(child_artifacts_dir)
    profile_result: dict[str, object] = {
        "enabled": True,
        "tool": "xperf",
        "source": profile_options.source,
        "profile_paths": {
            "etl": str(profile_paths.etl_path),
            "detail": str(profile_paths.detail_path),
            "summary": str(profile_paths.summary_path),
            "stack": str(profile_paths.stack_path),
        },
        "max_file_mb": profile_options.max_file_mb,
        "stack": profile_options.stack,
        "stack_min_hits": profile_options.stack_min_hits,
    }
    tools = cpu_profile.discover_cpu_profile_tools()
    if not tools.xperf:
        profile_result["status"] = "failed"
        profile_result["error"] = "xperf was not found."
        return run_suite_command(command), profile_result

    pdb_path = cpu_profile.resolve_app_pdb_path(app_exe)
    if profile_options.symbols_required and not pdb_path.is_file():
        profile_result["status"] = "failed"
        profile_result["error"] = f"Required app symbols were not found: {pdb_path}"
        return run_suite_command(command), profile_result

    start = cpu_profile.start_cpu_profile(
        tools=tools,
        paths=profile_paths,
        max_file_mb=profile_options.max_file_mb,
        timeout_seconds=30.0,
    )
    profile_result["start"] = start
    return_code = run_suite_command(command)
    stop = cpu_profile.stop_cpu_profile(tools=tools, paths=profile_paths, timeout_seconds=60.0)
    profile_result["stop"] = stop

    if start.get("return_code") == 0 and stop.get("return_code") == 0 and profile_paths.etl_path.is_file():
        export = cpu_profile.export_cpu_profile(
            tools=tools,
            paths=profile_paths,
            app_exe=app_exe,
            timeout_seconds=90.0,
            include_stack=profile_options.stack,
            stack_min_hits=profile_options.stack_min_hits,
        )
        detail_summary = cpu_profile.parse_xperf_profile_detail_file(profile_paths.detail_path)
        stack_summary = (
            cpu_profile.parse_xperf_stack_report_file(profile_paths.stack_path)
            if profile_options.stack
            else {"available": False, "reason": "stack export disabled"}
        )
        combined_summary = {"detail": detail_summary, "stack": stack_summary}
        profile_paths.summary_path.parent.mkdir(parents=True, exist_ok=True)
        profile_paths.summary_path.write_text(json.dumps(combined_summary, indent=2, sort_keys=True), encoding="utf-8")
        profile_result["export"] = export
        profile_result["summary"] = combined_summary
        profile_result["status"] = "passed" if detail_summary.get("available") else "failed"
    else:
        profile_result["status"] = "failed"

    return return_code, profile_result


def env_workspace_root_matches(workspace_root: Path) -> bool:
    """Returns whether EMULE_WORKSPACE_ROOT already covers a workspace child root."""

    env_root = os.environ.get("EMULE_WORKSPACE_ROOT")
    if not env_root:
        return False
    return (Path(env_root).resolve() / "workspaces" / workspace_root.name).resolve() == workspace_root.resolve()


def get_suite_status_from_return_code(return_code: int) -> str:
    """Maps one child process return code into an aggregate suite status."""

    if return_code == 0:
        return "passed"
    return "failed"


def read_child_suite_result(child_artifacts_dir: Path) -> dict[str, object] | None:
    """Reads a child suite result file when the child runner published one."""

    result_path = child_artifacts_dir / "result.json"
    if not result_path.is_file():
        return None
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def extract_child_resource_diagnostics(child_result: dict[str, object] | None) -> dict[str, object] | None:
    """Extracts bounded memory/resource diagnostics from a child suite report."""

    if not child_result:
        return None
    diagnostics = child_result.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return None
    extracted: dict[str, object] = {}
    resource_monitor = diagnostics.get("resource_monitor")
    if isinstance(resource_monitor, dict):
        extracted["resource_monitor"] = {
            key: value
            for key, value in resource_monitor.items()
            if key in {"enabled", "interval_seconds", "summary", "thread_alive_after_stop", "sample_file"}
        }
    for key in ("resource_deltas", "findings"):
        value = diagnostics.get(key)
        if isinstance(value, dict):
            extracted[key] = value
    if "resource_deltas" not in extracted:
        resource_deltas = child_result.get("resource_deltas")
        if isinstance(resource_deltas, dict):
            extracted["resource_deltas"] = resource_deltas
    return extracted or None


def build_parser() -> argparse.ArgumentParser:
    """Builds the aggregate live E2E argument parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--startup-trace-mode", choices=["required", "optional"], default="required")
    parser.add_argument("--shared-root", default=r"C:\tmp\00_long_paths")
    parser.add_argument(
        "--mounted-shared-root",
        help="Optional dedicated mounted-folder path passed to the shared-directories REST E2E suite.",
    )
    parser.add_argument("--admin-volume-fixtures", action="store_true")
    parser.add_argument("--vhd-size-mb", type=int, default=256)
    parser.add_argument("--mount-root")
    parser.add_argument("--keep-admin-fixtures", action="store_true")
    parser.add_argument("--preference-ui-directories-tree-stress", action="store_true")
    parser.add_argument("--shared-files-ui-scenario", action="append", choices=SHARED_FILES_UI_SCENARIOS)
    parser.add_argument("--shared-files-tree-stress-churn-cycles", type=int)
    parser.add_argument("--shared-files-ui-cpu-profile", action="store_true")
    parser.add_argument(
        "--shared-files-ui-cpu-profile-max-file-mb",
        type=int,
        default=DEFAULT_SHARED_FILES_UI_CPU_PROFILE_MAX_FILE_MB,
    )
    parser.add_argument("--shared-files-ui-cpu-profile-stack", action="store_true")
    parser.add_argument(
        "--shared-files-ui-cpu-profile-stack-min-hits",
        type=int,
        default=DEFAULT_SHARED_FILES_UI_CPU_PROFILE_STACK_MIN_HITS,
    )
    parser.add_argument(
        "--shared-files-ui-cpu-profile-symbols-required",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument("--profile-cpu", action="store_true")
    parser.add_argument("--profile-cpu-max-file-mb", type=int, default=DEFAULT_PROFILE_CPU_MAX_FILE_MB)
    parser.add_argument("--profile-cpu-stack", action="store_true")
    parser.add_argument("--profile-cpu-stack-min-hits", type=int, default=DEFAULT_PROFILE_CPU_STACK_MIN_HITS)
    parser.add_argument("--profile-symbols-required", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--profile-memory", action="store_true")
    parser.add_argument(
        "--profile-resource-interval-seconds",
        type=float,
        default=DEFAULT_PROFILE_RESOURCE_MONITOR_INTERVAL_SECONDS,
    )
    parser.add_argument("--suite", action="append", choices=SUITE_NAMES)
    parser.add_argument("--profile", choices=LIVE_E2E_PROFILES, default="default")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--resource-ui-language-timeout-seconds", type=float, default=DEFAULT_RESOURCE_UI_LANGUAGE_TIMEOUT_SECONDS)
    parser.add_argument("--skip-live-seed-refresh", action="store_true")
    parser.add_argument("--rest-server-search-count", type=int, default=DEFAULT_REST_SEARCH_COUNT)
    parser.add_argument("--rest-kad-search-count", type=int, default=DEFAULT_REST_SEARCH_COUNT)
    parser.add_argument("--rest-download-trigger-count", type=int, default=DEFAULT_REST_DOWNLOAD_TRIGGER_COUNT)
    parser.add_argument("--rest-search-method-override", choices=["automatic", "server", "global", "kad"])
    parser.add_argument("--rest-webserver-scheme", choices=["http", "https"], default="http")
    parser.add_argument("--rest-coverage-budget", choices=["smoke", "contract", "contract-stress"], default="contract")
    parser.add_argument("--rest-stress-budget", choices=["off", "smoke", "soak"], default="smoke")
    parser.add_argument("--rest-stress-duration-seconds", type=float, default=30.0)
    parser.add_argument("--rest-stress-concurrency", type=int, default=4)
    parser.add_argument("--rest-stress-max-failures", type=int, default=1)
    parser.add_argument("--rest-stress-request-timeout-seconds", type=float, default=5.0)
    parser.add_argument("--rest-socket-adversity-budget", choices=["off", "smoke"], default="off")
    parser.add_argument("--rest-tls-handshake-adversity-budget", choices=["off", "smoke"], default="off")
    parser.add_argument("--rest-leak-churn-budget", choices=["off", "smoke", "soak"], default="off")
    parser.add_argument("--rest-leak-churn-cycles", type=int)
    parser.add_argument("--rest-stop-start-after-churn", action="store_true")
    parser.add_argument("--arr-direct-search-stress-count", type=int, default=DEFAULT_ARR_DIRECT_SEARCH_STRESS_COUNT)
    parser.add_argument("--arr-prowlarr-search-stress-count", type=int, default=DEFAULT_ARR_PROWLARR_SEARCH_STRESS_COUNT)
    parser.add_argument("--emule-connection-timeout-seconds", type=float, default=DEFAULT_EMULE_CONNECTION_TIMEOUT_SECONDS)
    parser.add_argument("--arr-search-timeout-seconds", type=float, default=DEFAULT_ARR_SEARCH_TIMEOUT_SECONDS)
    parser.add_argument("--document-download-timeout-seconds", type=float, default=DEFAULT_DOCUMENT_DOWNLOAD_TIMEOUT_SECONDS)
    parser.add_argument("--media-acquisition-timeout-minutes", type=float, default=DEFAULT_MEDIA_ACQUISITION_TIMEOUT_MINUTES)
    parser.add_argument(
        "--arr-download-proof-mode",
        choices=["complete", "handoff"],
        default=DEFAULT_ARR_DOWNLOAD_PROOF_MODE,
    )
    parser.add_argument("--radarr-movie-root")
    parser.add_argument("--sonarr-series-root")
    parser.add_argument("--rest-cold-start-dump-stress-waves", type=int, default=DEFAULT_REST_COLD_START_DUMP_STRESS_WAVES)
    parser.add_argument(
        "--rest-cold-start-dump-stress-searches-per-wave",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_SEARCHES_PER_WAVE,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-max-concurrent-searches",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_MAX_CONCURRENT_SEARCHES,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-search-observation-timeout-seconds",
        type=float,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_SEARCH_OBSERVATION_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-downloads-per-wave",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_WAVE,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-downloads-per-search",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOADS_PER_SEARCH,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-max-missing-download-triggers",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_MAX_MISSING_DOWNLOAD_TRIGGERS,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-synthetic-queue-fill-count",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_COUNT,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-synthetic-queue-fill-size-bytes",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_SIZE_BYTES,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-synthetic-queue-fill-batch-size",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_SYNTHETIC_QUEUE_FILL_BATCH_SIZE,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-target-completed-downloads",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_TARGET_COMPLETED_DOWNLOADS,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-completion-timeout-seconds",
        type=float,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_COMPLETION_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-max-active-downloads",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_MAX_ACTIVE_DOWNLOADS,
    )
    parser.add_argument("--rest-cold-start-dump-stress-allow-required-zero-result-searches", action="store_true")
    parser.add_argument("--rest-cold-start-dump-stress-skip-transfer-cleanup", action="store_true")
    parser.add_argument(
        "--rest-cold-start-dump-stress-download-churn-interval-seconds",
        type=float,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOAD_CHURN_INTERVAL_SECONDS,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-download-remove-count-per-churn",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_DOWNLOAD_REMOVE_COUNT_PER_CHURN,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-resource-monitor-interval-seconds",
        type=float,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_RESOURCE_MONITOR_INTERVAL_SECONDS,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-post-drain-seconds",
        type=float,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_POST_DRAIN_SECONDS,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-tool-timeout-seconds",
        type=float,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_TOOL_TIMEOUT_SECONDS,
    )
    parser.add_argument("--rest-cold-start-dump-stress-enable-umdh", action="store_true")
    parser.add_argument("--rest-cold-start-dump-stress-skip-umdh-diffs", action="store_true")
    parser.add_argument("--rest-cold-start-dump-stress-cpu-profile", action="store_true")
    parser.add_argument(
        "--rest-cold-start-dump-stress-cpu-profile-max-file-mb",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_CPU_PROFILE_MAX_FILE_MB,
    )
    parser.add_argument("--rest-cold-start-dump-stress-cpu-profile-stack", action="store_true")
    parser.add_argument(
        "--rest-cold-start-dump-stress-cpu-profile-stack-min-hits",
        type=int,
        default=DEFAULT_REST_COLD_START_DUMP_STRESS_CPU_PROFILE_STACK_MIN_HITS,
    )
    parser.add_argument(
        "--rest-cold-start-dump-stress-cpu-profile-symbols-required",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument("--rest-cold-start-dump-stress-skip-dumps", action="store_true")
    parser.add_argument("--p2p-bind-interface-name", default="hide.me")
    parser.add_argument(
        "--live-wire-inputs-file",
        default=str(live_wire_inputs.get_default_inputs_path(Path(__file__).resolve().parent.parent)),
    )
    parser.add_argument("--search-ui-search-rounds", type=int, default=DEFAULT_SEARCH_UI_SEARCH_ROUNDS)
    parser.add_argument("--search-ui-download-lifecycle-count", type=int, default=DEFAULT_SEARCH_UI_DOWNLOAD_LIFECYCLE_COUNT)
    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validates aggregate runner arguments that affect child network searches."""

    if args.rest_server_search_count < 0 or args.rest_kad_search_count < 0:
        raise ValueError("REST live search counts must be zero or greater.")
    if args.rest_download_trigger_count < 0:
        raise ValueError("REST live download trigger count must be zero or greater.")
    if args.rest_stress_duration_seconds <= 0:
        raise ValueError("REST stress duration must be greater than zero.")
    if args.rest_stress_concurrency <= 0:
        raise ValueError("REST stress concurrency must be greater than zero.")
    if args.rest_stress_max_failures < 0:
        raise ValueError("REST stress max failures must be zero or greater.")
    if args.rest_stress_request_timeout_seconds <= 0:
        raise ValueError("REST stress request timeout must be greater than zero.")
    if args.rest_stop_start_after_churn and args.rest_leak_churn_budget == "off":
        raise ValueError("REST stop/start after churn requires --rest-leak-churn-budget.")
    if args.arr_direct_search_stress_count <= 0:
        raise ValueError("Arr direct search stress count must be greater than zero.")
    if args.arr_prowlarr_search_stress_count <= 0:
        raise ValueError("Arr Prowlarr search stress count must be greater than zero.")
    if args.emule_connection_timeout_seconds <= 0:
        raise ValueError("eMule connection timeout must be greater than zero.")
    if args.arr_search_timeout_seconds <= 0:
        raise ValueError("Arr search timeout must be greater than zero.")
    if args.document_download_timeout_seconds <= 0:
        raise ValueError("Document download timeout must be greater than zero.")
    if args.media_acquisition_timeout_minutes <= 0:
        raise ValueError("Media acquisition timeout must be greater than zero.")
    if args.rest_cold_start_dump_stress_waves <= 0:
        raise ValueError("REST cold-start dump stress waves must be greater than zero.")
    if args.rest_cold_start_dump_stress_searches_per_wave <= 0:
        raise ValueError("REST cold-start dump stress searches per wave must be greater than zero.")
    if args.rest_cold_start_dump_stress_max_concurrent_searches <= 0:
        raise ValueError("REST cold-start dump stress concurrency must be greater than zero.")
    if args.rest_cold_start_dump_stress_search_observation_timeout_seconds <= 0:
        raise ValueError("REST cold-start dump stress search observation timeout must be greater than zero.")
    if args.rest_cold_start_dump_stress_downloads_per_wave < 0:
        raise ValueError("REST cold-start dump stress downloads per wave must be zero or greater.")
    if args.rest_cold_start_dump_stress_downloads_per_search < 0:
        raise ValueError("REST cold-start dump stress downloads per search must be zero or greater.")
    if args.rest_cold_start_dump_stress_max_missing_download_triggers < 0:
        raise ValueError("REST cold-start dump stress max missing download triggers must be zero or greater.")
    if args.rest_cold_start_dump_stress_synthetic_queue_fill_count < 0:
        raise ValueError("REST cold-start dump stress synthetic queue fill count must be zero or greater.")
    if args.rest_cold_start_dump_stress_synthetic_queue_fill_size_bytes <= 0:
        raise ValueError("REST cold-start dump stress synthetic queue fill size bytes must be greater than zero.")
    if args.rest_cold_start_dump_stress_synthetic_queue_fill_batch_size <= 0:
        raise ValueError("REST cold-start dump stress synthetic queue fill batch size must be greater than zero.")
    if args.rest_cold_start_dump_stress_target_completed_downloads < 0:
        raise ValueError("REST cold-start dump stress target completed downloads must be zero or greater.")
    if args.rest_cold_start_dump_stress_completion_timeout_seconds <= 0:
        raise ValueError("REST cold-start dump stress completion timeout must be greater than zero.")
    if args.rest_cold_start_dump_stress_max_active_downloads <= 0:
        raise ValueError("REST cold-start dump stress max active downloads must be greater than zero.")
    if args.rest_cold_start_dump_stress_download_churn_interval_seconds < 0:
        raise ValueError("REST cold-start dump stress download churn interval must be zero or greater.")
    if args.rest_cold_start_dump_stress_download_remove_count_per_churn < 0:
        raise ValueError("REST cold-start dump stress download remove count must be zero or greater.")
    if args.rest_cold_start_dump_stress_resource_monitor_interval_seconds < 0:
        raise ValueError("REST cold-start dump stress resource monitor interval must be zero or greater.")
    if args.rest_cold_start_dump_stress_post_drain_seconds < 0:
        raise ValueError("REST cold-start dump stress post-drain seconds must be zero or greater.")
    if args.rest_cold_start_dump_stress_tool_timeout_seconds <= 0:
        raise ValueError("REST cold-start dump stress tool timeout must be greater than zero.")
    if args.rest_cold_start_dump_stress_cpu_profile_max_file_mb <= 0:
        raise ValueError("REST cold-start dump stress CPU profile max file MB must be greater than zero.")
    if args.rest_cold_start_dump_stress_cpu_profile_stack_min_hits <= 0:
        raise ValueError("REST cold-start dump stress CPU profile stack min hits must be greater than zero.")
    if args.shared_files_ui_cpu_profile_max_file_mb <= 0:
        raise ValueError("Shared Files UI CPU profile max file MB must be greater than zero.")
    if args.shared_files_ui_cpu_profile_stack_min_hits <= 0:
        raise ValueError("Shared Files UI CPU profile stack min hits must be greater than zero.")
    if args.profile_cpu_max_file_mb <= 0:
        raise ValueError("CPU profile max file MB must be greater than zero.")
    if args.profile_cpu_stack_min_hits <= 0:
        raise ValueError("CPU profile stack min hits must be greater than zero.")
    if args.profile_resource_interval_seconds <= 0:
        raise ValueError("Profile resource monitor interval must be greater than zero.")
    if args.vhd_size_mb <= 0:
        raise ValueError("Admin volume fixture VHD size must be greater than zero.")
    if args.search_ui_search_rounds <= 0:
        raise ValueError("Search UI rounds must be greater than zero.")
    if args.search_ui_download_lifecycle_count <= 0:
        raise ValueError("Search UI download lifecycle count must be greater than zero.")


def run_live_e2e_suite(args: argparse.Namespace, harness_cli_common) -> dict[str, object]:
    """Runs the selected live E2E suites and returns the aggregate summary."""

    explicit_suite_names = tuple(args.suite or ())
    apply_profile_defaults(args)
    if (
        args.profile_memory
        and args.rest_cold_start_dump_stress_resource_monitor_interval_seconds
        == DEFAULT_REST_COLD_START_DUMP_STRESS_RESOURCE_MONITOR_INTERVAL_SECONDS
    ):
        args.rest_cold_start_dump_stress_resource_monitor_interval_seconds = args.profile_resource_interval_seconds
    validate_args(args)
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="live-e2e-suite",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    selected_specs = resolve_suite_specs(args.suite)
    if any(spec.requires_admin_volume_fixtures for spec in selected_specs) and not args.admin_volume_fixtures:
        raise ValueError("Selected admin storage live suites require --admin-volume-fixtures.")
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    python_executable = harness_cli_common.find_python_executable()
    seed_config_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else None
    shared_root = Path(args.shared_root).resolve() if args.shared_root else None
    radarr_movie_root = args.radarr_movie_root.strip() if args.radarr_movie_root else None
    sonarr_series_root = args.sonarr_series_root.strip() if args.sonarr_series_root else None
    mounted_shared_root = Path(args.mounted_shared_root) if args.mounted_shared_root else None
    mount_root = Path(args.mount_root) if args.mount_root else None
    shared_files_ui_scenarios = tuple(args.shared_files_ui_scenario or ())
    resolved_shared_files_ui_scenarios = list(
        shared_files_ui_scenarios
        or next(
            (spec.scenarios for spec in selected_specs if spec.name == "shared-files-ui"),
            (),
        )
    )
    if (
        args.admin_volume_fixtures
        and any(spec.name == "shared-files-ui" for spec in selected_specs)
        and not shared_files_ui_scenarios
    ):
        resolved_shared_files_ui_scenarios = list(dict.fromkeys((*resolved_shared_files_ui_scenarios, *SHARED_FILES_UI_ADMIN_SCENARIOS)))
    live_wire_inputs_file = live_wire_inputs.resolve_inputs_path(
        Path(__file__).resolve().parent.parent,
        args.live_wire_inputs_file,
    )

    summary: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": "passed",
        "suite": "live-e2e-suite",
        "profile": args.profile,
        "profile_suite_selection_applied": args.profile != "default" and not explicit_suite_names,
        "explicit_suite_names": list(explicit_suite_names),
        "configuration": args.configuration,
        "app_exe": str(paths.app_exe),
        "workspace_root": str(paths.workspace_root),
        "app_root": str(paths.app_root),
        "artifact_dir": str(paths.run_report_dir),
        "latest_report_dir": str(paths.latest_report_dir),
        "source_artifact_dir": str(paths.source_artifacts_dir),
        "local_dumps": paths.local_dumps,
        "live_seed_source_url": EMULE_SECURITY_HOME_URL,
        "live_seed_refresh_enabled": not args.skip_live_seed_refresh,
        "live_wire_inputs_file": str(live_wire_inputs_file),
        "search_ui": {
            "search_rounds": args.search_ui_search_rounds,
            "download_lifecycle_count": args.search_ui_download_lifecycle_count,
        },
        "shared_files_ui_scenarios": resolved_shared_files_ui_scenarios,
        "shared_files_ui_cpu_profile": {
            "enabled": bool(args.shared_files_ui_cpu_profile),
            "max_file_mb": args.shared_files_ui_cpu_profile_max_file_mb,
            "stack": bool(args.shared_files_ui_cpu_profile_stack),
            "stack_min_hits": args.shared_files_ui_cpu_profile_stack_min_hits,
            "symbols_required": bool(args.shared_files_ui_cpu_profile_symbols_required),
        },
        "profiling": {
            "cpu": {
                "enabled": bool(args.profile_cpu),
                "suite_names": [spec.name for spec in selected_specs if spec.name in CPU_PROFILED_SUITE_NAMES],
                "max_file_mb": args.profile_cpu_max_file_mb,
                "stack": bool(args.profile_cpu_stack),
                "stack_min_hits": args.profile_cpu_stack_min_hits,
                "symbols_required": bool(args.profile_symbols_required),
            },
            "memory": {
                "enabled": bool(args.profile_memory),
                "resource_interval_seconds": args.profile_resource_interval_seconds,
                "rest_cold_start_resource_interval_seconds": args.rest_cold_start_dump_stress_resource_monitor_interval_seconds,
            },
        },
        "preference_ui_directories_tree_stress": bool(args.preference_ui_directories_tree_stress),
        "rest_coverage_budget": args.rest_coverage_budget,
        "rest_stress_budget": args.rest_stress_budget,
        "rest_stress_duration_seconds": args.rest_stress_duration_seconds,
        "rest_stress_concurrency": args.rest_stress_concurrency,
        "rest_stress_max_failures": args.rest_stress_max_failures,
        "rest_stress_request_timeout_seconds": args.rest_stress_request_timeout_seconds,
        "rest_socket_adversity_budget": args.rest_socket_adversity_budget,
        "rest_tls_handshake_adversity_budget": args.rest_tls_handshake_adversity_budget,
        "rest_leak_churn_budget": args.rest_leak_churn_budget,
        "rest_leak_churn_cycles": args.rest_leak_churn_cycles,
        "rest_stop_start_after_churn": bool(args.rest_stop_start_after_churn),
        "rest_download_trigger_count": args.rest_download_trigger_count,
        "rest_search_method_override": args.rest_search_method_override,
        "weak_path_matrix": {
            "adversity": {
                "rest_socket_adversity_budget": args.rest_socket_adversity_budget,
                "rest_tls_handshake_adversity_budget": args.rest_tls_handshake_adversity_budget,
                "rest_leak_churn_budget": args.rest_leak_churn_budget,
                "rest_stop_start_after_churn": bool(args.rest_stop_start_after_churn),
                "local_dumps_crash_smoke": any(spec.name == "local-dumps-crash-smoke" for spec in selected_specs),
            },
            "live_download_triggers": {
                "server_search_count": args.rest_server_search_count,
                "kad_search_count": args.rest_kad_search_count,
                "required_queued_triggers": args.rest_download_trigger_count,
                "success_policy": "accepted_and_materialized_in_transfer_queue",
            },
            "ui": {
                "resource_ui_smoke": any(spec.name == "resource-ui-smoke" for spec in selected_specs),
                "preference_ui": any(spec.name == "preference-ui" for spec in selected_specs),
                "preference_ui_directories_tree_stress": bool(args.preference_ui_directories_tree_stress),
                "shared_files_ui": any(spec.name == "shared-files-ui" for spec in selected_specs),
                "shared_hash_ui": any(spec.name == "shared-hash-ui" for spec in selected_specs),
                "search_ui_live": any(spec.name == "search-ui-live" for spec in selected_specs),
                "shared_directories_rest": any(spec.name == "shared-directories-rest" for spec in selected_specs),
            },
            "storage": {
                "shared_cache_volume_identity": any(spec.name == "shared-cache-volume-identity" for spec in selected_specs),
                "shared_cache_invalidation": any(spec.name == "shared-cache-invalidation" for spec in selected_specs),
                "unc_mapped_drive_identity": any(spec.name == "unc-mapped-drive-identity" for spec in selected_specs),
                "vhd_long_path_special_names": any(spec.name == "vhd-long-path-special-names" for spec in selected_specs),
                "disk_space_guard_live": any(spec.name == "disk-space-guard-live" for spec in selected_specs),
                "vhd_profile_isolation": any(spec.name == "vhd-profile-isolation" for spec in selected_specs),
                "vhd_profile_durability": any(spec.name == "vhd-profile-durability" for spec in selected_specs),
                "category_incoming_path_matrix": any(spec.name == "category-incoming-path-matrix" for spec in selected_specs),
                "vhd_partfile_recovery": any(spec.name == "vhd-partfile-recovery" for spec in selected_specs),
                "admin_volume_cleanup_audit": any(spec.name == "admin-volume-cleanup-audit" for spec in selected_specs),
                "admin_volume_fixtures": bool(args.admin_volume_fixtures),
            },
            "integrations": {
                "amutorrent_browser_smoke": any(spec.name == "amutorrent-browser-smoke" for spec in selected_specs),
                "arr_live_wire_suites": [
                    spec.name
                    for spec in selected_specs
                    if spec.is_prowlarr_emulebb or spec.is_arr_emulebb
                ],
            },
        },
        "arr_direct_search_stress_count": args.arr_direct_search_stress_count,
        "arr_prowlarr_search_stress_count": args.arr_prowlarr_search_stress_count,
        "child_suite_timeout_seconds": DEFAULT_CHILD_SUITE_TIMEOUT_SECONDS,
        "emule_connection_timeout_seconds": args.emule_connection_timeout_seconds,
        "arr_search_timeout_seconds": args.arr_search_timeout_seconds,
        "document_download_timeout_seconds": args.document_download_timeout_seconds,
        "media_acquisition_timeout_minutes": args.media_acquisition_timeout_minutes,
        "arr_download_proof_mode": args.arr_download_proof_mode,
        "radarr_movie_root_configured": bool(args.radarr_movie_root),
        "radarr_movie_root_present": bool(args.radarr_movie_root),
        "sonarr_series_root_configured": bool(args.sonarr_series_root),
        "sonarr_series_root_present": bool(args.sonarr_series_root),
        "mounted_shared_root_configured": mounted_shared_root is not None,
        "mounted_shared_root": str(mounted_shared_root) if mounted_shared_root is not None else None,
        "admin_volume_fixtures": {
            "enabled": bool(args.admin_volume_fixtures),
            "vhd_size_mb": args.vhd_size_mb,
            "mount_root": str(mount_root) if mount_root is not None else None,
            "keep": bool(args.keep_admin_fixtures),
            "suite_names": [
                spec.name
                for spec in selected_specs
                if spec.requires_admin_volume_fixtures or spec.accepts_admin_volume_fixtures
            ],
        },
        "rest_cold_start_dump_stress": {
            "waves": args.rest_cold_start_dump_stress_waves,
            "searches_per_wave": args.rest_cold_start_dump_stress_searches_per_wave,
            "max_concurrent_searches": args.rest_cold_start_dump_stress_max_concurrent_searches,
            "search_observation_timeout_seconds": args.rest_cold_start_dump_stress_search_observation_timeout_seconds,
            "downloads_per_wave": args.rest_cold_start_dump_stress_downloads_per_wave,
            "downloads_per_search": args.rest_cold_start_dump_stress_downloads_per_search,
            "max_missing_download_triggers": args.rest_cold_start_dump_stress_max_missing_download_triggers,
            "synthetic_queue_fill_count": args.rest_cold_start_dump_stress_synthetic_queue_fill_count,
            "synthetic_queue_fill_size_bytes": args.rest_cold_start_dump_stress_synthetic_queue_fill_size_bytes,
            "synthetic_queue_fill_batch_size": args.rest_cold_start_dump_stress_synthetic_queue_fill_batch_size,
            "target_completed_downloads": args.rest_cold_start_dump_stress_target_completed_downloads,
            "completion_timeout_seconds": args.rest_cold_start_dump_stress_completion_timeout_seconds,
            "max_active_downloads": args.rest_cold_start_dump_stress_max_active_downloads,
            "allow_required_zero_result_searches": bool(args.rest_cold_start_dump_stress_allow_required_zero_result_searches),
            "skip_transfer_cleanup": bool(args.rest_cold_start_dump_stress_skip_transfer_cleanup),
            "download_churn_interval_seconds": args.rest_cold_start_dump_stress_download_churn_interval_seconds,
            "download_remove_count_per_churn": args.rest_cold_start_dump_stress_download_remove_count_per_churn,
            "resource_monitor_interval_seconds": args.rest_cold_start_dump_stress_resource_monitor_interval_seconds,
            "post_drain_seconds": args.rest_cold_start_dump_stress_post_drain_seconds,
            "tool_timeout_seconds": args.rest_cold_start_dump_stress_tool_timeout_seconds,
            "enable_umdh": bool(args.rest_cold_start_dump_stress_enable_umdh),
            "skip_umdh_diffs": bool(args.rest_cold_start_dump_stress_skip_umdh_diffs),
            "cpu_profile": bool(args.rest_cold_start_dump_stress_cpu_profile),
            "cpu_profile_max_file_mb": args.rest_cold_start_dump_stress_cpu_profile_max_file_mb,
            "cpu_profile_stack": bool(args.rest_cold_start_dump_stress_cpu_profile_stack),
            "cpu_profile_stack_min_hits": args.rest_cold_start_dump_stress_cpu_profile_stack_min_hits,
            "cpu_profile_symbols_required": bool(args.rest_cold_start_dump_stress_cpu_profile_symbols_required),
            "skip_dumps": bool(args.rest_cold_start_dump_stress_skip_dumps),
        },
        "rest_contract_completeness_expected": args.rest_coverage_budget != "smoke",
        "arr_live_wire_suites": [
            spec.name
            for spec in selected_specs
            if spec.is_prowlarr_emulebb or spec.is_arr_emulebb
        ],
        "fail_fast": bool(args.fail_fast),
        "strict_success_required": True,
        "suites": [],
    }

    for spec in selected_specs:
        child_artifacts_dir = paths.source_artifacts_dir / spec.name
        command = build_suite_command(
            spec=spec,
            scripts_dir=scripts_dir,
            python_executable=python_executable,
            workspace_root=paths.workspace_root,
            configuration=args.configuration,
            artifacts_dir=paths.source_artifacts_dir,
            app_root=paths.app_root,
            app_exe=paths.app_exe,
            seed_config_dir=seed_config_dir,
            startup_trace_mode=args.startup_trace_mode,
            shared_root=shared_root,
            preference_ui_directories_tree_stress=args.preference_ui_directories_tree_stress,
            shared_files_ui_scenarios=shared_files_ui_scenarios or None,
            shared_files_tree_stress_churn_cycles=args.shared_files_tree_stress_churn_cycles,
            skip_live_seed_refresh=args.skip_live_seed_refresh,
            rest_server_search_count=args.rest_server_search_count,
            rest_kad_search_count=args.rest_kad_search_count,
            rest_download_trigger_count=args.rest_download_trigger_count,
            rest_search_method_override=args.rest_search_method_override,
            rest_webserver_scheme=args.rest_webserver_scheme,
            rest_coverage_budget=args.rest_coverage_budget,
            rest_stress_budget=args.rest_stress_budget,
            rest_stress_duration_seconds=args.rest_stress_duration_seconds,
            rest_stress_concurrency=args.rest_stress_concurrency,
            rest_stress_max_failures=args.rest_stress_max_failures,
            rest_stress_request_timeout_seconds=args.rest_stress_request_timeout_seconds,
            rest_socket_adversity_budget=args.rest_socket_adversity_budget,
            rest_tls_handshake_adversity_budget=args.rest_tls_handshake_adversity_budget,
            rest_leak_churn_budget=args.rest_leak_churn_budget,
            rest_leak_churn_cycles=args.rest_leak_churn_cycles,
            rest_stop_start_after_churn=args.rest_stop_start_after_churn,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
            live_wire_inputs_file=live_wire_inputs_file,
            search_ui_search_rounds=args.search_ui_search_rounds,
            search_ui_download_lifecycle_count=args.search_ui_download_lifecycle_count,
            arr_direct_search_stress_count=args.arr_direct_search_stress_count,
            arr_prowlarr_search_stress_count=args.arr_prowlarr_search_stress_count,
            emule_connection_timeout_seconds=args.emule_connection_timeout_seconds,
            arr_search_timeout_seconds=args.arr_search_timeout_seconds,
            document_download_timeout_seconds=args.document_download_timeout_seconds,
            media_acquisition_timeout_minutes=args.media_acquisition_timeout_minutes,
            arr_download_proof_mode=args.arr_download_proof_mode,
            radarr_movie_root=radarr_movie_root,
            sonarr_series_root=sonarr_series_root,
            rest_cold_start_dump_stress_waves=args.rest_cold_start_dump_stress_waves,
            rest_cold_start_dump_stress_searches_per_wave=args.rest_cold_start_dump_stress_searches_per_wave,
            rest_cold_start_dump_stress_max_concurrent_searches=args.rest_cold_start_dump_stress_max_concurrent_searches,
            rest_cold_start_dump_stress_search_observation_timeout_seconds=args.rest_cold_start_dump_stress_search_observation_timeout_seconds,
            rest_cold_start_dump_stress_downloads_per_wave=args.rest_cold_start_dump_stress_downloads_per_wave,
            rest_cold_start_dump_stress_downloads_per_search=args.rest_cold_start_dump_stress_downloads_per_search,
            rest_cold_start_dump_stress_max_missing_download_triggers=args.rest_cold_start_dump_stress_max_missing_download_triggers,
            rest_cold_start_dump_stress_synthetic_queue_fill_count=args.rest_cold_start_dump_stress_synthetic_queue_fill_count,
            rest_cold_start_dump_stress_synthetic_queue_fill_size_bytes=args.rest_cold_start_dump_stress_synthetic_queue_fill_size_bytes,
            rest_cold_start_dump_stress_synthetic_queue_fill_batch_size=args.rest_cold_start_dump_stress_synthetic_queue_fill_batch_size,
            rest_cold_start_dump_stress_target_completed_downloads=args.rest_cold_start_dump_stress_target_completed_downloads,
            rest_cold_start_dump_stress_completion_timeout_seconds=args.rest_cold_start_dump_stress_completion_timeout_seconds,
            rest_cold_start_dump_stress_max_active_downloads=args.rest_cold_start_dump_stress_max_active_downloads,
            rest_cold_start_dump_stress_allow_required_zero_result_searches=args.rest_cold_start_dump_stress_allow_required_zero_result_searches,
            rest_cold_start_dump_stress_skip_transfer_cleanup=args.rest_cold_start_dump_stress_skip_transfer_cleanup,
            rest_cold_start_dump_stress_download_churn_interval_seconds=args.rest_cold_start_dump_stress_download_churn_interval_seconds,
            rest_cold_start_dump_stress_download_remove_count_per_churn=args.rest_cold_start_dump_stress_download_remove_count_per_churn,
            rest_cold_start_dump_stress_resource_monitor_interval_seconds=args.rest_cold_start_dump_stress_resource_monitor_interval_seconds,
            rest_cold_start_dump_stress_post_drain_seconds=args.rest_cold_start_dump_stress_post_drain_seconds,
            rest_cold_start_dump_stress_tool_timeout_seconds=args.rest_cold_start_dump_stress_tool_timeout_seconds,
            rest_cold_start_dump_stress_enable_umdh=args.rest_cold_start_dump_stress_enable_umdh,
            rest_cold_start_dump_stress_skip_umdh_diffs=args.rest_cold_start_dump_stress_skip_umdh_diffs,
            rest_cold_start_dump_stress_cpu_profile=args.rest_cold_start_dump_stress_cpu_profile,
            rest_cold_start_dump_stress_cpu_profile_max_file_mb=args.rest_cold_start_dump_stress_cpu_profile_max_file_mb,
            rest_cold_start_dump_stress_cpu_profile_stack=args.rest_cold_start_dump_stress_cpu_profile_stack,
            rest_cold_start_dump_stress_cpu_profile_stack_min_hits=args.rest_cold_start_dump_stress_cpu_profile_stack_min_hits,
            rest_cold_start_dump_stress_cpu_profile_symbols_required=args.rest_cold_start_dump_stress_cpu_profile_symbols_required,
            rest_cold_start_dump_stress_skip_dumps=args.rest_cold_start_dump_stress_skip_dumps,
            resource_ui_language_timeout_seconds=args.resource_ui_language_timeout_seconds,
            mounted_shared_root=mounted_shared_root,
            admin_volume_fixtures=args.admin_volume_fixtures,
            vhd_size_mb=args.vhd_size_mb,
            mount_root=mount_root,
            keep_admin_fixtures=args.keep_admin_fixtures,
            fail_fast=args.fail_fast,
        )
        started = time.monotonic()
        return_code, suite_cpu_profile = run_suite_command_with_optional_cpu_profile(
            command,
            spec=spec,
            args=args,
            child_artifacts_dir=child_artifacts_dir,
            app_exe=paths.app_exe,
        )
        child_result = read_child_suite_result(child_artifacts_dir)
        suite_status = get_suite_status_from_return_code(return_code)
        result = {
            "name": spec.name,
            "category": spec.category,
            "status": suite_status,
            "return_code": return_code,
            "timed_out": return_code == SUITE_TIMEOUT_RETURN_CODE,
            "timeout_seconds": DEFAULT_CHILD_SUITE_TIMEOUT_SECONDS,
            "duration_seconds": round(time.monotonic() - started, 3),
            "artifacts_dir": str(child_artifacts_dir.resolve()),
            "command": command,
            "scenario_names": (
                list(shared_files_ui_scenarios)
                if spec.name == "shared-files-ui" and shared_files_ui_scenarios
                else list(spec.scenarios)
            ),
            "uses_live_seed_refresh": bool(spec.uses_live_seed_refresh and not args.skip_live_seed_refresh),
        }
        if suite_cpu_profile is not None:
            result["cpu_profile"] = suite_cpu_profile
            result.setdefault("diagnostics", {})["cpu_profile"] = suite_cpu_profile  # type: ignore[index]
            if suite_cpu_profile.get("status") == "failed" and suite_status == "passed":
                suite_status = "failed"
                result["status"] = suite_status
        if args.profile_memory:
            resource_diagnostics = extract_child_resource_diagnostics(child_result)
            result.setdefault("diagnostics", {})["resources"] = (  # type: ignore[index]
                resource_diagnostics
                or {
                    "resource_monitor": {
                        "enabled": False,
                        "reason": "child result did not publish resource diagnostics",
                    }
                }
            )
        if spec.name == "preference-ui":
            result["directories_tree_stress"] = bool(args.preference_ui_directories_tree_stress)
        if spec.is_resource_ui_smoke:
            result["language_scope"] = "release"
        if spec.is_rest_api:
            result.update(
                {
                    "rest_coverage_budget": args.rest_coverage_budget,
                    "rest_stress_budget": args.rest_stress_budget,
                    "rest_stress_duration_seconds": args.rest_stress_duration_seconds,
                    "rest_stress_concurrency": args.rest_stress_concurrency,
                    "rest_stress_max_failures": args.rest_stress_max_failures,
                    "rest_stress_request_timeout_seconds": args.rest_stress_request_timeout_seconds,
                    "rest_socket_adversity_budget": args.rest_socket_adversity_budget,
                    "rest_tls_handshake_adversity_budget": args.rest_tls_handshake_adversity_budget,
                    "rest_leak_churn_budget": args.rest_leak_churn_budget,
                    "rest_leak_churn_cycles": args.rest_leak_churn_cycles,
                    "rest_stop_start_after_churn": bool(args.rest_stop_start_after_churn),
                    "rest_download_trigger_count": args.rest_download_trigger_count,
                    "rest_search_method_override": args.rest_search_method_override,
                    "rest_contract_completeness_expected": args.rest_coverage_budget != "smoke",
                }
            )
        if spec.is_search_ui_live:
            result.update(
                {
                    "live_wire_inputs_file": str(live_wire_inputs_file),
                    "search_ui_search_rounds": args.search_ui_search_rounds,
                    "search_ui_download_lifecycle_count": args.search_ui_download_lifecycle_count,
                }
            )
        if spec.is_prowlarr_emulebb or spec.is_arr_emulebb:
            arr_result = {
                "arr_integration": True,
                "live_wire_inputs_file": str(live_wire_inputs_file),
                "emule_connection_timeout_seconds": args.emule_connection_timeout_seconds,
                "arr_search_timeout_seconds": args.arr_search_timeout_seconds,
            }
            if spec.is_prowlarr_emulebb:
                arr_result.update(
                    {
                        "arr_direct_search_stress_count": args.arr_direct_search_stress_count,
                        "arr_prowlarr_search_stress_count": args.arr_prowlarr_search_stress_count,
                        "document_download_timeout_seconds": args.document_download_timeout_seconds,
                    }
                )
            if spec.is_arr_emulebb:
                arr_result["media_acquisition_timeout_minutes"] = args.media_acquisition_timeout_minutes
                if spec.name == "radarr-emulebb":
                    arr_result["radarr_movie_root_configured"] = bool(args.radarr_movie_root)
                if spec.name == "sonarr-emulebb":
                    arr_result["sonarr_series_root_configured"] = bool(args.sonarr_series_root)
            result.update(arr_result)
        if spec.is_rest_cold_start_dump_stress:
            result.update(
                {
                    "live_wire_inputs_file": str(live_wire_inputs_file),
                    "rest_cold_start_dump_stress": dict(summary["rest_cold_start_dump_stress"]),  # type: ignore[arg-type]
                }
            )
        if spec.requires_admin_volume_fixtures or spec.accepts_admin_volume_fixtures:
            result["admin_volume_fixture"] = dict(summary["admin_volume_fixtures"])  # type: ignore[arg-type]
        summary["suites"].append(result)  # type: ignore[index]
        if suite_status == "failed":
            summary["status"] = "failed"
            if args.fail_fast:
                break

    summary["local_dump_files"] = harness_cli_common.collect_local_dump_files(paths.local_dumps)
    result_path = paths.source_artifacts_dir / "result.json"
    harness_cli_common.write_json_file(result_path, summary)
    harness_cli_common.publish_run_artifacts(paths)
    harness_cli_common.publish_latest_report(paths)
    harness_cli_common.cleanup_source_artifacts(paths)
    return summary
