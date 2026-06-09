"""Canonical main-vs-community coverage orchestration."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .artifact_names import utc_run_id
from .live_diff import LiveDiffConfig, run_live_diff
from .native_coverage import NativeCoverageConfig, publish_directory_snapshot, run_native_coverage
from .paths import get_test_artifacts_root, get_test_reports_root, get_workspace_output_root
from .workspace_layout import get_default_workspace_root

lan_bind_ENV_NAMES = ("X_LOCAL_IP", "EMULEBB_TEST_LAN_IP_RESOLVED")


@dataclass(frozen=True)
class CommunityCoreCoverageConfig:
    """Resolved configuration for one community-core coverage run."""

    test_repo_root: Path
    workspace_root: Path
    main_app_root: Path
    community_app_root: Path
    configuration: str
    platform: str
    preferred_coverage_root: Path | None = None
    include_live_rest_e2e: bool = False
    rest_coverage_budget: str = "contract"
    rest_stress_budget: str = "off"
    rest_app_scope: str = "main-only"
    live_rest_server_search_count: int = 6
    live_rest_kad_search_count: int = 6
    live_rest_search_observation_timeout_seconds: float = 120.0


def get_latest_coverage_summary_path(workspace_root: Path) -> Path:
    """Returns the most recently written native coverage summary."""

    coverage_root = get_test_reports_root(workspace_root) / "native-coverage"
    summaries = sorted(
        coverage_root.glob("**/coverage-summary.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not summaries:
        raise RuntimeError(f"Unable to locate a native coverage summary under '{coverage_root}'.")
    return summaries[0]


def run_community_core_coverage(config: CommunityCoreCoverageConfig) -> int:
    """Runs the canonical main-vs-community coverage and live-diff comparison."""

    report_root = get_test_reports_root(config.workspace_root)
    run_report_dir = report_root / "community-core-coverage" / utc_run_id()
    run_report_dir.mkdir(parents=True, exist_ok=True)

    run_native_coverage(
        NativeCoverageConfig(
            test_repo_root=config.test_repo_root,
            workspace_root=config.workspace_root,
            app_root=config.main_app_root,
            configuration=config.configuration,
            platform=config.platform,
            suite_names=("parity", "protocol-parity", "community-core-divergence"),
            preferred_coverage_root=config.preferred_coverage_root,
        )
    )
    main_coverage_summary_path = get_latest_coverage_summary_path(config.workspace_root)

    run_native_coverage(
        NativeCoverageConfig(
            test_repo_root=config.test_repo_root,
            workspace_root=config.workspace_root,
            app_root=config.community_app_root,
            configuration=config.configuration,
            platform=config.platform,
            suite_names=("parity", "protocol-parity"),
            preferred_coverage_root=config.preferred_coverage_root,
        )
    )
    community_coverage_summary_path = get_latest_coverage_summary_path(config.workspace_root)

    live_diff_result = run_live_diff(
        LiveDiffConfig(
            test_repo_root=config.test_repo_root,
            test_run_workspace_root=config.workspace_root,
            baseline_workspace_root=config.workspace_root,
            test_run_app_root=config.main_app_root,
            baseline_app_root=config.community_app_root,
            configuration=config.configuration,
            platform=config.platform,
            suite_names=("parity", "protocol-parity", "community-core-divergence"),
            report_root=report_root,
        )
    )
    if live_diff_result != 0:
        return live_diff_result

    live_diff_summary_path = report_root / "live-diff-summary.json"
    live_rest_e2e = None
    if config.include_live_rest_e2e:
        live_rest_e2e = run_live_rest_e2e_for_community_summary(config, run_report_dir)

    combined_summary_path = run_report_dir / "community-core-coverage-summary.json"
    payload = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "workspace_root": str(config.workspace_root),
        "main_app_root": str(config.main_app_root),
        "community_app_root": str(config.community_app_root),
        "configuration": config.configuration,
        "platform": config.platform,
        "main_coverage_summary": str(main_coverage_summary_path),
        "community_coverage_summary": str(community_coverage_summary_path),
        "live_diff_summary": str(live_diff_summary_path),
        "live_rest_e2e": live_rest_e2e,
    }
    combined_summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    publish_directory_snapshot(run_report_dir, report_root / "community-core-coverage" / "latest")
    print(f"Community core coverage summary: {combined_summary_path}")
    if isinstance(live_rest_e2e, dict) and live_rest_e2e.get("return_code") not in (None, 0):
        return int(live_rest_e2e["return_code"])
    return 0


def build_config(
    *,
    test_repo_root: Path,
    workspace_root: Path | None,
    main_app_root: Path | None,
    community_app_root: Path | None,
    configuration: str,
    platform: str,
    preferred_coverage_root: Path | None,
    include_live_rest_e2e: bool = False,
    rest_coverage_budget: str = "contract",
    rest_stress_budget: str = "off",
    rest_app_scope: str = "main-only",
    live_rest_server_search_count: int = 6,
    live_rest_kad_search_count: int = 6,
    live_rest_search_observation_timeout_seconds: float = 120.0,
) -> CommunityCoreCoverageConfig:
    """Builds a resolved community-core coverage config from CLI inputs."""

    resolved_test_repo_root = test_repo_root.resolve()
    resolved_workspace_root = (
        workspace_root.resolve()
        if workspace_root is not None
        else get_default_workspace_root(resolved_test_repo_root)
    )
    resolved_main_app_root = (
        main_app_root.resolve()
        if main_app_root is not None
        else (resolved_workspace_root / "app" / "emulebb-main").resolve()
    )
    resolved_community_app_root = (
        community_app_root.resolve()
        if community_app_root is not None
        else (resolved_workspace_root / "app" / "emulebb-community-baseline").resolve()
    )
    for label, path in (
        ("workspace root", resolved_workspace_root),
        ("main app root", resolved_main_app_root),
        ("community app root", resolved_community_app_root),
    ):
        if not path.exists():
            raise RuntimeError(f"{label} does not exist: {path}")
    return CommunityCoreCoverageConfig(
        test_repo_root=resolved_test_repo_root,
        workspace_root=resolved_workspace_root,
        main_app_root=resolved_main_app_root,
        community_app_root=resolved_community_app_root,
        configuration=configuration,
        platform=platform,
        preferred_coverage_root=preferred_coverage_root.resolve() if preferred_coverage_root is not None else None,
        include_live_rest_e2e=include_live_rest_e2e,
        rest_coverage_budget=rest_coverage_budget,
        rest_stress_budget=rest_stress_budget,
        rest_app_scope=rest_app_scope,
        live_rest_server_search_count=live_rest_server_search_count,
        live_rest_kad_search_count=live_rest_kad_search_count,
        live_rest_search_observation_timeout_seconds=live_rest_search_observation_timeout_seconds,
    )


def run_live_rest_e2e_for_community_summary(
    config: CommunityCoreCoverageConfig,
    run_report_dir: Path,
) -> dict[str, object]:
    """Runs optional main-scoped REST live E2E and returns summary metadata."""

    if config.rest_app_scope != "main-only":
        raise ValueError("Community REST E2E currently supports only main-only app scope.")
    artifacts_dir = get_test_artifacts_root(config.workspace_root) / "community-core-coverage" / run_report_dir.name / "live-rest-e2e"
    command = [
        sys.executable,
        str(config.test_repo_root / "scripts" / "rest-api-smoke.py"),
        "--app-root",
        str(config.main_app_root),
        "--configuration",
        config.configuration,
        "--artifacts-dir",
        str(artifacts_dir),
        "--rest-coverage-budget",
        config.rest_coverage_budget,
        "--rest-stress-budget",
        config.rest_stress_budget,
        "--server-search-count",
        str(config.live_rest_server_search_count),
        "--kad-search-count",
        str(config.live_rest_kad_search_count),
        "--search-observation-timeout-seconds",
        str(config.live_rest_search_observation_timeout_seconds),
    ]
    env = os.environ.copy()
    env["EMULEBB_WORKSPACE_ROOT"] = str(config.workspace_root.parent.parent)
    env["EMULEBB_WORKSPACE_OUTPUT_ROOT"] = str(get_workspace_output_root())
    lan_bind_addr = resolve_lan_bind_address(env)
    if lan_bind_addr:
        command.extend(["--lan-bind-addr", lan_bind_addr])
    completed = subprocess.run(command, check=False, env=env)
    return {
        "status": "passed" if completed.returncode == 0 else "failed",
        "return_code": completed.returncode,
        "summary_path": str(artifacts_dir),
        "app_scope": config.rest_app_scope,
        "rest_coverage_budget": config.rest_coverage_budget,
        "rest_stress_budget": config.rest_stress_budget,
        "server_search_count": config.live_rest_server_search_count,
        "kad_search_count": config.live_rest_kad_search_count,
        "search_observation_timeout_seconds": config.live_rest_search_observation_timeout_seconds,
        "lan_bind_address": lan_bind_addr or "",
        "command": command,
    }


def resolve_lan_bind_address(env: dict[str, str]) -> str:
    """Returns the developer-specific LAN bind address when supplied by orchestration."""

    for name in lan_bind_ENV_NAMES:
        value = env.get(name, "").strip()
        if value:
            return value
    return ""


def invoke_script(argv: list[str]) -> int:
    """Runs the CLI using the shared config builder."""

    from argparse import ArgumentParser

    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--test-repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--main-app-root", type=Path)
    parser.add_argument("--community-app-root", type=Path)
    parser.add_argument("--configuration", choices=("Debug", "Release"), default="Debug")
    parser.add_argument("--platform", choices=("x64",), default="x64")
    parser.add_argument("--preferred-coverage-root", type=Path)
    parser.add_argument("--include-live-rest-e2e", action="store_true")
    parser.add_argument("--rest-coverage-budget", choices=("smoke", "contract", "contract-stress"), default="contract")
    parser.add_argument("--rest-stress-budget", choices=("off", "smoke", "soak"), default="off")
    parser.add_argument("--rest-app-scope", choices=("main-only",), default="main-only")
    parser.add_argument("--live-rest-server-search-count", type=int, default=6)
    parser.add_argument("--live-rest-kad-search-count", type=int, default=6)
    parser.add_argument("--live-rest-search-observation-timeout-seconds", type=float, default=120.0)
    args = parser.parse_args(argv)
    return run_community_core_coverage(
        build_config(
            test_repo_root=args.test_repo_root,
            workspace_root=None,
            main_app_root=args.main_app_root,
            community_app_root=args.community_app_root,
            configuration=args.configuration,
            platform=args.platform,
            preferred_coverage_root=args.preferred_coverage_root,
            include_live_rest_e2e=args.include_live_rest_e2e,
            rest_coverage_budget=args.rest_coverage_budget,
            rest_stress_budget=args.rest_stress_budget,
            rest_app_scope=args.rest_app_scope,
            live_rest_server_search_count=args.live_rest_server_search_count,
            live_rest_kad_search_count=args.live_rest_kad_search_count,
            live_rest_search_observation_timeout_seconds=args.live_rest_search_observation_timeout_seconds,
        )
    )


if __name__ == "__main__":
    raise SystemExit(invoke_script(sys.argv[1:]))
