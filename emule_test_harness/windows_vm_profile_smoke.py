"""Guest-side package profile smokes for Windows VM Hyper-V runs."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

try:
    from emule_test_harness.campaign_scenarios import (
        DEFAULT_LOCAL_SWARM_TIER,
        EXECUTION_MODES,
        LOCAL_SWARM_CLIENT_PRODUCTS,
        LOCAL_SWARM_TIER_OPTIONS,
        LOCAL_SWARM_TIERS,
        REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE,
    )
    from emule_test_harness.windows_vm_host import LOCAL_SWARM_PAYLOAD_SCRIPT_FILES
    from emule_test_harness.vm_guest_profiles import (
        emit,
        http_json,
        retry_http_json,
        start_visible_app,
        wait_until,
        write_preferences_ini,
    )
except ModuleNotFoundError:
    from campaign_scenarios import (
        DEFAULT_LOCAL_SWARM_TIER,
        EXECUTION_MODES,
        LOCAL_SWARM_CLIENT_PRODUCTS,
        LOCAL_SWARM_TIER_OPTIONS,
        LOCAL_SWARM_TIERS,
        REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE,
    )
    from windows_vm_host import LOCAL_SWARM_PAYLOAD_SCRIPT_FILES
    from vm_guest_profiles import emit, http_json, retry_http_json, start_visible_app, wait_until, write_preferences_ini

SUPPORTED_PROFILES = {
    "rest-smoke-stress",
    "crash-dump-smoke",
    "cpu-heavy-quick",
    "resource-ui-smoke",
    "release-expanded-ui",
    "package-helper-install",
    "vhd-profile-isolation",
    "shared-cache-filesystem",
    "diagnostics-local-dumps",
    "ui-shared-files-depth",
} | set(REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE)
API_KEY = "vm-profile-smoke-api-key"
REST_PORT = 4711


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=sorted(SUPPORTED_PROFILES))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--package-zip", required=True, type=Path)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--fixture-size-bytes", type=int, default=25 * 1024 * 1024)
    parser.add_argument("--swarm-tier", type=int, choices=LOCAL_SWARM_TIERS, default=DEFAULT_LOCAL_SWARM_TIER)
    parser.add_argument("--harness-root", type=Path)
    parser.add_argument("--ed2k-server-exe", type=Path)
    parser.add_argument("--client2-app-exe", type=Path)
    parser.add_argument("--amule-daemon-exe", type=Path)
    parser.add_argument("--amule-control-exe", type=Path)
    parser.add_argument("--local-swarm-mode", choices=["plan", "execute"], default="plan")
    parser.add_argument("--lan-bind-addr", default="127.0.0.1")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    result = run_profile(args)
    return emit(result)


def run_profile(args: argparse.Namespace) -> dict[str, Any]:
    root = args.root
    artifacts = root / "artifacts"
    profile_dir = root / "profile"
    config_dir = profile_dir / "config"
    incoming_dir = profile_dir / "incoming"
    temp_dir = profile_dir / "temp"
    shared_dir = profile_dir / "shared"
    expanded = root / "expanded"
    checks: list[dict[str, Any]] = []
    errors: list[str] = []
    app_started = False
    app_root = expanded / "eMuleBB"
    exe_path = app_root / "emulebb.exe"
    base_url = f"http://127.0.0.1:{REST_PORT}"

    try:
        reset_directory(artifacts)
        for directory in (config_dir, incoming_dir, temp_dir, shared_dir):
            directory.mkdir(parents=True, exist_ok=True)
        checks.append(extract_package(args.package_zip, expanded))
        checks.append(check_package_resources(app_root, args.profile))
        write_preferences_ini(
            config_dir,
            offline_preferences_text(
                target=args.target,
                incoming_dir=incoming_dir,
                temp_dir=temp_dir,
                shared_dir=shared_dir,
                enable_diagnostics=args.profile in {"crash-dump-smoke", "diagnostics-local-dumps"},
            ),
        )
        checks.append(make_fixture(shared_dir, args.fixture_size_bytes, args.profile))
        start_visible_app(
            exe_path,
            profile_dir,
            task_name=f"eMuleBB VM {args.profile} {args.target}",
            username=args.username,
            password=args.password,
        )
        app_started = True
        checks.append(wait_rest(base_url))
        checks.extend(run_rest_baseline(base_url))
        checks.extend(run_profile_checks(args.profile, base_url, profile_dir, app_root, shared_dir, artifacts, args))
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        if app_started and args.profile != "crash-dump-smoke":
            stop_runtime()

    checks.append(collect_application_events(artifacts))
    if args.profile in {"crash-dump-smoke", "diagnostics-local-dumps"}:
        checks.append(collect_dumps(config_dir, "post-crash-profile-dumps"))
        if args.profile == "diagnostics-local-dumps":
            checks.append(collect_local_dumps(root / "local-dumps"))
        stop_runtime()
    status = "passed" if not errors and all(check.get("status") == "passed" for check in checks) else "failed"
    result = {
        "schema": "emulebb.windows-vm-profile-smoke-target-result.v1",
        "status": status,
        "profile": args.profile,
        "target": args.target,
        "generatedAtUtc": utc_now(),
        "guest": guest_info(),
        "packageZip": str(args.package_zip),
        "appExe": str(exe_path),
        "profileDir": str(profile_dir),
        "restBaseUrl": base_url,
        "checks": checks,
        "errors": errors,
        "artifactsDir": str(artifacts),
    }
    (root / "target-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def reset_directory(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def extract_package(package_zip: Path, expanded: Path) -> dict[str, Any]:
    reset_directory(expanded)
    with zipfile.ZipFile(package_zip) as archive:
        archive.extractall(expanded)
    exe_path = expanded / "eMuleBB" / "emulebb.exe"
    return {
        "name": "extract-package",
        "status": "passed" if exe_path.is_file() else "failed",
        "details": {"packageZip": str(package_zip), "appExe": str(exe_path)},
    }


def check_package_resources(app_root: Path, profile: str) -> dict[str, Any]:
    lang_files = sorted((app_root / "lang").glob("*.dll"))
    skin_files = sorted((app_root / "skins").glob("*.eMuleSkin.ini"))
    min_lang = 40 if profile in {"resource-ui-smoke", "release-expanded-ui"} else 1
    return {
        "name": "package-resources",
        "status": "passed" if len(lang_files) >= min_lang and len(skin_files) >= 1 else "failed",
        "details": {
            "languageDllCount": len(lang_files),
            "skinCount": len(skin_files),
            "minLanguageDllCount": min_lang,
            "sampleLanguages": [path.name for path in lang_files[:8]],
        },
    }


def offline_preferences_text(
    *,
    target: str,
    incoming_dir: Path,
    temp_dir: Path,
    shared_dir: Path,
    enable_diagnostics: bool,
) -> str:
    return "\n".join(
        [
            "[eMule]",
            f"Nick={target}-vm-profile",
            "ConfirmExit=0",
            f"IncomingDir={incoming_dir}",
            f"TempDir={temp_dir}",
            f"SharedDir={shared_dir}",
            "CreateCrashDump=2",
            "BindAddr=",
            "BindInterface=",
            "NetworkED2K=0",
            "NetworkKademlia=0",
            "Autoconnect=0",
            "Reconnect=0",
            "SaveLogToDisk=1",
            "SaveDebugToDisk=1",
            "Verbose=1",
            "FullVerbose=1",
            "GeoLocationLookupEnabled=0",
            "[WebServer]",
            "Enabled=1",
            f"ApiKey={API_KEY}",
            f"Port={REST_PORT}",
            "BindAddr=127.0.0.1",
            "UseHTTPS=0",
            "AllowAdminHiLevelFunc=1",
            f"EnableDiagnosticRestEndpoints={1 if enable_diagnostics else 0}",
            "[UPnP]",
            "EnableUPnP=0",
            "",
        ]
    )


def make_fixture(shared_dir: Path, fixture_size_bytes: int, profile: str) -> dict[str, Any]:
    file_count = 3
    if profile == "cpu-heavy-quick":
        file_count = 64
    elif profile == "release-expanded-ui":
        file_count = 12
    size_per_file = max(1024, min(1024 * 1024, fixture_size_bytes // max(file_count, 1)))
    payload = b"emulebb-vm-profile-smoke\n"
    for index in range(file_count):
        path = shared_dir / f"{profile}-{index:03d}.bin"
        with path.open("wb") as handle:
            remaining = size_per_file
            while remaining > 0:
                chunk = payload[: min(len(payload), remaining)]
                handle.write(chunk)
                remaining -= len(chunk)
    return {
        "name": "fixture-files",
        "status": "passed",
        "details": {"fileCount": file_count, "sizePerFile": size_per_file, "sharedDir": str(shared_dir)},
    }


def wait_rest(base_url: str) -> dict[str, Any]:
    payload = wait_until(
        "REST status",
        120.0,
        lambda: http_json(base_url, "/api/v1/status", api_key=API_KEY, timeout_seconds=5.0),
    )
    return {"name": "rest-status-ready", "status": "passed", "details": compact(payload)}


def run_rest_baseline(base_url: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for name, path in (
        ("rest-status", "/api/v1/status"),
        ("rest-transfers", "/api/v1/transfers"),
        ("rest-shared-files", "/api/v1/shared-files"),
    ):
        checks.append(call_check(name, base_url, path))
    return checks


def run_profile_checks(
    profile: str,
    base_url: str,
    profile_dir: Path,
    app_root: Path,
    shared_dir: Path,
    artifacts: Path,
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    if profile == "rest-smoke-stress":
        return [rest_loop_check(base_url, loops=80)]
    if profile == "crash-dump-smoke":
        return [manual_dump_check(base_url), crash_trigger_check(base_url)]
    if profile == "cpu-heavy-quick":
        return [rest_loop_check(base_url, loops=150), shared_fixture_scan_check(shared_dir)]
    if profile == "resource-ui-smoke":
        return [resource_presence_check(app_root, min_lang=40)]
    if profile == "release-expanded-ui":
        return [resource_presence_check(app_root, min_lang=40), rest_loop_check(base_url, loops=120)]
    if profile == "package-helper-install":
        return [
            powershell_script_parse_check(app_root),
            install_suite_dry_run_check(app_root, artifacts),
            firewall_repair_check(app_root, artifacts),
        ]
    if profile == "vhd-profile-isolation":
        return [vhd_profile_launch_check(app_root, args)]
    if profile == "shared-cache-filesystem":
        return [shared_directories_rest_check(base_url, shared_dir)]
    if profile == "diagnostics-local-dumps":
        return [configure_local_dumps_check(args.root / "local-dumps"), manual_dump_check(base_url), crash_trigger_check(base_url)]
    if profile == "ui-shared-files-depth":
        return [resource_presence_check(app_root, min_lang=40), shared_directories_rest_check(base_url, shared_dir)]
    if profile in REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE:
        return [
            local_swarm_contract_check(profile, args.swarm_tier),
            local_swarm_payload_check(args.harness_root),
            local_swarm_plan_check(
                profile,
                args.swarm_tier,
                args.harness_root,
                args.root,
                app_root,
                artifacts,
                ed2k_server_exe=args.ed2k_server_exe,
                client2_app_exe=args.client2_app_exe,
                amule_daemon_exe=args.amule_daemon_exe,
                amule_control_exe=args.amule_control_exe,
                lan_bind_addr=args.lan_bind_addr,
                execution_mode=args.local_swarm_mode,
            ),
        ]
    raise RuntimeError(f"Unsupported profile: {profile}")


def local_swarm_contract_check(profile: str, swarm_tier: int) -> dict[str, Any]:
    """Records the shared local/VM swarm scenario contract for migrated campaigns."""

    spec = REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE[profile]
    return {
        "name": "local-swarm-contract",
        "status": "passed",
        "details": {
            "vmProfile": profile,
            "scenarioId": spec.scenario_id,
            "localProfile": spec.local_profile,
            "localSuites": list(spec.local_suites),
            "executionModes": list(EXECUTION_MODES),
            "clientProducts": list(LOCAL_SWARM_CLIENT_PRODUCTS),
            "swarmTiers": list(LOCAL_SWARM_TIERS),
            "defaultSwarmTier": DEFAULT_LOCAL_SWARM_TIER,
            "selectedSwarmTier": swarm_tier,
            "selectedSwarmTierOptions": dict(LOCAL_SWARM_TIER_OPTIONS[swarm_tier]),
            "ed2kServerTarget": "win10",
            "vmTargets": ["win10", "win11"],
            "nonblockingCompanions": True,
        },
    }


def local_swarm_payload_check(harness_root: Path | None) -> dict[str, Any]:
    """Verifies that VM mode staged the local swarm harness payload."""

    if harness_root is None:
        return {"name": "local-swarm-payload-staged", "status": "failed", "details": {"error": "missing harness root"}}
    expected = (
        harness_root / "emule_test_harness" / "live_e2e_suite.py",
        *(harness_root / "scripts" / name for name in LOCAL_SWARM_PAYLOAD_SCRIPT_FILES),
    )
    missing = [str(path) for path in expected if not path.is_file()]
    return {
        "name": "local-swarm-payload-staged",
        "status": "passed" if not missing else "failed",
        "details": {
            "harnessRoot": str(harness_root),
            "expectedCount": len(expected),
            "missing": missing,
        },
    }


class _LocalSwarmHarnessCliCommon:
    """Minimal live-suite adapter used to run or resolve staged VM child commands."""

    def __init__(self, root: Path, app_root: Path, artifacts: Path, execution_mode: str) -> None:
        self.root = root
        self.app_root = app_root
        self.artifacts = artifacts
        self.execution_mode = execution_mode

    def prepare_run_paths(self, **kwargs):
        source_artifacts_dir = Path(kwargs["artifacts_dir"]).resolve()
        source_artifacts_dir.mkdir(parents=True, exist_ok=True)
        app_exe = Path(kwargs["app_exe"]).resolve() if kwargs.get("app_exe") else self.app_root / "emulebb.exe"
        return SimpleNamespace(
            repo_root=self.root,
            workspace_root=Path(kwargs["workspace_root"]).resolve(),
            app_root=Path(kwargs["app_root"]).resolve() if kwargs.get("app_root") else self.app_root,
            app_exe=app_exe,
            seed_config_dir=None,
            configuration=kwargs["configuration"],
            suite_name=kwargs["suite_name"],
            source_artifacts_dir=source_artifacts_dir,
            run_report_dir=self.artifacts / f"local-swarm-{self.execution_mode}-run",
            latest_report_dir=self.artifacts / f"local-swarm-{self.execution_mode}-latest",
            keep_source_artifacts=True,
            local_dumps={"dump_folder": str(source_artifacts_dir / "crash-dumps"), "image_names": ["emulebb.exe"]},
        )

    def find_python_executable(self) -> str:
        return sys.executable

    def write_json_file(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def publish_run_artifacts(self, paths: Any) -> None:
        paths.run_report_dir.mkdir(parents=True, exist_ok=True)

    def publish_latest_report(self, paths: Any) -> None:
        paths.latest_report_dir.mkdir(parents=True, exist_ok=True)

    def cleanup_source_artifacts(self, _paths: Any) -> None:
        return None

    def collect_local_dump_files(self, _local_dumps: Any) -> dict[str, Any]:
        return {"count": 0, "files": []}


def local_swarm_plan_check(
    profile: str,
    swarm_tier: int,
    harness_root: Path | None,
    root: Path,
    app_root: Path,
    artifacts: Path,
    ed2k_server_exe: Path | None = None,
    client2_app_exe: Path | None = None,
    amule_daemon_exe: Path | None = None,
    amule_control_exe: Path | None = None,
    lan_bind_addr: str = "127.0.0.1",
    execution_mode: str = "plan",
) -> dict[str, Any]:
    """Resolves or executes the staged local-swarm suite commands."""

    if execution_mode not in {"plan", "execute"}:
        return {"name": "local-swarm-plan", "status": "failed", "details": {"error": f"unsupported mode: {execution_mode}"}}
    check_name = "local-swarm-plan" if execution_mode == "plan" else "local-swarm-execute"
    if harness_root is None:
        return {"name": check_name, "status": "failed", "details": {"error": "missing harness root"}}
    if not (harness_root / "emule_test_harness" / "live_e2e_suite.py").is_file():
        return {
            "name": check_name,
            "status": "failed",
            "details": {"harnessRoot": str(harness_root), "error": "missing staged live_e2e_suite.py"},
        }
    try:
        if str(harness_root) not in sys.path:
            sys.path.insert(0, str(harness_root))
        from emule_test_harness import live_e2e_suite

        spec = REUSABLE_CAMPAIGN_SCENARIO_BY_VM_PROFILE[profile]
        suites = list(spec.local_suites)
        if spec.uses_local_swarm and "godzilla-local-swarm" not in suites:
            suites.append("godzilla-local-swarm")
        tier_options = LOCAL_SWARM_TIER_OPTIONS[swarm_tier]
        test_network = str(getattr(spec, "local_test_network", "default"))
        plan_artifacts = artifacts / "local-swarm-plan"
        argv = [
            "--workspace-root",
            str((root / "workspace").resolve()),
            "--app-root",
            str(app_root.resolve()),
            "--app-exe",
            str((app_root / "emulebb.exe").resolve()),
            "--artifacts-dir",
            str(plan_artifacts.resolve()),
            "--profile",
            str(spec.local_profile),
            "--test-network",
            test_network,
            "--admin-volume-fixtures",
            "--godzilla-stage",
            str(tier_options["stage"]),
            "--godzilla-total-client-count",
            str(tier_options["total_client_count"]),
            "--godzilla-peer-transfer-count",
            str(tier_options["peer_transfer_count"]),
            "--godzilla-harness-transfer-count",
            str(tier_options["harness_transfer_count"]),
            "--godzilla-emulebb-files",
            str(tier_options["emulebb_files"]),
            "--godzilla-extra-emulebb-files",
            str(tier_options["extra_emulebb_files"]),
            "--godzilla-harness-files",
            str(tier_options["harness_files"]),
            "--godzilla-amule-files",
            str(tier_options["amule_files"]),
            "--godzilla-adverse-kill-cycles",
            str(tier_options["adverse_kill_cycles"]),
            "--godzilla-adverse-kill-warmup-seconds",
            str(tier_options["adverse_kill_warmup_seconds"]),
            "--godzilla-adverse-recovery-timeout-seconds",
            str(tier_options["adverse_recovery_timeout_seconds"]),
        ]
        if execution_mode == "plan":
            argv.append("--plan-only")
        if bool(tier_options["cpu_profile"]):
            argv.append("--godzilla-cpu-profile")
        if bool(tier_options["fail_fast"]):
            argv.append("--fail-fast")
        if ed2k_server_exe is not None:
            argv.extend(["--ed2k-server-exe", str(ed2k_server_exe.resolve())])
        if client2_app_exe is not None:
            argv.extend(["--client2-app-exe", str(client2_app_exe.resolve())])
        if amule_daemon_exe is not None:
            argv.extend(["--amule-daemon-exe", str(amule_daemon_exe.resolve())])
        if amule_control_exe is not None:
            argv.extend(["--amule-control-exe", str(amule_control_exe.resolve())])
        for suite in suites:
            argv.extend(["--suite", suite])
        args = live_e2e_suite.build_parser().parse_args(argv)
        previous_x_local_ip = os.environ.get("X_LOCAL_IP")
        previous_lan_ip = os.environ.get("EMULEBB_TEST_LAN_IP_RESOLVED")
        if lan_bind_addr:
            os.environ["X_LOCAL_IP"] = lan_bind_addr
            os.environ.setdefault("EMULEBB_TEST_LAN_IP_RESOLVED", lan_bind_addr)
        try:
            if execution_mode == "execute":
                stop_runtime()
            summary = live_e2e_suite.run_live_e2e_suite(
                args,
                _LocalSwarmHarnessCliCommon(root, app_root, artifacts, execution_mode),
            )
        finally:
            if previous_x_local_ip is None:
                os.environ.pop("X_LOCAL_IP", None)
            else:
                os.environ["X_LOCAL_IP"] = previous_x_local_ip
            if previous_lan_ip is None:
                os.environ.pop("EMULEBB_TEST_LAN_IP_RESOLVED", None)
            else:
                os.environ["EMULEBB_TEST_LAN_IP_RESOLVED"] = previous_lan_ip
        planned_suites = summary.get("suites") if isinstance(summary, dict) else None
        planned_suite_rows = planned_suites if isinstance(planned_suites, list) else []
        commands = [
            row.get("command")
            for row in planned_suite_rows
            if isinstance(row, dict) and isinstance(row.get("command"), list)
        ]
        suite_names = [str(row.get("name")) for row in planned_suite_rows if isinstance(row, dict)]
        expected_suites = set(suites)
        expected_summary_status = "planned" if execution_mode == "plan" else "passed"
        expected_suite_status = "planned" if execution_mode == "plan" else "passed"
        status = (
            "passed"
            if summary.get("status") == expected_summary_status
            and expected_suites.issubset(set(suite_names))
            and all(row.get("status") == expected_suite_status for row in planned_suite_rows if isinstance(row, dict))
            else "failed"
        )
        return {
            "name": check_name,
            "status": status,
            "details": {
                "harnessRoot": str(harness_root),
                "executionMode": execution_mode,
                "vmProfile": profile,
                "scenarioId": spec.scenario_id,
                "testNetwork": test_network,
                "swarmTier": swarm_tier,
                "summaryStatus": summary.get("status"),
                "suiteNames": suite_names,
                "commands": commands,
                "tierOptions": dict(tier_options),
                "lanBindAddr": lan_bind_addr,
                "ed2kServerExe": str(ed2k_server_exe) if ed2k_server_exe is not None else "",
                "client2AppExe": str(client2_app_exe) if client2_app_exe is not None else "",
                "amuleDaemonExe": str(amule_daemon_exe) if amule_daemon_exe is not None else "",
                "amuleControlExe": str(amule_control_exe) if amule_control_exe is not None else "",
            },
        }
    except Exception as exc:
        return {
            "name": check_name,
            "status": "failed",
            "details": {"harnessRoot": str(harness_root), "error": f"{type(exc).__name__}: {exc}"},
        }


def powershell_script_parse_check(app_root: Path) -> dict[str, Any]:
    scripts = sorted((app_root / "scripts").glob("*.ps1"))
    failures: list[dict[str, str]] = []
    for script in scripts:
        command = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "& { param($path) $e=$null;$t=$null;"
            "[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$t,[ref]$e)|Out-Null;"
            "if($e.Count){$e|ForEach-Object{$_.Message}; exit 1} }",
            str(script),
        ]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if completed.returncode != 0:
            failures.append({"script": script.name, "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip()})
    return {
        "name": "package-helper-powershell-parse",
        "status": "passed" if scripts and not failures else "failed",
        "details": {"scriptCount": len(scripts), "failures": failures},
    }


def install_suite_dry_run_check(app_root: Path, artifacts: Path) -> dict[str, Any]:
    result_path = artifacts / "install-suite-dry-run.txt"
    install_root = artifacts.parent / "suite-install"
    script = app_root / "scripts" / "Install-eMuleBBSuite.ps1"
    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
        "-Bundle",
        "Core",
        "-InstallRoot",
        str(install_root),
        "-InstallKind",
        "Test",
        "-NonInteractive",
        "-DryRun",
        "-Force",
        "-NoStart",
    ]
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False, timeout=120.0)
    result_path.write_text(completed.stdout, encoding="utf-8", errors="replace")
    return {
        "name": "install-suite-dry-run",
        "status": "passed" if completed.returncode == 0 else "failed",
        "details": {"exitCode": completed.returncode, "stdoutPath": str(result_path)},
    }


def firewall_repair_check(app_root: Path, artifacts: Path) -> dict[str, Any]:
    result_path = artifacts / "firewall-repair-result.json"
    script = app_root / "scripts" / "Repair-Firewall.ps1"
    exe = app_root / "emulebb.exe"
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-ProgramPath",
            str(exe),
            "-ResultPath",
            str(result_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout=90.0,
    )
    payload = json.loads(result_path.read_text(encoding="utf-8-sig")) if result_path.is_file() else {}
    return {
        "name": "firewall-repair-helper",
        "status": "passed" if completed.returncode == 0 and payload.get("ok") is True else "failed",
        "details": {"exitCode": completed.returncode, "resultPath": str(result_path), "ruleCount": len(payload.get("rules", [])) if isinstance(payload, dict) else 0},
    }


def vhd_profile_launch_check(app_root: Path, args: argparse.Namespace) -> dict[str, Any]:
    stop_runtime()
    vhd_root = args.root / "vhd-profile"
    vhd_path = args.root / "profile-isolation.vhd"
    drive_letter = "V"
    script_path = args.root / "mount-vhd-profile.diskpart"
    script_path.write_text(
        "\n".join(
            [
                f'create vdisk file="{vhd_path}" maximum=128 type=expandable',
                f'select vdisk file="{vhd_path}"',
                "attach vdisk",
                "create partition primary",
                "format fs=ntfs quick label=EMULEBBVHD",
                f"assign letter={drive_letter}",
                "exit",
                "",
            ]
        ),
        encoding="ascii",
    )
    completed = subprocess.run(["diskpart.exe", "/s", str(script_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False, timeout=120.0)
    if completed.returncode != 0:
        return {"name": "vhd-profile-launch", "status": "failed", "details": {"phase": "diskpart", "output": completed.stdout}}
    mounted_root = Path(f"{drive_letter}:") / "emulebb-profile"
    config_dir = mounted_root / "config"
    incoming_dir = mounted_root / "incoming"
    temp_dir = mounted_root / "temp"
    shared_dir = mounted_root / "shared"
    for directory in (config_dir, incoming_dir, temp_dir, shared_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (shared_dir / "vhd-profile-sample.txt").write_text("vhd profile fixture\n", encoding="utf-8")
    write_preferences_ini(
        config_dir,
        offline_preferences_text(
            target=f"{args.target}-vhd",
            incoming_dir=incoming_dir,
            temp_dir=temp_dir,
            shared_dir=shared_dir,
            enable_diagnostics=False,
        ),
    )
    start_visible_app(
        app_root / "emulebb.exe",
        mounted_root,
        task_name=f"eMuleBB VM vhd-profile {args.target}",
        username=args.username,
        password=args.password,
    )
    try:
        wait_rest(f"http://127.0.0.1:{REST_PORT}")
        status = "passed"
    except Exception as exc:
        status = "failed"
        error = f"{type(exc).__name__}: {exc}"
    else:
        error = ""
    finally:
        stop_runtime()
        subprocess.run(["diskpart.exe", "/s", str(write_detach_vhd_script(args.root, vhd_path))], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return {
        "name": "vhd-profile-launch",
        "status": status,
        "details": {"vhdPath": str(vhd_path), "profileRoot": str(mounted_root), "error": error},
    }


def write_detach_vhd_script(root: Path, vhd_path: Path) -> Path:
    script_path = root / "detach-vhd-profile.diskpart"
    script_path.write_text(f'select vdisk file="{vhd_path}"\ndetach vdisk\nexit\n', encoding="ascii")
    return script_path


def shared_directories_rest_check(base_url: str, shared_dir: Path) -> dict[str, Any]:
    flat_dir = shared_dir / "flat-rest"
    recursive_dir = shared_dir / "recursive-rest"
    flat_dir.mkdir(parents=True, exist_ok=True)
    recursive_dir.joinpath("nested").mkdir(parents=True, exist_ok=True)
    (flat_dir / "flat.txt").write_text("flat shared directory\n", encoding="utf-8")
    (recursive_dir / "nested" / "recursive.txt").write_text("recursive shared directory\n", encoding="utf-8")
    payload = {
        "confirmReplaceRoots": True,
        "roots": [
            str(flat_dir) + "\\",
            {"path": str(recursive_dir) + "\\", "recursive": True},
        ],
    }
    try:
        patched = retry_http_json(
            "patch shared-directories",
            8,
            base_url,
            "/api/v1/shared-directories",
            api_key=API_KEY,
            method="PATCH",
            body=payload,
            timeout_seconds=20.0,
        )
        retry_http_json("reload shared-directories", 8, base_url, "/api/v1/shared-directories/operations/reload", api_key=API_KEY, method="POST", body={}, timeout_seconds=20.0)
        files = retry_http_json("shared-files after patch", 12, base_url, "/api/v1/shared-files", api_key=API_KEY, timeout_seconds=20.0)
        return {"name": "shared-directories-rest-cache", "status": "passed", "details": {"patched": compact(patched), "files": compact(files)}}
    except Exception as exc:
        return {"name": "shared-directories-rest-cache", "status": "failed", "details": {"error": f"{type(exc).__name__}: {exc}"}}


def configure_local_dumps_check(dump_dir: Path) -> dict[str, Any]:
    dump_dir.mkdir(parents=True, exist_ok=True)
    command = [
        "reg.exe",
        "add",
        r"HKCU\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\emulebb.exe",
        "/v",
        "DumpFolder",
        "/t",
        "REG_EXPAND_SZ",
        "/d",
        str(dump_dir),
        "/f",
    ]
    first = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    second = subprocess.run(
        [
            "reg.exe",
            "add",
            r"HKCU\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\emulebb.exe",
            "/v",
            "DumpType",
            "/t",
            "REG_DWORD",
            "/d",
            "2",
            "/f",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return {
        "name": "configure-wer-local-dumps",
        "status": "passed" if first.returncode == 0 and second.returncode == 0 else "failed",
        "details": {"dumpDir": str(dump_dir), "exitCodes": [first.returncode, second.returncode]},
    }


def call_check(name: str, base_url: str, path: str) -> dict[str, Any]:
    try:
        payload = retry_http_json(name, 8, base_url, path, api_key=API_KEY, timeout_seconds=15.0)
        return {"name": name, "status": "passed", "details": compact(payload)}
    except Exception as exc:
        return {"name": name, "status": "failed", "details": {"error": f"{type(exc).__name__}: {exc}"}}


def rest_loop_check(base_url: str, *, loops: int) -> dict[str, Any]:
    started = time.monotonic()
    failures: list[str] = []
    for index in range(loops):
        path = "/api/v1/status" if index % 2 == 0 else "/api/v1/transfers"
        try:
            retry_http_json(f"rest-loop-{index}", 5, base_url, path, api_key=API_KEY, timeout_seconds=10.0)
        except Exception as exc:
            failures.append(f"{index}:{type(exc).__name__}:{exc}")
            if len(failures) >= 5:
                break
        time.sleep(0.05)
    return {
        "name": "rest-loop-stress",
        "status": "passed" if not failures else "failed",
        "details": {"loops": loops, "failures": failures, "elapsedSeconds": round(time.monotonic() - started, 3)},
    }


def manual_dump_check(base_url: str) -> dict[str, Any]:
    try:
        payload = http_json(
            base_url,
            "/api/v1/diagnostics/dumps",
            api_key=API_KEY,
            method="POST",
            body={"confirmDump": True, "fullMemory": False},
            timeout_seconds=60.0,
        )
        data = payload.get("data") if isinstance(payload, dict) else None
        dump_path = Path(str(data.get("path") or "")) if isinstance(data, dict) else Path("")
        ok = dump_path.is_file() and dump_path.stat().st_size > 0
        return {
            "name": "manual-diagnostic-dump",
            "status": "passed" if ok else "failed",
            "details": {"response": compact(payload), "dumpPath": str(dump_path), "sizeBytes": dump_path.stat().st_size if dump_path.is_file() else 0},
        }
    except Exception as exc:
        return {"name": "manual-diagnostic-dump", "status": "failed", "details": {"error": f"{type(exc).__name__}: {exc}"}}


def crash_trigger_check(base_url: str) -> dict[str, Any]:
    try:
        http_json(
            base_url,
            "/api/v1/diagnostics/crash-tests",
            api_key=API_KEY,
            method="POST",
            body={"confirmCrash": True},
            timeout_seconds=20.0,
        )
        request_result: dict[str, Any] = {"requestCompleted": True}
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        request_result = {"requestCompleted": False, "expectedDisconnect": True, "error": f"{type(exc).__name__}: {exc}"}
    exited = wait_for_process_exit(timeout_seconds=90.0)
    return {
        "name": "crash-trigger",
        "status": "passed" if exited else "failed",
        "details": {**request_result, "processExited": exited},
    }


def shared_fixture_scan_check(shared_dir: Path) -> dict[str, Any]:
    files = list(shared_dir.glob("*.bin"))
    total = sum(path.stat().st_size for path in files)
    return {
        "name": "shared-fixture-scan",
        "status": "passed" if len(files) >= 32 and total > 0 else "failed",
        "details": {"fileCount": len(files), "totalBytes": total},
    }


def resource_presence_check(app_root: Path, *, min_lang: int) -> dict[str, Any]:
    lang_files = sorted((app_root / "lang").glob("*.dll"))
    docs = ["REST-API-CONTRACT.md", "REST-API-OPENAPI.yaml", "REST-API-PARITY-INVENTORY.md"]
    missing_docs = [name for name in docs if not (app_root / "docs" / name).is_file()]
    return {
        "name": "release-resource-presence",
        "status": "passed" if len(lang_files) >= min_lang and not missing_docs else "failed",
        "details": {"languageDllCount": len(lang_files), "minLanguageDllCount": min_lang, "missingDocs": missing_docs},
    }


def collect_dumps(config_dir: Path, name: str) -> dict[str, Any]:
    dumps = [
        {"path": str(path), "sizeBytes": path.stat().st_size}
        for path in sorted(config_dir.rglob("*.dmp"))
        if path.stat().st_size > 0
    ]
    return {"name": name, "status": "passed" if dumps else "failed", "details": {"dumpCount": len(dumps), "dumps": dumps}}


def collect_local_dumps(dump_dir: Path) -> dict[str, Any]:
    dumps = [
        {"path": str(path), "sizeBytes": path.stat().st_size}
        for path in sorted(dump_dir.glob("*.dmp"))
        if path.stat().st_size > 0
    ]
    return {
        "name": "wer-local-dumps-collected",
        "status": "passed",
        "details": {
            "dumpDir": str(dump_dir),
            "dumpCount": len(dumps),
            "dumps": dumps,
            "required": False,
            "reason": "WER LocalDumps can remain empty when the app crash handler writes its own dump first.",
        },
    }


def collect_application_events(artifacts: Path) -> dict[str, Any]:
    output = artifacts / "application-events.json"
    command = [
        "powershell.exe",
        "-NoProfile",
        "-Command",
        "Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddHours(-2) } -MaxEvents 50 | "
        "Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message | ConvertTo-Json -Depth 4",
    ]
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    output.write_text(completed.stdout if completed.stdout.strip() else "[]", encoding="utf-8")
    return {
        "name": "application-events-collected",
        "status": "passed",
        "details": {"path": str(output), "exitCode": completed.returncode},
    }


def stop_runtime() -> None:
    subprocess.run(["taskkill.exe", "/IM", "emulebb.exe", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    wait_for_process_exit(timeout_seconds=30.0)


def wait_for_process_exit(*, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not is_process_running():
            return True
        time.sleep(1.0)
    return not is_process_running()


def is_process_running() -> bool:
    completed = subprocess.run(
        ["tasklist.exe", "/FI", "IMAGENAME eq emulebb.exe"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return "emulebb.exe" in completed.stdout.lower()


def compact(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {key: compact(value) for key, value in list(payload.items())[:20]}
    if isinstance(payload, list):
        return [compact(item) for item in payload[:5]]
    return payload


def guest_info() -> dict[str, str]:
    return {"computerName": subprocess.getoutput("hostname").strip()}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


if __name__ == "__main__":
    raise SystemExit(main())
