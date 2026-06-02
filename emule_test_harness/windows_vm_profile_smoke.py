"""Guest-side package profile smokes for Windows VM Hyper-V runs."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
import urllib.error
import zipfile
from pathlib import Path
from typing import Any

try:
    from emule_test_harness.vm_guest_profiles import (
        emit,
        http_json,
        retry_http_json,
        start_visible_app,
        wait_until,
        write_preferences_ini,
    )
except ModuleNotFoundError:
    from vm_guest_profiles import emit, http_json, retry_http_json, start_visible_app, wait_until, write_preferences_ini

SUPPORTED_PROFILES = {
    "rest-smoke-stress",
    "crash-dump-smoke",
    "cpu-heavy-quick",
    "resource-ui-smoke",
    "release-expanded-ui",
}
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
                enable_diagnostics=args.profile == "crash-dump-smoke",
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
        checks.extend(run_profile_checks(args.profile, base_url, profile_dir, app_root, shared_dir))
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        if app_started and args.profile != "crash-dump-smoke":
            stop_runtime()

    checks.append(collect_application_events(artifacts))
    if args.profile == "crash-dump-smoke":
        checks.append(collect_dumps(config_dir, "post-crash-profile-dumps"))
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


def run_profile_checks(profile: str, base_url: str, profile_dir: Path, app_root: Path, shared_dir: Path) -> list[dict[str, Any]]:
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
    raise RuntimeError(f"Unsupported profile: {profile}")


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
