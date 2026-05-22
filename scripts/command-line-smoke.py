"""Runs release-gate command-line process smoke checks for eMuleBB."""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def load_local_module(module_name: str, filename: str):
    """Loads one sibling helper module from a hyphenated script filename."""

    module_path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load helper module from '{module_path}'.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


harness_cli_common = load_local_module("harness_cli_common", "harness-cli-common.py")

DEFAULT_PROCESS_TIMEOUT_SECONDS = 20.0
DEFAULT_CERT_TIMEOUT_SECONDS = 60.0


@dataclass(frozen=True)
class CommandLineCase:
    """One process-level command-line assertion."""

    name: str
    arguments: tuple[str, ...]
    expected_return_code: int
    stdout_contains: tuple[str, ...] = ()
    stderr_contains: tuple[str, ...] = ()
    timeout_seconds: float = DEFAULT_PROCESS_TIMEOUT_SECONDS


def compact_stream(text: str, limit: int = 4000) -> str:
    """Returns a bounded text stream for stable JSON diagnostics."""

    if len(text) <= limit:
        return text
    return text[:limit] + "\n... truncated ..."


def run_case(app_exe: Path, case: CommandLineCase) -> dict[str, object]:
    """Runs one eMule command-line case and returns a structured assertion row."""

    command = [str(app_exe), *case.arguments]
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=case.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "name": case.name,
            "status": "failed",
            "command": command,
            "return_code": None,
            "expected_return_code": case.expected_return_code,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": compact_stream(exc.stdout or ""),
            "stderr": compact_stream(exc.stderr or ""),
            "errors": [f"process timed out after {case.timeout_seconds} seconds"],
        }
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    errors: list[str] = []
    if completed.returncode != case.expected_return_code:
        errors.append(f"expected return code {case.expected_return_code}, got {completed.returncode}")
    for needle in case.stdout_contains:
        if needle not in stdout:
            errors.append(f"stdout did not contain {needle!r}")
    for needle in case.stderr_contains:
        if needle not in stderr:
            errors.append(f"stderr did not contain {needle!r}")
    return {
        "name": case.name,
        "status": "passed" if not errors else "failed",
        "command": command,
        "return_code": completed.returncode,
        "expected_return_code": case.expected_return_code,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": compact_stream(stdout),
        "stderr": compact_stream(stderr),
        "errors": errors,
    }


def build_headless_cases(artifacts_dir: Path) -> tuple[CommandLineCase, ...]:
    """Builds deterministic no-profile command-line cases."""

    return (
        CommandLineCase(
            name="help",
            arguments=("--help",),
            expected_return_code=0,
            stdout_contains=("Usage:", "--generate-webserver-cert"),
        ),
        CommandLineCase(
            name="unknown-switch",
            arguments=("--not-a-real-emulebb-switch",),
            expected_return_code=2,
            stderr_contains=("Unknown command-line switch", "--not-a-real-emulebb-switch"),
        ),
        CommandLineCase(
            name="relative-profile-rejected",
            arguments=("-c", "relative\\profile"),
            expected_return_code=2,
            stderr_contains=("The -c option requires a canonical absolute eMule base directory",),
        ),
        CommandLineCase(
            name="partial-cert-generation-rejected",
            arguments=(
                "--generate-webserver-cert",
                "--cert",
                str(artifacts_dir / "partial-cert" / "webserver.crt"),
            ),
            expected_return_code=2,
            stderr_contains=("--generate-webserver-cert command requires --cert and --key",),
        ),
    )


def run_certificate_generation_case(app_exe: Path, artifacts_dir: Path) -> dict[str, object]:
    """Runs the headless WebServer certificate-generation command."""

    cert_dir = artifacts_dir / "generated-cert"
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "webserver.crt"
    key_path = cert_dir / "webserver.key"
    case = CommandLineCase(
        name="generate-webserver-cert",
        arguments=(
            "--generate-webserver-cert",
            "--cert",
            str(cert_path),
            "--key",
            str(key_path),
            "--host",
            "localhost",
            "--host",
            "127.0.0.1",
            "--host",
            "2001:db8::1",
        ),
        expected_return_code=0,
        timeout_seconds=DEFAULT_CERT_TIMEOUT_SECONDS,
    )
    result = run_case(app_exe, case)
    artifacts = {
        "cert_path": str(cert_path),
        "key_path": str(key_path),
        "cert_exists": cert_path.is_file(),
        "key_exists": key_path.is_file(),
        "cert_size_bytes": cert_path.stat().st_size if cert_path.is_file() else 0,
        "key_size_bytes": key_path.stat().st_size if key_path.is_file() else 0,
    }
    result["artifacts"] = artifacts
    errors = list(result["errors"]) if isinstance(result.get("errors"), list) else []
    if not artifacts["cert_exists"] or artifacts["cert_size_bytes"] <= 0:
        errors.append("certificate output file was not created")
    if not artifacts["key_exists"] or artifacts["key_size_bytes"] <= 0:
        errors.append("private-key output file was not created")
    result["errors"] = errors
    result["status"] = "passed" if not errors else "failed"
    return result


def build_parser() -> argparse.ArgumentParser:
    """Builds the command-line smoke argument parser."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root")
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    return parser


def run_command_line_smoke(args: argparse.Namespace) -> dict[str, object]:
    """Runs process-level command-line smoke checks and publishes artifacts."""

    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name="command-line-smoke",
        configuration=args.configuration,
        workspace_root=args.workspace_root,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    checks: list[dict[str, object]] = []
    status = "passed"
    try:
        for case in build_headless_cases(paths.source_artifacts_dir):
            checks.append(run_case(paths.app_exe, case))
        checks.append(run_certificate_generation_case(paths.app_exe, paths.source_artifacts_dir))
        if any(check.get("status") != "passed" for check in checks):
            status = "failed"
        summary = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "status": status,
            "configuration": paths.configuration,
            "app_exe": str(paths.app_exe),
            "artifact_dir": str(paths.run_report_dir),
            "latest_report_dir": str(paths.latest_report_dir),
            "source_artifact_dir": str(paths.source_artifacts_dir),
            "local_dumps": paths.local_dumps,
            "strict_success_required": True,
            "checks": checks,
        }
        summary["local_dump_files"] = harness_cli_common.collect_local_dump_files(paths.local_dumps)
        harness_cli_common.write_json_file(paths.source_artifacts_dir / "result.json", summary)
        return summary
    finally:
        harness_cli_common.publish_run_artifacts(paths)
        harness_cli_common.publish_latest_report(paths)
        harness_cli_common.cleanup_source_artifacts(paths)


def main() -> int:
    """Runs the command-line smoke suite and returns a process exit code."""

    summary = run_command_line_smoke(build_parser().parse_args())
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
