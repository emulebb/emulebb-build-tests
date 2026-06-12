"""Publishes Rust overnight pytest proof as release-campaign evidence."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.artifact_names import utc_run_id  # noqa: E402
from emule_test_harness.paths import get_required_emule_workspace_root, get_workspace_output_root  # noqa: E402

SUITE_NAME = "rust-overnight-pytest-proof"


@dataclass(frozen=True)
class PytestCase:
    """One pytest command promoted to Rust overnight evidence."""

    case_id: str
    title: str
    paths: tuple[str, ...]
    evidence: dict[str, bool]


PYTEST_CASES: tuple[PytestCase, ...] = (
    PytestCase(
        case_id="local-client",
        title="Rust local client harness surface",
        paths=("..\\emulebb-build-tests\\tests\\python\\test_emulebb_rust_local_client.py",),
        evidence={
            "localClientPytestPassed": True,
            "localClientUnicodeCoverageRequired": True,
            "localClientHashOnlyMetadataCoverageRequired": True,
            "localClientLanBindCoverageRequired": True,
        },
    ),
    PytestCase(
        case_id="rest-contract",
        title="Rust REST contract parity",
        paths=("..\\emulebb-build-tests\\tests\\python\\test_emulebb_rust_rest_contract.py",),
        evidence={
            "restContractPytestPassed": True,
            "restContractRouteParityRequired": True,
            "restContractOpenApiParityRequired": True,
        },
    ),
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses command-line options."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path)
    parser.add_argument("--case", choices=[case.case_id for case in PYTEST_CASES], action="append")
    return parser.parse_args(argv)


def selected_cases(case_ids: list[str] | None) -> tuple[PytestCase, ...]:
    """Returns the selected pytest proof cases."""

    if not case_ids:
        return PYTEST_CASES
    selected = set(case_ids)
    return tuple(case for case in PYTEST_CASES if case.case_id in selected)


def tail_lines(text: str, limit: int = 40) -> list[str]:
    """Returns the last lines of command output for diagnostics."""

    return text.splitlines()[-limit:]


def build_repo(workspace_root: Path) -> Path:
    """Returns the workspace build-orchestration checkout."""

    repo = workspace_root / "repos" / "emulebb-build"
    if not (repo / "emule_workspace").is_dir():
        raise RuntimeError(f"emulebb-build checkout was not found at {repo}.")
    return repo


def run_pytest_case(case: PytestCase, build_repo_path: Path) -> dict[str, Any]:
    """Runs one orchestrated pytest case and returns summary evidence."""

    command = [sys.executable, "-m", "emule_workspace", "test", "python"]
    for path in case.paths:
        command.extend(["--path", path])
    command.append("--quiet")
    result = subprocess.run(
        command,
        cwd=build_repo_path,
        text=True,
        capture_output=True,
        check=False,
    )
    return {
        "id": case.case_id,
        "title": case.title,
        "status": "passed" if result.returncode == 0 else "failed",
        "returnCode": result.returncode,
        "command": command,
        "paths": list(case.paths),
        "evidence": {**case.evidence, "pytestPassed": result.returncode == 0},
        "stdoutTail": tail_lines(result.stdout),
        "stderrTail": tail_lines(result.stderr),
    }


def build_requirement_checks(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregates required Rust overnight pytest proof surfaces."""

    evidence_by_id = {
        str(case.get("id")): case.get("evidence")
        for case in cases
        if isinstance(case.get("evidence"), dict)
    }
    passed_ids = {str(case.get("id")) for case in cases if case.get("status") == "passed"}
    return {
        "caseCount": len(cases),
        "allCasesPassed": len(passed_ids) == len(cases),
        "localClientPytestPassed": bool(
            evidence_by_id.get("local-client", {}).get("localClientPytestPassed")
            and evidence_by_id.get("local-client", {}).get("localClientUnicodeCoverageRequired")
            and evidence_by_id.get("local-client", {}).get("localClientHashOnlyMetadataCoverageRequired")
            and evidence_by_id.get("local-client", {}).get("localClientLanBindCoverageRequired")
            and "local-client" in passed_ids
        ),
        "restContractPytestPassed": bool(
            evidence_by_id.get("rest-contract", {}).get("restContractPytestPassed")
            and evidence_by_id.get("rest-contract", {}).get("restContractRouteParityRequired")
            and evidence_by_id.get("rest-contract", {}).get("restContractOpenApiParityRequired")
            and "rest-contract" in passed_ids
        ),
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Writes one stable JSON artifact."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def publish_latest(run_dir: Path, latest_dir: Path) -> None:
    """Refreshes the lightweight latest evidence directory for this suite."""

    if latest_dir.exists():
        shutil.rmtree(latest_dir)
    shutil.copytree(run_dir, latest_dir)


def main(argv: list[str] | None = None) -> int:
    """Runs Rust overnight pytest proof cases and publishes campaign evidence."""

    args = parse_args(argv)
    workspace_root = get_required_emule_workspace_root()
    output_root = get_workspace_output_root()
    build_repo_path = build_repo(workspace_root)
    run_id = utc_run_id()
    run_dir = args.artifacts_dir.resolve() if args.artifacts_dir else output_root / "reports" / SUITE_NAME / run_id
    latest_dir = output_root / "reports" / SUITE_NAME / "latest"
    cases_to_run = selected_cases(args.case)
    report: dict[str, Any] = {
        "suite": SUITE_NAME,
        "status": "running",
        "runId": run_id,
        "startedAtUtc": datetime.now(UTC).isoformat(),
        "buildRepo": str(build_repo_path),
        "cases": [],
        "checks": {},
    }
    try:
        for case in cases_to_run:
            report["cases"].append(run_pytest_case(case, build_repo_path))
        report["checks"]["rust_overnight_pytest_requirements"] = build_requirement_checks(report["cases"])
        report["status"] = (
            "passed" if report["checks"]["rust_overnight_pytest_requirements"]["allCasesPassed"] else "failed"
        )
        return 0 if report["status"] == "passed" else 1
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        return 1
    finally:
        report["finishedAtUtc"] = datetime.now(UTC).isoformat()
        write_json(run_dir / f"{SUITE_NAME}-result.json", report)
        publish_latest(run_dir, latest_dir)


if __name__ == "__main__":
    raise SystemExit(main())
