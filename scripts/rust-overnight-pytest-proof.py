"""Record overnight pytest results without promoting missing native proof.

The default selection is non-native. Select --case native-bind explicitly for
the staged-daemon REST scenario; no case stages/builds that daemon. Comprehensive
overnight local-client evidence remains incomplete until native search/download,
observed socket binding and source provenance have their required proof.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
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
    native: bool = False


PYTEST_CASES: tuple[PytestCase, ...] = (
    PytestCase(
        case_id="local-client",
        title="Rust local client harness surface",
        paths=("..\\emulebb-build-tests\\tests\\python\\test_emulebb_rust_local_client.py",),
        evidence={
            "localClientUnitPytestPassed": True,
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
    PytestCase(
        case_id="native-bind",
        title="Native REST server operations with configured P2P bind",
        paths=("..\\emulebb-build-tests\\tests\\python\\test_emulebb_rust_local_client.py"
               "::test_emulebb_rust_server_connect_uses_configured_p2p_bind",),
        evidence={"localClientLanBindScenarioPassed": True},
        native=True,
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
        return tuple(case for case in PYTEST_CASES if not case.native)
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


def run_pytest_case(case: PytestCase, build_repo_path: Path, artifacts_dir: Path) -> dict[str, Any]:
    """Runs one orchestrated pytest case and returns summary evidence."""

    command = [sys.executable, "-m", "emule_workspace", "test", "python"]
    for path in case.paths:
        command.extend(["--path", path])
    command.append("--quiet")
    junit_path = artifacts_dir / "native-bind.xml"
    if case.native:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        # WHY: exit zero also permits skipped native cases. Require the exact
        # scenario to execute before publishing any runtime scenario evidence.
        junit_path.unlink(missing_ok=True)
        command.extend(["-m", "native", "--junitxml", str(junit_path)])
    result = subprocess.run(
        command,
        cwd=build_repo_path,
        text=True,
        capture_output=True,
        check=False,
    )
    passed = result.returncode == 0
    if case.native:
        try:
            nodes = ET.parse(junit_path).getroot().findall(".//testcase")
            passed = passed and len(nodes) == 1 and (
                nodes[0].get("name") == case.paths[0].split("::")[-1]
                and not any(nodes[0].find(tag) is not None for tag in ("skipped", "failure", "error"))
            )
        except (OSError, ET.ParseError):
            passed = False
    return {
        "id": case.case_id,
        "title": case.title,
        "status": "passed" if passed else "failed",
        "returnCode": result.returncode,
        "command": command,
        "paths": list(case.paths),
        "evidence": {key: value and passed for key, value in case.evidence.items()} | {"pytestPassed": passed},
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
        "localClientUnitPytestPassed": bool(
            evidence_by_id.get("local-client", {}).get("localClientUnitPytestPassed")
            and "local-client" in passed_ids
        ),
        "localClientLanBindScenarioPassed": bool(
            evidence_by_id.get("native-bind", {}).get("localClientLanBindScenarioPassed")
            and "native-bind" in passed_ids
        ),
        # The default unit selection excludes native search/download and bind
        # cases. Neither it nor the bind REST scenario proves the former full
        # Unicode/hash-only/observed-LAN-bind overnight claim.
        "localClientPytestPassed": False,
        "nativeSearchDownloadEvidence": "not-run",
        "stagedSourceProvenance": "unverified",
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
        "missingEvidence": [
            "Native search/download Unicode and hash-only metadata proof is not run by this wrapper.",
            "Configured-bind REST operations do not establish observed socket source IP.",
            "Staged executable/source provenance is unverified.",
        ],
    }
    try:
        for case in cases_to_run:
            report["cases"].append(run_pytest_case(case, build_repo_path, run_dir / case.case_id))
        report["checks"]["rust_overnight_pytest_requirements"] = build_requirement_checks(report["cases"])
        report["status"] = (
            "evidence-incomplete"
            if report["checks"]["rust_overnight_pytest_requirements"]["allCasesPassed"] else "failed"
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
