"""Helpers for parsing and comparing doctest XML result files."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from xml.etree import ElementTree

STRICT_PARITY_SUITE_NAMES = frozenset({"parity", "protocol-parity"})


@dataclass(frozen=True)
class DoctestCaseResult:
    """One parsed doctest test-case result."""

    workspace: str
    suite: str
    name: str
    success: bool
    failures: int
    skipped: bool


@dataclass(frozen=True)
class SuiteComparisonSummary:
    """Suite-level pass/warn/fail counters for one test-run-vs-baseline comparison."""

    suite_name: str
    total_cases: int
    pass_count: int = 0
    warn_count: int = 0
    fail_count: int = 0
    case_set_mismatch_count: int = 0

    def to_dict(self) -> dict[str, int | str]:
        """Returns a JSON-serializable representation."""

        return asdict(self)


@dataclass(frozen=True)
class SuiteComparisonResult:
    """Result of comparing one suite across test-run and baseline result sets."""

    has_failure: bool
    summary: SuiteComparisonSummary
    lines: tuple[str, ...]


def _parse_int(value: str | None, default: int = 0) -> int:
    """Parses one XML integer attribute using a safe default."""

    if value is None or value == "":
        return default
    return int(value)


def parse_doctest_xml(
    xml_path: Path,
    *,
    suite_name: str,
    workspace_id: str,
) -> dict[str, DoctestCaseResult]:
    """Parses doctest XML into case results for one suite name."""

    if not xml_path.is_file():
        raise RuntimeError(f"Structured test result not found: {xml_path}")

    root = ElementTree.parse(xml_path).getroot()
    results: dict[str, DoctestCaseResult] = {}
    for test_suite in root.findall("TestSuite"):
        parsed_suite_name = test_suite.get("name") or suite_name
        if parsed_suite_name != suite_name:
            continue
        for test_case in test_suite.findall("TestCase"):
            name = test_case.get("name") or ""
            if not name:
                continue
            overall = test_case.find("OverallResultsAsserts")
            success = overall is not None and overall.get("test_case_success") == "true"
            failures = _parse_int(overall.get("failures") if overall is not None else None)
            skipped = test_case.get("skipped") == "true"
            results[name] = DoctestCaseResult(
                workspace=workspace_id,
                suite=parsed_suite_name,
                name=name,
                success=success,
                failures=failures,
                skipped=skipped,
            )
    return results


def compare_case_sets(
    test_run_results: dict[str, DoctestCaseResult],
    baseline_results: dict[str, DoctestCaseResult],
    *,
    suite_name: str,
) -> SuiteComparisonResult:
    """Compares test-run and baseline result sets using the existing live-diff rules."""

    all_names = sorted(set(test_run_results) | set(baseline_results))
    pass_count = 0
    warn_count = 0
    fail_count = 0
    case_set_mismatch_count = 0
    has_failure = False
    lines: list[str] = []

    for name in all_names:
        test_run_case = test_run_results.get(name)
        baseline_case = baseline_results.get(name)
        if test_run_case is None or baseline_case is None:
            lines.append(f"[WARN] {suite_name}: case-set mismatch for '{name}'")
            warn_count += 1
            case_set_mismatch_count += 1
            continue

        if suite_name in STRICT_PARITY_SUITE_NAMES:
            if test_run_case.success and baseline_case.success:
                lines.append(f"[PASS] {suite_name}: {name}")
                pass_count += 1
            else:
                lines.append(
                    f"[FAIL] {suite_name}: {name} "
                    f"(test_run={test_run_case.success}, baseline={baseline_case.success})"
                )
                has_failure = True
                fail_count += 1
            continue

        if test_run_case.success and not baseline_case.success:
            lines.append(f"[PASS] divergence: {name} (test-run pass, baseline fail as expected)")
            pass_count += 1
        elif not test_run_case.success and not baseline_case.success:
            lines.append(f"[WARN] divergence: {name} (test-run and baseline both failed)")
            warn_count += 1
        elif not test_run_case.success and baseline_case.success:
            lines.append(f"[FAIL] divergence: {name} (test-run failed while baseline passed)")
            has_failure = True
            fail_count += 1
        elif baseline_case.success:
            lines.append(f"[WARN] divergence: {name} (baseline also passed)")
            warn_count += 1
        else:
            lines.append(
                f"[FAIL] divergence: {name} "
                f"(unexpected state test_run={test_run_case.success}, baseline={baseline_case.success})"
            )
            has_failure = True
            fail_count += 1

    return SuiteComparisonResult(
        has_failure=has_failure,
        summary=SuiteComparisonSummary(
            suite_name=suite_name,
            total_cases=len(all_names),
            pass_count=pass_count,
            warn_count=warn_count,
            fail_count=fail_count,
            case_set_mismatch_count=case_set_mismatch_count,
        ),
        lines=tuple(lines),
    )
