from __future__ import annotations

from pathlib import Path

from emule_test_harness.doctest_results import (
    DoctestCaseResult,
    compare_case_sets,
    parse_doctest_xml,
)


def write_xml(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def case(name: str, success: bool) -> DoctestCaseResult:
    return DoctestCaseResult(
        workspace="test",
        suite="parity",
        name=name,
        success=success,
        failures=0 if success else 1,
        skipped=False,
    )


def test_parse_doctest_xml_filters_suite_and_preserves_case_state(tmp_path: Path) -> None:
    xml_path = write_xml(
        tmp_path / "results.xml",
        """<doctest>
  <TestSuite name="parity">
    <TestCase name="passes"><OverallResultsAsserts test_case_success="true" failures="0" /></TestCase>
    <TestCase name="fails"><OverallResultsAsserts test_case_success="false" failures="2" /></TestCase>
    <TestCase name="skipped" skipped="true" />
  </TestSuite>
  <TestSuite name="other">
    <TestCase name="ignored"><OverallResultsAsserts test_case_success="true" failures="0" /></TestCase>
  </TestSuite>
</doctest>
""",
    )

    results = parse_doctest_xml(xml_path, suite_name="parity", workspace_id="test-run")

    assert sorted(results) == ["fails", "passes", "skipped"]
    assert results["passes"].success is True
    assert results["fails"].success is False
    assert results["fails"].failures == 2
    assert results["skipped"].skipped is True
    assert results["skipped"].success is False


def test_compare_parity_marks_any_side_failure_as_failure() -> None:
    comparison = compare_case_sets(
        {"same": case("same", True), "regressed": case("regressed", True)},
        {"same": case("same", True), "regressed": case("regressed", False)},
        suite_name="parity",
    )

    assert comparison.has_failure is True
    assert comparison.summary.pass_count == 1
    assert comparison.summary.fail_count == 1
    assert "[FAIL] parity: regressed" in "\n".join(comparison.lines)


def test_compare_divergence_accepts_test_run_pass_baseline_fail() -> None:
    comparison = compare_case_sets(
        {"fixed": case("fixed", True), "still_broken": case("still_broken", False)},
        {"fixed": case("fixed", False), "still_broken": case("still_broken", False)},
        suite_name="divergence",
    )

    assert comparison.has_failure is False
    assert comparison.summary.pass_count == 1
    assert comparison.summary.warn_count == 1
    assert comparison.summary.fail_count == 0


def test_compare_case_set_mismatch_is_warning_not_failure() -> None:
    comparison = compare_case_sets(
        {"test_run_only": case("test_run_only", True)},
        {},
        suite_name="parity",
    )

    assert comparison.has_failure is False
    assert comparison.summary.warn_count == 1
    assert comparison.summary.case_set_mismatch_count == 1
