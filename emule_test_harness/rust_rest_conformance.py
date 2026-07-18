"""Live emulebb-rust REST OpenAPI conformance runner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from emule_test_harness.script_modules import load_script_module

REST_COVERAGE_BUDGETS = ("contract", "contract-stress")


class RestConformanceError(AssertionError):
    """Raised when the live REST response conformance summary fails."""

    def __init__(self, summary: dict[str, object]):
        super().__init__(summary)
        self.summary = summary


def load_rest_smoke_module() -> Any:
    return load_script_module("rest_api_smoke_for_rust_conformance", "rest-api-smoke.py")


def run_response_conformance(
    base_url: str,
    api_key: str,
    *,
    budget: str = "contract",
    rest_smoke_module: Any | None = None,
) -> dict[str, object]:
    """Runs live REST contract completeness and fails on OpenAPI response drift."""

    if budget not in REST_COVERAGE_BUDGETS:
        raise ValueError(f"REST conformance budget must be one of {REST_COVERAGE_BUDGETS!r}: {budget!r}")
    rest_smoke = rest_smoke_module or load_rest_smoke_module()
    summary = rest_smoke.exercise_rest_contract_completeness(base_url, api_key, budget)
    if not bool(summary.get("ok")):
        raise RestConformanceError(summary)
    return summary


def write_report(path: Path, summary: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a running emulebb-rust /api/v1 daemon against OpenAPI.")
    parser.add_argument("--base-url", required=True, help="Running emulebb-rust REST base URL.")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--rest-coverage-budget", choices=REST_COVERAGE_BUDGETS, default="contract")
    parser.add_argument("--json-output", type=Path, help="Optional path for the conformance summary JSON.")
    args = parser.parse_args(argv)

    summary: dict[str, object] = {}
    try:
        summary = run_response_conformance(args.base_url, args.api_key, budget=args.rest_coverage_budget)
    except RestConformanceError as exc:
        summary = exc.summary
        if args.json_output is not None:
            write_report(args.json_output, summary)
        failed_routes = ", ".join(str(route) for route in summary.get("failed_routes", [])) or "<unknown>"
        print(f"emulebb-rust REST OpenAPI response conformance failed: {failed_routes}")
        return 1

    if args.json_output is not None:
        write_report(args.json_output, summary)
    print("emulebb-rust REST OpenAPI response conformance passed.")
    return 0
