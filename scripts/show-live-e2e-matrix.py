"""Print the generated live E2E scenario matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from emule_test_harness import scenario_matrix  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    """Builds the command-line parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit the full machine-readable matrix.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Runs the matrix reporter."""

    args = build_parser().parse_args(argv)
    matrix = scenario_matrix.build_live_e2e_scenario_matrix()
    if args.json:
        print(json.dumps(matrix, indent=2))
        return 0

    print(f"Live E2E scenario matrix: {matrix['suiteCount']} suites")
    print("")
    print("Suite                              Network  Topology              Stress   Profiles")
    print("---------------------------------  -------  --------------------  -------  -------------------------")
    for suite in matrix["suites"]:
        profiles = ",".join(suite["profiles"]) or "-"
        print(
            f"{suite['name']:<33}  {suite['networkScope']:<7}  "
            f"{suite['topology']:<20}  {suite['stressClass']:<7}  {profiles}"
        )
    print("")
    print("Rollups")
    for axis in ("byNetworkScope", "byTopology", "byStressClass"):
        values = ", ".join(f"{name}={count}" for name, count in matrix["rollups"][axis].items())
        print(f"- {axis}: {values}")
    if matrix["repetitions"]:
        print("")
        print("Repeated profile coverage")
        for repetition in matrix["repetitions"]:
            profiles = ",".join(repetition["profiles"])
            print(f"- {repetition['suite']}: {repetition['classification']} ({profiles})")
    if matrix["gaps"]:
        print("")
        print("Gaps")
        for gap in matrix["gaps"]:
            print(f"- {gap['suite']}: {gap['gap']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
