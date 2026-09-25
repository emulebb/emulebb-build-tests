"""Create a bounded operator-local Rust live hash allowlist from known.met."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.direct_safe_corpus import prepare_corpus  # noqa: E402
from emule_test_harness.paths import get_workspace_output_root  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--operator-inputs", type=Path, required=True)
    parser.add_argument("--max-candidates", type=int, default=50)
    args = parser.parse_args(argv)
    prior = json.loads(args.operator_inputs.read_text(encoding="utf-8-sig"))
    profile = Path(str(prior.get("mfc_profile", {}).get("profile_dir") or ""))
    known_met = profile / "config" / "known.met"
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = get_workspace_output_root() / "reports" / "rust-direct-corpus" / run_id / "inputs.local.json"
    result = prepare_corpus(args.source_root, known_met, args.operator_inputs, output,
                            max_candidates=args.max_candidates)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
