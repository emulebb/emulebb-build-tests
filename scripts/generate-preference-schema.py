from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from emule_test_harness.preference_schema import build_preference_schema, get_preference_paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate the eMule preference schema manifest.")
    args = parser.parse_args()

    workspace_root_value = os.environ.get("EMULEBB_WORKSPACE_ROOT", "").strip()
    if not workspace_root_value:
        raise RuntimeError("EMULEBB_WORKSPACE_ROOT must be set.")
    workspace_root = Path(workspace_root_value).resolve()
    schema = build_preference_schema(workspace_root)
    output_path = get_preference_paths(workspace_root).build_tests_root / "manifests" / "preference-schema.v1.json"
    output_path.write_text(json.dumps(schema, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"Wrote {len(schema['entries'])} schema entries and {len(schema['uiBindings'])} UI bindings to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
