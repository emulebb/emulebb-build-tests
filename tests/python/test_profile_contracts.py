from __future__ import annotations

import re
from pathlib import Path


RUNTIME_PROFILE_WRITER_ALLOWLIST = {
    "emule_test_harness/ini.py",
    "emule_test_harness/live_profiles.py",
    "emule_test_harness/vm_guest_profiles.py",
}
FORBIDDEN_RUNTIME_PROFILE_WRITER_PATTERNS = (
    re.compile(r"_preferences_content\s*\("),
    re.compile(r"preferences_path\.write_text\s*\("),
    re.compile(r"preferences_path\.write_bytes\s*\("),
    re.compile(r"\(\s*config_dir\s*/\s*[\"']preferences\.ini[\"']\s*\)\.write_text\s*\("),
    re.compile(r"\(\s*config_dir\s*/\s*[\"']preferences\.ini[\"']\s*\)\.write_bytes\s*\("),
)


def test_runtime_preferences_ini_writers_stay_in_shared_profile_helpers() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    offenders: list[str] = []

    for root_name in ("emule_test_harness", "scripts"):
        for source_path in sorted((repo_root / root_name).rglob("*.py")):
            relative_path = source_path.relative_to(repo_root).as_posix()
            if relative_path in RUNTIME_PROFILE_WRITER_ALLOWLIST:
                continue
            text = source_path.read_text(encoding="utf-8")
            for pattern in FORBIDDEN_RUNTIME_PROFILE_WRITER_PATTERNS:
                if pattern.search(text):
                    offenders.append(f"{relative_path}: {pattern.pattern}")

    assert offenders == []
