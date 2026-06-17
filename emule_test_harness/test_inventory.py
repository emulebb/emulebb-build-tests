"""Content-level inventory across the native, python-harness, and live-e2e layers.

The maintained test surface is too large to eyeball (native doctest suites,
hundreds of python-harness modules, and the live-e2e suite registry), so this
module builds one machine-readable catalog that maps every test asset to *what
it verifies*, a cost proxy, and how it is reached (tier / profile / targeted).

It reuses :mod:`emule_test_harness.scenario_matrix` for the live-e2e layer
(topology, stress class, profile membership, redundancy and orphan signals) and
adds the two layers that matrix does not cover: native C++ doctest suites and
the python-harness modules.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from emule_test_harness import scenario_matrix

SCHEMA = "emulebb-build-tests.test-inventory.v1"

# Native doctest suites auto-run by ``python -m emule_workspace test all`` (and
# therefore by the quick/fast/overnight certification tiers). Every other suite
# tag is reachable only through ``test native --suite-name`` or a helper script.
# Keep in sync with TEST_ALL_NATIVE_SUITES in emulebb-build test_runs.py.
TIER_NATIVE_SUITES = (
    "parity",
    "protocol-parity",
    "web_api",
    "async_dns_resolve",
    "background_refresh",
    "diagnostic_snapshot",
    "kad-base",
    "known_file_hash_open",
    "packets",
    "part_file_hash_launch",
    "part_file_majority_name",
    "process_launch",
    "restart_app",
    "search_trust_hint",
    "server_connect",
    "server_info",
    "standby_prevention",
    "startup_storage",
    "version_check_launch",
    "windows_firewall_repair",
)

_SUITE_RE = re.compile(r'TEST_SUITE(?:_BEGIN)?\(\s*"([^"]+)"')
_CASE_RE = re.compile(r'TEST_CASE(?:_FIXTURE|_TEMPLATE)?\(\s*"([^"]+)"')
_TEST_SUITE_FLAG_RE = re.compile(r'--test-suite=([A-Za-z0-9_-]+)')
_QUOTED_RE = re.compile(r'"([A-Za-z0-9_-]+)"')
_SCRIPT_REF_RE = re.compile(r'scripts["\'/\\\s]+([A-Za-z0-9][A-Za-z0-9_-]+\.py)')


def repo_root() -> Path:
    """Returns the emulebb-build-tests repository root for this module."""

    return Path(__file__).resolve().parents[1]


def build_test_inventory(root: Path | None = None) -> dict[str, Any]:
    """Returns the combined three-layer test inventory catalog."""

    root = root or repo_root()
    native = build_native_layer(root)
    python = build_python_layer(root)
    live = build_live_layer(root)
    return {
        "schema": SCHEMA,
        "layers": {
            "native": native,
            "pythonHarness": python,
            "liveE2e": live,
        },
        "rollups": {
            "nativeSuiteCount": len(native["suites"]),
            "nativeFileCount": len(native["files"]),
            "nativeCaseCount": sum(f["caseCount"] for f in native["files"]),
            "nativeDormantSuiteCount": sum(1 for s in native["suites"] if s["runBy"] == "targeted-only"),
            "pythonModuleCount": len(python["modules"]),
            "pythonSelfTestCount": sum(1 for m in python["modules"] if m["selfTestsScript"]),
            "liveSuiteCount": live["suiteCount"],
            "liveDefaultEnabledCount": live["rollups"]["defaultEnabledCount"],
        },
    }


# --------------------------------------------------------------------------- #
# Native C++ doctest layer
# --------------------------------------------------------------------------- #
def build_native_layer(root: Path) -> dict[str, Any]:
    """Inventories native doctest files, grouped by ``TEST_SUITE`` tag."""

    files: list[dict[str, Any]] = []
    suites: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "src").glob("*.tests.cpp")):
        text = path.read_text(encoding="utf-8", errors="replace")
        tags = sorted(set(_SUITE_RE.findall(text)))
        cases = _CASE_RE.findall(text)
        files.append(
            {
                "file": f"src/{path.name}",
                "suites": tags,
                "caseCount": len(cases),
                "cases": cases,
            }
        )
        for tag in tags:
            row = suites.setdefault(tag, {"suite": tag, "fileCount": 0, "caseCount": 0, "files": []})
            row["fileCount"] += 1
            row["caseCount"] += len(cases)
            row["files"].append(f"src/{path.name}")

    orchestrated = _orchestrated_native_suites(root, set(suites))
    for tag, row in suites.items():
        row["runBy"] = _native_run_by(tag, orchestrated)
    return {
        "suites": [suites[name] for name in sorted(suites)],
        "files": files,
    }


def _native_run_by(tag: str, orchestrated: dict[str, str]) -> str:
    """Returns how a native suite tag is reached by orchestration."""

    if tag in TIER_NATIVE_SUITES:
        return "test-all"
    if tag in orchestrated:
        return f"orchestrated:{orchestrated[tag]}"
    return "targeted-only"


def _orchestrated_native_suites(root: Path, known_tags: set[str]) -> dict[str, str]:
    """Maps native suite tags to a helper that auto-runs them (not via test all).

    Suites are selected either through an explicit ``--test-suite=<tag>`` flag or
    through a ``suite_name(s)=`` tuple of quoted tags passed to the native
    coverage runner. Scan both the helper scripts and the harness modules so a
    suite driven only by, for example, community-core coverage is not mislabeled
    as dormant.
    """

    found: dict[str, str] = {}
    for base in (root / "scripts", root / "emule_test_harness"):
        for path in sorted(base.glob("*.py")):
            if path.name == "test_inventory.py":
                continue
            rel = f"{base.name}/{path.name}"
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                for tag in _TEST_SUITE_FLAG_RE.findall(line):
                    found.setdefault(tag, rel)
                if "suite_name" in line or "--suite-name" in line:
                    for token in _QUOTED_RE.findall(line):
                        if token in known_tags:
                            found.setdefault(token, rel)
    return found


# --------------------------------------------------------------------------- #
# Python-harness layer
# --------------------------------------------------------------------------- #
def build_python_layer(root: Path) -> dict[str, Any]:
    """Inventories python-harness modules and their self-tested scripts."""

    modules: list[dict[str, Any]] = []
    for path in sorted((root / "tests" / "python").glob("test_*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        modules.append(
            {
                "module": f"tests/python/{path.name}",
                "loc": text.count("\n") + 1,
                "verifies": _python_summary(text),
                "selfTestsScript": _python_self_tested_script(text),
            }
        )
    return {"modules": modules}


def _python_summary(text: str) -> str:
    """Returns a one-line purpose for a python-harness module."""

    try:
        tree = ast.parse(text)
    except SyntaxError:
        return ""
    doc = ast.get_docstring(tree)
    if doc:
        return doc.strip().splitlines()[0]
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_doc = ast.get_docstring(node)
            if fn_doc:
                return fn_doc.strip().splitlines()[0]
    return ""


def _python_self_tested_script(text: str) -> str:
    """Returns the ``scripts/<name>.py`` a module unit-tests, when it loads one."""

    match = _SCRIPT_REF_RE.search(text)
    return f"scripts/{match.group(1)}" if match else ""


# --------------------------------------------------------------------------- #
# Live-e2e layer (reuses scenario_matrix)
# --------------------------------------------------------------------------- #
def build_live_layer(root: Path) -> dict[str, Any]:
    """Returns the live-e2e matrix enriched with each script's purpose line."""

    matrix = scenario_matrix.build_live_e2e_scenario_matrix()
    for suite in matrix["suites"]:
        suite["verifies"] = _script_docstring(root / "scripts" / suite["script"])
    return matrix


def _script_docstring(path: Path) -> str:
    """Returns the one-line module docstring of a live-e2e script."""

    if not path.is_file():
        return ""
    try:
        doc = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8", errors="replace")))
    except SyntaxError:
        return ""
    return doc.strip().splitlines()[0] if doc else ""
