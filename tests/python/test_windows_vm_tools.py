from __future__ import annotations

import json
from pathlib import Path

from emule_test_harness import windows_vm_tools


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_windows_vm_auxiliary_tools_are_classified() -> None:
    matrix = windows_vm_tools.build_windows_vm_auxiliary_tool_matrix()
    tools = {tool["script"]: tool for tool in matrix["tools"]}

    assert tools["windows-vm-rest-stress.py"] == {
        "name": "windows-vm-rest-stress",
        "script": "windows-vm-rest-stress.py",
        "status": "operator-add-on",
        "requiredProfile": "hideme-live-wire",
        "networkScope": "vpn",
        "resultFileName": "windows-vm-rest-stress-result.json",
        "requiredInputs": ["base-url", "api-key", "artifacts-dir"],
    }
    json.dumps(matrix)


def test_windows_vm_scripts_are_registered_as_auxiliary_tools() -> None:
    registered_scripts = {spec.script_name for spec in windows_vm_tools.WINDOWS_VM_AUXILIARY_TOOL_SPECS}
    script_paths = sorted((repo_root() / "scripts").glob("windows-vm-*.py"))

    assert {path.name for path in script_paths} == registered_scripts
