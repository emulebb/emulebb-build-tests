"""Windows VM auxiliary tool registry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class WindowsVmAuxiliaryToolSpec:
    """One operator-facing tool that extends an already-running Windows VM scenario."""

    name: str
    script_name: str
    status: str
    required_profile: str
    network_scope: str
    result_file_name: str
    required_inputs: tuple[str, ...]


WINDOWS_VM_AUXILIARY_TOOL_SPECS = (
    WindowsVmAuxiliaryToolSpec(
        name="windows-vm-rest-stress",
        script_name="windows-vm-rest-stress.py",
        status="operator-add-on",
        required_profile="hideme-live-wire",
        network_scope="vpn",
        result_file_name="windows-vm-rest-stress-result.json",
        required_inputs=("base-url", "api-key", "artifacts-dir"),
    ),
)


def build_windows_vm_auxiliary_tool_matrix() -> dict[str, Any]:
    """Returns auxiliary VM tools that are not standalone VM test profiles."""

    return {
        "schema": "emulebb-build-tests.windows-vm-auxiliary-tools.v1",
        "toolCount": len(WINDOWS_VM_AUXILIARY_TOOL_SPECS),
        "tools": [
            {
                "name": spec.name,
                "script": spec.script_name,
                "status": spec.status,
                "requiredProfile": spec.required_profile,
                "networkScope": spec.network_scope,
                "resultFileName": spec.result_file_name,
                "requiredInputs": list(spec.required_inputs),
            }
            for spec in WINDOWS_VM_AUXILIARY_TOOL_SPECS
        ],
    }
