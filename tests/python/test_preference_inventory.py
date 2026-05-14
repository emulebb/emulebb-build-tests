from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


CLASSIFICATIONS = {
    "active-roundtrip",
    "read-only-legacy",
    "write-only-session-stat",
    "disabled-tombstone",
    "dynamic-family",
    "external-state",
}

ASYMMETRIC_CLASSIFICATIONS = CLASSIFICATIONS - {"active-roundtrip"}


@dataclass
class IniKeyUse:
    source_expression: str
    key: str | None
    kind: str
    sections: set[str] = field(default_factory=set)
    access: set[str] = field(default_factory=set)
    value_kinds: set[str] = field(default_factory=set)


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _strip_cpp_comments(source: str) -> str:
    output: list[str] = []
    state = "code"
    i = 0
    while i < len(source):
        char = source[i]
        next_char = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if char == '"':
                output.append(char)
                state = "string"
                i += 1
            elif char == "'":
                output.append(char)
                state = "character"
                i += 1
            elif char == "/" and next_char == "/":
                output.extend("  ")
                i += 2
                while i < len(source) and source[i] != "\n":
                    output.append(" ")
                    i += 1
            elif char == "/" and next_char == "*":
                output.extend("  ")
                i += 2
                while i + 1 < len(source) and not (source[i] == "*" and source[i + 1] == "/"):
                    output.append("\n" if source[i] == "\n" else " ")
                    i += 1
                if i + 1 < len(source):
                    output.extend("  ")
                    i += 2
            else:
                output.append(char)
                i += 1
        elif state == "string":
            output.append(char)
            if char == "\\" and i + 1 < len(source):
                output.append(source[i + 1])
                i += 2
            elif char == '"':
                state = "code"
                i += 1
            else:
                i += 1
        else:
            output.append(char)
            if char == "\\" and i + 1 < len(source):
                output.append(source[i + 1])
                i += 2
            elif char == "'":
                state = "code"
                i += 1
            else:
                i += 1
    return "".join(output)


def _split_cpp_arguments(argument_source: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    state = "code"
    i = 0
    while i < len(argument_source):
        char = argument_source[i]
        if state == "code":
            if char == '"':
                current.append(char)
                state = "string"
            elif char == "'":
                current.append(char)
                state = "character"
            elif char in "([{":
                depth += 1
                current.append(char)
            elif char in ")]}":
                depth -= 1
                current.append(char)
            elif char == "," and depth == 0:
                args.append("".join(current).strip())
                current = []
            else:
                current.append(char)
        elif state == "string":
            current.append(char)
            if char == "\\" and i + 1 < len(argument_source):
                i += 1
                current.append(argument_source[i])
            elif char == '"':
                state = "code"
        else:
            current.append(char)
            if char == "\\" and i + 1 < len(argument_source):
                i += 1
                current.append(argument_source[i])
            elif char == "'":
                state = "code"
        i += 1
    if current or argument_source.strip():
        args.append("".join(current).strip())
    return args


def _find_call_end(source: str, open_paren_index: int) -> int:
    depth = 0
    state = "code"
    i = open_paren_index
    while i < len(source):
        char = source[i]
        if state == "code":
            if char == '"':
                state = "string"
            elif char == "'":
                state = "character"
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return i
        elif state == "string":
            if char == "\\":
                i += 1
            elif char == '"':
                state = "code"
        else:
            if char == "\\":
                i += 1
            elif char == "'":
                state = "code"
        i += 1
    raise AssertionError("unterminated C++ call while parsing Preferences.cpp")


def _load_preference_ini_constants(header_source: str) -> dict[str, str]:
    constants: dict[str, str] = {}
    namespaces: list[str] = []
    for line in header_source.splitlines():
        stripped = line.strip()
        namespace_match = re.fullmatch(r"namespace\s+(\w+)", stripped)
        if namespace_match:
            namespaces.append(namespace_match.group(1))
            continue
        if stripped == "}" and namespaces:
            namespaces.pop()
            continue
        constant_match = re.search(
            r'inline constexpr const TCHAR\*\s+(\w+)\s*=\s*_T\("([^"]*)"\)',
            line,
        )
        if not constant_match or not namespaces:
            continue
        suffix = "::".join([*namespaces[1:], constant_match.group(1)])
        constants[f"prefini::{suffix}"] = constant_match.group(2)
        constants[f"PreferenceIniMap::{suffix}"] = constant_match.group(2)
    return constants


def _normalize_ini_expression(expression: str, constants: dict[str, str]) -> tuple[str, str]:
    expression = expression.strip()
    literal_match = re.fullmatch(r'_T\("([^"]*)"\)', expression)
    if literal_match:
        return "literal", literal_match.group(1)
    if re.fullmatch(r"[A-Za-z_][\w:]*", expression) and expression in constants:
        return "constant", constants[expression]
    return "dynamic", expression


def _extract_ini_key_uses(workspace_root: Path) -> dict[str, IniKeyUse]:
    app_source = workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid"
    preferences_cpp = _strip_cpp_comments((app_source / "Preferences.cpp").read_text(encoding="utf-8", errors="ignore"))
    constants = _load_preference_ini_constants(
        (app_source / "PreferenceIniMap.h").read_text(encoding="utf-8", errors="ignore")
    )

    key_uses: dict[str, IniKeyUse] = {}
    for match in re.finditer(r"\bini\.(Get|Write)([A-Za-z0-9_]*)\s*\(", preferences_cpp):
        call_end = _find_call_end(preferences_cpp, match.end() - 1)
        args = _split_cpp_arguments(preferences_cpp[match.end() : call_end])
        if not args:
            continue
        key_kind, key = _normalize_ini_expression(args[0], constants)
        section = "<default>"
        if len(args) >= 3:
            section_kind, section_value = _normalize_ini_expression(args[2], constants)
            if section_kind != "dynamic":
                section = section_value

        inventory_id = key if key_kind != "dynamic" else f"<dynamic:{key}>"
        key_use = key_uses.setdefault(
            inventory_id,
            IniKeyUse(
                source_expression=args[0],
                key=None if key_kind == "dynamic" else key,
                kind=key_kind,
            ),
        )
        key_use.sections.add(section)
        key_use.access.add("read" if match.group(1) == "Get" else "write")
        key_use.value_kinds.add(match.group(2))
    return key_uses


def _load_inventory(workspace_root: Path) -> dict[str, object]:
    inventory_path = workspace_root / "repos" / "eMule-build-tests" / "manifests" / "preference-inventory.v1.json"
    return json.loads(inventory_path.read_text(encoding="utf-8"))


def test_preferences_cpp_ini_keys_match_machine_readable_inventory() -> None:
    workspace_root = _workspace_root()
    actual_uses = _extract_ini_key_uses(workspace_root)
    inventory = _load_inventory(workspace_root)
    entries = inventory["entries"]
    by_id = {entry["id"]: entry for entry in entries}

    assert inventory["schemaVersion"] == 1
    assert set(by_id) == set(actual_uses)

    for inventory_id, key_use in actual_uses.items():
        entry = by_id[inventory_id]
        assert entry["sourceExpression"] == key_use.source_expression
        assert entry["key"] == key_use.key
        assert entry["kind"] == key_use.kind
        assert set(entry["sections"]) == key_use.sections
        assert set(entry["access"]) == key_use.access
        assert set(entry["valueKinds"]) == key_use.value_kinds
        assert entry["classification"] in CLASSIFICATIONS

        if key_use.access != {"read", "write"}:
            assert entry["classification"] in ASYMMETRIC_CLASSIFICATIONS
        elif entry["kind"] == "dynamic":
            assert entry["classification"] == "dynamic-family"


def test_rest_mutable_preference_surface_is_covered_by_one_metadata_table() -> None:
    workspace_root = _workspace_root()
    app_source = workspace_root / "workspaces" / "v0.72a" / "app" / "eMule-main" / "srchybrid"
    surface_header = (app_source / "WebApiSurfaceSeams.h").read_text(encoding="utf-8", errors="ignore")
    json_seams_header = (app_source / "WebServerJsonSeams.h").read_text(encoding="utf-8", errors="ignore")
    json_cpp = (app_source / "WebServerJson.cpp").read_text(encoding="utf-8", errors="ignore")

    specs_block = re.search(
        r"GetMutablePreferenceSpecs\(\).*?specs\s*=\s*\{\{(?P<body>.*?)\}\};",
        surface_header,
        flags=re.S,
    )
    assert specs_block is not None
    spec_names = re.findall(r'\{\s*"([^"]+)"\s*,\s*EMutablePreference::', specs_block.group("body"))
    assert spec_names
    assert len(spec_names) == len(set(spec_names))

    csv_block = re.search(
        r"kMutablePreferenceFieldListCsv\s*=\s*(?P<body>.*?);",
        surface_header,
        flags=re.S,
    )
    assert csv_block is not None
    csv_names = "".join(re.findall(r'"([^"]*)"', csv_block.group("body"))).split(",")
    assert csv_names == spec_names

    assert "WebApiSurfaceSeams::kMutablePreferenceFieldListCsv" in json_seams_header
    assert "WebApiSurfaceSeams::GetMutablePreferenceSpecs()" in json_seams_header

    for field_name in spec_names:
        assert f'{{"{field_name}",' in json_cpp
        assert f'rPrefs.contains("{field_name}")' in json_cpp
