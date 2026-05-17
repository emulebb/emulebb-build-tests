from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_CLASSIFICATIONS = {
    "editable-ui",
    "editable-rest",
    "editable-ui-rest",
    "persisted-runtime",
    "read-only-legacy",
    "write-only-stat",
    "disabled-tombstone",
    "dynamic-family",
    "external-state",
    "ui-runtime",
}


REST_FIELD_TO_SCHEMA_ID = {
    "uploadLimitKiBps": "MaxUpload",
    "downloadLimitKiBps": "MaxDownload",
    "maxConnections": "MaxConnections",
    "maxConnectionsPerFiveSeconds": "MaxConnectionsPerFiveSeconds",
    "maxSourcesPerFile": "MaxSourcesPerFile",
    "uploadClientDataRate": "MaxUploadClientsAllowed",
    "maxUploadSlots": "MaxUploadClientsAllowed",
    "queueSize": "QueueSize",
    "autoConnect": "Autoconnect",
    "newAutoUp": "UAPPref",
    "newAutoDown": "DAPPref",
    "creditSystem": "UseCreditSystem",
    "safeServerConnect": "SafeServerConnect",
    "networkKademlia": "NetworkKademlia",
    "networkEd2k": "NetworkED2K",
    "autoBroadbandIo": "AutoBroadbandIO",
}


OWNER_TOKEN_TO_SCHEMA_ID = {
    "configuredmaxdownload": "MaxDownload",
    "maxdownload": "MaxDownload",
    "configuredmaxupload": "MaxUpload",
    "maxupload": "MaxUpload",
    "configuredmaxsourcesperfile": "MaxSourcesPerFile",
    "maxsourcesperfile": "MaxSourcesPerFile",
    "maxconperfive": "MaxConnectionsPerFiveSeconds",
    "maxconsperfive": "MaxConnectionsPerFiveSeconds",
    "maxuploadclientsallowed": "MaxUploadClientsAllowed",
    "alwaysshowtrayicon": "AlwaysShowTrayIcon",
    "storingsearches": "StoreSearches",
    "usedwlpercentage": "ShowDwlPercentage",
    "removefinisheddownloads": "AutoClearCompleted",
    "useautocompl": "UseAutocompletion",
    "useautocompletion": "UseAutocompletion",
    "transtoolbar": "WinaTransToolbar",
    "win7taskbargoodies": "ShowWin7TaskbarGoodies",
    "wsis": "Enabled::WebServer",
    "legacywebui": "EnableLegacyWebUi",
    "webusegzip": "UseGzip",
    "wsapikey": "ApiKey",
    "wsport": "Port::WebServer",
    "webbindaddr": "BindAddr::WebServer",
    "maxwebuploadfilesizemb": "MaxFileUploadSizeMB",
    "enableminimule": "MiniMule",
    "webtimeoutmins": "WebTimeoutMins",
    "webusehttps": "UseHTTPS",
    "webcertpath": "HTTPSCertificate",
    "webkeypath": "HTTPSKey",
    "wsislowuser": "UseLowRightsUser",
    "wslowpass": "PasswordLow",
    "wspass": "Password",
    "webadminhilevfunc": "AllowAdminHiLevelFunc",
    "webadminallowedhilevfunc": "AllowAdminHiLevelFunc",
    "wsuseupnp": "WebUseUPnP",
    "newautoup": "UAPPref",
    "newautodown": "DAPPref",
    "creditsystem": "UseCreditSystem",
    "networked2k": "NetworkED2K",
    "networkkademlia": "NetworkKademlia",
    "safeserverconnect": "SafeServerConnect",
    "autobroadbandioenabled": "AutoBroadbandIO",
    "exitonbindinterfaceloss": "ExitOnBindInterfaceLoss",
    "exitonbindinterfacelossenabled": "ExitOnBindInterfaceLoss",
    "port": "Port::<default>",
    "udpport": "UDPPort",
    "bindaddr": "BindAddr::<default>",
    "bindinterface": "BindInterface",
    "startupbindblock": "BlockNetworkWhenBindUnavailableAtStartup",
}


@dataclass(frozen=True)
class PreferencePaths:
    workspace_root: Path
    app_source: Path
    build_tests_root: Path


def get_preference_paths(workspace_root: Path) -> PreferencePaths:
    return PreferencePaths(
        workspace_root=workspace_root,
        app_source=workspace_root / "workspaces" / "workspace" / "app" / "eMule-main" / "srchybrid",
        build_tests_root=workspace_root / "repos" / "eMule-build-tests",
    )


def load_preference_inventory(workspace_root: Path) -> dict[str, Any]:
    paths = get_preference_paths(workspace_root)
    inventory_path = paths.build_tests_root / "manifests" / "preference-inventory.v1.json"
    return json.loads(inventory_path.read_text(encoding="utf-8"))


def load_preference_schema(workspace_root: Path) -> dict[str, Any]:
    paths = get_preference_paths(workspace_root)
    schema_path = paths.build_tests_root / "manifests" / "preference-schema.v1.json"
    return json.loads(schema_path.read_text(encoding="utf-8"))


def schema_id_for_inventory_entry(inventory_id: str, sections: list[str], section: str) -> str:
    if len(sections) == 1:
        return inventory_id
    return f"{inventory_id}::{section}"


def normalize_owner_token(value: str | None) -> str:
    text = value or ""
    text = text.replace("thePrefs.", "")
    text = re.sub(r"\([^)]*\)", "", text)
    text = re.sub(r"^(Get|Set|Is|Do|Use)", "", text)
    for word in ("Configured", "Preference", "Value", "Allowed", "Current"):
        text = text.replace(word, "")
    text = re.sub(r"[^A-Za-z0-9]", "", text).lower()
    for prefix in ("mstr", "mb", "mi", "mu", "mn", "ms", "dw", "str"):
        if text.startswith(prefix) and len(text) > len(prefix) + 2:
            text = text[len(prefix) :]
    return text


def value_type_for_inventory_entry(entry: dict[str, Any]) -> str:
    kinds = set(entry["valueKinds"])
    if "Bool" in kinds:
        return "bool"
    if "String" in kinds or "StringLong" in kinds:
        return "string"
    if "Float" in kinds:
        return "number"
    if "Binary" in kinds:
        return "binary"
    if "ColRef" in kinds:
        return "color"
    return "integer"


def base_schema_classification(entry: dict[str, Any]) -> str:
    classification = entry["classification"]
    if classification == "active-roundtrip":
        return "persisted-runtime"
    if classification == "read-only-legacy":
        return "read-only-legacy"
    if classification == "write-only-session-stat":
        return "write-only-stat"
    if classification == "disabled-tombstone":
        return "disabled-tombstone"
    if classification == "dynamic-family":
        return "dynamic-family"
    return "external-state"


def parse_resource_ids(app_source: Path) -> set[str]:
    resource_text = (app_source / "resource.h").read_text(encoding="utf-8", errors="ignore")
    return set(re.findall(r"^#define\s+(ID[CD]_[A-Za-z0-9_]+)\s+\d+", resource_text, flags=re.M))


def parse_preference_dialog_controls(app_source: Path) -> dict[str, set[str]]:
    dialogs: dict[str, set[str]] = {}
    current_dialog: str | None = None
    for line in (app_source / "emule.rc").read_text(encoding="utf-8", errors="ignore").splitlines():
        dialog_match = re.match(r"^(IDD_PPG_[A-Za-z0-9_]+)\s+DIALOG", line)
        if dialog_match:
            current_dialog = dialog_match.group(1)
            dialogs[current_dialog] = set()
            continue
        if current_dialog is not None and line.strip() == "END":
            current_dialog = None
            continue
        if current_dialog is not None:
            for control_id in re.findall(r"\b(IDC_[A-Za-z0-9_]+)\b", line):
                if control_id != "IDC_STATIC":
                    dialogs[current_dialog].add(control_id)
    return dialogs


def parse_preference_page_dialogs(app_source: Path) -> dict[str, str]:
    page_dialogs: dict[str, str] = {}
    for header_path in app_source.glob("PPg*.h"):
        header_text = header_path.read_text(encoding="utf-8", errors="ignore")
        dialog_match = re.search(r"IDD\s*=\s*(IDD_PPG_[A-Za-z0-9_]+)", header_text)
        if dialog_match:
            page_dialogs[f"{header_path.stem}.cpp"] = dialog_match.group(1)
    return page_dialogs


def parse_rest_mutable_preference_names(app_source: Path) -> list[str]:
    surface_text = (app_source / "WebApiSurfaceSeams.h").read_text(encoding="utf-8", errors="ignore")
    specs_block = re.search(
        r"GetMutablePreferenceSpecs\(\).*?specs\s*=\s*\{\{(?P<body>.*?)\}\};",
        surface_text,
        flags=re.S,
    )
    if specs_block is None:
        return []
    return re.findall(r'\{\s*"([^"]+)"\s*,\s*EMutablePreference::', specs_block.group("body"))


def direct_control_ids_for_line(line: str) -> list[str]:
    control_ids: list[str] = []
    for pattern in (
        r"CheckDlgButton\((IDC_\w+)",
        r"SetDlgItem(?:Int|Text)?\((IDC_\w+)",
        r"IsDlgButtonChecked\((IDC_\w+)",
        r"GetDlgItem(?:Int|Text)?\((IDC_\w+)",
    ):
        control_ids.extend(re.findall(pattern, line))
    return sorted(set(control_ids))


def all_control_ids_for_line(line: str) -> list[str]:
    return sorted(set(re.findall(r"\bIDC_[A-Za-z0-9_]+\b", line)))


def infer_schema_ids_for_owner(
    owner_expression: str,
    token_to_schema_ids: dict[str, list[str]],
) -> list[str]:
    token = normalize_owner_token(owner_expression)
    explicit = OWNER_TOKEN_TO_SCHEMA_ID.get(token)
    if explicit is not None:
        return [explicit]
    schema_ids = token_to_schema_ids.get(token, [])
    if schema_ids:
        return schema_ids
    if not token:
        token = "owner"
    return [f"ui-runtime::{token}"]


def parse_ui_bindings(
    app_source: Path,
    token_to_schema_ids: dict[str, list[str]],
) -> list[dict[str, Any]]:
    page_dialogs = parse_preference_page_dialogs(app_source)
    bindings: list[dict[str, Any]] = []
    for cpp_path in sorted(app_source.glob("PPg*.cpp")):
        current_function: str | None = None
        page = cpp_path.name
        dialog_id = page_dialogs.get(page)
        for line_number, line in enumerate(cpp_path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            function_match = re.search(r"CPPg\w+::(\w+)\s*\(", line)
            if function_match:
                current_function = function_match.group(1)
            if "thePrefs." not in line:
                continue
            owners = re.findall(r"thePrefs\.([A-Za-z_]\w*)", line)
            if not owners:
                continue
            access = "write" if current_function == "OnApply" else "read"
            control_ids = all_control_ids_for_line(line)
            direct_control_ids = direct_control_ids_for_line(line)
            for owner_index, owner_expression in enumerate(owners):
                schema_ids = infer_schema_ids_for_owner(owner_expression, token_to_schema_ids)
                bindings.append(
                    {
                        "id": f"{page}:{line_number}:{owner_index}:{owner_expression}",
                        "page": page,
                        "dialogId": dialog_id,
                        "line": line_number,
                        "function": current_function or "global",
                        "access": access,
                        "ownerExpression": owner_expression,
                        "controlIds": control_ids,
                        "directControlIds": direct_control_ids,
                        "schemaIds": schema_ids,
                    }
                )
    return bindings


def build_preference_schema(workspace_root: Path) -> dict[str, Any]:
    paths = get_preference_paths(workspace_root)
    inventory = load_preference_inventory(workspace_root)
    entries: list[dict[str, Any]] = []
    entry_by_id: dict[str, dict[str, Any]] = {}
    token_to_schema_ids: dict[str, list[str]] = {}

    for inventory_entry in inventory["entries"]:
        sections = list(inventory_entry["sections"])
        for section in sections:
            schema_id = schema_id_for_inventory_entry(inventory_entry["id"], sections, section)
            schema_entry = {
                "id": schema_id,
                "inventoryId": inventory_entry["id"],
                "storageFile": inventory_entry["storageFile"],
                "section": section,
                "key": inventory_entry["key"],
                "sourceExpression": inventory_entry["sourceExpression"],
                "valueType": value_type_for_inventory_entry(inventory_entry),
                "access": inventory_entry["access"],
                "classification": base_schema_classification(inventory_entry),
                "ownerExpressions": [],
                "defaultExpression": "",
                "clampOrNormalizer": inventory_entry.get("clampOrNormalizer", ""),
                "uiBindingIds": [],
                "restBindings": [],
                "notes": inventory_entry.get("notes", ""),
            }
            entries.append(schema_entry)
            entry_by_id[schema_id] = schema_entry
            for token in {normalize_owner_token(inventory_entry["key"]), normalize_owner_token(inventory_entry["id"])}:
                if token:
                    token_to_schema_ids.setdefault(token, []).append(schema_id)

    rest_fields = parse_rest_mutable_preference_names(paths.app_source)
    for rest_field in rest_fields:
        schema_id = REST_FIELD_TO_SCHEMA_ID[rest_field]
        entry_by_id[schema_id]["restBindings"].append(rest_field)

    ui_bindings = parse_ui_bindings(paths.app_source, token_to_schema_ids)
    for binding in ui_bindings:
        for schema_id in binding["schemaIds"]:
            if schema_id not in entry_by_id:
                token = schema_id.split("::", 1)[1] if "::" in schema_id else schema_id
                synthetic_entry = {
                    "id": schema_id,
                    "inventoryId": None,
                    "storageFile": None,
                    "section": None,
                    "key": None,
                    "sourceExpression": "",
                    "valueType": "unknown",
                    "access": [binding["access"]],
                    "classification": "ui-runtime",
                    "ownerExpressions": [binding["ownerExpression"]],
                    "defaultExpression": "",
                    "clampOrNormalizer": "",
                    "uiBindingIds": [],
                    "restBindings": [],
                    "notes": f"Synthetic UI/runtime preference owner token: {token}.",
                }
                entries.append(synthetic_entry)
                entry_by_id[schema_id] = synthetic_entry
            entry_by_id[schema_id]["uiBindingIds"].append(binding["id"])
            owner_expressions = entry_by_id[schema_id]["ownerExpressions"]
            if binding["ownerExpression"] not in owner_expressions:
                owner_expressions.append(binding["ownerExpression"])

    for entry in entries:
        if entry["classification"] == "persisted-runtime":
            has_ui = bool(entry["uiBindingIds"])
            has_rest = bool(entry["restBindings"])
            if has_ui and has_rest:
                entry["classification"] = "editable-ui-rest"
            elif has_ui:
                entry["classification"] = "editable-ui"
            elif has_rest:
                entry["classification"] = "editable-rest"
        entry["ownerExpressions"] = sorted(entry["ownerExpressions"])
        entry["uiBindingIds"] = sorted(set(entry["uiBindingIds"]))
        entry["restBindings"] = sorted(set(entry["restBindings"]))

    return {
        "schemaVersion": 1,
        "featureId": "FEAT-061",
        "sourceInventory": "manifests/preference-inventory.v1.json",
        "classifications": sorted(SCHEMA_CLASSIFICATIONS),
        "entries": sorted(entries, key=lambda item: item["id"].lower()),
        "uiBindings": sorted(ui_bindings, key=lambda item: item["id"].lower()),
    }


def schema_storage_tuples(schema: dict[str, Any]) -> list[tuple[str, str, str]]:
    tuples: list[tuple[str, str, str]] = []
    for entry in schema["entries"]:
        if entry["storageFile"] is not None and entry["section"] is not None and entry["key"] is not None:
            tuples.append((entry["storageFile"], entry["section"], entry["key"]))
    return tuples
