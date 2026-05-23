from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from emule_test_harness.preference_schema import (
    REST_FIELD_TO_SCHEMA_ID,
    SCHEMA_CLASSIFICATIONS,
    build_preference_schema,
    load_preference_inventory,
    load_preference_schema,
    parse_preference_dialog_controls,
    parse_resource_ids,
    parse_rest_mutable_preference_names,
    schema_id_for_inventory_entry,
    schema_storage_tuples,
)

RESOURCE_ONLY_DIRECT_CONTROLS = {
    ("IDD_PPG_STATS", "IDC_STATTREE"),
}


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[4]


def test_preference_schema_manifest_matches_source_generation() -> None:
    workspace_root = _workspace_root()
    checked_in = load_preference_schema(workspace_root)
    generated = build_preference_schema(workspace_root)

    assert checked_in == generated


def test_preference_schema_covers_every_inventory_storage_entry() -> None:
    workspace_root = _workspace_root()
    inventory = load_preference_inventory(workspace_root)
    schema = load_preference_schema(workspace_root)
    schema_ids = {entry["id"] for entry in schema["entries"]}

    expected_ids = {
        schema_id_for_inventory_entry(entry["id"], list(entry["sections"]), section)
        for entry in inventory["entries"]
        for section in entry["sections"]
    }

    assert expected_ids <= schema_ids


def test_preference_schema_has_no_duplicate_ids_or_storage_keys() -> None:
    schema = load_preference_schema(_workspace_root())
    entry_ids = [entry["id"] for entry in schema["entries"]]
    storage_tuples = schema_storage_tuples(schema)

    duplicate_entry_ids = sorted(item for item, count in Counter(entry_ids).items() if count > 1)
    duplicate_storage = sorted(item for item, count in Counter(storage_tuples).items() if count > 1)

    assert duplicate_entry_ids == []
    assert duplicate_storage == []
    assert all(entry["classification"] in SCHEMA_CLASSIFICATIONS for entry in schema["entries"])


def test_preference_schema_rest_bindings_match_native_metadata() -> None:
    workspace_root = _workspace_root()
    schema = load_preference_schema(workspace_root)
    app_source = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"
    native_rest_fields = parse_rest_mutable_preference_names(app_source)
    schema_by_id = {entry["id"]: entry for entry in schema["entries"]}
    rest_bindings = {
        rest_field: entry["id"]
        for entry in schema["entries"]
        for rest_field in entry["restBindings"]
    }

    assert native_rest_fields == list(REST_FIELD_TO_SCHEMA_ID)
    assert rest_bindings == REST_FIELD_TO_SCHEMA_ID
    assert len(rest_bindings) == len(set(rest_bindings))
    for rest_field, schema_id in REST_FIELD_TO_SCHEMA_ID.items():
        assert rest_field in schema_by_id[schema_id]["restBindings"]
        assert schema_by_id[schema_id]["classification"] in {"editable-rest", "editable-ui-rest"}


def test_preference_schema_ui_bindings_are_unique_and_resource_backed() -> None:
    workspace_root = _workspace_root()
    schema = load_preference_schema(workspace_root)
    app_source = workspace_root / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"
    resource_ids = parse_resource_ids(app_source)
    dialog_controls = parse_preference_dialog_controls(app_source)
    schema_ids = {entry["id"] for entry in schema["entries"]}
    binding_ids = [binding["id"] for binding in schema["uiBindings"]]

    assert sorted(item for item, count in Counter(binding_ids).items() if count > 1) == []
    for binding in schema["uiBindings"]:
        assert binding["dialogId"] in dialog_controls
        assert set(binding["schemaIds"]) <= schema_ids
        for control_id in binding["controlIds"]:
            assert control_id in resource_ids
        for control_id in binding["directControlIds"]:
            if (binding["dialogId"], control_id) not in RESOURCE_ONLY_DIRECT_CONTROLS:
                assert control_id in dialog_controls[binding["dialogId"]]


def test_preference_schema_ui_editable_bindings_have_single_manifest_owner() -> None:
    schema = load_preference_schema(_workspace_root())
    direct_control_owners: dict[tuple[str, str, str], set[str]] = defaultdict(set)

    for binding in schema["uiBindings"]:
        for control_id in binding["directControlIds"]:
            for schema_id in binding["schemaIds"]:
                direct_control_owners[(binding["dialogId"], control_id, binding["ownerExpression"])].add(schema_id)

    duplicate_owners = {
        key: sorted(value)
        for key, value in direct_control_owners.items()
        if len(value) > 1
    }
    assert duplicate_owners == {}
