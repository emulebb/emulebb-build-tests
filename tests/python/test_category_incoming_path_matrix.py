from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def load_script_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "category-incoming-path-matrix.py"
    spec = importlib.util.spec_from_file_location("category_incoming_path_matrix_test", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("win32"):
            pytest.skip(f"pywin32 live harness dependency is unavailable: {exc.name}")
        raise
    return module


def test_category_incoming_cases_cover_vhd_paths_and_selectors() -> None:
    module = load_script_module()

    cases = module.build_category_incoming_cases()

    assert [case.name for case in cases] == [
        "category-drive-incoming-by-id",
        "category-mount-incoming-by-id",
        "category-drive-incoming-by-name",
        "same-vhd-drive-temp-mount-category",
        "local-category-control-by-name",
    ]
    assert any(case.category_incoming_role == module.STORAGE_ROLE_VHD_DRIVE for case in cases)
    assert any(case.category_incoming_role == module.STORAGE_ROLE_VHD_MOUNT for case in cases)
    assert {case.selector for case in cases} == {module.CATEGORY_SELECTOR_ID, module.CATEGORY_SELECTOR_NAME}
    assert any(
        not case.expected_rejected
        and case.temp_role == module.STORAGE_ROLE_LOCAL
        and case.category_incoming_role == module.STORAGE_ROLE_LOCAL
        for case in cases
    )


def test_category_selector_payload_uses_exactly_one_selector() -> None:
    module = load_script_module()

    assert module.category_selector_payload(module.CATEGORY_SELECTOR_ID, 7, "Movies") == {"categoryId": 7}
    assert module.category_selector_payload(module.CATEGORY_SELECTOR_NAME, 7, "Movies") == {"categoryName": "Movies"}
    with pytest.raises(ValueError):
        module.category_selector_payload("both", 7, "Movies")


def test_find_category_row_matches_by_id_or_name() -> None:
    module = load_script_module()

    rows = [
        {"id": 1, "name": "Alpha", "path": "C:/incoming/a"},
        {"id": 2, "name": "Beta", "path": "C:/incoming/b"},
    ]

    assert module.find_category_row(rows, 2, "Missing") == rows[1]
    assert module.find_category_row(rows, 99, "Alpha") == rows[0]
    assert module.find_category_row(rows, 99, "Missing") is None


def test_find_test_owned_category_rows_matches_prefix_and_case_name() -> None:
    module = load_script_module()
    rows = [
        {"id": 0, "name": "Default", "path": "C:/incoming/default"},
        {"id": 1, "name": "CI035 00 category-drive-incoming-by-id", "path": "Z:/incoming"},
        {"id": 2, "name": "CI035 99 other-case", "path": "Z:/other"},
        {"id": 3, "name": "Personal", "path": "C:/incoming/personal"},
    ]

    matches = module.find_test_owned_category_rows(
        rows,
        "category-drive-incoming-by-id",
        "CI035 00 category-drive-incoming-by-id",
    )

    assert [row["id"] for row in matches] == [1]


def success_array(items: list[dict[str, object]]) -> dict[str, object]:
    return {
        "status": 200,
        "content_type": "application/json",
        "raw_json": {"data": {"items": items}, "meta": {"apiVersion": "v1"}},
        "json": {"items": items},
        "body_text": "",
    }


def not_found_response() -> dict[str, object]:
    return {
        "status": 404,
        "content_type": "application/json",
        "json": {"error": "NOT_FOUND", "message": "transfer not found"},
        "body_text": '{"error":"NOT_FOUND","message":"transfer not found"}',
    }


def test_collect_case_record_state_accepts_clean_default_only(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_script_module()

    def fake_request(_base_url: str, path: str, **_kwargs: object) -> dict[str, object]:
        if path == "/api/v1/categories":
            return success_array([{"id": 0, "name": "Default", "path": "C:/incoming"}])
        if path.startswith("/api/v1/transfers/"):
            return not_found_response()
        raise AssertionError(path)

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_request)

    state = module.collect_case_record_state(
        "http://127.0.0.1:4711",
        "api-key",
        case_name="category-drive-incoming-by-id",
        category_name="CI035 00 category-drive-incoming-by-id",
        transfer_hash="abcd",
    )

    assert state["clean"] is True
    assert state["matching_categories"] == []
    assert state["transfer_absent"] is True


def test_collect_case_record_state_detects_stale_category_and_transfer(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_script_module()

    def fake_request(_base_url: str, path: str, **_kwargs: object) -> dict[str, object]:
        if path == "/api/v1/categories":
            return success_array(
                [
                    {"id": 0, "name": "Default", "path": "C:/incoming"},
                    {"id": 7, "name": "CI035 00 category-drive-incoming-by-id", "path": "Z:/incoming"},
                ]
            )
        if path.startswith("/api/v1/transfers/"):
            return {"status": 200, "content_type": "application/json", "json": {"hash": "abcd"}, "body_text": "{}"}
        raise AssertionError(path)

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_request)

    state = module.collect_case_record_state(
        "http://127.0.0.1:4711",
        "api-key",
        case_name="category-drive-incoming-by-id",
        category_name="CI035 00 category-drive-incoming-by-id",
        transfer_hash="abcd",
    )

    assert state["clean"] is False
    assert state["matching_categories"] == [{"id": 7, "name": "CI035 00 category-drive-incoming-by-id", "path": "Z:/incoming"}]
    assert state["transfer_absent"] is False
    with pytest.raises(RuntimeError, match="pre-case"):
        module.require_clean_case_records(state, "pre-case")


def test_cleanup_case_records_deletes_transfer_then_category(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_script_module()
    calls: list[tuple[str, str, object]] = []
    categories = [{"id": 7, "name": "CI035 00 category-drive-incoming-by-id", "path": "Z:/incoming"}]
    transfer_present = True

    def fake_request(_base_url: str, path: str, **kwargs: object) -> dict[str, object]:
        nonlocal categories, transfer_present
        method = str(kwargs.get("method", "GET"))
        calls.append((method, path, kwargs.get("json_body")))
        if path == "/api/v1/categories" and method == "GET":
            return success_array([{"id": 0, "name": "Default", "path": "C:/incoming"}, *categories])
        if path == "/api/v1/categories/7" and method == "DELETE":
            categories = []
            return {"status": 200, "content_type": "application/json", "json": {"ok": True}, "body_text": "{}"}
        if path == "/api/v1/transfers/abcd" and method == "GET":
            if transfer_present:
                return {"status": 200, "content_type": "application/json", "json": {"hash": "abcd"}, "body_text": "{}"}
            return not_found_response()
        if path == "/api/v1/transfers/abcd/files?confirm=true" and method == "DELETE":
            transfer_present = False
            return {"status": 200, "content_type": "application/json", "json": {"ok": True}, "body_text": "{}"}
        raise AssertionError(f"{method} {path}")

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_request)

    cleanup = module.cleanup_case_records(
        "http://127.0.0.1:4711",
        "api-key",
        case_name="category-drive-incoming-by-id",
        category_name="CI035 00 category-drive-incoming-by-id",
        transfer_hash="abcd",
        created_category_id=7,
    )

    assert cleanup["clean"] is True
    assert calls[2] == ("DELETE", "/api/v1/transfers/abcd/files?confirm=true", None)
    assert calls[3] == ("DELETE", "/api/v1/categories/7", None)
    assert cleanup["after"]["clean"] is True


def test_build_admin_fixture_config_uses_sibling_mount_parent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_script_module()
    monkeypatch.setattr(module, "reject_windows_temp_path", lambda _path, _purpose: None)

    class Paths:
        source_artifacts_dir = tmp_path / "artifacts" / "category-incoming-path-matrix"

    class Args:
        mount_root = None
        vhd_size_mb = 384
        keep_admin_fixtures = False

    config = module.build_admin_fixture_config(Paths(), Args())

    assert config.vhd_path == Paths.source_artifacts_dir / "admin-volumes" / "category-incoming-path-matrix.vhdx"
    assert config.mount_root == tmp_path / "artifacts" / "admin-mounts" / "category-incoming-path-matrix" / "category-incoming-path-matrix"
    assert config.local_control_root == Paths.source_artifacts_dir / "local-control-volume"
    assert config.size_mb == 384
