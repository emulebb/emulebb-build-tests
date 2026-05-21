from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace


def load_shared_directories_rest_module():
    """Loads the hyphenated shared-directory REST live script for unit tests."""

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "shared-directories-rest-e2e.py"
    spec = importlib.util.spec_from_file_location("shared_directories_rest_e2e_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_shared_directory_patch_payload_uses_recursive_objects(tmp_path: Path) -> None:
    module = load_shared_directories_rest_module()

    flat = tmp_path / "flat"
    recursive = tmp_path / "recursive"
    payload = module.build_shared_directory_patch_payload([flat], [recursive])

    assert payload == {
        "confirmReplaceRoots": True,
        "roots": [
            module.live_common.win_path(flat, trailing_slash=True),
            {
                "path": module.live_common.win_path(recursive, trailing_slash=True),
                "recursive": True,
            },
        ]
    }


def test_read_persisted_path_list_handles_utf16_and_missing(tmp_path: Path) -> None:
    module = load_shared_directories_rest_module()

    path_list = tmp_path / "shareddir.dat"
    path_list.write_text("C:\\Share\\One\\\r\n\r\nC:\\Share\\Two\\\r\n", encoding="utf-16")

    assert module.read_persisted_path_list(path_list) == ["C:\\Share\\One\\", "C:\\Share\\Two\\"]
    assert module.read_persisted_path_list(tmp_path / "missing.dat") == []


def test_create_mounted_root_fixture_stays_below_operator_root(tmp_path: Path) -> None:
    module = load_shared_directories_rest_module()

    mounted_root = tmp_path / "mounted"
    mounted_root.mkdir()
    fixture = module.create_mounted_root_fixture(mounted_root)

    assert fixture["parent"] == tmp_path
    assert fixture["mounted_root"] == mounted_root
    assert fixture["root"].parent == mounted_root
    assert (fixture["root"] / module.MOUNTED_ROOT_FILE_NAME).read_bytes() == module.MOUNTED_ROOT_FILE_BYTES


def test_build_mounted_root_expectations_keeps_promoted_root_internal(tmp_path: Path) -> None:
    module = load_shared_directories_rest_module()

    mounted_root = tmp_path / "mounted"
    mounted_root.mkdir()
    fixture = module.create_mounted_root_fixture(mounted_root)
    expectations = module.build_mounted_root_expectations(fixture)
    mounted_root_path = module.live_common.win_path(mounted_root, trailing_slash=True)

    assert expectations["visible_roots"] == [module.live_common.win_path(tmp_path, trailing_slash=True)]
    assert mounted_root_path not in expectations["monitored_roots"]
    assert mounted_root_path in expectations["items_before_child"]
    assert mounted_root_path in expectations["monitor_owned_before_child"]
    assert mounted_root_path not in expectations["visible_roots"]


def test_build_admin_fixture_config_stays_under_source_artifacts(tmp_path: Path, monkeypatch) -> None:
    module = load_shared_directories_rest_module()
    monkeypatch.setattr(module, "reject_windows_temp_path", lambda _path, _purpose: None)
    paths = SimpleNamespace(source_artifacts_dir=tmp_path / "artifacts")
    args = SimpleNamespace(mount_root=None, vhd_size_mb=384, keep_admin_fixtures=True)

    config = module.build_admin_fixture_config(paths, args)

    assert config.vhd_path == tmp_path / "artifacts" / "admin-volumes" / "shared-directories-rest.vhdx"
    assert config.mount_root == tmp_path / "artifacts" / "admin-mounts" / "shared-directories-rest"
    assert config.local_control_root == tmp_path / "artifacts" / "local-control-volume"
    assert config.size_mb == 384
    assert config.keep is True


def test_remove_tree_long_path_removes_fixture_tree(tmp_path: Path) -> None:
    module = load_shared_directories_rest_module()

    root = tmp_path / "fixture"
    child = root / "child"
    child.mkdir(parents=True)
    (child / "file.txt").write_text("content", encoding="utf-8")

    module.remove_tree_long_path(root)

    assert not root.exists()


def test_assert_equivalent_path_sets_handles_case_slashes_and_trailing_separators() -> None:
    module = load_shared_directories_rest_module()

    module.assert_equivalent_path_sets(
        ["C:/Share/One/", "c:\\share\\two\\\\"],
        ["c:\\share\\one", "C:\\Share\\Two"],
        "test paths",
    )


def test_launch_and_wait_tolerates_minimized_to_tray_startup(tmp_path: Path, monkeypatch) -> None:
    module = load_shared_directories_rest_module()
    launched = object()

    monkeypatch.setattr(module, "launch_app", lambda _app_exe, _profile_base: launched)
    monkeypatch.setattr(module, "wait_for_rest_ready", lambda _base_url, _api_key, _timeout_seconds: {"status": 200})

    def fail_wait_for_main_window(_app, *, timeout=90.0, require_visible=False):
        raise RuntimeError("Timed out waiting for eMule main window. Last value: None")

    monkeypatch.setattr(module, "wait_for_main_window", fail_wait_for_main_window)

    app, title, ready = module.launch_and_wait(tmp_path / "emule.exe", tmp_path / "profile", "http://127.0.0.1:4712", "k", 30.0)

    assert app is launched
    assert title == "not observed (minimized to tray)"
    assert ready == {"status": 200, "content_type": None}


def test_require_shared_file_hash_rejects_missing_hash() -> None:
    module = load_shared_directories_rest_module()

    try:
        module.require_shared_file_hash({"name": "file.txt", "hash": "ABC"}, "file.txt")
    except AssertionError as exc:
        assert "lowercase MD4 hash" in str(exc)
    else:
        raise AssertionError("Expected invalid shared-file hash to fail.")


def test_assert_shared_file_ed2k_link_validates_hash_size_and_name(monkeypatch) -> None:
    module = load_shared_directories_rest_module()
    row = {"name": "mounted_root_file.txt", "hash": "0123456789abcdef0123456789abcdef"}

    def fake_http_request(_base_url, path, *, api_key=None):
        assert path == "/api/v1/shared-files/0123456789abcdef0123456789abcdef/ed2k-link"
        assert api_key == "key"
        data = {
            "hash": "0123456789abcdef0123456789abcdef",
            "link": "ed2k://|file|mounted_root_file.txt|22|0123456789ABCDEF0123456789ABCDEF|/",
        }
        return {
            "status": 200,
            "content_type": "application/json",
            "headers": {},
            "body_text": "{}",
            "json": data,
            "raw_json": {"data": data, "meta": {"apiVersion": "v1"}},
        }

    monkeypatch.setattr(module, "http_request", fake_http_request)

    result = module.assert_shared_file_ed2k_link(
        "http://127.0.0.1:4711",
        "key",
        row,
        expected_name="mounted_root_file.txt",
        expected_size=22,
    )

    assert result["hash"] == "0123456789abcdef0123456789abcdef"
    assert "ed2k://|file|" in result["link"]


def test_assert_shared_file_row_content_reads_exact_bytes(tmp_path: Path) -> None:
    module = load_shared_directories_rest_module()
    shared_file = tmp_path / "mounted_root_file.txt"
    shared_file.write_bytes(module.MOUNTED_ROOT_FILE_BYTES)
    row = {
        "name": "mounted_root_file.txt",
        "hash": "0123456789abcdef0123456789abcdef",
        "path": str(shared_file),
    }

    result = module.assert_shared_file_row_content(
        row,
        expected_name="mounted_root_file.txt",
        expected_content=module.MOUNTED_ROOT_FILE_BYTES,
    )

    assert result["bytes"] == len(module.MOUNTED_ROOT_FILE_BYTES)
    assert result["path"] == str(shared_file)


def test_assert_mounted_shared_file_serving_checks_ed2k_and_readable_bytes(monkeypatch) -> None:
    module = load_shared_directories_rest_module()
    row = {"name": "mounted_root_file.txt", "hash": "0123456789abcdef0123456789abcdef"}

    monkeypatch.setattr(module, "get_shared_file_row_by_name", lambda _base_url, _api_key, _name: row)
    monkeypatch.setattr(
        module,
        "assert_shared_file_ed2k_link",
        lambda _base_url, _api_key, _row, *, expected_name, expected_size: {
            "hash": _row["hash"],
            "expected_name": expected_name,
            "expected_size": expected_size,
        },
    )
    monkeypatch.setattr(
        module,
        "assert_shared_file_row_content",
        lambda _row, *, expected_name, expected_content: {
            "hash": _row["hash"],
            "expected_name": expected_name,
            "bytes": len(expected_content),
        },
    )

    result = module.assert_mounted_shared_file_serving(
        "http://127.0.0.1:4711",
        "key",
        expected_files={"mounted_root_file.txt": b"abc"},
    )

    assert result["mounted_root_file.txt"]["ed2k_link"]["expected_size"] == 3
    assert result["mounted_root_file.txt"]["filesystem_read"]["bytes"] == 3
