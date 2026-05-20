from __future__ import annotations

import importlib.util
from pathlib import Path


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
    assert "mounted root fixture" in (fixture["root"] / "mounted_root_file.txt").read_text(encoding="utf-8")


def test_build_mounted_root_expectations_keeps_promoted_root_internal(tmp_path: Path) -> None:
    module = load_shared_directories_rest_module()

    mounted_root = tmp_path / "mounted"
    mounted_root.mkdir()
    fixture = module.create_mounted_root_fixture(mounted_root)
    expectations = module.build_mounted_root_expectations(fixture)
    mounted_root_path = module.live_common.win_path(mounted_root, trailing_slash=True)

    assert expectations["visible_roots"] == [module.live_common.win_path(tmp_path, trailing_slash=True)]
    assert mounted_root_path in expectations["monitored_roots"]
    assert mounted_root_path in expectations["items_before_child"]
    assert mounted_root_path in expectations["monitor_owned_before_child"]
    assert mounted_root_path not in expectations["visible_roots"]


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
