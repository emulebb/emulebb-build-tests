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


def test_assert_equivalent_path_sets_handles_case_slashes_and_trailing_separators() -> None:
    module = load_shared_directories_rest_module()

    module.assert_equivalent_path_sets(
        ["C:/Share/One/", "c:\\share\\two\\\\"],
        ["c:\\share\\one", "C:\\Share\\Two"],
        "test paths",
    )
