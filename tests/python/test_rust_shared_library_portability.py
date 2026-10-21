from __future__ import annotations

from pathlib import Path

import pytest

from emule_test_harness import rust_shared_library_fixture as fixture
from emule_test_harness import rust_shared_library_storage as storage


@pytest.mark.unit
def test_production_fixture_has_deterministic_unicode_cohort() -> None:
    first = fixture.relative_file_for_index(fixture.UNICODE_COHORT_START)
    paths = [
        fixture.relative_file_for_index(fixture.UNICODE_COHORT_START + offset)
        for offset in range(len(fixture.UNICODE_FILE_NAMES))
    ]

    assert first == Path("group-098/unicode-cohort/case-00/café-nfc.bin")
    assert len(paths) == 16
    assert len(set(paths)) == len(paths)
    assert paths[1].name == "café-nfd.bin"
    assert paths[9].name == "emoji-🚀-💾.bin"
    assert all(len(path.parts) > 4 for path in paths[-4:])
    assert fixture.unicode_cohort_summary()["fileCount"] == 16


@pytest.mark.unit
def test_prune_superseded_fixture_paths_preserves_neighboring_files(tmp_path: Path) -> None:
    root = tmp_path / "library"
    superseded = fixture.superseded_unicode_baseline_paths()
    for relative in superseded:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"legacy")
    neighbor = root / "group-098" / "leaf-091" / "file-098916.bin"
    neighbor.write_bytes(b"keep")

    removed = fixture.prune_superseded_fixture_paths(root)

    assert removed == len(fixture.UNICODE_FILE_NAMES)
    assert all(not (root / relative).exists() for relative in superseded)
    assert neighbor.read_bytes() == b"keep"
    assert not (root / "group-098" / "leaf-090").exists()


@pytest.mark.unit
def test_native_length_helpers_and_name_probe_are_explicit(tmp_path: Path) -> None:
    expected_emoji_length = 2 if storage.native_length_unit() == "utf16CodeUnits" else 4
    assert storage.native_text_length("🚀") == expected_emoji_length
    assert storage.maximum_native_component_length(tmp_path / "café") >= 4

    capabilities = storage.detect_name_capabilities(tmp_path)

    assert set(capabilities) == {
        "caseDistinctNames",
        "normalizationDistinctNames",
        "caseCollisionDisposition",
        "normalizationCollisionDisposition",
    }
    assert capabilities["caseCollisionDisposition"] in {
        "supported",
        "skipped-native-alias",
    }
    assert capabilities["normalizationCollisionDisposition"] in {
        "supported",
        "skipped-native-alias",
    }
    assert not (tmp_path / ".emulebb-capability-probe").exists()
