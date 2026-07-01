from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RUST_SOAK_CONTROL = REPO_ROOT / "scripts" / "rust-soak-control.py"


def _load_rust_soak_control() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rust_soak_control_script", RUST_SOAK_CONTROL)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shared_directory_summary_redacts_paths_and_keeps_flags() -> None:
    control = _load_rust_soak_control()

    summary = control.summarize_shared_directory_rows(
        [
            {
                "path": r"F:\Private\Library\\",
                "accessible": True,
                "shareable": True,
                "recursive": True,
                "monitorOwned": False,
            },
            {
                "path": r"F:\Private\Library",
                "accessible": True,
                "shareable": True,
                "recursive": False,
                "monitorOwned": True,
            },
        ]
    )

    assert summary["count"] == 2
    assert summary["duplicateCount"] == 1
    assert summary["counts"]["accessible"] == 2
    assert summary["counts"]["recursive"] == 1
    assert summary["counts"]["monitorOwned"] == 1
    assert "Private" not in repr(summary)
    assert "Library" not in repr(summary)


def test_shared_summary_compare_reports_root_and_count_delta() -> None:
    control = _load_rust_soak_control()

    shared = control.private_path_fingerprint(r"F:\Private\Library")
    rust_only = control.private_path_fingerprint(r"F:\Private\RustOnly")
    mfc_only = control.private_path_fingerprint(r"F:\Private\MfcOnly")
    comparison = control.compare_shared_summaries(
        {
            "sharedFilesTotal": 10,
            "roots": {"fingerprints": [shared, rust_only]},
        },
        {
            "sharedFilesTotal": 12,
            "roots": {"fingerprints": [shared, mfc_only]},
        },
    )

    assert comparison == {
        "enabled": True,
        "rootFingerprintsMatch": False,
        "rustOnlyRootFingerprintCount": 1,
        "mfcOnlyRootFingerprintCount": 1,
        "rustOnlyRootFingerprints": [rust_only],
        "mfcOnlyRootFingerprints": [mfc_only],
        "sharedFilesDeltaRustMinusMfc": -2,
    }


def test_private_path_fingerprint_normalizes_windows_verbatim_prefix() -> None:
    control = _load_rust_soak_control()

    assert control.private_path_fingerprint(r"\\?\F:\Private\Library") == control.private_path_fingerprint(
        r"F:\Private\Library\\"
    )
    assert control.private_path_fingerprint(r"\\?\UNC\server\share\Library") == control.private_path_fingerprint(
        r"\\server\share\Library"
    )


def test_shared_file_hash_comparison_reports_unique_and_duplicate_gaps() -> None:
    control = _load_rust_soak_control()

    comparison = control.compare_shared_file_hashes(
        {"rowCount": 2, "duplicateHashCount": 0, "hashes": {"a" * 32, "b" * 32}},
        {"rowCount": 3, "duplicateHashCount": 1, "hashes": {"b" * 32, "c" * 32}},
    )

    assert comparison["uniqueHashesMatch"] is False
    assert comparison["rustOnlyUniqueHashCount"] == 1
    assert comparison["mfcOnlyUniqueHashCount"] == 1
    assert comparison["rustDuplicateHashCount"] == 0
    assert comparison["mfcDuplicateHashCount"] == 1
    assert comparison["uniqueHashDeltaRustMinusMfc"] == 0
    assert comparison["rowCountDeltaRustMinusMfc"] == -1


def test_shared_file_catalog_comparison_reports_path_and_hash_gaps() -> None:
    control = _load_rust_soak_control()

    comparison = control.compare_shared_file_catalogs(
        {
            "byPath": {
                "shared": "a" * 32,
                "rust-only": "b" * 32,
                "changed": "c" * 32,
            }
        },
        {
            "byPath": {
                "shared": "a" * 32,
                "mfc-only": "d" * 32,
                "changed": "e" * 32,
            }
        },
    )

    assert comparison["pathFingerprintsMatch"] is False
    assert comparison["rustOnlyPathCount"] == 1
    assert comparison["mfcOnlyPathCount"] == 1
    assert comparison["changedHashForSamePathCount"] == 1
    assert comparison["rustOnlyPathFingerprints"] == ["rust-only"]
    assert comparison["mfcOnlyPathFingerprints"] == ["mfc-only"]
    assert comparison["changedPathFingerprints"] == ["changed"]
