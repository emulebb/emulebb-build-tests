from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_soak_module():
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "fake-kad-trust-soak.py"
    spec = importlib.util.spec_from_file_location("fake_kad_trust_soak_for_tests", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["fake_kad_trust_soak_for_tests"] = module
    spec.loader.exec_module(module)
    return module


def test_kad_trust_hint_matches_native_bucket_thresholds() -> None:
    module = load_soak_module()

    assert module.build_kad_trust_hint(0)["kind"] == "unknown"
    assert module.build_kad_trust_hint((2 << 24) | (4 << 16) | 99)["kind"] == "low"
    assert module.build_kad_trust_hint((1 << 24) | (8 << 16) | 100)["kind"] == "normal"
    high = module.build_kad_trust_hint((1 << 24) | (8 << 16) | 300)

    assert high["kind"] == "high"
    assert high["publishers"] == 8
    assert high["differentNames"] == 1
    assert high["trustValueCent"] == 300


def test_fake_report_validation_rejects_inconsistent_score_and_divergence() -> None:
    module = load_soak_module()
    row = {
        "hash": "0123456789abcdef0123456789abcdef",
        "evidence": {
            "riskEvidence": {
                "score": 15,
                "severity": "none",
                "reasons": ["multiple_names"],
            },
            "nameEvidence": {
                "canonicalNames": ["one | ext:avi", "two | ext:avi"],
                "ignoredNameTokens": ["DivX"],
                "divergenceGroups": ["one | ext:avi"],
            },
            "integrityEvidence": {
                "pendingHeaderCheck": False,
            },
        }
    }

    errors, _report = module.validate_fake_report(row)

    assert "positive score has none severity" in errors
    assert "multiple_names reason has fewer than two divergence groups" in errors
    assert "ignored token is not normalized: 'DivX'" in errors


def test_fake_report_validation_rejects_removed_fake_file_contract() -> None:
    module = load_soak_module()
    row = {
        "hash": "0123456789abcdef0123456789abcdef",
        "fakeFile": {
            "score": 15,
            "severity": "low",
            "reasons": ["multiple_names"],
            "canonicalNames": ["one | ext:avi", "two | ext:avi"],
            "ignoredNameTokens": [],
            "nameDivergenceGroups": ["one | ext:avi", "two | ext:avi"],
        },
    }

    errors, report = module.validate_fake_report(row)

    assert errors == ["missing search risk evidence object"]
    assert report == {"score": None, "severity": "missing", "reasons": []}


def test_result_summary_counts_risk_and_kad_metrics() -> None:
    module = load_soak_module()
    rows = [
        {
            "hash": "0123456789abcdef0123456789abcdef",
            "name": "Operator Movie DivX 1080p.avi",
            "kadPublishInfo": (2 << 24) | (4 << 16) | 99,
            "evidence": {
                "riskEvidence": {
                    "score": 0,
                    "severity": "none",
                    "reasons": [],
                },
                "nameEvidence": {
                    "canonicalNames": ["operator movie | ext:avi"],
                    "ignoredNameTokens": ["divx", "1080p"],
                    "divergenceGroups": [],
                },
                "integrityEvidence": {
                    "pendingHeaderCheck": False,
                },
            },
        },
        {
            "hash": "fedcba98765432100123456789abcdef",
            "name": "Different Movie.avi",
            "kadPublishInfo": (1 << 24) | (8 << 16) | 300,
            "evidence": {
                "riskEvidence": {
                    "score": 15,
                    "severity": "low",
                    "reasons": ["multiple_names"],
                },
                "nameEvidence": {
                    "canonicalNames": ["different movie | ext:avi"],
                    "ignoredNameTokens": [],
                    "divergenceGroups": ["operator movie | ext:avi", "different movie | ext:avi"],
                },
                "integrityEvidence": {
                    "pendingHeaderCheck": False,
                },
            },
        },
    ]

    summary = module.summarize_result_rows(rows)

    assert summary["row_count"] == 2
    assert summary["unique_hash_count"] == 2
    assert summary["invalid_row_count"] == 0
    assert summary["fake_score_buckets"] == {"0": 1, "1-24": 1}
    assert summary["fake_reason_counts"] == {"multiple_names": 1}
    assert summary["kad_trust_counts"] == {"high": 1, "low": 1}
    assert summary["kad_publish_info_rows"] == 2
