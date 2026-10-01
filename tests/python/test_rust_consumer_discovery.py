from __future__ import annotations

from emule_test_harness import rust_consumer_discovery


def test_select_pdf_candidate_enforces_extension_size_hash_and_sources() -> None:
    valid_hash = "a" * 32
    selected = rust_consumer_discovery.select_pdf_candidate(
        [
            {"name": "linux.iso", "hash": valid_hash, "sizeBytes": 100, "sources": 10},
            {"name": "large.pdf", "hash": "b" * 32, "sizeBytes": 5000, "sources": 20},
            {"name": "idle.pdf", "hash": "c" * 32, "sizeBytes": 100, "sources": 0},
            {"name": "small.pdf", "hash": valid_hash, "sizeBytes": 800, "sources": 2},
            {"name": "healthy.pdf", "hash": "d" * 32, "sizeBytes": 1200, "sources": 4},
        ],
        4096,
    )

    assert selected == {
        "name": "healthy.pdf",
        "hash": "d" * 32,
        "size": 1200,
        "method": "direct_ed2k",
        "sources": 4,
    }
