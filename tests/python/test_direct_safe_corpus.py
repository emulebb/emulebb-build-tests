from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from emule_test_harness import direct_safe_corpus


def test_prepare_corpus_matches_known_met_identity_and_preserves_existing(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    document = source / "safe-linux-document.pdf"
    document.write_bytes(b"%PDF-" + b"x" * direct_safe_corpus.MIN_CANDIDATE_BYTES)
    stat = document.stat()
    known_met = tmp_path / "known.met"
    known_met.write_bytes(b"fixture")
    monkeypatch.setattr(
        direct_safe_corpus.mfc_known_met,
        "parse_known_met",
        lambda _path: [SimpleNamespace(
            name=document.name, size_bytes=stat.st_size, modified_s=int(stat.st_mtime),
            ed2k_hash="b" * 32, md4_hashset=[],
        )],
    )
    prior = tmp_path / "prior.json"
    prior.write_text(json.dumps({"auto_browse": {"direct_bootstrap_transfers": [
        {"name": "distribution.iso", "hash": "a" * 32, "size": 123, "sha256": "d" * 64},
    ]}}), encoding="utf-8")
    output = tmp_path / "output" / "inputs.local.json"

    summary = direct_safe_corpus.prepare_corpus(source, known_met, prior, output, max_candidates=2)

    rows = json.loads(output.read_text(encoding="utf-8"))["auto_browse"]["direct_bootstrap_transfers"]
    assert summary["allowlistCount"] == 2
    assert rows[0]["hash"] == "a" * 32
    assert rows[1]["hash"] == "b" * 32
    assert len(rows[1]["sha256"]) == 64


def test_prepare_corpus_rejects_ambiguous_known_met_hash(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    document = source / "ambiguous-linux.pdf"
    document.write_bytes(b"%PDF-" + b"x" * direct_safe_corpus.MIN_CANDIDATE_BYTES)
    stat = document.stat()
    known_met = tmp_path / "known.met"
    known_met.write_bytes(b"fixture")
    monkeypatch.setattr(
        direct_safe_corpus.mfc_known_met,
        "parse_known_met",
        lambda _path: [SimpleNamespace(
            name=document.name, size_bytes=stat.st_size, modified_s=int(stat.st_mtime),
            ed2k_hash=value * 32, md4_hashset=[],
        ) for value in ("b", "d")],
    )

    assert direct_safe_corpus.matched_candidates(source, known_met) == []


def test_matched_candidates_excludes_non_linux_and_oversized_pdfs(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    files = [source / "other-topic.pdf", source / "linux-guide.pdf", source / "linux-large.pdf"]
    entries = []
    for index, path in enumerate(files):
        size = direct_safe_corpus.MAX_PDF_BYTES + 1 if index == 2 else direct_safe_corpus.MIN_CANDIDATE_BYTES
        with path.open("wb") as handle:
            handle.truncate(size)
        stat = path.stat()
        entries.append(SimpleNamespace(
            name=path.name, size_bytes=stat.st_size, modified_s=int(stat.st_mtime),
            ed2k_hash=f"{index + 1:032x}",
            md4_hashset=[b"\0" * 16] * direct_safe_corpus.mfc_known_met.expected_md4_hash_count(stat.st_size),
        ))
    known_met = tmp_path / "known.met"
    known_met.write_bytes(b"fixture")
    monkeypatch.setattr(direct_safe_corpus.mfc_known_met, "parse_known_met", lambda _path: entries)

    assert [path.name for path, _, _ in direct_safe_corpus.matched_candidates(source, known_met)] == ["linux-guide.pdf"]


def test_prepare_corpus_prefers_recent_upload_activity(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    files = [source / "linux-old.pdf", source / "linux-recent.pdf"]
    entries = []
    for index, path in enumerate(files):
        path.write_bytes(b"%PDF-" + b"x" * direct_safe_corpus.MIN_CANDIDATE_BYTES)
        stat = path.stat()
        entries.append(SimpleNamespace(
            name=path.name, size_bytes=stat.st_size, modified_s=int(stat.st_mtime),
            ed2k_hash=f"{index + 1:032x}",
            md4_hashset=[b"\0" * 16] * direct_safe_corpus.mfc_known_met.expected_md4_hash_count(stat.st_size),
            last_upload_request_ms=(index + 1) * 1000,
            all_time_upload_accepts=index + 1,
            all_time_upload_requests=index + 1,
            all_time_uploaded_bytes=index + 1,
        ))
    known_met = tmp_path / "known.met"
    known_met.write_bytes(b"fixture")
    monkeypatch.setattr(direct_safe_corpus.mfc_known_met, "parse_known_met", lambda _path: entries)
    prior = tmp_path / "prior.json"
    prior.write_text(json.dumps({"auto_browse": {"direct_bootstrap_transfers": []}}), encoding="utf-8")
    output = tmp_path / "output" / "inputs.local.json"

    summary = direct_safe_corpus.prepare_corpus(source, known_met, prior, output, max_candidates=1)

    rows = json.loads(output.read_text(encoding="utf-8"))["auto_browse"]["direct_bootstrap_transfers"]
    assert rows[0]["hash"] == f"{2:032x}"
    assert summary["selectedWithUploadActivity"] == 1
