from __future__ import annotations

import json
from pathlib import Path
from urllib.error import HTTPError

import pytest

from emule_test_harness import rust_consumer_live


def write_inputs(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        json.dumps({"auto_browse": {"direct_bootstrap_transfers": rows}}),
        encoding="utf-8",
    )


def transfer_row(*, name: str, size: int, digit: str) -> dict[str, object]:
    return {
        "name": name,
        "size": size,
        "hash": digit * 32,
        "sha256": digit * 64,
    }


def test_load_consumer_transfer_selects_smallest_exact_pdf_and_rejects_iso(tmp_path: Path) -> None:
    inputs = tmp_path / "live-wire-inputs.local.json"
    write_inputs(
        inputs,
        [
            transfer_row(name="larger.iso", size=2048, digit="b"),
            transfer_row(name="small.pdf", size=1024, digit="a"),
            transfer_row(name="ignored.zip", size=1, digit="c"),
        ],
    )

    selected = rust_consumer_live.load_consumer_transfer(inputs, 4096)

    assert selected == {
        "name": "small.pdf",
        "hash": "a" * 32,
        "sha256": "a" * 64,
        "size": 1024,
        "suffix": ".pdf",
    }


def test_load_consumer_transfer_requires_bounded_pdf_allowlist_entry(tmp_path: Path) -> None:
    inputs = tmp_path / "live-wire-inputs.local.json"
    write_inputs(inputs, [transfer_row(name="too-large.iso", size=4097, digit="a")])

    with pytest.raises(RuntimeError, match="exact eD2K hash and size"):
        rust_consumer_live.load_consumer_transfer(inputs, 4096)


def test_completion_mode_requires_sha256_but_trigger_mode_does_not(tmp_path: Path) -> None:
    inputs = tmp_path / "rust-consumer-pdf.local.json"
    row = transfer_row(name="guide.pdf", size=1024, digit="a")
    row.pop("sha256")
    write_inputs(inputs, [row])

    assert rust_consumer_live.load_consumer_transfer(inputs, 4096)["name"] == "guide.pdf"
    with pytest.raises(RuntimeError, match="plus SHA-256 for completion mode"):
        rust_consumer_live.load_consumer_transfer(inputs, 4096, require_sha256=True)


def test_parser_requires_explicit_runtime_search_term() -> None:
    parser = rust_consumer_live.build_parser()

    args = parser.parse_args(
        [
            "--release-zip",
            "release.zip",
            "--inputs",
            "live-wire-inputs.local.json",
            "--search-term",
            "linux",
        ]
    )

    assert args.search_term == "linux"
    assert args.complete_transfer is False
    assert args.max_transfer_bytes == 5 * 1024 * 1024 - 1
    assert args.max_completion_bytes == 5 * 1024 * 1024 - 1


def test_verify_extracted_payload_rejects_extra_files(tmp_path: Path) -> None:
    root = tmp_path / "package"
    root.mkdir()
    (root / "expected.txt").write_text("expected", encoding="utf-8")
    (root / "extra.txt").write_text("extra", encoding="utf-8")
    manifest = {
        "perFileSha256": {
            "expected.txt": rust_consumer_live.sha256_file(root / "expected.txt"),
        }
    }

    with pytest.raises(RuntimeError, match="file set"):
        rust_consumer_live.verify_extracted_payload(root, manifest)


def test_persist_consumer_report_rewrites_post_run_recovery_fields(tmp_path: Path) -> None:
    path = tmp_path / "run" / "rust-consumer-live-result.json"
    report = {"runId": "test-run", "status": "passed"}
    rust_consumer_live.persist_consumer_report(path, report)

    report["operatorDaemonRestored"] = True
    rust_consumer_live.persist_consumer_report(path, report)

    assert json.loads(path.read_text(encoding="utf-8")) == report


def test_persistence_snapshot_reports_webui_deleted_transfer(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_api_data(_base_url: str, path: str, _api_key: str):
        if path == "searches":
            return {"items": [{"id": "1"}, {"id": "2"}, {"id": "3"}]}
        raise HTTPError("http://127.0.0.1/transfers/redacted", 404, "not found", None, None)

    monkeypatch.setattr(rust_consumer_live, "api_data", fake_api_data)

    assert rust_consumer_live._persistence_snapshot("http://127.0.0.1", "key", "redacted") == {
        "searchCount": 3,
        "transferPresent": False,
        "transferCompleted": False,
        "transferState": "deleted",
    }
