from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def load_module():
    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "media-metadata-corpus-live.py"
    spec = importlib.util.spec_from_file_location("media_metadata_corpus_live_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_discover_video_files_recurses_supported_extensions(tmp_path: Path) -> None:
    module = load_module()
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    keep = nested / "sample.MKV"
    keep.write_bytes(b"video")
    skip = nested / "sample.txt"
    skip.write_text("not video", encoding="utf-8")

    assert module.discover_video_files((root,)) == [keep.resolve()]


def test_media_metadata_report_schema_uses_emulebb_namespace() -> None:
    module = load_module()

    assert module.REPORT_SCHEMA == "emulebb-build-tests.media-metadata-corpus.v1"


def test_corpus_summary_tracks_failures_and_divergences() -> None:
    module = load_module()

    summary = module.summarize_results(
        [
            {"ok": True, "extension": ".mkv", "divergenceFindings": []},
            {"ok": False, "extension": ".mp4", "divergenceFindings": ["width differs"]},
        ]
    )

    assert summary == {
        "filesCount": 2,
        "okCount": 1,
        "failureCount": 1,
        "divergenceCount": 1,
        "byExtension": {".mkv": 1, ".mp4": 1},
    }


def test_run_one_diagnostic_reads_app_variant_report(tmp_path: Path, monkeypatch) -> None:
    module = load_module()
    emule = tmp_path / "emulebb.exe"
    media = tmp_path / "sample.mp4"
    output = tmp_path / "out.json"
    emule.write_text("stub", encoding="utf-8")
    media.write_bytes(b"video")

    def fake_run(command, check, stdout, stderr, text, timeout):
        assert command[1] == "--diagnose-media-metadata"
        output.write_text(
            json.dumps(
                {
                    "ok": True,
                    "referenceVariant": "Media Foundation",
                    "variants": [{"succeeded": True}, {"succeeded": False}],
                    "divergenceFindings": [],
                }
            ),
            encoding="utf-8",
        )

        class Completed:
            returncode = 0
            stdout = ""
            stderr = ""

        return Completed()

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    result = module.run_one_diagnostic(emule, media, output, 5)

    assert result["ok"] is True
    assert result["variantSuccessCount"] == 1
    assert result["referenceVariant"] == "Media Foundation"
