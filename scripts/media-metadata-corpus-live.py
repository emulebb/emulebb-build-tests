"""Runs eMuleBB media metadata extractor comparisons over local video roots."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import live_wire_inputs  # noqa: E402
from emule_test_harness.artifact_names import utc_run_id  # noqa: E402
from emule_test_harness.paths import get_test_reports_root, reject_windows_temp_path  # noqa: E402

VIDEO_EXTENSIONS = {
    ".avi",
    ".m2ts",
    ".m4v",
    ".mkv",
    ".mov",
    ".mp4",
    ".mpeg",
    ".mpg",
    ".ts",
    ".webm",
    ".wmv",
}


def build_parser() -> argparse.ArgumentParser:
    """Builds the local media corpus diagnostic CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-wire-inputs-file", default=str(live_wire_inputs.get_default_inputs_path(REPO_ROOT)))
    parser.add_argument("--emule-exe", type=Path)
    parser.add_argument("--report-root", type=Path, default=get_test_reports_root(WORKSPACE_ROOT / "workspaces" / "workspace") / "media-metadata-corpus-live")
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--fail-fast", action="store_true")
    return parser


def default_emule_exe() -> Path:
    """Returns the default release app binary used by live corpus diagnostics."""

    return WORKSPACE_ROOT / "workspaces" / "workspace" / "app" / "eMule-main" / "srchybrid" / "x64" / "Release" / "emulebb.exe"


def path_id(path: Path) -> str:
    """Returns a stable redacted identifier for one local media path."""

    return hashlib.sha256(str(path).lower().encode("utf-8", errors="replace")).hexdigest()[:16]


def discover_video_files(roots: tuple[Path, ...]) -> list[Path]:
    """Recursively discovers video files from existing operator-owned roots."""

    files: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in VIDEO_EXTENSIONS:
                files.append(path.resolve())
    return sorted(set(files), key=lambda item: str(item).lower())


def variant_success_count(report: dict[str, Any]) -> int:
    """Returns how many extractor variants succeeded in one diagnostic report."""

    variants = report.get("variants")
    if not isinstance(variants, list):
        return 0
    return sum(1 for variant in variants if isinstance(variant, dict) and variant.get("succeeded") is True)


def run_one_diagnostic(emule_exe: Path, file_path: Path, output_path: Path, timeout_seconds: int) -> dict[str, Any]:
    """Runs the app's headless metadata diagnostic command for one file."""

    command = [
        str(emule_exe),
        "--diagnose-media-metadata",
        "--input",
        str(file_path),
        "--output",
        str(output_path),
    ]
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_seconds,
    )
    result: dict[str, Any] = {
        "id": path_id(file_path),
        "extension": file_path.suffix.lower(),
        "sizeBytes": file_path.stat().st_size,
        "exitCode": completed.returncode,
        "stdoutTail": completed.stdout[-2000:],
        "stderrTail": completed.stderr[-2000:],
        "reportPath": str(output_path),
    }
    if output_path.is_file():
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        result["variantSuccessCount"] = variant_success_count(payload)
        result["referenceVariant"] = payload.get("referenceVariant")
        result["divergenceFindings"] = payload.get("divergenceFindings", [])
        result["ok"] = completed.returncode == 0 and bool(payload.get("ok"))
    else:
        result["variantSuccessCount"] = 0
        result["divergenceFindings"] = []
        result["ok"] = False
    return result


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Builds a compact success/divergence summary for the corpus run."""

    failures = [item for item in results if item.get("ok") is not True]
    divergences = [item for item in results if item.get("divergenceFindings")]
    by_extension: dict[str, int] = {}
    for item in results:
        extension = str(item.get("extension") or "")
        by_extension[extension] = by_extension.get(extension, 0) + 1
    return {
        "filesCount": len(results),
        "okCount": len(results) - len(failures),
        "failureCount": len(failures),
        "divergenceCount": len(divergences),
        "byExtension": dict(sorted(by_extension.items())),
    }


def run(args: argparse.Namespace) -> int:
    """Runs the full local media metadata corpus diagnostic campaign."""

    inputs = live_wire_inputs.load_live_wire_inputs(
        live_wire_inputs.resolve_inputs_path(REPO_ROOT, args.live_wire_inputs_file)
    )
    if not inputs.video_roots:
        raise RuntimeError("live-wire inputs media_corpus.video_roots is empty")
    emule_exe = (args.emule_exe or default_emule_exe()).resolve()
    if not emule_exe.is_file():
        raise RuntimeError(f"eMule executable is missing: {emule_exe}")

    report_root = args.report_root.resolve()
    reject_windows_temp_path(report_root, "report root")
    run_dir = report_root / utc_run_id()
    detail_dir = run_dir / "files"
    detail_dir.mkdir(parents=True, exist_ok=True)
    latest_dir = report_root / "latest"
    files = discover_video_files(inputs.video_roots)
    if not files:
        raise RuntimeError("No video files were discovered in media_corpus.video_roots")

    results: list[dict[str, Any]] = []
    for index, file_path in enumerate(files, start=1):
        output_path = detail_dir / f"{index:06d}-{path_id(file_path)}.json"
        try:
            result = run_one_diagnostic(emule_exe, file_path, output_path, args.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            result = {
                "id": path_id(file_path),
                "extension": file_path.suffix.lower(),
                "sizeBytes": file_path.stat().st_size,
                "exitCode": None,
                "timedOut": True,
                "timeoutSeconds": args.timeout_seconds,
                "stdoutTail": (exc.stdout or "")[-2000:] if isinstance(exc.stdout, str) else "",
                "stderrTail": (exc.stderr or "")[-2000:] if isinstance(exc.stderr, str) else "",
                "variantSuccessCount": 0,
                "divergenceFindings": [],
                "ok": False,
            }
        results.append(result)
        if args.fail_fast and result.get("ok") is not True:
            break

    report = {
        "schema": "emule-build-tests.media-metadata-corpus.v1",
        "createdUtc": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "liveWireInputs": {
            "path": str(inputs.path),
            "videoRoots": live_wire_inputs.summarize_paths(inputs.video_roots),
        },
        "emuleExe": str(emule_exe),
        "summary": summarize_results(results),
        "results": results,
    }
    summary_path = run_dir / "media-metadata-corpus-live-summary.json"
    summary_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if latest_dir.exists():
        shutil.rmtree(latest_dir)
    shutil.copytree(run_dir, latest_dir)
    print(f"[media-metadata] Report: {summary_path}")
    print(json.dumps(report["summary"], indent=2))
    return 0 if report["summary"]["failureCount"] == 0 else 1


def main() -> int:
    """Entrypoint for the media metadata corpus live diagnostic."""

    return run(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
