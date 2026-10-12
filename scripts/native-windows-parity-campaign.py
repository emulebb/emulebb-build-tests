"""Build and run the CI-054 native Windows Rust/MFC parity campaign."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
WORKSPACE_ROOT = REPO_ROOT.parent.parent
BUILD_REPO = WORKSPACE_ROOT / "repos" / "emulebb-build"
RUST_REPO = WORKSPACE_ROOT / "repos" / "emulebb-rust"
MFC_REPO = WORKSPACE_ROOT / "workspaces" / "workspace" / "app" / "emulebb-main"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import converged_live_wire as clw  # noqa: E402
from emule_test_harness.native_parity_inputs import (  # noqa: E402
    load_ed2k_link_fixture,
    load_native_parity_config,
)
from emule_test_harness.paths import get_workspace_output_root  # noqa: E402


@dataclass(frozen=True)
class StepResult:
    name: str
    return_code: int


@dataclass(frozen=True)
class FixturePin:
    """Stable private identity of the operator-local download fixture."""

    count: int
    content_digest: str


@dataclass(frozen=True)
class CompletionSet:
    """Private completed-file identities from one client/connectivity recording."""

    expected_count: int
    files: tuple[tuple[str, int, str], ...]


class IncompleteCompletionEvidence(RuntimeError):
    """The recording is valid but did not complete every pinned fixture."""


REQUIRED_COMPLETION_RECORDINGS = frozenset(
    {"upnp-rust", "upnp-mfc", "firewalled-rust", "firewalled-mfc"}
)
CAPTURE_CONTINUE_CODES = frozenset({0, 1, 3})
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ED2K_RE = re.compile(r"^[0-9a-f]{32}$")


def _utc_stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def build_commands(python: str = sys.executable) -> tuple[tuple[str, ...], ...]:
    common = ("--platform", "x64", "--build-output-mode", "ErrorsOnly")
    return (
        (
            python, "-m", "emule_workspace", "build", "clients", "--client", "emulebb-rust",
            "--config", "Release", *common, "--clean",
        ),
        (
            python, "-m", "emule_workspace", "build", "clients", "--client", "emulebb-rust",
            "--config", "Release", *common, "--diagnostics",
        ),
        (
            python, "-m", "emule_workspace", "build", "app", "--variant", "main",
            "--config", "Debug", *common, "--clean",
        ),
        (
            python, "-m", "emule_workspace", "build", "app", "--variant", "main",
            "--config", "Release", *common, "--clean",
        ),
        (
            python, "-m", "emule_workspace", "build", "app", "--variant", "main",
            "--config", "Release", *common, "--diagnostics", "--clean",
        ),
    )


def _run(command: Sequence[str], *, cwd: Path) -> int:
    return subprocess.run(tuple(command), cwd=cwd, check=False).returncode


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", *args), cwd=repo, check=True, capture_output=True, text=True
    )
    return completed.stdout.strip()


def require_clean_current_repositories() -> dict[str, str]:
    repositories = {
        "build_tests": REPO_ROOT,
        "rust": RUST_REPO,
        "build": BUILD_REPO,
        "mfc": MFC_REPO,
    }
    revisions: dict[str, str] = {}
    for name, repo in repositories.items():
        _git(repo, "fetch", "--prune")
        if _git(repo, "status", "--porcelain"):
            raise RuntimeError(f"Campaign repository {name} has uncommitted changes.")
        try:
            behind = int(_git(repo, "rev-list", "--count", "HEAD..@{upstream}"))
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"Campaign repository {name} has no usable upstream.") from exc
        if behind:
            raise RuntimeError(f"Campaign repository {name} is behind its upstream.")
        revisions[name] = _git(repo, "rev-parse", "HEAD")
    return revisions


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pin_download_fixture(inputs_path: Path) -> FixturePin:
    """Load and fingerprint the fixture while rejecting a concurrent rewrite."""

    fixture_path = load_native_parity_config(inputs_path).ed2k_links_file
    before = fixture_path.stat()
    fixtures = load_ed2k_link_fixture(fixture_path)
    content_digest = _sha256(fixture_path)
    after = fixture_path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RuntimeError("The operator-local download fixture changed while it was pinned.")
    return FixturePin(count=len(fixtures), content_digest=content_digest)


def _new_recording(
    campaign_dir: Path,
    client: str,
    previous: set[Path],
) -> Path:
    current = set(campaign_dir.glob(f"{client}-*.zip"))
    created = current - previous
    if len(created) != 1:
        raise RuntimeError("The capture did not create exactly one new recording archive.")
    return created.pop()


def load_completion_set(recording: Path, expected_count: int) -> CompletionSet:
    """Read private completion identities without returning them in campaign output."""

    with zipfile.ZipFile(recording) as archive:
        names = [name for name in archive.namelist() if name.casefold().endswith("results.json")]
        if len(names) != 1:
            raise RuntimeError("The recording does not contain exactly one results document.")
    private_path = (
        recording.with_name(f"{recording.stem}-downloaded-payloads")
        / "completion-private.json"
    )
    if not private_path.is_file():
        raise RuntimeError("The recording is missing its private completion sidecar.")
    section = json.loads(private_path.read_text(encoding="utf-8"))
    if not isinstance(section, dict) or section.get("required") is not True:
        raise RuntimeError("The recording did not opt in to native completion evidence.")
    if section.get("expectedCount") != expected_count:
        raise RuntimeError("The recording completion count does not match the pinned fixture.")
    rows = section.get("files")
    if not isinstance(rows, list) or len(rows) != expected_count:
        raise IncompleteCompletionEvidence(
            "The recording does not contain every required completion."
        )

    files: list[tuple[str, int, str]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("The recording contains malformed completion evidence.")
        action_id = str(row.get("actionId") or "")
        size_bytes = row.get("sizeBytes")
        ed2k_hash = str(row.get("ed2kHash") or "").casefold()
        sha256 = str(row.get("sha256") or "").casefold()
        if (
            not action_id
            or action_id in seen
            or row.get("status") != "verified"
            or row.get("sizeVerified") is not True
            or row.get("ed2kVerified") is not True
            or not isinstance(size_bytes, int)
            or isinstance(size_bytes, bool)
            or size_bytes <= 0
            or ED2K_RE.fullmatch(ed2k_hash) is None
            or SHA256_RE.fullmatch(sha256) is None
        ):
            raise RuntimeError("The recording contains malformed completion evidence.")
        seen.add(action_id)
        files.append((action_id, size_bytes, sha256))
    return CompletionSet(expected_count=expected_count, files=tuple(sorted(files)))


def compare_cross_case_completions(
    completion_sets: dict[str, CompletionSet], expected_count: int
) -> dict[str, object]:
    """Require four equivalent completion sets while emitting no content digests."""

    findings: list[str] = []
    if set(completion_sets) != REQUIRED_COMPLETION_RECORDINGS:
        findings.append("completion-recordings-missing")
    structurally_complete = not findings
    if structurally_complete and any(
        completion.expected_count != expected_count
        or len(completion.files) != expected_count
        for completion in completion_sets.values()
    ):
        findings.append("completion-count-mismatch")
        structurally_complete = False

    equivalent = False
    if structurally_complete:
        values = list(completion_sets.values())
        equivalent = all(completion.files == values[0].files for completion in values[1:])
        if not equivalent:
            findings.append("completion-set-mismatch")
    return {
        "complete": structurally_complete,
        "equivalent": equivalent,
        "expectedFileCount": expected_count,
        "recordingCount": len(completion_sets),
        "findings": findings,
    }


def adjudicate_campaign(
    steps: list[StepResult],
    completion_acceptance: dict[str, object],
    *,
    fixture_unchanged: bool,
) -> tuple[str, int]:
    """Reduce stage results with fixture/completion acceptance as hard gates."""

    return_codes = [step.return_code for step in steps]
    harness_step_failed = any(
        step.return_code != 0 and step.name.startswith("fresh-build-")
        or step.return_code == 2 and step.name.startswith("capture-")
        or step.return_code == 2 and step.name.startswith("offline-")
        or step.return_code != 0 and step.name.startswith("fixture-pin-")
        or step.return_code != 0 and step.name.startswith("completion-evidence-")
        for step in steps
    )
    if (
        harness_step_failed
        or any(code > 3 for code in return_codes)
        or not fixture_unchanged
    ):
        return "harness-failure", 2
    if any(
        step.return_code != 0 and step.name.startswith("deterministic-")
        for step in steps
    ):
        return "divergence", 1
    capture_divergence = any(
        step.return_code == 1 and step.name.startswith("capture-") for step in steps
    )
    if completion_acceptance.get("complete") is not True:
        if capture_divergence:
            return "divergence", 1
        if 3 in return_codes:
            return "inconclusive-external", 3
        return "harness-failure", 2
    if completion_acceptance.get("equivalent") is not True:
        return "divergence", 1
    if any(
        step.return_code != 0 and step.name.startswith("deterministic-")
        or step.return_code == 1 and step.name.startswith("offline-")
        or step.return_code == 1 and step.name.startswith("capture-")
        for step in steps
    ):
        return "divergence", 1
    if 3 in return_codes:
        return "inconclusive-external", 3
    return "parity", 0


def collect_binary_provenance(output_root: Path) -> dict[str, dict[str, object]]:
    binaries = {
        "rust_regular_release": clw.resolve_rust_regular_exe(output_root),
        "rust_diagnostics_release": clw.resolve_rust_diagnostics_exe(output_root),
        "mfc_debug": output_root / "builds/app/main/x64/Debug/standard/bin/emulebb.exe",
        "mfc_regular_release": output_root / "builds/app/main/x64/Release/standard/bin/emulebb.exe",
        "mfc_diagnostics_release": clw.resolve_mfc_diagnostics_exe(output_root),
    }
    provenance: dict[str, dict[str, object]] = {}
    for name, path in binaries.items():
        if not path.is_file():
            raise RuntimeError(f"Fresh build did not stage required binary {name}.")
        provenance[name] = {
            "path": str(path),
            "sizeBytes": path.stat().st_size,
            "sha256": _sha256(path),
        }
    return provenance


def sanitized_binary_provenance(
    provenance: dict[str, dict[str, object]], output_root: Path
) -> dict[str, dict[str, object]]:
    """Remove absolute operator paths while retaining reproducible binary identity."""

    sanitized: dict[str, dict[str, object]] = {}
    for role, row in provenance.items():
        path = Path(str(row["path"])).resolve()
        try:
            staged_path = str(path.relative_to(output_root.resolve()))
        except ValueError as exc:
            raise RuntimeError("A staged binary is outside the workspace output root.") from exc
        sanitized[role] = {
            "stagedPath": staged_path,
            "sizeBytes": row["sizeBytes"],
            "sha256": row["sha256"],
        }
    return sanitized


def deterministic_commands(local_address: str, mfc_diagnostics: Path) -> tuple[tuple[str, ...], ...]:
    return (
        (sys.executable, str(REPO_ROOT / "scripts/validate-protocol-goldens.py")),
        (
            sys.executable,
            str(REPO_ROOT / "scripts/stock-protocol-oracle-proof.py"),
            "--execute-rust-proofs",
        ),
        (
            sys.executable,
            str(REPO_ROOT / "scripts/local-ed2k-protocol-combinations.py"),
            "--lan-bind-addr", local_address,
            "--p2p-bind-interface-address", local_address,
            "--app-exe", str(mfc_diagnostics),
            "--client2-app-exe", str(mfc_diagnostics),
        ),
        (
            sys.executable,
            str(REPO_ROOT / "scripts/local-ed2k-rust-protocol-combinations.py"),
            "--diagnostics",
            "--lan-bind-addr", local_address,
            "--p2p-bind-interface-address", local_address,
            "--app-exe", str(mfc_diagnostics),
            "--client2-app-exe", str(mfc_diagnostics),
        ),
    )


def _capture_command(*, client: str, case: str, campaign: str, inputs: Path) -> tuple[str, ...]:
    return (
        sys.executable,
        str(REPO_ROOT / "scripts/soak-scripted-capture.py"),
        "--client", client,
        "--route", "direct",
        "--connectivity", case,
        "--campaign", campaign,
        "--inputs", str(inputs),
        "--fresh-profile",
    )


def _offline_command(campaign: str) -> tuple[str, ...]:
    return (
        sys.executable,
        str(REPO_ROOT / "scripts/soak-offline-diff.py"),
        "--campaign", campaign,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, default=REPO_ROOT / "live-wire-inputs.local.json")
    parser.add_argument("--campaign", default=None)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-deterministic", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    local_address = os.environ.get("X_LOCAL_IP", "").strip()
    if not local_address:
        raise RuntimeError("X_LOCAL_IP must be inherited for the native campaign.")
    output_root = get_workspace_output_root()
    inputs = args.inputs.resolve()
    if not inputs.is_file():
        raise RuntimeError("The ignored native campaign input file is missing.")

    fixture_pin = pin_download_fixture(inputs)
    revisions = require_clean_current_repositories()
    campaign_root = args.campaign or f"ci-054-native-{_utc_stamp()}"
    summary_dir = output_root / "soak" / "reports" / campaign_root
    summary_dir.mkdir(parents=True, exist_ok=True)
    steps: list[StepResult] = []
    completion_sets: dict[str, CompletionSet] = {}
    fixture_unchanged = True

    if not args.skip_build:
        for index, command in enumerate(build_commands(), start=1):
            code = _run(command, cwd=BUILD_REPO)
            steps.append(StepResult(f"fresh-build-{index}", code))
            if code != 0:
                break

    binaries = (
        collect_binary_provenance(output_root)
        if not any(step.return_code for step in steps)
        else {}
    )
    if binaries and not args.skip_deterministic:
        mfc_diagnostics = Path(str(binaries["mfc_diagnostics_release"]["path"]))
        for index, command in enumerate(
            deterministic_commands(local_address, mfc_diagnostics), start=1
        ):
            code = _run(command, cwd=REPO_ROOT)
            steps.append(StepResult(f"deterministic-{index}", code))
            if code != 0:
                break

    abort_live_matrix = False
    if binaries and not any(step.return_code for step in steps):
        for case in ("upnp", "firewalled"):
            case_campaign = f"{campaign_root}-{case}"
            case_dir = output_root / "soak" / "reports" / case_campaign
            for client in ("rust", "mfc"):
                try:
                    if pin_download_fixture(inputs) != fixture_pin:
                        raise RuntimeError("fixture pin changed")
                except (OSError, RuntimeError):
                    fixture_unchanged = False
                    steps.append(StepResult(f"fixture-pin-{case}-{client}", 2))
                    abort_live_matrix = True
                    break
                previous_recordings = set(case_dir.glob(f"{client}-*.zip"))
                code = _run(
                    _capture_command(client=client, case=case, campaign=case_campaign, inputs=inputs),
                    cwd=REPO_ROOT,
                )
                steps.append(StepResult(f"capture-{case}-{client}", code))
                if code in CAPTURE_CONTINUE_CODES:
                    try:
                        recording = _new_recording(case_dir, client, previous_recordings)
                        try:
                            completion_sets[f"{case}-{client}"] = load_completion_set(
                                recording, fixture_pin.count
                            )
                        except IncompleteCompletionEvidence:
                            if code not in (1, 3):
                                raise
                    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, json.JSONDecodeError):
                        steps.append(StepResult(f"completion-evidence-{case}-{client}", 2))
                        abort_live_matrix = True
                        break
                if code not in CAPTURE_CONTINUE_CODES:
                    abort_live_matrix = True
                    break
            if abort_live_matrix:
                break
            if all(
                step.return_code in CAPTURE_CONTINUE_CODES
                for step in steps
                if step.name.startswith(f"capture-{case}-")
            ) and len([step for step in steps if step.name.startswith(f"capture-{case}-")]) == 2:
                code = _run(_offline_command(case_campaign), cwd=REPO_ROOT)
                steps.append(StepResult(f"offline-{case}", code))

    try:
        fixture_unchanged = fixture_unchanged and pin_download_fixture(inputs) == fixture_pin
    except (OSError, RuntimeError):
        fixture_unchanged = False
    if not fixture_unchanged and not any(step.name.startswith("fixture-pin-") for step in steps):
        steps.append(StepResult("fixture-pin-final", 2))

    completion_acceptance = compare_cross_case_completions(
        completion_sets, fixture_pin.count
    )
    verdict, exit_code = adjudicate_campaign(
        steps,
        completion_acceptance,
        fixture_unchanged=fixture_unchanged,
    )

    summary = {
        "schema": "native_windows_parity_campaign_v1",
        "campaign": campaign_root,
        "verdict": verdict,
        "exitCode": exit_code,
        "sourceRevisions": revisions,
        "binaryProvenance": sanitized_binary_provenance(binaries, output_root),
        "fixturePin": {
            "fileCount": fixture_pin.count,
            "unchanged": fixture_unchanged,
        },
        "completionAcceptance": completion_acceptance,
        "steps": [step.__dict__ for step in steps],
    }
    summary_path = summary_dir / "native-parity-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"campaign verdict: {verdict} (exit {exit_code})")
    print(f"summary: {summary_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
