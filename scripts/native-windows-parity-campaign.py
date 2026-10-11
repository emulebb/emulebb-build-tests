"""Build and run the CI-054 native Windows Rust/MFC parity campaign."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
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
from emule_test_harness.paths import get_workspace_output_root  # noqa: E402


@dataclass(frozen=True)
class StepResult:
    name: str
    return_code: int


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

    revisions = require_clean_current_repositories()
    campaign_root = args.campaign or f"ci-054-native-{_utc_stamp()}"
    summary_dir = output_root / "soak" / "reports" / campaign_root
    summary_dir.mkdir(parents=True, exist_ok=True)
    steps: list[StepResult] = []

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

    if binaries and not any(step.return_code for step in steps):
        for case in ("upnp", "firewalled"):
            case_campaign = f"{campaign_root}-{case}"
            for client in ("rust", "mfc"):
                code = _run(
                    _capture_command(client=client, case=case, campaign=case_campaign, inputs=inputs),
                    cwd=REPO_ROOT,
                )
                steps.append(StepResult(f"capture-{case}-{client}", code))
                if code not in (0, 3):
                    break
            if all(
                step.return_code in (0, 3)
                for step in steps
                if step.name.startswith(f"capture-{case}-")
            ) and len([step for step in steps if step.name.startswith(f"capture-{case}-")]) == 2:
                code = _run(_offline_command(case_campaign), cwd=REPO_ROOT)
                steps.append(StepResult(f"offline-{case}", code))

    return_codes = [step.return_code for step in steps]
    harness_step_failed = any(
        step.return_code != 0 and step.name.startswith("fresh-build-")
        or step.return_code not in (0, 3) and step.name.startswith("capture-")
        or step.return_code == 2 and step.name.startswith("offline-")
        for step in steps
    )
    if harness_step_failed or any(code > 3 for code in return_codes):
        verdict, exit_code = "harness-failure", 2
    elif any(
        step.return_code != 0 and step.name.startswith("deterministic-")
        or step.return_code == 1 and step.name.startswith("offline-")
        for step in steps
    ):
        verdict, exit_code = "divergence", 1
    elif 3 in return_codes:
        verdict, exit_code = "inconclusive-external", 3
    else:
        verdict, exit_code = "parity", 0

    summary = {
        "schema": "native_windows_parity_campaign_v1",
        "campaign": campaign_root,
        "verdict": verdict,
        "exitCode": exit_code,
        "sourceRevisions": revisions,
        "binaryProvenance": binaries,
        "steps": [step.__dict__ for step in steps],
    }
    summary_path = summary_dir / "native-parity-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"campaign verdict: {verdict} (exit {exit_code})")
    print(f"summary: {summary_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
