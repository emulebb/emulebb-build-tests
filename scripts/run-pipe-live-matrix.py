"""Runs the recommended named-pipe live matrix and soak profile."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent


def build_parser() -> argparse.ArgumentParser:
    """Builds the pipe live matrix CLI parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emule-workspace-root", default="")
    parser.add_argument("--app-root", default="")
    parser.add_argument("--profile-root", type=Path)
    parser.add_argument("--seed-root", default="")
    parser.add_argument("--session-manifest-path", default="")
    parser.add_argument("--search-query", default="1080p")
    parser.add_argument("--stress-query", dest="stress_queries", action="append")
    parser.add_argument("--scenario-profile", choices=("balanced", "matrix", "soak"), default="balanced")
    parser.add_argument("--matrix-repeat-count", type=int, default=1)
    parser.add_argument("--bind-interface-name", default="hide.me")
    parser.add_argument("--helper-path", type=Path)
    parser.add_argument("--launch-only", action="store_true")
    parser.add_argument("--strict-matrix", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    return parser


def resolve_helper_path(explicit_helper_path: Path | None) -> Path:
    """Resolves the workspace-owned pipe live helper path."""

    if explicit_helper_path is not None:
        return explicit_helper_path.resolve()
    candidates = (
        (REPO_ROOT / ".." / "eMule-tooling" / "helpers" / "helper-runtime-pipe-live-session.ps1").resolve(),
        (REPO_ROOT / ".." / "eMule-build" / "eMule" / "helpers" / "helper-runtime-pipe-live-session.ps1").resolve(),
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError(f"Pipe live helper was not found. Checked: {', '.join(str(path) for path in candidates)}")


def find_powershell_executable() -> str:
    """Returns the PowerShell executable used for the external tooling helper."""

    for candidate in ("pwsh.exe", "pwsh"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise RuntimeError("pwsh was not found on PATH; the external pipe live helper still requires PowerShell.")


def build_helper_command(args: argparse.Namespace, helper_path: Path) -> tuple[str, ...]:
    """Builds the external helper command with the retained live-matrix defaults."""

    stress_queries = tuple(args.stress_queries or ("1080p x265", "1080p bluray"))
    profile_root = args.profile_root or (REPO_ROOT / "reports" / "live-profiles")
    command = [
        find_powershell_executable(),
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(helper_path),
        "-EmuleWorkspaceRoot",
        args.emule_workspace_root,
        "-AppRoot",
        args.app_root,
        "-ProfileRoot",
        str(profile_root),
        "-SeedRoot",
        args.seed_root,
        "-SessionManifestPath",
        args.session_manifest_path,
        "-BindInterfaceName",
        args.bind_interface_name,
        "-SearchQuery",
        args.search_query,
        "-StressQueries",
        *stress_queries,
        "-ScenarioProfile",
        args.scenario_profile,
        "-MatrixRepeatCount",
        str(args.matrix_repeat_count),
        "-SearchWaitSec",
        "30",
        "-SearchCycleCount",
        "2",
        "-SearchCyclePauseSec",
        "5",
        "-MonitorSec",
        "180",
        "-PollSec",
        "5",
        "-TransferProbeCount",
        "2",
        "-UploadProbeCount",
        "1",
        "-ExtraStatsBurstsPerPoll",
        "1",
        "-TransferChurnCycles",
        "6",
        "-TransfersPerChurnCycle",
        "3",
        "-TransferChurnPauseMs",
        "500",
        "-PipeWarmupSec",
        "12",
    ]
    for flag_name, enabled in (
        ("-LaunchOnly", args.launch_only),
        ("-StrictMatrix", args.strict_matrix),
        ("-SkipBuild", args.skip_build),
        ("-KeepRunning", args.keep_running),
    ):
        if enabled:
            command.append(flag_name)
    return tuple(command)


def main(argv: list[str] | None = None) -> int:
    """Runs the pipe live matrix wrapper."""

    args = build_parser().parse_args(argv)
    helper_path = resolve_helper_path(args.helper_path)
    completed = subprocess.run(build_helper_command(args, helper_path), check=False)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
