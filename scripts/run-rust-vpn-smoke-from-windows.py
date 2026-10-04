#!/usr/bin/env python3
"""Launch an isolated Rust VPN smoke through the Windows-to-WSL boundary."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def require_operator_path(name: str) -> Path:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must already be set")
    return Path(value).resolve()


def wsl_path(path: Path, distribution: str | None) -> str:
    argv = ["wsl.exe"]
    if distribution:
        argv.extend(("--distribution", distribution))
    argv.extend(("--", "wslpath", "-a", "-u", path.as_posix()))
    result = subprocess.run(argv, check=True, capture_output=True, text=True)
    translated = result.stdout.strip()
    if not translated.startswith("/"):
        raise RuntimeError(f"WSL path translation returned an invalid path for {path}")
    return translated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topology", choices=("openvpn", "gluetun"), required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--compose-override", type=Path)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-executable-sha256", required=True)
    parser.add_argument("--expected-gluetun-image", default="qmcgaw/gluetun:v3.41.3")
    parser.add_argument("--igd-url", required=True)
    parser.add_argument("--vpn-gateway")
    parser.add_argument("--allow-unsupported-nat", action="store_true")
    parser.add_argument("--skip-complete-transfer", action="store_true")
    parser.add_argument("--transfer-timeout-seconds", type=float, default=3600.0)
    parser.add_argument("--wsl-distribution")
    args = parser.parse_args(argv)

    if os.name != "nt":
        raise RuntimeError("this boundary launcher must run on Windows")
    workspace_root = require_operator_path("EMULEBB_WORKSPACE_ROOT")
    output_root = require_operator_path("EMULEBB_WORKSPACE_OUTPUT_ROOT")
    cargo_target = require_operator_path("CARGO_TARGET_DIR")
    if not workspace_root.is_dir():
        raise RuntimeError(f"EMULEBB_WORKSPACE_ROOT is missing: {workspace_root}")
    if output_root == workspace_root or output_root.is_relative_to(workspace_root):
        raise RuntimeError("EMULEBB_WORKSPACE_OUTPUT_ROOT must remain outside the workspace")
    if cargo_target == output_root or not cargo_target.is_relative_to(output_root):
        raise RuntimeError("CARGO_TARGET_DIR must remain below EMULEBB_WORKSPACE_OUTPUT_ROOT")
    required_files = [args.archive, args.compose, args.inputs]
    if args.compose_override:
        required_files.append(args.compose_override)
    for path in required_files:
        if not path.resolve().is_file():
            raise RuntimeError(f"required VPN smoke input is missing: {path}")
    if not args.private_root.resolve().is_dir():
        raise RuntimeError(f"VPN private root is missing: {args.private_root}")
    if args.topology == "gluetun" and not args.compose_override:
        raise RuntimeError("Gluetun smoke requires --compose-override")
    if args.report.exists():
        raise RuntimeError(f"refusing to overwrite VPN report: {args.report}")
    if args.transfer_timeout_seconds <= 0:
        raise RuntimeError("--transfer-timeout-seconds must be positive")
    args.report.parent.mkdir(parents=True, exist_ok=True)

    build_tests = workspace_root / "repos" / "emulebb-build-tests"
    translated = {
        "workspaceRoot": wsl_path(workspace_root, args.wsl_distribution),
        "outputRoot": wsl_path(output_root, args.wsl_distribution),
        "cargoTargetDir": wsl_path(cargo_target, args.wsl_distribution),
        "buildTests": wsl_path(build_tests, args.wsl_distribution),
        "archive": wsl_path(args.archive.resolve(), args.wsl_distribution),
        "compose": wsl_path(args.compose.resolve(), args.wsl_distribution),
        "privateRoot": wsl_path(args.private_root.resolve(), args.wsl_distribution),
        "report": wsl_path(args.report.resolve(), args.wsl_distribution),
        "inputs": wsl_path(args.inputs.resolve(), args.wsl_distribution),
    }
    if args.compose_override:
        translated["composeOverride"] = wsl_path(
            args.compose_override.resolve(), args.wsl_distribution
        )

    script = f"scripts/smoke-rust-{args.topology}.py"
    command = ["wsl.exe"]
    if args.wsl_distribution:
        command.extend(("--distribution", args.wsl_distribution))
    command.extend(
        (
            "--cd",
            translated["buildTests"],
            "--",
            "env",
            f"EMULEBB_WORKSPACE_ROOT={translated['workspaceRoot']}",
            f"EMULEBB_WORKSPACE_OUTPUT_ROOT={translated['outputRoot']}",
            f"CARGO_TARGET_DIR={translated['cargoTargetDir']}",
            "python3",
            script,
            "--archive",
            translated["archive"],
            "--compose",
            translated["compose"],
            "--private-root",
            translated["privateRoot"],
            "--report",
            translated["report"],
            "--inputs",
            translated["inputs"],
            "--image",
            args.image,
            "--expected-executable-sha256",
            args.expected_executable_sha256,
            "--nat-matrix",
            "--igd-url",
            args.igd_url,
            "--transfer-timeout-seconds",
            str(args.transfer_timeout_seconds),
        )
    )
    if not args.skip_complete_transfer:
        command.append("--complete-transfer")
    if args.vpn_gateway:
        command.extend(("--vpn-gateway", args.vpn_gateway))
    if args.allow_unsupported_nat:
        command.append("--allow-unsupported-nat")
    if args.topology == "gluetun":
        command.extend(
            (
                "--compose-override",
                translated["composeOverride"],
                "--expected-gluetun-image",
                args.expected_gluetun_image,
            )
        )

    started = datetime.now(timezone.utc)
    result = subprocess.run(command, check=False)
    run_id = started.strftime("%Y%m%dT%H%M%SZ")
    evidence_dir = output_root / "reports" / "rust-vpn-smoke-launch" / run_id
    evidence_dir.mkdir(parents=True, exist_ok=False)
    evidence_path = evidence_dir / "wsl-boundary.json"
    evidence = {
        "schema": "emulebb.rust-vpn-smoke-wsl-boundary.v1",
        "topology": args.topology,
        "startedAt": started.isoformat(),
        "exitCode": result.returncode,
        "source": {
            "workspaceRoot": str(workspace_root),
            "outputRoot": str(output_root),
            "cargoTargetDir": str(cargo_target),
        },
        "translated": translated,
        "report": str(args.report.resolve()),
    }
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"wslBoundaryEvidence": str(evidence_path), "exitCode": result.returncode}))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
