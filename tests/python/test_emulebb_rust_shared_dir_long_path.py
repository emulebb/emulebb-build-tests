from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from emule_test_harness import rust_client


# The behavioral shared-directory coverage lives as Rust integration tests in the
# emulebb-rust workspace (crates/emulebb-core/tests). This pytest plugs those targets
# into the campaign runner via the supported `test python` command so the long-path
# and live-monitor proofs run as part of the eMuleBB Rust release campaign rather than
# only via ad-hoc `cargo test`.
RUST_INTEGRATION_TESTS = (
    "long_path_shared_dir",
    "shared_dir_monitor_e2e",
)


def workspace_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _run_rust_integration_test(repo: Path, test_target: str) -> None:
    result = subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "emulebb-core",
            "--test",
            test_target,
            "--release",
            "--",
            "--nocapture",
        ],
        cwd=repo,
        env=rust_client.rust_cargo_env(),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"cargo integration test '{test_target}' failed (exit {result.returncode}):\n"
            f"{result.stdout}\n{result.stderr}"
        )


@pytest.mark.parametrize("test_target", RUST_INTEGRATION_TESTS)
def test_emulebb_rust_shared_dir_behavioral_target(test_target: str) -> None:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not available")
    repo = workspace_root() / "repos" / "emulebb-rust"
    if not repo.is_dir():
        pytest.skip("emulebb-rust repo is not available")

    _run_rust_integration_test(repo, test_target)
