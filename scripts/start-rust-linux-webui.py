"""Start or stop a detached WSL/Linux emulebb-rust WebUI-only profile."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.paths import get_workspace_output_root
from emule_test_harness.rust_client import write_rust_profile

REST_ADDR = "127.0.0.1"
REST_PORT = 4731
API_KEY = "beta-webui"


def manifest_path(output_root: Path) -> Path:
    return output_root / "profiles" / "rust-linux-webui" / "latest.json"


def stop(output_root: Path) -> int:
    path = manifest_path(output_root)
    if not path.is_file():
        print("No Linux WebUI launch manifest exists.")
        return 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    pid = int(payload.get("pid") or 0)
    if pid > 0:
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    path.unlink(missing_ok=True)
    print(f"Stopped Linux WebUI daemon pid={pid}.")
    return 0


def wait_ready(url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 30.0
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"emulebb-rust exited early with code {process.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=3.0) as response:
                if response.status == 200 and b'<div id="app"></div>' in response.read():
                    return
        except OSError as error:
            last_error = error
        time.sleep(0.5)
    raise RuntimeError(f"WebUI did not become ready: {last_error}")


def start(output_root: Path, workspace_root: Path) -> int:
    latest = manifest_path(output_root)
    if latest.is_file():
        payload = json.loads(latest.read_text(encoding="utf-8"))
        try:
            with urllib.request.urlopen(str(payload["url"]), timeout=2.0) as response:
                if response.status == 200:
                    print(json.dumps(payload, sort_keys=True))
                    return 0
        except OSError:
            latest.unlink(missing_ok=True)

    executable = output_root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust"
    rust_repo = workspace_root / "repos" / "emulebb-rust"
    if not executable.is_file():
        raise RuntimeError(f"staged Linux daemon is missing: {executable}")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    profile_dir = output_root / "profiles" / "rust-linux-webui" / stamp
    log_path = profile_dir / "daemon.log"
    profile_dir.mkdir(parents=True, exist_ok=True)
    write_rust_profile(
        profile_dir,
        rust_repo=rust_repo,
        rest_addr=REST_ADDR,
        rest_port=REST_PORT,
        api_key=API_KEY,
        initial_shared_directory_reload=False,
        vpn_guard_mode="off",
    )
    log_handle = log_path.open("wb", buffering=0)
    process = subprocess.Popen(
        [str(executable), "--profile", str(profile_dir)],
        cwd=executable.parent,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    log_handle.close()
    url = f"http://{REST_ADDR}:{REST_PORT}/"
    wait_ready(url, process)
    payload = {
        "schema": "emulebb.rust-linux-webui-launch.v1",
        "pid": process.pid,
        "url": url,
        "apiKey": API_KEY,
        "profile": str(profile_dir),
        "log": str(log_path),
        "networkStarted": False,
        "sharedRootCount": 0,
    }
    latest.parent.mkdir(parents=True, exist_ok=True)
    latest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(payload, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stop", action="store_true")
    args = parser.parse_args(argv)
    workspace_value = os.environ.get("EMULEBB_WORKSPACE_ROOT", "").strip()
    if not workspace_value:
        raise RuntimeError("EMULEBB_WORKSPACE_ROOT must already be set.")
    output_root = get_workspace_output_root()
    return stop(output_root) if args.stop else start(output_root, Path(workspace_value).resolve())


if __name__ == "__main__":
    raise SystemExit(main())
