from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from emule_test_harness import bounded_process_output as output


def retained_bytes(path: Path, retained_segments: int) -> bytes:
    chunks = [
        output.rotated_path(path, index).read_bytes()
        for index in range(retained_segments - 1, 0, -1)
        if output.rotated_path(path, index).is_file()
    ]
    if path.is_file():
        chunks.append(path.read_bytes())
    return b"".join(chunks)


def test_rotating_binary_log_preserves_exact_bytes_with_hard_bounds(tmp_path: Path) -> None:
    path = tmp_path / "process.stdout.log"
    payload = bytes(range(26))

    with output.RotatingBinaryLog(path, max_segment_bytes=10, retained_segments=3) as log:
        log.write(payload)

    assert retained_bytes(path, 3) == payload
    assert sorted(item.stat().st_size for item in tmp_path.iterdir()) == [6, 10, 10]


def test_rotating_binary_log_starts_a_new_run_and_prunes_invalid_generations(tmp_path: Path) -> None:
    path = tmp_path / "process.stdout.log"
    path.write_bytes(b"previous")
    output.rotated_path(path, 1).write_bytes(b"x" * 11)
    output.rotated_path(path, 3).write_bytes(b"expired")

    with output.RotatingBinaryLog(path, max_segment_bytes=10, retained_segments=3) as log:
        log.write(b"current")

    assert path.read_bytes() == b"current"
    assert output.rotated_path(path, 1).read_bytes() == b"previous"
    assert not output.rotated_path(path, 2).exists()
    assert not output.rotated_path(path, 3).exists()


def test_run_bounded_process_captures_both_streams_and_exit_code(tmp_path: Path) -> None:
    stdout_path = tmp_path / "stdout.log"
    stderr_path = tmp_path / "stderr.log"
    command = [
        sys.executable,
        "-c",
        "import os; os.write(1, b'raw-out\\x00'); os.write(2, b'raw-err\\xff'); raise SystemExit(7)",
    ]

    result = output.run_bounded_process(
        command,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        max_segment_bytes=64,
        retained_segments=2,
    )

    assert result == 7
    assert stdout_path.read_bytes() == b"raw-out\x00"
    assert stderr_path.read_bytes() == b"raw-err\xff"


def test_async_binary_capture_preserves_real_process_and_exact_merged_bytes(tmp_path: Path) -> None:
    path = tmp_path / "daemon.out"
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import os; os.write(1,b'out\\x00'); os.write(2,b'err\\xff')",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert process.stdout is not None
    capture = output.AsyncBinaryCapture(
        path,
        max_segment_bytes=6,
        retained_segments=2,
    )
    stopped: list[int] = []
    capture.start(process.stdout, stop_process=lambda: stopped.append(process.pid))

    assert process.wait(timeout=5.0) == 0
    capture.close()
    capture.raise_if_failed()

    assert retained_bytes(path, 2) == b"out\x00err\xff"
    assert stopped == []


def test_async_binary_capture_stops_process_and_propagates_sink_failure(tmp_path: Path) -> None:
    path = tmp_path / "daemon.out"
    stopped: list[bool] = []

    class FailingSink(output.RotatingBinaryLog):
        def write(self, data: bytes) -> None:
            raise OSError("simulated full disk")

    read_fd, write_fd = os.pipe()
    source = os.fdopen(read_fd, "rb", buffering=0)
    capture = output.AsyncBinaryCapture(
        path,
        max_segment_bytes=64,
        retained_segments=2,
        sink_factory=FailingSink,
    )
    capture.start(source, stop_process=lambda: stopped.append(True))
    os.write(write_fd, b"trigger")
    os.close(write_fd)
    capture.close()

    with pytest.raises(RuntimeError, match="simulated full disk"):
        capture.raise_if_failed()
    assert stopped == [True]


def test_run_bounded_process_drains_concurrent_large_streams_without_deadlock(tmp_path: Path) -> None:
    stdout_path = tmp_path / "stdout.log"
    stderr_path = tmp_path / "stderr.log"
    command = [
        sys.executable,
        "-c",
        "import os, threading; data=b'x'*1048576; "
        "a=threading.Thread(target=os.write,args=(1,data)); "
        "b=threading.Thread(target=os.write,args=(2,data)); "
        "a.start(); b.start(); a.join(); b.join()",
    ]

    result = output.run_bounded_process(
        command,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        max_segment_bytes=64 * 1024,
        retained_segments=4,
    )

    assert result == 0
    for path in tmp_path.iterdir():
        assert path.stat().st_size <= 64 * 1024
    assert len(list(tmp_path.glob("stdout.log*"))) == 4
    assert len(list(tmp_path.glob("stderr.log*"))) == 4


def test_run_bounded_process_fails_closed_on_output_error(tmp_path: Path) -> None:
    stdout_path = tmp_path / "stdout.log"
    stderr_path = tmp_path / "stderr.log"
    stop_file = tmp_path / "stop"
    forced: list[int] = []

    class FailingStdout(output.RotatingBinaryLog):
        def write(self, data: bytes) -> None:
            if self.path == stdout_path.resolve():
                raise OSError("simulated full disk")
            super().write(data)

    def force_stop(process) -> None:
        forced.append(process.pid)
        process.kill()
        process.wait(timeout=5.0)

    result = output.run_bounded_process(
        [sys.executable, "-c", "import os,time; os.write(1,b'x'); time.sleep(60)"],
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        max_segment_bytes=64,
        retained_segments=2,
        stop_files=(stop_file,),
        graceful_timeout_seconds=0.1,
        sink_factory=FailingStdout,
        force_stop=force_stop,
    )

    assert result == output.SUPERVISOR_FAILURE_EXIT_CODE
    assert stop_file.is_file()
    assert len(forced) == 1


def test_main_accepts_command_separator(tmp_path: Path) -> None:
    stdout_path = tmp_path / "stdout.log"
    stderr_path = tmp_path / "stderr.log"

    result = output.main(
        [
            "--stdout-path",
            os.fspath(stdout_path),
            "--stderr-path",
            os.fspath(stderr_path),
            "--max-segment-bytes",
            "64",
            "--retained-segments",
            "2",
            "--",
            sys.executable,
            "-c",
            "print('supervised')",
        ]
    )

    assert result == 0
    assert stdout_path.read_text(encoding="utf-8") == "supervised\n"
