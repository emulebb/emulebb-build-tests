"""Run one child process while preserving bounded raw stdout and stderr."""

from __future__ import annotations

import argparse
from contextlib import suppress
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import BinaryIO, Callable, Sequence

from . import windows_processes

SUPERVISOR_FAILURE_EXIT_CODE = 74
READ_CHUNK_BYTES = 64 * 1024


def rotated_path(path: Path, index: int) -> Path:
    """Returns one numbered process-output segment path."""

    return path.with_name(f"{path.name}.{index}")


class RotatingBinaryLog:
    """Preserves exact bytes across a bounded number of whole-file segments."""

    def __init__(self, path: Path, *, max_segment_bytes: int, retained_segments: int) -> None:
        if max_segment_bytes <= 0:
            raise ValueError("max_segment_bytes must be greater than zero.")
        if retained_segments <= 0:
            raise ValueError("retained_segments must be greater than zero.")
        self.path = path.resolve()
        self.max_segment_bytes = max_segment_bytes
        self.retained_segments = retained_segments
        self._handle: BinaryIO | None = None
        self._size = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prune_invalid_generations()
        self._start_new_run()

    def __enter__(self) -> RotatingBinaryLog:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _prune_invalid_generations(self) -> None:
        prefix = f"{self.path.name}."
        for candidate in self.path.parent.glob(f"{self.path.name}.*"):
            suffix = candidate.name.removeprefix(prefix)
            if not suffix.isdigit():
                continue
            generation = int(suffix)
            if generation >= self.retained_segments or candidate.stat().st_size > self.max_segment_bytes:
                candidate.unlink()

    def _start_new_run(self) -> None:
        if not self.path.is_file():
            return
        if self.path.stat().st_size > self.max_segment_bytes:
            self.path.unlink()
            return
        self._rotate()

    def _open(self) -> BinaryIO:
        if self._handle is None:
            self._handle = self.path.open("ab", buffering=0)
        return self._handle

    def _rotate(self) -> None:
        self.close()
        if self.retained_segments == 1:
            self.path.unlink(missing_ok=True)
            self._size = 0
            return
        rotated_path(self.path, self.retained_segments - 1).unlink(missing_ok=True)
        for index in range(self.retained_segments - 2, 0, -1):
            source = rotated_path(self.path, index)
            if source.is_file():
                source.replace(rotated_path(self.path, index + 1))
        if self.path.is_file():
            self.path.replace(rotated_path(self.path, 1))
        self._size = 0

    def write(self, data: bytes) -> None:
        """Writes every byte, rotating only between exact byte slices."""

        remaining = memoryview(data)
        while remaining:
            if self._size >= self.max_segment_bytes:
                self._rotate()
            available = self.max_segment_bytes - self._size
            chunk = remaining[:available]
            written = self._open().write(chunk)
            if written != len(chunk):
                raise OSError(f"Short process-log write: expected {len(chunk)} bytes, wrote {written}.")
            self._size += written
            remaining = remaining[written:]

    def close(self) -> None:
        """Closes the active segment handle."""

        if self._handle is not None:
            self._handle.close()
            self._handle = None


def _pump_stream(
    source: BinaryIO,
    sink: RotatingBinaryLog,
    errors: queue.Queue[BaseException],
) -> None:
    try:
        while chunk := source.read(READ_CHUNK_BYTES):
            sink.write(chunk)
    except BaseException as error:  # noqa: BLE001 - worker failures cross the thread boundary
        errors.put(error)
    finally:
        source.close()


def _request_stop(paths: Sequence[Path]) -> None:
    for path in paths:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=True)
        except OSError:
            continue


def _force_stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        with suppress(Exception):
            row = next(
                (item for item in windows_processes.collect_processes() if item.pid == process.pid),
                None,
            )
            if row is not None:
                result = windows_processes.terminate_process_tree(
                    process.pid,
                    expected_root_creation_date=row.creation_date,
                )
                if result.get("return_code") == 0:
                    return
    process.terminate()
    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5.0)


def run_bounded_process(
    command: Sequence[str],
    *,
    stdout_path: Path,
    stderr_path: Path,
    max_segment_bytes: int,
    retained_segments: int,
    stop_files: Sequence[Path] = (),
    graceful_timeout_seconds: float = 90.0,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    sink_factory: Callable[..., RotatingBinaryLog] = RotatingBinaryLog,
    force_stop: Callable[[subprocess.Popen[bytes]], None] = _force_stop,
) -> int:
    """Runs one process and fails closed if bounded output cannot be preserved."""

    if not command:
        raise ValueError("command must not be empty.")
    if graceful_timeout_seconds <= 0:
        raise ValueError("graceful_timeout_seconds must be greater than zero.")
    with (
        sink_factory(
            stdout_path,
            max_segment_bytes=max_segment_bytes,
            retained_segments=retained_segments,
        ) as stdout_log,
        sink_factory(
            stderr_path,
            max_segment_bytes=max_segment_bytes,
            retained_segments=retained_segments,
        ) as stderr_log,
    ):
        try:
            process = popen(
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
        except Exception as error:
            stderr_log.write(f"supervisor spawn failure: {type(error).__name__}: {error}\n".encode())
            return SUPERVISOR_FAILURE_EXIT_CODE
        assert process.stdout is not None
        assert process.stderr is not None
        errors: queue.Queue[BaseException] = queue.Queue()
        threads = [
            threading.Thread(target=_pump_stream, args=(process.stdout, stdout_log, errors), daemon=True),
            threading.Thread(target=_pump_stream, args=(process.stderr, stderr_log, errors), daemon=True),
        ]
        for thread in threads:
            thread.start()

        failure: BaseException | None = None
        while process.poll() is None:
            try:
                failure = errors.get_nowait()
            except queue.Empty:
                time.sleep(0.05)
                continue
            break

        if failure is not None:
            _request_stop(stop_files)
            try:
                process.wait(timeout=graceful_timeout_seconds)
            except subprocess.TimeoutExpired:
                force_stop(process)

        for thread in threads:
            thread.join()
        if failure is None and not errors.empty():
            failure = errors.get_nowait()
        if failure is not None:
            try:
                stderr_log.write(f"supervisor output failure: {type(failure).__name__}: {failure}\n".encode())
            except OSError:
                pass
            return SUPERVISOR_FAILURE_EXIT_CODE
        return int(process.returncode or 0)


def build_parser() -> argparse.ArgumentParser:
    """Builds the bounded-process supervisor parser."""

    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--stdout-path", type=Path, required=True)
    parser.add_argument("--stderr-path", type=Path, required=True)
    parser.add_argument("--max-segment-bytes", type=int, required=True)
    parser.add_argument("--retained-segments", type=int, required=True)
    parser.add_argument("--stop-file", action="append", type=Path, default=[])
    parser.add_argument("--graceful-timeout-seconds", type=float, default=90.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Runs the requested child with bounded raw output capture."""

    args = build_parser().parse_args(argv)
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    return run_bounded_process(
        command,
        stdout_path=args.stdout_path,
        stderr_path=args.stderr_path,
        max_segment_bytes=args.max_segment_bytes,
        retained_segments=args.retained_segments,
        stop_files=args.stop_file,
        graceful_timeout_seconds=args.graceful_timeout_seconds,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
