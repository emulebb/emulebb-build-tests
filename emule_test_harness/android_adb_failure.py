"""Closed diagnostic projection for Android subprocess failures."""
import errno
import subprocess
import threading
from .bounded_process_output import AsyncBinaryCapture


class AdbOperationFailure(RuntimeError):
    """Keep an actionable category without retaining argv or native output."""
    def __init__(self, arguments, *, exit_code=None, stderr=None, error=None, output_bound=False, message=None):
        operation = {("shell", "mkdir"): "shell-mkdir", ("shell", "chmod"): "shell-chmod",
                     ("shell", "sha256sum"): "shell-sha256", ("shell", "cat"): "shell-cat",
                     ("shell", "sh"): "shell-script", ("shell", "input"): "shell-input",
                     ("shell", "dumpsys"): "shell-dumpsys", ("exec-out", "cat"): "binary-read"}.get(tuple(arguments[:2]))
        operation = operation or {"push": "push", "forward": "forward", "install": "install"}.get(arguments[0], "device-command")
        reason = "unclassified-command-failure"
        if output_bound:
            reason = "output-bound-exceeded"
        elif isinstance(error, subprocess.TimeoutExpired):
            reason = "command-timeout"
        elif isinstance(error, OSError):
            reason = {errno.EACCES: "permission-denied", errno.EPERM: "operation-not-permitted",
                      errno.ENOENT: "missing-file", errno.EEXIST: "already-exists", errno.ENOSPC: "no-space",
                      errno.ECONNRESET: "connection-reset", errno.ETIMEDOUT: "command-timeout"}.get(error.errno, "unclassified-os-error")
        elif stderr:
            text = stderr.decode(errors="replace") if isinstance(stderr, bytes) else stderr
            text = text.lower()
            for phrase, category in (("permission denied", "permission-denied"), ("file exists", "already-exists"),
                    ("no such file or directory", "missing-file"), ("no space left", "no-space"),
                    ("unknown option", "unsupported-option"), ("invalid option", "unsupported-option"),
                    ("device offline", "device-offline"), ("device not found", "device-not-found"),
                    ("error: closed", "transport-closed")):
                if phrase in text:
                    reason = category
                    break
        self.safe_failure = {"operation": operation, "reason": reason,
                             "exitCode": exit_code if type(exit_code) is int else None}
        super().__init__(message or "Selected physical-device ADB operation failed: " + operation + "/" + reason)


class _StartupCodes:
    def __init__(self):
        self.tail = b""
        self.contexts, self.conditions = set(), set()
        self.lock = threading.Lock()

    def write(self, data):
        from .android_emulator import _classify_startup_error
        with self.lock:
            value = _classify_startup_error(self.tail + data)
            self.contexts.add(value["context"])
            self.conditions.add(value["systemCondition"])
            self.tail = data[-512:]

    def close(self):
        with self.lock:
            self.tail = b""

    def summary(self):
        with self.lock:
            return {"contexts": sorted(self.contexts - {"unknown"}),
                    "systemConditions": sorted(self.conditions - {"unknown"})}


class StartupSummaryCapture(AsyncBinaryCapture):
    """Reuse the existing pipe owner, replacing its file sink with fixed codes."""
    def __init__(self, report_dir):
        self.codes = _StartupCodes()
        super().__init__(report_dir / "unretained-peer-startup", max_segment_bytes=65536, retained_segments=1,
                         sink_factory=lambda *args, **kwargs: self.codes)

    def summary(self):
        return self.codes.summary()
