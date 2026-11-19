"""Read kernel evidence for the shared campaign's constrained process tree."""

from __future__ import annotations

import os
from pathlib import Path

MEMORY_BYTES = 512 * 1024 * 1024


def _number(value: str) -> int:
    number = int(value)
    if number < 0:
        raise ValueError("cgroup counters must be nonnegative")
    return number


def _limit(value: str) -> int | None:
    return None if value == "max" else _number(value)


def _counters(path: Path) -> dict[str, int]:
    return {key: _number(value) for key, value in
            (line.split() for line in path.read_text(encoding="ascii").splitlines())}


def sample_budget(*, root: Path = Path("/sys/fs/cgroup"),
                  membership: Path = Path("/proc/self/cgroup")) -> dict | None:
    """Observe a unified namespace root only when it contains this controller.

    The controller and its ordinary children share the measured budget; this
    does not claim that the Python controller runs outside the daemon's cap.
    """
    if not membership.is_file() or membership.read_text(encoding="ascii").strip() != "0::/":
        return None
    processes = {_number(value) for value in (root / "cgroup.procs").read_text(encoding="ascii").split()}
    if os.getpid() not in processes:
        raise RuntimeError("cgroup budget evidence does not cover the campaign controller")
    quota, period = (root / "cpu.max").read_text(encoding="ascii").split()
    period = _number(period)
    if period == 0:
        raise ValueError("cgroup CPU period must be positive")
    identity = root.stat()
    events = _counters(root / "memory.events")
    return {
        "scope": "campaign-process-tree",
        "scopeIdentity": [identity.st_dev, identity.st_ino],
        "memoryMaxBytes": _limit((root / "memory.max").read_text(encoding="ascii").strip()),
        "swapMaxBytes": _limit((root / "memory.swap.max").read_text(encoding="ascii").strip()),
        "cpuQuotaMicros": _limit(quota), "cpuPeriodMicros": period,
        "memoryPeakBytes": _number((root / "memory.peak").read_text(encoding="ascii").strip()),
        "oom": events["oom"], "oomKill": events["oom_kill"],
        "oomGroupKill": events["oom_group_kill"],
    }


def matches_target(value: dict) -> bool:
    """Require the exact resident limit, disabled swap and one CPU of quota."""
    return (value["memoryMaxBytes"] == MEMORY_BYTES and value["swapMaxBytes"] == 0
            and value["cpuQuotaMicros"] == value["cpuPeriodMicros"])


def finish_report(report: dict, before: dict | None) -> None:
    """Retain budget evidence and fail an observed budget whose proof changed."""
    if before is None:
        return
    evidence = {"before": before}
    report["kernelResourceBudget"] = evidence
    try:
        after = sample_budget()
        evidence["after"] = after
        limit_fields = ("memoryMaxBytes", "swapMaxBytes", "cpuQuotaMicros", "cpuPeriodMicros")
        checks = {
            "sameScope": after is not None and before["scopeIdentity"] == after["scopeIdentity"],
            "limitsUnchanged": after is not None and all(before[key] == after[key] for key in limit_fields),
            "noOomEvents": after is not None and all(before[key] == after[key]
                                                     for key in ("oom", "oomKill", "oomGroupKill")),
        }
        evidence["checks"] = checks
        evidence["ok"] = all(checks.values())
        report["qualificationScope"]["containerLimitsEnforced"] = (
            matches_target(before) and checks["sameScope"] and checks["limitsUnchanged"])
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        evidence["error"] = type(error).__name__
        evidence["ok"] = False
        report["qualificationScope"]["containerLimitsEnforced"] = False
    # WHY: resource checks also cover the replay's early return through finally;
    # functional success cannot conceal a killed worker or changed budget.
    if not evidence["ok"]:
        report["status"] = "failed"
        report.setdefault("acceptance", {})["ok"] = False
