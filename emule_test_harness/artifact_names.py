"""Canonical test-harness artifact names."""

from __future__ import annotations

import re
from datetime import datetime, timezone


def utc_run_id() -> str:
    """Returns the sortable UTC run id used in generated test paths."""

    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def suite_token(suite_name: str) -> str:
    """Returns a filesystem-safe suite token."""

    token = re.sub(r'[\\/:*?"<>|\s]+', "-", suite_name)
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", token).strip("-").lower()
    return token or "suite"


def result_file_name(suite_name: str) -> str:
    """Returns the canonical final result filename for one suite."""

    return f"{suite_token(suite_name)}-result.json"


def partial_result_file_name(suite_name: str) -> str:
    """Returns the canonical partial result filename for one suite."""

    return f"{suite_token(suite_name)}-result.partial.json"


def summary_file_name(suite_name: str) -> str:
    """Returns the canonical summary filename for one suite."""

    return f"{suite_token(suite_name)}-summary.json"
