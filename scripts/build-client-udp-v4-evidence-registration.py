#!/usr/bin/env python3
"""Build catalog registration rows from a client-UDP V4 campaign receipt."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness.protocol_evidence_registration import (  # noqa: E402
    run_client_udp_v4_registration_cli,
)


if __name__ == "__main__":
    raise SystemExit(run_client_udp_v4_registration_cli())
