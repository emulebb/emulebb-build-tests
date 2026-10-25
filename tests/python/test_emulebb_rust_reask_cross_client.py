from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from tests.python.diagnostic_fixtures import current_diagnostic_writer_health


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "emulebb-rust-reask-cross-client.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("emulebb_rust_reask_cross_client_test", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_mfc_run(log_dir: Path) -> None:
    for segment_id, waiting_sessions in ((0, 1), (1, 3)):
        segment = log_dir / f"emulebb-mfc-diag-42-active-{segment_id:06}.jsonl"
        segment.write_text(
            json.dumps(
                {
                    "schema": "diag_event_v2",
                    "client": "mfc",
                    "processId": 42,
                    "runId": "active",
                    "segmentId": segment_id,
                    "seq": segment_id + 1,
                    "streamSeq": segment_id + 1,
                    "event": "capacity_snapshot",
                    "body": {
                        "effectiveSlotCap": 2,
                        "activeSlots": 2,
                        "waitingSessions": waiting_sessions,
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
    active = log_dir / "emulebb-mfc-diag-42-active-000001.jsonl"
    (log_dir / "emulebb-mfc-diag-health.json").write_text(
        json.dumps(
            current_diagnostic_writer_health(
                client="mfc",
                run_id="active",
                segment_id=1,
                active_file_name=active.name,
            )
        ),
        encoding="utf-8",
    )


def test_capacity_oracle_reads_all_health_validated_segments(tmp_path: Path) -> None:
    module = _load_module()
    _write_mfc_run(tmp_path)

    assert module.max_waiting_sessions(tmp_path) == 3


def test_capacity_oracle_rejects_missing_writer_health(tmp_path: Path) -> None:
    module = _load_module()
    _write_mfc_run(tmp_path)
    (tmp_path / "emulebb-mfc-diag-health.json").unlink()

    with pytest.raises(ValueError, match="missing MFC diagnostic writer health"):
        module.max_waiting_sessions(tmp_path)
