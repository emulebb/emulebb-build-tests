from __future__ import annotations

import json
from pathlib import Path

from emule_test_harness import diagnostic_logs


def test_analyze_diagnostic_logs_summarizes_bad_peers_and_slot_summaries(tmp_path: Path) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    write_json_lines(
        logs_dir / "emulebb-diagnostics-bad-peer-20260608-090000.log",
        [
            bad_peer_event(
                ts="2026-06-08T09:09:30.000Z",
                event="upload_failed_admission_cooldown",
                reason="Failed upload admission",
                action="cooldown",
                user_hash="hash-old",
                address="192.0.2.40",
                strikes=None,
                productive=False,
            ),
        ],
    )
    write_json_lines(
        logs_dir / diagnostic_logs.BAD_PEER_LOG_NAME,
        [
            bad_peer_event(
                ts="2026-06-08T09:10:00.000Z",
                event="upload_no_request_repeat_cooldown",
                reason="Repeated zero-request upload slot abuse",
                action="cooldown",
                user_hash="hash-a",
                address="192.0.2.10",
                strikes=3,
                productive=False,
            ),
            bad_peer_event(
                ts="2026-06-08T09:10:30.000Z",
                event="upload_queued_request_rejected",
                reason="Queued block request could not reopen upload slot",
                action="reject_block_request",
                user_hash="hash-a",
                address="192.0.2.10",
                strikes=None,
                productive=False,
            ),
            bad_peer_event(
                ts="2026-06-08T09:11:00.000Z",
                event="upload_no_request_repeat_ban",
                reason="Repeated zero-request upload slot abuse",
                action="ban",
                user_hash="hash-a",
                address="192.0.2.10",
                strikes=8,
                productive=False,
                scope="hash",
            ),
            bad_peer_event(
                ts="2026-06-08T09:12:00.000Z",
                event="upload_no_request_recycle",
                reason="Broadband productive no-request recycle",
                action="cooldown",
                user_hash="hash-b",
                address="192.0.2.20",
                strikes=None,
                productive=True,
            ),
            bad_peer_event(
                ts="2026-06-08T09:12:15.000Z",
                event="client_ban",
                reason="Repeated zero-request upload slot abuse with rotating hashes",
                action="ban",
                user_hash="hash-c",
                address="192.0.2.30",
                strikes=None,
                productive=False,
                scope="ip",
            ),
            bad_peer_event(
                ts="2026-06-08T09:12:20.000Z",
                event="upload_repeat_block_request_observed",
                reason="Repeated same upload block request",
                action="observe",
                user_hash="hash-a",
                address="192.0.2.10",
                strikes=None,
                productive=False,
            ),
            bad_peer_event(
                ts="2026-06-08T09:12:25.000Z",
                event="upload_repeat_file_request_observed",
                reason="Repeated same-file no-request upload churn",
                action="observe",
                user_hash="hash-a",
                address="192.0.2.10",
                strikes=None,
                productive=False,
            ),
            {
                "schema": "bad_peer_event_v1",
                "ts_utc": "2026-06-08T09:12:30.000Z",
                "event": "fake_file_search_detected",
                "reason": "Fake-file detector flagged search result",
                "action": "flag",
                "peer": None,
                "evidence": {},
            },
        ],
    )
    (logs_dir / diagnostic_logs.UPLOAD_SLOT_LOG_NAME).write_text(
        "UploadSlotDiagnostics: summary uploadSlots=12 activeSlots=11 waitingCooldown=5 "
        "activeZeroRate=3 activeNoRequest=11 toNetworkBytesPerSec=3770439\n",
        encoding="utf-8",
    )
    (logs_dir / diagnostic_logs.DOWNLOAD_SLOT_LOG_NAME).write_text(
        "DownloadSlotDiagnostics: summary files=25 readyFiles=25 activeFiles=6 "
        "downloadingSources=10 duplicateZeroWritePackets=12 bufferedReadyBytes=3337590\n",
        encoding="utf-8",
    )

    analysis = diagnostic_logs.analyze_diagnostic_logs(logs_dir, window_minutes=15, top_count=5)

    assert analysis["bad_peer"]["total_events"] == 9
    assert analysis["bad_peer"]["log_files"] == 2
    assert analysis["bad_peer"]["recent_events"] == 9
    assert analysis["bad_peer"]["cooldowns"] == 3
    assert analysis["bad_peer"]["bans"] == 2
    assert analysis["bad_peer"]["ban_events"] == 2
    assert analysis["bad_peer"]["ban_decisions"] == 2
    assert analysis["bad_peer"]["hash_bans"] == 1
    assert analysis["bad_peer"]["ip_bans"] == 1
    assert analysis["bad_peer"]["productive_no_request"] == 1
    assert analysis["bad_peer"]["unproductive_no_request"] == 2
    assert analysis["bad_peer"]["repeat_block_requests"] == 1
    assert analysis["bad_peer"]["repeat_file_churn"] == 1
    assert analysis["bad_peer"]["top_peers"][0]["name"].startswith("hash-a 192.0.2.10")
    assert analysis["bad_peer"]["top_cooldown_rejections"][0]["count"] == 1
    assert analysis["bad_peer"]["top_repeat_block_peers"][0]["name"].startswith("hash-a 192.0.2.10")
    assert analysis["bad_peer"]["top_repeat_file_peers"][0]["name"].startswith("hash-a 192.0.2.10")
    assert analysis["bad_peer"]["top_unproductive_no_request_peers"][0]["name"].startswith("hash-a 192.0.2.10")
    assert analysis["bad_peer"]["top_productive_no_request_peers"][0]["name"].startswith("hash-b 192.0.2.20")
    assert analysis["bad_peer"]["top_banned_peers"][0]["files_touched"] == 1
    assert analysis["bad_peer"]["top_banned_peers"][0]["ever_uploaded_payload"] is False
    assert analysis["bad_peer"]["max_strikes"][0]["strikes"] == 8
    assert analysis["upload_slot"]["last_summary"]["waitingCooldown"] == 5
    assert analysis["download_slot"]["last_summary"]["duplicateZeroWritePackets"] == 12

    formatted = diagnostic_logs.format_diagnostic_log_analysis(analysis)
    assert "Bad peer window: 9 events" in formatted
    assert "ban_events=2, ban_decisions=2" in formatted
    assert "hash_bans=1, ip_bans=1" in formatted
    assert "repeat_block_requests=1, repeat_file_churn=1" in formatted
    assert "Cooldown re-entry rejections:" in formatted
    assert "Top repeated upload block requests:" in formatted
    assert "Top repeated same-file upload churn:" in formatted
    assert "Top banned peers:" in formatted
    assert "Latest upload summary:" in formatted


def write_json_lines(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def bad_peer_event(
    *,
    ts: str,
    event: str,
    reason: str,
    action: str,
    user_hash: str,
    address: str,
    strikes: int | None,
    productive: bool,
    scope: str | None = None,
) -> dict[str, object]:
    evidence: dict[str, object] = {"productive": productive}
    if strikes is not None:
        evidence.update({"strikes": strikes, "threshold": 8, "cooldown_seconds": 15})
    if scope is not None:
        evidence["scope"] = scope
    return {
        "schema": "bad_peer_event_v1",
        "ts_utc": ts,
        "event": event,
        "reason": reason,
        "action": action,
        "peer": {
            "user_hash": user_hash,
            "address": address,
            "client_software": "eMule v0.70b",
            "user_name": "test",
        },
        "file": {"hash": "file-hash-1", "name": "fixture.bin"},
        "evidence": evidence,
    }
