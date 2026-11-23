from __future__ import annotations

import json
from pathlib import Path

import pytest

from emule_test_harness import vpn_transfer_completion


def transfer_row() -> dict[str, object]:
    return {
        "name": "safe fixture.bin",
        "hash": "00112233445566778899aabbccddeeff",
        "size": 123,
        "sha256": "ab" * 32,
    }


def test_load_exact_transfer_requires_one_complete_allowlist_entry(
    tmp_path: Path,
) -> None:
    inputs = tmp_path / "inputs.json"
    inputs.write_text(
        json.dumps(
            {"auto_browse": {"direct_bootstrap_transfers": [transfer_row()]}}
        ),
        encoding="utf-8",
    )

    assert vpn_transfer_completion.load_exact_transfer(inputs) == transfer_row()
    assert vpn_transfer_completion.ed2k_link(transfer_row()) == (
        "ed2k://|file|safe%20fixture.bin|123|00112233445566778899AABBCCDDEEFF|/"
    )


def completed_row() -> dict[str, object]:
    return {"id": "7", "hash": transfer_row()["hash"], "state": "completed", "sizeBytes": 123,
            "payloadVerified": True, "completedAt": 1,
            "delivery": {"state": "delivered", "path": "/data/ed2k/incoming/safe fixture.bin", "ownership": "owned"}}


def test_completion_requires_captured_job_sha_and_final_rehash_evidence() -> None:
    created = []
    reads = []
    verified = []
    def create(payload):
        created.append(payload)
        return {"id": "7", "hash": transfer_row()["hash"]}
    def read(job_id):
        reads.append(job_id)
        return completed_row()
    def verify(path, size, digest):
        verified.append((path, size, digest))
        return True
    result = vpn_transfer_completion.wait_for_completion(row=transfer_row(), create_download=create, read_download=read,
        verify_delivered_sha256=verify,
        read_daemon_logs=lambda: "final_completion_rehash_started\nfinal_completion_rehash_succeeded\n", timeout_seconds=1)
    assert created == [{"source": {"type": "ed2k-link", "link": vpn_transfer_completion.ed2k_link(transfer_row())}, "intent": "started"}]
    assert reads == ["7"]
    assert verified == [(completed_row()["delivery"]["path"], 123, "ab" * 32)]
    assert result["status"] == "passed" and result["downloadId"] == "7"
    assert result["sha256Verified"] is True and result["finalRehashSucceeded"] is True


def test_completion_rejects_delivery_without_final_rehash_log() -> None:
    with pytest.raises(RuntimeError, match="final ED2K rehash"):
        vpn_transfer_completion.wait_for_completion(row=transfer_row(), create_download=lambda _payload: completed_row(),
            read_download=lambda _id: completed_row(), verify_delivered_sha256=lambda _path, _size, _digest: True,
            read_daemon_logs=lambda: "", timeout_seconds=1)


def test_completion_waits_for_payload_verification_and_delivery(monkeypatch):
    rows = iter([{**completed_row(), "state": "verifying", "payloadVerified": False}, completed_row()])
    reads = []
    def read(job_id):
        reads.append(job_id)
        return next(rows)
    monkeypatch.setattr(vpn_transfer_completion.time, "sleep", lambda _seconds: None)
    vpn_transfer_completion.wait_for_completion(row=transfer_row(), create_download=lambda _payload: completed_row(),
        read_download=read, verify_delivered_sha256=lambda _path, _size, _digest: True,
        read_daemon_logs=lambda: "final_completion_rehash_started final_completion_rehash_succeeded", timeout_seconds=1)
    assert reads == ["7", "7"]


def test_completion_rejects_same_hash_job_substitution():
    with pytest.raises(RuntimeError, match="different download job"):
        vpn_transfer_completion.wait_for_completion(row=transfer_row(), create_download=lambda _payload: completed_row(),
            read_download=lambda _id: {**completed_row(), "id": "8"},
            verify_delivered_sha256=lambda *_args: pytest.fail("substituted job"),
            read_daemon_logs=lambda: "", timeout_seconds=1)


def test_failed_download_does_not_restart_or_wait_for_completion():
    calls = []
    def create(_payload):
        calls.append("create")
        return completed_row()
    def read(_job_id):
        calls.append("read")
        return {**completed_row(), "state": "failed"}
    with pytest.raises(RuntimeError, match="explicit operator action"):
        vpn_transfer_completion.wait_for_completion(row=transfer_row(), create_download=create, read_download=read,
            verify_delivered_sha256=lambda *_args: pytest.fail("failed job"), read_daemon_logs=lambda: "", timeout_seconds=1)
    assert calls == ["create", "read"]


def test_container_delivery_reads_only_the_recorded_path():
    from types import SimpleNamespace
    path = "/saved/output with spaces.bin"
    calls = []
    def docker(*args, **kwargs):
        calls.append(args)
        assert args[-2:] == ("--", path)
        assert kwargs == {"check": False}
        return SimpleNamespace(returncode=0, stdout="123\n" if "stat" in args else "ab" * 32 + "  " + path + "\n")
    assert vpn_transfer_completion.container_delivery_matches(docker, "rust", path, 123, "ab" * 32)
    assert calls == [("exec", "rust", "stat", "-c", "%s", "--", path),
                     ("exec", "rust", "sha256sum", "--", path)]


def test_missing_recorded_output_does_not_search_for_another_copy():
    from types import SimpleNamespace
    calls = []
    def docker(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=1, stdout="")
    assert not vpn_transfer_completion.container_delivery_matches(docker, "rust", "/saved/missing.bin", 123, "ab" * 32)
    assert len(calls) == 1 and "stat" in calls[0]
