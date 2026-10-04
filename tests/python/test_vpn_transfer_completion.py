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


def test_completion_requires_sha_and_final_rehash_evidence() -> None:
    created: list[dict[str, object]] = []
    result = vpn_transfer_completion.wait_for_completion(
        row=transfer_row(),
        create_transfer=created.append,
        read_transfer=lambda _hash: {"state": "completed", "completedBytes": 123},
        verify_delivered_sha256=lambda size, digest: size == 123 and digest == "ab" * 32,
        read_daemon_logs=lambda: (
            "final_completion_rehash_started\nfinal_completion_rehash_succeeded\n"
        ),
        timeout_seconds=1,
    )

    assert created == [
        {
            "link": "ed2k://|file|safe%20fixture.bin|123|00112233445566778899AABBCCDDEEFF|/",
            "paused": False,
        }
    ]
    assert result["status"] == "passed"
    assert result["sha256Verified"] is True
    assert result["finalRehashSucceeded"] is True


def test_completion_rejects_delivery_without_final_rehash_log() -> None:
    with pytest.raises(RuntimeError, match="final ED2K rehash"):
        vpn_transfer_completion.wait_for_completion(
            row=transfer_row(),
            create_transfer=lambda _payload: None,
            read_transfer=lambda _hash: {
                "state": "completed",
                "completedBytes": 123,
            },
            verify_delivered_sha256=lambda _size, _digest: True,
            read_daemon_logs=lambda: "",
            timeout_seconds=1,
        )
