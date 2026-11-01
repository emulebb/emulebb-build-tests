from __future__ import annotations

import pytest

from emule_test_harness import ed2k_server_state_campaign as campaign


@pytest.mark.unit
def test_published_row_requires_exact_hash_name_size_and_source_state() -> None:
    row = {
        "hash": campaign.FILE_HASH.hex().upper(),
        "name": campaign.FILE_NAME,
        "size": campaign.FILE_SIZE,
        "sources": 1,
        "complete_sources": 1,
    }

    assert campaign.assert_published_row(row) is row

    with pytest.raises(RuntimeError, match="differs"):
        campaign.assert_published_row({**row, "size": campaign.FILE_SIZE + 1})


@pytest.mark.unit
def test_source_assertion_requires_lowid_port_and_obfuscated_identity() -> None:
    result = {
        "sources": [
            {
                "kind": "low-id",
                "client_id": 7,
                "host": None,
                "port": 41662,
                "user_hash": campaign.PUBLISHER_HASH.hex().upper(),
            }
        ]
    }

    source = campaign.assert_single_lowid_source(
        result,
        publisher_port=41662,
        require_user_hash=True,
    )
    assert source["client_id"] == 7

    with pytest.raises(RuntimeError, match="omitted or changed"):
        campaign.assert_single_lowid_source(
            {"sources": [{**result["sources"][0], "user_hash": None}]},
            publisher_port=41662,
            require_user_hash=True,
        )


@pytest.mark.unit
def test_exact_search_row_ignores_unrelated_results() -> None:
    expected = {"hash": campaign.FILE_HASH.hex().upper()}
    rows = [{"hash": "00" * 16}, expected]

    assert campaign.exact_search_row(rows) is expected


@pytest.mark.unit
def test_state_machine_failure_keeps_partial_transcript(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingClient:
        def __init__(self, _host: str, _port: int, _timeout: float) -> None:
            self.transcript: list[dict[str, object]] = []

        def connect(self) -> None:
            self.transcript.append({"direction": "connect"})

        def login(self, **_kwargs: object) -> dict[str, object]:
            self.transcript.append({"direction": "send", "opcode": "login"})
            raise RuntimeError("synthetic login failure")

        def close(self) -> None:
            return None

    monkeypatch.setattr(campaign.ed2k_wire, "Ed2kWireClient", FailingClient)

    with pytest.raises(campaign.StateCampaignFailure) as raised:
        campaign.execute_state_machine(host="127.0.0.1", port=4661, timeout_seconds=1)

    assert isinstance(raised.value.cause, RuntimeError)
    assert raised.value.evidence["states"] == ["disconnected"]
    assert raised.value.evidence["failure"] == {
        "type": "RuntimeError",
        "message": "synthetic login failure",
    }
    assert raised.value.evidence["transcripts"]["publisher"] == [
        {"direction": "connect"},
        {"direction": "send", "opcode": "login"},
    ]
