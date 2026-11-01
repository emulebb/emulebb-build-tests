from __future__ import annotations

import pytest

from emule_test_harness import ed2k_file_observer as observer
from emule_test_harness import ed2k_wire


FILE_HASH = "00112233445566778899AABBCCDDEEFF"


@pytest.mark.unit
def test_observe_uses_exact_search_and_obfuscated_source_reply(monkeypatch) -> None:
    class FakeClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            assert (host, port, timeout) == ("127.0.0.1", 4661, 2.0)
            self.transcript = [{"direction": "send", "opcode": "fixture"}]

        def connect(self) -> None:
            return None

        def close(self) -> None:
            return None

        def login(self, **kwargs: object) -> dict[str, object]:
            assert kwargs["nickname"] == observer.OBSERVER_NICK
            return {"assigned_id": 7, "id_kind": "low-id"}

        def search_hash(self, file_hash: bytes) -> list[dict[str, object]]:
            assert file_hash.hex().upper() == FILE_HASH
            return [
                {
                    "hash": FILE_HASH,
                    "name": "fixture.bin",
                    "size": 123,
                    "sources": 1,
                    "complete_sources": 1,
                    "result_source_id": 0xC000020A,
                    "result_source_port": 4662,
                }
            ]

        def get_sources(self, **kwargs: object) -> dict[str, object]:
            assert kwargs["size"] == 123
            assert kwargs["obfuscated"] is True
            return {
                "hash": FILE_HASH,
                "source_count": 1,
                "sources": [
                    {
                        "kind": "high-id",
                        "host": "192.0.2.10",
                        "port": 4662,
                        "user_hash": "AA" * 16,
                    }
                ],
            }

    monkeypatch.setattr(observer.ed2k_wire, "Ed2kWireClient", FakeClient)

    result = observer.Ed2kFileObserver("127.0.0.1", 4661, 2.0).observe(
        FILE_HASH.lower(), 123
    )

    assert result["indexed"] is True
    assert result["name"] == "fixture.bin"
    assert result["sources"] == 1
    assert result["endpoints"] == [
        {
            "kind": "high-id",
            "host": "192.0.2.10",
            "port": 4662,
            "user_hash": "AA" * 16,
        }
    ]
    assert result["search_source"] == {
        "kind": "high-id-search-reference",
        "id": 0xC000020A,
        "port": 4662,
    }
    assert result["transcript"] == [{"direction": "send", "opcode": "fixture"}]


@pytest.mark.unit
def test_observe_rejects_exact_hash_size_mismatch(monkeypatch) -> None:
    class MismatchClient:
        transcript: list[dict[str, object]] = []

        def __init__(self, *_args: object) -> None:
            return None

        def connect(self) -> None:
            return None

        def close(self) -> None:
            return None

        def login(self, **_kwargs: object) -> dict[str, object]:
            return {"assigned_id": 7, "id_kind": "low-id"}

        def search_hash(self, _file_hash: bytes) -> list[dict[str, object]]:
            return [{"hash": FILE_HASH, "size": 124}]

    monkeypatch.setattr(observer.ed2k_wire, "Ed2kWireClient", MismatchClient)

    with pytest.raises(ed2k_wire.Ed2kWireError, match="unexpected file size"):
        observer.Ed2kFileObserver("127.0.0.1", 4661).observe(FILE_HASH, 123)


@pytest.mark.unit
def test_withdrawal_waits_for_direct_source_cache_after_search_disappears(monkeypatch) -> None:
    observations = [
        {
            "indexed": False,
            "endpoints": [{"host": "192.0.2.10", "port": 4662}],
        },
        {"indexed": False, "endpoints": []},
    ]
    file_observer = observer.Ed2kFileObserver("127.0.0.1", 4661)
    monkeypatch.setattr(
        observer.Ed2kFileObserver,
        "observe",
        lambda *_args: observations.pop(0),
    )
    monkeypatch.setattr(
        observer,
        "wait_for",
        lambda _description, _timeout, resolve: resolve() or resolve(),
    )

    result = file_observer.wait_for_source_absent(
        FILE_HASH,
        123,
        "192.0.2.10",
        4662,
        1.0,
    )

    assert result["absent"] is True
    assert len(result["observations"]) == 2
    assert result["observations"][0]["indexed"] is False
    assert result["observations"][0]["endpoints"] != []
    assert result["observation"]["endpoints"] == []


@pytest.mark.unit
def test_low_id_search_reference_is_authoritative_source_evidence(monkeypatch) -> None:
    observations = [
        {
            "indexed": True,
            "endpoints": [],
            "search_source": {
                "kind": "low-id-search-reference",
                "id": 2,
                "port": 4662,
            },
        }
    ]
    file_observer = observer.Ed2kFileObserver("127.0.0.1", 4661)
    monkeypatch.setattr(
        observer.Ed2kFileObserver,
        "observe",
        lambda *_args: observations.pop(0),
    )
    monkeypatch.setattr(observer, "wait_for", lambda _description, _timeout, resolve: resolve())

    result = file_observer.wait_for_source(
        FILE_HASH,
        123,
        "127.0.0.1",
        4662,
        1.0,
    )

    assert result["matched_source"] == {
        "kind": "low-id-search-reference",
        "id": 2,
        "port": 4662,
    }


@pytest.mark.unit
@pytest.mark.parametrize("value", ["", "00", "G" * 32, "00" * 17])
def test_parse_file_hash_rejects_non_exact_values(value: str) -> None:
    with pytest.raises(ValueError, match="exactly 32 hexadecimal"):
        observer.parse_file_hash(value)
