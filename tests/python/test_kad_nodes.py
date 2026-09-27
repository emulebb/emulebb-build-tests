from __future__ import annotations

import struct

from emule_test_harness.kad_nodes import parse_nodes_dat


def _basic(seed: int, version_or_type: int = 9) -> bytes:
    return (
        bytes([seed]) * 16
        + struct.pack("<I", int.from_bytes(bytes([8, 8, 4, seed]), "big"))
        + struct.pack("<HHB", 4600 + seed, 4700 + seed, version_or_type)
    )


def _extended(seed: int) -> bytes:
    return (
        _basic(seed)
        + struct.pack("<I", 0x11223344 + seed)
        + struct.pack("<I", int.from_bytes(bytes([198, 51, 100, seed]), "big"))
        + b"\x01"
    )


def _modern(version: int, entries: list[bytes], edition: int | None = None) -> bytes:
    header = struct.pack("<II", 0, version)
    if edition is not None:
        header += struct.pack("<I", edition)
    return header + struct.pack("<I", len(entries)) + b"".join(entries)


def test_unversioned_two_and_three_are_counts_not_version_headers() -> None:
    for count in (0, 1, 2, 3, 6):
        payload = struct.pack("<I", count) + b"".join(
            _basic(index) for index in range(1, count + 1)
        )
        assert len(parse_nodes_dat(payload)) == count


def test_stock_modern_versions_and_bootstrap_edition_parse() -> None:
    assert len(parse_nodes_dat(_modern(1, [_basic(1)]))) == 1
    assert len(parse_nodes_dat(_modern(2, [_extended(2)]))) == 1
    assert len(parse_nodes_dat(_modern(3, [_extended(3)], edition=0))) == 1
    assert len(parse_nodes_dat(_modern(3, [_basic(4)], edition=1))) == 1


def test_exact_record_width_rejects_truncated_and_extra_payloads() -> None:
    for exact in (_modern(1, [_basic(1)]), _modern(2, [_extended(2)])):
        assert len(parse_nodes_dat(exact)) == 1
        assert parse_nodes_dat(exact[:-1]) == []
        assert parse_nodes_dat(exact + b"\x00") == []


def test_unsupported_headers_are_rejected() -> None:
    assert parse_nodes_dat(b"") == []
    assert parse_nodes_dat(struct.pack("<III", 0, 99, 0)) == []
    assert parse_nodes_dat(_modern(3, [], edition=2)) == []
