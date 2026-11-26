import socket
import struct
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from emule_test_harness import ed2k_wire as wire
from emule_test_harness import emule_met_dump
from emule_test_harness import native_large_file_status as probe
from emule_test_harness.scripted_actions import _md4_digest


USER_HASH = bytes(range(16))
SMALL_HASH, LARGE_HASH = (row[2] for row in probe.JOBS)
SMALL_REQUEST = SMALL_HASH + struct.pack("<I", 4_290_048_000)
LARGE_REQUEST = LARGE_HASH + struct.pack("<IQ", 0, 4_290_048_001)


def test_seed_offer_partials_writes_only_the_first_part_with_valid_native_metadata(tmp_path):
    receipts = probe.seed_offer_partials(tmp_path)
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "001.part", "001.part.met", "002.part", "002.part.met",
    ]
    assert [(row["name"], row["sizeBytes"], row["fileHash"]) for row in receipts] == [
        ("OfferLegacyLimit.bin", 4_290_048_000, "9255169b8890cb208966de9a5a3a45b5"),
        ("OfferAboveLegacyLimit.bin", 4_290_048_001, "1a51c5c998a24bddd54eeb3cdc59fac7"),
    ]
    for index, receipt in enumerate(receipts):
        part_path = Path(receipt["partPath"])
        dump = emule_met_dump.dump_file(Path(receipt["partMetPath"]), strict=True)
        record = dump["records"][0]
        assert dump["version"].lower() == ("0xe0", "0xe2")[index]
        assert dump["summary"]["trailingBytes"] == 0
        assert record["fields"]["fileName"] == receipt["name"]
        assert record["fields"]["sizeBytes"] == receipt["sizeBytes"]
        assert record["ed2kHash"] == receipt["fileHash"]
        assert record["modifiedUnix"] == receipt["modifiedUnix"] == (
            part_path.stat().st_mtime_ns // 1_000_000_000
        )
        assert emule_met_dump.part_file_gaps(record) == [(9_728_000, receipt["sizeBytes"])]
        assert [tag["type"] for tag in record["tags"][1:]] == [
            ("uint32", "uint64")[index],
        ] * 3
        part = part_path.read_bytes()
        assert len(part) == receipt["partLength"] == 9_728_000
        first_hash = _md4_digest(part).hex()
        assert first_hash == receipt["firstPartMd4"] == "240568858a65f85133d858f538d17467"
        assert record["partHashCount"] == receipt["partHashCount"] == 442
        assert record["partHashes"] == [first_hash] * 441 + [
            _md4_digest((b"", b"\0")[index]).hex(),
        ]


def test_seed_offer_partials_refuses_to_touch_nonempty_temp(tmp_path):
    existing = tmp_path / "001.part.met"
    existing.write_bytes(b"existing job")
    with pytest.raises(ValueError, match="empty native Temp"):
        probe.seed_offer_partials(tmp_path)
    assert list(tmp_path.iterdir()) == [existing]
    assert existing.read_bytes() == b"existing job"


@pytest.mark.parametrize("capable", [False, True])
def test_native_tcp_cutoff_collects_exact_requests(capable):
    with socket.create_server(("127.0.0.1", 0)) as listener, ThreadPoolExecutor(1) as executor:
        with wire.Ed2kWireClient(*listener.getsockname()) as peer:
            stream, _ = listener.accept()
            with stream:
                result = executor.submit(
                    probe.observe_tcp_source_requests, stream, capable=capable, expected_user_hash=USER_HASH,
                    timeout_seconds=2, quiet_seconds=0.05,
                )
                peer.send(0x01, wire.encode_login_request(user_hash=USER_HASH, tcp_port=4662, nickname="fixture"))
                id_change = peer.receive()
                assert id_change.opcode == 0x40
                assert struct.unpack("<II", id_change.payload) == (0x0100007F, 0x0100 if capable else 0)
                payloads = [LARGE_REQUEST, SMALL_REQUEST] if capable else [SMALL_REQUEST]
                frames = [wire.encode_frame(0x19, payload) for payload in payloads]
                # Both clients concatenate independent frames in a single TCP write.
                peer._require_socket().sendall(b"".join(frames))
                for payload in payloads:
                    assert peer.receive() == wire.Ed2kFrame(0xE3, 0x42, payload[:16] + b"\0")
                receipt = result.result(timeout=3)
                assert [row["frameHex"] for row in receipt["requests"]] == [frame.hex() for frame in frames]
                assert receipt["legacyObservationSeconds"] == (None if capable else 0.05)


@pytest.mark.parametrize(("capable", "bad", "message"), [
    (False, LARGE_REQUEST, "oversized"),
    (True, LARGE_HASH + struct.pack("<I", 4_290_048_001), "exact plain request"),
])
def test_native_tcp_cutoff_rejects_wrong_capability_or_size_encoding(capable, bad, message):
    with socket.create_server(("127.0.0.1", 0)) as listener, socket.create_connection(listener.getsockname()) as peer:
        stream, _ = listener.accept()
        with stream:
            login = wire.encode_login_request(user_hash=USER_HASH, tcp_port=4662, nickname="fixture")
            peer.sendall(wire.encode_frame(1, login) + wire.encode_frame(0x19, SMALL_REQUEST) + wire.encode_frame(0x19, bad))
            with pytest.raises(wire.Ed2kWireError, match=message):
                probe.observe_tcp_source_requests(
                    stream, capable=capable, expected_user_hash=USER_HASH, timeout_seconds=2, quiet_seconds=0.05,
                )


@pytest.mark.parametrize("capable", [False, True])
def test_native_tcp_cutoff_receives_partial_offers_with_exact_size_tags(capable):
    small = SMALL_HASH + bytes.fromhex("fcfcfcfc fcfc 01000000 03010002") + struct.pack("<I", probe.LEGACY_MAX)
    large = (
        LARGE_HASH + bytes.fromhex("fcfcfcfc fcfc 02000000 03010002")
        + struct.pack("<I", probe.LEGACY_MAX + 1) + bytes.fromhex("0301003a00000000")
    )
    payload = (struct.pack("<I", 2) + small + large) if capable else (struct.pack("<I", 1) + small)
    packed = zlib.compress(payload)
    offer_frame = struct.pack("<BIB", 0xD4, len(packed) + 1, 0x15) + packed
    with socket.create_server(("127.0.0.1", 0)) as listener, socket.create_connection(listener.getsockname()) as peer:
        stream, _ = listener.accept()
        with stream:
            login = wire.encode_login_request(user_hash=USER_HASH, tcp_port=4662, nickname="fixture")
            requests = wire.encode_frame(0x19, SMALL_REQUEST)
            if capable:
                requests += wire.encode_frame(0x19, LARGE_REQUEST)
            peer.sendall(wire.encode_frame(1, login) + requests + offer_frame)
            receipt = probe.observe_tcp_source_requests(
                stream, capable=capable, expected_user_hash=USER_HASH, timeout_seconds=2,
                quiet_seconds=0.05, require_partial_offers=True,
            )
            assert [row["sizeHigh"] for row in receipt["offers"]] == ([None, 0] if capable else [None])
            assert all(row["frameHex"] == offer_frame.hex() for row in receipt["offers"])
            assert bytes.fromhex(receipt["idChangeFrameHex"])[10:] == (b"\x01\x01\x00\x00" if capable else b"\x01\x00\x00\x00")
