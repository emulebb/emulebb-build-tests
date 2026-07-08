from __future__ import annotations

import json
import struct
from pathlib import Path

from emule_test_harness import emule_met_dump


def _tag_string(name_id: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return bytes([emule_met_dump.TAGTYPE_STRING]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<H", len(raw)) + raw


def _tag_uint32(name_id: int, value: int) -> bytes:
    return bytes([emule_met_dump.TAGTYPE_UINT32]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<I", value)


def _tag_uint64(name_id: int, value: int) -> bytes:
    return bytes([emule_met_dump.TAGTYPE_UINT64]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<Q", value)


def _tag_blob(name_id: int, value: bytes) -> bytes:
    return bytes([emule_met_dump.TAGTYPE_BLOB]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<I", len(value)) + value


def _known_record(
    *,
    modified_s: int,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    aich_blob: bytes | None = None,
) -> bytes:
    tags = [
        _tag_string(emule_met_dump.FT_FILENAME, name),
        _tag_uint64(emule_met_dump.FT_FILESIZE, size_bytes),
    ]
    if aich_blob is not None:
        tags.append(_tag_blob(emule_met_dump.FT_AICHHASHSET, aich_blob))
    return (
        struct.pack("<I", modified_s)
        + bytes.fromhex(ed2k_hash)
        + struct.pack("<H", 0)
        + struct.pack("<I", len(tags))
        + b"".join(tags)
    )


def test_dump_known_met_extracts_hashes_tags_and_fields(tmp_path: Path) -> None:
    aich_blob = bytes.fromhex("aa" * 20) + struct.pack("<H", 1) + bytes.fromhex("bb" * 20)
    known_met = tmp_path / "known.met"
    known_met.write_bytes(
        bytes([emule_met_dump.MET_HEADER_I64TAGS])
        + struct.pack("<I", 1)
        + _known_record(
            modified_s=1_700_000_000,
            ed2k_hash="00112233445566778899aabbccddeeff",
            name="Sample File.bin",
            size_bytes=12_345,
            aich_blob=aich_blob,
        )
    )

    dump = emule_met_dump.dump_file(known_met)

    assert dump["status"] == "ok"
    assert dump["kind"] == "known_met"
    record = dump["records"][0]
    assert record["ed2kHash"] == "00112233445566778899aabbccddeeff"
    assert record["fields"]["fileName"] == "Sample File.bin"
    assert record["fields"]["sizeBytes"] == 12_345
    assert record["fields"]["aichHashset"]["root"] == "aa" * 20
    assert record["fields"]["aichHashset"]["partHashes"] == ["bb" * 20]


def test_dump_known2_met_can_emit_raw_or_summary_hashsets(tmp_path: Path) -> None:
    known2 = tmp_path / "known2_64.met"
    known2.write_bytes(
        bytes([emule_met_dump.KNOWN2_MET_VERSION])
        + bytes.fromhex("aa" * 20)
        + struct.pack("<I", 2)
        + bytes.fromhex("bb" * 20)
        + bytes.fromhex("cc" * 20)
    )

    raw = emule_met_dump.dump_file(known2)
    summary = emule_met_dump.dump_file(known2, summary=True)

    assert raw["records"][0]["aichRoot"] == "aa" * 20
    assert raw["records"][0]["hashes"] == ["bb" * 20, "cc" * 20]
    assert summary["records"][0]["hashBytes"] == 40
    assert "hashes" not in summary["records"][0]
    assert summary["summary"]["hashArraysOmitted"] is True


def test_dump_known2_truncation_is_reported_without_strict(tmp_path: Path) -> None:
    known2 = tmp_path / "known2.met"
    known2.write_bytes(bytes([emule_met_dump.KNOWN2_MET_VERSION]) + bytes.fromhex("aa" * 20) + struct.pack("<I", 2))

    dump = emule_met_dump.dump_file(known2)

    assert dump["status"] == "parse_error"
    assert "declares 2 hashes past EOF" in dump["error"]


def test_dump_part_met_extracts_download_fields(tmp_path: Path) -> None:
    part_met = tmp_path / "001.part.met"
    tags = [
        _tag_string(emule_met_dump.FT_FILENAME, "Alpha Payload.bin"),
        _tag_uint64(emule_met_dump.FT_FILESIZE, 99),
        _tag_string(emule_met_dump.FT_PARTFILENAME, "001.part"),
        _tag_uint32(emule_met_dump.FT_STATUS, 1),
        _tag_uint32(emule_met_dump.FT_CATEGORY, 2),
    ]
    part_met.write_bytes(
        bytes([emule_met_dump.PARTFILE_VERSION])
        + struct.pack("<I", 1_700_000_000)
        + bytes.fromhex("00112233445566778899aabbccddeeff")
        + struct.pack("<H", 0)
        + struct.pack("<I", len(tags))
        + b"".join(tags)
    )

    dump = emule_met_dump.dump_file(part_met)

    assert dump["status"] == "ok"
    record = dump["records"][0]
    assert record["ed2kHash"] == "00112233445566778899aabbccddeeff"
    assert record["fields"]["fileName"] == "Alpha Payload.bin"
    assert record["fields"]["partFileName"] == "001.part"
    assert record["fields"]["sizeBytes"] == 99
    assert record["fields"]["status"] == 1
    assert record["fields"]["category"] == 2


def test_dump_canceled_preferences_and_statistics_dat(tmp_path: Path) -> None:
    canceled = tmp_path / "canceled.met"
    canceled.write_bytes(
        bytes([emule_met_dump.CANCELEDFILE_VERSION])
        + struct.pack("<I", 1)
        + bytes.fromhex("00112233445566778899aabbccddeeff")
    )
    preferences = tmp_path / "preferences.dat"
    preferences.write_bytes(bytes([emule_met_dump.PREFFILE_VERSION]) + bytes.fromhex("11" * 16))
    statistics = tmp_path / "statistics.dat"
    statistics.write_bytes(bytes([0]) + struct.pack("<Q", 10) + struct.pack("<Q", 20))

    dumped = {Path(item["path"]).name: item for item in emule_met_dump.dump_paths([tmp_path])["inputs"]}

    assert dumped["canceled.met"]["records"][0]["ed2kHash"] == "00112233445566778899aabbccddeeff"
    assert dumped["preferences.dat"]["records"][0]["userHash"] == "11" * 16
    assert dumped["statistics.dat"]["records"][0]["totalSentBytes"] == 10
    assert dumped["statistics.dat"]["records"][0]["totalReceivedBytes"] == 20


def test_cli_writes_json_to_requested_output(tmp_path: Path) -> None:
    known2 = tmp_path / "known2_64.met"
    known2.write_bytes(bytes([emule_met_dump.KNOWN2_MET_VERSION]))
    output = tmp_path / "dump.json"

    result = emule_met_dump.main([str(tmp_path), "--summary", "--output", str(output)])

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert result == 0
    assert payload["schemaVersion"] == 1
    assert payload["inputs"][0]["kind"] == "known2_met"
    assert payload["inputs"][0]["summary"]["recordCount"] == 0


def test_explicit_unsupported_file_reports_parse_error(tmp_path: Path) -> None:
    unsupported = tmp_path / "nodes.dat"
    unsupported.write_bytes(b"\x00")

    dump = emule_met_dump.dump_paths([unsupported])

    assert dump["inputs"][0]["status"] == "parse_error"
    assert dump["inputs"][0]["kind"] == "unsupported"
    assert dump["errors"][0]["path"] == str(unsupported)
