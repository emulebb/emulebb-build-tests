"""Dump download-related eMule MET/DAT files to JSON."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterable, TextIO

MET_HEADER = 0x0E
MET_HEADER_I64TAGS = 0x0F
KNOWN2_MET_VERSION = 0x02
PREFFILE_VERSION = 0x14
PARTFILE_VERSION = 0xE0
PARTFILE_SPLITTEDVERSION = 0xE1
PARTFILE_VERSION_LARGEFILE = 0xE2
CANCELEDFILE_VERSION = 0x21
PART_SIZE = 9_728_000

FT_FILENAME = 0x01
FT_FILESIZE = 0x02
FT_GAPSTART = 0x09
FT_GAPEND = 0x0A
FT_PARTFILENAME = 0x12
FT_STATUS = 0x14
FT_AICHHASHSET = 0x35
FT_FILESIZE_HI = 0x3A
FT_CATEGORY = 0x53

TAGTYPE_STRING = 0x02
TAGTYPE_UINT32 = 0x03
TAGTYPE_FLOAT32 = 0x04
TAGTYPE_BOOL = 0x05
TAGTYPE_BOOLARRAY = 0x06
TAGTYPE_BLOB = 0x07
TAGTYPE_UINT16 = 0x08
TAGTYPE_UINT8 = 0x09
TAGTYPE_UINT64 = 0x0B
TAGTYPE_STR1 = 0x11
TAGTYPE_STR16 = 0x20

SUPPORTED_FILENAMES = {
    "known.met",
    "known2.met",
    "known2_64.met",
    "canceled.met",
    "preferences.dat",
    "statistics.dat",
}

TAG_NAME_BY_ID = {
    FT_FILENAME: "FT_FILENAME",
    FT_FILESIZE: "FT_FILESIZE",
    FT_GAPSTART: "FT_GAPSTART",
    FT_GAPEND: "FT_GAPEND",
    FT_PARTFILENAME: "FT_PARTFILENAME",
    FT_STATUS: "FT_STATUS",
    FT_AICHHASHSET: "FT_AICHHASHSET",
    FT_FILESIZE_HI: "FT_FILESIZE_HI",
    FT_CATEGORY: "FT_CATEGORY",
}

TAG_TYPE_BY_ID = {
    TAGTYPE_STRING: "string",
    TAGTYPE_UINT32: "uint32",
    TAGTYPE_FLOAT32: "float32Raw",
    TAGTYPE_BOOL: "bool",
    TAGTYPE_BOOLARRAY: "boolArrayRaw",
    TAGTYPE_BLOB: "blob",
    TAGTYPE_UINT16: "uint16",
    TAGTYPE_UINT8: "uint8",
    TAGTYPE_UINT64: "uint64",
}


class MetParseError(ValueError):
    """Raised when a MET/DAT file cannot be decoded as the expected format."""


@dataclass(frozen=True)
class RawTag:
    name: int | str
    tag_type: int
    value: Any


class FileReader:
    """Small little-endian reader that tracks offsets for parse diagnostics."""

    def __init__(self, file: BinaryIO, label: str) -> None:
        self.file = file
        self.label = label

    def tell(self) -> int:
        return self.file.tell()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> None:
        self.file.seek(offset, whence)

    def read(self, count: int) -> bytes:
        if count < 0:
            raise MetParseError(f"{self.label}: negative read length at offset {self.tell()}")
        offset = self.tell()
        chunk = self.file.read(count)
        if len(chunk) != count:
            raise MetParseError(
                f"{self.label}: truncated at offset {offset}; wanted {count} bytes, got {len(chunk)}"
            )
        return chunk

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.read(2), "little")

    def u32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.read(8), "little")


def detect_kind(path: Path) -> str | None:
    """Returns the supported eMule file kind for a path, or None."""

    name = path.name.lower()
    if name == "known.met":
        return "known_met"
    if name in {"known2.met", "known2_64.met"}:
        return "known2_met"
    if name.endswith(".part.met"):
        return "part_met"
    if name == "canceled.met":
        return "canceled_met"
    if name == "preferences.dat":
        return "preferences_dat"
    if name == "statistics.dat":
        return "statistics_dat"
    return None


def discover_supported_files(paths: Iterable[Path]) -> list[Path]:
    """Expands files and directories to eMule MET/DAT files.

    Directory scans include only recognized download-state files. Explicit file
    paths are preserved so typos and unsupported files produce visible errors.
    """

    discovered: list[Path] = []
    seen: set[Path] = set()
    for raw_path in paths:
        path = raw_path.expanduser()
        candidates: Iterable[Path]
        if path.is_dir():
            candidates = (candidate for candidate in path.rglob("*") if candidate.is_file())
        else:
            candidates = (path,)
        for candidate in candidates:
            if path.is_dir() and detect_kind(candidate) is None:
                continue
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            discovered.append(candidate)
    return sorted(discovered, key=lambda item: str(item).lower())


def dump_paths(paths: Iterable[Path], *, summary: bool = False, strict: bool = False) -> dict[str, Any]:
    """Returns a JSON-serializable dump for supported files under paths."""

    inputs = []
    errors = []
    for path in discover_supported_files(paths):
        item = dump_file(path, summary=summary, strict=strict)
        inputs.append(item)
        if item["status"] != "ok":
            errors.append({"path": item["path"], "error": item.get("error", "parse failed")})

    return {
        "schemaVersion": 1,
        "tool": "dump-emule-met.py",
        "generatedUtc": _utc_now_iso(),
        "summaryMode": summary,
        "inputs": inputs,
        "errors": errors,
    }


def dump_file(path: Path, *, summary: bool = False, strict: bool = False) -> dict[str, Any]:
    """Returns a JSON-serializable dump for one supported eMule file."""

    kind = detect_kind(path)
    size_bytes: int | None = None
    try:
        size_bytes = path.stat().st_size
        if kind is None:
            raise MetParseError("unsupported eMule MET/DAT file name")
        with path.open("rb") as file:
            reader = FileReader(file, str(path))
            payload = _parse_by_kind(reader, kind, size_bytes=size_bytes, summary=summary)
        return {
            "path": str(path),
            "kind": kind,
            "sizeBytes": size_bytes,
            "status": "ok",
            **payload,
        }
    except Exception as exc:
        if strict:
            raise
        return {
            "path": str(path),
            "kind": kind or "unsupported",
            "sizeBytes": size_bytes,
            "status": "parse_error",
            "error": str(exc),
            "records": [],
            "summary": {},
        }


def write_dump_json(dump: dict[str, Any], output: Path | None) -> Path | None:
    """Writes a dump to output or stdout. Returns the written path, if any."""

    if output is None:
        json.dump(dump, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return None
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(dump, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def default_output_path() -> Path:
    """Returns the policy-compliant default dump path under the workspace output root."""

    output_root = os.environ.get("EMULEBB_WORKSPACE_OUTPUT_ROOT")
    if not output_root:
        raise ValueError("EMULEBB_WORKSPACE_OUTPUT_ROOT is not set; provide --output")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(output_root) / "tmp" / "met-dumps" / f"emule-met-dump-{timestamp}.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", type=Path, nargs="+", help="MET/DAT file or directory paths to scan")
    parser.add_argument("--output", type=Path, help="JSON output path. Defaults under EMULEBB_WORKSPACE_OUTPUT_ROOT.")
    parser.add_argument("--stdout", action="store_true", help="Write JSON to stdout instead of a file.")
    parser.add_argument("--summary", action="store_true", help="Omit large per-hash arrays from known2 records.")
    parser.add_argument("--strict", action="store_true", help="Fail on the first unsupported or corrupt file.")
    args = parser.parse_args(argv)

    output = None if args.stdout else (args.output or default_output_path())
    dump = dump_paths(args.paths, summary=args.summary, strict=args.strict)
    if args.strict and dump["errors"]:
        raise MetParseError(dump["errors"][0]["error"])
    written = write_dump_json(dump, output)
    if written is not None:
        print(f"Wrote eMule MET/DAT JSON dump to {written}")
    return 0 if not dump["errors"] else 2


def _parse_by_kind(reader: FileReader, kind: str, *, size_bytes: int, summary: bool) -> dict[str, Any]:
    if kind == "known_met":
        return _parse_known_met(reader, size_bytes=size_bytes, summary=summary)
    if kind == "known2_met":
        return _parse_known2_met(reader, size_bytes=size_bytes, summary=summary)
    if kind == "part_met":
        return _parse_part_met(reader, size_bytes=size_bytes, summary=summary)
    if kind == "canceled_met":
        return _parse_canceled_met(reader, size_bytes=size_bytes)
    if kind == "preferences_dat":
        return _parse_preferences_dat(reader)
    if kind == "statistics_dat":
        return _parse_statistics_dat(reader)
    raise MetParseError(f"unsupported kind {kind}")


def _parse_known_met(reader: FileReader, *, size_bytes: int, summary: bool) -> dict[str, Any]:
    version = reader.u8()
    if version not in {MET_HEADER, MET_HEADER_I64TAGS}:
        raise MetParseError(f"unsupported known.met header 0x{version:02x}")
    record_count = reader.u32()
    records = []
    for index in range(record_count):
        offset = reader.tell()
        modified_unix = reader.u32()
        hashset = _read_ed2k_hashset(reader, summary=summary)
        tags = [_read_tag(reader) for _ in range(reader.u32())]
        record = {
            "index": index,
            "offset": offset,
            "modifiedUnix": modified_unix,
            **hashset,
            "tags": [_tag_to_json(tag, summary=summary) for tag in tags],
            "fields": _fields_from_tags(tags, summary=summary),
        }
        records.append(record)
    return {
        "version": _hex_byte(version),
        "records": records,
        "summary": {
            "recordCount": record_count,
            "parsedRecords": len(records),
            "trailingBytes": size_bytes - reader.tell(),
        },
    }


def _parse_known2_met(reader: FileReader, *, size_bytes: int, summary: bool) -> dict[str, Any]:
    version = reader.u8()
    if version != KNOWN2_MET_VERSION:
        raise MetParseError(f"unsupported known2.met header 0x{version:02x}")
    records = []
    index = 0
    total_leaf_hashes = 0
    while reader.tell() < size_bytes:
        offset = reader.tell()
        root_hash = reader.read(20).hex()
        hash_count = reader.u32()
        hash_bytes = hash_count * 20
        if reader.tell() + hash_bytes > size_bytes:
            raise MetParseError(
                f"known2.met record {index} at offset {offset} declares {hash_count} hashes past EOF"
            )
        record: dict[str, Any] = {
            "index": index,
            "offset": offset,
            "aichRoot": root_hash,
            "hashCount": hash_count,
            "hashBytes": hash_bytes,
        }
        if summary:
            reader.seek(hash_bytes, os.SEEK_CUR)
        else:
            record["hashes"] = [reader.read(20).hex() for _ in range(hash_count)]
        records.append(record)
        total_leaf_hashes += hash_count
        index += 1
    return {
        "version": _hex_byte(version),
        "records": records,
        "summary": {
            "recordCount": len(records),
            "totalLeafHashes": total_leaf_hashes,
            "lastValidOffset": reader.tell(),
            "trailingBytes": size_bytes - reader.tell(),
            "hashArraysOmitted": summary,
        },
    }


def _parse_part_met(reader: FileReader, *, size_bytes: int, summary: bool) -> dict[str, Any]:
    version = reader.u8()
    if version not in {PARTFILE_VERSION, PARTFILE_SPLITTEDVERSION, PARTFILE_VERSION_LARGEFILE}:
        raise MetParseError(f"unsupported part.met header 0x{version:02x}")

    is_new_style = _is_new_style_part_met(reader, version, size_bytes)
    record: dict[str, Any] = {"index": 0, "offset": 0, "newStyle": is_new_style}
    if is_new_style:
        temp = reader.u32()
        if temp == 0:
            record.update(_read_ed2k_hashset(reader, summary=summary))
        else:
            reader.seek(2)
            record["modifiedUnix"] = reader.u32()
            record["ed2kHash"] = reader.read(16).hex()
    else:
        record["modifiedUnix"] = reader.u32()
        record.update(_read_ed2k_hashset(reader, summary=summary))

    tags = [_read_tag(reader) for _ in range(reader.u32())]
    fields = _fields_from_tags(tags, summary=summary)
    record["tags"] = [_tag_to_json(tag, summary=summary) for tag in tags]
    record["fields"] = fields

    trailing_hashes = []
    if is_new_style and reader.tell() < size_bytes:
        reader.u8()
        part_count = _part_count(fields.get("sizeBytes"))
        while len(trailing_hashes) < part_count and reader.tell() + 16 <= size_bytes:
            trailing_hashes.append(reader.read(16).hex())
        if trailing_hashes and not summary:
            record["trailingHashset"] = trailing_hashes
        elif trailing_hashes:
            record["trailingHashCount"] = len(trailing_hashes)

    return {
        "version": _hex_byte(version),
        "versionName": _part_version_name(version),
        "records": [record],
        "summary": {
            "recordCount": 1,
            "newStyle": is_new_style,
            "trailingBytes": size_bytes - reader.tell(),
        },
    }


def _parse_canceled_met(reader: FileReader, *, size_bytes: int) -> dict[str, Any]:
    version = reader.u8()
    if version != CANCELEDFILE_VERSION:
        raise MetParseError(f"unsupported canceled.met header 0x{version:02x}")
    record_count = reader.u32()
    records = [{"index": index, "ed2kHash": reader.read(16).hex()} for index in range(record_count)]
    return {
        "version": _hex_byte(version),
        "records": records,
        "summary": {
            "recordCount": record_count,
            "parsedRecords": len(records),
            "trailingBytes": size_bytes - reader.tell(),
        },
    }


def _parse_preferences_dat(reader: FileReader) -> dict[str, Any]:
    version = reader.u8()
    user_hash = reader.read(16).hex()
    return {
        "version": _hex_byte(version),
        "records": [{"index": 0, "userHash": user_hash}],
        "summary": {
            "versionExpected": version == PREFFILE_VERSION,
            "downloadFields": ["userHash"],
        },
    }


def _parse_statistics_dat(reader: FileReader) -> dict[str, Any]:
    version = reader.u8()
    record: dict[str, Any] = {"index": 0}
    if version == 0:
        record["totalSentBytes"] = reader.u64()
        record["totalReceivedBytes"] = reader.u64()
    return {
        "version": _hex_byte(version),
        "records": [record],
        "summary": {
            "recordCount": 1,
            "hasTransferTotals": version == 0,
        },
    }


def _is_new_style_part_met(reader: FileReader, version: int, size_bytes: int) -> bool:
    if version == PARTFILE_SPLITTEDVERSION:
        return True
    if size_bytes < 28:
        reader.seek(1)
        return False
    reader.seek(24)
    marker = reader.read(4)
    reader.seek(1)
    return marker == b"\x00\x00\x02\x01"


def _read_ed2k_hashset(reader: FileReader, *, summary: bool) -> dict[str, Any]:
    file_hash = reader.read(16).hex()
    part_count = reader.u16()
    hashset = [reader.read(16).hex() for _ in range(part_count)]
    result: dict[str, Any] = {
        "ed2kHash": file_hash,
        "partHashCount": part_count,
    }
    if summary:
        result["partHashBytes"] = part_count * 16
    else:
        result["partHashes"] = hashset
    return result


def _read_tag(reader: FileReader) -> RawTag:
    raw_type = reader.u8()
    tag_type = raw_type
    if raw_type & 0x80:
        tag_type = raw_type & 0x7F
        name: int | str = reader.u8()
    else:
        name_len = reader.u16()
        if name_len == 1:
            name = reader.u8()
        else:
            name = _decode_mfc_string(reader.read(name_len))

    if tag_type == TAGTYPE_STRING:
        value = _decode_mfc_string(reader.read(reader.u16()))
    elif TAGTYPE_STR1 <= tag_type <= TAGTYPE_STR16:
        value = _decode_mfc_string(reader.read(tag_type - TAGTYPE_STR1 + 1))
    elif tag_type == TAGTYPE_UINT32:
        value = reader.u32()
    elif tag_type == TAGTYPE_UINT64:
        value = reader.u64()
    elif tag_type == TAGTYPE_UINT16:
        value = reader.u16()
    elif tag_type == TAGTYPE_UINT8:
        value = reader.u8()
    elif tag_type == TAGTYPE_FLOAT32:
        value = reader.read(4)
    elif tag_type == TAGTYPE_BOOL:
        value = bool(reader.u8())
    elif tag_type == TAGTYPE_BOOLARRAY:
        bit_count = reader.u16()
        value = {"bitCount": bit_count, "bytes": reader.read((bit_count // 8) + 1)}
    elif tag_type == TAGTYPE_BLOB:
        value = reader.read(reader.u32())
    else:
        raise MetParseError(f"unsupported tag type 0x{tag_type:02x} at offset {reader.tell()}")
    return RawTag(name=name, tag_type=tag_type, value=value)


def _tag_to_json(tag: RawTag, *, summary: bool) -> dict[str, Any]:
    item: dict[str, Any] = {
        "name": tag.name,
        "type": TAG_TYPE_BY_ID.get(tag.tag_type, f"str{tag.tag_type - TAGTYPE_STR1 + 1}" if TAGTYPE_STR1 <= tag.tag_type <= TAGTYPE_STR16 else f"0x{tag.tag_type:02x}"),
    }
    if isinstance(tag.name, int):
        item["nameId"] = tag.name
        item["nameText"] = TAG_NAME_BY_ID.get(tag.name)

    if isinstance(tag.value, bytes):
        item["length"] = len(tag.value)
        if not summary:
            item["valueHex"] = tag.value.hex()
    elif isinstance(tag.value, dict) and isinstance(tag.value.get("bytes"), bytes):
        item["value"] = {
            "bitCount": tag.value["bitCount"],
            "byteLength": len(tag.value["bytes"]),
        }
        if not summary:
            item["value"]["bytesHex"] = tag.value["bytes"].hex()
    else:
        item["value"] = tag.value
    return item


def _fields_from_tags(tags: list[RawTag], *, summary: bool) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    file_size_low: int | None = None
    file_size_hi: int | None = None
    for tag in tags:
        if tag.name == FT_FILENAME and isinstance(tag.value, str):
            fields["fileName"] = tag.value
        elif tag.name == FT_PARTFILENAME and isinstance(tag.value, str):
            fields["partFileName"] = tag.value
        elif tag.name == FT_FILESIZE and isinstance(tag.value, int):
            file_size_low = tag.value
            fields["sizeBytes"] = tag.value
        elif tag.name == FT_FILESIZE_HI and isinstance(tag.value, int):
            file_size_hi = tag.value
        elif tag.name == FT_STATUS and isinstance(tag.value, int):
            fields["status"] = tag.value
        elif tag.name == FT_CATEGORY and isinstance(tag.value, int):
            fields["category"] = tag.value
        elif tag.name == FT_AICHHASHSET and isinstance(tag.value, bytes):
            fields["aichHashset"] = _parse_aich_hashset_blob(tag.value, summary=summary)

    if file_size_low is not None and file_size_hi is not None:
        fields["sizeBytes"] = (file_size_hi << 32) | file_size_low
    return fields


def _parse_aich_hashset_blob(blob: bytes, *, summary: bool) -> dict[str, Any]:
    if len(blob) < 22:
        return {"error": "truncated AICH hashset blob", "byteLength": len(blob)}
    root = blob[:20].hex()
    part_count = int.from_bytes(blob[20:22], "little")
    expected = 22 + (part_count * 20)
    item: dict[str, Any] = {
        "root": root,
        "partHashCount": part_count,
        "byteLength": len(blob),
        "lengthMatches": len(blob) == expected,
    }
    if not summary and len(blob) >= expected:
        item["partHashes"] = [blob[offset : offset + 20].hex() for offset in range(22, expected, 20)]
    return item


def _decode_mfc_string(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", errors="replace")
    for encoding in ("mbcs", "cp1252", "utf-8"):
        try:
            return raw.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def _part_count(size_bytes: Any) -> int:
    if not isinstance(size_bytes, int) or size_bytes <= 0:
        return 0
    return (size_bytes + PART_SIZE - 1) // PART_SIZE


def _part_version_name(version: int) -> str:
    if version == PARTFILE_VERSION:
        return "PARTFILE_VERSION"
    if version == PARTFILE_SPLITTEDVERSION:
        return "PARTFILE_SPLITTEDVERSION"
    if version == PARTFILE_VERSION_LARGEFILE:
        return "PARTFILE_VERSION_LARGEFILE"
    return "unknown"


def _hex_byte(value: int) -> str:
    return f"0x{value:02x}"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
