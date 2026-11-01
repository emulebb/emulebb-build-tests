"""Causal ``diag_event_v2`` evidence for one deterministic peer transfer."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable
from typing import Any

SCHEMA = "emulebb-build-tests.deterministic-transfer-diagnostics.v1"
ED2K_HASH_PATTERN = re.compile(r"^[0-9a-f]{32}$")
EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)
UNCOMPRESSED_PAYLOAD_OPCODES = frozenset({"OP_SENDINGPART", "OP_SENDINGPART_I64"})
COMPRESSED_PAYLOAD_OPCODES = frozenset({"OP_COMPRESSEDPART", "OP_COMPRESSEDPART_I64"})
TRANSPORT_MODES = frozenset({"plaintext", "obfuscated"})
PAYLOAD_ENCODINGS = frozenset({"uncompressed", "compressed"})
ED2K_PART_SIZE = 9_728_000
OP_REQUESTFILENAME = 0x58
OP_REQFILENAMEANSWER = 0x59
OP_SETREQFILEID = 0x4F
OP_FILESTATUS = 0x50


def normalize_ed2k_hash(value: str) -> str:
    """Returns one canonical lowercase eD2K hash or raises."""

    normalized = value.strip().lower()
    if not ED2K_HASH_PATTERN.fullmatch(normalized):
        raise ValueError(f"Invalid eD2K hash: {value!r}.")
    return normalized


def record_file_hash(record: dict[str, Any]) -> str | None:
    """Returns a record's exact ``keys.fileHash`` when present and valid."""

    keys = record.get("keys")
    if not isinstance(keys, dict):
        return None
    value = keys.get("fileHash")
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if ED2K_HASH_PATTERN.fullmatch(normalized) else None


def _sequence(record: dict[str, Any]) -> int:
    for field in ("seq", "streamSeq"):
        value = record.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return -1


def _body(record: dict[str, Any]) -> dict[str, Any]:
    body = record.get("body")
    return body if isinstance(body, dict) else {}


def _matches(
    records: Iterable[dict[str, Any]],
    *,
    family: str,
    event: str,
    file_hash: str | None = None,
    predicate: Callable[[dict[str, Any]], bool] | None = None,
) -> list[dict[str, Any]]:
    matched: list[dict[str, Any]] = []
    for record in records:
        if record.get("family") != family or record.get("event") != event:
            continue
        if file_hash is not None and record_file_hash(record) != file_hash:
            continue
        if predicate is not None and not predicate(record):
            continue
        matched.append(record)
    return matched


def _check(
    name: str,
    records: list[dict[str, Any]],
    *,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "name": name,
        "ok": bool(records),
        "matchingRecordCount": len(records),
        "firstStreamSeq": _sequence(records[0]) if records else None,
        "lastStreamSeq": _sequence(records[-1]) if records else None,
    }
    if detail:
        row.update(detail)
    return row


def _published_hash(record: dict[str, Any], file_hash: str) -> bool:
    hashes = _body(record).get("fileHashes")
    return isinstance(hashes, list) and file_hash in {
        str(item).strip().lower() for item in hashes
    }


def _positive_body_field(record: dict[str, Any], field: str) -> bool:
    value = _body(record).get(field)
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def _outcome(record: dict[str, Any], field: str, expected: str) -> bool:
    return str(_body(record).get(field) or "").strip().lower() == expected


def _ordered(checks: dict[str, dict[str, Any]], names: tuple[str, ...]) -> dict[str, Any]:
    positions = [checks[name]["firstStreamSeq"] for name in names]
    complete = all(isinstance(value, int) and value >= 0 for value in positions)
    return {
        "name": " -> ".join(names),
        "ok": complete and positions == sorted(positions),
        "positions": dict(zip(names, positions, strict=True)),
    }


def _packet_frame_key(record: dict[str, Any]) -> tuple[int, int, str] | None:
    keys = record.get("keys")
    body = _body(record)
    if not isinstance(keys, dict):
        return None
    marker = keys.get("protocolMarker", body.get("protocolMarker"))
    opcode = keys.get("opcode", body.get("opcode"))
    clear_frame_hex = body.get("clearFrameHex")
    if (
        not isinstance(marker, int)
        or isinstance(marker, bool)
        or not isinstance(opcode, int)
        or isinstance(opcode, bool)
        or not isinstance(clear_frame_hex, str)
        or not clear_frame_hex
    ):
        return None
    return marker, opcode, clear_frame_hex.lower()


def _packet_payload(record: dict[str, Any]) -> bytes:
    body = _body(record)
    payload_hex = body.get("payloadHex")
    payload_len = body.get("payloadLen")
    clear_frame_hex = body.get("clearFrameHex")
    if body.get("payloadHexTruncated") is not False or not isinstance(payload_hex, str):
        raise ValueError("packet payload is absent or truncated")
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as exc:
        raise ValueError("packet payload is not hexadecimal") from exc
    if not isinstance(payload_len, int) or isinstance(payload_len, bool) or payload_len != len(payload):
        raise ValueError("packet payload length does not match payloadHex")
    if not isinstance(clear_frame_hex, str):
        raise ValueError("packet clear frame is absent")
    try:
        clear_frame = bytes.fromhex(clear_frame_hex)
    except ValueError as exc:
        raise ValueError("packet clear frame is not hexadecimal") from exc
    if len(clear_frame) < 6:
        raise ValueError("packet clear frame is too short")
    declared_len = int.from_bytes(clear_frame[1:5], "little")
    if declared_len != len(clear_frame) - 5:
        raise ValueError("packet clear frame length header is inconsistent")
    if clear_frame[6:] != payload:
        raise ValueError("packet payload differs from the complete clear frame")
    marker = body.get("protocolMarker")
    opcode = body.get("opcode")
    if clear_frame[0] != marker or clear_frame[5] != opcode:
        raise ValueError("packet marker or opcode differs from the complete clear frame")
    return payload


def _decode_file_identifier(
    payload: bytes,
    *,
    expected_file_hash: str,
    expected_file_size: int,
) -> tuple[dict[str, Any], bytes]:
    if not payload:
        raise ValueError("short FileIdentifier descriptor")
    descriptor = payload[0]
    if descriptor & 0x18:
        raise ValueError(f"unsupported mandatory FileIdentifier options 0x{descriptor:02x}")
    if descriptor & 0x01 == 0:
        raise ValueError("FileIdentifier does not contain the mandatory MD4 hash")
    cursor = 1
    if len(payload) < cursor + 16:
        raise ValueError("short FileIdentifier MD4 hash")
    file_hash = payload[cursor : cursor + 16].hex()
    cursor += 16
    if file_hash != expected_file_hash:
        raise ValueError(f"FileIdentifier hash {file_hash} does not match {expected_file_hash}")

    file_size: int | None = None
    if descriptor & 0x02:
        if len(payload) < cursor + 8:
            raise ValueError("short FileIdentifier size")
        file_size = int.from_bytes(payload[cursor : cursor + 8], "little")
        cursor += 8
    if file_size != expected_file_size:
        raise ValueError(f"FileIdentifier size {file_size} does not match {expected_file_size}")

    aich_root: str | None = None
    if descriptor & 0x04:
        if len(payload) < cursor + 20:
            raise ValueError("short FileIdentifier AICH root")
        aich_root = payload[cursor : cursor + 20].hex()
        cursor += 20
    if aich_root is None:
        raise ValueError("FileIdentifier does not contain an AICH root")
    return {
        "descriptor": descriptor,
        "fileHash": file_hash,
        "fileSize": file_size,
        "aichRoot": aich_root,
    }, payload[cursor:]


def _decode_multipacket_request(
    record: dict[str, Any],
    *,
    expected_file_hash: str,
    expected_file_size: int,
) -> dict[str, Any]:
    identifier, remaining = _decode_file_identifier(
        _packet_payload(record),
        expected_file_hash=expected_file_hash,
        expected_file_size=expected_file_size,
    )
    if not remaining or remaining[0] != OP_REQUESTFILENAME:
        raise ValueError("OP_MULTIPACKET_EXT2 does not start with OP_REQUESTFILENAME")
    remaining = remaining[1:]
    if len(remaining) < 4:
        raise ValueError("short OP_REQUESTFILENAME ext-info")
    part_count = int.from_bytes(remaining[:2], "little")
    expected_part_count = (expected_file_size // ED2K_PART_SIZE) + 1
    if part_count not in {0, expected_part_count}:
        raise ValueError(
            f"OP_REQUESTFILENAME part count {part_count} does not match {expected_part_count}"
        )
    ext_info_len = 2 + ((part_count + 7) // 8) + 2
    if len(remaining) < ext_info_len:
        raise ValueError("short OP_REQUESTFILENAME part status")
    remaining = remaining[ext_info_len:]
    if expected_file_size > ED2K_PART_SIZE and (
        not remaining or remaining[0] != OP_SETREQFILEID
    ):
        raise ValueError("large-file OP_MULTIPACKET_EXT2 omits OP_SETREQFILEID")
    return {**identifier, "requestFilenamePartCount": part_count}


def _decode_multipacket_answer(
    record: dict[str, Any],
    *,
    expected_file_hash: str,
    expected_file_name: str,
    expected_file_size: int,
) -> dict[str, Any]:
    identifier, remaining = _decode_file_identifier(
        _packet_payload(record),
        expected_file_hash=expected_file_hash,
        expected_file_size=expected_file_size,
    )
    if len(remaining) < 3 or remaining[0] != OP_REQFILENAMEANSWER:
        raise ValueError("OP_MULTIPACKETANSWER_EXT2 omits OP_REQFILENAMEANSWER")
    name_len = int.from_bytes(remaining[1:3], "little")
    name_end = 3 + name_len
    if len(remaining) < name_end:
        raise ValueError("short OP_REQFILENAMEANSWER name")
    try:
        file_name = remaining[3:name_end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("OP_REQFILENAMEANSWER name is not UTF-8") from exc
    if file_name != expected_file_name:
        raise ValueError(f"startup filename {file_name!r} does not match {expected_file_name!r}")
    remaining = remaining[name_end:]
    if len(remaining) < 3 or remaining[0] != OP_FILESTATUS:
        raise ValueError("OP_MULTIPACKETANSWER_EXT2 omits OP_FILESTATUS")
    part_count = int.from_bytes(remaining[1:3], "little")
    status_len = 3 + ((part_count + 7) // 8)
    if len(remaining) != status_len:
        raise ValueError("OP_FILESTATUS has a truncated or trailing part-status body")
    return {**identifier, "fileName": file_name, "fileStatusPartCount": part_count}


def _decode_hashset_request(
    record: dict[str, Any],
    *,
    expected_file_hash: str,
    expected_file_size: int,
) -> dict[str, Any]:
    identifier, remaining = _decode_file_identifier(
        _packet_payload(record),
        expected_file_hash=expected_file_hash,
        expected_file_size=expected_file_size,
    )
    if remaining != b"\x03":
        raise ValueError("OP_HASHSETREQUEST2 does not request exactly MD4 plus AICH")
    return {**identifier, "requestMd4": True, "requestAich": True}


def _decode_hashset_answer(
    record: dict[str, Any],
    *,
    expected_file_hash: str,
    expected_file_size: int,
) -> dict[str, Any]:
    identifier, remaining = _decode_file_identifier(
        _packet_payload(record),
        expected_file_hash=expected_file_hash,
        expected_file_size=expected_file_size,
    )
    if not remaining or remaining[0] != 0x03:
        raise ValueError("OP_HASHSETANSWER2 does not contain MD4 plus AICH")
    remaining = remaining[1:]
    if len(remaining) < 18:
        raise ValueError("short OP_HASHSETANSWER2 MD4 section")
    returned_hash = remaining[:16].hex()
    if returned_hash != expected_file_hash:
        raise ValueError("OP_HASHSETANSWER2 MD4 section belongs to another file")
    md4_count = int.from_bytes(remaining[16:18], "little")
    md4_end = 18 + (md4_count * 16)
    if md4_count <= 0 or len(remaining) < md4_end:
        raise ValueError("short or empty OP_HASHSETANSWER2 MD4 hashset")
    md4_hashset = [
        remaining[offset : offset + 16].hex()
        for offset in range(18, md4_end, 16)
    ]
    remaining = remaining[md4_end:]
    if len(remaining) < 22:
        raise ValueError("short OP_HASHSETANSWER2 AICH section")
    aich_root = remaining[:20].hex()
    if aich_root != identifier["aichRoot"]:
        raise ValueError("OP_HASHSETANSWER2 AICH root differs from FileIdentifier")
    aich_count = int.from_bytes(remaining[20:22], "little")
    aich_end = 22 + (aich_count * 20)
    if aich_count <= 0 or len(remaining) != aich_end:
        raise ValueError("short, empty, or trailing OP_HASHSETANSWER2 AICH hashset")
    aich_hashset = [
        remaining[offset : offset + 20].hex()
        for offset in range(22, aich_end, 20)
    ]
    return {
        **identifier,
        "md4HashsetCount": md4_count,
        "md4Hashset": md4_hashset,
        "aichHashsetCount": aich_count,
        "aichHashset": aich_hashset,
    }


def _semantic_check(
    name: str,
    records: list[dict[str, Any]],
    decoder: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    decoded: list[dict[str, Any]] = []
    errors: list[str] = []
    for record in records:
        try:
            decoded.append(decoder(record))
        except ValueError as exc:
            errors.append(str(exc))
    first = decoded[0] if decoded else {}
    return {
        "name": name,
        "ok": bool(records) and len(decoded) == len(records) and not errors,
        "recordCount": len(records),
        "decodedCount": len(decoded),
        "errors": errors,
        **first,
    }


def _manifest_check(
    manifest: dict[str, Any] | None,
    *,
    expected_file_hash: str,
    expected_file_name: str,
    expected_file_size: int,
    hashset_answer: dict[str, Any],
) -> dict[str, Any]:
    manifest = manifest if isinstance(manifest, dict) else {}
    md4_hashset = manifest.get("md4_hashset")
    aich_hashset = manifest.get("aich_hashset")
    expected_md4 = hashset_answer.get("md4Hashset")
    expected_aich = hashset_answer.get("aichHashset")
    checks = {
        "fileHash": str(manifest.get("file_hash") or "").lower() == expected_file_hash,
        "fileName": manifest.get("canonical_name") == expected_file_name,
        "fileSize": manifest.get("file_size") == expected_file_size,
        "completed": manifest.get("completed") is True,
        "md4Acquired": manifest.get("md4_hashset_acquired") is True,
        "md4Hashset": isinstance(md4_hashset, list) and md4_hashset == expected_md4,
        "aichAcquired": manifest.get("aich_hashset_acquired") is True,
        "aichRoot": manifest.get("aich_root") == hashset_answer.get("aichRoot"),
        "aichHashset": isinstance(aich_hashset, list) and aich_hashset == expected_aich,
    }
    return {
        "name": "Rust persisted the exact bilateral MD4 and AICH startup metadata",
        "ok": all(checks.values()),
        "checks": checks,
        "md4HashsetCount": len(md4_hashset) if isinstance(md4_hashset, list) else 0,
        "aichHashsetCount": len(aich_hashset) if isinstance(aich_hashset, list) else 0,
    }


def _packet_records(
    records: Iterable[dict[str, Any]],
    *,
    file_hash: str,
    direction: str,
    outcome: str,
    opcode_names: set[str],
    require_complete_write: bool = False,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for record in _matches(
        records,
        family="ed2k_tcp",
        event="packet",
        file_hash=file_hash,
    ):
        body = _body(record)
        if body.get("direction") != direction or body.get("outcome") != outcome:
            continue
        if body.get("opcodeName") not in opcode_names or _packet_frame_key(record) is None:
            continue
        if require_complete_write:
            attempted = body.get("attemptedLen")
            written = body.get("writtenLen")
            if (
                not isinstance(attempted, int)
                or isinstance(attempted, bool)
                or attempted <= 0
                or written != attempted
            ):
                continue
        selected.append(record)
    return selected


def _paired_packet_check(
    name: str,
    left: list[dict[str, Any]],
    right: list[dict[str, Any]],
) -> dict[str, Any]:
    left_frames = Counter(
        key for record in left if (key := _packet_frame_key(record)) is not None
    )
    right_frames = Counter(
        key for record in right if (key := _packet_frame_key(record)) is not None
    )
    matched = left_frames & right_frames
    matched_count = sum(matched.values())
    left_count = sum(left_frames.values())
    right_count = sum(right_frames.values())
    return {
        "name": name,
        "ok": matched_count > 0 and matched == left_frames == right_frames,
        "matchedFrameCount": matched_count,
        "leftFrameCount": left_count,
        "rightFrameCount": right_count,
        "unmatchedLeftFrameCount": left_count - matched_count,
        "unmatchedRightFrameCount": right_count - matched_count,
        "opcodes": sorted(
            {
                str(_body(record).get("opcodeName"))
                for record in (*left, *right)
                if _body(record).get("opcodeName")
            }
        ),
    }


def _transport_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    modes = Counter(str(_body(record).get("transportMode") or "") for record in records)
    obfuscated = Counter(str(_body(record).get("obfuscated")).lower() for record in records)
    return {
        "recordCount": len(records),
        "transportModes": dict(sorted(modes.items())),
        "obfuscatedValues": dict(sorted(obfuscated.items())),
    }


def _paired_transport_check(
    name: str,
    *,
    expected_transport_mode: str,
    left_label: str,
    left: list[dict[str, Any]],
    right_label: str,
    right: list[dict[str, Any]],
) -> dict[str, Any]:
    expected_obfuscated = expected_transport_mode == "obfuscated"

    def matches(record: dict[str, Any]) -> bool:
        body = _body(record)
        return (
            body.get("transportMode") == expected_transport_mode
            and body.get("obfuscated") is expected_obfuscated
        )

    return {
        "name": name,
        "ok": bool(left) and bool(right) and all(matches(record) for record in (*left, *right)),
        "expectedTransportMode": expected_transport_mode,
        "expectedObfuscated": expected_obfuscated,
        "clients": {
            left_label: _transport_summary(left),
            right_label: _transport_summary(right),
        },
    }


def _payload_encoding_check(
    observed_opcodes: set[str],
    expected_payload_encoding: str,
) -> dict[str, Any]:
    expected_opcodes = (
        COMPRESSED_PAYLOAD_OPCODES
        if expected_payload_encoding == "compressed"
        else UNCOMPRESSED_PAYLOAD_OPCODES
    )
    return {
        "name": "Payload frames used only the selected encoding",
        "ok": bool(observed_opcodes) and observed_opcodes.issubset(expected_opcodes),
        "expectedPayloadEncoding": expected_payload_encoding,
        "expectedOpcodes": sorted(expected_opcodes),
        "observedOpcodes": sorted(observed_opcodes),
    }


def build_transfer_diagnostic_evidence(
    *,
    file_hash: str,
    expected_file_name: str,
    expected_file_size: int,
    expected_transport_mode: str,
    expected_payload_encoding: str,
    rust_manifest: dict[str, Any] | None,
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Builds the mandatory hash-correlated diagnostics gate for Rust <- MFC."""

    normalized_hash = normalize_ed2k_hash(file_hash)
    if expected_transport_mode not in TRANSPORT_MODES:
        raise ValueError(f"Unsupported peer transport mode: {expected_transport_mode!r}.")
    if expected_payload_encoding not in PAYLOAD_ENCODINGS:
        raise ValueError(f"Unsupported payload encoding: {expected_payload_encoding!r}.")
    if not expected_file_name:
        raise ValueError("Expected file name must not be empty.")
    if expected_file_size <= ED2K_PART_SIZE:
        raise ValueError(
            f"Canonical startup evidence requires a fixture larger than {ED2K_PART_SIZE} bytes."
        )
    rust = list(rust_records)
    mfc = list(mfc_records)

    rust_hash_records = [record for record in rust if record_file_hash(record) == normalized_hash]
    mfc_hash_records = [record for record in mfc if record_file_hash(record) == normalized_hash]
    publication = _matches(
        mfc,
        family="sched",
        event="shared_publish_offer_batch",
        predicate=lambda record: _published_hash(record, normalized_hash),
    )
    rust_request_packets = _packet_records(
        rust,
        file_hash=normalized_hash,
        direction="send",
        outcome="send_succeeded",
        opcode_names={"OP_REQUESTPARTS"},
        require_complete_write=True,
    )
    mfc_request_packets = _packet_records(
        mfc,
        file_hash=normalized_hash,
        direction="recv",
        outcome="accepted",
        opcode_names={"OP_REQUESTPARTS"},
    )
    payload_opcodes = {
        "OP_SENDINGPART",
        "OP_COMPRESSEDPART",
        "OP_SENDINGPART_I64",
        "OP_COMPRESSEDPART_I64",
    }
    mfc_payload_packets = _packet_records(
        mfc,
        file_hash=normalized_hash,
        direction="send",
        outcome="send_succeeded",
        opcode_names=payload_opcodes,
    )
    rust_payload_packets = _packet_records(
        rust,
        file_hash=normalized_hash,
        direction="recv",
        outcome="accepted",
        opcode_names=payload_opcodes,
    )
    observed_payload_opcodes = {
        str(_body(record).get("opcodeName"))
        for record in (*mfc_payload_packets, *rust_payload_packets)
        if _body(record).get("opcodeName")
    }
    rust_multipacket_requests = _packet_records(
        rust,
        file_hash=normalized_hash,
        direction="send",
        outcome="send_succeeded",
        opcode_names={"OP_MULTIPACKET_EXT2"},
        require_complete_write=True,
    )
    mfc_multipacket_requests = _packet_records(
        mfc,
        file_hash=normalized_hash,
        direction="recv",
        outcome="accepted",
        opcode_names={"OP_MULTIPACKET_EXT2"},
    )
    mfc_multipacket_answers = _packet_records(
        mfc,
        file_hash=normalized_hash,
        direction="send",
        outcome="send_succeeded",
        opcode_names={"OP_MULTIPACKETANSWER_EXT2"},
    )
    rust_multipacket_answers = _packet_records(
        rust,
        file_hash=normalized_hash,
        direction="recv",
        outcome="accepted",
        opcode_names={"OP_MULTIPACKETANSWER_EXT2"},
    )
    rust_hashset_requests = _packet_records(
        rust,
        file_hash=normalized_hash,
        direction="send",
        outcome="send_succeeded",
        opcode_names={"OP_HASHSETREQUEST2"},
        require_complete_write=True,
    )
    mfc_hashset_requests = _packet_records(
        mfc,
        file_hash=normalized_hash,
        direction="recv",
        outcome="accepted",
        opcode_names={"OP_HASHSETREQUEST2"},
    )
    mfc_hashset_answers = _packet_records(
        mfc,
        file_hash=normalized_hash,
        direction="send",
        outcome="send_succeeded",
        opcode_names={"OP_HASHSETANSWER2"},
    )
    rust_hashset_answers = _packet_records(
        rust,
        file_hash=normalized_hash,
        direction="recv",
        outcome="accepted",
        opcode_names={"OP_HASHSETANSWER2"},
    )
    multipacket_request_semantics = _semantic_check(
        "Rust sent a valid exact-file OP_MULTIPACKET_EXT2 startup request",
        rust_multipacket_requests,
        lambda record: _decode_multipacket_request(
            record,
            expected_file_hash=normalized_hash,
            expected_file_size=expected_file_size,
        ),
    )
    multipacket_answer_semantics = _semantic_check(
        "MFC returned exact filename and status in OP_MULTIPACKETANSWER_EXT2",
        mfc_multipacket_answers,
        lambda record: _decode_multipacket_answer(
            record,
            expected_file_hash=normalized_hash,
            expected_file_name=expected_file_name,
            expected_file_size=expected_file_size,
        ),
    )
    hashset_request_semantics = _semantic_check(
        "Rust requested exact-file MD4 plus AICH hashsets",
        rust_hashset_requests,
        lambda record: _decode_hashset_request(
            record,
            expected_file_hash=normalized_hash,
            expected_file_size=expected_file_size,
        ),
    )
    hashset_answer_semantics = _semantic_check(
        "MFC returned exact-file MD4 plus AICH hashsets",
        mfc_hashset_answers,
        lambda record: _decode_hashset_answer(
            record,
            expected_file_hash=normalized_hash,
            expected_file_size=expected_file_size,
        ),
    )
    startup_checks = {
        "multipacketRequestFrames": _paired_packet_check(
            "Rust OP_MULTIPACKET_EXT2 exactly matches MFC receive",
            rust_multipacket_requests,
            mfc_multipacket_requests,
        ),
        "multipacketAnswerFrames": _paired_packet_check(
            "MFC OP_MULTIPACKETANSWER_EXT2 exactly matches Rust receive",
            mfc_multipacket_answers,
            rust_multipacket_answers,
        ),
        "multipacketRequestSemantics": multipacket_request_semantics,
        "multipacketAnswerSemantics": multipacket_answer_semantics,
        "hashsetRequestFrames": _paired_packet_check(
            "Rust OP_HASHSETREQUEST2 exactly matches MFC receive",
            rust_hashset_requests,
            mfc_hashset_requests,
        ),
        "hashsetAnswerFrames": _paired_packet_check(
            "MFC OP_HASHSETANSWER2 exactly matches Rust receive",
            mfc_hashset_answers,
            rust_hashset_answers,
        ),
        "hashsetRequestSemantics": hashset_request_semantics,
        "hashsetAnswerSemantics": hashset_answer_semantics,
    }
    startup_checks["persistedManifest"] = _manifest_check(
        rust_manifest,
        expected_file_hash=normalized_hash,
        expected_file_name=expected_file_name,
        expected_file_size=expected_file_size,
        hashset_answer=hashset_answer_semantics,
    )
    wire_checks = {
        "requestFrames": _paired_packet_check(
            "Rust request frames exactly match MFC receive frames",
            rust_request_packets,
            mfc_request_packets,
        ),
        "payloadFrames": _paired_packet_check(
            "MFC payload frames exactly match Rust receive frames",
            mfc_payload_packets,
            rust_payload_packets,
        ),
        "requestTransport": _paired_transport_check(
            "Request frames used the selected peer transport on both clients",
            expected_transport_mode=expected_transport_mode,
            left_label="rustSend",
            left=rust_request_packets,
            right_label="mfcReceive",
            right=mfc_request_packets,
        ),
        "payloadTransport": _paired_transport_check(
            "Payload frames used the selected peer transport on both clients",
            expected_transport_mode=expected_transport_mode,
            left_label="mfcSend",
            left=mfc_payload_packets,
            right_label="rustReceive",
            right=rust_payload_packets,
        ),
        "payloadEncoding": _payload_encoding_check(
            observed_payload_opcodes,
            expected_payload_encoding,
        ),
    }
    rust_checks = {
        "sourceEngaged": _check(
            "Rust accepted the exact source",
            _matches(
                rust,
                family="sched",
                event="source_engaged",
                file_hash=normalized_hash,
                predicate=lambda record: _outcome(record, "outcome", "engaged"),
            ),
        ),
        "payloadAccepted": _check(
            "Rust accepted payload for the exact file",
            _matches(
                rust,
                family="sched",
                event="download_payload_accepted",
                file_hash=normalized_hash,
                predicate=lambda record: _positive_body_field(record, "bytes"),
            ),
        ),
        "taskSettled": _check(
            "Rust settled the exact download task as completed",
            _matches(
                rust,
                family="sched",
                event="download_task_settled",
                file_hash=normalized_hash,
                predicate=lambda record: _outcome(record, "state", "completed"),
            ),
        ),
    }
    mfc_checks = {
        "published": _check("MFC published the exact file hash", publication),
        "uploadSlotOpened": _check(
            "MFC opened an upload slot for the exact file",
            _matches(
                mfc,
                family="sched",
                event="upload_slot_opened",
                file_hash=normalized_hash,
                predicate=lambda record: _outcome(record, "outcome", "opened"),
            ),
        ),
        "uploadRequestServed": _check(
            "MFC admitted an upload request for the exact file",
            _matches(
                mfc,
                family="sched",
                event="upload_request_outcome",
                file_hash=normalized_hash,
                predicate=lambda record: _outcome(record, "outcomeClass", "served"),
            ),
        ),
        "uploadPayloadSent": _check(
            "MFC sent payload for the exact file",
            _matches(
                mfc,
                family="sched",
                event="upload_payload_accounting",
                file_hash=normalized_hash,
                predicate=lambda record: _positive_body_field(record, "sentFileBytes"),
            ),
            detail={
                "sentFileBytes": sum(
                    int(_body(record).get("sentFileBytes") or 0)
                    for record in _matches(
                        mfc,
                        family="sched",
                        event="upload_payload_accounting",
                        file_hash=normalized_hash,
                    )
                )
            },
        ),
    }
    ordering = {
        "rust": _ordered(
            rust_checks,
            ("sourceEngaged", "payloadAccepted", "taskSettled"),
        ),
        "mfc": _ordered(
            mfc_checks,
            ("published", "uploadSlotOpened", "uploadRequestServed", "uploadPayloadSent"),
        ),
    }
    required_checks = [
        *startup_checks.values(),
        *wire_checks.values(),
        *rust_checks.values(),
        *mfc_checks.values(),
        *ordering.values(),
    ]
    failures = [str(check["name"]) for check in required_checks if not check["ok"]]
    eligible_coverage_ids: list[str] = []
    if not failures:
        eligible_coverage_ids.extend(
            ["peer.startup.multipacket-ext2", "peer.startup.aich"]
        )
        eligible_coverage_ids.append("queue.admission")
        if observed_payload_opcodes.intersection(UNCOMPRESSED_PAYLOAD_OPCODES):
            eligible_coverage_ids.append("transfer.block.uncompressed")
        if observed_payload_opcodes.intersection(COMPRESSED_PAYLOAD_OPCODES):
            eligible_coverage_ids.append("transfer.block.compressed")
    return {
        "schema": SCHEMA,
        "ok": not failures,
        "fileHash": normalized_hash,
        "expectedTransportMode": expected_transport_mode,
        "expectedPayloadEncoding": expected_payload_encoding,
        "expectedFileName": expected_file_name,
        "expectedFileSize": expected_file_size,
        "failures": failures,
        "coverageClaims": {
            "eligibleCoverageIds": sorted(eligible_coverage_ids),
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
        "wireChecks": wire_checks,
        "startupChecks": startup_checks,
        "clients": {
            "rust": {
                "recordCount": len(rust),
                "hashCorrelatedRecordCount": len(rust_hash_records),
                "checks": rust_checks,
                "schedRecords": [
                    record for record in rust_hash_records if record.get("family") == "sched"
                ],
            },
            "mfc": {
                "recordCount": len(mfc),
                "hashCorrelatedRecordCount": len(mfc_hash_records) + len(publication),
                "checks": mfc_checks,
                "schedRecords": [
                    *publication,
                    *(
                        record
                        for record in mfc_hash_records
                        if record.get("family") == "sched"
                    ),
                ],
            },
        },
        "ordering": ordering,
    }


def require_transfer_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raises when one deterministic transfer lacks its mandatory causal chain."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError("Deterministic transfer diagnostics report has an unexpected schema.")
    if report.get("ok") is not True:
        failures = report.get("failures")
        raise RuntimeError(f"Deterministic transfer diagnostics are incomplete: {failures!r}")
