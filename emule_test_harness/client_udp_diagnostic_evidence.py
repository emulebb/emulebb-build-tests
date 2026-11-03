"""Canonical causal evidence gates for deterministic client-UDP scenarios."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Iterable


SCHEMA = "emulebb-build-tests.client-udp-v4-diagnostics.v1"
V2_SCHEMA = "emulebb-build-tests.client-udp-v2-diagnostics.v1"
V2_RAW_EVIDENCE_SCHEMA = "emulebb-build-tests.client-udp-v2-raw-evidence.v1"
V3_SCHEMA = "emulebb-build-tests.client-udp-v3-diagnostics.v1"
V3_RAW_EVIDENCE_SCHEMA = "emulebb-build-tests.client-udp-v3-raw-evidence.v1"
CLEAR_SCHEMA = "emulebb-build-tests.client-udp-clear-diagnostics.v1"
CLEAR_RAW_EVIDENCE_SCHEMA = "emulebb-build-tests.client-udp-clear-raw-evidence.v1"
ENCRYPTED_SCHEMA = "emulebb-build-tests.client-udp-encrypted-diagnostics.v1"
ENCRYPTED_RAW_EVIDENCE_SCHEMA = (
    "emulebb-build-tests.client-udp-encrypted-raw-evidence.v1"
)
QUEUE_FULL_SCHEMA = "emulebb-build-tests.client-udp-queue-full-diagnostics.v1"
FILE_NOT_FOUND_SCHEMA = "emulebb-build-tests.client-udp-file-not-found-diagnostics.v1"
DIAGNOSTIC_SCHEMA = "diag_event_v2"
COVERAGE_ID = "client-udp.v4"
V2_COVERAGE_ID = "client-udp.v2"
V3_COVERAGE_ID = "client-udp.v3"
CLEAR_COVERAGE_ID = "client-udp.clear"
ENCRYPTED_COVERAGE_ID = "client-udp.encrypted"
QUEUE_FULL_COVERAGE_ID = "client-udp.queue-full"
FILE_NOT_FOUND_COVERAGE_ID = "client-udp.file-not-found"
CLIENTS = ("rust", "mfc")
EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)
STOCK_RECORD_ID = "stock.client-udp.corpus"
STOCK_CORPUS_SHA256 = "89468db8e028268f21598216f5949ae11c2b1c3e1370b151d3d7136e8fda812b"
OP_EMULEPROT = 0xC5
OP_REASKFILEPING = 0x90
OP_REASKACK = 0x91
OP_FILENOTFOUND = 0x92
OP_QUEUEFULL = 0x93
OP_REASKCALLBACKUDP = 0x94
CLIENT_UDP_CRYPT_OVERHEAD = 8
CLIENT_UDP_RESERVED_MARKERS = frozenset((0xC5, 0xD4, 0xE4, 0xE5, 0xA3, 0xB2))


@dataclass(frozen=True)
class ClientUdpAckTransition:
    requester: str
    responder: str
    source_tcp_endpoint: str
    source_udp_endpoint: str
    source_user_hash: bytes
    requester_udp_endpoint: str
    control_receipt: object
    requester_records: Iterable[dict[str, Any]]
    responder_records: Iterable[dict[str, Any]]


@dataclass(frozen=True)
class ClientUdpQueueFullTransition:
    requester: str
    responder: str
    source_tcp_endpoint: str
    source_udp_endpoint: str
    source_user_hash: bytes
    requester_udp_endpoint: str
    control_receipt: object
    waiter_removal_receipt: object
    queue_pressure_receipt: object
    requester_records: Iterable[dict[str, Any]]
    responder_records: Iterable[dict[str, Any]]


@dataclass(frozen=True)
class ClientUdpFileNotFoundTransition:
    requester: str
    responder: str
    source_tcp_endpoint: str
    source_udp_endpoint: str
    source_user_hash: bytes
    requester_udp_endpoint: str
    control_receipt: object
    shared_withdrawal_receipt: object
    source_absence_receipt: object
    requester_records: Iterable[dict[str, Any]]
    responder_records: Iterable[dict[str, Any]]


def _body(record: dict[str, Any] | None) -> dict[str, Any]:
    value = record.get("body") if record is not None else None
    return value if isinstance(value, dict) else {}


def _keys(record: dict[str, Any] | None) -> dict[str, Any]:
    value = record.get("keys") if record is not None else None
    return value if isinstance(value, dict) else {}


def _sequence(record: dict[str, Any] | None) -> int:
    value = record.get("seq") if record is not None else None
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
        else 0
    )


def _event(record: dict[str, Any], family: str, event: str) -> bool:
    return bool(
        record.get("schema") == DIAGNOSTIC_SCHEMA
        and record.get("family") == family
        and record.get("event") == event
        and _sequence(record) > 0
    )


def _single(
    records: list[dict[str, Any]],
    predicate: Callable[[dict[str, Any]], bool],
) -> tuple[dict[str, Any] | None, int]:
    matches = [record for record in records if predicate(record)]
    return (matches[0] if len(matches) == 1 else None, len(matches))


def _split_endpoint(endpoint: str) -> tuple[str, int] | None:
    host, separator, raw_port = endpoint.rpartition(":")
    if not separator or not host:
        return None
    try:
        port = int(raw_port)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port


def _decode_part_status(
    data: bytes,
    offset: int,
) -> tuple[dict[str, Any], int]:
    if len(data) < offset + 2:
        raise ValueError("short part-status header")
    count = int.from_bytes(data[offset : offset + 2], "little")
    offset += 2
    byte_count = (count + 7) // 8
    if len(data) < offset + byte_count:
        raise ValueError("short part-status bitmap")
    bitmap = data[offset : offset + byte_count]
    offset += byte_count
    if count and count % 8 and bitmap[-1] >> (count % 8):
        raise ValueError("non-zero part-status padding bits")
    bits = "".join(
        "1" if bitmap[index // 8] & (1 << (index % 8)) else "0"
        for index in range(count)
    )
    return {
        "wirePartCount": count,
        "partStatusBits": bits if count else None,
        "completeSource": count == 0,
        "rawHex": data[offset - byte_count - 2 : offset].hex(),
    }, offset


def _encode_part_status(bits: str | None) -> bytes:
    if bits is None:
        return bytes(2)
    if any(bit not in "01" for bit in bits) or len(bits) > 0xFFFF:
        raise ValueError("invalid part-status bits")
    encoded = bytearray(len(bits).to_bytes(2, "little"))
    encoded.extend(bytes((len(bits) + 7) // 8))
    for index, bit in enumerate(bits):
        if bit == "1":
            encoded[2 + index // 8] |= 1 << (index % 8)
    return bytes(encoded)


def _decode_request(raw_hex: object, *, udp_version: int = 4) -> dict[str, Any]:
    try:
        raw = bytes.fromhex(str(raw_hex))
        if udp_version not in range(1, 5):
            raise ValueError("unsupported client-UDP version")
        if len(raw) < 18 or raw[:2] != bytes((OP_EMULEPROT, OP_REASKFILEPING)):
            raise ValueError(f"not a version-{udp_version} OP_REASKFILEPING frame")
        offset = 18
        part_status = None
        if udp_version > 3:
            part_status, offset = _decode_part_status(raw, offset)
        complete_source_count = None
        if udp_version > 2:
            if len(raw) < offset + 2:
                raise ValueError("short OP_REASKFILEPING complete-source count")
            complete_source_count = int.from_bytes(raw[offset : offset + 2], "little")
            offset += 2
        if len(raw) != offset:
            raise ValueError("unexpected OP_REASKFILEPING tail")
        return {
            "ok": True,
            "rawHex": raw.hex(),
            "udpVersion": udp_version,
            "fileHash": raw[2:18].hex(),
            "partStatus": part_status,
            "completeSourceCount": complete_source_count,
        }
    except (TypeError, ValueError) as error:
        return {"ok": False, "error": str(error)}


def _decode_ack(raw_hex: object, *, udp_version: int = 4) -> dict[str, Any]:
    try:
        raw = bytes.fromhex(str(raw_hex))
        if udp_version not in range(1, 5):
            raise ValueError("unsupported client-UDP version")
        if len(raw) < 4 or raw[:2] != bytes((OP_EMULEPROT, OP_REASKACK)):
            raise ValueError(f"not a version-{udp_version} OP_REASKACK frame")
        offset = 2
        part_status = None
        if udp_version > 3:
            part_status, offset = _decode_part_status(raw, offset)
        if len(raw) != offset + 2:
            raise ValueError("unexpected OP_REASKACK tail")
        rank = int.from_bytes(raw[offset : offset + 2], "little")
        if rank == 0:
            raise ValueError("OP_REASKACK queue rank must be non-zero")
        return {
            "ok": True,
            "rawHex": raw.hex(),
            "udpVersion": udp_version,
            "partStatus": part_status,
            "queueRank": rank,
        }
    except (TypeError, ValueError) as error:
        return {"ok": False, "error": str(error)}


def _decode_queue_full(raw_hex: object) -> dict[str, Any]:
    try:
        raw = bytes.fromhex(str(raw_hex))
        if raw != bytes((OP_EMULEPROT, OP_QUEUEFULL)):
            raise ValueError("not an exact clear OP_QUEUEFULL frame")
        return {"ok": True, "rawHex": raw.hex(), "payloadLength": 0}
    except (TypeError, ValueError) as error:
        return {"ok": False, "error": str(error)}


def _decode_file_not_found(raw_hex: object) -> dict[str, Any]:
    try:
        raw = bytes.fromhex(str(raw_hex))
        if raw != bytes((OP_EMULEPROT, OP_FILENOTFOUND)):
            raise ValueError("not an exact clear OP_FILENOTFOUND frame")
        return {"ok": True, "rawHex": raw.hex(), "payloadLength": 0}
    except (TypeError, ValueError) as error:
        return {"ok": False, "error": str(error)}


def _diagnostic_clear_frame_hex(record: dict[str, Any] | None) -> str | None:
    """Rebuild the diagnosed clear frame without decrypting trusted ciphertext."""

    if record is None:
        return None
    marker = _keys(record).get("protocolMarker")
    opcode = _keys(record).get("opcode")
    body = _body(record)
    payload_hex = body.get("payloadHex")
    if (
        not isinstance(marker, int)
        or isinstance(marker, bool)
        or not 0 <= marker <= 0xFF
        or not isinstance(opcode, int)
        or isinstance(opcode, bool)
        or not 0 <= opcode <= 0xFF
        or not isinstance(payload_hex, str)
        or len(payload_hex) % 2 != 0
        or body.get("payloadHexTruncated") is not False
    ):
        return None
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        return None
    if body.get("payloadLen") != len(payload):
        return None
    return (bytes((marker, opcode)) + payload).hex()


def _packet_transport_evidence(
    record: dict[str, Any] | None,
    *,
    expected_transport_mode: str,
) -> dict[str, Any]:
    """Validate one diagnosed plaintext or obfuscated client-UDP datagram."""

    body = _body(record)
    raw_hex = body.get("rawHex")
    clear_hex = _diagnostic_clear_frame_hex(record)
    raw: bytes | None = None
    clear: bytes | None = None
    try:
        if isinstance(raw_hex, str) and len(raw_hex) % 2 == 0:
            raw = bytes.fromhex(raw_hex)
        if clear_hex is not None:
            clear = bytes.fromhex(clear_hex)
    except ValueError:
        raw = None
        clear = None
    expected_obfuscated = expected_transport_mode == "obfuscated"
    overhead = len(raw) - len(clear) if raw is not None and clear is not None else None
    common_ok = bool(
        record is not None
        and expected_transport_mode in {"plaintext", "obfuscated"}
        and body.get("transportMode") == expected_transport_mode
        and body.get("obfuscated") is expected_obfuscated
        and raw is not None
        and clear is not None
        and body.get("rawLen") == len(raw)
    )
    if expected_obfuscated:
        framing_ok = bool(
            common_ok
            and overhead == CLIENT_UDP_CRYPT_OVERHEAD
            and raw != clear
            and raw
            and raw[0] & 0x01 == 0x01
            and raw[0] not in CLIENT_UDP_RESERVED_MARKERS
        )
    else:
        framing_ok = bool(common_ok and overhead == 0 and raw == clear)
    return {
        "ok": framing_ok,
        "transportMode": body.get("transportMode"),
        "obfuscated": body.get("obfuscated"),
        "rawHex": raw.hex() if raw is not None else None,
        "clearFrameHex": clear.hex() if clear is not None else None,
        "rawLen": len(raw) if raw is not None else None,
        "clearFrameLen": len(clear) if clear is not None else None,
        "overheadBytes": overhead,
        "wireMarker": raw[0] if raw else None,
    }


def _stock_authority(
    value: object, *, coverage_id: str = COVERAGE_ID
) -> dict[str, Any]:
    record = value if isinstance(value, dict) else {}
    try:
        fixture = base64.b64decode(
            str(record.get("fixtureBase64") or ""), validate=True
        )
        digest = hashlib.sha256(fixture).hexdigest()
        v1_request = fixture[:18]
        v1_ack = fixture[18:22]
        file_not_found = fixture[22:24]
        queue_full = fixture[24:26]
        callback = fixture[26:]
        semantics_ok = bool(
            len(fixture) == 64
            and v1_request == bytes((OP_EMULEPROT, OP_REASKFILEPING)) + bytes(range(16))
            and v1_ack == bytes((OP_EMULEPROT, OP_REASKACK, 1, 0))
            and file_not_found == bytes((OP_EMULEPROT, OP_FILENOTFOUND))
            and queue_full == bytes((OP_EMULEPROT, OP_QUEUEFULL))
            and callback[:2] == bytes((OP_EMULEPROT, OP_REASKCALLBACKUDP))
            and callback[2:18] == bytes(range(16))
            and callback[18:34] == bytes(range(16, 32))
            and callback[34:] == bytes.fromhex("02000100")
        )
    except (TypeError, ValueError):
        fixture = b""
        digest = ""
        semantics_ok = False
    ok = bool(
        record.get("recordId") == STOCK_RECORD_ID
        and record.get("protocol") == "client_udp"
        and record.get("recordType") == "udp-packet"
        and record.get("direction") == "both"
        and record.get("transport") == "udp"
        and isinstance(record.get("coverageIds"), list)
        and coverage_id in record["coverageIds"]
        and record.get("fixtureEncoding") == "concatenated-client-udp-corpus"
        and record.get("fixtureLength") == len(fixture) == 64
        and record.get("payloadDigest") == f"sha256:{STOCK_CORPUS_SHA256}"
        and digest == STOCK_CORPUS_SHA256
        and semantics_ok
    )
    return {
        "ok": ok,
        "recordId": record.get("recordId"),
        "sha256": digest or None,
        "length": len(fixture),
        "semanticsOk": semantics_ok,
    }


def _control_evidence(
    value: object,
    *,
    file_hash: str,
    source_tcp_endpoint: str,
    source_udp_endpoint: str,
    source_user_hash: str,
    source_udp_version: int = 4,
) -> dict[str, Any]:
    receipt = value if isinstance(value, dict) else {}
    request = receipt.get("request") if isinstance(receipt.get("request"), dict) else {}
    response = (
        receipt.get("response") if isinstance(receipt.get("response"), dict) else {}
    )
    tcp = _split_endpoint(source_tcp_endpoint)
    udp = _split_endpoint(source_udp_endpoint)
    expected_request = (
        {
            "fileHash": file_hash,
            "sourceIp": tcp[0],
            "sourceTcpPort": tcp[1],
            "sourceUdpPort": udp[1],
            "sourceUserHash": source_user_hash,
            "sourceUdpVersion": source_udp_version,
        }
        if tcp is not None and udp is not None and tcp[0] == udp[0]
        else None
    )
    expected_response = (
        {
            "accepted": True,
            "fileHash": file_hash,
            "sourceEndpoint": source_udp_endpoint,
            "sourceTcpPort": tcp[1],
            "sourceUserHash": source_user_hash,
            "sourceUdpVersion": source_udp_version,
            "state": "queued-source-reask-pending",
        }
        if tcp is not None
        else None
    )
    return {
        "ok": bool(
            expected_request is not None
            and request == expected_request
            and response.get("status") == 200
            and response.get("json") == expected_response
        ),
        "request": request or None,
        "response": response or None,
    }


def _waiter_removal_evidence(
    value: object,
    *,
    file_hash: str,
    requester_udp_endpoint: str,
) -> dict[str, Any]:
    receipt = value if isinstance(value, dict) else {}
    waiter = receipt.get("waiter") if isinstance(receipt.get("waiter"), dict) else {}
    response = (
        receipt.get("response") if isinstance(receipt.get("response"), dict) else {}
    )
    requester = _split_endpoint(requester_udp_endpoint)
    client_id = waiter.get("clientId")
    expected_waiter = (
        {
            "clientId": client_id,
            "address": requester[0],
            "requestedFileHash": file_hash,
            "waitingQueue": True,
        }
        if requester is not None
        and isinstance(client_id, str)
        and bool(client_id.strip())
        else None
    )
    return {
        "ok": bool(
            expected_waiter is not None
            and waiter == expected_waiter
            and response.get("status") == 200
            and response.get("json") == {"ok": True, "removed": "queue"}
            and receipt.get("verifiedAbsent") is True
        ),
        "waiter": waiter or None,
        "response": response or None,
        "verifiedAbsent": receipt.get("verifiedAbsent") is True,
    }


def _queue_pressure_evidence(
    value: object,
    *,
    file_hash: str,
    requester_udp_endpoint: str,
) -> dict[str, Any]:
    receipt = value if isinstance(value, dict) else {}
    request = receipt.get("request") if isinstance(receipt.get("request"), dict) else {}
    response = (
        receipt.get("response") if isinstance(receipt.get("response"), dict) else {}
    )
    response_json = (
        response.get("json") if isinstance(response.get("json"), dict) else {}
    )
    requester = _split_endpoint(requester_udp_endpoint)
    fixture_id = response_json.get("fixtureId")
    actual_count = response_json.get("actualWaitingUserCount")
    effective_count = response_json.get("effectiveWaitingUserCount")
    queue_size = response_json.get("queueSize")
    integers_ok = bool(
        isinstance(fixture_id, int)
        and not isinstance(fixture_id, bool)
        and fixture_id > 0
        and isinstance(actual_count, int)
        and not isinstance(actual_count, bool)
        and actual_count >= 0
        and isinstance(effective_count, int)
        and not isinstance(effective_count, bool)
        and effective_count >= 0
        and isinstance(queue_size, int)
        and not isinstance(queue_size, bool)
        and queue_size > 0
    )
    expected_request = (
        {
            "fileHash": file_hash,
            "sourceIp": requester[0],
            "sourceUdpPort": requester[1],
        }
        if requester is not None
        else None
    )
    expected_response = (
        {
            "accepted": True,
            "fixtureId": fixture_id,
            "fileHash": file_hash,
            "sourceEndpoint": requester_udp_endpoint,
            "actualWaitingUserCount": actual_count,
            "effectiveWaitingUserCount": effective_count,
            "queueSize": queue_size,
            "expiresAfterMillis": 30000,
            "state": "client-udp-queue-pressure-armed",
        }
        if integers_ok
        else None
    )
    pressure_ok = bool(
        integers_ok
        and effective_count > actual_count
        and effective_count + 50 == queue_size + 1
    )
    return {
        "ok": bool(
            expected_request is not None
            and request == expected_request
            and response.get("status") == 200
            and expected_response is not None
            and response_json == expected_response
            and pressure_ok
        ),
        "request": request or None,
        "response": response or None,
        "fixtureId": fixture_id if integers_ok else None,
        "actualWaitingUserCount": actual_count if integers_ok else None,
        "effectiveWaitingUserCount": effective_count if integers_ok else None,
        "queueSize": queue_size if integers_ok else None,
        "queueFullMargin": 50,
    }


def _shared_withdrawal_evidence(
    value: object,
    *,
    file_hash: str,
) -> dict[str, Any]:
    receipt = value if isinstance(value, dict) else {}
    method = receipt.get("method")
    fixture_path = receipt.get("fixturePath")
    reload_response = (
        receipt.get("reloadResponse")
        if isinstance(receipt.get("reloadResponse"), dict)
        else {}
    )
    method_evidence: dict[str, Any]
    if method == "file-move":
        moved_to_path = receipt.get("movedToPath")
        method_ok = bool(
            isinstance(fixture_path, str)
            and fixture_path.strip()
            and isinstance(moved_to_path, str)
            and moved_to_path.strip()
            and fixture_path.casefold() != moved_to_path.casefold()
        )
        method_evidence = {"movedToPath": moved_to_path}
    elif method == "shared-roots-cleared":
        shared_directories = (
            receipt.get("sharedDirectories")
            if isinstance(receipt.get("sharedDirectories"), dict)
            else {}
        )
        request = (
            shared_directories.get("request")
            if isinstance(shared_directories.get("request"), dict)
            else {}
        )
        response = (
            shared_directories.get("response")
            if isinstance(shared_directories.get("response"), dict)
            else {}
        )
        response_json = response.get("json")
        method_ok = bool(
            isinstance(fixture_path, str)
            and fixture_path.strip()
            and request == {"roots": [], "confirmReplaceRoots": True}
            and response.get("status") == 200
            and (response_json is None or isinstance(response_json, dict))
        )
        method_evidence = {
            "sharedDirectories": {
                "request": request or None,
                "response": {
                    "status": response.get("status"),
                    "json": response_json,
                },
            }
        }
    else:
        method_ok = False
        method_evidence = {}
    result = {
        "ok": bool(
            receipt.get("fileHash") == file_hash
            and method_ok
            and receipt.get("presentBefore") is True
            and reload_response.get("status") == 200
            and receipt.get("absentAfter") is True
        ),
        "fileHash": receipt.get("fileHash"),
        "method": method,
        "fixturePath": fixture_path,
        **method_evidence,
        "presentBefore": receipt.get("presentBefore") is True,
        "reloadResponse": reload_response or None,
        "absentAfter": receipt.get("absentAfter") is True,
    }
    return result


def _source_absence_evidence(
    value: object,
    *,
    file_hash: str,
    source_tcp_endpoint: str,
    source_user_hash: str,
) -> dict[str, Any]:
    receipt = value if isinstance(value, dict) else {}
    return {
        "ok": bool(
            receipt
            == {
                "fileHash": file_hash,
                "sourceTcpEndpoint": source_tcp_endpoint,
                "sourceUserHash": source_user_hash,
                "verifiedAbsent": True,
            }
        ),
        "fileHash": receipt.get("fileHash"),
        "sourceTcpEndpoint": receipt.get("sourceTcpEndpoint"),
        "sourceUserHash": receipt.get("sourceUserHash"),
        "verifiedAbsent": receipt.get("verifiedAbsent") is True,
    }


def _sched_identity(
    record: dict[str, Any],
    *,
    file_hash: str,
    source_tcp_endpoint: str,
    source_user_hash: str,
) -> bool:
    keys = _keys(record)
    return bool(
        str(keys.get("fileHash") or "").casefold() == file_hash
        and str(keys.get("peer") or "").casefold() == source_tcp_endpoint.casefold()
        and str(keys.get("peerHash") or "").casefold() == source_user_hash
    )


def _ack_application_semantics(
    body: dict[str, Any],
    *,
    udp_version: int,
    part_count: int,
) -> bool:
    if udp_version > 3:
        expected = {
            "partStatusIncluded": True,
            "wirePartCount": 0,
            "partStatusApplied": True,
            "partCountAfter": part_count,
            "availablePartsAfter": part_count,
            "partStatusBitsAfter": "1" * part_count,
            "noNeededPartsAfter": False,
        }
    else:
        expected = {
            "partStatusIncluded": False,
            "wirePartCount": None,
            "partStatusApplied": False,
            "partCountAfter": None,
            "availablePartsAfter": None,
            "partStatusBitsAfter": None,
            "noNeededPartsAfter": None,
        }
    return all(body.get(field) == value for field, value in expected.items())


def _ack_transition_evidence(
    transition: ClientUdpAckTransition,
    *,
    file_hash: str,
    part_count: int,
    udp_version: int,
    expected_transport_mode: str = "plaintext",
    expected_should_crypt: bool | None = None,
) -> dict[str, Any]:
    requester_records = list(transition.requester_records)
    responder_records = list(transition.responder_records)
    source_hash = transition.source_user_hash.hex()
    control = _control_evidence(
        transition.control_receipt,
        file_hash=file_hash,
        source_tcp_endpoint=transition.source_tcp_endpoint,
        source_udp_endpoint=transition.source_udp_endpoint,
        source_user_hash=source_hash,
        source_udp_version=udp_version,
    )

    def identity(record: dict[str, Any]) -> bool:
        return _sched_identity(
            record,
            file_hash=file_hash,
            source_tcp_endpoint=transition.source_tcp_endpoint,
            source_user_hash=source_hash,
        )

    registration, registration_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_source_registered") and identity(record)
        ),
    )
    registration_ok = bool(
        registration is not None
        and _body(registration).get("outcome") == "accepted"
        and _body(registration).get("sourceUdpEndpoint")
        == transition.source_udp_endpoint
        and _body(registration).get("sourceUdpVersion") == udp_version
        and (
            expected_should_crypt is None
            or _body(registration).get("shouldCrypt") is expected_should_crypt
        )
        and _body(registration).get("lowId") is False
        and _body(registration).get("buddyEndpoint") is None
        and _body(registration).get("buddyId") is None
    )
    schedule, schedule_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_schedule_decision")
            and identity(record)
            and _body(record).get("outcome") == "eligible"
            and _body(record).get("reason") == "eligible"
        ),
    )
    schedule_ok = bool(
        schedule is not None
        and _body(schedule).get("outcome") == "eligible"
        and _body(schedule).get("reason") == "eligible"
    )
    decision, decision_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_decision")
            and identity(record)
            and _body(record).get("outcome") == "sent"
            and _body(record).get("transportEligible") is True
            and _body(record).get("reason") == "udp_reask_sent"
            and _body(record).get("path") == "direct"
        ),
    )
    decision_ok = bool(
        decision is not None
        and _body(decision).get("outcome") == "sent"
        and _body(decision).get("transportEligible") is True
        and _body(decision).get("reason") == "udp_reask_sent"
        and _body(decision).get("path") == "direct"
    )
    request_out, request_out_count = _single(
        requester_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.source_udp_endpoint.casefold()
            and str(_keys(record).get("fileHash") or "").casefold() == file_hash
            and _keys(record).get("protocolMarker") == OP_EMULEPROT
            and _keys(record).get("opcode") == OP_REASKFILEPING
            and _body(record).get("direction") == "send"
        ),
    )
    request_out_transport = _packet_transport_evidence(
        request_out,
        expected_transport_mode=expected_transport_mode,
    )
    request_out_ok = bool(
        request_out is not None
        and _body(request_out).get("outcome") == "attempted"
        and _body(request_out).get("role") == "reask_request"
        and _body(request_out).get("phase") == "reask_request"
        and request_out_transport["ok"] is True
    )
    request_attempt_id = (
        _keys(request_out).get("sendAttemptId") if request_out else None
    )
    request_terminal, request_terminal_count = _single(
        requester_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "send_outcome")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.source_udp_endpoint.casefold()
            and _keys(record).get("sendAttemptId") == request_attempt_id
            and _body(record).get("sendAttemptId") == request_attempt_id
        ),
    )
    request_terminal_ok = bool(
        request_terminal is not None
        and _body(request_terminal).get("outcome") == "send_succeeded"
        and _body(request_terminal).get("deliveryKnown") is True
        and _body(request_terminal).get("role") == "reask_request"
    )
    request_in, request_in_count = _single(
        responder_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.requester_udp_endpoint.casefold()
            and _keys(record).get("protocolMarker") == OP_EMULEPROT
            and _keys(record).get("opcode") == OP_REASKFILEPING
            and _body(record).get("direction") == "recv"
        ),
    )
    request_in_transport = _packet_transport_evidence(
        request_in,
        expected_transport_mode=expected_transport_mode,
    )
    request_in_ok = bool(
        request_in is not None
        and _body(request_in).get("outcome") == "accepted"
        and _body(request_in).get("phase") == "reask_request"
        and request_in_transport["ok"] is True
    )
    ack_out, ack_out_count = _single(
        responder_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.requester_udp_endpoint.casefold()
            and _keys(record).get("protocolMarker") == OP_EMULEPROT
            and _keys(record).get("opcode") == OP_REASKACK
            and _body(record).get("direction") == "send"
        ),
    )
    ack_out_transport = _packet_transport_evidence(
        ack_out,
        expected_transport_mode=expected_transport_mode,
    )
    ack_out_ok = bool(
        ack_out is not None
        and _body(ack_out).get("outcome") == "attempted"
        and _body(ack_out).get("role") == "reciprocity_reply"
        and _body(ack_out).get("phase") == "reciprocity_reply"
        and ack_out_transport["ok"] is True
    )
    ack_attempt_id = _keys(ack_out).get("sendAttemptId") if ack_out else None
    ack_terminal, ack_terminal_count = _single(
        responder_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "send_outcome")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.requester_udp_endpoint.casefold()
            and _keys(record).get("sendAttemptId") == ack_attempt_id
            and _body(record).get("sendAttemptId") == ack_attempt_id
        ),
    )
    ack_terminal_ok = bool(
        ack_terminal is not None
        and _body(ack_terminal).get("outcome") == "send_succeeded"
        and _body(ack_terminal).get("deliveryKnown") is True
        and _body(ack_terminal).get("role") == "reciprocity_reply"
    )
    ack_in, ack_in_count = _single(
        requester_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.source_udp_endpoint.casefold()
            and _keys(record).get("protocolMarker") == OP_EMULEPROT
            and _keys(record).get("opcode") == OP_REASKACK
            and _body(record).get("direction") == "recv"
        ),
    )
    ack_in_transport = _packet_transport_evidence(
        ack_in,
        expected_transport_mode=expected_transport_mode,
    )
    ack_in_ok = bool(
        ack_in is not None
        and _body(ack_in).get("outcome") == "accepted"
        and _body(ack_in).get("phase") == "reask_reply"
        and ack_in_transport["ok"] is True
    )

    request = _decode_request(
        request_out_transport["clearFrameHex"], udp_version=udp_version
    )
    responder_request = _decode_request(
        request_in_transport["clearFrameHex"], udp_version=udp_version
    )
    ack = _decode_ack(ack_out_transport["clearFrameHex"], udp_version=udp_version)
    requester_ack = _decode_ack(
        ack_in_transport["clearFrameHex"], udp_version=udp_version
    )
    queue_rank = ack.get("queueRank") if ack.get("ok") is True else None
    applied, applied_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_reply_applied")
            and identity(record)
            and _body(record).get("outcome") == "applied"
            and _body(record).get("replyOpcode") == OP_REASKACK
            and _body(record).get("queueRank") == queue_rank
            and _body(record).get("requestPendingAfter") is False
            and _body(record).get("remoteQueueFullAfter") is False
            and _body(record).get("sourceUdpEndpoint") == transition.source_udp_endpoint
            and _body(record).get("sourceUdpVersion") == udp_version
            and _body(record).get("queueRankApplied") is True
            and _ack_application_semantics(
                _body(record), udp_version=udp_version, part_count=part_count
            )
        ),
    )
    applied_ok = bool(
        applied is not None
        and _body(applied).get("outcome") == "applied"
        and _body(applied).get("replyOpcode") == OP_REASKACK
        and _body(applied).get("queueRank") == queue_rank
        and _body(applied).get("requestPendingAfter") is False
        and _body(applied).get("remoteQueueFullAfter") is False
        and _body(applied).get("sourceUdpEndpoint") == transition.source_udp_endpoint
        and _body(applied).get("sourceUdpVersion") == udp_version
        and _body(applied).get("queueRankApplied") is True
        and _ack_application_semantics(
            _body(applied), udp_version=udp_version, part_count=part_count
        )
    )

    requester_sequences = {
        "registration": _sequence(registration),
        "schedule": _sequence(schedule),
        "decision": _sequence(decision),
        "requestOut": _sequence(request_out),
        "requestTerminal": _sequence(request_terminal),
        "ackIn": _sequence(ack_in),
        "applied": _sequence(applied),
    }
    responder_sequences = {
        "requestIn": _sequence(request_in),
        "ackOut": _sequence(ack_out),
        "ackTerminal": _sequence(ack_terminal),
    }
    requester_ordered = bool(
        all(requester_sequences.values())
        and requester_sequences["registration"]
        < requester_sequences["schedule"]
        < requester_sequences["decision"]
        < requester_sequences["requestOut"]
        < requester_sequences["requestTerminal"]
        < requester_sequences["ackIn"]
        < requester_sequences["applied"]
    )
    responder_ordered = bool(
        all(responder_sequences.values())
        and responder_sequences["requestIn"]
        < responder_sequences["ackOut"]
        < responder_sequences["ackTerminal"]
    )
    counts = {
        "registration": registration_count,
        "schedule": schedule_count,
        "decision": decision_count,
        "requestOut": request_out_count,
        "requestTerminal": request_terminal_count,
        "requestIn": request_in_count,
        "ackOut": ack_out_count,
        "ackTerminal": ack_terminal_count,
        "ackIn": ack_in_count,
        "applied": applied_count,
    }
    expected_request = (
        bytes((OP_EMULEPROT, OP_REASKFILEPING))
        + bytes.fromhex(file_hash)
        + (_encode_part_status("0" * part_count) if udp_version > 3 else b"")
        + (
            int(request.get("completeSourceCount") or 0).to_bytes(2, "little")
            if udp_version > 2
            else b""
        )
        if request.get("ok") is True
        else b""
    )
    expected_ack = (
        bytes((OP_EMULEPROT, OP_REASKACK))
        + (_encode_part_status(None) if udp_version > 3 else b"")
        + int(queue_rank or 0).to_bytes(2, "little")
        if queue_rank
        else b""
    )
    wire_ok = bool(
        request_out_ok
        and request_in_ok
        and ack_out_ok
        and ack_in_ok
        and request.get("ok") is True
        and request.get("fileHash") == file_hash
        and (
            request.get("partStatus", {}).get("wirePartCount") == part_count
            and request.get("partStatus", {}).get("partStatusBits") == "0" * part_count
            if udp_version > 3
            else request.get("partStatus") is None
        )
        and (
            isinstance(request.get("completeSourceCount"), int)
            if udp_version > 2
            else request.get("completeSourceCount") is None
        )
        and request.get("rawHex") == expected_request.hex()
        and responder_request == request
        and ack.get("ok") is True
        and (
            ack.get("partStatus", {}).get("completeSource") is True
            if udp_version > 3
            else ack.get("partStatus") is None
        )
        and ack.get("rawHex") == expected_ack.hex()
        and requester_ack == ack
    )
    diagnostics_semantics_ok = all(
        (
            registration_ok,
            schedule_ok,
            decision_ok,
            request_terminal_ok,
            ack_terminal_ok,
            applied_ok,
        )
    )
    clear_transport = None
    encrypted_transport = None
    transport_decision_ok = expected_should_crypt is None
    if expected_should_crypt is False:
        plaintext = {"transportMode": "plaintext", "obfuscated": False}

        def packet_transport(record: dict[str, Any] | None) -> dict[str, Any] | None:
            if record is None:
                return None
            body = _body(record)
            return {
                "transportMode": body.get("transportMode"),
                "obfuscated": body.get("obfuscated"),
            }

        clear_transport = {
            "registrationShouldCrypt": (
                _body(registration).get("shouldCrypt")
                if registration is not None
                else None
            ),
            "requestOut": packet_transport(request_out),
            "requestIn": packet_transport(request_in),
            "ackOut": packet_transport(ack_out),
            "ackIn": packet_transport(ack_in),
        }
        clear_transport["ok"] = bool(
            clear_transport["registrationShouldCrypt"] is False
            and all(
                clear_transport[field] == plaintext
                for field in ("requestOut", "requestIn", "ackOut", "ackIn")
            )
        )
        transport_decision_ok = clear_transport["ok"] is True
    elif expected_should_crypt is True:
        encrypted_transport = {
            "registrationShouldCrypt": (
                _body(registration).get("shouldCrypt")
                if registration is not None
                else None
            ),
            "requestOut": request_out_transport,
            "requestIn": request_in_transport,
            "ackOut": ack_out_transport,
            "ackIn": ack_in_transport,
            "requestWireBytesEqual": (
                request_out_transport["rawHex"] == request_in_transport["rawHex"]
            ),
            "ackWireBytesEqual": (
                ack_out_transport["rawHex"] == ack_in_transport["rawHex"]
            ),
        }
        encrypted_transport["ok"] = bool(
            encrypted_transport["registrationShouldCrypt"] is True
            and all(
                encrypted_transport[field]["ok"] is True
                for field in ("requestOut", "requestIn", "ackOut", "ackIn")
            )
            and encrypted_transport["requestWireBytesEqual"] is True
            and encrypted_transport["ackWireBytesEqual"] is True
        )
        transport_decision_ok = encrypted_transport["ok"] is True
    ok = bool(
        transition.requester in CLIENTS
        and transition.responder in CLIENTS
        and transition.requester != transition.responder
        and control["ok"]
        and all(count == 1 for count in counts.values())
        and diagnostics_semantics_ok
        and isinstance(request_attempt_id, int)
        and not isinstance(request_attempt_id, bool)
        and request_attempt_id > 0
        and isinstance(ack_attempt_id, int)
        and not isinstance(ack_attempt_id, bool)
        and ack_attempt_id > 0
        and requester_ordered
        and responder_ordered
        and wire_ok
        and transport_decision_ok
    )
    result = {
        "ok": ok,
        "requester": transition.requester,
        "responder": transition.responder,
        "sourceTcpEndpoint": transition.source_tcp_endpoint,
        "sourceUdpEndpoint": transition.source_udp_endpoint,
        "sourceUserHash": source_hash,
        "requesterUdpEndpoint": transition.requester_udp_endpoint,
        "control": control,
        "wire": {
            "ok": wire_ok,
            "request": request,
            "ack": ack,
            "expectedRequestRawHex": expected_request.hex() or None,
            "expectedAckRawHex": expected_ack.hex() or None,
        },
        "diagnostics": {
            "ok": all(count == 1 for count in counts.values())
            and diagnostics_semantics_ok
            and requester_ordered
            and responder_ordered,
            "counts": counts,
            "requesterSequences": requester_sequences,
            "responderSequences": responder_sequences,
            "requesterOrdered": requester_ordered,
            "responderOrdered": responder_ordered,
            "requestSendAttemptId": request_attempt_id,
            "ackSendAttemptId": ack_attempt_id,
        },
        "application": _body(applied) if applied is not None else None,
    }
    if clear_transport is not None:
        result["clearTransport"] = clear_transport
    if encrypted_transport is not None:
        result["encryptedTransport"] = encrypted_transport
    return result


def _queue_full_transition_evidence(
    transition: ClientUdpQueueFullTransition,
    *,
    file_hash: str,
    part_count: int,
) -> dict[str, Any]:
    requester_records = list(transition.requester_records)
    responder_records = list(transition.responder_records)
    source_hash = transition.source_user_hash.hex()
    control = _control_evidence(
        transition.control_receipt,
        file_hash=file_hash,
        source_tcp_endpoint=transition.source_tcp_endpoint,
        source_udp_endpoint=transition.source_udp_endpoint,
        source_user_hash=source_hash,
    )
    waiter_removal = _waiter_removal_evidence(
        transition.waiter_removal_receipt,
        file_hash=file_hash,
        requester_udp_endpoint=transition.requester_udp_endpoint,
    )
    queue_pressure = _queue_pressure_evidence(
        transition.queue_pressure_receipt,
        file_hash=file_hash,
        requester_udp_endpoint=transition.requester_udp_endpoint,
    )

    def identity(record: dict[str, Any]) -> bool:
        return _sched_identity(
            record,
            file_hash=file_hash,
            source_tcp_endpoint=transition.source_tcp_endpoint,
            source_user_hash=source_hash,
        )

    def requester_packet(record: dict[str, Any], opcode: int, direction: str) -> bool:
        return bool(
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.source_udp_endpoint.casefold()
            and _keys(record).get("protocolMarker") == OP_EMULEPROT
            and _keys(record).get("opcode") == opcode
            and _body(record).get("direction") == direction
        )

    def responder_packet(record: dict[str, Any], opcode: int, direction: str) -> bool:
        return bool(
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.requester_udp_endpoint.casefold()
            and _keys(record).get("protocolMarker") == OP_EMULEPROT
            and _keys(record).get("opcode") == opcode
            and _body(record).get("direction") == direction
        )

    registration, registration_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_source_registered")
            and identity(record)
            and _body(record).get("outcome") == "accepted"
            and _body(record).get("sourceUdpEndpoint") == transition.source_udp_endpoint
            and _body(record).get("sourceUdpVersion") == 4
            and _body(record).get("lowId") is False
            and _body(record).get("buddyEndpoint") is None
            and _body(record).get("buddyId") is None
        ),
    )
    schedule, schedule_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_schedule_decision")
            and identity(record)
            and _body(record).get("outcome") == "eligible"
            and _body(record).get("reason") == "eligible"
        ),
    )
    decision, decision_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_decision")
            and identity(record)
            and _body(record).get("outcome") == "sent"
            and _body(record).get("transportEligible") is True
            and _body(record).get("reason") == "udp_reask_sent"
            and _body(record).get("path") == "direct"
        ),
    )
    request_out, request_out_count = _single(
        requester_records,
        lambda record: (
            requester_packet(record, OP_REASKFILEPING, "send")
            and str(_keys(record).get("fileHash") or "").casefold() == file_hash
            and _body(record).get("outcome") == "attempted"
            and _body(record).get("role") == "reask_request"
            and _body(record).get("phase") == "reask_request"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    request_attempt_id = (
        _keys(request_out).get("sendAttemptId") if request_out else None
    )
    request_terminal, request_terminal_count = _single(
        requester_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "send_outcome")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.source_udp_endpoint.casefold()
            and _keys(record).get("sendAttemptId") == request_attempt_id
            and _body(record).get("sendAttemptId") == request_attempt_id
            and _body(record).get("outcome") == "send_succeeded"
            and _body(record).get("deliveryKnown") is True
            and _body(record).get("role") == "reask_request"
        ),
    )
    request_in, request_in_count = _single(
        responder_records,
        lambda record: (
            responder_packet(record, OP_REASKFILEPING, "recv")
            and _body(record).get("outcome") == "accepted"
            and _body(record).get("phase") == "reask_request"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    consumed_body = {
        "outcome": "consumed",
        "fixtureId": queue_pressure["fixtureId"],
        "actualWaitingUserCount": queue_pressure["actualWaitingUserCount"],
        "effectiveWaitingUserCount": queue_pressure["effectiveWaitingUserCount"],
        "queueSize": queue_pressure["queueSize"],
        "queueFullMargin": queue_pressure["queueFullMargin"],
    }
    fixture_consumed, fixture_consumed_count = _single(
        responder_records,
        lambda record: (
            _event(record, "sched", "client_udp_queue_pressure_fixture_consumed")
            and str(_keys(record).get("fileHash") or "").casefold() == file_hash
            and str(_keys(record).get("peer") or "").casefold()
            == transition.requester_udp_endpoint.casefold()
            and _body(record) == consumed_body
        ),
    )
    queue_full_out, queue_full_out_count = _single(
        responder_records,
        lambda record: (
            responder_packet(record, OP_QUEUEFULL, "send")
            and _body(record).get("outcome") == "attempted"
            and _body(record).get("role") == "reciprocity_reply"
            and _body(record).get("phase") == "reciprocity_reply"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    queue_full_attempt_id = (
        _keys(queue_full_out).get("sendAttemptId") if queue_full_out else None
    )
    queue_full_terminal, queue_full_terminal_count = _single(
        responder_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "send_outcome")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.requester_udp_endpoint.casefold()
            and _keys(record).get("sendAttemptId") == queue_full_attempt_id
            and _body(record).get("sendAttemptId") == queue_full_attempt_id
            and _body(record).get("outcome") == "send_succeeded"
            and _body(record).get("deliveryKnown") is True
            and _body(record).get("role") == "reciprocity_reply"
        ),
    )
    queue_full_in, queue_full_in_count = _single(
        requester_records,
        lambda record: (
            requester_packet(record, OP_QUEUEFULL, "recv")
            and _body(record).get("outcome") == "accepted"
            and _body(record).get("phase") == "reask_reply"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    forbidden_responder_reply_count = sum(
        1
        for record in responder_records
        if any(
            responder_packet(record, opcode, "send")
            for opcode in (OP_REASKACK, OP_FILENOTFOUND)
        )
    )
    forbidden_requester_reply_count = sum(
        1
        for record in requester_records
        if any(
            requester_packet(record, opcode, "recv")
            for opcode in (OP_REASKACK, OP_FILENOTFOUND)
        )
    )

    request = _decode_request(_body(request_out).get("rawHex") if request_out else None)
    responder_request = _decode_request(
        _body(request_in).get("rawHex") if request_in else None
    )
    queue_full = _decode_queue_full(
        _body(queue_full_out).get("rawHex") if queue_full_out else None
    )
    requester_queue_full = _decode_queue_full(
        _body(queue_full_in).get("rawHex") if queue_full_in else None
    )
    applied, applied_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_reply_applied")
            and identity(record)
            and _body(record).get("outcome") == "applied"
            and _body(record).get("replyOpcode") == OP_QUEUEFULL
            and _body(record).get("queueRank") == 0
            and _body(record).get("requestPendingAfter") is False
            and _body(record).get("remoteQueueFullAfter") is True
            and _body(record).get("sourceUdpEndpoint") == transition.source_udp_endpoint
            and _body(record).get("sourceUdpVersion") == 4
            and _body(record).get("queueRankApplied") is True
            and _body(record).get("partStatusIncluded") is False
            and _body(record).get("wirePartCount") is None
            and _body(record).get("partStatusApplied") is False
            and _body(record).get("partCountAfter") is None
            and _body(record).get("availablePartsAfter") is None
            and _body(record).get("partStatusBitsAfter") is None
            and _body(record).get("noNeededPartsAfter") is None
            and isinstance(_body(record).get("udpTotalAfter"), int)
            and not isinstance(_body(record).get("udpTotalAfter"), bool)
            and _body(record).get("udpTotalAfter") > 0
            and _body(record).get("udpFailedAfter") == 0
            and _body(record).get("nextReaskScheduled") is True
            and _body(record).get("sourceRetainedAfter") is True
        ),
    )

    requester_sequences = {
        "registration": _sequence(registration),
        "schedule": _sequence(schedule),
        "decision": _sequence(decision),
        "requestOut": _sequence(request_out),
        "requestTerminal": _sequence(request_terminal),
        "queueFullIn": _sequence(queue_full_in),
        "applied": _sequence(applied),
    }
    responder_sequences = {
        "requestIn": _sequence(request_in),
        "fixtureConsumed": _sequence(fixture_consumed),
        "queueFullOut": _sequence(queue_full_out),
        "queueFullTerminal": _sequence(queue_full_terminal),
    }
    requester_ordered = bool(
        all(requester_sequences.values())
        and requester_sequences["registration"]
        < requester_sequences["schedule"]
        < requester_sequences["decision"]
        < requester_sequences["requestOut"]
        < requester_sequences["requestTerminal"]
        < requester_sequences["queueFullIn"]
        < requester_sequences["applied"]
    )
    responder_ordered = bool(
        all(responder_sequences.values())
        and responder_sequences["requestIn"] < responder_sequences["queueFullOut"]
        and responder_sequences["fixtureConsumed"]
        < responder_sequences["queueFullOut"]
        < responder_sequences["queueFullTerminal"]
    )
    counts = {
        "registration": registration_count,
        "schedule": schedule_count,
        "decision": decision_count,
        "requestOut": request_out_count,
        "requestTerminal": request_terminal_count,
        "requestIn": request_in_count,
        "fixtureConsumed": fixture_consumed_count,
        "queueFullOut": queue_full_out_count,
        "queueFullTerminal": queue_full_terminal_count,
        "queueFullIn": queue_full_in_count,
        "applied": applied_count,
        "forbiddenResponderReply": forbidden_responder_reply_count,
        "forbiddenRequesterReply": forbidden_requester_reply_count,
    }
    expected_request = (
        bytes((OP_EMULEPROT, OP_REASKFILEPING))
        + bytes.fromhex(file_hash)
        + _encode_part_status("0" * part_count)
        + int(request.get("completeSourceCount") or 0).to_bytes(2, "little")
        if request.get("ok") is True
        else b""
    )
    wire_ok = bool(
        request.get("ok") is True
        and request.get("fileHash") == file_hash
        and request.get("partStatus", {}).get("wirePartCount") == part_count
        and request.get("partStatus", {}).get("partStatusBits") == "0" * part_count
        and request.get("rawHex") == expected_request.hex()
        and responder_request == request
        and queue_full.get("ok") is True
        and queue_full.get("rawHex") == bytes((OP_EMULEPROT, OP_QUEUEFULL)).hex()
        and queue_full.get("payloadLength") == 0
        and requester_queue_full == queue_full
    )
    required_counts_ok = all(
        count == 1 for name, count in counts.items() if not name.startswith("forbidden")
    )
    forbidden_counts_ok = bool(
        forbidden_responder_reply_count == 0 and forbidden_requester_reply_count == 0
    )
    diagnostics_ok = bool(
        required_counts_ok
        and forbidden_counts_ok
        and requester_ordered
        and responder_ordered
    )
    ok = bool(
        transition.requester in CLIENTS
        and transition.responder in CLIENTS
        and transition.requester != transition.responder
        and control["ok"]
        and waiter_removal["ok"]
        and queue_pressure["ok"]
        and isinstance(request_attempt_id, int)
        and not isinstance(request_attempt_id, bool)
        and request_attempt_id > 0
        and isinstance(queue_full_attempt_id, int)
        and not isinstance(queue_full_attempt_id, bool)
        and queue_full_attempt_id > 0
        and diagnostics_ok
        and wire_ok
    )
    return {
        "ok": ok,
        "requester": transition.requester,
        "responder": transition.responder,
        "sourceTcpEndpoint": transition.source_tcp_endpoint,
        "sourceUdpEndpoint": transition.source_udp_endpoint,
        "sourceUserHash": source_hash,
        "requesterUdpEndpoint": transition.requester_udp_endpoint,
        "control": control,
        "waiterRemoval": waiter_removal,
        "queuePressure": queue_pressure,
        "wire": {
            "ok": wire_ok,
            "request": request,
            "queueFull": queue_full,
            "expectedRequestRawHex": expected_request.hex() or None,
            "expectedQueueFullRawHex": bytes((OP_EMULEPROT, OP_QUEUEFULL)).hex(),
        },
        "diagnostics": {
            "ok": diagnostics_ok,
            "counts": counts,
            "requesterSequences": requester_sequences,
            "responderSequences": responder_sequences,
            "requesterOrdered": requester_ordered,
            "responderOrdered": responder_ordered,
            "requestSendAttemptId": request_attempt_id,
            "queueFullSendAttemptId": queue_full_attempt_id,
        },
        "application": _body(applied) if applied is not None else None,
    }


def _file_not_found_transition_evidence(
    transition: ClientUdpFileNotFoundTransition,
    *,
    file_hash: str,
    part_count: int,
) -> dict[str, Any]:
    requester_records = list(transition.requester_records)
    responder_records = list(transition.responder_records)
    source_hash = transition.source_user_hash.hex()
    control = _control_evidence(
        transition.control_receipt,
        file_hash=file_hash,
        source_tcp_endpoint=transition.source_tcp_endpoint,
        source_udp_endpoint=transition.source_udp_endpoint,
        source_user_hash=source_hash,
    )
    withdrawal = _shared_withdrawal_evidence(
        transition.shared_withdrawal_receipt,
        file_hash=file_hash,
    )
    source_absence = _source_absence_evidence(
        transition.source_absence_receipt,
        file_hash=file_hash,
        source_tcp_endpoint=transition.source_tcp_endpoint,
        source_user_hash=source_hash,
    )

    def identity(record: dict[str, Any]) -> bool:
        return _sched_identity(
            record,
            file_hash=file_hash,
            source_tcp_endpoint=transition.source_tcp_endpoint,
            source_user_hash=source_hash,
        )

    def requester_packet(record: dict[str, Any], opcode: int, direction: str) -> bool:
        return bool(
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.source_udp_endpoint.casefold()
            and _keys(record).get("protocolMarker") == OP_EMULEPROT
            and _keys(record).get("opcode") == opcode
            and _body(record).get("direction") == direction
        )

    def responder_packet(record: dict[str, Any], opcode: int, direction: str) -> bool:
        return bool(
            _event(record, "ed2k_client_udp", "packet")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.requester_udp_endpoint.casefold()
            and _keys(record).get("protocolMarker") == OP_EMULEPROT
            and _keys(record).get("opcode") == opcode
            and _body(record).get("direction") == direction
        )

    registration, registration_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_source_registered")
            and identity(record)
            and _body(record).get("outcome") == "accepted"
            and _body(record).get("sourceUdpEndpoint") == transition.source_udp_endpoint
            and _body(record).get("sourceUdpVersion") == 4
            and _body(record).get("lowId") is False
            and _body(record).get("buddyEndpoint") is None
            and _body(record).get("buddyId") is None
        ),
    )
    schedule, schedule_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_schedule_decision")
            and identity(record)
            and _body(record).get("outcome") == "eligible"
            and _body(record).get("reason") == "eligible"
        ),
    )
    decision, decision_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_decision")
            and identity(record)
            and _body(record).get("outcome") == "sent"
            and _body(record).get("transportEligible") is True
            and _body(record).get("reason") == "udp_reask_sent"
            and _body(record).get("path") == "direct"
        ),
    )
    request_out, request_out_count = _single(
        requester_records,
        lambda record: (
            requester_packet(record, OP_REASKFILEPING, "send")
            and str(_keys(record).get("fileHash") or "").casefold() == file_hash
            and _body(record).get("outcome") == "attempted"
            and _body(record).get("role") == "reask_request"
            and _body(record).get("phase") == "reask_request"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    request_attempt_id = (
        _keys(request_out).get("sendAttemptId") if request_out else None
    )
    request_terminal, request_terminal_count = _single(
        requester_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "send_outcome")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.source_udp_endpoint.casefold()
            and _keys(record).get("sendAttemptId") == request_attempt_id
            and _body(record).get("sendAttemptId") == request_attempt_id
            and _body(record).get("outcome") == "send_succeeded"
            and _body(record).get("deliveryKnown") is True
            and _body(record).get("role") == "reask_request"
        ),
    )
    request_in, request_in_count = _single(
        responder_records,
        lambda record: (
            responder_packet(record, OP_REASKFILEPING, "recv")
            and _body(record).get("outcome") == "accepted"
            and _body(record).get("phase") == "reask_request"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    file_not_found_out, file_not_found_out_count = _single(
        responder_records,
        lambda record: (
            responder_packet(record, OP_FILENOTFOUND, "send")
            and _body(record).get("outcome") == "attempted"
            and _body(record).get("role") == "reciprocity_reply"
            and _body(record).get("phase") == "reciprocity_reply"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    file_not_found_attempt_id = (
        _keys(file_not_found_out).get("sendAttemptId") if file_not_found_out else None
    )
    file_not_found_terminal, file_not_found_terminal_count = _single(
        responder_records,
        lambda record: (
            _event(record, "ed2k_client_udp", "send_outcome")
            and str(_keys(record).get("peer") or "").casefold()
            == transition.requester_udp_endpoint.casefold()
            and _keys(record).get("sendAttemptId") == file_not_found_attempt_id
            and _body(record).get("sendAttemptId") == file_not_found_attempt_id
            and _body(record).get("outcome") == "send_succeeded"
            and _body(record).get("deliveryKnown") is True
            and _body(record).get("role") == "reciprocity_reply"
        ),
    )
    file_not_found_in, file_not_found_in_count = _single(
        requester_records,
        lambda record: (
            requester_packet(record, OP_FILENOTFOUND, "recv")
            and _body(record).get("outcome") == "accepted"
            and _body(record).get("phase") == "reask_reply"
            and _body(record).get("transportMode") == "plaintext"
            and _body(record).get("obfuscated") is False
            and _body(record).get("payloadHexTruncated") is False
        ),
    )
    forbidden_responder_reply_count = sum(
        1
        for record in responder_records
        if any(
            responder_packet(record, opcode, "send")
            for opcode in (OP_REASKACK, OP_QUEUEFULL)
        )
    )
    forbidden_requester_reply_count = sum(
        1
        for record in requester_records
        if any(
            requester_packet(record, opcode, "recv")
            for opcode in (OP_REASKACK, OP_QUEUEFULL)
        )
    )
    applied, applied_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "udp_reask_reply_applied")
            and identity(record)
            and _body(record).get("outcome") == "applied"
            and _body(record).get("replyOpcode") == OP_FILENOTFOUND
            and "queueRank" not in _body(record)
            and _body(record).get("requestPendingAfter") is False
            and _body(record).get("remoteQueueFullAfter") is False
            and _body(record).get("sourceUdpEndpoint") == transition.source_udp_endpoint
            and _body(record).get("sourceUdpVersion") == 4
            and _body(record).get("queueRankApplied") is False
            and _body(record).get("partStatusIncluded") is False
            and _body(record).get("wirePartCount") is None
            and _body(record).get("partStatusApplied") is False
            and _body(record).get("partCountAfter") is None
            and _body(record).get("availablePartsAfter") is None
            and _body(record).get("partStatusBitsAfter") is None
            and _body(record).get("noNeededPartsAfter") is None
        ),
    )
    dead_listed, dead_listed_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "source_dead_listed")
            and identity(record)
            and _body(record)
            == {
                "outcome": "dead_listed",
                "reason": "udp_fnf",
                "blockSecs": 45 * 60,
            }
        ),
    )
    dropped, dropped_count = _single(
        requester_records,
        lambda record: (
            _event(record, "sched", "source_dropped")
            and identity(record)
            and _body(record) == {"outcome": "dropped"}
        ),
    )
    forbidden_swap_count = sum(
        1
        for record in requester_records
        if _event(record, "sched", "source_swapped") and identity(record)
    )

    request = _decode_request(_body(request_out).get("rawHex") if request_out else None)
    responder_request = _decode_request(
        _body(request_in).get("rawHex") if request_in else None
    )
    file_not_found = _decode_file_not_found(
        _body(file_not_found_out).get("rawHex") if file_not_found_out else None
    )
    requester_file_not_found = _decode_file_not_found(
        _body(file_not_found_in).get("rawHex") if file_not_found_in else None
    )
    requester_sequences = {
        "registration": _sequence(registration),
        "schedule": _sequence(schedule),
        "decision": _sequence(decision),
        "requestOut": _sequence(request_out),
        "requestTerminal": _sequence(request_terminal),
        "fileNotFoundIn": _sequence(file_not_found_in),
        "applied": _sequence(applied),
        "deadListed": _sequence(dead_listed),
        "dropped": _sequence(dropped),
    }
    responder_sequences = {
        "requestIn": _sequence(request_in),
        "fileNotFoundOut": _sequence(file_not_found_out),
        "fileNotFoundTerminal": _sequence(file_not_found_terminal),
    }
    requester_ordered = bool(
        all(requester_sequences.values())
        and requester_sequences["registration"]
        < requester_sequences["schedule"]
        < requester_sequences["decision"]
        < requester_sequences["requestOut"]
        < requester_sequences["requestTerminal"]
        < requester_sequences["fileNotFoundIn"]
        < requester_sequences["applied"]
        < requester_sequences["deadListed"]
        < requester_sequences["dropped"]
    )
    responder_ordered = bool(
        all(responder_sequences.values())
        and responder_sequences["requestIn"]
        < responder_sequences["fileNotFoundOut"]
        < responder_sequences["fileNotFoundTerminal"]
    )
    counts = {
        "registration": registration_count,
        "schedule": schedule_count,
        "decision": decision_count,
        "requestOut": request_out_count,
        "requestTerminal": request_terminal_count,
        "requestIn": request_in_count,
        "fileNotFoundOut": file_not_found_out_count,
        "fileNotFoundTerminal": file_not_found_terminal_count,
        "fileNotFoundIn": file_not_found_in_count,
        "applied": applied_count,
        "deadListed": dead_listed_count,
        "dropped": dropped_count,
        "forbiddenResponderReply": forbidden_responder_reply_count,
        "forbiddenRequesterReply": forbidden_requester_reply_count,
        "forbiddenSwap": forbidden_swap_count,
    }
    expected_request = (
        bytes((OP_EMULEPROT, OP_REASKFILEPING))
        + bytes.fromhex(file_hash)
        + _encode_part_status("0" * part_count)
        + int(request.get("completeSourceCount") or 0).to_bytes(2, "little")
        if request.get("ok") is True
        else b""
    )
    wire_ok = bool(
        request.get("ok") is True
        and request.get("fileHash") == file_hash
        and request.get("partStatus", {}).get("wirePartCount") == part_count
        and request.get("partStatus", {}).get("partStatusBits") == "0" * part_count
        and request.get("rawHex") == expected_request.hex()
        and responder_request == request
        and file_not_found.get("ok") is True
        and file_not_found.get("rawHex") == bytes((OP_EMULEPROT, OP_FILENOTFOUND)).hex()
        and file_not_found.get("payloadLength") == 0
        and requester_file_not_found == file_not_found
    )
    required_counts_ok = all(
        count == 1 for name, count in counts.items() if not name.startswith("forbidden")
    )
    forbidden_counts_ok = all(
        count == 0 for name, count in counts.items() if name.startswith("forbidden")
    )
    diagnostics_ok = bool(
        required_counts_ok
        and forbidden_counts_ok
        and requester_ordered
        and responder_ordered
    )
    ok = bool(
        transition.requester in CLIENTS
        and transition.responder in CLIENTS
        and transition.requester != transition.responder
        and control["ok"]
        and withdrawal["ok"]
        and source_absence["ok"]
        and isinstance(request_attempt_id, int)
        and not isinstance(request_attempt_id, bool)
        and request_attempt_id > 0
        and isinstance(file_not_found_attempt_id, int)
        and not isinstance(file_not_found_attempt_id, bool)
        and file_not_found_attempt_id > 0
        and diagnostics_ok
        and wire_ok
    )
    return {
        "ok": ok,
        "requester": transition.requester,
        "responder": transition.responder,
        "sourceTcpEndpoint": transition.source_tcp_endpoint,
        "sourceUdpEndpoint": transition.source_udp_endpoint,
        "sourceUserHash": source_hash,
        "requesterUdpEndpoint": transition.requester_udp_endpoint,
        "control": control,
        "sharedWithdrawal": withdrawal,
        "sourceAbsence": source_absence,
        "wire": {
            "ok": wire_ok,
            "request": request,
            "fileNotFound": file_not_found,
            "expectedRequestRawHex": expected_request.hex() or None,
            "expectedFileNotFoundRawHex": bytes((OP_EMULEPROT, OP_FILENOTFOUND)).hex(),
        },
        "diagnostics": {
            "ok": diagnostics_ok,
            "counts": counts,
            "requesterSequences": requester_sequences,
            "responderSequences": responder_sequences,
            "requesterOrdered": requester_ordered,
            "responderOrdered": responder_ordered,
            "requestSendAttemptId": request_attempt_id,
            "fileNotFoundSendAttemptId": file_not_found_attempt_id,
        },
        "application": _body(applied) if applied is not None else None,
        "deadList": _body(dead_listed) if dead_listed is not None else None,
    }


def _build_client_udp_ack_diagnostic_evidence(
    *,
    file_hash: bytes,
    part_count: int,
    stock_record: object,
    transitions: Iterable[ClientUdpAckTransition],
    schema: str,
    coverage_id: str,
    udp_version: int,
    expected_transport_mode: str,
    expected_should_crypt: bool | None,
) -> dict[str, Any]:
    """Prove both clients originate, answer, and apply one exact direct ACK reask."""

    file_hash_hex = file_hash.hex()
    stock = _stock_authority(stock_record, coverage_id=coverage_id)
    transition_list = list(transitions)
    clients: dict[str, dict[str, Any]] = {}
    duplicate_requesters: list[str] = []
    for transition in transition_list:
        if transition.requester in clients:
            duplicate_requesters.append(transition.requester)
            continue
        clients[transition.requester] = _ack_transition_evidence(
            transition,
            file_hash=file_hash_hex,
            part_count=part_count,
            udp_version=udp_version,
            expected_transport_mode=expected_transport_mode,
            expected_should_crypt=expected_should_crypt,
        )
    exact_clients = set(clients) == set(CLIENTS) and not duplicate_requesters
    ordered_clients = [clients[client] for client in CLIENTS if client in clients]
    requests = [
        client.get("wire", {}).get("request", {}).get("rawHex")
        for client in ordered_clients
    ]
    acks = [
        client.get("wire", {}).get("ack", {}).get("rawHex")
        for client in ordered_clients
    ]
    ranks = [
        client.get("wire", {}).get("ack", {}).get("queueRank")
        for client in ordered_clients
    ]
    application_fields = (
        "replyOpcode",
        "queueRank",
        "requestPendingAfter",
        "remoteQueueFullAfter",
        "sourceUdpVersion",
        "queueRankApplied",
        "partStatusIncluded",
        "wirePartCount",
        "partStatusApplied",
        "partCountAfter",
        "availablePartsAfter",
        "partStatusBitsAfter",
        "noNeededPartsAfter",
        "outcome",
    )
    applications = [
        {field: application.get(field) for field in application_fields}
        for client in ordered_clients
        if isinstance((application := client.get("application")), dict)
    ]
    comparison = {
        "requestBytesEqual": len(requests) == 2 and requests[0] == requests[1],
        "ackBytesEqual": len(acks) == 2 and acks[0] == acks[1],
        "queueRankEqual": len(ranks) == 2 and ranks[0] == ranks[1],
        "applicationEqual": len(applications) == 2
        and applications[0] == applications[1],
        "bothApplied": exact_clients
        and all(client.get("ok") is True for client in clients.values()),
    }
    comparison["ok"] = all(comparison.values())
    failures = [
        *([] if stock["ok"] else ["stockAuthority"]),
        *([] if exact_clients else ["transitionSet"]),
        *[
            f"client.{client}"
            for client, evidence in clients.items()
            if evidence.get("ok") is not True
        ],
        *([] if comparison["ok"] else ["comparison"]),
    ]
    return {
        "schema": schema,
        "ok": not failures,
        "fileHash": file_hash_hex,
        "partCount": part_count,
        "stockAuthority": stock,
        "failures": failures,
        "clients": clients,
        "comparison": comparison,
        "coverageClaims": {
            "eligibleCoverageIds": [coverage_id] if not failures else [],
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def build_client_udp_v4_diagnostic_evidence(
    *,
    file_hash: bytes,
    part_count: int,
    stock_record: object,
    transitions: Iterable[ClientUdpAckTransition],
) -> dict[str, Any]:
    """Prove both clients originate, answer, and apply one exact direct V4 reask."""

    return _build_client_udp_ack_diagnostic_evidence(
        file_hash=file_hash,
        part_count=part_count,
        stock_record=stock_record,
        transitions=transitions,
        schema=SCHEMA,
        coverage_id=COVERAGE_ID,
        udp_version=4,
        expected_transport_mode="plaintext",
        expected_should_crypt=None,
    )


def build_client_udp_v2_diagnostic_evidence(
    *,
    file_hash: bytes,
    part_count: int,
    stock_record: object,
    transitions: Iterable[ClientUdpAckTransition],
) -> dict[str, Any]:
    """Prove both clients originate, answer, and apply one exact direct V2 reask."""

    return _build_client_udp_ack_diagnostic_evidence(
        file_hash=file_hash,
        part_count=part_count,
        stock_record=stock_record,
        transitions=transitions,
        schema=V2_SCHEMA,
        coverage_id=V2_COVERAGE_ID,
        udp_version=2,
        expected_transport_mode="plaintext",
        expected_should_crypt=None,
    )


def build_client_udp_v3_diagnostic_evidence(
    *,
    file_hash: bytes,
    part_count: int,
    stock_record: object,
    transitions: Iterable[ClientUdpAckTransition],
) -> dict[str, Any]:
    """Prove both clients originate, answer, and apply one exact direct V3 reask."""

    return _build_client_udp_ack_diagnostic_evidence(
        file_hash=file_hash,
        part_count=part_count,
        stock_record=stock_record,
        transitions=transitions,
        schema=V3_SCHEMA,
        coverage_id=V3_COVERAGE_ID,
        udp_version=3,
        expected_transport_mode="plaintext",
        expected_should_crypt=None,
    )


def build_client_udp_clear_diagnostic_evidence(
    *,
    file_hash: bytes,
    part_count: int,
    stock_record: object,
    transitions: Iterable[ClientUdpAckTransition],
) -> dict[str, Any]:
    """Prove the direct V4 request/ACK path was selected and carried in clear."""

    return _build_client_udp_ack_diagnostic_evidence(
        file_hash=file_hash,
        part_count=part_count,
        stock_record=stock_record,
        transitions=transitions,
        schema=CLEAR_SCHEMA,
        coverage_id=CLEAR_COVERAGE_ID,
        udp_version=4,
        expected_transport_mode="plaintext",
        expected_should_crypt=False,
    )


def build_client_udp_encrypted_diagnostic_evidence(
    *,
    file_hash: bytes,
    part_count: int,
    stock_record: object,
    transitions: Iterable[ClientUdpAckTransition],
) -> dict[str, Any]:
    """Prove the direct V4 request/ACK path used stock obfuscated transport."""

    return _build_client_udp_ack_diagnostic_evidence(
        file_hash=file_hash,
        part_count=part_count,
        stock_record=stock_record,
        transitions=transitions,
        schema=ENCRYPTED_SCHEMA,
        coverage_id=ENCRYPTED_COVERAGE_ID,
        udp_version=4,
        expected_transport_mode="obfuscated",
        expected_should_crypt=True,
    )


def _require_client_udp_ack_diagnostic_evidence(
    report: dict[str, Any],
    *,
    schema: str,
    coverage_id: str,
    label: str,
) -> None:
    """Raise unless both clients causally completed one exact direct ACK transition."""

    if report.get("schema") != schema:
        raise RuntimeError(f"Client-UDP {label} diagnostics have an unexpected schema")
    if report.get("ok") is not True:
        raise RuntimeError(
            f"Client-UDP {label} diagnostics are incomplete: {report.get('failures')!r}"
        )
    claims = report.get("coverageClaims")
    if not isinstance(claims, dict) or claims.get("eligibleCoverageIds") != [
        coverage_id
    ]:
        raise RuntimeError(f"Client-UDP {label} coverage claims are invalid")


def require_client_udp_v4_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raise unless both clients causally completed the exact direct V4 transition."""

    _require_client_udp_ack_diagnostic_evidence(
        report,
        schema=SCHEMA,
        coverage_id=COVERAGE_ID,
        label="V4",
    )


def require_client_udp_v2_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raise unless both clients causally completed the exact direct V2 transition."""

    _require_client_udp_ack_diagnostic_evidence(
        report,
        schema=V2_SCHEMA,
        coverage_id=V2_COVERAGE_ID,
        label="V2",
    )


def require_client_udp_v3_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raise unless both clients causally completed the exact direct V3 transition."""

    _require_client_udp_ack_diagnostic_evidence(
        report,
        schema=V3_SCHEMA,
        coverage_id=V3_COVERAGE_ID,
        label="V3",
    )


def require_client_udp_clear_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raise unless both clients causally selected and completed the clear path."""

    _require_client_udp_ack_diagnostic_evidence(
        report,
        schema=CLEAR_SCHEMA,
        coverage_id=CLEAR_COVERAGE_ID,
        label="clear",
    )


def require_client_udp_encrypted_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raise unless both clients causally selected and completed encrypted UDP."""

    _require_client_udp_ack_diagnostic_evidence(
        report,
        schema=ENCRYPTED_SCHEMA,
        coverage_id=ENCRYPTED_COVERAGE_ID,
        label="encrypted",
    )


def build_client_udp_queue_full_diagnostic_evidence(
    *,
    file_hash: bytes,
    part_count: int,
    stock_record: object,
    transitions: Iterable[ClientUdpQueueFullTransition],
) -> dict[str, Any]:
    """Prove both clients originate, answer, and apply one exact queue-full reask."""

    file_hash_hex = file_hash.hex()
    stock = _stock_authority(stock_record, coverage_id=QUEUE_FULL_COVERAGE_ID)
    transition_list = list(transitions)
    clients: dict[str, dict[str, Any]] = {}
    duplicate_requesters: list[str] = []
    for transition in transition_list:
        if transition.requester in clients:
            duplicate_requesters.append(transition.requester)
            continue
        clients[transition.requester] = _queue_full_transition_evidence(
            transition,
            file_hash=file_hash_hex,
            part_count=part_count,
        )
    exact_clients = set(clients) == set(CLIENTS) and not duplicate_requesters
    ordered_clients = [clients[client] for client in CLIENTS if client in clients]
    requests = [
        client.get("wire", {}).get("request", {}).get("rawHex")
        for client in ordered_clients
    ]
    replies = [
        client.get("wire", {}).get("queueFull", {}).get("rawHex")
        for client in ordered_clients
    ]
    application_fields = (
        "replyOpcode",
        "queueRank",
        "requestPendingAfter",
        "remoteQueueFullAfter",
        "sourceUdpVersion",
        "queueRankApplied",
        "partStatusIncluded",
        "wirePartCount",
        "partStatusApplied",
        "partCountAfter",
        "availablePartsAfter",
        "partStatusBitsAfter",
        "noNeededPartsAfter",
        "udpFailedAfter",
        "nextReaskScheduled",
        "sourceRetainedAfter",
        "outcome",
    )
    applications = [
        {field: application.get(field) for field in application_fields}
        for client in ordered_clients
        if isinstance((application := client.get("application")), dict)
    ]
    comparison = {
        "requestBytesEqual": len(requests) == 2 and requests[0] == requests[1],
        "queueFullBytesEqual": len(replies) == 2 and replies[0] == replies[1],
        "applicationEqual": len(applications) == 2
        and applications[0] == applications[1],
        "bothApplied": exact_clients
        and all(client.get("ok") is True for client in ordered_clients),
    }
    comparison["ok"] = all(comparison.values())
    shape_ok = len(file_hash) == 16 and part_count > 0
    failures = [
        *([] if shape_ok else ["fixtureShape"]),
        *([] if stock["ok"] else ["stockAuthority"]),
        *([] if exact_clients else ["transitionSet"]),
        *[
            f"client.{client}"
            for client, client_evidence in clients.items()
            if client_evidence.get("ok") is not True
        ],
        *([] if comparison["ok"] else ["comparison"]),
    ]
    return {
        "schema": QUEUE_FULL_SCHEMA,
        "ok": not failures,
        "fileHash": file_hash_hex,
        "partCount": part_count,
        "stockAuthority": stock,
        "failures": failures,
        "clients": clients,
        "comparison": comparison,
        "coverageClaims": {
            "eligibleCoverageIds": [QUEUE_FULL_COVERAGE_ID] if not failures else [],
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_client_udp_queue_full_diagnostic_evidence(
    report: dict[str, Any],
) -> None:
    """Raise unless both clients causally completed the exact queue-full transition."""

    if report.get("schema") != QUEUE_FULL_SCHEMA:
        raise RuntimeError(
            "Client-UDP queue-full diagnostics have an unexpected schema"
        )
    if report.get("ok") is not True:
        raise RuntimeError(
            "Client-UDP queue-full diagnostics are incomplete: "
            f"{report.get('failures')!r}"
        )
    claims = report.get("coverageClaims")
    if not isinstance(claims, dict) or claims.get("eligibleCoverageIds") != [
        QUEUE_FULL_COVERAGE_ID
    ]:
        raise RuntimeError("Client-UDP queue-full coverage claims are invalid")


def build_client_udp_file_not_found_diagnostic_evidence(
    *,
    file_hash: bytes,
    part_count: int,
    stock_record: object,
    transitions: Iterable[ClientUdpFileNotFoundTransition],
) -> dict[str, Any]:
    """Prove both clients answer and apply one exact file-not-found reask."""

    file_hash_hex = file_hash.hex()
    stock = _stock_authority(
        stock_record,
        coverage_id=FILE_NOT_FOUND_COVERAGE_ID,
    )
    transition_list = list(transitions)
    clients: dict[str, dict[str, Any]] = {}
    duplicate_requesters: list[str] = []
    for transition in transition_list:
        if transition.requester in clients:
            duplicate_requesters.append(transition.requester)
            continue
        clients[transition.requester] = _file_not_found_transition_evidence(
            transition,
            file_hash=file_hash_hex,
            part_count=part_count,
        )
    exact_clients = set(clients) == set(CLIENTS) and not duplicate_requesters
    ordered_clients = [clients[client] for client in CLIENTS if client in clients]
    requests = [
        client.get("wire", {}).get("request", {}).get("rawHex")
        for client in ordered_clients
    ]
    replies = [
        client.get("wire", {}).get("fileNotFound", {}).get("rawHex")
        for client in ordered_clients
    ]
    application_fields = (
        "replyOpcode",
        "queueRank",
        "requestPendingAfter",
        "remoteQueueFullAfter",
        "sourceUdpVersion",
        "queueRankApplied",
        "partStatusIncluded",
        "wirePartCount",
        "partStatusApplied",
        "partCountAfter",
        "availablePartsAfter",
        "partStatusBitsAfter",
        "noNeededPartsAfter",
        "outcome",
    )
    applications = [
        {field: application.get(field) for field in application_fields}
        for client in ordered_clients
        if isinstance((application := client.get("application")), dict)
    ]
    dead_lists = [
        client.get("deadList")
        for client in ordered_clients
        if isinstance(client.get("deadList"), dict)
    ]
    comparison = {
        "requestBytesEqual": len(requests) == 2 and requests[0] == requests[1],
        "fileNotFoundBytesEqual": len(replies) == 2 and replies[0] == replies[1],
        "applicationEqual": len(applications) == 2
        and applications[0] == applications[1],
        "deadListEqual": len(dead_lists) == 2 and dead_lists[0] == dead_lists[1],
        "bothDropped": exact_clients
        and all(client.get("ok") is True for client in ordered_clients),
    }
    comparison["ok"] = all(comparison.values())
    shape_ok = len(file_hash) == 16 and part_count > 0
    failures = [
        *([] if shape_ok else ["fixtureShape"]),
        *([] if stock["ok"] else ["stockAuthority"]),
        *([] if exact_clients else ["transitionSet"]),
        *[
            f"client.{client}"
            for client, client_evidence in clients.items()
            if client_evidence.get("ok") is not True
        ],
        *([] if comparison["ok"] else ["comparison"]),
    ]
    return {
        "schema": FILE_NOT_FOUND_SCHEMA,
        "ok": not failures,
        "fileHash": file_hash_hex,
        "partCount": part_count,
        "stockAuthority": stock,
        "failures": failures,
        "clients": clients,
        "comparison": comparison,
        "coverageClaims": {
            "eligibleCoverageIds": (
                [FILE_NOT_FOUND_COVERAGE_ID] if not failures else []
            ),
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_client_udp_file_not_found_diagnostic_evidence(
    report: dict[str, Any],
) -> None:
    """Raise unless both clients causally completed file-not-found handling."""

    if report.get("schema") != FILE_NOT_FOUND_SCHEMA:
        raise RuntimeError(
            "Client-UDP file-not-found diagnostics have an unexpected schema"
        )
    if report.get("ok") is not True:
        raise RuntimeError(
            "Client-UDP file-not-found diagnostics are incomplete: "
            f"{report.get('failures')!r}"
        )
    claims = report.get("coverageClaims")
    if not isinstance(claims, dict) or claims.get("eligibleCoverageIds") != [
        FILE_NOT_FOUND_COVERAGE_ID
    ]:
        raise RuntimeError("Client-UDP file-not-found coverage claims are invalid")
