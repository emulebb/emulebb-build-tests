"""Minimal provider-neutral eD2K server wire client for deterministic campaigns."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import struct
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Iterable


PROTO_EDONKEY = 0xE3
PROTO_PACKED = 0xD4

OP_LOGINREQUEST = 0x01
OP_OFFERFILES = 0x15
OP_SEARCHREQUEST = 0x16
OP_GETSOURCES = 0x19
OP_GETSOURCES_OBFU = 0x23
OP_SEARCHRESULT = 0x33
OP_SERVERSTATUS = 0x34
OP_IDCHANGE = 0x40
OP_SERVERIDENT = 0x41
OP_FOUNDSOURCES = 0x42
OP_FOUNDSOURCES_OBFU = 0x44
OP_GLOBGETSOURCES2 = 0x94
OP_GLOBSERVSTATREQ = 0x96
OP_GLOBSERVSTATRES = 0x97
OP_GLOBGETSOURCES = 0x9A
OP_GLOBFOUNDSOURCES = 0x9B
OP_SERVER_DESC_REQ = 0xA2
OP_SERVER_DESC_RES = 0xA3

CT_NAME = 0x01
CT_SERVER_FLAGS = 0x20
FT_FILENAME = 0x01
FT_FILESIZE = 0x02
FT_SOURCES = 0x15
FT_COMPLETE_SOURCES = 0x30
FT_FILESIZE_HI = 0x3A
ST_SERVERNAME = 0x01
ST_DESCRIPTION = 0x0B
ST_DYNIP = 0x85
ST_VERSION = 0x91
ST_AUXPORTSLIST = 0x93

TAGTYPE_HASH = 0x01
TAGTYPE_STRING = 0x02
TAGTYPE_UINT32 = 0x03
TAGTYPE_FLOAT32 = 0x04
TAGTYPE_BOOL = 0x05
TAGTYPE_BOOLARRAY = 0x06
TAGTYPE_BLOB = 0x07
TAGTYPE_UINT16 = 0x08
TAGTYPE_UINT8 = 0x09
TAGTYPE_BSOB = 0x0A
TAGTYPE_UINT64 = 0x0B
TAGTYPE_STR1_BASE = 0x10
TAG_SHORT_NAME = 0x80

SRVCAP_ZLIB = 0x0001
SRVCAP_NEWTAGS = 0x0008
SRVCAP_UNICODE = 0x0010
SRVCAP_LARGEFILES = 0x0100
SRVCAP_SUPPORTCRYPT = 0x0200
SRVCAP_LUGDUNUM_NAT_CALLBACK = 0x1000
SERVER_UDP_FLAG_UDPOBFUSCATION = 0x0000_0200
SERVER_UDP_FLAG_TCPOBFUSCATION = 0x0000_0400
SERVER_STATUS_CHALLENGE_PREFIX = 0x55AA_0000
SERVER_DESCRIPTION_CHALLENGE_SUFFIX = 0xF0FF
DEFAULT_SERVER_FLAGS = (
    SRVCAP_ZLIB
    | SRVCAP_NEWTAGS
    | SRVCAP_UNICODE
    | SRVCAP_LARGEFILES
    | SRVCAP_SUPPORTCRYPT
    | SRVCAP_LUGDUNUM_NAT_CALLBACK
)

LOW_ID_CEILING = 0x0100_0000
IPV6_SOURCE_SENTINEL = 0xFFFF_FFFF
COMPLETE_FILE_ID = 0xFBFB_FBFB
COMPLETE_FILE_PORT = 0xFBFB
MAX_FRAME_BYTES = 8_000_000

SEARCH_PARAM_BOOLEAN = 0x00
SEARCH_PARAM_STRING = 0x01
SEARCH_PARAM_NUMERIC32 = 0x03
SEARCH_BOOL_AND = 0x00
SEARCH_OP_GREATER_EQUAL = 0x03
SEARCH_OP_LESS_EQUAL = 0x04


class Ed2kWireError(RuntimeError):
    """Raised for malformed, truncated, or unexpected eD2K traffic."""


@dataclass(frozen=True)
class ServerSearchCriteria:
    """Deterministic subset of stock eD2K server-search constraints."""

    min_size_bytes: int | None = None
    max_size_bytes: int | None = None

    def __post_init__(self) -> None:
        for field_name, value in (
            ("min_size_bytes", self.min_size_bytes),
            ("max_size_bytes", self.max_size_bytes),
        ):
            if value is not None and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 < value <= 0xFFFF_FFFF
            ):
                raise ValueError(f"{field_name} must be a positive u32 when set")
        if (
            self.min_size_bytes is not None
            and self.max_size_bytes is not None
            and self.max_size_bytes < self.min_size_bytes
        ):
            raise ValueError("max_size_bytes must be greater than or equal to min_size_bytes")


@dataclass(frozen=True)
class Ed2kFrame:
    """One decoded eD2K TCP frame."""

    marker: int
    opcode: int
    payload: bytes

    def evidence(self, direction: str) -> dict[str, object]:
        """Returns the complete local-test frame evidence record."""

        return {
            "direction": direction,
            "protocolMarker": self.marker,
            "opcode": self.opcode,
            "payloadLength": len(self.payload),
            "payloadSha256": hashlib.sha256(self.payload).hexdigest(),
            "payloadHex": self.payload.hex(),
        }


class _Reader:
    """Bounded little-endian reader used by protocol decoders."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def take(self, size: int) -> bytes:
        if size < 0 or self.remaining < size:
            raise Ed2kWireError(
                f"eD2K payload underrun at {self.offset}: need {size}, have {self.remaining}."
            )
        value = self.data[self.offset : self.offset + size]
        self.offset += size
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "little")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "little")


def encode_frame(opcode: int, payload: bytes = b"") -> bytes:
    """Encodes one clear eD2K TCP frame."""

    if not 0 <= opcode <= 0xFF:
        raise ValueError("opcode must fit in one byte")
    return (
        bytes([PROTO_EDONKEY])
        + struct.pack("<I", len(payload) + 1)
        + bytes([opcode])
        + payload
    )


def decode_frame_bytes(data: bytes) -> Ed2kFrame:
    """Decodes exactly one complete clear or packed eD2K TCP frame."""

    if len(data) < 6:
        raise Ed2kWireError("eD2K frame is shorter than its six-byte header.")
    marker = data[0]
    if marker not in {PROTO_EDONKEY, PROTO_PACKED}:
        raise Ed2kWireError(f"Unsupported eD2K protocol marker 0x{marker:02X}.")
    declared = int.from_bytes(data[1:5], "little")
    if declared < 1 or declared > MAX_FRAME_BYTES:
        raise Ed2kWireError(f"Invalid eD2K frame length {declared}.")
    if len(data) != declared + 5:
        raise Ed2kWireError(
            f"eD2K frame length mismatch: declared {declared + 5}, received {len(data)}."
        )
    opcode = data[5]
    payload = data[6:]
    if marker == PROTO_PACKED:
        try:
            payload = zlib.decompress(payload)
        except zlib.error as exc:
            raise Ed2kWireError(
                f"Packed eD2K frame decompression failed: {exc}"
            ) from exc
        if len(payload) > MAX_FRAME_BYTES:
            raise Ed2kWireError("Packed eD2K frame expands beyond the harness limit.")
    return Ed2kFrame(marker=marker, opcode=opcode, payload=payload)


def _short_string_tag(tag_id: int, value: str) -> bytes:
    encoded = value.encode("utf-8")
    return (
        bytes([TAG_SHORT_NAME | TAGTYPE_STRING, tag_id])
        + struct.pack("<H", len(encoded))
        + encoded
    )


def _u32_tag(tag_id: int, value: int) -> bytes:
    return bytes([TAG_SHORT_NAME | TAGTYPE_UINT32, tag_id]) + struct.pack("<I", value)


def encode_login_request(
    *,
    user_hash: bytes,
    tcp_port: int,
    nickname: str,
    server_flags: int = DEFAULT_SERVER_FLAGS,
) -> bytes:
    """Builds a stock-shaped server LOGINREQUEST payload."""

    if len(user_hash) != 16:
        raise ValueError("user_hash must be 16 bytes")
    tags = [
        _short_string_tag(CT_NAME, nickname),
        _u32_tag(CT_SERVER_FLAGS, server_flags),
    ]
    return (
        user_hash
        + struct.pack("<IH", 0, tcp_port)
        + struct.pack("<I", len(tags))
        + b"".join(tags)
    )


def decode_login_request(payload: bytes) -> dict[str, object]:
    """Decodes one complete ``OP_LOGINREQUEST`` payload without losing tag order."""

    reader = _Reader(payload)
    user_hash = reader.take(16)
    client_id = reader.u32()
    tcp_port = reader.u16()
    tag_count = reader.u32()
    tags: list[dict[str, object]] = []
    for _ in range(tag_count):
        name, value = _decode_tag(reader)
        if isinstance(value, bytes):
            normalized_value: object = value.hex().upper()
        else:
            normalized_value = value
        tags.append({"name": name, "value": normalized_value})
    if reader.remaining:
        raise Ed2kWireError(f"LOGINREQUEST has {reader.remaining} trailing bytes.")
    return {
        "user_hash": user_hash.hex().upper(),
        "client_id": client_id,
        "tcp_port": tcp_port,
        "tag_count": tag_count,
        "tags": tags,
    }


def decode_id_change(payload: bytes) -> dict[str, object]:
    """Decodes the assigned client ID from an accepted ``OP_IDCHANGE`` payload."""

    reader = _Reader(payload)
    assigned_id = reader.u32()
    return {
        "assigned_id": assigned_id,
        "id_kind": "low-id" if assigned_id < LOW_ID_CEILING else "high-id",
        "extension_hex": reader.take(reader.remaining).hex().upper(),
    }


def decode_server_status(payload: bytes) -> dict[str, int]:
    """Decodes one exact eight-byte ``OP_SERVERSTATUS`` payload."""

    reader = _Reader(payload)
    users = reader.u32()
    files = reader.u32()
    if reader.remaining:
        raise Ed2kWireError(f"SERVERSTATUS has {reader.remaining} trailing bytes.")
    return {"users": users, "files": files}


def decode_server_udp_status_request(payload: bytes) -> dict[str, int]:
    """Decodes one exact challenged ``OP_GLOBSERVSTATREQ`` payload."""

    if len(payload) != 4:
        raise Ed2kWireError(
            f"GLOBSERVSTATREQ must contain one four-byte challenge, got {len(payload)} bytes."
        )
    challenge = int.from_bytes(payload, "little")
    if challenge & 0xFFFF_0000 != SERVER_STATUS_CHALLENGE_PREFIX:
        raise Ed2kWireError(
            f"GLOBSERVSTATREQ challenge 0x{challenge:08X} lacks the 0x55AA prefix."
        )
    return {"challenge": challenge}


def decode_server_udp_status_response(
    payload: bytes,
    *,
    expected_challenge: int | None = None,
    server_port: int | None = None,
) -> dict[str, int | str]:
    """Decodes the complete stock ``OP_GLOBSERVSTATRES`` optional-field layout."""

    if len(payload) < 12:
        raise Ed2kWireError(
            f"GLOBSERVSTATRES requires challenge/users/files, got {len(payload)} bytes."
        )
    reader = _Reader(payload)
    challenge = reader.u32()
    if expected_challenge is not None and challenge != expected_challenge:
        raise Ed2kWireError(
            f"GLOBSERVSTATRES challenge 0x{challenge:08X} does not match 0x{expected_challenge:08X}."
        )
    users = reader.u32()
    files = reader.u32()
    max_users = reader.u32() if len(payload) >= 16 else 0
    soft_files = reader.u32() if len(payload) >= 24 else 0
    hard_files = reader.u32() if len(payload) >= 24 else 0
    udp_flags = reader.u32() if len(payload) >= 28 else 0
    low_id_users = reader.u32() if len(payload) >= 32 else 0
    wire_obfuscation_port_udp = reader.u16() if len(payload) >= 40 else 0
    wire_obfuscation_port_tcp = reader.u16() if len(payload) >= 40 else 0
    udp_key = reader.u32() if len(payload) >= 40 else 0
    trailing = reader.take(reader.remaining)
    obfuscation_port_udp = wire_obfuscation_port_udp
    obfuscation_port_tcp = wire_obfuscation_port_tcp
    if server_port is not None:
        if not obfuscation_port_tcp and udp_flags & SERVER_UDP_FLAG_TCPOBFUSCATION:
            obfuscation_port_tcp = server_port
        if not obfuscation_port_udp and udp_flags & SERVER_UDP_FLAG_UDPOBFUSCATION:
            obfuscation_port_udp = server_port + 12 if server_port <= 0xFFFF - 12 else 0
    return {
        "challenge": challenge,
        "users": users,
        "files": files,
        "max_users": max_users,
        "soft_files": soft_files,
        "hard_files": hard_files,
        "udp_flags": udp_flags,
        "low_id_users": low_id_users,
        "wire_obfuscation_port_udp": wire_obfuscation_port_udp,
        "wire_obfuscation_port_tcp": wire_obfuscation_port_tcp,
        "obfuscation_port_udp": obfuscation_port_udp,
        "obfuscation_port_tcp": obfuscation_port_tcp,
        "udp_key": udp_key,
        "trailing_hex": trailing.hex().upper(),
    }


def _server_udp_payload(
    datagram: bytes,
    *,
    expected_opcode: int,
    message_name: str,
) -> bytes:
    """Returns the payload of one exact clear eD2K server UDP datagram."""

    if len(datagram) < 2:
        raise Ed2kWireError(f"{message_name} is shorter than its marker and opcode.")
    marker, opcode = datagram[:2]
    if marker != PROTO_EDONKEY:
        raise Ed2kWireError(
            f"{message_name} has unsupported protocol marker 0x{marker:02X}."
        )
    if opcode != expected_opcode:
        raise Ed2kWireError(
            f"{message_name} has opcode 0x{opcode:02X}, expected 0x{expected_opcode:02X}."
        )
    return datagram[2:]


def encode_server_udp_source_v1_request(file_hashes: Iterable[bytes]) -> bytes:
    """Encodes one clear ``OP_GLOBGETSOURCES`` hash-only datagram."""

    hashes = tuple(file_hashes)
    if not hashes:
        raise ValueError("GLOBGETSOURCES requires at least one file hash")
    if any(len(file_hash) != 16 for file_hash in hashes):
        raise ValueError("each GLOBGETSOURCES file hash must be 16 bytes")
    return bytes([PROTO_EDONKEY, OP_GLOBGETSOURCES]) + b"".join(hashes)


def decode_server_udp_source_v1_request(datagram: bytes) -> dict[str, object]:
    """Decodes one exact clear ``OP_GLOBGETSOURCES`` hash-only datagram."""

    payload = _server_udp_payload(
        datagram,
        expected_opcode=OP_GLOBGETSOURCES,
        message_name="GLOBGETSOURCES",
    )
    if not payload or len(payload) % 16:
        raise Ed2kWireError(
            "GLOBGETSOURCES payload must contain one or more complete 16-byte hashes."
        )
    hashes = [
        payload[offset : offset + 16].hex().upper()
        for offset in range(0, len(payload), 16)
    ]
    return {"hash_count": len(hashes), "hashes": hashes}


def encode_server_udp_source_v2_request(
    targets: Iterable[tuple[bytes, int]],
) -> bytes:
    """Encodes one canonical clear ``OP_GLOBGETSOURCES2`` datagram."""

    target_rows = tuple(targets)
    if not target_rows:
        raise ValueError("GLOBGETSOURCES2 requires at least one target")
    payload = bytearray()
    for file_hash, file_size in target_rows:
        if len(file_hash) != 16:
            raise ValueError("each GLOBGETSOURCES2 file hash must be 16 bytes")
        if (
            not isinstance(file_size, int)
            or isinstance(file_size, bool)
            or not 1 <= file_size <= 0xFFFF_FFFF_FFFF_FFFF
        ):
            raise ValueError("each GLOBGETSOURCES2 file size must fit in a nonzero u64")
        payload.extend(file_hash)
        if file_size > 0xFFFF_FFFF:
            payload.extend(struct.pack("<IQ", 0, file_size))
        else:
            payload.extend(struct.pack("<I", file_size))
    return bytes([PROTO_EDONKEY, OP_GLOBGETSOURCES2]) + bytes(payload)


def decode_server_udp_source_v2_request(datagram: bytes) -> dict[str, object]:
    """Decodes one canonical clear ``OP_GLOBGETSOURCES2`` datagram."""

    payload = _server_udp_payload(
        datagram,
        expected_opcode=OP_GLOBGETSOURCES2,
        message_name="GLOBGETSOURCES2",
    )
    if not payload:
        raise Ed2kWireError("GLOBGETSOURCES2 requires at least one target.")
    targets: list[dict[str, object]] = []
    offset = 0
    while offset < len(payload):
        remaining = len(payload) - offset
        if remaining < 20:
            raise Ed2kWireError(
                "GLOBGETSOURCES2 target requires a 16-byte hash and 4-byte file size."
            )
        file_hash = payload[offset : offset + 16]
        file_size32 = struct.unpack_from("<I", payload, offset + 16)[0]
        offset += 20
        large_file = file_size32 == 0
        if large_file:
            if len(payload) - offset < 8:
                raise Ed2kWireError(
                    "GLOBGETSOURCES2 large-file target requires an 8-byte file size."
                )
            file_size = struct.unpack_from("<Q", payload, offset)[0]
            offset += 8
            if file_size <= 0xFFFF_FFFF:
                raise Ed2kWireError(
                    "GLOBGETSOURCES2 large-file marker requires a size above u32."
                )
        else:
            file_size = file_size32
        targets.append(
            {
                "hash": file_hash.hex().upper(),
                "size_bytes": file_size,
                "large_file": large_file,
            }
        )
    return {"target_count": len(targets), "targets": targets}


def encode_server_udp_source_reply(
    *,
    file_hash: bytes,
    sources: Iterable[tuple[int, int]],
) -> bytes:
    """Encodes one clear IPv4 ``OP_GLOBFOUNDSOURCES`` datagram."""

    if len(file_hash) != 16:
        raise ValueError("file_hash must be 16 bytes")
    source_rows = tuple(sources)
    if len(source_rows) > 0xFF:
        raise ValueError("GLOBFOUNDSOURCES source count must fit in one byte")
    payload = bytearray(file_hash)
    payload.append(len(source_rows))
    for client_id, port in source_rows:
        if (
            not isinstance(client_id, int)
            or isinstance(client_id, bool)
            or not 0 <= client_id <= 0xFFFF_FFFF
        ):
            raise ValueError("GLOBFOUNDSOURCES client ID must fit in u32")
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 0xFFFF
        ):
            raise ValueError("GLOBFOUNDSOURCES TCP port must be in 1..65535")
        payload.extend(struct.pack("<IH", client_id, port))
    return bytes([PROTO_EDONKEY, OP_GLOBFOUNDSOURCES]) + bytes(payload)


def decode_server_udp_source_reply(datagram: bytes) -> dict[str, object]:
    """Decodes one exact clear IPv4 ``OP_GLOBFOUNDSOURCES`` datagram."""

    payload = _server_udp_payload(
        datagram,
        expected_opcode=OP_GLOBFOUNDSOURCES,
        message_name="GLOBFOUNDSOURCES",
    )
    if len(payload) < 17:
        raise Ed2kWireError(
            "GLOBFOUNDSOURCES payload requires a 16-byte hash and source count."
        )
    source_count = payload[16]
    expected_length = 17 + source_count * 6
    if len(payload) != expected_length:
        raise Ed2kWireError(
            "GLOBFOUNDSOURCES payload length mismatch: "
            f"expected {expected_length}, received {len(payload)}."
        )
    return decode_found_sources(payload, obfuscated=False)


def decode_server_udp_description_request(payload: bytes) -> dict[str, int]:
    """Decodes one exact modern ``OP_SERVER_DESC_REQ`` challenge."""

    if len(payload) != 4:
        raise Ed2kWireError(
            f"SERVER_DESC_REQ must contain one four-byte challenge, got {len(payload)} bytes."
        )
    challenge = int.from_bytes(payload, "little")
    if challenge & 0xFFFF != SERVER_DESCRIPTION_CHALLENGE_SUFFIX:
        raise Ed2kWireError(
            f"SERVER_DESC_REQ challenge 0x{challenge:08X} lacks the 0xF0FF suffix."
        )
    return {"challenge": challenge}


def decode_server_udp_description_response(
    payload: bytes,
    *,
    expected_challenge: int | None = None,
) -> dict[str, object]:
    """Decodes one complete modern challenged ``OP_SERVER_DESC_RES`` payload."""

    if len(payload) < 8:
        raise Ed2kWireError(
            f"SERVER_DESC_RES modern payload requires challenge and tag count, got {len(payload)} bytes."
        )
    reader = _Reader(payload)
    challenge = reader.u32()
    if challenge & 0xFFFF != SERVER_DESCRIPTION_CHALLENGE_SUFFIX:
        raise Ed2kWireError(
            f"SERVER_DESC_RES is not the modern challenged format: 0x{challenge:08X}."
        )
    if expected_challenge is not None and challenge != expected_challenge:
        raise Ed2kWireError(
            f"SERVER_DESC_RES challenge 0x{challenge:08X} does not match 0x{expected_challenge:08X}."
        )
    tags: list[dict[str, object]] = []
    for _ in range(reader.u32()):
        name, value = _decode_tag(reader)
        tags.append(
            {
                "name": name,
                "value": value.hex().upper() if isinstance(value, bytes) else value,
            }
        )
    if reader.remaining:
        raise Ed2kWireError(f"SERVER_DESC_RES has {reader.remaining} trailing bytes.")
    by_name = {row["name"]: row["value"] for row in tags}
    raw_version = by_name.get(ST_VERSION)
    version = (
        f"{raw_version >> 16}.{raw_version & 0xFFFF:02}"
        if isinstance(raw_version, int)
        else raw_version
    )
    raw_auxiliary_ports = by_name.get(ST_AUXPORTSLIST)
    auxiliary_ports = []
    if isinstance(raw_auxiliary_ports, str):
        for value in raw_auxiliary_ports.split(","):
            try:
                port = int(value.strip())
            except ValueError:
                continue
            if 0 < port <= 0xFFFF and port not in auxiliary_ports:
                auxiliary_ports.append(port)
    return {
        "challenge": challenge,
        "response_format": "tagged",
        "name": by_name.get(ST_SERVERNAME),
        "description": by_name.get(ST_DESCRIPTION),
        "dynamic_host": by_name.get(ST_DYNIP),
        "version": version,
        "auxiliary_ports": auxiliary_ports,
        "tags": tags,
    }


def decode_server_ident(payload: bytes) -> dict[str, object]:
    """Decodes one complete stock ``OP_SERVERIDENT`` payload."""

    reader = _Reader(payload)
    server_hash = reader.take(16)
    advertised_ip = ipaddress.IPv4Address(reader.take(4))
    advertised_port = reader.u16()
    tags: list[dict[str, object]] = []
    for _ in range(reader.u32()):
        name, value = _decode_tag(reader)
        tags.append(
            {
                "name": name,
                "value": value.hex().upper() if isinstance(value, bytes) else value,
            }
        )
    if reader.remaining:
        raise Ed2kWireError(f"SERVERIDENT has {reader.remaining} trailing bytes.")
    by_name = {row["name"]: row["value"] for row in tags}
    return {
        "server_hash": server_hash.hex().upper(),
        "advertised_ip": str(advertised_ip),
        "advertised_port": advertised_port,
        "name": by_name.get(ST_SERVERNAME),
        "description": by_name.get(ST_DESCRIPTION),
        "tags": tags,
    }


def encode_offer_file(*, file_hash: bytes, name: str, size: int) -> bytes:
    """Builds one complete-file OFFERFILES payload."""

    if len(file_hash) != 16:
        raise ValueError("file_hash must be 16 bytes")
    if size < 0 or size > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("size must fit in u64")
    tags = [
        _short_string_tag(FT_FILENAME, name),
        _u32_tag(FT_FILESIZE, size & 0xFFFF_FFFF),
    ]
    size_hi = size >> 32
    if size_hi:
        tags.append(_u32_tag(FT_FILESIZE_HI, size_hi))
    return (
        struct.pack("<I", 1)
        + file_hash
        + struct.pack("<IH", COMPLETE_FILE_ID, COMPLETE_FILE_PORT)
        + struct.pack("<I", len(tags))
        + b"".join(tags)
    )


def encode_hash_search(file_hash: bytes) -> bytes:
    """Builds a hash-exact SEARCHREQUEST expression."""

    if len(file_hash) != 16:
        raise ValueError("file_hash must be 16 bytes")
    return encode_search_request(f"ed2k::{file_hash.hex().upper()}")


def _encode_size_search_leaf(value: int, operator: int) -> bytes:
    return (
        bytes([SEARCH_PARAM_NUMERIC32])
        + struct.pack("<I", value)
        + bytes([operator])
        + struct.pack("<H", 1)
        + bytes([FT_FILESIZE])
    )


def _fold_search_and(leaves: list[bytes]) -> bytes:
    if not leaves:
        return b""
    folded = leaves[-1]
    for leaf in reversed(leaves[:-1]):
        folded = bytes([SEARCH_PARAM_BOOLEAN, SEARCH_BOOL_AND]) + leaf + folded
    return folded


def encode_search_request(
    term: str,
    criteria: ServerSearchCriteria | None = None,
) -> bytes:
    """Builds the exact stock SEARCHREQUEST expression for one server search."""

    encoded = term.encode("utf-8")
    if not encoded or len(encoded) > 0xFFFF:
        raise ValueError("search term must encode to 1..65535 bytes")
    keyword = bytes([SEARCH_PARAM_STRING]) + struct.pack("<H", len(encoded)) + encoded
    criteria = criteria or ServerSearchCriteria()
    constraints: list[bytes] = []
    if criteria.min_size_bytes is not None:
        constraints.append(
            _encode_size_search_leaf(
                criteria.min_size_bytes,
                SEARCH_OP_GREATER_EQUAL,
            )
        )
    if criteria.max_size_bytes is not None:
        constraints.append(
            _encode_size_search_leaf(
                criteria.max_size_bytes,
                SEARCH_OP_LESS_EQUAL,
            )
        )
    if not constraints:
        return keyword
    return (
        bytes([SEARCH_PARAM_BOOLEAN, SEARCH_BOOL_AND])
        + keyword
        + _fold_search_and(constraints)
    )


def encode_source_request(file_hash: bytes, size: int) -> bytes:
    """Builds a small- or large-file GETSOURCES payload."""

    if len(file_hash) != 16:
        raise ValueError("file_hash must be 16 bytes")
    if size < 0 or size > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("size must fit in u64")
    if size <= 0xFFFF_FFFF:
        return file_hash + struct.pack("<I", size)
    return file_hash + struct.pack("<I", 0) + struct.pack("<Q", size)


def _decode_tag(reader: _Reader) -> tuple[int | str, Any]:
    raw_type = reader.u8()
    if raw_type & TAG_SHORT_NAME:
        tag_type = raw_type & ~TAG_SHORT_NAME
        name: int | str = reader.u8()
    else:
        tag_type = raw_type
        name_bytes = reader.take(reader.u16())
        name = (
            name_bytes[0]
            if len(name_bytes) == 1
            else name_bytes.decode("utf-8", errors="replace")
        )

    if tag_type == TAGTYPE_HASH:
        value: Any = reader.take(16)
    elif tag_type == TAGTYPE_STRING:
        value = reader.take(reader.u16()).decode("utf-8", errors="replace")
    elif tag_type == TAGTYPE_UINT32:
        value = reader.u32()
    elif tag_type == TAGTYPE_FLOAT32:
        value = struct.unpack("<f", reader.take(4))[0]
    elif tag_type == TAGTYPE_BOOL:
        value = bool(reader.u8())
    elif tag_type == TAGTYPE_BOOLARRAY:
        bit_count = reader.u16()
        value = reader.take((bit_count + 7) // 8)
    elif tag_type == TAGTYPE_BLOB:
        value = reader.take(reader.u32())
    elif tag_type == TAGTYPE_UINT16:
        value = reader.u16()
    elif tag_type == TAGTYPE_UINT8:
        value = reader.u8()
    elif tag_type == TAGTYPE_BSOB:
        value = reader.take(reader.u8())
    elif tag_type == TAGTYPE_UINT64:
        value = reader.u64()
    elif TAGTYPE_STR1_BASE + 1 <= tag_type <= TAGTYPE_STR1_BASE + 22:
        value = reader.take(tag_type - TAGTYPE_STR1_BASE).decode(
            "utf-8", errors="replace"
        )
    else:
        raise Ed2kWireError(f"Unsupported eD2K tag type 0x{tag_type:02X}.")
    return name, value


def decode_search_results(payload: bytes) -> list[dict[str, object]]:
    """Decodes one SEARCHRESULT page into normalized file rows."""

    reader = _Reader(payload)
    count = reader.u32()
    rows: list[dict[str, object]] = []
    for _ in range(count):
        file_hash = reader.take(16)
        source_id = reader.u32()
        source_port = reader.u16()
        tags = dict(_decode_tag(reader) for _ in range(reader.u32()))
        size = int(tags.get(FT_FILESIZE, 0)) | (int(tags.get(FT_FILESIZE_HI, 0)) << 32)
        rows.append(
            {
                "hash": file_hash.hex().upper(),
                "name": str(tags.get(FT_FILENAME, "")),
                "size": size,
                "sources": int(tags.get(FT_SOURCES, 0)),
                "complete_sources": int(tags.get(FT_COMPLETE_SOURCES, 0)),
                "result_source_id": source_id,
                "result_source_port": source_port,
            }
        )
    if reader.remaining == 1:
        reader.u8()
    if reader.remaining:
        raise Ed2kWireError(f"SEARCHRESULT has {reader.remaining} trailing bytes.")
    return rows


def decode_found_sources(payload: bytes, *, obfuscated: bool) -> dict[str, object]:
    """Decodes one FOUNDSOURCES or FOUNDSOURCES_OBFU payload."""

    reader = _Reader(payload)
    file_hash = reader.take(16)
    source_count = reader.u8()
    sources: list[dict[str, object]] = []
    for _ in range(source_count):
        source_id = reader.u32()
        port = reader.u16()
        crypt_options = reader.u8() if obfuscated else 0
        user_hash = reader.take(16).hex().upper() if crypt_options & 0x80 else None
        if source_id == IPV6_SOURCE_SENTINEL:
            host = str(ipaddress.IPv6Address(reader.take(16)))
            kind = "ipv6"
        elif source_id < LOW_ID_CEILING:
            host = None
            kind = "low-id"
        else:
            host = str(ipaddress.IPv4Address(struct.pack("<I", source_id)))
            kind = "high-id"
        sources.append(
            {
                "kind": kind,
                "client_id": source_id,
                "host": host,
                "port": port,
                "crypt_options": crypt_options,
                "user_hash": user_hash,
            }
        )
    if reader.remaining:
        raise Ed2kWireError(f"FOUNDSOURCES has {reader.remaining} trailing bytes.")
    return {
        "hash": file_hash.hex().upper(),
        "source_count": source_count,
        "sources": sources,
    }


@dataclass
class Ed2kWireClient:
    """Blocking deterministic eD2K server client with a complete transcript."""

    host: str
    port: int
    timeout_seconds: float = 5.0
    transcript: list[dict[str, object]] = field(default_factory=list)
    _socket: socket.socket | None = field(default=None, init=False, repr=False)

    def __enter__(self) -> "Ed2kWireClient":
        self.connect()
        return self

    def __exit__(self, _kind, _value, _traceback) -> None:
        self.close()

    def connect(self) -> None:
        """Opens the server TCP connection."""

        if self._socket is not None:
            raise Ed2kWireError("eD2K wire client is already connected.")
        self._socket = socket.create_connection(
            (self.host, self.port), timeout=self.timeout_seconds
        )
        self._socket.settimeout(self.timeout_seconds)

    def close(self) -> None:
        """Closes the server TCP connection."""

        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def _require_socket(self) -> socket.socket:
        if self._socket is None:
            raise Ed2kWireError("eD2K wire client is not connected.")
        return self._socket

    def send(self, opcode: int, payload: bytes = b"") -> None:
        """Sends and records one clear frame."""

        frame = Ed2kFrame(PROTO_EDONKEY, opcode, payload)
        self._require_socket().sendall(encode_frame(opcode, payload))
        self.transcript.append(frame.evidence("send"))

    def receive(self, *, timeout_seconds: float | None = None) -> Ed2kFrame:
        """Receives and records one complete frame."""

        stream = self._require_socket()
        previous_timeout = stream.gettimeout()
        if timeout_seconds is not None:
            stream.settimeout(timeout_seconds)
        try:
            header = _recv_exact(stream, 6)
            declared = int.from_bytes(header[1:5], "little")
            if declared < 1 or declared > MAX_FRAME_BYTES:
                raise Ed2kWireError(f"Invalid eD2K frame length {declared}.")
            frame = decode_frame_bytes(header + _recv_exact(stream, declared - 1))
        finally:
            if timeout_seconds is not None:
                stream.settimeout(previous_timeout)
        self.transcript.append(frame.evidence("recv"))
        return frame

    def receive_until(
        self, opcodes: set[int], *, timeout_seconds: float | None = None
    ) -> Ed2kFrame:
        """Receives until one requested opcode arrives or the deadline expires."""

        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timed out waiting for eD2K opcodes {sorted(opcodes)}."
                )
            frame = self.receive(timeout_seconds=remaining)
            if frame.opcode in opcodes:
                return frame

    def login(
        self,
        *,
        user_hash: bytes,
        tcp_port: int,
        nickname: str,
        server_flags: int = DEFAULT_SERVER_FLAGS,
    ) -> dict[str, object]:
        """Logs in and returns the assigned ID plus observed welcome opcodes."""

        self.send(
            OP_LOGINREQUEST,
            encode_login_request(
                user_hash=user_hash,
                tcp_port=tcp_port,
                nickname=nickname,
                server_flags=server_flags,
            ),
        )
        welcome: list[int] = []
        assigned_id: int | None = None
        got_status = False
        deadline = time.monotonic() + self.timeout_seconds
        while assigned_id is None or not got_status:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for ED2K login welcome frames.")
            frame = self.receive(timeout_seconds=remaining)
            welcome.append(frame.opcode)
            if frame.opcode == OP_IDCHANGE:
                if len(frame.payload) < 4:
                    raise Ed2kWireError("OP_IDCHANGE is shorter than its assigned ID.")
                assigned_id = int.from_bytes(frame.payload[:4], "little")
            elif frame.opcode == OP_SERVERSTATUS:
                got_status = True
        return {
            "assigned_id": assigned_id,
            "id_kind": "low-id" if assigned_id < LOW_ID_CEILING else "high-id",
            "welcome_opcodes": welcome,
        }

    def offer_file(self, *, file_hash: bytes, name: str, size: int) -> None:
        """Publishes one complete file on the current session."""

        self.send(
            OP_OFFERFILES, encode_offer_file(file_hash=file_hash, name=name, size=size)
        )

    def search_hash(self, file_hash: bytes) -> list[dict[str, object]]:
        """Runs one exact hash search and returns its decoded result page."""

        self.send(OP_SEARCHREQUEST, encode_hash_search(file_hash))
        frame = self.receive_until({OP_SEARCHRESULT})
        return decode_search_results(frame.payload)

    def search_term(self, term: str) -> list[dict[str, object]]:
        """Runs one keyword search and returns its decoded result page."""

        self.send(OP_SEARCHREQUEST, encode_search_request(term))
        frame = self.receive_until({OP_SEARCHRESULT})
        return decode_search_results(frame.payload)

    def get_sources(
        self,
        *,
        file_hash: bytes,
        size: int,
        obfuscated: bool = True,
    ) -> dict[str, object]:
        """Runs one TCP source lookup and returns decoded source records."""

        request_opcode = OP_GETSOURCES_OBFU if obfuscated else OP_GETSOURCES
        response_opcode = OP_FOUNDSOURCES_OBFU if obfuscated else OP_FOUNDSOURCES
        self.send(request_opcode, encode_source_request(file_hash, size))
        frame = self.receive_until({response_opcode})
        result = decode_found_sources(frame.payload, obfuscated=obfuscated)
        if result["hash"] != file_hash.hex().upper():
            raise Ed2kWireError(
                f"FOUNDSOURCES hash mismatch: expected {file_hash.hex().upper()}, got {result['hash']}."
            )
        return result


def _recv_exact(stream: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise Ed2kWireError(
                f"eD2K connection closed with {size - len(data)} frame bytes outstanding."
            )
        data.extend(chunk)
    return bytes(data)
