"""Prepare and probe native eD2K jobs at the legacy size boundary."""

import math
import select
import socket
import stat
import struct
import time
from pathlib import Path

from emule_test_harness import ed2k_file_observer, ed2k_wire, emule_met_dump, rust_local_ed2k
from emule_test_harness.scripted_actions import _md4_digest

PART_SIZE = 9_728_000
LEGACY_MAX = ed2k_wire.LEGACY_FILE_SIZE_MAX
JOBS = (
    ("LegacyLimit.bin", LEGACY_MAX, bytes.fromhex("4ed0cda3d30f49b9a215edc044bc6e28")),
    ("AboveLegacyLimit.bin", LEGACY_MAX + 1, bytes.fromhex("30ac14adc2d14c71a71468527608a022")),
)
HELLO = 0x01
HELLOANSWER = 0x4C
SETREQFILEID = 0x4F
FILESTATUS = 0x50
NOFILE = 0x48


def source_less_links() -> list[str]:
    """Declare two empty native jobs without publishing a payload or source."""
    return [f"ed2k://|file|{name}|{size}|{digest.hex()}|/" for name, size, digest in JOBS]


def seed_offer_partials(temp_dir: Path) -> list[dict[str, object]]:
    """Seed two shareable partials in an existing empty offline native Temp directory."""
    directory = temp_dir.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(directory.st_mode)
        or getattr(directory, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        or any(temp_dir.iterdir())
    ):
        raise ValueError("OfferFiles fixtures require an empty native Temp directory.")

    payload = bytes(range(256)) * (PART_SIZE // 256)
    first_hash = _md4_digest(payload)
    full_part_hashes = first_hash * (LEGACY_MAX // PART_SIZE)
    jobs = (
        ("OfferLegacyLimit.bin", LEGACY_MAX, b""),
        ("OfferAboveLegacyLimit.bin", LEGACY_MAX + 1, payload[:1]),
    )
    receipts = []
    created = []
    try:
        for slot, (name, size, tail) in enumerate(jobs, 1):
            part_path = temp_dir / f"{slot:03}.part"
            met_path = part_path.with_suffix(".part.met")
            hashset = full_part_hashes + _md4_digest(tail)
            file_hash = _md4_digest(hashset)
            part_hash_count = len(hashset) // len(file_hash)
            with part_path.open("xb") as part:
                created.append(part_path)
                part.write(payload)
            modified = part_path.stat().st_mtime_ns // 1_000_000_000

            # Native .part.met uses old-format tags. The gap end is exclusive.
            name_bytes = name.encode("ascii")
            name_tag = struct.pack(
                "<BHBH",
                emule_met_dump.TAGTYPE_STRING,
                1,
                emule_met_dump.FT_FILENAME,
                len(name_bytes),
            ) + name_bytes
            large = size > LEGACY_MAX
            version = emule_met_dump.PARTFILE_VERSION_LARGEFILE if large else emule_met_dump.PARTFILE_VERSION
            int_type = emule_met_dump.TAGTYPE_UINT64 if large else emule_met_dump.TAGTYPE_UINT32
            int_format = "<Q" if large else "<I"
            number_tags = b"".join(
                struct.pack("<BH", int_type, len(key)) + key + struct.pack(int_format, value)
                for key, value in (
                    (bytes((emule_met_dump.FT_FILESIZE,)), size),
                    (bytes((emule_met_dump.FT_GAPSTART,)) + b"0", PART_SIZE),
                    (bytes((emule_met_dump.FT_GAPEND,)) + b"0", size),
                )
            )
            metadata = (
                struct.pack("<BI16sH", version, modified, file_hash, part_hash_count)
                + hashset
                + struct.pack("<I", 4)
                + name_tag
                + number_tags
            )
            with met_path.open("xb") as met:
                created.append(met_path)
                met.write(metadata)
            receipts.append({
                "name": name,
                "sizeBytes": size,
                "fileHash": file_hash.hex(),
                "partPath": str(part_path),
                "partMetPath": str(met_path),
                "partLength": len(payload),
                "modifiedUnix": modified,
                "gap": [PART_SIZE, size],
                "partHashCount": part_hash_count,
                "firstPartMd4": first_hash.hex(),
            })
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    return receipts


def observe_tcp_source_requests(
    stream: socket.socket, *, capable: bool, expected_user_hash: bytes, timeout_seconds: float,
    quiet_seconds: float = 5.0, jobs: tuple[tuple[str, int, bytes], ...] = JOBS,
    require_partial_offers: bool = False,
) -> dict[str, object]:
    """Serve one accepted native login and observe already-admitted jobs on its TCP connection.

    The legacy arm requires an exact-limit positive control followed by a full observation
    window on the still-open connection. The capable arm requires both exact wire requests.
    """
    expected = {digest: size for _, size, digest in jobs}
    if len(expected) != 2 or set(expected.values()) != {LEGACY_MAX, LEGACY_MAX + 1}:
        raise ValueError("TCP witness requires two distinct hashes at the legacy limit and one byte above")
    if len(expected_user_hash) != 16 or any(len(digest) != 16 for digest in expected):
        raise ValueError("TCP witness requires 16-byte login and file hashes")
    if not all(math.isfinite(value) and value > 0 for value in (timeout_seconds, quiet_seconds)):
        raise ValueError("TCP witness deadlines must be positive and finite")
    deadline = time.monotonic() + timeout_seconds

    def read_exact(size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Native TCP witness exceeded its deadline inside a frame")
            stream.settimeout(remaining)
            chunk = stream.recv(size - len(data))
            if not chunk:
                raise ed2k_wire.Ed2kWireError("Native client disconnected during the TCP witness")
            data.extend(chunk)
        return bytes(data)

    def read_frame() -> tuple[bytes, ed2k_wire.Ed2kFrame]:
        header = read_exact(6)
        length = int.from_bytes(header[1:5], "little")
        if header[0] not in (ed2k_wire.PROTO_EDONKEY, ed2k_wire.PROTO_PACKED) or not 1 <= length <= ed2k_wire.MAX_FRAME_BYTES:
            raise ed2k_wire.Ed2kWireError("Expected a bounded eD2K server frame")
        raw = header + read_exact(length - 1)
        return raw, ed2k_wire.decode_frame_bytes(raw)

    previous_timeout = stream.gettimeout()
    try:
        _, login = read_frame()
        if login.opcode != ed2k_wire.OP_LOGINREQUEST:
            raise ed2k_wire.Ed2kWireError("Expected native server LOGINREQUEST")
        identity = ed2k_wire.decode_login_request(login.payload)
        if identity["user_hash"] != expected_user_hash.hex().upper():
            raise ed2k_wire.Ed2kWireError("Native server login did not match the selected client")
        assigned_id = int.from_bytes(socket.inet_aton(stream.getpeername()[0]), "little")
        if assigned_id < ed2k_wire.LOW_ID_CEILING:
            raise ValueError("A native TCP witness needs a client address that encodes as a HighID")
        flags = ed2k_wire.SRVCAP_LARGEFILES if capable else 0
        if require_partial_offers:
            flags |= ed2k_wire.SRVCAP_ZLIB
        id_change = ed2k_wire.encode_frame(ed2k_wire.OP_IDCHANGE, struct.pack("<II", assigned_id, flags))
        stream.sendall(id_change)
        requests = {}
        offers = {}
        targets = {digest: size for digest, size in expected.items() if capable or size <= LEGACY_MAX}
        observe_until = None
        while True:
            now = time.monotonic()
            if now >= deadline:
                raise TimeoutError("Native TCP GETSOURCES or its observation window did not complete")
            remaining = (observe_until if observe_until is not None else deadline) - now
            if not select.select([stream], [], [], max(0, remaining))[0]:
                if observe_until is not None and time.monotonic() >= observe_until:
                    break
                continue
            raw, frame = read_frame()
            if frame.opcode in {ed2k_wire.OP_GETSOURCES, ed2k_wire.OP_GETSOURCES_OBFU}:
                digest = frame.payload[:16]
                if digest not in expected:
                    continue
                size = expected[digest]
                if digest not in targets:
                    raise ed2k_wire.Ed2kWireError("Native client requested an oversized file from a legacy server")
                if (
                    frame.marker != ed2k_wire.PROTO_EDONKEY
                    or frame.opcode != ed2k_wire.OP_GETSOURCES
                    or frame.payload != ed2k_wire.encode_source_request(digest, size)
                ):
                    raise ed2k_wire.Ed2kWireError("Native GETSOURCES did not match the exact plain request")
                requests[digest] = {"fileHash": digest.hex(), "sizeBytes": size, "frameHex": raw.hex()}
                stream.sendall(ed2k_wire.encode_frame(ed2k_wire.OP_FOUNDSOURCES, digest + b"\x00"))
            elif require_partial_offers and frame.opcode == ed2k_wire.OP_OFFERFILES:
                for offer in ed2k_wire.decode_offer_files(frame.payload):
                    digest = bytes.fromhex(offer["fileHash"])
                    if digest not in expected:
                        continue
                    if digest not in targets:
                        raise ed2k_wire.Ed2kWireError("Native client offered an oversized file to a legacy server")
                    size = expected[digest]
                    if (
                        offer["sourceId"] != ed2k_wire.PARTIAL_FILE_ID
                        or offer["sourcePort"] != ed2k_wire.PARTIAL_FILE_PORT
                        or offer["sizeLow"] != (size & 0xFFFF_FFFF)
                        or offer["sizeHigh"] != (size >> 32 if size > LEGACY_MAX else None)
                    ):
                        raise ed2k_wire.Ed2kWireError(f"Native OFFERFILES row differs from the partial fixture: {offer!r}")
                    offers[digest] = {**offer, "frameHex": raw.hex()}
            if requests.keys() == targets.keys() and (not require_partial_offers or offers.keys() == targets.keys()):
                if capable:
                    break
                if observe_until is None:
                    observe_until = time.monotonic() + quiet_seconds
                    if observe_until > deadline:
                        raise TimeoutError("Insufficient time for the full legacy TCP observation window")
        return {
            "supportsLargeFiles": capable, "loginUserHash": identity["user_hash"],
            "idChangeFrameHex": id_change.hex(), "requests": list(requests.values()),
            "offers": list(offers.values()),
            "legacyObservationSeconds": quiet_seconds if not capable else None,
        }
    finally:
        stream.settimeout(previous_timeout)


def classify_status(
    frame: ed2k_wire.Ed2kFrame, digest: bytes, size: int, *, identity: str, capable: bool,
) -> str:
    """Match the request hash, expected opcode and empty native part-map geometry."""
    if identity not in {"stock_emule", "amule"}:
        raise ValueError(f"Unsupported native status oracle: {identity}")
    expect_missing = identity == "stock_emule" and not capable and size > LEGACY_MAX
    expected = NOFILE if expect_missing else FILESTATUS
    if frame.marker != ed2k_wire.PROTO_EDONKEY or frame.opcode != expected or frame.payload[:16] != digest:
        raise ValueError(f"Unexpected native status for {size} bytes: opcode {frame.opcode:#x}")
    body = frame.payload[16:]
    if expect_missing:
        if body:
            raise ValueError("File-not-found reply contains trailing bytes")
        return "no-file"
    parts = size // PART_SIZE + 1
    if len(body) != 2 + (parts + 7) // 8 or int.from_bytes(body[:2], "little") != parts:
        raise ValueError("Wrong native status part count or bitmap width")
    # On an exact multiple the last declared bit represents a virtual EOF part.
    bitmap = int.from_bytes(body[2:], "little")
    if bitmap and not (size % PART_SIZE == 0 and bitmap == 1 << (parts - 1)):
        raise ValueError("A source-less download advertises unexpected available parts")
    return "empty-part-map"


def observe(identity: str, host: str, port: int, temp_dir: Path) -> dict[str, object]:
    """Confirm native admission before issuing two requests per HELLO profile."""
    expected = {(name, size, digest.hex()) for name, size, digest in JOBS}

    def admitted():
        part_lengths = {}
        for path in temp_dir.glob("*.part.met"):
            for record in emule_met_dump.dump_file(path, summary=True, strict=True)["records"]:
                fields = record["fields"]
                key = (fields.get("fileName"), fields.get("sizeBytes"), record.get("ed2kHash"))
                if key in expected:
                    if emule_met_dump.part_file_gaps(record) != [(0, key[1])]:
                        raise RuntimeError("Source-less native status jobs must have a full-file gap")
                    part_lengths[key[0]] = path.with_suffix("").stat().st_size
        if len(part_lengths) != len(expected):
            return None
        if any(part_lengths.values()):
            raise RuntimeError("Source-less native status jobs must have empty part files")
        return part_lengths

    part_lengths = rust_local_ed2k.wait_for(
        admitted, timeout_seconds=30, interval_seconds=0.25,
        description="native legacy-boundary part metadata", retry_exceptions=(OSError, emule_met_dump.MetParseError),
    )
    sessions = []
    for capable in (False, True):
        # CT_EMULE_VERSION marks a modern HELLO. MISCOPTIONS2 bit 4 alone changes.
        hello = ed2k_wire.peer_hello_payload(
            bytes.fromhex("0d9c5b3e4b0ec99f2e3b976161ba6f83"), 0, 4662,
            ((0xFB, 50 << 10), (0xFE, 0x10 if capable else 0)),
        )
        results = []
        with ed2k_wire.Ed2kWireClient(host, port, peer_protocol=True) as peer:
            peer.send(HELLO, hello)
            peer.receive_until({HELLOANSWER})
            for name, size, digest in JOBS:
                filename_reply = None
                if capable:
                    filename_reply, reply = ed2k_file_observer.observe_filename_before_status(peer, digest)
                    if identity == "stock_emule":
                        if filename_reply is not None:
                            raise ValueError("Stock answered a filename request for an empty part file")
                    else:
                        filename = name.encode("ascii")
                        filename_payload = digest + len(filename).to_bytes(2, "little") + filename
                        if filename_reply is None or filename_reply.opcode != 0x59 or filename_reply.payload != filename_payload:
                            raise ValueError("aMule did not return the empty part file's filename")
                else:
                    peer.send(SETREQFILEID, digest)
                    reply = peer.receive_until({FILESTATUS, NOFILE})
                outcome = classify_status(reply, digest, size, identity=identity, capable=capable)
                results.append({
                    "sizeBytes": size, "fileHash": digest.hex(), "status": outcome,
                    "replyOpcode": reply.opcode, "replyPayload": reply.payload.hex(),
                    **({"filenameReplyOpcode": filename_reply.opcode if filename_reply else None} if capable else {}),
                })
        sessions.append({"supportsLargeFiles": capable, "helloPayload": hello.hex(), "requests": results})
    return {"nativeClient": identity, "partFileLengths": part_lengths, "sessions": sessions}
