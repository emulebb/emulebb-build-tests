"""Probe a native client's standalone file status at the eD2K legacy size boundary."""

from pathlib import Path

from emule_test_harness import ed2k_wire, emule_met_dump, rust_local_ed2k

PART_SIZE = 9_728_000
LEGACY_MAX = 4_290_048_000
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
            for _, size, digest in JOBS:
                peer.send(SETREQFILEID, digest)
                reply = peer.receive_until({FILESTATUS, NOFILE})
                outcome = classify_status(reply, digest, size, identity=identity, capable=capable)
                results.append({
                    "sizeBytes": size, "fileHash": digest.hex(), "status": outcome,
                    "replyOpcode": reply.opcode, "replyPayload": reply.payload.hex(),
                })
        sessions.append({"supportsLargeFiles": capable, "helloPayload": hello.hex(), "requests": results})
    return {"nativeClient": identity, "partFileLengths": part_lengths, "sessions": sessions}
