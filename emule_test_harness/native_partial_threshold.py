"""Observe the exact native eD2K partial-file metadata threshold."""

from collections.abc import Callable
from pathlib import Path
from struct import pack

from . import ed2k_file_observer, emule_met_dump, rust_local_ed2k
from .native_partial_publisher import PART_SIZE, PartialPublisher


def wait_for_native_progress(
    temp_dir: Path, file_hash: bytes, size: int, expected: tuple[int, int], *,
    accept_written_payload: bool = False,
) -> dict:
    """Match persisted native gap accounting for both incomplete parts."""
    parts = ((0, PART_SIZE), (PART_SIZE, size))
    head, tail = expected
    payload = b"A" * head + bytes(PART_SIZE - head) + b"B" * tail if accept_written_payload else None

    def observe():
        for path in temp_dir.glob("*.part.met"):
            for record in emule_met_dump.dump_file(path, summary=True, strict=True)["records"]:
                if record.get("ed2kHash") != file_hash.hex():
                    continue
                if record["fields"].get("sizeBytes") != size:
                    raise RuntimeError("Native partial job size changed")
                gaps = emule_met_dump.part_file_gaps(record)
                received = tuple(
                    end - start - sum(max(0, min(end, right) - max(start, left)) for left, right in gaps)
                    for start, end in parts
                )
                if received == expected:
                    return {"partBytes": received, "receivedBytes": sum(received), "gaps": gaps,
                            "evidence": "part-met"}
                if any(count > target for count, target in zip(received, expected)):
                    raise RuntimeError("Native partial job received bytes beyond the staged boundary")
                if payload is not None:
                    # Frozen aMule can flush payload before its gap tags are saved.
                    # The two source ranges use nonzero bytes; untouched holes read as zero.
                    part_path = path.with_suffix("")
                    if part_path.stat().st_size == len(payload):
                        with part_path.open("rb") as stream:
                            written = stream.read(len(payload) + 1)
                        if written == payload:
                            return {
                                "partBytes": expected, "receivedBytes": sum(expected),
                                "gaps": [(head, PART_SIZE), (PART_SIZE + tail, size)],
                                "evidence": "part-file-payload",
                            }
        return None

    return rust_local_ed2k.wait_for(
        observe, timeout_seconds=82, interval_seconds=0.25,
        description=f"native part.met at {sum(expected)} accepted bytes",
        retry_exceptions=(OSError, emule_met_dump.MetParseError),
    )


def observe_metadata(identity: str, host: str, port: int, publisher: PartialPublisher, *, reached: bool) -> dict:
    """Check native filename, empty status map, and upload admission independently."""
    digest = publisher.file_hash
    expected_name = identity == "amule" or reached
    with ed2k_file_observer.Ed2kFilePeerObserver(host, port) as observer:
        filename, status = ed2k_file_observer.observe_filename_before_status(observer.client, digest)
        if expected_name:
            name = publisher.file_name.encode("ascii")
            if filename is None or filename.opcode != 0x59 or filename.payload != digest + pack("<H", len(name)) + name:
                raise RuntimeError("Native peer did not return the expected partial filename")
        elif filename is not None:
            raise RuntimeError("Stock answered below its received-byte threshold")
        if status.payload != digest + bytes((2, 0, 0)):
            raise RuntimeError("Native peer did not return an empty two-part availability bitmap")

        observer.client.send(0x54, digest)
        observer.client.send(0x4F, digest)
        gate = observer.client.receive_until({0x46, 0x48, 0x50, 0x55})
        if gate.opcode == 0x48 and gate.payload == digest:
            gate = observer.client.receive_until({0x46, 0x50, 0x55})
        if gate.opcode != 0x50 or gate.payload != status.payload:
            raise RuntimeError("Native peer granted upload or served an unverified range")
        try:
            observer.client.receive_until({0x46, 0x55}, timeout_seconds=1)
        except TimeoutError:
            pass
        else:
            raise RuntimeError("Native peer granted a slot after the file-status reply")
        return {
            "filenameReplyOpcode": filename.opcode if filename else None,
            "availability": status.payload[16:].hex(),
            "uploadAdmitted": False,
        }


def observe_threshold(
    *, identity: str, host: str, port: int, temp_dir: Path, aliases: tuple[str, str], submit_link: Callable[[str], None],
) -> dict[str, object]:
    """Drive two isolated part sources through the byte below and at PART_SIZE."""
    head = PartialPublisher(aliases[0], 0, 0)
    tail = PartialPublisher(aliases[1], 0, 1)
    try:
        head.start()
        tail.start()
        link = f"ed2k://|file|{head.file_name}|{head.file_size}|{head.file_hash.hex()}|/"
        submit_link(f"{link}|sources,{aliases[0]}:{head.tcp_port}|/")
        head.wait_for_sent(PART_SIZE - 2, 100)
        submit_link(f"{link}|sources,{aliases[1]}:{tail.tcp_port}|/")
        tail.wait_for_sent(1, 55)
        below = wait_for_native_progress(
            temp_dir, head.file_hash, head.file_size, (PART_SIZE - 2, 1),
            accept_written_payload=identity == "amule",
        )
        below.update(observe_metadata(identity, host, port, head, reached=False))
        tail.release_threshold_byte(8)
        tail.wait_for_sent(2, 15)
        reached = wait_for_native_progress(
            temp_dir, head.file_hash, head.file_size, (PART_SIZE - 2, 2),
            accept_written_payload=identity == "amule",
        )
        reached.update(observe_metadata(identity, host, port, head, reached=True))
        return {"nativeClient": identity, "fileHash": head.file_hash.hex(), "below": below, "reached": reached}
    finally:
        try:
            tail.stop()
        finally:
            head.stop()
