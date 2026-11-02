"""Harness-owned ED2K UDP v1 source server for deterministic parity campaigns."""

from __future__ import annotations

import ipaddress
import json
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any

OP_EDONKEYPROT = 0xE3
OP_GLOBGETSOURCES2 = 0x94
OP_GLOBSERVSTATREQ = 0x96
OP_GLOBSERVSTATRES = 0x97
OP_GLOBGETSOURCES = 0x9A
OP_GLOBFOUNDSOURCES = 0x9B

SERVER_UDP_FLAG_EXT_GETSOURCES = 0x0000_0001
TRANSCRIPT_SCHEMA = "scripted_ed2k_udp_source_v1_transcript_v1"


class ScriptedEd2kUdpSourceServer:
    """Answers stock UDP status and one exact v1 source-query shape.

    The fixture deliberately advertises ``EXT_GETSOURCES`` without
    ``EXT_GETSOURCES2``. A client can therefore reach the source only by sending
    ``E3 9A <hash>``; every received datagram and emitted reply is persisted.
    """

    def __init__(
        self,
        *,
        bind_host: str,
        server_tcp_port: int,
        file_hash: bytes,
        source_host: str,
        source_tcp_port: int,
        transcript_path: Path,
    ) -> None:
        if len(file_hash) != 16:
            raise ValueError("ED2K file hash must be exactly 16 bytes.")
        if not 1 <= server_tcp_port <= 65531:
            raise ValueError("ED2K server TCP port must leave room for UDP +4.")
        if not 1 <= source_tcp_port <= 65535:
            raise ValueError("ED2K source TCP port is out of range.")
        source_ip = ipaddress.ip_address(source_host)
        if source_ip.version != 4:
            raise ValueError("The deterministic ED2K source must be IPv4.")

        self.bind_host = bind_host
        self.server_tcp_port = server_tcp_port
        self.server_udp_port = server_tcp_port + 4
        self.file_hash = bytes(file_hash)
        self.source_host = str(source_ip)
        self.source_tcp_port = source_tcp_port
        self.transcript_path = Path(transcript_path)
        self._source_client_id = int.from_bytes(source_ip.packed, "little")
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._failure: BaseException | None = None

    def start(self, timeout_seconds: float = 5.0) -> None:
        """Starts the UDP fixture and waits until the socket is bound."""

        if self._thread is not None:
            raise RuntimeError("Scripted ED2K UDP source server is already started.")
        self._thread = threading.Thread(
            target=self._serve,
            name="scripted-ed2k-udp-source-v1",
            daemon=True,
        )
        self._thread.start()
        if not self._ready.wait(timeout_seconds):
            raise TimeoutError("Timed out starting scripted ED2K UDP source server.")
        self.raise_if_failed()

    def stop(self, timeout_seconds: float = 5.0) -> None:
        """Stops the fixture, persists its final transcript, and surfaces failures."""

        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout_seconds)
            if thread.is_alive():
                raise TimeoutError("Timed out stopping scripted ED2K UDP source server.")
        self._write_transcript()
        self.raise_if_failed()

    def raise_if_failed(self) -> None:
        """Raises an error recorded by the fixture thread."""

        if self._failure is not None:
            raise RuntimeError("Scripted ED2K UDP source server failed.") from self._failure

    def snapshot(self) -> dict[str, Any]:
        """Returns a detached transcript suitable for the campaign report."""

        with self._lock:
            events = [dict(event) for event in self._events]
        return {
            "schema": TRANSCRIPT_SCHEMA,
            "serverEndpoint": f"{self.bind_host}:{self.server_tcp_port}",
            "udpEndpoint": f"{self.bind_host}:{self.server_udp_port}",
            "udpFlags": SERVER_UDP_FLAG_EXT_GETSOURCES,
            "fileHash": self.file_hash.hex(),
            "source": {
                "host": self.source_host,
                "clientId": self._source_client_id,
                "tcpPort": self.source_tcp_port,
            },
            "events": events,
        }

    def _serve(self) -> None:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket = udp_socket
        try:
            udp_socket.bind((self.bind_host, self.server_udp_port))
            udp_socket.settimeout(0.1)
            self._ready.set()
            self._write_transcript()
            while not self._stop.is_set():
                try:
                    datagram, peer = udp_socket.recvfrom(65_535)
                except TimeoutError:
                    continue
                self._handle_datagram(udp_socket, datagram, peer)
        except BaseException as exc:
            self._failure = exc
            self._ready.set()
        finally:
            udp_socket.close()
            self._socket = None

    def _handle_datagram(
        self,
        udp_socket: socket.socket,
        datagram: bytes,
        peer: tuple[str, int],
    ) -> None:
        opcode = datagram[1] if len(datagram) >= 2 and datagram[0] == OP_EDONKEYPROT else None
        payload = datagram[2:] if opcode is not None else b""
        accepted = False
        note = "unsupported-or-malformed"
        response: bytes | None = None

        if opcode == OP_GLOBSERVSTATREQ and len(payload) == 4:
            challenge = int.from_bytes(payload, "little")
            if challenge & 0xFFFF_0000 == 0x55AA_0000:
                accepted = True
                note = "v1-only-capabilities"
                response_payload = struct.pack(
                    "<IIIIIIIIHHI",
                    challenge,
                    1,
                    1,
                    1_000,
                    100,
                    100,
                    SERVER_UDP_FLAG_EXT_GETSOURCES,
                    0,
                    0,
                    0,
                    0,
                )
                response = bytes((OP_EDONKEYPROT, OP_GLOBSERVSTATRES)) + response_payload
        elif opcode == OP_GLOBGETSOURCES and payload == self.file_hash:
            accepted = True
            note = "exact-v1-source-request"
            response_payload = (
                self.file_hash
                + b"\x01"
                + self._source_client_id.to_bytes(4, "little")
                + self.source_tcp_port.to_bytes(2, "little")
            )
            response = bytes((OP_EDONKEYPROT, OP_GLOBFOUNDSOURCES)) + response_payload
        elif opcode == OP_GLOBGETSOURCES2:
            note = "forbidden-v2-source-request"
        elif opcode == OP_GLOBGETSOURCES:
            note = "wrong-v1-source-payload"

        self._record(
            direction="recv",
            peer=peer,
            datagram=datagram,
            opcode=opcode,
            accepted=accepted,
            note=note,
        )
        if response is not None:
            udp_socket.sendto(response, peer)
            self._record(
                direction="send",
                peer=peer,
                datagram=response,
                opcode=response[1],
                accepted=True,
                note="reply",
            )

    def _record(
        self,
        *,
        direction: str,
        peer: tuple[str, int],
        datagram: bytes,
        opcode: int | None,
        accepted: bool,
        note: str,
    ) -> None:
        with self._lock:
            event = {
                "sequence": len(self._events) + 1,
                "monotonicNs": time.monotonic_ns(),
                "direction": direction,
                "peer": f"{peer[0]}:{peer[1]}",
                "protocolMarker": datagram[0] if datagram else None,
                "opcode": opcode,
                "payloadHex": datagram[2:].hex().upper() if len(datagram) >= 2 else "",
                "frameHex": datagram.hex().upper(),
                "accepted": accepted,
                "note": note,
            }
            self._events.append(event)
        self._write_transcript()

    def _write_transcript(self) -> None:
        payload = self.snapshot()
        self.transcript_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.transcript_path.with_suffix(self.transcript_path.suffix + ".tmp")
        temporary_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        temporary_path.replace(self.transcript_path)
