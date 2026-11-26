"""Harness-owned ED2K UDP source server for deterministic parity campaigns."""

from __future__ import annotations

import ipaddress
import json
import socket
import struct
import threading
import time
from copy import deepcopy
from pathlib import Path
from typing import Any

from emule_test_harness import ed2k_wire

SERVER_UDP_FLAG_EXT_GETSOURCES = 0x0000_0001
SERVER_UDP_FLAG_EXT_GETSOURCES2 = 0x0000_0020
SERVER_UDP_FLAG_LARGEFILES = 0x0000_0100
V1_TRANSCRIPT_SCHEMA = "scripted_ed2k_udp_source_v1_transcript_v1"
V2_TRANSCRIPT_SCHEMA = "scripted_ed2k_udp_source_v2_transcript_v1"
BOUNDARY_TRANSCRIPT_SCHEMA = "scripted_ed2k_udp_source_boundary_transcript_v1"


class ScriptedEd2kUdpSourceServer:
    """Advertises UDP flags and records source queries and replies."""

    def __init__(
        self,
        *,
        bind_host: str,
        server_tcp_port: int,
        file_hash: bytes,
        source_request_version: int,
        file_size: int | None = None,
        source_host: str | None,
        source_tcp_port: int | None,
        transcript_path: Path,
        _boundary_catalogue: tuple[tuple[bytes, int], ...] = (),
        _boundary_udp_flags: int = 0,
    ) -> None:
        if len(file_hash) != 16:
            raise ValueError("ED2K file hash must be exactly 16 bytes.")
        if source_request_version not in {1, 2}:
            raise ValueError("ED2K UDP source request version must be 1 or 2.")
        if source_request_version == 1 and file_size is not None:
            raise ValueError("ED2K UDP source v1 does not carry a file size.")
        if source_request_version == 2 and (
            not isinstance(file_size, int)
            or isinstance(file_size, bool)
            or not 1 <= file_size <= 0xFFFF_FFFF_FFFF_FFFF
        ):
            raise ValueError("ED2K UDP source v2 requires a nonzero u64 file size.")
        if not 1 <= server_tcp_port <= 65531:
            raise ValueError("ED2K server TCP port must leave room for UDP +4.")
        self.bind_host = bind_host
        self.server_tcp_port = server_tcp_port
        self.server_udp_port = server_tcp_port + 4
        self.file_hash = bytes(file_hash)
        self.source_request_version = source_request_version
        self.file_size = file_size
        self.transcript_path = Path(transcript_path)
        self._boundary_catalogue = {
            digest.hex().upper(): size for digest, size in _boundary_catalogue
        }
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._failure: BaseException | None = None
        if source_request_version == 1:
            self.request_opcode = ed2k_wire.OP_GLOBGETSOURCES
            self.udp_flags = SERVER_UDP_FLAG_EXT_GETSOURCES
            self.transcript_schema = V1_TRANSCRIPT_SCHEMA
            self._expected_request = ed2k_wire.encode_server_udp_source_v1_request(
                [self.file_hash]
            )
        else:
            self.request_opcode = ed2k_wire.OP_GLOBGETSOURCES2
            self.udp_flags = (
                SERVER_UDP_FLAG_EXT_GETSOURCES | SERVER_UDP_FLAG_EXT_GETSOURCES2
            )
            self.transcript_schema = V2_TRANSCRIPT_SCHEMA
            self._expected_request = ed2k_wire.encode_server_udp_source_v2_request(
                [(self.file_hash, file_size)]
            )
        self._reply = None
        if self._boundary_catalogue:
            self.udp_flags = _boundary_udp_flags
            self.transcript_schema = BOUNDARY_TRANSCRIPT_SCHEMA
        else:
            if source_tcp_port is None or not 1 <= source_tcp_port <= 65535:
                raise ValueError("ED2K source TCP port is out of range.")
            source_ip = ipaddress.ip_address(source_host)
            if source_ip.version != 4:
                raise ValueError("The deterministic ED2K source must be IPv4.")
            self.source_host = str(source_ip)
            self.source_tcp_port = source_tcp_port
            self._source_client_id = int.from_bytes(source_ip.packed, "little")
            self._reply = ed2k_wire.encode_server_udp_source_reply(
                file_hash=self.file_hash,
                sources=[(self._source_client_id, source_tcp_port)],
            )

    @classmethod
    def for_legacy_size_boundary(
        cls,
        *,
        bind_host: str,
        server_tcp_port: int,
        udp_flags: int,
        transcript_path: Path,
        jobs: tuple[tuple[str, int, bytes], ...] | None = None,
    ) -> ScriptedEd2kUdpSourceServer:
        """Advertise an exact source capability profile and observe the two native jobs."""

        from emule_test_harness.native_large_file_status import JOBS, LEGACY_MAX

        allowed_flags = (
            SERVER_UDP_FLAG_EXT_GETSOURCES
            | SERVER_UDP_FLAG_EXT_GETSOURCES2
            | SERVER_UDP_FLAG_LARGEFILES
        )
        if type(udp_flags) is not int or udp_flags < 0 or udp_flags & ~allowed_flags:
            raise ValueError("Boundary probe UDP flags must be source capability bits.")
        version = 2 if udp_flags & SERVER_UDP_FLAG_EXT_GETSOURCES2 else 1
        catalogue = {size: digest for _, size, digest in (JOBS if jobs is None else jobs)}
        if set(catalogue) != {LEGACY_MAX, LEGACY_MAX + 1} or len(set(catalogue.values())) != 2:
            raise ValueError("Boundary probe requires distinct jobs at the legacy limit and one byte above")
        legacy_hash = catalogue[LEGACY_MAX]
        return cls(
            bind_host=bind_host,
            server_tcp_port=server_tcp_port,
            file_hash=legacy_hash,
            source_request_version=version,
            file_size=LEGACY_MAX if version == 2 else None,
            source_host=None,
            source_tcp_port=None,
            transcript_path=transcript_path,
            _boundary_catalogue=tuple((catalogue[size], size) for size in sorted(catalogue)),
            _boundary_udp_flags=udp_flags,
        )

    def start(self, timeout_seconds: float = 5.0) -> None:
        """Starts the UDP fixture and waits until the socket is bound."""

        if self._thread is not None:
            raise RuntimeError("Scripted ED2K UDP source server is already started.")
        self._thread = threading.Thread(
            target=self._serve,
            name=f"scripted-ed2k-udp-source-v{self.source_request_version}",
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
            events = deepcopy(self._events)
        snapshot = {
            "schema": self.transcript_schema,
            "serverEndpoint": f"{self.bind_host}:{self.server_tcp_port}",
            "udpEndpoint": f"{self.bind_host}:{self.server_udp_port}",
            "udpFlags": self.udp_flags,
            "fileHash": self.file_hash.hex(),
            "events": events,
        }
        if self._boundary_catalogue:
            snapshot["catalogue"] = [
                {"fileHash": digest, "sizeBytes": size}
                for digest, size in self._boundary_catalogue.items()
            ]
        else:
            snapshot["source"] = {
                "host": self.source_host,
                "clientId": self._source_client_id,
                "tcpPort": self.source_tcp_port,
            }
        if self.source_request_version == 2:
            snapshot["fileSize"] = self.file_size
        return snapshot

    def wait_for_status_clients(
        self,
        expected_clients: int,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """Waits until distinct UDP peers have accepted the selected flags."""

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            self.raise_if_failed()
            snapshot = self.snapshot()
            peers = {
                str(event.get("peer") or "")
                for event in snapshot["events"]
                if event.get("direction") == "recv"
                and event.get("opcode") == ed2k_wire.OP_GLOBSERVSTATREQ
                and event.get("accepted") is True
            }
            if len(peers) >= expected_clients:
                return {
                    "ok": True,
                    "expectedClients": expected_clients,
                    "distinctClientCount": len(peers),
                    "peers": sorted(peers),
                    "udpFlags": self.udp_flags,
                }
            time.sleep(0.05)
        snapshot = self.snapshot()
        raise TimeoutError(
            "Timed out waiting for scripted ED2K UDP status requests: "
            f"expected={expected_clients} events={snapshot['events']!r}"
        )

    def wait_for_boundary_requests(
        self,
        timeout_seconds: float,
        *,
        observation_seconds: float = 1.0,
        peer: str | None = None,
    ) -> dict[str, Any]:
        """Require the boundary witness and check the profile through a bounded window."""

        if not self._boundary_catalogue:
            raise RuntimeError("The UDP source fixture is not observing the legacy boundary.")
        if not 0 < observation_seconds < timeout_seconds:
            raise ValueError("Boundary observation must fit inside a positive timeout.")

        expected = {
            digest
            for digest, size in self._boundary_catalogue.items()
            if size <= ed2k_wire.LEGACY_FILE_SIZE_MAX
            or self.udp_flags & SERVER_UDP_FLAG_LARGEFILES
        }
        deadline = time.monotonic() + timeout_seconds
        matched_at = None
        while time.monotonic() < deadline:
            self.raise_if_failed()
            events_by_peer: dict[str, list[dict[str, Any]]] = {}
            for event in self.snapshot()["events"]:
                if peer is not None and peer != event["peer"]:
                    continue
                if event.get("boundaryViolation"):
                    raise AssertionError(
                        f"Invalid UDP boundary request: {event['boundaryViolation']}; "
                        f"peer={event['peer']} frame={event['frameHex']}"
                    )
                if event.get("boundaryTargets"):
                    events_by_peer.setdefault(event["peer"], []).append(event)
            for matched_peer, events in events_by_peer.items():
                hashes = {
                    row["fileHash"]
                    for event in events
                    for row in event["boundaryTargets"]
                }
                if hashes == expected:
                    now = time.monotonic()
                    if matched_at is None:
                        matched_at = now
                    if now - matched_at >= observation_seconds:
                        return {
                            "ok": True,
                            "peer": matched_peer,
                            "udpFlags": self.udp_flags,
                            "expectedFileHashes": sorted(expected),
                            "observationSeconds": observation_seconds,
                            "requests": events,
                        }
                    break
            time.sleep(min(0.05, observation_seconds))
        raise TimeoutError(
            f"Timed out waiting for UDP boundary requests for {sorted(expected)}; "
            f"transcript={self.transcript_path}"
        )

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
        opcode = (
            datagram[1]
            if len(datagram) >= 2 and datagram[0] == ed2k_wire.PROTO_EDONKEY
            else None
        )
        payload = datagram[2:] if opcode is not None else b""
        accepted = False
        note = "unsupported-or-malformed"
        response: bytes | None = None
        boundary_details: dict[str, Any] = {}

        if opcode == ed2k_wire.OP_GLOBSERVSTATREQ and len(payload) == 4:
            challenge = int.from_bytes(payload, "little")
            if challenge & 0xFFFF_0000 == 0x55AA_0000:
                accepted = True
                note = f"v{self.source_request_version}-capabilities"
                response_payload = struct.pack(
                    "<IIIIIIIIHHI",
                    challenge,
                    1,
                    1,
                    1_000,
                    100,
                    100,
                    self.udp_flags,
                    0,
                    0,
                    0,
                    0,
                )
                response = (
                    bytes((ed2k_wire.PROTO_EDONKEY, ed2k_wire.OP_GLOBSERVSTATRES))
                    + response_payload
                )
        elif self._boundary_catalogue and opcode in {
            ed2k_wire.OP_GLOBGETSOURCES,
            ed2k_wire.OP_GLOBGETSOURCES2,
        }:
            boundary_details = self._inspect_boundary_request(datagram, opcode)
            accepted = bool(boundary_details.get("boundaryTargets")) and not (
                boundary_details.get("boundaryViolation")
            )
            note = (
                "boundary-source-request"
                if accepted
                else "unmatched-boundary-source-request"
            )
        elif opcode == self.request_opcode and datagram == self._expected_request:
            accepted = True
            note = f"exact-v{self.source_request_version}-source-request"
            response = self._reply
        elif opcode == self.request_opcode:
            note = f"wrong-v{self.source_request_version}-source-payload"
        elif opcode in {
            ed2k_wire.OP_GLOBGETSOURCES,
            ed2k_wire.OP_GLOBGETSOURCES2,
        }:
            opposite_version = 2 if self.source_request_version == 1 else 1
            note = f"forbidden-v{opposite_version}-source-request"

        self._record(
            direction="recv",
            peer=peer,
            datagram=datagram,
            opcode=opcode,
            accepted=accepted,
            note=note,
            **boundary_details,
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

    def _inspect_boundary_request(self, datagram: bytes, opcode: int) -> dict[str, Any]:
        try:
            if opcode == ed2k_wire.OP_GLOBGETSOURCES2:
                targets = [
                    {"fileHash": row["hash"], "wireSizeBytes": row["size_bytes"]}
                    for row in ed2k_wire.decode_server_udp_source_v2_request(datagram)["targets"]
                ]
            else:
                targets = [
                    {"fileHash": digest, "wireSizeBytes": None}
                    for digest in ed2k_wire.decode_server_udp_source_v1_request(datagram)["hashes"]
                ]
        except ed2k_wire.Ed2kWireError as exc:
            return {"boundaryViolation": str(exc)}
        boundary_targets = [
            row for row in targets if row["fileHash"] in self._boundary_catalogue
        ]
        if not boundary_targets:
            return {}
        details = {"boundaryTargets": boundary_targets}
        if opcode != self.request_opcode:
            return {**details, "boundaryViolation": "unexpected UDP source opcode"}
        if len(targets) > 1 and not self.udp_flags & SERVER_UDP_FLAG_EXT_GETSOURCES:
            return {**details, "boundaryViolation": "multiple targets without EXT_GETSOURCES"}
        for target in boundary_targets:
            size = self._boundary_catalogue[target["fileHash"]]
            if (
                size > ed2k_wire.LEGACY_FILE_SIZE_MAX
                and not self.udp_flags & SERVER_UDP_FLAG_LARGEFILES
            ):
                return {**details, "boundaryViolation": "above-boundary hash without LARGEFILES"}
            if opcode == ed2k_wire.OP_GLOBGETSOURCES2 and target["wireSizeBytes"] != size:
                return {**details, "boundaryViolation": "unexpected UDP source target size"}
        return details

    def _record(
        self,
        *,
        direction: str,
        peer: tuple[str, int],
        datagram: bytes,
        opcode: int | None,
        accepted: bool,
        note: str,
        **details: Any,
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
                **details,
            }
            self._events.append(event)
        self._write_transcript()

    def _write_transcript(self) -> None:
        payload = self.snapshot()
        self.transcript_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.transcript_path.with_suffix(self.transcript_path.suffix + ".tmp")
        temporary_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        temporary_path.replace(self.transcript_path)
