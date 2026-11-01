"""Harness-owned eD2K file and source observations over the stock wire protocol."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from . import ed2k_wire


OBSERVER_HASH = bytes.fromhex("5A6B7C8D9EAF0E81A2B3C4D5E6F7182F")
OBSERVER_NICK = "emulebb-harness-file-observer"
OBSERVER_PORT = 1


def wait_for(
    description: str,
    timeout_seconds: float,
    probe: Callable[[], Any | None],
) -> Any:
    """Polls one bounded local wire state transition."""

    deadline = time.monotonic() + timeout_seconds
    while True:
        value = probe()
        if value is not None:
            return value
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Timed out waiting for {description}.")
        time.sleep(0.5)


def parse_file_hash(value: str) -> bytes:
    """Parses one exact 16-byte eD2K hash."""

    normalized = value.strip()
    if len(normalized) != 32:
        raise ValueError("file_hash must contain exactly 32 hexadecimal characters")
    try:
        return bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(
            "file_hash must contain exactly 32 hexadecimal characters"
        ) from exc


def exact_search_row(
    rows: list[dict[str, object]], file_hash: bytes
) -> dict[str, object] | None:
    """Returns the exact hash row from one server search page."""

    expected = file_hash.hex().upper()
    return next((row for row in rows if row.get("hash") == expected), None)


def endpoint_present(observation: dict[str, object], *, host: str, port: int) -> bool:
    """Reports whether one exact directly-addressable source is present."""

    endpoints = observation.get("endpoints")
    rows = endpoints if isinstance(endpoints, list) else []
    return any(
        isinstance(endpoint, dict)
        and endpoint.get("host") == host
        and int(endpoint.get("port") or 0) == port
        for endpoint in rows
    )


@dataclass(frozen=True)
class Ed2kFileObserver:
    """Observes indexed-file and source state without a server-private API."""

    host: str
    port: int
    request_timeout_seconds: float = 5.0

    def observe(self, file_hash: str, file_size: int) -> dict[str, object]:
        """Returns one causally complete search and source observation."""

        if file_size < 0 or file_size > 0xFFFF_FFFF_FFFF_FFFF:
            raise ValueError("file_size must fit in u64")
        hash_bytes = parse_file_hash(file_hash)
        client = ed2k_wire.Ed2kWireClient(
            self.host,
            self.port,
            self.request_timeout_seconds,
        )
        client.connect()
        try:
            login = client.login(
                user_hash=OBSERVER_HASH,
                tcp_port=OBSERVER_PORT,
                nickname=OBSERVER_NICK,
            )
            search_rows = client.search_hash(hash_bytes)
            search_row = exact_search_row(search_rows, hash_bytes)
            if search_row is not None and int(search_row.get("size") or 0) != file_size:
                raise ed2k_wire.Ed2kWireError(
                    "Exact-hash search returned an unexpected file size: "
                    f"expected={file_size} result={search_row!r}"
                )
            source_reply = client.get_sources(
                file_hash=hash_bytes,
                size=file_size,
                obfuscated=True,
            )
        finally:
            client.close()

        raw_sources = source_reply.get("sources")
        source_rows = raw_sources if isinstance(raw_sources, list) else []
        endpoints = [dict(row) for row in source_rows if isinstance(row, dict)]
        indexed = search_row is not None
        return {
            "hash": hash_bytes.hex().upper(),
            "requested_size": file_size,
            "indexed": indexed,
            "name": str(search_row.get("name") or "") if indexed else "",
            "size": int(search_row.get("size") or 0) if indexed else file_size,
            "sources": int(source_reply.get("source_count") or 0),
            "search_sources": int(search_row.get("sources") or 0) if indexed else 0,
            "complete_sources": (
                int(search_row.get("complete_sources") or 0) if indexed else 0
            ),
            "endpoints": endpoints,
            "search_result": search_row,
            "source_reply": source_reply,
            "observer_login": login,
            "transcript": client.transcript,
        }

    def wait_for_file(
        self,
        file_hash: str,
        file_size: int,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """Waits until exact-hash search returns the expected file."""

        observations: list[dict[str, object]] = []

        def resolve() -> dict[str, object] | None:
            observation = self.observe(file_hash, file_size)
            observations.append(observation)
            if observation["indexed"] is not True:
                return None
            return {**observation, "observations": observations}

        return wait_for(
            "ED2K wire file publication",
            timeout_seconds,
            resolve,
        )

    def wait_for_endpoint(
        self,
        file_hash: str,
        file_size: int,
        host: str,
        port: int,
        timeout_seconds: float,
        description: str = "ED2K wire source publication",
    ) -> dict[str, Any]:
        """Waits until one exact directly-addressable source is returned."""

        observations: list[dict[str, object]] = []

        def resolve() -> dict[str, object] | None:
            observation = self.observe(file_hash, file_size)
            observations.append(observation)
            if not endpoint_present(observation, host=host, port=port):
                return None
            return {**observation, "observations": observations}

        return wait_for(
            description,
            timeout_seconds,
            resolve,
        )

    def wait_for_endpoint_absent(
        self,
        file_hash: str,
        file_size: int,
        host: str,
        port: int,
        timeout_seconds: float,
        description: str = "ED2K wire source withdrawal",
    ) -> dict[str, Any]:
        """Waits until the source reply, not only search, drops one endpoint."""

        observations: list[dict[str, object]] = []

        def resolve() -> dict[str, object] | None:
            observation = self.observe(file_hash, file_size)
            observations.append(observation)
            if endpoint_present(observation, host=host, port=port):
                return None
            return {
                "absent": True,
                "observation": observation,
                "observations": observations,
            }

        return wait_for(
            description,
            timeout_seconds,
            resolve,
        )
