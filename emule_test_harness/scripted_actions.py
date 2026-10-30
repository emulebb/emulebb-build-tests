"""Scripted, labelled action sets for solo *capture-then-offline-diff* parity runs.

The same action set is executed identically against ONE client at a time (rust
solo, then MFC solo — never simultaneously, which flaps rust off the operator via
the shared HighID ``client_id`` = egress IP; see the ``converged-soak-live`` memo).
Each action emits ``begin``/``end`` markers carrying ``ts_utc`` so the offline diff
can slice the ``[t0, t1]`` diag/packet window per action and correlate the two solo
recordings by ``actionId``.

Downloads use FIXED ed2k hashes taken from the git-ignored live-wire inputs
(``auto_browse.direct_bootstrap_transfers`` → ``LiveWireInputs.direct_bootstrap_transfers``)
so BOTH clients fetch the same files — source-acquisition/transfer behaviour is then
directly comparable, unlike drifting search results. Hashes/paths never live in the
committed code. Search terms are generic and spaced (be-gentle: the operator throttles
on volume — 0-results-for-all is that throttle, not a bug).

Pure helpers (``build_ed2k_link``/``default_action_set``/``execute_action_set``) are
unit-tested; the live REST wiring is isolated in :func:`make_rest_runner`.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import os
import re
import struct
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

MARKER_SCHEMA = "scripted_action_marker_v1"
DEFAULT_SEARCH_METHODS = ("server", "global", "kad")
DEFAULT_SPACING_SECONDS = 15.0
ED2K_PART_SIZE = 9_728_000
_SENSITIVE_OUTCOME_KEYS = frozenset(
    {
        "detail",
        "ed2khash",
        "error",
        "exception",
        "filehash",
        "hash",
        "link",
        "message",
        "name",
        "query",
        "term",
    }
)

ActionRunner = Callable[["ScriptedAction"], dict[str, Any]]
MarkerWriter = Callable[[dict[str, Any]], None]


@dataclasses.dataclass(frozen=True)
class ScriptedAction:
    """One labelled action. ``id`` is the opaque correlation key across solo runs."""

    id: str
    kind: str  # "search" | "download"
    params: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class CompletedFileVerification:
    """Locally held content verification for one completed client download."""

    path: Path
    size_bytes: int
    ed2k_hash: str
    sha256: str

    def sanitized_result(self) -> dict[str, Any]:
        """Return retention-safe proof without the path, name, or either hash."""

        return {
            "status": "verified",
            "sizeBytes": self.size_bytes,
            "sizeVerified": True,
            "ed2kVerified": True,
            "sha256Computed": True,
        }


def utc_now_iso() -> str:
    """RFC3339 UTC with a ``Z`` suffix, matching the diag/packet ``ts_utc`` format."""

    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def build_ed2k_link(fixture: dict[str, Any]) -> str:
    """``ed2k://|file|<name>|<size>|<hash>|/`` from a direct-transfer fixture row.

    Mirrors the harness link format used by local ED2K campaigns. Raises on a fixture
    missing the fields the REST transfer-add requires.
    """

    file_hash = str(fixture.get("hash") or "").strip().lower()
    name = str(fixture.get("name") or "").strip()
    size = fixture.get("size")
    if len(file_hash) != 32:
        raise ValueError("direct-transfer fixture needs a 32-char ed2k hash")
    if not name:
        raise ValueError("direct-transfer fixture needs a non-empty name")
    if not isinstance(size, int) or size <= 0:
        raise ValueError("direct-transfer fixture needs a positive integer size")
    return f"ed2k://|file|{name}|{size}|{file_hash}|/"


def default_action_set(
    search_terms: list[str],
    download_fixtures: list[dict[str, Any]],
    *,
    methods: tuple[str, ...] = DEFAULT_SEARCH_METHODS,
    search_options: dict[str, Any] | None = None,
) -> list[ScriptedAction]:
    """One search per method (over the given terms, round-robin) + one download per
    fixture. Kept small on purpose — the goal is exercising each path once, gently."""

    actions: list[ScriptedAction] = []

    def append_action(kind: str, params: dict[str, Any]) -> None:
        # WHY: retained marker/result files are sanitized campaign evidence. IDs
        # derived from queries, names, or hashes disclose operator-local inputs.
        actions.append(
            ScriptedAction(id=f"action-{len(actions) + 1:04d}", kind=kind, params=params)
        )

    if search_terms:
        for index, method in enumerate(methods):
            term = search_terms[index % len(search_terms)]
            append_action(
                "search",
                {"query": term, "method": method, **dict(search_options or {})},
            )
    for fixture in download_fixtures:
        file_hash = str(fixture.get("hash") or "").strip().lower()
        append_action(
            "download",
            {
                "hash": file_hash,
                "size": fixture.get("size"),
                "name": fixture.get("name"),
                "link": fixture.get("link"),
            },
        )
    return actions


def _private_action_tokens(action: ScriptedAction) -> tuple[str, ...]:
    tokens: set[str] = set()
    for key in ("query", "term", "name"):
        value = str(action.params.get(key) or "").strip()
        if value:
            tokens.add(value)
    file_hash = str(action.params.get("hash") or "").strip()
    if file_hash:
        tokens.add(file_hash)
        if len(file_hash) >= 8:
            tokens.add(file_hash[:8])
    return tuple(sorted(tokens, key=len, reverse=True))


def _redact_text(value: str, private_tokens: tuple[str, ...]) -> str:
    redacted = value
    for token in private_tokens:
        redacted = re.sub(re.escape(token), "<redacted>", redacted, flags=re.IGNORECASE)
    return redacted


def sanitize_action_outcome(action: ScriptedAction, outcome: Any) -> Any:
    """Remove local queries, names, and eD2K hashes from retained action results."""

    private_tokens = _private_action_tokens(action)

    def sanitize(value: Any, *, key: str | None = None) -> Any:
        normalized_key = re.sub(r"[^a-z0-9]", "", (key or "").casefold())
        if normalized_key in _SENSITIVE_OUTCOME_KEYS:
            return "<redacted>"
        if isinstance(value, dict):
            return {str(child_key): sanitize(child, key=str(child_key)) for child_key, child in value.items()}
        if isinstance(value, list):
            return [sanitize(child) for child in value]
        if isinstance(value, tuple):
            return [sanitize(child) for child in value]
        if isinstance(value, str):
            return _redact_text(value, private_tokens)
        return value

    return sanitize(outcome)


def execute_action_set(
    actions: list[ScriptedAction],
    runner: ActionRunner,
    marker_writer: MarkerWriter,
    *,
    spacing_seconds: float = DEFAULT_SPACING_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict[str, Any]]:
    """Run every action in order, emitting begin/end markers around each and pausing
    ``spacing_seconds`` between them (be-gentle). ``runner``/``sleep`` are injected so
    the sequencing + marker contract is testable without a live client."""

    results: list[dict[str, Any]] = []
    for action in actions:
        # Search markers carry the method (server/global/kad) so the offline diff
        # can pick the method-aware coverage gate without parsing the actionId.
        method = action.params.get("method") if action.kind == "search" else None
        extra = {"method": method} if method else {}
        marker_writer(
            {
                "schema": MARKER_SCHEMA,
                "marker": "begin",
                "actionId": action.id,
                "kind": action.kind,
                **extra,
                "ts_utc": utc_now_iso(),
            }
        )
        try:
            outcome = sanitize_action_outcome(action, runner(action))
            status = "ok"
        except Exception as exc:  # noqa: BLE001 - one failing action must not abort the set
            # WHY: third-party exception text can embed operator-local paths,
            # queries, hashes, or response bodies. Retain only stable taxonomy.
            outcome = {
                "errorCode": "action-runner-exception",
                "errorType": type(exc).__name__,
            }
            status = "error"
        marker_writer(
            {
                "schema": MARKER_SCHEMA,
                "marker": "end",
                "actionId": action.id,
                "kind": action.kind,
                **extra,
                "status": status,
                "outcome": outcome,
                "ts_utc": utc_now_iso(),
            }
        )
        results.append({"actionId": action.id, "status": status, "outcome": outcome})
        if action is not actions[-1]:
            sleep(spacing_seconds)
    return results


# ── live REST wiring (isolated from the pure logic above) ─────────────────────────


def _http(base_url: str, api_key: str, path: str, method: str = "GET", body: Any = None, timeout: float = 30.0) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"X-API-Key": api_key}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base_url + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - trusted LAN REST
        return json.loads(response.read())


def _http_optional(base_url: str, api_key: str, path: str) -> Any | None:
    try:
        return _http(base_url, api_key, path)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def _data(payload: Any) -> Any:
    return payload.get("data", payload) if isinstance(payload, dict) else payload


def _items(payload: Any) -> list[dict[str, Any]]:
    data = _data(payload)
    if isinstance(data, list):
        return data
    return list(data.get("items") or []) if isinstance(data, dict) else []


def run_search(
    base_url: str,
    api_key: str,
    query: str,
    method: str,
    *,
    poll_seconds: float = 25.0,
    file_type: str = "",
    extension: str | None = None,
    min_availability: int | None = None,
) -> dict[str, Any]:
    """POST a search then poll to completion (async contract), returning the method,
    the search id, and the count of well-formed result hashes."""

    request_body: dict[str, Any] = {"query": query, "method": method, "type": file_type}
    if extension:
        request_body["extension"] = extension
    if min_availability is not None:
        request_body["minAvailability"] = min_availability
    search_id = str(
        _data(_http(base_url, api_key, "/api/v1/searches", "POST", request_body)).get("id")
        or ""
    )
    rows: list[dict[str, Any]] = []
    deadline = time.monotonic() + poll_seconds
    while time.monotonic() < deadline:
        page = _http(base_url, api_key, f"/api/v1/searches/{search_id}")
        rows = _items(page) or rows
        if str(_data(page).get("status") or "").lower().startswith("complet"):
            break
        time.sleep(2.0)
    result_count = len([r for r in rows if len(str(r.get("hash") or "")) == 32])
    return {"method": method, "searchId": search_id, "resultCount": result_count}


def run_download(
    base_url: str, api_key: str, fixture: dict[str, Any]
) -> dict[str, Any]:
    """Ensure the approved direct transfer is active in a persisted profile."""

    link = build_ed2k_link(fixture)
    file_hash = str(fixture["hash"]).strip().lower()
    expected_size = int(fixture["size"])
    existing_payload = _http_optional(
        base_url, api_key, f"/api/v1/transfers/{file_hash}"
    )
    if existing_payload is None:
        _http(base_url, api_key, "/api/v1/transfers", "POST", {"link": link})
        return {"added": True, "reused": False, "resumed": False}

    existing = _data(existing_payload)
    if not isinstance(existing, dict):
        raise RuntimeError("persisted transfer response is not an object")
    if str(existing.get("hash") or "").strip().lower() != file_hash:
        raise RuntimeError("persisted transfer hash does not match approved fixture")
    if existing.get("sizeBytes") != expected_size:
        raise RuntimeError("persisted transfer size does not match approved fixture")

    state = str(existing.get("state") or "").strip().lower()
    if not state:
        raise RuntimeError("persisted transfer response has no state")
    if bool(existing.get("stopped")):
        raise RuntimeError("approved persisted transfer is stopped")
    if state == "completed":
        raise RuntimeError("approved persisted transfer is already completed")
    if state == "paused":
        _http(
            base_url,
            api_key,
            f"/api/v1/transfers/{file_hash}/operations/resume",
            "POST",
        )
        return {"added": False, "reused": True, "resumed": True}
    if state in {"downloading", "queued"}:
        return {"added": False, "reused": True, "resumed": False}
    raise RuntimeError("approved persisted transfer is not runnable")


def _rotate_left_32(value: int, shift: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def _windows_md4_digest(payload: bytes) -> bytes:
    """Use the native Windows CryptoAPI provider for campaign-sized payloads."""

    import ctypes

    provider = ctypes.c_void_p()
    hash_handle = ctypes.c_void_p()
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.CryptAcquireContextW.argtypes = (
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    )
    api.CryptAcquireContextW.restype = ctypes.c_int
    api.CryptCreateHash.argtypes = (
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    )
    api.CryptCreateHash.restype = ctypes.c_int
    api.CryptHashData.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    )
    api.CryptHashData.restype = ctypes.c_int
    api.CryptGetHashParam.argtypes = (
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint32,
    )
    api.CryptGetHashParam.restype = ctypes.c_int
    api.CryptDestroyHash.argtypes = (ctypes.c_void_p,)
    api.CryptReleaseContext.argtypes = (ctypes.c_void_p, ctypes.c_uint32)

    if not api.CryptAcquireContextW(
        ctypes.byref(provider), None, None, 1, 0xF0000000
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not api.CryptCreateHash(provider, 0x00008002, None, 0, ctypes.byref(hash_handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if payload:
                buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
                if not api.CryptHashData(hash_handle, buffer, len(payload), 0):
                    raise ctypes.WinError(ctypes.get_last_error())
            digest = (ctypes.c_ubyte * 16)()
            digest_size = ctypes.c_uint32(len(digest))
            if not api.CryptGetHashParam(
                hash_handle, 2, digest, ctypes.byref(digest_size), 0
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            return bytes(digest[: digest_size.value])
        finally:
            if hash_handle:
                api.CryptDestroyHash(hash_handle)
    finally:
        api.CryptReleaseContext(provider, 0)


def _portable_md4_digest(payload: bytes) -> bytes:
    """Small dependency-free fallback used where ``hashlib`` has no MD4."""

    bit_length = len(payload) * 8
    padded = payload + b"\x80"
    padded += b"\x00" * ((56 - len(padded) % 64) % 64)
    padded += struct.pack("<Q", bit_length)
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def apply_round(
        registers: list[int],
        words: tuple[int, ...],
        order: tuple[int, ...],
        shifts: tuple[int, ...],
        function: Callable[[int, int, int], int],
        constant: int,
    ) -> None:
        targets = (0, 3, 2, 1)
        for index, word_index in enumerate(order):
            target = targets[index % 4]
            value = (
                registers[target]
                + function(
                    registers[(target + 1) % 4],
                    registers[(target + 2) % 4],
                    registers[(target + 3) % 4],
                )
                + words[word_index]
                + constant
            )
            registers[target] = _rotate_left_32(value, shifts[index % 4])

    for offset in range(0, len(padded), 64):
        words = struct.unpack("<16I", padded[offset : offset + 64])
        registers = state.copy()
        apply_round(
            registers,
            words,
            tuple(range(16)),
            (3, 7, 11, 19),
            lambda x, y, z: (x & y) | (~x & z),
            0,
        )
        apply_round(
            registers,
            words,
            (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15),
            (3, 5, 9, 13),
            lambda x, y, z: (x & y) | (x & z) | (y & z),
            0x5A827999,
        )
        apply_round(
            registers,
            words,
            (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15),
            (3, 9, 11, 15),
            lambda x, y, z: x ^ y ^ z,
            0x6ED9EBA1,
        )
        state = [(state[index] + registers[index]) & 0xFFFFFFFF for index in range(4)]
    return struct.pack("<4I", *state)


def _md4_digest(payload: bytes) -> bytes:
    """Return MD4 through a standard provider, native API, or portable fallback."""

    try:
        digest = hashlib.new("md4")
    except ValueError:
        if os.name == "nt":
            return _windows_md4_digest(payload)
        return _portable_md4_digest(payload)
    digest.update(payload)
    return digest.digest()


def file_digests(path: Path) -> tuple[int, str, str]:
    """Return size, eD2K hash, and SHA-256 for one local regular file."""

    sha256 = hashlib.sha256()
    part_hashes: list[bytes] = []
    size_bytes = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(ED2K_PART_SIZE), b""):
            size_bytes += len(chunk)
            sha256.update(chunk)
            part_hashes.append(_md4_digest(chunk))

    if size_bytes < ED2K_PART_SIZE:
        ed2k_digest = part_hashes[0] if part_hashes else _md4_digest(b"")
    else:
        # eMule's historical format includes the empty trailing part when the
        # size is an exact PARTSIZE multiple.
        if size_bytes % ED2K_PART_SIZE == 0:
            part_hashes.append(_md4_digest(b""))
        ed2k_digest = _md4_digest(b"".join(part_hashes))
    return size_bytes, ed2k_digest.hex(), sha256.hexdigest()


def verify_completed_file(
    path: Path,
    *,
    expected_size: int,
    expected_ed2k_hash: str,
    expected_sha256: str | None = None,
) -> CompletedFileVerification:
    """Verify one completed payload and return local cross-client hash evidence."""

    expected_ed2k_hash = expected_ed2k_hash.strip().lower()
    expected_sha256 = expected_sha256.strip().lower() if expected_sha256 is not None else None
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
        raise ValueError("expected_size must be a non-negative integer")
    if not re.fullmatch(r"[0-9a-f]{32}", expected_ed2k_hash):
        raise ValueError("expected_ed2k_hash must be a 32-character hexadecimal digest")
    if expected_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("expected_sha256 must be a 64-character hexadecimal digest")
    if not path.is_file():
        raise RuntimeError("completed payload is not a regular file")

    before = path.stat()
    size_bytes, ed2k_hash, sha256 = file_digests(path)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RuntimeError("completed payload changed during verification")
    if size_bytes != expected_size:
        raise RuntimeError("completed payload size does not match the approved fixture")
    if ed2k_hash != expected_ed2k_hash:
        raise RuntimeError("completed payload eD2K hash does not match the approved fixture")
    if expected_sha256 is not None and sha256 != expected_sha256:
        raise RuntimeError("completed payload SHA-256 does not match the expected digest")
    return CompletedFileVerification(path.resolve(), size_bytes, ed2k_hash, sha256)


def wait_for_completed_file(
    locate_completed_file: Callable[[], Path | None],
    *,
    expected_size: int,
    expected_ed2k_hash: str,
    timeout_seconds: float,
    expected_sha256: str | None = None,
    interval_seconds: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> CompletedFileVerification:
    """Wait for either client to expose its completed path, then verify its bytes."""

    if timeout_seconds < 0:
        raise ValueError("timeout_seconds must be non-negative")
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")
    deadline = monotonic() + timeout_seconds
    while True:
        candidate = locate_completed_file()
        if candidate is not None:
            return verify_completed_file(
                Path(candidate),
                expected_size=expected_size,
                expected_ed2k_hash=expected_ed2k_hash,
                expected_sha256=expected_sha256,
            )
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise RuntimeError("timed out waiting for a completed payload")
        sleep(min(interval_seconds, remaining))


def verify_matching_sha256(
    verifications: list[CompletedFileVerification],
) -> dict[str, Any]:
    """Require two or more completed copies to match without returning their digest."""

    if len(verifications) < 2:
        raise ValueError("at least two completed-file verifications are required")
    if len({verification.sha256 for verification in verifications}) != 1:
        raise RuntimeError("completed payloads do not share the same SHA-256 digest")
    return {"fileCount": len(verifications), "sha256Matched": True}


def make_rest_runner(base_url: str, api_key: str) -> ActionRunner:
    """Binds a live-REST :data:`ActionRunner` for ``execute_action_set``."""

    def _run(action: ScriptedAction) -> dict[str, Any]:
        if action.kind == "search":
            return run_search(
                base_url,
                api_key,
                action.params["query"],
                action.params["method"],
                file_type=str(action.params.get("type") or ""),
                extension=action.params.get("extension"),
                min_availability=action.params.get("minAvailability"),
            )
        if action.kind == "download":
            return run_download(base_url, api_key, action.params)
        raise ValueError(f"unknown scripted action kind: {action.kind!r}")

    return _run
