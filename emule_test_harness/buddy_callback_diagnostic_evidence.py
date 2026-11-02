"""Causal bilateral evidence gate for deterministic Kad buddy callbacks."""

from __future__ import annotations

import ipaddress
from typing import Any, Callable, Iterable

from emule_test_harness import buddy_callback_probe, ed2k_wire


SCHEMA = "emulebb-build-tests.deterministic-buddy-callback-diagnostics.v1"
DIAGNOSTIC_SCHEMA = "diag_event_v2"
COVERAGE_ID = "lowid.buddy-callback"
CLIENTS = ("rust", "mfc")
CONTROL_PATH = "/api/v1/diagnostics/protocol-fixtures/buddy-relay-eligibility"
EVIDENCE_LAYERS = (
    "codec-transcript",
    "deterministic-state-machine",
    "local-cross-client",
)


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


def _single(
    records: list[dict[str, Any]],
    predicate: Callable[[dict[str, Any]], bool],
) -> tuple[dict[str, Any] | None, int]:
    matches = [record for record in records if predicate(record)]
    return (matches[0] if len(matches) == 1 else None, len(matches))


def _event(record: dict[str, Any], family: str, event: str) -> bool:
    return bool(
        record.get("schema") == DIAGNOSTIC_SCHEMA
        and record.get("family") == family
        and record.get("event") == event
        and _sequence(record) > 0
    )


def _same_hex(value: object, expected: bytes | str) -> bool:
    expected_hex = expected.hex() if isinstance(expected, bytes) else expected
    return isinstance(value, str) and value.casefold() == expected_hex.casefold()


def _timestamp(value: object) -> float | None:
    return (
        float(value)
        if isinstance(value, (int, float)) and not isinstance(value, bool)
        else None
    )


def _target(value: object) -> dict[str, Any]:
    row = value if isinstance(value, dict) else {}
    user_hash = str(row.get("userHash") or "").upper()
    client_id = row.get("clientId")
    peer_hello_client_id = row.get("peerHelloClientId")
    tcp_port = row.get("tcpPort")
    udp_port = row.get("udpPort")
    ok = bool(
        row.get("idKind") == "low-id"
        and isinstance(client_id, int)
        and not isinstance(client_id, bool)
        and 0 < client_id < ed2k_wire.LOW_ID_CEILING
        and peer_hello_client_id == 0
        and isinstance(tcp_port, int)
        and not isinstance(tcp_port, bool)
        and 0 < tcp_port <= 0xFFFF
        and isinstance(udp_port, int)
        and not isinstance(udp_port, bool)
        and 0 < udp_port <= 0xFFFF
        and len(user_hash) == 32
        and all(character in "0123456789ABCDEF" for character in user_hash)
    )
    return {
        "ok": ok,
        "userHash": user_hash or None,
        "clientId": client_id,
        "peerHelloClientId": peer_hello_client_id,
        "tcpPort": tcp_port,
        "udpPort": udp_port,
        "idKind": row.get("idKind"),
    }


def _control(value: object) -> dict[str, Any]:
    receipt = value if isinstance(value, dict) else {}
    request = receipt.get("request") if isinstance(receipt.get("request"), dict) else {}
    response = (
        receipt.get("response") if isinstance(receipt.get("response"), dict) else {}
    )
    expected_response = {
        "prepared": True,
        "tcpFirewalled": False,
        "udpVerified": True,
        "udpOpen": True,
        "state": "buddy-relay-eligible",
    }
    ok = bool(
        request == {"method": "POST", "path": CONTROL_PATH}
        and response.get("status") == 200
        and response.get("json") == expected_response
    )
    return {"ok": ok, "request": request or None, "response": response or None}


def _decode_hello_request(raw_hex: object) -> dict[str, object] | None:
    if not isinstance(raw_hex, str):
        return None
    try:
        frame = ed2k_wire.decode_frame_bytes(bytes.fromhex(raw_hex))
    except (ValueError, ed2k_wire.Ed2kWireError):
        return None
    payload = frame.payload
    if (
        raw_hex != bytes.fromhex(raw_hex).hex().upper()
        or frame.marker != ed2k_wire.PROTO_EDONKEY
        or frame.opcode != buddy_callback_probe.OP_HELLO
        or len(payload) < 23
        or payload[0] != 16
    ):
        return None
    return {
        "userHash": payload[1:17].hex().upper(),
        "clientId": int.from_bytes(payload[17:21], "little"),
        "tcpPort": int.from_bytes(payload[21:23], "little"),
    }


def _decode_hello_answer(value: object) -> dict[str, object] | None:
    row = value if isinstance(value, dict) else {}
    raw_hex = row.get("rawHex")
    if not isinstance(raw_hex, str):
        return None
    try:
        raw = bytes.fromhex(raw_hex)
        frame = ed2k_wire.decode_frame_bytes(raw)
    except (ValueError, ed2k_wire.Ed2kWireError):
        return None
    if (
        raw_hex != raw.hex().upper()
        or frame.marker != ed2k_wire.PROTO_EDONKEY
        or frame.opcode != buddy_callback_probe.OP_HELLOANSWER
        or len(frame.payload) < 22
    ):
        return None
    return {
        "userHash": frame.payload[:16].hex().upper(),
        "clientId": int.from_bytes(frame.payload[16:20], "little"),
        "tcpPort": int.from_bytes(frame.payload[20:22], "little"),
    }


def _listener_hello(value: object) -> dict[str, object] | None:
    row = value if isinstance(value, dict) else {}
    payload_hex = row.get("payloadHex")
    if not isinstance(payload_hex, str):
        return None
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        return None
    if (
        payload_hex != payload.hex().upper()
        or row.get("payloadLength") != len(payload)
        or len(payload) < 23
        or payload[0] != 16
    ):
        return None
    return {
        "userHash": payload[1:17].hex().upper(),
        "clientId": int.from_bytes(payload[17:21], "little"),
        "tcpPort": int.from_bytes(payload[21:23], "little"),
    }


def _probe_receipt(
    value: object,
    *,
    client: str,
    target_host: str,
    target: dict[str, Any],
    buddy_host: str,
    buddy_tcp_port: int,
    buddy_udp_port: int,
    buddy_user_hash: bytes,
    buddy_client_id: int,
    buddy_id: bytes,
    file_hash: bytes,
    requester_tcp_port: int,
    requester_user_hash: bytes,
) -> dict[str, Any]:
    receipt = value if isinstance(value, dict) else {}
    find_request = (
        receipt.get("findBuddyRequest")
        if isinstance(receipt.get("findBuddyRequest"), dict)
        else {}
    )
    find_response = (
        receipt.get("findBuddyResponse")
        if isinstance(receipt.get("findBuddyResponse"), dict)
        else {}
    )
    held = (
        receipt.get("heldBuddyConnection")
        if isinstance(receipt.get("heldBuddyConnection"), dict)
        else {}
    )
    callback_request = (
        receipt.get("callbackRequest")
        if isinstance(receipt.get("callbackRequest"), dict)
        else {}
    )
    relay_readiness = (
        receipt.get("relayReadiness")
        if isinstance(receipt.get("relayReadiness"), dict)
        else {}
    )
    relay = (
        receipt.get("callbackRelay")
        if isinstance(receipt.get("callbackRelay"), dict)
        else {}
    )
    resulting = (
        receipt.get("resultingPeerSession")
        if isinstance(receipt.get("resultingPeerSession"), dict)
        else {}
    )
    held_hello = held.get("hello") if isinstance(held.get("hello"), dict) else {}
    held_answer = (
        held.get("helloAnswer") if isinstance(held.get("helloAnswer"), dict) else {}
    )
    resulting_hello = (
        resulting.get("hello") if isinstance(resulting.get("hello"), dict) else {}
    )
    resulting_answer = (
        resulting.get("helloAnswer")
        if isinstance(resulting.get("helloAnswer"), dict)
        else {}
    )
    listener_observation = (
        resulting.get("listenerObservation")
        if isinstance(resulting.get("listenerObservation"), dict)
        else {}
    )
    expected_find_request = buddy_callback_probe.encode_find_buddy_request(
        buddy_id=buddy_id,
        client_hash=buddy_user_hash,
        tcp_port=buddy_tcp_port,
    )
    expected_callback_request = buddy_callback_probe.encode_callback_request(
        buddy_id=buddy_id,
        file_hash=file_hash,
        requester_tcp_port=requester_tcp_port,
    )
    try:
        decoded_response = buddy_callback_probe.decode_find_buddy_response(
            bytes.fromhex(str(find_response.get("rawHex") or ""))
        )
        decoded_relay = buddy_callback_probe.decode_callback_relay(
            bytes.fromhex(str(relay.get("rawHex") or ""))
        )
    except (ValueError, ed2k_wire.Ed2kWireError):
        decoded_response = {}
        decoded_relay = {}
    requester = (
        receipt.get("requester") if isinstance(receipt.get("requester"), dict) else {}
    )
    requester_udp_port = requester.get("udpPort")
    relay_readiness_sequence = relay_readiness.get("sequence")
    relay_readiness_sequence = (
        relay_readiness_sequence
        if isinstance(relay_readiness_sequence, int)
        and not isinstance(relay_readiness_sequence, bool)
        and relay_readiness_sequence > 0
        else None
    )
    timestamps = [
        _timestamp(find_request.get("sentAt")),
        _timestamp(find_response.get("receivedAt")),
        _timestamp(held_hello.get("sentAt")),
        _timestamp(held_answer.get("receivedAt")),
        _timestamp(relay_readiness.get("observedAt")),
        _timestamp(callback_request.get("sentAt")),
        _timestamp(relay.get("receivedAt")),
        _timestamp(resulting_hello.get("sentAt")),
        _timestamp(resulting_answer.get("receivedAt")),
        _timestamp(listener_observation.get("observedAt")),
    ]
    ordered_timestamps = bool(
        all(value is not None for value in timestamps)
        and all(
            current <= following
            for current, following in zip(timestamps[:-2], timestamps[1:-1])
        )
        and timestamps[-1] >= timestamps[-3]
    )
    expected_buddy_identity = {
        "userHash": buddy_user_hash.hex().upper(),
        "clientId": buddy_client_id,
        "tcpPort": buddy_tcp_port,
    }
    expected_target_identity = {
        "userHash": target["userHash"],
        "clientId": target["peerHelloClientId"],
        "tcpPort": target["tcpPort"],
    }
    requester_answer_identity = {
        "userHash": requester_user_hash.hex().upper(),
        "clientId": int.from_bytes(ipaddress_bytes(buddy_host), "little"),
        "tcpPort": requester_tcp_port,
    }
    ok = bool(
        target["ok"]
        and receipt.get("schema") == "emulebb.buddy-callback-probe/1"
        and receipt.get("status") == "completed"
        and receipt.get("targetLabel") == client
        and receipt.get("target")
        == {
            "host": target_host,
            "tcpPort": target["tcpPort"],
            "udpPort": target["udpPort"],
            "userHash": target["userHash"],
            "serverClientId": target["clientId"],
            "peerHelloClientId": target["peerHelloClientId"],
        }
        and receipt.get("buddy")
        == {
            "host": buddy_host,
            "tcpPort": buddy_tcp_port,
            "udpPort": buddy_udp_port,
            "userHash": buddy_user_hash.hex().upper(),
            "clientId": buddy_client_id,
            "buddyId": buddy_id.hex().upper(),
        }
        and requester.get("host") == buddy_host
        and requester.get("tcpPort") == requester_tcp_port
        and isinstance(requester_udp_port, int)
        and not isinstance(requester_udp_port, bool)
        and 0 < requester_udp_port <= 0xFFFF
        and requester.get("userHash") == requester_user_hash.hex().upper()
        and receipt.get("fileHash") == file_hash.hex().upper()
        and relay_readiness.get("ok") is True
        and relay_readiness.get("client") == client
        and relay_readiness.get("family") == "kad_event"
        and relay_readiness.get("event") == "buddy_socket"
        and relay_readiness.get("milestone") == "buddy_socket_attached"
        and relay_readiness_sequence is not None
        and find_request.get("sourceEndpoint") == f"{buddy_host}:{buddy_udp_port}"
        and find_request.get("targetEndpoint") == f"{target_host}:{target['udpPort']}"
        and find_request.get("rawHex") == expected_find_request.hex().upper()
        and find_request.get("sentBytes") == len(expected_find_request)
        and decoded_response.get("buddyId") == buddy_id.hex().upper()
        and decoded_response.get("clientHash") == target["userHash"]
        and decoded_response.get("tcpPort") == target["tcpPort"]
        and decoded_response.get("connectOptions") is None
        and _decode_hello_request(held_hello.get("rawHex")) == expected_buddy_identity
        and _decode_hello_answer(held_answer) == expected_target_identity
        and callback_request.get("sourceEndpoint")
        == f"{buddy_host}:{requester_udp_port}"
        and callback_request.get("targetEndpoint")
        == f"{target_host}:{target['udpPort']}"
        and callback_request.get("rawHex") == expected_callback_request.hex().upper()
        and callback_request.get("sentBytes") == len(expected_callback_request)
        and decoded_relay.get("buddyId") == buddy_id.hex().upper()
        and decoded_relay.get("fileHash") == file_hash.hex().upper()
        and decoded_relay.get("requesterHost") == buddy_host
        and decoded_relay.get("requesterTcpPort") == requester_tcp_port
        and _decode_hello_request(resulting_hello.get("rawHex"))
        == expected_buddy_identity
        and _decode_hello_answer(resulting_answer) == requester_answer_identity
        and _listener_hello(listener_observation) == expected_buddy_identity
        and ordered_timestamps
    )
    return {
        "ok": ok,
        "requesterUdpPort": requester_udp_port,
        "findRequestRawHex": expected_find_request.hex().upper(),
        "findResponseRawHex": find_response.get("rawHex"),
        "callbackRequestRawHex": expected_callback_request.hex().upper(),
        "relayRawHex": relay.get("rawHex"),
        "heldSourceEndpoint": held.get("sourceEndpoint"),
        "relayReadinessSequence": relay_readiness_sequence,
        "orderedTimestamps": ordered_timestamps,
        "targetHelloIdentity": _decode_hello_answer(held_answer),
        "resultingHelloIdentity": _listener_hello(listener_observation),
    }


def ipaddress_bytes(host: str) -> bytes:
    """Returns the four IPv4 bytes used by the requester-listener identity."""

    return ipaddress.IPv4Address(host).packed


def _kad_packet(
    record: dict[str, Any],
    *,
    direction: str,
    peer: str,
    raw: bytes,
) -> bool:
    keys = _keys(record)
    body = _body(record)
    return bool(
        _event(record, "kad_udp", "packet")
        and str(keys.get("peer") or "").casefold() == peer.casefold()
        and keys.get("protocolMarker") == raw[0]
        and keys.get("opcode") == raw[1]
        and body.get("direction") == direction
        and body.get("protocolMarker") == raw[0]
        and body.get("opcode") == raw[1]
        and body.get("decodedLen") == len(raw)
        and _same_hex(body.get("decodedHex"), raw)
    )


def _fixture_event(record: dict[str, Any]) -> bool:
    body = _body(record)
    return bool(
        _event(record, "kad_event", "buddy_fixture")
        and body
        == {
            "milestone": "buddy_relay_eligibility_prepared",
            "action": "prepare",
            "outcome": "eligible",
            "reason": "diagnostic_test_control",
            "tcpFirewalled": False,
            "udpVerified": True,
            "udpOpen": True,
        }
    )


def _buddy_request_event(
    record: dict[str, Any],
    *,
    buddy_endpoint: str,
    buddy_user_hash: bytes,
    buddy_id: bytes,
    buddy_tcp_port: int,
    target_tcp_port: int,
) -> bool:
    keys = _keys(record)
    body = _body(record)
    return bool(
        _event(record, "kad_event", "buddy_request")
        and str(keys.get("peer") or "").casefold() == buddy_endpoint.casefold()
        and _same_hex(keys.get("peerHash"), buddy_user_hash)
        and body.get("milestone") == "buddy_request_accepted"
        and body.get("action") == "accept"
        and body.get("outcome") == "accepted"
        and body.get("reason") == "eligible"
        and _same_hex(body.get("buddyId"), buddy_id)
        and _same_hex(body.get("clientHash"), buddy_user_hash)
        and body.get("tcpFirewalled") is False
        and body.get("udpVerified") is True
        and body.get("udpOpen") is True
        and body.get("requesterHasUdpKey") is False
        and body.get("requesterTcpPort") == buddy_tcp_port
        and body.get("localTcpPort") == target_tcp_port
    )


def _buddy_socket_event(
    record: dict[str, Any],
    *,
    buddy_host: str,
    buddy_user_hash: bytes,
    buddy_id: bytes,
    buddy_tcp_port: int,
) -> bool:
    keys = _keys(record)
    body = _body(record)
    peer = str(keys.get("peer") or "")
    return bool(
        _event(record, "kad_event", "buddy_socket")
        and peer.startswith(f"{buddy_host}:")
        and _same_hex(keys.get("peerHash"), buddy_user_hash)
        and body.get("milestone") == "buddy_socket_attached"
        and body.get("action") == "attach"
        and body.get("outcome") == "attached"
        and _same_hex(body.get("buddyId"), buddy_id)
        and _same_hex(body.get("clientHash"), buddy_user_hash)
        and body.get("advertisedTcpPort") == buddy_tcp_port
    )


def buddy_socket_readiness(
    records: Iterable[dict[str, Any]],
    *,
    client: str,
    buddy_host: str,
    buddy_user_hash: bytes,
    buddy_id: bytes,
    buddy_tcp_port: int,
) -> dict[str, Any] | None:
    """Returns one exact receipt only after the held socket can own relays."""

    record, count = _single(
        list(records),
        lambda candidate: _buddy_socket_event(
            candidate,
            buddy_host=buddy_host,
            buddy_user_hash=buddy_user_hash,
            buddy_id=buddy_id,
            buddy_tcp_port=buddy_tcp_port,
        ),
    )
    if record is None or count != 1:
        return None
    return {
        "ok": True,
        "client": client,
        "family": "kad_event",
        "event": "buddy_socket",
        "milestone": "buddy_socket_attached",
        "sequence": _sequence(record),
        "runId": record.get("runId"),
        "processId": record.get("processId"),
    }


def _callback_event(
    record: dict[str, Any],
    *,
    requester_endpoint: str,
    requester_host: str,
    requester_udp_port: int,
    requester_tcp_port: int,
    buddy_endpoint: str,
    buddy_id: bytes,
    file_hash: bytes,
) -> bool:
    keys = _keys(record)
    body = _body(record)
    return bool(
        _event(record, "kad_event", "buddy_callback")
        and str(keys.get("peer") or "").casefold() == requester_endpoint.casefold()
        and _same_hex(keys.get("fileHash"), file_hash)
        and body.get("milestone") == "buddy_callback_relayed"
        and body.get("action") == "relay"
        and body.get("outcome") == "relayed"
        and body.get("reason") == "eligible"
        and _same_hex(body.get("buddyId"), buddy_id)
        and _same_hex(body.get("fileHash"), file_hash)
        and body.get("requesterIp") == requester_host
        and body.get("requesterUdpPort") == requester_udp_port
        and body.get("requesterTcpPort") == requester_tcp_port
        and str(body.get("buddyTcpEndpoint") or "").casefold()
        == buddy_endpoint.casefold()
    )


def _relay_packet(record: dict[str, Any], *, raw: bytes) -> bool:
    keys = _keys(record)
    body = _body(record)
    return bool(
        _event(record, "ed2k_tcp", "packet")
        and keys.get("protocolMarker") == buddy_callback_probe.OP_EMULEPROT
        and keys.get("opcode") == buddy_callback_probe.OP_CALLBACK
        and body.get("direction") == "send"
        and body.get("outcome") == "send_succeeded"
        and body.get("protocolMarker") == buddy_callback_probe.OP_EMULEPROT
        and body.get("opcode") == buddy_callback_probe.OP_CALLBACK
        and body.get("payloadLen") == buddy_callback_probe.CALLBACK_RELAY_PAYLOAD_BYTES
        and _same_hex(body.get("payloadHex"), raw[6:])
        and body.get("transportMode") == "plaintext"
        and body.get("obfuscated") is False
        and body.get("flow") == "listener"
        and body.get("rawLen") == len(raw)
        and _same_hex(body.get("rawHex"), raw)
    )


def _client_evidence(
    *,
    client: str,
    records: list[dict[str, Any]],
    target_host: str,
    target_value: object,
    control_value: object,
    probe_value: object,
    buddy_host: str,
    buddy_tcp_port: int,
    buddy_udp_port: int,
    buddy_user_hash: bytes,
    buddy_client_id: int,
    buddy_id: bytes,
    file_hash: bytes,
    requester_tcp_port: int,
    requester_user_hash: bytes,
) -> dict[str, Any]:
    target = _target(target_value)
    control = _control(control_value)
    probe = _probe_receipt(
        probe_value,
        client=client,
        target_host=target_host,
        target=target,
        buddy_host=buddy_host,
        buddy_tcp_port=buddy_tcp_port,
        buddy_udp_port=buddy_udp_port,
        buddy_user_hash=buddy_user_hash,
        buddy_client_id=buddy_client_id,
        buddy_id=buddy_id,
        file_hash=file_hash,
        requester_tcp_port=requester_tcp_port,
        requester_user_hash=requester_user_hash,
    )
    try:
        find_request_raw = bytes.fromhex(str(probe["findRequestRawHex"] or ""))
        find_response_raw = bytes.fromhex(str(probe["findResponseRawHex"] or ""))
        callback_request_raw = bytes.fromhex(str(probe["callbackRequestRawHex"] or ""))
        relay_raw = bytes.fromhex(str(probe["relayRawHex"] or ""))
    except ValueError:
        find_request_raw = find_response_raw = callback_request_raw = relay_raw = b""
    buddy_udp_endpoint = f"{buddy_host}:{buddy_udp_port}"
    requester_udp_port = probe.get("requesterUdpPort")
    requester_udp_endpoint = f"{buddy_host}:{requester_udp_port}"
    buddy_tcp_endpoint = f"{buddy_host}:{buddy_tcp_port}"

    fixture, fixture_count = _single(records, _fixture_event)
    find_request, find_request_count = _single(
        records,
        lambda record: (
            bool(find_request_raw)
            and _kad_packet(
                record,
                direction="recv",
                peer=buddy_udp_endpoint,
                raw=find_request_raw,
            )
        ),
    )
    find_response, find_response_count = _single(
        records,
        lambda record: (
            bool(find_response_raw)
            and _kad_packet(
                record,
                direction="send",
                peer=buddy_udp_endpoint,
                raw=find_response_raw,
            )
        ),
    )
    request_event, request_event_count = _single(
        records,
        lambda record: _buddy_request_event(
            record,
            buddy_endpoint=buddy_udp_endpoint,
            buddy_user_hash=buddy_user_hash,
            buddy_id=buddy_id,
            buddy_tcp_port=buddy_tcp_port,
            target_tcp_port=target.get("tcpPort"),
        ),
    )
    socket_event, socket_event_count = _single(
        records,
        lambda record: _buddy_socket_event(
            record,
            buddy_host=buddy_host,
            buddy_user_hash=buddy_user_hash,
            buddy_id=buddy_id,
            buddy_tcp_port=buddy_tcp_port,
        ),
    )
    readiness_joined = bool(
        socket_event is not None
        and probe.get("relayReadinessSequence") == _sequence(socket_event)
    )
    callback_request, callback_request_count = _single(
        records,
        lambda record: (
            bool(callback_request_raw)
            and _kad_packet(
                record,
                direction="recv",
                peer=requester_udp_endpoint,
                raw=callback_request_raw,
            )
        ),
    )
    callback_event, callback_event_count = _single(
        records,
        lambda record: (
            isinstance(requester_udp_port, int)
            and _callback_event(
                record,
                requester_endpoint=requester_udp_endpoint,
                requester_host=buddy_host,
                requester_udp_port=requester_udp_port,
                requester_tcp_port=requester_tcp_port,
                buddy_endpoint=buddy_tcp_endpoint,
                buddy_id=buddy_id,
                file_hash=file_hash,
            )
        ),
    )
    relay_packet, relay_packet_count = _single(
        records,
        lambda record: bool(relay_raw) and _relay_packet(record, raw=relay_raw),
    )
    ordered = bool(
        fixture is not None
        and find_request is not None
        and find_response is not None
        and request_event is not None
        and socket_event is not None
        and callback_request is not None
        and callback_event is not None
        and relay_packet is not None
        and _sequence(fixture)
        < _sequence(find_request)
        < _sequence(find_response)
        < _sequence(request_event)
        < _sequence(socket_event)
        < _sequence(callback_request)
        < _sequence(callback_event)
        and _sequence(callback_request) < _sequence(relay_packet)
    )
    ok = bool(
        target["ok"]
        and control["ok"]
        and probe["ok"]
        and readiness_joined
        and ordered
        and all(
            count == 1
            for count in (
                fixture_count,
                find_request_count,
                find_response_count,
                request_event_count,
                socket_event_count,
                callback_request_count,
                callback_event_count,
                relay_packet_count,
            )
        )
    )
    return {
        "ok": ok,
        "target": target,
        "control": control,
        "probe": probe,
        "causalChain": {
            "ok": ordered,
            "fixture": {"count": fixture_count, "sequence": _sequence(fixture) or None},
            "findRequest": {
                "count": find_request_count,
                "sequence": _sequence(find_request) or None,
            },
            "findResponse": {
                "count": find_response_count,
                "sequence": _sequence(find_response) or None,
            },
            "requestAccepted": {
                "count": request_event_count,
                "sequence": _sequence(request_event) or None,
            },
            "socketAttached": {
                "count": socket_event_count,
                "sequence": _sequence(socket_event) or None,
                "probeReadinessJoined": readiness_joined,
            },
            "callbackRequest": {
                "count": callback_request_count,
                "sequence": _sequence(callback_request) or None,
            },
            "callbackRelayed": {
                "count": callback_event_count,
                "sequence": _sequence(callback_event) or None,
            },
            "relayPacket": {
                "count": relay_packet_count,
                "sequence": _sequence(relay_packet) or None,
            },
        },
    }


def build_buddy_callback_diagnostic_evidence(
    *,
    target_host: str,
    targets: dict[str, object],
    controls: dict[str, object],
    probe_results: dict[str, object],
    buddy_host: str,
    buddy_tcp_port: int,
    buddy_udp_port: int,
    buddy_user_hash: bytes,
    buddy_client_id: int,
    buddy_id: bytes,
    file_hash: bytes,
    requester_tcp_port: int,
    requester_user_hash: bytes,
    rust_records: Iterable[dict[str, Any]],
    mfc_records: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Builds an exact bilateral buddy-discovery and callback-relay verdict."""

    records = {"rust": list(rust_records), "mfc": list(mfc_records)}
    clients = {
        client: _client_evidence(
            client=client,
            records=records[client],
            target_host=target_host,
            target_value=targets.get(client),
            control_value=controls.get(client),
            probe_value=probe_results.get(client),
            buddy_host=buddy_host,
            buddy_tcp_port=buddy_tcp_port,
            buddy_udp_port=buddy_udp_port,
            buddy_user_hash=buddy_user_hash,
            buddy_client_id=buddy_client_id,
            buddy_id=buddy_id,
            file_hash=file_hash,
            requester_tcp_port=requester_tcp_port,
            requester_user_hash=requester_user_hash,
        )
        for client in CLIENTS
    }
    comparison = {
        "findRequestBytesEqual": len(
            {row["probe"]["findRequestRawHex"] for row in clients.values()}
        )
        == 1,
        "callbackRequestBytesEqual": len(
            {row["probe"]["callbackRequestRawHex"] for row in clients.values()}
        )
        == 1,
        "relayBytesEqual": len(
            {row["probe"]["relayRawHex"] for row in clients.values()}
        )
        == 1,
        "bothComplete": all(row["ok"] is True for row in clients.values()),
    }
    comparison["ok"] = all(comparison.values())
    failures = [
        *[
            f"client.{client}"
            for client, row in clients.items()
            if row["ok"] is not True
        ],
        *([] if comparison["ok"] else ["comparison"]),
    ]
    return {
        "schema": SCHEMA,
        "ok": not failures,
        "failures": failures,
        "clients": clients,
        "comparison": comparison,
        "coverageClaims": {
            "eligibleCoverageIds": [COVERAGE_ID] if not failures else [],
            "evidenceLayers": list(EVIDENCE_LAYERS),
        },
    }


def require_buddy_callback_diagnostic_evidence(report: dict[str, Any]) -> None:
    """Raises unless both clients complete the exact causal buddy relay chain."""

    if report.get("schema") != SCHEMA:
        raise RuntimeError(
            "Deterministic buddy-callback diagnostics have an unexpected schema"
        )
    if report.get("ok") is not True:
        raise RuntimeError(
            "Deterministic buddy-callback diagnostics are incomplete: "
            f"{report.get('failures')!r}"
        )
    claims = report.get("coverageClaims")
    if not isinstance(claims, dict) or claims.get("eligibleCoverageIds") != [
        COVERAGE_ID
    ]:
        raise RuntimeError("Deterministic buddy-callback coverage claims are invalid")
