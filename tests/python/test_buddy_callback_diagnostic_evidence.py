from __future__ import annotations

import copy
import ipaddress
import struct

import pytest

from emule_test_harness import buddy_callback_diagnostic_evidence as evidence
from emule_test_harness import buddy_callback_probe
from emule_test_harness.docker_ed2k_source_publisher import encode_hello_answer


HOST = "127.0.0.1"
BUDDY_TCP_PORT = 35101
BUDDY_UDP_PORT = 35102
REQUESTER_TCP_PORT = 35103
BUDDY_CLIENT_ID = 7
BUDDY_ID = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
DIAGNOSTIC_BUDDY_ID = bytes.fromhex("3322110077665544BBAA9988FFEEDDCC")
BUDDY_HASH = bytes.fromhex("1032547698BADCFE1032547698BADCFE")
REQUESTER_HASH = bytes.fromhex("21436587A9CBED0F21436587A9CBED0F")
FILE_HASH = bytes.fromhex("32547698BADCFE1032547698BADCFE10")
TARGETS = {
    "rust": {
        "clientId": 1,
        "peerHelloClientId": 0,
        "idKind": "low-id",
        "tcpPort": 35201,
        "udpPort": 35202,
        "userHash": "436587A9CBED0F21436587A9CBED0F21",
    },
    "mfc": {
        "clientId": 2,
        "peerHelloClientId": 0,
        "idKind": "low-id",
        "tcpPort": 35301,
        "udpPort": 35302,
        "userHash": "547698BADCFE1032547698BADCFE1032",
    },
}


def _env(
    sequence: int,
    family: str,
    event: str,
    *,
    keys: dict[str, object] | None = None,
    body: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema": "diag_event_v2",
        "seq": sequence,
        "family": family,
        "event": event,
        "severity": "info",
        "keys": keys or {},
        "body": body or {},
    }


def _kad_packet(
    sequence: int,
    direction: str,
    peer: str,
    raw: bytes,
) -> dict[str, object]:
    return _env(
        sequence,
        "kad_udp",
        "packet",
        keys={"peer": peer, "protocolMarker": raw[0], "opcode": raw[1]},
        body={
            "direction": direction,
            "protocolMarker": raw[0],
            "opcode": raw[1],
            "decodedLen": len(raw),
            "decodedHex": raw.hex().upper(),
        },
    )


def _relay_raw(requester_host: str = HOST) -> bytes:
    payload = (
        BUDDY_ID
        + buddy_callback_probe._kad_uint128_wire_bytes(FILE_HASH, "file_hash")
        + int(ipaddress.IPv4Address(requester_host)).to_bytes(4, "little")
        + struct.pack("<H", REQUESTER_TCP_PORT)
    )
    return (
        bytes((buddy_callback_probe.OP_EMULEPROT,))
        + struct.pack("<I", len(payload) + 1)
        + bytes((buddy_callback_probe.OP_CALLBACK,))
        + payload
    )


def _control() -> dict[str, object]:
    return {
        "request": {"method": "POST", "path": evidence.CONTROL_PATH},
        "response": {
            "status": 200,
            "json": {
                "prepared": True,
                "tcpFirewalled": False,
                "udpVerified": True,
                "udpOpen": True,
                "state": "buddy-relay-eligible",
            },
        },
    }


def _probe(client: str, requester_udp_port: int) -> dict[str, object]:
    target = TARGETS[client]
    find_request = buddy_callback_probe.encode_find_buddy_request(
        buddy_id=BUDDY_ID,
        client_hash=BUDDY_HASH,
        tcp_port=BUDDY_TCP_PORT,
    )
    find_response = (
        bytes((0xE4, 0x5A))
        + BUDDY_ID
        + buddy_callback_probe._kad_uint128_wire_bytes(
            bytes.fromhex(target["userHash"]), "target_hash"
        )
        + struct.pack("<H", target["tcpPort"])
    )
    callback_request = buddy_callback_probe.encode_callback_request(
        buddy_id=BUDDY_ID,
        file_hash=FILE_HASH,
        requester_tcp_port=REQUESTER_TCP_PORT,
    )
    buddy_hello = buddy_callback_probe.encode_hello_request(
        user_hash=BUDDY_HASH,
        client_id=BUDDY_CLIENT_ID,
        tcp_port=BUDDY_TCP_PORT,
    )
    target_answer = encode_hello_answer(
        user_hash=bytes.fromhex(target["userHash"]),
        client_id=target["peerHelloClientId"],
        tcp_port=target["tcpPort"],
    )
    requester_answer = encode_hello_answer(
        user_hash=REQUESTER_HASH,
        client_id=int.from_bytes(ipaddress.IPv4Address(HOST).packed, "little"),
        tcp_port=REQUESTER_TCP_PORT,
    )
    buddy_payload = buddy_hello[6:]
    return {
        "schema": "emulebb.buddy-callback-probe/1",
        "status": "completed",
        "targetLabel": client,
        "target": {
            "host": HOST,
            "tcpPort": target["tcpPort"],
            "udpPort": target["udpPort"],
            "userHash": target["userHash"],
            "serverClientId": target["clientId"],
            "peerHelloClientId": target["peerHelloClientId"],
        },
        "buddy": {
            "host": HOST,
            "tcpPort": BUDDY_TCP_PORT,
            "udpPort": BUDDY_UDP_PORT,
            "userHash": BUDDY_HASH.hex().upper(),
            "clientId": BUDDY_CLIENT_ID,
            "buddyId": BUDDY_ID.hex().upper(),
        },
        "requester": {
            "host": HOST,
            "tcpPort": REQUESTER_TCP_PORT,
            "udpPort": requester_udp_port,
            "userHash": REQUESTER_HASH.hex().upper(),
        },
        "fileHash": FILE_HASH.hex().upper(),
        "findBuddyRequest": {
            "sourceEndpoint": f"{HOST}:{BUDDY_UDP_PORT}",
            "targetEndpoint": f"{HOST}:{target['udpPort']}",
            "rawHex": find_request.hex().upper(),
            "sentBytes": len(find_request),
            "sentAt": 1.0,
        },
        "findBuddyResponse": {
            "rawHex": find_response.hex().upper(),
            "receivedAt": 2.0,
        },
        "heldBuddyConnection": {
            "sourceEndpoint": f"{HOST}:40100",
            "hello": {"rawHex": buddy_hello.hex().upper(), "sentAt": 3.0},
            "helloAnswer": {
                "rawHex": target_answer.hex().upper(),
                "receivedAt": 4.0,
            },
        },
        "relayReadiness": {
            "ok": True,
            "client": client,
            "family": "kad_event",
            "event": "buddy_socket",
            "milestone": "buddy_socket_attached",
            "sequence": 5,
            "observedAt": 4.5,
        },
        "callbackRequest": {
            "sourceEndpoint": f"{HOST}:{requester_udp_port}",
            "targetEndpoint": f"{HOST}:{target['udpPort']}",
            "rawHex": callback_request.hex().upper(),
            "sentBytes": len(callback_request),
            "sentAt": 5.0,
        },
        "callbackRelay": {"rawHex": _relay_raw().hex().upper(), "receivedAt": 6.0},
        "resultingPeerSession": {
            "hello": {"rawHex": buddy_hello.hex().upper(), "sentAt": 7.0},
            "helloAnswer": {
                "rawHex": requester_answer.hex().upper(),
                "receivedAt": 8.0,
            },
            "listenerObservation": {
                "userHash": BUDDY_HASH.hex().upper(),
                "clientId": BUDDY_CLIENT_ID,
                "tcpPort": BUDDY_TCP_PORT,
                "payloadLength": len(buddy_payload),
                "payloadHex": buddy_payload.hex().upper(),
                "observedAt": 7.5,
            },
        },
    }


def _records(client: str, requester_udp_port: int) -> list[dict[str, object]]:
    target = TARGETS[client]
    probe = _probe(client, requester_udp_port)
    find_request = bytes.fromhex(probe["findBuddyRequest"]["rawHex"])
    find_response = bytes.fromhex(probe["findBuddyResponse"]["rawHex"])
    callback_request = bytes.fromhex(probe["callbackRequest"]["rawHex"])
    relay = _relay_raw()
    buddy_udp_endpoint = f"{HOST}:{BUDDY_UDP_PORT}"
    requester_udp_endpoint = f"{HOST}:{requester_udp_port}"
    return [
        _env(
            1,
            "kad_event",
            "buddy_fixture",
            body={
                "milestone": "buddy_relay_eligibility_prepared",
                "action": "prepare",
                "outcome": "eligible",
                "reason": "diagnostic_test_control",
                "tcpFirewalled": False,
                "udpVerified": True,
                "udpOpen": True,
            },
        ),
        _kad_packet(2, "recv", buddy_udp_endpoint, find_request),
        _kad_packet(3, "send", buddy_udp_endpoint, find_response),
        _env(
            4,
            "kad_event",
            "buddy_request",
            keys={
                "peer": buddy_udp_endpoint,
                "peerHash": BUDDY_HASH.hex().lower(),
            },
            body={
                "milestone": "buddy_request_accepted",
                "action": "accept",
                "outcome": "accepted",
                "reason": "eligible",
                "buddyId": DIAGNOSTIC_BUDDY_ID.hex().lower(),
                "clientHash": BUDDY_HASH.hex().lower(),
                "tcpFirewalled": False,
                "udpVerified": True,
                "udpOpen": True,
                "requesterHasUdpKey": False,
                "requesterTcpPort": BUDDY_TCP_PORT,
                "localTcpPort": target["tcpPort"],
            },
        ),
        _env(
            5,
            "kad_event",
            "buddy_socket",
            keys={"peer": f"{HOST}:40100", "peerHash": BUDDY_HASH.hex()},
            body={
                "milestone": "buddy_socket_attached",
                "action": "attach",
                "outcome": "attached",
                "buddyId": DIAGNOSTIC_BUDDY_ID.hex(),
                "clientHash": BUDDY_HASH.hex(),
                "advertisedTcpPort": BUDDY_TCP_PORT,
            },
        ),
        _kad_packet(6, "recv", requester_udp_endpoint, callback_request),
        _env(
            7,
            "ed2k_tcp",
            "packet",
            keys={"protocolMarker": 0xC5, "opcode": 0x99},
            body={
                "direction": "send",
                "outcome": "send_succeeded",
                "protocolMarker": 0xC5,
                "opcode": 0x99,
                "payloadLen": 38,
                "payloadHex": relay[6:].hex(),
                "transportMode": "plaintext",
                "obfuscated": False,
                "flow": "listener",
                "rawLen": len(relay),
                "rawHex": relay.hex(),
            },
        ),
        _env(
            8,
            "kad_event",
            "buddy_callback",
            keys={"peer": requester_udp_endpoint, "fileHash": FILE_HASH.hex()},
            body={
                "milestone": "buddy_callback_relayed",
                "action": "relay",
                "outcome": "relayed",
                "reason": "eligible",
                "buddyId": DIAGNOSTIC_BUDDY_ID.hex(),
                "fileHash": FILE_HASH.hex(),
                "requesterIp": HOST,
                "requesterUdpPort": requester_udp_port,
                "requesterTcpPort": REQUESTER_TCP_PORT,
                "buddyTcpEndpoint": f"{HOST}:{BUDDY_TCP_PORT}",
            },
        ),
    ]


def _report() -> dict[str, object]:
    requester_ports = {"rust": 36101, "mfc": 36102}
    return evidence.build_buddy_callback_diagnostic_evidence(
        target_host=HOST,
        targets=TARGETS,
        controls={client: _control() for client in ("rust", "mfc")},
        probe_results={
            client: _probe(client, requester_ports[client])
            for client in ("rust", "mfc")
        },
        buddy_host=HOST,
        buddy_tcp_port=BUDDY_TCP_PORT,
        buddy_udp_port=BUDDY_UDP_PORT,
        buddy_user_hash=BUDDY_HASH,
        buddy_client_id=BUDDY_CLIENT_ID,
        buddy_id=BUDDY_ID,
        file_hash=FILE_HASH,
        requester_tcp_port=REQUESTER_TCP_PORT,
        requester_user_hash=REQUESTER_HASH,
        rust_records=_records("rust", requester_ports["rust"]),
        mfc_records=_records("mfc", requester_ports["mfc"]),
    )


@pytest.mark.unit
def test_complete_bilateral_buddy_callback_chain_is_eligible() -> None:
    report = _report()

    evidence.require_buddy_callback_diagnostic_evidence(report)
    assert report["ok"] is True
    assert report["coverageClaims"]["eligibleCoverageIds"] == ["lowid.buddy-callback"]
    assert report["comparison"] == {
        "findRequestBytesEqual": True,
        "callbackRequestBytesEqual": True,
        "relayBytesEqual": True,
        "bothComplete": True,
        "ok": True,
    }


@pytest.mark.unit
def test_buddy_socket_readiness_requires_one_exact_ready_event() -> None:
    records = _records("mfc", 36102)

    receipt = evidence.buddy_socket_readiness(
        records,
        client="mfc",
        buddy_host=HOST,
        buddy_user_hash=BUDDY_HASH,
        buddy_id=BUDDY_ID,
        buddy_tcp_port=BUDDY_TCP_PORT,
    )

    assert receipt is not None
    assert receipt["sequence"] == 5

    wire_order_records = copy.deepcopy(records)
    wire_order_records[4]["body"]["buddyId"] = BUDDY_ID.hex()
    assert (
        evidence.buddy_socket_readiness(
            wire_order_records,
            client="mfc",
            buddy_host=HOST,
            buddy_user_hash=BUDDY_HASH,
            buddy_id=BUDDY_ID,
            buddy_tcp_port=BUDDY_TCP_PORT,
        )
        is None
    )
    assert (
        evidence.buddy_socket_readiness(
            [*records, copy.deepcopy(records[4])],
            client="mfc",
            buddy_host=HOST,
            buddy_user_hash=BUDDY_HASH,
            buddy_id=BUDDY_ID,
            buddy_tcp_port=BUDDY_TCP_PORT,
        )
        is None
    )


@pytest.mark.unit
@pytest.mark.parametrize("missing_index", range(8))
def test_each_missing_causal_record_is_evidence_incomplete(missing_index: int) -> None:
    requester_ports = {"rust": 36101, "mfc": 36102}
    rust_records = _records("rust", requester_ports["rust"])
    del rust_records[missing_index]
    report = evidence.build_buddy_callback_diagnostic_evidence(
        target_host=HOST,
        targets=TARGETS,
        controls={client: _control() for client in ("rust", "mfc")},
        probe_results={
            client: _probe(client, requester_ports[client])
            for client in ("rust", "mfc")
        },
        buddy_host=HOST,
        buddy_tcp_port=BUDDY_TCP_PORT,
        buddy_udp_port=BUDDY_UDP_PORT,
        buddy_user_hash=BUDDY_HASH,
        buddy_client_id=BUDDY_CLIENT_ID,
        buddy_id=BUDDY_ID,
        file_hash=FILE_HASH,
        requester_tcp_port=REQUESTER_TCP_PORT,
        requester_user_hash=REQUESTER_HASH,
        rust_records=rust_records,
        mfc_records=_records("mfc", requester_ports["mfc"]),
    )

    assert report["ok"] is False
    assert "client.rust" in report["failures"]
    assert report["coverageClaims"]["eligibleCoverageIds"] == []
    with pytest.raises(RuntimeError, match="incomplete"):
        evidence.require_buddy_callback_diagnostic_evidence(report)


@pytest.mark.unit
def test_probe_or_diagnostic_identity_mismatch_cannot_claim_parity() -> None:
    requester_ports = {"rust": 36101, "mfc": 36102}
    probes = {
        client: _probe(client, requester_ports[client]) for client in ("rust", "mfc")
    }
    probes["mfc"] = copy.deepcopy(probes["mfc"])
    probes["mfc"]["callbackRelay"]["rawHex"] = _relay_raw("127.0.0.2").hex().upper()
    report = evidence.build_buddy_callback_diagnostic_evidence(
        target_host=HOST,
        targets=TARGETS,
        controls={client: _control() for client in ("rust", "mfc")},
        probe_results=probes,
        buddy_host=HOST,
        buddy_tcp_port=BUDDY_TCP_PORT,
        buddy_udp_port=BUDDY_UDP_PORT,
        buddy_user_hash=BUDDY_HASH,
        buddy_client_id=BUDDY_CLIENT_ID,
        buddy_id=BUDDY_ID,
        file_hash=FILE_HASH,
        requester_tcp_port=REQUESTER_TCP_PORT,
        requester_user_hash=REQUESTER_HASH,
        rust_records=_records("rust", requester_ports["rust"]),
        mfc_records=_records("mfc", requester_ports["mfc"]),
    )

    assert report["ok"] is False
    assert report["clients"]["mfc"]["probe"]["ok"] is False
    assert report["comparison"]["relayBytesEqual"] is False
