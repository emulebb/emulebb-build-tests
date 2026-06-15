"""Measure whether the hide.me VPN preserves the UDP *source port* on egress.

This is the decisive diagnostic for the eD2K UDP source-reask "no ack" symptom
(FEAT-001). A peer answers a reask only if it can locate us in its upload queue
by `(ip, udp_port)` (eMule `GetWaitingClientByIP_UDP`), matching the reask
datagram's *source port* against the UDP port we advertised in
`CT_EMULE_UDPPORTS` (= our local Kad UDP port). If the VPN rewrites our outbound
source port, that match fails and the peer stays silent — exactly the observed
behaviour.

Method (gentle, NOT eD2K traffic — a few STUN packets to public servers):
  * bind one UDP socket to the VPN tunnel IP on a fixed local port P;
  * send an RFC 5389 STUN Binding Request to two *different* STUN servers from
    that same socket;
  * read the XOR-MAPPED-ADDRESS (external ip:port) each server reflects back.

Interpretation:
  * mapped_port == P on both servers  -> port-preserving (cone) NAT: the reask
    source port equals the advertised port, so the (ip,udp_port) match HOLDS;
    the silence is NOT a source-port problem (look at queue membership/timing).
  * mapped_port == same value != P     -> endpoint-independent but REMAPPED: the
    peer sees a consistent port, but not the advertised one -> match BREAKS.
  * mapped_port differs between servers -> symmetric NAT: every peer sees a
    different source port -> match BREAKS. Root cause confirmed.

Usage: python scripts/reask-vpn-source-port-probe.py --bind-ip <tunnel-ipv4>
"""

from __future__ import annotations

import argparse
import secrets
import socket
import struct

# Windows IPv4 IP_UNICAST_IF: egress-pin a socket to an interface so a split-tunnel
# default route does not steal the packet (the interface index goes in *network*
# byte order). Mirrors emulebb-rust stun.rs / kad socket_opts pinning.
IP_UNICAST_IF = 31

STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_MAGIC_COOKIE = 0x2112A442
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020

# Same default set (and order) as emulebb-rust stun.rs / eMuleBB StunProbeSeams.
DEFAULT_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun1.l.google.com", 19302),
    ("stun.nextcloud.com", 3478),
]


def build_request(txid: bytes) -> bytes:
    return struct.pack(">HHI", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE) + txid


def parse_mapped(buf: bytes, txid: bytes) -> tuple[str, int]:
    if len(buf) < 20:
        raise ValueError(f"response too short ({len(buf)} bytes)")
    msg_type, msg_len, cookie = struct.unpack(">HHI", buf[:8])
    if msg_type != STUN_BINDING_SUCCESS:
        raise ValueError(f"not a binding success (type=0x{msg_type:04x})")
    if cookie != STUN_MAGIC_COOKIE:
        raise ValueError("bad magic cookie")
    if buf[8:20] != txid:
        raise ValueError("transaction id mismatch")
    pos = 20
    end = min(len(buf), 20 + msg_len)
    while pos + 4 <= end:
        attr_type, alen = struct.unpack(">HH", buf[pos : pos + 4])
        vpos = pos + 4
        if vpos + alen > end:
            break
        if attr_type in (ATTR_XOR_MAPPED_ADDRESS, ATTR_MAPPED_ADDRESS) and alen >= 8:
            family = buf[vpos + 1]
            port = struct.unpack(">H", buf[vpos + 2 : vpos + 4])[0]
            addr = struct.unpack(">I", buf[vpos + 4 : vpos + 8])[0]
            if attr_type == ATTR_XOR_MAPPED_ADDRESS:
                port ^= STUN_MAGIC_COOKIE >> 16
                addr ^= STUN_MAGIC_COOKIE
            if family == 0x01:  # IPv4 only
                return (socket.inet_ntoa(struct.pack(">I", addr)), port)
        pos = vpos + ((alen + 3) & ~3)
    raise ValueError("no IPv4 mapped-address attribute")


def probe(sock: socket.socket, host: str, port: int, timeout: float) -> tuple[str, int]:
    server_ip = socket.gethostbyname(host)
    txid = secrets.token_bytes(12)
    sock.settimeout(timeout)
    sock.sendto(build_request(txid), (server_ip, port))
    while True:
        data, src = sock.recvfrom(1500)
        if src[0] == server_ip:
            return parse_mapped(data, txid)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind-ip", required=True, help="VPN tunnel IPv4 to bind/egress on")
    parser.add_argument("--bind-port", type=int, default=0, help="fixed local UDP port (0 = ephemeral)")
    parser.add_argument("--if-index", type=int, required=True, help="tunnel interface index for IP_UNICAST_IF egress pinning")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Egress-pin to the tunnel interface BEFORE bind so the probe leaves via the
    # VPN even under a split tunnel (else we'd measure the LAN NAT, not hide.me).
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack(">I", args.if_index))
    except OSError as exc:
        print(f"FAILED to set IP_UNICAST_IF if_index={args.if_index}: {exc}")
        return 2
    try:
        sock.bind((args.bind_ip, args.bind_port))
    except OSError as exc:
        print(f"FAILED to bind {args.bind_ip}:{args.bind_port}: {exc}")
        return 2
    local_ip, local_port = sock.getsockname()
    print(f"bound local {local_ip}:{local_port} (egress-pinned if_index={args.if_index})")

    results: list[tuple[str, str, int]] = []
    for host, port in DEFAULT_SERVERS:
        try:
            ip, mport = probe(sock, host, port, args.timeout)
            print(f"  {host}:{port:<6} -> mapped {ip}:{mport}")
            results.append((host, ip, mport))
        except Exception as exc:  # noqa: BLE001
            print(f"  {host}:{port:<6} -> ERROR {type(exc).__name__}: {exc}")
        if len(results) >= 2:
            break

    sock.close()
    if len(results) < 2:
        print("VERDICT: inconclusive (need 2 successful probes)")
        return 1

    mapped_ports = {r[2] for r in results}
    mapped_ips = {r[1] for r in results}
    print(f"\nlocal_port={local_port}  mapped_ips={mapped_ips}  mapped_ports={mapped_ports}")
    if len(mapped_ports) > 1:
        print("VERDICT: SYMMETRIC NAT (source port differs per destination) -> "
              "reask (ip,udp_port) match BREAKS. Root cause of the silence confirmed.")
    elif mapped_ports == {local_port}:
        print("VERDICT: PORT-PRESERVING NAT -> reask source port == advertised port; "
              "(ip,udp_port) match HOLDS. Silence is NOT a source-port issue.")
    else:
        print("VERDICT: ENDPOINT-INDEPENDENT but REMAPPED port -> peer sees a "
              f"consistent port {mapped_ports} != advertised {local_port} -> match BREAKS "
              "unless we advertise the STUN-observed external port.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
