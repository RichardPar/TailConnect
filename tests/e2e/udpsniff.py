#!/usr/bin/env python3
"""Print one line per IPv4 UDP packet seen on an interface: "src -> dst len".

Used by tests/e2e/nat.sh (TC_NAT_PCAP=1) to see NAT port mappings. Needs
CAP_NET_RAW in the interface's network namespace (fine inside the test's
user namespace). Usage: udpsniff.py IFACE [IGNORE_PORT ...]
"""
import socket
import struct
import sys

iface = sys.argv[1]
ignore = {int(p) for p in sys.argv[2:]}
# ETH_P_ALL: protocol-specific taps don't see frames consumed by a bridge.
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
s.bind((iface, 0))
seen = set()
while True:
    frame, (_, _, pkttype, _, _) = s.recvfrom(65535)
    if pkttype == socket.PACKET_OUTGOING:
        continue  # each packet crosses the bridge once; skip our own echo
    if frame[12:14] != b"\x08\x00":
        continue
    ip = frame[14:]
    if len(ip) < 20 or ip[9] != 17:
        continue
    ihl = (ip[0] & 0x0F) * 4
    src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    sport, dport, ulen = struct.unpack("!HHH", ip[ihl:ihl + 6])
    if sport in ignore or dport in ignore:
        continue
    print(f"{src}:{sport} -> {dst}:{dport} len={ulen - 8}", flush=True)
