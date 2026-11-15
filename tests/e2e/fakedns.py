#!/usr/bin/env python3
"""Minimal upstream DNS server for tests: answers A queries for names under
example.com with ANSWER; every other name is NXDOMAIN.

Used by tests/e2e/nat.sh to check that MagicDNS forwards names outside its
domain to the host's original resolver. Usage: fakedns.py LISTEN_IP ANSWER
"""
import socket
import struct
import sys

listen, answer = sys.argv[1], socket.inet_aton(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((listen, 53))
while True:
    q, src = s.recvfrom(1500)
    if len(q) < 12:
        continue
    qid, flags, qdcount = struct.unpack("!HHH", q[:6])
    # Walk the question name to find QTYPE.
    i = 12
    while i < len(q) and q[i] != 0:
        i += q[i] + 1
    qtype = struct.unpack("!H", q[i + 1:i + 3])[0] if i + 3 <= len(q) else 0
    question = q[12:i + 5]
    ours = q[12:i + 1].lower().endswith(b"\x07example\x03com\x00")
    an, rcode = 0, 0 if ours else 3
    body = question
    if ours and qtype == 1:
        an = 1
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + answer
    hdr = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, an, 0, 0)
    s.sendto(hdr + body, src)
