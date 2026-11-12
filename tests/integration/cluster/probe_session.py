"""Try a real encrypted session against the pool's schedd.

The negotiation gives us the schedd's ECDH public key; the AES key follows from
the shared secret by HKDF, as `crypto.py` already implements. What is unproven is
the session framing itself: the 64 handshake-digest bytes that precede the first
packet in each direction, and whether the peer validates them or only uses them
as additional authenticated data.
"""

from __future__ import annotations

import base64
import re
import socket
import subprocess
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from xrdhtcondor import cedar, crypto

VERSION = "$CondorVersion: 23.0.28 2025-08-21 BuildID: 827396 PackageID: 23.0.28-1 $"
#: The QMGMT session start a second connection announces (from the capture).
QMGMT = 421


def schedd_address() -> tuple[str, str]:
    """The schedd's host and sock name, as the pool publishes them."""
    said = subprocess.run(
        ["condor_status", "-schedd", "-af", "MyAddress"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    named = re.search(r"sock=([^&>]+)", said)
    host = re.match(r"<([^:>]+)", said)
    if not (named and host):
        raise SystemExit(f"{said!r}: no sock in the schedd's address")
    return host.group(1), named.group(1)


def negotiate(host: str, sock: str, command: int, key: ec.EllipticCurvePrivateKey) -> dict:
    """Greet the schedd and return its SECMAN reply, which carries its public key."""
    request = cedar.SecurityRequest(
        auth_methods="CLAIMTOBE",
        remote_version=VERSION,
        ecdh_public=base64.b64encode(
            key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        ).decode(),
        connect_sinful=f"<{host}:9618?sock={sock}>",
        encryption="NEVER",
        integrity="NEVER",
        command=command,
    )
    with socket.create_connection((host, 9618), timeout=30) as conn:
        conn.settimeout(20)
        conn.sendall(cedar.greeting(sock))
        conn.sendall(cedar.frame(cedar.security_message(request.as_classads())))
        answer = conn.recv(65536)
    for _kind, payload in cedar.Deframer().feed(answer):
        try:
            return cedar.parse_wire_classads(payload)
        except cedar.CedarError:
            continue
    raise SystemExit("no classad in the schedd's reply")


def main() -> int:
    host, sock = schedd_address()
    print(f"schedd {host} sock={sock}")

    key = ec.generate_private_key(ec.SECP256R1())
    reply = negotiate(host, sock, QMGMT, key)
    print(f"  negotiation: auth={reply.get('Authentication')!r} enact={reply.get('Enact')!r}")

    theirs = reply.get("ECDHPublicKey")
    if not isinstance(theirs, str):
        print("  FAILED: the reply names no ECDH key")
        return 1
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(theirs))
    secret = key.exchange(ec.ECDH(), peer)
    session = crypto.session_key(secret)
    print(f"  shared secret: {len(secret)} bytes, session key {len(session)} bytes")

    # The session itself: a fresh connection, greeting, negotiation, then packets
    # whose first bytes in each direction are the two handshake digests.
    with socket.create_connection((host, 9618), timeout=30) as conn:
        conn.settimeout(10)
        conn.sendall(cedar.greeting(sock))
        request = cedar.SecurityRequest(
            auth_methods="CLAIMTOBE",
            remote_version=VERSION,
            ecdh_public=base64.b64encode(
                key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            ).decode(),
            connect_sinful=f"<{host}:9618?sock={sock}>",
            encryption="NEVER",
            integrity="NEVER",
            command=QMGMT,
        )
        conn.sendall(cedar.frame(cedar.security_message(request.as_classads())))
        answer = conn.recv(65536)
        print(f"  second negotiation: {len(answer)} bytes")
        digests = bytes(64)
        payload = cedar.code_int(QMGMT) + b"XXXX\x00"  # a nonce-shaped message
        header = b"\x01" + len(payload).to_bytes(4, "big")
        sealed = crypto.PacketCodec(key=session).seal(header, payload, digests)
        conn.sendall(digests + header + sealed)
        try:
            got = conn.recv(65536)
            print(f"  session reply: {len(got)} bytes {got[:24]!r}")
        except socket.timeout:
            print("  session reply: none")
        print("  (a reply here means the pool decrypted our first session packet)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
