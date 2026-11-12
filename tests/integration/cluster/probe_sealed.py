"""Sealed queue-manager traffic against the pool, after the CLAIMTOBE handshake.

The pool closes on the first sealed packet. That does not settle the cipher either
way: CLAIMTOBE performs no key exchange, so a CLAIMTOBE session has no shared ECDH
secret to derive a key from, and a test of the sealing rules needs a *method that
exchanges keys* - SCITOKENS or GSI. The pool is not configured for either, so this
is parked until a live token and a token-enabled daemon are available together.
"""

from __future__ import annotations

import base64
import socket
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from xrdhtcondor import cedar, collector, session

USER = subprocess.run(["id", "-un"], capture_output=True, text=True, check=True).stdout.strip()


def read_frame(conn: socket.socket) -> bytes:
    header = b""
    while len(header) < 5:
        chunk = conn.recv(5 - len(header))
        if not chunk:
            return b""
        header += chunk
    size = int.from_bytes(header[1:5], "big")
    body = b""
    while len(body) < size:
        chunk = conn.recv(size - len(body))
        if not chunk:
            return b""
        body += chunk
    return body


def main() -> int:
    host, port, sock = collector.schedd_address("cm")
    private = ec.generate_private_key(ec.SECP256R1())
    public = base64.b64encode(
        private.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    ).decode()
    request = cedar.SecurityRequest(
        auth_methods="CLAIMTOBE",
        ecdh_public=public,
        crypto_methods="AES",
        encryption="OPTIONAL",
        integrity="OPTIONAL",
        authentication="REQUIRED",
        command=1112,
        subsystem="SUBMIT",
        connect_sinful=f"<{host}:{port}?sock={sock}>",
    )
    conn = socket.create_connection((host, port), timeout=20)
    conn.settimeout(6)
    conn.sendall(cedar.greeting(sock))
    sent = cedar.frame(cedar.security_message(request.as_classads()))
    conn.sendall(sent)
    negotiated = read_frame(conn)
    said = cedar.parse_wire_classads(negotiated)
    print(f"negotiated: {said.get('AuthMethods')!r} enact={said.get('Enact')!r}")

    int2 = cedar.frame(cedar.code_int(2))
    ident = cedar.frame(cedar.code_int(1) + USER.encode() + b"\x00")
    conn.sendall(int2)
    conn.sendall(ident)
    after = b""
    while True:
        try:
            body = read_frame(conn)
        except TimeoutError:
            break
        if not body:
            break
        after += cedar.frame(body)

    formed = session.Session.between(private, base64.b64decode(said["ECDHPublicKey"]))
    # Everything exchanged since the SECMAN request is what the first sealed packet
    # authenticates, so the clear-text frames are kept in the history too.
    formed._sent.update(sent + int2 + ident)
    formed._heard.update(cedar.frame(negotiated) + after)

    for command, label in ((10001, "initialize"), (10002, "new cluster")):
        conn.sendall(formed.seal(cedar.code_int(command)))
        try:
            reply = read_frame(conn)
        except TimeoutError:
            print(f"  {label}: no reply")
            return 1
        if not reply:
            print(f"  {label}: closed")
            return 1
        plain = formed.open(cedar.frame(reply))
        print(f"  {label}: {int.from_bytes(plain[4:8], 'big', signed=True)}")
    print("OK: the daemon accepted sealed queue-manager traffic")
    return 0


if __name__ == "__main__":
    sys.exit(main())
