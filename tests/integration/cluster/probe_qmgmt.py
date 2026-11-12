"""Claim an identity at the schedd, the way a real client does.

Captured from a `condor_submit` in this pool, the handshake after the SECMAN
classads is plain integers:

- the client sends ``int 2``, then ``int 1`` followed by its user name and a NUL
  (``Condor_Auth_Claim::authenticate`` in ``condor_auth_claim.cpp``);
- the schedd answers ``int 2``, ``int 1``, ``int 0``.

With that, the schedd maps a user - which is what a queue-manager *write* requires,
and what it refuses without. After it, the connection is an enacted session, so
every queue-manager message must be sealed; that is what this probe reports.
"""

from __future__ import annotations

import socket
import subprocess
import sys

from xrdhtcondor import cedar, collector

QMGMT_WRITE_CMD = 1112
INITIALIZE = 10001


def drain(conn: socket.socket) -> bytes:
    """Everything the daemon sends before it waits for us again."""
    data = b""
    while True:
        try:
            chunk = conn.recv(65536)
        except TimeoutError:
            return data
        if not chunk:
            return data
        data += chunk


def integers(stream: bytes) -> list[int]:
    """The bare ``code(int)`` messages in ``stream``, in order."""
    found: list[int] = []
    for _kind, payload in cedar.Deframer().feed(stream):
        if len(payload) == 8:
            found.append(int.from_bytes(payload[4:], "big", signed=True))
    return found


def main() -> int:
    user = subprocess.run(["id", "-un"], capture_output=True, text=True, check=True).stdout.strip()
    host, port, sock = collector.schedd_address("cm")
    print(f"schedd {host}:{port} sock={sock}, claiming to be {user!r}")

    with socket.create_connection((host, port), timeout=30) as conn:
        conn.settimeout(4)
        request = cedar.SecurityRequest(
            auth_methods="CLAIMTOBE",
            encryption="OPTIONAL",
            integrity="OPTIONAL",
            authentication="REQUIRED",
            command=QMGMT_WRITE_CMD,
            subsystem="SUBMIT",
            connect_sinful=f"<{host}:{port}?sock={sock}>",
        )
        conn.sendall(cedar.greeting(sock))
        conn.sendall(cedar.frame(cedar.security_message(request.as_classads())))
        negotiated = drain(conn)
        print(f"  negotiation: {len(negotiated)} bytes")

        conn.sendall(cedar.frame(cedar.code_int(2)))
        conn.sendall(cedar.frame(cedar.code_int(1) + user.encode() + b"\x00"))
        claimed = drain(conn)
        said = integers(claimed)
        print(f"  the schedd answered {said}")
        if said != [2, 1, 0]:
            print("  FAILED: the identity was not accepted")
            return 1
        print(f"  OK: the schedd accepted the claim as {user!r}")

        # A plaintext queue-manager message is refused once a session is enacted:
        # the daemon either says nothing or closes, which is the point being made.
        try:
            conn.sendall(cedar.frame(cedar.code_int(INITIALIZE)))
            answer = drain(conn)
            print(f"  initialize (plaintext): {answer!r}")
        except OSError as exc:
            print(f"  initialize (plaintext): {type(exc).__name__}")

    print(
        "OK: authenticated, and the queue manager stays silent until the message is\n"
        "    sealed - the enacted session is the last piece."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
