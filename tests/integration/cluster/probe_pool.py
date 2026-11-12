"""Ask the pool's collector for its schedd, then negotiate with that schedd.

This is the path a CE requires: greet the collector through the shared port, ask
it who its schedd is, then greet the schedd by the sock name the collector
publishes. Run inside the `submit` container of the testbed pool.
"""

from __future__ import annotations

import base64
import re
import socket
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from xrdhtcondor import cedar

VERSION = "$CondorVersion: 23.0.28 2025-08-21 BuildID: 827396 PackageID: 23.0.28-1 $"
QUERY_SCHEDD_ADS = 6


def our_key() -> str:
    """A P-256 public key, base64 of the uncompressed point."""
    key = ec.generate_private_key(ec.SECP256R1())
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    ).decode()


def negotiate(host: str, sock: str) -> dict[str, object]:
    """Greet ``host``'s daemon ``sock``, offer CLAIMTOBE, and return the reply."""
    request = cedar.SecurityRequest(
        auth_methods="CLAIMTOBE",
        remote_version=VERSION,
        ecdh_public=our_key(),
        connect_sinful=f"<{host}:9618?sock={sock}>",
        encryption="NEVER",
        integrity="NEVER",
    )
    with socket.create_connection((host, 9618), timeout=30) as conn:
        conn.settimeout(20)
        conn.sendall(cedar.greeting(sock))
        conn.sendall(cedar.frame(cedar.security_message(request.as_classads())))
        answer = conn.recv(65536)
    if not answer:
        raise SystemExit(f"{host} sock={sock}: the daemon closed without a reply")
    for _kind, payload in cedar.Deframer().feed(answer):
        try:
            return cedar.parse_wire_classads(payload)
        except cedar.CedarError:
            continue
    raise SystemExit(f"{host} sock={sock}: no classad in the reply")


def schedd_address() -> tuple[str, str]:
    """The schedd's host and sock name, read from the collector it advertises to."""
    request = cedar.SecurityRequest(
        auth_methods="CLAIMTOBE",
        remote_version=VERSION,
        ecdh_public=our_key(),
        connect_sinful="<cm:9618?sock=collector>",
        encryption="NEVER",
        integrity="NEVER",
    )
    # DaemonCore registers these "with payload": the command travels as one
    # message and the query classad as the next, not both in one message.
    command = cedar.frame(cedar.code_int(QUERY_SCHEDD_ADS))
    query = cedar.frame(cedar.put_classad({"TargetType": "Schedd", "Requirements": "true"}))
    # Unused today: the collector enacts an encrypted session (Enact = "YES"), so a
    # plaintext query earns error 2. The address is asked of Condor itself until
    # that session layer is wired to crypto.py.
    with socket.create_connection(("cm", 9618), timeout=30) as conn:
        conn.settimeout(20)
        conn.sendall(cedar.greeting("collector"))
        conn.sendall(cedar.frame(cedar.security_message(request.as_classads())))
        conn.sendall(command)
        conn.sendall(query)
        collected = b""
        while True:
            answer = conn.recv(65536)
            if not answer:
                break
            collected += answer
    for _kind, payload in cedar.Deframer().feed(collected):
        try:
            attributes = cedar.parse_wire_classads(payload)
        except cedar.CedarError:
            continue
        address = attributes.get("MyAddress") or attributes.get("ScheddIpAddr")
        if isinstance(address, str):
            named = re.search(r"sock=([^&>]+)", address)
            host = re.match(r"<([^:>]+)", address)
            if named and host:
                print(f"collector says the schedd is {host.group(1)} sock={named.group(1)}")
                return host.group(1), named.group(1)
    raise SystemExit("the collector named no schedd")


def main() -> int:
    host, sock = schedd_address()

    collector = negotiate("cm", "collector")
    print(f"collector negotiation: Authentication={collector.get('Authentication')!r}")
    schedd = negotiate(host, sock)
    print(f"schedd negotiation:    Authentication={schedd.get('Authentication')!r} "
          f"Enact={schedd.get('Enact')!r}")

    if collector.get("Authentication") != "YES" or schedd.get("Authentication") != "YES":
        print("FAILED: a daemon did not agree to the session")
        return 1
    print("OK: the collector and the schedd both negotiated a session")
    return 0


if __name__ == "__main__":
    sys.exit(main())
