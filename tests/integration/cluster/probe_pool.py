"""Our client against a real pool: greet and negotiate with both daemons.

Run inside the pool (`./run.sh` does it):

- the **collector** is greeted by the sock name `collector`, as a CE's shared port
  maps it, and negotiates a SECMAN session with the command it will be sent;
- the **schedd** is greeted by the sock name the collector publishes for it, and
  negotiates too - so the whole path a CE requires is exercised: collector query,
  address, greeting, session.
"""

from __future__ import annotations

import base64
import socket
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from xrdhtcondor import cedar, collector

VERSION = "$CondorVersion: 23.0.28 2025-08-21 BuildID: 827396 PackageID: 23.0.28-1 $"
COLLECTOR_HOST = "cm"
QUERY_SCHEDD_ADS = 6


def our_key() -> str:
    """A P-256 public key, base64 of the uncompressed point."""
    key = ec.generate_private_key(ec.SECP256R1())
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    ).decode()


def negotiate(host: str, sock: str, command: int, port: int = 9618) -> list[dict[str, object]]:
    """Greet a daemon, offer CLAIMTOBE for ``command``, and return every classad."""
    request = cedar.SecurityRequest(
        auth_methods="CLAIMTOBE",
        remote_version=VERSION,
        ecdh_public=our_key(),
        connect_sinful=f"<{host}:{port}?sock={sock}>",
        encryption="NEVER",
        integrity="NEVER",
        command=command,
    )
    with socket.create_connection((host, port), timeout=30) as conn:
        conn.settimeout(20)
        conn.sendall(cedar.greeting(sock))
        conn.sendall(cedar.frame(cedar.security_message(request.as_classads())))
        gathered = b""
        while True:
            try:
                answer = conn.recv(65536)
            except TimeoutError:
                break  # the daemon holds the link open, waiting for the command
            if not answer:
                break
            gathered += answer
    ads = collector.parse_reply(gathered)
    if not ads:
        raise SystemExit(f"{host} sock={sock!r}: no classad in the reply")
    return ads


def verdict(ads: list[dict[str, object]]) -> object:
    """What a daemon said about the session it was offered."""
    for ad in ads:
        if ad.get("ReturnCode"):
            return ad["ReturnCode"]
    return None


def schedd_address() -> tuple[str, int, str]:
    """The schedd's host, port and sock name, asked of the pool's collector."""
    return collector.schedd_address(COLLECTOR_HOST, "collector")


def main() -> int:
    failures = 0

    asked = negotiate(COLLECTOR_HOST, "collector", QUERY_SCHEDD_ADS)
    print(f"collector: {verdict(asked)!r}")
    failures += verdict(asked) != "AUTHORIZED"

    host, port, sock = schedd_address()
    print(f"the collector names its schedd {host}:{port} sock={sock}")
    met = negotiate(host, sock, QUERY_SCHEDD_ADS, port)
    print(f"schedd:    {verdict(met)!r}")
    failures += verdict(met) != "AUTHORIZED"

    if failures:
        print(f"FAILED: {failures} daemon(s) refused the session")
        return 1
    print("OK: the collector named the schedd, and both daemons authorised us")
    return 0


if __name__ == "__main__":
    sys.exit(main())
