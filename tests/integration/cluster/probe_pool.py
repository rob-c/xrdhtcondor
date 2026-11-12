"""Our client against a real pool: greet and negotiate with both daemons.

Run inside the pool (`./run.sh` does it):

- the **collector** is greeted by the sock name `collector`, as a CE's shared port
  maps it, and negotiates a SECMAN session with the command it will be sent;
- the **schedd** is greeted by the sock name the pool publishes, and negotiates
  too. Its address is asked of Condor itself: reading it from the collector needs
  the encrypted session the daemon enacts (`Enact = "YES"`), and that layer is not
  wired yet - `crypto.py` implements the cipher, the session does not.
"""

from __future__ import annotations

import base64
import re
import socket
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from xrdhtcondor import cedar

VERSION = "$CondorVersion: 23.0.28 2025-08-21 BuildID: 827396 PackageID: 23.0.28-1 $"
COLLECTOR_HOST = "cm"
QUERY_SCHEDD_ADS = 6


def our_key() -> str:
    """A P-256 public key, base64 of the uncompressed point."""
    key = ec.generate_private_key(ec.SECP256R1())
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    ).decode()


def negotiate(host: str, sock: str, command: int) -> dict[str, object]:
    """Greet a daemon, offer CLAIMTOBE for ``command``, and return its reply."""
    request = cedar.SecurityRequest(
        auth_methods="CLAIMTOBE",
        remote_version=VERSION,
        ecdh_public=our_key(),
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
    if not answer:
        raise SystemExit(f"{host} sock={sock!r}: closed without a reply")
    for _kind, payload in cedar.Deframer().feed(answer):
        try:
            return cedar.parse_wire_classads(payload)
        except cedar.CedarError:
            continue
    raise SystemExit(f"{host} sock={sock!r}: no classad in the reply")


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


def main() -> int:
    failures = 0

    collector = negotiate(COLLECTOR_HOST, "collector", QUERY_SCHEDD_ADS)
    print(
        f"collector: {collector.get('Authentication')!r} auth, "
        f"enact={collector.get('Enact')!r}, domain={collector.get('TrustDomain')!r}"
    )
    failures += collector.get("Authentication") != "YES"

    host, sock = schedd_address()
    print(f"the pool names its schedd {host} sock={sock}")
    schedd = negotiate(host, sock, QUERY_SCHEDD_ADS)
    print(f"schedd:    {schedd.get('Authentication')!r} auth, enact={schedd.get('Enact')!r}")
    failures += schedd.get("Authentication") != "YES"

    if failures:
        print(f"FAILED: {failures} daemon(s) did not agree to a session")
        return 1
    print("OK: both daemons negotiated a session with our own messages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
