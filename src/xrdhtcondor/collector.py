"""Asking a collector which schedd it knows, so its socket can be addressed.

A shared port routes by the sock name in a greeting, and that name is published by
the collector. Querying it is how a client learns where to send a job - and the
query is the part that is easy to get subtly wrong: ``Requirements`` must be the
boolean ``true``, not the string, or the collector evaluates a type error, skips
every ad and answers with silence.
"""

from __future__ import annotations

import base64
import re
import socket
from collections.abc import Iterable
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import cedar

#: ``QUERY_SCHEDD_ADS`` in ``condor_commands.h``.
QUERY_SCHEDD_ADS = 6

#: The attributes then answered with the schedd's address.
ADVERTISE = ("Machine", "MyAddress", "Name")

#: ``<172.20.0.3:9618?addrs=...&sock=schedd_1_43af>``, as a collector publishes it.
_SINFUL = re.compile(r"<(?P<host>[^:>]+):(?P<port>\d+)(?P<params>[^>]*)>")
_SOCK = re.compile(r"sock=(?P<sock>[^&>]+)")


def query_classad() -> dict[str, Any]:
    """The query a real client sends, as the capture shows it byte for byte."""
    return {
        "TargetType": "Scheduler",
        "MyType": "Query",
        "Requirements": True,
        "Projection": " ".join(ADVERTISE),
    }


def address_parts(sinful: str) -> tuple[str, int, str] | None:
    """``(host, port, sock)`` of a sinful string, or ``None`` if it names no sock."""
    match = _SINFUL.search(sinful)
    if match is None:
        return None
    named = _SOCK.search(match.group("params"))
    if named is None:
        return None
    return match.group("host"), int(match.group("port")), named.group("sock")


def schedd_ad(attributes: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    """The first reply that carries a schedd's address."""
    for ad in attributes:
        if isinstance(ad.get("MyAddress"), str):
            return ad
    return None


def _request(sock: str, command: int) -> dict[str, Any]:
    """A SECMAN request for ``command``, with a fresh ECDH key."""
    key = ec.generate_private_key(ec.SECP256R1())
    public = base64.b64encode(
        key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    ).decode()
    return cedar.SecurityRequest(
        auth_methods="CLAIMTOBE",
        ecdh_public=public,
        encryption="OPTIONAL",
        integrity="OPTIONAL",
        authentication="OPTIONAL",
        command=command,
        subsystem="TOOL",
        connect_sinful=f"<collector.unknown?sock={sock}>",
    ).as_classads()


def _gather(host: str, port: int, sock: str, timeout: float) -> bytes:
    """Greet, negotiate, ask, and return every byte the collector answers with."""
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        conn.sendall(cedar.greeting(sock))
        conn.sendall(cedar.frame(cedar.security_message(_request(sock, QUERY_SCHEDD_ADS))))
        conn.sendall(cedar.frame(cedar.put_classad(query_classad())))
        gathered = b""
        while True:
            answer = conn.recv(65536)
            if not answer:
                return gathered
            gathered += answer


def parse_reply(stream: bytes) -> list[dict[str, Any]]:
    """The classads in a reply stream, skipping the ones that do not decode."""
    found: list[dict[str, Any]] = []
    for _kind, payload in cedar.Deframer().feed(stream):
        try:
            found.append(cedar.parse_wire_classads(payload))
        except cedar.CedarError:
            continue
    return found


def schedd_address(
    host: str, sock: str = "collector", port: int = 9618, timeout: float = 30.0
) -> tuple[str, int, str]:
    """Ask the collector at ``host`` which schedd it knows, and how to reach it."""
    ads = parse_reply(_gather(host, port, sock, timeout))
    ad = schedd_ad(ads)
    if ad is None:
        raise LookupError(f"{host}: no schedd ad in {len(ads)} classads of the reply")
    parts = address_parts(str(ad["MyAddress"]))
    if parts is None:
        raise LookupError(f"{host}: the schedd's address names no sock: {ad['MyAddress']}")
    return parts
