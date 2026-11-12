"""SCITOKENS: a bearer token presented over TLS, carried inside CEDAR messages.

HTCondor's SciTokens method is ``Condor_Auth_SSL`` in ``m_scitokens_mode``
(``condor_io/condor_auth_ssl.cpp``), and the shape is unusual enough to be worth
stating plainly:

* every handshake step is a CEDAR message carrying ``code(int status)``,
  ``code(int length)`` and that many bytes of a TLS record - so a TLS session is
  multiplexed through the CEDAR framing rather than opened on its own socket;
* once the TLS session is up, the client writes ``[uint32 length][JWT]`` *through*
  it - the token travels encrypted, which is the whole point;
* the result is told by the status codes in the messages, and by whether the daemon
  goes on to map the identity.

The token itself comes from ``SCITOKENS_FILE``, ``BEARER_TOKEN_FILE``, or one file
per token under ``~/.condor/tokens.d/``, and the file holds the JWT on its first
non-empty line.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import cedar

#: ``AUTH_SSL_A_OK`` and friends from ``condor_auth_ssl.h``.
A_OK = 0
SENDING = 1
#: ``QMGMT_WRITE_CMD``: the session a submission negotiates.
QMGMT_WRITE_CMD = 1112

#: ``QUERY_SCHEDD_ADS``: what a collector is asked, and so what a collector
#: session is negotiated for. A collector closes on a command it cannot serve.
QUERY_SCHEDD_ADS = 6

#: The version string a SECMAN request announces, as HTCondor writes it.
VERSION = "$CondorVersion: 23.0.28 2025-08-21 BuildID: 827396 PackageID: 23.0.28-1 $"
RECEIVING = 2
QUITTING = 3
HOLDING = 4

#: The tokens directory HTCondor reads, one file per token.
TOKENS_DIR = ".condor/tokens.d"

#: Where a token may be named, in the order HTCondor consults them.
VARIABLES = ("SCITOKENS_FILE", "BEARER_TOKEN_FILE")


class SciTokenError(cedar.CedarError):
    """No token could be found, chosen, or presented."""


@dataclass(frozen=True, slots=True)
class Token:
    """A token as it was found: where it came from, its text, and what it claims."""

    path: str
    text: str
    claims: Mapping[str, Any]

    @property
    def audiences(self) -> tuple[str, ...]:
        """The ``aud`` claim as one or more audiences."""
        said = self.claims.get("aud")
        if isinstance(said, str):
            return (said,)
        if isinstance(said, list):
            return tuple(str(one) for one in said)
        return ()

    @property
    def issuer(self) -> str:
        """The ``iss`` claim, which is what a daemon's trust decisions are made on."""
        return str(self.claims.get("iss") or "")


def message(status: int, payload: bytes) -> bytes:
    """One handshake step: the status, the length, and the TLS record bytes."""
    return cedar.code_int(status) + cedar.code_int(len(payload)) + payload


def parse_message(payload: bytes) -> tuple[int, bytes]:
    """``(status, bytes)`` from a handshake message, as :func:`message` wrote it."""
    if len(payload) < 16:
        raise SciTokenError(f"a handshake message is at least 16 bytes, not {len(payload)}")
    status = int.from_bytes(payload[4:8], "big", signed=True)
    length = int.from_bytes(payload[12:16], "big", signed=True)
    body = payload[16:]
    if length < 0 or length > len(body):
        raise SciTokenError(f"a handshake message claims {length} bytes but carries {len(body)}")
    return status, body[:length]


def claims_of(token: str) -> dict[str, Any]:
    """The payload claims of a JWT, read without checking its signature.

    Selecting a token only needs to know who it is for and until when; believing it
    is the daemon's job, and it is the daemon that has the keys.
    """
    parts = token.split(".")
    if len(parts) < 2:
        raise SciTokenError("a token is three dot-separated parts")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        said = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, TypeError) as exc:
        raise SciTokenError(f"a token's claims are not base64url JSON: {exc}") from exc
    if not isinstance(said, dict):
        raise SciTokenError("a token's claims are a JSON object")
    return said


def _token_at(path: str) -> Token | None:
    """The token in ``path``: its first non-empty line, or ``None`` if unreadable."""
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                text = line.strip()
                if text:
                    return Token(path, text, claims_of(text))
    except (OSError, SciTokenError):
        return None
    return None


def candidates(environ: Mapping[str, str] | None = None) -> list[Token]:
    """Every token this session can offer, named sources first, then ``tokens.d``."""
    env = os.environ if environ is None else environ
    paths: list[str] = []
    for variable in VARIABLES:
        named = (env.get(variable) or "").strip()
        if named:
            paths.append(named)
    home = (env.get("HOME") or "").strip()
    if home:
        directory = os.path.join(home, TOKENS_DIR)
        try:
            paths += [os.path.join(directory, name) for name in sorted(os.listdir(directory))]
        except OSError:
            pass
    found: list[Token] = []
    for path in paths:
        token = _token_at(path)
        if token is not None:
            found.append(token)
    return found


def choose(found: Sequence[Token], audience: str = "") -> Token:
    """The token to present: one for ``audience`` when it is named, else the first.

    A daemon checks the audience itself; this only avoids offering a token that
    says it is for somewhere else when a better one is sitting beside it.
    """
    if not found:
        raise SciTokenError("no token found: set SCITOKENS_FILE or BEARER_TOKEN_FILE")
    if audience:
        for token in found:
            if audience in token.audiences or "https://wlcg.cern.ch/jwt/v1/any" in token.audiences:
                return token
    return found[0]


def _ecdh_public() -> str:
    """A fresh P-256 public key, as a SECMAN request advertises one."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = ec.generate_private_key(ec.SECP256R1())
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    ).decode()


def _client_context() -> ssl.SSLContext:
    """The TLS context of the token exchange.

    A SciTokens exchange authenticates with the *token*, not with the server's
    certificate, and HTCondor's own verify callback tolerates a certificate it
    cannot chain (``condor_auth_ssl.cpp``). Checking nothing here is therefore the
    same posture, and the token is what a daemon believes.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _pump(
    incoming: ssl.MemoryBIO,
    outgoing: ssl.MemoryBIO,
    exchange: Callable[[bytes], bytes],
    step: Callable[[], Any],
) -> int:
    """Run ``step`` until it stops wanting more, and return the last status seen.

    A step that wants more input hands its records to ``exchange`` and takes the
    daemon's reply back; a step that wants to write flushes what it produced.
    """
    status = A_OK
    while True:
        try:
            step()
            return status
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pending = outgoing.read()
            if not pending:
                raise SciTokenError("the handshake has nothing to send and cannot proceed")
            answer = exchange(pending)
            if not answer:
                raise SciTokenError("the daemon closed the connection mid-handshake")
            status, body = parse_message(answer)
            if status == QUITTING:
                raise SciTokenError("the daemon refused the SCITOKENS exchange")
            if body:
                incoming.write(body)


def authenticate(
    exchange: Callable[[bytes], bytes],
    token: Token,
    *,
    context: ssl.SSLContext | None = None,
) -> int:
    """Present ``token`` and return the last status the daemon gave.

    ``exchange`` sends one handshake message and returns the daemon's reply; it is
    what makes this testable without a daemon, and what a socket becomes in use.
    """
    used = _client_context() if context is None else context
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    sslobject = used.wrap_bio(incoming, outgoing, server_side=False)
    _pump(incoming, outgoing, exchange, sslobject.do_handshake)
    payload = struct.pack(">I", len(token.text.encode())) + token.text.encode()
    status = _pump(incoming, outgoing, exchange, lambda: sslobject.write(payload))
    # The daemon answers with status codes, not with an application reply: what it
    # does next - map the identity and go on, or quit - is the verdict.
    trailing = outgoing.read()
    if trailing:
        answer = exchange(trailing)
        if answer:
            status, _body = parse_message(answer)
    return status


def _classads_of(reply: bytes) -> dict[str, Any]:
    """The attributes of a reply, whether or not its frame is still attached."""
    for candidate in (reply, *(body for _kind, body in cedar.Deframer().feed(reply))):
        try:
            return cedar.parse_wire_classads(candidate)
        except cedar.CedarError:
            continue
    return {}


@dataclass(frozen=True, slots=True)
class Verdict:
    """What a daemon said about the identity we offered."""

    #: The SECMAN classads, so a caller can see the trust domain and the method.
    negotiated: Mapping[str, Any] = field(default_factory=dict)
    #: The last status the SciTokens exchange returned.
    status: int = A_OK

    @property
    def accepted(self) -> bool:
        """Whether the daemon took the token and stayed with us."""
        return self.status != QUITTING and self.negotiated.get("Authentication") == "YES"


@dataclass(slots=True)
class Framed:
    """A CEDAR-framed socket: one message in, one message out."""

    connection: Any

    def send(self, payload: bytes) -> None:
        """Send ``payload`` as one CEDAR message."""
        self.connection.sendall(cedar.frame(payload))

    def receive(self) -> bytes:
        """The payload of the next CEDAR message, or empty at the end."""
        header = b""
        while len(header) < 5:
            chunk = self.connection.recv(5 - len(header))
            if not chunk:
                return b""
            header += chunk
        size = int.from_bytes(header[1:5], "big")
        payload = b""
        while len(payload) < size:
            chunk = self.connection.recv(size - len(payload))
            if not chunk:
                return b""
            payload += chunk
        return payload

    def exchange(self, records: bytes) -> bytes:
        """One handshake step: send the TLS records, return the daemon's message."""
        self.send(message(SENDING, records))
        return self.receive()


def negotiate(
    framed: Any,
    token: Token,
    *,
    command: int = QMGMT_WRITE_CMD,
    subsystem: str = "TOOL",
    connect_sinful: str = "",
) -> Verdict:
    """Offer SCITOKENS for ``command``, then present ``token`` when it is taken."""
    request = cedar.SecurityRequest(
        auth_methods="SCITOKENS",
        ecdh_public=_ecdh_public(),
        remote_version=VERSION,
        encryption="OPTIONAL",
        integrity="OPTIONAL",
        authentication="REQUIRED",
        command=command,
        subsystem=subsystem,
        connect_sinful=connect_sinful,
    )
    framed.send(cedar.security_message(request.as_classads()))
    reply = framed.receive()
    if not reply:
        raise SciTokenError("the daemon closed the connection before negotiating")
    merged = _classads_of(reply)
    if str(merged.get("Enact") or "").upper() in {"YES", "TRUE"} and str(
        merged.get("Encryption") or ""
    ).upper() in {"YES", "TRUE"}:
        raise SciTokenError(
            "the daemon enacted an encrypted session (Enact/Encryption = YES), so the"
            " token exchange has to be sealed with the session key; this client does not"
            " implement that session yet, and the daemon will ignore anything sent in clear"
        )
    if merged.get("AuthMethods") != "SCITOKENS":
        raise SciTokenError(
            "the daemon did not offer SCITOKENS: it said "
            f"{merged.get('AuthMethods')!r} (it may not support tokens, or not this issuer)"
        )
    status = authenticate(framed.exchange, token)
    return Verdict(negotiated=merged, status=status)


def authenticate_daemon(
    host: str,
    sock: str,
    token: Token | None = None,
    *,
    port: int = 9619,
    command: int = QUERY_SCHEDD_ADS,
    timeout: float = 60.0,
    greeting: bool = True,
) -> Verdict:
    """Greet ``host``'s daemon ``sock`` and become a user there, with a token."""
    chosen = token or choose(candidates())
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        if greeting:
            connection.sendall(cedar.greeting(sock))
        return negotiate(
            Framed(connection),
            chosen,
            command=command,
            connect_sinful=f"<{host}:{port}?sock={sock}>",
        )
