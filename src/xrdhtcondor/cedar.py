"""CEDAR: HTCondor's framing and classad wire form, as the capture shows them.

Everything here is taken from bytes this project recorded — a `condor_submit` to a
personal HTCondor 23.0.28, in `docs/evidence/` — not from a reading of HTCondor's
source, and the tests parse those very bytes.

Three things the capture pinned:

* **framing**: one byte of message type (``0x01``), then a ``uint32`` big-endian
  payload length, then the payload. Two messages confirmed it: ``01 00 00 00 2f``
  and 47 bytes on the wire, ``01 00 00 02 9f`` and 671;
* **classads**: *old classads* on the wire, ``name = value`` pairs each terminated
  by a ``.``, strings double-quoted with ``\\"`` escapes, integers bare, and
  ``true``/``false`` bare - which is why a decoder must not treat ``.`` as part of
  a value;
* **the greeting**: a 4-byte zero, the daemon's sock name, the subsystem, and eight
  bytes of ``0xff`` - the shared-port target that tells the peer which daemon the
  connection is for.

What is *not* here, and is not pretended: the SECMAN session's encryption. The
capture's traffic after the handshake is ciphertext, and the key it uses is derived
from the ECDH public keys in that handshake by a function only HTCondor knows.
HTCondor is Apache-2.0, so that function may be implemented from its source; until
it is, this module speaks the plaintext part of the protocol and nothing else.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from .classads import ClassadError, format_value, parse_value

__all__ = [
    "COMMAND",
    "GREETING_TAIL",
    "SUBSYSTEM",
    "CedarError",
    "Deframer",
    "SecurityReply",
    "SecurityRequest",
    "frame",
    "greeting",
    "parse_wire_classads",
    "wire_classads",
]

#: The message type every CEDAR message in the capture begins with.
COMMAND = 0x01

#: The subsystem a submission names in its greeting and its SECMAN request.
SUBSYSTEM = "SUBMIT"

#: What follows the subsystem in a greeting: eight ``0xff`` bytes, then eight zeros.
#: Their meaning is not yet known; the capture says they are always there.
GREETING_TAIL = b"\xff" * 8 + b"\x00" * 8


class CedarError(ValueError):
    """A frame, a greeting or a classad on the wire that this will not accept."""


def frame(payload: bytes, kind: int = COMMAND) -> bytes:
    """One CEDAR message: the type byte, the big-endian length, the payload."""
    if not 0 <= kind <= 0xFF:
        raise CedarError(f"a message type is one byte, not {kind}")
    return bytes([kind]) + struct.pack(">I", len(payload)) + payload


class Deframer:
    """Bytes in, whole messages out, however the network cut them."""

    def __init__(self) -> None:
        """A deframer with nothing buffered."""
        self._buffer = bytearray()

    def feed(self, data: bytes) -> Iterator[tuple[int, bytes]]:
        """Every complete message in ``data`` and what was already held, in order."""
        self._buffer.extend(data)
        while len(self._buffer) >= 5:
            kind = self._buffer[0]
            length = struct.unpack(">I", self._buffer[1:5])[0]
            if len(self._buffer) < 5 + length:
                return
            payload = bytes(self._buffer[5 : 5 + length])
            del self._buffer[: 5 + length]
            yield kind, payload

    @property
    def pending(self) -> int:
        """How many bytes are held for a message that has not arrived whole."""
        return len(self._buffer)


def greeting(sock: str, subsystem: str = SUBSYSTEM) -> bytes:
    """The first message a client sends: which daemon, and which subsystem.

    ``sock`` is the socket name a shared port published (``schedd_363_822f``); a
    client talking to a daemon's own port still names it, which is why a frame with
    anything else there is reset.
    """
    if not sock or "\x00" in sock or "\x00" in subsystem:
        raise CedarError(f"a greeting names a sock and a subsystem, not {sock!r}/{subsystem!r}")
    return frame(
        struct.pack(">I", 0)
        + struct.pack(">I", ord("K"))
        + sock.encode()
        + b"\x00"
        + subsystem.encode()
        + b"\x00"
        + GREETING_TAIL
    )


def wire_classads(attributes: Mapping[str, Any]) -> bytes:
    """``attributes`` in the wire form: ``name = value`` pairs, NUL-separated."""
    if any("\x00" in name for name in attributes):
        raise CedarError("an attribute name cannot contain NUL: it separates the pairs")
    return b"".join(
        f"{name} = {format_value(value)}".encode() + b"\x00" for name, value in attributes.items()
    )


def parse_wire_classads(payload: bytes) -> dict[str, Any]:
    """The attributes of a wire classad payload.

    A dot ends a pair, so a value is never read across one; the text before the
    first ``name =`` is skipped, because the capture shows a short binary preamble
    in front of the classad in a SECMAN message.
    """
    text = payload.decode("utf-8", "replace").lstrip("\x00")
    start = _first_assignment(text)
    if start is None:
        raise CedarError("no 'name = value.' pair in this payload")
    found: dict[str, Any] = {}
    for piece in _split_pairs(text[start:]):
        name, _separator, raw = piece.partition("=")
        name = name.strip()
        if not name:
            raise CedarError(f"a wire classad has a pair with no name: {piece!r}")
        try:
            found[name] = parse_value(raw.strip())
        except ClassadError as refused:
            raise CedarError(f"{name}: {refused}") from refused
    return found


#: An assignment in a wire classad: an attribute name, whitespace, then ``=``.
_ASSIGNMENT = re.compile(r"[A-Za-z+][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*\s*=")


def _first_assignment(text: str) -> int | None:
    """Where the first ``name = `` starts, past any binary preamble.

    A SECMAN message carries a short binary preamble (a length and a command in
    the capture), so the classad's start is found by its first real assignment
    rather than by the first letter - the preamble contains letters too.
    """
    match = _ASSIGNMENT.search(text)
    return None if match is None else match.start()


def _split_pairs(text: str) -> Iterator[str]:
    """The ``name = value`` pieces of a wire classad, separated by NUL.

    NUL is the separator on the wire: ``tcpdump -A`` shows it as a dot, which is
    how a first reading of this capture mistook it for punctuation. A NUL inside
    a quoted value would end a pair too, so values this writes never contain one.
    """
    for piece in text.split("\x00"):
        if piece.strip():
            yield piece.strip()


#: The SECMAN attributes this understands, in the order the capture shows them.
SECMAN_KEYS = (
    "NegotiatedSession",
    "NewSession",
    "AuthMethods",
    "Integrity",
    "RemoteVersion",
    "TrustDomain",
    "CryptoMethods",
    "OutgoingNegotiation",
    "SessionLease",
    "Authentication",
    "ConnectSinful",
    "Encryption",
    "Enact",
    "ServerPid",
    "Command",
    "Subsystem",
    "SessionDuration",
    "ECDHPublicKey",
)


@dataclass(frozen=True, slots=True)
class SecurityRequest:
    """What a client asks for in the SECMAN exchange (`Command` 1112 for a submit)."""

    #: The methods offered, in preference order: ``GSI`` on a grid CE.
    auth_methods: str = "GSI"
    #: The ciphers offered.
    crypto_methods: str = "AES,BLOWFISH,3DES"
    #: ``REQUIRED``/``OPTIONAL``/``NEVER`` per attribute, as the capture spells them.
    encryption: str = "REQUIRED"
    integrity: str = "REQUIRED"
    #: The client's own version string, exactly as HTCondor writes it.
    remote_version: str = ""
    #: This end's ECDH public key, base64 of the uncompressed point.
    ecdh_public: str = ""
    #: The socket the client reached, which the server echoes for its session.
    connect_sinful: str = ""
    command: int = 1112
    subsystem: str = SUBSYSTEM
    session_duration: str = "60"

    def as_classads(self) -> dict[str, Any]:
        """The request as the attributes the capture shows."""
        return {
            "NegotiatedSession": True,
            "NewSession": "YES",
            "AuthMethods": self.auth_methods,
            "Integrity": self.integrity,
            "RemoteVersion": self.remote_version,
            "CryptoMethods": self.crypto_methods,
            "OutgoingNegotiation": self.integrity,
            "SessionLease": 3600,
            "Authentication": "REQUIRED",
            "ConnectSinful": self.connect_sinful,
            "Encryption": self.encryption,
            "Enact": "NO",
            "Command": self.command,
            "Subsystem": self.subsystem,
            "SessionDuration": self.session_duration,
            "ECDHPublicKey": self.ecdh_public,
        }


@dataclass(frozen=True, slots=True)
class SecurityReply:
    """What the server answers: which method and cipher it chose, and its ECDH key."""

    #: The attributes as the server sent them.
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def authenticated(self) -> bool:
        """Whether the server agreed to a session."""
        return str(self.attributes.get("Authentication", "")).upper() in {"YES", "TRUE"}

    @property
    def method(self) -> str:
        """The authentication method the server chose (`GSI`, `CLAIMTOBE`…)."""
        return str(self.attributes.get("AuthMethods", ""))

    @property
    def cipher(self) -> str:
        """The cipher the server chose."""
        return str(self.attributes.get("CryptoMethods", ""))

    @property
    def enacts(self) -> bool:
        """Whether the server will use a session at all."""
        return str(self.attributes.get("Enact", "")).upper() in {"YES", "TRUE"}

    @property
    def ecdh_public(self) -> str:
        """The server's ECDH public key, base64, for the session key agreement."""
        return str(self.attributes.get("ECDHPublicKey", ""))

    @classmethod
    def parse(cls, payload: bytes) -> SecurityReply:
        """The reply in a SECMAN message's payload."""
        return cls(attributes=parse_wire_classads(payload))
