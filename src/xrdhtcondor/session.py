"""The enacted session: what a daemon expects once SECMAN says ``Enact = YES``.

After a successful negotiation a real daemon encrypts both directions, and anything
sent in clear is ignored - which is what stopped token authentication and every
queue-manager command. This module is the wiring around :mod:`xrdhtcondor.crypto`:

* every message is ``[type 0x01][uint32 length][payload]`` where the length is the
  *sealed* size, and the payload is ``[base IV, first packet only][ciphertext][tag]``;
* the additional authenticated data is a **running digest of the conversation**:
  the SHA-256 of every frame sent before this one, then every frame received before
  it (the greeting is not part of either), and after the first packet in each
  direction the five-byte header alone.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from . import cedar, crypto

#: The frame type byte CEDAR uses for a message.
TYPE = 0x01


@dataclass
class Session:
    """One connection's session: seal what goes out, open what comes back."""

    codec: crypto.PacketCodec
    #: Everything sent so far, as the daemon hashes it: whole frames, header included.
    _sent: Any = field(default_factory=hashlib.sha256)
    #: Everything received so far.
    _heard: Any = field(default_factory=hashlib.sha256)
    _sealed_first: bool = False
    _opened_first: bool = False

    @classmethod
    def between(
        cls, private_key: Any, peer_public: bytes, *, send_iv: bytes | None = None
    ) -> Session:
        """The session two ends share: ECDH secret through HKDF, as HTCondor derives it."""
        from cryptography.hazmat.primitives.asymmetric import ec

        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public)
        secret = private_key.exchange(ec.ECDH(), peer)
        codec = (
            crypto.PacketCodec(key=crypto.session_key(secret))
            if send_iv is None
            else crypto.PacketCodec(key=crypto.session_key(secret), send_iv=send_iv)
        )
        return cls(codec)

    def seal(self, payload: bytes) -> bytes:
        """``payload`` as a sealed frame: header, then the ciphertext and its tag.

        The header's length is the sealed size, and it is the *same* header that is
        authenticated - so it is built before sealing rather than after.
        """
        first = not self._sealed_first
        sealed_size = len(payload) + crypto.TAG_SIZE + (crypto.IV_SIZE if first else 0)
        header = bytes([TYPE]) + sealed_size.to_bytes(4, "big")
        sealed = self.codec.seal(
            header, payload, self._digests(self._sent, self._heard, first=first)
        )
        if len(sealed) != sealed_size:
            raise cedar.CedarError(f"a sealed packet is {sealed_size} bytes, not {len(sealed)}")
        frame = header + sealed
        self._sent.update(frame)
        self._sealed_first = True
        return frame

    def open(self, frame: bytes) -> bytes:
        """The plaintext of ``frame``, which the daemon sealed for us."""
        header, sealed = frame[:5], frame[5:]
        plaintext: bytes = self.codec.open(
            header, sealed, self._digests(self._heard, self._sent, first=not self._opened_first)
        )
        self._heard.update(frame)
        self._opened_first = True
        return plaintext

    @staticmethod
    def _digests(mine: Any, theirs: Any, *, first: bool) -> bytes:
        """What this packet authenticates: the conversation, or nothing but its header."""
        if not first:
            return b""
        joined: bytes = mine.copy().digest() + theirs.copy().digest()
        return joined


def frames(stream: bytes) -> list[bytes]:
    """The frames in ``stream``, whole, header included."""
    found: list[bytes] = []
    position = 0
    while position + 5 <= len(stream):
        size = int.from_bytes(stream[position + 1 : position + 5], "big")
        found.append(stream[position : position + 5 + size])
        position += 5 + size
    return found
