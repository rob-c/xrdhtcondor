"""CEDAR's session cryptography, taken from HTCondor 23.0.28 (Apache-2.0).

HTCondor's wire protocol encrypts every message once a security session is
established, and nothing about that is guessable: the key comes from an ECDH
exchange through a specific KDF, the IV is a counter over a random base, and the
first packet in each direction carries extra authenticated data. All of it is in
the source, which is Apache-2.0 and may therefore be implemented from directly -
unlike DIRAC's protocol, where the licence made a clean room mandatory.

The three facts this implements, with where each comes from:

* **the key**: ``Condor_Crypt_Base::hkdf`` (``condor_io/condor_crypt.cpp``) is
  HKDF-SHA256 with the salt ``"htcondor"`` and the info ``"keygen"``, over the
  ECDH shared secret; the output is the AES key, 32 bytes for AES-256:
  ``Condor_Crypt_AESGCM::encrypt`` calls ``EVP_aes_256_gcm()``;
* **the IV**: 16 bytes, whose first four are a big-endian packet counter added to
  the base IV's first four, and whose remaining twelve come from the base IV
  (``condor_crypt_aesgcm.cpp``). The base IV travels with the *first* packet in a
  direction and is never sent again;
* **the packet**: ``[base IV, first packet only][ciphertext][16-byte tag]`` with
  the 5-byte frame header as additional authenticated data - and, on the first
  packet in each direction, two SHA-256 digests in front of that header
  (``condor_io/reli_sock.cpp``). Those digests are **not sent**: they are running
  digests of the traffic each side has already exchanged, so they bind the
  session to the conversation that established it.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

__all__ = ["IV_SIZE", "KEY_SIZE", "TAG_SIZE", "PacketCodec", "session_key"]

#: The AES key's length: ``EVP_aes_256_gcm``.
KEY_SIZE = 32

#: The IV's length, and how much of it the packet counter occupies.
IV_SIZE = 16
_IV_COUNTER = 4

#: The GCM tag's length, appended to every ciphertext by ``AESGCM.encrypt``.
TAG_SIZE = 16

#: HKDF parameters, as ``Condor_Crypt_Base::hkdf`` hard-codes them.
SALT = b"htcondor"
INFO = b"keygen"


def session_key(secret: bytes, length: int = KEY_SIZE) -> bytes:
    """The session key from the ECDH shared secret, as HTCondor derives it."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if not secret:
        raise ValueError("an ECDH secret is not empty")
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=SALT, info=INFO).derive(secret)


@dataclass
class PacketCodec:
    """One direction-pair of a session: seal outgoing packets, open incoming ones.

    One codec serves both directions of a connection, because the two share a
    key but keep separate counters and separate base IVs - each side sends its
    own base IV with its first packet, which is why the receiver learns it there
    and not from the handshake.
    """

    key: bytes
    #: This end's base IV, random unless a test sets it, sent with our first packet.
    send_iv: bytes = field(default_factory=lambda: os.urandom(IV_SIZE))
    #: The peer's base IV, learned from its first packet.
    recv_iv: bytes = b""
    _sent: int = 0
    _seen: int = 0
    _sent_first: bool = False
    _seen_first: bool = False

    def __post_init__(self) -> None:
        """A codec needs a key the cipher can use and an IV of the right size."""
        if len(self.key) != KEY_SIZE:
            raise ValueError(f"a session key is {KEY_SIZE} bytes, not {len(self.key)}")
        if len(self.send_iv) != IV_SIZE:
            raise ValueError(f"a base IV is {IV_SIZE} bytes, not {len(self.send_iv)}")

    # -- sealing ---------------------------------------------------------------------------

    def seal(self, header: bytes, plaintext: bytes, handshake: bytes = b"") -> bytes:
        """``plaintext`` as it goes on the wire under ``header``.

        ``handshake`` is the two SHA-256 digests a connection's first encrypted
        packet authenticates; a later packet ignores it, as HTCondor does.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        first = not self._sent_first
        iv = _packet_iv(self.send_iv, self._sent)
        sealed = AESGCM(self.key).encrypt(iv, plaintext, _aad(header, handshake, first))
        self._sent += 1
        self._sent_first = True
        return self.send_iv + sealed if first else sealed

    # -- opening ---------------------------------------------------------------------------

    def open(self, header: bytes, payload: bytes, handshake: bytes = b"") -> bytes:
        """``payload`` decrypted and authenticated under ``header``.

        Raises :class:`cryptography.exceptions.InvalidTag` when it is not what
        the peer sent - a tampered packet, the wrong key, or a header that does
        not match what went on the wire.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        first = not self._seen_first
        if first:
            if len(payload) < IV_SIZE + TAG_SIZE:
                raise ValueError("a first packet carries the base IV and a tag")
            self.recv_iv, payload = payload[:IV_SIZE], payload[IV_SIZE:]
        iv = _packet_iv(self.recv_iv, self._seen)
        opened = AESGCM(self.key).decrypt(iv, payload, _aad(header, handshake, first))
        self._seen += 1
        self._seen_first = True
        return opened


def _packet_iv(base: bytes, counter: int) -> bytes:
    """The packet counter in the first four bytes, then the rest of ``base``.

    ``Condor_Crypt_AESGCM`` copies the counter into the IV's first four bytes and
    keeps the base IV from there on - it does not add to what is already there, so
    the first packet's IV begins with four zero bytes.
    """
    if counter > 0xFFFFFFFF:
        raise ValueError("a connection has run out of packet counters")
    return struct.pack(">I", counter) + base[_IV_COUNTER:]


def _aad(header: bytes, handshake: bytes, first: bool) -> bytes:
    """What a packet authenticates: its header, and the handshake on the first one."""
    return handshake + header if first else header
