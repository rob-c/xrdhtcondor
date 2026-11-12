"""The session crypto, against the layout HTCondor's source defines."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from xrdhtcondor import crypto
from xrdhtcondor.crypto import IV_SIZE, KEY_SIZE, TAG_SIZE, PacketCodec, session_key

HEADER = b"\x01\x00\x00\x00\x10"
HANDSHAKE = b"\x11" * 32 + b"\x22" * 32


def _codec(key: bytes | None = None) -> PacketCodec:
    return PacketCodec(
        key=key or session_key(b"a shared secret", KEY_SIZE), send_iv=bytes(range(16))
    )


def test_the_key_is_hkdf_sha256_of_the_secret_with_htcondors_parameters() -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    expected = HKDF(
        algorithm=hashes.SHA256(), length=KEY_SIZE, salt=b"htcondor", info=b"keygen"
    ).derive(b"secret")
    assert session_key(b"secret") == expected and len(expected) == 32
    with pytest.raises(ValueError, match="not empty"):
        session_key(b"")


def test_a_sealed_packet_is_the_base_iv_a_ciphertext_then_a_tag() -> None:
    sender, receiver = _codec(), _codec()
    first = sender.seal(HEADER, b"hello", HANDSHAKE)
    assert len(first) == IV_SIZE + len(b"hello") + TAG_SIZE
    assert first[:IV_SIZE] == sender.send_iv  # the base IV travels with the first packet
    assert receiver.open(HEADER, first, HANDSHAKE) == b"hello"
    later = sender.seal(HEADER, b"again", HANDSHAKE)
    assert len(later) == len(b"again") + TAG_SIZE  # and never again
    assert receiver.open(HEADER, later, HANDSHAKE) == b"again"


def test_the_counter_replaces_the_iv_head_and_keeps_the_tail() -> None:
    """Each packet's IV is the counter, then the base IV's tail.

    ``Condor_Crypt_AESGCM`` copies the counter into the first four bytes rather
    than adding to them, so the first packet's IV starts with four zero bytes and
    the base IV's own head is never used.
    """
    import struct

    from xrdhtcondor.crypto import _packet_iv

    # A base IV whose first four bytes are zero, so the counter is what shows.
    base = bytes(4) + bytes(range(4, 16))
    assert _packet_iv(base, 0) == base
    assert _packet_iv(base, 2) == struct.pack(">I", 2) + base[4:]
    assert _packet_iv(base, 0xFFFFFFFF)[:4] == struct.pack(">I", 0xFFFFFFFF)
    with pytest.raises(ValueError, match="run out of packet counters"):
        _packet_iv(base, 0x100000000)
    sender, receiver = _codec(), _codec()
    for _ in range(3):
        assert receiver.open(HEADER, sender.seal(HEADER, b"x")) == b"x"


def test_a_tampered_packet_is_refused() -> None:
    sender, receiver = _codec(), _codec()
    packet = bytearray(sender.seal(HEADER, b"hello"))
    packet[-1] ^= 0xFF
    with pytest.raises(InvalidTag):
        receiver.open(HEADER, bytes(packet))


def test_a_packet_under_another_header_is_refused() -> None:
    """The header is authenticated data: the peer's framing cannot be rewritten."""
    sender, receiver = _codec(), _codec()
    packet = sender.seal(HEADER, b"hello")
    with pytest.raises(InvalidTag):
        receiver.open(b"\x01\x00\x00\x00\x11", packet)


@pytest.mark.parametrize("offered", [b"\x00" * 64, b""], ids=["another-negotiation", "none"])
def test_the_handshake_digests_are_bound_to_the_first_packet(offered: bytes) -> None:
    """The first encrypted packet proves which negotiation it belongs to."""
    sender = _codec()
    receiver = PacketCodec(key=sender.key)
    packet = sender.seal(HEADER, b"hello", HANDSHAKE)
    with pytest.raises(InvalidTag):
        receiver.open(HEADER, packet, offered)
    again, receiver = _codec(), PacketCodec(key=sender.key)
    assert receiver.open(HEADER, again.seal(HEADER, b"hello", HANDSHAKE), HANDSHAKE) == b"hello"


def test_a_codec_refuses_what_it_cannot_use() -> None:
    with pytest.raises(ValueError, match="session key is 32 bytes"):
        PacketCodec(key=b"short")
    with pytest.raises(ValueError, match="base IV is 16 bytes"):
        PacketCodec(key=session_key(b"x"), send_iv=b"short")
    with pytest.raises(ValueError, match="carries the base IV"):
        _codec().open(HEADER, b"tiny")
    with pytest.raises(InvalidTag):
        _codec().open(HEADER, bytes(IV_SIZE + TAG_SIZE + 1))


def test_the_base_iv_head_is_not_part_of_a_packet_iv() -> None:
    """A base IV with a non-zero head still gives a packet IV that starts at zero."""
    base = bytes.fromhex("deadbeef") + bytes(range(12))
    first = crypto._packet_iv(base, 0)
    second = crypto._packet_iv(base, 1)
    assert first == bytes(4) + bytes(range(12))
    assert second == bytes.fromhex("00000001") + bytes(range(12))
