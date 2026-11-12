"""The enacted session: sealing, opening, and the digest that binds them."""

from __future__ import annotations

import hashlib

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

from xrdhtcondor import cedar, session


def _pair() -> tuple[session.Session, session.Session]:
    """Two ends of one session, each with its own base IV as a real pair has."""
    one = ec.generate_private_key(ec.SECP256R1())
    two = ec.generate_private_key(ec.SECP256R1())
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    def public(key: ec.EllipticCurvePrivateKey) -> bytes:
        return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    return (
        session.Session.between(one, public(two)),
        session.Session.between(two, public(one)),
    )


def test_what_one_end_seals_the_other_opens() -> None:
    """The whole point: a sealed message survives the round trip."""
    here, there = _pair()
    sealed = here.seal(b"initialize")
    assert sealed[0] == session.TYPE
    assert int.from_bytes(sealed[1:5], "big") == len(sealed) - 5
    assert there.open(sealed) == b"initialize"


def test_several_messages_keep_their_order_and_their_keys() -> None:
    """Every packet is sealed with the next counter, so they must be read in order."""
    here, there = _pair()
    sent = [here.seal(f"message {number}".encode()) for number in range(4)]
    assert [there.open(frame) for frame in sent] == [
        f"message {number}".encode() for number in range(4)
    ]


def test_a_packet_out_of_order_is_refused() -> None:
    """The counter is the IV: a swapped packet does not authenticate."""
    here, there = _pair()
    first, second = here.seal(b"one"), here.seal(b"two")
    # Out of order, the second packet is read as the first, and its IV is not there.
    with pytest.raises((InvalidTag, ValueError)):
        there.open(second)


def test_a_tampered_packet_is_refused() -> None:
    """The tag is the proof that nothing was touched."""
    here, there = _pair()
    sealed = bytearray(here.seal(b"initialize"))
    sealed[-1] ^= 0xFF
    with pytest.raises(InvalidTag):
        there.open(bytes(sealed))


def test_a_stranger_cannot_open_the_session() -> None:
    """Two sessions that never negotiated share no key."""
    here, _there = _pair()
    _other, stranger = _pair()
    with pytest.raises(InvalidTag):
        stranger.open(here.seal(b"initialize"))


def test_the_digest_is_the_conversation_before_this_packet() -> None:
    """The first packet authenticates everything said so far; later ones do not."""
    here, there = _pair()
    here._sent.update(b"the SECMAN request")
    there._heard.update(b"the SECMAN request")
    sealed = here.seal(b"identity")
    expected = hashlib.sha256(b"the SECMAN request").digest() * 2
    assert (
        here._digests(
            hashlib.sha256(b"the SECMAN request"), hashlib.sha256(b"the SECMAN request"), first=True
        )
        == expected
    )
    assert there.open(sealed) == b"identity"


def test_a_later_packet_authenticates_only_its_header() -> None:
    """After the first, the AAD is the header alone, as ``reli_sock.cpp`` writes it."""
    assert session.Session._digests(hashlib.sha256(b"x"), hashlib.sha256(b"y"), first=False) == b""


def test_frames_are_cut_where_the_headers_say() -> None:
    """A stream is frames, and a partial one at the end is not a frame."""
    stream = cedar.frame(b"one") + cedar.frame(b"two") + b"\x01\x00"
    assert [frame[5:] for frame in session.frames(stream)] == [b"one", b"two"]


def test_a_session_needs_two_keys_that_belong_together() -> None:
    """An ECDH exchange between unrelated keys derives a key that opens nothing."""
    one = ec.generate_private_key(ec.SECP256R1())
    stranger = ec.generate_private_key(ec.SECP256R1())
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    ours, theirs = _pair()
    wrong = session.Session.between(
        one,
        stranger.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
    )
    with pytest.raises(InvalidTag):
        wrong.open(ours.seal(b"initialize"))
    assert theirs is not None


def test_a_sealed_packet_of_the_wrong_size_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The header's length is what the daemon trusts; a packet that disagrees is a bug."""
    here, _there = _pair()
    monkeypatch.setattr(here.codec, "seal", lambda header, payload, handshake: b"short")
    with pytest.raises(cedar.CedarError, match="is .* bytes, not"):
        here.seal(b"initialize")
