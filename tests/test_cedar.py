"""CEDAR framing and the SECMAN exchange, against the capture's own bytes."""

from __future__ import annotations

import pathlib
import struct

import pytest

from xrdhtcondor import cedar

FIXTURES = pathlib.Path(__file__).with_name("data") / "cedar-20261111.txt"


def _captured() -> list[bytes]:
    """The plaintext segments of the capture, in the order the file lists them."""
    lines = [line for line in FIXTURES.read_text().splitlines() if not line.startswith("#")]
    return [bytes.fromhex(line) for line in lines]


GREETING, REQUEST, REPLY, IDENTITY, COMMAND, NONCE = _captured()


# -- framing -----------------------------------------------------------------------------------


def test_a_frame_is_a_type_byte_a_length_and_the_payload() -> None:
    assert cedar.frame(b"hello") == b"\x01\x00\x00\x00\x05hello"
    assert cedar.frame(b"", kind=2) == b"\x02\x00\x00\x00\x00"
    with pytest.raises(cedar.CedarError, match="one byte"):
        cedar.frame(b"x", kind=256)


def test_the_deframer_handles_split_and_merged_messages() -> None:
    """The network cuts wherever it likes; the frames must not care."""
    two = cedar.frame(b"one") + cedar.frame(b"two")
    whole = list(cedar.Deframer().feed(two))
    assert whole == [(1, b"one"), (1, b"two")]
    deframer = cedar.Deframer()
    assert list(deframer.feed(two[:4])) == [] and deframer.pending == 4
    # A header with only part of its payload is held, not guessed at.
    assert list(deframer.feed(two[4:6])) == [] and deframer.pending == 6
    assert list(deframer.feed(two[6:])) == [(1, b"one"), (1, b"two")]
    assert deframer.pending == 0


def test_the_deframer_reads_what_the_capture_carried() -> None:
    deframer = cedar.Deframer()
    messages = list(deframer.feed(GREETING))
    assert len(messages) == 1 and messages[0][0] == cedar.COMMAND
    assert messages[0][1].startswith(b"\x00\x00\x00\x00\x00\x00\x00K")


# -- the greeting ------------------------------------------------------------------------------


def test_the_greeting_is_the_bytes_a_client_actually_sent() -> None:
    """Byte for byte, from the capture: this is not reconstructible by guessing."""
    assert cedar.greeting("schedd_363_822f") == GREETING


def test_a_greeting_names_a_sock_and_a_subsystem() -> None:
    with pytest.raises(cedar.CedarError, match="names a sock"):
        cedar.greeting("")
    with pytest.raises(cedar.CedarError, match="names a sock"):
        cedar.greeting("a\x00b")


# -- classads on the wire ----------------------------------------------------------------------


def test_the_secman_request_parses_as_the_capture_has_it() -> None:
    attributes = cedar.parse_wire_classads(REQUEST[5:])
    assert len(attributes) == 18
    assert attributes["AuthMethods"] == "CLAIMTOBE"
    assert attributes["CryptoMethods"] == "AES,BLOWFISH,3DES"
    assert attributes["Command"] == 1112 and attributes["Subsystem"] == "SUBMIT"
    assert attributes["NegotiatedSession"] is True and attributes["Enact"] == "NO"
    assert attributes["ECDHPublicKey"].startswith("BPwl") and attributes["SessionLease"] == 3600
    assert attributes["ConnectSinful"].startswith("<172.17.0.2:37973?addrs=")


def test_the_wire_form_is_nul_separated_and_round_trips() -> None:
    """`tcpdump -A` shows the separator as a dot; on the wire it is NUL."""
    attributes = cedar.parse_wire_classads(REQUEST[5:])
    written = cedar.wire_classads(attributes)
    assert written.endswith(b"\x00") and b"\x00" * 2 not in written
    assert cedar.parse_wire_classads(written) == attributes


def test_a_payload_without_an_assignment_is_refused() -> None:
    with pytest.raises(cedar.CedarError, match="no 'name = value"):
        cedar.parse_wire_classads(b"\x00\x00\x00\x00binary only")


def test_a_pair_with_no_name_is_refused() -> None:
    """The first real assignment starts the classad; a nameless pair after it is an error."""
    with pytest.raises(cedar.CedarError, match="no name"):
        cedar.parse_wire_classads(b"X = 1\x00 = 2\x00")


def test_a_value_that_is_not_one_is_refused() -> None:
    with pytest.raises(cedar.CedarError, match="X"):
        cedar.parse_wire_classads(b'X = "open\x00')


def test_an_attribute_name_cannot_hold_the_separator() -> None:
    with pytest.raises(cedar.CedarError, match="cannot contain NUL"):
        cedar.wire_classads({"a\x00b": 1})


# -- the SECMAN messages -----------------------------------------------------------------------


def test_a_request_carries_what_a_submission_announces() -> None:
    request = cedar.SecurityRequest(
        auth_methods="GSI",
        remote_version="$CondorVersion: test $",
        ecdh_public="KEY",
        connect_sinful="<host:9619>",
    )
    attributes = request.as_classads()
    assert attributes["Command"] == 1112 and attributes["Subsystem"] == "SUBMIT"
    assert attributes["AuthMethods"] == "GSI" and attributes["NewSession"] == "YES"
    assert attributes["ECDHPublicKey"] == "KEY" and attributes["ConnectSinful"] == "<host:9619>"


def test_the_reply_says_what_the_server_agreed_to() -> None:
    reply = cedar.SecurityReply.parse(REPLY[5:])
    assert reply.authenticated and reply.enacts
    assert reply.method == "CLAIMTOBE" and reply.cipher == "AES"
    assert reply.ecdh_public.startswith("BD28")


@pytest.mark.parametrize(
    ("attributes", "authenticated", "enacts"),
    [
        ({"Authentication": "NO", "Enact": "NO"}, False, False),
        ({"Authentication": "YES", "Enact": "YES"}, True, True),
        ({}, False, False),
    ],
    ids=["refused", "agreed", "empty"],
)
def test_a_reply_reads_its_two_verdicts(
    attributes: dict[str, str], authenticated: bool, enacts: bool
) -> None:
    reply = cedar.SecurityReply(attributes=attributes)
    assert (reply.authenticated, reply.enacts) == (authenticated, enacts)
    assert isinstance(reply.ecdh_public, str)


def test_the_second_connection_announces_a_qmgmt_command() -> None:
    """`condor_submit` opens a second connection for QMGMT: Command 421, then a Nonce."""
    assert struct.unpack(">I", COMMAND[5:9])[0] == 0
    attributes = cedar.parse_wire_classads(COMMAND[5:])
    assert attributes["Command"] == 421
    assert attributes["ConnectSinful"].startswith("<172.17.0.2:37973")
    assert cedar.parse_wire_classads(NONCE[5:])["Nonce"]
