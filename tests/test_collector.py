"""The collector query: what it asks for, and how its answer is read."""

from __future__ import annotations

from typing import Self

import pytest

from xrdhtcondor import cedar, collector

REPLY_AD = {
    "Machine": "submit",
    "MyAddress": "<172.20.0.3:9618?addrs=172.20.0.3-9618&alias=submit&noUDP&sock=schedd_1_43af>",
    "Name": "schedd@submit",
}


def test_the_query_is_the_one_a_real_client_sends() -> None:
    """``TargetType``, ``MyType``, a boolean ``Requirements``, and a projection.

    ``Requirements`` as the *string* ``"true"`` is the trap: the collector
    evaluates a type error, skips the ad and answers with no ads at all.
    """
    query = collector.query_classad()
    assert query["TargetType"] == "Scheduler"
    assert query["MyType"] == "Query"
    assert query["Requirements"] is True
    # Written unquoted: a string here is a type error the collector skips on.
    assert b"Requirements = true\x00" in cedar.put_classad(query)


def test_a_sinful_string_gives_its_host_port_and_sock() -> None:
    """The parts a shared port needs, taken from the address it publishes."""
    parts = collector.address_parts(REPLY_AD["MyAddress"])
    assert parts == ("172.20.0.3", 9618, "schedd_1_43af")


@pytest.mark.parametrize(
    "sinful",
    [
        "<172.20.0.3:9618>",
        "172.20.0.3:9618",
        "",
    ],
)
def test_an_address_without_a_sock_is_not_a_shared_port_target(sinful: str) -> None:
    """Nothing to route by: a caller must not treat this as reachable."""
    assert collector.address_parts(sinful) is None


def test_the_schedd_is_the_reply_that_carries_an_address() -> None:
    """The first classad with a ``MyAddress`` is the one worth reading."""
    assert collector.schedd_ad([{"Name": "x"}, REPLY_AD]) == REPLY_AD


def test_no_address_anywhere_is_no_schedd() -> None:
    """A reply of session classads names no schedd."""
    assert collector.schedd_ad([{"ReturnCode": "AUTHORIZED"}]) is None


def test_a_reply_stream_is_read_as_classads() -> None:
    """Frames that are not classads are skipped; the ad among them is kept."""
    stream = b"".join(
        [
            cedar.frame(cedar.code_int(0)),
            cedar.frame(cedar.put_classad({"ReturnCode": "AUTHORIZED"})),
            cedar.frame(cedar.put_classad(REPLY_AD)),
        ]
    )
    ads = collector.parse_reply(stream)
    assert ads == [{"ReturnCode": "AUTHORIZED"}, REPLY_AD]


def test_the_request_names_the_command_it_will_send() -> None:
    """A session is negotiated for the command that follows, as a daemon expects."""
    asked = collector._request("collector", collector.QUERY_SCHEDD_ADS)
    assert asked["Command"] == collector.QUERY_SCHEDD_ADS
    assert asked["Subsystem"] == "TOOL"
    assert asked["AuthMethods"] == "CLAIMTOBE"
    assert asked["ECDHPublicKey"]


class _FakeConnection:
    """A socket that answers with a canned stream and records what was sent."""

    def __init__(self, answer: bytes) -> None:
        self.answer = answer
        self.sent = b""
        self.delivered = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def settimeout(self, _timeout: float) -> None:
        return None

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, _size: int) -> bytes:
        if self.delivered:
            return b""
        self.delivered = True
        return self.answer


def test_a_pool_answers_with_the_schedd_it_knows(monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole query, against a canned reply: the address comes back parsed."""
    answer = b"".join(
        [
            cedar.frame(cedar.put_classad({"ReturnCode": "AUTHORIZED"})),
            cedar.frame(cedar.put_classad(REPLY_AD)),
        ]
    )
    fake = _FakeConnection(answer)
    monkeypatch.setattr(collector.socket, "create_connection", lambda *a, **k: fake)

    host, port, sock = collector.schedd_address("cm")

    assert (host, port, sock) == ("172.20.0.3", 9618, "schedd_1_43af")
    assert cedar.greeting("collector") in fake.sent


def test_a_reply_without_a_schedd_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A collector that names no schedd is a failure, not an empty answer."""
    fake = _FakeConnection(cedar.frame(cedar.put_classad({"ReturnCode": "AUTHORIZED"})))
    monkeypatch.setattr(collector.socket, "create_connection", lambda *a, **k: fake)

    with pytest.raises(LookupError, match="no schedd ad"):
        collector.schedd_address("cm")


def test_an_address_without_a_sock_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """An address we cannot route to must not be returned as if it were usable."""
    fake = _FakeConnection(cedar.frame(cedar.put_classad({"MyAddress": "<10.0.0.1:9618>"})))
    monkeypatch.setattr(collector.socket, "create_connection", lambda *a, **k: fake)

    with pytest.raises(LookupError, match="names no sock"):
        collector.schedd_address("cm")
