"""SCITOKENS: finding a token, choosing one, and presenting it over CEDAR."""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import threading
from typing import Self

import pytest

from xrdhtcondor import cedar, scitokens


def _jwt(**claims: object) -> str:
    """A token-shaped string: this suite never checks a signature."""

    def part(said: object) -> str:
        raw = json.dumps(said).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{part({'alg': 'RS256'})}.{part(claims)}.signature"


def test_a_handshake_message_round_trips() -> None:
    """The status, the length and the bytes, as ``send_message`` writes them."""
    written = scitokens.message(scitokens.SENDING, b"tls-record")
    assert scitokens.parse_message(written) == (scitokens.SENDING, b"tls-record")


@pytest.mark.parametrize("payload", [b"", b"\x00" * 15])
def test_a_short_message_is_refused(payload: bytes) -> None:
    """Two ``code(int)``s are sixteen bytes; less than that is not a message."""
    with pytest.raises(scitokens.SciTokenError, match="at least 16 bytes"):
        scitokens.parse_message(payload)


def test_a_message_that_overstates_its_length_is_refused() -> None:
    """A length past the end of the message would read somebody else's bytes."""
    written = cedar.code_int(0) + cedar.code_int(99) + b"short"
    with pytest.raises(scitokens.SciTokenError, match="claims 99 bytes"):
        scitokens.parse_message(written)


def test_a_token_s_claims_are_read_without_believing_them() -> None:
    """Who it is for, and until when: the signature is the daemon's business."""
    token = scitokens.Token(
        "p",
        _jwt(iss="https://iam", aud="https://ce"),
        {"iss": "https://iam", "aud": "https://ce"},
    )
    assert token.audiences == ("https://ce",)
    assert token.issuer == "https://iam"


def test_one_audience_or_many() -> None:
    """``aud`` may be a string or a list, and both mean the same thing."""
    assert scitokens.claims_of(_jwt(aud=["a", "b"]))["aud"] == ["a", "b"]
    token = scitokens.Token("p", "t", {"aud": ["a", "b"]})
    assert token.audiences == ("a", "b")
    assert scitokens.Token("p", "t", {}).audiences == ()


@pytest.mark.parametrize("token", ["one-part", "a.!!!.c"])
def test_something_that_is_not_a_token_is_refused(token: str) -> None:
    """A file that is not a JWT is not a token."""
    with pytest.raises(scitokens.SciTokenError):
        scitokens.claims_of(token)


def test_a_token_whose_claims_are_not_an_object_is_refused() -> None:
    """A JSON list is not a set of claims."""
    raw = base64.urlsafe_b64encode(b"[1, 2]").rstrip(b"=").decode()
    with pytest.raises(scitokens.SciTokenError, match="object"):
        scitokens.claims_of(f"header.{raw}.signature")


def test_tokens_are_found_where_htcondor_looks(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``BEARER_TOKEN_FILE`` first, then one file per token under tokens.d."""
    tokens_dir = tmp_path / ".condor" / "tokens.d"
    tokens_dir.mkdir(parents=True)
    (tokens_dir / "b-wlcg").write_text(_jwt(sub="two") + "\n")
    (tokens_dir / "a-empty").write_text("\n")
    named = tmp_path / "named"
    named.write_text("\n" + _jwt(sub="one") + "\n")
    found = scitokens.candidates({"BEARER_TOKEN_FILE": str(named), "HOME": str(tmp_path)})
    assert [token.claims["sub"] for token in found] == ["one", "two"]
    assert found[0].path == str(named)


def test_no_tokens_anywhere_is_no_tokens() -> None:
    """An empty session has nothing to offer, and that is not an error."""
    assert scitokens.candidates({"HOME": "/nonexistent"}) == []


def test_a_token_named_but_missing_is_skipped(tmp_path: pytest.TempPathFactory) -> None:
    """A dangling ``SCITOKENS_FILE`` does not hide what tokens.d holds."""
    tokens_dir = tmp_path / ".condor" / "tokens.d"
    tokens_dir.mkdir(parents=True)
    (tokens_dir / "wlcg").write_text(_jwt(sub="found") + "\n")
    found = scitokens.candidates({"SCITOKENS_FILE": str(tmp_path / "gone"), "HOME": str(tmp_path)})
    assert [token.claims["sub"] for token in found] == ["found"]


def test_choosing_prefers_the_audience_it_was_asked_about() -> None:
    """Offering a token that says it is for somewhere else, when another fits, is silly."""
    other = scitokens.Token("a", "t", {"aud": "https://elsewhere"})
    wanted = scitokens.Token("b", "t", {"aud": "https://ce"})
    assert scitokens.choose([other, wanted], "https://ce") is wanted
    assert scitokens.choose([other, wanted]) is other


def test_the_wlcg_audience_fits_anywhere() -> None:
    """The generic WLCG audience is accepted by every WLCG service."""
    generic = scitokens.Token("a", "t", {"aud": "https://wlcg.cern.ch/jwt/v1/any"})
    assert scitokens.choose([generic], "https://ce") is generic


def test_choosing_nothing_says_what_to_set() -> None:
    """The message names the variables, because that is what a person must fix."""
    with pytest.raises(scitokens.SciTokenError, match="SCITOKENS_FILE"):
        scitokens.choose([])


class _Daemon:
    """A TLS server speaking the same CEDAR framing, for one exchange."""

    def __init__(self, verdict: bytes = b'{"user": "rcurrie"}') -> None:
        self.verdict = verdict
        self.expect_greeting = True
        self.received = b""
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.certificate = _self_signed()
        self.context.load_cert_chain(self.certificate, self.certificate)
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _frame_of(self, conn: socket.socket) -> bytes:
        header = b""
        while len(header) < 5:
            chunk = conn.recv(5 - len(header))
            if not chunk:
                return b""
            header += chunk
        size = int.from_bytes(header[1:5], "big")
        body = b""
        while len(body) < size:
            chunk = conn.recv(size - len(body))
            if not chunk:
                return b""
            body += chunk
        return body

    def _serve(self) -> None:
        conn, _ = self.sock.accept()
        with conn:
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            server = self.context.wrap_bio(incoming, outgoing, server_side=True)
            while True:
                try:
                    server.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    pending = outgoing.read()
                    if pending:
                        conn.sendall(cedar.frame(scitokens.message(scitokens.SENDING, pending)))
                    reply = self._frame_of(conn)
                    if not reply:
                        return
                    _status, body = scitokens.parse_message(reply)
                    incoming.write(body)
            wanted = server.read(4)
            length = struct.unpack(">I", wanted)[0]
            read = b""
            while len(read) < length:
                read += server.read(length - len(read))
            self.received = read
            server.write(self.verdict)

    def exchange(self, payload: bytes) -> bytes:
        """The client side of the same framing: send records, take the reply."""
        self.conn.sendall(cedar.frame(scitokens.message(scitokens.A_OK, payload)))
        return self._frame_of(self.conn)

    def __enter__(self) -> Self:
        self.thread.start()
        self.conn = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        return self

    def __exit__(self, *_exc: object) -> None:
        self.thread.join(timeout=10)
        self.conn.close()
        self.sock.close()


def _self_signed() -> str:
    """A throwaway certificate: the exchange authenticates with the token."""
    import datetime
    import ipaddress
    import tempfile

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    moment = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(moment - datetime.timedelta(minutes=5))
        .not_valid_after(moment + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    handle, path = tempfile.mkstemp(suffix=".pem")
    with os.fdopen(handle, "wb") as written:
        written.write(
            certificate.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return path


def test_a_token_is_presented_over_tls_and_arrives_intact() -> None:
    """The whole exchange against a local daemon: handshake, token, verdict."""
    token = scitokens.Token("p", _jwt(sub="rcurrie"), {"sub": "rcurrie"})
    with _Daemon() as daemon:
        status = scitokens.authenticate(daemon.exchange, token)
    assert daemon.received.decode() == token.text
    assert status != scitokens.QUITTING


def test_a_daemon_that_hangs_up_is_an_error() -> None:
    """A closed connection mid-handshake is not a verdict."""

    def gone(_payload: bytes) -> bytes:
        return b""

    with pytest.raises(scitokens.SciTokenError, match="closed the connection"):
        scitokens.authenticate(gone, scitokens.Token("p", _jwt(), {}))


def test_a_daemon_that_refuses_says_so() -> None:
    """``AUTH_SSL_QUITTING`` is the daemon ending the exchange."""

    def quitting(_payload: bytes) -> bytes:
        return scitokens.message(scitokens.QUITTING, b"")

    with pytest.raises(scitokens.SciTokenError, match="refused"):
        scitokens.authenticate(quitting, scitokens.Token("p", _jwt(), {}))


class _DaemonWithSecman(_Daemon):
    """A daemon that answers SECMAN with SCITOKENS, then runs the token exchange."""

    def _serve(self) -> None:
        conn, _ = self.sock.accept()
        with conn:
            if self.expect_greeting:
                self._frame_of(conn)  # the greeting
            request = self._frame_of(conn)  # the SECMAN message
            self.asked = cedar.parse_wire_classads(request)
            conn.sendall(
                cedar.frame(
                    cedar.put_classad(
                        {
                            "Authentication": "YES",
                            "AuthMethods": "SCITOKENS",
                            "TrustDomain": "cern.ch",
                        }
                    )
                )
            )
            self._serve_on(conn)

    def _serve_on(self, conn: socket.socket) -> None:
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        server = self.context.wrap_bio(incoming, outgoing, server_side=True)
        while True:
            try:
                server.do_handshake()
                break
            except ssl.SSLWantReadError:
                pending = outgoing.read()
                if pending:
                    conn.sendall(cedar.frame(scitokens.message(scitokens.SENDING, pending)))
                reply = self._frame_of(conn)
                if not reply:
                    return
                _status, body = scitokens.parse_message(reply)
                incoming.write(body)
        wanted = server.read(4)
        length = struct.unpack(">I", wanted)[0]
        read = b""
        while len(read) < length:
            read += server.read(length - len(read))
        self.received = read
        pending = outgoing.read()
        if pending:
            conn.sendall(cedar.frame(scitokens.message(scitokens.SENDING, pending)))


def test_a_daemon_that_offers_scitokens_gets_the_token() -> None:
    """SECMAN offers the method, the daemon takes it, and the token arrives over TLS."""
    token = scitokens.Token("p", _jwt(sub="rcurrie", iss="https://iam"), {"sub": "rcurrie"})
    with _DaemonWithSecman() as daemon:
        daemon.expect_greeting = False
        verdict = scitokens.negotiate(Framed_of(daemon.conn), token)
    assert daemon.asked["AuthMethods"] == "SCITOKENS"
    assert daemon.asked["Command"] == scitokens.QMGMT_WRITE_CMD
    assert daemon.received.decode() == token.text
    assert verdict.accepted


def Framed_of(connection: socket.socket) -> scitokens.Framed:
    """The CEDAR framing around a connected socket."""
    return scitokens.Framed(connection)


def test_a_daemon_that_offers_something_else_is_refused() -> None:
    """If the daemon will not take tokens, saying which method it named helps."""

    class _Other:
        def send(self, _payload: bytes) -> None:
            return None

        def receive(self) -> bytes:
            return cedar.frame(cedar.put_classad({"AuthMethods": "GSI"}))

    with pytest.raises(scitokens.SciTokenError, match="did not offer SCITOKENS"):
        scitokens.negotiate(_Other(), scitokens.Token("p", _jwt(), {}))


def test_a_daemon_that_says_nothing_says_nothing() -> None:
    """A closed connection before any classad is not a negotiation."""

    class _Silent:
        def send(self, _payload: bytes) -> None:
            return None

        def receive(self) -> bytes:
            return b""

    with pytest.raises(scitokens.SciTokenError, match="closed the connection"):
        scitokens.negotiate(_Silent(), scitokens.Token("p", _jwt(), {}))


def test_the_framing_reads_and_writes_cedar_messages() -> None:
    """One message in, one message out, and an end that reads as empty."""
    left, right = socket.socketpair()
    with left, right:
        framing = scitokens.Framed(left)
        framing.send(b"one")
        header = right.recv(5)
        assert header[0] == 0x01
        assert int.from_bytes(header[1:5], "big") == 3
        assert right.recv(3) == b"one"
        right.sendall(cedar.frame(b"two"))
        assert framing.receive() == b"two"
        right.close()
        assert framing.receive() == b""


def test_a_handshake_with_nothing_to_send_says_so() -> None:
    """A step that wants input while there is nothing to write cannot proceed."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()

    def wants() -> None:
        raise ssl.SSLWantReadError

    with pytest.raises(scitokens.SciTokenError, match="nothing to send"):
        scitokens._pump(incoming, outgoing, lambda _b: b"", wants)


def test_a_reply_that_is_not_a_classad_is_no_attributes() -> None:
    """Garbage in a reply is an empty answer, not a crash."""
    assert scitokens._classads_of(b"\x00\x01\x02") == {}


def test_a_truncated_message_reads_as_the_end() -> None:
    """A peer that promises bytes and then hangs up is an end, not a hang."""
    left, right = socket.socketpair()
    with left, right:
        framing = scitokens.Framed(left)
        right.sendall(b"\x01\x00\x00\x00\x09short")
        right.close()
        assert framing.receive() == b""


def test_the_socket_wiring_sends_a_greeting_then_negotiates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``authenticate_daemon`` greets the daemon by its sock, then negotiates."""
    token = scitokens.Token("p", _jwt(), {})

    class _Connection:
        def __init__(self) -> None:
            self.sent = b""

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, data: bytes) -> None:
            self.sent += data

        def recv(self, _size: int) -> bytes:
            return cedar.frame(cedar.put_classad({"AuthMethods": "GSI"}))

    connection = _Connection()
    monkeypatch.setattr(scitokens.socket, "create_connection", lambda *a, **k: connection)
    with pytest.raises(scitokens.SciTokenError, match="did not offer SCITOKENS"):
        scitokens.authenticate_daemon("ce.example", "collector", token)
    assert connection.sent.startswith(cedar.greeting("collector"))


def test_a_daemon_that_enacts_a_session_is_named_as_the_reason() -> None:
    """An enacted session is why a clear-text exchange would be ignored - say so."""

    class _Enacting:
        def send(self, _payload: bytes) -> None:
            return None

        def receive(self) -> bytes:
            return cedar.frame(
                cedar.put_classad(
                    {
                        "AuthMethods": "SCITOKENS",
                        "Authentication": "YES",
                        "Enact": "YES",
                        "Encryption": "YES",
                    }
                )
            )

    with pytest.raises(scitokens.SciTokenError, match="enacted an encrypted session"):
        scitokens.negotiate(_Enacting(), scitokens.Token("p", _jwt(), {}))
