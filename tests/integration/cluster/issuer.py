"""A local SciTokens issuer: mints tokens and publishes the JWKS that verifies them.

No browser, no external IdP - which is what makes the handshake iterable.
"""

import base64
import json
import os
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ISSUER = "https://submit:8443"
AUDIENCE = "https://wlcg.cern.ch/jwt/v1/any"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
NUMBERS = KEY.public_key().public_numbers()


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "local-1",
            "n": b64(NUMBERS.n.to_bytes((NUMBERS.n.bit_length() + 7) // 8, "big")),
            "e": b64(NUMBERS.e.to_bytes((NUMBERS.e.bit_length() + 7) // 8, "big")),
        }
    ]
}


def mint(subject: str = "rcurrie", lifetime: int = 3600) -> str:
    header = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "local-1"}).encode())
    now = int(time.time())
    claims = b64(
        json.dumps(
            {
                "iss": ISSUER,
                "sub": subject,
                "aud": AUDIENCE,
                "iat": now,
                "nbf": now,
                "exp": now + lifetime,
                "scope": "storage.read:/ wlcg.groups",
                "wlcg.groups": ["/wlcg", "/lhcboff"],
            }
        ).encode()
    )
    signing = f"{header}.{claims}".encode()
    signature = KEY.sign(signing, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{claims}.{b64(signature)}"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.rstrip("/") in ("/.well-known/openid-configuration", "/openid-configuration"):
            # What libscitokens actually reads: an OpenID configuration naming the JWKS.
            body = json.dumps(
                {
                    "issuer": ISSUER,
                    "jwks_uri": f"{ISSUER}/jwks",
                    "token_endpoint": f"{ISSUER}/token",
                    "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                }
            ).encode()
        elif self.path.rstrip("/") in ("/.well-known/scitoken-config", "/scitoken-config"):
            body = json.dumps({"issuer": ISSUER, "jwks_uri": f"{ISSUER}/jwks"}).encode()
        elif self.path.rstrip("/") == "/jwks":
            body = json.dumps(JWKS).encode()
        else:
            body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return None


def _tls_context() -> ssl.SSLContext:
    """A throwaway certificate: libscitokens wants https, and does not chain-check it."""
    import datetime
    import tempfile

    from cryptography import x509
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "submit")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        # A trust anchor, so a daemon can be told to believe this endpoint.
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    handle, path = tempfile.mkstemp(suffix=".pem")
    with os.fdopen(handle, "wb") as written:
        written.write(certificate.public_bytes(serialization.Encoding.PEM))
        written.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    # The certificate is also written where a daemon's trust store can be given it:
    # libscitokens verifies the JWKS endpoint's TLS ("SSL peer certificate ... not OK"
    # is what it says otherwise).
    with open("/tmp/issuer-ca.pem", "wb") as anchor:
        anchor.write(certificate.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(path)
    return context


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "mint":
        print(mint())
    else:
        server = HTTPServer(("0.0.0.0", 8443), Handler)
        server.socket = _tls_context().wrap_socket(server.socket, server_side=True)
        print(f"issuer on {ISSUER}", flush=True)
        server.serve_forever()
