"""A local SciTokens issuer: mints tokens and publishes the JWKS that verifies them.

No browser, no external IdP - which is what makes the handshake iterable.
"""

import base64, json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

ISSUER = "http://127.0.0.1:8080"
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
    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") in ("/.well-known/scitoken-config", "/scitoken-config"):
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


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "mint":
        print(mint())
    else:
        print(f"issuer on {ISSUER}", flush=True)
        HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
