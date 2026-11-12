# A three-node HTCondor pool in containers

`cm` (collector and negotiator), `submit` (schedd), `execute` (startd), each an
AlmaLinux 9 container with HTCondor from its own repository. All three share one
port, as a real HTCondor-CE does, so a client has to name the daemon it wants in
its greeting.

```sh
docker compose up -d --build          # start the pool
docker compose exec submit condor_status      # slot1@execute
docker compose exec submit condor_q          # schedd@submit
./run.sh                             # the whole check, from scratch
```

## What is asserted

1. **The pool is real**: a job submitted with `condor_submit` reaches `Completed`,
   exit code 0, and its output is transferred back. `run.sh` checks this, because
   everything else is meaningless if the pool is broken.
2. **Our client reaches both daemons**: `probe_pool.py` greets the collector's
   sock, negotiates a SECMAN session, greets the schedd by the sock name the pool
   publishes, and negotiates again - both answering `Authentication = "YES"`.

## What the pool already taught

- **The `SECMAN` command must match the command that follows.** A session request
  carrying `Command = 1112` and then a collector query (6) is closed without a
  word; with `Command = 6` the collector answers properly.
- **A real daemon enacts an encrypted session** (`Enact = "YES"`), so the traffic
  after `SECMAN` is AES-GCM under an ECDH-derived key. `crypto.py` implements that
  cipher; wiring it into a session is the next piece.
- **Security classes are per subsystem and per access level.** A pool needs
  `ALLOW_ADVERTISE_SCHEDD`/`ALLOW_ADVERTISE_STARTD` as well as `ALLOW_*`, and its
  config must load *after* the packaged `00-htcondor-9.0.config` (hence `98-`).

## The next milestone: the session itself

`probe_session.py` is the experiment that comes next, and it is not in `run.sh`
because it does not pass yet. It negotiates, derives the session key from the
shared secret (`32 bytes -> 32 bytes`, HKDF as `crypto.py` implements it), and
sends one sealed QMGMT packet - to which the schedd does not reply. What that
leaves to settle is the session framing: the 64 handshake-digest bytes in front
of the first packet in each direction, and whether the peer validates them or
merely uses them as additional authenticated data, plus the exact shape of the
QMGMT session-start message after `Command = 421`.

## `probe_qmgmt.py`: how far QMGMT gets

It negotiates for `QMGMT_WRITE_CMD` (1112), sends `InitializeConnection` (which
the pool answers `0`, so the framing is right), and then `NewCluster` - where the
pool closes the connection, having logged:

```
DC_AUTHENTICATE: authentication of <...> did not result in a valid mapped user
name, which is required for this command (1112 QMGMT_WRITE_CMD), so aborting.
```

A collector query may be anonymous; a queue-manager write may not. The remaining
work is therefore authentication (CLAIMTOBE's identity correctly sent, and GSI for
a real CE), not more QMGMT framing.

## The session is not optional

Capturing a real `condor_submit` in the pool shows the schedd answer the
negotiation with `Enact = "YES"`: the CLAIMTOBE identity and every QMGMT command
after it travel **encrypted**. There is no plaintext queue-manager exchange to
imitate, which is why `probe_qmgmt.py` reaches `InitializeConnection` and stops.
`crypto.py` holds the cipher; `probe_session.py` is where the framing is being
settled, with this pool as the oracle.

## The session, as far as it goes

`probe_session.py` establishes what the pool will do and what it will not:

| step | outcome |
| --- | --- |
| negotiation with `Authentication = "REQUIRED"` | `YES`/`YES`/`YES`, `Enact = "YES"`, **and its ECDH key** |
| session key from the shared secret | 32 bytes, HKDF as `crypto.py` derives it |
| one sealed packet (identity), header length = sealed size | the daemon closes |

So the key exchange works and the remaining fault is inside the first sealed
packet: the running-digest AAD (which traffic is hashed, and how the two digests
are ordered) or the header's length and type. Everything above it - query, address,
greeting, negotiation, QMGMT framing - is now proven against this pool.

## A token-based pool (`issuer.py`, `--token` paths)

The pool can be made token-capable, which is what lets the SciTokens exchange be
developed without any site's cooperation and without a browser:

```sh
docker compose cp issuer.py cm:/tmp/issuer.py
docker compose exec cm bash -c 'nohup python3 /tmp/issuer.py & sleep 1; python3 /tmp/issuer.py mint > /tmp/token'
docker compose cp cm:/tmp/token /tmp/token && docker compose cp /tmp/token submit:/tmp/token
```

`issuer.py` is a self-contained SciTokens issuer: it signs RS256 tokens with a key
it generates, and publishes the JWKS the daemon fetches to verify them. The pool's
config (`98-testbed-common.config`) accepts the audience those tokens carry
(`https://wlcg.cern.ch/jwt/v1/any`) and any foreign issuer
(`SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS = *`), with SCITOKENS in the READ and WRITE
classes - a collector query is a READ, so DEFAULT alone is not enough.

Two things this taught, both worth keeping:

- **Reads do not authenticate.** `condor_status -direct` against an open pool
  succeeds without any token at all, so a "successful" real-client test proves
  nothing about SCITOKENS. Only a *write* - a submit - forces the exchange.
- The real client sends its SECMAN request and then the query in clear on the same
  connection when the daemon authorises anonymously, which is what the capture of
  a read looks like.

### What the token stack needs, learned the hard way

- **https, not http.** With an `http` issuer the *client* silently drops the method
  (`HANDSHAKE: client sent (methods == 0)`); serving the same JWKS over https makes
  it offer SCITOKENS properly. `issuer.py` therefore wraps itself in TLS with a
  throwaway certificate.
- **`scitokens-cpp` on both ends**, or the method is excluded before it is offered.
- **Reads do not authenticate**: a `condor_status` against an open pool says nothing.
- A collector query is a **READ**, so SCITOKENS has to be in `SEC_READ_*` as well as
  `SEC_DEFAULT_*`, or the daemon's offer comes back empty.

With those in place the real client offers the method and the daemon attempts the
validation, failing with `AUTHENTICATE: method 4096 (SCITOKENS) failed` and no
further detail at `D_SECURITY|D_FULLDEBUG`. That last failure is the open item:
either libscitokens cannot verify our self-signed JWKS endpoint, or it dislikes a
claim. The quickest way to see its reason is to call `scitoken_deserialize`
directly in a container against a minted token.

### The issuer, as it now stands (and the last thing it needs)

`issuer.py` mints tokens and serves, over https with a throwaway CA certificate:

| path | what libscitokens wants from it |
| --- | --- |
| `/.well-known/openid-configuration` | **`jwks_uri`** - it reads this, not `scitoken-config` |
| `/jwks` | the RSA key that signed the token |

The certificate must also be a trust anchor in the daemon's store
(`/etc/pki/ca-trust/source/anchors/local-issuer.crt`, then `update-ca-trust`), and
libscitokens **persists a negative cache** - `~/.cache/scitokens/scitokens_cpp.sqllite`
- so a failed fetch keeps failing until that file is removed.

Its remaining complaint, in its own words, is `SSL peer certificate or SSH remote key
was not OK` even after `curl` trusts the anchor: it uses its own TLS store rather than
the system bundle that `update-ca-trust` rewrites. Making it use ours (a
`SSL_CERT_FILE`/`CURL_CA_BUNDLE` for the daemon, or a certificate signed by an anchor
already in its store) is the next step - and then the successful SCITOKENS *write*
can be captured, which is what the client's handshake needs.

### The token stack, as far as it now goes (measured, step by step)

Getting a real daemon to *believe* a locally minted token took these, in this order:

1. **https**, with a CA the daemons trust: `pki/` holds a test CA and an issuer
   certificate, mounted at `/pki` and exported as `SSL_CERT_FILE`/`CURL_CA_BUNDLE`;
   the anchor also has to be installed (`anchors/*.crt` + `update-ca-trust`).
2. **`/.well-known/openid-configuration` with a `jwks_uri`** - that is the document
   libscitokens reads.
3. **One signing key for both the mint and the server**, kept at
   `/tmp/token-signing.key`. A key per process gives `failed to verify signature:
   VerifyFinal failed` because the token never matches the published JWKS.
4. `scitoken_deserialize` then returns **0** and `enforcer_create` succeeds, so the
   token is valid and its keys are fetched.
5. The last gate is libscitokens' ACL step:
   `token verification failed: 'wlcg.groups' claim verification is mandatory`.
   HTCondor tolerates that for a "foreign token type"
   (`SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES` with the issuer listed), which is set
   here, and still the daemon refuses - so either that path is not reached or an ACL
   source (`scitokens.cfg`) is expected.

`asklib.py` is the diagnostic that made all of this possible: it calls
`scitoken_deserialize`/`enforcer_create`/`enforcer_generate_acls` directly and prints
the library's own error text, which no amount of daemon debug output revealed.

### The ACL gate, and what was tried

libscitokens refuses to build ACLs for a token that carries `wlcg.groups`:
`token verification failed: 'wlcg.groups' claim verification is mandatory`. Tried
against it and not the answer: an `/etc/scitokens/scitokens.cfg` naming the issuer
with a `default_user`, and `SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES = TRUE` with
`SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS = *`.

The token itself is otherwise accepted - `scitoken_deserialize` returns 0 and
`enforcer_create` succeeds - so what remains is a *policy* question the library
answers, not a transport one: which groups this pool believes, and under what ACLs.
That is also the point at which the testbed stops standing in for a real site, since
a real site has exactly that configuration and this one does not.
