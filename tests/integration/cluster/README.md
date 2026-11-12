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
