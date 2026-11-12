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
