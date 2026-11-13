# Changelog

## [0.5.0] - 2026-11-12

### Added

- **`xrdhtcondor.scitokens`**: WLCG tokens - discovery (`SCITOKENS_FILE`,
  `BEARER_TOKEN_FILE`, `~/.condor/tokens.d`), audience-aware choice, the SCITOKENS
  negotiation, and the handshake the way `condor_auth_ssl.cpp` does it: TLS records
  carried *inside* CEDAR messages, the JWT written through TLS as
  `[uint32 length][token]`.
- **`xrdhtcondor.session`**: the enacted session - `[type][sealed size][IV][ciphertext][tag]`
  with the running-digest AAD, both halves measured from a daemon's own log.
- **`xrdhtcondor.collector`**: ask a collector which schedd it knows and how to reach
  it (`TargetType = "Scheduler"`, a boolean `Requirements`, the address read back out).
- **CEDAR**: `security_message()`, `code_int()` and `put_classad()` write a SECMAN
  message the way `putClassAd` does - the count, the pairs, then two empty strings.
  `xrdhtcondor auth` presents a token to a daemon and reports its verdict.
- **A testbed pool** (`tests/integration/cluster/`): AlmaLinux 9 containers sharing one
  port, a local issuer (`issuer.py`) that mints RS256 tokens and publishes a JWKS, and
  `run.sh`, which proves a job runs through the pool before the client is tested.

The offline half first: a submission agent's data layer before its transport.

### Added

- `xrdhtcondor.classads`: parse and write HTCondor classads — the `(key = value)`
  form, strings with their quoting, integers, reals, booleans, lists, nested ads
  and `undefined` - so a job's attributes can be built and checked without
  HTCondor's libraries.
- `xrdhtcondor.submitfile`: read a `.sub` submit description (attributes, `+`
  custom attributes, macros) and expand its `queue` statements into the jobs
  they mean, which is what `condor_submit` does before it talks to a schedd.
- `docs/DESIGN.md`: the honest map of what a pure-Python submission agent must
  speak - classads, the submit description, job-ad assembly, CEDAR with GSI,
  QMGMT - and what the later stages need from a real CE.
