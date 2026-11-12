# xrdhtcondor: design

A **pure-Python, LGPL** re-implementation of an HTCondor *submission agent*: push
a job to an HTCondor-CE from a macOS or Linux client, follow it to completion,
and collect its results — without HTCondor's C++ libraries, without its Python
bindings, and without shelling out to `condor_submit`.

Like `xrddirac`, this is **specification-first**: HTCondor is Apache-2.0, so the
licence is not the constraint here, but the protocol is undocumented outside its
source, and a guessed wire format is a bug that looks like a working client.

## What a submission agent has to speak (the honest map)

| layer | what it is | difficulty |
| --- | --- | --- |
| **classads** | HTCondor's data language: `(key = value)` with strings, ints, floats, booleans, lists `{…}`, nested ads `[…]`, `undefined`, and expressions. Publicly documented, stable. | small, testable offline |
| **submit description** | the `.sub` file: `executable`, `arguments`, `+Custom` attributes, `queue [N] [args]`, macros (`$(Cluster)`, `$(Process)`). Publicly documented. | small, testable offline |
| **job ad assembly** | turning a submit description into the attributes a schedd expects (`Cmd`, `Args`, `Iwd`, `Out`, `Err`, `Requirements`, `+x509UserProxy*` …), which is what `condor_submit` does before it talks to the schedd. | medium; needs a real schedd to check against |
| **CEDAR transport** | HTCondor's own wire protocol: length-prefixed messages, then `DC_AUTHENTICATE` (Security Session negotiation: methods, session key exchange, MACs), then commands. **Undocumented outside the source.** | **large** — this is the research-scale part |
| **GSI authentication in CEDAR** | what a grid submission needs: the client authenticates with its X.509 proxy (HTCondor speaks GSI; `GSI_DAEMON`/`GSI` security methods), and a CE maps that identity to a submitter. | large, and entangled with the above |
| **QMGMT transactions** | how a job is actually created: `NEW_CLUSTER`, `SET_JOB_ATTR` per attribute, `COMMIT_TRANSACTION`, plus queries for status. | medium, once the transport works |
| **job router / CE policy** | the CE's own rules: which identities may submit directly, quotas, pilot-vs-user jobs, the `condor_ce` mapping. | not a client problem, but it decides whether *anything* can be submitted |

So the project is staged, and only the first stages can be verified today:

1. **classads + submit description** (this repository's first code): pure Python,
   100 % covered, no network. Everything later depends on it.
2. **job ad assembly**: pure Python, checked against a real schedd's own view of a
   job (`condor_q -long`) before it is trusted.
3. **CEDAR + GSI**: spec-first, from captured bytes of a real exchange (as
   `xrddirac`'s DISET work is doing), against a CE that accepts the client's
   identity.
4. **QMGMT**: create, poll, remove.
5. **xrdwms backend**: `-b htcondor:<ce>`, so a job goes through xrdwms's journal,
   retries and outputs like any other backend.

## What is needed before stage 3 can start

* **the CE**: a hostname and port (HTCondor-CE's schedd is usually 9619, its
  collector 9618) that (a) runs HTCondor, not ARC, (b) supports LHCb, and (c)
  accepts *this* identity for a direct submission rather than only pilots;
* **one captured exchange**: `condor_submit` talking to that CE, recorded with
  `SSLKEYLOGFILE`-equivalent means for HTCondor — its SECMAN session keys are not
  TLS's, so the capture has to be taken on the *CE* side or at the
  client's socket layer (a `strace`-free way in: run `condor_submit` under a
  Python shim that wraps its socket calls, exactly as `diset-capture hook` does
  for DIRAC).

## What this repository is *not*

* not a server: nothing here accepts submissions;
* not a replacement for `condor_submit` on a machine that has HTCondor — the
  point is the machine that does not;
* not a pilot: it submits *user* jobs, and the CE's policy decides whether it
  may.

## A first attempt against IC-HEP (UK HTCondor-CE for LHCb), 2026-11-11

`ceprod00.grid.hep.ph.ic.ac.uk` (146.179.233.210) is LHCb's HTCondor-CE at IC-HEP.
What was established, from a macOS host and from an AlmaLinux 9 container with an
HTCondor 23.0.28 client, the LHCb X.509 proxy and the IGTF CAs:

| probe | result |
| --- | --- |
| TCP 9619 (schedd) | **open** |
| TCP 9618 (collector) | **closed** from here |
| `condor_q -name ceprod00…` (23.0.28, `SEC_CLIENT_AUTHENTICATION_METHODS=GSI`) | fails: it asks the collector, which is not reachable — "the condor_collector is not responding" |
| `condor_q -direct schedd` with a hand-written `SCHEDD_ADDRESS_FILE` | refused: HTCondor wants an address file a *running* schedd writes, so the stock client cannot be pointed at 9619 from outside |
| connect, send nothing | held open, silent |
| any guessed frame (empty, 4-byte int, 8-byte pair, a text command) | **immediate connection reset** |

Two conclusions, both useful:

1. **A stock HTCondor client cannot submit to this CE from outside**, because
   discovery goes through the collector and that port is firewalled. A client that
   speaks 9619 directly, with the address supplied out of band, does something
   `condor_submit` here cannot — which is precisely `xrdhtcondor`'s premise.
2. **The protocol cannot be derived by probing.** Every wrong guess is answered by
   the same reset, so there is no signal to learn from and no error text to read.
   The CEDAR layer therefore needs a **capture of a working exchange**, which has
   to be taken where a real `condor_submit` can reach that schedd:

   * on the CE itself (`tcpdump -i any -s0 -w cedar.pcap tcp port 9619` while
     `condor_submit` runs) — CEDAR is plaintext unless `ENCRYPTION_METHODS` says
     otherwise, so the capture is readable as it stands; or
   * on any GridPP node where `condor_q -name ceprod00…` works (the collector is
     reachable from inside), recording the same way.

   That capture is the input stage 3 needs; nothing before it can be written
   honestly.

## What is now implemented, and what is left (2026-11-11, later)

Implemented, tested to 100 % and green: `classads`, `submitfile`, `cedar`
(framing, deframer, greeting - byte-identical to the capture, wire classads,
SECMAN request/reply) and `crypto` (HKDF-SHA256 key, IV scheme, AES-256-GCM
packet layout, handshake-digest AAD). 69 tests, six modules, no gaps.

The remaining path is now fully specified, each step with its source:

1. **`ReliSock`'s scalar encoding** (`condor_io/stream.cpp`): `code(int)` is a
   big-endian `int`, sign-extended to `INT_SIZE` bytes; `code(string)` is the
   bytes and a NUL, with no length prefix - the frame's length already bounds it.
   The ciphertext's *padding* to a multiple of the block size (or not) has to be
   read out of `reli_sock.cpp` before the packet layout is final.
2. **The SECMAN client flow** (`condor_io/condor_secman.cpp`): greeting, the
   request classad with our ECDH public key, the reply's key, then the session
   frames the capture shows - the 8-byte `\x02`/`\x01` exchanges and the identity
   (`tester\0`) - and the two SHA-256 handshake digests over everything sent and
   received before the first encrypted packet.
3. **QMGMT** (`condor_schedd.V6/qmgmt_constants.h`, `qmgmt_receivers.cpp`):
   `CONDOR_InitializeConnection` 10001, `CONDOR_NewCluster` 10002,
   `CONDOR_SetAttribute` 10006 (`code(cluster)`, `code(proc)`, `code(value)`,
   `code(name)`, `end_of_message()`, reply `code(rval)`, `code(terrno)`),
   `CONDOR_CommitTransactionNoFlags` 10007, `CONDOR_GetJobAd` 10018. The second
   connection in the capture announces `Command = 421` and a `Nonce`: that is the
   SECMAN session for the QMGMT command, which is how a submit reaches a schedd.
4. **GSI authentication** (`condor_io/condor_auth_x509.cpp`): what a grid CE
   requires, over the same SECMAN negotiation (`AuthMethods = "GSI"`), presenting
   `X509_USER_PROXY` - the parts `xrdsec.gsi` already knows how to drive.
5. **The front end**: `xrdhtcondor submit/status/get` and the `xrdwms`
   `htcondor:<schedd>` backend, which is then mechanical.

## The honest size of "fully compatible" (measured 2026-11-11)

The three layers left are not small, and the source says how small they are not:

| what | reference size | what it contains |
| --- | --- | --- |
| SECMAN client | `condor_secman.cpp`: 4,268 lines, a `SecManStartCommand` state machine of 40 methods across two classes | the start/resume/continue states, session caching and reuse, the `Enact`/session handshake, the two handshake digests, fallback to another method, and the failure codes a client has to distinguish |
| GSI authentication | `condor_auth_x509` (the X.509 method's own file, ~1.5k lines) | the certificate exchange, the signed nonce, the proxy chain and the mapping onto a submitter - overlapping `xrdsec.gsi`, which already implements the GSS/CEDAR half of a grid login |
| QMGMT | `qmgmt_receivers.cpp` 1,254 lines (server side) plus the send stubs | 28 opcodes, their argument orders, transactions and their error semantics |
| monitoring | `condor_q`'s paths | job ads, history, and the `GetJobAd`/`GetAllJobsByConstraint` encodings |

So "fully compatible" is a multi-week implementation with a live schedd in the
loop - not a finishing sprint. What that loop is worth: the *local personal
Condor* answers every mistake with a reason (unlike a CE, which resets), so each
of the layers above can be built and checked there, one opcode at a time, before
anything is pointed at IC-HEP.

The order that lands value soonest:

1. **CLAIMTOBE first, not GSI**: SECMAN with `AuthMethods = "CLAIMTOBE"` against
   the local container proves the framing, the session frames, the key
   derivation, the encryption and the QMGMT submit - everything except the
   certificate exchange. GSI then replaces one method name in the negotiation.
2. **`NewCluster` + `SetAttribute` + `CommitTransaction`** is a submission; that
   is the first milestone worth calling "submits jobs".
3. **`GetJobAd`** makes status tracking, and then `get` is a sandbox fetch.
4. The `xrdwms` backend last, because by then it is the third caller of the same
   client.

## xrdhtcondor against IC-HEP, 2026-11-11: how far the layers reach

`ceprod00.grid.hep.ph.ic.ac.uk:9619` (LHCb's HTCondor-CE at IC-HEP), with the
modules that exist today:

| step | result |
| --- | --- |
| TCP connect | accepted |
| **our greeting** (`cedar.greeting("schedd")`, the 47 bytes the capture shows) | **accepted**: the CE holds the connection and answers nothing, where arbitrary bytes get an immediate reset |
| our SECMAN request (GSI offered, a fresh P-256 key, the capture's preamble) | **no answer** (10 s timeout) |
| the same with no preamble | no answer |

So the two layers below the negotiation are right against a production
HTCondor-CE as well as against the local schedd: the CE recognises its own
framing and waits for a proper session request. What it does not do is answer
ours, and the difference is the one piece the capture has not given up yet - the
**preamble in front of the classad** (`00 00 00 00 00 00 00 ea 6a 00 00 00 00 00
00 00 12 4e 65 67 …`), which is the SECMAN command's own encoding: an 8-byte
integer (234) and a 1-byte something before the first attribute name, whose
meaning lives in `SecManStartCommand`.

Two ways to settle it, both cheap next to the state machine itself:

* decode it from the local capture by trying the two plausibilities - an
  `INT_SIZE`-padded `code(int)` (4 or 8 bytes) followed by the classad, or a
  second framing layer - and check which one the local schedd answers;
* read `SecManStartCommand::startCommand` (`condor_secman.cpp`) for the
  message it builds, which is where that preamble comes from.

Until then the honest statement is: `xrdhtcondor` speaks CEDAR's framing to a
real HTCondor-CE; it does not yet complete a security negotiation, and therefore
does not yet submit.

## Two findings from the local negotiation loop (2026-11-11, latest)

1. **`SecurityRequest` never sent `CryptoMethods`** — the real client's message
   carries `CryptoMethods = "AES,BLOWFISH,3DES"` and ours omitted it. Fixed; the
   builder now sends it.
2. **The message preamble is a per-message header, not a constant.** By
   measuring every plaintext segment of the capture, the bytes in front of the
   classad are `[u32 0][u32 234][0x6a][7 bytes][len(first name)+1]` in one
   message and `[u32 0][u32 len(first name)+1]` in another, with the segments
   alternating direction - so the fixtures mix the client's messages and the
   server's, and a preamble copied from one is not the other's. That is why our
   request, sent with a *reply's* preamble, gets silence from a schedd that
   answers the captured bytes immediately (503 bytes, `Authentication = YES`,
   `Enact = YES`).

The route from here is short and definite: read `SecManStartCommand`'s message
construction in `condor_secman.cpp` (the 40-method class this project already
located) and reproduce the header from it, rather than inferring it from
captures that alternate direction. Everything below the header - framing,
classads, the session key, the AES-GCM packet layout - is implemented and
tested, and the local schedd already answers a real client's bytes through this
code.

## Where the negotiation stands (latest)

With the command and classad confirmed against the capture, the request works:

- a personal HTCondor answers ours with `Authentication = "YES"`,
  `Enact = "YES"`, `AuthMethods = "CLAIMTOBE"`;
- our encoder writes a real client's message back byte-for-byte (671 bytes,
  asserted in `tests/test_cedar.py`);
- `DC_AUTHENTICATE` is 60010 (`DC_BASE` 60000 + 10), not the 234 that had been
  guessed from the capture's hex, and `putClassAd` writes the attribute count in
  front of the pairs and two empty strings after them.

Against IC-HEP's HTCondor-CE (`ceprod00.grid.hep.ph.ic.ac.uk:9619`) the same
request, offering GSI, now gets the connection **closed** rather than a hang -
the CE parsed the message and refused it, which is what a CE does when it wants
the GSI method it advertises. That is the next piece: `GSI` over CEDAR, whose
handshake is Condor's own (its framing, its ECDH, its AES), not a copy of
XrdSec's.

### What IC-HEP actually refuses (measured)

`ceprod00.grid.hep.ph.ic.ac.uk:9619` closes the connection **immediately after the
greeting** - before any SECMAN message, with GSI, CLAIMTOBE, or no request at
all. So the refusal is not about the method: the CE's schedd sits behind
`condor_shared_port`, which routes by the sock name in the greeting, and an
unknown name is closed. Its collector port, 9618, which is where that name is
published, is closed to us. IC-HEP is therefore not reachable over CEDAR from
here for a transport reason, whatever we implement above it.

CERN's CEs are a better target: `condorce01/02.cern.ch` and `ce503.cern.ch`
have **both** 9618 and 9619 open, so the schedd's address - and its published
sock name - can be read from the collector, then negotiated with. That is the
next step, and it does not depend on IC-HEP's firewalling.

### The control experiment that settles it

A **local** shared-port schedd was greeted three ways:

| greeting names | daemon |
| --- | --- |
| the sock in its address file | **holds** |
| `schedd` | closes |
| the right sock, then a captured SECMAN request | **answers, 503 bytes** |

So a shared port closes on an unknown sock name, and IC-HEP behaves identically.
The sock name lives in the collector, and the collectors are not reachable:
IC-HEP's 9618 refuses connections, and CERN's `condorce01`/`ce503` on 9618 and
9619 **reset** the connection on every greeting variant tried (no sock, `schedd`,
`collector`) - a policy refusal, not a protocol one, since a real daemon reached
over loopback answers the same bytes.

Conclusion: CEDAR submission to these CEs is blocked by network policy from an
outside host, whatever the client implements. The LHCb submit paths that *do*
work from here are the ones already proven in this project - DIRAC (`xrdwms`,
`xrddirac`: completed jobs) and ARC (`xrdarc`: completed job) - and HTCondor can
be exercised end to end against a local schedd, which is what the tests do.

### IC-HEP is reachable - through the collector's sock name

The earlier conclusion was wrong, and the mistake was mine: that probe hand-built
the greeting with a fixed length byte, so every variant was malformed and the
resets proved nothing. Framed through `cedar.greeting()`, all three CEs **hold**
the connection when the greeting names `collector`:

| host | :9619 `sock=collector` | :9619 `sock=schedd` | :9618 |
| --- | --- | --- | --- |
| ceprod00.grid.hep.ph.ic.ac.uk | **held** | closed | refused |
| condorce01.cern.ch | **held** | closed | closed |
| ce503.cern.ch | **held** | closed | closed |

So a CE's shared port maps `collector`, and IC-HEP needs no reachable 9618 after
all. The schedd's own sock name is the one published by that collector.

What the collector will not do is answer anonymously: a SECMAN request offering
CLAIMTOBE gets nothing, and so does a bare `QUERY_SCHEDD_ADS`, on both CEs. A CE
collector restricts reads, so authentication comes first - on LHCb's CEs,
`SCITOKEN`, which is the WLCG JWT this project already acquires for XRootD. That
is the next piece of the client: SCITOKEN over CEDAR (then GSI), and the collector
then names the schedd so the greeting can reach it.

## What a real collector query looks like (captured inside the testbed pool)

A `tcpdump` of `condor_status -schedd` against the pool, with the pool negotiating
`Encryption = "NO"`, gives the whole exchange in the clear:

- the SECMAN request for a query carries `Command = 6`, `Subsystem = "TOOL"`,
  `Integrity`/`Encryption`/`Authentication` all `OPTIONAL`,
  `OutgoingNegotiation = "PREFERRED"`, `TrustDomain`, `ServerPid`, a session
  lease and an ECDH key - eighteen attributes in all;
- the reply has three parts: the SECMAN classad, a result classad
  (`ReturnCode = "AUTHORIZED"`, `Sid = "cm:40:1794443770:19"`, `ValidCommands`,
  `User`), then the **ads themselves**;
- the query classad is `TargetType = "Scheduler"`, `MyType = "Query"`,
  `Requirements = true`, `Projection = "Machine MyAddress Name"`.

Two things we got wrong and now know:

1. `SecurityRequest` sent `OutgoingNegotiation` as the *integrity* value, and
   defaulted every verdict to `REQUIRED`. A real client sends `PREFERRED` and
   `OPTIONAL`, and a server reconciles against what it is given. Both fixed.
2. Our query returns **zero ads**, and the collector's own D_FULLDEBUG says why:
   `matched=0; skipped=1; filter_private_attrs=1`,
   `User = unauthenticated@unmapped`. An unauthenticated query is not shown the
   schedd's ad. Authentication has to come first: CLAIMTOBE clients send their
   claimed identity straight after the negotiation (`code(int 1)` then the name
   with a NUL, as segment 5 of the capture shows). Our attempt at that frame is
   refused and resets the connection, so its exact shape - or the point in the
   exchange at which it belongs - is still open.

## QMGMT, mapped out against the pool

`qmgmt_constants.h` gives the opcodes and `qmgmt_receivers.cpp` the arguments:

| command | opcode | message |
| --- | --- | --- |
| `InitializeConnection` | 10001 | the opcode alone |
| `NewCluster` | 10002 | the opcode alone; reply is the new cluster id |
| `SetAttribute` | 10006 | cluster, proc, **value**, **name** |
| `CommitTransactionNoFlags` | 10007 | the opcode alone |

Each is its own message, and each reply is `code(int rval)`, plus `code(int
terrno)` when it failed. A cluster-level attribute uses proc `-1`, and strings go
on the wire with their NUL. `QMGMT_BASE` is 1110, so the queue manager's own
command is `QMGMT_WRITE_CMD` 1112 - the value our `SecurityRequest` defaults to.

Against the pool, `InitializeConnection` answers `0`, so the framing is right.
`NewCluster` then closes the connection, and the schedd says why in one line:

```
DC_AUTHENTICATE: authentication of <...> did not result in a valid mapped user
name, which is required for this command (1112 QMGMT_WRITE_CMD), so aborting.
```

A query can be anonymous; a *write* cannot. So the last piece is not QMGMT at all,
it is authentication: asking for `Authentication = "REQUIRED"` moves the failure
on to `AUTHENTICATE:1002:Failure performing handshake`, which is where the
CLAIMTOBE identity (`code(int 1)` then the name with a NUL, segment 5 of the
capture) has to be sent correctly - and where GSI would go for a real CE.

## Why QMGMT needs the session layer (captured from a real submit)

A `tcpdump` of `condor_submit` inside the pool shows the whole shape:

- the client offers `Authentication = "OPTIONAL"`, `Integrity = "OPTIONAL"`,
  `OutgoingNegotiation = "PREFERRED"`, with a trust domain, a lease and an ECDH key;
- the schedd answers `Authentication = "YES"`, `Encryption = "YES"`,
  `Integrity = "YES"`, `Enact = "YES"` - **it enacts an encrypted session**;
- everything after that message is ciphertext: the CLAIMTOBE identity, the
  `InitializeConnection`, `NewCluster`, every `SetAttribute`, and the commit.

So there is no plaintext QMGMT to imitate, and our plaintext identity frame was
refused because the schedd had already moved to the session. `crypto.py` already
implements the cipher (HKDF-SHA256 with the `"htcondor"` salt and `"keygen"` info
over the ECDH secret, AES-256-GCM, the IV counters, the handshake-digest AAD), and
the session framing is now the one piece left before a job can be submitted by our
own messages: `probe_session.py` is where that is being settled, against this pool.

### The session's wire form, read out of `reli_sock.cpp`

`ReliSock::put` under AES-GCM writes `[type byte][uint32 length][ciphertext][tag]`
- and **nothing else**. The handshake digests are not transmitted: they are
**running SHA-256 digests of the connection's own traffic**, kept in
`m_send_md_ctx` and `m_recv_md_ctx`, and used only as additional authenticated
data. On the first encrypted packet the AAD is

    SHA256(traffic sent so far) || SHA256(traffic received so far) || header   (69 bytes)

and on every later packet it is just the five-byte header. Our field name for
them, "handshake", is a misnomer: they are the connection's own history.

`probe_session.py` sent 64 zero bytes on the wire before the header, which is
wrong twice over - those bytes are not sent at all, and their content must be the
real digests. That is the correction to make before the session can open.

## The CLAIMTOBE handshake, from a captured submit

After the SECMAN classads, authentication is a handful of plain integers, and the
capture shows both directions:

| direction | messages |
| --- | --- |
| client | `int 2`, then `int 1` and its user name with a NUL |
| schedd | `int 2`, `int 1`, `int 0` |

`Condor_Auth_Claim::authenticate` (`condor_auth_claim.cpp`) explains the second
client message: `code(retval = 1)` then `code(myUser)`, and the user is
`my_username()` unless `SEC_CLAIMTOBE_USER` says otherwise. Ours had been sending
the identity *without* the preceding `int 2`, which is why the schedd logged
`AUTHENTICATE: handshake failed!` and closed.

With the order right, the pool accepts the claim - `the schedd answered [2, 1, 0]`
and `accepted the claim as 'root'`. That is a mapped user, which is exactly what
`QMGMT_WRITE_CMD` demands.

What follows is the enacted session: a plaintext `InitializeConnection` after the
handshake gets nothing at all, and the capture's next frames are ciphertext. So the
session cipher is the last piece of a submit, and everything before it - greeting,
negotiation, identity, mapped user - now works against a real schedd.

## The session AAD, solved against the daemon's own log

`D_NETWORK` makes HTCondor print the AAD it expects, so the rule can be *read out*
rather than guessed. A probe recorded exactly what it sent, the schedd logged what
it expected, and one candidate matched byte for byte:

    sha256 of every frame from the SECMAN request onward, headers included
    (the greeting is not part of it)

| candidate | digest |
| --- | --- |
| all bytes sent | `8aa01f91…` |
| payloads only | `34065932…` |
| **frames after the greeting** | **`bb2ad9cf…` — the daemon's own value** |

The same log line confirmed the framing independently: its trailing five bytes
were `01 00 00 00 28` - type 1 and a length of 40, which is exactly the sealed size
of an 8-byte `code(int)` with a 16-byte IV and a 16-byte tag. So the packet shape
and its length are right, the AAD rule is now known exactly, and what is left is
the key and IV derivation inside the session.

### Two more corrections the pool forced

1. **The IV's head is replaced, not added to.** `Condor_Crypt_AESGCM::encrypt`
   copies the packet counter into the IV's first four bytes and keeps the base
   IV's tail (`memcpy(iv, &ctr_encoded, 4); memcpy(iv + 4, base + 4, 12)`), so the
   first packet's IV begins with four zero bytes. Our codec added the counter to
   the base IV's own head, which changes every packet's IV.
2. **The daemon chooses the cipher, and it does not choose AES by default.** When
   the request offered `AES,BLOWFISH,3DES`, the schedd's session info said
   `CryptoMethods = "BLOWFISH"` - we would have been sealing AES-GCM packets into a
   session that agreed to Blowfish. Offering only `AES` makes the negotiation say
   `CryptoMethods = "AES"`, matching what `crypto.py` implements.

With the digest rule measured, the framing confirmed and the cipher pinned, the
next failure can be attributed: the sealed `InitializeConnection` still gets no
reply, so what remains is inside the key derivation (the ECDH secret through
`Condor_Crypt_Base::hkdf`, salt `"htcondor"`, info `"keygen"`, which is what
`condor_secman.cpp` calls) or the digest contexts' starting point.

### What is *not* the fault (checked in the source, one by one)

- **The key exchange**: `SecMan::EncodePubkey` base64s `i2d_PublicKey`, and the
  capture's value decodes to a 65-byte uncompressed point, which is what our client
  sends and what `from_encoded_point` reads. `o2i_ECPublicKey`/`d2i_PublicKey`
  accept exactly that.
- **The derivation**: `Condor_Crypt_Base::hkdf` calls
  `Condor_Auth_Passwd::hkdf` with salt `"htcondor"` and info `"keygen"`, which is
  `EVP_PKEY_HKDF` with SHA-256 - the same construction `crypto.py` implements.
- **The cipher**: pinned to `AES` by asking for `AES` alone, so the session says
  `CryptoMethods = "AES"` and `EVP_aes_256_gcm()` applies.
- **The AAD and the framing**: measured from `D_NETWORK`, byte-exactly.

So the sealed `InitializeConnection` failing is none of the obvious things. The two
candidates left are *when* the digest contexts start (the measured match fixes the
client's own digest, not the daemon's half of the AAD) and the session binding: a
queue-manager connection may have to name the `Sid` the negotiation returned before
its commands are honoured.

### Both halves of the AAD, measured

The first half was solved first: the daemon's `Expecting AAD` line named a digest
that matched `sha256` of every frame the client had sent since the SECMAN request,
headers included. The second half was solved the same way, by recording what the
daemon sent and hashing candidates:

| candidate (daemon's own traffic) | digest |
| --- | --- |
| all received | `9e480d71…` |
| SECMAN reply only | `41396a98…` |
| payloads only | `3650f0de…` |
| **every frame before the current one** | **`6dc5163d…` — the daemon's value** |

So the AAD is

    sha256(every frame sent before this one) || sha256(every frame received before this one)

with frames counted from the SECMAN request onward (the greeting is not part of
it) and the packet being sealed excluded. That is a running digest finalised at
the moment of sending, which is exactly what `m_send_md_ctx`/`m_recv_md_ctx` do.

One more observation from the recording: during the handshake the daemon sends five
frames, and the last of them (376 bytes) is already ciphertext - it opens the
session from its side. A client that treats it as a stray message and ignores it
will never see the state the daemon expects.

### A negative result worth keeping

The daemon's last handshake frame (376 bytes) does **not** open under the key
derived from the SECMAN ECDH exchange, with any of the AAD variants tried - the
digests in either order, its own half alone, or none at all - and with any of the
derivations tried (HKDF-32 with the documented salt and info, the salt and info
swapped, `sha256(secret)`, `sha256(secret + "htcondor")`, and the raw secret).

So that frame is either keyed by something other than the SECMAN secret, or it is
not a session packet at all. The next thing to establish is what it *is* - its
length (376 - 32 = 344 bytes of ciphertext under the assumed layout) and the fact
that it arrives before any client session packet are the only clues.

Everything else is settled and measured: the CLAIMTOBE handshake, the packet
framing, the cipher choice, the IV rule, and both halves of the AAD.

## IC-HEP, measured (what it will and will not do)

`ceprod00.grid.hep.ph.ic.ac.uk:9619` is reachable, and its shared port maps the
sock name `collector`: a greeting naming it is held reliably, three times in a row,
where `schedd` is closed immediately.

The collector then answers our SECMAN request - 497 bytes, `Enact = "YES"`,
`TrustDomain = "users.htcondor.org"` - but with an **empty `AuthMethodsList`**, and
the query that follows gets no reply at all. Offering each method in turn says why:

| offered | `AuthMethods` in the reply |
| --- | --- |
| `CLAIMTOBE` | `""` |
| `GSI` | `""` |
| `SCITOKEN` | `""` |
| `GSI,SCITOKEN` | `""` |
| `FS` | `"FS"` |

So this CE accepts only a **filesystem** identity - the local HTCondor users of
`users.htcondor.org` - and no grid identity at all. That is not a client-side
problem: a GSI proxy or a WLCG token cannot authenticate here, so the schedd's sock
name cannot be read, so the schedd cannot be reached and no job can be submitted
over CEDAR. IC-HEP's LHCb access is through its ARC/AREX and DIRAC endpoints, which
this project already uses successfully.

## A survey of LHCb-relevant HTCondor-CEs, from outside

Eight reachable CEs, each greeted with `sock=collector` and offered `GSI,SCITOKEN`
in a SECMAN request for a collector query:

| CE | trust domain | reply | `AuthMethods` |
| --- | --- | --- | --- |
| condorce01.cern.ch | cern.ch | 486 B | `""` |
| ce503.cern.ch | cern.ch | 486 B | `""` |
| ce15.pic.es | pic.es | 756 B | `""` |
| htcondor-ce-1-kit.gridka.de | ce.gridka.de | 491 B | `""` |
| htc01.ppgrid1.rhul.ac.uk | cm.cluster | 756 B | `""` |
| lcgce02.phy.bris.ac.uk | phy.bris.ac.uk | 791 B | `""` |
| hepcondor.ph.liv.ac.uk | ph.liv.ac.uk | 493 B | `""` |
| ceprod00.grid.hep.ph.ic.ac.uk | users.htcondor.org | 497 B | `""` |

Every one of them negotiates: `Enact = "YES"`, `Encryption = "YES"`,
`CryptoMethods = "AES"`, and an ECDH key comes back (CERN's run HTCondor 25.0.14,
so the pool's 23.0.28 is not the issue). Not one selects a method, whether the
request says `OPTIONAL` or `REQUIRED`, and whatever is offered - `GSI`, `SCITOKEN`,
both, or `CLAIMTOBE`.

So the wall is not reachability and not framing: these CEs will not authenticate an
outside client at all, which means the collector never names its schedd and the
schedd is never reachable. Submitting to one of them over CEDAR requires the CE to
be configured to accept GSI or SCITOKEN from outside, which is a site decision.
