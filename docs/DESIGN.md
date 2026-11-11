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
