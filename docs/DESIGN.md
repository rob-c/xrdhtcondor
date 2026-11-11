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
