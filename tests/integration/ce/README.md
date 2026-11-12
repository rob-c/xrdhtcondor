# A real HTCondor-CE client, to submit to a grid CE with an X.509 proxy

The point of this directory is to answer one question with evidence rather than
theory: **can a genuine HTCondor client with a real LHCb proxy submit to an LHCb
HTCondor-CE from this network?**

## What is needed

| piece | where it comes from |
| --- | --- |
| `Dockerfile.gsi90` | AlmaLinux 8 + HTCondor **9.0.17**, the last line with GSI |
| proxy | `~/.x509up` on the VM: valid, LHCb, `/lhcb/Role=NULL/Capability=NULL` |
| trust anchors | `~/grid-ca/certificates` (906 entries, including CERN-GridCA) |

Run `--platform linux/amd64`: **the arm64 HTCondor builds have no GSI at all**
(their method list is FS and CLAIMTOBE, and asking for GSI makes the client report
`SECMAN:2002:...the security policy is invalid`). Even the el9 x86_64 23.0 and
10.0.9 builds have dropped GSI; 9.0.17 is the newest that still performs it.

## What it does

```sh
./submit_and_capture.sh condorce01.cern.ch     # after placing the proxy and CAs
```

The script copies the proxy into the container, runs `condor_status`/`condor_submit`
against the CE with GSI, and records the traffic to `ce.pcap` for reading.

## What happened (measured)

- **`condorce01.cern.ch:9618`** - the port a client uses by default - answers
  nothing: the client sends its 491-byte SECMAN request (offering
  `AuthMethods = "GSI"`) and the capture ends there. Filtered from this network.
- **`condorce01.cern.ch:9619?sock=collector`** - reachable, CEDAR accepted, and the
  client attempts the GSI handshake, which fails:
  `AUTHENTICATE:1002:Failure performing handshake`.
- The same at `ce503.cern.ch`, `ce15.pic.es`, `htcondor-ce-1-kit.gridka.de`,
  `htc01.ppgrid1.rhul.ac.uk`, `lcgce02.phy.bris.ac.uk`, `hepcondor.ph.liv.ac.uk`.

The credential is not the problem: with the same proxy and CAs,
`xrd-fs ls root://eosuser.cern.ch//eos/user/r/rcurrie` authenticates and lists the
area over GSI.

## What the capture is still good for

The real client's SECMAN request is a reference for ours: it offers
`AuthMethods = "GSI"`, `Authentication = "REQUIRED"`, `OutgoingNegotiation =
"REQUIRED"`, `Enact = "NO"`, and carries `ServerPid` and `TrustDomain`. Everything
above that - the handshake itself - never happens against these CEs.
