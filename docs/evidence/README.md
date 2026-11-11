# Evidence

Captures and decoded transcripts of real HTCondor conversations, so that a claim
in [`../DESIGN.md`](../DESIGN.md) can be checked against bytes rather than
believed. The pattern is `xrddirac`'s: the capture is the evidence, the transcript
is what a reviewer reads, and each file says where it came from and what it pins.

| bundle | what it is |
| --- | --- |
| [`20261111-local-submit.*`](20261111-local-submit.pcap) | one `condor_submit` of a two-job description to a *personal* HTCondor 23.0.28 in an AlmaLinux 9 container, captured on `any` (link type SLL). `CLAIMTOBE` security with encryption for the session, so the handshake is readable and the traffic after it is not. Establishes the framing and the SECMAN exchange; leaves the QMGMT payload for the next capture. |

## What the local capture pins (2026-11-11)

**Framing.** Every message is

```
0x01                    one byte: the message type (0x01 = command)
uint32 big-endian       the payload's length
payload                 that many bytes
```

Confirmed on two messages: `01 00 00 00 2f` + 47 bytes = 52 bytes on the wire,
and `01 00 00 02 9f` + 671 bytes = 676.

**The first message** is the shared-port target: a 4-byte zero, the schedd's sock
name (``K`` then `schedd_363_822f`), `SUBMIT`, and eight bytes of `0xff` — which is
why a guessed frame gets a reset: the server has to recognise its own name there.

**Classads on the wire** are *old classads*: `name = value.` pairs, each terminated
by a `.` and not by a newline, with values double-quoted. The SECMAN exchange names
its keys plainly:

```
client  NegotiatedSession = true. NewSession = "YES". AuthMethods = "CLAIMTOBE".
        Integrity = "REQUIRED". RemoteVersion = "$CondorVersion: 23.0.28 … $".
        TrustDomain = "50e246508b58". CryptoMethods = "AES,BLOWFISH,3DES".
        OutgoingNegotiation = "REQUIRED". SessionLease = 3600.
        Authentication = "REQUIRED". ConnectSinful = "<172.17.0.2:37973?addrs=…>".
        Encryption = "NEVER". Enact = "NO". ServerPid = 427. Command = 1112.
        Subsystem = "SUBMIT". SessionDuration = "60". ECDHPublicKey = "BPwl…"
server  ECDHPublicKey = "BD28…". Authentication = "YES". Encryption = "YES".
        NegotiatedSession = true. Integrity = "YES". AuthMethods = "CLAIMTOBE".
        AuthMethodsList = "CLAIMTOBE". CryptoMethods = "AES". CryptoMethodsList = ….
        SessionLease = 3600. SessionDuration = "60". Enact = "YES". TrustDomain = ….
```

So a submission is announced by `Command = 1112` and `Subsystem = "SUBMIT"`, the
session key is an ECDH public key each way (P-256, base64), and `Enact = YES` is the
server agreeing to a session.

**What is not yet readable:** with this configuration the server chose to encrypt
the session (`Encryption = "YES"`), so everything after the handshake — the QMGMT
create/set/commit that carries the job's attributes — is AES ciphertext. The next
capture must turn session encryption off on the *schedd* (`SEC_DEFAULT_ENCRYPTION`
did not take effect under `use role: personal`; try `SEC_DEFAULT_SESSION_ENCRYPTION`
or a plain config without the role) and take the exchange again, or be made where
a CE's own `condor_submit` runs.
