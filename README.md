# xrdhtcondor

A pure-Python, LGPL **HTCondor submission agent**: push a job to an HTCondor-CE,
follow it to completion, collect its results — no HTCondor libraries, no
`condor_submit`.

**Status: the offline layers are being built.** The protocol work (CEDAR, GSI,
QMGMT) is specification-first and needs a captured exchange from a real CE; see
[`docs/DESIGN.md`](docs/DESIGN.md) for the staged plan and exactly what it needs.

What exists today is the part that needs no server:

* `xrdhtcondor.classads` — HTCondor's data language: parse and write ads, with
  the quoting rules, lists, nested ads, `undefined`, and expressions refused
  rather than guessed at;
* `xrdhtcondor.submitfile` — the `.sub` submit description: attributes, `+`
  custom attributes, macros, and `queue` statements expanded into the jobs they
  mean.

Both are needed by every later layer, and both are testable to the last branch.
