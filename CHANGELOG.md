# Changelog

## 0.1.0 - unreleased

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
