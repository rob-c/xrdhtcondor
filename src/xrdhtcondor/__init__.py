"""A pure-Python HTCondor submission agent, in stages: the data layer first.

`docs/DESIGN.md` maps what an agent must speak - classads, the submit
description, job-ad assembly, the CEDAR protocol with GSI, QMGMT transactions -
and why the transport comes last: it is the part that has to be derived from a
captured exchange rather than from a guess.

What is here now needs no server:

* :mod:`xrdhtcondor.classads` - HTCondor's data language, with expressions kept
  as the text they are;
* :mod:`xrdhtcondor.submitfile` - the ``.sub`` description, expanded into the
  jobs its ``queue`` statements mean.
"""

from ._version import __version__

__all__ = ["__version__"]
