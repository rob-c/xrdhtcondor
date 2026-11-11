"""``xrdhtcondor``: the parts that need no server, as a command.

Two things a submission agent must get right before it speaks to a schedd, and
both can be checked offline:

* ``xrdhtcondor ad FILE`` - is this a classad, and what does it say? Expressions
  are shown as the text they are, because an expression is not a value;
* ``xrdhtcondor jobs FILE`` - what jobs does this ``.sub`` ask for? The queue is
  expanded, macros substituted, and anything this cannot know is named.

Every refusal says which line it came from, so a description can be fixed
without guessing.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import Any

import xrdcore.report as output
from xrdcore.report import Parser

from ._version import __version__
from .classads import ClassadError, Expression, format_ad, parse_ad
from .submitfile import SubmitDescription, SubmitFileError

PROGRAM = "xrdhtcondor"
OK = 0
ERROR = 1


def main(argv: Sequence[str] | None = None) -> int:
    """Parse the command line and run one thing, inside xrdcore's report."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    return output.run_cli(PROGRAM, arguments, lambda: _run(arguments))


def _run(arguments: Sequence[str]) -> int:
    """The command, with the report already chosen from ``arguments``."""
    parser = _parser()
    args = parser.parse_args(list(arguments))
    try:
        handler: Any = args.handler
        return int(handler(args))
    except (ClassadError, SubmitFileError) as refused:
        return _fail(str(refused))


def _parser() -> Parser:
    """The command line: two subcommands, the report flags at both levels."""
    parser = Parser(prog=PROGRAM, description="HTCondor submissions, offline first.")
    parser.add_argument("-V", "--version", action="version", version=f"{PROGRAM} {__version__}")
    output.flags(parser)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    ad = commands.add_parser("ad", help="parse a classad file and show what it says")
    _common(ad)
    ad.add_argument("path", metavar="FILE")
    ad.set_defaults(handler=_ad)
    jobs = commands.add_parser("jobs", help="expand a .sub description into the jobs it makes")
    _common(jobs)
    jobs.add_argument("path", metavar="FILE")
    jobs.add_argument("--cluster", type=int, default=None, metavar="N", help="fill $(Cluster)")
    jobs.add_argument("-v", "--verbose", action="store_true", help="each job's attributes")
    jobs.set_defaults(handler=_jobs)
    return parser


def _common(parser: Parser) -> None:
    """What every subcommand takes: the report flags, and quiet."""
    output.flags(parser)
    parser.add_argument("-q", "--quiet", action="store_true", help="print nothing but errors")


def _read(path: str) -> str:
    """The file's text, with a refusal a person can act on."""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise SubmitFileError(f"cannot read {path}: {exc}") from exc


def _ad(args: Any) -> int:
    """``ad``: the attributes, normalised; expressions as their text."""
    attributes = parse_ad(_read(args.path))
    for name, value in attributes.items():
        output.record("attribute", name=name, value=_shown(value))
    if not args.quiet:
        output.message(format_ad(attributes))
    return OK


def _jobs(args: Any) -> int:
    """``jobs``: what the queue statements mean, one line per job."""
    description = SubmitDescription.parse(_read(args.path))
    made = description.jobs(cluster=args.cluster)
    for job in made:
        output.record(
            "job",
            process=job.process,
            attributes={name: _shown(value) for name, value in job.attributes.items()},
        )
    if not args.quiet:
        output.message(
            f"{description.count} job(s) from {len(description.queues)} queue statement(s)\n"
        )
        if args.verbose:
            for job in made:
                output.message(f"--- job {job.process}\n")
                output.message(format_ad(job.attributes))
    return OK


def _shown(value: Any) -> str:
    """A value for a report: an expression as its text, anything else as a classad writes it."""
    from .classads import format_value

    return value.text if isinstance(value, Expression) else format_value(value)


def _fail(said: str) -> int:
    """One line on stderr, and the failure's exit code."""
    output.record("error", message=said)
    print(f"{PROGRAM}: {said}", file=sys.stderr)
    return ERROR
