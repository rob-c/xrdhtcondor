"""The ``.sub`` submit description: what a person writes, expanded into the jobs it means.

A submit description is a list of ``name = value`` attributes (with ``+Name`` for
a custom classad attribute), a ``queue`` statement that says how many jobs to
make of it, and macros - ``$(Cluster)``, ``$(Process)``, and for a queue with
arguments the positional ``$(1)``, ``$(2)`` and ``$(Item)``.

This module parses that and *expands* the queue into one attribute set per job,
which is the step every submission agent has to do before a schedd is asked for
a cluster id: ``$(Process)`` becomes the job's index, ``$(Cluster)`` stays as it
is until the schedd says what the cluster is (or is filled in when the caller
knows it), and any other macro is refused by name rather than passed on as
unexpanded text a job would carry into its own arguments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .classads import ClassadError, Expression, Value, format_value, parse_value

__all__ = ["JobInput", "SubmitDescription", "SubmitFileError"]

#: A macro, ``$(Name)`` or ``$(Name+1)``; only the names below are expanded.
_MACRO = re.compile(r"\$\(([A-Za-z][A-Za-z0-9_]*|\d+)([+-]\d+)?\)")

#: Macros this expands; anything else is refused, so a job never carries one unexpanded.
KNOWN_MACROS = frozenset({"Cluster", "Process", "Item"})


class SubmitFileError(ValueError):
    """A submit description that is not one, or not one this will expand."""


@dataclass(frozen=True, slots=True)
class JobInput:
    """One job's attributes, after expansion: the ``queue`` statement's i-th job."""

    #: The job's ``Process`` index, from 0.
    process: int
    #: Its attributes: submit attributes and ``+Custom`` ones alike, macro-free.
    attributes: dict[str, Value] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SubmitDescription:
    """A parsed ``.sub`` file: its attributes and the queue statements that follow them."""

    #: ``name -> value``, in the order written; ``+Name`` keys keep their ``+``.
    attributes: dict[str, Value] = field(default_factory=dict)
    #: The jobs the ``queue`` statements ask for, in order: ``count`` and any arguments.
    queues: tuple[tuple[int, tuple[Value, ...]], ...] = ()

    @property
    def count(self) -> int:
        """How many jobs the description submits."""
        return sum(count for count, _arguments in self.queues)

    def jobs(self, *, cluster: int | None = None) -> list[JobInput]:
        """The jobs this description makes, in order, with their macros expanded.

        ``cluster`` fills ``$(Cluster)`` in when the caller already knows it; left
        out, that macro stays literal because only a schedd can assign it.
        """
        made: list[JobInput] = []
        process = 0
        for count, arguments in self.queues:
            for index in range(count):
                made.append(
                    JobInput(
                        process=process,
                        attributes={
                            name: self._expanded(
                                value,
                                process=process,
                                cluster=cluster,
                                arguments=arguments,
                                index=index,
                            )
                            for name, value in self.attributes.items()
                        },
                    )
                )
                process += 1
        return made

    def _expanded(
        self,
        value: Value,
        *,
        process: int,
        cluster: int | None,
        arguments: tuple[Value, ...],
        index: int,
    ) -> Value:
        """``value`` with its macros substituted for this job."""
        if isinstance(value, str):
            return _substitute(value, process=process, cluster=cluster, arguments=arguments)
        if isinstance(value, list):
            return [
                self._expanded(
                    item, process=process, cluster=cluster, arguments=arguments, index=index
                )
                for item in value
            ]
        if isinstance(value, Expression):
            text = _substitute(value.text, process=process, cluster=cluster, arguments=arguments)
            return Expression(text)
        return value

    @classmethod
    def parse(cls, text: str) -> SubmitDescription:
        """``text`` as a description; a refusal names the line it came from."""
        attributes: dict[str, Value] = {}
        queues: list[tuple[int, tuple[Value, ...]]] = []
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.split("#", 1)[0].strip() if not line.lstrip().startswith("#") else ""
            if not stripped:
                continue
            if stripped.lower().startswith("queue"):
                queues.append(_queue(stripped, number))
                continue
            if queues:
                raise SubmitFileError(
                    f"line {number}: attributes after 'queue' would belong to no job"
                )
            name, _separator, raw = _assignment(stripped, number)
            if name in attributes:
                raise SubmitFileError(f"line {number}: {name!r} is assigned twice")
            try:
                attributes[name] = parse_value(raw, where=f"line {number}")
            except ClassadError as refused:
                raise SubmitFileError(str(refused)) from refused
        if not queues:
            raise SubmitFileError("no 'queue' statement: this description submits nothing")
        return cls(attributes=attributes, queues=tuple(queues))


def _assignment(line: str, number: int) -> tuple[str, str, str]:
    """``(name, '=', value text)``, with ``+`` allowed on a custom attribute's name."""
    name, separator, raw = line.partition("=")
    name = name.strip()
    if not separator or not name:
        raise SubmitFileError(f"line {number}: not 'name = value': {line!r}")
    if not re.fullmatch(r"\+?[A-Za-z_][A-Za-z0-9_]*", name):
        raise SubmitFileError(f"line {number}: not a submit attribute name: {name!r}")
    return name, separator, raw.strip()


def _queue(line: str, number: int) -> tuple[int, tuple[Value, ...]]:
    """``queue [N] [args…]``: how many jobs, and the itemdata arguments."""
    words = line.split()[1:]
    count = 1
    if words and words[0].isdigit():
        count = int(words[0])
        words = words[1:]
    arguments: list[Value] = []
    for word in words:
        try:
            arguments.append(parse_value(word, where=f"line {number}"))
        except ClassadError as refused:
            raise SubmitFileError(str(refused)) from refused
    return count, tuple(arguments)


def _substitute(
    text: str, *, process: int, cluster: int | None, arguments: tuple[Value, ...]
) -> str:
    """Every macro in ``text`` replaced, or a refusal naming the one this cannot know."""

    def replace(match: re.Match[str]) -> str:
        return _expanded(match, process=process, cluster=cluster, arguments=arguments)

    return _MACRO.sub(replace, text)


def _expanded(
    match: re.Match[str], *, process: int, cluster: int | None, arguments: tuple[Value, ...]
) -> str:
    """One macro's replacement."""
    name, offset = match.group(1), match.group(2)
    if name.isdigit():
        return _positional(name, arguments)
    if name in {"Process", "Cluster"}:
        known = process if name == "Process" else cluster
        return _numbered(known, offset) if known is not None else match.group(0)
    if name == "Item":
        return str(format_value(arguments[0] if arguments else ""))
    raise SubmitFileError(
        f"$({name}) is not a macro this expands: known are {', '.join(sorted(KNOWN_MACROS))}"
    )


def _positional(name: str, arguments: tuple[Value, ...]) -> str:
    """``$(1)``: the queue's n-th argument."""
    position = int(name)
    if not 1 <= position <= len(arguments):
        raise SubmitFileError(f"$({name}) has no argument: the queue gave {len(arguments)}")
    return str(format_value(arguments[position - 1]))


def _numbered(value: int, offset: str | None) -> str:
    """``$(Process)``, ``$(Cluster)`` and their ``$(Process+1)`` spelling."""
    return str(value + (int(offset) if offset else 0))
