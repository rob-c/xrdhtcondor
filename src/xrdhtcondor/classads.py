"""HTCondor's classads: the data language every job attribute is written in.

A *new classad* is a list of ``name = value`` assignments, one per line, and its
values are strings (double-quoted, with ``\\"`` and ``\\\\`` escaped), integers,
reals, ``true``/``false``, ``undefined``, lists (``{1, "a"}``), nested classads
(``[a = 1, b = 2]``) - and **expressions**, which are not data at all but the
language's own syntax: ``Requirements = (OpSys == "LINUX_7")``.

This module parses and writes that, and it is deliberately conservative: an
expression is kept as the text it was, in :class:`Expression`, and never
evaluated or translated. A submission agent does not need to *understand* an
expression to carry it to a schedd - and pretending to evaluate one would be a
guess dressed as an answer.

What is refused, by name, rather than half-read: ``@="..."`` multi-line strings,
``error``, and any value that is neither a literal this knows nor plausibly an
expression (a bare word, say - HTCondor would read that as an attribute name,
which a client may not invent).
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, NoReturn

__all__ = [
    "ClassadError",
    "Expression",
    "format_ad",
    "format_value",
    "parse_ad",
    "parse_value",
]

#: A value as this module sees it: a literal it understood, or an expression text.
Value = Any


class ClassadError(ValueError):
    """Something that is not a classad, or not one this will write."""


@dataclass(frozen=True, slots=True)
class Expression:
    """An expression, kept as the text it was - never evaluated, never rewritten."""

    text: str

    def __str__(self) -> str:
        """The expression as HTCondor wrote it."""
        return self.text


#: Names a value may not be: they are syntax, not identifiers.
RESERVED = frozenset({"true", "false", "undefined", "error"})

#: What a name may look like: an attribute, or a `+Custom` one.
_BARE = re.compile(r"\+?[A-Za-z_][A-Za-z0-9_]*$")

#: A real, in the forms a classad writes one.
_REAL = re.compile(r"[+-]?(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?")

#: An integer, with the sign HTCondor prints.
_INTEGER = re.compile(r"[+-]?\d+")


def parse_ad(text: str) -> dict[str, Value]:
    """The attributes of a new classad, in the order the text gives them.

    Blank lines and ``#`` comments are skipped; a line that is not
    ``name = value`` is a :class:`ClassadError` naming the line number, because
    a silently ignored attribute is a job that runs without part of its
    description.
    """
    found: dict[str, Value] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, _separator, raw = _split_assignment(stripped, number)
        if name in found:
            raise ClassadError(f"line {number}: {name!r} is assigned twice")
        found[name] = parse_value(raw, where=f"line {number}")
    return found


def _split_assignment(line: str, number: int) -> tuple[str, str, str]:
    """``(name, '=', value text)`` for one line, or a refusal naming it."""
    name, separator, raw = line.partition("=")
    name = name.strip()
    if not separator or not name:
        raise ClassadError(f"line {number}: not 'name = value': {line!r}")
    if not _BARE.match(name):
        raise ClassadError(f"line {number}: not an attribute name: {name!r}")
    return name, separator, raw.strip()


def parse_value(text: str, *, where: str = "") -> Value:
    """One value: a literal this understands, or an :class:`Expression` with the text.

    ``where`` names the place, for a refusal a person can find.
    """
    reader = _Reader(text.strip(), where)
    value = reader.value()
    reader.finish()
    return value


class _Reader:
    """A cursor over one value's text."""

    def __init__(self, text: str, where: str) -> None:
        self.text = text
        self.where = f"{where}: " if where else ""
        self.at = 0

    def finish(self) -> None:
        """Refuse text left over after the value."""
        if self.text[self.at :].strip():
            self.refuse(f"{self.text[self.at :]!r} is left over after the value")

    def refuse(self, said: str) -> NoReturn:
        """Raise, naming where this value was."""
        raise ClassadError(f"{self.where}{said}")

    def value(self) -> Value:
        """The value at the cursor."""
        if self.at >= len(self.text):
            self.refuse("an empty value")
        head = self.text[self.at]
        if head == '"':
            return self.string()
        if head in "{[":
            return self.list_like()
        return self.atom()

    def string(self) -> str:
        """A double-quoted string, with its escapes."""
        out: list[str] = []
        at = self.at + 1
        while at < len(self.text):
            char = self.text[at]
            if char == "\\":
                if at + 1 >= len(self.text):
                    self.refuse("a string that ends in a backslash")
                following = self.text[at + 1]
                out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(following, following))
                at += 2
                continue
            if char == '"':
                self.at = at + 1
                return "".join(out)
            out.append(char)
            at += 1
        self.refuse("a string with no closing quote")

    def list_like(self) -> Value:
        """``{...}``, a list.

        ``[...]``, a nested *classad literal*, is refused by name: its member
        syntax (assignments separated by ``,`` or ``;``) is grammar this has not
        verified against a real parser, and a half-read ad is a job description
        with an attribute missing. Keeping the ad flat costs nothing - a job's
        attributes are flat.
        """
        if self.text[self.at] == "[":
            self.refuse("a nested classad literal is not supported: keep the ad flat")
        closing = "}"
        self.at += 1
        items: list[Value] = []
        while True:
            self.skip_space()
            if self.at >= len(self.text):
                self.refuse(f"a value with no closing {closing!r}")
            if self.text[self.at] == closing:
                self.at += 1
                break
            items.append(self.value())
            self.skip_space()
            if self.at < len(self.text) and self.text[self.at] == ",":
                self.at += 1
                continue
            self.skip_space()
            if self.at < len(self.text) and self.text[self.at] == closing:
                self.at += 1
                break
            self.refuse(f"expected ',' or {closing!r} in a list")
        return items

    def skip_space(self) -> None:
        """Move past spaces."""
        while self.at < len(self.text) and self.text[self.at].isspace():
            self.at += 1

    def atom(self) -> Value:
        """A number, a boolean, ``undefined``, or an expression - never a bare word."""
        rest = self.text[self.at :]
        lowered = rest.lower()
        for word, value in (("true", True), ("false", False), ("undefined", None)):
            if lowered == word:
                self.at = len(self.text)
                return value
        if lowered.startswith("error"):
            self.refuse("'error' is not a value this carries")
        if _INTEGER.fullmatch(rest):
            self.at = len(self.text)
            return int(rest)
        if _REAL.fullmatch(rest):
            self.at = len(self.text)
            number = float(rest)
            if math.isinf(number) or math.isnan(number):
                self.refuse(f"{rest!r} is not a finite real")
            return number
        if _BARE.fullmatch(rest):
            self.refuse(
                f"{rest!r} alone is an attribute *name*, not a value; quote it as a"
                " string if that is what was meant"
            )
        self.at = len(self.text)
        return Expression(rest)


def format_value(value: Value) -> str:
    """``value`` as a classad writes it: quoted strings, braces, brackets, expressions."""
    if value is None:
        return "undefined"
    if value is True or value is False:
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isinf(value) or math.isnan(value):
            raise ClassadError(f"{value!r} is not a finite real")
        return repr(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'"{escaped}"'
    if isinstance(value, Expression):
        return value.text
    if isinstance(value, Mapping):
        return (
            "[" + ", ".join(f"{name} = {format_value(item)}" for name, item in value.items()) + "]"
        )
    if isinstance(value, Sequence):
        return "{" + ", ".join(format_value(item) for item in value) + "}"
    raise ClassadError(f"cannot be written as a classad value: {type(value).__name__}")


def format_ad(attributes: Mapping[str, Value]) -> str:
    """The attributes as a new classad, one assignment per line, in order."""
    return "".join(f"{name} = {format_value(value)}\n" for name, value in attributes.items())
