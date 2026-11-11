"""Classads: the quoting, the values, and the things that are refused rather than guessed."""

from __future__ import annotations

import pytest

from xrdhtcondor.classads import (
    ClassadError,
    Expression,
    format_ad,
    format_value,
    parse_ad,
    parse_value,
)

SAMPLE = """Cmd = "/bin/echo"
Args = "hello \\"world\\"\\n"
Requirements = (OpSys == "LINUX_7") && (Arch == "X86_64")
+ProjectName = "lhcb"
NiceUser = undefined
RequestCpus = 1
RequestMemory = 2048.5
Rank = -0.5
Real = 1.5e10
WantProxy = true
NotProxy = false
Env = {"A=1", "B=2"}
Empty = {}
"""


def test_a_job_ad_is_read_in_order_and_written_back_the_same() -> None:
    ad = parse_ad(SAMPLE)
    assert list(ad) == [
        "Cmd",
        "Args",
        "Requirements",
        "+ProjectName",
        "NiceUser",
        "RequestCpus",
        "RequestMemory",
        "Rank",
        "Real",
        "WantProxy",
        "NotProxy",
        "Env",
        "Empty",
    ]
    assert ad["Cmd"] == "/bin/echo" and ad["Args"] == 'hello "world"\n'
    assert isinstance(ad["Requirements"], Expression)
    assert ad["Requirements"].text == '(OpSys == "LINUX_7") && (Arch == "X86_64")'
    assert ad["+ProjectName"] == "lhcb" and ad["NiceUser"] is None
    assert ad["RequestCpus"] == 1 and ad["RequestMemory"] == 2048.5 and ad["Rank"] == -0.5
    assert ad["WantProxy"] is True and ad["NotProxy"] is False
    assert ad["Env"] == ["A=1", "B=2"] and ad["Empty"] == []
    assert parse_ad(format_ad(ad)) == ad


def test_a_string_is_written_with_its_escapes() -> None:
    assert format_value('a "quoted" \\ thing\n') == '"a \\"quoted\\" \\\\ thing\\n"'
    assert parse_value(format_value('a "x" \\ b')) == 'a "x" \\ b'


@pytest.mark.parametrize(
    ("text", "refusal"),
    [
        ("X = ", "an empty value"),
        ("X = Y", r"alone is an attribute"),
        ("X = error", r"'error' is not a value"),
        ('X = "open', "no closing quote"),
        ('X = "backslash\\', "ends in a backslash"),
        ("X = [a = 1]", "nested classad literal"),
        ("X = {1, 2", r"expected ',' or"),
        ("X = {1 2}", "expected ',' or"),
        ("not a line", "not 'name = value'"),
        ("1bad = 1", "not an attribute name"),
        ("X = 1\nX = 2", "assigned twice"),
        ("X = nan", r"alone is an attribute"),
    ],
    ids=[
        "empty",
        "bare-word",
        "error",
        "unclosed-string",
        "trailing-backslash",
        "nested",
        "unclosed-list",
        "list-separator",
        "no-assignment",
        "bad-name",
        "twice",
        "nan",
    ],
)
def test_what_is_not_a_value_is_refused_by_name(text: str, refusal: str) -> None:
    with pytest.raises(ClassadError, match=refusal):
        parse_ad(text)


def test_comments_and_blank_lines_are_skipped() -> None:
    assert parse_ad("# a comment\n\nX = 1\n") == {"X": 1}


def test_an_expression_is_never_rewritten() -> None:
    """An expression is the text it was: a client carries it, it does not evaluate it."""
    text = 'Requirements = TARGET.Arch == "X86_64" && (Memory > 1000)'
    value = parse_value(text.partition("=")[2].strip())
    assert (
        isinstance(value, Expression) and value.text == 'TARGET.Arch == "X86_64" && (Memory > 1000)'
    )
    assert str(value) == value.text


def test_what_has_no_classad_form_is_refused() -> None:
    with pytest.raises(ClassadError, match="cannot be written"):
        format_value(object())
    with pytest.raises(ClassadError, match="finite real"):
        format_value(float("inf"))


def test_a_refusal_names_the_line_it_came_from() -> None:
    with pytest.raises(ClassadError, match="line 2: not 'name = value'"):
        parse_ad("A = 1\nnonsense\n")


def test_text_after_a_value_is_refused() -> None:
    with pytest.raises(ClassadError, match="left over after the value"):
        parse_ad('X = "a" b')


def test_a_list_that_is_never_closed_is_refused() -> None:
    with pytest.raises(ClassadError, match="no closing"):
        parse_ad("X = {")


def test_a_real_too_large_for_a_double_is_refused() -> None:
    with pytest.raises(ClassadError, match="not a finite real"):
        parse_ad("X = 1.0e999")


def test_a_nested_ad_can_be_written_even_though_it_is_not_read() -> None:
    """Writing one is useful; reading one needs grammar this has not verified."""
    assert format_value({"a": 1, "b": "x"}) == '[a = 1, b = "x"]'
