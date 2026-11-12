"""`xrdhtcondor` as a command: the two subcommands, and their refusals."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from xrdhtcondor.cli import main

SUBMIT = 'executable = /bin/echo\narguments = "hi $(Process)"\nqueue 2\n'


def _file(tmp_path: Path, text: str, name: str = "job.sub") -> Path:
    path = tmp_path / name
    path.write_text(text)
    return path


def test_jobs_says_how_many_and_what_each_is(tmp_path: Path, capsys: Any) -> None:
    assert main(["jobs", str(_file(tmp_path, SUBMIT)), "-v"]) == 0
    said = capsys.readouterr().out
    assert "2 job(s) from 1 queue statement(s)" in said
    assert 'arguments = "hi 0"' in said and 'arguments = "hi 1"' in said


def test_jobs_as_json_is_one_record_per_job(tmp_path: Path, capsys: Any) -> None:
    assert main(["jobs", str(_file(tmp_path, SUBMIT)), "--json", "-q"]) == 0
    report = json.loads(capsys.readouterr().out)
    jobs = [record for record in report["records"] if record["kind"] == "job"]
    assert [job["process"] for job in jobs] == [0, 1]


def test_ad_shows_the_attributes_and_an_expression_as_text(tmp_path: Path, capsys: Any) -> None:
    path = _file(tmp_path, 'Cmd = "/bin/echo"\nRequirements = (Arch == "X86_64")\n', "ad.txt")
    assert main(["ad", str(path)]) == 0
    said = capsys.readouterr().out
    assert 'Cmd = "/bin/echo"' in said and "Requirements = (Arch" in said


def test_ad_can_fill_the_cluster(tmp_path: Path, capsys: Any) -> None:
    path = _file(tmp_path, 'arguments = "c$(Cluster)"\nqueue 1\n', "s.sub")
    assert main(["jobs", "--cluster", "12", str(path), "-v"]) == 0
    assert 'arguments = "c12"' in capsys.readouterr().out


@pytest.mark.parametrize("command", ["ad", "jobs"])
def test_a_description_that_cannot_be_read_is_one_line(
    tmp_path: Path, command: str, capsys: Any
) -> None:
    assert main([command, str(tmp_path / "gone")]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_a_refusal_exits_nonzero_with_the_line_number(tmp_path: Path, capsys: Any) -> None:
    path = _file(tmp_path, "executable = /bin/echo\nnonsense\nqueue 1\n")
    assert main(["jobs", str(path)]) == 1
    assert "line 2" in capsys.readouterr().err


def test_the_version_is_printed() -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["--version"])
    assert stopped.value.code == 0


def test_auth_lists_the_tokens_it_found(tmp_path: Any, monkeypatch: Any) -> None:
    """``--list`` says what is available before any daemon is troubled."""
    from xrdhtcondor import scitokens

    token = "header." + "eyJzdWIiOiJyY3VycmllIiwiaXNzIjoiaHR0cHM6Ly9pYW0ifQ" + ".sig"
    monkeypatch.setattr(
        scitokens, "candidates", lambda *a, **k: [scitokens.Token("p", token, {"sub": "rcurrie"})]
    )
    assert main(["auth", "--host", "ce.example", "--list"]) == 0


def test_auth_reports_a_refusal(tmp_path: Any, monkeypatch: Any) -> None:
    """A daemon that will not take the token is a failure, said in its own words."""
    from xrdhtcondor import scitokens

    def refused(*_a: Any, **_k: Any) -> None:
        raise scitokens.SciTokenError("the daemon did not offer SCITOKENS")

    monkeypatch.setattr(scitokens, "authenticate_daemon", refused)
    assert main(["auth", "--host", "ce.example"]) == 1


def test_auth_says_nothing_when_the_token_file_is_empty(tmp_path: Any) -> None:
    """A named token file with no token is refused before connecting."""
    empty = tmp_path / "empty"
    empty.write_text("\n")
    assert main(["auth", "--host", "ce.example", "--token", str(empty)]) == 1


def test_auth_accepts_an_identity_the_daemon_took(monkeypatch: Any) -> None:
    """The whole point: a token the daemon accepts is reported as accepted."""
    from xrdhtcondor import scitokens

    token = "header.eyJzdWIiOiJyY3VycmllIn0.sig"
    monkeypatch.setattr(
        scitokens, "candidates", lambda *a, **k: [scitokens.Token("p", token, {"sub": "r"})]
    )
    monkeypatch.setattr(
        scitokens,
        "authenticate_daemon",
        lambda *a, **k: scitokens.Verdict(
            negotiated={
                "AuthMethods": "SCITOKENS",
                "Authentication": "YES",
                "TrustDomain": "cern.ch",
            },
            status=0,
        ),
    )
    assert main(["auth", "--host", "ce.example", "--token", "/dev/null"]) == 0
