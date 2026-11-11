"""The submit description: attributes, macros, and the jobs a queue statement means."""

from __future__ import annotations

import pytest

from xrdhtcondor.classads import Expression
from xrdhtcondor.submitfile import SubmitDescription, SubmitFileError

TWO_JOBS = """# two jobs that print their index
executable = /bin/echo
arguments = "hello $(Process)"
output = job.$(Process).out
+ProjectName = "lhcb"
queue 2
"""


def test_a_description_expands_into_the_jobs_its_queue_asks_for() -> None:
    description = SubmitDescription.parse(TWO_JOBS)
    assert description.count == 2 and len(description.queues) == 1
    first, second = description.jobs()
    assert first.process == 0 and second.process == 1
    assert first.attributes["arguments"] == "hello 0"
    assert second.attributes["arguments"] == "hello 1"
    assert first.attributes["+ProjectName"] == "lhcb"
    assert isinstance(first.attributes["output"], Expression)
    assert first.attributes["output"].text == "job.0.out"


def test_the_cluster_macro_is_filled_in_only_when_it_is_known() -> None:
    text = 'executable = /bin/echo\narguments = "c$(Cluster).$(Process)"\nqueue 1\n'
    description = SubmitDescription.parse(text)
    assert description.jobs()[0].attributes["arguments"] == "c$(Cluster).0"
    assert description.jobs(cluster=7)[0].attributes["arguments"] == "c7.0"


def test_a_queue_with_arguments_feeds_the_positional_macros() -> None:
    text = 'executable = /bin/echo\narguments = "$(1) and $(Item)"\nqueue 2 a.root b.root\n'
    made = SubmitDescription.parse(text).jobs()
    assert [job.attributes["arguments"] for job in made] == ["a.root and a.root"] * 2


def test_a_macro_this_cannot_know_is_refused_rather_than_carried() -> None:
    description = SubmitDescription.parse('arguments = "$(Year)"\nqueue 1\n')
    with pytest.raises(SubmitFileError, match=r"\$\(Year\) is not a macro"):
        description.jobs()


def test_a_positional_macro_with_no_argument_is_refused() -> None:
    description = SubmitDescription.parse('arguments = "$(2)"\nqueue 1 only-one\n')
    with pytest.raises(SubmitFileError, match=r"\$\(2\) has no argument"):
        description.jobs()


@pytest.mark.parametrize(
    ("text", "refusal"),
    [
        ("executable = /bin/echo\n", "no 'queue' statement"),
        ("executable = /bin/echo\nqueue 1\narguments = x\n", "attributes after 'queue'"),
        ("executable = /bin/echo\nexecutable = /bin/true\nqueue 1\n", "assigned twice"),
        ("not an attribute\nqueue 1\n", "not 'name = value'"),
        ("1bad = x\nqueue 1\n", "not a submit attribute name"),
        ("executable = error\nqueue 1\n", "not a value"),
        ("executable = /bin/echo\nqueue 1 1.0e999\n", "finite real"),
    ],
    ids=[
        "no-queue",
        "after-queue",
        "twice",
        "no-assignment",
        "bad-name",
        "bad-value",
        "bad-argument",
    ],
)
def test_a_description_that_is_not_one_is_refused(text: str, refusal: str) -> None:
    with pytest.raises(SubmitFileError, match=refusal):
        SubmitDescription.parse(text)


def test_several_queue_statements_make_a_job_each() -> None:
    text = 'executable = /bin/echo\nqueue 2\nqueue 3 "x"\n'
    description = SubmitDescription.parse(text)
    assert description.count == 5
    assert [job.process for job in description.jobs()] == [0, 1, 2, 3, 4]


def test_a_list_and_a_plain_attribute_are_expanded_too() -> None:
    text = 'executable = /bin/echo\nEnv = {"JOB=$(Process)"}\nRequestCpus = 1\nqueue 1\n'
    job = SubmitDescription.parse(text).jobs()[0]
    assert job.attributes["Env"] == ["JOB=0"] and job.attributes["RequestCpus"] == 1
