"""The canary reporter across runs: coverage of the expected matrix, partial re-runs,
ordering against issues filed by other runs, and honest closing comments.

- a failed lane names every expected leg with no usable result, whatever other legs recorded;
- a re-run mixes attempts: an earlier pass covers its leg and closes only when the lane is
  green, an earlier failure is stale, a later attempt than the report's is rejected;
- a pass closes only issues filed strictly before it was recorded, and a result from more
  than a minute in the future is rejected;
- a close says superseded, not passed, when it did not retest the combination the title
  names.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
from collections.abc import Sequence

import pytest

from tests.canary_report_support import (
    RUN_URL,
    STALE_OCTOBER,
    T0,
    Gh,
    Report,
    close_comments,
    created_titles,
    load_script,
    numbers,
    record,
    report,
    unrecorded_body,
)


@pytest.fixture(scope="module")
def script() -> Report:
    return load_script()


@pytest.fixture(autouse=True)
def no_workflow_files(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)


def test_every_missing_leg_is_named_even_when_another_leg_recorded_a_failure(
    script: Report, tmp_path: pathlib.Path
) -> None:
    record(script, tmp_path, lane="head", version="1.6.30", outcome="failure", harness="1.6.30")
    record(script, tmp_path, lane="head", version="1.7.1", outcome="success", harness="1.7.1")
    gh = Gh({})

    report(
        script,
        tmp_path,
        gh,
        jobs={"head": "failure", "wheel": "success"},
        versions=["1.6.30", "1.7.1", "1.7.5", "latest"],
    )

    assert "canary: conformance failure against better-auth@1.6.30" in created_titles(gh)
    body = unrecorded_body(gh, "head")
    assert "better-auth@1.7.5" in body
    assert "better-auth@latest" in body
    assert "1.6.30" not in body
    assert "better-auth@1.7.1" not in body
    assert RUN_URL in body


def test_a_missing_leg_comments_on_the_open_unrecorded_issue(
    script: Report, tmp_path: pathlib.Path
) -> None:
    gh = Gh({40: "canary: a published-wheel leg failed without recording its result"})

    report(
        script,
        tmp_path,
        gh,
        jobs={"head": "success", "wheel": "failure"},
        versions=["1.7.5", "1.7.6"],
    )

    (comment,) = gh.of("comment")
    assert comment[2] == "40"
    assert "better-auth@1.7.5" in comment[comment.index("--body") + 1]
    assert gh.of("create") == []


@pytest.mark.parametrize("lane_result", ["cancelled", "skipped"])
def test_a_cancelled_or_skipped_lane_with_missing_legs_stays_silent(
    script: Report, tmp_path: pathlib.Path, lane_result: str
) -> None:
    gh = Gh({})

    report(
        script,
        tmp_path,
        gh,
        jobs={"head": lane_result, "wheel": "success"},
        versions=["1.7.1", "1.7.5"],
    )

    assert gh.calls == []


def test_a_result_for_a_version_the_matrix_does_not_list_is_rejected(
    script: Report, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    record(script, tmp_path, lane="head", version="1.7.1", outcome="success", harness="1.7.1")
    gh = Gh(STALE_OCTOBER)

    assert report(script, tmp_path, gh, versions=["1.6.30"]) == 1

    assert gh.of("close") == []
    assert "::error::" in capsys.readouterr().err


@pytest.mark.parametrize(
    "versions",
    ["not json", "[]", '["1.7.1", "next"]', '["1.7.1", "1.7.1"]', '{"a": 1}', '["1.7.1\\n"]'],
    ids=["not-json", "empty", "unknown-tag", "duplicate", "object", "newline"],
)
def test_an_implausible_expected_matrix_is_refused_before_any_call(
    script: Report, tmp_path: pathlib.Path, versions: str
) -> None:
    calls: list[list[str]] = []

    def gh(argv: Sequence[str]) -> tuple[int, str]:
        calls.append(list(argv))
        return 0, "[]"

    argv = [
        "report", "--results-dir", str(tmp_path), "--run-url", RUN_URL,
        "--upstream-watch", "failure", "--head-job", "success", "--wheel-job", "success",
        "--expected-versions", versions, "--run-attempt", "1",
    ]  # fmt: skip

    with pytest.raises(SystemExit) as exited:
        script.main(argv, gh=gh)

    assert exited.value.code == 1
    assert calls == []


def test_the_canary_label_is_ensured_before_an_issue_is_created(
    script: Report, tmp_path: pathlib.Path
) -> None:
    gh = Gh({})

    report(script, tmp_path, gh, watch="failure")

    verbs = [call[:2] for call in gh.calls]
    assert verbs.index(["label", "create"]) < verbs.index(["issue", "create"])


# --- report: re-runs ------------------------------------------------------------------------
#
# "Re-run failed jobs" re-runs only the failed legs (and the report job); a leg that passed keeps
# its earlier attempt's artifact. download-artifact then hands the report a mix of attempts.


@pytest.mark.parametrize("attempt", ["0", "-1", "x", "", "1.5"])
def test_record_refuses_an_implausible_attempt(
    script: Report, tmp_path: pathlib.Path, attempt: str
) -> None:
    with pytest.raises(SystemExit) as exited:
        record(script, tmp_path, lane="head", version="1.7.1", outcome="success", attempt=attempt)

    assert exited.value.code == 1
    assert list(tmp_path.rglob("canary-result.json")) == []


def test_record_writes_its_attempt(script: Report, tmp_path: pathlib.Path) -> None:
    record(script, tmp_path, lane="head", version="1.7.1", outcome="success", attempt="3")

    written = json.loads(next(tmp_path.rglob("canary-result.json")).read_text(encoding="utf-8"))
    assert written["attempt"] == "3"


def test_an_earlier_pass_closes_when_its_lane_is_green(
    script: Report, tmp_path: pathlib.Path
) -> None:
    """Lane success on attempt 2 means every leg's latest attempt passed, this one included."""
    record(script, tmp_path, lane="head", version="1.7.1", outcome="success", harness="1.7.1")
    gh = Gh(STALE_OCTOBER)

    report(script, tmp_path, gh, attempt="2")

    assert numbers(gh.of("close")) == ["95"]


def test_an_earlier_pass_covers_its_leg_but_closes_nothing_when_the_lane_failed(
    script: Report, tmp_path: pathlib.Path
) -> None:
    record(script, tmp_path, lane="head", version="1.7.1", outcome="success", harness="1.7.1")
    gh = Gh(STALE_OCTOBER)

    report(
        script,
        tmp_path,
        gh,
        attempt="2",
        jobs={"head": "failure", "wheel": "success"},
        versions=["1.7.1", "1.7.5"],
    )

    assert gh.of("close") == []
    body = unrecorded_body(gh, "head")
    assert "better-auth@1.7.5" in body
    assert "better-auth@1.7.1" not in body


def test_an_earlier_failure_is_stale_files_nothing_and_counts_as_missing(
    script: Report, tmp_path: pathlib.Path
) -> None:
    """A failed leg is always re-run; its attempt-1 file only means attempt 2 left nothing."""
    record(script, tmp_path, lane="head", version="1.7.1", outcome="failure", harness="1.7.1")
    gh = Gh(STALE_OCTOBER)

    report(
        script,
        tmp_path,
        gh,
        attempt="2",
        jobs={"head": "failure", "wheel": "success"},
        versions=["1.7.1"],
    )

    assert gh.of("comment") == []
    assert created_titles(gh) == [
        "canary: a HEAD conformance leg failed without recording its result"
    ]
    assert "better-auth@1.7.1" in unrecorded_body(gh, "head")


def test_a_current_attempt_result_is_used_as_before(script: Report, tmp_path: pathlib.Path) -> None:
    record(
        script, tmp_path, lane="head", version="1.7.1", outcome="failure", harness="1.7.1",
        attempt="2",
    )  # fmt: skip
    gh = Gh(STALE_OCTOBER)

    report(script, tmp_path, gh, attempt="2", jobs={"head": "failure", "wheel": "success"})

    assert numbers(gh.of("comment")) == ["95"]


def test_a_result_from_a_later_attempt_than_the_report_is_rejected(
    script: Report, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    record(
        script, tmp_path, lane="head", version="1.7.1", outcome="success", harness="1.7.1",
        attempt="3",
    )  # fmt: skip
    gh = Gh(STALE_OCTOBER)

    assert report(script, tmp_path, gh, attempt="2") == 1

    assert gh.of("close") == []
    assert "::error::" in capsys.readouterr().err


@pytest.mark.parametrize("attempt", ["0", "x", ""])
def test_report_refuses_an_implausible_attempt(
    script: Report, tmp_path: pathlib.Path, attempt: str
) -> None:
    gh = Gh({})

    with pytest.raises(SystemExit) as exited:
        report(script, tmp_path, gh, watch="failure", attempt=attempt)

    assert exited.value.code == 1
    assert gh.calls == []


# --- report: a pass closes only what was filed before it ------------------------------------


def test_record_writes_when_it_recorded_in_utc(script: Report, tmp_path: pathlib.Path) -> None:
    record(script, tmp_path, lane="head", version="1.7.1", outcome="success", now=T0)

    written = json.loads(next(tmp_path.rglob("canary-result.json")).read_text(encoding="utf-8"))
    assert written["recorded_at"] == "2026-11-24T12:00:00Z"


def test_a_pass_leaves_open_an_issue_filed_after_it_was_recorded(
    script: Report, tmp_path: pathlib.Path
) -> None:
    """Another run may file after this leg passed; this report must not close that issue."""
    record(
        script, tmp_path, lane="head", version="1.7.1", outcome="success", harness="1.7.1", now=T0
    )
    gh = Gh(
        {
            95: "canary: conformance failure against better-auth@1.7.1",
            101: "canary: HEAD conformance lane cannot run against better-auth@1.7.1",
            102: "canary: HEAD conformance lane cannot run against better-auth@1.7.1 ",
        },
        created={95: "2026-11-24T11:00:00Z", 101: "2026-11-24T12:05:00Z"},
    )

    report(script, tmp_path, gh, now=T0 + dt.timedelta(minutes=10))

    assert numbers(gh.of("close")) == ["95"]


def test_an_issue_filed_in_the_same_second_as_the_pass_stays_open(
    script: Report, tmp_path: pathlib.Path
) -> None:
    record(
        script, tmp_path, lane="head", version="1.7.1", outcome="success", harness="1.7.1", now=T0
    )
    gh = Gh(
        {95: "canary: conformance failure against better-auth@1.7.1"},
        created={95: "2026-11-24T12:00:00Z"},
    )

    report(script, tmp_path, gh, now=T0 + dt.timedelta(minutes=10))

    assert gh.of("close") == []


@pytest.mark.parametrize(
    ("ahead", "accepted"),
    [(dt.timedelta(seconds=60), True), (dt.timedelta(seconds=61), False)],
    ids=["within-skew", "future"],
)
def test_a_result_recorded_in_the_future_is_rejected_beyond_a_minute_of_skew(
    script: Report,
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    ahead: dt.timedelta,
    accepted: bool,
) -> None:
    """Runner clocks are NTP-synced but not identical; a minute absorbs that, not more."""
    record(
        script,
        tmp_path,
        lane="head",
        version="1.7.1",
        outcome="success",
        harness="1.7.1",
        now=T0 + ahead,
    )
    gh = Gh(STALE_OCTOBER)

    code = report(script, tmp_path, gh, now=T0)

    assert code == (0 if accepted else 1)
    assert numbers(gh.of("close")) == (["95"] if accepted else [])
    assert ("::error::" in capsys.readouterr().err) is not accepted


@pytest.mark.parametrize("created", ["", "yesterday", "2026-10-15T21:44:29"], ids=str)
def test_an_issue_list_without_a_usable_creation_time_acts_on_nothing(
    script: Report, tmp_path: pathlib.Path, created: str
) -> None:
    record(script, tmp_path, lane="head", version="1.7.1", outcome="success", harness="1.7.1")
    gh = Gh(STALE_OCTOBER, created={95: created})

    with pytest.raises(SystemExit):
        report(script, tmp_path, gh)

    assert gh.calls == []


# --- report: recovered versus superseded ----------------------------------------------------


def test_a_close_says_passed_only_when_the_titled_combination_was_retested(
    script: Report, tmp_path: pathlib.Path
) -> None:
    """The project supports only the latest release, so an old wheel's or an old `latest`'s
    issue closes either way - but the comment must not claim a retest that did not happen."""
    record(
        script, tmp_path, lane="wheel", version="latest", outcome="success", harness="1.8.1",
        wheel="0.3.0",
    )  # fmt: skip
    gh = Gh(
        {
            10: "canary: published wheel 0.2.0 fails conformance against better-auth@latest (1.8.1)",
            11: "canary: published wheel 0.3.0 fails conformance against better-auth@latest (1.8.0)",
            12: "canary: published wheel 0.3.0 fails conformance against better-auth@latest (1.8.1)",
            13: "canary: published-wheel lane cannot run against better-auth@latest (unresolved)",
            14: "canary: published-wheel lane cannot run against better-auth@latest (1.8.0)",
        }
    )

    report(script, tmp_path, gh)

    comments = close_comments(gh)
    assert sorted(comments) == ["10", "11", "12", "13", "14"]
    for number in ("10", "11", "14"):
        text = comments[number].lower()
        assert "superseded" in text, number
        assert "not retested" in text, number
        assert "better-auth 1.8.1" in comments[number], number
    assert "wheel 0.2.0" in comments["10"]
    assert "wheel 0.3.0" in comments["10"]
    assert "better-auth 1.8.0" in comments["11"]
    for number in ("12", "13"):
        assert "superseded" not in comments[number].lower(), number
        assert "passed" in comments[number], number


def test_a_pinned_leg_always_recovers_what_it_titles(
    script: Report, tmp_path: pathlib.Path
) -> None:
    record(script, tmp_path, lane="head", version="1.7.1", outcome="success", harness="1.7.1")
    gh = Gh(STALE_OCTOBER)

    report(script, tmp_path, gh)

    comment = close_comments(gh)["95"]
    assert "passed" in comment
    assert "superseded" not in comment.lower()


def test_superseding_never_widens_which_issues_a_leg_owns(
    script: Report, tmp_path: pathlib.Path
) -> None:
    record(
        script, tmp_path, lane="wheel", version="1.7.1", outcome="success", harness="1.7.1",
        wheel="0.3.0",
    )  # fmt: skip
    gh = Gh(
        {
            20: "canary: published wheel 0.2.0 fails conformance against better-auth@1.7.10",
            21: "canary: published wheel 0.2.0 fails conformance against better-auth@1.7.1 (1.7.1)x",
            22: "canary: published wheel 0.2.0 fails conformance against better-auth@1.7.1",
        }
    )

    report(script, tmp_path, gh)

    assert sorted(close_comments(gh)) == ["22"]
    assert "superseded" in close_comments(gh)["22"].lower()
