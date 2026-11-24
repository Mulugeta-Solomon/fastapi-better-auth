"""The canary's issue reporter: what each leg's outcome does to the `canary` issues on `main`.

`.github/scripts/canary_report.py` has two halves. `record` runs at the end of every matrix leg
and turns the conformance step's outcome into one of three verdicts - passed, conformance
failed (the pytest step ran and failed), could not run (something before pytest failed) - in a
small JSON file the leg uploads as an artifact. `report` runs in the one job that holds
`issues: write`: it reads every leg's file plus the upstream watch's job result and files,
comments on, or closes issues.

What this file pins, because each is a way the old inline shell masked a real failure:

- a failure whose issue is already open adds a comment instead of staying silent;
- a leg that passes closes its own open issues - including the four stale October issues
  (#95-#98), whose literal titles are tested here - and nobody else's (`1.7.1` never closes a
  `1.7.10` issue);
- a cancelled leg files nothing;
- a leg that failed without leaving a result still files something.

The leg files come from jobs that ran npm-installed upstream code and pytest, so `report`
treats them as untrusted: every field is validated before it can reach an issue title, and
`gh` is always called with an argument list, never through a shell.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol, cast

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "canary_report.py"
RUN_URL = "https://github.com/acme/bridge/actions/runs/123"
WATCH_TITLE = "canary: upstream release watch cannot read the npm registry"
STALE_OCTOBER = {
    95: "canary: conformance failure against better-auth@1.7.1",
    96: "canary: conformance failure against better-auth@1.6.30",
    97: "canary: published-wheel lane cannot run against better-auth@1.6.30",
    98: "canary: published-wheel lane cannot run against better-auth@1.7.1",
}
ALL_GREEN = {"head": "success", "wheel": "success"}


class Report(Protocol):
    def main(
        self,
        argv: Sequence[str] | None = None,
        gh: Callable[[Sequence[str]], tuple[int, str]] | None = None,
    ) -> int: ...


class Gh:
    """Stands in for the `gh` CLI: serves one issue list and records every other call."""

    def __init__(self, issues: Mapping[int, str], *, failing: str = "") -> None:
        self.issues = dict(issues)
        self.failing = failing
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str]) -> tuple[int, str]:
        call = list(argv)
        if call[:2] == ["issue", "list"]:
            listed = [{"number": n, "title": t} for n, t in self.issues.items()]
            return 0, json.dumps(listed)
        self.calls.append(call)
        if self.failing and call[:2] == ["issue", self.failing]:
            return 1, ""
        return 0, ""

    def of(self, verb: str) -> list[list[str]]:
        return [call for call in self.calls if call[:2] == ["issue", verb]]


@pytest.fixture(scope="module")
def script() -> Report:
    spec = importlib.util.spec_from_file_location("canary_report", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # `dataclasses` resolves string annotations through sys.modules[cls.__module__].
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(Report, module)


@pytest.fixture(autouse=True)
def no_workflow_files(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)


def record(
    script: Report,
    results: pathlib.Path,
    *,
    lane: str,
    version: str,
    outcome: str,
    harness: str = "",
    wheel: str = "",
) -> int:
    """One leg's `record` call, into its own subdirectory the way download-artifact lays it out."""
    out = results / f"canary-result-{lane}-{version}" / "canary-result.json"
    argv = [
        "record",
        "--lane",
        lane,
        "--matrix-version",
        version,
        "--harness-version",
        harness,
        "--wheel-version",
        wheel,
        "--conformance-outcome",
        outcome,
        "--out",
        str(out),
    ]
    return script.main(argv)


def report(
    script: Report,
    results: pathlib.Path,
    gh: Gh,
    *,
    watch: str = "skipped",
    jobs: Mapping[str, str] = ALL_GREEN,
) -> int:
    argv = [
        "report",
        "--results-dir",
        str(results),
        "--run-url",
        RUN_URL,
        "--upstream-watch",
        watch,
        "--head-job",
        jobs["head"],
        "--wheel-job",
        jobs["wheel"],
    ]
    return script.main(argv, gh=gh)


def created_titles(gh: Gh) -> list[str]:
    return [call[call.index("--title") + 1] for call in gh.of("create")]


def numbers(calls: list[list[str]]) -> list[str]:
    return [call[2] for call in calls]


# --- record: three verdicts, and nothing for a cancelled leg --------------------------------


@pytest.mark.parametrize(
    ("step", "verdict"),
    [
        ("success", "passed"),
        ("failure", "conformance-failed"),
        ("skipped", "could-not-run"),
        ("", "could-not-run"),
    ],
    ids=["pytest-passed", "pytest-failed", "pytest-skipped", "pytest-never-reached"],
)
def test_record_maps_the_conformance_step_to_one_of_three_verdicts(
    script: Report, tmp_path: pathlib.Path, step: str, verdict: str
) -> None:
    assert record(script, tmp_path, lane="head", version="1.7.1", outcome=step) == 0

    written = json.loads(next(tmp_path.rglob("canary-result.json")).read_text(encoding="utf-8"))
    assert written["outcome"] == verdict
    assert written["lane"] == "head"
    assert written["matrix_version"] == "1.7.1"


def test_record_writes_nothing_for_a_cancelled_step(script: Report, tmp_path: pathlib.Path) -> None:
    assert record(script, tmp_path, lane="wheel", version="1.7.1", outcome="cancelled") == 0

    assert list(tmp_path.rglob("canary-result.json")) == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"lane": "main"},
        {"version": "next"},
        {"version": "1.7.1\nversion=9.9.9"},
        {"harness": "1.7.1 (forged)"},
        {"wheel": "0.3.0\n"},
        {"outcome": "passed"},
    ],
    ids=["lane", "matrix-tag", "matrix-newline", "harness", "wheel-newline", "outcome"],
)
def test_record_refuses_a_field_that_could_forge_a_title(
    script: Report, tmp_path: pathlib.Path, overrides: dict[str, str]
) -> None:
    fields: dict[str, Any] = {"lane": "head", "version": "1.7.1", "outcome": "success"}
    fields.update(overrides)

    with pytest.raises(SystemExit) as exited:
        record(script, tmp_path, **fields)

    assert exited.value.code == 1
    assert list(tmp_path.rglob("canary-result.json")) == []


# --- report: failures file, or comment when already open ------------------------------------


def test_a_conformance_failure_files_an_issue_naming_the_leg(
    script: Report, tmp_path: pathlib.Path
) -> None:
    record(script, tmp_path, lane="head", version="1.7.5", outcome="failure", harness="1.7.5")
    gh = Gh({})

    assert report(script, tmp_path, gh, jobs={"head": "failure", "wheel": "success"}) == 0

    assert created_titles(gh) == ["canary: conformance failure against better-auth@1.7.5"]
    body = gh.of("create")[0]
    assert RUN_URL in body[body.index("--body") + 1]
    assert ["--label", "canary"] == body[body.index("--label") : body.index("--label") + 2]


def test_a_harness_that_could_not_start_is_not_filed_as_a_conformance_failure(
    script: Report, tmp_path: pathlib.Path
) -> None:
    record(script, tmp_path, lane="head", version="1.6.30", outcome="skipped")
    gh = Gh({})

    report(script, tmp_path, gh, jobs={"head": "failure", "wheel": "success"})

    assert created_titles(gh) == [
        "canary: HEAD conformance lane cannot run against better-auth@1.6.30"
    ]


@pytest.mark.parametrize(
    ("outcome", "wheel", "title"),
    [
        (
            "failure",
            "0.3.0",
            "canary: published wheel 0.3.0 fails conformance against better-auth@1.7.6",
        ),
        ("skipped", "", "canary: published-wheel lane cannot run against better-auth@1.7.6"),
    ],
    ids=["conformance-failed", "could-not-run"],
)
def test_the_wheel_lane_keeps_its_two_titles(
    script: Report, tmp_path: pathlib.Path, outcome: str, wheel: str, title: str
) -> None:
    record(script, tmp_path, lane="wheel", version="1.7.6", outcome=outcome, wheel=wheel)
    gh = Gh({})

    report(script, tmp_path, gh, jobs={"head": "success", "wheel": "failure"})

    assert created_titles(gh) == [title]


def test_latest_names_what_it_resolved_to_or_says_it_was_unresolved(
    script: Report, tmp_path: pathlib.Path
) -> None:
    record(script, tmp_path, lane="head", version="latest", outcome="failure", harness="1.8.0")
    record(script, tmp_path, lane="wheel", version="latest", outcome="skipped")
    gh = Gh({})

    report(script, tmp_path, gh, jobs={"head": "failure", "wheel": "failure"})

    assert sorted(created_titles(gh)) == [
        "canary: conformance failure against better-auth@latest (1.8.0)",
        "canary: published-wheel lane cannot run against better-auth@latest (unresolved)",
    ]


def test_a_failure_whose_issue_is_open_comments_instead_of_staying_silent(
    script: Report, tmp_path: pathlib.Path
) -> None:
    record(script, tmp_path, lane="head", version="1.7.1", outcome="failure", harness="1.7.1")
    gh = Gh(STALE_OCTOBER)

    report(script, tmp_path, gh, jobs={"head": "failure", "wheel": "success"})

    assert gh.of("create") == []
    comments = gh.of("comment")
    assert numbers(comments) == ["95"]
    assert RUN_URL in comments[0][comments[0].index("--body") + 1]
    assert gh.of("close") == []


# --- report: a pass closes its own issues, and only those -----------------------------------


def test_green_legs_close_the_four_stale_october_issues(
    script: Report, tmp_path: pathlib.Path
) -> None:
    for lane in ("head", "wheel"):
        for version in ("1.6.30", "1.7.1"):
            record(script, tmp_path, lane=lane, version=version, outcome="success", harness=version)
    gh = Gh(STALE_OCTOBER)

    assert report(script, tmp_path, gh) == 0

    closes = gh.of("close")
    assert sorted(numbers(closes)) == ["95", "96", "97", "98"]
    assert all(RUN_URL in call[call.index("--comment") + 1] for call in closes)
    assert gh.of("create") == []


def test_a_pass_closes_every_title_its_leg_has_used(script: Report, tmp_path: pathlib.Path) -> None:
    """Older wheel versions and older `latest` resolutions are the same leg."""
    record(script, tmp_path, lane="wheel", version="latest", outcome="success", harness="1.8.1")
    gh = Gh(
        {
            10: "canary: published wheel 0.2.0 fails conformance against better-auth@latest (1.8.0)",
            11: "canary: published-wheel lane cannot run against better-auth@latest (unresolved)",
            12: "canary: conformance failure against better-auth@latest (1.8.0)",
        }
    )

    report(script, tmp_path, gh)

    assert sorted(numbers(gh.of("close"))) == ["10", "11"]


def test_a_pass_never_closes_another_versions_issue(script: Report, tmp_path: pathlib.Path) -> None:
    record(script, tmp_path, lane="head", version="1.7.1", outcome="success", harness="1.7.1")
    gh = Gh(
        {
            20: "canary: conformance failure against better-auth@1.7.10",
            21: "canary: conformance failure against better-auth@1.7.15",
            22: "canary: conformance failure against better-auth@1.7.1x",
            23: "canary: published-wheel lane cannot run against better-auth@1.7.1",
            24: "canary: conformance failure against better-auth@1.7.1 and more",
        }
    )

    report(script, tmp_path, gh)

    assert gh.of("close") == []


def test_a_conformance_failure_does_not_close_the_legs_other_issue(
    script: Report, tmp_path: pathlib.Path
) -> None:
    record(script, tmp_path, lane="head", version="1.7.1", outcome="skipped")
    gh = Gh(STALE_OCTOBER)

    report(script, tmp_path, gh, jobs={"head": "failure", "wheel": "success"})

    assert gh.of("close") == []
    assert created_titles(gh) == [
        "canary: HEAD conformance lane cannot run against better-auth@1.7.1"
    ]


# --- report: the upstream watch, skipped sweeps, cancelled and unrecorded legs --------------


def test_a_failed_upstream_watch_files_then_comments(
    script: Report, tmp_path: pathlib.Path
) -> None:
    first, second = Gh({}), Gh({7: WATCH_TITLE})

    report(script, tmp_path, first, watch="failure")
    report(script, tmp_path, second, watch="failure")

    assert created_titles(first) == [WATCH_TITLE]
    assert numbers(second.of("comment")) == ["7"]
    assert second.of("create") == []


def test_a_green_upstream_watch_closes_its_issue(script: Report, tmp_path: pathlib.Path) -> None:
    gh = Gh({7: WATCH_TITLE, 8: "canary: conformance failure against better-auth@1.7.1"})

    report(script, tmp_path, gh, watch="success")

    assert numbers(gh.of("close")) == ["7"]


@pytest.mark.parametrize("watch", ["skipped", "cancelled"])
def test_a_skipped_sweep_touches_nothing(
    script: Report, tmp_path: pathlib.Path, watch: str
) -> None:
    """The daily watch found nothing new: no leg ran, no artifact exists, nothing changes."""
    gh = Gh({**STALE_OCTOBER, 7: WATCH_TITLE})

    assert (
        report(
            script,
            tmp_path / "never-downloaded",
            gh,
            watch=watch,
            jobs={"head": "skipped", "wheel": "skipped"},
        )
        == 0
    )

    assert gh.calls == []


def test_a_cancelled_leg_files_nothing(script: Report, tmp_path: pathlib.Path) -> None:
    record(script, tmp_path, lane="head", version="1.7.1", outcome="cancelled")
    gh = Gh({})

    report(script, tmp_path, gh, jobs={"head": "cancelled", "wheel": "success"})

    assert gh.calls == []


@pytest.mark.parametrize("lane", ["head", "wheel"])
def test_a_lane_that_failed_without_recording_a_failure_still_files(
    script: Report, tmp_path: pathlib.Path, lane: str
) -> None:
    """A leg whose record or upload step itself broke must not read as green."""
    record(script, tmp_path, lane=lane, version="1.7.5", outcome="success", harness="1.7.5")
    gh = Gh({})
    jobs = {**ALL_GREEN, lane: "failure"}

    report(script, tmp_path, gh, jobs=jobs)

    titles = created_titles(gh)
    assert len(titles) == 1
    assert "without recording" in titles[0]


def test_an_unrecorded_failure_issue_closes_when_its_lane_is_green(
    script: Report, tmp_path: pathlib.Path
) -> None:
    first = Gh({})
    report(script, tmp_path, first, jobs={"head": "failure", "wheel": "success"})
    (title,) = created_titles(first)
    second = Gh({30: title})

    report(script, tmp_path, second)

    assert numbers(second.of("close")) == ["30"]


def test_the_canary_label_is_ensured_before_an_issue_is_created(
    script: Report, tmp_path: pathlib.Path
) -> None:
    gh = Gh({})

    report(script, tmp_path, gh, watch="failure")

    verbs = [call[:2] for call in gh.calls]
    assert verbs.index(["label", "create"]) < verbs.index(["issue", "create"])


# --- report: untrusted input and failed calls are loud --------------------------------------


@pytest.mark.parametrize(
    "document",
    [
        {"lane": "head", "matrix_version": "1.7.1", "outcome": "passed"},
        {
            "lane": "head",
            "matrix_version": "1.7.1\nx",
            "harness_version": "",
            "wheel_version": "",
            "outcome": "passed",
        },
        {
            "lane": "head",
            "matrix_version": "1.7.1",
            "harness_version": "",
            "wheel_version": "",
            "outcome": "fine",
        },
        ["not", "an", "object"],
    ],
    ids=["missing-fields", "newline", "unknown-outcome", "not-an-object"],
)
def test_a_tampered_result_file_is_rejected_and_its_leg_left_alone(
    script: Report, capsys: pytest.CaptureFixture[str], tmp_path: pathlib.Path, document: object
) -> None:
    leg = tmp_path / "canary-result-head-1.7.1"
    leg.mkdir()
    (leg / "canary-result.json").write_text(json.dumps(document), encoding="utf-8")
    gh = Gh(STALE_OCTOBER)

    assert report(script, tmp_path, gh) == 1

    assert gh.calls == []
    assert "::error::" in capsys.readouterr().err


def result_bytes(script: Report, staging: pathlib.Path, *, lane: str, version: str) -> bytes:
    """A genuine passing result for one leg, written by `record`, to plant somewhere else."""
    harness = "1.8.0" if version == "latest" else version
    record(script, staging, lane=lane, version=version, outcome="success", harness=harness)
    return next(staging.rglob("canary-result.json")).read_bytes()


@pytest.mark.parametrize(
    ("directory", "lane", "version"),
    [
        ("canary-result-head-1.7.1", "head", "1.6.30"),
        ("canary-result-head-1.7.1", "wheel", "1.7.1"),
        ("canary-result-head-1.7.1", "head", "1.7.10"),
        ("canary-result-wheel-latest", "head", "latest"),
    ],
    ids=["other-version", "other-lane", "prefix-version", "other-lane-latest"],
)
def test_a_leg_may_only_speak_for_itself(
    script: Report,
    capsys: pytest.CaptureFixture[str],
    tmp_path: pathlib.Path,
    directory: str,
    lane: str,
    version: str,
) -> None:
    """A leg that ran compromised upstream code must not close, or collide with, another leg.

    The directory is the artifact name the workflow gave the leg, which the leg's own code cannot
    choose; the file's contents are whatever that code wrote.
    """
    planted = result_bytes(script, tmp_path / "staging", lane=lane, version=version)
    results = tmp_path / "results"
    (results / directory).mkdir(parents=True)
    (results / directory / "canary-result.json").write_bytes(planted)
    gh = Gh(STALE_OCTOBER)

    assert report(script, results, gh) == 1

    assert gh.calls == []
    assert "::error::" in capsys.readouterr().err


@pytest.mark.parametrize(
    "where",
    [
        "canary-result.json",
        "duplicate/canary-result.json",
        "canary-result-head-1.7.1/x/canary-result.json",
    ],
    ids=["flat", "unnamed-directory", "nested"],
)
def test_a_result_outside_its_legs_artifact_directory_is_refused(
    script: Report, capsys: pytest.CaptureFixture[str], tmp_path: pathlib.Path, where: str
) -> None:
    """Only `<results>/canary-result-<lane>-<version>/canary-result.json` can be bound to a leg.

    download-artifact v8 does write a lone pattern match flat into the target directory, but a
    flat file carries no artifact name, so it cannot be bound to the leg that wrote it. With ten
    legs that each record unless cancelled, one lone artifact means nine legs were cancelled:
    a red report job is the right answer, not a file trusted for whichever leg it names.
    """
    planted = result_bytes(script, tmp_path / "staging", lane="head", version="1.7.1")
    results = tmp_path / "results"
    target = results / where
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(planted)
    gh = Gh(STALE_OCTOBER)

    assert report(script, results, gh) == 1

    assert gh.calls == []
    assert "::error::" in capsys.readouterr().err


def test_a_rejected_result_does_not_block_valid_legs_or_the_watch(
    script: Report, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Validation stays exactly as strict; only its blast radius shrinks to the one file."""
    record(script, tmp_path, lane="head", version="1.6.30", outcome="success", harness="1.6.30")
    bad = tmp_path / "canary-result-head-1.7.1"
    bad.mkdir()
    (bad / "canary-result.json").write_text("{not json", encoding="utf-8")
    gh = Gh({**STALE_OCTOBER, 7: WATCH_TITLE})

    assert report(script, tmp_path, gh, watch="success") == 1

    assert sorted(numbers(gh.of("close"))) == ["7", "96"]
    error = capsys.readouterr().err
    assert "::error::" in error
    assert "canary-result-head-1.7.1" in error


@pytest.mark.parametrize(
    "url",
    ["https://github.com/acme/bridge/actions/runs/1\n", "javascript:alert(1)", ""],
    ids=["newline", "scheme", "empty"],
)
def test_an_implausible_run_url_is_refused(
    script: Report, tmp_path: pathlib.Path, url: str
) -> None:
    gh = Gh({})
    argv = [
        "report",
        "--results-dir",
        str(tmp_path),
        "--run-url",
        url,
        "--upstream-watch",
        "failure",
        "--head-job",
        "success",
        "--wheel-job",
        "success",
    ]

    with pytest.raises(SystemExit):
        script.main(argv, gh=gh)

    assert gh.calls == []


def test_an_unreadable_issue_list_acts_on_nothing(script: Report, tmp_path: pathlib.Path) -> None:
    """Without the list, a failure cannot be deduplicated nor a pass matched to its issue."""
    calls: list[list[str]] = []

    def broken(argv: Sequence[str]) -> tuple[int, str]:
        calls.append(list(argv))
        return (1, "") if list(argv[:2]) == ["issue", "list"] else (0, "")

    with pytest.raises(SystemExit):
        script.main(
            [
                "report",
                "--results-dir",
                str(tmp_path),
                "--run-url",
                RUN_URL,
                "--upstream-watch",
                "failure",
                "--head-job",
                "success",
                "--wheel-job",
                "success",
            ],
            gh=broken,
        )

    assert [call[:2] for call in calls] == [["issue", "list"]]


def test_a_failed_issue_call_still_attempts_the_rest_and_fails_the_job(
    script: Report, tmp_path: pathlib.Path
) -> None:
    for version in ("1.6.30", "1.7.1"):
        record(script, tmp_path, lane="head", version=version, outcome="success")
    gh = Gh(STALE_OCTOBER, failing="close")

    assert report(script, tmp_path, gh) == 1

    assert sorted(numbers(gh.of("close"))) == ["95", "96"]


def test_the_default_gh_runner_uses_an_argument_list(
    script: Report, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No shell anywhere: a title is one argv element whatever characters it holds."""
    seen: list[object] = []

    def fake_run(argv: object, **kwargs: object) -> object:
        seen.append(argv)
        seen.append(kwargs.get("shell", False))

        class Done:
            returncode = 0
            stdout = "[]"

        return Done()

    module = cast(Any, script)
    monkeypatch.setattr(module.subprocess, "run", fake_run)

    assert module.run_gh(["issue", "list"]) == (0, "[]")
    assert seen == [["gh", "issue", "list"], False]


def test_the_script_imports_nothing_outside_the_standard_library() -> None:
    """The report job runs it with the runner's python3 and never syncs the project."""
    allowed = set(sys.stdlib_module_names) | {"__future__"}
    text = SCRIPT.read_text(encoding="utf-8")
    imported = {
        line.split()[1].split(".")[0]
        for line in text.splitlines()
        if line.startswith(("import ", "from "))
    }

    assert imported <= allowed, imported - allowed
