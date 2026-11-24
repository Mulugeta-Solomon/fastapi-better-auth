"""Turn the canary legs' outcomes into `canary` issues: file, comment, or close.

`record` runs at the end of each matrix leg. It maps the conformance step's outcome to one of
three verdicts - passed, conformance-failed (pytest ran and failed), could-not-run (something
before pytest failed) - and writes it, with the versions the leg ran, its run attempt and when it
was recorded (UTC), to a small JSON file the leg uploads as an artifact. A cancelled step writes
nothing: a cancelled leg files nothing.

`report` runs in the one job that may write issues, one canary run at a time. It reads every
leg's file, the upstream watch's job result and the expected matrix, lists the open `canary`
issues with their last-update times, and then:

- a failure files an issue, or comments on the open issue with that title, so a repeat failure
  is never silent;
- a pass closes the open issues its own leg filed that were last updated before the pass was
  recorded. An issue filed, or commented with a repeat failure, after the pass stays open, so an
  older pass never closes past a newer failure. This is deliberately conservative: anything
  else that touches the issue after the pass (a human comment, a label) also keeps it open
  until the next pass. The comment says the leg passed when it retested the combination the title
  names, and says the issue is superseded, not retested, when the title names an older wheel or
  an older resolution of `latest`;
- a lane whose job failed names, in one issue, every expected leg with no usable result, however
  many other legs recorded failures. A green lane closes that issue only when every expected leg
  is covered; a green lane with a gap keeps it open, names the gap and fails the job;
- on a partial re-run, results from earlier attempts are weighed by attempt: an earlier pass
  covers its leg and closes only when the lane is green, an earlier failure is stale; a failed
  lane warns (no issue) about every leg covered only by an earlier pass, which on a full re-run
  may hide a leg that died before recording.

The leg files were written by jobs that ran npm-installed upstream code and pytest, so they are
untrusted. Every field is validated before it can reach an issue title, a file counts only for
the leg whose artifact directory holds it, and `gh` is only ever called with an argument list.
The `recorded_at` time comes from the leg too, but because a result is bound to its own leg, a
lying leg can only affect its own issues. A refused file is reported as an `::error::` and its
leg treated as missing; it never blocks the valid legs or the upstream watch, and the job exits
non-zero at the end. Standard library only: the report job never installs the project.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import NoReturn

GhRunner = Callable[[Sequence[str]], tuple[int, str]]
Clock = Callable[[], dt.datetime]

LABEL = "canary"
LABEL_COLOR = "D93F0B"
LABEL_DESCRIPTION = "automated conformance canary"
RESULT_FILE = "canary-result.json"
ARTIFACT_PREFIX = "canary-result-"
MAX_RESULT_BYTES = 4096
GH_TIMEOUT_SECONDS = 120.0
ISSUE_LIMIT = "500"

LANES = ("head", "wheel")
LANE_NAMES = {"head": "HEAD conformance", "wheel": "published-wheel"}
VERDICTS = ("passed", "conformance-failed", "could-not-run")
STEP_VERDICTS = {
    "success": "passed",
    "failure": "conformance-failed",
    "skipped": "could-not-run",
    "": "could-not-run",
}
JOB_RESULTS = frozenset({"success", "failure", "cancelled", "skipped"})
DIST_TAGS = frozenset({"latest"})
VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.]{1,32})?")
WHEEL_VERSION = re.compile(r"[0-9][0-9A-Za-z.+!-]{0,63}")
ATTEMPT = re.compile(r"[1-9][0-9]{0,5}")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
CLOCK_SKEW = dt.timedelta(seconds=60)
"""How far a leg's clock may run ahead of the report job's before its result is refused."""
RUN_URL = re.compile(r"https://[A-Za-z0-9.-]+/[\w.-]+/[\w.-]+/actions/runs/\d+(?:/attempts/\d+)?")
WATCH_TITLE = "canary: upstream release watch cannot read the npm registry"
RESOLVED = r"(?: \((?P<resolved>[^()]*)\))?"
UNRESOLVED = "unresolved"


def fail(message: str) -> NoReturn:
    print(f"::error::{message}", file=sys.stderr)
    raise SystemExit(1)


class Rejected(ValueError):
    """A value that must not reach an issue; `record` exits on it, `report` skips the file."""


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_timestamp(value: str) -> dt.datetime:
    """`YYYY-MM-DDTHH:MM:SSZ` and nothing else: UTC, whole seconds, a real calendar date."""
    if not TIMESTAMP.fullmatch(value):
        raise Rejected(f"implausible timestamp {value!r}")
    try:
        parsed = dt.datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError as exc:
        raise Rejected(f"implausible timestamp {value!r}") from exc
    return parsed.replace(tzinfo=dt.timezone.utc)


def report_line(line: str) -> None:
    print(line)
    destination = os.environ.get("GITHUB_STEP_SUMMARY")
    if not destination:
        return
    with open(destination, "a", encoding="utf-8") as handle:
        handle.write(f"{line}\n")


@dataclass(frozen=True)
class LegResult:
    lane: str
    matrix_version: str
    harness_version: str
    wheel_version: str
    outcome: str
    attempt: str
    recorded_at: str

    def __post_init__(self) -> None:
        # Everything here ends up in an issue title, a comment, or the step summary.
        if self.lane not in LANES:
            raise Rejected(f"unknown lane {self.lane!r}")
        if self.matrix_version not in DIST_TAGS and not VERSION.fullmatch(self.matrix_version):
            raise Rejected(f"implausible matrix version {self.matrix_version!r}")
        if self.harness_version and not VERSION.fullmatch(self.harness_version):
            raise Rejected(f"implausible harness version {self.harness_version!r}")
        if self.wheel_version and not WHEEL_VERSION.fullmatch(self.wheel_version):
            raise Rejected(f"implausible wheel version {self.wheel_version!r}")
        if self.outcome not in VERDICTS:
            raise Rejected(f"unknown verdict {self.outcome!r}")
        if not ATTEMPT.fullmatch(self.attempt):
            raise Rejected(f"implausible run attempt {self.attempt!r}")
        parse_timestamp(self.recorded_at)

    @property
    def recorded(self) -> dt.datetime:
        return parse_timestamp(self.recorded_at)

    @property
    def leg(self) -> tuple[str, str]:
        return self.lane, self.matrix_version

    @property
    def target(self) -> str:
        target = f"better-auth@{self.matrix_version}"
        if self.matrix_version in DIST_TAGS:
            target += f" ({self.harness_version or UNRESOLVED})"
        return target

    @property
    def ran(self) -> str:
        return f"its harness servers ran better-auth {self.harness_version or '(unread)'}"


@dataclass(frozen=True)
class OpenIssue:
    number: int
    title: str
    updated: dt.datetime


@dataclass(frozen=True)
class Create:
    title: str
    body: str


@dataclass(frozen=True)
class Comment:
    number: int
    body: str


@dataclass(frozen=True)
class Close:
    number: int
    comment: str


Action = Create | Comment | Close


def owned_by(lane: str, matrix_version: str) -> re.Pattern[str]:
    """Every title a leg has filed under, across wheel versions and `latest` resolutions."""
    target = f"better-auth@{re.escape(matrix_version)}{RESOLVED}"
    if lane == "head":
        kinds = "conformance failure|HEAD conformance lane cannot run"
    else:
        kinds = r"published wheel (?P<wheel>\S+) fails conformance|published-wheel lane cannot run"
    return re.compile(f"canary: (?:{kinds}) against {target}")


def unrecorded_title(lane: str) -> str:
    return f"canary: a {LANE_NAMES[lane]} leg failed without recording its result"


def failure_issue(result: LegResult, run_url: str) -> Create:
    lane = LANE_NAMES[result.lane]
    if result.lane == "head" and result.outcome == "conformance-failed":
        return Create(
            f"canary: conformance failure against {result.target}",
            f"The HEAD conformance leg against {result.target} ran its conformance tests and "
            f"they failed; {result.ran}. Run: {run_url}",
        )
    if result.lane == "wheel" and result.outcome == "conformance-failed":
        wheel = result.wheel_version or "unknown"
        return Create(
            f"canary: published wheel {wheel} fails conformance against {result.target}",
            f"fastapi-better-auth-bridge {wheel}, installed from PyPI, failed the e2e "
            f"conformance lane against {result.target}; {result.ran}. This is the artifact "
            f"users have, not HEAD. Run: {run_url}",
        )
    title = (
        f"canary: HEAD conformance lane cannot run against {result.target}"
        if result.lane == "head"
        else f"canary: published-wheel lane cannot run against {result.target}"
    )
    return Create(
        title,
        f"The {lane} leg against {result.target} failed before its conformance tests ran "
        f"(harness startup, the better-auth version echo, or installing the code under test); "
        f"{result.ran}. Until this is fixed the leg proves nothing. Run: {run_url}",
    )


def file_or_comment(issue: Create, open_issues: Sequence[OpenIssue], run_url: str) -> Action:
    same = sorted(candidate.number for candidate in open_issues if candidate.title == issue.title)
    if same:
        return Comment(same[0], f"Failed again in {run_url}.\n\n{issue.body}")
    return issue


def close_matching(
    pattern: re.Pattern[str], open_issues: Sequence[OpenIssue], comment: str
) -> list[Action]:
    """Close every open issue whose title the pattern matches (the watch and unrecorded ones;
    a leg's pass closes through `plan_leg`, which also checks when each issue was last updated)."""
    return [
        Close(candidate.number, comment)
        for candidate in sorted(open_issues, key=lambda issue: issue.number)
        if pattern.fullmatch(candidate.title)
    ]


@dataclass(frozen=True)
class Context:
    """What every planning step reads: the run, the open issues, and what the jobs reported."""

    run_url: str
    open_issues: tuple[OpenIssue, ...]
    upstream_watch: str
    job_results: Mapping[str, str]
    expected: tuple[str, ...]
    attempt: int

    def is_current(self, result: LegResult) -> bool:
        return int(result.attempt) == self.attempt

    def covers(self, result: LegResult) -> bool:
        """A leg is covered by a current result, or by an earlier pass a re-run left in place.

        "Re-run failed jobs" re-runs only failed legs, so a leg that passed keeps its earlier
        attempt's artifact, and that pass is still the truth. An earlier failure is stale by
        construction - a failed leg is always re-run - so it covers nothing.
        """
        return self.is_current(result) or result.outcome == "passed"


def plan(results: Sequence[LegResult], context: Context) -> list[Action]:
    return [
        *plan_watch(context),
        *(action for result in results for action in plan_leg(result, context)),
        *(action for lane in LANES for action in plan_coverage(lane, results, context)),
    ]


def plan_watch(context: Context) -> list[Action]:
    if context.upstream_watch == "failure":
        watch = Create(
            WATCH_TITLE,
            "The daily watch could not decide whether better-auth published a release. Today's "
            "sweep ran anyway - the gates fail open - so this is not a missed canary, but the "
            "watch is no longer narrowing anything and every daily tick will run the full "
            f"matrix until it is fixed. Run: {context.run_url}",
        )
        return [file_or_comment(watch, context.open_issues, context.run_url)]
    if context.upstream_watch == "success":
        exact = re.compile(re.escape(WATCH_TITLE))
        comment = f"The upstream watch read npm in {context.run_url}."
        return close_matching(exact, context.open_issues, comment)
    return []


def plan_leg(result: LegResult, context: Context) -> list[Action]:
    if not context.is_current(result):
        # An earlier pass may close only when the lane is green: then every leg's latest
        # attempt passed. An earlier failure files and comments nothing by itself.
        if result.outcome != "passed" or context.job_results[result.lane] != "success":
            return []
    elif result.outcome != "passed":
        issue = failure_issue(result, context.run_url)
        return [file_or_comment(issue, context.open_issues, context.run_url)]
    pattern = owned_by(*result.leg)
    return [
        Close(issue.number, close_comment(result, match, context.run_url))
        for issue in sorted(context.open_issues, key=lambda issue: issue.number)
        if (match := pattern.fullmatch(issue.title)) and issue.updated < result.recorded
    ]


def close_comment(result: LegResult, title: re.Match[str], run_url: str) -> str:
    """Recovered when the leg retested what the title names; superseded when it did not.

    The title names a Better Auth version only for `latest` (an `unresolved` one names none)
    and a wheel version only on a wheel conformance failure. Either differing from what the leg
    ran means the titled combination was not retested: it closes all the same, because only the
    latest release is supported, but the comment says so instead of claiming a pass.
    """
    lane = LANE_NAMES[result.lane]
    titled_auth = title.group("resolved") or ""
    titled_wheel = title.groupdict().get("wheel") or ""
    tested = f"better-auth {result.harness_version or '(unread)'}"
    if result.lane == "wheel":
        tested += f", wheel {result.wheel_version or 'unknown'}"
    auth_differs = titled_auth not in {"", UNRESOLVED, result.harness_version}
    wheel_differs = bool(titled_wheel) and titled_wheel != result.wheel_version
    if not (auth_differs or wheel_differs):
        return f"The {lane} leg against {result.target} passed in {run_url} ({tested}); closing."
    titled = f"better-auth {titled_auth or result.matrix_version}"
    if titled_wheel:
        titled += f", wheel {titled_wheel}"
    return (
        f"Superseded, not recovered: the {lane} leg against better-auth@{result.matrix_version} "
        f"passed in {run_url} running {tested}, but the combination this issue names "
        f"({titled}) was not retested. Closing because only the latest release is supported."
    )


def missing_legs(lane: str, results: Sequence[LegResult], context: Context) -> list[str]:
    """Expected versions this lane has no covering result for, in matrix order."""
    covered = {r.matrix_version for r in results if r.lane == lane and context.covers(r)}
    return [version for version in context.expected if version not in covered]


def carried_legs(lane: str, results: Sequence[LegResult], context: Context) -> list[str]:
    """Expected versions this lane covers only with a pass from an earlier attempt.

    On "Re-run all jobs" such a leg may have died before recording in this attempt; on "Re-run
    failed jobs" it simply was not re-run. Only each job's start time tells the two apart, and
    the reporter is not given that (it would need `actions: read` and a binding from job names
    to legs), so this only feeds a warning when the lane failed, never an issue.
    """
    carried = {
        r.matrix_version
        for r in results
        if r.lane == lane and r.outcome == "passed" and not context.is_current(r)
    }
    return [version for version in context.expected if version in carried]


def coverage_gaps(results: Sequence[LegResult], context: Context) -> dict[str, list[str]]:
    """Green lanes that still miss a leg: uploads tolerate a missing file, so `success` alone
    does not prove every leg spoke. Each one fails the report job, as a rejection does."""
    gaps = {
        lane: missing_legs(lane, results, context)
        for lane in LANES
        if context.job_results[lane] == "success"
    }
    return {lane: missing for lane, missing in gaps.items() if missing}


def plan_coverage(lane: str, results: Sequence[LegResult], context: Context) -> list[Action]:
    """A lane with a gap names every expected leg with no usable result; full coverage closes.

    Checked per leg, so another leg's recorded failure never hides a missing one. A green lane
    closes the issue only when every expected leg is covered; a green lane with a gap keeps it
    open and says so. A cancelled or skipped lane says nothing.
    """
    job = context.job_results[lane]
    if job not in {"success", "failure"}:
        return []
    title = unrecorded_title(lane)
    missing = missing_legs(lane, results, context)
    named = ", ".join(f"better-auth@{version}" for version in missing)
    if job == "success" and not missing:
        comment = f"Every {LANE_NAMES[lane]} leg recorded its result in {context.run_url}."
        return close_matching(re.compile(re.escape(title)), context.open_issues, comment)
    if job == "success":
        body = (
            f"The {LANE_NAMES[lane]} lane reported success, yet these legs left no usable "
            f"result: {named}. Until each records one, the lane proves nothing about them. "
            f"Run: {context.run_url}"
        )
    elif missing:
        body = (
            f"These {LANE_NAMES[lane]} legs left no usable result: {named}. A leg lands here "
            "when it failed before recording, its result was rejected by the reporter, or it "
            f"only has a stale result from an earlier attempt; read the run. Run: {context.run_url}"
        )
    elif not any(
        r.lane == lane and r.outcome != "passed" and context.is_current(r) for r in results
    ):
        body = (
            f"The {LANE_NAMES[lane]} lane failed, yet every leg recorded a pass, so the reporter "
            f"cannot say which leg failed or why; read the run. Run: {context.run_url}"
        )
    else:
        return []
    return [file_or_comment(Create(title, body), context.open_issues, context.run_url)]


def run_gh(argv: Sequence[str]) -> tuple[int, str]:
    """One `gh` call as an argument list: no shell ever sees a title or a body."""
    try:
        finished = subprocess.run(
            ["gh", *argv],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=GH_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"::warning::gh {argv[:2]} could not run: {type(exc).__name__}", file=sys.stderr)
        return 1, ""
    if finished.returncode != 0 and finished.stderr:
        print(finished.stderr.strip()[-500:], file=sys.stderr)
    return finished.returncode, finished.stdout


def list_open_issues(gh: GhRunner) -> list[OpenIssue]:
    argv = ["issue", "list", "--state", "open", "--label", LABEL, "--limit", ISSUE_LIMIT]
    code, output = gh([*argv, "--json", "number,title,updatedAt"])
    if code != 0:
        fail("cannot list the open canary issues; acting on nothing rather than guessing")
    try:
        listed: object = json.loads(output)
    except ValueError:
        fail("gh issue list did not return JSON")
    if not isinstance(listed, list):
        fail("gh issue list did not return a JSON list")
    issues: list[OpenIssue] = []
    for entry in listed:  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(entry, dict):
            fail("gh issue list returned a non-object entry")
        number: object = entry.get("number")  # pyright: ignore[reportUnknownMemberType]
        title: object = entry.get("title")  # pyright: ignore[reportUnknownMemberType]
        updated: object = entry.get("updatedAt")  # pyright: ignore[reportUnknownMemberType]
        if not (isinstance(number, int) and isinstance(title, str) and isinstance(updated, str)):
            fail("gh issue list returned an entry without a number, a title and an updatedAt")
        try:
            issues.append(OpenIssue(number, title, parse_timestamp(updated)))
        except Rejected as exc:
            fail(f"gh issue list returned issue #{number} with {exc}")
    return issues


def execute(actions: Iterable[Action], gh: GhRunner) -> int:
    """Attempt every action; return how many failed so the job goes red without stopping."""
    failures = 0
    labelled = False
    for action in actions:
        if isinstance(action, Create):
            if not labelled:
                # Fails harmlessly when the label already exists.
                gh(["label", "create", LABEL, "--color", LABEL_COLOR, "--description",
                    LABEL_DESCRIPTION])  # fmt: skip
                labelled = True
            argv = ["issue", "create", "--title", action.title, "--label", LABEL,
                    "--body", action.body]  # fmt: skip
            done = f"filed: {action.title}"
        elif isinstance(action, Comment):
            argv = ["issue", "comment", str(action.number), "--body", action.body]
            done = f"commented on #{action.number}"
        else:
            argv = ["issue", "close", str(action.number), "--comment", action.comment]
            done = f"closed #{action.number}"
        code, _ = gh(argv)
        if code != 0:
            failures += 1
            print(f"::error::gh failed: {done}", file=sys.stderr)
        else:
            report_line(done)
    return failures


def artifact_name(lane: str, matrix_version: str) -> str:
    """The artifact name canary.yml gives a leg; the leg's own code cannot choose it."""
    return f"{ARTIFACT_PREFIX}{lane}-{matrix_version}"


@dataclass(frozen=True)
class Loaded:
    results: tuple[LegResult, ...]
    rejected: int


def load_results(directory: Path) -> Loaded:
    """Every leg's file, each bound to the artifact directory the workflow named for its leg.

    A file is accepted only at `<directory>/canary-result-<lane>-<version>/canary-result.json`
    and only if it names that same lane and version: a leg that ran compromised upstream code
    may speak for itself, never for another leg. download-artifact writes a lone pattern match
    flat, with no artifact name to bind it to, so that layout is refused too.

    A refused file is reported as an `::error::` and skipped, so its leg simply has no result;
    it never stops the valid legs or the upstream watch from being acted on.
    """
    if not directory.is_dir():
        return Loaded((), 0)
    results: list[LegResult] = []
    rejected = 0
    for path in sorted(directory.rglob(RESULT_FILE)):
        try:
            results.append(bound_result(directory, path))
        except Rejected as exc:
            rejected += 1
            print(f"::error::rejected {path}: {exc}", file=sys.stderr)
    return Loaded(tuple(results), rejected)


def bound_result(directory: Path, path: Path) -> LegResult:
    result = read_result(path)
    if path.parent.parent != directory or path.parent.name != artifact_name(*result.leg):
        raise Rejected(
            f"it names the {result.lane} leg against {result.matrix_version} but is not in "
            f"that leg's artifact directory {artifact_name(*result.leg)!r}"
        )
    return result


def read_result(path: Path) -> LegResult:
    """One leg's file, or Rejected: nothing a hostile file holds may escape as another error."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_RESULT_BYTES + 1)
    except OSError as exc:  # a directory named like the file, a vanished or unreadable path
        raise Rejected(f"it cannot be read: {type(exc).__name__}") from exc
    if len(raw) > MAX_RESULT_BYTES:
        raise Rejected(f"it is larger than {MAX_RESULT_BYTES} bytes")
    try:
        document: object = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as exc:  # UnicodeDecodeError is a ValueError
        # Nested arrays well inside the size cap exhaust the decoder's recursion on CPython
        # 3.10 and 3.11.
        raise Rejected("it is not decodable JSON") from exc
    if not isinstance(document, dict):
        raise Rejected("it is not a JSON object")
    fields = {str(k): v for k, v in document.items()}  # pyright: ignore[reportUnknownVariableType]
    expected = set(LegResult.__dataclass_fields__)
    if set(fields) != expected or not all(isinstance(v, str) for v in fields.values()):
        raise Rejected(f"it does not hold exactly the string fields {sorted(expected)}")
    return LegResult(**{key: str(value) for key, value in fields.items()})


def record(args: argparse.Namespace, clock: Clock) -> int:
    step: str = args.conformance_outcome
    if step == "cancelled":
        print("the conformance step was cancelled; recording nothing")
        return 0
    if step not in STEP_VERDICTS:
        fail(f"unknown conformance step outcome {step!r}")
    try:
        result = LegResult(
            lane=args.lane,
            matrix_version=args.matrix_version,
            harness_version=args.harness_version,
            wheel_version=args.wheel_version,
            outcome=STEP_VERDICTS[step],
            attempt=args.run_attempt,
            recorded_at=clock().astimezone(dt.timezone.utc).strftime(TIMESTAMP_FORMAT),
        )
    except Rejected as exc:
        fail(str(exc))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(asdict(result), sort_keys=True), encoding="utf-8")
    report_line(f"{LANE_NAMES[result.lane]} leg against {result.target}: {result.outcome}")
    return 0


def expected_versions(value: str) -> tuple[str, ...]:
    """The matrix both lanes sweep, as the one JSON list canary.yml passes."""
    try:
        listed: object = json.loads(value)
    except ValueError:
        fail(f"--expected-versions is not JSON: {value!r}")
    if not isinstance(listed, list) or not listed:
        fail("--expected-versions must be a non-empty JSON list")
    versions: list[str] = []
    for entry in listed:  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(entry, str) or not (entry in DIST_TAGS or VERSION.fullmatch(entry)):
            fail(f"--expected-versions holds an implausible entry: {entry!r}")
        if entry in versions:
            fail(f"--expected-versions lists {entry} twice")
        versions.append(entry)
    return tuple(versions)


def admissible(loaded: Loaded, expected: Sequence[str], attempt: int, now: dt.datetime) -> Loaded:
    """Drop, as rejected, results no expected leg of this run attempt could have written."""
    kept: list[LegResult] = []
    rejected = loaded.rejected
    for result in loaded.results:
        if result.matrix_version not in expected:
            why = "the matrix does not list that version"
        elif int(result.attempt) > attempt:
            why = f"it claims attempt {result.attempt}, after this report's attempt {attempt}"
        elif result.recorded > now + CLOCK_SKEW:
            why = f"it claims to be recorded at {result.recorded_at}, in the future"
        else:
            kept.append(result)
            continue
        rejected += 1
        print(
            f"::error::rejected the {result.lane} result for better-auth@"
            f"{result.matrix_version}: {why}",
            file=sys.stderr,
        )
    return Loaded(tuple(kept), rejected)


def run_attempt(value: str) -> int:
    if not ATTEMPT.fullmatch(value):
        fail(f"--run-attempt is not a positive integer: {value!r}")
    return int(value)


def job_result(value: str, what: str) -> str:
    if value not in JOB_RESULTS:
        fail(f"{what} is not a job result: {value!r}")
    return value


def report(args: argparse.Namespace, gh: GhRunner, clock: Clock) -> int:
    run_url: str = args.run_url
    if not RUN_URL.fullmatch(run_url):
        fail(f"implausible run URL {run_url!r}")
    upstream_watch = job_result(args.upstream_watch, "--upstream-watch")
    job_results = {
        "head": job_result(args.head_job, "--head-job"),
        "wheel": job_result(args.wheel_job, "--wheel-job"),
    }
    expected = expected_versions(args.expected_versions)
    attempt = run_attempt(args.run_attempt)
    loaded = admissible(load_results(Path(args.results_dir)), expected, attempt, clock())
    for result in loaded.results:
        report_line(f"{LANE_NAMES[result.lane]} leg against {result.target}: {result.outcome}")
    if (
        upstream_watch not in {"success", "failure"}
        and not loaded.results
        and not loaded.rejected
        and all(value not in {"success", "failure"} for value in job_results.values())
    ):
        report_line("no leg ran and the watch did not decide; nothing to report")
        return 0
    context = Context(
        run_url=run_url,
        open_issues=tuple(list_open_issues(gh)),
        upstream_watch=upstream_watch,
        job_results=job_results,
        expected=expected,
        attempt=attempt,
    )
    actions = plan(loaded.results, context)
    failures = execute(actions, gh)
    gaps = coverage_gaps(loaded.results, context)
    for lane, missing in gaps.items():
        named = ", ".join(missing)
        print(f"::error::the {lane} lane reported success but left no result for {named}",
              file=sys.stderr)  # fmt: skip
    warn_carried(loaded.results, context)
    return 1 if failures or loaded.rejected or gaps else 0


def warn_carried(results: Sequence[LegResult], context: Context) -> None:
    """One warning per failed lane whose legs are covered only by an earlier attempt's pass, for
    the person who started the re-run. It changes no issue and no exit code."""
    for lane in LANES:
        if context.job_results[lane] != "failure":
            continue
        carried = carried_legs(lane, results, context)
        if not carried:
            continue
        named = ", ".join(f"better-auth@{version}" for version in carried)
        print(
            f"::warning::the {lane} lane failed and {named} has only an earlier attempt's pass; "
            "if it was re-run in this attempt, it failed before recording",
            file=sys.stderr,
        )


def parse(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    leg = commands.add_parser("record", help="write one leg's verdict")
    # Validated by LegResult rather than `choices`, so every refusal exits 1 the same way.
    leg.add_argument("--lane", required=True, help=f"one of {list(LANES)}")
    leg.add_argument("--matrix-version", required=True)
    leg.add_argument("--harness-version", default="")
    leg.add_argument("--wheel-version", default="")
    leg.add_argument("--conformance-outcome", required=True, help="steps.<id>.outcome")
    leg.add_argument("--run-attempt", required=True, help="GITHUB_RUN_ATTEMPT")
    leg.add_argument("--out", required=True)
    summary = commands.add_parser("report", help="file, comment on, or close issues")
    summary.add_argument("--results-dir", required=True)
    summary.add_argument("--run-url", required=True)
    summary.add_argument("--upstream-watch", required=True, help="needs.upstream-check.result")
    summary.add_argument("--head-job", required=True, help="needs.conformance.result")
    summary.add_argument("--wheel-job", required=True, help="needs.published-wheel.result")
    summary.add_argument(
        "--expected-versions", required=True, help="the matrix both lanes sweep, as a JSON list"
    )
    summary.add_argument("--run-attempt", required=True, help="GITHUB_RUN_ATTEMPT")
    return parser.parse_args(argv)


def main(
    argv: Sequence[str] | None = None, gh: GhRunner | None = None, clock: Clock | None = None
) -> int:
    args = parse(argv)
    now = utc_now if clock is None else clock
    if args.command == "record":
        return record(args, now)
    return report(args, run_gh if gh is None else gh, now)


if __name__ == "__main__":
    raise SystemExit(main())
