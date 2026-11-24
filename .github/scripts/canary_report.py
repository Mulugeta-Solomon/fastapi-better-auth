"""Turn the canary legs' outcomes into `canary` issues: file, comment, or close.

`record` runs at the end of each matrix leg. It maps the conformance step's outcome to one of
three verdicts - passed, conformance-failed (pytest ran and failed), could-not-run (something
before pytest failed) - and writes it with the versions the leg ran to a small JSON file the leg
uploads as an artifact. A cancelled step writes nothing: a cancelled leg files nothing.

`report` runs in the one job that may write issues. It reads every leg's file and the upstream
watch's job result, lists the open `canary` issues, and then: a failure files an issue, or
comments on the open issue with that title so a repeat failure is never silent; a pass closes
every open issue its own leg filed. A lane whose job failed without recording any failure files
an issue of its own, so a broken record step cannot read as green.

The leg files were written by jobs that ran npm-installed upstream code and pytest, so every
field is validated again here before it can reach an issue title, and `gh` is only ever called
with an argument list. Standard library only: the report job never installs the project.
"""

from __future__ import annotations

import argparse
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

LABEL = "canary"
LABEL_COLOR = "D93F0B"
LABEL_DESCRIPTION = "automated conformance canary"
RESULT_FILE = "canary-result.json"
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
RUN_URL = re.compile(r"https://[A-Za-z0-9.-]+/[\w.-]+/[\w.-]+/actions/runs/\d+(?:/attempts/\d+)?")
WATCH_TITLE = "canary: upstream release watch cannot read the npm registry"
RESOLVED = r"(?: \([^()]*\))?"


def fail(message: str) -> NoReturn:
    print(f"::error::{message}", file=sys.stderr)
    raise SystemExit(1)


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

    def __post_init__(self) -> None:
        # Everything here ends up in an issue title, a comment, or the step summary.
        if self.lane not in LANES:
            fail(f"unknown lane {self.lane!r}")
        if self.matrix_version not in DIST_TAGS and not VERSION.fullmatch(self.matrix_version):
            fail(f"implausible matrix version {self.matrix_version!r}")
        if self.harness_version and not VERSION.fullmatch(self.harness_version):
            fail(f"implausible harness version {self.harness_version!r}")
        if self.wheel_version and not WHEEL_VERSION.fullmatch(self.wheel_version):
            fail(f"implausible wheel version {self.wheel_version!r}")
        if self.outcome not in VERDICTS:
            fail(f"unknown verdict {self.outcome!r}")

    @property
    def leg(self) -> tuple[str, str]:
        return self.lane, self.matrix_version

    @property
    def target(self) -> str:
        target = f"better-auth@{self.matrix_version}"
        if self.matrix_version in DIST_TAGS:
            target += f" ({self.harness_version or 'unresolved'})"
        return target

    @property
    def ran(self) -> str:
        return f"its harness servers ran better-auth {self.harness_version or '(unread)'}"


@dataclass(frozen=True)
class OpenIssue:
    number: int
    title: str


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
        kinds = r"published wheel \S+ fails conformance|published-wheel lane cannot run"
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
    return [
        Close(candidate.number, comment)
        for candidate in sorted(open_issues, key=lambda issue: issue.number)
        if pattern.fullmatch(candidate.title)
    ]


def plan(
    results: Sequence[LegResult],
    open_issues: Sequence[OpenIssue],
    *,
    run_url: str,
    upstream_watch: str,
    job_results: Mapping[str, str],
) -> list[Action]:
    actions: list[Action] = []
    if upstream_watch == "failure":
        watch = Create(
            WATCH_TITLE,
            "The daily watch could not decide whether better-auth published a release. Today's "
            "sweep ran anyway - the gates fail open - so this is not a missed canary, but the "
            "watch is no longer narrowing anything and every daily tick will run the full "
            f"matrix until it is fixed. Run: {run_url}",
        )
        actions.append(file_or_comment(watch, open_issues, run_url))
    elif upstream_watch == "success":
        exact = re.compile(re.escape(WATCH_TITLE))
        actions += close_matching(exact, open_issues, f"The upstream watch read npm in {run_url}.")

    for result in results:
        if result.outcome == "passed":
            comment = (
                f"The {LANE_NAMES[result.lane]} leg against {result.target} passed in {run_url} "
                f"({result.ran}); closing."
            )
            actions += close_matching(owned_by(*result.leg), open_issues, comment)
        else:
            actions.append(file_or_comment(failure_issue(result, run_url), open_issues, run_url))

    for lane in LANES:
        title = unrecorded_title(lane)
        recorded_failure = any(r.lane == lane and r.outcome != "passed" for r in results)
        if job_results[lane] == "failure" and not recorded_failure:
            missing = Create(
                title,
                f"A {LANE_NAMES[lane]} leg failed but left no failure result, so the reporter "
                f"cannot say which leg or why; read the run. Run: {run_url}",
            )
            actions.append(file_or_comment(missing, open_issues, run_url))
        elif job_results[lane] == "success":
            exact = re.compile(re.escape(title))
            comment = f"Every {LANE_NAMES[lane]} leg recorded its result in {run_url}."
            actions += close_matching(exact, open_issues, comment)
    return actions


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
    code, output = gh([*argv, "--json", "number,title"])
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
        if not isinstance(number, int) or not isinstance(title, str):
            fail("gh issue list returned an entry without a number and a title")
        issues.append(OpenIssue(number, title))
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


def load_results(directory: Path) -> list[LegResult]:
    """Every leg's file, wherever download-artifact put it (flat when only one matched)."""
    if not directory.is_dir():
        return []
    results: dict[tuple[str, str], LegResult] = {}
    for path in sorted(directory.rglob(RESULT_FILE)):
        if path.stat().st_size > MAX_RESULT_BYTES:
            fail(f"{path} is larger than {MAX_RESULT_BYTES} bytes")
        try:
            document: object = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            fail(f"{path} is not JSON")
        if not isinstance(document, dict):
            fail(f"{path} is not a JSON object")
        fields = {str(k): v for k, v in document.items()}  # pyright: ignore[reportUnknownVariableType]
        expected = set(LegResult.__dataclass_fields__)
        if set(fields) != expected or not all(isinstance(v, str) for v in fields.values()):
            fail(f"{path} does not hold exactly the string fields {sorted(expected)}")
        result = LegResult(**{key: str(value) for key, value in fields.items()})
        if result.leg in results:
            fail(f"two results for the {result.lane} leg against {result.matrix_version}")
        results[result.leg] = result
    return list(results.values())


def record(args: argparse.Namespace) -> int:
    step: str = args.conformance_outcome
    if step == "cancelled":
        print("the conformance step was cancelled; recording nothing")
        return 0
    if step not in STEP_VERDICTS:
        fail(f"unknown conformance step outcome {step!r}")
    result = LegResult(
        lane=args.lane,
        matrix_version=args.matrix_version,
        harness_version=args.harness_version,
        wheel_version=args.wheel_version,
        outcome=STEP_VERDICTS[step],
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(asdict(result), sort_keys=True), encoding="utf-8")
    report_line(f"{LANE_NAMES[result.lane]} leg against {result.target}: {result.outcome}")
    return 0


def job_result(value: str, what: str) -> str:
    if value not in JOB_RESULTS:
        fail(f"{what} is not a job result: {value!r}")
    return value


def report(args: argparse.Namespace, gh: GhRunner) -> int:
    run_url: str = args.run_url
    if not RUN_URL.fullmatch(run_url):
        fail(f"implausible run URL {run_url!r}")
    upstream_watch = job_result(args.upstream_watch, "--upstream-watch")
    job_results = {
        "head": job_result(args.head_job, "--head-job"),
        "wheel": job_result(args.wheel_job, "--wheel-job"),
    }
    results = load_results(Path(args.results_dir))
    for result in results:
        report_line(f"{LANE_NAMES[result.lane]} leg against {result.target}: {result.outcome}")
    if (
        upstream_watch not in {"success", "failure"}
        and not results
        and all(value not in {"success", "failure"} for value in job_results.values())
    ):
        report_line("no leg ran and the watch did not decide; nothing to report")
        return 0
    actions = plan(
        results,
        list_open_issues(gh),
        run_url=run_url,
        upstream_watch=upstream_watch,
        job_results=job_results,
    )
    return 1 if execute(actions, gh) else 0


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
    leg.add_argument("--out", required=True)
    summary = commands.add_parser("report", help="file, comment on, or close issues")
    summary.add_argument("--results-dir", required=True)
    summary.add_argument("--run-url", required=True)
    summary.add_argument("--upstream-watch", required=True, help="needs.upstream-check.result")
    summary.add_argument("--head-job", required=True, help="needs.conformance.result")
    summary.add_argument("--wheel-job", required=True, help="needs.published-wheel.result")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None, gh: GhRunner | None = None) -> int:
    args = parse(argv)
    if args.command == "record":
        return record(args)
    return report(args, run_gh if gh is None else gh)


if __name__ == "__main__":
    raise SystemExit(main())
