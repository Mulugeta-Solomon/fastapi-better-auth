"""Shared helpers for the canary reporter tests: the script loader, a `gh` stand-in, and
the `record` / `report` calls a workflow would make."""

from __future__ import annotations

import datetime as dt
import functools
import importlib.util
import json
import pathlib
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, cast

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
OCTOBER = "2026-10-15T21:44:29Z"
T0 = dt.datetime(2026, 11, 24, 12, 0, 0, tzinfo=dt.timezone.utc)
LANE_NAMES = {"head": "HEAD conformance", "wheel": "published-wheel"}


class Report(Protocol):
    def main(
        self,
        argv: Sequence[str] | None = None,
        gh: Callable[[Sequence[str]], tuple[int, str]] | None = None,
        clock: Callable[[], dt.datetime] | None = None,
    ) -> int: ...


class Gh:
    """Stands in for the `gh` CLI: serves one issue list and records every other call."""

    def __init__(
        self,
        issues: Mapping[int, str],
        *,
        failing: str = "",
        created: Mapping[int, str] | None = None,
    ) -> None:
        self.issues = dict(issues)
        self.created = dict(created or {})
        self.failing = failing
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str]) -> tuple[int, str]:
        call = list(argv)
        if call[:2] == ["issue", "list"]:
            listed = [
                {"number": n, "title": t, "createdAt": self.created.get(n, OCTOBER)}
                for n, t in self.issues.items()
            ]
            return 0, json.dumps(listed)
        self.calls.append(call)
        if self.failing and call[:2] == ["issue", self.failing]:
            return 1, ""
        return 0, ""

    def of(self, verb: str) -> list[list[str]]:
        return [call for call in self.calls if call[:2] == ["issue", verb]]


@functools.cache
def load_script() -> Report:
    spec = importlib.util.spec_from_file_location("canary_report", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # `dataclasses` resolves string annotations through sys.modules[cls.__module__].
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(Report, module)


def record(
    script: Report,
    results: pathlib.Path,
    *,
    lane: str,
    version: str,
    outcome: str,
    harness: str = "",
    wheel: str = "",
    attempt: str = "1",
    now: dt.datetime | None = None,
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
        "--run-attempt",
        attempt,
        "--out",
        str(out),
    ]
    return script.main(argv, clock=None if now is None else (lambda: now))


def report(
    script: Report,
    results: pathlib.Path,
    gh: Gh,
    *,
    watch: str = "skipped",
    jobs: Mapping[str, str] | None = None,
    versions: Sequence[str] | None = None,
    attempt: str = "1",
    now: dt.datetime | None = None,
) -> int:
    expected = recorded_versions(results) if versions is None else list(versions)
    lanes = {**default_jobs(results), **(jobs or {})}
    argv = [
        "report",
        "--results-dir",
        str(results),
        "--run-url",
        RUN_URL,
        "--upstream-watch",
        watch,
        "--head-job",
        lanes["head"],
        "--wheel-job",
        lanes["wheel"],
        "--expected-versions",
        json.dumps(expected),
        "--run-attempt",
        attempt,
    ]
    return script.main(argv, gh=gh, clock=None if now is None else (lambda: now))


def default_jobs(results: pathlib.Path) -> dict[str, str]:
    """A lane a test leaves unnamed is green when it recorded something and skipped otherwise:
    a green lane that recorded nothing is a coverage gap, which only coverage tests want."""
    recorded: set[str] = (
        {path.name.split("-")[2] for path in results.glob("canary-result-*-*") if path.is_dir()}
        if results.is_dir()
        else set()
    )
    return {lane: "success" if lane in recorded else "skipped" for lane in ("head", "wheel")}


def recorded_versions(results: pathlib.Path) -> list[str]:
    """By default a test expects exactly the legs it recorded, so only coverage tests see gaps."""
    if not results.is_dir():
        return ["1.7.1"]
    found = {
        path.name.split("-", 3)[3]
        for path in results.glob("canary-result-*-*")
        if path.is_dir() and path.name.count("-") >= 3
    }
    return sorted(found) or ["1.7.1"]


def created_titles(gh: Gh) -> list[str]:
    return [call[call.index("--title") + 1] for call in gh.of("create")]


def numbers(calls: list[list[str]]) -> list[str]:
    return [call[2] for call in calls]


def unrecorded_body(gh: Gh, lane: str) -> str:
    title = f"canary: a {LANE_NAMES[lane]} leg failed without recording its result"
    (call,) = [c for c in gh.of("create") if c[c.index("--title") + 1] == title]
    return call[call.index("--body") + 1]


def close_comments(gh: Gh) -> dict[str, str]:
    return {call[2]: call[call.index("--comment") + 1] for call in gh.of("close")}
