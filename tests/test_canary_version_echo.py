"""The canary's version echo: a leg is named for its matrix entry, and this holds it to the name.

`.github/scripts/harness_better_auth_version.py` runs right after the harness starts. It reads
the better-auth version every harness server really imports and fails the leg when a concrete
matrix entry is not what is running - a green leg under the wrong name would put a version
into `VERIFIED_BETTER_AUTH` that nothing verified. For `latest` it publishes what the tag
resolved to, so a failure issue can say which release broke.

The script talks to Docker, so its decisions are driven here through an injected reader and its
subprocess edge through a stand-in command. That the real read works is the canary's own job:
every leg runs it before the conformance lane can start.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import NamedTuple, Protocol, cast

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "harness_better_auth_version.py"
COMPOSE_FILE = ROOT / "harness" / "docker-compose.yml"
CANARY = ROOT / ".github" / "workflows" / "canary.yml"

SERVICE_LINE = re.compile(r"^  ([a-z][a-z0-9-]*):\s*$")
MATRIX_JOBS = 2
ECHO_CALL = 'harness_better_auth_version.py --expected "$MATRIX_VERSION"'
MAIN_ONLY = "github.ref == 'refs/heads/main'"


class EchoScript(Protocol):
    SERVICES: tuple[str, ...]

    def main(
        self, argv: Sequence[str] | None = None, read: Callable[[str], str] | None = None
    ) -> int: ...

    def read_version(
        self, service: str, *, command: Sequence[str] = ..., timeout: float = ...
    ) -> str: ...


class Workflow(NamedTuple):
    output: pathlib.Path
    summary: pathlib.Path


class Reader:
    """Stands in for `docker compose exec`: one answer per service, and a record of who was asked."""

    def __init__(self, answers: Mapping[str, str]) -> None:
        self.answers = dict(answers)
        self.asked: list[str] = []

    def __call__(self, service: str) -> str:
        self.asked.append(service)
        return self.answers[service]


@pytest.fixture(scope="module")
def script() -> EchoScript:
    spec = importlib.util.spec_from_file_location("harness_better_auth_version", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast(EchoScript, module)


@pytest.fixture
def workflow(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Workflow:
    """The two files a GitHub step appends to, empty, so every write can be asserted."""
    output, summary = tmp_path / "output", tmp_path / "summary"
    output.touch()
    summary.touch()
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    return Workflow(output, summary)


def everywhere(script: EchoScript, version: str) -> dict[str, str]:
    return dict.fromkeys(script.SERVICES, version)


def auth_server_services() -> frozenset[str]:
    """Every compose service built from `./auth-server` - the servers a canary leg tests."""
    services: set[str] = set()
    current = ""
    for line in COMPOSE_FILE.read_text(encoding="utf-8").splitlines():
        if match := SERVICE_LINE.match(line):
            current = match.group(1)
        elif line.strip() == "context: ./auth-server":
            services.add(current)
    return frozenset(services)


def matrix_jobs() -> tuple[str, ...]:
    """The text of every canary job that sweeps a `version:` matrix, in file order."""
    text = CANARY.read_text(encoding="utf-8")
    _, jobs = text.split("\njobs:\n", 1)
    bodies = re.split(r"^  [a-z][a-z0-9-]*:\s*$", jobs, flags=re.MULTILINE)
    return tuple(body for body in bodies if re.search(r"^\s*version: \[", body, re.MULTILINE))


def test_every_server_the_harness_builds_is_read(script: EchoScript) -> None:
    """A fifth posture added to the compose file without being read would be an unnamed leg."""
    assert "auth" in script.SERVICES
    assert auth_server_services() == frozenset(script.SERVICES)


def test_a_concrete_entry_the_servers_run_passes_and_publishes_it(
    script: EchoScript, workflow: Workflow
) -> None:
    reader = Reader(everywhere(script, "1.7.5"))

    assert script.main(["--expected", "1.7.5"], read=reader) == 0

    assert reader.asked == list(script.SERVICES)
    assert workflow.output.read_text(encoding="utf-8") == "version=1.7.5\n"
    assert "better-auth@1.7.5" in workflow.summary.read_text(encoding="utf-8")


def test_a_concrete_entry_the_servers_do_not_run_fails_the_leg_naming_both(
    script: EchoScript, workflow: Workflow, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exited:
        script.main(["--expected", "1.7.5"], read=Reader(everywhere(script, "1.7.4")))

    assert exited.value.code == 1
    error = capsys.readouterr().err
    assert "better-auth@1.7.5" in error
    assert "1.7.4" in error
    assert workflow.output.read_text(encoding="utf-8") == "version=1.7.4\n"


def test_latest_passes_and_publishes_what_it_resolved_to(
    script: EchoScript, workflow: Workflow
) -> None:
    assert script.main(["--expected", "latest"], read=Reader(everywhere(script, "1.7.6"))) == 0

    assert workflow.output.read_text(encoding="utf-8") == "version=1.7.6\n"
    summary = workflow.summary.read_text(encoding="utf-8")
    assert "latest" in summary
    assert "1.7.6" in summary


@pytest.mark.parametrize("expected", ["1.7.5", "latest"])
def test_servers_that_disagree_fail_the_leg_and_publish_nothing(
    script: EchoScript, workflow: Workflow, capsys: pytest.CaptureFixture[str], expected: str
) -> None:
    answers = {**everywhere(script, "1.7.5"), "auth-strict": "1.7.6"}

    with pytest.raises(SystemExit) as exited:
        script.main(["--expected", expected], read=Reader(answers))

    assert exited.value.code == 1
    error = capsys.readouterr().err
    assert "auth-strict" in error
    assert "1.7.6" in error
    assert workflow.output.read_text(encoding="utf-8") == ""


@pytest.mark.parametrize(
    "reported",
    ["", "1.7", "v1.7.5", "latest", "1.7.5 ", "1.7.5\nversion=9.9.9", f"1.7.5-{'x' * 200}"],
    ids=["empty", "partial", "prefixed", "tag", "padded", "forges-an-output", "overlong"],
)
def test_an_implausible_version_never_reaches_the_workflow(
    script: EchoScript, workflow: Workflow, capsys: pytest.CaptureFixture[str], reported: str
) -> None:
    """Every server says the same thing, so the agreement check cannot be what refuses it."""
    with pytest.raises(SystemExit) as exited:
        script.main(["--expected", "latest"], read=Reader(everywhere(script, reported)))

    assert exited.value.code == 1
    assert "implausible better-auth version" in capsys.readouterr().err
    assert workflow.output.read_text(encoding="utf-8") == ""
    assert workflow.summary.read_text(encoding="utf-8") == ""


@pytest.mark.parametrize("expected", ["", "next", "1.7", "LATEST", "1.7.5\n"])
def test_an_entry_that_is_neither_a_version_nor_a_known_tag_is_refused_before_any_read(
    script: EchoScript, workflow: Workflow, expected: str
) -> None:
    reader = Reader(everywhere(script, "1.7.5"))

    with pytest.raises(SystemExit) as exited:
        script.main(["--expected", expected], read=reader)

    assert exited.value.code == 1
    assert reader.asked == []
    assert workflow.output.read_text(encoding="utf-8") == ""


def test_the_read_execs_node_in_the_named_service(script: EchoScript) -> None:
    """What reaches `docker compose`: the service, then a node read of better-auth's manifest."""
    echo_argv = (sys.executable, "-c", "import json, sys; print(json.dumps(sys.argv[1:]))")

    argv = json.loads(script.read_version("auth-redis", command=echo_argv, timeout=30))

    assert argv[:3] == ["exec", "-T", "auth-redis"]
    assert argv[3:5] == ["node", "-p"]
    assert "/node_modules/better-auth/package.json" in argv[5]


def test_the_read_returns_the_printed_version_without_its_newline(script: EchoScript) -> None:
    printer = (sys.executable, "-c", "print('1.7.1')")

    assert script.read_version("auth", command=printer, timeout=30) == "1.7.1"


@pytest.mark.parametrize(
    ("command", "timeout"),
    [
        ((sys.executable, "-c", "import sys; sys.exit('no such service')"), 30),
        ((sys.executable, "-c", "import time; time.sleep(30)"), 1.0),
        (("a-docker-binary-that-is-not-installed",), 30),
    ],
    ids=["exits-non-zero", "hangs", "not-installed"],
)
def test_a_read_that_cannot_be_answered_fails_the_leg(
    script: EchoScript, command: tuple[str, ...], timeout: float
) -> None:
    with pytest.raises(SystemExit) as exited:
        script.read_version("auth", command=command, timeout=timeout)

    assert exited.value.code == 1


def test_both_matrix_jobs_echo_after_the_harness_starts_and_before_any_test() -> None:
    jobs = matrix_jobs()

    assert len(jobs) == MATRIX_JOBS
    for job in jobs:
        started, echoed = job.index("- name: Start harness"), job.index(ECHO_CALL)
        assert started < echoed < job.index("pytest")


def test_no_matrix_job_files_an_issue_from_a_branch() -> None:
    """A dispatch on a branch is its dispatcher's to read; an issue it filed would be public."""
    jobs = matrix_jobs()

    assert len(jobs) == MATRIX_JOBS
    for job in jobs:
        step = job.split("- name: Open issue on failure\n", 1)[1]
        condition = step.splitlines()[0].strip()
        assert condition.startswith("if: "), condition
        assert condition.endswith(f"&& {MAIN_ONLY}"), condition
