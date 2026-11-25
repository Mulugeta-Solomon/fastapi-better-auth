"""The CI guardrails the workflows, the harness and Dependabot promise, held as text.

Each test here is a property a reviewer would otherwise have to re-check by eye on every
workflow change, and each one guards a concrete failure:

- a release publishes only a commit on `main` whose full test workflow, e2e conformance
  included, passed in the same run, and only the publish job can mint the PyPI OIDC token;
- no checkout leaves the job token in `.git/config` for npm-installed or pytest code to read,
  and the only job that can write issues is the small reporter;
- uv is the version `pyproject.toml` asks for, and a stale lock fails instead of being
  silently re-resolved;
- no `run:` step splices an expression into shell source;
- the harness listens on loopback only, on overridable ports below the ephemeral range, its images are pinned by digest, and Dependabot keeps
  them current without touching the deliberate better-auth conformance pin.

There is no YAML parser in the locked dependencies, so these read the files as text, the way
`test_verified_better_auth.py` and `test_canary_version_echo.py` already do. Every locator is
guarded against finding nothing, because a parser that silently matched zero steps would make
every assertion below pass over an empty set.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
TEST = WORKFLOWS / "test.yml"
RELEASE = WORKFLOWS / "release.yml"
CANARY = WORKFLOWS / "canary.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
COMPOSE = ROOT / "harness" / "docker-compose.yml"
DOCKERFILE = ROOT / "harness" / "auth-server" / "Dockerfile"
E2E_CONFTEST = ROOT / "tests" / "e2e" / "conftest.py"

JOB = re.compile(r"^  ([a-z][a-z0-9-]*):\s*$", re.MULTILINE)
STEP = re.compile(r"^      - ", re.MULTILINE)
USES = re.compile(r"^\s*(?:- )?uses:\s*(\S+)(.*)$", re.MULTILINE)
PINNED = re.compile(r"(?P<action>[\w.-]+/[\w./-]+)@(?P<sha>[0-9a-f]{40})")
TAG_COMMENT = re.compile(r"^\s+# v\d+\.\d+\.\d+$")
RUN_KEY = re.compile(r"^(?P<indent>\s*)(?:- )?run:\s?(?P<value>.*)$")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\b")
PORT_MAPPING = re.compile(
    r"127\.0\.0\.1:\$\{(?P<variable>HARNESS_[A-Z_]+_PORT):-(?P<default>\d+)\}:(?P<container>\d+)"
)
EPHEMERAL_FLOOR = 32768
HOST_PORT_VARIABLES = {
    "postgres": "HARNESS_POSTGRES_PORT",
    "redis": "HARNESS_REDIS_PORT",
    "auth": "HARNESS_AUTH_PORT",
    "auth-redis": "HARNESS_AUTH_REDIS_PORT",
    "auth-strict": "HARNESS_AUTH_STRICT_PORT",
    "auth-throttled": "HARNESS_AUTH_THROTTLED_PORT",
}
JOB_TIMEOUT = re.compile(r"^    timeout-minutes: (?P<minutes>\d+)\s*$", re.MULTILINE)
"""A job-level bound: four spaces deep, beside `runs-on:`, not a step's own six-space one."""
MAX_JOB_MINUTES = 60
UNLOCKED_SYNC_JOBS = {"floors"}
"""`floors` re-locks with `--resolution lowest-direct` on purpose and then syncs `--frozen`."""


def workflow_files() -> list[pathlib.Path]:
    files = sorted(WORKFLOWS.glob("*.yml"))
    assert {TEST, RELEASE, CANARY} <= set(files)
    return files


def jobs(path: pathlib.Path) -> dict[str, str]:
    """Each job's text, keyed by its id."""
    _, body = path.read_text(encoding="utf-8").split("\njobs:\n", 1)
    names = JOB.findall(body)
    texts = JOB.split(body)[2::2]
    assert names, f"no jobs found in {path.name}"
    return dict(zip(names, texts, strict=True))


def steps(job: str) -> list[str]:
    found = [f"      - {text}" for text in STEP.split(job)[1:]]
    return found


def all_steps() -> list[tuple[str, str, str]]:
    found = [
        (path.name, name, step)
        for path in workflow_files()
        for name, job in jobs(path).items()
        for step in steps(job)
    ]
    assert len(found) > 30, "the step locator found too few steps"
    return found


def run_blocks(step: str) -> list[str]:
    """The shell source of a step's `run:` key, single-line or block scalar."""
    lines = step.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        match = RUN_KEY.match(line)
        if not match:
            continue
        value = match.group("value")
        if value.strip() not in {"|", ">", "|-", ">-"}:
            blocks.append(value)
            continue
        indent = len(match.group("indent")) + (2 if line.lstrip().startswith("- ") else 0)
        body: list[str] = []
        for following in lines[index + 1 :]:
            if following.strip() and len(following) - len(following.lstrip()) <= indent:
                break
            body.append(following)
        blocks.append("\n".join(body))
    return blocks


def steps_using(action: str) -> list[tuple[str, str, str]]:
    found = [entry for entry in all_steps() if f"uses: {action}@" in entry[2]]
    assert found, f"no step uses {action}"
    return found


# --- actions and tooling ----------------------------------------------------------------------


def test_every_remote_action_is_a_full_sha_with_its_tag_alongside() -> None:
    uses = [
        match
        for path in workflow_files()
        for match in USES.finditer(path.read_text(encoding="utf-8"))
    ]
    remote = [match for match in uses if not match.group(1).startswith("./")]

    assert remote
    for match in remote:
        assert PINNED.fullmatch(match.group(1)), match.group(0)
        assert TAG_COMMENT.match(match.group(2)), match.group(0)


def test_each_action_is_pinned_to_one_sha_everywhere() -> None:
    pins: dict[str, set[str]] = {}
    for path in workflow_files():
        for match in USES.finditer(path.read_text(encoding="utf-8")):
            if pinned := PINNED.fullmatch(match.group(1)):
                pins.setdefault(pinned["action"], set()).add(f"{pinned['sha']}{match.group(2)}")

    assert pins
    assert {action: shas for action, shas in pins.items() if len(shas) > 1} == {}


def test_every_checkout_leaves_no_credentials_in_git_config() -> None:
    for workflow, job, step in steps_using("actions/checkout"):
        assert "persist-credentials: false" in step, f"{workflow}:{job}"


def test_every_setup_uv_reads_its_version_from_pyproject() -> None:
    for workflow, job, step in steps_using("astral-sh/setup-uv"):
        assert "version-file: pyproject.toml" in step, f"{workflow}:{job}"


def uv_required_version() -> str | None:
    """`[tool.uv].required-version`, read as text: Python 3.10 ships no `tomllib`."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    section = re.search(r"^\[tool\.uv\]\s*$(?P<body>.*?)(?=^\[)", text, re.MULTILINE | re.DOTALL)
    if section is None:
        return None
    value = re.search(r'^required-version\s*=\s*"([^"]+)"', section["body"], re.MULTILINE)
    return value.group(1) if value else None


def test_pyproject_gives_every_setup_uv_a_version_to_read() -> None:
    """With an explicit version-file, setup-uv throws when the file names no uv version, so
    removing this key would turn every job that sets up uv red, release included."""
    readers = [
        s for s in steps_using("astral-sh/setup-uv") if "version-file: pyproject.toml" in s[2]
    ]
    required = uv_required_version()

    assert readers
    assert required is not None, "pyproject.toml has no [tool.uv] required-version"
    assert re.fullmatch(r"[<>=!~]=?\s*\d+(\.\d+)*(\s*,\s*[<>=!~]=?\s*\d+(\.\d+)*)*", required)


def test_uv_sync_never_re_resolves_a_stale_lock() -> None:
    syncs = [
        (workflow, job, block)
        for workflow, job, step in all_steps()
        for block in run_blocks(step)
        if "uv sync" in block
    ]

    assert syncs
    for workflow, job, block in syncs:
        expected = "--frozen" if job in UNLOCKED_SYNC_JOBS else "--locked"
        assert expected in block, f"{workflow}:{job}: {block.strip()}"


def test_no_run_step_splices_an_expression_into_shell_source() -> None:
    """Values reach the shell through `env:`; `${{ }}` in `run:` is template injection."""
    blocks = [(w, j, b) for w, j, s in all_steps() for b in run_blocks(s)]

    assert len(blocks) > 20, "the run-block locator found too few blocks"
    for workflow, job, block in blocks:
        assert "${{" not in block, f"{workflow}:{job}: {block.strip()}"


# --- release ----------------------------------------------------------------------------------


def test_the_test_workflow_is_reusable_and_keeps_its_triggers() -> None:
    head = TEST.read_text(encoding="utf-8").split("\njobs:\n", 1)[0]

    for trigger in ("push:", "pull_request:", "workflow_dispatch:", "workflow_call:"):
        assert f"\n  {trigger}" in head, trigger


def test_every_test_job_is_bounded_in_time() -> None:
    """A hung test holds a runner for GitHub's default six hours and reports nothing; a job
    bound turns that into a failure within the hour. The bound is generous - the unit lanes take
    minutes - so it only ever fires on a hang (pytest's `faulthandler_timeout` says where)."""
    for name, job in jobs(TEST).items():
        bound = JOB_TIMEOUT.search(job)
        assert bound is not None, f"test.yml job {name!r} has no job-level timeout-minutes"
        assert 0 < int(bound.group("minutes")) <= MAX_JOB_MINUTES, (name, bound.group(0))


def test_publish_waits_for_main_ancestry_and_the_full_test_workflow() -> None:
    release = jobs(RELEASE)

    calls = [name for name, job in release.items() if "uses: ./.github/workflows/test.yml" in job]
    assert len(calls) == 1
    guard = next(name for name, job in release.items() if "merge-base --is-ancestor" in job)
    assert "fetch-depth: 0" in release[guard]
    build_needs = re.search(r"needs: \[(.*)\]", release["build"])
    assert build_needs is not None
    assert {part.strip() for part in build_needs.group(1).split(",")} == {guard, calls[0]}
    publish_needs = re.search(r"^    needs: \[(.*)\]$", release["publish"], re.MULTILINE)
    assert publish_needs is not None
    assert {part.strip() for part in publish_needs.group(1).split(",")} == {
        guard,
        calls[0],
        "build",
    }


def test_release_can_be_rehearsed_by_dispatch_without_publishing() -> None:
    """PR CI never runs release.yml, and `v*` tags are immutable: a bug first found on the real
    release burns the tag. A dispatch runs on-main, the tests and build, and never publish."""
    head = RELEASE.read_text(encoding="utf-8").split("\njobs:\n", 1)[0]
    release = jobs(RELEASE)

    assert "\n  release:\n    types: [published]\n" in head
    assert "\n  workflow_dispatch:\n" in head
    publish_if = re.findall(r"^    if: (.*)$", release["publish"], re.MULTILINE)
    assert publish_if == ["github.event_name == 'release'"]
    for name in ("on-main", "tests", "build"):
        assert not re.search(r"^    if: ", release[name], re.MULTILINE), name


def test_only_the_tag_guard_is_skipped_on_a_dispatch() -> None:
    """There is no tag on a dispatch; every other build guard runs either way."""
    build_steps = steps(jobs(RELEASE)["build"])
    conditions = {
        step.splitlines()[0]: re.findall(r"^        if: (.*)$", step, re.MULTILINE)
        for step in build_steps
    }

    tag_guard = [line for line in conditions if "git tag must equal" in line]
    assert len(tag_guard) == 1
    assert conditions[tag_guard[0]] == ["github.event_name != 'workflow_dispatch'"]
    others = {line: found for line, found in conditions.items() if line not in tag_guard}
    assert others
    assert all(found == [] for found in others.values()), others


def test_only_the_checkout_free_publish_job_can_mint_the_pypi_token() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    release = jobs(RELEASE)

    assert text.count("id-token: write") == 1
    assert "id-token: write" in release["publish"]
    assert "actions/checkout" not in release["publish"]
    assert "environment: pypi" in release["publish"]


# --- canary -----------------------------------------------------------------------------------


def test_exactly_one_small_job_can_write_issues() -> None:
    text = CANARY.read_text(encoding="utf-8")
    writers = [name for name, job in jobs(CANARY).items() if "issues: write" in job]

    assert text.count("issues: write") == 1
    assert len(writers) == 1
    writer = jobs(CANARY)[writers[0]]
    assert "docker" not in writer
    assert "uv " not in writer
    assert "canary_report.py report" in writer


def test_the_issue_writer_runs_only_on_main_and_never_for_a_cancelled_run() -> None:
    (writer,) = [job for job in jobs(CANARY).values() if "issues: write" in job]
    condition = re.search(r"^    if: (.*)$", writer, re.MULTILINE)

    assert condition is not None
    assert "!cancelled()" in condition.group(1)
    assert "github.ref == 'refs/heads/main'" in condition.group(1)


def test_no_workflow_talks_to_issues_outside_the_reporter_script() -> None:
    for path in workflow_files():
        assert "gh issue" not in path.read_text(encoding="utf-8"), path.name


def test_the_reporter_expects_exactly_the_matrix_both_lanes_sweep() -> None:
    """Three copies of one list: the two matrices and the reporter's expected coverage. If the
    reporter's copy drifted, a dropped leg would never be reported missing."""
    text = CANARY.read_text(encoding="utf-8")
    matrices = re.findall(r"^\s+version: (\[[^]]*\])$", text, re.MULTILINE)
    expected = re.findall(r"^\s+EXPECTED_VERSIONS: '(\[[^]]*\])'$", text, re.MULTILINE)

    assert len(matrices) == 2
    assert len(expected) == 1
    assert json.loads(matrices[0]) == json.loads(matrices[1]) == json.loads(expected[0])
    (writer,) = [job for job in jobs(CANARY).values() if "issues: write" in job]
    assert '--expected-versions "$EXPECTED_VERSIONS"' in writer


def test_one_canary_run_at_a_time_and_none_cancelled_mid_flight() -> None:
    """Two runs reporting at once could both file one title, or one could close what the other
    just filed. Queued, never cancelled in progress: a cancelled run would report nothing."""
    head = CANARY.read_text(encoding="utf-8").split("\njobs:\n", 1)[0]

    assert (
        "\nconcurrency:\n"
        "  group: ${{ github.workflow }}-${{ github.ref }}\n"
        "  cancel-in-progress: false\n"
    ) in head


def test_every_record_and_the_report_name_their_run_attempt() -> None:
    """A partial re-run mixes attempts in one download; the reporter weighs them by attempt."""
    text = CANARY.read_text(encoding="utf-8")

    assert text.count("canary_report.py record") == 2
    assert text.count('--run-attempt "$GITHUB_RUN_ATTEMPT"') == 3
    (writer,) = [job for job in jobs(CANARY).values() if "issues: write" in job]
    assert '--run-attempt "$GITHUB_RUN_ATTEMPT"' in writer


def test_every_matrix_leg_records_and_uploads_its_verdict() -> None:
    legs = [job for job in jobs(CANARY).values() if "version: [" in job]

    assert len(legs) == 2
    for job in legs:
        record, upload = job.index("canary_report.py record"), job.index("actions/upload-artifact")
        assert job.index("id: conformance") < record < upload
        assert "${{ !cancelled() }}" in job[job.rindex("- name", 0, record) : record]


# --- harness and Dependabot -------------------------------------------------------------------


def compose_services() -> dict[str, str]:
    """Each compose service's text, keyed by its name."""
    body = COMPOSE.read_text(encoding="utf-8").split("\nservices:\n", 1)[1]
    names = JOB.findall(body)
    assert names, "no services found in the compose file"
    return dict(zip(names, JOB.split(body)[2::2], strict=True))


def published_ports() -> dict[str, tuple[str, int, int]]:
    """service -> (host-port variable, its default, container port), from each port mapping."""
    found: dict[str, tuple[str, int, int]] = {}
    for service, text in compose_services().items():
        for mapping in re.findall(r'^\s+- "([^"]+)"$', text, re.MULTILINE):
            match = PORT_MAPPING.fullmatch(mapping)
            assert match, f"{service}: {mapping} is not 127.0.0.1:${{HARNESS_*_PORT:-n}}:n"
            found[service] = (match["variable"], int(match["default"]), int(match["container"]))
    return found


def test_every_published_harness_port_is_loopback_overridable_and_below_ephemeral() -> None:
    """Linux hands out 32768-60999 to outgoing connections and Windows reserves blocks of its
    49152+ range for Hyper-V per boot, so a default up there collides at random (Nov 9 run)."""
    ports = published_ports()

    assert {service: variable for service, (variable, _, _) in ports.items()} == HOST_PORT_VARIABLES
    for service, (_, default, _) in ports.items():
        assert 1024 < default < EPHEMERAL_FLOOR, f"{service} defaults to {default}"
    assert ports["postgres"][1:] == (15432, 5432)
    assert ports["redis"][1:] == (16379, 6379)


def test_an_auth_servers_origin_follows_its_host_port() -> None:
    """Better Auth trusts its own baseURL origin, and the e2e lane sends that host-side origin,
    so a moved host port must move BETTER_AUTH_URL with it or every signed POST is refused."""
    services = compose_services()
    auth = {name: port for name, port in published_ports().items() if name.startswith("auth")}

    assert len(auth) == 4
    for service, (variable, default, container) in auth.items():
        url = f"BETTER_AUTH_URL: http://localhost:${{{variable}:-{default}}}"
        assert url in services[service], service
        assert f'PORT: "{container}"' in services[service], service


def test_the_e2e_defaults_follow_the_compose_defaults() -> None:
    conftest = E2E_CONFTEST.read_text(encoding="utf-8")

    for variable, default, _ in published_ports().values():
        assert f'harness_port("{variable}", "{default}")' in conftest, variable


@pytest.mark.parametrize("value", [None, "", "   "], ids=["unset", "empty", "blank"])
def test_an_unset_or_empty_port_variable_falls_back_to_the_compose_default(
    monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    """Compose's `${VAR:-default}` treats an empty variable as unset; the fixtures must too, or
    an empty `HARNESS_AUTH_PORT=` builds `http://localhost:` and every e2e leg errors."""
    from tests.e2e import conftest

    for variable, default, _ in published_ports().values():
        if value is None:
            monkeypatch.delenv(variable, raising=False)
        else:
            monkeypatch.setenv(variable, value)
        assert conftest.harness_port(variable, str(default)) == str(default)


def test_a_set_port_variable_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.e2e import conftest

    monkeypatch.setenv("HARNESS_POSTGRES_PORT", "25432")

    assert conftest.harness_port("HARNESS_POSTGRES_PORT", "15432") == "25432"


def test_each_leg_uploads_under_the_name_the_reporter_binds_it_to() -> None:
    text = CANARY.read_text(encoding="utf-8")

    for lane in ("head", "wheel"):
        assert f"name: canary-result-{lane}-${{{{ matrix.version }}}}\n" in text, lane


def test_every_harness_image_is_pinned_by_digest_and_keeps_its_tag() -> None:
    images = re.findall(r"^\s+image:\s*(\S+)", COMPOSE.read_text(encoding="utf-8"), re.MULTILINE)
    bases = re.findall(r"^FROM\s+(\S+)", DOCKERFILE.read_text(encoding="utf-8"), re.MULTILINE)

    assert len(images) == 2
    assert len(bases) == 1
    for image in (*images, *bases):
        assert DIGEST.search(image), image
        assert re.match(r"[\w.-]+:[\w.-]+@", image), f"{image} lost its readable tag"


def test_the_canary_version_override_is_retried_but_still_fails_loudly() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    override = text[text.index("ARG BETTER_AUTH_VERSION") :].split("\nCOPY ", 1)[0]

    assert 'npm install --no-save "better-auth@${BETTER_AUTH_VERSION}"' in override
    assert re.search(r"-ge \d", override), "the retry is not bounded"
    assert '"$BETTER_AUTH_VERSION" = "$pinned"' in override, "the no-op install is not skipped"
    assert "exit 1" in override


@pytest.mark.parametrize(
    ("ecosystem", "directory"),
    [
        ("github-actions", "/"),
        ("uv", "/"),
        ("npm", "/harness/auth-server"),
        ("docker", "/harness/auth-server"),
        ("docker-compose", "/harness"),
    ],
)
def test_dependabot_watches_every_pinned_surface(ecosystem: str, directory: str) -> None:
    text = DEPENDABOT.read_text(encoding="utf-8")

    assert f"package-ecosystem: {ecosystem}\n    directory: {directory}\n" in text


def test_dependabot_leaves_the_better_auth_conformance_pin_alone() -> None:
    """better-auth and auth move with COMPATIBILITY.md, the canary matrix and the constant."""
    text = DEPENDABOT.read_text(encoding="utf-8")
    npm = text.split("package-ecosystem: npm\n", 1)[1].split("package-ecosystem:", 1)[0]

    for package in ("better-auth", "auth"):
        assert f'- dependency-name: "{package}"' in npm, package
