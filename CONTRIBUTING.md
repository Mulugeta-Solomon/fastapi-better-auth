# Contributing

After reading this page you can set up the project, run every check CI runs, run the live
conformance tests, and prepare a change the way the maintainer reviews it.

## Setup

The project uses [uv](https://docs.astral.sh/uv/). `pyproject.toml` pins the uv version
(`[tool.uv] required-version`), and the build backend `uv_build` is pinned to the same release
line, so use a uv inside that range. Install the locked development environment:

```bash
uv sync --locked
```

`--locked` fails if `uv.lock` does not match `pyproject.toml`, instead of quietly updating it. If
you change a dependency, run `uv lock` and commit `uv.lock` with the change.

## The checks

Run all of these before you open a pull request. CI runs them on every pull request and every push
to `main`.

```bash
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest -q
uv build
```

- `pyright` runs in strict mode over `src/`, `tests/` and `.github/scripts/`.
- `pytest -q` runs the unit tests. Warnings are errors (`filterwarnings = ["error", ...]` in
  `pyproject.toml`).
- Many tests run on both anyio backends, asyncio and trio.
- `tests/test_readme.py` runs every Python example in `README.md`, `COMPATIBILITY.md` and
  `docs/*.md`. If you change an example, run it. An example that cannot run offline (it needs a
  database, a network or your own application) goes in a `text` block, not a `python` block.
- `tests/test_doc_links.py` checks that every link in the README and `docs/` resolves. Links in
  `README.md` must be absolute `https://` URLs, because PyPI renders the README and relative links
  break there. Links between `docs/` pages are relative.
- `uv build` builds the wheel and the sdist. The README is the package's long description.

CI also runs the unit tests on every supported Python version, on macOS and Windows, against the
lowest declared dependency versions, and on the next Python pre-release (advisory only). See
`.github/workflows/test.yml` and [COMPATIBILITY.md](COMPATIBILITY.md).

## The live conformance tests

The tests marked `e2e` run against real Better Auth servers. They are excluded by default
(`addopts = "-m 'not e2e'"` in `pyproject.toml`), so `uv run pytest -q` never needs Docker.

The servers are defined in `harness/docker-compose.yml`: Better Auth on Node with Postgres, and
optional profiles for Redis secondary storage, the strict `bearer` posture and a rate-limited
`get-session`. Start every profile, as CI does, then run the marked tests:

```bash
docker compose -f harness/docker-compose.yml --profile redis --profile strict --profile throttled up --build -d --wait
uv run pytest -m e2e -q
docker compose -f harness/docker-compose.yml --profile redis --profile strict --profile throttled down -v
```

The ports each service listens on are in `harness/docker-compose.yml`. The tests read the server
URLs from `HARNESS_URL`, `REDIS_HARNESS_URL`, `STRICT_HARNESS_URL`, `THROTTLED_HARNESS_URL`,
`HARNESS_POSTGRES_URL` and `HARNESS_REDIS_URL` (defaults in `tests/e2e/conftest.py`). Locally, a
test whose profile is not running is skipped with a reason; in CI it fails. `harness/README.md`
describes each server.

## How to make a change

- **A bug fix starts with a failing test.** Commit the test that reproduces the bug, see it fail,
  then fix the code. The pull request says which test failed before the fix.
- **Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):**
  `<type>: <description>`, where the type is one of `feat`, `fix`, `refactor`, `docs`, `test`,
  `chore`, `perf` or `ci`.
- **Document what you change.** A change a user can see gets a line under "Unreleased" in
  [CHANGELOG.md](CHANGELOG.md), with an upgrade note if users must change something, and an update
  to the page in `docs/` that describes it.
- **Security problems** are reported privately; see [SECURITY.md](SECURITY.md).

## How a release happens

The maintainer releases. The steps:

1. A release pull request sets the new version in both `pyproject.toml` (`version`) and
   `src/fastapi_better_auth/__init__.py` (`__version__`), updates `uv.lock`, and moves the
   "Unreleased" entries in `CHANGELOG.md` under the new version. A unit test fails if
   `__version__` and the installed package version differ.
2. After it is merged, the maintainer publishes a GitHub release with the tag `vX.Y.Z` on the merge
   commit.
3. Publishing the release runs `.github/workflows/release.yml`. It builds with
   `uv build --no-sources`, refuses to continue if the tag does not equal the built wheel's version
   or if the wheel does not ship `py.typed`, and uploads to PyPI with Trusted Publishing from the
   `pypi` environment. No API token is stored anywhere.
4. The weekly canary (`.github/workflows/canary.yml`) then also tests the wheel published on PyPI.
   The "Last green on the published wheel" column of [COMPATIBILITY.md](COMPATIBILITY.md) is
   updated by hand from that run.
