"""Read the better-auth version every running harness server imports, and hold the leg to it.

A canary leg is named for its matrix entry; this reads what the leg actually runs. A concrete
entry the servers do not match fails the leg, because a green leg under the wrong name claims a
verified version that nothing verified. The `latest` dist-tag passes, and what it resolved to
is published as the step output `version` so a failure issue can name it. A read that cannot be
answered exits non-zero: an echo that fails quietly is a leg whose name nobody checked.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import NoReturn

COMPOSE = (
    "docker",
    "compose",
    "-f",
    "harness/docker-compose.yml",
    "--profile",
    "redis",
    "--profile",
    "strict",
    "--profile",
    "throttled",
)
SERVICES = ("auth", "auth-redis", "auth-strict", "auth-throttled")
DIST_TAGS = frozenset({"latest"})
# `better-auth/package.json` is not in the package's `exports` map, so requiring it by name
# throws; this absolute path is the file the server's own `import "better-auth"` resolves to.
READ_VERSION = 'require("/app/node_modules/better-auth/package.json").version'
VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.]{1,32})?")
TIMEOUT_SECONDS = 60.0
SHOWN = 64


def fail(message: str) -> NoReturn:
    print(f"::error::{message}", file=sys.stderr)
    raise SystemExit(1)


def emit_output(name: str, value: str) -> None:
    """One `name=value` line, or none. A newline here forges arbitrary step outputs."""
    for part, what in ((name, "name"), (value, "value")):
        if "\n" in part or "\r" in part:
            fail(f"refusing to write a step output whose {what} spans lines: {part!r}")
    destination = os.environ.get("GITHUB_OUTPUT")
    if not destination:
        return
    with open(destination, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def report(line: str) -> None:
    print(line)
    destination = os.environ.get("GITHUB_STEP_SUMMARY")
    if not destination:
        return
    with open(destination, "a", encoding="utf-8") as handle:
        handle.write(f"{line}\n")


def shown(text: str) -> str:
    """A bounded, quoted rendering: what a container printed must not flood the log."""
    return repr(text[:SHOWN]) + ("..." if len(text) > SHOWN else "")


def read_version(
    service: str, *, command: Sequence[str] = COMPOSE, timeout: float = TIMEOUT_SECONDS
) -> str:
    """The better-auth version one running harness service imports, as node reports it."""
    argv = [*command, "exec", "-T", service, "node", "-p", READ_VERSION]
    try:
        finished = subprocess.run(
            argv,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"cannot read better-auth's version from {service}: {type(exc).__name__}: {exc}")
    if finished.returncode != 0:
        stderr = finished.stderr.strip()
        fail(
            f"reading better-auth's version from {service} exited {finished.returncode}: "
            f"{shown(stderr[-SHOWN:])}"
        )
    return finished.stdout.strip()


def checked(service: str, reported: str) -> str:
    # Everything downstream - the log, the summary, a step output, an issue title - embeds this.
    if not VERSION.fullmatch(reported):
        fail(f"{service} reports an implausible better-auth version: {shown(reported)}")
    return reported


def agreed(versions: Mapping[str, str]) -> str:
    """The one version every server runs; servers that disagree make any leg name a lie."""
    distinct = sorted(set(versions.values()))
    if len(distinct) != 1:
        listed = ", ".join(f"{service}={version}" for service, version in versions.items())
        fail(f"the harness servers run different better-auth versions: {listed}")
    return distinct[0]


def parse_expected(argv: Sequence[str] | None) -> str:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expected",
        required=True,
        help=f"the leg's matrix entry: a version, or one of {sorted(DIST_TAGS)}",
    )
    expected: str = parser.parse_args(argv).expected
    if expected not in DIST_TAGS and not VERSION.fullmatch(expected):
        fail(f"--expected is neither a version nor a known dist-tag: {shown(expected)}")
    return expected


def main(argv: Sequence[str] | None = None, read: Callable[[str], str] | None = None) -> int:
    expected = parse_expected(argv)
    reader = read_version if read is None else read
    versions = {service: checked(service, reader(service)) for service in SERVICES}
    for service, version in versions.items():
        print(f"{service}: better-auth@{version}")
    resolved = agreed(versions)
    emit_output("version", resolved)
    servers = f"all {len(versions)} harness servers ({', '.join(versions)})"
    if expected in DIST_TAGS:
        report(f"better-auth@{expected} resolved to {resolved} in {servers}")
        return 0
    if resolved != expected:
        report(f"better-auth@{resolved} is what {servers} run, NOT the matrix entry {expected}")
        fail(f"the leg is named better-auth@{expected} but its harness runs better-auth@{resolved}")
    report(f"better-auth@{resolved} is what {servers} run, as the matrix entry names")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
