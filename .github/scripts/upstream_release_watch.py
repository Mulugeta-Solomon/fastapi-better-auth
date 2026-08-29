"""Report whether better-auth published its current `latest` inside a lookback window.

Reads the npm registry only: the answer is derived from the publish timestamp the registry
serves, so no state has to survive between runs. Any query that cannot be answered exits
non-zero, because a watch that fails quietly reads as "upstream is stable" forever.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import Any, NoReturn

REGISTRY_URL = "https://registry.npmjs.org/better-auth"
USER_AGENT = "fastapi-better-auth-bridge-canary"


def fail(message: str) -> NoReturn:
    print(f"::error::{message}", file=sys.stderr)
    raise SystemExit(1)


def emit_output(name: str, value: str) -> None:
    destination = os.environ.get("GITHUB_OUTPUT")
    if not destination:
        return
    with open(destination, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def emit_summary(line: str) -> None:
    destination = os.environ.get("GITHUB_STEP_SUMMARY")
    if not destination:
        return
    with open(destination, "a", encoding="utf-8") as handle:
        handle.write(f"{line}\n")


def fetch_packument(url: str, timeout: float, attempts: int) -> dict[str, Any]:
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": USER_AGENT}
    )
    last_error = "no attempt was made"
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read()
            document = json.loads(payload)
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < attempts:
                time.sleep(2.0 * attempt)
            continue
        if not isinstance(document, dict):
            fail(f"{url} returned a JSON {type(document).__name__}, not an object")
        return document
    fail(f"{url} could not be read in {attempts} attempts: {last_error}")


def parse_timestamp(raw: str) -> dt.datetime:
    text = f"{raw[:-1]}+00:00" if raw.endswith("Z") else raw
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        fail(f"registry publish timestamp {raw!r} is not an ISO-8601 datetime")
    if parsed.tzinfo is None:
        fail(f"registry publish timestamp {raw!r} carries no timezone")
    return parsed.astimezone(dt.timezone.utc)


def latest_release(document: dict[str, Any]) -> tuple[str, dt.datetime]:
    tags = document.get("dist-tags")
    if not isinstance(tags, dict):
        fail("registry document carries no dist-tags object")
    latest = tags.get("latest")
    if not isinstance(latest, str) or not latest:
        fail("registry dist-tags carries no latest version")
    times = document.get("time")
    if not isinstance(times, dict):
        fail("registry document carries no time map")
    published = times.get(latest)
    if not isinstance(published, str) or not published:
        fail(f"registry time map carries no publish timestamp for {latest}")
    return latest, parse_timestamp(published)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=REGISTRY_URL, help="npm packument URL")
    parser.add_argument(
        "--window-hours",
        type=float,
        default=26.0,
        help="fire when latest was published this recently (default: 26)",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="per-attempt seconds")
    parser.add_argument("--attempts", type=int, default=3, help="registry read attempts")
    args = parser.parse_args(argv)
    if args.window_hours <= 0:
        fail(f"--window-hours must be positive, got {args.window_hours}")
    if args.attempts < 1:
        fail(f"--attempts must be at least 1, got {args.attempts}")

    latest, published = latest_release(fetch_packument(args.url, args.timeout, args.attempts))
    age_hours = (dt.datetime.now(dt.timezone.utc) - published).total_seconds() / 3600
    should_run = age_hours < args.window_hours

    verdict = "run the conformance lanes" if should_run else "nothing to do"
    line = (
        f"better-auth@{latest} published {published.isoformat()} "
        f"({age_hours:.1f}h ago, window {args.window_hours:g}h) -> {verdict}"
    )
    print(line)
    emit_summary(line)
    emit_output("should-run", "true" if should_run else "false")
    emit_output("latest", latest)
    emit_output("published", published.isoformat())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
