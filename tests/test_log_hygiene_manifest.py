"""The manifest is honest, and the instrument that keeps it honest is proven in both directions.

`tests/log_hygiene.py` collects every log site in `src/` by AST and carries the manifest naming
the scenario that drives each one. This suite asserts the two are equal - the enumeration, not a
sample - and then proves the collector itself: it sees a log call whatever its receiver is called
(B3), it marks a message that is not a literal template rather than swallowing it (B4), it holds
`getLogger` to one module-level binding, and it finds a site planted in a file it has never seen.
The scenarios the manifest names live in `test_log_hygiene_sites.py`.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from tests.log_hygiene import (
    COVERED_BY,
    NON_LITERAL,
    LogSite,
    collect_log_sites,
    log_sites,
    logger_binding_violations,
    parsed_src,
    src_files,
)


def test_every_log_site_in_src_is_driven_by_a_scenario() -> None:
    """A sampled property is not a set property: this is the enumeration, not a sample.

    A new `logger.*` call anywhere in `src/` fails here until a scenario drives it, which is
    the only thing that stops an unexercised log line from being the one that leaks.
    """
    assert log_sites() == frozenset(COVERED_BY)


def test_the_collector_is_not_reading_an_empty_file_set() -> None:
    """Guards that scan nothing pass by vacuum."""
    scanned = {path.name for path in src_files()}

    assert "core.py" in scanned
    assert "jwks.py" in scanned
    assert len(log_sites()) >= 2


@pytest.mark.parametrize(
    ("source", "level"),
    [
        ("logger.warning('hi %s', v)", "warning"),
        ("audit = logging.getLogger('x')\naudit.warning('hi %s', v)", "warning"),
        ("_L = logging.getLogger('x')\n_L.info('hi %s', v)", "info"),
        ("self._sink.error('hi %s', v)", "error"),
        ("AUDIT.exception('hi %s', v)", "exception"),
        ("logging.getLogger('x').critical('hi %s', v)", "critical"),
        ("from logging import getLogger\ntrail = getLogger('x')\ntrail.debug('hi %s', v)", "debug"),
    ],
    ids=["logger", "aliased", "initial", "method-receiver", "upper", "inline", "from-import"],
)
def test_the_collector_sees_a_log_call_whatever_its_receiver_is_called(
    source: str, level: str
) -> None:
    """B3, as reproduced. Every one of these was invisible to the previous collector, which
    matched the receiver against log-shaped words - so the one thing this enumeration exists to
    catch, a log site added under a name nobody anticipated, was exactly what it could not see.
    """
    sites = collect_log_sites(ast.parse(source), "probe")

    assert LogSite("probe", level, "hi %s") in sites


@pytest.mark.parametrize(
    "source",
    ["logger.info(f'hi {v}')", "logger.info(msg)", "logger.info()", "logger.info(TEMPLATE % v)"],
    ids=["f-string", "variable", "no-args", "pre-formatted"],
)
def test_a_message_that_is_not_a_literal_is_marked_rather_than_swallowed(source: str) -> None:
    """B4. All four used to collapse to `""`, which is a *valid-looking* template - so the site
    joined the enumeration under a key that says nothing and matched nothing."""
    sites = collect_log_sites(ast.parse(source), "probe")

    assert {site.template for site in sites} == {NON_LITERAL}


def test_every_log_call_in_src_passes_a_literal_template() -> None:
    """B4 over the real tree. A `%`-style literal plus arguments is also the log-injection-safe
    form: `logging` renders the arguments, so nothing a client chose becomes the template."""
    offenders = [site for site in log_sites() if site.template == NON_LITERAL]

    assert not offenders, (
        "these log calls build their message at the call site rather than passing a literal"
        f" template and arguments: {sorted((s.module, s.level) for s in offenders)}"
    )


def test_get_logger_is_only_ever_bound_to_a_module_level_logger() -> None:
    """The convention that makes B3's over-collection cheap: one logger per module, one name.

    Without it, `collect_log_sites` catching every `.warning(...)` would be noise; with it, a
    reviewer knows any logging call in `src/` goes through the one binding at the top of the file.
    """
    offenders = [
        problem
        for module, tree in parsed_src()
        for problem in logger_binding_violations(tree, module)
    ]

    assert not offenders, "\n".join(offenders)


@pytest.mark.parametrize(
    ("source", "compliant"),
    [
        ("import logging\nlogger = logging.getLogger('x')\n", True),
        ("from logging import getLogger\nlogger = getLogger('x')\n", True),
        ("import logging\naudit = logging.getLogger('x')\n", False),
        ("import logging\nlogging.getLogger('x').info('hi')\n", False),
        ("import logging\ndef f():\n    logger = logging.getLogger('x')\n", False),
        ("import logging\nself.logger = logging.getLogger('x')\n", False),
    ],
    ids=["module-level", "from-import", "aliased", "inline", "in-function", "attribute"],
)
def test_the_binding_pin_fires_on_every_way_of_getting_it_wrong(
    source: str, compliant: bool
) -> None:
    """Prove the instrument, both directions: a pin that never fires pins nothing."""
    assert (logger_binding_violations(ast.parse(source), "probe") == ()) is compliant


def test_the_collector_finds_a_synthetic_site_in_a_planted_file(tmp_path: pathlib.Path) -> None:
    """The scan is exercised end to end against a file it has never seen."""
    planted = tmp_path / "planted.py"
    planted.write_text(
        "import logging\nlogger = logging.getLogger()\nlogger.info('hi %s', x)\n", encoding="utf-8"
    )

    sites = collect_log_sites(ast.parse(planted.read_text(encoding="utf-8")), planted.stem)

    assert LogSite("planted", "info", "hi %s") in sites
