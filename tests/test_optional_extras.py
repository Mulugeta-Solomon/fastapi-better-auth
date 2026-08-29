"""`import fastapi_better_auth` works with neither optional store installed.

`[sqlalchemy]` and `[redis]` are extras, so the overwhelmingly common install has neither - and
a module-level `import sqlalchemy` anywhere under the package would turn that install into an
`ImportError` on the first line of the consumer's application. The store classes are exported
from the root, so the deferral has to survive the export as well as the module.

Driven in a **subprocess**, because by the time this suite runs the package is already imported
and both libraries are already in `sys.modules`: monkeypatching them out here would prove
nothing about the import that actually matters, which is the first one. A meta-path finder that
refuses the two names is the closest thing to an environment that never had them.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

PROBE = """
import sys

BLOCKED = {"sqlalchemy", "redis", "greenlet", "aiosqlite", "asyncpg"}


class Blocked:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in BLOCKED:
            raise ImportError(f"blocked for this probe: {name}")
        return None


sys.meta_path.insert(0, Blocked())

import fastapi_better_auth as package

assert package.__all__, "the package published nothing"
for name in package.__all__:
    assert getattr(package, name, None) is not None, name

assert not [name for name in sys.modules if name.split(".")[0] in BLOCKED], sorted(
    name for name in sys.modules if name.split(".")[0] in BLOCKED
)


def refused(build, extra):
    try:
        build()
    except package.ConfigurationError as exc:
        assert f"fastapi-better-auth-bridge[{extra}]" in str(exc), str(exc)
    except Exception as exc:
        raise AssertionError(f"{extra}: wrong exception {type(exc).__name__}: {exc}") from None
    else:
        raise AssertionError(f"{extra}: a store was built without the library")


refused(lambda: package.SqlAlchemySessionStore(engine=object()), "sqlalchemy")
refused(lambda: package.SyncStoreAdapter(engine=object()), "sqlalchemy")
refused(lambda: package.RedisSessionStore(url="redis://localhost:6379/0"), "redis")

print("OK")
"""


@pytest.mark.filterwarnings("ignore")
def test_the_package_imports_and_publishes_everything_without_either_extra() -> None:
    """Also asserts neither library ended up in `sys.modules` - an import that was merely
    *possible* would still have happened, and the probe would pass while the deferral was gone."""
    finished = subprocess.run(
        [sys.executable, "-c", PROBE],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert finished.returncode == 0, finished.stderr
    assert finished.stdout.strip().endswith("OK")
