"""Throwaway LOGIN roles on the harness Postgres, for the least-privilege cases (#68, #121).

Each role is created under a random name and password by the harness superuser, and dropped
again however the test ends. The password never reaches a log, a reason, an assertion or a repr:
it lives in a `Login` whose repr leaves it out, the engine's URL masks it, and every statement
that carries it runs through `as_superuser`, which re-raises a failure without the statement text.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field

from sqlalchemy import URL, Engine, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from .conftest import POSTGRES_URL

READ_BOTH = 'GRANT SELECT ON "session", "user" TO "{role}"'
READ_SESSION_ONLY = 'GRANT SELECT ON "session" TO "{role}"'


@dataclass(frozen=True)
class Login:
    """A throwaway LOGIN role. The password is in no repr, so in no failure message either."""

    name: str
    password: str = field(repr=False)

    @property
    def url(self) -> URL:
        """The harness database's own host, port and name, logged in as this role."""
        return make_url(POSTGRES_URL).set(username=self.name, password=self.password)


async def as_superuser(*statements: str, step: str) -> None:
    """Run DDL as the harness superuser, in one transaction, never echoing a statement back.

    SQLAlchemy's error text embeds the statement, and one of these carries a password, so a
    failure is re-raised as its class and SQLSTATE only - outside the `except`, with no chain.
    """
    engine = create_async_engine(POSTGRES_URL)
    failure: RuntimeError | None = None
    try:
        async with engine.begin() as connection:
            for statement in statements:
                await connection.exec_driver_sql(statement)
    except SQLAlchemyError as exc:
        code = getattr(getattr(exc, "orig", None), "sqlstate", None)
        failure = RuntimeError(f"{step} failed: {type(exc).__name__} (SQLSTATE {code})")
    finally:
        await engine.dispose()
    if failure is not None:
        raise failure from None


@asynccontextmanager
async def login_granted(grant: str) -> AsyncGenerator[Login]:
    """A LOGIN role holding exactly `grant`, dropped again however the test ends."""
    login = Login(name=f"wp25_store_{secrets.token_hex(8)}", password=secrets.token_hex(24))
    await as_superuser(
        f"CREATE ROLE \"{login.name}\" LOGIN PASSWORD '{login.password}'",
        grant.format(role=login.name),
        step="creating the least-privilege role",
    )
    try:
        yield login
    finally:
        await as_superuser(
            f'DROP OWNED BY "{login.name}"',
            f'DROP ROLE "{login.name}"',
            step="dropping the least-privilege role",
        )


@asynccontextmanager
async def engine_as(login: Login) -> AsyncGenerator[AsyncEngine]:
    engine = create_async_engine(login.url)
    try:
        yield engine
    finally:
        await engine.dispose()


# ---------------------------------------------------------------- the same, through a sync driver
#
# For a case that runs on trio, where asyncpg cannot: every statement goes through `driver`, one
# of `tests.stores.SYNC_DRIVERS`, and a case without that driver skips (`sync_postgres_engine`).
# `tests.stores` names post-0.1.0 exports, and modules that import this one at their top run on
# the published-wheel lane, so it is reached only when a sync case calls for an engine.


def _sync_engine(driver: str, url: str | URL) -> Engine:
    from tests.stores import sync_postgres_engine

    return sync_postgres_engine(driver, url)


def sync_as_superuser(driver: str, *statements: str, step: str) -> None:
    """`as_superuser` through `driver`: one transaction, never echoing a statement back."""
    engine = _sync_engine(driver, POSTGRES_URL)
    failure: RuntimeError | None = None
    try:
        with engine.begin() as connection:
            for statement in statements:
                connection.exec_driver_sql(statement)
    except SQLAlchemyError as exc:
        orig = getattr(exc, "orig", None)
        code = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
        failure = RuntimeError(f"{step} failed: {type(exc).__name__} (SQLSTATE {code})")
    finally:
        engine.dispose()
    if failure is not None:
        raise failure from None


@contextmanager
def sync_login_granted(driver: str, grant: str) -> Generator[Login, None, None]:
    """`login_granted` through `driver`: a LOGIN role holding exactly `grant`, then dropped."""
    login = Login(name=f"wp57_store_{secrets.token_hex(8)}", password=secrets.token_hex(24))
    sync_as_superuser(
        driver,
        f"CREATE ROLE \"{login.name}\" LOGIN PASSWORD '{login.password}'",
        grant.format(role=login.name),
        step="creating the least-privilege role",
    )
    try:
        yield login
    finally:
        sync_as_superuser(
            driver,
            f'DROP OWNED BY "{login.name}"',
            f'DROP ROLE "{login.name}"',
            step="dropping the least-privilege role",
        )


@contextmanager
def sync_engine_as(driver: str, login: Login) -> Generator[Engine, None, None]:
    engine = _sync_engine(driver, login.url)
    try:
        yield engine
    finally:
        engine.dispose()
