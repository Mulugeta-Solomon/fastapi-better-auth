"""The revocation watermark: "revoke every session" is a key of its own, and the store must read it.

Since better-auth 1.7.16, revoking all of a user's sessions also writes
`revoked-sessions-before-<userId>` - a millisecond timestamp, as a string - and upstream's own
session read refuses any session whose `createdAt` is strictly before it
(`internal-adapter.mjs`, `isRevokedSession`). The watermark exists because the per-token keys can
outlive the revocation: a failed delete, a replica, a refresh racing the revocation and writing
the key back. A store that reads the token key alone accepts exactly the sessions upstream refuses.

The bridge's reading is upstream's comparison with every fail-open branch closed: a watermark it
cannot read, or a session whose `createdAt` it cannot read while a watermark exists, is a miss.
A revoked session is a miss like an absent key - same `None`, nothing logged for it.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import anyio
import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from fastapi_better_auth import RedisSessionStore
from fastapi_better_auth._internal.reasons import REDACTED
from tests.stores import NOW, TOKEN, USER_ID, DecodingRedis, RecordingRedis, stored, wire_session

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
CREATED_MS = (NOW - EPOCH) // timedelta(milliseconds=1)
"""`wire_session()`'s `createdAt`, as `new Date(createdAt).getTime()` reads it."""

WATERMARK_KEY = f"revoked-sessions-before-{USER_ID}"
LIBRARY_LOGGER = "fastapi_better_auth"


def store_over(
    values: dict[str, str | bytes], *, prefix: str = ""
) -> tuple[RedisSessionStore, RecordingRedis]:
    client = RecordingRedis(values)
    return RedisSessionStore(client=client, key_prefix=prefix), client


def with_watermark(watermark: str | bytes, value: str | None = None) -> dict[str, str | bytes]:
    return {TOKEN: stored() if value is None else value, WATERMARK_KEY: watermark}


def without(name: str) -> str:
    session = {key: val for key, val in wire_session().items() if key != name}
    return stored(session=session)


class TestTheWatermarkIsRead:
    @pytest.mark.anyio
    async def test_a_session_created_before_the_watermark_is_a_miss(self) -> None:
        """F1 itself: the key outlived "revoke all sessions", and upstream refuses it."""
        store, _client = store_over(with_watermark(str(CREATED_MS + 1)))

        assert await store.fetch_session_by_token(TOKEN) is None

    @pytest.mark.anyio
    async def test_the_second_read_is_the_watermark_key_named_by_the_stored_user_id(self) -> None:
        store, client = store_over({TOKEN: stored()})

        await store.fetch_session_by_token(TOKEN)

        assert client.calls == [("get", (TOKEN,)), ("get", (WATERMARK_KEY,))]

    @pytest.mark.anyio
    async def test_an_absent_watermark_is_not_a_revocation(self) -> None:
        """Every version before 1.7.16, and every user nobody revoked: the key is simply absent."""
        store, _client = store_over({TOKEN: stored()})

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.user_id == USER_ID

    @pytest.mark.anyio
    async def test_a_session_created_exactly_at_the_watermark_stands(self) -> None:
        """Upstream compares `createdAt < revokedBefore`, strictly. Equal is not revoked."""
        store, _client = store_over(with_watermark(str(CREATED_MS)))

        assert await store.fetch_session_by_token(TOKEN) is not None

    @pytest.mark.anyio
    async def test_a_session_created_after_the_watermark_stands(self) -> None:
        """A sign-in after the revocation is a new session, and the watermark does not touch it."""
        store, _client = store_over(with_watermark(str(CREATED_MS - 1)))

        assert await store.fetch_session_by_token(TOKEN) is not None

    @pytest.mark.anyio
    async def test_a_sub_millisecond_created_at_is_floored_the_way_a_js_date_reads_it(
        self,
    ) -> None:
        """`new Date(...)` keeps whole milliseconds. A `createdAt` 0.9 ms past the watermark is
        the watermark's own millisecond to upstream, so it is not after it - and not before it."""
        created = (NOW + timedelta(microseconds=900)).isoformat().replace("+00:00", "Z")
        value = stored(session=wire_session(createdAt=created))
        store, _client = store_over(with_watermark(str(CREATED_MS + 1), value))

        assert await store.fetch_session_by_token(TOKEN) is None

    @pytest.mark.anyio
    async def test_a_prefixed_store_prefixes_the_watermark_key_too(self) -> None:
        """better-auth hands every key to `secondaryStorage.get` unprefixed; a namespace is the
        deployment's storage adapter's, applied to every key it stores - so to this one as well."""
        values: dict[str, str | bytes] = {
            f"ba:{TOKEN}": stored(),
            f"ba:{WATERMARK_KEY}": str(CREATED_MS + 1),
            WATERMARK_KEY: "0",
        }
        store, client = store_over(values, prefix="ba:")

        assert await store.fetch_session_by_token(TOKEN) is None
        assert client.calls == [("get", (f"ba:{TOKEN}",)), ("get", (f"ba:{WATERMARK_KEY}",))]

    @pytest.mark.anyio
    async def test_a_decoding_client_answering_str_is_read_the_same_way(self) -> None:
        client = DecodingRedis(with_watermark(str(CREATED_MS + 1)))
        store = RedisSessionStore(client=client)

        assert await store.fetch_session_by_token(TOKEN) is None

    @pytest.mark.anyio
    async def test_a_bytes_watermark_is_read_the_same_way(self) -> None:
        store, _client = store_over(with_watermark(str(CREATED_MS + 1).encode()))

        assert await store.fetch_session_by_token(TOKEN) is None

    @pytest.mark.anyio
    async def test_a_revocation_logs_nothing(self, caplog: pytest.LogCaptureFixture) -> None:
        """A revoked session is a miss like an absent key, and an absent key is not news."""
        store, _client = store_over(with_watermark(str(CREATED_MS + 1)))

        with caplog.at_level(logging.DEBUG, logger=LIBRARY_LOGGER):
            assert await store.fetch_session_by_token(TOKEN) is None

        assert caplog.records == []


class TestOnlyAStandingDocumentCostsASecondRead:
    """The watermark is asked about a session the store would otherwise accept, and only then."""

    @pytest.mark.anyio
    async def test_an_absent_session_key_is_one_read(self) -> None:
        store, client = store_over({WATERMARK_KEY: str(CREATED_MS + 1)})

        assert await store.fetch_session_by_token(TOKEN) is None
        assert client.calls == [("get", (TOKEN,))]

    @pytest.mark.anyio
    async def test_a_malformed_document_is_one_read(self) -> None:
        store, client = store_over(with_watermark("0", "{not json"))

        assert await store.fetch_session_by_token(TOKEN) is None
        assert client.calls == [("get", (TOKEN,))]

    @pytest.mark.anyio
    async def test_a_document_naming_another_token_is_one_read(self) -> None:
        value = stored(session=wire_session(token="another-token-entirely-0123456789"))
        store, client = store_over(with_watermark("0", value))

        assert await store.fetch_session_by_token(TOKEN) is None
        assert client.calls == [("get", (TOKEN,))]


class TestAWatermarkItCannotRead:
    """Upstream reads the watermark with `Number(...)` and a `NaN` compares false - it fails open.
    The bridge accepts only what upstream writes, `String(<whole milliseconds>)`, and refuses the
    session on anything else, with a warning that names the key by fingerprint."""

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "watermark",
        [
            "",
            "soon",
            "NaN",
            "Infinity",
            "-Infinity",
            "inf",
            "nan",
            "-1",
            "-1767225600000",
            "+1",
            " 1",
            "1 ",
            "1.5",
            "1e3",
            "0x10",
            "1_000",
            "١٢",
            "1" * 17,
            "null",
            '"1"',
        ],
        ids=lambda value: repr(value)[:24],
    )
    async def test_it_is_a_miss_and_a_warning(
        self, watermark: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        store, _client = store_over(with_watermark(watermark))

        with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER):
            assert await store.fetch_session_by_token(TOKEN) is None

        assert caplog.records, "an unreadable watermark was refused silently"

    @pytest.mark.anyio
    async def test_a_non_ascii_bytes_watermark_is_a_miss(self) -> None:
        store, _client = store_over(with_watermark(b"\xff\xfe12"))

        assert await store.fetch_session_by_token(TOKEN) is None

    @pytest.mark.anyio
    async def test_a_client_answering_something_that_is_not_text_is_a_miss(self) -> None:
        class Odd(RecordingRedis):
            async def get(self, name: str) -> Any:
                self.calls.append(("get", (name,)))
                return stored().encode() if name == TOKEN else CREATED_MS - 1

        store = RedisSessionStore(client=Odd())

        assert await store.fetch_session_by_token(TOKEN) is None

    @pytest.mark.anyio
    async def test_the_warning_names_neither_the_token_nor_the_user(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        store, _client = store_over(with_watermark("soon"))

        with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER):
            await store.fetch_session_by_token(TOKEN)

        written = " ".join(entry.getMessage() for entry in caplog.records)
        assert written
        assert TOKEN not in written
        assert USER_ID not in written

    @pytest.mark.anyio
    async def test_the_warning_says_it_was_the_watermark(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The line an operator acts on. Its kind goes through `safe_label`, so a kind the label
        pattern refuses would render as `<redacted>` and name nothing."""
        store, _client = store_over(with_watermark("soon"))

        with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER):
            await store.fetch_session_by_token(TOKEN)

        (line,) = [entry.getMessage() for entry in caplog.records]
        assert line.startswith("stored watermark is unusable (")
        assert REDACTED not in line


class TestACreatedAtItCannotRead:
    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("label", "value"),
        [
            ("absent", without("createdAt")),
            ("null", stored(session=wire_session(createdAt=None))),
            ("not-a-date", stored(session=wire_session(createdAt="yesterday"))),
            ("a-number", stored(session=wire_session(createdAt=CREATED_MS - 10))),
            ("empty", stored(session=wire_session(createdAt=""))),
        ],
        ids=lambda value: value if isinstance(value, str) and len(value) < 16 else "value",
    )
    async def test_with_a_watermark_it_is_a_miss_and_a_warning(
        self, label: str, value: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Upstream's `new Date(undefined).getTime()` is `NaN`, and `NaN < watermark` is false:
        upstream lets it through. With a watermark present the bridge cannot tell revoked from
        standing, and refuses."""
        store, _client = store_over(with_watermark(str(CREATED_MS - 1_000_000), value))

        with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER):
            assert await store.fetch_session_by_token(TOKEN) is None, label

        assert caplog.records, f"{label} was refused silently"

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "value",
        [without("createdAt"), stored(session=wire_session(createdAt="yesterday"))],
        ids=["absent", "not-a-date"],
    )
    async def test_without_a_watermark_it_is_not_asked_about(self, value: str) -> None:
        """No watermark, no question: `createdAt` matters only to a comparison that is not made,
        and refusing here would refuse sessions the store has always accepted."""
        store, _client = store_over({TOKEN: value})

        assert await store.fetch_session_by_token(TOKEN) is not None


class TestTheComparisonIsUpstreams:
    @settings(derandomize=True, max_examples=200)
    @given(
        created=st.datetimes(
            min_value=datetime(1971, 1, 1),
            max_value=datetime(2999, 12, 31),
            timezones=st.just(timezone.utc),
        ),
        offset=st.integers(min_value=-5_000, max_value=5_000),
    )
    def test_revoked_exactly_when_created_ms_is_strictly_below(
        self, created: datetime, offset: int
    ) -> None:
        """Integer milliseconds both sides, floored like a JS `Date` - never a float."""
        created_ms = (created - EPOCH) // timedelta(milliseconds=1)
        watermark = created_ms + offset
        iso = created.isoformat(timespec="microseconds").replace("+00:00", "Z")
        assume(watermark >= 0)
        value = stored(session=wire_session(createdAt=iso))
        store, _client = store_over(with_watermark(str(watermark), value))

        record = anyio.run(store.fetch_session_by_token, TOKEN)

        assert (record is None) == (created_ms < watermark)
