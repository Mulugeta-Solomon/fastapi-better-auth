"""The structural cookie parser: header → pairs → resolved value → (token, signature).

No cryptography lives here and none is asserted here - the keyring HMAC is the verifier's, and
this layer only proves the *shape* of a signed cookie. Every rejection is `InvalidCredential`
(present-but-malformed), and every one carries a distinct `reason` so a mutation that removes one
guard changes the reason a test pins rather than only the accept/reject a later, broader guard
would still produce.

The property tests land here (hypothesis): the pipeline never crashes on arbitrary bytes, never
accepts a non-44-character signature, and splits at the *last* dot even for a token full of them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest

from fastapi_better_auth import InvalidCredential
from fastapi_better_auth._internal.cookie_parsing import (
    HMAC_BYTES,
    MAX_COOKIE_BYTES,
    SIGNATURE_LENGTH,
    ParsedCookie,
    acceptable_names,
    cookie_pairs,
    parse_signed_value,
    resolve_cookie_value,
    session_data_names,
)

pytest.importorskip("hypothesis")
from hypothesis import given, settings
from hypothesis import strategies as st

COOKIE = "better-auth.session_token"
SECURE = "__Secure-better-auth.session_token"
PREFIX = "__Secure-"
SECRET = b"harness-secret-do-not-use-in-production"

VALID_TOKEN = "SBYZ1bzGdkhXcLuqsW70JjhvmIY4PU3B"


def sign(token: str, secret: bytes = SECRET) -> str:
    """The canonical signed value: token + '.' + standard-base64(HMAC-SHA256(secret, token))."""
    digest = hmac.new(secret, token.encode(), hashlib.sha256).digest()
    return f"{token}.{base64.b64encode(digest).decode()}"


# ---------------------------------------------------------------- cookie header → pairs


class TestCookiePairs:
    def test_a_single_pair_splits_on_the_first_equals(self) -> None:
        assert cookie_pairs("a=b") == (("a", "b"),)

    def test_a_value_may_contain_further_equals(self) -> None:
        """RFC 6265 splits on the first `=`; a base64 value's own padding survives in the value."""
        assert cookie_pairs("a=b=c=") == (("a", "b=c="),)

    def test_multiple_pairs_are_split_on_semicolons_and_stripped(self) -> None:
        assert cookie_pairs("a=1; b=2 ;c=3") == (("a", "1"), ("b", "2"), ("c", "3"))

    def test_duplicate_names_are_preserved_in_order(self) -> None:
        """The whole reason to read the raw header: duplicates a verifier must notice itself."""
        assert cookie_pairs("s=one; s=two") == (("s", "one"), ("s", "two"))

    def test_a_pair_with_no_equals_is_dropped(self) -> None:
        assert cookie_pairs("novalue; a=b") == (("a", "b"),)

    def test_a_blank_value_is_a_present_pair(self) -> None:
        """`name=` is present with an empty value, not absent - the verifier must dispatch it."""
        assert cookie_pairs("s=") == (("s", ""),)

    def test_an_empty_header_is_no_pairs(self) -> None:
        assert cookie_pairs("") == ()
        assert cookie_pairs("   ") == ()


# ---------------------------------------------------------------- the acceptable name sets


class TestAcceptableNames:
    def test_the_single_base_and_its_chunk_names_are_accepted(self) -> None:
        """D1: exactly one base's names, never both. The base is whatever the verifier resolved."""
        names = acceptable_names(SECURE)

        assert SECURE in names
        assert f"{SECURE}.0" in names
        assert f"{SECURE}.99" in names
        # The plain name is another cookie's now, not this verifier's second base.
        assert COOKIE not in names

    def test_a_chunk_index_past_the_cap_is_not_a_name(self) -> None:
        names = acceptable_names(COOKIE)

        assert f"{COOKIE}.100" not in names
        assert "" not in names

    def test_the_session_data_name_matches_the_secure_choice(self) -> None:
        """One session_data name, tracking the token cookie's secure/plain choice (D-189)."""
        secure = session_data_names(COOKIE, PREFIX, True)
        plain = session_data_names(COOKIE, PREFIX, False)

        assert secure == frozenset({"__Secure-better-auth.session_data"})
        assert plain == frozenset({"better-auth.session_data"})
        assert COOKIE not in secure and COOKIE not in plain


# ---------------------------------------------------------------- resolving the cookie value


def pairs(*items: tuple[str, str]) -> tuple[tuple[str, str], ...]:
    return items


class TestResolveCookieValue:
    def test_a_single_cookie_for_the_base_is_returned(self) -> None:
        assert resolve_cookie_value(pairs((COOKIE, "value")), COOKIE) == "value"

    def test_only_the_configured_base_is_read(self) -> None:
        """D1: with the plain base configured, a `__Secure-` cookie beside it is not read at all -
        the base resolves the plain value and the other name is another cookie's (D-189)."""
        resolved = resolve_cookie_value(pairs((COOKIE, "plain"), (SECURE, "secure")), COOKIE)

        assert resolved == "plain"

    def test_a_duplicate_of_one_cookie_name_is_refused(self) -> None:
        with pytest.raises(InvalidCredential) as caught:
            resolve_cookie_value(pairs((COOKIE, "one"), (COOKIE, "two")), COOKIE)

        assert "more than once" in caught.value.reason

    def test_a_whole_and_a_chunked_cookie_for_one_base_is_refused(self) -> None:
        with pytest.raises(InvalidCredential) as caught:
            resolve_cookie_value(pairs((COOKIE, "whole"), (f"{COOKIE}.0", "chunk")), COOKIE)

        assert "both whole and chunked" in caught.value.reason

    def test_contiguous_chunks_are_reassembled_in_index_order(self) -> None:
        resolved = resolve_cookie_value(
            pairs((f"{COOKIE}.1", "BB"), (f"{COOKIE}.0", "AA"), (f"{COOKIE}.2", "CC")),
            COOKIE,
        )

        assert resolved == "AABBCC"

    def test_a_gap_in_the_chunk_sequence_is_refused(self) -> None:
        with pytest.raises(InvalidCredential) as caught:
            resolve_cookie_value(pairs((f"{COOKIE}.0", "AA"), (f"{COOKIE}.2", "CC")), COOKIE)

        assert "contiguous" in caught.value.reason

    def test_a_duplicate_chunk_index_is_refused(self) -> None:
        with pytest.raises(InvalidCredential) as caught:
            resolve_cookie_value(pairs((f"{COOKIE}.0", "AA"), (f"{COOKIE}.0", "BB")), COOKIE)

        assert "contiguous" in caught.value.reason

    def test_chunks_that_do_not_start_at_zero_are_refused(self) -> None:
        with pytest.raises(InvalidCredential) as caught:
            resolve_cookie_value(pairs((f"{COOKIE}.1", "AA"), (f"{COOKIE}.2", "BB")), COOKIE)

        assert "contiguous" in caught.value.reason

    def test_no_material_at_all_is_refused_defensively(self) -> None:
        """Unreachable through extract, which only dispatches when a name matched; refused so a
        direct caller can never be handed an empty string."""
        with pytest.raises(InvalidCredential) as caught:
            resolve_cookie_value(pairs(("unrelated", "x")), COOKIE)

        assert "no session cookie material" in caught.value.reason

    def test_a_reassembled_run_over_the_byte_cap_is_refused(self) -> None:
        half = MAX_COOKIE_BYTES // 2 + 1
        chunked = pairs((f"{COOKIE}.0", "a" * half), (f"{COOKIE}.1", "b" * half))
        with pytest.raises(InvalidCredential) as caught:
            resolve_cookie_value(chunked, COOKIE)

        assert "over the cap" in caught.value.reason


# ---------------------------------------------------------------- parsing the signed value


class TestParseSignedValue:
    def test_a_captured_valid_cookie_parses_into_token_and_signature(self) -> None:
        signed = sign(VALID_TOKEN)

        parsed = parse_signed_value(signed)

        assert isinstance(parsed, ParsedCookie)
        assert parsed.token == VALID_TOKEN
        assert len(parsed.signature) == SIGNATURE_LENGTH

    def test_the_parsed_cookie_repr_hides_both_halves(self) -> None:
        parsed = parse_signed_value(sign(VALID_TOKEN))

        rendered = repr(parsed)
        assert VALID_TOKEN not in rendered
        assert parsed.signature not in rendered
        assert "redacted" in rendered

    def test_a_percent_encoded_cookie_is_unquoted_once(self) -> None:
        from urllib.parse import quote

        parsed = parse_signed_value(quote(sign(VALID_TOKEN)))

        assert parsed.token == VALID_TOKEN

    def test_a_double_encoded_cookie_is_not_resolved_by_one_unquote(self) -> None:
        from urllib.parse import quote

        once = quote(sign(VALID_TOKEN))
        twice = quote(once)

        with pytest.raises(InvalidCredential):
            parse_signed_value(twice)

    def test_an_invalid_percent_escape_is_refused_not_replaced(self) -> None:
        """`errors='strict'`: a `%ff` that is not valid UTF-8 is a rejection, never a U+FFFD."""
        with pytest.raises(InvalidCredential) as caught:
            parse_signed_value(f"{VALID_TOKEN}.%ff%fe")

        assert "percent-encoded UTF-8" in caught.value.reason

    def test_a_value_with_no_dot_is_refused(self) -> None:
        with pytest.raises(InvalidCredential) as caught:
            parse_signed_value(VALID_TOKEN)

        assert "separator" in caught.value.reason

    def test_an_empty_token_is_refused_before_any_comparison(self) -> None:
        """The `empty-token` shape: a valid HMAC over the empty string must never be honoured."""
        empty_signed = sign("")

        with pytest.raises(InvalidCredential) as caught:
            parse_signed_value(empty_signed)

        assert "empty token" in caught.value.reason

    def test_the_last_dot_is_the_separator(self) -> None:
        """A token that itself contains dots: split at the LAST one, never the first."""
        dotted = "aa.bb.cc"
        parsed = parse_signed_value(sign(dotted))

        assert parsed.token == dotted

    @pytest.mark.parametrize("length", [0, 43, 45, 88])
    def test_a_signature_that_is_not_forty_four_characters_is_refused(self, length: int) -> None:
        material = f"{VALID_TOKEN}.{'A' * length}"

        with pytest.raises(InvalidCredential) as caught:
            parse_signed_value(material)

        assert "44" in caught.value.reason

    def test_a_forty_four_character_non_standard_alphabet_signature_is_refused(self) -> None:
        """The base64url alphabet at the right length: `_` is not standard base64."""
        material = f"{VALID_TOKEN}.{'_' * SIGNATURE_LENGTH}"

        with pytest.raises(InvalidCredential) as caught:
            parse_signed_value(material)

        assert "standard base64" in caught.value.reason

    def test_a_forty_four_character_signature_that_decodes_short_is_refused(self) -> None:
        """44 standard-base64 characters ending `==` decode to 31 bytes, not 32."""
        thirty_one = base64.b64encode(b"x" * 31).decode()
        assert len(thirty_one) == SIGNATURE_LENGTH and thirty_one.endswith("==")

        with pytest.raises(InvalidCredential) as caught:
            parse_signed_value(f"{VALID_TOKEN}.{thirty_one}")

        assert f"{HMAC_BYTES} bytes" in caught.value.reason

    def test_a_cookie_value_over_the_byte_cap_is_refused(self) -> None:
        with pytest.raises(InvalidCredential) as caught:
            parse_signed_value("x" * (MAX_COOKIE_BYTES + 1))

        assert "cap" in caught.value.reason

    def test_no_credential_substring_reaches_a_rejection_reason(self) -> None:
        """Every parse reason is a fingerprint and a phrase this module wrote, never the value."""
        signed = sign(VALID_TOKEN)
        with pytest.raises(InvalidCredential) as caught:
            parse_signed_value(f"{signed}.junk")  # last-dot split makes the sig 'junk'

        assert VALID_TOKEN not in caught.value.reason
        assert signed not in caught.value.reason


# ---------------------------------------------------------------- frame-locals hygiene (D-094)


def _library_frames(error: BaseException) -> list[object]:
    frames: list[object] = []
    traceback = error.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        if "fastapi_better_auth" in frame.f_code.co_filename:
            frames.append(frame)
        traceback = traceback.tb_next
    return frames


def _rendered_frames(error: BaseException) -> str:
    frames = _library_frames(error)
    assert frames, "no library frame was captured; retune this probe"
    return " ".join(repr(frame.f_locals) for frame in frames)  # type: ignore[attr-defined]


MARK = "ZZmaterialZZ"


class TestFrameLocalsHygiene:
    """Every frame that holds cookie material must scrub it before a raise puts it on a traceback -
    the guarantee both parse modules claim (D-094). Covers the parse pipeline AND the resolution
    helpers (the non-contiguous-chunk raise, the duplicate raise, the whole+chunked raise), which
    hold the raw `pairs`/`ordered` on their frames."""

    def test_a_parse_failure_leaves_no_material_in_a_library_frame(self) -> None:
        with pytest.raises(InvalidCredential) as caught:
            parse_signed_value(f"{MARK}.{'_' * SIGNATURE_LENGTH}")

        assert MARK not in _rendered_frames(caught.value)

    def test_a_non_contiguous_chunk_run_leaves_no_material_in_a_library_frame(self) -> None:
        crafted = pairs((f"{COOKIE}.0", MARK + "A"), (f"{COOKIE}.2", MARK + "C"))
        with pytest.raises(InvalidCredential) as caught:
            resolve_cookie_value(crafted, COOKIE)

        assert MARK not in _rendered_frames(caught.value)

    def test_a_duplicate_cookie_leaves_no_material_in_a_library_frame(self) -> None:
        crafted = pairs((COOKIE, MARK + "one"), (COOKIE, MARK + "two"))
        with pytest.raises(InvalidCredential) as caught:
            resolve_cookie_value(crafted, COOKIE)

        assert MARK not in _rendered_frames(caught.value)

    def test_a_whole_and_chunked_cookie_leaves_no_material_in_a_library_frame(self) -> None:
        crafted = pairs((COOKIE, MARK + "whole"), (f"{COOKIE}.0", MARK + "chunk"))
        with pytest.raises(InvalidCredential) as caught:
            resolve_cookie_value(crafted, COOKIE)

        assert MARK not in _rendered_frames(caught.value)


# ---------------------------------------------------------------- property tests (hypothesis)

ARBITRARY = st.text(max_size=200)


class TestParserProperties:
    @settings(derandomize=True, max_examples=300)
    @given(ARBITRARY)
    def test_the_pipeline_never_raises_anything_but_invalid_credential(self, value: str) -> None:
        try:
            parse_signed_value(value)
        except InvalidCredential:
            pass

    @settings(derandomize=True, max_examples=300)
    @given(st.text(max_size=100), st.text(alphabet="ABCabc012+/=_-", max_size=60))
    def test_no_signature_of_the_wrong_length_is_ever_accepted(self, token: str, sig: str) -> None:
        if len(sig) == SIGNATURE_LENGTH:
            return  # the right length is the accept case; this property is about the others
        try:
            parse_signed_value(f"{token}.{sig}")
        except InvalidCredential:
            return
        pytest.fail("a signature of the wrong length parsed")

    @settings(derandomize=True, max_examples=200)
    @given(st.lists(st.text(alphabet="ab", min_size=1, max_size=4), min_size=1, max_size=6))
    def test_the_last_dot_invariant_holds_for_tokens_full_of_dots(self, parts: list[str]) -> None:
        token = ".".join(parts)
        parsed = parse_signed_value(sign(token))
        assert parsed.token == token
