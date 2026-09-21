package click.yukio.dbsc;

import click.yukio.dbsc.core.DbscErrorCode;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.SkippedEntry;
import click.yukio.dbsc.core.SkippedReason;
import click.yukio.dbsc.protocol.BoundProofHeader;
import click.yukio.dbsc.protocol.CookieScope;
import click.yukio.dbsc.protocol.DbscHeaderCodec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Wire-format tests for cookies, headers and the proof header.
 *
 * <p>These rules are security-critical and byte-exact: a single wrong character
 * makes Chromium silently drop the binding, or lets a malformed proof through.
 */
class WireFormatTest {

    /**
     * The attributes string MUST match the real {@code Set-Cookie} byte-for-byte,
     * or Chromium drops the session — it re-reads the string to know how to
     * re-issue the bound cookie on refresh.
     */
    @Nested
    class Cookies {

        @Test
        @DisplayName("host scope: __Host- names and the exact attributes string")
        void hostScope() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.HOST, null);

            assertEquals("__Host-dbsc-session", scope.bindingCookieName());
            assertEquals("__Host-dbsc-reg", scope.registrationCookieName());
            assertEquals("__Host-dbsc-challenge", scope.challengeCookieName());
            assertEquals("Path=/; Secure; HttpOnly; SameSite=Lax", scope.attributesString());
        }

        @Test
        @DisplayName("site scope: __Secure- names, Domain appended without a leading dot")
        void siteScope() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.SITE, "example.com");

            assertEquals("__Secure-dbsc-session", scope.bindingCookieName());
            assertEquals(
                    "Path=/; Secure; HttpOnly; SameSite=Lax; Domain=example.com",
                    scope.attributesString());
        }

        @Test
        @DisplayName("insecure dev: no prefix")
        void insecureDev() {
            CookieScope scope = CookieScope.resolve(false, CookieScope.Scope.HOST, null);

            assertEquals("dbsc-session", scope.bindingCookieName());
            assertEquals("dbsc-reg", scope.registrationCookieName());
            assertEquals("dbsc-challenge", scope.challengeCookieName());
        }

        @Test
        @DisplayName("the Set-Cookie value and the advertised attributes agree byte-for-byte")
        void setCookieMatchesAttributes() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.HOST, null);
            String setCookie = scope.setCookieValue("__Host-dbsc-session", "sess_abc", 600_000);

            // The advertised string must be a literal substring of the real header.
            assertTrue(setCookie.startsWith("__Host-dbsc-session=sess_abc; " + scope.attributesString() + ";"),
                    "attributes must appear verbatim, in order: " + setCookie);
            // Max-Age is a raw Set-Cookie field in SECONDS, not milliseconds.
            assertTrue(setCookie.endsWith("Max-Age=600"), setCookie);
        }

        @Test
        @DisplayName("deleting a cookie emits Max-Age=0 with the same attributes")
        void deleteCookie() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.HOST, null);
            assertEquals("__Host-dbsc-challenge=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
                    scope.deleteCookieValue("__Host-dbsc-challenge"));
        }

        @Test
        @DisplayName("a sub-second TTL still emits a positive Max-Age rather than zero")
        void subSecondTtl() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.HOST, null);
            // Max-Age=0 would delete the cookie instead of setting it.
            assertTrue(scope.setCookieValue("__Host-dbsc-session", "x", 500).endsWith("Max-Age=1"));
        }

        @Test
        @DisplayName("site scope without a domain, without secure, or with a leading dot is rejected")
        void siteScopeValidation() {
            assertThrows(IllegalArgumentException.class,
                    () -> CookieScope.resolve(true, CookieScope.Scope.SITE, null));
            assertThrows(IllegalArgumentException.class,
                    () -> CookieScope.resolve(false, CookieScope.Scope.SITE, "example.com"));
            assertThrows(IllegalArgumentException.class,
                    () -> CookieScope.resolve(true, CookieScope.Scope.SITE, ".example.com"));
            // A domain outside site scope is a misconfiguration, not a silent no-op.
            assertThrows(IllegalArgumentException.class,
                    () -> CookieScope.resolve(true, CookieScope.Scope.HOST, "example.com"));
        }
    }

    @Nested
    class RegistrationHeader {

        @Test
        @DisplayName("format is (alg);path=\"...\";challenge=\"...\" with no spaces and no id")
        void exactFormat() {
            assertEquals(
                    "(ES256);path=\"/dbsc/registration\";challenge=\"abc\"",
                    DbscHeaderCodec.buildRegistrationHeader("ES256", "/dbsc/registration", "abc"));
        }

        @Test
        @DisplayName("RS256 is representable in the native registration header")
        void rs256() {
            assertEquals(
                    "(RS256);path=\"/r\";challenge=\"j\"",
                    DbscHeaderCodec.buildRegistrationHeader("RS256", "/r", "j"));
        }

        @Test
        @DisplayName("the challenge header is bare, or carries id when a session is known")
        void challengeHeader() {
            assertEquals("\"abc\"", DbscHeaderCodec.buildChallengeHeader("abc", null));
            assertEquals("\"abc\";id=\"sess_1\"", DbscHeaderCodec.buildChallengeHeader("abc", "sess_1"));
        }
    }

    @Nested
    class SkippedHeader {

        @Test
        @DisplayName("recognized reasons are parsed and unrecognized tokens ignored")
        void parseRecognizedAndUnknown() {
            List<SkippedEntry> entries = DbscHeaderCodec.parseSkippedHeader(
                    "quota_exceeded;session_identifier=\"sess_1\", nonsense;session_identifier=\"sess_2\"");
            assertEquals(1, entries.size(), "an unrecognized token MUST be ignored, not rejected");
            assertEquals(SkippedReason.QUOTA_EXCEEDED, entries.get(0).reason());
            assertEquals("sess_1", entries.get(0).sessionId());
        }

        @Test
        @DisplayName("multiple entries, quotes stripped, session id optional")
        void multipleEntries() {
            List<SkippedEntry> entries = DbscHeaderCodec.parseSkippedHeader(
                    "unreachable;session_identifier=\"1\", server_error;session_identifier=\"2\"");
            assertEquals(2, entries.size());
            assertEquals(SkippedReason.UNREACHABLE, entries.get(0).reason());
            assertEquals("1", entries.get(0).sessionId());
            assertEquals(SkippedReason.SERVER_ERROR, entries.get(1).reason());
            assertEquals("2", entries.get(1).sessionId());
        }

        @Test
        @DisplayName("an empty or absent header yields no entries and raises nothing")
        void emptyIsNotAnError() {
            assertTrue(DbscHeaderCodec.parseSkippedHeader(null).isEmpty());
            assertTrue(DbscHeaderCodec.parseSkippedHeader("").isEmpty());
            assertTrue(DbscHeaderCodec.parseSkippedHeader("   ").isEmpty());
        }
    }

    @Nested
    class ProofHeaderParsing {

        @Test
        @DisplayName("a well-formed header parses, with and without bh")
        void wellFormed() {
            BoundProofHeader.Parsed bare = BoundProofHeader.parse("ts=1700000000000;sig=abc");
            assertEquals(1_700_000_000_000L, bare.timestamp());
            assertEquals("abc", bare.signature());
            assertNull(bare.bodyHash());

            BoundProofHeader.Parsed withBody =
                    BoundProofHeader.parse("ts=1700000000000;sig=abc;bh=deadbeef");
            assertEquals("deadbeef", withBody.bodyHash());
        }

        @Test
        @DisplayName("segment order is not significant")
        void orderInsignificant() {
            BoundProofHeader.Parsed parsed = BoundProofHeader.parse("sig=abc;bh=beef;ts=1700000000000");
            assertEquals(1_700_000_000_000L, parsed.timestamp());
            assertEquals("abc", parsed.signature());
            assertEquals("beef", parsed.bodyHash());
        }

        @Test
        @DisplayName("rejects a header over 8192 bytes")
        void tooLong() {
            String huge = "ts=1700000000000;sig=" + "a".repeat(9000);
            DbscException failure = assertThrows(DbscException.class,
                    () -> BoundProofHeader.parse(huge));
            assertEquals(DbscErrorCode.MALFORMED_PROOF, failure.code());
        }

        @Test
        @DisplayName("rejects more than 8 segments")
        void tooManySegments() {
            String many = "ts=1;sig=a;a=1;b=2;c=3;d=4;e=5;f=6;g=7";
            DbscException failure = assertThrows(DbscException.class,
                    () -> BoundProofHeader.parse(many));
            assertEquals(DbscErrorCode.MALFORMED_PROOF, failure.code());
        }

        @Test
        @DisplayName("rejects a duplicate key")
        void duplicateKey() {
            DbscException failure = assertThrows(DbscException.class,
                    () -> BoundProofHeader.parse("ts=1;sig=a;ts=2"));
            assertEquals(DbscErrorCode.MALFORMED_PROOF, failure.code());
        }

        @ParameterizedTest
        @DisplayName("rejects a segment with an empty value or no '='")
        @ValueSource(strings = {
                "ts=1;sig=",
                "ts=1;sig",
                "ts=;sig=abc",
        })
        void emptyValueOrNoEquals(String header) {
            assertThrows(DbscException.class, () -> BoundProofHeader.parse(header));
        }

        @Test
        @DisplayName("an empty segment is skipped, matching the reference parser")
        void emptySegmentSkipped() {
            BoundProofHeader.Parsed parsed = BoundProofHeader.parse("ts=1;;sig=abc");
            assertEquals(1L, parsed.timestamp());
            assertEquals("abc", parsed.signature());
        }

        @ParameterizedTest
        @DisplayName("rejects a non-finite ts")
        @ValueSource(strings = {
                "ts=NaN;sig=abc",
                "ts=Infinity;sig=abc",
                "ts=-Infinity;sig=abc",
                "ts=notanumber;sig=abc",
                "ts=1.5;sig=abc",
        })
        void nonFiniteTimestamp(String header) {
            assertThrows(DbscException.class, () -> BoundProofHeader.parse(header));
        }

        @ParameterizedTest
        @DisplayName("rejects a missing ts or sig")
        @ValueSource(strings = {"sig=abc", "ts=1", "bh=beef"})
        void missingRequiredFields(String header) {
            assertThrows(DbscException.class, () -> BoundProofHeader.parse(header));
        }

        @Test
        @DisplayName("the replay key uses the first 43 characters of the signature")
        void replayKeyPrefix() {
            String signature = "A".repeat(43) + "BBBBBBBB";
            BoundProofHeader.Parsed parsed =
                    BoundProofHeader.parse("ts=1700000000000;sig=" + signature);
            assertEquals(
                    "sess_1.1700000000000." + "A".repeat(43),
                    parsed.replayKey("sess_1"));
        }
    }

    @Nested
    class SignedMessage {

        @Test
        @DisplayName("the method is uppercased and fields join with single dots")
        void methodUppercased() {
            assertEquals(
                    "sess_1.POST./api/payment.1700000000000",
                    BoundProofHeader.signedMessage("sess_1", "post", "/api/payment", 1_700_000_000_000L, null));
        }

        @Test
        @DisplayName("body signing appends the body hash as a fifth field")
        void withBodyHash() {
            assertEquals(
                    "sess_1.POST./api/payment.1700000000000.abc",
                    BoundProofHeader.signedMessage(
                            "sess_1", "POST", "/api/payment", 1_700_000_000_000L, "abc"));
        }
    }

    @Nested
    class CookieHeaderParsing {

        @Test
        @DisplayName("parses names and values, keeps the first duplicate, strips quotes")
        void parse() {
            Map<String, String> cookies = DbscHeaderCodec.parseCookieHeader(
                    "__Host-dbsc-session=sess_1; __Host-dbsc-challenge=\"jti_1\"; other=x");
            assertEquals("sess_1", cookies.get("__Host-dbsc-session"));
            assertEquals("jti_1", cookies.get("__Host-dbsc-challenge"));
            assertEquals("x", cookies.get("other"));
        }

        @Test
        @DisplayName("a __proto__ cookie name is a plain entry, not prototype pollution")
        void prototypePollutionResistance() {
            Map<String, String> cookies = DbscHeaderCodec.parseCookieHeader("__proto__=evil; a=b");
            assertEquals("evil", cookies.get("__proto__"));
            assertEquals("b", cookies.get("a"));
            assertFalse(cookies.isEmpty());
        }

        @Test
        @DisplayName("malformed percent-encoding keeps the raw value instead of throwing")
        void malformedEncoding() {
            Map<String, String> cookies = DbscHeaderCodec.parseCookieHeader("a=%E0%A4%A; b=1");
            assertEquals("%E0%A4%A", cookies.get("a"));
            assertEquals("1", cookies.get("b"));
        }

        @Test
        @DisplayName("an absent header yields an empty map")
        void absent() {
            assertTrue(DbscHeaderCodec.parseCookieHeader(null).isEmpty());
            assertTrue(DbscHeaderCodec.parseCookieHeader("").isEmpty());
        }
    }
}
