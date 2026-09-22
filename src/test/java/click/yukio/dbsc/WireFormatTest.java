package click.yukio.dbsc;

import click.yukio.dbsc.core.SkippedEntry;
import click.yukio.dbsc.core.SkippedReason;
import click.yukio.dbsc.protocol.CookieScope;
import click.yukio.dbsc.protocol.DbscHeaderCodec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Wire-format tests for cookies and headers.
 *
 * <p>These rules are security-critical and byte-exact: a single wrong character
 * makes Chromium silently drop the binding.
 */
class WireFormatTest {

    /**
     * The attributes string MUST match the real {@code Set-Cookie} byte-for-byte,
     * or Chromium drops the session — it re-reads the string to know how to
     * to re-issue the binding cookie on refresh.
     */
    @Nested
    class Cookies {

        @Test
        @DisplayName("host scope: __Host- names and the exact attributes string")
        void hostScope() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.HOST, null);

            assertEquals("__Host-dbsc-session", scope.bindingCookieName());
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
            // A token path, which is what the caller actually passes: the session is
            // named by the token, not by a cookie.
            assertEquals(
                    "(ES256);path=\"/dbsc/regist/tok\";challenge=\"abc\"",
                    DbscHeaderCodec.buildRegistrationHeader("ES256", "/dbsc/regist/tok", "abc"));
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
