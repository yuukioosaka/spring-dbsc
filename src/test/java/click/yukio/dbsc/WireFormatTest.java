package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.SkippedEntry;
import click.yukio.dbsc.core.SkippedReason;
import click.yukio.dbsc.protocol.CookieScope;
import click.yukio.dbsc.protocol.DbscHeaderCodec;
import click.yukio.dbsc.protocol.SessionConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
     * {@code scope.scope_specification} and {@code allowed_refresh_initiators}: the two
     * JSON keys that tell the browser where the session applies and who may make it
     * refresh. Both are advisory to the user agent, so what matters here is that the
     * configured shape survives into the JSON unaltered — array order included, since
     * §8.2 walks the specs in reverse.
     */
    @Nested
    class ScopeAndInitiators {

        private DbscProperties properties() {
            DbscProperties properties = new DbscProperties();
            properties.setCookieScope(CookieScope.Scope.HOST);
            return properties;
        }

        private Map<String, Object> render(DbscProperties properties) {
            return SessionConfig.build("https://example.com", "/dbsc/refresh", "sid-1",
                    CookieScope.resolve(true, CookieScope.Scope.HOST, null), false, properties);
        }

        @SuppressWarnings("unchecked")
        private List<Map<String, Object>> specs(Map<String, Object> config) {
            return (List<Map<String, Object>>) ((Map<String, Object>) config.get("scope"))
                    .get("scope_specification");
        }

        @SuppressWarnings("unchecked")
        private Map<String, Object> scopeOf(Map<String, Object> config) {
            return (Map<String, Object>) config.get("scope");
        }

        private String str(Object value) {
            return String.valueOf(value);
        }

        @SuppressWarnings("unchecked")
        private List<String> initiators(Map<String, Object> config) {
            return (List<String>) config.get("allowed_refresh_initiators");
        }

        @Test
        @DisplayName("both keys are always present, empty when unconfigured")
        void defaultsAreEmptyLists() {
            Map<String, Object> config = render(properties());

            // Emitted rather than omitted: an absent key and an empty list mean the same
            // thing to the browser, and writing it makes the behaviour legible.
            assertTrue(config.containsKey("allowed_refresh_initiators"));
            assertTrue(initiators(config).isEmpty());
            assertTrue(specs(config).isEmpty());
        }

        @Test
        @DisplayName("origin is the resolved origin, and is omitted only when unknown")
        void originIsRendered() {
            assertEquals("https://example.com", scopeOf(render(properties())).get("origin"));

            // null means "let Chromium infer it from the request URL". Emitting the key
            // with a null value would fail §8.9's "valid non-opaque origin" check, so it
            // is dropped entirely instead.
            Map<String, Object> noOrigin = SessionConfig.build(
                    null, "/dbsc/refresh", "sid-1",
                    CookieScope.resolve(true, CookieScope.Scope.HOST, null), false, properties());
            assertFalse(scopeOf(noOrigin).containsKey("origin"), str(scopeOf(noOrigin)));
        }

        @Test
        @DisplayName("scope specifications keep their configured order and type")
        void scopeSpecificationsPreserveOrder() {
            DbscProperties properties = properties();
            properties.setScopeSpecifications(List.of(
                    spec(DbscProperties.ScopeSpecification.Type.EXCLUDE, "*", "/static"),
                    spec(DbscProperties.ScopeSpecification.Type.INCLUDE, "localhost", "/api")));

            List<Map<String, Object>> rendered = specs(render(properties));

            assertEquals(2, rendered.size());
            // §8.2 walks the list in reverse, so the server's order is the whole point:
            // the second entry is the one that wins. Re-sorting would invert the rules.
            assertEquals("exclude", rendered.get(0).get("type"));
            assertEquals("*", rendered.get(0).get("domain"));
            assertEquals("/static", rendered.get(0).get("path"));
            assertEquals("include", rendered.get(1).get("type"));
            assertEquals("localhost", rendered.get(1).get("domain"));
            assertEquals("/api", rendered.get(1).get("path"));
        }

        @Test
        @DisplayName("an omitted domain or path is written out as the spec's default")
        void scopeSpecificationFillsDefaults() {
            DbscProperties properties = properties();
            properties.setScopeSpecifications(List.of(
                    spec(DbscProperties.ScopeSpecification.Type.EXCLUDE, null, null)));

            Map<String, Object> rendered = specs(render(properties)).get(0);

            // §9.8 makes both keys optional, defaulting to "*" and "/". Filling them in
            // keeps the emitted JSON self-describing instead of relying on the browser's
            // defaults for a rule that excluded everything.
            assertEquals("*", rendered.get("domain"));
            assertEquals("/", rendered.get("path"));
        }

        @Test
        @DisplayName("initiators are trimmed, and blank entries dropped")
        void initiatorsAreNormalised() {
            DbscProperties properties = properties();
            properties.setAllowedRefreshInitiators(
                    List.of(" example.com ", "", "*.example.com", "  "));

            assertEquals(List.of("example.com", "*.example.com"), initiators(render(properties)));
        }

        @Test
        @DisplayName("a null list is normalised to empty rather than thrown on")
        void nullListsAreTolerated() {
            DbscProperties properties = properties();
            properties.setScopeSpecifications(null);
            properties.setAllowedRefreshInitiators(null);

            assertTrue(specs(render(properties)).isEmpty());
            assertTrue(initiators(render(properties)).isEmpty());
        }

        @Test
        @DisplayName("the config declares neither key on a terminated session")
        void terminatedKeepsScopeKeys() {
            Map<String, Object> config = SessionConfig.terminated(
                    "https://example.com", "/dbsc/refresh", "sid-1",
                    CookieScope.resolve(true, CookieScope.Scope.HOST, null), properties());

            // continue:false terminates, but the keys must still parse: §8.9 reads the
            // whole object before it looks at `continue`.
            assertEquals(Boolean.FALSE, config.get("continue"));
            assertTrue(config.containsKey("scope"));
            assertTrue(config.containsKey("allowed_refresh_initiators"));
        }

        private DbscProperties.ScopeSpecification spec(
                DbscProperties.ScopeSpecification.Type type, String domain, String path) {
            DbscProperties.ScopeSpecification spec = new DbscProperties.ScopeSpecification();
            spec.setType(type);
            spec.setDomain(domain);
            spec.setPath(path);
            return spec;
        }
    }

    /**
     * The attributes string MUST match the real {@code Set-Cookie} byte-for-byte,
     * or Chromium drops the session — it re-reads the string to know how to
     * to re-issue the binding cookie on refresh.
     */
    @Nested
    class Cookies {

        @Test
        @DisplayName("host scope: the credential name is verbatim and the attributes exact")
        void hostScope() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.HOST, null);

            assertEquals(CookieScope.DEFAULT_CREDENTIAL_COOKIE, scope.credentialCookieName());
            assertEquals("Path=/; Secure; HttpOnly; SameSite=Lax", scope.attributesString());
        }

        @Test
        @DisplayName("site scope: Domain appended without a leading dot")
        void siteScope() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.SITE, "example.com");

            assertEquals(
                    "Path=/; Secure; HttpOnly; SameSite=Lax; Domain=example.com",
                    scope.attributesString());
        }

        @Test
        @DisplayName("the credential cookie name is taken verbatim from configuration")
        void credentialCookieNameIsVerbatim() {
            CookieScope scope = CookieScope.resolve(
                    true, CookieScope.Scope.HOST, null, "__Host-auth_cookie");

            // The name is a deployer choice: no prefix is added, and it is independent
            // of the cookie session_identifier refers to -- which is not a cookie at all.
            assertEquals("__Host-auth_cookie", scope.credentialCookieName());
            assertNotEquals("__Host-dbsc-session", scope.credentialCookieName());
        }

        @Test
        @DisplayName("a blank credential cookie name falls back to the default")
        void credentialCookieNameDefaults() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.HOST, null, "  ");

            assertEquals(CookieScope.DEFAULT_CREDENTIAL_COOKIE, scope.credentialCookieName());
        }

        @Test
        @DisplayName("insecure dev: no prefix is applied to a configured name")
        void insecureDev() {
            CookieScope scope = CookieScope.resolve(
                    false, CookieScope.Scope.HOST, null, "auth_cookie");

            assertEquals("auth_cookie", scope.credentialCookieName());
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

        /**
         * {@code Max-Age} MUST NOT travel in {@code credentials[].attributes}. Chromium
         * parses that string as a cookie attribute list, where {@code Max-Age} is not
         * permitted, and rejects the registration with "cookie attribute not permitted"
         * — observed against a real browser. §8.6 matches only Domain, Path, Secure,
         * HttpOnly and SameSite, so the lifetime is not merely optional there, it is
         * invalid.
         */
        @Test
        @DisplayName("the advertised attributes carry no Max-Age, which Chromium rejects")
        void attributesCarryNoMaxAge() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.HOST, null);

            assertFalse(scope.attributesString().contains("Max-Age"),
                    "Max-Age in credentials[].attributes invalidates the registration");
            // The lifetime is still present on the real header; only the advertised
            // attribute string omits it.
            assertTrue(scope.setCookieValue("__Host-auth_cookie", "ticket", 30_000)
                    .endsWith("Max-Age=30"));
        }

        @Test
        @DisplayName("with site scope the attributes end at Domain, with no Max-Age")
        void siteScopeAttributesCarryNoMaxAge() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.SITE, "example.com");

            assertEquals("Path=/; Secure; HttpOnly; SameSite=Lax; Domain=example.com",
                    scope.attributesString());
            assertFalse(scope.attributesString().contains("Max-Age"));
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
        @DisplayName("SameSite defaults to Lax, and each value is written verbatim")
        void sameSiteIsConfigurable() {
            assertEquals(CookieScope.SameSite.LAX,
                    CookieScope.resolve(true, CookieScope.Scope.HOST, null).sameSite());

            for (CookieScope.SameSite value : CookieScope.SameSite.values()) {
                CookieScope scope = CookieScope.resolve(
                        true, CookieScope.Scope.HOST, null, null, value);
                assertTrue(scope.attributesString().contains("SameSite=" + value.wireValue()),
                        value + " must reach the attributes: " + scope.attributesString());
                // The advertised string and the real header must never disagree, in any
                // combination -- that mismatch is what Chromium discards silently.
                assertTrue(scope.setCookieValue("c", "v", 1000)
                                .contains("SameSite=" + value.wireValue()),
                        "the Set-Cookie value must carry the same SameSite");
            }
        }

        @Test
        @DisplayName("SameSite=None without Secure is rejected rather than silently dropped by the browser")
        void sameSiteNoneRequiresSecure() {
            assertThrows(IllegalArgumentException.class,
                    () -> CookieScope.resolve(false, CookieScope.Scope.HOST, null, null,
                            CookieScope.SameSite.NONE));
        }

        @Test
        @DisplayName("SameSite=Strict is accepted, and still carries Secure")
        void sameSiteStrict() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.HOST, null, null,
                    CookieScope.SameSite.STRICT);

            assertEquals("Path=/; Secure; HttpOnly; SameSite=Strict", scope.attributesString());
        }

        @Test
        @DisplayName("Path is configurable, and a relative one is rejected")
        void pathIsConfigurable() {
            CookieScope scope = CookieScope.resolve(true, CookieScope.Scope.HOST, null, null,
                    null, "/app", null);

            assertEquals("Path=/app; Secure; HttpOnly; SameSite=Lax", scope.attributesString());
            assertEquals("/app", scope.path());

            // A blank path is the default, not an error.
            assertEquals(CookieScope.DEFAULT_PATH, CookieScope.resolve(
                    true, CookieScope.Scope.HOST, null, null, null, "  ", null).path());

            // A relative path is rewritten by the browser, so the advertised string would
            // stop matching the real cookie and the binding would never complete.
            assertThrows(IllegalArgumentException.class,
                    () -> CookieScope.resolve(true, CookieScope.Scope.HOST, null, null,
                            null, "app", null));
        }

        @Test
        @DisplayName("HttpOnly is on by default and can be turned off, dropping it from both outputs")
        void httpOnlyIsConfigurable() {
            CookieScope defaulted = CookieScope.resolve(true, CookieScope.Scope.HOST, null);
            assertTrue(defaulted.httpOnly());
            assertTrue(defaulted.attributesString().contains("HttpOnly"));

            CookieScope off = CookieScope.resolve(true, CookieScope.Scope.HOST, null, null,
                    null, null, false);
            assertFalse(off.httpOnly());
            assertEquals("Path=/; Secure; SameSite=Lax", off.attributesString());
            assertEquals("c=v; Path=/; Secure; SameSite=Lax; Max-Age=1",
                    off.setCookieValue("c", "v", 1000));
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
