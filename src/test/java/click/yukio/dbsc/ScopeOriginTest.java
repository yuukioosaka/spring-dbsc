package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.web.OriginResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code dbsc.scope-origin} pins the origin written into {@code scope.origin}.
 *
 * <p>The failure this guards against is quiet: §8.9 terminates a session whose
 * {@code origin} is not same-site with the destination, and it does so in the
 * <em>browser</em>, so the server still answers 200 and logs nothing. Validation
 * therefore has to happen where a mistake is still visible — at startup.
 */
class ScopeOriginTest {

    private static MockHttpServletRequest request(String scheme, String host, int port) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme(scheme);
        request.setServerName(host);
        request.setServerPort(port);
        return request;
    }

    @Nested
    @DisplayName("resolution")
    class Resolution {

        @Test
        @DisplayName("with no override, the request decides")
        void derivedFromRequest() {
            assertEquals("https://public.example:8443", OriginResolver.resolve(
                    request("https", "public.example", 8443), false, null));
            assertEquals("https://public.example", OriginResolver.resolve(
                    request("https", "public.example", 443), false, null));
            assertEquals("http://public.example", OriginResolver.resolve(
                    request("http", "public.example", 80), false, null));
        }

        @Test
        @DisplayName("a configured origin wins over the request and its headers")
        void overrideWins() {
            MockHttpServletRequest request = request("http", "internal-lb", 8080);
            // Forwarded headers are a competing source of truth; the override outranks
            // them too, so it stays predictable rather than becoming input-dependent.
            request.addHeader("X-Forwarded-Proto", "https");
            request.addHeader("X-Forwarded-Host", "from-proxy.example");

            assertEquals("https://example.com", OriginResolver.resolve(
                    request, true, "https://example.com"));
            assertEquals("https://example.com", OriginResolver.resolve(
                    request, false, "https://example.com"));
        }

        @Test
        @DisplayName("a blank override is treated as unset, not as an empty origin")
        void blankOverrideIsIgnored() {
            // "" would resolve to an opaque origin in §8.9 and terminate every session,
            // so it has to mean "derive this" rather than "use nothing".
            assertEquals("https://public.example", OriginResolver.resolve(
                    request("https", "public.example", 443), false, ""));
            assertEquals("https://public.example", OriginResolver.resolve(
                    request("https", "public.example", 443), false, "   "));
        }

        @Test
        @DisplayName("no host on the request and no override yields null, not a broken string")
        void unknownHost() {
            assertNull(OriginResolver.resolve(request("https", "", 443), false, null));
        }
    }

    @Nested
    @DisplayName("startup validation")
    class Validation {

        @Test
        @DisplayName("unset is valid, so the property can stay absent")
        void unset() {
            OriginResolver.validateConfigured(null);
            OriginResolver.validateConfigured("");
            OriginResolver.validateConfigured("   ");
        }

        @Test
        @DisplayName("absolute http/https origins are accepted, port and all")
        void accepted() {
            OriginResolver.validateConfigured("https://example.com");
            OriginResolver.validateConfigured("https://example.com:8443");
            OriginResolver.validateConfigured("https://localhost:8443");
            OriginResolver.validateConfigured("http://127.0.0.1:8080");
            OriginResolver.validateConfigured("https://[::1]:8443");
        }

        @Test
        @DisplayName("a scheme-less value is rejected: https:// cannot be assumed")
        void rejectsSchemeLess() {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured("example.com"));
            assertEquals(true, e.getMessage().contains("absolute origin"));
        }

        @Test
        @DisplayName("a non-http scheme is rejected")
        void rejectsOtherSchemes() {
            assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured("ftp://example.com"));
            assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured("//example.com"));
        }

        @Test
        @DisplayName("a path, query, or fragment is rejected: origin is not a URL")
        void rejectsPathAndFriends() {
            // §8.9 parses this with the URL parser and requires a non-opaque origin, so
            // a path would either be dropped or make the value opaque. Neither is a
            // diagnosis the operator could reach from the browser behaviour.
            assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured("https://example.com/app"));
            assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured("https://example.com?x=1"));
            assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured("https://example.com#frag"));
        }

        @Test
        @DisplayName("a bad port is rejected rather than passed to the browser")
        void rejectsBadPort() {
            assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured("https://example.com:abc"));
            assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured("https://example.com:"));
            assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured("https://example.com:0"));
            assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured("https://example.com:70000"));
        }

        @Test
        @DisplayName("a missing host is rejected")
        void rejectsEmptyHost() {
            assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured("https://"));
        }

        @Test
        @DisplayName("surrounding whitespace is rejected, not silently trimmed")
        void rejectsWhitespace() {
            // Trimming would be the friendly thing to do, but the value is compared
            // against a browser-generated origin, so a value that needed trimming is a
            // sign the property was built by concatenation somewhere upstream.
            assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured(" https://example.com"));
            assertThrows(IllegalArgumentException.class,
                    () -> OriginResolver.validateConfigured("https://example.com "));
        }
    }

    /**
     * {@code scope-origin} is read once, at startup, and reaches the response through
     * the service rather than through any per-request lookup.
     */
    @Nested
    @DisplayName("wiring")
    class Wiring {

        @Test
        @DisplayName("the property defaults to unset so derivation stays the norm")
        void defaultIsUnset() {
            assertNull(new DbscProperties().getScopeOrigin(),
                    "a hardcoded default would break every deployment that is not that origin");
        }

        @Test
        @DisplayName("scope lists default to empty, never null")
        void listDefaultsAreEmpty() {
            DbscProperties properties = new DbscProperties();
            assertEquals(List.of(), properties.getScopeSpecifications());
            assertEquals(List.of(), properties.getAllowedRefreshInitiators());
        }
    }
}
