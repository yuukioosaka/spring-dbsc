package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.web.OriginResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code X-Forwarded-* } is client-supplied on every request that reaches the
 * application directly, so trusting it lets the caller choose the origin handed
 * to the browser as the scope a session is bound to.
 *
 * <p>These tests run against two separate contexts (trust on and trust off)
 * because the property is read once at startup.
 */
class ForwardedHeaderTrustTest {

    private static MockHttpServletRequest request(String forwardedProto, String forwardedHost) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/dbsc/refresh");
        request.setScheme("http");
        request.setServerName("internal-host");
        request.setServerPort(8080);
        if (forwardedProto != null) {
            request.addHeader("X-Forwarded-Proto", forwardedProto);
        }
        if (forwardedHost != null) {
            request.addHeader("X-Forwarded-Host", forwardedHost);
        }
        return request;
    }

    @Test
    @DisplayName("default: forwarding headers are not trusted")
    void trustedByDefaultIsFalse() {
        DbscProperties properties = new DbscProperties();
        assertEquals(false, properties.isTrustForwardedHeaders(),
                "a forged X-Forwarded-Host must not be believed unless configured otherwise");
        assertEquals("http://internal-host:8080",
                OriginResolver.resolve(request("https", "evil.example"), false, null),
                "with the default, the headers are ignored in favour of the request itself");
    }

    @Test
    @DisplayName("trusted proxy: the forwarded scheme and host are used")
    void forwardedOriginIsUsedWhenTrusted() {
        assertEquals("https://public.example:8080",
                OriginResolver.resolve(request("https", "public.example"), true, null),
                "a trusted proxy's scheme and host are what the browser must be told");
        assertEquals("https://public.example",
                OriginResolver.resolve(request("https", "public.example:443"), true, null),
                "a forwarded port of 443 is the default for https, so it is dropped");
    }

    @Test
    @DisplayName("trusting forwarding headers is independent of the Secure cookie flag")
    void independentOfSecureFlag() {
        DbscProperties properties = new DbscProperties();
        // secure=true is the TLS-terminating-proxy case, which is exactly when an
        // operator might wrongly assume the forwarding headers are safe to trust.
        assertTrue(properties.isSecure());
        assertEquals(false, properties.isTrustForwardedHeaders(),
                "terminating TLS does not imply inbound forwarding headers are stripped");
    }

    /** The property is bound from the environment, so the wiring is asserted too. */
    @SpringBootTest
    @AutoConfigureMockMvc
    @ActiveProfiles("test")
    @TestPropertySource(properties = "dbsc.trust-forwarded-headers=true")
    static class WiredOn {
        @Autowired
        private DbscProperties properties;

        @Test
        @DisplayName("dbsc.trust-forwarded-headers is bound onto the properties")
        void propertyIsBound() {
            assertTrue(properties.isTrustForwardedHeaders());
        }
    }
}
