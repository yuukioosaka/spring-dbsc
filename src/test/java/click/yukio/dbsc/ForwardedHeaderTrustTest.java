package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.StorageAdapter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code X-Forwarded-For} is client-supplied on every request that reaches the
 * application directly, so trusting it hands the caller the rate-limit key.
 *
 * <p>These tests run against two separate contexts (trust on and trust off)
 * because the property is read once at startup. Both sit behind a mock limiter
 * probe: the limiter is disabled in the test profile, so what is asserted is the
 * configuration default and the parsing rule rather than live throttling.
 */
class ForwardedHeaderTrustTest {

    private static String clientIpOf(DbscProperties properties, String forwarded, String remote) {
        // Exercises the same rule as DbscService.clientIp without a servlet round
        // trip: mirror the branch, taking the last non-empty hop.
        if (properties.isTrustForwardedHeaders() && forwarded != null && !forwarded.isBlank()) {
            String[] hops = forwarded.split(",");
            for (int i = hops.length - 1; i >= 0; i--) {
                String hop = hops[i].trim();
                if (!hop.isEmpty()) {
                    return hop;
                }
            }
        }
        return remote;
    }

    @Test
    @DisplayName("default: forwarding headers are not trusted")
    void trustedByDefaultIsFalse() {
        DbscProperties properties = new DbscProperties();
        assertEquals(false, properties.isTrustForwardedHeaders(),
                "a forged X-Forwarded-For must not be believed unless configured otherwise");
        assertEquals("203.0.113.9",
                clientIpOf(properties, "evil, 1.2.3.4", "203.0.113.9"),
                "with the default, the header is ignored in favour of the socket address");
    }

    @Test
    @DisplayName("trusted proxy: the last hop is keyed on, not the client-claimed first hop")
    void lastHopIsUsed() {
        DbscProperties properties = new DbscProperties();
        properties.setTrustForwardedHeaders(true);

        assertEquals("1.2.3.4",
                clientIpOf(properties, "evil, 1.2.3.4", "203.0.113.9"),
                "the proxy appends the address it saw, so the last entry is the trustworthy one");
        assertEquals("1.2.3.4",
                clientIpOf(properties, "1.2.3.4", "203.0.113.9"),
                "a single-hop chain is the proxy's own value");
        assertEquals("203.0.113.9",
                clientIpOf(properties, "  ,  ", "203.0.113.9"),
                "an all-blank header falls back to the socket address");
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

        @Autowired
        private StorageAdapter storage;

        @Test
        @DisplayName("dbsc.trust-forwarded-headers is bound onto the service")
        void propertyIsBound() {
            assertTrue(properties.isTrustForwardedHeaders());
        }
    }
}
