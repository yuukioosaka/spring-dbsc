package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.GuardDecision;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.protocol.ChallengeService;
import click.yukio.dbsc.protocol.CookieScope;
import click.yukio.dbsc.protocol.DbscProtocolEngine;
import click.yukio.dbsc.ratelimit.RateLimiter;
import click.yukio.dbsc.storage.InMemoryStorageAdapter;
import click.yukio.dbsc.telemetry.DbscTelemetryEvent;
import click.yukio.dbsc.telemetry.TelemetryPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The nine rules behind {@link DbscService#guardDecision}, each stated as its own
 * case.
 *
 * <p>The reason a table like this needs its own test file: every refusal and every
 * allowance here looks identical to a bare tier check. "Tier is none" is both the
 * normal state of a browser that has never heard of DBSC and the state of a
 * session that was demoted, and telling those apart is the only thing the guard
 * exists to do. The tests are written against the real service and the real
 * storage adapter, because the distinction rests on records that
 * {@code DbscService} writes ({@code lastRefreshAt}, {@code revoked},
 * {@code appSessionId}) — not on anything the filter computes.
 */
class GuardDecisionTest {

    private static final long NOW_MS = 1_700_000_000_000L;
    private static final String SESSION_ID = "sess_guard000000000000000000000000001";
    private static final String APP_SESSION_ID = "72234F6E7E0569EA030946A762211A28";
    private static final String USER_ID = "user_1";

    private DbscProperties properties;
    private StorageAdapter storage;
    private CookieScope cookieScope;
    private DbscService dbsc;

    @BeforeEach
    void setUp() {
        properties = new DbscProperties();

        // Long enough that nothing in here expires: these tests are about the
        // decision, not about the clock.
        properties.setSessionTtl(Duration.ofHours(1));

        storage = new InMemoryStorageAdapter();
        Clock clock = Clock.fixed(Instant.ofEpochMilli(NOW_MS), ZoneOffset.UTC);
        ChallengeService challenges = new ChallengeService(storage, properties, clock);
        List<DbscTelemetryEvent> events = new ArrayList<>();
        TelemetryPublisher telemetry = new TelemetryPublisher(event -> {
            if (event instanceof DbscTelemetryEvent dbscEvent) {
                events.add(dbscEvent);
            }
        }, true);
        DbscProtocolEngine engine =
                new DbscProtocolEngine(storage, properties, challenges, clock, telemetry);
        // Cookie names are derived from the secure flag, never hardcoded (spec 07),
        // so the tests go through the same derivation the service does.
        cookieScope = CookieScope.resolve(false, CookieScope.Scope.HOST, null);
        dbsc = new DbscService(properties, storage, challenges, engine, cookieScope,
                RateLimiter.UNLIMITED, clock, false);
    }

    // ------------------------------------------------------------------
    // A DBSC cookie is present
    // ------------------------------------------------------------------

    @Test
    @DisplayName("protected: the session is registered and proving possession - allowed")
    void protectedSessionIsAllowed() {
        storage.setSession(session().withTierAndLastRefreshAt(ProtectionTier.DBSC, NOW_MS));

        GuardDecision decision = decide(bindingCookie());

        assertTrue(decision.allowed());
        assertEquals(GuardDecision.Reason.PROTECTED, decision.reason());
    }

    @Test
    @DisplayName("lapsed: registered once, then demoted - refused")
    void demotedSessionIsRefused() {
        // The shape a failed refresh leaves behind: tier none, lastRefreshAt set,
        // key still stored. A tier check alone cannot distinguish this from a
        // browser that never registered, which is why lastRefreshAt is carried.
        storage.setSession(session().withTierAndLastRefreshAt(ProtectionTier.NONE, NOW_MS));

        GuardDecision decision = decide(bindingCookie());

        assertFalse(decision.allowed());
        assertEquals(GuardDecision.Reason.LAPSED, decision.reason());
        assertTrue(decision.hadBinding());
    }

    @Test
    @DisplayName("unregistered: bind() ran but registration has not completed - allowed")
    void preRegistrationWindowIsAllowed() {
        // lastRefreshAt == 0 is the witness: nothing has ever succeeded for this
        // session. Refusing here would lock out every browser that cannot do DBSC.
        storage.setSession(session());

        GuardDecision decision = decide(bindingCookie());

        assertTrue(decision.allowed());
        assertEquals(GuardDecision.Reason.UNREGISTERED, decision.reason());
        assertFalse(decision.hadBinding());
    }

    @Test
    @DisplayName("revoked: the binding was terminated - refused, even though the key remains")
    void revokedSessionIsRefused() {
        storage.setSession(session()
                .withTierAndLastRefreshAt(ProtectionTier.DBSC, NOW_MS)
                .withRevoked(true));

        GuardDecision decision = decide(bindingCookie());

        assertFalse(decision.allowed());
        assertEquals(GuardDecision.Reason.REVOKED, decision.reason());
    }

    @Test
    @DisplayName("lapsed: the cookie names a session record that no longer exists - refused")
    void cookieForVanishedSessionIsRefused() {
        // A binding demonstrably existed, since the browser still holds the cookie,
        // but the server has no record. Treating that as a fresh client would let a
        // session survive by having its record deleted.
        GuardDecision decision = decide(bindingCookie());

        assertFalse(decision.allowed());
        assertEquals(GuardDecision.Reason.LAPSED, decision.reason());
    }

    @Test
    @DisplayName("revoked beats unregistered: a revoked pre-registration record is still refused")
    void revokedPreRegistrationIsRefused() {
        // The ordering inside the cookie branch: revocation is checked before the
        // lastRefreshAt heuristic, so a record cannot be revoked and then read as
        // "never registered".
        storage.setSession(session().withRevoked(true));

        GuardDecision decision = decide(bindingCookie());

        assertFalse(decision.allowed());
        assertEquals(GuardDecision.Reason.REVOKED, decision.reason());
    }

    // ------------------------------------------------------------------
    // No DBSC cookie
    // ------------------------------------------------------------------

    @Test
    @DisplayName("cookie omitted while a binding exists - refused (the bypass)")
    void omittedCookieIsRefusedWhenABindingExists() {
        // The whole reason the application session id is passed in. A client that
        // registered can simply stop sending the DBSC cookies; without this rule it
        // would be indistinguishable from a first-time visitor and drop back to
        // unbound access.
        storage.setSession(session().withTierAndLastRefreshAt(ProtectionTier.DBSC, NOW_MS));

        GuardDecision decision = decide(null);

        assertFalse(decision.allowed());
        assertEquals(GuardDecision.Reason.COOKIE_MISSING, decision.reason());
        assertTrue(decision.hadBinding());
    }

    @Test
    @DisplayName("cookie omitted while a revoked binding exists - refused as revoked")
    void omittedCookieIsRefusedWhenTheBindingWasRevoked() {
        storage.setSession(session().withRevoked(true));

        GuardDecision decision = decide(null);

        assertFalse(decision.allowed());
        assertEquals(GuardDecision.Reason.REVOKED, decision.reason());
    }

    @Test
    @DisplayName("cookie omitted and no binding at all - allowed")
    void omittedCookieIsAllowedWhenNothingWasEverBound() {
        GuardDecision decision = decide(null);

        assertTrue(decision.allowed());
        assertEquals(GuardDecision.Reason.UNREGISTERED, decision.reason());
    }

    @Test
    @DisplayName("no cookie and no application session id - allowed, there is nothing to look up")
    void noCookieAndNoAppSessionIsAllowed() {
        storage.setSession(session().withTierAndLastRefreshAt(ProtectionTier.DBSC, NOW_MS));

        GuardDecision decision = decide(null, null);

        assertTrue(decision.allowed());
        assertEquals(GuardDecision.Reason.UNREGISTERED, decision.reason());
    }

    @Test
    @DisplayName("a blank application session id is treated as absent")
    void blankAppSessionIdIsAllowed() {
        storage.setSession(session().withTierAndLastRefreshAt(ProtectionTier.DBSC, NOW_MS));

        GuardDecision decision = decide(null, "   ");

        assertTrue(decision.allowed());
        assertEquals(GuardDecision.Reason.UNREGISTERED, decision.reason());
    }

    @Test
    @DisplayName("the DBSC session id and the application session id are unrelated")
    void lookupFallsBackToTheAppSessionId() {
        // The binding is stored under appSessionId, which is deliberately not equal
        // to the DBSC id. Finding it proves the lookup is by the recorded
        // application session id rather than by anything derived from the DBSC id.
        storage.setSession(session().withTierAndLastRefreshAt(ProtectionTier.DBSC, NOW_MS));

        assertFalse(SESSION_ID.equals(APP_SESSION_ID), "the two ids must differ for this test to mean anything");

        GuardDecision byAppSessionOnly = decide(null);
        assertEquals(GuardDecision.Reason.COOKIE_MISSING, byAppSessionOnly.reason(),
                "the binding must be found from the application session id alone");

        GuardDecision otherAppSession = decide(null, "some-other-session-id");
        assertTrue(otherAppSession.allowed(),
                "a different application session must not inherit the binding");
    }

    @Test
    @DisplayName("a present DBSC cookie wins over the application session lookup")
    void dbscCookieTakesPrecedenceOverAppSessionLookup() {
        // Two records: the cookie names one, the application session maps to the
        // other. The cookie is what the request is about, so its session decides.
        storage.setSession(session().withTierAndLastRefreshAt(ProtectionTier.DBSC, NOW_MS));
        storage.setSession(new Session(SESSION_ID, "a-different-app-session", USER_ID,
                ProtectionTier.NONE, false, NOW_MS, NOW_MS + 3_600_000L, NOW_MS));

        GuardDecision decision = decide(bindingCookie());

        assertFalse(decision.allowed());
        assertEquals(GuardDecision.Reason.LAPSED, decision.reason());
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** A record in the pre-registration state: tier none, never refreshed. */
    private static Session session() {
        return new Session(SESSION_ID, APP_SESSION_ID, USER_ID, ProtectionTier.NONE,
                false, NOW_MS, NOW_MS + 3_600_000L, 0L);
    }

    private GuardDecision decide(jakarta.servlet.http.Cookie bindingCookie) {
        return decide(bindingCookie, APP_SESSION_ID);
    }

    private GuardDecision decide(jakarta.servlet.http.Cookie bindingCookie, String appSessionId) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        // The cookie is read off the raw Cookie header, not the servlet's parsed
        // array, so set the header the way a browser would send it.
        if (bindingCookie != null) {
            request.addHeader("Cookie", bindingCookie.getName() + "=" + bindingCookie.getValue());
        }
        return dbsc.guardDecision(request, appSessionId);
    }

    /**
     * The binding cookie as {@code bind()} leaves it: named for the DBSC session id.
     * The name comes from the scope, because it depends on the secure flag.
     */
    private jakarta.servlet.http.Cookie bindingCookie() {
        return new jakarta.servlet.http.Cookie(cookieScope.bindingCookieName(), SESSION_ID);
    }
}
