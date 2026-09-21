package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.DbscErrorCode;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.protocol.ChallengeService;
import click.yukio.dbsc.protocol.CookieScope;
import click.yukio.dbsc.protocol.DbscProtocolEngine;
import click.yukio.dbsc.ratelimit.InMemoryRateLimiter;
import click.yukio.dbsc.ratelimit.RateLimiter;
import click.yukio.dbsc.replay.InMemoryProofReplayCache;
import click.yukio.dbsc.storage.InMemoryStorageAdapter;
import click.yukio.dbsc.telemetry.TelemetryPublisher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The unauthenticated registration/refresh surface is the only place DBSC is
 * reachable without a session, so the rate limiter is the sole defence there
 * against an attacker grinding challenges. Spec 08 maps a tripped limit to
 * {@code RATE_LIMITED} / 429 rather than 403, because it is throttling and not a
 * rejected proof.
 */
class RateLimitTest {

    /**
     * Records the key each check and each failure is attributed to.
     *
     * <p>Exists so a test can assert that the two agree. The limiter itself cannot
     * detect a mismatch: {@link InMemoryRateLimiter} keeps every budget in one map
     * and simply never trips when the key it checks is not the key it charged.
     */
    private static final class RecordingLimiter implements RateLimiter {

        record Charge(String kind, String ip, String sessionId) {
        }

        final List<Charge> charges = new ArrayList<>();
        boolean allow = true;

        @Override
        public boolean checkRegistration(String ip) {
            charges.add(new Charge("checkRegistration", ip, null));
            return allow;
        }

        @Override
        public boolean checkRefresh(String ip, String sessionId) {
            charges.add(new Charge("checkRefresh", ip, sessionId));
            return allow;
        }

        @Override
        public void recordFailure(String ip, String sessionId) {
            charges.add(new Charge("recordFailure", ip, sessionId));
        }
    }

    @Test
    @DisplayName("registration budget is spent at capacity and refills on the next window")
    void registrationBudgetByWindow() {
        RateLimiter limiter = new InMemoryRateLimiter(3, Duration.ofMillis(50));

        assertTrue(limiter.checkRegistration("10.0.0.1"), "first of three is allowed");
        assertTrue(limiter.checkRegistration("10.0.0.1"), "second is allowed");
        assertTrue(limiter.checkRegistration("10.0.0.1"), "third is allowed");
        assertFalse(limiter.checkRegistration("10.0.0.1"), "fourth exceeds capacity");

        sleep(80);

        assertTrue(limiter.checkRegistration("10.0.0.1"), "a new window resets the budget");
    }

    @Test
    @DisplayName("one client exhausting its budget does not throttle another")
    void budgetsArePerClient() {
        RateLimiter limiter = new InMemoryRateLimiter(2, Duration.ofMinutes(1));

        assertTrue(limiter.checkRegistration("10.0.0.1"));
        assertTrue(limiter.checkRegistration("10.0.0.1"));
        assertFalse(limiter.checkRegistration("10.0.0.1"), "the first client is throttled");

        assertTrue(limiter.checkRegistration("10.0.0.2"), "a second client has its own budget");
    }

    @Test
    @DisplayName("refresh budget is per session, so one busy session cannot throttle others")
    void refreshBudgetIsPerSession() {
        RateLimiter limiter = new InMemoryRateLimiter(2, Duration.ofMinutes(1));

        assertTrue(limiter.checkRefresh("10.0.0.1", "sess_a"));
        assertTrue(limiter.checkRefresh("10.0.0.1", "sess_a"));
        assertFalse(limiter.checkRefresh("10.0.0.1", "sess_a"), "the session is throttled");

        assertTrue(limiter.checkRefresh("10.0.0.1", "sess_b"),
                "another session from the same client still refreshes");
    }

    @Test
    @DisplayName("recorded failures exhaust the failure budget even under the request limit")
    void failuresAreCharged() {
        // A budget of 10 requests with a failure budget of 5: well under capacity
        // by volume, but 5 invalid proofs is enough to be throttled.
        RateLimiter limiter = new InMemoryRateLimiter(10, 5, Duration.ofMinutes(1));

        for (int i = 0; i < 5; i++) {
            limiter.recordFailure("10.0.0.1", "sess_a");
        }

        assertFalse(limiter.checkRegistration("10.0.0.1"),
                "a client that keeps presenting invalid proofs is throttled");
        assertTrue(limiter.checkRegistration("10.0.0.2"),
                "another client is unaffected");
    }

    @Test
    @DisplayName("a failure is charged to both the request and the failure budget")
    void failuresAlsoCostRequestBudget() {
        // Failure budget is generous, request budget is not, so only the request
        // budget can explain a refusal here.
        RateLimiter limiter = new InMemoryRateLimiter(3, 100, Duration.ofMinutes(1));

        limiter.recordFailure("10.0.0.1", null);
        limiter.recordFailure("10.0.0.1", null);
        limiter.recordFailure("10.0.0.1", null);

        assertFalse(limiter.checkRegistration("10.0.0.1"),
                "three failures exhaust a request budget of three");
    }

    @Test
    @DisplayName("refresh failures are charged to the session's refresh budget, not just the client's")
    void refreshFailuresAreChargedToTheRefreshBudget() {
        // The request budget is deliberately huge so the shared registration prefix
        // cannot explain a refusal: only a correctly-keyed refresh charge can. This
        // is a regression test. checkRefresh used to be consulted with a null session
        // while recordFailure charged the real one, so the two keys never matched and
        // a client could fail refreshes forever without ever seeing a 429.
        RateLimiter limiter = new InMemoryRateLimiter(5000, 5, Duration.ofMinutes(1));

        for (int i = 0; i < 5; i++) {
            limiter.recordFailure("10.0.0.1", "sess_a");
        }

        assertFalse(limiter.checkRefresh("10.0.0.1", "sess_a"),
                "five failed refreshes for this session exhaust its refresh budget");
        assertTrue(limiter.checkRefresh("10.0.0.2", "sess_a"),
                "another client is unaffected");
        assertTrue(limiter.checkRefresh("10.0.0.1", "sess_b"),
                "another session from the same client is unaffected");
    }

    @Test
    @DisplayName("a failure budget recovers when its window rolls over")
    void failureBudgetRecovers() {
        RateLimiter limiter = new InMemoryRateLimiter(100, 2, Duration.ofMillis(50));

        limiter.recordFailure("10.0.0.1", null);
        limiter.recordFailure("10.0.0.1", null);
        assertFalse(limiter.checkRegistration("10.0.0.1"), "the failure budget is spent");

        sleep(80);

        assertTrue(limiter.checkRegistration("10.0.0.1"), "a new window clears the failures");
    }

    @Test
    @DisplayName("a non-positive capacity still admits one request rather than deadlocking")
    void degenerateCapacity() {
        RateLimiter limiter = new InMemoryRateLimiter(0, Duration.ofMinutes(1));

        assertTrue(limiter.checkRegistration("10.0.0.1"), "capacity is floored at one");
        assertFalse(limiter.checkRegistration("10.0.0.1"));
    }

    @Test
    @DisplayName("spoofed keys cannot exhaust memory: the tracked-window table stays bounded")
    void distinctKeysAreBounded() {
        // The keys here stand in for attacker-chosen values, which is exactly what
        // an IP taken from a forwarding header or a session id from a cookie is.
        // Without a cap this loop would grow the map without limit.
        RateLimiter limiter = new InMemoryRateLimiter(5, Duration.ofMinutes(10));

        for (int i = 0; i < 50_000; i++) {
            limiter.recordFailure("10.0.0." + i, "sess_" + i);
        }

        // The limiter must still work afterwards: the cap drops counters, it does
        // not corrupt the table or start throwing.
        assertTrue(limiter.checkRegistration("10.9.9.9"),
                "the limiter remains usable once the table is full");
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ------------------------------------------------------------------
    // Key agreement between what is checked and what is charged
    // ------------------------------------------------------------------

    /**
     * Builds a {@link DbscService} whose limiter records every attribution.
     *
     * <p>The service is real, not mocked: the bug this guards against lived in
     * {@code DbscService} choosing which key to pass, and a mock would assume the
     * very behaviour under test.
     */
    private static DbscService serviceWith(RecordingLimiter limiter) {
        DbscProperties properties = new DbscProperties();
        properties.setSecure(false);
        properties.getRateLimit().setEnabled(true);
        InMemoryStorageAdapter storage = new InMemoryStorageAdapter();
        Clock clock = Clock.systemUTC();
        ChallengeService challenges = new ChallengeService(storage, properties, clock);
        DbscProtocolEngine engine = new DbscProtocolEngine(
                storage, properties, challenges, clock,
                org.mockito.Mockito.mock(TelemetryPublisher.class));
        return new DbscService(properties, storage, challenges, engine,
                CookieScope.resolve(false, null, null), limiter,
                new InMemoryProofReplayCache(), clock, false);
    }

    private static MockHttpServletRequest refreshRequest(String sessionId) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/dbsc-bound/refresh");
        request.setRemoteAddr("10.0.0.1");
        if (sessionId != null) {
            // Named through the scope rather than hardcoded: with secure=false the
            // __Host- prefix is absent, and a hardcoded name would silently not be
            // found (making the test pass for the wrong reason).
            CookieScope scope = CookieScope.resolve(false, null, null);
            request.setCookies(new jakarta.servlet.http.Cookie(
                    scope.registrationCookieName(), sessionId));
        }
        return request;
    }

    @Test
    @DisplayName("a refresh failure is charged to the same session key the refresh check reads")
    void refreshChargeMatchesTheKeyThatIsChecked() {
        RecordingLimiter limiter = new RecordingLimiter();
        DbscService dbsc = serviceWith(limiter);

        MockHttpServletRequest request = refreshRequest("sess_a");

        // The refresh is refused for an unrelated reason (no such session), which
        // is what a failing client produces in practice.
        assertThrows(DbscException.class, () -> dbsc.boundRefresh(
                request, new MockHttpServletResponse(), "sig", "jti", 1L));

        // The filter charges the failure after the service refuses it.
        dbsc.recordRateLimitFailure(request);

        List<RecordingLimiter.Charge> checks = limiter.charges.stream()
                .filter(c -> c.kind().equals("checkRefresh")).toList();
        List<RecordingLimiter.Charge> records = limiter.charges.stream()
                .filter(c -> c.kind().equals("recordFailure")).toList();

        assertEquals(1, checks.size(), "the refresh check runs once");
        assertEquals(1, records.size(), "the failure is recorded once");
        assertEquals(checks.get(0).sessionId(), records.get(0).sessionId(),
                "the session id checked must be the session id charged, or the "
                        + "refresh budget is never consulted and failed refreshes are "
                        + "never throttled");
        assertEquals("sess_a", records.get(0).sessionId(),
                "the charge is attributed to the session that was presented");
    }

    @Test
    @DisplayName("a refresh naming no session is checked and charged as sessionless")
    void sessionlessRefreshKeysAgreeOnNull() {
        RecordingLimiter limiter = new RecordingLimiter();
        DbscService dbsc = serviceWith(limiter);

        MockHttpServletRequest request = refreshRequest(null);
        assertThrows(DbscException.class, () -> dbsc.boundRefresh(
                request, new MockHttpServletResponse(), "sig", "jti", 1L));
        dbsc.recordRateLimitFailure(request);

        List<String> checked = limiter.charges.stream()
                .filter(c -> c.kind().equals("checkRefresh")).map(c -> c.sessionId()).toList();
        List<String> recorded = limiter.charges.stream()
                .filter(c -> c.kind().equals("recordFailure")).map(c -> c.sessionId()).toList();

        assertEquals(1, checked.size());
        assertEquals(1, recorded.size());
        assertEquals(checked.get(0), recorded.get(0),
                "an unauthenticated refresh must be keyed identically on both sides");
    }

    @Test
    @DisplayName("a tripped refresh budget surfaces as RATE_LIMITED before any proof work")
    void trippedRefreshBudgetIsRateLimited() {
        RecordingLimiter limiter = new RecordingLimiter();
        limiter.allow = false;
        DbscService dbsc = serviceWith(limiter);

        DbscException thrown = assertThrows(DbscException.class, () -> dbsc.boundRefresh(
                refreshRequest("sess_a"), new MockHttpServletResponse(), "sig", "jti", 1L));

        assertEquals(DbscErrorCode.RATE_LIMITED, thrown.code());
        assertEquals(429, org.springframework.http.HttpStatus.TOO_MANY_REQUESTS.value(),
                "RATE_LIMITED maps to 429, not 403");
    }
}
