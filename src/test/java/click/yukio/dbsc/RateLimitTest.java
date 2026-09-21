package click.yukio.dbsc;

import click.yukio.dbsc.ratelimit.InMemoryRateLimiter;
import click.yukio.dbsc.ratelimit.RateLimiter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The unauthenticated registration/refresh surface is the only place DBSC is
 * reachable without a session, so the rate limiter is the sole defence there
 * against an attacker grinding challenges. Spec 08 maps a tripped limit to
 * {@code RATE_LIMITED} / 429 rather than 403, because it is throttling and not a
 * rejected proof.
 */
class RateLimitTest {

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

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
