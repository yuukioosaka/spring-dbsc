package click.yukio.dbsc.ratelimit;

/**
 * Rate limiter for the unauthenticated registration and refresh surface.
 *
 * <p>Rate limiting is a SHOULD in the toolkit spec (08), and the algorithm is
 * explicitly out of scope, so this interface exists to let an application swap in
 * a shared limiter (Redis, a gateway) without touching the protocol code. A
 * tripped limit maps to HTTP 429 with the {@code RATE_LIMITED} code.
 *
 * <p>Implementations MUST make a recorded failure (see {@link #recordFailure})
 * reduce the budget consulted by {@link #checkRegistration} and
 * {@link #checkRefresh}. Tracking failures in a counter that no check reads
 * leaves the failure path decorative.
 */
public interface RateLimiter {

    /** @return {@code true} when the client is within its registration budget. */
    boolean checkRegistration(String ip);

    /** @return {@code true} when the client is within its refresh budget. */
    boolean checkRefresh(String ip, String sessionId);

    /**
     * Records a failed attempt, so repeated failures are throttled harder than
     * repeated legitimate requests.
     *
     * @param sessionId the session the attempt named, or {@code null} when the
     *                  request did not identify one
     */
    void recordFailure(String ip, String sessionId);

    /** Accepts everything. */
    RateLimiter UNLIMITED = new RateLimiter() {
        @Override
        public boolean checkRegistration(String ip) {
            return true;
        }

        @Override
        public boolean checkRefresh(String ip, String sessionId) {
            return true;
        }

        @Override
        public void recordFailure(String ip, String sessionId) {
            // no-op
        }
    };
}
