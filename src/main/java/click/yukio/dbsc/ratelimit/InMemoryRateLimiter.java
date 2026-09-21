package click.yukio.dbsc.ratelimit;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fixed-window, per-process rate limiter. Adequate for a single instance; a
 * multi-instance deployment should supply a shared implementation.
 *
 * <p>Counters are keyed by client IP and window start, and stale windows are
 * dropped opportunistically so an idle limiter does not grow without bound.
 *
 * <p>Two budgets are tracked per client: ordinary request volume, and failed
 * attempts. Both are checked on entry — a client that keeps presenting invalid
 * proofs exhausts the failure budget even when its request volume is low, which
 * is the point of charging failures at all.
 */
public class InMemoryRateLimiter implements RateLimiter {

    /**
     * Ceiling on distinct counters held at once. Keys can embed client-supplied
     * values, so an attacker varying them would otherwise grow the map unbounded;
     * see {@link #count(String)} for what happens at the limit.
     */
    private static final int MAX_TRACKED_KEYS = 10_000;

    private final int capacity;
    private final int failureCapacity;
    private final long windowMs;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    /**
     * @param capacity        permitted requests per window
     * @param failureCapacity permitted <em>failed</em> attempts per window; a
     *                        client that exceeds this is throttled even if it is
     *                        well under {@code capacity}
     * @param window          window length
     */
    public InMemoryRateLimiter(int capacity, int failureCapacity, Duration window) {
        this.capacity = Math.max(1, capacity);
        // A failure budget below one would reject every request from a client that
        // has ever failed, so it is floored at one as well.
        this.failureCapacity = Math.max(1, failureCapacity);
        this.windowMs = Math.max(1, window.toMillis());
    }

    public InMemoryRateLimiter(int capacity, Duration window) {
        this(capacity, defaultFailureCapacity(capacity), window);
    }

    /**
     * Failures are cheaper than ordinary requests but still bounded: an attacker
     * guessing proofs trips this long before it trips the request budget.
     */
    private static int defaultFailureCapacity(int capacity) {
        return Math.max(1, capacity / 2);
    }

    @Override
    public boolean checkRegistration(String ip) {
        return allow(registrationKey(ip));
    }

    @Override
    public boolean checkRefresh(String ip, String sessionId) {
        return allow(refreshKey(ip, sessionId));
    }

    @Override
    public void recordFailure(String ip, String sessionId) {
        if (ip == null || ip.isBlank()) {
            return;
        }
        // A failure is charged against the client's ordinary budget as well as
        // its failure budget: a failure is also a request, and charging only the
        // failure bucket would let an attacker halve its cost by interleaving
        // failures with valid-looking traffic.
        charge(registrationKey(ip));
        if (sessionId != null) {
            charge(refreshKey(ip, sessionId));
        }
    }

    /**
     * Admits a request only when neither budget is exhausted, then records the
     * attempt against the ordinary request budget. The failure budget is charged
     * by {@link #recordFailure} alone — a successful request must not consume
     * it, or ordinary traffic would throttle itself.
     */
    private boolean allow(String key) {
        if (!withinBudget(key, capacity) || !withinBudget(failureKey(key), failureCapacity)) {
            return false;
        }
        count(key);
        return true;
    }

    /** Records one attempt against both the ordinary and the failure budget. */
    private void charge(String key) {
        count(key);
        count(failureKey(key));
    }

    private static String registrationKey(String ip) {
        return "reg:" + ip;
    }

    private static String refreshKey(String ip, String sessionId) {
        return "refresh:" + ip + ":" + sessionId;
    }

    private static String failureKey(String key) {
        return "failed:" + key;
    }

    /**
     * In increments a window counter, creating or rolling it as needed.
     *
     * <p>The map is pruned before inserting, and the key is dropped rather than
     * stored when the table is full. That bound matters because the key can contain
     * a client-supplied value (an IP from a forwarding header, a session id from a
     * cookie): without it, a client varying that value grows the map without limit.
     * Dropping an entry only loses a counter, and a lost counter fails open by at
     * most one window.
     */
    private void count(String key) {
        long now = System.currentTimeMillis();
        if (windows.size() >= MAX_TRACKED_KEYS) {
            windows.entrySet().removeIf(entry -> entry.getValue().startedAt + windowMs < now);
            if (windows.size() >= MAX_TRACKED_KEYS && !windows.containsKey(key)) {
                return;
            }
        }
        windows.compute(key, (k, existing) -> {
            if (existing == null || existing.startedAt + windowMs < now) {
                return new Window(now, 1);
            }
            return new Window(existing.startedAt, existing.count + 1);
        });
    }

    private boolean withinBudget(String key, int limit) {
        Window window = windows.get(key);
        if (window == null || window.startedAt + windowMs < System.currentTimeMillis()) {
            return true;
        }
        return window.count < limit;
    }

    private record Window(long startedAt, int count) {
    }
}
