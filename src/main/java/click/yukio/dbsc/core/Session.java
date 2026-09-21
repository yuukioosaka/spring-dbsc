package click.yukio.dbsc.core;

import java.util.Map;
import java.util.Objects;

/**
 * A session record. All timestamps are milliseconds since the Unix epoch;
 * {@code lastRefreshAt == 0} means "never refreshed".
 *
 * @param id            session identifier
 * @param userId        authenticated user this session belongs to
 * @param tier          current binding strength
 * @param createdAt     creation time (ms)
 * @param expiresAt     expiry time (ms)
 * @param lastRefreshAt last successful registration/refresh (ms), 0 = never
 */
public record Session(
        String id,
        String userId,
        ProtectionTier tier,
        long createdAt,
        long expiresAt,
        long lastRefreshAt) {

    public Session {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(tier, "tier");
    }

    public Session withTier(ProtectionTier newTier) {
        return new Session(id, userId, newTier, createdAt, expiresAt, lastRefreshAt);
    }

    public Session withLastRefreshAt(long timestamp) {
        return new Session(id, userId, tier, createdAt, expiresAt, timestamp);
    }

    public Session withTierAndLastRefreshAt(ProtectionTier newTier, long timestamp) {
        return new Session(id, userId, newTier, createdAt, expiresAt, timestamp);
    }

    public boolean isExpired(long nowMs) {
        return nowMs > expiresAt;
    }

    /**
     * Retention deadline used by storage adapters for lazy cleanup.
     */
    public long retentionDeadlineMs() {
        return Math.max(expiresAt, lastRefreshAt);
    }

    /** The session id, exposed under the toolkit's field name. */
    public Map<String, Object> toDebugMap() {
        return Map.of(
                "id", id,
                "userId", userId,
                "tier", tier.wireValue(),
                "createdAt", createdAt,
                "expiresAt", expiresAt,
                "lastRefreshAt", lastRefreshAt);
    }
}
