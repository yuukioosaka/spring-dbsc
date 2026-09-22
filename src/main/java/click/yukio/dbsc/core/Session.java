package click.yukio.dbsc.core;

import java.util.Map;
import java.util.Objects;

/**
 * A session record. All timestamps are milliseconds since the Unix epoch;
 * {@code lastRefreshAt == 0} means "never refreshed".
 *
 * @param id            DBSC session identifier (independent of any application
 *                      session id)
 * @param appSessionId  the application's own session identifier this binding was
 *                      created for, used to spot a request that dropped its DBSC
 *                      cookies while a binding still exists
 * @param userId        authenticated user this session belongs to
 * @param tier          current binding strength
 * @param revoked       whether the binding was ended, e.g. by logout. The record is
 *                      kept so the binding can still be recognised as "was bound"
 * @param createdAt     creation time (ms)
 * @param expiresAt     expiry time (ms)
 * @param lastRefreshAt last successful registration/refresh (ms), 0 = never
 */
public record Session(
        String id,
        String appSessionId,
        String userId,
        ProtectionTier tier,
        boolean revoked,
        long createdAt,
        long expiresAt,
        long lastRefreshAt) {

    public Session {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(appSessionId, "appSessionId");
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(tier, "tier");
    }

    /**
     * Whether the session is registered but not currently proving protection.
     *
     * <p>A session that has never completed a registration or refresh has
     * {@code lastRefreshAt == 0}; that is the window between {@code bind()} and the
     * browser's registration POST, and it is not a demotion. A non-zero
     * {@code lastRefreshAt} with tier {@code none} is a demotion — the session
     * registered once and then stopped proving possession.
     */
    public boolean isDemoted() {
        return tier == ProtectionTier.NONE && lastRefreshAt > 0;
    }

    /** Whether the session was ended, e.g. by logout. */
    public boolean isRevoked() {
        return revoked;
    }

    public Session withTier(ProtectionTier newTier) {
        return new Session(id, appSessionId, userId, newTier, revoked, createdAt, expiresAt, lastRefreshAt);
    }

    public Session withLastRefreshAt(long timestamp) {
        return new Session(id, appSessionId, userId, tier, revoked, createdAt, expiresAt, timestamp);
    }

    public Session withTierAndLastRefreshAt(ProtectionTier newTier, long timestamp) {
        return new Session(id, appSessionId, userId, newTier, revoked, createdAt, expiresAt, timestamp);
    }

    public Session withRevoked(boolean newRevoked) {
        return new Session(id, appSessionId, userId, tier, newRevoked, createdAt, expiresAt, lastRefreshAt);
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
                "appSessionId", appSessionId,
                "userId", userId,
                "tier", tier.wireValue(),
                "revoked", revoked,
                "createdAt", createdAt,
                "expiresAt", expiresAt,
                "lastRefreshAt", lastRefreshAt);
    }
}
