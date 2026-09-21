package click.yukio.dbsc.core;

import java.util.Optional;

/**
 * Logical persistence contract for DBSC (toolkit spec 06). Backed by whatever a
 * platform offers, as long as the semantics below hold — in particular the
 * <strong>atomic challenge consume</strong>.
 *
 * <p>Implementations must be durable for any deployment that can restart: an
 * in-memory store breaks live sessions across a restart (the browser still holds
 * a binding cookie, refresh fails with {@code KEY_NOT_FOUND}, and the
 * browser loops registration).
 */
public interface StorageAdapter {

    // ---- Sessions ----

    Optional<Session> getSession(String id);

    /** Create or replace. */
    void setSession(Session session);

    void deleteSession(String id);

    // ---- Bound keys ----

    /**
     * Read the session's registered key, if it has one.
     */
    Optional<DeviceKey> getDeviceKey(String sessionId);

    /** Create or replace, keyed by {@code sessionId}. */
    void setDeviceKey(DeviceKey key);

    /** Delete the session's key. */
    void deleteDeviceKey(String sessionId);

    // ---- Challenges ----

    Optional<Challenge> getChallenge(String jti);

    void setChallenge(Challenge challenge);

    /**
     * Atomically mark the challenge consumed and report whether <em>this</em>
     * call was the one that consumed it.
     *
     * <p>Returns {@code true} if the challenge was unconsumed and this call
     * consumed it; {@code false} if it was already consumed or does not exist.
     *
     * <p>This MUST NOT be implemented as a read followed by a separate write. Two
     * concurrent refresh attempts for the same challenge MUST result in exactly
     * one {@code true}; a non-atomic implementation is a replay vulnerability.
     */
    boolean consumeChallenge(String jti);

    // ---- Revocation ----

    /** Invalidate one session's binding. Called on logout. */
    void revokeSession(String sessionId);
}
