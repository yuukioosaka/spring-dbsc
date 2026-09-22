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

    /**
     * The session bound to an application session id, if any.
     *
     * <p>This is what lets a guarded route tell a browser that never registered
     * apart from one that registered and then dropped its DBSC cookies: the
     * application's own session id is the one identifier a request cannot omit.
     * At most one record exists per application session id.
     */
    Optional<Session> getSessionByAppSessionId(String appSessionId);

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

    // ---- Registration tokens ----

    /**
     * Look up the registration token a registration POST presented in its path.
     */
    Optional<RegistrationToken> getRegistrationToken(String token);

    void setRegistrationToken(RegistrationToken token);

    /**
     * Atomically mark the token consumed and report whether <em>this</em> call was
     * the one that consumed it.
     *
     * <p>Returns {@code true} if the token was unconsumed and this call consumed
     * it; {@code false} if it was already consumed or does not exist.
     *
     * <p>Same rule as {@link #consumeChallenge}: this MUST NOT be a read followed
     * by a separate write. The token is single-use precisely so that a registration
     * POST captured from a log or a proxy cannot be replayed into a second binding.
     */
    boolean consumeRegistrationToken(String token);

    // ---- Revocation ----

    /**
     * Ends one session's binding, called on logout. The record is kept and marked
     * revoked rather than deleted, so a later request that presents the same
     * application session id without its DBSC cookies can still be recognised as
     * having had a binding.
     */
    void revokeSession(String sessionId);
}
