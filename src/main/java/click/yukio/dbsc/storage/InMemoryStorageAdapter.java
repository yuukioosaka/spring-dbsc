package click.yukio.dbsc.storage;

import click.yukio.dbsc.core.BoundKey;
import click.yukio.dbsc.core.BoundKeyKind;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory storage for development and tests.
 *
 * <p>An in-memory store is acceptable <strong>only</strong> for development:
 * losing bound keys across a restart breaks live sessions, because the browser
 * still holds a binding cookie, refresh fails with {@code KEY_NOT_FOUND_NATIVE},
 * and the browser loops registration. Use {@link JdbcStorageAdapter} for any
 * deployment that can restart.
 *
 * <p>The atomicity requirement is met with {@link ConcurrentHashMap#compute}:
 * the challenge row is read and marked consumed while holding the bin lock, so
 * exactly one concurrent caller observes {@code true}.
 */
public class InMemoryStorageAdapter implements StorageAdapter {

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Map<KeyId, BoundKey> boundKeys = new ConcurrentHashMap<>();
    private final Map<String, Challenge> challenges = new ConcurrentHashMap<>();

    @Override
    public Optional<Session> getSession(String id) {
        return Optional.ofNullable(sessions.get(id));
    }

    @Override
    public void setSession(Session session) {
        sessions.put(session.id(), session);
    }

    @Override
    public void deleteSession(String id) {
        sessions.remove(id);
        boundKeys.keySet().removeIf(key -> key.sessionId().equals(id));
        challenges.values().removeIf(challenge -> challenge.sessionId().equals(id));
    }

    @Override
    public Optional<BoundKey> getBoundKey(String sessionId, BoundKeyKind kind) {
        if (kind != null) {
            return Optional.ofNullable(boundKeys.get(new KeyId(sessionId, kind)));
        }
        Optional<BoundKey> nativeKey = getBoundKey(sessionId, BoundKeyKind.NATIVE);
        return nativeKey.isPresent() ? nativeKey : getBoundKey(sessionId, BoundKeyKind.BOUND);
    }

    @Override
    public void setBoundKey(BoundKey key) {
        boundKeys.put(new KeyId(key.sessionId(), key.kind()), key);
    }

    @Override
    public void deleteBoundKey(String sessionId, BoundKeyKind kind) {
        if (kind != null) {
            boundKeys.remove(new KeyId(sessionId, kind));
        } else {
            boundKeys.keySet().removeIf(key -> key.sessionId().equals(sessionId));
        }
    }

    @Override
    public Optional<Challenge> getChallenge(String jti) {
        return Optional.ofNullable(challenges.get(jti));
    }

    @Override
    public void setChallenge(Challenge challenge) {
        challenges.put(challenge.jti(), challenge);
    }

    @Override
    public boolean consumeChallenge(String jti) {
        boolean[] consumed = {false};
        challenges.computeIfPresent(jti, (key, existing) -> {
            if (existing.consumed()) {
                return existing;
            }
            consumed[0] = true;
            return new Challenge(
                    existing.jti(), existing.sessionId(), existing.createdAt(),
                    existing.expiresAt(), true);
        });
        return consumed[0];
    }

    @Override
    public void revokeSession(String sessionId) {
        deleteSession(sessionId);
    }

    /** Package-visible for tests that assert cleanup behavior. */
    int challengeCount() {
        return challenges.size();
    }

    private record KeyId(String sessionId, BoundKeyKind kind) {
    }
}
