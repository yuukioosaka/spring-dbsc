package click.yukio.dbsc.storage;

import click.yukio.dbsc.core.DeviceKey;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.RegistrationToken;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory storage for development and tests.
 *
 * <p>An in-memory store is acceptable <strong>only</strong> for development:
 * losing device keys across a restart breaks live sessions, because the browser
 * still holds a binding cookie, refresh fails with {@code KEY_NOT_FOUND},
 * and the browser loops registration. Use {@link JdbcStorageAdapter} for any
 * deployment that can restart.
 *
 * <p>The atomicity requirement is met with {@link ConcurrentHashMap#compute}:
 * the challenge row is read and marked consumed while holding the bin lock, so
 * exactly one concurrent caller observes {@code true}.
 */
public class InMemoryStorageAdapter implements StorageAdapter {

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Map<KeyId, DeviceKey> deviceKeys = new ConcurrentHashMap<>();
    private final Map<String, Challenge> challenges = new ConcurrentHashMap<>();
    private final Map<String, RegistrationToken> registrationTokens = new ConcurrentHashMap<>();

    @Override
    public Optional<Session> getSession(String id) {
        return Optional.ofNullable(sessions.get(id));
    }

    @Override
    public Optional<Session> getSessionByAppSessionId(String appSessionId) {
        return sessions.values().stream()
                .filter(session -> session.appSessionId().equals(appSessionId))
                .findFirst();
    }

    @Override
    public void setSession(Session session) {
        sessions.put(session.id(), session);
    }

    @Override
    public void deleteSession(String id) {
        sessions.remove(id);
        deviceKeys.keySet().removeIf(key -> key.sessionId().equals(id));
        challenges.values().removeIf(challenge -> challenge.sessionId().equals(id));
        registrationTokens.values().removeIf(token -> token.sessionId().equals(id));
    }

    @Override
    public Optional<DeviceKey> getDeviceKey(String sessionId) {
        return Optional.ofNullable(deviceKeys.get(new KeyId(sessionId)));
    }

    @Override
    public void setDeviceKey(DeviceKey key) {
        deviceKeys.put(new KeyId(key.sessionId()), key);
    }

    @Override
    public void deleteDeviceKey(String sessionId) {
        deviceKeys.remove(new KeyId(sessionId));
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
    public Optional<RegistrationToken> getRegistrationToken(String token) {
        return Optional.ofNullable(registrationTokens.get(token));
    }

    @Override
    public void setRegistrationToken(RegistrationToken token) {
        registrationTokens.put(token.token(), token);
    }

    @Override
    public boolean consumeRegistrationToken(String token) {
        boolean[] consumed = {false};
        registrationTokens.computeIfPresent(token, (key, existing) -> {
            if (existing.consumed()) {
                return existing;
            }
            consumed[0] = true;
            return new RegistrationToken(
                    existing.token(), existing.sessionId(), existing.createdAt(),
                    existing.expiresAt(), true);
        });
        return consumed[0];
    }

    @Override
    public void revokeSession(String sessionId) {
        // Keep the record: a later request carrying the same application session id
        // must still be recognisable as having had a binding.
        getSession(sessionId).ifPresent(session -> setSession(session.withRevoked(true)));
    }

    /** Package-visible for tests that assert cleanup behavior. */
    int challengeCount() {
        return challenges.size();
    }

    private record KeyId(String sessionId) {
    }
}
