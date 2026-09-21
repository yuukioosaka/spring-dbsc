package click.yukio.dbsc.core;

import java.util.Map;
import java.util.Objects;

/**
 * A registered hardware key. Its identity is the {@code sessionId}, so a session
 * holds at most one key: re-registering replaces it.
 *
 * @param sessionId the session this key binds
 * @param jwk       the public key as a JWK map. Never logged.
 * @param algorithm {@code ES256} or {@code RS256}
 * @param createdAt registration time (ms)
 */
public record DeviceKey(
        String sessionId,
        Map<String, Object> jwk,
        String algorithm,
        long createdAt) {

    public DeviceKey {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(jwk, "jwk");
        Objects.requireNonNull(algorithm, "algorithm");
        jwk = Map.copyOf(jwk);
    }

    /**
     * Redacts key material so a {@code DeviceKey} can be logged safely.
     */
    @Override
    public String toString() {
        return "DeviceKey[sessionId=" + sessionId
                + ", algorithm=" + algorithm
                + ", jwk=<redacted>"
                + ", createdAt=" + createdAt + "]";
    }
}
