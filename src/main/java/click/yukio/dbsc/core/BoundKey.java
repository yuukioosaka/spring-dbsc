package click.yukio.dbsc.core;

import java.util.Map;
import java.util.Objects;

/**
 * A registered public key. The pair {@code (sessionId, kind)} is its identity,
 * so a session may hold at most one {@code native} and one {@code bound} key.
 *
 * @param sessionId the session this key binds
 * @param kind      {@code native} (hardware key) or {@code bound} (polyfill key)
 * @param jwk       the public key as a JWK map. Never logged.
 * @param algorithm {@code ES256} or {@code RS256}
 * @param createdAt registration time (ms)
 */
public record BoundKey(
        String sessionId,
        BoundKeyKind kind,
        Map<String, Object> jwk,
        String algorithm,
        long createdAt) {

    public BoundKey {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(jwk, "jwk");
        Objects.requireNonNull(algorithm, "algorithm");
        jwk = Map.copyOf(jwk);
    }

    /**
     * Redacts key material so a {@code BoundKey} can be logged safely.
     */
    @Override
    public String toString() {
        return "BoundKey[sessionId=" + sessionId
                + ", kind=" + kind.wireValue()
                + ", algorithm=" + algorithm
                + ", jwk=<redacted>"
                + ", createdAt=" + createdAt + "]";
    }
}
