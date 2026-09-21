package click.yukio.dbsc.core;

import java.util.Objects;

/**
 * A single-use nonce issued for a registration or refresh.
 *
 * @param jti       the 43-character base64url nonce (also its lookup key)
 * @param sessionId the session this challenge was issued for
 * @param createdAt issuance time (ms)
 * @param expiresAt expiry time (ms); default issue + 5 minutes
 * @param consumed  whether it has been used
 */
public record Challenge(
        String jti,
        String sessionId,
        long createdAt,
        long expiresAt,
        boolean consumed) {

    public Challenge {
        Objects.requireNonNull(jti, "jti");
        Objects.requireNonNull(sessionId, "sessionId");
    }

    public boolean isExpired(long nowMs) {
        return nowMs > expiresAt;
    }
}
