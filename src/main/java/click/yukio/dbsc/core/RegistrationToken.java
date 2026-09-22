package click.yukio.dbsc.core;

import java.util.Objects;

/**
 * A single-use token naming the session a registration POST belongs to.
 *
 * <p>It is carried in the registration path ({@code /dbsc/regist/<token>}) rather
 * than in a cookie, which is what makes registration work behind a cross-site
 * callback: the browser's registration POST is issued by Chromium from the
 * identity provider's navigation context, where a {@code SameSite=Lax} cookie is
 * withheld. A path segment has no such problem.
 *
 * <p>The token is <strong>not</strong> the session id and must never be used as
 * one. It is a lookup key with a short life whose only power is "this POST names
 * this session"; possessing it grants nothing beyond the ability to attempt a
 * registration, which still has to satisfy the challenge and the JWS.
 *
 * @param token     the 43-character base64url value (also its lookup key)
 * @param sessionId the DBSC session this token was issued for
 * @param createdAt issuance time (ms)
 * @param expiresAt expiry time (ms)
 * @param consumed  whether a registration has already used it
 */
public record RegistrationToken(
        String token,
        String sessionId,
        long createdAt,
        long expiresAt,
        boolean consumed) {

    public RegistrationToken {
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(sessionId, "sessionId");
    }

    public boolean isExpired(long nowMs) {
        return nowMs > expiresAt;
    }
}
