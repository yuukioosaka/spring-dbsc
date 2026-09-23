package click.yukio.dbsc.core;

import java.util.List;

/**
 * The DBSC error code catalog (toolkit spec 08). These are the contract for
 * diagnostics and telemetry.
 */
public enum DbscErrorCode {
    MISSING_RESPONSE_HEADER,
    MALFORMED_JWS,
    INVALID_JWK,
    UNKNOWN_ALGORITHM,
    CHALLENGE_NOT_FOUND,
    CHALLENGE_EXPIRED,
    CHALLENGE_CONSUMED,
    JTI_MISMATCH,
    SIGNATURE_INVALID,
    KEY_NOT_FOUND,
    SESSION_NOT_FOUND,
    SESSION_ALREADY_REGISTERED,

    /**
     * The registration path carried a token that has already been used. Separate
     * from {@link #SESSION_NOT_FOUND} because the two mean very different things: an
     * unknown token is a path that was never ours, while a consumed one is a
     * captured registration POST being replayed.
     */
    REGISTRATION_TOKEN_CONSUMED,

    /** The registration token's TTL passed before the browser registered. */
    REGISTRATION_TOKEN_EXPIRED,

    /**
     * A structurally incomplete request: a missing cookie or body field. Spec 08
     * maps this to 400 rather than 403, because it is a client bug and not a
     * rejected signature.
     */
    BAD_REQUEST;

    /** Codes that indicate a signature problem rather than a protocol misuse. */
    private static final List<DbscErrorCode> SECURITY_RELEVANT = List.of(
            SIGNATURE_INVALID, MALFORMED_JWS, INVALID_JWK, JTI_MISMATCH);

    public boolean isSecurityRelevant() {
        return SECURITY_RELEVANT.contains(this);
    }
}
