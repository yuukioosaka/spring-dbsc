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
    KEY_NOT_FOUND_NATIVE,
    KEY_NOT_FOUND_BOUND,
    /** Legacy, kind-agnostic code retained for back-compat. */
    KEY_NOT_FOUND,
    SESSION_NOT_FOUND,
    /** No session record for the cookie, so nothing has been registered yet. */
    SESSION_NOT_REGISTERED,
    SESSION_ALREADY_REGISTERED,
    RATE_LIMITED,
    MISSING_PROOF,
    MALFORMED_PROOF,
    PROOF_REPLAY,

    /**
     * A structurally incomplete request: a missing bound-protocol cookie or body
     * field. Spec 08 maps this to 400 rather than 403, because it is a client bug
     * and not a rejected proof.
     */
    BAD_REQUEST;

    /** Codes that indicate a proof/signature problem rather than a protocol misuse. */
    private static final List<DbscErrorCode> SECURITY_RELEVANT = List.of(
            SIGNATURE_INVALID, MALFORMED_JWS, INVALID_JWK, JTI_MISMATCH,
            PROOF_REPLAY, MALFORMED_PROOF);

    public boolean isSecurityRelevant() {
        return SECURITY_RELEVANT.contains(this);
    }
}
