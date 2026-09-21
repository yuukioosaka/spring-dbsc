package click.yukio.dbsc.core;

/**
 * Thrown for any DBSC verification or protocol failure. Carries the
 * {@link DbscErrorCode} so callers and telemetry can distinguish conditions.
 *
 * <p>This is an unchecked exception: DBSC failures are protocol-level control
 * flow, not programming errors, but every call site in this codebase handles it
 * explicitly at the web boundary.
 */
public class DbscException extends RuntimeException {

    private final DbscErrorCode code;

    public DbscException(DbscErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public DbscException(DbscErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public DbscErrorCode code() {
        return code;
    }

    public static DbscException missingResponseHeader(String message) {
        return new DbscException(DbscErrorCode.MISSING_RESPONSE_HEADER, message);
    }

    public static DbscException malformedJws(String message) {
        return new DbscException(DbscErrorCode.MALFORMED_JWS, message);
    }

    public static DbscException invalidJwk(String message) {
        return new DbscException(DbscErrorCode.INVALID_JWK, message);
    }

    public static DbscException unknownAlgorithm(String message) {
        return new DbscException(DbscErrorCode.UNKNOWN_ALGORITHM, message);
    }

    public static DbscException signatureInvalid(String message) {
        return new DbscException(DbscErrorCode.SIGNATURE_INVALID, message);
    }

    public static DbscException challengeNotFound() {
        return new DbscException(DbscErrorCode.CHALLENGE_NOT_FOUND, "challenge not found");
    }

    public static DbscException challengeExpired() {
        return new DbscException(DbscErrorCode.CHALLENGE_EXPIRED, "challenge expired");
    }

    public static DbscException challengeConsumed() {
        return new DbscException(DbscErrorCode.CHALLENGE_CONSUMED, "challenge already consumed");
    }

    public static DbscException jtiMismatch(String message) {
        return new DbscException(DbscErrorCode.JTI_MISMATCH, message);
    }

    /**
     * The request is missing a cookie or body field the protocol requires. This is
     * the one protocol failure that is not a 403.
     */
    public static DbscException badRequest(String message) {
        return new DbscException(DbscErrorCode.BAD_REQUEST, message);
    }
}
