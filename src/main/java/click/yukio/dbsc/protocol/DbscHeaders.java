package click.yukio.dbsc.protocol;

/**
 * The DBSC header names, current and legacy (spec 02).
 *
 * <p>Inbound matching MUST be case-insensitive; Spring's {@code HttpHeaders} is
 * already case-insensitive, and {@link Http} centralizes the reads so no call
 * site has to remember the fallback to the legacy names.
 */
public final class DbscHeaders {

    // Server -> browser
    public static final String REGISTRATION = "Secure-Session-Registration";
    public static final String CHALLENGE = "Secure-Session-Challenge";

    // Browser -> server
    public static final String RESPONSE = "Secure-Session-Response";
    public static final String SESSION_ID = "Sec-Secure-Session-Id";
    public static final String SKIPPED = "Secure-Session-Skipped";

    // Legacy outbound aliases, emitted alongside the current names
    public static final String LEGACY_REGISTRATION = "Sec-Session-Registration";
    public static final String LEGACY_CHALLENGE = "Sec-Session-Challenge";

    // Legacy inbound aliases, MUST be accepted
    public static final String LEGACY_RESPONSE = "Sec-Session-Response";
    public static final String LEGACY_SKIPPED = "Sec-Session-Skipped";

    /** Per-request proof header (spec 04). */
    public static final String BOUND_PROOF = "X-Dbsc-Bound-Proof";

    /** Server clock hint on bound endpoints (spec 03). */
    public static final String SERVER_TIME = "X-Server-Time";

    private DbscHeaders() {
    }
}
