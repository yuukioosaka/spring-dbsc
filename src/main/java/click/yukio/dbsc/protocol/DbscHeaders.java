package click.yukio.dbsc.protocol;

/**
 * The DBSC header names, current and legacy (spec 02).
 *
 * <p>Inbound matching MUST be case-insensitive. Spring's {@code HttpHeaders} is
 * already case-insensitive, and this class centralises the reads so no call site
 * has to remember the fallback to the legacy names.
 */
public final class DbscHeaders {

    // Server -> browser
    public static final String REGISTRATION = "Secure-Session-Registration";
    public static final String CHALLENGE = "Secure-Session-Challenge";

    // Browser -> server
    public static final String RESPONSE = "Secure-Session-Response";
    public static final String SESSION_ID = "Sec-Secure-Session-Id";
    public static final String SKIPPED = "Secure-Session-Skipped";

    /**
     * The session identifier as a JavaScript client sends it.
     *
     * <p>Functionally this duplicates {@link #SESSION_ID}: both name a session on the
     * refresh route and both are read there. It exists because a script cannot rely on
     * the {@code Sec-} prefixed name. That prefix is reserved by RFC 6648 for
     * protocol-defined headers rather than for application ones, and it is outside the
     * CORS safelist, so a fetch that carries it is preflighted and the name has to be
     * named in {@code Access-Control-Allow-Headers} by every deployment. A plain
     * {@code X-} name carries the same value with none of that, which is what a client
     * this library does not control needs.
     *
     * <p>Read <strong>before</strong> {@link #SESSION_ID} so a client sending both is
     * resolved by the name it chose, but neither is preferred over the other in any
     * way that affects the outcome: an unknown or malformed value fails the same lookup
     * from either name.
     */
    public static final String JS_SESSION_ID = "X-Session-Id";

    // Legacy outbound aliases, emitted alongside the current names
    public static final String LEGACY_REGISTRATION = "Sec-Session-Registration";
    public static final String LEGACY_CHALLENGE = "Sec-Session-Challenge";

    // Legacy inbound aliases, MUST be accepted
    public static final String LEGACY_RESPONSE = "Sec-Session-Response";
    public static final String LEGACY_SKIPPED = "Sec-Session-Skipped";
    public static final String LEGACY_SESSION_ID = "Sec-Session-Id";

    /** Server clock hint. */
    public static final String SERVER_TIME = "X-Server-Time";

    private DbscHeaders() {
    }
}
