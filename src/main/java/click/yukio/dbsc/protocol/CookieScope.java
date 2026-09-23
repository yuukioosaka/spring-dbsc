package click.yukio.dbsc.protocol;

import java.util.ArrayList;
import java.util.List;

/**
 * Names and attributes for the DBSC credential cookie (spec 07).
 *
 * <p>One cookie remains: the credential cookie that carries the rotating ticket and
 * is the cookie the protocol protects. The pre-registration cookie is gone — the
 * registration route is identified by a single-use token in its <em>path</em> — and
 * so is the challenge cookie: the challenge is held server-side against the session,
 * and travels to the browser only as the JTI inside the {@code Secure-Session-Challenge}
 * header it signs (spec §8.7, §9.2). Nothing about the challenge depends on a cookie
 * surviving the cross-site registration POST.
 *
 * <p>Note that the credential cookie is {@code SameSite=Lax} by default: it is a
 * long-lived credential that should never travel cross-site. That is configurable
 * ({@code dbsc.cookie-same-site}) because a deployment may have a reason, but the other
 * two values each cost something specific — {@link SameSite#STRICT} breaks a login that
 * returns from another site, {@link SameSite#NONE} needs {@code Secure} and hands the
 * credential to cross-site callers. With {@code secure=false} (plain-HTTP development
 * only) the {@code __Host-}/{@code __Secure-} prefixes are dropped, which is correct
 * there because a plain-HTTP origin cannot carry them.
 *
 * <p>Cookie names are <strong>never hardcoded</strong>: the credential name is derived
 * from configuration, so the name written into the JSON config's
 * {@code credentials[].name} always matches the cookie actually set.
 */
public final class CookieScope {

    /** Used when no credential cookie name is configured. */
    public static final String DEFAULT_CREDENTIAL_COOKIE = "__Host-auth_cookie";

    /** The {@code Path} attribute used when none is configured. */
    public static final String DEFAULT_PATH = "/";

    /** How widely the binding cookie is shared. */
    public enum Scope {
        /** {@code __Host-} cookies: origin-locked, no {@code Domain}. Strongest. */
        HOST,
        /** {@code __Secure-} cookies carrying {@code Domain=<cookieDomain>}. */
        SITE
    }

    /**
     * The {@code SameSite} attribute written on the credential cookie, and echoed in
     * {@code credentials[].attributes}.
     */
    public enum SameSite {

        /**
         * The default, and the right answer for almost every deployment.
         *
         * <p>The cookie rides along on top-level navigations into the site but not on
         * cross-site subrequests, which is exactly the credential's job: it has to
         * survive the redirect back from an identity provider, and it has no business
         * being attached to a third party's {@code fetch}.
         */
        LAX("Lax"),

        /**
         * Strictest: the cookie is not sent on any cross-site request, including
         * top-level navigation.
         *
         * <p>Worth choosing only when the login flow never lands on a DBSC route
         * directly from another site. It breaks the OIDC/SAML callback case that the
         * token-in-path registration route exists to survive: the callback arrives
         * cross-site, so a {@code Strict} session cookie is withheld and the
         * application sees an unauthenticated request. The registration POST itself is
         * unaffected — it is named by a token in its path — but the application session
         * behind it is not.
         */
        STRICT("Strict"),

        /**
         * Sent on every request, cross-site included. Requires {@code Secure}.
         *
         * <p>Choose this only when the site is embedded or called cross-origin in a way
         * that must carry the credential — which is the situation DBSC's threat model
         * otherwise avoids. It hands the credential to any cross-site caller the browser
         * decides to attach it to, and softens the protection that the default
         * {@code Lax} provides. Validation rejects it without {@code Secure}.
         */
        NONE("None");

        private final String wireValue;

        SameSite(String wireValue) {
            this.wireValue = wireValue;
        }

        /** The value as it appears in a {@code Set-Cookie} header. */
        public String wireValue() {
            return wireValue;
        }
    }

    private final boolean secure;
    private final Scope scope;
    private final String domain;
    private final String credentialCookieName;
    private final SameSite sameSite;
    private final String path;
    private final boolean httpOnly;

    private CookieScope(boolean secure, Scope scope, String domain, String credentialCookieName,
                        SameSite sameSite, String path, boolean httpOnly) {
        this.secure = secure;
        this.scope = scope;
        this.domain = domain;
        this.credentialCookieName = credentialCookieName;
        this.sameSite = sameSite;
        this.path = path;
        this.httpOnly = httpOnly;
    }

    /**
     * Resolves and validates a cookie-scope configuration.
     *
     * @throws IllegalArgumentException when site scope is requested without a
     *         domain, when site scope is requested without {@code Secure}, when
     *         the domain carries a leading dot, or when a domain is supplied
     *         outside site scope
     */
    public static CookieScope resolve(boolean secure, Scope scope, String domain) {
        return resolve(secure, scope, domain, null);
    }

    /**
     * Resolves and validates a cookie-scope configuration.
     *
     * @param credentialCookieName the cookie named in {@code credentials[]} and
     *         protected by the binding. Used verbatim — a prefix is the deployer's
     *         choice, not something added here. When blank, the default
     *         {@link #DEFAULT_CREDENTIAL_COOKIE} is used
     * @throws IllegalArgumentException when site scope is requested without a
     *         domain, when site scope is requested without {@code Secure}, when
     *         the domain carries a leading dot, or when a domain is supplied
     *         outside site scope
     */
    public static CookieScope resolve(
            boolean secure, Scope scope, String domain, String credentialCookieName) {
        return resolve(secure, scope, domain, credentialCookieName, null);
    }

    /**
     * Resolves and validates a cookie-scope configuration, with every attribute at its
     * default (see {@link #resolve(boolean, Scope, String, String, SameSite, String, Boolean)}).
     */
    public static CookieScope resolve(
            boolean secure, Scope scope, String domain, String credentialCookieName,
            SameSite sameSite) {
        return resolve(secure, scope, domain, credentialCookieName, sameSite, null, null);
    }

    /**
     * Resolves and validates a cookie-scope configuration.
     *
     * <p>Everything resolved here feeds {@link #attributesString()}, which is used for
     * <strong>both</strong> the real {@code Set-Cookie} header and the JSON config's
     * {@code credentials[].attributes} that Chromium compares against it. Values are
     * therefore validated rather than passed through: an attribute the browser rejects
     * or cannot match fails silently on the wire — the session simply never exists — so
     * the only place the mistake can be legible is startup.
     *
     * @param credentialCookieName the cookie named in {@code credentials[]} and
     *         protected by the binding. Used verbatim — a prefix is the deployer's
     *         choice, not something added here. When blank, the default
     *         {@link #DEFAULT_CREDENTIAL_COOKIE} is used
     * @param sameSite the {@code SameSite} value to write; {@code null} means
     *         {@link SameSite#LAX}
     * @param path the {@code Path} attribute; {@code null} or blank means {@code /}. Must
     *         start with {@code /}: this string is compared against the real header, and a
     *         value the browser rewrites (a relative path, a trailing slash it normalises)
     *         would match nothing
     * @param httpOnly the {@code HttpOnly} flag; {@code null} means {@code true}. Turning it
     *         off exposes the credential to page script, which is what {@code HttpOnly}
     *         exists to prevent, so it is only right for a client that genuinely cannot use
     *         a cookie jar — and note Soft DBSC does not need it, because a worker never
     *         reads the cookie either
     * @throws IllegalArgumentException when site scope is requested without a domain, when
     *         site scope is requested without {@code Secure}, when the domain carries a
     *         leading dot, when a domain is supplied outside site scope, when
     *         {@code SameSite=None} is requested without {@code Secure}, or when the path
     *         is not absolute
     */
    public static CookieScope resolve(
            boolean secure, Scope scope, String domain, String credentialCookieName,
            SameSite sameSite, String path, Boolean httpOnly) {
        String credentialName = credentialCookieName == null || credentialCookieName.isBlank()
                ? DEFAULT_CREDENTIAL_COOKIE
                : credentialCookieName;
        Scope resolved = scope == null ? Scope.HOST : scope;
        SameSite resolvedSameSite = sameSite == null ? SameSite.LAX : sameSite;
        String resolvedPath = path == null || path.isBlank() ? DEFAULT_PATH : path;
        boolean resolvedHttpOnly = httpOnly == null || httpOnly;

        // An empty Path= is not a path: the browser defaults it to the directory of the
        // response, so nothing predictable is compared and the binding never completes.
        if (!resolvedPath.startsWith("/")) {
            throw new IllegalArgumentException(
                    "cookiePath must be absolute: use \"/\", not \"" + resolvedPath + "\"");
        }
        // SameSite=None without Secure is rejected by every browser, so the cookie
        // would simply never be stored -- a failure that shows up as "DBSC does not
        // work" rather than as a validation error. Same reasoning as the __Secure-
        // check below: catch it at startup, where it is legible.
        if (resolvedSameSite == SameSite.NONE && !secure) {
            throw new IllegalArgumentException(
                    "sameSite \"None\" requires secure=true: browsers reject a SameSite=None "
                            + "cookie that is not also Secure, so the credential would never be stored");
        }
        if (resolved == Scope.SITE) {
            if (domain == null || domain.isBlank()) {
                throw new IllegalArgumentException(
                        "cookieScope \"site\" requires a cookieDomain: set it to the registrable apex "
                                + "(e.g. \"example.com\") so the binding cookie is shared across subdomains");
            }
            if (!secure) {
                throw new IllegalArgumentException(
                        "cookieScope \"site\" requires secure=true: the __Secure- prefix is rejected "
                                + "by browsers without the Secure flag");
            }
            if (domain.startsWith(".")) {
                throw new IllegalArgumentException(
                        "cookieDomain must not start with a leading dot: use \"example.com\", not \"." + domain.substring(1) + "\"");
            }
            return new CookieScope(true, Scope.SITE, domain, credentialName, resolvedSameSite,
                    resolvedPath, resolvedHttpOnly);
        }
        if (domain != null && !domain.isBlank()) {
            throw new IllegalArgumentException(
                    "cookieDomain is only valid when cookieScope is \"site\"");
        }
        return new CookieScope(secure, Scope.HOST, null, credentialName, resolvedSameSite,
                resolvedPath, resolvedHttpOnly);
    }

    public boolean secure() {
        return secure;
    }

    public Scope scope() {
        return scope;
    }

    public String domain() {
        return domain;
    }

    /**
     * {@code __Host-}, {@code __Secure-}, or empty for insecure development.
     */
    public String prefix() {
        if (scope == Scope.SITE) {
            return "__Secure-";
        }
        return secure ? "__Host-" : "";
    }

    /**
     * The cookie named in the JSON config's {@code credentials[]}, whose value is the
     * rotating ticket (spec §9.6).
     *
     * <p>Returned verbatim from configuration — no prefix is added, because whether
     * the name carries {@code __Host-} is the deployer's decision. The attributes it
     * is written with are {@link #attributesString()}, which is also what the JSON
     * config echoes, so the two cannot drift.
     */
    public String credentialCookieName() {
        return credentialCookieName;
    }

    /**
     * The {@code SameSite} attribute written on the credential cookie.
     *
     * <p>{@link SameSite#LAX} unless configured otherwise. See the enum for what each
     * value costs: {@code Strict} breaks a cross-site login callback, {@code None}
     * requires {@code Secure} and weakens the default protection.
     */
    public SameSite sameSite() {
        return sameSite;
    }

    /**
     * The {@code Path} attribute written on the credential cookie.
     *
     * <p>{@link #DEFAULT_PATH} unless configured otherwise. Narrowing it to e.g.
     * {@code /app} is legitimate, but note that the route carrying the offer has to be
     * under it: a binding cookie the registration POST cannot send is a session that
     * never registers.
     */
    public String path() {
        return path;
    }

    /**
     * Whether the credential cookie carries {@code HttpOnly}.
     *
     * <p>True unless configured otherwise. {@code false} is a real reduction — the
     * credential becomes readable by page script, which is the XSS surface
     * {@code HttpOnly} exists to close.
     */
    public boolean httpOnly() {
        return httpOnly;
    }

    /**
     * The attributes string echoed back in the registration response's
     * {@code credentials[].attributes} field, which Chromium compares against the
     * protected cookie's real attributes.
     *
     * <p>It carries exactly the five attributes {@code §8.6} matches on — Domain,
     * Path, Secure, HttpOnly, SameSite — and no others. {@code Max-Age} in particular
     * MUST NOT appear here: Chromium parses this string as a cookie attribute list,
     * where {@code Max-Age} is not permitted, and answers the registration with
     * "cookie attribute not permitted". Segments are joined by {@code "; "} and site
     * scope appends {@code Domain=} without a leading dot.
     *
     * <p>{@code SameSite} comes from {@link #sameSite()}, and it is the single source
     * for both this string and the real {@code Set-Cookie} header — which is the point:
     * §8.6 compares the two, so a value written in one place and not the other would be
     * silently discarded by the browser rather than reported.
     */
    public String attributesString() {
        List<String> parts = new ArrayList<>(List.of(
                "Path=" + path, "Secure"));
        if (httpOnly) {
            parts.add("HttpOnly");
        }
        parts.add("SameSite=" + sameSite.wireValue());
        if (domain != null) {
            parts.add("Domain=" + domain);
        }
        return String.join("; ", parts);
    }

    /**
     * Converts a millisecond lifetime to the seconds {@code Max-Age} takes. A
     * positive lifetime never rounds down to zero, which would delete the cookie
     * instead of shortening it.
     */
    private static long maxAgeSeconds(long maxAgeMs) {
        return maxAgeMs <= 0 ? 0 : Math.max(1, maxAgeMs / 1000);
    }

    /**
     * Renders a full {@code Set-Cookie} value: {@code name=value; <attributes>;
     * Max-Age=<seconds>}.
     *
     * <p>The attribute prefix is the same {@link #attributesString()} that fills
     * {@code credentials[].attributes}, minus the {@code Max-Age} that only the real
     * header may carry.
     */
    public String setCookieValue(String name, String value, long maxAgeMs) {
        return name + "=" + value + "; " + attributesString()
                + "; Max-Age=" + maxAgeSeconds(maxAgeMs);
    }

    /**
     * Renders a {@code Set-Cookie} value that deletes the named cookie. The deletion
     * carries {@code Max-Age=0}, so the attribute list here intentionally omits the
     * lifetime only the header carries.
     */
    public String deleteCookieValue(String name) {
        return name + "=; " + attributesString() + "; Max-Age=0";
    }
}
