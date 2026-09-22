package click.yukio.dbsc.protocol;

import java.util.ArrayList;
import java.util.List;

/**
 * Names and attributes for the DBSC cookies (spec 07).
 *
 * <p>Two cookies remain: the binding cookie that names the session, and the
 * challenge cookie carrying the single-use JTI. The pre-registration cookie
 * ({@code dbsc-reg}) is gone — the registration route is identified by a
 * single-use token in its <em>path</em> instead.
 *
 * <p>That token removes the need for a session cookie on the registration POST,
 * but the challenge cookie is still needed to know which JTI was signed, so it is
 * the one cookie that must survive a cross-site request. It is therefore
 * {@code SameSite=None} while the binding cookie stays {@code Lax}: the binding
 * cookie is a long-lived credential that should never travel cross-site, whereas
 * the challenge is a short-lived, single-use nonce that is worthless to an
 * attacker who cannot also sign with the device key.
 *
 * <p>Note that {@code SameSite=None} requires {@code Secure} on every browser
 * that supports it. With {@code secure=false} (plain-HTTP development only) the
 * challenge cookie keeps {@code Lax}, which is correct there because a
 * plain-HTTP origin can never be cross-site for a production callback.
 *
 * <p>Cookie names are <strong>never hardcoded</strong>: they are derived from the
 * secure flag and the cookie scope, so the name written into the JSON config's
 * {@code credentials[].name} always matches the cookie actually set.
 */
public final class CookieScope {

    public static final String CHALLENGE_SUFFIX = "dbsc-challenge";

    /** Used when no credential cookie name is configured. */
    public static final String DEFAULT_CREDENTIAL_COOKIE = "__Host-auth_cookie";

    /**
     * The default {@code session_identifier}, taken verbatim from the spec's own
     * config key name: this library keys its session store server-side and never
     * sets a cookie under it, so a name that looks like a cookie would only
     * advertise something that does not exist.
     */
    public static final String DEFAULT_SESSION_IDENTIFIER = "session_identifier";

    /** How widely the binding cookie is shared. */
    public enum Scope {
        /** {@code __Host-} cookies: origin-locked, no {@code Domain}. Strongest. */
        HOST,
        /** {@code __Secure-} cookies carrying {@code Domain=<cookieDomain>}. */
        SITE
    }

    private final boolean secure;
    private final Scope scope;
    private final String domain;
    private final String credentialCookieName;

    private CookieScope(boolean secure, Scope scope, String domain, String credentialCookieName) {
        this.secure = secure;
        this.scope = scope;
        this.domain = domain;
        this.credentialCookieName = credentialCookieName;
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
        String credentialName = credentialCookieName == null || credentialCookieName.isBlank()
                ? DEFAULT_CREDENTIAL_COOKIE
                : credentialCookieName;
        Scope resolved = scope == null ? Scope.HOST : scope;
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
            return new CookieScope(true, Scope.SITE, domain, credentialName);
        }
        if (domain != null && !domain.isBlank()) {
            throw new IllegalArgumentException(
                    "cookieDomain is only valid when cookieScope is \"site\"");
        }
        return new CookieScope(secure, Scope.HOST, null, credentialName);
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
     * The challenge cookie's {@code SameSite} policy: {@code None} when Secure
     * cookies are usable, {@code Lax} otherwise.
     *
     * <p>The challenge must reach the server on a cross-site registration POST —
     * that is the whole reason the registration token lives in the URL — so it
     * cannot be {@code Lax}. {@code None} is only honoured alongside
     * {@code Secure}, hence the fallback.
     */
    public String challengeSameSite() {
        return secure ? "None" : "Lax";
    }

    /**
     * The value written into the JSON config's {@code session_identifier}: the literal
     * string {@code session_identifier} (spec §9.6).
     *
     * <p>This is a key into the browser's session store, <strong>not a cookie</strong> this
     * server reads or writes, which is why it is fixed and never derived from a cookie
     * name. Chromium keys the session's key and state by this string; the session id
     * itself is supplied to {@code bind()} and stays server-side, and the only cookie
     * that travels is the credential one named in {@code credentials[]}, whose value
     * rotates on every refresh.
     */
    public String sessionIdentifierName() {
        return DEFAULT_SESSION_IDENTIFIER;
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

    public String challengeCookieName() {
        return prefix() + CHALLENGE_SUFFIX;
    }

    /**
     * The challenge cookie's attributes, which differ from the binding cookie's
     * only in {@code SameSite}.
     *
     * <p>Unlike the binding cookie, this string is not echoed to the browser in
     * the JSON config — Chromium re-issues only the binding cookie — so it is free
     * to differ without breaking the byte-for-byte requirement.
     */
    public String challengeAttributesString() {
        return attributesString().replace("SameSite=Lax", "SameSite=" + challengeSameSite());
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
     */
    public String attributesString() {
        List<String> parts = new ArrayList<>(List.of("Path=/", "Secure", "HttpOnly", "SameSite=Lax"));
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
     * Renders the challenge cookie's {@code Set-Cookie} value. See
     * {@link #challengeAttributesString()} for why it departs from the binding
     * cookie's attributes.
     */
    public String setChallengeCookieValue(String name, String value, long maxAgeMs) {
        return name + "=" + value + "; " + challengeAttributesString()
                + "; Max-Age=" + maxAgeSeconds(maxAgeMs);
    }

    /** Renders a {@code Set-Cookie} value that deletes the challenge cookie. */
    public String deleteChallengeCookieValue(String name) {
        return name + "=; " + challengeAttributesString() + "; Max-Age=0";
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
