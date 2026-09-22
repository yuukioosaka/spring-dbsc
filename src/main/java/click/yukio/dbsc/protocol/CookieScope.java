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
    public static final String BINDING_SUFFIX = "dbsc-session";

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

    private CookieScope(boolean secure, Scope scope, String domain) {
        this.secure = secure;
        this.scope = scope;
        this.domain = domain;
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
            return new CookieScope(true, Scope.SITE, domain);
        }
        if (domain != null && !domain.isBlank()) {
            throw new IllegalArgumentException(
                    "cookieDomain is only valid when cookieScope is \"site\"");
        }
        return new CookieScope(secure, Scope.HOST, null);
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

    public String bindingCookieName() {
        return prefix() + BINDING_SUFFIX;
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
     * {@code credentials[].attributes} field, which Chromium re-reads to know how
     * to re-issue the binding cookie on refresh.
     *
     * <p>This MUST match what the server actually sets in {@code Set-Cookie},
     * byte for byte, or Chromium drops the binding. Segments are joined by
     * {@code "; "}, the order is fixed, and site scope appends {@code Domain=}
     * without a leading dot.
     */
    public String attributesString() {
        List<String> parts = new ArrayList<>(List.of("Path=/", "Secure", "HttpOnly", "SameSite=Lax"));
        if (domain != null) {
            parts.add("Domain=" + domain);
        }
        return String.join("; ", parts);
    }

    /**
     * Renders a full {@code Set-Cookie} value: {@code name=value; <attributes>;
     * Max-Age=<seconds>}.
     *
     * <p>{@code maxAgeMs} is converted to seconds here — the one place the unit
     * change happens — and a non-positive value emits {@code Max-Age=0}, the
     * standard way to delete a cookie.
     */
    public String setCookieValue(String name, String value, long maxAgeMs) {
        String attributes = attributesString();
        long seconds = maxAgeMs <= 0 ? 0 : Math.max(1, maxAgeMs / 1000);
        return name + "=" + value + "; " + attributes + "; Max-Age=" + seconds;
    }

    /**
     * Renders the challenge cookie's {@code Set-Cookie} value. See
     * {@link #challengeAttributesString()} for why it departs from the binding
     * cookie's attributes.
     */
    public String setChallengeCookieValue(String name, String value, long maxAgeMs) {
        long seconds = maxAgeMs <= 0 ? 0 : Math.max(1, maxAgeMs / 1000);
        return name + "=" + value + "; " + challengeAttributesString() + "; Max-Age=" + seconds;
    }

    /** Renders a {@code Set-Cookie} value that deletes the challenge cookie. */
    public String deleteChallengeCookieValue(String name) {
        return name + "=; " + challengeAttributesString() + "; Max-Age=0";
    }

    /** Renders a {@code Set-Cookie} value that deletes the named cookie. */
    public String deleteCookieValue(String name) {
        return name + "=; " + attributesString() + "; Max-Age=0";
    }
}
