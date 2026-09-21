package click.yukio.dbsc.protocol;

import java.util.ArrayList;
import java.util.List;

/**
 * Names and attributes for the three DBSC cookies (spec 07).
 *
 * <p>Cookie names are <strong>never hardcoded</strong>: they are derived from the
 * secure flag and the cookie scope, so the name written into the JSON config's
 * {@code credentials[].name} always matches the cookie actually set.
 */
public final class CookieScope {

    public static final String CHALLENGE_SUFFIX = "dbsc-challenge";
    public static final String BINDING_SUFFIX = "dbsc-session";
    public static final String REGISTRATION_SUFFIX = "dbsc-reg";

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

    /** {@code "__Host-"}, {@code "__Secure-"}, or empty for insecure development. */
    public String prefix() {
        if (scope == Scope.SITE) {
            return "__Secure-";
        }
        return secure ? "__Host-" : "";
    }

    public String bindingCookieName() {
        return prefix() + BINDING_SUFFIX;
    }

    public String registrationCookieName() {
        return prefix() + REGISTRATION_SUFFIX;
    }

    public String challengeCookieName() {
        return prefix() + CHALLENGE_SUFFIX;
    }

    /**
     * The attributes string echoed back in the registration response's
     * {@code credentials[].attributes} field, which Chromium re-reads to know how
     * to re-issue the bound cookie on refresh.
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

    /** Renders a {@code Set-Cookie} value that deletes the named cookie. */
    public String deleteCookieValue(String name) {
        return name + "=; " + attributesString() + "; Max-Age=0";
    }
}
