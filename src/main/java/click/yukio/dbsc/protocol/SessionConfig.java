package click.yukio.dbsc.protocol;

import click.yukio.dbsc.config.DbscProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds the JSON session config returned (200, {@code application/json}) from
 * both a successful registration and a successful refresh (spec 02).
 *
 * <p>The body is <strong>mandatory</strong>: a 200 without a valid JSON config is
 * interpreted by Chromium as an opt-out and the session dies after one cycle.
 *
 * <p>{@code credentials[0].attributes} MUST equal the protected cookie's actual
 * {@code Set-Cookie} attributes byte-for-byte, or Chromium silently drops the
 * binding. That string is produced by {@link CookieScope#attributesString()} —
 * the same call that renders the {@code Set-Cookie} header — so the two cannot
 * drift.
 *
 * <p>Two different names appear in the body, and they are not interchangeable.
 * {@code session_identifier} is the name of the cookie holding the DBSC session id —
 * it is how Chromium keys the session in its own store (spec §7.2).
 * {@code credentials[].name} is the name of the <em>protected</em> cookie, whose value
 * is the rotating ticket; §8.6 asks only that the cookie of that name be present on a
 * request. The two are frequently the same cookie in a simple deployment and are
 * deliberately separate here.
 */
public final class SessionConfig {

    private SessionConfig() {
    }

    /**
     * Renders the session config.
     *
     * @param origin      the request origin ({@code scheme://host}); may be
     *                    {@code null} to let Chromium infer it, but when present
     *                    it MUST be correct
     * @param refreshUrl  the refresh path from the config
     * @param scope       the resolved cookie scope, for the credential name and
     *                    attributes
     * @param includeSite whether to extend the session to all subdomains
     */
    public static Map<String, Object> build(
            String origin,
            String refreshUrl,
            CookieScope scope,
            boolean includeSite,
            DbscProperties properties) {

        Map<String, Object> scopeMap = new LinkedHashMap<>();
        if (origin != null && !origin.isBlank()) {
            scopeMap.put("origin", origin);
        }
        scopeMap.put("include_site", includeSite);
        scopeMap.put("scope_specification", List.of());

        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("type", "cookie");
        credential.put("name", scope.credentialCookieName());
        credential.put("attributes", scope.attributesString());

        List<Map<String, Object>> credentials = new ArrayList<>();
        credentials.add(credential);

        // session_identifier is the NAME of the cookie carrying the session id, not the
        // id itself. Chromium keys its session store by this string (spec §7.2), and
        // §8.9 validates Sec-Secure-Session-Id against it on every refresh -- so sending
        // the id here would make every refresh a mismatch.
        Map<String, Object> config = new LinkedHashMap<>();
        String identifierName = properties.getSessionIdentifierName();
        if (identifierName == null || identifierName.isBlank()) {
            // The name must be one this library actually sets a cookie under, or the
            // browser stores a session it cannot satisfy on refresh. See DbscProperties.
            identifierName = scope.sessionIdentifierName();
        }
        config.put("session_identifier", identifierName);
        config.put("refresh_url", refreshUrl);
        config.put("scope", scopeMap);
        config.put("credentials", credentials);
        return config;
    }

    /**
     * Renders the config used to terminate a session, e.g. on logout. Chromium
     * forgets the binding immediately rather than waiting out the cookie.
     */
    public static Map<String, Object> terminated(
            String origin, String refreshUrl, CookieScope scope, DbscProperties properties) {
        Map<String, Object> config = build(origin, refreshUrl, scope, false, properties);
        config.put("continue", false);
        return config;
    }
}
