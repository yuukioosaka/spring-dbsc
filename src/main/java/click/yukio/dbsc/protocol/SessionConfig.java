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
 * <p>{@code credentials[0].attributes} MUST equal the binding cookie's actual
 * {@code Set-Cookie} attributes byte-for-byte, or Chromium silently drops the
 * binding. That string is produced by {@link CookieScope#attributesString()} —
 * the same call that renders the {@code Set-Cookie} header — so the two cannot
 * drift.
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
     * @param sessionId   the session identifier
     * @param refreshUrl  the refresh path from the config
     * @param scope       the resolved cookie scope, for the credential name and
     *                    attributes
     * @param includeSite whether to extend the session to all subdomains
     */
    public static Map<String, Object> build(
            String origin,
            String sessionId,
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
        credential.put("name", scope.bindingCookieName());
        credential.put("attributes", scope.attributesString());

        List<Map<String, Object>> credentials = new ArrayList<>();
        credentials.add(credential);

        Map<String, Object> config = new LinkedHashMap<>();
        config.put("session_identifier", sessionId);
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
            String origin, String sessionId, String refreshUrl, CookieScope scope, DbscProperties properties) {
        Map<String, Object> config = build(origin, sessionId, refreshUrl, scope, false, properties);
        config.put("continue", false);
        return config;
    }

    /**
     * Renders the bound protocol's registration/refresh response body (spec 03).
     */
    public static Map<String, Object> boundResponse(
            String sessionId, String refreshUrl, String tier) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("session_identifier", sessionId);
        body.put("refresh_url", refreshUrl);
        body.put("tier", tier);
        return body;
    }
}
