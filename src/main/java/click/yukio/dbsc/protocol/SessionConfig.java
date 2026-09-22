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
 * <p>{@code credentials[0].attributes} MUST match the protected cookie's actual
 * {@code Set-Cookie} attributes byte-for-byte, or Chromium silently drops the
 * binding. That string is produced by {@link CookieScope#attributesString()} —
 * the same prefix {@code Set-Cookie} is written with — so the two cannot drift.
 *
 * <p>{@code Max-Age} MUST NOT appear in it. The spec's own example annotates the
 * string with "Attributes Max-Age and Expires are ignored" (§9.9), and Chromium does
 * not merely ignore them — it parses this value as a cookie attribute list, where
 * {@code Max-Age} is not permitted, and refuses the registration with "cookie
 * attribute not permitted". §8.6 matches on Domain, Path, Secure, HttpOnly and
 * SameSite only. The cookie's lifetime belongs in the {@code Set-Cookie} header
 * alone.
 *
 * <p>{@code session_identifier} is the session id <strong>itself</strong>, not the name of
 * a cookie holding it. The spec is explicit (§9.6): "a string representing a session
 * identifier. During registration, this is the identifier for the newly created
 * session." Chromium stores the session under that value (§8.1 keys its session store by
 * it) and sends it back as {@code Sec-Secure-Session-Id} on every refresh (§9.4), so the
 * server looks the session up by exactly this string. A name — any constant — would
 * name no session at all, and every refresh would miss.
 *
 * <p>{@code credentials[].name} is the name of the <em>protected</em> cookie, whose value
 * is the rotating ticket; §8.6 asks only that the cookie of that name be present on a
 * request. The two are unrelated, and conflating them was the bug: one is an id, the
 * other a cookie name.
 *
 * <p>{@code scope.scope_specification} and {@code allowed_refresh_initiators} are the two
 * keys that decide <em>where</em> the browser applies the session and <em>who</em> may make
 * it refresh. Both come from configuration ({@code dbsc.scope-specifications} and
 * {@code dbsc.allowed-refresh-initiators}) and neither is enforced server-side: they are
 * instructions to the user agent, so an absent list here silently means "whole site" and
 * "nobody out of scope" respectively.
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
     * @param sessionId   the session id, sent as {@code session_identifier}
     * @param scope       the resolved cookie scope, for the credential name and
     *                    attributes
     * @param includeSite whether to extend the session to all subdomains
     */
    public static Map<String, Object> build(
            String origin,
            String refreshUrl,
            String sessionId,
            CookieScope scope,
            boolean includeSite,
            DbscProperties properties) {

        Map<String, Object> scopeMap = new LinkedHashMap<>();
        if (origin != null && !origin.isBlank()) {
            scopeMap.put("origin", origin);
        }
        scopeMap.put("include_site", includeSite);
        scopeMap.put("scope_specification", scopeSpecification(properties));

        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("type", "cookie");
        credential.put("name", scope.credentialCookieName());
        // The attribute set §8.6 compares against -- Domain, Path, Secure, HttpOnly,
        // SameSite -- and nothing else. Max-Age is deliberately absent: it is not one of the
        // attributes §8.6 matches on, and Chromium parses this string as a cookie attribute
        // list, where Max-Age is not permitted ("cookie attribute not permitted"). A
        // lifetime here is not merely ignored, it invalidates the registration.
        credential.put("attributes", scope.attributesString());

        List<Map<String, Object>> credentials = new ArrayList<>();
        credentials.add(credential);

        // The session id itself. Chromium keys its session store by this value (§8.1)
        // and echoes it back in Sec-Secure-Session-Id on every refresh (§9.4), which is
        // what the server resolves the session from -- so it has to be the id the server
        // knows the session by, not the name of a cookie.
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("session_identifier", sessionId);
        config.put("refresh_url", refreshUrl);
        config.put("scope", scopeMap);
        config.put("credentials", credentials);
        config.put("allowed_refresh_initiators", allowedRefreshInitiators(properties));
        return config;
    }

    /**
     * Renders {@code scope.scope_specification} (spec §9.7, §9.8).
     *
     * <p>The browser applies these rules to the scope it already defaulted from
     * {@code origin} and {@code include_site}, and walks the list in <em>reverse</em>,
     * stopping at the first match (§8.2) — so the server's array order is preserved
     * verbatim, and the last rule written is the one that wins.
     *
     * <p>The spec makes {@code domain} and {@code path} optional on each rule, defaulting
     * to {@code *} and {@code /}. They are written out explicitly anyway: the defaults are
     * filled in here so the emitted JSON says what it means, and an operator reading the
     * response is not left to work out which rule was quietly the broad one.
     */
    private static List<Map<String, Object>> scopeSpecification(DbscProperties properties) {
        List<Map<String, Object>> rules = new ArrayList<>();
        for (DbscProperties.ScopeSpecification rule : properties.getScopeSpecifications()) {
            Map<String, Object> rendered = new LinkedHashMap<>();
            rendered.put("type", rule.getType() == DbscProperties.ScopeSpecification.Type.EXCLUDE
                    ? "exclude" : "include");
            rendered.put("domain", blankTo(rule.getDomain(), "*"));
            rendered.put("path", blankTo(rule.getPath(), "/"));
            rules.add(rendered);
        }
        return rules;
    }

    /**
     * Renders {@code allowed_refresh_initiators} (spec §9.6, §8.3).
     *
     * <p>An empty list is emitted rather than the key being omitted: both mean the same
     * thing to the browser, but writing it makes the refusal to refresh out-of-scope
     * initiators explicit in the response instead of implicit in a missing key.
     */
    private static List<String> allowedRefreshInitiators(DbscProperties properties) {
        List<String> initiators = new ArrayList<>();
        for (String initiator : properties.getAllowedRefreshInitiators()) {
            if (initiator != null && !initiator.isBlank()) {
                initiators.add(initiator.trim());
            }
        }
        return initiators;
    }

    private static String blankTo(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    /**
     * Renders the config used to terminate a session, e.g. on logout. Chromium
     * forgets the binding immediately rather than waiting out the cookie.
     */
    public static Map<String, Object> terminated(
            String origin, String refreshUrl, String sessionId, CookieScope scope,
            DbscProperties properties) {
        Map<String, Object> config = build(origin, refreshUrl, sessionId, scope, false, properties);
        config.put("continue", false);
        return config;
    }
}
