package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.DbscErrorCode;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.SkippedEntry;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.protocol.ChallengeService;
import click.yukio.dbsc.protocol.CookieScope;
import click.yukio.dbsc.protocol.DbscHeaderCodec;
import click.yukio.dbsc.protocol.DbscHeaders;
import click.yukio.dbsc.protocol.DbscProtocolEngine;
import click.yukio.dbsc.protocol.SessionConfig;
import click.yukio.dbsc.ratelimit.RateLimiter;
import click.yukio.dbsc.web.OriginResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The HTTP-facing DBSC facade.
 *
 * <p>Controllers stay thin by delegating here; this class owns the mapping from
 * protocol outcomes to status codes, headers, cookies, and JSON bodies. The
 * status rules are strict and load-bearing: the native refresh route MUST answer
 * 403 (never 401) when the signature is missing or invalid, and a success MUST
 * carry the JSON session config (a bodyless 200 is read as an opt-out and kills
 * the session).
 */
public class DbscService {

    private static final Logger log = LoggerFactory.getLogger(DbscService.class);

    private final DbscProperties properties;
    private final StorageAdapter storage;
    private final ChallengeService challenges;
    private final DbscProtocolEngine engine;
    private final CookieScope cookieScope;
    private final RateLimiter rateLimiter;
    private final Clock clock;
    private final boolean trustForwardedHeaders;

    public DbscService(
            DbscProperties properties,
            StorageAdapter storage,
            ChallengeService challenges,
            DbscProtocolEngine engine,
            CookieScope cookieScope,
            RateLimiter rateLimiter,
            Clock clock,
            boolean trustForwardedHeaders) {
        this.properties = properties;
        this.storage = storage;
        this.challenges = challenges;
        this.engine = engine;
        this.cookieScope = cookieScope;
        this.rateLimiter = rateLimiter;
        this.clock = clock;
        this.trustForwardedHeaders = trustForwardedHeaders;
    }

    // ------------------------------------------------------------------
    // Binding (called by the login route)
    // ------------------------------------------------------------------

    /**
     * Starts a DBSC session: persists the session record and primes the browser
     * with the registration header plus the two short-lived cookies. Chromium
     * then POSTs the registration JWS on its own, with no client-side code.
     *
     * <p>Call it from any authenticated request. It is idempotent, and it is
     * deliberately <strong>speculative</strong>: the server cannot know whether
     * this browser supports DBSC, whether the response will be withheld from it,
     * or whether the offer will simply be ignored. Nothing here inspects
     * {@code Sec-Fetch-Site}: an earlier revision withheld the header on
     * cross-site responses, on the theory that the registration POST would lose
     * its {@code SameSite=Lax} cookie — but that made the offer depend on the
     * browser re-initiating the request, which no server-side redirect can force,
     * so behind an OIDC or SAML callback the header was never sent at all.
     * Whether a registration succeeds is the browser's business.
     *
     * <p>Whether a registration succeeds is the browser's business. If you have
     * reason to believe the response will not reach the browser as a binding
     * opportunity — an OIDC or SAML callback is the common case — call this again
     * from a later, same-site request. See "Binding behind OIDC or SAML" in the
     * README; retrying is a strategy the caller owns, not something this library
     * does on your behalf.
     *
     * @param sessionId the application's session id (its own authenticated id)
     * @param userId    the authenticated user
     * @param ttlMs     lifetime of the coupled application session in ms; a
     *                  non-positive value falls back to the configured default
     */
    public void bind(String sessionId, String userId, long ttlMs,
                     HttpServletRequest request, HttpServletResponse response) {
        long now = clock.millis();
        long effectiveTtlMs = ttlMs > 0 ? ttlMs : properties.sessionTtlMs();
        Session session = new Session(
                sessionId, userId, ProtectionTier.NONE, now, now + effectiveTtlMs, 0);
        storage.setSession(session);

        Challenge challenge = challenges.issue(session.id());

        response.addHeader(DbscHeaders.REGISTRATION, DbscHeaderCodec.buildRegistrationHeader(
                "ES256", properties.getRegistrationPath(), challenge.jti()));
        // Some Chromium builds straddle the header rename, so emit the legacy name too.
        response.addHeader(DbscHeaders.LEGACY_REGISTRATION, DbscHeaderCodec.buildRegistrationHeader(
                "ES256", properties.getRegistrationPath(), challenge.jti()));

        setCookie(response, cookieScope.registrationCookieName(), session.id(),
                properties.registrationCookieTtlMs());
        setCookie(response, cookieScope.challengeCookieName(), challenge.jti(),
                properties.challengeTtlMs());
    }

    /**
     * Terminates a session, e.g. on logout. The response tells Chromium to forget
     * the binding immediately, and the binding cookie is cleared.
     */
    public Map<String, Object> terminate(String sessionId, HttpServletRequest request,
                                         HttpServletResponse response) {
        storage.revokeSession(sessionId);
        response.addHeader("Set-Cookie", cookieScope.deleteCookieValue(cookieScope.bindingCookieName()));
        response.addHeader("Set-Cookie", cookieScope.deleteCookieValue(cookieScope.challengeCookieName()));
        return SessionConfig.terminated(
                OriginResolver.resolve(request, trustForwardedHeaders),
                sessionId, properties.getRefreshPath(), cookieScope, properties);
    }

    // ------------------------------------------------------------------
    // Native registration (spec 02)
    // ------------------------------------------------------------------

    /**
     * Handles {@code POST /dbsc/registration}.
     *
     * @return the JSON session config
     */
    public Map<String, Object> handleRegistration(
            HttpServletRequest request, HttpServletResponse response) {
        checkRegistrationRateLimit(request);

        String sessionId = requireBinderSession(request);
        String responseHeader = readResponseHeader(request);
        String expectedJti = readCookie(request, cookieScope.challengeCookieName())
                .orElseThrow(DbscException::challengeNotFound);

        engine.handleRegistration(sessionId, responseHeader, expectedJti);

        // The challenge cookie has served its purpose; clear it.
        response.addHeader("Set-Cookie", cookieScope.deleteCookieValue(cookieScope.challengeCookieName()));
        setCookie(response, cookieScope.bindingCookieName(), sessionId, properties.bindingCookieTtlMs());

        return sessionConfig(request, sessionId);
    }

    // ------------------------------------------------------------------
    // Native refresh (spec 02)
    // ------------------------------------------------------------------

    /**
     * Handles {@code POST /dbsc/refresh}.
     *
     * <p>The first leg arrives with no {@code Secure-Session-Response}: the
     * answer MUST be 403 with a fresh challenge. 401 is ignored by Chromium and
     * the session dies. The second leg carries the JWS; success returns 200 with
     * the JSON config and a fresh binding cookie.
     */
    public Map<String, Object> handleRefresh(HttpServletRequest request, HttpServletResponse response) {
        checkRefreshRateLimit(request);

        // The binding cookie is gone by the time a refresh runs, so the session
        // identifier arrives in a header. The challenge cookie is still present
        // from the first leg and carries the JTI the browser signed.
        String sessionId = resolveRefreshSessionId(request);

        String responseHeader = readResponseHeader(request);
        if (responseHeader == null || responseHeader.isBlank()) {
            // First leg: no proof yet. Issue a challenge and answer 403.
            issueChallengeAndReject(response, sessionId);
            return null;
        }

        String expectedJti = readCookie(request, cookieScope.challengeCookieName())
                .orElseThrow(DbscException::challengeNotFound);
        engine.handleRefresh(sessionId, responseHeader, expectedJti);

        response.addHeader("Set-Cookie", cookieScope.deleteCookieValue(cookieScope.challengeCookieName()));
        setCookie(response, cookieScope.bindingCookieName(), sessionId, properties.bindingCookieTtlMs());

        return sessionConfig(request, sessionId);
    }

    /**
     * Resolves the session identifier on a native refresh: {@code Sec-Secure-Session-Id}
     * (or its legacy alias), falling back to the session cookie.
     */
    private String resolveRefreshSessionId(HttpServletRequest request) {
        String sessionId = request.getHeader(DbscHeaders.SESSION_ID);
        if (sessionId == null || sessionId.isBlank()) {
            sessionId = request.getHeader("Sec-Secure-Session-Id");
        }
        if (sessionId == null || sessionId.isBlank()) {
            sessionId = resolveBinderSession(request).orElse(null);
        }
        if (sessionId == null || sessionId.isBlank()) {
            throw new DbscException(DbscErrorCode.SESSION_NOT_FOUND,
                    "refresh requires the session identifier header");
        }
        return sessionId.trim();
    }

    /**
     * Issues a fresh challenge with a 403 and a challenge cookie. The status is
     * 403 by spec: Chromium ignores 401 here.
     */
    public void issueChallengeAndReject(HttpServletResponse response, String sessionId) {
        Challenge challenge = challenges.issue(sessionId);
        String challengeHeader = DbscHeaderCodec.buildChallengeHeader(challenge.jti(), sessionId);
        response.addHeader(DbscHeaders.CHALLENGE, challengeHeader);
        response.addHeader(DbscHeaders.LEGACY_CHALLENGE, challengeHeader);
        setCookie(response, cookieScope.challengeCookieName(), challenge.jti(), properties.challengeTtlMs());
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }

    // ------------------------------------------------------------------
    // Session resolution
    // ------------------------------------------------------------------

    /**
     * Resolves the session identifier from the binding cookie.
     *
     * <p>A cookie proves nothing: it is attacker-supplied on any unauthenticated
     * request, so this only names a candidate session. The caller's proof check is
     * what admits or rejects it. The pre-registration cookie carries the session id
     * as written by {@link #bind}, and is the candidate the registration route
     * resolves when no binding cookie exists yet.
     */
    public Optional<String> resolveBinderSession(HttpServletRequest request) {
        Optional<String> binding = readCookie(request, cookieScope.bindingCookieName());
        if (binding.isPresent()) {
            return binding;
        }
        return readCookie(request, cookieScope.registrationCookieName());
    }

    private String requireBinderSession(HttpServletRequest request) {
        return requireBinderSession(request, false);
    }

    /**
     * @param clientError when true, a missing cookie is reported as
     *                    {@link DbscErrorCode#BAD_REQUEST} (400) instead of the
     *                    403 that a rejected proof gets
     */
    private String requireBinderSession(HttpServletRequest request, boolean clientError) {
        return resolveBinderSession(request)
                .orElseThrow(() -> clientError
                        ? DbscException.badRequest("no DBSC session cookie on the request")
                        : new DbscException(DbscErrorCode.SESSION_NOT_FOUND,
                                "no DBSC session cookie on the request"));
    }

    /** The session's tier as reported to the application. */
    public ProtectionTier tierFor(String sessionId) {
        return storage.getSession(sessionId).map(engine::effectiveTier).orElse(ProtectionTier.NONE);
    }

    public Optional<Session> sessionFor(HttpServletRequest request) {
        return resolveBinderSession(request).flatMap(storage::getSession);
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private Map<String, Object> sessionConfig(HttpServletRequest request, String sessionId) {
        boolean includeSite = cookieScope.scope() == CookieScope.Scope.SITE;
        return SessionConfig.build(
                OriginResolver.resolve(request, trustForwardedHeaders),
                sessionId,
                properties.getRefreshPath(),
                cookieScope,
                includeSite,
                properties);
    }

    private String readResponseHeader(HttpServletRequest request) {
        String value = request.getHeader(DbscHeaders.RESPONSE);
        if (value == null || value.isBlank()) {
            value = request.getHeader(DbscHeaders.LEGACY_RESPONSE);
        }
        return value;
    }

    private Optional<String> readCookie(HttpServletRequest request, String name) {
        Map<String, String> cookies = DbscHeaderCodec.parseCookieHeader(request.getHeader("Cookie"));
        return Optional.ofNullable(cookies.get(name));
    }

    private List<SkippedEntry> parseSkipped(HttpServletRequest request) {
        String value = request.getHeader(DbscHeaders.SKIPPED);
        if (value == null || value.isBlank()) {
            value = request.getHeader(DbscHeaders.LEGACY_SKIPPED);
        }
        return DbscHeaderCodec.parseSkippedHeader(value);
    }

    /**
     * Echoes parsed skip reasons. A skip is diagnostic only: it is never mapped to
     * an error code and never changes the response status.
     */
    private void addSkipped(Map<String, Object> body, List<SkippedEntry> skipped) {
        if (skipped.isEmpty()) {
            return;
        }
        body.put("nativeSkipped", skipped.stream().map(entry -> {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("reason", entry.reason().wireValue());
            if (entry.sessionId() != null) {
                map.put("sessionId", entry.sessionId());
            }
            return map;
        }).toList());
    }

    /**
     * Emits {@code Set-Cookie} with the exact attributes echoed in the JSON
     * config's {@code credentials[].attributes}.
     */
    private void setCookie(HttpServletResponse response, String name, String value, long maxAgeMs) {
        response.addHeader("Set-Cookie", cookieScope.setCookieValue(name, value, maxAgeMs));
    }

    private void checkRegistrationRateLimit(HttpServletRequest request) {
        if (properties.getRateLimit().isEnabled()
                && !rateLimiter.checkRegistration(clientIp(request))) {
            throw new DbscException(DbscErrorCode.RATE_LIMITED, "registration rate limit tripped");
        }
    }

    /**
     * Charges a rejected request to the client's failure budget.
     *
     * <p>Called by {@code DbscFilter} on every DBSC failure. Without it the
     * failure budgets are never consulted: an attacker could present unlimited
     * invalid proofs while staying inside the ordinary request budget, which is
     * sized for legitimate traffic.
     *
     * <p>A rate-limited request is deliberately <em>not</em> charged again — it
     * was already counted when it was refused, and charging the refusal too would
     * extend the lockout each time the client retries.
     */
    public void recordRateLimitFailure(HttpServletRequest request) {
        if (!properties.getRateLimit().isEnabled()) {
            return;
        }
        rateLimiter.recordFailure(clientIp(request), resolveBinderSession(request).orElse(null));
    }

    private void checkRefreshRateLimit(HttpServletRequest request) {
        if (properties.getRateLimit().isEnabled()
                && !rateLimiter.checkRefresh(clientIp(request), refreshSessionKey(request))) {
            throw new DbscException(DbscErrorCode.RATE_LIMITED, "refresh rate limit tripped");
        }
    }

    /**
     * The session component of the refresh rate-limit key.
     *
     * <p>It must match what {@link #recordRateLimitFailure} charges, or the refresh
     * budget is never consulted: the check and the record would use different keys,
     * and repeated failed refreshes would go unthrottled. {@link RateLimiter} keys
     * refreshes on the session so one noisy client cannot throttle every session
     * behind the same address, so both sides resolve it identically here.
     *
     * <p>A request naming no session is keyed as {@code null} on both sides, which
     * is correct: it is unauthenticated and rate-limited per client, and the shared
     * registration budget covers it.
     */
    private String refreshSessionKey(HttpServletRequest request) {
        return resolveBinderSession(request).orElse(null);
    }

    /**
     * The client IP used as a rate-limit key.
     *
     * <p>Only consulted when {@code dbsc.trust-forwarded-headers} is on. Even then
     * the <em>last</em> hop is taken, not the first: a proxy appends the address it
     * saw, so the last entry is the one the nearest trusted hop observed, while the
     * first is whatever the client claimed. Taking the first entry — the common
     * mistake — hands every request an attacker-chosen identity.
     */
    private String clientIp(HttpServletRequest request) {
        if (trustForwardedHeaders) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                String[] hops = forwarded.split(",");
                for (int i = hops.length - 1; i >= 0; i--) {
                    String hop = hops[i].trim();
                    if (!hop.isEmpty()) {
                        return hop;
                    }
                }
            }
        }
        String remote = request.getRemoteAddr();
        return remote == null ? "unknown" : remote;
    }

    // ------------------------------------------------------------------
    // Accessors for controllers and diagnostics
    // ------------------------------------------------------------------

    /** The resolved cookie scope, for controllers that must set a cookie directly. */
    public CookieScope cookieScope() {
        return cookieScope;
    }

    /** The resolved configuration. */
    public DbscProperties properties() {
        return properties;
    }

    /** Whether the session holds a device key. */
    public boolean hasDeviceKey(String sessionId) {
        return storage.getDeviceKey(sessionId).isPresent();
    }
}
