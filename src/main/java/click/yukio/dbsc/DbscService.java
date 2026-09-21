package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.BoundKeyKind;
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
import click.yukio.dbsc.replay.ProofReplayCache;
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
 * 403 (never 401) when proof is missing or invalid, and a success MUST carry the
 * JSON session config (a bodyless 200 is read as an opt-out and kills the
 * session).
 */
public class DbscService {

    private static final Logger log = LoggerFactory.getLogger(DbscService.class);

    private final DbscProperties properties;
    private final StorageAdapter storage;
    private final ChallengeService challenges;
    private final DbscProtocolEngine engine;
    private final CookieScope cookieScope;
    private final RateLimiter rateLimiter;
    private final ProofReplayCache replayCache;
    private final Clock clock;
    private final boolean trustForwardedHeaders;

    public DbscService(
            DbscProperties properties,
            StorageAdapter storage,
            ChallengeService challenges,
            DbscProtocolEngine engine,
            CookieScope cookieScope,
            RateLimiter rateLimiter,
            ProofReplayCache replayCache,
            Clock clock,
            boolean trustForwardedHeaders) {
        this.properties = properties;
        this.storage = storage;
        this.challenges = challenges;
        this.engine = engine;
        this.cookieScope = cookieScope;
        this.rateLimiter = rateLimiter;
        this.replayCache = replayCache;
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
     * <p>If the response would be cross-site — the usual case behind an OIDC or
     * SAML callback, where the request that produces this response was initiated
     * by the identity provider — the registration header is withheld. Chromium
     * makes DBSC requests inherit the initiator, so honouring it there would make
     * the registration POST cross-site and drop the {@code SameSite=Lax} session
     * cookie. Chromium records that failure as permanent and does not retry for the
     * rest of the login, so the session would stay unbound. Call
     * {@link #bind(String, String, long, HttpServletRequest, HttpServletResponse)}
     * again from a same-site request (or navigate the browser through a page that
     * does) to complete the registration; the session record itself is created
     * either way.
     *
     * @param sessionId the application's session id (its own authenticated id)
     * @param userId    the authenticated user
     * @param ttlMs     lifetime of the coupled application session in ms; a
     *                  non-positive value falls back to the configured default
     */
    public void bind(String sessionId, String userId, long ttlMs,
                     HttpServletRequest request, HttpServletResponse response) {
        if (!properties.isEnabled()) {
            return;
        }
        long now = clock.millis();
        long effectiveTtlMs = ttlMs > 0 ? ttlMs : properties.sessionTtlMs();
        Session session = new Session(
                sessionId, userId, ProtectionTier.NONE, now, now + effectiveTtlMs, 0);
        storage.setSession(session);

        if (isCrossSite(request)) {
            log.debug("DBSC bind for session {} deferred: the request is cross-site, so a"
                    + " registration header here would be sent without the session cookie", sessionId);
            return;
        }

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
        requireEnabled();
        checkRegistrationRateLimit(request);

        String sessionId = requireBinderSession(request);
        String responseHeader = readResponseHeader(request);
        String expectedJti = readCookie(request, cookieScope.challengeCookieName())
                .orElseThrow(DbscException::challengeNotFound);

        engine.handleRegistration(sessionId, responseHeader, expectedJti);

        // The challenge cookie has served its purpose; clear it.
        response.addHeader("Set-Cookie", cookieScope.deleteCookieValue(cookieScope.challengeCookieName()));
        setCookie(response, cookieScope.bindingCookieName(), sessionId, properties.boundCookieTtlMs());

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
        requireEnabled();
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
        setCookie(response, cookieScope.bindingCookieName(), sessionId, properties.boundCookieTtlMs());

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
    // Bound protocol (spec 03)
    // ------------------------------------------------------------------

    /** {@code GET /dbsc-bound/state} always answers 200 (spec 03). */
    public BoundStateResult boundState(HttpServletRequest request) {
        String sessionId = resolveBinderSession(request).orElse(null);
        Session session = sessionId == null ? null : storage.getSession(sessionId).orElse(null);

        if (session == null) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("phase", "unbound");
            body.put("sessionId", null);
            addSkipped(body, parseSkipped(request));
            return new BoundStateResult(body, null);
        }

        boolean hasNative = storage.getBoundKey(session.id(), BoundKeyKind.NATIVE).isPresent();
        boolean hasBound = storage.getBoundKey(session.id(), BoundKeyKind.BOUND).isPresent();

        Map<String, Object> body = new LinkedHashMap<>();
        Challenge challenge = null;
        if (hasBound) {
            body.put("phase", "bound");
            body.put("sessionId", session.id());
            body.put("tier", hasNative ? ProtectionTier.DBSC.wireValue() : ProtectionTier.BOUND.wireValue());
            body.put("refreshIntervalMs", properties.boundRefreshIntervalMs());
        } else if (hasNative) {
            // A Chromium session that has done native registration but has no
            // per-request key yet. The tier stays "dbsc".
            challenge = challenges.issue(session.id());
            body.put("phase", "needs-bound-registration");
            body.put("sessionId", session.id());
            body.put("tier", ProtectionTier.DBSC.wireValue());
            body.put("challenge", challenge.jti());
            body.put("refreshIntervalMs", properties.boundRefreshIntervalMs());
        } else {
            challenge = challenges.issue(session.id());
            body.put("phase", "needs-registration");
            body.put("sessionId", session.id());
            body.put("challenge", challenge.jti());
        }

        addSkipped(body, parseSkipped(request));
        return new BoundStateResult(body, challenge);
    }

    /**
     * The state route's response plus the challenge it issued, so the controller
     * can mirror it into a cookie. The bound registration endpoint identifies the
     * session by cookie and validates the challenge it finds there.
     *
     * @param body      the JSON body to render
     * @param challenge the challenge to set as a cookie, or {@code null}
     */
    public record BoundStateResult(Map<String, Object> body, Challenge challenge) {
    }

    /**
     * {@code GET /dbsc-bound/challenge}: 403 when the request carries no session
     * identifier.
     *
     * <p>The sessionless case is not an exception: spec 03 pins the exact body
     * {@code {"error":"no session"}}, so it is returned here for the controller to
     * render alongside the 403 status.
     *
     * <p>A cookie naming a session with no record is treated the same as no cookie:
     * registration is lazy, so "not registered yet" is the normal first state of
     * every session and must not be an error. The challenge issued here is bound to
     * the session identifier, and registration re-validates it.
     */
    public BoundChallengeResult boundChallenge(HttpServletRequest request, HttpServletResponse response) {
        // Registration is lazy: the browser may not have registered yet, so a
        // cookie naming a session the server has no record of just means "not
        // registered". Both cases answer the same way, and the caller decides how
        // to render them.
        Optional<String> sessionId = resolveBinderSession(request);
        if (sessionId.isEmpty()) {
            return new BoundChallengeResult(Map.of("error", "no session"), false);
        }

        // The JTI goes in the body only, never in the challenge cookie: that
        // cookie is the native routes' channel and overwriting it here would
        // invalidate a native registration in flight.
        Challenge challenge = challenges.issue(sessionId.get());
        return new BoundChallengeResult(Map.of("challenge", challenge.jti()), true);
    }

    /**
     * The challenge body plus whether the request was authenticated, so the
     * controller knows which status to use.
     *
     * @param body     the JSON body to render
     * @param hasSession whether a session was found; {@code false} means 403
     */
    public record BoundChallengeResult(Map<String, Object> body, boolean hasSession) {
    }

    /** {@code POST /dbsc-bound/registration}. */
    public Map<String, Object> boundRegistration(
            HttpServletRequest request, Map<String, Object> publicKey, String signature, String challengeJti) {
        requireBoundEnabled();
        checkRegistrationRateLimit(request);

        // Missing cookie or field is 400 here (spec 03/08), unlike every other
        // DBSC failure: it is a client bug, not a rejected proof.
        // The browser may be registering for the first time, so the record is
        // deliberately not required to exist yet: registration is what creates it.
        String sessionId = requireBinderSession(request, true);
        if (publicKey == null || signature == null || signature.isEmpty()
                || challengeJti == null || challengeJti.isEmpty()) {
            throw DbscException.badRequest(
                    "bound registration requires publicKey, signature and challenge");
        }
        engine.handleBoundRegistration(sessionId, publicKey, signature, challengeJti);

        ProtectionTier tier = engine.currentTier(sessionId);
        String refreshUrl = properties.getBoundPath() + "/refresh";
        return SessionConfig.boundResponse(sessionId, refreshUrl, tier.wireValue());
    }

    /** {@code POST /dbsc-bound/refresh}. */
    public Map<String, Object> boundRefresh(
            HttpServletRequest request, HttpServletResponse response,
            String signature, String challengeJti, Long timestamp) {
        requireBoundEnabled();
        checkRefreshRateLimit(request);

        // A refresh carries a signature over a challenge this server issued, so an
        // unknown session is a forged cookie: a rejected proof (403), not a client
        // bug.
        String sessionId = requireRegisteredSession(request, false);
        if (signature == null || signature.isEmpty() || challengeJti == null || challengeJti.isEmpty()
                || timestamp == null) {
            throw DbscException.badRequest("bound refresh requires challenge, signature and timestamp");
        }
        engine.handleBoundRefresh(sessionId, signature, challengeJti, timestamp);

        // Only the binding cookie is touched. Clearing the challenge cookie here
        // would delete a native challenge that is still in flight; the bound
        // protocol keeps its JTI in the body, so it has nothing to clear.
        setCookie(response, cookieScope.bindingCookieName(), sessionId, properties.boundCookieTtlMs());

        ProtectionTier tier = engine.currentTier(sessionId);
        String refreshUrl = properties.getBoundPath() + "/refresh";
        return SessionConfig.boundResponse(sessionId, refreshUrl, tier.wireValue());
    }

    // ------------------------------------------------------------------
    // Per-request proof guard (spec 04)
    // ------------------------------------------------------------------

    /**
     * Verifies a per-request proof for a guarded route.
     *
     * @param signBody whether the route binds the request body into the proof
     */
    public void requireProof(
            HttpServletRequest request, String sessionId, String path, byte[] bodyBytes, boolean signBody) {
        String proofHeader = request.getHeader(DbscHeaders.BOUND_PROOF);
        engine.verifyBoundProof(
                sessionId, proofHeader, request.getMethod(), path, bodyBytes, signBody, replayCache);
    }

    // ------------------------------------------------------------------
    // Session resolution
    // ------------------------------------------------------------------

    /**
     * Resolves the session identifier from the binding cookie, falling back to the
     * registration cookie for the bound protocol's pre-binding requests.
     *
     * <p>A cookie proves nothing: it is attacker-supplied on any unauthenticated
     * request, so this only names a candidate session. The caller's proof check is
     * what admits or rejects it.
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

    /**
     * Like {@link #requireBinderSession(HttpServletRequest, boolean)}, but also
     * refuses a cookie whose value was never issued a record.
     *
     * <p>Used where the request carries a proof to verify: there, an unknown
     * session is indistinguishable from a forged cookie, so it is a rejected proof
     * (403) rather than a client bug (400). Registration is deliberately excluded —
     * whether the browser has registered is unknowable up front, so routes that
     * lead to a registration must not require a record to exist yet.
     */
    private String requireRegisteredSession(HttpServletRequest request, boolean clientError) {
        String sessionId = requireBinderSession(request, clientError);
        if (storage.getSession(sessionId).isEmpty()) {
            throw clientError
                    ? DbscException.badRequest("no such DBSC session")
                    : new DbscException(DbscErrorCode.SESSION_NOT_REGISTERED,
                            "no such DBSC session");
        }
        return sessionId;
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

    /**
     * Whether the request was initiated by another origin, per
     * {@code Sec-Fetch-Site}. A browser that sends no such header is not assumed to
     * be cross-site: the value is only trusted when it is present.
     */
    private boolean isCrossSite(HttpServletRequest request) {
        String site = request.getHeader("Sec-Fetch-Site");
        return "cross-site".equalsIgnoreCase(site);
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

    private void requireEnabled() {
        if (!properties.isEnabled()) {
            throw new DbscException(DbscErrorCode.SESSION_NOT_FOUND, "DBSC is disabled");
        }
    }

    private void requireBoundEnabled() {
        requireEnabled();
        if (!properties.isBound()) {
            throw new DbscException(DbscErrorCode.SESSION_NOT_FOUND,
                    "the bound protocol is disabled");
        }
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
                && !rateLimiter.checkRefresh(clientIp(request), null)) {
            throw new DbscException(DbscErrorCode.RATE_LIMITED, "refresh rate limit tripped");
        }
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

    /** Whether the session holds a native (hardware) key. */
    public boolean hasNativeKey(String sessionId) {
        return storage.getBoundKey(sessionId, BoundKeyKind.NATIVE).isPresent();
    }

    /** Whether the session holds a bound (polyfill) key. */
    public boolean hasBoundKey(String sessionId) {
        return storage.getBoundKey(sessionId, BoundKeyKind.BOUND).isPresent();
    }
}
