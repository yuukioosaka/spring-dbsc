package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.DbscErrorCode;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.GuardDecision;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.RegistrationToken;
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
     * Starts a DBSC session: persists the session record, mints a single-use
     * registration token, and primes the browser with the registration header and
     * the challenge cookie. Chromium then POSTs the registration JWS on its own,
     * with no client-side code.
     *
     * <p>Call it from any authenticated request. It is deliberately
     * <strong>speculative</strong>: the server cannot know whether this browser
     * supports DBSC, whether the response will be withheld from it, or whether the
     * offer will simply be ignored. Nothing here inspects {@code Sec-Fetch-Site},
     * and nothing about the offer depends on a cookie surviving the trip: the
     * session is named by a token in the registration <em>path</em>, so the offer
     * works even when the browser's registration POST is issued from a cross-site
     * navigation context where a {@code SameSite=Lax} cookie is withheld. That was
     * the whole reason the token exists — see "Binding behind OIDC or SAML" in the
     * README.
     *
     * <p>Calling this twice is not merged or rejected: each call writes a session
     * record and issues a fresh challenge, so a second call under the same id
     * replaces the first. Whether that is wanted is the caller's decision.
     *
     * @param sessionId    the <strong>DBSC</strong> session id. It is not the
     *                     application's own session id and is deliberately
     *                     independent of it: this value is the key the device's
     *                     public key is stored under, and it is what the binding
     *                     cookie carries. Mint whatever you like —
     *                     {@code UUID.randomUUID().toString()} is a fine choice —
     *                     and keep it if you want to call {@link #terminate} or
     *                     {@link #tierFor} by value; otherwise read it back from the
     *                     binding cookie with {@link #sessionFor}
     * @param appSessionId the application's own session id ({@code JSESSIONID} or
     *                     equivalent). It is recorded so that
     *                     {@link #guardDecision} can tell a client that never
     *                     registered apart from one that registered and then
     *                     dropped its DBSC cookies
     * @param userId       the authenticated user
     * @param ttlMs        lifetime of the session record in ms; a non-positive value
     *                     falls back to the configured default
     */
    public void bind(String sessionId, String appSessionId, String userId, long ttlMs,
                     HttpServletRequest request, HttpServletResponse response) {
        long now = clock.millis();
        long effectiveTtlMs = ttlMs > 0 ? ttlMs : properties.sessionTtlMs();
        Session session = new Session(
                sessionId, appSessionId, userId, ProtectionTier.NONE, false, now, now + effectiveTtlMs, 0);
        storage.setSession(session);

        Challenge challenge = challenges.issue(session.id());
        String registrationToken = issueRegistrationToken(session.id());

        response.addHeader(DbscHeaders.REGISTRATION, DbscHeaderCodec.buildRegistrationHeader(
                "ES256", registrationPathFor(registrationToken), challenge.jti()));
        // Some Chromium builds straddle the header rename, so emit the legacy name too.
        response.addHeader(DbscHeaders.LEGACY_REGISTRATION, DbscHeaderCodec.buildRegistrationHeader(
                "ES256", registrationPathFor(registrationToken), challenge.jti()));

        setChallengeCookie(response, cookieScope.challengeCookieName(), challenge.jti(),
                properties.challengeTtlMs());
        // One cookie, one job. The credential cookie carries a ticket and is the cookie
        // the protocol actually protects: §8.6 asks whether a cookie of the name in
        // credentials[] is present, and that is the cookie a refresh replaces.
        //
        // The ticket minted here is already unrelated to the session id -- the browser is
        // registered by this very request, so there is nothing for the id to protect yet
        // -- which keeps the value's meaning constant: always a ticket, never the id.
        setCookie(response, cookieScope.credentialCookieName(), engine.rotateAfterRefresh(session.id()),
                properties.bindingCookieTtlMs());
    }

    /**
     * Mints and persists a single-use registration token for the session.
     *
     * <p>The token is a 43-character base64url value from the same generator as a
     * challenge JTI, and it is deliberately <em>not</em> the session id: it travels
     * in a URL, which is written to access logs, proxy logs, and referrers, so it
     * must not be a credential that is useful anywhere else. Its only power is to
     * name the session for one registration POST.
     */
    public String issueRegistrationToken(String sessionId) {
        long now = clock.millis();
        RegistrationToken token = new RegistrationToken(
                Base64Url.randomJti(),
                sessionId,
                now,
                now + properties.registrationCookieTtlMs(),
                false);
        storage.setRegistrationToken(token);
        return token.token();
    }

    /** The path Chromium is told to POST a registration JWS to. */
    public String registrationPathFor(String registrationToken) {
        String prefix = properties.getRegistrationPath();
        if (prefix.endsWith("/")) {
            prefix = prefix.substring(0, prefix.length() - 1);
        }
        return prefix + "/" + registrationToken;
    }

    /**
     * The configured registration path prefix, e.g. {@code /dbsc/regist}.
     */
    public String registrationPathPrefix() {
        return properties.getRegistrationPath();
    }

    /**
     * Terminates a session, e.g. on logout. The response tells Chromium to forget
     * the binding immediately, and the binding cookie is cleared.
     *
     * <p>The record is <strong>kept</strong>, marked revoked. Deleting it would
     * make the next request that still carries the application's session id look
     * like a client that never bound, so a logged-out session would silently fall
     * back to cookie-only access.
     */
    public Map<String, Object> terminate(String sessionId, HttpServletRequest request,
                                         HttpServletResponse response) {
        storage.revokeSession(sessionId);
        response.addHeader("Set-Cookie", cookieScope.deleteCookieValue(cookieScope.credentialCookieName()));
        // The challenge cookie uses the SameSite=None attribute set, so it must be
        // deleted with the same attributes or the browser keeps the old one.
        response.addHeader("Set-Cookie",
                cookieScope.deleteChallengeCookieValue(cookieScope.challengeCookieName()));
        return SessionConfig.terminated(
                OriginResolver.resolve(request, trustForwardedHeaders),
                properties.getRefreshPath(), cookieScope, properties);
    }

    // ------------------------------------------------------------------
    // Native registration (spec 02)
    // ------------------------------------------------------------------

    /**
     * Handles {@code POST /dbsc/regist/<token>}.
     *
     * <p>The session is named by the token in the path, not by a cookie. That is
     * the point: the registration POST is issued by Chromium from whatever
     * navigation context produced the registration header, and behind an OIDC or
     * SAML callback that context is cross-site, so a {@code SameSite=Lax} cookie is
     * withheld and cookie-based discovery fails with {@code SESSION_NOT_FOUND}. A
     * path segment is not subject to any of that.
     *
     * <p>Failure modes are ordered as in spec 03: the token is validated first
     * (it is what selects the session), then the challenge, and finally the
     * token is consumed atomically on the success path so a replayed
     * registration POST cannot bind a second key.
     *
     * @param registrationToken the path segment naming the session
     * @return the JSON session config
     */
    public Map<String, Object> handleRegistration(
            String registrationToken, HttpServletRequest request, HttpServletResponse response) {
        checkRegistrationRateLimit(request);

        String sessionId = requireSessionForToken(registrationToken);
        String responseHeader = readResponseHeader(request);
        String expectedJti = readCookie(request, cookieScope.challengeCookieName())
                .orElseThrow(DbscException::challengeNotFound);

        engine.handleRegistration(sessionId, responseHeader, expectedJti);

        // The token has now done its job. Consuming it — not deleting it — leaves
        // the record for the failure path to report a replay as
        // REGISTRATION_TOKEN_CONSUMED rather than as an unknown token, which is
        // the difference between "you are replaying a captured POST" and "this URL
        // was never ours".
        storage.consumeRegistrationToken(registrationToken);

        // The challenge cookie carried the JTI the browser signed and is spent.
        response.addHeader("Set-Cookie",
                cookieScope.deleteChallengeCookieValue(cookieScope.challengeCookieName()));
        // Registration is the one place the credential cookie is dropped rather than
        // replaced. Until now the browser held a ticket that predates the binding; the
        // correct move is to stop honouring it, so a pre-registration value cannot
        // survive into the session it was meant for.
        storage.deleteTicket(readCookie(request, cookieScope.credentialCookieName()).orElse(null));
        setCookie(response, cookieScope.credentialCookieName(), engine.rotateAfterRefresh(sessionId),
                properties.bindingCookieTtlMs());

        return sessionConfig(request);
    }

    /**
     * Resolves and validates a registration token, returning the session it names.
     *
     * @throws DbscException {@code SESSION_NOT_FOUND} when the token is unknown,
     *         {@code REGISTRATION_TOKEN_CONSUMED} when it was already used, and
     *         {@code REGISTRATION_TOKEN_EXPIRED} when its TTL has passed
     */
    private String requireSessionForToken(String registrationToken) {
        if (registrationToken == null || registrationToken.isBlank()) {
            throw new DbscException(DbscErrorCode.SESSION_NOT_FOUND,
                    "the registration path carries no token");
        }
        RegistrationToken token = storage.getRegistrationToken(registrationToken)
                .orElseThrow(() -> new DbscException(DbscErrorCode.SESSION_NOT_FOUND,
                        "unknown registration token"));
        if (token.consumed()) {
            throw new DbscException(DbscErrorCode.REGISTRATION_TOKEN_CONSUMED,
                    "this registration token has already been used");
        }
        if (token.isExpired(clock.millis())) {
            throw new DbscException(DbscErrorCode.REGISTRATION_TOKEN_EXPIRED,
                    "this registration token has expired");
        }
        return token.sessionId();
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

        // Rotation happens only now, after the signature verified: this returns the
        // ticket to present, which is always a fresh one. The session id itself does not
        // move -- session_identifier names a session, and Chromium keys its store by that
        // name (§7.2), so rotating the value would strand the session.
        String ticket = engine.rotateAfterRefresh(sessionId);

        response.addHeader("Set-Cookie",
                cookieScope.deleteChallengeCookieValue(cookieScope.challengeCookieName()));
        setCookie(response, cookieScope.credentialCookieName(), ticket,
                properties.bindingCookieTtlMs());

        return sessionConfig(request);
    }

    /**
     * Resolves the session identifier on a native refresh: {@code Sec-Secure-Session-Id}
     * (or its legacy alias), falling back to the session cookie.
     *
     * <p>The result is <strong>always</strong> run through the rotation alias table
     * before it is used. A refresh that arrives on a retired id is the normal case
     * while rotation is on -- another tab, a retry, a slow proxy -- and acting on the
     * retired id directly would look up a session record that no longer exists, fail
     * to recognise the still-valid key, and hand back an id the browser would then
     * refresh against forever.
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
        setChallengeCookie(response, cookieScope.challengeCookieName(), challenge.jti(),
                properties.challengeTtlMs());
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }

    // ------------------------------------------------------------------
    // Session resolution
    // ------------------------------------------------------------------

    /**
     * Resolves the DBSC session identifier from the cookie the browser sends.
     *
     * <p>There is exactly one such cookie: the credential one named in
     * {@code credentials[]}, whose value is a ticket. It has to be resolved through the
     * ticket table rather than used directly, because a refresh retires the value it
     * replaces and a request already in flight still carries the old one; the table is
     * what makes that value name the same session during the grace.
     *
     * <p>{@code session_identifier} is deliberately not consulted. It holds a cookie
     * <em>name</em>, and this server mints no cookie of that name — its value is the
     * session id, which is carried nowhere in the request at all. The session id being
     * absent from the cookie jar is the point: it never leaves the server, so there is
     * no long-lived value to lift, and the only thing a thief can take is a ticket that
     * stops resolving shortly after the real browser's next refresh.
     *
     * <p>A cookie proves nothing: it is attacker-supplied on any unauthenticated
     * request, so this only names a candidate session. The caller's proof check is what
     * admits or rejects it. Session discovery on the registration route does <em>not</em>
     * go through here — that route names its session with a token in the path, because
     * it is the one route that runs from a cross-site context where this cookie would be
     * withheld.
     */
    public Optional<String> resolveBinderSession(HttpServletRequest request) {
        String ticket = readCookie(request, cookieScope.credentialCookieName()).orElse(null);
        if (ticket == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(storage.resolveTicket(ticket));
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

    /**
     * Decides whether a request may proceed under DBSC's rules.
     *
     * <p>The rule the caller gets, and the reason it is more than a tier check:
     *
     * <ul>
     *   <li>DBSC cookies present and the session is protected - allowed.</li>
     *   <li>DBSC cookies present and the session is registered but lapsed (or
     *       revoked) - refused.</li>
     *   <li>DBSC cookies present and the session has not registered yet (the window
     *       between {@code bind()} and the browser's registration POST) - allowed.
     *       Calling this a refusal would break every browser that has not finished
     *       registering.</li>
     *   <li>No DBSC cookies, but a binding exists for this application session -
     *       refused. This is the case a bare tier check cannot see: dropping the
     *       DBSC cookies is something the client controls, so it must not be a way
     *       to escape a binding that exists.</li>
     *   <li>No DBSC cookies and no binding for this application session - allowed.
     *       Nothing was ever bound, so DBSC has nothing to add.</li>
     * </ul>
     *
     * <p>Note what this deliberately does <em>not</em> do: it never consults
     * {@link #hasDeviceKey}. A stored key is what a session can reach, not what it
     * currently proves, and a demoted session keeps its key on purpose.
     *
     * @param request   the request under test
     * @param appSessionId the application's own session id for this request, or
     *                  {@code null} when the caller has none. With no id there is
     *                  nothing to look a binding up by, so the no-cookie case is
     *                  treated as unregistered
     */
    public GuardDecision guardDecision(HttpServletRequest request, String appSessionId) {
        Optional<String> dbscSessionId = resolveBinderSession(request);

        if (dbscSessionId.isPresent()) {
            Optional<Session> session = storage.getSession(dbscSessionId.get());
            if (session.isEmpty()) {
                // The cookie names a session that no longer exists: a binding once
                // existed and is gone, which is a lapse, not a fresh client.
                return GuardDecision.deny(GuardDecision.Reason.LAPSED);
            }

            Session found = session.get();
            if (found.isRevoked()) {
                return GuardDecision.deny(GuardDecision.Reason.REVOKED);
            }
            if (engine.effectiveTier(found) == ProtectionTier.DBSC) {
                return GuardDecision.allow(GuardDecision.Reason.PROTECTED);
            }
            if (found.isDemoted()) {
                return GuardDecision.deny(GuardDecision.Reason.LAPSED);
            }
            // Tier none with lastRefreshAt 0: bind() ran but registration has not
            // completed. The browser is still unregistered, not lapsed.
            return unregisteredDecision();
        }

        if (appSessionId == null || appSessionId.isBlank()) {
            return unregisteredDecision();
        }

        Optional<Session> byAppSession = storage.getSessionByAppSessionId(appSessionId);
        if (byAppSession.isEmpty()) {
            return unregisteredDecision();
        }

        // A binding exists for this application session yet the request carried no
        // DBSC cookie. The client dropped them, or never sent them; either way a
        // binding exists, so this is not a fresh client.
        if (byAppSession.get().isRevoked()) {
            return GuardDecision.deny(GuardDecision.Reason.REVOKED);
        }
        return GuardDecision.deny(GuardDecision.Reason.COOKIE_MISSING);
    }

    public Optional<Session> sessionFor(HttpServletRequest request) {
        // resolveBinderSession already resolves the credential ticket to a session id,
        // so a request mid-rotation is a client with a session, not one without.
        return resolveBinderSession(request)
                .flatMap(storage::getSession);
    }

    /**
     * Applies the {@code dbsc.unregistered} policy to a client with no binding.
     *
     * <p>Every "nothing was ever bound" branch funnels through here, so the policy
     * has exactly one implementation. The refusal is still reported as
     * {@link GuardDecision.Reason#UNREGISTERED} rather than as a lapse, so an
     * application can tell "this client cannot do DBSC" apart from "this session
     * stopped proving possession".
     */
    private GuardDecision unregisteredDecision() {
        return properties.getUnregistered() == DbscProperties.Unregistered.DENY
                ? GuardDecision.deny(GuardDecision.Reason.UNREGISTERED)
                : GuardDecision.allow(GuardDecision.Reason.UNREGISTERED);
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private Map<String, Object> sessionConfig(HttpServletRequest request) {
        boolean includeSite = cookieScope.scope() == CookieScope.Scope.SITE;
        return SessionConfig.build(
                OriginResolver.resolve(request, trustForwardedHeaders),
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

    /**
     * Writes the challenge cookie with its own attribute set, which differs from
     * the binding cookie's in {@code SameSite}. See
     * {@link CookieScope#challengeAttributesString()}.
     */
    private void setChallengeCookie(HttpServletResponse response, String name, String value, long maxAgeMs) {
        response.addHeader("Set-Cookie", cookieScope.setChallengeCookieValue(name, value, maxAgeMs));
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
