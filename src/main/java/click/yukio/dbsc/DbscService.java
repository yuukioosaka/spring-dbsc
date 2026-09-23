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
    private final Clock clock;
    private final boolean trustForwardedHeaders;

    public DbscService(
            DbscProperties properties,
            StorageAdapter storage,
            ChallengeService challenges,
            DbscProtocolEngine engine,
            CookieScope cookieScope,
            Clock clock,
            boolean trustForwardedHeaders) {
        this.properties = properties;
        this.storage = storage;
        this.challenges = challenges;
        this.engine = engine;
        this.cookieScope = cookieScope;
        this.clock = clock;
        this.trustForwardedHeaders = trustForwardedHeaders;
    }

    // ------------------------------------------------------------------
    // Binding (called by the login route)
    // ------------------------------------------------------------------

    /**
     * Starts a DBSC session: persists the session record, mints a single-use
     * registration token, and primes the browser with the registration header and
     * the challenge header. Chromium then POSTs the registration JWS on its own,
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

        // The challenge travels to the browser only as the JTI inside the registration
        // header the user agent signs; it is already persisted server-side against the
        // session, so registration finds it by session id rather than by any cookie.
        // Emitting it here as a challenge header (spec §8.7, §9.2) makes the value the
        // browser should sign explicit, without asking it to hold state of ours.
        addChallengeHeader(response, challenge.jti(), session.id());

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
                now + properties.registrationTokenTtlMs(),
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
        return SessionConfig.terminated(
                OriginResolver.resolve(request, trustForwardedHeaders, properties.getScopeOrigin()),
                properties.getRefreshPath(), sessionId, cookieScope, properties);
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
        String sessionId = requireSessionForToken(registrationToken);
        String responseHeader = readResponseHeader(request);

        // The token is spent on the attempt, not on the success. A registration POST
        // is issued by Chromium within about a second of the login response (02 step 2)
        // and is never retried — not after a network error and not after a rejected
        // proof — so a token that only a success consumes has exactly one client that
        // will ever present it, and a short TTL costs that client nothing.
        //
        // Consuming it here rather than after the verification also closes the window
        // the previous ordering left open: the route is unauthenticated, nothing else
        // stands between an attacker and unlimited verification attempts on a captured
        // token, and each attempt is an ECDSA verification against a header-supplied
        // key. Spending the token first makes an invalid proof unusable the moment it
        // is rejected.
        //
        // Consuming — not deleting — leaves the record for the failure path to report a
        // replay as REGISTRATION_TOKEN_CONSUMED rather than as an unknown token, which
        // is the difference between "you are replaying a captured POST" and "this URL
        // was never ours".
        storage.consumeRegistrationToken(registrationToken);

        engine.handleRegistration(sessionId, responseHeader);

        // Registration is the one place the credential cookie is dropped rather than
        // replaced. Until now the browser held a ticket that predates the binding; the
        // correct move is to stop honouring it, so a pre-registration value cannot
        // survive into the session it was meant for.
        storage.deleteTicket(readCookie(request, cookieScope.credentialCookieName()).orElse(null));
        setCookie(response, cookieScope.credentialCookieName(), engine.rotateAfterRefresh(sessionId),
                properties.bindingCookieTtlMs());

        // The session's challenge was consumed by the registration, and the spec has the
        // server re-issue one on every registration response (§8.7): without it the
        // session has nothing to refresh against, because there is no challenge cookie
        // to fall back to and the browser would be asked to sign a value the server no
        // longer holds.
        rearmChallenge(response, sessionId);

        return sessionConfig(sessionId, request);
    }

    /**
     * Resolves and validates a registration token, returning the session it names.
     *
     * <p>This only reads; the caller spends the token. Keeping the two apart is what
     * lets the token be consumed before the proof is verified — the lookup has to
     * succeed first, and a token that is unknown or already spent must be reported as
     * such without a verification attempt.
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
        // The binding cookie is gone by the time a refresh runs, so the session
        // identifier arrives in a header. The challenge is held server-side against
        // that session; the browser carries only the signed value, in the proof.
        String sessionId = resolveRefreshSessionId(request);

        String responseHeader = readResponseHeader(request);
        if (responseHeader == null || responseHeader.isBlank()) {
            // First leg: no proof yet. Issue a challenge and answer 403.
            requireBoundSession(sessionId);
            issueChallengeAndReject(response, sessionId);
            return null;
        }

        engine.handleRefresh(sessionId, responseHeader);

        // Rotation happens only now, after the signature verified: this returns the
        // ticket to present, which is always a fresh one. The ticket has no other role
        // -- the session was identified by the header above, and nothing here depends
        // on the ticket the browser was carrying.
        String ticket = engine.rotateAfterRefresh(sessionId);

        setCookie(response, cookieScope.credentialCookieName(), ticket,
                properties.bindingCookieTtlMs());

        // A 200 that carried no challenge would leave the session with nothing to sign
        // on the next cadence: the challenge just verified was consumed, and there is no
        // challenge cookie holding the next one. Re-issuing here is what makes the
        // session refreshable more than once (§8.7).
        rearmChallenge(response, sessionId);

        return sessionConfig(sessionId, request);
    }

    /**
     * Resolves the session identifier on a native refresh, from the
     * {@code Sec-Secure-Session-Id} header (or its legacy alias) and from nothing else.
     *
     * <p>The credential cookie is deliberately <strong>not</strong> consulted. Its value
     * is a ticket that rotates on every refresh, so it names a ticket rather than a
     * session, and a refresh that fell back to it would be resolving a session by a
     * value whose whole purpose is to stop being one. The header is what the spec sends
     * on this route (§9.4, toolkit 02 L149: "The session identifier comes from the
     * {@code Sec-Secure-Session-Id} header, <strong>not</strong> from a cookie"); a
     * refresh without it has no session to act on.
     */
    private String resolveRefreshSessionId(HttpServletRequest request) {
        String sessionId = request.getHeader(DbscHeaders.SESSION_ID);
        if (sessionId == null || sessionId.isBlank()) {
            // The legacy alias is accepted inbound and is not a fallback to anything
            // else: either name carries the session id, or the request is refused.
            sessionId = request.getHeader(DbscHeaders.LEGACY_SESSION_ID);
        }
        // Spec 09.4 types this as an sf-string, so it may arrive quoted; unquoting is
        // not optional, or the quotes become part of the id and every lookup misses.
        sessionId = DbscHeaderCodec.parseStructuredString(sessionId);
        if (sessionId == null || sessionId.isBlank()) {
            throw new DbscException(DbscErrorCode.SESSION_NOT_FOUND,
                    "refresh requires the " + DbscHeaders.SESSION_ID + " header");
        }
        return sessionId;
    }

    /**
     * Verifies that the session named by {@code Sec-Secure-Session-Id} exists and can
     * still refresh, before anything is issued against it.
     *
     * <p>The header is client-supplied and unauthenticated, and the value goes on to
     * name a record: without this check, a request naming any string at all would
     * persist a challenge for it. The record is small and expires, but nothing bounds
     * the number of distinct ids — the storage contract has no eviction — so a client
     * willing to spend the round trips can create rows without limit. Deployments that
     * need that bounded should do it at the edge, where the whole unauthenticated
     * surface can be shaped at once.
     *
     * <p>The rule is existence plus a key, which is what spec 02 step 2 makes
     * normative for a refresh ({@code KEY_NOT_FOUND_NATIVE}): a session that was never
     * bound has no key to verify a proof against, so there is nothing to challenge it
     * for. Asking for a proof from a session that cannot produce one tells the caller
     * nothing, while a challenge issued to an unknown id is pure attack surface.
     *
     * <p>A session that is merely demoted still has its key and passes: the refresh
     * cadence is exactly how a demoted session climbs back, so it has to reach this
     * route. Only a session with no key — unknown, or bound and then cleared — is
     * refused.
     *
     * <p>Note the deliberate absence of a Cookie header on this leg. Hardening
     * {@code SameSite=Lax} to {@code Strict} would cost the browser nothing if the
     * refresh POST never carried a cookie, which is what a flow with no challenge
     * cookie should look like; but nothing in this implementation depends on it, so it
     * is an observation for a future change rather than a requirement today.
     *
     * <p>A refusal is reported as {@code SESSION_NOT_FOUND} /
     * {@code KEY_NOT_FOUND} and maps to the same 403 as any other rejected refresh, so
     * a caller cannot use the status to tell an unknown session from one whose proof
     * failed. That indistinguishability is intentional on an unauthenticated route
     * that is reachable without a cookie, which makes it worth a client's time to
     * enumerate session ids against it.
     *
     * @throws DbscException {@code SESSION_NOT_FOUND} when no session carries this id,
     *         {@code KEY_NOT_FOUND} when it carries no device key
     */
    private void requireBoundSession(String sessionId) {
        if (storage.getSession(sessionId).isEmpty()) {
            throw new DbscException(DbscErrorCode.SESSION_NOT_FOUND,
                    "refresh names a session that does not exist");
        }
        if (storage.getDeviceKey(sessionId).isEmpty()) {
            throw new DbscException(DbscErrorCode.KEY_NOT_FOUND,
                    "no device key for session");
        }
    }

    /**
     * Issues a fresh challenge with a 403. The status is 403 by spec:
     * Chromium ignores 401 here.
     */
    public void issueChallengeAndReject(HttpServletResponse response, String sessionId) {
        Challenge challenge = challenges.issue(sessionId);
        addChallengeHeader(response, challenge.jti(), sessionId);
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
     * <p>{@code session_identifier} is deliberately not consulted: it is the browser's
     * store key, not a cookie, so nothing of that name is ever on the request. The
     * session id is carried nowhere in the request at all — being absent from the cookie
     * jar is the point: it never leaves the server, so there is no long-lived value to
     * lift, and the only thing a thief can take is a ticket that stops resolving shortly
     * after the real browser's next refresh.
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

    private Map<String, Object> sessionConfig(String sessionId, HttpServletRequest request) {
        boolean includeSite = cookieScope.scope() == CookieScope.Scope.SITE;
        return SessionConfig.build(
                OriginResolver.resolve(request, trustForwardedHeaders, properties.getScopeOrigin()),
                properties.getRefreshPath(),
                sessionId,
                cookieScope,
                includeSite,
                properties);
    }

    private String readResponseHeader(HttpServletRequest request) {
        String value = request.getHeader(DbscHeaders.RESPONSE);
        if (value == null || value.isBlank()) {
            value = request.getHeader(DbscHeaders.LEGACY_RESPONSE);
        }
        // Also an sf-string (spec 09.3): a quoted JWS must not keep its quotes, or the
        // JWS parser sees a malformed token.
        return DbscHeaderCodec.parseStructuredString(value);
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
     * Emits the {@code Secure-Session-Challenge} header (and its legacy alias) naming
     * the JTI and the session it belongs to (spec §9.2). The value is also stored
     * against the session, which is what registration and refresh look it back up by.
     */
    private void addChallengeHeader(HttpServletResponse response, String jti, String sessionId) {
        String challengeHeader = DbscHeaderCodec.buildChallengeHeader(jti, sessionId);
        response.addHeader(DbscHeaders.CHALLENGE, challengeHeader);
        response.addHeader(DbscHeaders.LEGACY_CHALLENGE, challengeHeader);
    }

    /**
     * Issues a fresh challenge for the session and hands it to the browser in the
     * {@code Secure-Session-Challenge} header, keeping it server-side.
     *
     * <p>This is the only way a client ever learns a JTI, now that there is no challenge
     * cookie: the server holds the value against the session and re-issues one whenever
     * the previous one has been spent. Both the registration response and the successful
     * refresh response call it, which is what lets a session refresh repeatedly rather
     * than exactly once (§8.7).
     */
    private void rearmChallenge(HttpServletResponse response, String sessionId) {
        Challenge challenge = challenges.issue(sessionId);
        addChallengeHeader(response, challenge.jti(), sessionId);
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
