package click.yukio.dbsc.config;

import click.yukio.dbsc.protocol.CookieScope;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for the DBSC server, prefixed {@code dbsc}.
 *
 * <p>Defaults match the toolkit spec: 10-minute binding cookie, 24-hour
 * registration cookie, 5-minute challenge, and a 30-second refresh grace.
 */
@ConfigurationProperties(prefix = "dbsc")
public class DbscProperties {

    /** Use {@code __Host-} cookies and the {@code Secure} flag. Default true. */
    private boolean secure = true;

    /**
     * Believe {@code X-Forwarded-For} / {@code X-Forwarded-Proto} from the client.
     * Default false, and it must stay false unless a reverse proxy is known to
     * overwrite those headers.
     *
     * <p>These drive the {@code scope.origin} written into the JSON config, and the
     * origin reported when a session is terminated. They are trivially forgeable by
     * anyone who can reach the application directly, and a forged origin is handed
     * to the browser as the scope a session is bound to. It is therefore separate
     * from {@link #secure}: terminating TLS with {@code secure} on does not imply
     * that a trusted proxy is stripping inbound forwarding headers.
     */
    private boolean trustForwardedHeaders = false;

    /** {@code host} (default) or {@code site}. */
    private CookieScope.Scope cookieScope = CookieScope.Scope.HOST;

    /**
     * The {@code Domain} attribute attached to every DBSC cookie when
     * {@code cookieScope} is {@code site}. Typically the registrable apex
     * ({@code example.com}). Omit the leading dot. Required for site scope.
     */
    private String cookieDomain;

    /**
     * Path prefix Chromium POSTs a registration JWS to. The registration header
     * advertises {@code <prefix>/<token>}, where the token names the session, so
     * the route is dynamic rather than a single fixed path.
     */
    private String registrationPath = "/dbsc/regist";

    /** Path Chromium POSTs a refresh JWS to, and the value of {@code refresh_url}. */
    private String refreshPath = "/dbsc/refresh";

    /**
     * Path a JavaScript client POSTs to in order to be re-offered a registration.
     *
     * <p>This route is for clients that do their own key management instead of the
     * browser's, and it exists to solve an ordering problem the native flow does not
     * have: such a client can only register once its own code is running, which may be
     * arbitrarily later than the login response that carried the offer. Rather than
     * hold an offer from a response it may not have been able to read, it asks for a
     * fresh one here.
     *
     * <p>It answers with the same {@code Secure-Session-Registration} and
     * {@code Secure-Session-Challenge} headers {@code bind()} writes, so a script reads
     * the identical wire format and POSTs to the identical registration path. The
     * session is named by the application's own session cookie — this route is
     * authenticated — rather than by a token in the path, because the client is already
     * logged in by the time it can ask.
     */
    private String bindPath = "/dbsc/bind";

    /**
     * Soft DBSC: the JavaScript fallback for browsers with no native support.
     */
    private Soft soft = new Soft();

    /**
     * Settings for Soft DBSC, the script-driven fallback.
     *
     * <p>"Soft" because the key is not hardware-backed: it is a WebCrypto key in
     * IndexedDB, reachable by any script on the origin, so it is an oracle rather
     * than a secret. It is a different tier from the native one precisely because
     * it proves less. It is on by default because a browser with no native DBSC
     * would otherwise get nothing, but it is a deployment decision rather than a
     * free win — see the README's "Soft DBSC" section for what it does and does not
     * buy.
     */
    public static class Soft {

        /**
         * Whether the fallback is offered at all. Default true.
         *
         * <p>Off means the re-offer route is not registered, so {@code POST
         * bind-path} is a 404 and no client can start a soft binding. The device
         * key table and the native path are unaffected either way: a session that
         * registered natively keeps working, and turning this off does not
         * invalidate an existing soft key.
         *
         * <p>The default is true because the alternative is worse in practice on the
         * browsers this exists for. A browser with no native DBSC — Safari, Firefox —
         * gets no protection at all rather than the weaker protection this offers, and
         * a deployment that never noticed the property would simply have an inert
         * feature. It still widens the trust model, so the trade is worth knowing: a
         * stolen cookie cannot be replayed without the key, but the key now lives
         * where an XSS can use it. Deployments that would rather not make that trade
         * set this to false, and the route stops existing.
         */
        private boolean enabled = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /**
     * The cookie named in the JSON config's {@code credentials[]} and protected by
     * the binding (spec §9.6).
     *
     * <p>Its value is a rotating ticket, not the DBSC session id: a refresh mints a
     * new one and the retired one keeps resolving for {@link #rotationGrace}. That
     * that is what puts a clock on a captured cookie — see the README's credential
     * rotation section.
     *
     * <p>The full name is used verbatim. Whether it carries a {@code __Host-} or
     * {@code __Secure-} prefix is the deployer's decision, not something the library
     * adds.
     */
    private String credentialCookieName = "__Host-auth_cookie";

    /**
     * The {@code SameSite} attribute on the credential cookie, and on nothing else.
     *
     * <p>{@code Lax} unless set. The value is written into both the real {@code Set-Cookie}
     * header and {@code credentials[].attributes}, which Chromium compares against the
     * real cookie (§8.6); the two cannot drift because they come from one place.
     *
     * <p>{@code Strict} is safe only when nothing ever lands on a DBSC route directly
     * from another site — a login that returns from an identity provider does, so it is
     * withheld and the application sees an unauthenticated request. {@code None} requires
     * {@code secure=true} (validated at startup, because the browser otherwise rejects
     * the cookie silently) and hands the credential to cross-site callers, which is what
     * the default avoids.
     */
    private CookieScope.SameSite cookieSameSite = CookieScope.SameSite.LAX;

    /**
     * The {@code Path} attribute on the credential cookie.
     *
     * <p>{@code /} unless set. Narrowing it means the credential is not sent to routes
     * outside that path, which is a mild reduction in what a network attacker could
     * capture. It must be an absolute path starting with {@code /} — the browser
     * normalises relative values, and the result would no longer match the string
     * advertised in {@code credentials[].attributes}, so the binding would never
     * complete. It must also cover the registration route, or the registration POST
     * cannot present the credential.
     */
    private String cookiePath = CookieScope.DEFAULT_PATH;

    /**
     * Whether the credential cookie carries {@code HttpOnly}.
     *
     * <p>True unless set to false. {@code HttpOnly} stops page script reading the
     * credential, which is the point of it; a script client does not need it turned off,
     * because a Service Worker has no access to the cookie jar either. Leave it alone
     * unless a deployment has a specific reason, and treat turning it off as widening the
     * XSS surface to include the credential itself.
     */
    private boolean cookieHttpOnly = true;

    /**
     * Grace window applied after the binding cookie expires.
     */
    private Duration bindingCookieTtl = Duration.ofMinutes(10);

    /**
     * Lifetime of a registration token, and so of the registration opportunity.
     *
     * <p>Five minutes, not hours, and deliberately the same span as a challenge. The
     * window this value bounds is not how long a user may take to log in — it is how
     * long one already-issued token stays usable, and Chromium POSTs its registration
     * within about a second of the login response (02, step 2). The token is spent on
     * the attempt, success or failure, so a short ceiling costs a real browser
     * nothing while denying a captured token a long retry window.
     */
    private Duration registrationTokenTtl = Duration.ofMinutes(5);

    /** Lifetime of a challenge JTI. */
    private Duration challengeTtl = Duration.ofMinutes(5);

    /**
     * Grace window applied after the binding cookie expires, so a freshness poll
     * during the in-flight gap before the browser's next refresh does not see
     * {@code tier: none} and false-alarm an auto-logout.
     */
    private Duration refreshGrace = Duration.ofSeconds(30);

    /** Default lifetime assigned by {@code bind()} when the caller does not set one. */
    private Duration sessionTtl = Duration.ofDays(7);

    /** How the guard treats a request from a client with no DBSC binding at all. */
    private Unregistered unregistered = Unregistered.ALLOW;

    /**
     * How long a retired DBSC session id keeps resolving to the id that replaced it.
     *
     * <p>Rotation itself is not optional: the DBSC session id is replaced on every
     * successful refresh, unconditionally. What is configurable is how long the
     * <em>previous</em> id goes on working, because a browser only learns the new id
     * from the refresh response and a second tab will be holding the old one. That
     * window is exactly the exposure rotation removes, so it is the one value worth
     * tuning: set it to the longest gap between refresh attempts that must not fail.
     */
    private Duration rotationGrace = Duration.ofSeconds(60);

    /**
     * Rules narrowing or widening which URLs the session covers, written into the JSON
     * config's {@code scope.scope_specification} (spec §9.8).
     *
     * <p>Scope is decided by the browser, not by this server: the list only tells the
     * user agent where to attach the DBSC credential and when to refresh. Each rule has a
     * {@code type} ({@code include} or {@code exclude}), a {@code domain} pattern, and a
     * {@code path} prefix; the browser walks the list in <em>reverse</em>, so later rules
     * win (§8.2). That makes the natural spelling outermost-first: exclude a broad area,
     * then include the part of it that matters.
     *
     * <p>Empty by default, which means the whole origin (or site, when
     * {@link #cookieScope} is {@code site}) is in scope. The array order in YAML is
     * preserved as written.
     */
    private List<ScopeSpecification> scopeSpecifications = new ArrayList<>();

    /**
     * Hosts outside the session scope that may still trigger a DBSC refresh, written into
     * the JSON config's {@code allowed_refresh_initiators} (spec §9.6, §8.3).
     *
     * <p>An out-of-scope request can normally trigger a refresh, which is how a
     * cross-origin fetch to a protected endpoint ends up blocking on the refresh URL and
     * thereby leaking whether the user is logged in, through timing alone (§3.2). Listing
     * the embedding or calling hosts here confines that to the ones that need it; every
     * other initiator gets no refresh, so there is no timing signal to measure.
     *
     * <p>Each entry is a host or host pattern: {@code *} matches everything,
     * {@code *.example.com} matches subdomains of {@code example.com} but not
     * {@code example.com} itself, and a bare host matches only itself (§8.4). In-scope
     * requests are allowed regardless, so the list is about out-of-scope callers only.
     *
     * <p>Empty by default: no out-of-scope host may refresh.
     */
    private List<String> allowedRefreshInitiators = new ArrayList<>();

    /**
     * A fixed origin written into the JSON config's {@code scope.origin}, overriding
     * whatever the request (or its forwarded headers) appears to say.
     *
     * <p>Leave it unset: the origin is normally derived from the request, which is the
     * only value that can be right for every deployment. Set it only when that derivation
     * is known to produce the wrong answer — a proxy that rewrites the host to an internal
     * name, or a CDN that sets no forwarding header this library reads. Turning on
     * {@link #trustForwardedHeaders} is the other remedy, and a safer one where it applies,
     * because it stays correct if the public name changes.
     *
     * <p>It must be an absolute origin with no path — {@code https://example.com} or
     * {@code https://example.com:8443} — or an {@code http} origin for development. The
     * scheme is used verbatim: unlike the derived path, there is no way to correct it from
     * the request. A mismatch against the real origin is invisible on the wire: Chromium
     * discards the session while the server still answers 200, so this is validated at
     * startup rather than left to fail silently.
     */
    private String scopeOrigin;

    /**
     * One entry of {@code scope.scope_specification} (spec §9.8).
     *
     * <p>The {@code domain} and {@code path} fields are optional in the spec: an absent
     * domain means {@code *} (every host) and an absent path means {@code /} (every path).
     * Both defaults are filled in when the JSON is rendered, so a rule is never emitted
     * with a key the browser would have to default itself.
     */
    public static class ScopeSpecification {

        /** {@code include} adds the match to the scope, {@code exclude} removes it. */
        public enum Type {
            INCLUDE,
            EXCLUDE
        }

        private Type type = Type.INCLUDE;
        private String domain;
        private String path;

        public Type getType() {
            return type;
        }

        public void setType(Type type) {
            this.type = type;
        }

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }
    }

    /**
     * What the guard does with a client that has no DBSC binding.
     *
     * <p>This is separate from {@code cookieScope} and the other protocol settings:
     * it is policy, not protocol. The distinction matters because it decides whether
     * the library is an additional layer or a requirement.
     */
    public enum Unregistered {
        /**
         * Let it through. DBSC is additive: a browser without support for the
         * protocol, and a client that has logged in but not yet registered, both
         * look like this, and neither should be locked out of the application.
         * This is the default, and it is what makes a guard matcher covering
         * every route a reasonable thing to write.
         */
        ALLOW,
        /**
         * Refuse it with {@code 403 DBSC_REQUIRED}. DBSC becomes a requirement:
         * every browser that does not support the protocol is locked out, so this
         * is only appropriate when the client population is known to be capable.
         * A session that registered and then <em>lapsed</em> is refused either way.
         */
        DENY
    }

    public boolean isSecure() {
        return secure;
    }

    public void setSecure(boolean secure) {
        this.secure = secure;
    }

    public boolean isTrustForwardedHeaders() {
        return trustForwardedHeaders;
    }

    public void setTrustForwardedHeaders(boolean trustForwardedHeaders) {
        this.trustForwardedHeaders = trustForwardedHeaders;
    }

    public CookieScope.Scope getCookieScope() {
        return cookieScope;
    }

    public void setCookieScope(CookieScope.Scope cookieScope) {
        this.cookieScope = cookieScope;
    }

    public String getCookieDomain() {
        return cookieDomain;
    }

    public void setCookieDomain(String cookieDomain) {
        this.cookieDomain = cookieDomain;
    }

    public String getRegistrationPath() {
        return registrationPath;
    }

    public void setRegistrationPath(String registrationPath) {
        this.registrationPath = registrationPath;
    }

    public String getRefreshPath() {
        return refreshPath;
    }

    public void setRefreshPath(String refreshPath) {
        this.refreshPath = refreshPath;
    }

    public String getBindPath() {
        return bindPath;
    }

    public void setBindPath(String bindPath) {
        this.bindPath = bindPath;
    }

    public Soft getSoft() {
        return soft;
    }

    public void setSoft(Soft soft) {
        this.soft = soft;
    }

    public String getCredentialCookieName() {
        return credentialCookieName;
    }

    public void setCredentialCookieName(String credentialCookieName) {
        this.credentialCookieName = credentialCookieName;
    }

    public CookieScope.SameSite getCookieSameSite() {
        return cookieSameSite;
    }

    public void setCookieSameSite(CookieScope.SameSite cookieSameSite) {
        this.cookieSameSite = cookieSameSite;
    }

    public String getCookiePath() {
        return cookiePath;
    }

    public void setCookiePath(String cookiePath) {
        this.cookiePath = cookiePath;
    }

    public boolean isCookieHttpOnly() {
        return cookieHttpOnly;
    }

    public void setCookieHttpOnly(boolean cookieHttpOnly) {
        this.cookieHttpOnly = cookieHttpOnly;
    }

    public Duration getBindingCookieTtl() {
        return bindingCookieTtl;
    }

    public void setBindingCookieTtl(Duration bindingCookieTtl) {
        this.bindingCookieTtl = bindingCookieTtl;
    }

    public Duration getRegistrationTokenTtl() {
        return registrationTokenTtl;
    }

    public void setRegistrationTokenTtl(Duration registrationTokenTtl) {
        this.registrationTokenTtl = registrationTokenTtl;
    }

    public Duration getChallengeTtl() {
        return challengeTtl;
    }

    public void setChallengeTtl(Duration challengeTtl) {
        this.challengeTtl = challengeTtl;
    }

    public Duration getRefreshGrace() {
        return refreshGrace;
    }

    public void setRefreshGrace(Duration refreshGrace) {
        this.refreshGrace = refreshGrace;
    }

    public Duration getSessionTtl() {
        return sessionTtl;
    }

    public void setSessionTtl(Duration sessionTtl) {
        this.sessionTtl = sessionTtl;
    }

    public Unregistered getUnregistered() {
        return unregistered;
    }

    public void setUnregistered(Unregistered unregistered) {
        this.unregistered = unregistered;
    }

    public Duration getRotationGrace() {
        return rotationGrace;
    }

    public void setRotationGrace(Duration rotationGrace) {
        this.rotationGrace = rotationGrace;
    }

    public List<ScopeSpecification> getScopeSpecifications() {
        return scopeSpecifications;
    }

    public void setScopeSpecifications(List<ScopeSpecification> scopeSpecifications) {
        this.scopeSpecifications = scopeSpecifications == null ? new ArrayList<>() : scopeSpecifications;
    }

    public List<String> getAllowedRefreshInitiators() {
        return allowedRefreshInitiators;
    }

    public void setAllowedRefreshInitiators(List<String> allowedRefreshInitiators) {
        this.allowedRefreshInitiators =
                allowedRefreshInitiators == null ? new ArrayList<>() : allowedRefreshInitiators;
    }

    public String getScopeOrigin() {
        return scopeOrigin;
    }

    public void setScopeOrigin(String scopeOrigin) {
        this.scopeOrigin = scopeOrigin;
    }

    // ---- Derived values, in milliseconds ----

    public long bindingCookieTtlMs() {
        return bindingCookieTtl.toMillis();
    }

    public long registrationTokenTtlMs() {
        return registrationTokenTtl.toMillis();
    }

    public long challengeTtlMs() {
        return challengeTtl.toMillis();
    }

    public long refreshGraceMs() {
        return refreshGrace.toMillis();
    }

    public long sessionTtlMs() {
        return sessionTtl.toMillis();
    }

    public long rotationGraceMs() {
        return rotationGrace.toMillis();
    }
}
