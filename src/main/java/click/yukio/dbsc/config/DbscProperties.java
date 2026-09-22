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
     * <p>These drive the client IP used for rate limiting. They are trivially
     * forgeable by anyone who can reach the application directly, and a forged IP
     * gets a fresh rate-limit budget, which defeats the limiter entirely. It is
     * therefore separate from {@link #secure}: terminating TLS with {@code secure} on
     * does not imply that a trusted proxy is stripping inbound forwarding headers.
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

    /** Rate limiting for the unauthenticated registration/refresh surface. */
    private RateLimit rateLimit = new RateLimit();

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

    /**
     * Rate limiting is a SHOULD, not a MUST: the spec leaves the algorithm out of
     * scope. Enabled by default so a public deployment is not trivially abusable.
     */
    public static class RateLimit {
        private boolean enabled = true;

        /** Requests allowed per window, per client IP, for the auth endpoints. */
        private int capacity = 30;

        /**
         * <em>Failed</em> attempts allowed per window. A client that exceeds this
         * is throttled even while well under {@code capacity}, so an attacker
         * guessing proofs is stopped long before legitimate request volume would
         * stop it. Defaults to half of {@code capacity}.
         */
        private int failureCapacity = 15;

        /** Window the capacity applies to. */
        private Duration window = Duration.ofMinutes(1);

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getCapacity() {
            return capacity;
        }

        public void setCapacity(int capacity) {
            this.capacity = capacity;
        }

        public int getFailureCapacity() {
            return failureCapacity;
        }

        public void setFailureCapacity(int failureCapacity) {
            this.failureCapacity = failureCapacity;
        }

        public Duration getWindow() {
            return window;
        }

        public void setWindow(Duration window) {
            this.window = window;
        }
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

    public String getCredentialCookieName() {
        return credentialCookieName;
    }

    public void setCredentialCookieName(String credentialCookieName) {
        this.credentialCookieName = credentialCookieName;
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

    public RateLimit getRateLimit() {
        return rateLimit;
    }

    public void setRateLimit(RateLimit rateLimit) {
        this.rateLimit = rateLimit;
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
