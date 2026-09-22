package click.yukio.dbsc.config;

import click.yukio.dbsc.protocol.CookieScope;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

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
     * Grace window applied after the binding cookie expires.
     */
    private Duration bindingCookieTtl = Duration.ofMinutes(10);

    /** Lifetime of a registration token, and so of the registration opportunity. */
    private Duration registrationCookieTtl = Duration.ofHours(24);

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

    public Duration getBindingCookieTtl() {
        return bindingCookieTtl;
    }

    public void setBindingCookieTtl(Duration bindingCookieTtl) {
        this.bindingCookieTtl = bindingCookieTtl;
    }

    public Duration getRegistrationCookieTtl() {
        return registrationCookieTtl;
    }

    public void setRegistrationCookieTtl(Duration registrationCookieTtl) {
        this.registrationCookieTtl = registrationCookieTtl;
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

    // ---- Derived values, in milliseconds ----

    public long bindingCookieTtlMs() {
        return bindingCookieTtl.toMillis();
    }

    public long registrationCookieTtlMs() {
        return registrationCookieTtl.toMillis();
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
}
