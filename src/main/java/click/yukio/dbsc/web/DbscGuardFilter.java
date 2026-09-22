package click.yukio.dbsc.web;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.core.GuardDecision;
import click.yukio.dbsc.core.Json;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;
import java.util.Map;

/**
 * Requires the requests it guards to ride a session DBSC currently protects.
 *
 * <p>This is the enforcement half of the library. {@link DbscFilter} serves the
 * protocol and stops there; nothing in it looks at an application route. This
 * filter is the one place where the session state DBSC recorded is turned into a
 * status code on a route that is not DBSC's own.
 *
 * <p>The check is deliberately about the <em>tier</em>, not the presence of a
 * key. A session has a key from the moment the browser registers, but
 * {@code ProtectionTier} demotes it to {@code none} the moment a refresh window
 * passes without a successful signature — which is what a session hijacked away
 * from its device looks like from here. Reading the stored key instead would
 * report protection that has already lapsed.
 *
 * <p>The decision itself is made by {@link DbscService#guardDecision}, which also
 * covers the case a tier check alone cannot: a request that presents no DBSC
 * cookie at all, while a binding exists for its application session. Dropping a
 * cookie is something the client controls, so "no cookie" must not silently mean
 * "no binding" — otherwise a stolen session id could escape its binding by
 * omitting the DBSC cookies, and a client that never registered would be
 * indistinguishable from one that did.
 *
 * <p>Which session is being asked about comes from the DBSC cookies, not from the
 * application's own session cookie. The two are different identifiers on purpose:
 *
 * <pre>
 * JSESSIONID=72234F6E…             the application's session
 * __Host-auth_cookie=0Jp36T8T…     the rotating credential for the binding
 * __Host-dbsc-challenge=…          the single-use JTI to sign
 * </pre>
 *
 * <p>The registration route is not in this list on purpose: it names its session
 * with a single-use token in the <em>path</em> ({@code /dbsc/regist/<token>}), not
 * with a cookie, so that it keeps working when the browser's registration POST is
 * issued from a cross-site navigation context.
 *
 * <p>The DBSC id is what identifies the session record and the device key, and it
 * is whatever the login route passed to {@code bind()} — it carries no relationship
 * to the application's session id, so nothing here assumes they match. The
 * application's session id is read too, but only as a second way to find a binding
 * the request failed to present.
 *
 * <p><strong>A refusal here is a step-up prompt, not a login redirect.</strong>
 * The response is a 403 carrying {@code DBSC_REQUIRED}, so the application can
 * ask the user to re-authenticate rather than treating them as signed out. A
 * 401 would also be wrong for a subtler reason: Chromium treats it as fatal on
 * the refresh route and terminates the session, and this filter runs in the same
 * chain.
 *
 * <p>Which requests it runs on is declared with a {@link DbscGuardRoutes} bean. Guard
 * nothing by default: with no such bean the filter is a no-op, and declaring one is
 * what opts in. The matcher decides only <em>where</em> the question is asked; what
 * the answer is — and so whether an unregistered client is allowed through — is
 * {@link DbscService#guardDecision}'s, and is configured separately.
 */
public class DbscGuardFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DbscGuardFilter.class);

    /** The error code a refused request carries, for the application to key on. */
    public static final String REQUIRED_CODE = "DBSC_REQUIRED";

    private final DbscService dbsc;
    private final RequestMatcher guardRoutes;

    /**
     * @param guardRoutes the requests to guard. Matched with a Spring Security
     *                    {@link RequestMatcher}, so patterns like {@code /api/**} work
     *                    the same way they do in {@code authorizeHttpRequests}
     */
    public DbscGuardFilter(DbscService dbsc, RequestMatcher guardRoutes) {
        this.dbsc = dbsc;
        this.guardRoutes = guardRoutes;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !guardRoutes.matches(request);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // The decision itself lives in DbscService.guardDecision: it needs the
        // session store and the storage contract, and keeping it out of the filter
        // means an application that checks the tier inline gets the same answer.
        GuardDecision decision = dbsc.guardDecision(request, appSessionId(request));
        if (!decision.allowed()) {
            deny(response, decision);
            return;
        }

        log.debug("DBSC guard: {} {} allowed ({})", request.getMethod(),
                request.getRequestURI(), decision.reason());
        chain.doFilter(request, response);
    }

    /**
     * The application's own session id, used to recognise a client that has a
     * binding but sent no DBSC cookie.
     *
     * <p>This deliberately reads the servlet session rather than the authenticated
     * principal: the id must be the one the login route passed to {@code bind()},
     * and that is the {@code HttpSession} id. A request with no session simply has
     * no id to look up, and the decision falls back to treating it as unregistered.
     */
    private static String appSessionId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? null : session.getId();
    }

    private void deny(HttpServletResponse response, GuardDecision decision) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("DBSC guard -> 403: {}", decision.reason());
        }
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(Json.write(Map.of(
                "error", REQUIRED_CODE,
                "message", message(decision.reason()))));
        response.flushBuffer();
    }

    private static String message(GuardDecision.Reason reason) {
        return switch (reason) {
            case LAPSED -> "the session is not currently device bound";
            case COOKIE_MISSING -> "a DBSC binding exists for this session but the request carried no DBSC cookie";
            case REVOKED -> "the DBSC binding was terminated";
            // Neither is reachable from the filter, which only ever sees a refusal;
            // listed so the switch stays exhaustive without a default.
            case PROTECTED, UNREGISTERED -> "the session is not currently device bound";
        };
    }
}
