package click.yukio.dbsc.web;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.core.Json;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
 * {@link ProtectionTier} demotes it to {@code none} the moment a refresh window
 * passes without a successful signature — which is what a session hijacked away
 * from its device looks like from here. Reading the stored key instead would
 * report protection that has already lapsed.
 *
 * <p>Which session is being asked about comes from the DBSC cookies, not from the
 * application's own session cookie:
 *
 * <pre>
 * JSESSIONID=72234F6E…        the application's session
 * __Host-dbsc-reg=72234F6E…   pre-registration, carries the session id
 * __Host-dbsc-session=72234F6E…  the binding, established at registration
 * </pre>
 *
 * <p>In the common case all three carry the same id, because {@code bind()} is
 * called with the application's session id. The DBSC cookie is what is read
 * because that is the one bound to the key; the application cookie is only
 * presumed to match.
 *
 * <p><strong>A refusal here is a step-up prompt, not a login redirect.</strong>
 * The response is a 403 carrying {@code DBSC_REQUIRED}, so the application can
 * ask the user to re-authenticate rather than treating them as signed out. A
 * 401 would also be wrong for a subtler reason: Chromium treats it as fatal on
 * the refresh route and terminates the session, and this filter runs in the same
 * chain.
 *
 * <p>Guard no paths by default. Declaring a {@link GuardedRoute} per route is
 * what opts in, and the filter is a no-op — one list lookup — until then.
 */
public class DbscGuardFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DbscGuardFilter.class);

    /** The error code a refused request carries, for the application to key on. */
    public static final String REQUIRED_CODE = "DBSC_REQUIRED";

    private final DbscService dbsc;
    private final List<String> guardedPaths;

    public DbscGuardFilter(DbscService dbsc, List<GuardedRoute> guardedRoutes) {
        this.dbsc = dbsc;
        this.guardedPaths = guardedRoutes.stream().map(GuardedRoute::path).toList();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !guardedPaths.contains(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        Optional<Session> session = dbsc.sessionFor(request);
        if (session.isEmpty()) {
            // No DBSC cookie at all. The session may still be perfectly valid —
            // this browser simply never bound one, which is normal for a browser
            // without DBSC support, or for the window between login and the
            // browser's registration POST.
            deny(response, "no DBSC session on the request", null);
            return;
        }

        String sessionId = session.get().id();
        ProtectionTier tier = dbsc.tierFor(sessionId);
        if (tier == ProtectionTier.NONE) {
            deny(response, "the session is not currently device bound", sessionId);
            return;
        }

        log.debug("DBSC guard: {} {} allowed at tier {}", request.getMethod(),
                request.getRequestURI(), tier);
        chain.doFilter(request, response);
    }

    private void deny(HttpServletResponse response, String message, String sessionId)
            throws IOException {
        log.debug("DBSC guard -> 403: {} (session {})", message,
                sessionId == null ? "none" : sessionId);
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(Json.write(Map.of(
                "error", REQUIRED_CODE,
                "message", message)));
        response.flushBuffer();
    }
}
