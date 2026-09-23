package click.yukio.dbsc.web;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.DbscErrorCode;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.Json;
import click.yukio.dbsc.protocol.DbscHeaders;
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

/**
 * Serves the Soft DBSC re-offer route, {@code POST /dbsc/bind}.
 *
 * <p>Why this is not a route in {@link DbscFilter}: that filter's routes are all
 * <em>protocol</em> routes. The browser drives them, each request carries its own proof
 * (a JWS, a single-use token in the path), and being answered before the application's
 * security runs is the entire point — a 401 from Security's entry point is fatal to
 * Chromium, so those routes must never meet it.
 *
 * <p>This route is the opposite in every respect. It names its session from the
 * application's own session cookie rather than from a token, so reaching it means
 * being logged in; and it changes state, by offering to bind a device key to that
 * session. Putting it in {@link DbscFilter} would mean the filter terminated the
 * request before the host's authentication and CSRF had run — a route the deployment
 * believes is protected, open to anyone who can name a session. So it lives here, a
 * filter for the application's chain, where those checks are.
 *
 * <p>The wire format is identical to what {@code bind()} writes — the same
 * {@code Secure-Session-Registration} and {@code Secure-Session-Challenge} response
 * headers — which is what lets one client parse one format whichever route offered it.
 *
 * <p>Register it in the same chain as the rest of the application's routes. Because it
 * terminates the request, order it <em>after</em> whatever performs authentication and
 * after CSRF, so that the token check it relies on has already run. It performs no
 * check of its own beyond proving the caller owns the session it names: it is an
 * ordinary application route and ordinary Spring Security CSRF is what protects it.
 */
public class DbscBindFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DbscBindFilter.class);

    private final DbscService dbsc;
    private final String bindPath;
    private final boolean enabled;

    public DbscBindFilter(DbscService dbsc, DbscProperties properties) {
        this.dbsc = dbsc;
        this.bindPath = properties.getBindPath();
        this.enabled = properties.getSoft().isEnabled();
    }

    /**
     * Off means the route is not registered, so this filter is inert and the path falls
     * through to the application. Registered as a bean it may still be wired into a
     * chain, so the check is here rather than at construction: toggling the property
     * must not leave a chain holding a filter that answers a path it no longer owns.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !enabled
                || bindPath == null
                || !"POST".equalsIgnoreCase(request.getMethod())
                || !bindPath.equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // Cross-site requests are refused before anything else. The route is only ever
        // useful to a client running on one of our own pages, and its response is an
        // instruction to bind a key to whatever session the cookies name. A cross-site
        // caller is either an attacker's page asking the browser to bind on its behalf,
        // or a navigation with no client code to read the offer -- a third party's form
        // POST with SameSite=None cookies would qualify.
        //
        // This is a narrowing, not the control: the header is client-supplied, and a
        // script can always spend a request. What actually protects the route is that
        // it sits behind the application's authentication and CSRF, and that the service
        // only issues an offer for a session the request's own cookie proves the caller
        // holds. A missing header is allowed because not every client sends Fetch
        // Metadata -- refusing it would break the script clients this route exists for.
        String fetchSite = request.getHeader("Sec-Fetch-Site");
        if (fetchSite != null && !"same-origin".equalsIgnoreCase(fetchSite)) {
            log.debug("DBSC bind refused: Sec-Fetch-Site {}", fetchSite);
            writeError(response, new DbscException(DbscErrorCode.SESSION_NOT_FOUND,
                    "the re-offer route is only for same-origin requests"));
            return;
        }

        try {
            writeOffer(response, dbsc.handleBind(request, response));
        } catch (DbscException e) {
            writeError(response, e);
        } catch (IllegalArgumentException e) {
            writeError(response, new DbscException(DbscErrorCode.BAD_REQUEST,
                    String.valueOf(e.getMessage())));
        }
    }

    /**
     * Writes the offer, which {@code handleBind} has already put on the response as
     * headers. The JSON body is a convenience for the client: the headers are the
     * protocol, and a client that reads only those is correct.
     */
    private void writeOffer(HttpServletResponse response, Object body) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.setHeader(DbscHeaders.SERVER_TIME, Long.toString(System.currentTimeMillis()));
        if (response.getHeader("Cache-Control") == null) {
            response.setHeader("Cache-Control", "no-store");
        }
        response.getWriter().write(Json.write(body));
        response.flushBuffer();
    }

    /**
     * DBSC's own error shape and 403, matching every other refusal on these routes.
     * The status is load-bearing: Chromium treats 401 as a hard failure and responds by
     * terminating the session, and the script client reads the body's {@code error} to
     * tell "not signed in" from "already bound".
     */
    private void writeError(HttpServletResponse response, DbscException e) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        log.debug("DBSC bind -> 403: {}", e.code());
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(Json.write(java.util.Map.of(
                "error", e.code().name(),
                "message", String.valueOf(e.getMessage()))));
        response.flushBuffer();
    }
}
