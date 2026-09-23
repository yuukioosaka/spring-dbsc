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
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Serves every DBSC protocol route, as a filter rather than as controllers.
 *
 * <p>Why a filter: these routes are a protocol surface, not application
 * endpoints. They must be reachable <em>before</em> the application's own
 * authentication and routing run, must never be wrapped by a peer's exception
 * handling or content negotiation, and must answer with DBSC's own status and
 * header contract — where 403 rather than 401 is load-bearing. A single
 * {@link OncePerRequestFilter} placed early in the chain gives exactly that, and
 * it means the routes cannot be accidentally re-mapped, secured differently, or
 * shadowed by a peer controller.
 *
 * <p>A request on a DBSC path is <strong>terminated here</strong>: the filter
 * writes the response in full and never calls {@link FilterChain#doFilter}. Every
 * other request passes straight through untouched.
 *
 * <p>The demo registers it before the application's authentication filter; see
 * {@code DemoFormLoginTestConfig}. The ordering matters because a 403 from DBSC must not
 * be replaced by Spring Security's 401, which Chromium treats as a hard failure and
 * responds to by terminating the session.
 */
public class DbscFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DbscFilter.class);

    private final DbscService dbsc;
    private final DbscProperties properties;
    private final List<RouteMatcher> routes;

    public DbscFilter(DbscService dbsc, DbscProperties properties) {
        this.dbsc = dbsc;
        this.properties = properties;
        this.routes = List.of(
                new PrefixRoute("POST", properties.getRegistrationPath(), this::registration),
                new Route("POST", properties.getRefreshPath(), this::refresh),
                new Route("GET", "/.well-known/device-bound-sessions", this::wellKnownDocument));
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        for (RouteMatcher route : routes) {
            if (!route.matches(request)) {
                continue;
            }
            log.debug("DBSC route {} {} entered", request.getMethod(), request.getRequestURI());
            // A DBSC route owns its response completely; the chain stops here.
            handle(route.handler(), request, response);
            return;
        }

        chain.doFilter(request, response);
    }

    /**
     * The filter must not run late: Spring Security's authentication entry point
     * answers 401, and on the refresh route Chromium treats 401 as fatal. Register
     * it before {@code CsrfFilter} — the earliest anchor that is still a Security
     * filter, and therefore the only one that also keeps CSRF from rejecting the
     * browser's registration POST first.
     */
    @Override
    protected boolean shouldNotFilterAsyncDispatch() {
        return false;
    }

    private void handle(Handler handler, HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        try {
            handler.handle(request, response);
        } catch (DbscException e) {
            writeError(response, e);
        } catch (IllegalArgumentException e) {
            // A non-JSON body on a protocol route is a client bug: 400.
            writeJson(response, HttpStatus.BAD_REQUEST, Map.of("error", "MALFORMED_JWS",
                    "message", String.valueOf(e.getMessage())));
        }
    }

    // ------------------------------------------------------------------
    // Protocol routes (spec 02)
    // ------------------------------------------------------------------

    private void registration(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        Map<String, Object> config = dbsc.handleRegistration(
                registrationToken(request), request, response);
        writeJson(response, HttpStatus.OK, config);
    }

    /**
     * The token segment of the registration path, i.e. everything after the
     * configured prefix. Returns {@code null} when the path is the bare prefix
     * with nothing after it.
     */
    private String registrationToken(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String prefix = properties.getRegistrationPath();
        if (prefix.endsWith("/")) {
            prefix = prefix.substring(0, prefix.length() - 1);
        }
        if (uri.length() <= prefix.length() + 1) {
            return null;
        }
        return uri.substring(prefix.length() + 1);
    }

    private void refresh(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        Map<String, Object> config = dbsc.handleRefresh(request, response);
        if (config == null) {
            // The 403 and its challenge header are already written by the
            // service, which had to decide the status before returning.
            return;
        }
        writeJson(response, HttpStatus.OK, config);
    }

    // ------------------------------------------------------------------
    // Well-known document
    // ------------------------------------------------------------------

    private void wellKnownDocument(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("registering_origins", List.of());
        document.put("relying_origins", List.of());
        if (properties.getCookieDomain() != null && !properties.getCookieDomain().isBlank()) {
            document.put("provider_origin", "https://" + properties.getCookieDomain());
        }
        // Public, cacheable metadata: unlike the protocol responses it holds no
        // session material and no key material.
        response.setHeader("Cache-Control", "public, max-age=300");
        writeJson(response, HttpStatus.OK, document);
    }

    // ------------------------------------------------------------------
    // Response plumbing
    // ------------------------------------------------------------------

    /**
     * Writes the DBSC JSON response: JSON content type, no-store, and the server
     * clock that lets a client correct skew before signing a time-bound message.
     *
     * <p>{@code Cache-Control} is set only when the handler has not set one. The
     * well-known document is deliberately cacheable, and a blanket {@code no-store}
     * here would silently override it.
     */
    private void writeJson(HttpServletResponse response, HttpStatus status, Object body)
            throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        if (status == HttpStatus.OK) {
            response.setHeader(DbscHeaders.SERVER_TIME, Long.toString(System.currentTimeMillis()));
        }
        if (response.getHeader("Cache-Control") == null) {
            response.setHeader("Cache-Control", "no-store");
        }
        response.getWriter().write(Json.write(body));
        response.flushBuffer();
    }

    /**
     * Maps a DBSC failure onto its status. The mapping is duplicated nowhere else
     * now that the routes are filters: this is the single place it happens.
     */
    private void writeError(HttpServletResponse response, DbscException e) throws IOException {
        HttpStatus status = HttpStatus.FORBIDDEN;
        log.debug("DBSC {} -> {}: {}", e.code(), status.value(), e.getMessage());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", e.code().name());
        body.put("message", e.getMessage());
        writeJson(response, status, body);
    }

    /**
     * Reads the request body, bounded. The filter is a terminal handler, so this is
     * safe — but the size cap is not optional: see {@link RequestBodies}.
     */
    private String readBody(HttpServletRequest request) throws IOException {
        return new String(RequestBodies.readBounded(request), StandardCharsets.UTF_8);
    }

    /** A route that recognizes a request; the two shapes differ only in matching. */
    private interface RouteMatcher {

        boolean matches(HttpServletRequest request);

        Handler handler();
    }

    /**
     *
     * @param method  the HTTP method to match
     * @param path    the exact path to match
     * @param handler what to do when it matches
     */
    private record Route(String method, String path, Handler handler) implements RouteMatcher {

        @Override
        public boolean matches(HttpServletRequest request) {
            return method.equalsIgnoreCase(request.getMethod())
                    && path.equals(request.getRequestURI());
        }

        @Override
        public Handler handler() {
            return handler;
        }
    }

    /**
     * A route matching any path under a prefix, for the registration route: its
     * path carries the single-use token, so it is {@code <prefix>/<token>} rather
     * than one fixed path.
     *
     * <p>A bare prefix with no token still matches, and is rejected by the service
     * as an unknown token — reporting that as {@code SESSION_NOT_FOUND} is more
     * useful than letting it fall through to the application's 404.
     */
    private record PrefixRoute(String method, String prefix, Handler handler) implements RouteMatcher {

        @Override
        public boolean matches(HttpServletRequest request) {
            if (!method.equalsIgnoreCase(request.getMethod())) {
                return false;
            }
            String uri = request.getRequestURI();
            String normalized = prefix.endsWith("/")
                    ? prefix.substring(0, prefix.length() - 1)
                    : prefix;
            return uri.equals(normalized) || uri.startsWith(normalized + "/");
        }

        @Override
        public Handler handler() {
            return handler;
        }
    }

    @FunctionalInterface
    private interface Handler {
        void handle(HttpServletRequest request, HttpServletResponse response) throws IOException;
    }
}
