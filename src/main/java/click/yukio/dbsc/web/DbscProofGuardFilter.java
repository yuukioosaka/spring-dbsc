package click.yukio.dbsc.web;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.core.DbscErrorCode;
import click.yukio.dbsc.core.DbscException;
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
 * Enforces a per-request DBSC proof on guarded routes (spec 04).
 *
 * <p>A guarded route requires the session to have a {@code bound} key and the
 * request to carry a fresh {@code X-Dbsc-Bound-Proof}. A request riding a cookie
 * stolen from another device has no bound key and cannot produce a valid
 * signature, so it is refused on the first guarded request rather than after the
 * next refresh cycle.
 *
 * <p>This supersedes an earlier interceptor-based guard. Because a filter runs
 * before the servlet reads the body, the body can be buffered and replayed in one
 * place: the proof is hashed over the exact bytes and the downstream handler still
 * sees them. The previous two-part arrangement — an interceptor that consumed the
 * body plus a separate filter to make it replayable — existed only because
 * interceptors run after body binding, and is gone.
 */
public class DbscProofGuardFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DbscProofGuardFilter.class);

    private final DbscService dbsc;
    private final List<String> guardedPaths;
    private final BodySigningPolicy bodySigningPolicy;

    /**
     * @param guardedPaths    the request paths to guard
     * @param bodySigningPolicy whether a given request's body is bound into the proof
     */
    public DbscProofGuardFilter(
            DbscService dbsc, List<String> guardedPaths, BodySigningPolicy bodySigningPolicy) {
        this.dbsc = dbsc;
        this.guardedPaths = List.copyOf(guardedPaths);
        this.bodySigningPolicy = bodySigningPolicy;
    }

    /** Whether a given route binds the request body into its proof. */
    @FunctionalInterface
    public interface BodySigningPolicy {
        boolean signBody(HttpServletRequest request);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !guardedPaths.contains(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        boolean signBody = bodySigningPolicy.signBody(request);

        // Buffer the body once, up front. Both the proof hash and the downstream
        // handler must see the same bytes, and a servlet input stream can only be
        // read once, so the read has to happen here and the result has to be
        // handed on wrapped rather than re-read from the original request.
        ReplayableBodyRequest buffered = signBody ? new ReplayableBodyRequest(request) : null;

        try {
            verify(request, buffered == null ? null : buffered.body());
        } catch (DbscException e) {
            writeDenied(response, e);
            return;
        }

        if (buffered == null) {
            chain.doFilter(request, response);
        } else {
            chain.doFilter(buffered, response);
        }
    }

    /**
     * The checks run in the order spec 04 requires: presence before shape before
     * freshness before lookup, so a malformed proof is not reported as a missing
     * key and a stale proof is rejected before touching storage.
     */
    private void verify(HttpServletRequest request, byte[] body) throws IOException {
        Optional<String> sessionId = dbsc.resolveBinderSession(request);
        if (sessionId.isEmpty()) {
            throw new DbscException(DbscErrorCode.MISSING_PROOF, "no DBSC session on the request");
        }

        Session session = dbsc.sessionFor(request)
                .orElseThrow(() -> new DbscException(
                        DbscErrorCode.SESSION_NOT_FOUND, "no DBSC session record"));

        if (dbsc.tierFor(session.id()) == ProtectionTier.NONE) {
            throw new DbscException(DbscErrorCode.KEY_NOT_FOUND_BOUND,
                    "session is not bound; a per-request proof cannot be verified");
        }

        dbsc.requireProof(request, session.id(), request.getRequestURI(), body, body != null);
    }

    private void writeDenied(HttpServletResponse response, DbscException e) throws IOException {
        log.debug("DBSC guard {} -> 403: {}", e.code(), e.getMessage());
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(Json.write(Map.of(
                "error", e.code().name(),
                "message", String.valueOf(e.getMessage()))));
        response.flushBuffer();
    }
}
