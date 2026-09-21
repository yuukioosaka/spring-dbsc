package click.yukio.dbsc.demo;

import click.yukio.dbsc.DbscService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * The landing page after OIDC login, and the place the binding is made.
 *
 * <p>This is "Strategy 2" from the README: {@code bind()} is not called from the
 * OIDC callback, because that response is cross-site and the registration POST it
 * would trigger loses its {@code SameSite=Lax} session cookie. It is called here
 * instead — on a request the browser issued on its own, whose cookie is therefore
 * present.
 *
 * <p>Note that {@code DbscFilter} has nothing to do with this. It serves the
 * protocol routes and never stamps the registration header onto an application
 * response, so without the {@code bind()} below there would be no binding at all.
 *
 * <p>The alternative the README describes is to have the page run
 * {@code location.replace(...)} to reach a route that binds. The demo does not need
 * that: the user navigates on to {@code /app} in the normal course of things, which
 * is already a browser-initiated same-site request.
 */
@Controller
class OidcBindPage {

    private final DbscService dbsc;

    OidcBindPage(DbscService dbsc) {
        this.dbsc = dbsc;
    }

    @GetMapping("/oidc")
    String oidc(HttpServletRequest request, HttpServletResponse response) {
        // The session must exist before it can be bound, and its id is the key the
        // browser will present back. OIDC's success handler created it already; the
        // call here is what makes this route safe to hit directly.
        String sessionId = request.getSession().getId();

        // Idempotent: calling it on every visit re-advertises the header and costs
        // one challenge plus two cookies. Chromium ignores the offer once the
        // session has reached tier "dbsc".
        dbsc.bind(sessionId, request.getUserPrincipal().getName(),
                86_400_000L, request, response);

        return "oidc";
    }
}
