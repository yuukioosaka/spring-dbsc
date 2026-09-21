package click.yukio.dbsc.demo;

import click.yukio.dbsc.DbscService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.io.IOException;
import java.time.Duration;

/**
 * The same-site half of the OIDC flow: the landing page after login and the bind
 * hop its script navigates to.
 *
 * <p>Splitting the bind out of the login success handler is what makes DBSC work
 * behind OIDC. The success handler's response is cross-site (its initiator is the
 * identity provider), so a registration header there would produce a registration
 * POST without the session cookie. By the time the browser has navigated here it
 * has been re-originated on this site, so the cookie is present.
 */
@Controller
class OidcBindPage {

    /** Stands in for the application's own session/TTL policy. */
    private static final long SESSION_TTL_MS = Duration.ofDays(7).toMillis();

    private final DbscService dbsc;

    OidcBindPage(DbscService dbsc) {
        this.dbsc = dbsc;
    }

    /**
     * Landing page. It renders a page rather than redirecting, because a redirect
     * would keep the callback's initiator and change nothing.
     */
    @GetMapping("/oidc")
    String oidc() {
        return "oidc";
    }

    /**
     * Same-site, authenticated, so this is the point at which the session cookie
     * exists and the registration header can safely be returned.
     *
     * <p>The id is the servlet session id, not the OIDC subject: the subject
     * identifies the user, not the browser, so binding to it would make two
     * browsers share one DBSC session.
     */
    @GetMapping("/oidc/bind")
    void bind(Authentication authentication, HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        dbsc.bind(request.getSession().getId(), authentication.getName(),
                SESSION_TTL_MS, request, response);
        response.sendRedirect("/app");
    }
}
