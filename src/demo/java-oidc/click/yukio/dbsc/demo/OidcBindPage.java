package click.yukio.dbsc.demo;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * The landing page after OIDC login.
 *
 * <p>It does <em>not</em> bind anything. The DBSC registration header is
 * advertised by {@code DbscFilter} on any authenticated request, so by the time
 * the browser navigates here the offer has already been made — or, if this
 * browser is not going to accept it, has been given up on. The application never
 * calls {@code bind()} itself.
 *
 * <p>The login success handler still redirects here rather than straight to the
 * app: the callback response is cross-site, and a browser-initiated navigation to
 * a page on this site is what re-originates the request so the session cookie is
 * present for the next one.
 */
@Controller
class OidcBindPage {

    @GetMapping("/oidc")
    String oidc(HttpServletRequest request) {
        // The session must exist for the filter to have a record to key the
        // binding on.
        request.getSession();
        return "oidc";
    }
}
