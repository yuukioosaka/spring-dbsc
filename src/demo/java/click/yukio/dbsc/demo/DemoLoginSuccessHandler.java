package click.yukio.dbsc.demo;

import click.yukio.dbsc.DbscService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

/**
 * Binds a DBSC session at the moment form login succeeds.
 *
 * <p>This is the whole integration point. Three details are worth copying:
 *
 * <ul>
 *   <li><strong>The session id is the application's own.</strong> DBSC does not
 *       mint sessions; it binds one that already exists. Here that is the
 *       servlet session's id, so a DBSC binding and a login session are the same
 *       thing and cannot drift apart.</li>
 *   <li><strong>It runs for every successful login, not just the first.</strong>
 *       A returning user whose browser already holds a binding gets a fresh
 *       registration header and fresh cookies, which is what re-couples the new
 *       session to the device key.</li>
 *   <li><strong>The TTL is the application's policy, not DBSC's.</strong> Pass
 *       the same lifetime the login session gets, or the two expire on different
 *       clocks.</li>
 * </ul>
 */
class DemoLoginSuccessHandler implements AuthenticationSuccessHandler {

    /** Stands in for the application's own session/TTL policy. */
    private static final long SESSION_TTL_MS = 7L * 24 * 60 * 60 * 1000;

    private final DbscService dbsc;

    DemoLoginSuccessHandler(DbscService dbsc) {
        this.dbsc = dbsc;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        // The demo asserts below that the session id is stable; forcing creation
        // here means a login always has one, even if nothing touched it earlier.
        HttpSession session = request.getSession();

        dbsc.bind(session.getId(), authentication.getName(), SESSION_TTL_MS, request, response);

        response.sendRedirect("/app");
    }
}
