package click.yukio.dbsc.demo;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

/**
 * Deliberately does <em>not</em> bind the DBSC session.
 *
 * <p>The response this handler writes is the OIDC callback's, and Chromium makes
 * DBSC requests inherit the initiator of the request that caused them. The
 * initiator here is the identity provider, so a registration header returned from
 * this response makes the registration POST cross-site and its
 * {@code SameSite=Lax} session cookie is dropped. Chromium records that failure
 * as permanent and never retries for the rest of the login.
 *
 * <p>A server-side redirect does not reset the initiator either — only a
 * navigation the browser issues itself does. So this handler sends the browser to
 * {@code /oidc}, a page the browser navigates to on its own, and the binding is made
 * there. See README.md, "Binding behind OIDC or SAML".
 */
class OidcLoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        // The session must exist before /oidc reads its id.
        request.getSession();

        // No bind() here: this response is the callback's, so it is cross-site.
        response.sendRedirect("/oidc");
    }
}
