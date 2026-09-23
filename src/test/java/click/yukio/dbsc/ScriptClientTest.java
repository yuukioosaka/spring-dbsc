package click.yukio.dbsc;

import click.yukio.dbsc.core.Json;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.protocol.CookieScope;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The script client's two affordances: {@code POST /dbsc/bind} and the
 * {@code X-Session-Id} header.
 *
 * <p>Both exist for a client that manages its own key instead of letting the
 * browser do it, and both are protocol-compatible with the native flow they stand
 * beside: the offer is the same header, the proof is the same JWS on the same
 * registration path, and a refresh is the same two-legged exchange.
 *
 * <p>What these tests pin down is the part that is <em>not</em> shared — that the
 * re-offer route names its session from the application's own session rather than
 * from a path token, that it is single-use, and that the alternate header name
 * resolves the same session without weakening the lookup.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ScriptClientTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private StorageAdapter storage;

    @Autowired
    private CookieScope cookieScope;

    @Autowired
    private CsrfTokenRepository tokenRepository;

    private static final String CSRF_HEADER = "X-CSRF-TOKEN";

    private static final Pattern CHALLENGE = Pattern.compile("challenge=\"([^\"]+)\"");
    private static final Pattern PATH = Pattern.compile("path=\"([^\"]+)\"");
    /** The challenge header carries a bare sf-string: {@code "<jti>";id="<sessionId>"}. */
    private static final Pattern CHALLENGE_HEADER = Pattern.compile("^\"([^\"]+)\"");

    // ------------------------------------------------------------------
    // POST /dbsc/bind
    // ------------------------------------------------------------------

    @Test
    @DisplayName("bind route: re-offers registration as the same headers bind() writes")
    void bindRouteOffersTheSameWireFormat() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);

        MvcResult result = bind(login);
        var response = result.getResponse();
        assertEquals(200, response.getStatus(), response.getContentAsString());

        String registration = response.getHeader("Secure-Session-Registration");
        assertNotNull(registration, "the offer is the point of this route");
        assertTrue(registration.matches(
                        "\\(ES256\\);path=\"/dbsc/regist/[A-Za-z0-9_-]{43}\";challenge=\"[A-Za-z0-9_-]{43}\""),
                "the wire format must be identical to bind()'s: " + registration);

        // A client that reads the legacy name has to find it here too, or it
        // registers with neither.
        assertEquals(registration, response.getHeader("Sec-Session-Registration"));

        String challengeHeader = response.getHeader("Secure-Session-Challenge");
        assertNotNull(challengeHeader);
        assertTrue(challengeHeader.matches("\"[A-Za-z0-9_-]{43}\";id=\"[^\"]+\""), challengeHeader);
        assertEquals(challengeHeader, response.getHeader("Sec-Session-Challenge"));

        // The challenge in the header and the one in the registration offer must be
        // the same value: a client signs whichever it read, and they are one challenge.
        Matcher offer = CHALLENGE.matcher(registration);
        assertTrue(offer.find(), registration);
        assertTrue(challengeHeader.contains("\"" + offer.group(1) + "\""),
                "the two headers must name one challenge: " + challengeHeader);
    }

    @Test
    @DisplayName("bind route: the session it offers for is the one the login bound")
    void bindRouteNamesTheSameSession() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);

        var response = bind(login).getResponse();
        String challengeHeader = response.getHeader("Secure-Session-Challenge");
        assertNotNull(challengeHeader);
        assertTrue(challengeHeader.contains("id=\"" + login.sessionId() + "\""),
                "the offer must name the session the login bound: " + challengeHeader);

        Map<String, Object> body = Json.parseObject(response.getContentAsString());
        assertEquals(login.sessionId(), body.get("sessionId"));
        assertNotNull(body.get("registrationPath"));
        assertNotNull(body.get("challenge"));
    }

    @Test
    @DisplayName("bind route: each call mints a fresh token, and only the newest one works")
    void bindRouteTokenIsSingleUsePerOffer() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);

        var first = bind(login).getResponse();
        String firstPath = pathOf(first.getHeader("Secure-Session-Registration"));
        assertNotNull(firstPath);

        // A client that lost the response asks again rather than reusing the token.
        var second = bind(login).getResponse();
        assertEquals(200, second.getStatus(), second.getContentAsString());
        String secondPath = pathOf(second.getHeader("Secure-Session-Registration"));
        assertNotEquals(firstPath, secondPath,
                "a second call must mint a fresh token, not re-offer the spent one");

        // The offer is the credential for one registration POST, so it must still be
        // usable when the client gets around to using it. Consuming it here would make
        // the route hand out a path that is already dead.
        String token = secondPath.substring(secondPath.lastIndexOf('/') + 1);
        assertFalse(storage.getRegistrationToken(token).orElseThrow().consumed(),
                "the offered token must be live until the registration POST spends it");
    }

    @Test
    @DisplayName("bind route: an offer is spent by the registration POST, and replayed offers are refused")
    void bindRouteOffersAreSingleUseOncePresented() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);
        HttpFlowTest.TestKey key = HttpFlowTest.TestKey.generate();

        String registration = bind(login).getResponse().getHeader("Secure-Session-Registration");
        String path = pathOf(registration);
        String challenge = challengeOf(registration);

        // The first presentation spends the token, regardless of whether the proof
        // verifies, so this one is reported as a replay rather than granted a binding.
        String replay = key.registrationJws(challenge, login.sessionId());
        mvc.perform(post(path).header("Secure-Session-Response", replay)).andReturn();
        MvcResult result = mvc.perform(post(path).header("Secure-Session-Response", replay))
                .andReturn();

        assertEquals(403, result.getResponse().getStatus());
        assertEquals("REGISTRATION_TOKEN_CONSUMED",
                Json.parseObject(result.getResponse().getContentAsString()).get("error"));
    }

    @Test
    @DisplayName("bind route: a fresh offer supersedes the challenge the login issued")
    void bindRouteSupersedesThePreviousOffer() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);

        var response = bind(login).getResponse();
        String registration = response.getHeader("Secure-Session-Registration");
        assertNotNull(registration, response.getContentAsString());
        Matcher offer = CHALLENGE.matcher(registration);
        assertTrue(offer.find(), registration);
        assertNotEquals(login.challenge(), offer.group(1),
                "the re-offer must not reuse a challenge the login already published");
    }

    @Test
    @DisplayName("bind route: the re-offered challenge registers a key on the normal path")
    void bindRouteOfferActuallyRegisters() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);
        HttpFlowTest.TestKey key = HttpFlowTest.TestKey.generate();

        var offer = bind(login).getResponse();
        String registrationHeader = offer.getHeader("Secure-Session-Registration");
        assertNotNull(registrationHeader, offer.getContentAsString());
        String path = pathOf(registrationHeader);
        Matcher challengeMatcher = CHALLENGE.matcher(registrationHeader);
        assertTrue(challengeMatcher.find(), registrationHeader);
        String challenge = challengeMatcher.group(1);

        // The whole point of the route: what it offers must be registerable. The
        // token is spent by the route that handed it out -- that is what makes it
        // single-use -- so the client registers on the path it was just given, which
        // is the only place the session is named.
        MvcResult result = mvc.perform(post(path)
                        .header("Secure-Session-Response",
                                key.registrationJws(challenge, login.sessionId())))
                .andReturn();
        assertEquals(200, result.getResponse().getStatus(),
                "the re-offered challenge must register: " + result.getResponse().getContentAsString()
                        + " (path " + path + ")");
        assertEquals(ProtectionTier.DBSC, storage.getSession(login.sessionId()).orElseThrow().tier());
    }

    @Test
    @DisplayName("bind route: an unauthenticated caller holds no session and is refused")
    void bindRouteWithoutASessionIsRefused() throws Exception {
        MvcResult result = mvc.perform(post("/dbsc/bind")
                        .contentType(MediaType.APPLICATION_JSON))
                .andReturn();

        // No session, so no token either, and the CSRF check refuses it before the
        // offer logic is reached. That the refusal is the CSRF one rather than
        // SESSION_NOT_FOUND is the point: a caller with no session fails the first
        // check on the route, and never gets to ask what sessions exist.
        assertEquals(403, result.getResponse().getStatus(),
                "an unauthenticated bind must not be answered with an offer");
        assertNull(result.getResponse().getHeader("Secure-Session-Registration"));
    }

    @Test
    @DisplayName("bind route: a session that already has a key is not offered a second one")
    void bindRouteRefusesAnAlreadyRegisteredSession() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);
        HttpFlowTest.register(mvc, cookieScope, login, HttpFlowTest.TestKey.generate());

        MvcResult result = bind(login);
        assertEquals(403, result.getResponse().getStatus(),
                "a bound session must not be able to replace its key without proving it has it");
        assertTrue(result.getResponse().getContentAsString().contains("SESSION_ALREADY_REGISTERED"),
                result.getResponse().getContentAsString());
        assertFalse(result.getResponse().containsHeader("Secure-Session-Registration"),
                "a refusal must not carry an offer on the side");
    }

    // ------------------------------------------------------------------
    // X-Session-Id
    // ------------------------------------------------------------------

    @Test
    @DisplayName("X-Session-Id names the session on the refresh first leg")
    void xSessionIdResolvesTheRefreshSession() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);
        HttpFlowTest.register(mvc, cookieScope, login, HttpFlowTest.TestKey.generate());

        MvcResult result = mvc.perform(post("/dbsc/refresh")
                        .header("X-Session-Id", login.sessionId())
                        .contentType(MediaType.APPLICATION_JSON))
                .andReturn();

        // The first leg is the proof-less one: it must be answered with 403 and a
        // challenge, which is only possible if the header named a real session.
        assertEquals(403, result.getResponse().getStatus());
        String challengeHeader = result.getResponse().getHeader("Secure-Session-Challenge");
        assertNotNull(challengeHeader, "an unknown session would have been KEY_NOT_FOUND instead");
        assertTrue(challengeHeader.contains("id=\"" + login.sessionId() + "\""), challengeHeader);
    }

    @Test
    @DisplayName("X-Session-Id completes a full refresh, same as the Sec- name")
    void xSessionIdCompletesARefresh() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);
        HttpFlowTest.TestKey key = HttpFlowTest.TestKey.generate();
        HttpFlowTest.register(mvc, cookieScope, login, key);

        String challenge = refreshChallenge(login, "X-Session-Id");
        MvcResult result = mvc.perform(post("/dbsc/refresh")
                        .header("X-Session-Id", login.sessionId())
                        .header("Secure-Session-Response", key.refreshJws(challenge))
                        .contentType(MediaType.APPLICATION_JSON))
                .andReturn();

        assertEquals(200, result.getResponse().getStatus(),
                "a proven refresh over X-Session-Id must succeed: "
                        + result.getResponse().getContentAsString());
        Map<String, Object> body = Json.parseObject(result.getResponse().getContentAsString());
        assertEquals(login.sessionId(), body.get("session_identifier"),
                "the session id does not move on refresh; only the ticket does");
        assertNotNull(result.getResponse().getCookie(cookieScope.credentialCookieName()),
                "a successful refresh must set the credential cookie");
    }

    @Test
    @DisplayName("X-Session-Id: a value that is not a session is refused, not treated as absent")
    void xSessionIdWithAnUnknownValueIsRefused() throws Exception {
        MvcResult result = mvc.perform(post("/dbsc/refresh")
                        .header("X-Session-Id", "not_a_session")
                        .contentType(MediaType.APPLICATION_JSON))
                .andReturn();

        // A value that names no session is refused, and refused as a lookup that
        // found nothing rather than as a missing header: the point of reading this
        // name is that it resolves a session, so a value that cannot must not become
        // a way to skip the check by presenting something unparseable.
        assertEquals(403, result.getResponse().getStatus());
        String body = result.getResponse().getContentAsString();
        assertTrue(body.contains("SESSION_NOT_FOUND") || body.contains("KEY_NOT_FOUND"), body);
        assertFalse(body.contains("refresh requires"),
                "a value was supplied; it must not be reported as a missing header: " + body);
    }

    @Test
    @DisplayName("X-Session-Id: the value may be a quoted sf-string, as the Sec- name may")
    void xSessionIdAcceptsAQuotedValue() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);
        HttpFlowTest.register(mvc, cookieScope, login, HttpFlowTest.TestKey.generate());

        MvcResult result = mvc.perform(post("/dbsc/refresh")
                        .header("X-Session-Id", "\"" + login.sessionId() + "\"")
                        .contentType(MediaType.APPLICATION_JSON))
                .andReturn();

        // Quotes are stripped the same way for both names; a quoted value that kept
        // its quotes would name nothing and every refresh would miss.
        assertEquals(403, result.getResponse().getStatus());
        String challengeHeader = result.getResponse().getHeader("Secure-Session-Challenge");
        assertNotNull(challengeHeader, "the quoted id must still resolve: "
                + result.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("X-Session-Id: when both names are present the X- one wins")
    void xSessionIdTakesPrecedenceWhenBothAreSent() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);
        HttpFlowTest.TestKey key = HttpFlowTest.TestKey.generate();
        HttpFlowTest.register(mvc, cookieScope, login, key);

        // Two sessions, so the two headers name genuinely different sessions and the
        // outcome says which one was read.
        HttpFlowTest.LoginState other = HttpFlowTest.loginWithState(mvc, cookieScope);
        HttpFlowTest.register(mvc, cookieScope, other, HttpFlowTest.TestKey.generate());

        MvcResult result = mvc.perform(post("/dbsc/refresh")
                        .header("X-Session-Id", login.sessionId())
                        .header("Sec-Secure-Session-Id", other.sessionId())
                        .contentType(MediaType.APPLICATION_JSON))
                .andReturn();

        assertEquals(403, result.getResponse().getStatus());
        String challengeHeader = result.getResponse().getHeader("Secure-Session-Challenge");
        assertNotNull(challengeHeader, result.getResponse().getContentAsString());
        assertTrue(challengeHeader.contains("id=\"" + login.sessionId() + "\""),
                "X-Session-Id must be the one read: " + challengeHeader);
    }

    // ------------------------------------------------------------------
    // The re-offer route's own protections
    // ------------------------------------------------------------------

    @Test
    @DisplayName("bind route: refuses a session that is not carried in a cookie")
    void bindRouteRefusesASessionThatIsNotInACookie() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);

        // The session is real and the route is authenticated, but the caller names it
        // by a header rather than by a cookie. Nothing in the request shows the caller
        // owns that session, so it must not be handed an offer for it: an offer is an
        // instruction to bind a key to the session, and this caller could name anyone's.
        var response = mvc.perform(post("/dbsc/bind")
                        .session(login.appSession())
                        .header("X-Session-Id", login.sessionId())
                        .header(CSRF_HEADER, csrfToken(login))
                        .contentType(MediaType.APPLICATION_JSON))
                .andReturn().getResponse();

        assertEquals(403, response.getStatus(), response.getContentAsString());
        assertTrue(response.getContentAsString().contains("UNSUPPORTED_CLIENT"),
                response.getContentAsString());
        assertNull(response.getHeader("Secure-Session-Registration"),
                "no offer may be issued for a session the caller cannot be shown to own");
    }

    @Test
    @DisplayName("bind route: refuses a request the browser calls cross-site")
    void bindRouteRefusesCrossSite() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);

        var response = mvc.perform(post("/dbsc/bind")
                        .session(login.appSession())
                        .cookie(new Cookie("JSESSIONID", login.appSession().getId()))
                        .header("Sec-Fetch-Site", "cross-site")
                        .header(CSRF_HEADER, csrfToken(login))
                        .contentType(MediaType.APPLICATION_JSON))
                .andReturn().getResponse();

        assertEquals(403, response.getStatus(), response.getContentAsString());
        assertNull(response.getHeader("Secure-Session-Registration"));
    }

    @Test
    @DisplayName("bind route: a same-origin request with no Sec-Fetch-Site is still served")
    void bindRouteServesRequestsWithoutFetchMetadata() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);

        // Firefox before 90 and anything that is not a browser send no Sec-Fetch-Site.
        // Refusing the absent header would break the clients this route exists for, so
        // only an explicitly cross-site value is turned away.
        var response = mvc.perform(post("/dbsc/bind")
                        .session(login.appSession())
                        .cookie(new Cookie("JSESSIONID", login.appSession().getId()))
                        .header(CSRF_HEADER, csrfToken(login))
                        .contentType(MediaType.APPLICATION_JSON))
                .andReturn().getResponse();

        assertEquals(200, response.getStatus(), response.getContentAsString());
        assertNotNull(response.getHeader("Secure-Session-Registration"));
    }

    @Test
    @DisplayName("bind route: the offer names a session whose value the cookie actually carried")
    void bindRouteNamesOnlyTheCookieProvenSession() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);

        // A cookie that is present but carries someone else's value proves nothing,
        // and must not be accepted as evidence: the offer would name the session this
        // caller guessed at rather than the one it holds.
        var response = mvc.perform(post("/dbsc/bind")
                        .session(login.appSession())
                        .cookie(new Cookie("JSESSIONID", "00000000000000000000000000000000"))
                        .header(CSRF_HEADER, csrfToken(login))
                        .contentType(MediaType.APPLICATION_JSON))
                .andReturn().getResponse();

        assertEquals(403, response.getStatus(), response.getContentAsString());
        assertNull(response.getHeader("Secure-Session-Registration"));
    }

    // ------------------------------------------------------------------
    // X-Session-Id on refresh
    // ------------------------------------------------------------------

    /**
     * POSTs the re-offer route on the session the login created, with the token and
     * cookie a real browser would send.
     *
     * <p>All three parts are load-bearing and each fails differently without it: the
     * session as a {@code JSESSIONID} cookie is what shows the caller owns the session
     * the route would offer on, and the CSRF token is what shows the request came from
     * a page of ours. A test that set only {@code .session(...)} would be exercising a
     * caller this route is designed to turn away.
     */
    private MvcResult bind(HttpFlowTest.LoginState login) throws Exception {
        return mvc.perform(post("/dbsc/bind")
                        .session(login.appSession())
                        .cookie(new Cookie("JSESSIONID", login.appSession().getId()))
                        .header(CSRF_HEADER, csrfToken(login))
                        .contentType(MediaType.APPLICATION_JSON))
                .andReturn();
    }

    /**
     * The token the session was issued, read from the repository the filter checks
     * against. A browser reads the same value from the page's meta tag.
     */
    private String csrfToken(HttpFlowTest.LoginState login) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(login.appSession());

        CsrfToken token = tokenRepository.loadToken(request);
        if (token == null) {
            token = tokenRepository.generateToken(request);
            tokenRepository.saveToken(token, request, new MockHttpServletResponse());
        }
        return token.getToken();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** Runs the proof-less refresh leg and returns the challenge it issues. */
    private String refreshChallenge(HttpFlowTest.LoginState login, String sessionIdHeader) throws Exception {
        MvcResult result = mvc.perform(post("/dbsc/refresh")
                        .header(sessionIdHeader, login.sessionId())
                        .contentType(MediaType.APPLICATION_JSON))
                .andReturn();
        String header = result.getResponse().getHeader("Secure-Session-Challenge");
        assertNotNull(header, "the first leg must issue a challenge: "
                + result.getResponse().getContentAsString());
        Matcher matcher = CHALLENGE_HEADER.matcher(header);
        assertTrue(matcher.find(), header);
        return matcher.group(1);
    }

    private static String pathOf(String registrationHeader) {
        assertNotNull(registrationHeader);
        Matcher matcher = PATH.matcher(registrationHeader);
        assertTrue(matcher.find(), registrationHeader);
        return matcher.group(1);
    }

    /** The {@code challenge} parameter of a registration offer. */
    private static String challengeOf(String registrationHeader) {
        assertNotNull(registrationHeader);
        Matcher matcher = CHALLENGE.matcher(registrationHeader);
        assertTrue(matcher.find(), registrationHeader);
        return matcher.group(1);
    }
}
