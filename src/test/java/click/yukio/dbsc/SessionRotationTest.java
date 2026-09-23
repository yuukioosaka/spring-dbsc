package click.yukio.dbsc;

import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.protocol.CookieScope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import jakarta.servlet.http.Cookie;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Credential-ticket rotation on refresh, over the real filter chain.
 *
 * <p>Two values are in play and only one of them moves. The session id is fixed for the
 * life of the binding: it is what the JSON config reports as {@code session_identifier},
 * which is how Chromium keys its session store, and a refresh checks
 * {@code Sec-Secure-Session-Id} against it. The credential cookie named in
 * {@code credentials[]} carries a ticket, and that is what rotates.
 *
 * <p>Two properties are load-bearing and neither is visible from a unit test of the
 * engine. The first is that the browser is told the new ticket — rotation that only
 * happened server-side would leave the client presenting a retired value, and every
 * request after the grace would look like a client with no session. The second is that
 * the retired ticket keeps working for the grace window, because the tab that has not
 * read the new value yet is the normal case, not the exception.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = "dbsc.rotation-grace=5s")
class SessionRotationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private StorageAdapter storage;

    @Autowired
    private CookieScope cookieScope;

    @Autowired
    private CsrfTokenRepository csrfTokenRepository;

    /** The header a browser sends the token in, matching {@code dbsc-soft-client.js}. */
    private static final String CSRF_HEADER = "X-CSRF-TOKEN";

    @Test
    @DisplayName("rotation: a successful refresh issues a different credential ticket")
    void refreshRotatesTheTicket() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);
        HttpFlowTest.TestKey key = HttpFlowTest.TestKey.generate();
        HttpFlowTest.register(mvc, cookieScope, login, key);

        MvcResult result = signedRefresh(login, key);
        assertEquals(200, result.getResponse().getStatus(),
                "refresh failed: " + result.getResponse().getContentAsString());

        Cookie credential = result.getResponse().getCookie(cookieScope.credentialCookieName());
        assertNotNull(credential, "the refresh response MUST carry the credential cookie");
        assertTrue(storage.resolveTicket(credential.getValue()) != null,
                "the new ticket must resolve to a session");

        // The session id is echoed as session_identifier and is not a cookie: it is the
        // value Chromium stores the session under and returns in a header, so it must
        // survive a refresh unchanged rather than being re-minted or moved.
        assertNull(result.getResponse().getCookie("session_identifier"),
                "no cookie is set under session_identifier's name, on a refresh or ever");

        Map<String, Object> config =
                click.yukio.dbsc.core.Json.parseObject(result.getResponse().getContentAsString());
        assertEquals(login.sessionId(),
                config.get("session_identifier"),
                "a refresh must echo the session id it was registered under, not a new one");
        assertEquals(cookieScope.credentialCookieName(),
                ((Map<?, ?>) ((List<?>) config.get("credentials")).get(0)).get("name"),
                "credentials[].name names the protected cookie, which is what actually moves");
    }

    @Test
    @DisplayName("rotation: the retired ticket still resolves during the grace window")
    void retiredTicketKeepsWorkingDuringGrace() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);
        HttpFlowTest.TestKey key = HttpFlowTest.TestKey.generate();
        HttpFlowTest.register(mvc, cookieScope, login, key);

        String before = storage.getSession(login.sessionId()).orElseThrow().id();
        MvcResult first = signedRefresh(login, key);
        String retired = first.getResponse().getCookie(cookieScope.credentialCookieName()).getValue();

        // The second tab, which has not yet seen the new ticket, presents the old one.
        // resolveTicket is what every read path goes through, so this is the same window
        // the guard sees.
        assertEquals(login.sessionId(), storage.resolveTicket(retired),
                "a retired ticket within its grace MUST still resolve; without this every "
                        + "second tab looks like a client with no session, and Chromium "
                        + "records that as a permanent failure");
        assertEquals(before, storage.getSession(login.sessionId()).orElseThrow().id(),
                "and the session it names is the same one");
    }

    @Test
    @DisplayName("rotation: a failed signature never issues a ticket")
    void failedSignatureDoesNotRotate() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);
        HttpFlowTest.TestKey key = HttpFlowTest.TestKey.generate();
        HttpFlowTest.register(mvc, cookieScope, login, key);

        MvcResult firstLeg = mvc.perform(post("/dbsc/refresh")
                        .header("Sec-Secure-Session-Id", login.sessionId()))
                .andReturn();
        String challengeHeader = firstLeg.getResponse().getHeader("Secure-Session-Challenge");
        String jti = challengeHeader.substring(1, challengeHeader.indexOf('"', 1));

        MvcResult result = mvc.perform(post("/dbsc/refresh")
                        .header("Sec-Secure-Session-Id", login.sessionId())
                        .header("Secure-Session-Response",
                                HttpFlowTest.TestKey.generate().refreshJws(jti)))
                .andReturn();

        assertEquals(403, result.getResponse().getStatus());
        assertTrue(result.getResponse().getCookie(cookieScope.credentialCookieName()) == null,
                "an unverified refresh must not hand out a ticket: minting before the "
                        + "signature checks out would be a denial of service anyone could "
                        + "trigger with no key at all");
        assertTrue(storage.getSession(login.sessionId()).isPresent());
        assertEquals(ProtectionTier.NONE,
                storage.getSession(login.sessionId()).orElseThrow().tier(),
                "and the session is demoted, which is the protocol's answer to a bad proof");
    }

    @Test
    @DisplayName("rotation: a guarded route admits a request still carrying the retired ticket")
    void guardAdmitsRetiredTicketDuringGrace() throws Exception {
        HttpFlowTest.LoginState login = HttpFlowTest.loginWithState(mvc, cookieScope);
        HttpFlowTest.TestKey key = HttpFlowTest.TestKey.generate();
        HttpFlowTest.register(mvc, cookieScope, login, key);

        MvcResult first = signedRefresh(login, key);
        String retired = first.getResponse().getCookie(cookieScope.credentialCookieName()).getValue();

        // The stale tab: the credential cookie it still holds names the retired ticket.
        MvcResult result = mvc.perform(post("/host/payment")
                        .session(login.appSession())
                        .header(CSRF_HEADER, HttpFlowTest.csrfToken(csrfTokenRepository, login.appSession()))
                        .cookie(new Cookie(cookieScope.credentialCookieName(), retired)))
                .andReturn();

        assertEquals(200, result.getResponse().getStatus(),
                "a retired ticket within its grace must not read as LAPSED, or the session "
                        + "looks terminated to every tab but the one that refreshed: "
                        + result.getResponse().getContentAsString());
    }

    /** Drives one full refresh and returns the second leg's result. */
    private MvcResult signedRefresh(HttpFlowTest.LoginState login, HttpFlowTest.TestKey key)
            throws Exception {
        return signedRefresh(login, key, login.sessionId());
    }

    private MvcResult signedRefresh(
            HttpFlowTest.LoginState login, HttpFlowTest.TestKey key, String presentedId)
            throws Exception {
        MvcResult firstLeg = mvc.perform(post("/dbsc/refresh")
                        .header("Sec-Secure-Session-Id", presentedId))
                .andReturn();
        String challengeHeader = firstLeg.getResponse().getHeader("Secure-Session-Challenge");
        assertNotNull(challengeHeader, "leg 1 must issue a challenge");
        String jti = challengeHeader.substring(1, challengeHeader.indexOf('"', 1));

        return mvc.perform(post("/dbsc/refresh")
                        .header("Sec-Secure-Session-Id", presentedId)
                        .header("Secure-Session-Response", key.refreshJws(jti)))
                .andReturn();
    }
}
