package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.protocol.CookieScope;
import click.yukio.dbsc.web.DbscFilter;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * The registration offer is made speculatively, so it needs a ceiling.
 *
 * <p>A browser that supports DBSC registers in response to
 * {@code Secure-Session-Registration}; one that does not — no support, a declined
 * prompt, a cross-site callback that strips the cookie — simply ignores it. Without
 * a budget the second kind would draw a fresh challenge and two rewritten cookies
 * on every authenticated request, forever.
 *
 * <p>The count lives in the pre-registration cookie, so it is per login rather than
 * global, and it survives across requests exactly as the browser carries that
 * cookie.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class BindAttemptsTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private DbscProperties properties;

    @Autowired
    private CookieScope cookieScope;

    @Autowired
    private StorageAdapter storage;

    @Autowired
    private DbscFilter filter;

    @Test
    @DisplayName("an authenticated request is offered the registration header without the app calling bind()")
    @WithMockUser(username = "user_1")
    void authenticatedRequestIsOfferedRegistration() throws Exception {
        String sessionId = seedSession("user_1");

        MvcResult result = mvc.perform(get("/host/whoami")
                        .cookie(sessionCookie(sessionId)))
                .andReturn();

        assertNotNull(result.getResponse().getHeader("Secure-Session-Registration"),
                "the filter must advertise registration on an authenticated request");
        assertNotNull(result.getResponse().getCookie(cookieScope.registrationCookieName()),
                "and must set the pre-registration cookie that carries the attempt count");
    }

    @Test
    @DisplayName("the offer stops after dbsc.bind-attempts requests")
    @WithMockUser(username = "user_1")
    void offerIsBounded() throws Exception {
        String sessionId = seedSession("user_1");
        List<Cookie> cookies = new ArrayList<>();
        cookies.add(sessionCookie(sessionId));

        int budget = properties.getBindAttempts();
        assertTrue(budget > 0, "a zero budget would make DBSC unreachable");

        for (int attempt = 1; attempt <= budget; attempt++) {
            MvcResult result = mvc.perform(get("/host/whoami").cookie(cookies.toArray(new Cookie[0])))
                    .andReturn();

            assertNotNull(result.getResponse().getHeader("Secure-Session-Registration"),
                    "attempt " + attempt + " of " + budget + " must still be offered");

            Cookie counter = result.getResponse().getCookie(cookieScope.registrationCookieName());
            assertNotNull(counter, "each offer refreshes the attempt counter cookie");
            cookies.removeIf(c -> c.getName().equals(cookieScope.registrationCookieName()));
            cookies.add(counter);
            assertEquals(sessionId + "." + attempt, counter.getValue(),
                    "the cookie carries the session id plus the attempts spent");
        }

        // Budget spent: no header, and no further challenge issued.
        MvcResult spent = mvc.perform(get("/host/whoami").cookie(cookies.toArray(new Cookie[0])))
                .andReturn();

        assertEquals(null, spent.getResponse().getHeader("Secure-Session-Registration"),
                "the offer must stop once the budget is spent");
        assertEquals(null, spent.getResponse().getCookie(cookieScope.challengeCookieName()),
                "a request past the budget must not issue another challenge");
    }

    @Test
    @DisplayName("the session id is still read out of a counter-bearing cookie")
    @WithMockUser(username = "user_1")
    void counterDoesNotBreakSessionLookup() throws Exception {
        String sessionId = seedSession("user_1");

        MvcResult result = mvc.perform(get("/host/whoami")
                        .cookie(new Cookie(cookieScope.registrationCookieName(), sessionId + ".2")))
                .andReturn();

        // whoami resolves the session through the same cookie; a mis-parsed counter
        // would report no session at all.
        assertTrue(result.getResponse().getContentAsString().contains(sessionId),
                "the counter suffix must not become part of the session id: "
                        + result.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("an unauthenticated request is not offered registration")
    void anonymousRequestIsNotOffered() throws Exception {
        String sessionId = seedSession("user_1");

        MvcResult result = mvc.perform(get("/host/whoami")
                        .cookie(sessionCookie(sessionId)))
                .andReturn();

        assertEquals(null, result.getResponse().getHeader("Secure-Session-Registration"),
                "there is no authenticated session to bind, so no offer belongs on this response");
    }

    private Cookie sessionCookie(String sessionId) {
        return new Cookie(cookieScope.registrationCookieName(), sessionId);
    }

    private String seedSession(String userId) {
        String sessionId = "sess_" + UUID.randomUUID().toString().replace("-", "");
        storage.setSession(new Session(sessionId, userId, ProtectionTier.NONE,
                0L, System.currentTimeMillis() + 3_600_000L, 0L));
        return sessionId;
    }
}
