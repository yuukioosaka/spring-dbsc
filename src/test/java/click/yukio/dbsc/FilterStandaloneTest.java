package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.web.DbscFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The filters are not Spring Security components, and these tests pin that down.
 *
 * <p>The library declares no {@code SecurityFilterChain} — only the filter — so an
 * application with its own security stack, or none at all, can drop
 * {@link DbscFilter} into a plain servlet chain.
 * If the filter starts depending on Security's request wrappers or context,
 * these tests fail.
 */
class FilterStandaloneTest {

    private DbscService dbsc;
    private DbscProperties properties;
    private DbscFilter dbscFilter;

    @BeforeEach
    void setUp() {
        dbsc = Mockito.mock(DbscService.class);
        properties = new DbscProperties();
        dbscFilter = new DbscFilter(dbsc, properties);
    }

    @Test
    @DisplayName("a non-DBSC path passes straight through to the chain")
    void unrelatedRequestIsUntouched() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        dbscFilter.doFilter(request, response, chain);

        assertTrue(chain.getRequest() != null,
                "an unrelated request must reach the rest of the chain");
        assertNull(((MockHttpServletResponse) chain.getResponse())
                .getHeader("Secure-Session-Registration"));
    }

    @Test
    @DisplayName("a DBSC path never reaches the rest of the chain")
    void dbscRouteTerminatesTheChain() throws Exception {
        Mockito.when(dbsc.handleRegistration(Mockito.any(), Mockito.any()))
                .thenReturn(java.util.Map.of("session_identifier", "sess_1"));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/dbsc/registration");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        dbscFilter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertNull(chain.getRequest(),
                "DBSC owns the response; nothing downstream may run for these paths");
    }

    @Test
    @DisplayName("a DBSC failure is 403 with a JSON error, emitted by the filter itself")
    void dbscFailureIsForbidden() throws Exception {
        Mockito.when(dbsc.handleRegistration(Mockito.any(), Mockito.any()))
                .thenThrow(new click.yukio.dbsc.core.DbscException(
                        click.yukio.dbsc.core.DbscErrorCode.SIGNATURE_INVALID, "bad signature"));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/dbsc/registration");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        dbscFilter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus(),
                "401 here would be ignored by Chromium and the session would die");
        assertTrue(response.getContentAsString().contains("SIGNATURE_INVALID"),
                response.getContentAsString());
    }

    @Test
    @DisplayName("the well-known document is served without a session")
    void wellKnownNeedsNothing() throws Exception {
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/.well-known/device-bound-sessions");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        dbscFilter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertTrue(response.getContentAsString().contains("registering_origins"));
    }
}
