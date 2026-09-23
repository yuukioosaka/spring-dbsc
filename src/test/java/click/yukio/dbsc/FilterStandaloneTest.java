package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.web.DbscBindFilter;
import click.yukio.dbsc.web.DbscFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
        Mockito.when(dbsc.handleRegistration(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(java.util.Map.of("session_identifier", "sess_1"));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/dbsc/regist/tok_1");
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
        Mockito.when(dbsc.handleRegistration(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenThrow(new click.yukio.dbsc.core.DbscException(
                        click.yukio.dbsc.core.DbscErrorCode.SIGNATURE_INVALID, "bad signature"));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/dbsc/regist/tok_1");
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

    /**
     * Soft DBSC is opt-in, and the gate is route registration rather than a check
     * inside the handler. The difference is observable: with the feature off the
     * request reaches the application untouched, so whatever it answers (a 404, a
     * login redirect, a handler of the same name) is what the client sees, and the
     * DBSC service is never consulted at all.
     */
    @Test
    @DisplayName("POST to the bind path passes through when Soft DBSC is off")
    void bindRouteIsAbsentByDefault() throws Exception {
        // The default is off, so the setUp() filter already has no such route.
        assertFalse(properties.getSoft().isEnabled(),
                "the default must stay false: enabling it widens the trust model");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/dbsc/bind");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        dbscFilter.doFilter(request, response, chain);

        assertNotNull(chain.getRequest(),
                "with the feature off the request must reach the application");
        Mockito.verify(dbsc, Mockito.never())
                .handleBind(Mockito.any(), Mockito.any());
    }

    @Test
    @DisplayName("POST to the bind path is owned by DbscBindFilter when Soft DBSC is on")
    void bindRouteAppearsWhenEnabled() throws Exception {
        properties.getSoft().setEnabled(true);
        // The bind route is deliberately not part of DbscFilter: that filter's routes
        // are protocol routes it must answer before the application's security runs,
        // and this one is an application route that has to be reached only after it.
        // What DbscFilter owns is the decision of whether the route exists at all.
        DbscFilter enabled = new DbscFilter(dbsc, properties);
        Mockito.when(dbsc.handleBind(Mockito.any(), Mockito.any()))
                .thenReturn(java.util.Map.of("sessionId", "sess_1"));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/dbsc/bind");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        enabled.doFilter(request, response, chain);

        assertTrue(enabled.isBindRouteEnabled(),
                "the property must be what decides whether the route is served");
        assertNotNull(chain.getRequest(),
                "the bind route must reach the application chain, where it is served");

        // And the filter that does serve it answers it, rather than passing through.
        DbscBindFilter bindFilter = new DbscBindFilter(dbsc, properties);
        MockHttpServletResponse bindResponse = new MockHttpServletResponse();
        MockFilterChain bindChain = new MockFilterChain();
        bindFilter.doFilter(request, bindResponse, bindChain);

        assertEquals(200, bindResponse.getStatus());
        assertNull(bindChain.getRequest(), "DbscBindFilter owns the response on this path");
    }

    @Test
    @DisplayName("the bind filter is inert when Soft DBSC is off")
    void bindFilterIsInertWhenDisabled() throws Exception {
        DbscBindFilter bindFilter = new DbscBindFilter(dbsc, properties);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/dbsc/bind");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        bindFilter.doFilter(request, response, chain);

        assertNotNull(chain.getRequest(),
                "with the feature off the path must fall through to the application");
        Mockito.verify(dbsc, Mockito.never()).handleBind(Mockito.any(), Mockito.any());
    }
}
