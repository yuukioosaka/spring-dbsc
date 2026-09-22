package click.yukio.dbsc;

import click.yukio.dbsc.core.GuardDecision;
import click.yukio.dbsc.web.DbscGuardFilter;
import click.yukio.dbsc.web.DbscGuardRoutes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The guard filter at the boundary: what it refuses, what it lets through, and
 * what it hands to the decision.
 *
 * <p>The decision itself lives in {@link DbscService#guardDecision}, which needs the
 * session store; here it is stubbed so these pin the filter's own contract. The
 * rules themselves are covered in {@link GuardDecisionTest}.
 */
class GuardFilterTest {

    private static final String GUARDED = "/api/transfer";

    private DbscService dbsc;
    private DbscGuardFilter guard;

    @BeforeEach
    void setUp() {
        dbsc = Mockito.mock(DbscService.class);
        guard = new DbscGuardFilter(dbsc, DbscGuardRoutes.of(
                new AntPathRequestMatcher(GUARDED)));
    }

    private MockHttpServletRequest request(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        // AntPathRequestMatcher matches on the path *within the context*, so it
        // reads servletPath rather than requestURI. MockHttpServletRequest derives
        // servletPath from the URI in the constructor, but setting it explicitly
        // keeps the mock honest about what a real container hands the filter.
        request.setServletPath(path);
        return request;
    }

    private void decide(GuardDecision decision) {
        Mockito.when(dbsc.guardDecision(Mockito.any(), Mockito.any())).thenReturn(decision);
    }

    @Test
    @DisplayName("an unguarded path is never even inspected")
    void unguardedPathPassesThrough() throws Exception {
        MockHttpServletRequest request = request("/api/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        guard.doFilter(request, response, chain);

        assertNotNull(chain.getRequest(), "an unguarded route must reach the chain");
        Mockito.verifyNoInteractions(dbsc);
    }

    @Test
    @DisplayName("a guarded route passes when the decision allows it")
    void allowedSessionReachesTheHandler() throws Exception {
        decide(GuardDecision.allow(GuardDecision.Reason.PROTECTED));

        MockHttpServletRequest request = request(GUARDED);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        guard.doFilter(request, response, chain);

        assertNotNull(chain.getRequest(), "an allowed session must reach the handler");
        assertEquals(200, response.getStatus());
    }

    @Test
    @DisplayName("an unregistered client is allowed: DBSC is additive")
    void unregisteredClientIsAllowed() throws Exception {
        decide(GuardDecision.allow(GuardDecision.Reason.UNREGISTERED));

        MockFilterChain chain = new MockFilterChain();
        guard.doFilter(request(GUARDED), new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest(),
                "a browser that never registered must still be able to use the route");
    }

    @Test
    @DisplayName("a lapsed session is refused")
    void lapsedSessionIsRefused() throws Exception {
        decide(GuardDecision.deny(GuardDecision.Reason.LAPSED));

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        guard.doFilter(request(GUARDED), response, chain);

        assertEquals(403, response.getStatus());
        assertNull(chain.getRequest(), "a refused request must not reach the handler");
        assertTrue(response.getContentAsString().contains(DbscGuardFilter.REQUIRED_CODE),
                response.getContentAsString());
    }

    @Test
    @DisplayName("a binding whose cookies were not sent is refused")
    void missingCookieIsRefused() throws Exception {
        decide(GuardDecision.deny(GuardDecision.Reason.COOKIE_MISSING));

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        guard.doFilter(request(GUARDED), response, chain);

        assertEquals(403, response.getStatus());
        assertNull(chain.getRequest());
        assertTrue(response.getContentAsString().contains(DbscGuardFilter.REQUIRED_CODE),
                response.getContentAsString());
    }

    @Test
    @DisplayName("a revoked binding is refused")
    void revokedSessionIsRefused() throws Exception {
        decide(GuardDecision.deny(GuardDecision.Reason.REVOKED));

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        guard.doFilter(request(GUARDED), response, chain);

        assertEquals(403, response.getStatus());
        assertNull(chain.getRequest());
    }

    @Test
    @DisplayName("the refusal is 403, never 401")
    void refusalIsForbiddenNotUnauthorized() throws Exception {
        decide(GuardDecision.deny(GuardDecision.Reason.LAPSED));

        MockHttpServletResponse response = new MockHttpServletResponse();
        guard.doFilter(request(GUARDED), response, new MockFilterChain());

        assertEquals(403, response.getStatus(),
                "401 is fatal to Chromium on the refresh route and reads as signed-out"
                        + " rather than step-up");
        assertEquals("no-store", response.getHeader("Cache-Control"));
    }

    @Test
    @DisplayName("the application's session id is offered to the decision")
    void appSessionIdIsPassedToTheDecision() throws Exception {
        decide(GuardDecision.allow(GuardDecision.Reason.PROTECTED));

        MockHttpServletRequest request = request(GUARDED);
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        guard.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        Mockito.verify(dbsc).guardDecision(request, session.getId());
    }

    @Test
    @DisplayName("declaring no guarded routes leaves the filter inert")
    void noGuardedRoutesMeansNoGuard() throws Exception {
        // What the auto-configuration hands the filter when the application declares
        // no DbscGuardRoutes bean.
        DbscGuardFilter inert = new DbscGuardFilter(dbsc, request -> false);

        MockHttpServletRequest request = request(GUARDED);
        MockFilterChain chain = new MockFilterChain();
        inert.doFilter(request, new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest());
        Mockito.verifyNoInteractions(dbsc);
    }

    @Test
    @DisplayName("a matcher can cover a prefix, the way authorizeHttpRequests does")
    void prefixMatcherGuardsEveryPathUnderIt() throws Exception {
        DbscGuardFilter byPrefix = new DbscGuardFilter(dbsc, DbscGuardRoutes.of(
                new AntPathRequestMatcher("/api/**")));
        decide(GuardDecision.deny(GuardDecision.Reason.LAPSED));

        MockHttpServletResponse response = new MockHttpServletResponse();
        byPrefix.doFilter(request("/api/v1/transfer"), response, new MockFilterChain());
        assertEquals(403, response.getStatus());

        // Outside the pattern, the filter does not run at all.
        MockFilterChain chain = new MockFilterChain();
        byPrefix.doFilter(request("/other/transfer"), new MockHttpServletResponse(), chain);
        assertNotNull(chain.getRequest());
    }

    @Test
    @DisplayName("several matchers are OR-ed")
    void severalMatchersAreOred() throws Exception {
       DbscGuardFilter multi = new DbscGuardFilter(dbsc, DbscGuardRoutes.of(List.of(
                new AntPathRequestMatcher("/api/**"),
                new AntPathRequestMatcher("/account/**"))));
        decide(GuardDecision.deny(GuardDecision.Reason.LAPSED));

        MockHttpServletResponse second = new MockHttpServletResponse();
        multi.doFilter(request("/account/settings"), second, new MockFilterChain());
        assertEquals(403, second.getStatus());
    }

    @Test
    @DisplayName("an empty matcher list is refused rather than silently disabling the guard")
    void emptyRoutesAreRejected() {
        assertThrows(IllegalArgumentException.class, DbscGuardRoutes::of);
        assertThrows(IllegalArgumentException.class, () -> DbscGuardRoutes.of(List.of()));
    }
}
