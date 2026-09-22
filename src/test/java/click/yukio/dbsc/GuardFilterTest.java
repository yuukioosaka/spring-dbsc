package click.yukio.dbsc;

import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.web.DbscGuardFilter;
import click.yukio.dbsc.web.GuardedRoute;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The tier guard, at the filter boundary.
 *
 * <p>These pin the contract an application depends on: a guarded route refuses
 * with 403 and {@code DBSC_REQUIRED} whenever the session is not currently
 * protected, and passes through untouched when it is. Everything else in the
 * chain — authentication, authorization, the route itself — is unchanged, which
 * is what {@link DbscGuardFilter} existing as a filter rather than as a
 * replacement for the application's own authorization is meant to guarantee.
 */
class GuardFilterTest {

    private static final String GUARDED = "/api/transfer";

    private DbscService dbsc;
    private DbscGuardFilter guard;

    @BeforeEach
    void setUp() {
        dbsc = Mockito.mock(DbscService.class);
        guard = new DbscGuardFilter(dbsc, List.of(GuardedRoute.at(GUARDED)));
    }

    private MockHttpServletRequest request(String path) {
        return new MockHttpServletRequest("POST", path);
    }

    private static Session session(String id, ProtectionTier tier) {
        long now = System.currentTimeMillis();
        return new Session(id, "user_1", tier, now, now + 60_000, 0);
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
    @DisplayName("a guarded route passes when the session is at tier dbsc")
    void boundSessionIsAllowed() throws Exception {
        Mockito.when(dbsc.sessionFor(Mockito.any()))
                .thenReturn(Optional.of(session("sess_1", ProtectionTier.DBSC)));
        Mockito.when(dbsc.tierFor("sess_1")).thenReturn(ProtectionTier.DBSC);

        MockHttpServletRequest request = request(GUARDED);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        guard.doFilter(request, response, chain);

        assertNotNull(chain.getRequest(), "a bound session must reach the handler");
        assertNull(chain.getRequest().getAttribute("dbsc.denied"));
    }

    @Test
    @DisplayName("a guarded route refuses when no DBSC session is on the request")
    void missingSessionIsRefused() throws Exception {
        Mockito.when(dbsc.sessionFor(Mockito.any())).thenReturn(Optional.empty());

        MockHttpServletRequest request = request(GUARDED);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        guard.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertNull(chain.getRequest(), "a refused request must not reach the handler");
        assertTrue(response.getContentAsString().contains(DbscGuardFilter.REQUIRED_CODE),
                response.getContentAsString());
    }

    @Test
    @DisplayName("a guarded route refuses a session that has been demoted to none")
    void demotedSessionIsRefused() throws Exception {
        // The key is still registered — this is the theft case, where the stored
        // key proves nothing because the refreshes stopped.
        Mockito.when(dbsc.sessionFor(Mockito.any()))
                .thenReturn(Optional.of(session("sess_1", ProtectionTier.NONE)));
        Mockito.when(dbsc.tierFor("sess_1")).thenReturn(ProtectionTier.NONE);

        MockHttpServletRequest request = request(GUARDED);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        guard.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertNull(chain.getRequest());
        assertTrue(response.getContentAsString().contains(DbscGuardFilter.REQUIRED_CODE),
                response.getContentAsString());
    }

    @Test
    @DisplayName("the refusal is 403, never 401")
    void refusalIsForbiddenNotUnauthorized() throws Exception {
        Mockito.when(dbsc.sessionFor(Mockito.any())).thenReturn(Optional.empty());

        MockHttpServletResponse response = new MockHttpServletResponse();
        guard.doFilter(request(GUARDED), response, new MockFilterChain());

        assertEquals(403, response.getStatus(),
                "401 is fatal to Chromium on the refresh route and reads as signed-out"
                        + " rather than step-up");
        assertEquals("no-store", response.getHeader("Cache-Control"));
    }

    @Test
    @DisplayName("the guard asks about the tier, not about the key")
    void tierIsWhatMatters() throws Exception {
        Mockito.when(dbsc.sessionFor(Mockito.any()))
                .thenReturn(Optional.of(session("sess_1", ProtectionTier.NONE)));
        Mockito.when(dbsc.tierFor("sess_1")).thenReturn(ProtectionTier.NONE);

        guard.doFilter(request(GUARDED), new MockHttpServletResponse(), new MockFilterChain());

        Mockito.verify(dbsc).tierFor("sess_1");
        Mockito.verify(dbsc, Mockito.never()).hasDeviceKey(Mockito.anyString());
    }

    @Test
    @DisplayName("declaring no guarded routes leaves the filter inert")
    void noGuardedRoutesMeansNoGuard() throws Exception {
        DbscGuardFilter inert = new DbscGuardFilter(dbsc, List.of());

        MockHttpServletRequest request = request(GUARDED);
        MockFilterChain chain = new MockFilterChain();
        inert.doFilter(request, new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest());
        Mockito.verifyNoInteractions(dbsc);
    }

    @Test
    @DisplayName("a guarded route has to be a real path")
    void guardedRouteValidatesItsPath() {
        assertThrows(IllegalArgumentException.class, () -> GuardedRoute.at(null));
        assertThrows(IllegalArgumentException.class, () -> GuardedRoute.at("  "));
        assertThrows(IllegalArgumentException.class, () -> GuardedRoute.at("api/transfer"));
    }
}
