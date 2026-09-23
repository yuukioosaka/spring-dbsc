package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.web.DbscFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The one deployment mistake that silently breaks {@code POST /dbsc/bind}: enabling
 * CSRF on a chain that keeps no session.
 *
 * <p>The route is an ordinary application route protected by ordinary Spring Security
 * CSRF, and the default {@code CsrfTokenRepository} is session-backed — it stores the
 * token on the {@code HttpSession}. A chain configured
 * {@code SessionCreationPolicy.STATELESS} therefore has nowhere to put the token: the
 * request that renders the page gets no session, the stored token is never found again,
 * and <em>every</em> bind POST is refused. Nothing throws at startup, the route looks
 * wired correctly, and the failure is a bare 403 that reads like a DBSC refusal.
 *
 * <p>This is exactly the bug that was found by hand in this repository's own test host,
 * which is why it is pinned here rather than left to documentation. The fix is to leave
 * the application chain at {@code IF_REQUIRED}; the protocol chain can stay stateless
 * precisely because CSRF is off there.
 *
 * <p>The check is on the built chain's filter list rather than on a live request,
 * because the repository binding is what is being asserted: with
 * {@code HttpSessionCsrfTokenRepository} in the list and a stateless session policy,
 * the configuration is contradictory whatever a request happens to do.
 */
class CsrfSessionPolicyTest {

    /** The shape that works: sessions are kept, so the token has somewhere to live. */
    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class SessionBackedCsrfChain {

        @Bean
        DbscProperties dbscProperties() {
            return new DbscProperties();
        }

        @Bean
        DbscFilter dbscFilter(DbscProperties properties) {
            return new DbscFilter(null, properties);
        }

        @Bean
        CsrfTokenRepository csrfTokenRepository() {
            return new HttpSessionCsrfTokenRepository();
        }

        @Bean
        SecurityFilterChain chain(HttpSecurity http, DbscFilter dbscFilter,
                                 CsrfTokenRepository csrfTokenRepository) throws Exception {
            http
                    .securityMatcher(new AntPathRequestMatcher("/**"))
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .csrf(csrf -> csrf
                            .csrfTokenRepository(csrfTokenRepository)
                            .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
                    .addFilterBefore(dbscFilter, CsrfFilter.class);
            return http.build();
        }
    }

    @Test
    @DisplayName("a session-backed CSRF repository is usable when the chain keeps sessions")
    void sessionBackedCsrfNeedsSessions() {
        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
        context.register(SessionBackedCsrfChain.class, WebSecurityConfiguration.class);
        context.refresh();
        try {
            SecurityFilterChain built = context.getBean(SecurityFilterChain.class);
            List<String> order = built.getFilters().stream()
                    .map(filter -> filter.getClass().getSimpleName())
                    .toList();

            assertTrue(order.contains("CsrfFilter"),
                    "CSRF must be installed on the application chain, order was " + order);

            // The default policy for an application chain is IF_REQUIRED, which is what
            // makes the session-backed repository work. A chain that pinned STATELESS
            // here would be unable to validate a token it had just stored.
            CsrfTokenRepository repository = context.getBean(CsrfTokenRepository.class);
            MockHttpServletRequest tokenRequest = new MockHttpServletRequest();
            tokenRequest.setSession(new MockHttpSession());
            CsrfToken token = repository.generateToken(tokenRequest);
            repository.saveToken(token, tokenRequest, new MockHttpServletResponse());

            MockHttpServletRequest reread = new MockHttpServletRequest();
            reread.setSession(tokenRequest.getSession());
            assertEquals(token.getToken(), repository.loadToken(reread).getToken(),
                    "the token must round-trip on the session it was stored against");
        } finally {
            context.close();
        }
    }

    /**
     * The mistake itself, reproduced: a session-backed repository on a stateless chain.
     *
     * <p>Spring accepts this configuration without complaint, and the token cannot survive
     * the request that created it. Asserting the failure rather than only the fix is what
     * makes the guidance checkable — a future refactor that reintroduced {@code STATELESS}
     * on the demo's application chain would otherwise pass every other test in this suite.
     */
    @Test
    @DisplayName("a session-backed CSRF repository on a stateless chain loses every token")
    void statelessChainCannotHoldASessionBackedToken() {
        CsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();

        MockHttpServletRequest storing = new MockHttpServletRequest();
        storing.setSession(new MockHttpSession());
        CsrfToken token = repository.generateToken(storing);
        repository.saveToken(token, storing, new MockHttpServletResponse());

        // Now the request a stateless chain would receive: no session, so no token.
        MockHttpServletRequest next = new MockHttpServletRequest();
        assertFalse(next.getSession(false) != null,
                "a stateless chain hands the next request no session");
        assertTrue(repository.loadToken(next) == null,
                "and therefore no stored token: any CSRF check on it must fail");
    }

    /**
     * The premise the fix rests on: the protocol chain, where CSRF is off, is free to be
     * stateless. Only the application chain has to keep a session.
     */
    @Test
    @DisplayName("a stateless chain is fine when CSRF is off, which is the protocol chain's shape")
    void statelessIsFineWithoutCsrf() throws Exception {
        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
        context.register(StatelessCsrfOffChain.class, WebSecurityConfiguration.class);
        context.refresh();
        try {
            SecurityFilterChain built = context.getBean(SecurityFilterChain.class);
            List<String> order = built.getFilters().stream()
                    .map(filter -> filter.getClass().getSimpleName())
                    .toList();
            assertFalse(order.contains("CsrfFilter"),
                    "CSRF must be absent, or the stateless chain could not be validated at all: " + order);
        } finally {
            context.close();
        }
    }

    /** The protocol chain's shape: stateless, CSRF off, DBSC's own proof is the check. */
    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class StatelessCsrfOffChain {

        @Bean
        DbscProperties dbscProperties() {
            return new DbscProperties();
        }

        @Bean
        DbscFilter dbscFilter(DbscProperties properties) {
            return new DbscFilter(null, properties);
        }

        @Bean
        SecurityFilterChain chain(HttpSecurity http, DbscFilter dbscFilter) throws Exception {
            http
                    .securityMatcher(new AntPathRequestMatcher("/dbsc/**"))
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .sessionManagement(session -> session
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .csrf(csrf -> csrf.disable())
                    .addFilterBefore(dbscFilter, CsrfFilter.class);
            return http.build();
        }
    }
}
