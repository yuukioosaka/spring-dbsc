package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.web.DbscFilter;
import click.yukio.dbsc.web.DbscProofGuardFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Answers whether the DBSC filters work in a chain that does not use form login —
 * OIDC login, a bearer-token resource server, or a hand-rolled chain.
 *
 * <p>The library anchors both filters with
 * {@code addFilterBefore(..., UsernamePasswordAuthenticationFilter.class)}, and
 * form login is what normally registers that filter, so this looks like a hidden
 * form-login dependency.
 *
 * <p>It is not one: {@code HttpSecurity} registers an order for
 * {@code UsernamePasswordAuthenticationFilter} as soon as it is created, because
 * the class is in Spring Security's {@code FilterOrderRegistration} table. The
 * anchor names a <em>position</em>, not a bean, so it resolves in any chain. Only
 * an anchor naming a filter <em>instance</em> would impose a dependency, and the
 * library never does that.
 *
 * <p>The test builds the smallest chain that never calls {@code formLogin()},
 * anchored exactly as the library anchors its own, and asserts it builds.
 */
class NonFormLoginChainTest {

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class OidcStyleChain {

        @Bean
        DbscProperties dbscProperties() {
            return new DbscProperties();
        }

        @Bean
        DbscFilter dbscFilter(DbscProperties properties) {
            return new DbscFilter(null, properties);
        }

        @Bean
        DbscProofGuardFilter dbscProofGuardFilter() {
            return new DbscProofGuardFilter(null, List.of(), request -> false);
        }

        @Bean
        SecurityFilterChain chain(HttpSecurity http, DbscFilter dbscFilter,
                                  DbscProofGuardFilter guardFilter) throws Exception {
            http
                    .securityMatcher(new AntPathRequestMatcher("/**"))
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .sessionManagement(session -> session
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .csrf(csrf -> csrf.disable())
                    // Deliberately no formLogin(): the point is whether the anchor
                    // below resolves without it.
                    .addFilterBefore(dbscFilter, UsernamePasswordAuthenticationFilter.class)
                    .addFilterBefore(guardFilter, UsernamePasswordAuthenticationFilter.class);
            return http.build();
        }
    }

    @Test
    @DisplayName("a chain without form login builds with the library's filter anchors")
    void chainWithoutFormLoginBuilds() {
        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
        context.register(OidcStyleChain.class, WebSecurityConfiguration.class);
        context.refresh();
        try {
            // Chain construction is what would have thrown had the anchor required
            // form login, so holding a built chain is the assertion.
            assertNotNull(context.getBean(SecurityFilterChain.class),
                    "the chain built with no form login configured");
            assertEquals(1, context.getBeanNamesForType(SecurityFilterChain.class).length);
        } finally {
            context.close();
        }
    }

    @Test
    @DisplayName("the anchored filter is actually installed, ahead of authorization")
    void anchoredFilterIsInstalledInOrder() {
        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
        context.register(OidcStyleChain.class, WebSecurityConfiguration.class);
        context.refresh();
        try {
            SecurityFilterChain built = context.getBean(SecurityFilterChain.class);
            List<String> order = built.getFilters().stream()
                    .map(filter -> filter.getClass().getSimpleName())
                    .toList();

            int dbsc = order.indexOf("DbscFilter");
            int guard = order.indexOf("DbscProofGuardFilter");
            int authz = order.indexOf("AuthorizationFilter");

            assertTrue(dbsc >= 0, "DbscFilter must be installed, order was " + order);
            assertTrue(guard >= 0, "DbscProofGuardFilter must be installed, order was " + order);
            assertTrue(authz >= 0, "AuthorizationFilter must be present, order was " + order);
            // The anchors name UsernamePasswordAuthenticationFilter's position, and
            // authorization runs after it -- so both DBSC filters precede it and can
            // answer 403 before Spring Security can replace it with its own 401/403.
            assertTrue(dbsc < authz, "DbscFilter must precede authorization, order was " + order);
            assertTrue(guard < authz, "guard must precede authorization, order was " + order);
        } finally {
            context.close();
        }
    }

    /**
     * A real {@code oauth2Login()} chain. This is the arrangement the question is
     * really about: the OIDC login filter takes the place of form login, and
     * {@code UsernamePasswordAuthenticationFilter} is never registered as a bean.
     */
    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class Oauth2LoginChain {

        @Bean
        DbscProperties dbscProperties() {
            return new DbscProperties();
        }

        @Bean
        DbscFilter dbscFilter(DbscProperties properties) {
            return new DbscFilter(null, properties);
        }

        @Bean
        DbscProofGuardFilter dbscProofGuardFilter() {
            return new DbscProofGuardFilter(null, List.of(), request -> false);
        }

        /**
         * {@code oauth2Login()} requires a registration to configure its filter.
         * The values are never used: nothing performs a real OIDC handshake here.
         */
        @Bean
        org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
                clientRegistrationRepository() {
            var registration = org.springframework.security.oauth2.client.registration
                    .ClientRegistration.withRegistrationId("test")
                    .clientId("test-client")
                    .clientSecret("test-secret")
                    .clientAuthenticationMethod(
                            org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(
                            org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                    .scope("openid")
                    .authorizationUri("https://example.test/oauth2/authorize")
                    .tokenUri("https://example.test/oauth2/token")
                    .jwkSetUri("https://example.test/oauth2/jwks")
                    .issuerUri("https://example.test")
                    .userNameAttributeName("sub")
                    .build();
            return new org.springframework.security.oauth2.client.registration
                    .InMemoryClientRegistrationRepository(registration);
        }

        @Bean
        SecurityFilterChain chain(HttpSecurity http, DbscFilter dbscFilter,
                                  DbscProofGuardFilter guardFilter) throws Exception {
            http
                    .securityMatcher(new AntPathRequestMatcher("/**"))
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .sessionManagement(session -> session
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .csrf(csrf -> csrf.disable())
                    .oauth2Login(org.springframework.security.config.Customizer.withDefaults())
                    // The library's anchors, unchanged, in a chain whose
                    // authentication is OIDC rather than a login form.
                    .addFilterBefore(dbscFilter, UsernamePasswordAuthenticationFilter.class)
                    .addFilterBefore(guardFilter, UsernamePasswordAuthenticationFilter.class);
            return http.build();
        }
    }

    @Test
    @DisplayName("a real oauth2Login() chain accommodates the DBSC filters")
    void oauth2LoginChainBuilds() {
        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
        context.register(Oauth2LoginChain.class, WebSecurityConfiguration.class);
        context.refresh();
        try {
            SecurityFilterChain built = context.getBean(SecurityFilterChain.class);
            List<String> order = built.getFilters().stream()
                    .map(filter -> filter.getClass().getSimpleName())
                    .toList();

            // OIDC login is in the chain, and so are both DBSC filters.
            assertTrue(order.stream().anyMatch(name -> name.contains("OAuth2")),
                    "an OAuth2 login filter must be present, order was " + order);
            assertTrue(order.contains("DbscFilter"), "DBSC protocol filter installed: " + order);
            assertTrue(order.contains("DbscProofGuardFilter"), "guard installed: " + order);

            int dbsc = order.indexOf("DbscFilter");
            int authz = order.indexOf("AuthorizationFilter");
            assertTrue(dbsc < authz,
                    "DBSC must still precede authorization under OIDC, order was " + order);
        } finally {
            context.close();
        }
    }
}
