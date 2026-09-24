package click.yukio.dbsc.demo;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.web.DbscBindFilter;
import click.yukio.dbsc.web.DbscFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import java.util.UUID;

/**
 * The application's own security chains, with the DBSC filters inside them.
 *
 * <p>This is the shape of every real adopter: the library ships the filter, the
 * application decides where it sits. Nothing has to be opted out of or worked
 * around, because the library declares no chain of its own.
 *
 * <p>Two chains, in order. The protocol chain exists because these routes must be
 * reachable <em>unauthenticated</em>, must not have CSRF applied to them, and must
 * reach {@code DbscFilter} rather than Security's entry point — a 401 there is fatal
 * to Chromium. Everything else is the application's.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class DemoFormLoginTestConfig {

    /**
     * The DBSC protocol routes, unauthenticated by construction.
     *
     * <p>Matched on Ant patterns rather than the String overload, which resolves
     * to {@code MvcRequestMatcher} and drags in an MVC dependency the filter layer
     * has no business having.
     *
     * <p>The two application chains are nested in {@link FormLoginChains} so the
     * whole authentication setup can be switched off at once under the
     * {@code oidc} profile, which supplies its own instead. Registering both would
     * leave two chains matching {@code /**} and the winner up to bean ordering.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnExpression("!environment.acceptsProfiles('oidc')")
    static class FormLoginChains {

        @Bean
        @Order(0)
        SecurityFilterChain dbscProtocolChain(
                HttpSecurity http, @Qualifier("dbscFilter") DbscFilter dbscFilter) throws Exception {
            http
                    // One OrRequestMatcher rather than chained securityMatcher() calls:
                    // each call SETS the matcher, so chaining silently keeps only the
                    // last path and the other routes fall through to the app chain.
                    //
                    // The bind path is deliberately NOT here. It is the one DBSC route
                    // that names its session from the application's own cookie and is
                    // therefore authenticated -- see ScriptClientTest. Leaving it on the
                    // protocol chain would put an unauthenticated route next to an
                    // authenticated one and lose the distinction entirely.
                    .securityMatcher(new OrRequestMatcher(
                            new AntPathRequestMatcher("/dbsc/regist/**"),
                            new AntPathRequestMatcher("/dbsc/refresh"),
                            new AntPathRequestMatcher("/.well-known/device-bound-sessions")))
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    // Chromium drives these routes before any user session exists and
                    // posts no CSRF token with them.
                    .sessionManagement(session -> session
                            .sessionCreationPolicy(
                                    org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
                    .csrf(csrf -> csrf.disable())
                    // CsrfFilter sits before UsernamePasswordAuthenticationFilter, so a
                    // filter positioned relative to the latter would still land after
                    // it and let CSRF reject the browser's registration POST first.
                    // Anchor on CsrfFilter instead, so DBSC sees the request first.
                    .addFilterBefore(dbscFilter, CsrfFilter.class);
            return http.build();
        }

        /**
         * The application chain: form login, authorization and logout.
         */
        @Bean
        @Order(1)
        SecurityFilterChain appChain(HttpSecurity http, DbscService dbsc,
                                     DbscBindFilter dbscBindFilter)
                throws Exception {

            http
                    .securityMatcher(new AntPathRequestMatcher("/**"))
                    .authorizeHttpRequests(auth -> auth
                            // The Soft DBSC client and its Service Worker. A module
                            // import that 302s to the login page fails before any of
                            // it runs, and neither file is a secret: they are the
                            // same scripts every visitor gets. They are served even
                            // when the feature is off (the page does not reference
                            // them then), which keeps the static paths independent of
                            // the property.
                            .requestMatchers("/login", "/css/**", "/favicon.ico",
                                    "/dbsc-soft-client.js", "/dbsc-soft-sw.js").permitAll()
                            // The script client's re-offer route, and the reason it is on
                            // this chain rather than the protocol one: it names its
                            // session from the request's own cookie, so being able to
                            // reach it means being logged in. Authentication and CSRF
                            // are the ordinary ones, and there is nothing DBSC-specific
                            // about either.
                            .requestMatchers("/dbsc/bind").authenticated()
                            // /app/payment needs a session DBSC currently protects;
                            // /app/whoami does not. Both are authenticated -- that is the
                            // difference the tier makes.
                            //
                            // Authentication is repeated inside allOf rather than left to
                            // `anyRequest().authenticated()` below, because this rule is
                            // the one that matches and returns first: one rule per matcher,
                            // both conditions, or the second condition is dead code.
                            // RuleCompositionTest demonstrates exactly that failure.
                            .requestMatchers("/app/payment").access(AuthorizationManagers.allOf(
                                    AuthenticatedAuthorizationManager.authenticated(),
                                    (authentication, context) ->
                                            new AuthorizationDecision(
                                                    dbsc.isProtected(context.getRequest()))))
                            .anyRequest().authenticated())
                    // The one DBSC call the application has to make, and it belongs
                    // here rather than in a separate handler class: it needs the
                    // request, the response and the authenticated principal together,
                    // and after Security's own authentication this is the earliest
                    // point where all three exist.
                    .formLogin(form -> form
                            .loginPage("/login")
                            .successHandler((request, response, authentication) -> {
                                // The DBSC session id is minted here and is
                                // deliberately unrelated to the application's own
                                // session id: it identifies the binding and keys the
                                // device's public key, so the two identifiers are
                                // free to be independent. Nothing needs to be held
                                // on to it — the logout handler reads it back from
                                // the DBSC session cookie.
                                String dbscSessionId = UUID.randomUUID().toString();

                                // The application's own session id is passed too, so
                                // the guard can tell a client that never registered
                                // apart from one that dropped its DBSC cookies. Force
                                // the session to exist first: a login always has one,
                                // even if nothing touched it earlier.
                                String appSessionId = request.getSession().getId();

                                // The lifetime is dbsc.session-ttl: a binding's deadline
                                // is deployment configuration, not something a login
                                // route decides per call.
                                dbsc.bind(dbscSessionId, appSessionId, authentication.getName(),
                                        request, response);

                                response.sendRedirect("/app");
                            })
                            .permitAll())
                    // Spring Security keeps the CSRF token in the session and, by
                    // default, only accepts it as a request parameter. The demo's
                    // fetch() calls send JSON, so the token has to be accepted as a
                    // header instead; without this every POST is refused by
                    // CsrfFilter and the 403 is indistinguishable from DBSC's own.
                    //
                    // The bind route needs nothing beyond this: it is an ordinary
                    // application route, so CsrfFilter protects it with no help from
                    // the library.
                    .csrf(csrf -> csrf
                            .csrfTokenRepository(new HttpSessionCsrfTokenRepository())
                            .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
                    // The re-offer route, after everything that could refuse it. It
                    // writes its own response, so it has to be last: an authenticated
                    // and token-checked request that gets here is one the host has
                    // already allowed.
                    .addFilterAfter(dbscBindFilter, CsrfFilter.class)
                    .logout(logout -> logout
                            .logoutUrl("/logout")
                            .addLogoutHandler(demoLogoutHandler(dbsc))
                            .logoutSuccessUrl("/login?loggedout"));
            return http.build();
        }
    }

    /**
     * Ends the DBSC binding when the user logs out.
     *
     * <p>{@code terminate()} tells the browser to forget the binding and clears
     * every DBSC cookie. Without it the device key outlives the login session:
     * the browser keeps refreshing a session the application has already ended,
     * and a later login re-couples to a stale key instead of registering a fresh
     * one.
     */
    private static LogoutHandler demoLogoutHandler(DbscService dbsc) {
        return (request, response, authentication) -> {
            // The DBSC session id is not the application's session id, so it is
            // read back from the DBSC session cookie rather than from the
            // HttpSession. Ending the HttpSession alone would leave the binding
            // alive.
            dbsc.sessionFor(request).ifPresent(session ->
                    dbsc.terminate(session.id(), request, response));
        };
    }

    /**
     * Boot auto-registers every {@code Filter} bean as a plain servlet filter,
     * outside the security chain — which would run the filter a second time,
     * before authentication and on every path. Disabling the registration keeps
     * it in the chain only.
     */
    @Bean
    FilterRegistrationBean<DbscFilter> dbscFilterRegistration(DbscFilter filter) {
        FilterRegistrationBean<DbscFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    /**
     * The re-offer route. It runs in the application chain, after authentication and
     * CSRF, because unlike the protocol routes it is not something a browser proves
     * its way into -- it is an application route that names its session from the
     * request's own cookie. Registering it as a bean also lets Boot's "every filter is
     * a servlet filter" rule be switched off for it below.
     */
    @Bean
    DbscBindFilter dbscBindFilter(DbscService dbsc, click.yukio.dbsc.config.DbscProperties properties) {
        return new DbscBindFilter(dbsc, properties);
    }

    /**
     * Boot would otherwise register the filter above as a plain servlet filter, outside
     * the security chain and before authentication -- which would answer the route
     * with none of the checks this chain applies.
     */
    @Bean
    FilterRegistrationBean<DbscBindFilter> dbscBindFilterRegistration(DbscBindFilter filter) {
        FilterRegistrationBean<DbscBindFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(PasswordEncoder encoder) {
        UserDetails user = User.withUsername("demo")
                .password(encoder.encode("demo"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
