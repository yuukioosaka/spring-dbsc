package click.yukio.dbsc.demo;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.web.DbscFilter;
import click.yukio.dbsc.web.DbscGuardFilter;
import click.yukio.dbsc.web.DbscGuardRoutes;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
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

    /** Stands in for the application's own session/TTL policy. */
    private static final long SESSION_TTL_MS = 7L * 24 * 60 * 60 * 1000;

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
                    .securityMatcher(new OrRequestMatcher(
                            new AntPathRequestMatcher("/dbsc/**"),
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
                                     @Qualifier("dbscGuardFilter") DbscGuardFilter dbscGuardFilter)
                throws Exception {

            http
                    .securityMatcher(new AntPathRequestMatcher("/**"))
                    .authorizeHttpRequests(auth -> auth
                            .requestMatchers("/login", "/css/**", "/favicon.ico").permitAll()
                            .requestMatchers("/app/payment").authenticated()
                            .anyRequest().authenticated())
                    // The guard, on the application chain: /app/payment needs a
                    // session DBSC currently protects, /app/whoami does not. Both
                    // are authenticated; that is the difference the tier makes.
                    .addFilterBefore(dbscGuardFilter, CsrfFilter.class)
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

                                // The TTL is the application's policy, not DBSC's.
                                dbsc.bind(dbscSessionId, appSessionId, authentication.getName(),
                                        SESSION_TTL_MS, request, response);

                                response.sendRedirect("/app");
                            })
                            .permitAll())
                    // Spring Security keeps the CSRF token in the session and, by
                    // default, only accepts it as a request parameter. The demo's
                    // fetch() calls send JSON, so the token has to be accepted as a
                    // header instead; without this every POST is refused by
                    // CsrfFilter and the 403 is indistinguishable from DBSC's own.
                    .csrf(csrf -> csrf
                            .csrfTokenRepository(new HttpSessionCsrfTokenRepository())
                            .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
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
     * The routes whose session must currently be DBSC-protected. Declaring none
     * leaves the guard filter a no-op, which is the library's default: DBSC
     * protects nothing until the application says which requests matter.
     *
     * <p>The pattern is what the application decides, not the library: a wider
     * matcher does not mean a stricter application, because a client that never
     * registered is allowed through either way ({@code dbsc.unregistered}).
     */
    @Bean
    DbscGuardRoutes dbscGuardRoutes() {
        return DbscGuardRoutes.of(new AntPathRequestMatcher("/app/payment"));
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

    @Bean
    FilterRegistrationBean<DbscGuardFilter> dbscGuardFilterRegistration(DbscGuardFilter filter) {
        FilterRegistrationBean<DbscGuardFilter> registration = new FilterRegistrationBean<>(filter);
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
