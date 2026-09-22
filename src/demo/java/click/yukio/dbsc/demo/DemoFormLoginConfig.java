package click.yukio.dbsc.demo;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.web.DbscFilter;
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
import jakarta.servlet.http.HttpSession;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

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
public class DemoFormLoginConfig {

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
        SecurityFilterChain appChain(HttpSecurity http, DbscService dbsc) throws Exception {

            http
                    .securityMatcher(new AntPathRequestMatcher("/**"))
                    .authorizeHttpRequests(auth -> auth
                            .requestMatchers("/login", "/css/**", "/favicon.ico").permitAll()
                            .requestMatchers("/app/payment").authenticated()
                            .anyRequest().authenticated())
                    // The one DBSC call the application has to make, and it belongs
                    // here rather than in a separate handler class: it needs the
                    // request, the response and the authenticated principal together,
                    // and after Security's own authentication this is the earliest
                    // point where all three exist.
                    .formLogin(form -> form
                            .loginPage("/login")
                            .successHandler((request, response, authentication) -> {
                                // The demo asserts the session id is stable; forcing
                                // creation here means a login always has one, even if
                                // nothing touched it earlier. bind() keys the DBSC
                                // session on exactly this id, so a DBSC binding and a
                                // login session cannot drift apart.
                                HttpSession session = request.getSession();

                                // The TTL is the application's policy, not DBSC's.
                                // Pass the same lifetime the login session gets, or
                                // the two expire on different clocks.
                                dbsc.bind(session.getId(), authentication.getName(),
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
     * the binding cookie. Without it the device key outlives the login session:
     * the browser keeps refreshing a session the application has already ended,
     * and a later login re-couples to a stale key instead of registering a fresh
     * one.
     */
    private static LogoutHandler demoLogoutHandler(DbscService dbsc) {
        return (request, response, authentication) -> {
            HttpSession session = request.getSession(false);
            if (session != null) {
                dbsc.terminate(session.getId(), request, response);
            }
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
