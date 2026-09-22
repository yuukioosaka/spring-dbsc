package click.yukio.dbsc.demo;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.web.DbscFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.springframework.web.servlet.function.RouterFunctions.route;

/**
 * The OIDC variant of the demo's security setup, active only under the
 * {@code oidc} profile.
 *
 * <p>It exists to show that the DBSC filter is independent of how the user
 * authenticates: the protocol chain is wired exactly as in the form login demo,
 * and only the application chain's authentication differs.
 *
 * <p>The form-login chains live in {@link DemoFormLoginConfig} and are switched
 * off here, because two chains matching {@code /**} would leave the winner up to
 * bean ordering.
 *
 * <p>The binding route is a {@link RouterFunction} bean here rather than a controller
 * class: it is four lines, and it only makes sense next to the success handler that
 * sends the browser to it.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@ConditionalOnProperty(name = "demo.oidc.enabled", havingValue = "true")
public class DemoOidcConfig {

    /**
     * The DBSC protocol routes: reachable unauthenticated, no CSRF, and reaching
     * {@code DbscFilter} rather than Security's entry point.
     */
    @Bean
    @Order(0)
    SecurityFilterChain dbscProtocolChain(
            HttpSecurity http, @Qualifier("dbscFilter") DbscFilter dbscFilter) throws Exception {
        http
                .securityMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/dbsc/**"),
                        new AntPathRequestMatcher("/.well-known/device-bound-sessions")))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .sessionManagement(session -> session.sessionCreationPolicy(
                        org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                // Anchored on CsrfFilter, which sits before
                // UsernamePasswordAuthenticationFilter: a filter placed relative to
                // the latter would still run after CSRF and let it reject the
                // browser's registration POST first.
                .addFilterBefore(dbscFilter, CsrfFilter.class);
        return http.build();
    }

    /**
     * The application chain: OIDC login.
     *
     * <p>{@code DbscFilter} answers the protocol routes, and those are only the
     * paths it matches. It is wired here because the browser's registration POST
     * must reach it before anything else in the chain can reject it: Spring
     * Security's entry point answers {@code 401}, which Chromium treats as fatal on
     * the refresh route and responds to by terminating the session.
     *
     * <p>The filter does <em>not</em> advertise the registration header on ordinary
     * responses; the application does that by calling {@code bind()} itself. In this
     * demo that call lives in {@link #oidcBindRoute}, reached by a navigation the
     * callback's own response issues — because the callback and every server-side
     * redirect after it are cross-site.
     *
     * <p>Anchored on {@link CsrfFilter} for the same reason as the protocol chain:
     * the browser's registration POST must reach the filter before anything can
     * reject it.
     */
    @Bean
    @Order(1)
    SecurityFilterChain appChain(
            HttpSecurity http,
            @Qualifier("dbscFilter") DbscFilter dbscFilter,
            ClientRegistrationRepository clientRegistrationRepository) throws Exception {

        http
                .securityMatcher(new AntPathRequestMatcher("/**"))
                .authorizeHttpRequests(auth -> auth
                        // /oidc/bind is authenticated on purpose: the binding needs
                        // a principal to key the session on.
                        .requestMatchers("/oauth2/**", "/login/**", "/error").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(subjectAsName()))
                        // No bind() here: this response is the callback's, so Chromium
                        // treats it as cross-site and the registration POST it would
                        // trigger loses its SameSite=Lax session cookie. What is needed
                        // is a navigation the browser issues on its own, so answer with
                        // a page that makes one. See "Binding behind OIDC or SAML" in
                        // README.md.
                        .successHandler((request, response, authentication) -> {
                            response.setContentType("text/html");
                            // location.replace, not location.href: the hop stays out of
                            // the history, so Back from the app does not land here and
                            // bind a second time.
                            response.getWriter().write("<script>location.replace('/oidc/bind');</script>");
                        }))
                .csrf(csrf -> csrf.disable())
                .addFilterBefore(dbscFilter, CsrfFilter.class);
        return http.build();
    }

    /**
     * Maps the OIDC principal's name to the {@code sub} claim.
     *
     * <p>{@code preferred_username} and {@code email} are both mutable, so a DBSC
     * session keyed on either would change owner if the address did.
     */
    private static OAuth2UserService<OidcUserRequest, OidcUser> subjectAsName() {
        OidcUserService delegate = new OidcUserService();
        return userRequest -> {
            OidcUser user = delegate.loadUser(userRequest);
            Set<GrantedAuthority> authorities = new LinkedHashSet<>(user.getAuthorities());
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            return new DefaultOidcUser(authorities, user.getIdToken(), user.getUserInfo(), "sub");
        };
    }

    /**
     * The one route the OIDC binding runs on, declared as a {@link RouterFunction} so it
     * lives beside the chain that calls it rather than in a class of its own.
     *
     * <p>The OIDC callback's response is <strong>cross-site</strong>: Chromium makes
     * DBSC requests inherit the initiator of the request that produced them, and that
     * initiator is the identity provider. Two things follow, and together they are why
     * this route exists at all:
     *
     * <ol>
     *   <li>A registration header on the callback response is useless — the
     *       registration POST it triggers arrives without the {@code SameSite=Lax}
     *       session cookie.</li>
     *   <li>A server-side redirect does not escape this. A {@code 302} to another route
     *       still carries the callback as its initiator, so binding there fails the same
     *       way. Only a navigation the browser issues on its own re-originates the
     *       request on this site.</li>
     * </ol>
     *
     * <p>So the success handler answers the callback with a small HTML document whose
     * script navigates here. That navigation is one the browser issues itself, which is
     * what makes the request arriving here same-site and carries the session cookie with
     * it.
     *
     * <p>This is the pattern the README describes under "Binding behind OIDC or SAML",
     * and it is the variant that works unconditionally — hanging the binding on a
     * route the user happened to navigate to needs that navigation to exist, which a
     * pure redirect chain never provides.
     *
     * <p>{@code DbscFilter} plays no part in this: it serves the protocol routes and
     * never advertises the registration header on an application response.
     */
    @Bean
    RouterFunction<ServerResponse> oidcBindRoute(DbscService dbsc) {
        return route().GET("/oidc/bind", request -> {
            // Reached only via the script the callback returned, so this request is
            // same-site and its session cookie travels with it. That is what makes the
            // bind() below succeed where the same call on the callback's response did
            // not.
            //
            // bind() writes headers and cookies, so it needs the real ServletResponse.
            // RouterFunction gives no access to it: the response has not been created
            // yet when the handler runs, so it is reached through the request context
            // instead. A controller method taking the response as a parameter is the
            // cleaner shape, and the README shows both.
            HttpServletRequest servletRequest = request.servletRequest();
            HttpServletResponse servletResponse =
                    ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes())
                            .getResponse();
            dbsc.bind(servletRequest.getSession().getId(),
                    servletRequest.getUserPrincipal().getName(),
                    86_400_000L, servletRequest, servletResponse);
            return ServerResponse.temporaryRedirect(URI.create("/app")).build();
        }).build();
    }
}
