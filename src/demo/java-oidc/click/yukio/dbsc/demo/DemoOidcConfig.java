package click.yukio.dbsc.demo;

import click.yukio.dbsc.web.DbscFilter;
import click.yukio.dbsc.web.DbscProofGuardFilter;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The OIDC variant of the demo's security setup, active only under the
 * {@code oidc} profile.
 *
 * <p>It exists to show that the DBSC filters are independent of how the user
 * authenticates: the protocol chain and the guard are wired exactly as in the form
 * login demo, and only the application chain's authentication differs.
 *
 * <p>The form-login chains live in {@link DemoFormLoginConfig} and are switched
 * off here, because two chains matching {@code /**} would leave the winner up to
 * bean ordering.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@ConditionalOnProperty(name = "demo.oidc.enabled", havingValue = "true")
public class DemoOidcConfig {

    @Bean
    OidcLoginSuccessHandler oidcLoginSuccessHandler() {
        return new OidcLoginSuccessHandler();
    }

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
                        new AntPathRequestMatcher("/dbsc-bound/**"),
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
     * The application chain: OIDC login plus the proof guard.
     *
     * <p>No CSRF repository is configured for {@code /oidc/bind}, because it is a
     * GET; the guard is anchored on {@code UsernamePasswordAuthenticationFilter},
     * which is present as an ordering position even when no form login is
     * configured.
     */
    @Bean
    @Order(1)
    SecurityFilterChain appChain(
            HttpSecurity http,
            @Qualifier("dbscProofGuardFilter") DbscProofGuardFilter guardFilter,
            OidcLoginSuccessHandler successHandler,
            ClientRegistrationRepository clientRegistrationRepository) throws Exception {

        http
                .securityMatcher(new AntPathRequestMatcher("/**"))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/oauth2/**", "/login/**", "/error").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(subjectAsName()))
                        .successHandler(successHandler))
                .csrf(csrf -> csrf.disable())
                .addFilterBefore(guardFilter, UsernamePasswordAuthenticationFilter.class);
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
}
