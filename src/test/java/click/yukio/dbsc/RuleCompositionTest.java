package click.yukio.dbsc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import click.yukio.dbsc.config.DbscAutoConfiguration;
import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.protocol.CookieScope;
import click.yukio.dbsc.web.DbscBindFilter;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Proves the composition rule that decides how an {@code access()} clause must be
 * written, by putting the two shapes side by side in one application.
 *
 * <p>Spring Security's {@code authorizeHttpRequests} is <em>first match wins</em>:
 * {@code RequestMatcherDelegatingAuthorizationManager.check} returns at the first matcher
 * that matches, and {@code Builder.add} appends rather than replaces. So for one pattern,
 * this:
 *
 * <pre>{@code
 * .requestMatchers("/two-rules/**").authenticated()
 * .requestMatchers("/two-rules/**").access(dbscCondition)
 * }</pre>
 *
 * <p>does not mean "authenticated and DBSC-protected". It means "authenticated" — the
 * second rule is never reached. The route reads as guarded and is not, which is the silent
 * failure these two tests demonstrate rather than assert from documentation.
 *
 * <p>{@code /two-rules} is that broken shape, {@code /one-rule} the correct one, and the
 * pair shows a demoted session refused at {@code /one-rule} and admitted at
 * {@code /two-rules}. That contrast is the argument for combining the conditions with
 * {@code AuthorizationManagers.allOf} instead of stacking rules.
 *
 * <p>The session is real rather than hand-seeded: {@link DbscService#bind} is called the
 * way an application's login route calls it, which is what puts a credential cookie in the
 * client's hands and a session record in storage. Only the tier is then changed, because
 * the question here is what an authorization rule does with a demoted session — how a
 * session becomes demoted is {@code GuardDecisionTest}'s subject.
 */
@SpringBootTest(
        classes = RuleCompositionTest.TestApp.class,
        properties = {"dbsc.storage=memory"})
@AutoConfigureMockMvc
class RuleCompositionTest {

    private static final String APP_SESSION_ID = "composition-app-session";

    @Autowired
    MockMvc mvc;

    @Autowired
    StorageAdapter storage;

    @Autowired
    DbscService dbsc;

    @Autowired
    CookieScope cookieScope;

    @BeforeEach
    void clear() {
        storage.getSession(APP_SESSION_ID).ifPresent(session -> storage.deleteSession(session.id()));
    }

    /**
     * Binds a session the way a login route does, demotes it, then POSTs {@code path} with
     * the credential cookie {@code bind()} issued.
     *
     * <p>{@code bind()} overwrites {@code lastRefreshAt} to zero, so the demotion is written
     * after it: tier {@code none} with a non-zero {@code lastRefreshAt} is exactly the
     * "registered once, now proving nothing" state the guard refuses.
     */
    private int callAfterDemotion(String path) throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequest bindRequest = new MockHttpServletRequest();
        bindRequest.setSession(session);
        MockHttpServletResponse bindResponse = new MockHttpServletResponse();

        dbsc.bind("composition-binding", APP_SESSION_ID, "host", bindRequest, bindResponse);

        Cookie credential = bindResponse.getCookie(cookieScope.credentialCookieName());
        assertThat(credential).as("bind() must issue the credential cookie").isNotNull();

        String boundId = storage.getSessionByAppSessionId(APP_SESSION_ID).orElseThrow().id();
        storage.setSession(storage.getSession(boundId).orElseThrow()
                .withTierAndLastRefreshAt(ProtectionTier.NONE, System.currentTimeMillis()));

        return mvc.perform(post(path)
                        .session(session)
                        .cookie(credential)
                        .with(org.springframework.security.test.web.servlet.request
                                .SecurityMockMvcRequestPostProcessors.user("host"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andReturn().getResponse().getStatus();
    }

    /**
     * The correct shape: both conditions on the one rule that matches, so the DBSC half runs
     * and refuses the demoted session.
     */
    @Test
    @DisplayName("allOf on one rule refuses the demoted session")
    void oneRuleRefuses() throws Exception {
        assertThat(callAfterDemotion("/one-rule")).isEqualTo(403);
    }

    /**
     * The broken shape, and the reason the library documents {@code allOf}: the
     * {@code authenticated()} rule matches first and returns, so the DBSC rule below it is
     * dead code and the demoted session gets through.
     */
    @Test
    @DisplayName("stacking two rules for one pattern leaves the DBSC half dead")
    void twoRulesAdmits() throws Exception {
        assertThat(callAfterDemotion("/two-rules")).isEqualTo(200);
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class TestSecurity {

        @Bean
        @Order(1)
        SecurityFilterChain chain(HttpSecurity http, DbscService dbsc,
                                  DbscProperties dbscProperties) throws Exception {
            // Built here rather than injected: being a terminating filter, it has to be
            // ordered relative to this chain's own checks, and this test owns the only chain
            // that serves its routes.
            DbscBindFilter dbscBindFilter = new DbscBindFilter(dbsc, dbscProperties);

            http
                    // A prefix rather than /** so this does not collide with any
                    // auto-configured chain.
                    .securityMatcher(new OrRequestMatcher(
                            new AntPathRequestMatcher("/one-rule/**"),
                            new AntPathRequestMatcher("/two-rules/**")))
                    .authorizeHttpRequests(auth -> auth
                            // The broken shape: two rules, one pattern. Only the first ever
                            // runs.
                            .requestMatchers(new AntPathRequestMatcher("/two-rules/**"))
                            .authenticated()
                            .requestMatchers(new AntPathRequestMatcher("/two-rules/**"))
                            .access((authentication, context) -> new AuthorizationDecision(
                                    dbsc.isProtected(context.getRequest())))
                            // The correct shape: one rule, both conditions.
                            .requestMatchers(new AntPathRequestMatcher("/one-rule/**"))
                            .access(AuthorizationManagers.allOf(
                                    AuthenticatedAuthorizationManager.authenticated(),
                                    (authentication, context) -> new AuthorizationDecision(
                                            dbsc.isProtected(context.getRequest()))))
                            .anyRequest().permitAll())
                    .csrf(csrf -> csrf.disable())
                    .addFilterAfter(dbscBindFilter,
                            org.springframework.security.web.csrf.CsrfFilter.class);
            return http.build();
        }
    }

    @RestController
    static class TestController {

        @PostMapping("/one-rule")
        String oneRule() {
            return "{}";
        }

        @PostMapping("/two-rules")
        String twoRules() {
            return "{}";
        }
    }

    /**
     * Stand-in for the host application; the library ships none.
     *
     * <p>A plain {@code @Configuration}, not a {@code @SpringBootApplication}: a second
     * {@code @SpringBootConfiguration} in this package would make Spring Boot's test
     * context loader refuse to choose between this and {@code DbscTestHostApplication} in
     * every other test that auto-discovers its configuration.
     *
     * <p>Scanning is off for the same reason it would be in a host that imports this
     * library: the only beans needed here are the library's auto-configuration, the chain
     * under test, and the two routes it guards.
     */
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @Import({DbscAutoConfiguration.class, TestSecurity.class, TestController.class})
    static class TestApp {
    }
}
