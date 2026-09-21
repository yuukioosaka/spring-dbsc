package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscAutoConfiguration;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.protocol.CookieScope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Proves that a host application can adopt DBSC by importing the
 * auto-configuration and calling one method from its login route.
 *
 * <p>The host app below declares no DBSC beans, no database, and no XML — the
 * only DBSC-specific line in it is {@code dbsc.bind(...)}. Everything else
 * (storage, challenge service, engine, cookie scope, rate limiter) has to arrive
 * from {@link DbscAutoConfiguration}. If a future change adds a required
 * collaborator without a default, this test fails, which is the point.
 */
@SpringBootTest(
        classes = AutoConfigurationIntegrationTest.HostApplication.class,
        properties = {
                // The host app has no DataSource, so storage must fall back to its
                // single-process form rather than fail.
                "dbsc.storage=memory",
                "dbsc.secure=false",
        })
class AutoConfigurationIntegrationTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private DbscService dbsc;

    @Autowired
    private CookieScope cookieScope;

    @Autowired
    private StorageAdapter storage;

    @Test
    @DisplayName("a host app that imports the auto-config gets a working DbscService")
    void autoConfigurationWiresEverything() {
        assertNotNull(dbsc, "DbscService must be provided by the auto-configuration");
        assertNotNull(cookieScope, "CookieScope must be provided too");
        assertNotNull(storage, "a StorageAdapter must be provided even without a DataSource");
    }

    @Test
    @DisplayName("the one-line integration point issues the headers and cookies a browser needs")
    void bindFromHostLoginRoute() throws Exception {
        MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).build();

        var result = mvc.perform(post("/login")).andReturn();
        var response = result.getResponse();

        assertEquals(200, response.getStatus());
        String registration = response.getHeader("Secure-Session-Registration");
        assertNotNull(registration, "bind() must advertise the registration path to Chromium");
        assertTrue(registration.contains("path=\"/dbsc/registration\""), registration);
        assertTrue(registration.contains("challenge=\""), registration);

        assertNotNull(response.getCookie(cookieScope.registrationCookieName()),
                "bind() must set the registration cookie that identifies the session");
        assertNotNull(response.getCookie(cookieScope.challengeCookieName()),
                "bind() must set the challenge cookie the registration JWS is validated against");

        String sessionId = response.getContentAsString()
                .replaceAll(".*\"sessionId\":\"([^\"]+)\".*", "$1");
        assertEquals(sessionId, storage.getSession(sessionId).orElseThrow().id());
        assertEquals(sessionId, response.getCookie(cookieScope.registrationCookieName()).getValue(),
                "the registration cookie must name the session");
    }

    /**
     * A host application. Note what is absent: no DBSC beans, no DBSC schema, and
     * a login route whose only DBSC line is {@code bind}.
     *
     * <p>It brings its <em>own</em> {@link SecurityFilterChain}, which is the case
     * that matters: the library's convenience chain must back off rather than
     * compete with it. That is what makes {@code HttpSecurity} available here and
     * not there — a chain is only created in an application that enables Security
     * itself.
     */
    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    @Import(DbscAutoConfiguration.class)
    static class HostApplication {

        @Bean
        HostController hostController(DbscService dbsc) {
            return new HostController(dbsc);
        }

        /** The host's own rules; DBSC adds nothing here on purpose. */
        @Bean
        SecurityFilterChain hostSecurityFilterChain(HttpSecurity http) throws Exception {
            http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .csrf(csrf -> csrf.disable());
            return http.build();
        }
    }

    @RestController
    static class HostController {

        private final DbscService dbsc;

        HostController(DbscService dbsc) {
            this.dbsc = dbsc;
        }

        @PostMapping(path = "/login", produces = MediaType.APPLICATION_JSON_VALUE)
        String login(HttpServletRequest request, HttpServletResponse response) {
            String sessionId = "sess_" + UUID.randomUUID().toString().replace("-", "");
            dbsc.bind(sessionId, "user_1", 86_400_000L, request, response);
            return "{\"sessionId\":\"" + sessionId + "\"}";
        }
    }
}
