package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscAutoConfiguration;
import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.Json;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.web.DbscBindFilter;
import click.yukio.dbsc.web.DbscFilter;
import click.yukio.dbsc.web.DbscGuardFilter;
import click.yukio.dbsc.web.DbscGuardRoutes;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The host application the web tests run against.
 *
 * <p>This lives in test sources on purpose: the library itself ships no
 * {@code @SpringBootApplication} and no controllers. A consuming application
 * writes the handful of lines below — bind at login, read the tier where the UI
 * needs it, end the binding at logout — and declares which of its routes DBSC
 * guards.
 *
 * <p>It also brings its own {@code SecurityFilterChain}s, which is the realistic
 * case: the library ships filters, not chains, so there is nothing to opt out of and
 * no chance of its policy colliding with the host's.
 */
@SpringBootApplication
@Import(DbscAutoConfiguration.class)
public class DbscTestHostApplication {

    /** Stands in for an application's own session/TTL policy. */
    private static final long HOST_SESSION_TTL_MS = 7L * 24 * 60 * 60 * 1000;

    /** The host's session lifetime, exposed so tests can assert against it. */
    public static long hostSessionTtlMs() {
        return HOST_SESSION_TTL_MS;
    }

    /**
     * The host's own rules: permit everything, so the fixture exercises the DBSC
     * filters and nothing else.
     *
     * <p>Both chains are the application's. DBSC supplies the filters and the
     * protocol paths they serve; the shape of the chain around them is the host's,
     * which is why the library declares no chain of its own.
     * {@code DemoFormLoginTestConfig} in the demo is the same pattern with form login.
     */
    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class HostSecurity {

        @Bean
        @Order(0)
        SecurityFilterChain hostDbscProtocolChain(
                HttpSecurity http, DbscFilter dbscFilter) throws Exception {
            http
                    // One OrRequestMatcher rather than chained securityMatcher()
                    // calls: each call SETS the matcher, so chaining keeps only the
                    // last path and the others silently fall through to the app
                    // chain, which answers 403 before DbscFilter runs.
                    //
                    // /dbsc/bind is deliberately not here: it is an application route,
                    // and the app chain below is where its checks live.
                    .securityMatcher(new OrRequestMatcher(
                            new AntPathRequestMatcher("/dbsc/regist/**"),
                            new AntPathRequestMatcher("/dbsc/refresh"),
                            new AntPathRequestMatcher("/.well-known/device-bound-sessions")))
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .sessionManagement(session -> session
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .csrf(csrf -> csrf.disable())
                    .addFilterBefore(dbscFilter, CsrfFilter.class);
            return http.build();
        }

        @Bean
        @Order(1)
        SecurityFilterChain hostApplicationChain(
                HttpSecurity http, DbscGuardFilter dbscGuardFilter,
                DbscBindFilter dbscBindFilter) throws Exception {
            http
                    .securityMatcher(new AntPathRequestMatcher("/**"))
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    // Standard Spring Security CSRF, deliberately on, because
                    // /dbsc/bind is a state-changing application route. Nothing
                    // library-specific is involved: the route is protected by the
                    // very CsrfFilter every other POST route is protected by.
                    //
                    // The plain request handler rather than the default: the default
                    // masks the token with a per-request BREACH nonce, which is right
                    // for a browser reading it out of a rendered form and wrong for a
                    // client that holds the raw value — which is what the demo's
                    // script client does, and what these tests assert.
                    .csrf(csrf -> csrf
                            .csrfTokenRepository(csrfTokenRepository())
                            .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
                    // IF_REQUIRED, not STATELESS as on the protocol chain above: CSRF
                    // stores its token on the session, so a chain that refuses to keep
                    // one could never validate a token. This is the ordinary shape for
                    // an application chain that has real sessions.
                    .sessionManagement(session -> session
                            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                    // The guard sits in the application chain, not the protocol one:
                    // it is about the host's routes. /host/payment is declared below.
                    .addFilterBefore(dbscGuardFilter, CsrfFilter.class)
                    // The re-offer route itself, after CSRF: it terminates the
                    // request, so everything that is going to refuse it — auth and
                    // the token check — must have run already.
                    .addFilterAfter(dbscBindFilter, CsrfFilter.class);
            return http.build();
        }

        /**
         * The re-offer route. Declared here rather than left to the library's
         * auto-configuration because the chain it belongs to is the host's, and a
         * terminating filter has to be ordered relative to the host's own checks.
         */
        @Bean
        DbscBindFilter dbscBindFilter(DbscService dbsc, DbscProperties dbscProperties) {
            return new DbscBindFilter(dbsc, dbscProperties);
        }

        /**
         * The token store {@link CsrfFilter} uses. Only the application chain needs
         * one; the protocol chain serves requests the browser issues on its own, with
         * no page of ours to put a token in, which is why CSRF stays off there.
         */
        @Bean
        CsrfTokenRepository csrfTokenRepository() {
            return new HttpSessionCsrfTokenRepository();
        }

        /**
         * One guarded route, so the tier check has a real path to refuse. The
         * other host routes stay unguarded, which is what lets a test compare a
         * request that DBSC enforces against one it only observes.
         */
        @Bean
        DbscGuardRoutes hostGuardRoutes() {
            return DbscGuardRoutes.of(new AntPathRequestMatcher("/host/payment"));
        }
    }

    @RestController
    @RequestMapping("/host")
    static class HostController {

        private final DbscService dbsc;

        HostController(DbscService dbsc) {
            this.dbsc = dbsc;
        }

        /** A stand-in for the application's own login route. */
        @PostMapping(path = "/login", produces = MediaType.APPLICATION_JSON_VALUE)
        ResponseEntity<String> login(@RequestBody(required = false) String rawBody,
                                     HttpServletRequest request,
                                     HttpServletResponse response) {
            String sessionId = "sess_" + UUID.randomUUID().toString().replace("-", "");
            String userId = userIdFrom(rawBody);

            // The one DBSC call a login route needs to make. The second argument
            // is the application's own session id, which the guard uses to spot a
            // request that presents no DBSC cookie while a binding exists.
            dbsc.bind(sessionId, request.getSession().getId(), userId,
                    HOST_SESSION_TTL_MS, request, response);

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("userId", userId);
            body.put("sessionId", sessionId);
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(Json.write(body));
        }

        /** Reports the session tier so a UI can explain why a browser is unbound. */
        @GetMapping(path = "/whoami", produces = MediaType.APPLICATION_JSON_VALUE)
        ResponseEntity<String> whoami(HttpServletRequest request) {
            Optional<Session> session = dbsc.sessionFor(request);

            Map<String, Object> body = new LinkedHashMap<>();
            if (session.isEmpty()) {
                body.put("tier", ProtectionTier.NONE.wireValue());
                body.put("sessionId", null);
                return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(Json.write(body));
            }

            String sessionId = session.get().id();
            body.put("tier", dbsc.tierFor(sessionId).wireValue());
            body.put("sessionId", sessionId);
            body.put("deviceKey", dbsc.hasDeviceKey(sessionId));
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(Json.write(body));
        }

        /**
         * A POST route, present so the CSRF and body-handling mechanics of a
         * JSON request can be exercised end to end.
         */
        @PostMapping(path = "/payment", produces = MediaType.APPLICATION_JSON_VALUE)
        ResponseEntity<String> payment(@RequestBody(required = false) String rawBody) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("status", "authorized");
            body.put("receivedBody", rawBody);
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(Json.write(body));
        }

        /** Ends the DBSC binding so Chromium forgets it immediately. */
        @PostMapping(path = "/logout", produces = MediaType.APPLICATION_JSON_VALUE)
        ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
            Optional<Session> session = dbsc.sessionFor(request);
            if (session.isEmpty()) {
                return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body("{\"ok\":true}");
            }
            Map<String, Object> config = dbsc.terminate(session.get().id(), request, response);
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(Json.write(config));
        }

        private static String userIdFrom(String rawBody) {
            if (rawBody != null && !rawBody.isBlank()) {
                Map<String, Object> parsed = Json.tryParseObject(rawBody);
                if (parsed != null) {
                    String userId = Json.string(parsed, "userId");
                    if (userId != null && !userId.isBlank()) {
                        return userId;
                    }
                }
            }
            return "user_1";
        }
    }
}
