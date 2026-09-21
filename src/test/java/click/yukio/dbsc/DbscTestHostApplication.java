package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscAutoConfiguration;
import click.yukio.dbsc.core.Json;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.web.DbscFilter;
import click.yukio.dbsc.web.DbscProofGuardFilter;
import click.yukio.dbsc.web.DbscFilterConfiguration.GuardedRoute;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
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
     * {@code DemoFormLoginConfig} in the demo is the same pattern with form login.
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
                    .securityMatcher(new OrRequestMatcher(
                            new AntPathRequestMatcher("/dbsc/**"),
                            new AntPathRequestMatcher("/dbsc-bound/**"),
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
                HttpSecurity http, DbscProofGuardFilter guardFilter) throws Exception {
            http
                    .securityMatcher(new AntPathRequestMatcher("/**"))
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .sessionManagement(session -> session
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .csrf(csrf -> csrf.disable())
                    .addFilterBefore(guardFilter, UsernamePasswordAuthenticationFilter.class);
            return http.build();
        }
    }

    /**
     * An application opts into per-request proofs by declaring guarded routes.
     * Nothing is guarded by default, so adopting DBSC never silently changes the
     * behaviour of existing endpoints.
     */
    @Configuration(proxyBeanMethods = false)
    static class GuardedRoutes {

        @Bean
        GuardedRoute paymentRoute() {
            // The body is bound into the proof: a captured proof cannot be replayed
            // against a modified transfer amount.
            return GuardedRoute.withBody("/host/payment");
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

            // The one DBSC call a login route needs to make.
            dbsc.bind(sessionId, userId, HOST_SESSION_TTL_MS, request, response);

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
            body.put("nativeKey", dbsc.hasNativeKey(sessionId));
            body.put("boundKey", dbsc.hasBoundKey(sessionId));
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(Json.write(body));
        }

        /**
         * A guarded route. It requires a bound key and a per-request proof whose
         * signed message binds the request body. This handler only ever sees
         * requests that already passed verification.
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
