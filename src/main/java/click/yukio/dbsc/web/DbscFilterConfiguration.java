package click.yukio.dbsc.web;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.config.DbscProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * The two DBSC filters as plain beans.
 *
 * <p>The library declares no {@link org.springframework.security.web.SecurityFilterChain}.
 * Where the filters sit, which paths bypass authentication and what authorization runs
 * underneath them are policy decisions that belong to the application, and a chain
 * shipped here would either collide with the adopter's own or quietly replace their
 * rules. Adopters wire these two beans into their chain; the README's "Getting Started"
 * has the block to copy.
 *
 * <p>Nothing here depends on Spring Security, so these beans exist whether or not
 * Security is on the classpath. An application with no Security at all can take
 * them and register them as ordinary servlet filters.
 */
@Configuration(proxyBeanMethods = false)
public class DbscFilterConfiguration {

    /**
     * The guarded-route filter, built from the application's declared routes.
     *
     * <p>No routes are guarded by default: DBSC protects nothing until the
     * application says which requests matter. Declare {@link GuardedRoute} beans to
     * opt in.
     */
    @Bean
    public DbscProofGuardFilter dbscProofGuardFilter(
            DbscService dbsc, List<GuardedRoute> guardedRoutes) {
        return new DbscProofGuardFilter(
                dbsc,
                guardedRoutes.stream().map(GuardedRoute::path).toList(),
                request -> guardedRoutes.stream()
                        .filter(route -> route.path().equals(request.getRequestURI()))
                        .findFirst()
                        .map(GuardedRoute::signBody)
                        .orElse(false));
    }

    @Bean
    public DbscFilter dbscFilter(DbscService dbsc, DbscProperties properties) {
        return new DbscFilter(dbsc, properties);
    }

    /**
     * Declares a request path that requires a per-request DBSC proof.
     *
     * @param path     the request path, matched exactly
     * @param signBody whether the request body is bound into the proof. Turn this
     *                 on for anything whose payload must not be modifiable in
     *                 flight — a captured proof then cannot be replayed on a
     *                 different body. Leave it off for routes with no meaningful
     *                 body, where hashing it would only add cost.
     */
    public record GuardedRoute(String path, boolean signBody) {

        /** Guards {@code path} and binds its request body into the proof. */
        public static GuardedRoute withBody(String path) {
            return new GuardedRoute(path, true);
        }

        /** Guards {@code path} without binding the body. */
        public static GuardedRoute withoutBody(String path) {
            return new GuardedRoute(path, false);
        }
    }
}
