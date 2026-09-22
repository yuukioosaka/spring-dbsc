package click.yukio.dbsc.web;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.config.DbscProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * The DBSC filters as plain beans.
 *
 * <p>The library declares no {@link org.springframework.security.web.SecurityFilterChain}.
 * Where the filters sit, which paths bypass authentication and what authorization runs
 * underneath them are policy decisions that belong to the application, and a chain
 * shipped here would either collide with the adopter's own or quietly replace their
 * rules. Adopters wire these beans into their chain; the README's "Getting Started"
 * has the block to copy.
 *
 * <p>Nothing here depends on Spring Security, so these beans exist whether or not
 * Security is on the classpath. An application with no Security at all can take
 * them and register them as ordinary servlet filters.
 */
@Configuration(proxyBeanMethods = false)
public class DbscFilterConfiguration {

    /**
     * The protocol filter, serving native registration, refresh and the
     * well-known session status route.
     */
    @Bean
    public DbscFilter dbscFilter(DbscService dbsc, DbscProperties properties) {
        return new DbscFilter(dbsc, properties);
    }

    /**
     * The route guard: refuses a request whose session DBSC does not currently
     * protect.
     *
     * <p>Built from the application's own {@link DbscGuardRoutes} bean, so it guards
     * nothing until one is declared. An application that wants the tier check inline
     * instead, on a route that is not worth a filter, can call {@code sessionFor} and
     * {@code tierFor} directly — this filter exists so that the common case does not
     * have to repeat that block everywhere.
     *
     * <p>{@code ObjectProvider} rather than a direct dependency: with no bean the
     * filter must still exist (an application may wire it and find it does nothing),
     * and a missing guard configuration is the documented default rather than a
     * context failure.
     */
    @Bean
    public DbscGuardFilter dbscGuardFilter(DbscService dbsc, ObjectProvider<DbscGuardRoutes> routes) {
        RequestMatcher matcher = routes.getIfAvailable();
        return new DbscGuardFilter(dbsc, matcher == null ? request -> false : matcher);
    }
}
