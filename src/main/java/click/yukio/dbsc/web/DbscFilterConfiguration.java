package click.yukio.dbsc.web;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.config.DbscProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The DBSC filter as a plain bean.
 *
 * <p>The library declares no {@link org.springframework.security.web.SecurityFilterChain}.
 * Where the filters sit, which paths bypass authentication and what authorization runs
 * underneath them are policy decisions that belong to the application, and a chain
 * shipped here would either collide with the adopter's own or quietly replace their
 * rules. Adopters wire these beans into their chain; the README's "Getting Started"
 * has the block to copy.
 *
 * <p>Nothing here depends on Spring Security, so this bean exists whether or not
 * Security is on the classpath. An application with no Security at all can take it
 * and register it as an ordinary servlet filter.
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
}
