package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscAutoConfiguration;
import click.yukio.dbsc.config.DbscProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code dbsc.soft.*} toggle.
 *
 * <p>The gate itself is asserted in {@code FilterStandaloneTest} by building a filter
 * with the flag set either way. What that test cannot catch is the binding: a property
 * that never reaches the object looks identical to a property nobody set, and the
 * failure mode is silent — the feature stays off and the operator sees no error. So the
 * name is pinned here, against a real context.
 */
class SoftDbscConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(DbscAutoConfiguration.class))
            // The library's own defaults file sets storage: jdbc, which is unrelated
            // here but would pull in a DataSource.
            .withPropertyValues("dbsc.storage=memory", "dbsc.secure=false");

    @Test
    @DisplayName("dbsc.soft.enabled defaults to false")
    void offByDefault() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(DbscProperties.class);
            assertThat(context.getBean(DbscProperties.class).getSoft().isEnabled())
                    .as("enabling the script fallback widens the trust model, so it is opt-in")
                    .isFalse();
        });
    }

    @Test
    @DisplayName("dbsc.soft.enabled=true binds")
    void enablingBinds() {
        runner.withPropertyValues("dbsc.soft.enabled=true").run(context ->
                assertThat(context.getBean(DbscProperties.class).getSoft().isEnabled()).isTrue());
    }

    @Test
    @DisplayName("dbsc.soft.enabled=false binds to off, not just to the default")
    void disablingBinds() {
        runner.withPropertyValues("dbsc.soft.enabled=false").run(context ->
                assertThat(context.getBean(DbscProperties.class).getSoft().isEnabled()).isFalse());
    }
}
