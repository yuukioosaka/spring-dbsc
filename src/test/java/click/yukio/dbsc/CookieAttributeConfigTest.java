package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscAutoConfiguration;
import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.protocol.CookieScope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The credential cookie's Path, HttpOnly and SameSite, from YAML to the wire string.
 *
 * <p>{@code WireFormatTest} proves {@link CookieScope} honours each value. What it cannot
 * prove is that a property set in configuration ever reaches that object — an unbound
 * property looks exactly like an unset one, and the failure is silent twice over: the
 * browser stores a cookie that does not match the advertised attributes and discards the
 * registration, so the server answers 200 and the session never exists.
 *
 * <p>So each key is pinned here against a real context, together with the mismatch that is
 * worse than a silent no-op: a value the container must refuse at startup.
 */
class CookieAttributeConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(DbscAutoConfiguration.class))
            // The library's own defaults file sets storage: jdbc, which is unrelated
            // here but would pull in a DataSource.
            .withPropertyValues("dbsc.storage=memory", "dbsc.secure=true");

    @Test
    @DisplayName("Path, HttpOnly and SameSite default to the shipped values")
    void defaults() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(CookieScope.class);
            CookieScope scope = context.getBean(CookieScope.class);

            assertThat(scope.attributesString())
                    .isEqualTo("Path=/; Secure; HttpOnly; SameSite=Lax");
        });
    }

    @Test
    @DisplayName("dbsc.cookie-path / cookie-http-only / cookie-same-site bind to the scope")
    void valuesBind() {
        runner.withPropertyValues(
                        "dbsc.cookie-path=/app",
                        "dbsc.cookie-http-only=false",
                        "dbsc.cookie-same-site=STRICT")
                .run(context -> {
                    CookieScope scope = context.getBean(CookieScope.class);

                    assertThat(scope.path()).isEqualTo("/app");
                    assertThat(scope.httpOnly()).isFalse();
                    assertThat(scope.sameSite()).isEqualTo(CookieScope.SameSite.STRICT);
                    // Both consumers of this string -- Set-Cookie and
                    // credentials[].attributes -- must carry all three.
                    assertThat(scope.attributesString())
                            .isEqualTo("Path=/app; Secure; SameSite=Strict");
                    assertThat(scope.setCookieValue("__Host-auth_cookie", "t", 1000))
                            .isEqualTo("__Host-auth_cookie=t; Path=/app; Secure; SameSite=Strict; Max-Age=1");
                });
    }

    @Test
    @DisplayName("a relative cookie-path fails context startup, not the browser")
    void relativePathFailsStartup() {
        runner.withPropertyValues("dbsc.cookie-path=app").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .rootCause()
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("cookiePath must be absolute");
        });
    }

    @Test
    @DisplayName("SameSite=None without secure fails context startup")
    void sameSiteNoneWithoutSecureFailsStartup() {
        runner.withPropertyValues("dbsc.secure=false", "dbsc.cookie-same-site=NONE")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("requires secure=true");
                });
    }

    @Test
    @DisplayName("an unknown cookie-same-site value fails context startup")
    void unknownSameSiteFailsStartup() {
        runner.withPropertyValues("dbsc.cookie-same-site=SOMETIMES").run(context ->
                assertThat(context).hasFailed());
    }

    @Test
    @DisplayName("the property names are the ones the README documents")
    void propertyNames() {
        runner.withPropertyValues("dbsc.cookie-path=/x").run(context ->
                assertThat(context.getBean(DbscProperties.class).getCookiePath())
                        .as("a renamed key would silently fall back to the default")
                        .isEqualTo("/x"));
    }
}
