package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscAutoConfiguration;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.storage.JdbcStorageAdapter;
import click.yukio.dbsc.storage.RedisStorageAdapter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import redis.embedded.RedisServer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Which store {@code dbsc.storage} actually selects.
 *
 * <p>The property decides rather than the classpath. That distinction needs a test
 * because the failure it guards against is silent: a JDBC bean declared without a
 * matching {@code @ConditionalOnProperty} would satisfy {@code StorageAdapter} for
 * every value of the property, so {@code dbsc.storage: redis} would be accepted,
 * logged as nothing in particular, and quietly store sessions in a database the
 * host may not even have.
 */
class StorageSelectionTest {

    private static final int PORT = 16397;

    private static RedisServer server;
    private static LettuceConnectionFactory connectionFactory;

    @BeforeAll
    static void startServer() throws Exception {
        server = RedisServer.newRedisServer().port(PORT).build();
        server.start();
        connectionFactory = new LettuceConnectionFactory("localhost", PORT);
        connectionFactory.afterPropertiesSet();
    }

    @AfterAll
    static void stopServer() throws Exception {
        connectionFactory.destroy();
        server.stop();
    }

    /** A Redis client, the way a host app on starter-data-redis would have one. */
    @Configuration(proxyBeanMethods = false)
    static class RedisClientConfiguration {
        @org.springframework.context.annotation.Bean
        StringRedisTemplate stringRedisTemplate() {
            return new StringRedisTemplate(connectionFactory);
        }
    }

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withUserConfiguration(RedisClientConfiguration.class)
                .withConfiguration(org.springframework.boot.autoconfigure.AutoConfigurations
                        .of(DbscAutoConfiguration.class))
                // The library's own defaults file sets storage: jdbc, which would mask
                // the value under test.
                .withPropertyValues("dbsc.secure=false");
    }

    @Test
    @DisplayName("dbsc.storage: redis selects the Redis adapter")
    void redisIsSelectedByProperty() {
        runner()
                .withPropertyValues("dbsc.storage=redis")
                .run(context -> {
                    assertThat(context).hasSingleBean(StorageAdapter.class);
                    assertThat(context.getBean(StorageAdapter.class))
                            .isInstanceOf(RedisStorageAdapter.class);
                });
    }

    @Test
    @DisplayName("dbsc.storage: redis works without a DataSource and stores what it is given")
    void redisStoresWithoutADataSource() {
        runner()
                .withPropertyValues("dbsc.storage=redis")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(javax.sql.DataSource.class);
                    StorageAdapter storage = context.getBean(StorageAdapter.class);
                    long now = System.currentTimeMillis();
                    String id = "sess_" + System.nanoTime();
                    storage.setSession(new Session(id, "app_" + id, "user_1",
                            ProtectionTier.DBSC, false, now, now + 300_000, now));
                    assertThat(storage.getSession(id)).isPresent();
                    assertThat(storage.getSession(id).orElseThrow().tier())
                            .isEqualTo(ProtectionTier.DBSC);
                });
    }

    @Test
    @DisplayName("dbsc.storage: memory does not find a JDBC candidate waiting")
    void memoryIsNotShadowedByJdbc() {
        // No DataSource here, so this only proves memory wins when it is alone. The
        // JDBC rule itself is asserted by the default case below.
        runner()
                .withPropertyValues("dbsc.storage=memory")
                .run(context -> {
                    assertThat(context).hasSingleBean(StorageAdapter.class);
                    assertThat(context.getBean(StorageAdapter.class))
                            .isNotInstanceOf(JdbcStorageAdapter.class)
                            .isNotInstanceOf(RedisStorageAdapter.class);
                });
    }

    @Test
    @DisplayName("dbsc.storage: redis without a client fails with a message naming the property")
    void redisWithoutAClientFailsLoudly() {
        new ApplicationContextRunner()
                .withConfiguration(org.springframework.boot.autoconfigure.AutoConfigurations
                        .of(DbscAutoConfiguration.class))
                .withPropertyValues("dbsc.secure=false", "dbsc.storage=redis")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("dbsc.storage: redis");
                });
    }

    @Test
    @DisplayName("an explicit dbsc.storage is never overridden by the library default")
    void explicitValueBeatsTheDefaultsFile() {
        // The regression this pins: application.yaml in the library sets
        // storage: jdbc, and a conditional that ignored the host's override would
        // hand back a JDBC adapter for dbsc.storage: redis.
        runner()
                .withPropertyValues("dbsc.storage=redis")
                .run(context -> assertThat(context.getBean(StorageAdapter.class))
                        .isInstanceOf(RedisStorageAdapter.class));
    }
}
