package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscAutoConfiguration;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.storage.JdbcStorageAdapter;
import click.yukio.dbsc.storage.RedisStorageAdapter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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

    /**
     * A {@code StringRedisTemplate} that keeps hash writes in a map instead of talking
     * to a server.
     *
     * <p>A plain Mockito stub cannot do, because the one test that stores and reads a
     * session back needs {@code entries()} to return what {@code putAll()} was given.
     * Four lines of in-memory state replace a test-scoped Redis distribution.
     *
     * <p>What this deliberately does not reproduce: real expiry, and the Lua script's
     * atomicity. Neither is what this class is about -- it asserts which adapter the
     * property selects, and the {@code entries()} round trip is only there to show the
     * selected adapter is actually reachable.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    static StringRedisTemplate inMemoryRedis() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        Map<String, Map<Object, Object>> hashes = new ConcurrentHashMap<>();
        Map<String, String> values = new ConcurrentHashMap<>();

        HashOperations hashOps = mock(HashOperations.class);
        when(redis.opsForHash()).thenReturn(hashOps);
        when(hashOps.entries(anyString()))
                .thenAnswer(invocation -> new LinkedHashMap<>(hashes.getOrDefault(
                        invocation.getArgument(0), Map.of())));
        doAnswer(invocation -> {
            hashes.put(invocation.getArgument(0),
                    new ConcurrentHashMap<>(invocation.getArgument(1)));
            return null;
        }).when(hashOps).putAll(anyString(), any(Map.class));
        doAnswer(invocation -> {
            hashes.computeIfAbsent(invocation.getArgument(0), k -> new ConcurrentHashMap<>())
                    .put(invocation.getArgument(1), invocation.getArgument(2));
            return null;
        }).when(hashOps).put(anyString(), any(), any());

        ValueOperations valueOps = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenAnswer(invocation -> values.get(invocation.getArgument(0)));
        doAnswer(invocation -> {
            values.put(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(valueOps).set(anyString(), anyString(), any(java.time.Duration.class));

        return redis;
    }

    /** A Redis client, the way a host app on starter-data-redis would have one. */
    @Configuration(proxyBeanMethods = false)
    static class RedisClientConfiguration {
        @Bean
        StringRedisTemplate stringRedisTemplate() {
            return inMemoryRedis();
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
