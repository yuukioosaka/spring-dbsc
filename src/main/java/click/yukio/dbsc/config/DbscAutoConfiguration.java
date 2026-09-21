package click.yukio.dbsc.config;

import click.yukio.dbsc.DbscService;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.protocol.ChallengeService;
import click.yukio.dbsc.protocol.CookieScope;
import click.yukio.dbsc.protocol.DbscProtocolEngine;
import click.yukio.dbsc.ratelimit.InMemoryRateLimiter;
import click.yukio.dbsc.ratelimit.RateLimiter;
import click.yukio.dbsc.replay.InMemoryProofReplayCache;
import click.yukio.dbsc.replay.JdbcProofReplayCache;
import click.yukio.dbsc.replay.ProofReplayCache;
import click.yukio.dbsc.storage.InMemoryStorageAdapter;
import click.yukio.dbsc.storage.JdbcStorageAdapter;
import click.yukio.dbsc.telemetry.TelemetryPublisher;
import click.yukio.dbsc.web.DbscFilterConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import javax.sql.DataSource;
import java.time.Clock;

/**
 * Wires the DBSC building blocks.
 *
 * <p>Every collaborator is replaceable: an application that already has a
 * session store can supply its own {@link StorageAdapter}, and a deployment with
 * more than one process should supply a shared {@link ProofReplayCache} and
 * {@link RateLimiter}.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(DbscProperties.class)
@ConditionalOnProperty(prefix = "dbsc", name = "enabled", havingValue = "true", matchIfMissing = true)
// Filters only. The library declares no SecurityFilterChain: which paths are DBSC
// protocol routes and what runs before authentication are Security-policy decisions
// that belong to the application. A library-supplied chain would either collide with
// the adopter's own (two chains matching /** is a hard startup error) or, worse, be
// kept and replace their authorization rules. See the README's "Getting Started".
@Import(DbscFilterConfiguration.class)
public class DbscAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(DbscAutoConfiguration.class);

    /**
     * A durable JDBC store backed by the application's {@link DataSource}.
     *
     * <p>Persistence is required for any deployment that can restart: an
     * in-memory store breaks live sessions, because the browser still holds a
     * binding cookie, refresh fails with {@code KEY_NOT_FOUND_NATIVE}, and the
     * browser loops registration.
     */
    @Bean
    @ConditionalOnMissingBean(StorageAdapter.class)
    public StorageAdapter dbscStorageAdapter(DataSource dataSource) {
        JdbcStorageAdapter adapter = new JdbcStorageAdapter(dataSource);
        adapter.initialize();
        log.info("DBSC storage: JDBC (durable)");
        return adapter;
    }

    @Bean
    @ConditionalOnMissingBean(ChallengeService.class)
    public ChallengeService dbscChallengeService(
            StorageAdapter storage, DbscProperties properties, Clock clock) {
        return new ChallengeService(storage, properties, clock);
    }

    @Bean
    @ConditionalOnMissingBean(TelemetryPublisher.class)
    public TelemetryPublisher dbscTelemetryPublisher(ApplicationEventPublisher publisher) {
        return new TelemetryPublisher(publisher, true);
    }

    @Bean
    @ConditionalOnMissingBean(DbscProtocolEngine.class)
    public DbscProtocolEngine dbscProtocolEngine(
            StorageAdapter storage,
            DbscProperties properties,
            ChallengeService challenges,
            Clock clock,
            TelemetryPublisher telemetry) {
        return new DbscProtocolEngine(storage, properties, challenges, clock, telemetry);
    }

    /**
     * A replay cache shared through the application's {@link DataSource}, so the
     * check-and-record is atomic across processes. Falls back to a single-process
     * cache when no DataSource is available.
     */
    @Bean
    @ConditionalOnMissingBean(ProofReplayCache.class)
    public ProofReplayCache dbscReplayCache(ObjectProvider<DataSource> dataSource) {
        DataSource ds = dataSource.getIfAvailable();
        if (ds == null) {
            log.warn("DBSC replay cache: in-memory (single process only)");
            return new InMemoryProofReplayCache();
        }
        JdbcProofReplayCache cache = new JdbcProofReplayCache(ds);
        cache.initialize();
        log.info("DBSC replay cache: JDBC (multi-process)");
        return cache;
    }

    @Bean
    @ConditionalOnMissingBean(RateLimiter.class)
    public RateLimiter dbscRateLimiter(DbscProperties properties) {
        if (!properties.getRateLimit().isEnabled()) {
            return RateLimiter.UNLIMITED;
        }
        return new InMemoryRateLimiter(
                properties.getRateLimit().getCapacity(),
                properties.getRateLimit().getFailureCapacity(),
                properties.getRateLimit().getWindow());
    }

    @Bean
    @ConditionalOnMissingBean(CookieScope.class)
    public CookieScope dbscCookieScope(DbscProperties properties) {
        return CookieScope.resolve(
                properties.isSecure(), properties.getCookieScope(), properties.getCookieDomain());
    }

    @Bean
    @ConditionalOnMissingBean(Clock.class)
    public Clock dbscClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean(DbscService.class)
    public DbscService dbscService(
            DbscProperties properties,
            StorageAdapter storage,
            ChallengeService challenges,
            DbscProtocolEngine engine,
            CookieScope cookieScope,
            RateLimiter rateLimiter,
            ProofReplayCache replayCache,
            Clock clock) {
        return new DbscService(
                properties,
                storage,
                challenges,
                engine,
                cookieScope,
                rateLimiter,
                replayCache,
                clock,
                properties.isSecure());
    }

    /**
     * The in-memory store is only for development. This bean exists so a
     * dev profile can opt in without supplying a {@link DataSource}.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "dbsc", name = "storage", havingValue = "memory")
    static class DevStorageConfiguration {

        @Bean
        @ConditionalOnMissingBean(StorageAdapter.class)
        public StorageAdapter devStorageAdapter() {
            log.warn("DBSC storage: in-memory — bound keys are lost on restart. "
                    + "Live sessions will break. Development only.");
            return new InMemoryStorageAdapter();
        }
    }
}
