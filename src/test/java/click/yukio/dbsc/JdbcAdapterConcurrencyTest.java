package click.yukio.dbsc;

import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.storage.JdbcStorageAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;

import javax.sql.DataSource;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Atomicity of the JDBC adapters under real concurrency.
 *
 * <p>The in-memory adapter gets its atomicity from
 * {@code ConcurrentHashMap.compute}; the JDBC adapter gets it from a conditional
 * {@code UPDATE} and a primary key. A non-atomic challenge consume is a replay
 * vulnerability, so it needs its own test.
 *
 * <p>Each test uses its own uniquely-named in-memory H2 database, so they can run
 * in parallel without sharing state.
 */
class JdbcAdapterConcurrencyTest {

    private static final int THREADS = 16;

    private DataSource dataSource;
    private JdbcStorageAdapter storage;

    @BeforeEach
    void setUp() {
        // DB_CLOSE_DELAY=-1 keeps the database alive while the pool churns connections.
        String url = "jdbc:h2:mem:dbsc_concurrency_" + System.nanoTime() + ";DB_CLOSE_DELAY=-1";
        SimpleDriverDataSource source = new SimpleDriverDataSource();
        source.setDriverClass(org.h2.Driver.class);
        source.setUrl(url);
        source.setUsername("sa");
        source.setPassword("");

        dataSource = source;
        storage = new JdbcStorageAdapter(dataSource);
        storage.initialize();
    }

    @Test
    @DisplayName("JDBC consumeChallenge: exactly one of N concurrent callers wins")
    void consumeChallengeIsAtomic() throws Exception {
        String jti = "jti_concurrent";
        seedChallenge(jti);

        AtomicInteger winners = new AtomicInteger();
        runConcurrently(() -> {
            if (storage.consumeChallenge(jti)) {
                winners.incrementAndGet();
            }
        });

        assertEquals(1, winners.get(),
                "the UPDATE ... WHERE consumed = false must let exactly one caller win");
    }

    @Test
    @DisplayName("JDBC consumeChallenge: a consumed challenge stays consumed")
    void consumedStaysConsumed() {
        seedChallenge("jti_sequential");
        assertTrue(storage.consumeChallenge("jti_sequential"));
        assertFalse(storage.consumeChallenge("jti_sequential"));
    }

    /** Runs {@code work} on {@value #THREADS} threads released from a single latch. */
    private void runConcurrently(Runnable work) throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(THREADS);

        // ExecutorService only became AutoCloseable in Java 19, and these tests
        // compile at the Java 17 level, so shutdown is explicit.
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        try {
            for (int i = 0; i < THREADS; i++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        work.run();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(30, TimeUnit.SECONDS), "concurrent work did not finish");
        } finally {
            pool.shutdownNow();
        }
    }

    private void seedChallenge(String jti) {
        long now = System.currentTimeMillis();
        storage.setChallenge(new Challenge(jti, "sess_jdbc", now, now + 300_000, false));
    }

    @Test
    @DisplayName("JDBC storage: a session round-trips through the database")
    void sessionRoundTrip() {
        long now = System.currentTimeMillis();
        storage.setSession(new Session("sess_jdbc", "app_jdbc", "user_1",
                ProtectionTier.DBSC, false, now, now + 60_000, now));

        Session loaded = storage.getSession("sess_jdbc").orElseThrow();
        assertEquals(ProtectionTier.DBSC, loaded.tier());
        assertEquals("user_1", loaded.userId());
    }
}
