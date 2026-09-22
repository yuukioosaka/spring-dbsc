package click.yukio.dbsc;

import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.DeviceKey;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.RegistrationToken;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.storage.RedisStorageAdapter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import redis.embedded.RedisServer;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Redis adapter against a real server.
 *
 * <p>Not a mock. The adapter's correctness argument is that one Lua script runs to
 * completion server-side without interleaving, and a stubbed client cannot show
 * that — it would pass just as happily against the read-then-write implementation
 * the script exists to avoid. {@code embedded-redis} ships a server binary for this
 * platform, so the real thing is available in the test JVM.
 *
 * <p>The port is fixed rather than random because {@code RedisServer} is started as
 * a separate process; a collision fails this class loudly rather than silently
 * testing nothing.
 */
class RedisStorageAdapterTest {

    private static final int PORT = 16399;
    private static final int THREADS = 16;

    private static RedisServer server;
    private static LettuceConnectionFactory connectionFactory;
    private static RedisStorageAdapter storage;

    @BeforeAll
    static void startServer() throws Exception {
        server = RedisServer.newRedisServer().port(PORT).build();
        server.start();
        connectionFactory = new LettuceConnectionFactory("localhost", PORT);
        connectionFactory.afterPropertiesSet();
        storage = new RedisStorageAdapter(new StringRedisTemplate(connectionFactory));
    }

    @AfterAll
    static void stopServer() throws Exception {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
        if (server != null) {
            server.stop();
        }
    }

    @Test
    @DisplayName("redis: a session round-trips")
    void sessionRoundTrip() {
        long now = System.currentTimeMillis();
        String id = "sess_" + System.nanoTime();
        storage.setSession(new Session(id, "app_" + id, "user_1",
                ProtectionTier.DBSC, false, now, now + 300_000, now));

        Session loaded = storage.getSession(id).orElseThrow();
        assertEquals(ProtectionTier.DBSC, loaded.tier());
        assertEquals("user_1", loaded.userId());
        assertEquals("app_" + id, loaded.appSessionId());
        assertEquals(now, loaded.lastRefreshAt());
    }

    @Test
    @DisplayName("redis: a session is found by its application session id")
    void lookupByAppSessionId() {
        long now = System.currentTimeMillis();
        String id = "sess_" + System.nanoTime();
        String app = "app_" + id;
        storage.setSession(new Session(id, app, "user_1",
                ProtectionTier.NONE, false, now, now + 300_000, 0));

        assertEquals(id, storage.getSessionByAppSessionId(app).orElseThrow().id());
        assertTrue(storage.getSessionByAppSessionId("unknown_" + id).isEmpty());
    }

    @Test
    @DisplayName("redis: a device key round-trips with its JWK intact")
    void deviceKeyRoundTrip() {
        long now = System.currentTimeMillis();
        String id = "sess_" + System.nanoTime();
        storage.setSession(new Session(id, "app_" + id, "user_1",
                ProtectionTier.DBSC, false, now, now + 300_000, now));
        Map<String, Object> jwk = Map.of(
                "kty", "EC", "crv", "P-256", "x", "abc", "y", "def");
        storage.setDeviceKey(new DeviceKey(id, jwk, "ES256", now));

        DeviceKey loaded = storage.getDeviceKey(id).orElseThrow();
        assertEquals("ES256", loaded.algorithm());
        assertEquals("P-256", loaded.jwk().get("crv"));
        assertEquals("abc", loaded.jwk().get("x"));
    }

    @Test
    @DisplayName("redis: deleting a session clears its reverse index and key")
    void deleteSessionClearsRelatedRecords() {
        long now = System.currentTimeMillis();
        String id = "sess_" + System.nanoTime();
        String app = "app_" + id;
        storage.setSession(new Session(id, app, "user_1",
                ProtectionTier.DBSC, false, now, now + 300_000, now));
        storage.setDeviceKey(new DeviceKey(id, Map.of("kty", "EC"), "ES256", now));

        storage.deleteSession(id);

        assertTrue(storage.getSession(id).isEmpty());
        assertTrue(storage.getDeviceKey(id).isEmpty());
        // The reverse index is keyed by the application session id, not the DBSC id, so
        // it is the one that a naive delete would leave pointing at a removed session.
        assertTrue(storage.getSessionByAppSessionId(app).isEmpty());
    }

    @Test
    @DisplayName("redis: consumeChallenge is atomic under real concurrency")
    void consumeChallengeIsAtomic() throws Exception {
        String jti = "jti_" + System.nanoTime();
        long now = System.currentTimeMillis();
        storage.setChallenge(new Challenge(jti, "sess_concurrent", now, now + 300_000, false));

        AtomicInteger winners = new AtomicInteger();
        runConcurrently(() -> {
            if (storage.consumeChallenge(jti)) {
                winners.incrementAndGet();
            }
        });

        assertEquals(1, winners.get(),
                "exactly one concurrent caller may observe a successful consume");
    }

    @Test
    @DisplayName("redis: a consumed challenge stays consumed")
    void consumedStaysConsumed() {
        String jti = "jti_" + System.nanoTime();
        long now = System.currentTimeMillis();
        storage.setChallenge(new Challenge(jti, "sess_seq", now, now + 300_000, false));

        assertTrue(storage.consumeChallenge(jti));
        assertFalse(storage.consumeChallenge(jti));
        assertTrue(storage.getChallenge(jti).orElseThrow().consumed());
    }

    @Test
    @DisplayName("redis: consuming an unknown or expired challenge is false, not an error")
    void consumingAMissingChallengeIsFalse() {
        // An expired record is gone from Redis by the time the client presents it, so
        // this is the CHALLENGE_EXPIRED path: it must read as "not consumed by me"
        // rather than throwing, or expiry would surface as a 500.
        assertFalse(storage.consumeChallenge("jti_never_existed_" + System.nanoTime()));
    }

    @Test
    @DisplayName("redis: registration tokens consume exactly once")
    void registrationTokenIsSingleUse() {
        String token = "tok_" + System.nanoTime();
        long now = System.currentTimeMillis();
        storage.setRegistrationToken(new RegistrationToken(token, "sess_tok", now, now + 300_000, false));

        assertEquals("sess_tok", storage.getRegistrationToken(token).orElseThrow().sessionId());
        assertTrue(storage.consumeRegistrationToken(token));
        assertFalse(storage.consumeRegistrationToken(token));
    }

    @Test
    @DisplayName("redis: revokeSession keeps the record and marks it revoked")
    void revokeKeepsTheRecord() {
        long now = System.currentTimeMillis();
        String id = "sess_" + System.nanoTime();
        String app = "app_" + id;
        storage.setSession(new Session(id, app, "user_1",
                ProtectionTier.DBSC, false, now, now + 300_000, now));

        storage.revokeSession(id);

        Session revoked = storage.getSession(id).orElseThrow();
        assertTrue(revoked.revoked());
        assertEquals(ProtectionTier.DBSC, revoked.tier());
        // The application session id lookup is what the guard uses to tell "never
        // registered" from "registered and dropped its cookies". Deleting the record
        // would erase that distinction.
        assertTrue(storage.getSessionByAppSessionId(app).isPresent());
    }

    @Test
    @DisplayName("redis: a losing re-registration replaces the key, not appends to it")
    void deviceKeyIsReplacedNotAccumulated() {
        long now = System.currentTimeMillis();
        String id = "sess_" + System.nanoTime();
        storage.setDeviceKey(new DeviceKey(id, Map.of("kty", "EC", "x", "first"), "ES256", now));
        storage.setDeviceKey(new DeviceKey(id, Map.of("kty", "EC", "x", "second"), "ES256", now));

        assertEquals("second", storage.getDeviceKey(id).orElseThrow().jwk().get("x"));
    }

    @Test
    @DisplayName("redis: an app session id maps to at most one DBSC session")
    void oneBindingPerAppSession() {
        long now = System.currentTimeMillis();
        String app = "app_" + System.nanoTime();
        String first = "sess_a_" + System.nanoTime();
        String second = "sess_b_" + System.nanoTime();
        storage.setSession(new Session(first, app, "user_1",
                ProtectionTier.DBSC, false, now, now + 300_000, now));
        storage.setSession(new Session(second, app, "user_1",
                ProtectionTier.DBSC, false, now, now + 300_000, now));

        // The latest write owns the index; the older record is unreachable by app
        // session id, which is the property the guard's "already bound" answer needs.
        assertEquals(second, storage.getSessionByAppSessionId(app).orElseThrow().id());
        assertNotEquals(first, storage.getSessionByAppSessionId(app).orElseThrow().id());
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
}
