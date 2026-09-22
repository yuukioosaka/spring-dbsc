package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.core.DeviceKey;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.DbscErrorCode;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.crypto.DbscAlgorithm;
import click.yukio.dbsc.crypto.Jwk;
import click.yukio.dbsc.crypto.SignatureVerifier;
import click.yukio.dbsc.protocol.ChallengeService;
import click.yukio.dbsc.protocol.DbscProtocolEngine;
import click.yukio.dbsc.storage.InMemoryStorageAdapter;
import click.yukio.dbsc.telemetry.DbscTelemetryEvent;
import click.yukio.dbsc.telemetry.TelemetryPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.context.ApplicationEventPublisher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Protocol behavior tests: the ordered algorithms, the demotion-on-failure
 * mechanism, and the atomicity requirement.
 *
 * <p>Time is frozen so the vectors' timestamps are exactly inside the window,
 * which is what lets the vector signatures be replayed through the real engine.
 */
class ProtocolBehaviourTest {

    /** The instant the toolkit vectors were generated at. */
    private static final long VECTOR_NOW_MS = 1_700_000_000_000L;

    private static final String SESSION_ID = "sess_3f9a1c7e8b2d4f60a1b2c3d4e5f60718";
    private static final String CHALLENGE = "KN3qw_pQxR8tY5uI8oP1aS2dF3gH4jK5lM6nO7pQ8rS";

    private DbscProperties properties;
    private StorageAdapter storage;
    private ChallengeService challenges;
    private DbscProtocolEngine engine;
    private List<DbscTelemetryEvent> events;

    @BeforeEach
    void setUp() {
        properties = new DbscProperties();
        storage = new InMemoryStorageAdapter();
        Clock clock = Clock.fixed(Instant.ofEpochMilli(VECTOR_NOW_MS), ZoneOffset.UTC);
        challenges = new ChallengeService(storage, properties, clock);
        events = new ArrayList<>();
        // Collect the events an application would receive via @EventListener.
        ApplicationEventPublisher publisher = event -> {
            if (event instanceof DbscTelemetryEvent dbscEvent) {
                events.add(dbscEvent);
            }
        };
        TelemetryPublisher telemetry = new TelemetryPublisher(publisher, true);
        engine = new DbscProtocolEngine(storage, properties, challenges, clock, telemetry);
    }

    // ------------------------------------------------------------------
    // Native registration
    // ------------------------------------------------------------------

    @Test
    @DisplayName("registration: the vector JWS registers, stores a native key, and sets tier dbsc")
    void registrationWithVectorJws() {
        Map<String, Object> vector = TestVectors.load("registration");
        String jws = TestVectors.string(vector, "secureSessionResponse");
        seedSession();
        seedChallenge(CHALLENGE);

        DeviceKey key = engine.handleRegistration(SESSION_ID, jws, CHALLENGE);

        assertEquals("ES256", key.algorithm());
        assertEquals(SESSION_ID, key.sessionId());

        Session session = storage.getSession(SESSION_ID).orElseThrow();
        assertEquals(ProtectionTier.DBSC, session.tier());
        assertEquals(VECTOR_NOW_MS, session.lastRefreshAt());

        assertNotNull(events.stream()
                .filter(e -> e.type().equals("registration")).findFirst().orElse(null));
        assertNotNull(events.stream()
                .filter(e -> e.type().equals("tier_change")).findFirst().orElse(null));
    }

    @Test
    @DisplayName("registration: a missing response header fails MISSING_RESPONSE_HEADER")
    void registrationWithoutHeader() {
        seedSession();
        seedChallenge(CHALLENGE);

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleRegistration(SESSION_ID, null, CHALLENGE));
        assertEquals(DbscErrorCode.MISSING_RESPONSE_HEADER, failure.code());
    }

    @Test
    @DisplayName("registration: a second native key fails SESSION_ALREADY_REGISTERED")
    void registrationTwice() {
        Map<String, Object> vector = TestVectors.load("registration");
        String jws = TestVectors.string(vector, "secureSessionResponse");
        seedSession();
        seedChallenge(CHALLENGE);
        engine.handleRegistration(SESSION_ID, jws, CHALLENGE);

        seedChallenge(CHALLENGE);
        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleRegistration(SESSION_ID, jws, CHALLENGE));
        assertEquals(DbscErrorCode.SESSION_ALREADY_REGISTERED, failure.code());
    }

    @Test
    @DisplayName("registration: an unknown challenge fails CHALLENGE_NOT_FOUND")
    void registrationUnknownChallenge() {
        Map<String, Object> vector = TestVectors.load("registration");
        seedSession();

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleRegistration(SESSION_ID,
                        TestVectors.string(vector, "secureSessionResponse"), CHALLENGE));
        assertEquals(DbscErrorCode.CHALLENGE_NOT_FOUND, failure.code());
    }

    @Test
    @DisplayName("registration: a consumed challenge fails CHALLENGE_CONSUMED")
    void registrationConsumedChallenge() {
        Map<String, Object> vector = TestVectors.load("registration");
        seedSession();
        // Seed the challenge already consumed.
        storage.setChallenge(new Challenge(CHALLENGE, SESSION_ID,
                VECTOR_NOW_MS - 1000, VECTOR_NOW_MS + 60_000, true));

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleRegistration(SESSION_ID,
                        TestVectors.string(vector, "secureSessionResponse"), CHALLENGE));
        assertEquals(DbscErrorCode.CHALLENGE_CONSUMED, failure.code());
    }

    @Test
    @DisplayName("registration: an expired challenge fails CHALLENGE_EXPIRED")
    void registrationExpiredChallenge() {
        Map<String, Object> vector = TestVectors.load("registration");
        seedSession();
        storage.setChallenge(new Challenge(CHALLENGE, SESSION_ID,
                VECTOR_NOW_MS - 600_000, VECTOR_NOW_MS - 300_000, false));

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleRegistration(SESSION_ID,
                        TestVectors.string(vector, "secureSessionResponse"), CHALLENGE));
        assertEquals(DbscErrorCode.CHALLENGE_EXPIRED, failure.code());
    }

    @Test
    @DisplayName("registration: a challenge belonging to another session fails JTI_MISMATCH")
    void registrationChallengeForAnotherSession() {
        Map<String, Object> vector = TestVectors.load("registration");
        seedSession();
        storage.setChallenge(new Challenge(CHALLENGE, "sess_someone_else",
                VECTOR_NOW_MS, VECTOR_NOW_MS + 60_000, false));

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleRegistration(SESSION_ID,
                        TestVectors.string(vector, "secureSessionResponse"), CHALLENGE));
        assertEquals(DbscErrorCode.JTI_MISMATCH, failure.code());
    }

    // ------------------------------------------------------------------
    // Native refresh
    // ------------------------------------------------------------------

    @Test
    @DisplayName("refresh: the vector JWS verifies against the stored key and keeps tier dbsc")
    void refreshWithVectorJws() {
        Map<String, Object> vector = TestVectors.load("refresh");
        seedSession();
        storeDeviceKey(TestVectors.object(vector, "storedPublicKeyJwk"));
        seedChallenge(CHALLENGE);

        var outcome = engine.handleRefresh(
                SESSION_ID, TestVectors.string(vector, "secureSessionResponse"), CHALLENGE);

        assertEquals(SESSION_ID, outcome.sessionId());
        assertEquals(CHALLENGE, outcome.jti());
        assertEquals(ProtectionTier.DBSC, storage.getSession(SESSION_ID).orElseThrow().tier());
        assertEquals(VECTOR_NOW_MS, storage.getSession(SESSION_ID).orElseThrow().lastRefreshAt());
    }

    @Test
    @DisplayName("refresh: a bad signature demotes to none, burns the challenge, and reports session_stolen")
    void refreshFailureDemotesAndAlerts() {
        Map<String, Object> vector = TestVectors.load("refresh");
        seedSession();
        storeDeviceKey(TestVectors.object(vector, "storedPublicKeyJwk"));
        seedChallenge(CHALLENGE);
        // Start from dbsc so the demotion is observable.
        storage.setSession(storage.getSession(SESSION_ID).orElseThrow()
                .withTier(ProtectionTier.DBSC));

        // A JWS signed by a fresh key: its own self-signature is valid, but it
        // does not verify against the stored registration key.
        String foreignJws = registrationJwsFromFreshKey();

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleRefresh(SESSION_ID, foreignJws, CHALLENGE));
        assertEquals(DbscErrorCode.SIGNATURE_INVALID, failure.code());

        // Demotion-on-failure is the security mechanism.
        assertEquals(ProtectionTier.NONE,
                storage.getSession(SESSION_ID).orElseThrow().tier(),
                "a failed refresh signature MUST demote the session to tier: none");

        // The challenge is burned, so a captured proof cannot be retried.
        assertTrue(storage.getChallenge(CHALLENGE).orElseThrow().consumed(),
                "a failed refresh MUST consume the challenge");

        // A stolen cookie replayed without the key is the session_stolen signal.
        assertTrue(events.stream().anyMatch(e -> e.type().equals("session_stolen")),
                "session_stolen MUST fire when a refresh fails while the key exists");
        assertTrue(events.stream().anyMatch(e -> e.type().equals("verification_failure")));
    }

    @Test
    @DisplayName("refresh: no stored native key fails KEY_NOT_FOUND")
    void refreshWithoutStoredKey() {
        Map<String, Object> vector = TestVectors.load("refresh");
        seedSession();
        seedChallenge(CHALLENGE);

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleRefresh(SESSION_ID,
                        TestVectors.string(vector, "secureSessionResponse"), CHALLENGE));
        assertEquals(DbscErrorCode.KEY_NOT_FOUND, failure.code());
    }

    @Test
    @DisplayName("refresh: an expired challenge fails CHALLENGE_EXPIRED")
    void refreshExpiredChallenge() {
        Map<String, Object> vector = TestVectors.load("refresh");
        seedSession();
        storeDeviceKey(TestVectors.object(vector, "storedPublicKeyJwk"));
        storage.setChallenge(new Challenge(CHALLENGE, SESSION_ID,
                VECTOR_NOW_MS - 600_000, VECTOR_NOW_MS - 300_000, false));

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleRefresh(SESSION_ID,
                        TestVectors.string(vector, "secureSessionResponse"), CHALLENGE));
        assertEquals(DbscErrorCode.CHALLENGE_EXPIRED, failure.code());
    }

    // ------------------------------------------------------------------
    // Storage atomicity
    // ------------------------------------------------------------------

    @Test
    @DisplayName("consumeChallenge: exactly one of N concurrent callers wins")
    void challengeConsumptionIsAtomic() throws Exception {
        int threads = 16;
        seedChallenge(CHALLENGE);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger winners = new AtomicInteger();

        // ExecutorService only became AutoCloseable in Java 19, and these tests
        // compile at the Java 17 level, so shutdown is explicit.
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        if (storage.consumeChallenge(CHALLENGE)) {
                            winners.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(10, TimeUnit.SECONDS), "concurrent consume did not finish");
        } finally {
            pool.shutdownNow();
        }

        assertEquals(1, winners.get(),
                "a non-atomic consumeChallenge is a replay vulnerability: exactly one caller may win");
    }

    @Test
    @DisplayName("consumeChallenge: returns false for an unknown or already-consumed challenge")
    void consumeChallengeEdgeCases() {
        assertFalse(storage.consumeChallenge("no_such_jti"));
        seedChallenge(CHALLENGE);
        assertTrue(storage.consumeChallenge(CHALLENGE));
        assertFalse(storage.consumeChallenge(CHALLENGE));
    }

    // ------------------------------------------------------------------
    // Tier model
    // ------------------------------------------------------------------

    @Test
    @DisplayName("tier: the refresh grace window keeps a stale session readable")
    void refreshGraceWindow() {
        seedSession();
        storeDeviceKey(TestVectors.object(TestVectors.load("refresh"), "storedPublicKeyJwk"));

        // A stored key alone does not make a session protected: the stored tier is
        // authoritative. The key decides the ceiling the session can reach, not
        // whether it is currently protected, because a demoted session keeps its
        // key on purpose (so a later failure is still recognisable as stolen).
        Session promoted = storage.getSession(SESSION_ID).orElseThrow()
                .withTier(ProtectionTier.DBSC);
        storage.setSession(promoted);
        assertEquals(ProtectionTier.DBSC, engine.effectiveTier(promoted));

        // With the key gone and the grace elapsed, the session reads none.
        storage.deleteDeviceKey(SESSION_ID);
        Session stale = promoted.withTierAndLastRefreshAt(ProtectionTier.DBSC, VECTOR_NOW_MS - 3_600_000);
        storage.setSession(stale);
        assertEquals(ProtectionTier.NONE, engine.effectiveTier(stale));

        // Inside the grace window, the previous tier is still reported.
        Session inGrace = promoted.withTierAndLastRefreshAt(
                ProtectionTier.DBSC,
                VECTOR_NOW_MS - properties.bindingCookieTtlMs() - properties.refreshGraceMs() + 1000);
        storage.setSession(inGrace);
        assertEquals(ProtectionTier.DBSC, engine.effectiveTier(inGrace));
    }

    @Test
    @DisplayName("tier: a demoted session reads none even though its key survives")
    void demotedSessionReadsNoneDespiteLiveKey() {
        seedSession();
        storeDeviceKey(TestVectors.object(TestVectors.load("refresh"), "storedPublicKeyJwk"));
        storage.setSession(storage.getSession(SESSION_ID).orElseThrow()
                .withTier(ProtectionTier.DBSC));
        assertEquals(ProtectionTier.DBSC,
                engine.effectiveTier(storage.getSession(SESSION_ID).orElseThrow()));

        // Demote the way a failed refresh does: the tier goes to none, the key
        // stays. Reporting dbsc here would silently undo the demotion, leaving a
        // session whose proof just failed still able to open guarded routes.
        Session demoted = storage.getSession(SESSION_ID).orElseThrow()
                .withTier(ProtectionTier.NONE);
        storage.setSession(demoted);

        assertEquals(ProtectionTier.NONE, engine.effectiveTier(demoted),
                "a demoted session MUST NOT be reported as protected");
        assertTrue(storage.getDeviceKey(SESSION_ID).isPresent(),
                "the key MUST survive the demotion so session_stolen stays detectable");
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private void seedSession() {
        seedSession(SESSION_ID);
    }

    private void seedSession(String sessionId) {
        storage.setSession(new Session(sessionId, "app_" + sessionId, "user_1", ProtectionTier.NONE,
                false, VECTOR_NOW_MS, VECTOR_NOW_MS + 3_600_000, 0));
    }

    private void seedChallenge(String jti) {
        storage.setChallenge(new Challenge(jti, SESSION_ID,
                VECTOR_NOW_MS, VECTOR_NOW_MS + properties.challengeTtlMs(), false));
    }

    private void storeDeviceKey(Map<String, Object> jwk) {
        storeDeviceKey(SESSION_ID, jwk);
    }

    private void storeDeviceKey(String sessionId, Map<String, Object> jwk) {
        storage.setDeviceKey(new DeviceKey(sessionId, jwk, "ES256", VECTOR_NOW_MS));
    }


    /**
     * Builds a structurally valid registration JWS signed by a fresh P-256 key.
     *
     * <p>It is deliberately a <em>refresh-shaped</em> token: no {@code jwk} in the
     * header, so it gets past the shape checks and fails at the signature check
     * against the stored key. That is the path the demotion logic guards.
     */
    private String registrationJwsFromFreshKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = generator.generateKeyPair();

            // A refresh JWS carries no jwk: the server uses the stored key.
            String header = base64Url(click.yukio.dbsc.core.Json.write(Map.of(
                    "alg", "ES256", "typ", "dbsc+jwt")).getBytes(StandardCharsets.UTF_8));
            String payload = base64Url(click.yukio.dbsc.core.Json.write(Map.of("jti", CHALLENGE))
                    .getBytes(StandardCharsets.UTF_8));

            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(pair.getPrivate());
            signer.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));

            return header + "." + payload + "." + base64Url(derToRaw(signer.sign()));
        } catch (Exception e) {
            throw new IllegalStateException("failed to build a fixture JWS", e);
        }
    }

    private static byte[] paddedCoordinate(byte[] value) {
        if (value.length == 32) {
            return value;
        }
        byte[] out = new byte[32];
        int copy = Math.min(value.length, 32);
        System.arraycopy(value, value.length - copy, out, 32 - copy, copy);
        return out;
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Converts a DER ECDSA signature into the fixed-width JWS form. */
    private static byte[] derToRaw(byte[] der) {
        int offset = 2;
        if ((der[1] & 0xFF) > 0x80) {
            offset = 3;
        }
        int rLength = der[offset + 1] & 0xFF;
        int rStart = offset + 2;
        int sLength = der[rStart + rLength + 1] & 0xFF;
        int sStart = rStart + rLength + 2;

        byte[] raw = new byte[64];
        copyComponent(der, rStart, rLength, raw, 0);
        copyComponent(der, sStart, sLength, raw, 32);
        return raw;
    }

    private static void copyComponent(byte[] der, int start, int length, byte[] out, int outOffset) {
        int effectiveStart = start;
        int effectiveLength = length;
        // Strip a leading zero the DER encoder adds to keep the integer positive.
        while (effectiveLength > 32 && der[effectiveStart] == 0) {
            effectiveStart++;
            effectiveLength--;
        }
        System.arraycopy(der, effectiveStart, out, outOffset + 32 - effectiveLength, effectiveLength);
    }
}
