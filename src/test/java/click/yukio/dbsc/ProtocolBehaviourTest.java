package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.core.BoundKey;
import click.yukio.dbsc.core.BoundKeyKind;
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
import click.yukio.dbsc.replay.InMemoryProofReplayCache;
import click.yukio.dbsc.replay.ProofReplayCache;
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

        BoundKey key = engine.handleRegistration(SESSION_ID, jws, CHALLENGE);

        assertEquals(BoundKeyKind.NATIVE, key.kind());
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
        storeNativeKey(TestVectors.object(vector, "storedPublicKeyJwk"));
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
        storeNativeKey(TestVectors.object(vector, "storedPublicKeyJwk"));
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
    @DisplayName("refresh: no stored native key fails KEY_NOT_FOUND_NATIVE")
    void refreshWithoutStoredKey() {
        Map<String, Object> vector = TestVectors.load("refresh");
        seedSession();
        seedChallenge(CHALLENGE);

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleRefresh(SESSION_ID,
                        TestVectors.string(vector, "secureSessionResponse"), CHALLENGE));
        assertEquals(DbscErrorCode.KEY_NOT_FOUND_NATIVE, failure.code());
    }

    @Test
    @DisplayName("refresh: an expired challenge fails CHALLENGE_EXPIRED")
    void refreshExpiredChallenge() {
        Map<String, Object> vector = TestVectors.load("refresh");
        seedSession();
        storeNativeKey(TestVectors.object(vector, "storedPublicKeyJwk"));
        storage.setChallenge(new Challenge(CHALLENGE, SESSION_ID,
                VECTOR_NOW_MS - 600_000, VECTOR_NOW_MS - 300_000, false));

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleRefresh(SESSION_ID,
                        TestVectors.string(vector, "secureSessionResponse"), CHALLENGE));
        assertEquals(DbscErrorCode.CHALLENGE_EXPIRED, failure.code());
    }

    // ------------------------------------------------------------------
    // Bound protocol
    // ------------------------------------------------------------------

    @Test
    @DisplayName("bound registration: the vector signature over the bare JTI registers a bound key")
    void boundRegistrationWithVector() {
        Map<String, Object> vector = TestVectors.load("bound-registration");
        Map<String, Object> body = TestVectors.object(vector, "requestBody");
        seedSession();
        seedChallenge(CHALLENGE);

        BoundKey key = engine.handleBoundRegistration(
                SESSION_ID,
                TestVectors.object(body, "publicKey"),
                TestVectors.string(body, "signature"),
                TestVectors.string(body, "challenge"));

        assertEquals(BoundKeyKind.BOUND, key.kind());
        assertEquals("ES256", key.algorithm());
        // No native key, so the tier becomes bound.
        assertEquals(ProtectionTier.BOUND, storage.getSession(SESSION_ID).orElseThrow().tier());
    }

    @Test
    @DisplayName("bound registration: RS256 is rejected even though native permits it")
    void boundRegistrationRejectsRsa() {
        seedSession();
        seedChallenge(CHALLENGE);
        // A valid 2048-bit RSA public key: acceptable as a JWK, but the bound
        // protocol permits ES256 exclusively.
        Map<String, Object> rsaJwk = new LinkedHashMap<>();
        rsaJwk.put("kty", "RSA");
        rsaJwk.put("n", "wAAAd3q0cW_Oa8a2tmyO2m1qBsSRVRXoPege0mFElhzeR9tnpjLgO7V1QmZ4KPsJcMEdv"
                + "V7cJ7-PqKx3HpKjdG3yfTkO3DvNsW5tJTPuKAhM2lUZ4oWdVpErwYbLxNncXqC1sT8hR"
                + "mAz8QdKmN6PvT1yXcG3sQz3QcJ0JhKd1RhbWvFj2sV7tL0pMzYQ4nZkSdX8PzU5nCb"
                + "Q2wV9rD1mHtF3kJx8YqZ6bNfL4sT0vW7cR5pEaB2uG9dK3mH6nS1xQ8jZ4yT7wV0rC5fL"
                + "9kP2bN8dM4sX1qG6hJ3tR7yW0zA5vE9uB4iC8lO2nF6pD3mK1aT5sY7xQ9rV0wZ2gH4jc"
                + "N6bP8dT1mK3sY5xA7vQ9wR2zF4hJ6lC8nE0pG3iB5uD7oM9tS1rL4kX6yZ8aV0cW2fQ4"
                + "H6jN8bP1dT3mK5sY7xA9vQ2wR4zF6hJ8lC1nE3pG5iB7uD9oM1tS3rL6kX8yZ0aV2cW4"
                + "fQ6H8jN1bP3dT5mK7sY9xA2vQ4wR6zF8hJ1lC3nE5pG7iB9uD2oM4tS6rL8kX0yZ3aV5c"
                + "W7fQ9H2jN4bP6dT8mK1sY3xA5vQ7wR9zF2hJ4lC6nE8pG1iB3uD5oM7tS9rL2kX4yZ6aV8"
                + "cW1fQ3H5jN7bP9dT2mK4sY6xA8vQ1wR3zF5hJ7lC9nE2pG4iB6uD8oM1tS3rL5kX7yZ9aV"
                + "2cW4fQ6H8jN1bP3dT5mK7sY9xA2vQ4wR6zF8hJ1lC3nE5pG7iB9uD2oM4tS6rL8kX0yZ3"
                + "aV5cW7fQ9H2jN4bP6dT8mK1sY3xA5vQ7wR9zF2hJ4lC6nE8pG1iB3uD5oM7tS9rL2kX4y"
                + "Z6aV8cW1fQ3H5jN7bP9dT2mK4sY6xA8vQ1wR3zF5hJ7lC9nE2pG4iB6uD8oM1tS3rL5kX"
                + "7yZ9aV2cW4fQ6H8jN1bP3dT5mK7sY9xA2vQ4wR6zF8hJ1lC3nE5pG7iB9uD2oM4tS6rL8"
                + "kX0yZ3aV5cW7fQ9H2jN4bP6dT8mK1sY3xA5vQ7wR9zF2hJ4lC6nE8pG1iB3uD5oM7tS9"
                + "rL2kX4yZ6aV8cW1fQ3H5jN7bP9dT2mK4sY6xA8vQ1wR3zF5hJ7lC9nE2pG4iB6uD8oM1"
                + "tS3rL5kX7yZ9aV2cW4fQ6H8jN1bP3dT5mK7sY9xA2vQ4wR6zF8hJ1lC3nE5pG7iB9uD2"
                + "oM4tS6rL8kX0yZ3aV5cW7fQ9H2jN4bP6dT8mK1sY3xA5vQ7wR9zF2hJ4lC6nE8pG1i"
                + "B3uD5oM7tS9rL2kX4yZ6aV8cW1fQ3H5jN7bP9dT2mK4sY6xA8vQ1wR3zF5hJ7lC9nE2"
                + "pG4iB6uD8oM1tS3rL5kX7yZ9aV2cW4fQ6H8j");
        rsaJwk.put("e", "AQAB");
        Jwk.validate(rsaJwk);
        assertEquals(DbscAlgorithm.RS256, Jwk.detectAlgorithm(rsaJwk));

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleBoundRegistration(SESSION_ID, rsaJwk, "sig", CHALLENGE));
        assertEquals(DbscErrorCode.UNKNOWN_ALGORITHM, failure.code());
    }

    @Test
    @DisplayName("bound registration: a session holding a native key keeps tier dbsc")
    void boundRegistrationKeepsNativeTier() {
        Map<String, Object> vector = TestVectors.load("bound-registration");
        Map<String, Object> body = TestVectors.object(vector, "requestBody");
        seedSession();
        storeNativeKey(TestVectors.object(
                TestVectors.load("refresh"), "storedPublicKeyJwk"));
        storage.setSession(storage.getSession(SESSION_ID).orElseThrow()
                .withTier(ProtectionTier.DBSC));
        seedChallenge(CHALLENGE);

        engine.handleBoundRegistration(
                SESSION_ID,
                TestVectors.object(body, "publicKey"),
                TestVectors.string(body, "signature"),
                TestVectors.string(body, "challenge"));

        assertEquals(ProtectionTier.DBSC,
                storage.getSession(SESSION_ID).orElseThrow().tier(),
                "a Chromium session with both keys keeps the native tier");
        // Both slots are now occupied.
        assertTrue(storage.getBoundKey(SESSION_ID, BoundKeyKind.NATIVE).isPresent());
        assertTrue(storage.getBoundKey(SESSION_ID, BoundKeyKind.BOUND).isPresent());
    }

    @Test
    @DisplayName("bound refresh: the vector signature over <jti>.<ts> verifies")
    void boundRefreshWithVector() {
        Map<String, Object> vector = TestVectors.load("bound-refresh");
        Map<String, Object> body = TestVectors.object(vector, "requestBody");
        seedSession();
        storeBoundKey(TestVectors.object(vector, "publicKeyJwk"));
        seedChallenge(CHALLENGE);

        var outcome = engine.handleBoundRefresh(
                SESSION_ID,
                TestVectors.string(body, "signature"),
                TestVectors.string(body, "challenge"),
                TestVectors.longValue(body, "timestamp"));

        assertEquals(CHALLENGE, outcome.jti());
        assertEquals(ProtectionTier.BOUND, storage.getSession(SESSION_ID).orElseThrow().tier());
    }

    @Test
    @DisplayName("bound refresh: a timestamp outside the window fails SIGNATURE_INVALID")
    void boundRefreshTimestampOutsideWindow() {
        Map<String, Object> vector = TestVectors.load("bound-refresh");
        Map<String, Object> body = TestVectors.object(vector, "requestBody");
        seedSession();
        storeBoundKey(TestVectors.object(vector, "publicKeyJwk"));
        seedChallenge(CHALLENGE);

        // 6 minutes past the vector's timestamp: outside the ±5-minute window.
        long staleTimestamp = TestVectors.longValue(body, "timestamp") + 6 * 60 * 1000;

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.handleBoundRefresh(
                        SESSION_ID,
                        TestVectors.string(body, "signature"),
                        TestVectors.string(body, "challenge"),
                        staleTimestamp));
        assertEquals(DbscErrorCode.SIGNATURE_INVALID, failure.code());
    }

    // ------------------------------------------------------------------
    // Per-request proof
    // ------------------------------------------------------------------

    @Test
    @DisplayName("proof: the vector's bodyless proof verifies through the engine")
    void proofWithoutBody() {
        Map<String, Object> vector = TestVectors.load("per-request-proof");
        Map<String, Object> withoutBody = TestVectors.object(vector, "withoutBody");
        String sessionId = TestVectors.string(vector, "sessionId");
        seedSession(sessionId);
        storeBoundKey(sessionId, TestVectors.object(vector, "publicKeyJwk"));

        engine.verifyBoundProof(
                sessionId,
                TestVectors.string(withoutBody, "header"),
                TestVectors.string(withoutBody, "method"),
                TestVectors.string(withoutBody, "path"),
                null,
                false,
                null);
    }

    @Test
    @DisplayName("proof: the vector's body-bound proof verifies, and a modified body does not")
    void proofWithBody() {
        Map<String, Object> vector = TestVectors.load("per-request-proof");
        Map<String, Object> withBody = TestVectors.object(vector, "withBody");
        String sessionId = TestVectors.string(vector, "sessionId");
        seedSession(sessionId);
        storeBoundKey(sessionId, TestVectors.object(vector, "publicKeyJwk"));

        byte[] body = TestVectors.string(withBody, "body").getBytes(StandardCharsets.UTF_8);

        engine.verifyBoundProof(
                sessionId,
                TestVectors.string(withBody, "header"),
                TestVectors.string(withBody, "method"),
                TestVectors.string(withBody, "path"),
                body,
                true,
                null);

        // The body-hash binding stops a captured proof being reused on a new body.
        byte[] tampered = "{\"amount\":9999,\"currency\":\"usd\"}".getBytes(StandardCharsets.UTF_8);
        DbscException failure = assertThrows(DbscException.class,
                () -> engine.verifyBoundProof(
                        sessionId,
                        TestVectors.string(withBody, "header"),
                        TestVectors.string(withBody, "method"),
                        TestVectors.string(withBody, "path"),
                        tampered,
                        true,
                        null));
        assertEquals(DbscErrorCode.SIGNATURE_INVALID, failure.code());
    }

    @Test
    @DisplayName("proof: a missing header fails MISSING_PROOF")
    void proofMissing() {
        Map<String, Object> vector = TestVectors.load("per-request-proof");
        String sessionId = TestVectors.string(vector, "sessionId");
        seedSession(sessionId);
        storeBoundKey(sessionId, TestVectors.object(vector, "publicKeyJwk"));

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.verifyBoundProof(sessionId, null, "GET", "/api", null, false, null));
        assertEquals(DbscErrorCode.MISSING_PROOF, failure.code());
    }

    @Test
    @DisplayName("proof: no bound key fails KEY_NOT_FOUND_BOUND")
    void proofWithoutBoundKey() {
        Map<String, Object> vector = TestVectors.load("per-request-proof");
        Map<String, Object> withoutBody = TestVectors.object(vector, "withoutBody");
        String sessionId = TestVectors.string(vector, "sessionId");
        seedSession(sessionId);
        // Only a native key exists; a per-request proof needs the polyfill key.
        storeNativeKey(sessionId, TestVectors.object(vector, "publicKeyJwk"));

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.verifyBoundProof(
                        sessionId,
                        TestVectors.string(withoutBody, "header"),
                        TestVectors.string(withoutBody, "method"),
                        TestVectors.string(withoutBody, "path"),
                        null,
                        false,
                        null));
        assertEquals(DbscErrorCode.KEY_NOT_FOUND_BOUND, failure.code());
    }

    @Test
    @DisplayName("proof: a stale timestamp fails SIGNATURE_INVALID")
    void proofStaleTimestamp() {
        Map<String, Object> vector = TestVectors.load("per-request-proof");
        Map<String, Object> withoutBody = TestVectors.object(vector, "withoutBody");
        String sessionId = TestVectors.string(vector, "sessionId");
        seedSession(sessionId);
        storeBoundKey(sessionId, TestVectors.object(vector, "publicKeyJwk"));

        // Freshness is checked before the signature, so a far-future proof is
        // rejected for its timestamp alone.
        String futureHeader = TestVectors.string(withoutBody, "header")
                .replace("ts=1700000000000", "ts=1700099999999");

        DbscException failure = assertThrows(DbscException.class,
                () -> engine.verifyBoundProof(sessionId, futureHeader,
                        TestVectors.string(withoutBody, "method"),
                        TestVectors.string(withoutBody, "path"), null, false, null));
        assertEquals(DbscErrorCode.SIGNATURE_INVALID, failure.code());
    }

    @Test
    @DisplayName("proof: bh without body signing is MALFORMED_PROOF, and vice versa")
    void proofBodyHashRules() {
        Map<String, Object> vector = TestVectors.load("per-request-proof");
        Map<String, Object> withBody = TestVectors.object(vector, "withBody");
        String sessionId = TestVectors.string(vector, "sessionId");
        seedSession(sessionId);
        storeBoundKey(sessionId, TestVectors.object(vector, "publicKeyJwk"));

        // A header carrying bh when body signing is off is malformed.
        DbscException failure = assertThrows(DbscException.class,
                () -> engine.verifyBoundProof(
                        sessionId,
                        TestVectors.string(withBody, "header"),
                        TestVectors.string(withBody, "method"),
                        TestVectors.string(withBody, "path"),
                        null,
                        false,
                        null));
        assertEquals(DbscErrorCode.MALFORMED_PROOF, failure.code());

        // Body signing on, but the proof carries no bh: also malformed.
        Map<String, Object> withoutBody = TestVectors.object(vector, "withoutBody");
        DbscException missingBh = assertThrows(DbscException.class,
                () -> engine.verifyBoundProof(
                        sessionId,
                        TestVectors.string(withoutBody, "header"),
                        TestVectors.string(withoutBody, "method"),
                        TestVectors.string(withoutBody, "path"),
                        "{}".getBytes(StandardCharsets.UTF_8),
                        true,
                        null));
        assertEquals(DbscErrorCode.MALFORMED_PROOF, missingBh.code());
    }

    @Test
    @DisplayName("proof: the replay cache rejects a second identical proof")
    void proofReplayCache() {
        Map<String, Object> vector = TestVectors.load("per-request-proof");
        Map<String, Object> withoutBody = TestVectors.object(vector, "withoutBody");
        String sessionId = TestVectors.string(vector, "sessionId");
        seedSession(sessionId);
        storeBoundKey(sessionId, TestVectors.object(vector, "publicKeyJwk"));
        ProofReplayCache replayCache = new InMemoryProofReplayCache();

        String header = TestVectors.string(withoutBody, "header");
        String method = TestVectors.string(withoutBody, "method");
        String path = TestVectors.string(withoutBody, "path");

        // The first sighting is allowed.
        engine.verifyBoundProof(sessionId, header, method, path, null, false, replayCache);

        // The second is a replay.
        DbscException failure = assertThrows(DbscException.class,
                () -> engine.verifyBoundProof(sessionId, header, method, path, null, false, replayCache));
        assertEquals(DbscErrorCode.PROOF_REPLAY, failure.code());
    }

    @Test
    @DisplayName("proof: a garbage signature does not poison the replay cache")
    void proofDoesNotPoisonReplayCache() {
        Map<String, Object> vector = TestVectors.load("per-request-proof");
        Map<String, Object> withoutBody = TestVectors.object(vector, "withoutBody");
        String sessionId = TestVectors.string(vector, "sessionId");
        seedSession(sessionId);
        storeBoundKey(sessionId, TestVectors.object(vector, "publicKeyJwk"));
        ProofReplayCache replayCache = new InMemoryProofReplayCache();

        String goodHeader = TestVectors.string(withoutBody, "header");
        String method = TestVectors.string(withoutBody, "method");
        String path = TestVectors.string(withoutBody, "path");

        // An attacker submits a forged proof first. It must be rejected on the
        // signature, and must NOT be recorded.
        String forgedHeader = goodHeader.replace(
                goodHeader.substring(goodHeader.indexOf("sig=") + 4), "/lXQV4NoUzSYeorTjL_lb_ilozYv7DUgef9Dw9oQq8GOq904CIMnBM6aQHl1pV6ZwYX4XQB");
        assertThrows(DbscException.class,
                () -> engine.verifyBoundProof(sessionId, forgedHeader, method, path, null, false, replayCache));

        // The legitimate client's proof must still be accepted, and then replayed.
        engine.verifyBoundProof(sessionId, goodHeader, method, path, null, false, replayCache);
        DbscException replay = assertThrows(DbscException.class,
                () -> engine.verifyBoundProof(sessionId, goodHeader, method, path, null, false, replayCache));
        assertEquals(DbscErrorCode.PROOF_REPLAY, replay.code());
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
        storeBoundKey(SESSION_ID, TestVectors.object(
                TestVectors.load("refresh"), "storedPublicKeyJwk"));

        // A bound key alone does not make a session protected: the stored tier is
        // authoritative. The key decides the ceiling the session can reach, not
        // whether it is currently protected, because a demoted session keeps its
        // key on purpose (so a later failure is still recognisable as stolen).
        Session promoted = storage.getSession(SESSION_ID).orElseThrow()
                .withTier(ProtectionTier.BOUND);
        storage.setSession(promoted);
        assertEquals(ProtectionTier.BOUND, engine.effectiveTier(promoted));

        // With the key gone and the grace elapsed, the session reads none.
        storage.deleteBoundKey(SESSION_ID, BoundKeyKind.BOUND);
        Session stale = promoted.withTierAndLastRefreshAt(ProtectionTier.BOUND, VECTOR_NOW_MS - 3_600_000);
        storage.setSession(stale);
        assertEquals(ProtectionTier.NONE, engine.effectiveTier(stale));

        // Inside the grace window, the previous tier is still reported.
        Session inGrace = promoted.withTierAndLastRefreshAt(
                ProtectionTier.BOUND,
                VECTOR_NOW_MS - properties.boundCookieTtlMs() - properties.refreshGraceMs() + 1000);
        storage.setSession(inGrace);
        assertEquals(ProtectionTier.BOUND, engine.effectiveTier(inGrace));
    }

    @Test
    @DisplayName("tier: a demoted session reads none even though its key survives")
    void demotedSessionReadsNoneDespiteLiveKey() {
        seedSession();
        storeNativeKey(TestVectors.object(TestVectors.load("refresh"), "storedPublicKeyJwk"));
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
        assertTrue(storage.getBoundKey(SESSION_ID, BoundKeyKind.NATIVE).isPresent(),
                "the key MUST survive the demotion so session_stolen stays detectable");
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private void seedSession() {
        seedSession(SESSION_ID);
    }

    private void seedSession(String sessionId) {
        storage.setSession(new Session(sessionId, "user_1", ProtectionTier.NONE,
                VECTOR_NOW_MS, VECTOR_NOW_MS + 3_600_000, 0));
    }

    private void seedChallenge(String jti) {
        storage.setChallenge(new Challenge(jti, SESSION_ID,
                VECTOR_NOW_MS, VECTOR_NOW_MS + properties.challengeTtlMs(), false));
    }

    private void storeNativeKey(Map<String, Object> jwk) {
        storeNativeKey(SESSION_ID, jwk);
    }

    private void storeNativeKey(String sessionId, Map<String, Object> jwk) {
        storage.setBoundKey(new BoundKey(sessionId, BoundKeyKind.NATIVE, jwk, "ES256", VECTOR_NOW_MS));
    }

    private void storeBoundKey(Map<String, Object> jwk) {
        storeBoundKey(SESSION_ID, jwk);
    }

    private void storeBoundKey(String sessionId, Map<String, Object> jwk) {
        storage.setBoundKey(new BoundKey(sessionId, BoundKeyKind.BOUND, jwk, "ES256", VECTOR_NOW_MS));
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
