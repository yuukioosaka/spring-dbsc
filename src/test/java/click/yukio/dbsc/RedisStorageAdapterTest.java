package click.yukio.dbsc;

import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.DeviceKey;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.RegistrationToken;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.storage.RedisStorageAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;

import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The Redis adapter's key layout, field encoding, and command sequence.
 *
 * <p>Deliberately a mock. It <strong>cannot</strong> show that
 * {@link RedisStorageAdapter} is correct under concurrency — the atomicity of
 * {@code consumeChallenge} rests on a Lua script running uninterrupted inside the Redis
 * server, and a stub would pass just as happily against the read-then-write
 * implementation the script exists to avoid. What is asserted here is the surrounding
 * work: which keys are written, with which fields, and with which TTL, plus that the
 * consumption path delegates to the script at all and reads a {@code 1}/{@code 0}
 * reply as a boolean.
 *
 * <p>Everything the mock cannot reach is covered elsewhere: the consume-once
 * semantics are asserted against real Redis by nothing — that guarantee is the Lua
 * script's, and it is argued in that script's own Javadoc rather than tested here.
 */
class RedisStorageAdapterTest {

    private StringRedisTemplate redis;
    private HashOperations<String, Object, Object> hashOps;
    private ValueOperations<String, String> valueOps;
    private RedisStorageAdapter storage;

    @SuppressWarnings("unchecked")
    @BeforeEach
    void setUp() {
        redis = mock(StringRedisTemplate.class);
        hashOps = mock(HashOperations.class);
        valueOps = mock(ValueOperations.class);
        when(redis.opsForHash()).thenReturn(hashOps);
        when(redis.opsForValue()).thenReturn(valueOps);
        storage = new RedisStorageAdapter(redis);
    }

    /** The map a caller handed to {@code putAll}, captured for inspection. */
    @SuppressWarnings("unchecked")
    private Map<Object, Object> capturedFields(String key) {
        var captor = org.mockito.ArgumentCaptor.forClass(Map.class);
        verify(hashOps).putAll(eq(key), captor.capture());
        return captor.getValue();
    }

    private Map<Object, Object> sessionRecord(Session session) {
        Map<Object, Object> fields = new LinkedHashMap<>();
        fields.put("id", session.id());
        fields.put("app_session_id", session.appSessionId());
        fields.put("user_id", session.userId());
        fields.put("tier", session.tier().wireValue());
        fields.put("revoked", session.revoked() ? "1" : "0");
        fields.put("created_at", Long.toString(session.createdAt()));
        fields.put("expires_at", Long.toString(session.expiresAt()));
        fields.put("last_refresh_at", Long.toString(session.lastRefreshAt()));
        return fields;
    }

    @Test
    @DisplayName("redis: a session is written under dbsc:session:<id> with its retention TTL")
    void setSessionWritesHashAndTtl() {
        long now = 1_700_000_000_000L;
        Session session = new Session("sess_1", "app_1", "user_1",
                ProtectionTier.DBSC, false, now, now + 300_000, now);

        storage.setSession(session);

        Map<Object, Object> fields = capturedFields("dbsc:session:sess_1");
        assertEquals("sess_1", fields.get("id"));
        assertEquals("app_1", fields.get("app_session_id"));
        assertEquals("user_1", fields.get("user_id"));
        assertEquals("dbsc", fields.get("tier"));
        assertEquals("0", fields.get("revoked"));

        // The reverse index is a plain string key with its own TTL. It is what
        // getSessionByAppSessionId reads, and the guard relies on it to distinguish
        // "never registered" from "registered and dropped its cookies".
        verify(valueOps).set(eq("dbsc:app-session:app_1"), eq("sess_1"), any(Duration.class));
        // The record's own expiry has to be refreshed on every write, or a renewing
        // session would expire on its original deadline.
        verify(redis).expire(eq("dbsc:session:sess_1"), any(Duration.class));
    }

    @Test
    @DisplayName("redis: the TTL is never non-positive, so a lapsed record survives")
    void retentionNeverDeletesImmediately() {
        long now = 1_700_000_000_000L;
        // A session whose deadline has already passed: EXPIRE with a non-positive TTL
        // deletes the key, which would discard the revoked record the guard still needs.
        Session lapsed = new Session("sess_lapsed", "app_lapsed", "user_1",
                ProtectionTier.NONE, true, now, now - 60_000, 0);

        storage.setSession(lapsed);

        var captor = org.mockito.ArgumentCaptor.forClass(Duration.class);
        verify(redis).expire(eq("dbsc:session:sess_lapsed"), captor.capture());
        assertTrue(captor.getValue().toMillis() >= 1_000,
                "a floor of one second, not a policy: " + captor.getValue());
    }

    @Test
    @DisplayName("redis: a missing session reads as empty rather than throwing")
    void missingSessionIsEmpty() {
        when(hashOps.entries("dbsc:session:sess_absent")).thenReturn(Map.of());

        assertTrue(storage.getSession("sess_absent").isEmpty());
        assertTrue(storage.getSessionByAppSessionId("app_absent").isEmpty());
        assertTrue(storage.getChallenge("jti_absent").isEmpty());
        assertTrue(storage.getRegistrationToken("tok_absent").isEmpty());
        assertTrue(storage.getDeviceKey("sess_absent").isEmpty());
    }

    @Test
    @DisplayName("redis: a session round-trips through its own field encoding")
    void sessionRoundTrip() {
        long now = 1_700_000_000_000L;
        Session session = new Session("sess_1", "app_1", "user_1",
                ProtectionTier.DBSC, false, now, now + 300_000, now);
        when(hashOps.entries("dbsc:session:sess_1")).thenReturn(sessionRecord(session));
        when(valueOps.get("dbsc:app-session:app_1")).thenReturn("sess_1");

        Session loaded = storage.getSession("sess_1").orElseThrow();
        assertEquals(ProtectionTier.DBSC, loaded.tier());
        assertEquals("user_1", loaded.userId());
        assertEquals("app_1", loaded.appSessionId());
        assertEquals(now, loaded.lastRefreshAt());
        assertEquals("sess_1", storage.getSessionByAppSessionId("app_1").orElseThrow().id());
    }

    @Test
    @DisplayName("redis: an unknown tier reads as none, never as protected")
    void unknownTierIsNone() {
        long now = 1_700_000_000_000L;
        Map<Object, Object> fields = sessionRecord(new Session("sess_1", "app_1", "user_1",
                ProtectionTier.DBSC, false, now, now + 300_000, now));
        // A value written by a newer build must not be trusted as a protected tier.
        fields.put("tier", "bound");
        when(hashOps.entries("dbsc:session:sess_1")).thenReturn(fields);

        assertEquals(ProtectionTier.NONE, storage.getSession("sess_1").orElseThrow().tier());
    }

    @Test
    @DisplayName("redis: deleteSession removes the record, the key and the reverse index")
    void deleteSessionClearsRelatedRecords() {
        long now = 1_700_000_000_000L;
        Session session = new Session("sess_1", "app_1", "user_1",
                ProtectionTier.DBSC, false, now, now + 300_000, now);
        when(hashOps.entries("dbsc:session:sess_1")).thenReturn(sessionRecord(session));

        storage.deleteSession("sess_1");

        // The reverse index is keyed by the application session id, so it cannot be
        // addressed without first reading the record that is about to go.
        verify(redis).delete("dbsc:app-session:app_1");
        verify(redis).delete(List.of("dbsc:session:sess_1", "dbsc:device-key:sess_1"));
    }

    @Test
    @DisplayName("redis: revokeSession marks the record instead of deleting it")
    void revokeKeepsTheRecord() {
        storage.revokeSession("sess_1");

        // Deleting would erase the fact that a binding ever existed, which is exactly
        // what the guard must still be able to answer.
        verify(hashOps).put("dbsc:session:sess_1", "revoked", "1");
        verify(redis, times(0)).delete("dbsc:session:sess_1");
    }

    @Test
    @DisplayName("redis: a device key round-trips with its JWK intact")
    void deviceKeyRoundTrip() {
        long now = 1_700_000_000_000L;
        storage.setDeviceKey(new DeviceKey("sess_1",
                Map.of("kty", "EC", "crv", "P-256", "x", "abc"), "ES256", now));

        Map<Object, Object> fields = capturedFields("dbsc:device-key:sess_1");
        assertEquals("ES256", fields.get("algorithm"));
        assertTrue(String.valueOf(fields.get("jwk_json")).contains("\"kty\":\"EC\""),
                String.valueOf(fields.get("jwk_json")));

        Map<Object, Object> stored = Map.of(
                "jwk_json", fields.get("jwk_json"),
                "algorithm", "ES256",
                "created_at", Long.toString(now));
        when(hashOps.entries("dbsc:device-key:sess_1")).thenReturn(stored);

        DeviceKey loaded = storage.getDeviceKey("sess_1").orElseThrow();
        assertEquals("ES256", loaded.algorithm());
        assertEquals("P-256", loaded.jwk().get("crv"));
    }

    @Test
    @DisplayName("redis: an orphaned key gets a bounded TTL, a keyed one follows its session")
    void deviceKeyTtl() {
        long now = System.currentTimeMillis();
        // No session: the fallback is a day, so an orphan cannot live forever.
        storage.setDeviceKey(new DeviceKey("sess_orphan", Map.of("kty", "EC"), "ES256", now));
        var orphanCaptor = org.mockito.ArgumentCaptor.forClass(Duration.class);
        verify(redis).expire(eq("dbsc:device-key:sess_orphan"), orphanCaptor.capture());
        assertEquals(86_400_000L, orphanCaptor.getValue().toMillis());

        // The keyed case has to look like a *live* session, or retentionOf() clamps the TTL
        // to its one-second floor -- which is correct behaviour and would make this
        // assertion pass for the wrong reason. So the session's deadline is relative to now.
        Session session = new Session("sess_1", "app_1", "user_1",
                ProtectionTier.DBSC, false, now, now + 300_000, now);
        when(hashOps.entries("dbsc:session:sess_1")).thenReturn(sessionRecord(session));
        storage.setDeviceKey(new DeviceKey("sess_1", Map.of("kty", "EC"), "ES256", now));
        var keyedCaptor = org.mockito.ArgumentCaptor.forClass(Duration.class);
        verify(redis).expire(eq("dbsc:device-key:sess_1"), keyedCaptor.capture());
        // Measured against the clock, not pinned: the session has ~300s left and the TTL is
        // that remainder. Anything in (1s, 300s] proves the session's deadline was used
        // rather than the orphan fallback or the floor.
        assertTrue(keyedCaptor.getValue().toMillis() > 1_000L, "not the floor");
        assertTrue(keyedCaptor.getValue().toMillis() <= 300_000L, "not more than the session");
    }

    @Test
    @DisplayName("redis: a challenge outlives its stated expiry, so expiry stays observable")
    void challengeOutlivesItsExpiry() {
        long now = System.currentTimeMillis();
        storage.setChallenge(new Challenge("jti_1", "sess_1", now, now + 300_000, false));

        Map<Object, Object> fields = capturedFields("dbsc:challenge:jti_1");
        // A fresh record is written as consumed=0, not left absent: the Lua script tests
        // the field's VALUE, so an absent field would make HSETNX-style logic refuse
        // every first consume.
        assertEquals("0", fields.get("consumed"));
        assertEquals("sess_1", fields.get("session_id"));

        // The extra hour is the window in which "expired" and "never existed" are
        // distinguishable, which is the CHALLENGE_EXPIRED vs CHALLENGE_NOT_FOUND split.
        var captor = org.mockito.ArgumentCaptor.forClass(Duration.class);
        verify(redis).expire(eq("dbsc:challenge:jti_1"), captor.capture());
        assertTrue(captor.getValue().toMillis() > 300_000L,
                "the record must outlive its expiry: " + captor.getValue());
    }

    @Test
    @DisplayName("redis: a challenge round-trips, consumed flag included")
    void challengeRoundTrip() {
        long now = 1_700_000_000_000L;
        when(hashOps.entries("dbsc:challenge:jti_1")).thenReturn(Map.of(
                "session_id", "sess_1",
                "created_at", Long.toString(now),
                "expires_at", Long.toString(now + 300_000),
                "consumed", "1"));

        Challenge loaded = storage.getChallenge("jti_1").orElseThrow();
        assertEquals("sess_1", loaded.sessionId());
        assertTrue(loaded.consumed());
    }

    @Test
    @DisplayName("redis: consuming reads the script's 1/0 reply as a boolean")
    void consumeDelegatesToTheScript() {
        // The mock returns the script's reply; it cannot show that the script is atomic.
        // What it does pin is the direction of the mapping and the key that is passed,
        // which is where a copy-paste error between the two update* methods lands.
        // Three calls, one reply each: >0 is consumed, 0 is already consumed, and null is
        // a reply with nothing usable in it. Only the first may be read as true.
        when(redis.execute(any(RedisScript.class), anyList())).thenReturn(1L, 0L, null);

        assertTrue(storage.consumeChallenge("jti_1"));
        assertFalse(storage.consumeChallenge("jti_1"));
        // A null reply means the script returned nothing usable; refusing is the only
        // safe reading, since the alternative is accepting an unproven proof.
        assertFalse(storage.consumeChallenge("jti_1"));

        // All three went to the challenge key: the arguments of the *last* call are what
        // Mockito records, and that is where a copy-paste error between the two
        // consume* methods would land.
        verify(redis, times(3)).execute(any(RedisScript.class),
                eq(Collections.singletonList("dbsc:challenge:jti_1")));
    }

    @Test
    @DisplayName("redis: registration tokens consume under their own key")
    void registrationTokenKey() {
        long now = System.currentTimeMillis();
        storage.setRegistrationToken(new RegistrationToken(
                "tok_1", "sess_1", now, now + 300_000, false));

        Map<Object, Object> fields = capturedFields("dbsc:registration-token:tok_1");
        assertEquals("sess_1", fields.get("session_id"));
        assertEquals("0", fields.get("consumed"));

        when(redis.execute(any(RedisScript.class), anyList())).thenReturn(1L);
        assertTrue(storage.consumeRegistrationToken("tok_1"));
        verify(redis).execute(any(RedisScript.class),
                eq(Collections.singletonList("dbsc:registration-token:tok_1")));
    }

    @Test
    @DisplayName("redis: a ticket is a string key whose TTL is the grace, with a floor")
    void ticketResolvesAndExpires() {
        storage.setTicket("tkt_a", "sess_1", 60_000);
        verify(valueOps).set("dbsc:credential-ticket:tkt_a", "sess_1", Duration.ofMillis(60_000));

        storage.setTicket("tkt_zero", "sess_1", 0);
        // EXPIRE with a non-positive TTL deletes the key. That would make a zero grace
        // mean "no ticket at all" rather than "stops resolving at once".
        verify(valueOps).set("dbsc:credential-ticket:tkt_zero", "sess_1", Duration.ofMillis(1_000));

        // No read-time expiry check: Redis deletes the key when the grace lapses, so a
        // value that comes back is live by construction.
        when(valueOps.get("dbsc:credential-ticket:tkt_a")).thenReturn("sess_1");
        assertEquals("sess_1", storage.resolveTicket("tkt_a"));
        assertNull(storage.resolveTicket("tkt_never_issued"));
    }

    @Test
    @DisplayName("redis: deleting a null ticket is a no-op, not a delete of the literal \"null\"")
    void deleteNullTicket() {
        storage.deleteTicket(null);

        verify(redis, times(0)).delete(any(String.class));
    }
}
