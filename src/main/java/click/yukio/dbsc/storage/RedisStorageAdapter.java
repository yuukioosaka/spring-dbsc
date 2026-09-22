package click.yukio.dbsc.storage;

import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.DeviceKey;
import click.yukio.dbsc.core.Json;
import click.yukio.dbsc.core.RegistrationToken;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Durable storage on Redis, or on any server speaking RESP — Valkey, KeyDB, Dragonfly
 * and AWS ElastiCache all qualify.
 *
 * <p>This exists for deployments that are already running a Redis-compatible server and
 * would rather not add a database: sessions, device keys, challenges and registration
 * tokens are all small values with an expiry, which is what such a server is good at.
 *
 * <p>The atomicity requirement is met with a Lua script, not with {@code GET} followed
 * by {@code SET}. Two concurrent refresh attempts for one challenge MUST result in
 * exactly one {@code true}, and a read-then-write would let an attacker race a captured
 * proof against the legitimate client and have both accepted. Lua runs to completion on
 * the server without interleaving, so the check and the write are one step.
 *
 * <p><strong>Keys are not namespaced by tenant.</strong> Two applications sharing one
 * server must be given separate ones (or separate databases), because a DBSC session id
 * is opaque to this adapter and collisions between two apps' keys would be silent.
 *
 * @see <a href="https://redis.io/docs/latest/develop/programmability/eval-intro/">Redis
 *      server-side scripting</a>
 */
public class RedisStorageAdapter implements StorageAdapter {

    /**
     * Marks a challenge or registration token as consumed, in one round trip.
     *
     * <p>A single script serves both cases because the two records differ only in their
     * key layout, and the reply must be exactly {@code 1}/{@code 0} in both.
     *
     * <p>{@code redis.call('EXISTS', key) == 0} covers the record that expired between
     * issuance and use: its TTL has already deleted it, and "consumed a record that no
     * longer exists" must report {@code false} rather than throw, or expiry would surface
     * as a 500 instead of the protocol's {@code CHALLENGE_EXPIRED}.
     *
     * <p>The consumed test is on the field's <strong>value</strong>, not its presence.
     * {@code setChallenge} always writes a {@code consumed} field, holding {@code "0"}
     * for a fresh record, so {@code HSETNX} would see the field as already set and refuse
     * every first consume -- a replay guard that refuses everything, which is the loudest
     * way to get this wrong but not the only one.
     *
     * <p>The consumed marker keeps the record's own TTL. Setting a fresh one would let a
     * client that replays a stale JTI extend the life of the record being refused.
     */
    private static final DefaultRedisScript<Long> CONSUME = new DefaultRedisScript<>("""
            if redis.call('EXISTS', KEYS[1]) == 0 then
                return 0
            end
            if redis.call('HGET', KEYS[1], 'consumed') == '1' then
                return 0
            end
            redis.call('HSET', KEYS[1], 'consumed', '1')
            return 1
            """, Long.class);

    private final StringRedisTemplate redis;

    public RedisStorageAdapter(StringRedisTemplate redis) {
        this.redis = redis;
    }

    // ---- Key layout ----
    //
    // One hash per record rather than one string per field: the fields of a session are
    // always read together, and a hash expiry is a single command. The TTL lives on the
    // record so a crashed server cannot leave unbounded garbage behind.

    private static String sessionKey(String id) {
        return "dbsc:session:" + id;
    }

    /** Reverse index behind {@link #getSessionByAppSessionId}: app session -> DBSC id. */
    private static String appSessionKey(String appSessionId) {
        return "dbsc:app-session:" + appSessionId;
    }

    private static String deviceKeyKey(String sessionId) {
        return "dbsc:device-key:" + sessionId;
    }

    private static String challengeKey(String jti) {
        return "dbsc:challenge:" + jti;
    }

    private static String registrationTokenKey(String token) {
        return "dbsc:registration-token:" + token;
    }

    /**
     * Credential-cookie value -> the session it names. A plain string key with a TTL,
     * which is exactly the lifetime semantics a ticket needs: Redis drops the pointer
     * when the grace lapses, so nothing has to sweep it.
     */
    private static String ticketKey(String ticket) {
        return "dbsc:credential-ticket:" + ticket;
    }

    // ---- Sessions ----

    @Override
    public Optional<Session> getSession(String id) {
        Map<Object, Object> fields = redis.opsForHash().entries(sessionKey(id));
        return fields.isEmpty() ? Optional.empty() : Optional.of(readSession(fields));
    }

    @Override
    public Optional<Session> getSessionByAppSessionId(String appSessionId) {
        // Two reads, and deliberately not an atomic pair: the index and the session are
        // only ever written in that order by setSession, so a dangling index entry reads
        // as "no binding", which is the safe answer. The guard treats it as unregistered
        // rather than as a lapsed session, and the browser recovers by registering again.
        String id = redis.opsForValue().get(appSessionKey(appSessionId));
        return id == null ? Optional.empty() : getSession(id);
    }

    @Override
    public void setSession(Session session) {
        Map<String, String> fields = sessionFields(session);
        String key = sessionKey(session.id());
        redis.opsForHash().putAll(key, fields);
        // The record's own expiry is the retention bound, and it has to be refreshed on
        // every write: bind() creates a session with a fresh TTL and a later refresh
        // extends it, so a write that left the old TTL in place would expire a session
        // that had just been renewed.
        redis.expire(key, Duration.ofMillis(retentionOf(session)));
        redis.opsForValue().set(appSessionKey(session.appSessionId()), session.id(),
                Duration.ofMillis(retentionOf(session)));
    }

    @Override
    public void deleteSession(String id) {
        // The reverse index is keyed by the *application* session id, which is not the
        // one being deleted, so it has to be read out before the record goes. Without
        // this the index would point at a deleted session and a later request would look
        // like "a binding exists" while getSession returned nothing.
        getSession(id).ifPresent(session -> redis.delete(appSessionKey(session.appSessionId())));
        redis.delete(List.of(sessionKey(id), deviceKeyKey(id)));
        // Challenges and registration tokens are keyed by their own value, not by the
        // session, so they cannot be addressed without scanning. They are given short
        // TTLs precisely so they clean themselves up; leaving them is bounded work.
        // Credential tickets are the same: the grace is short and the TTL removes them.
    }

    @Override
    public String resolveTicket(String ticket) {
        // No read-time expiry check is needed here, unlike the JDBC adapter: Redis
        // deletes the key on its own when the grace lapses, so a value that comes back
        // is by construction still live.
        return redis.opsForValue().get(ticketKey(ticket));
    }

    @Override
    public void setTicket(String ticket, String sessionId, long ttlMs) {
        // A one-second floor rather than a policy: EXPIRE with a non-positive TTL
        // deletes immediately, which would make a zero grace mean "no ticket at all"
        // instead of "a ticket that stops resolving at once after the refresh".
        redis.opsForValue().set(ticketKey(ticket), sessionId,
                Duration.ofMillis(Math.max(ttlMs, 1_000L)));
    }

    @Override
    public void deleteTicket(String ticket) {
        if (ticket != null) {
            redis.delete(ticketKey(ticket));
        }
    }

    private static long retentionOf(Session session) {
        // A session that has already lapsed but not yet been swept would otherwise get a
        // non-positive TTL, and EXPIRE with one deletes the key immediately -- which
        // would silently discard the revoked record the guard still needs to answer
        // "this session had a binding". One second is a floor, not a policy.
        return Math.max(session.retentionDeadlineMs() - System.currentTimeMillis(), 1_000L);
    }

    private static Map<String, String> sessionFields(Session session) {
        Map<String, String> fields = new LinkedHashMap<>();
        // The id is stored as a field as well as being the key. A key is not readable
        // from a hash's entries(), so without this readSession() has no way to recover it.
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

    private static Session readSession(Map<Object, Object> fields) {
        return new Session(
                field(fields, "id"),
                field(fields, "app_session_id"),
                field(fields, "user_id"),
                click.yukio.dbsc.core.ProtectionTier.fromWire(field(fields, "tier")),
                "1".equals(field(fields, "revoked")),
                longField(fields, "created_at"),
                longField(fields, "expires_at"),
                longField(fields, "last_refresh_at"));
    }

    // ---- Device keys ----

    @Override
    public Optional<DeviceKey> getDeviceKey(String sessionId) {
        Map<Object, Object> fields = redis.opsForHash().entries(deviceKeyKey(sessionId));
        if (fields.isEmpty()) {
            return Optional.empty();
        }
        String jwkJson = field(fields, "jwk_json");
        Map<String, Object> jwk = jwkJson == null ? null : Json.tryParseObject(jwkJson);
        return Optional.of(new DeviceKey(
                sessionId,
                StorageSupport.requireJwk(jwk, sessionId),
                field(fields, "algorithm"),
                longField(fields, "created_at")));
    }

    @Override
    public void setDeviceKey(DeviceKey key) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("jwk_json", Json.write(key.jwk()));
        fields.put("algorithm", key.algorithm());
        fields.put("created_at", Long.toString(key.createdAt()));
        // The key is read by refresh, which requires the session, so the session's own
        // TTL is the right outer bound. Fall back to a day when there is no session, so
        // an orphaned key cannot live forever.
        redis.opsForHash().putAll(deviceKeyKey(key.sessionId()), fields);
        redis.expire(deviceKeyKey(key.sessionId()), Duration.ofMillis(deviceKeyTtl(key.sessionId())));
    }

    private long deviceKeyTtl(String sessionId) {
        return getSession(sessionId)
                .map(RedisStorageAdapter::retentionOf)
                .orElse(86_400_000L);
    }

    @Override
    public void deleteDeviceKey(String sessionId) {
        redis.delete(deviceKeyKey(sessionId));
    }

    // ---- Challenges ----

    @Override
    public Optional<Challenge> getChallenge(String jti) {
        Map<Object, Object> fields = redis.opsForHash().entries(challengeKey(jti));
        return fields.isEmpty() ? Optional.empty() : Optional.of(readChallenge(jti, fields));
    }

    @Override
    public void setChallenge(Challenge challenge) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("session_id", challenge.sessionId());
        fields.put("created_at", Long.toString(challenge.createdAt()));
        fields.put("expires_at", Long.toString(challenge.expiresAt()));
        fields.put("consumed", challenge.consumed() ? "1" : "0");
        String key = challengeKey(challenge.jti());
        redis.opsForHash().putAll(key, fields);
        // The record must outlive its stated expiry, or a client presenting a JTI that
        // expired a moment ago would get CHALLENGE_NOT_FOUND instead of the protocol's
        // CHALLENGE_EXPIRED. The extra hour is the window in which the difference is
        // observable; after that the two are equivalent and the key is reclaimed.
        redis.expire(key, Duration.ofMillis(
                Math.max(challenge.expiresAt() - System.currentTimeMillis(), 0L) + 3_600_000L));
    }

    @Override
    public boolean consumeChallenge(String jti) {
        return consumed(redis.execute(CONSUME, Collections.singletonList(challengeKey(jti))));
    }

    private static Challenge readChallenge(String jti, Map<Object, Object> fields) {
        return new Challenge(
                jti,
                field(fields, "session_id"),
                longField(fields, "created_at"),
                longField(fields, "expires_at"),
                "1".equals(field(fields, "consumed")));
    }

    // ---- Registration tokens ----

    @Override
    public Optional<RegistrationToken> getRegistrationToken(String token) {
        Map<Object, Object> fields = redis.opsForHash().entries(registrationTokenKey(token));
        if (fields.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new RegistrationToken(
                token,
                field(fields, "session_id"),
                longField(fields, "created_at"),
                longField(fields, "expires_at"),
                "1".equals(field(fields, "consumed"))));
    }

    @Override
    public void setRegistrationToken(RegistrationToken token) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("session_id", token.sessionId());
        fields.put("created_at", Long.toString(token.createdAt()));
        fields.put("expires_at", Long.toString(token.expiresAt()));
        fields.put("consumed", token.consumed() ? "1" : "0");
        String key = registrationTokenKey(token.token());
        redis.opsForHash().putAll(key, fields);
        // Same reasoning as a challenge: the token's own expiry is the protocol answer,
        // and the record outlives it so the difference between "expired" and "never
        // existed" stays observable.
        redis.expire(key, Duration.ofMillis(
                Math.max(token.expiresAt() - System.currentTimeMillis(), 0L) + 3_600_000L));
    }

    @Override
    public boolean consumeRegistrationToken(String token) {
        return consumed(redis.execute(CONSUME, Collections.singletonList(registrationTokenKey(token))));
    }

    // ---- Revocation ----

    @Override
    public void revokeSession(String sessionId) {
        // Marked, not deleted, and the TTL is left alone: a later request carrying the
        // same application session id without its DBSC cookies must still be recognised
        // as having had a binding. The record expires on its own schedule.
        redis.opsForHash().put(sessionKey(sessionId), "revoked", "1");
    }

    // ---- Helpers ----

    /** A Lua script answers with an integer; null means the server replied with nothing. */
    private static boolean consumed(Long reply) {
        return reply != null && reply == 1L;
    }

    private static String field(Map<Object, Object> fields, String name) {
        Object value = fields.get(name);
        return value == null ? null : value.toString();
    }

    private static long longField(Map<Object, Object> fields, String name) {
        String value = field(fields, name);
        if (value == null) {
            throw new IllegalStateException("stored DBSC record is missing field '" + name + "'");
        }
        return Long.parseLong(value);
    }

    /** Thrown when the backing store fails. */
    public static class StorageException extends RuntimeException {
        public StorageException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
