package click.yukio.dbsc.storage;

import click.yukio.dbsc.core.DeviceKey;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.Json;
import click.yukio.dbsc.core.RegistrationToken;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Durable JDBC-backed storage (spec 06).
 *
 * <p>Persistence MUST be durable for any deployment that can restart: a store
 * that loses device keys breaks live sessions, because the browser still holds a
 * binding cookie, refresh fails with {@code KEY_NOT_FOUND}, and the
 * browser loops registration.
 *
 * <p>The atomicity requirement is met by
 * {@code UPDATE challenges SET consumed = true WHERE jti = ? AND consumed = false}
 * and checking the affected-row count — never a read followed by a separate
 * write, which would let an attacker race a captured proof against the
 * legitimate client and have both accepted.
 */
public class JdbcStorageAdapter implements StorageAdapter {

    private final DataSource dataSource;

    public JdbcStorageAdapter(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /** Creates the schema when absent. Safe to call on every start. */
    public void initialize() {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS dbsc_sessions (
                        id              VARCHAR(255) PRIMARY KEY,
                        app_session_id  VARCHAR(255) NOT NULL,
                        user_id         VARCHAR(255) NOT NULL,
                        tier            VARCHAR(16)  NOT NULL,
                        revoked         BOOLEAN      NOT NULL,
                        created_at      BIGINT       NOT NULL,
                        expires_at      BIGINT       NOT NULL,
                        last_refresh_at BIGINT       NOT NULL
                    )
                    """);
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS dbsc_sessions_user_idx ON dbsc_sessions (user_id)");
            // At most one binding per application session, and this is the lookup a
            // guarded route makes when a request arrives with no DBSC cookie.
            statement.executeUpdate("CREATE UNIQUE INDEX IF NOT EXISTS dbsc_sessions_app_session_idx ON dbsc_sessions (app_session_id)");
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS dbsc_device_keys (
                        session_id VARCHAR(255) PRIMARY KEY,
                        jwk_json   TEXT         NOT NULL,
                        algorithm  VARCHAR(16)  NOT NULL,
                        created_at BIGINT       NOT NULL
                    )
                    """);
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS dbsc_challenges (
                        jti        VARCHAR(255) PRIMARY KEY,
                        session_id VARCHAR(255) NOT NULL,
                        created_at BIGINT       NOT NULL,
                        expires_at BIGINT       NOT NULL,
                        consumed   BOOLEAN      NOT NULL
                    )
                    """);
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS dbsc_challenges_session_idx ON dbsc_challenges (session_id)");
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS dbsc_registration_tokens (
                        token      VARCHAR(255) PRIMARY KEY,
                        session_id VARCHAR(255) NOT NULL,
                        created_at BIGINT       NOT NULL,
                        expires_at BIGINT       NOT NULL,
                        consumed   BOOLEAN      NOT NULL
                    )
                    """);
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS dbsc_registration_tokens_session_idx ON dbsc_registration_tokens (session_id)");
        } catch (SQLException e) {
            throw new StorageException("failed to initialize the DBSC schema", e);
        }
    }

    // ---- Sessions ----

    @Override
    public Optional<Session> getSession(String id) {
        String sql = "SELECT id, app_session_id, user_id, tier, revoked, created_at, expires_at, last_refresh_at "
                + "FROM dbsc_sessions WHERE id = ?";
        return StorageSupport.optional(queryOne(sql, statement -> statement.setString(1, id), this::readSession));
    }

    @Override
    public Optional<Session> getSessionByAppSessionId(String appSessionId) {
        String sql = "SELECT id, app_session_id, user_id, tier, revoked, created_at, expires_at, last_refresh_at "
                + "FROM dbsc_sessions WHERE app_session_id = ?";
        return StorageSupport.optional(queryOne(
                sql, statement -> statement.setString(1, appSessionId), this::readSession));
    }

    @Override
    public void setSession(Session session) {
        String sql = """
                MERGE INTO dbsc_sessions
                    (id, app_session_id, user_id, tier, revoked, created_at, expires_at, last_refresh_at)
                KEY (id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """;
        update(sql, statement -> {
            statement.setString(1, session.id());
            statement.setString(2, session.appSessionId());
            statement.setString(3, session.userId());
            statement.setString(4, session.tier().wireValue());
            statement.setBoolean(5, session.revoked());
            statement.setLong(6, session.createdAt());
            statement.setLong(7, session.expiresAt());
            statement.setLong(8, session.lastRefreshAt());
        });
    }

    @Override
    public void deleteSession(String id) {
        update("DELETE FROM dbsc_challenges WHERE session_id = ?", s -> s.setString(1, id));
        update("DELETE FROM dbsc_registration_tokens WHERE session_id = ?", s -> s.setString(1, id));
        update("DELETE FROM dbsc_device_keys WHERE session_id = ?", s -> s.setString(1, id));
        update("DELETE FROM dbsc_sessions WHERE id = ?", s -> s.setString(1, id));
    }

    // ---- Bound keys ----

    @Override
    public Optional<DeviceKey> getDeviceKey(String sessionId) {
        String sql = "SELECT session_id, jwk_json, algorithm, created_at "
                + "FROM dbsc_device_keys WHERE session_id = ?";
        return StorageSupport.optional(queryOne(
                sql,
                statement -> statement.setString(1, sessionId),
                this::readDeviceKey));
    }

    @Override
    public void setDeviceKey(DeviceKey key) {
        String sql = """
                MERGE INTO dbsc_device_keys
                    (session_id, jwk_json, algorithm, created_at)
                KEY (session_id)
                VALUES (?, ?, ?, ?)
                """;
        update(sql, statement -> {
            statement.setString(1, key.sessionId());
            statement.setString(2, Json.write(key.jwk()));
            statement.setString(3, key.algorithm());
            statement.setLong(4, key.createdAt());
        });
    }

    @Override
    public void deleteDeviceKey(String sessionId) {
        update("DELETE FROM dbsc_device_keys WHERE session_id = ?", statement ->
                statement.setString(1, sessionId));
    }

    // ---- Challenges ----

    @Override
    public Optional<Challenge> getChallenge(String jti) {
        String sql = "SELECT jti, session_id, created_at, expires_at, consumed "
                + "FROM dbsc_challenges WHERE jti = ?";
        return StorageSupport.optional(queryOne(sql, statement -> statement.setString(1, jti), this::readChallenge));
    }

    @Override
    public void setChallenge(Challenge challenge) {
        String sql = """
                MERGE INTO dbsc_challenges (jti, session_id, created_at, expires_at, consumed)
                KEY (jti)
                VALUES (?, ?, ?, ?, ?)
                """;
        update(sql, statement -> {
            statement.setString(1, challenge.jti());
            statement.setString(2, challenge.sessionId());
            statement.setLong(3, challenge.createdAt());
            statement.setLong(4, challenge.expiresAt());
            statement.setBoolean(5, challenge.consumed());
        });
    }

    /**
     * {@inheritDoc}
     *
     * <p>The conditional update writes only when the row is still unconsumed and
     * reports the affected-row count: exactly one concurrent caller observes
     * {@code true}.
     */
    @Override
    public boolean consumeChallenge(String jti) {
        String sql = "UPDATE dbsc_challenges SET consumed = true WHERE jti = ? AND consumed = false";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, jti);
            return statement.executeUpdate() == 1;
        } catch (SQLException e) {
            throw new StorageException("consumeChallenge failed for jti", e);
        }
    }

    // ---- Registration tokens ----

    @Override
    public Optional<RegistrationToken> getRegistrationToken(String token) {
        String sql = "SELECT token, session_id, created_at, expires_at, consumed "
                + "FROM dbsc_registration_tokens WHERE token = ?";
        return StorageSupport.optional(queryOne(
                sql, statement -> statement.setString(1, token), this::readRegistrationToken));
    }

    @Override
    public void setRegistrationToken(RegistrationToken token) {
        String sql = """
                MERGE INTO dbsc_registration_tokens (token, session_id, created_at, expires_at, consumed)
                KEY (token)
                VALUES (?, ?, ?, ?, ?)
                """;
        update(sql, statement -> {
            statement.setString(1, token.token());
            statement.setString(2, token.sessionId());
            statement.setLong(3, token.createdAt());
            statement.setLong(4, token.expiresAt());
            statement.setBoolean(5, token.consumed());
        });
    }

    /**
     * {@inheritDoc}
     *
     * <p>The conditional update writes only when the row is still unconsumed and
     * reports the affected-row count: exactly one concurrent caller observes
     * {@code true}.
     */
    @Override
    public boolean consumeRegistrationToken(String token) {
        String sql = "UPDATE dbsc_registration_tokens SET consumed = true WHERE token = ? AND consumed = false";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, token);
            return statement.executeUpdate() == 1;
        } catch (SQLException e) {
            throw new StorageException("consumeRegistrationToken failed for token", e);
        }
    }

    // ---- Revocation ----

    @Override
    public void revokeSession(String sessionId) {
        // Marked, not deleted: a later request carrying the same application session
        // id without its DBSC cookies must still be recognisable as bound.
        update("UPDATE dbsc_sessions SET revoked = true WHERE id = ?",
                statement -> statement.setString(1, sessionId));
    }

    // ---- Row mapping ----

    private Session readSession(ResultSet rs) throws SQLException {
        return new Session(
                rs.getString("id"),
                rs.getString("app_session_id"),
                rs.getString("user_id"),
                click.yukio.dbsc.core.ProtectionTier.fromWire(rs.getString("tier")),
                rs.getBoolean("revoked"),
                rs.getLong("created_at"),
                rs.getLong("expires_at"),
                rs.getLong("last_refresh_at"));
    }

    private DeviceKey readDeviceKey(ResultSet rs) throws SQLException {
        String sessionId = rs.getString("session_id");
        String jwkJson = rs.getString("jwk_json");
        Map<String, Object> jwk = jwkJson == null ? null : Json.tryParseObject(jwkJson);
        return new DeviceKey(
                sessionId,
                StorageSupport.requireJwk(jwk, sessionId),
                rs.getString("algorithm"),
                rs.getLong("created_at"));
    }

    private Challenge readChallenge(ResultSet rs) throws SQLException {
        return new Challenge(
                rs.getString("jti"),
                rs.getString("session_id"),
                rs.getLong("created_at"),
                rs.getLong("expires_at"),
                rs.getBoolean("consumed"));
    }

    private RegistrationToken readRegistrationToken(ResultSet rs) throws SQLException {
        return new RegistrationToken(
                rs.getString("token"),
                rs.getString("session_id"),
                rs.getLong("created_at"),
                rs.getLong("expires_at"),
                rs.getBoolean("consumed"));
    }

    // ---- JDBC plumbing ----

    @FunctionalInterface
    private interface Binder {
        void bind(PreparedStatement statement) throws SQLException;
    }

    @FunctionalInterface
    private interface RowMapper<T> {
        T map(ResultSet resultSet) throws SQLException;
    }

    private <T> T queryOne(String sql, Binder binder, RowMapper<T> mapper) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            binder.bind(statement);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next() ? mapper.map(resultSet) : null;
            }
        } catch (SQLException e) {
            throw new StorageException("query failed: " + sql, e);
        }
    }

    private <T> java.util.List<T> queryList(String sql, Binder binder, RowMapper<T> mapper) {
        java.util.List<T> results = new java.util.ArrayList<>();
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            binder.bind(statement);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    results.add(mapper.map(resultSet));
                }
            }
            return results;
        } catch (SQLException e) {
            throw new StorageException("query failed: " + sql, e);
        }
    }

    private void update(String sql, Binder binder) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            binder.bind(statement);
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("update failed: " + sql, e);
        }
    }

    /** Thrown when the backing store fails. */
    public static class StorageException extends RuntimeException {
        public StorageException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
