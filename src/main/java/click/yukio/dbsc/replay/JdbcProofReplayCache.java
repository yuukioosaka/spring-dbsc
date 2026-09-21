package click.yukio.dbsc.replay;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Multi-process replay cache backed by the same database as the session store.
 *
 * <p>Atomicity comes from a single {@code INSERT} against a primary key: the
 * first writer wins, and a duplicate-key violation means the proof was already
 * seen. Expired rows are swept opportunistically on each check.
 */
public class JdbcProofReplayCache implements ProofReplayCache {

    private final DataSource dataSource;
    private volatile long lastSweepAt;

    public JdbcProofReplayCache(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public void initialize() {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS dbsc_proof_replay (
                        replay_key VARCHAR(512) PRIMARY KEY,
                        expires_at BIGINT       NOT NULL
                    )
                    """);
        } catch (SQLException e) {
            throw new IllegalStateException("failed to initialize the DBSC replay cache schema", e);
        }
    }

    @Override
    public boolean checkAndRecord(String key, long ttlMs) {
        long now = System.currentTimeMillis();
        sweepIfDue(now);
        String sql = "INSERT INTO dbsc_proof_replay (replay_key, expires_at) VALUES (?, ?)";
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, key);
            statement.setLong(2, now + ttlMs);
            statement.executeUpdate();
            return true;
        } catch (SQLException e) {
            // A unique-constraint violation is the replay signal, not a failure.
            return false;
        }
    }

    private void sweepIfDue(long now) {
        if (now - lastSweepAt < 60_000) {
            return;
        }
        lastSweepAt = now;
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement("DELETE FROM dbsc_proof_replay WHERE expires_at < ?")) {
            statement.setLong(1, now);
            statement.executeUpdate();
        } catch (SQLException ignored) {
            // Sweeping is best-effort; a missed sweep only means stale rows linger.
        }
    }
}
