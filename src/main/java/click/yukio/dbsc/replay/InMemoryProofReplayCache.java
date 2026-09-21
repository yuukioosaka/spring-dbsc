package click.yukio.dbsc.replay;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Single-process replay cache. Suitable for development and for a single
 * instance; use {@link click.yukio.dbsc.replay.JdbcProofReplayCache} when more than one
 * process can serve requests.
 */
public class InMemoryProofReplayCache implements ProofReplayCache {

    private final ConcurrentHashMap<String, Long> entries = new ConcurrentHashMap<>();

    @Override
    public boolean checkAndRecord(String key, long ttlMs) {
        long now = System.currentTimeMillis();
        // Sweep opportunistically so an idle cache does not grow without bound.
        entries.entrySet().removeIf(entry -> entry.getValue() < now);

        AtomicBoolean fresh = new AtomicBoolean(false);
        entries.compute(key, (k, expiresAt) -> {
            if (expiresAt != null && expiresAt >= now) {
                return expiresAt;
            }
            fresh.set(true);
            return now + ttlMs;
        });
        return fresh.get();
    }
}
