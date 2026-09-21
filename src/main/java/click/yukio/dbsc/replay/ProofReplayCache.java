package click.yukio.dbsc.replay;

/**
 * Replay cache for per-request proofs (spec 04).
 *
 * <p>Without it, an attacker who captured one valid proof can replay the exact
 * bytes until the timestamp window closes. With it, the second arrival of the
 * same {@code (sessionId, ts, sig-prefix)} tuple is rejected as
 * {@code PROOF_REPLAY}.
 *
 * <p>The record MUST be written only after the cryptographic checks pass.
 */
public interface ProofReplayCache {

    /**
     * Records {@code key} with the given TTL.
     *
     * @return {@code true} if this is the first sighting (the request is allowed),
     *         {@code false} if the key was already present (a replay)
     */
    boolean checkAndRecord(String key, long ttlMs);
}
