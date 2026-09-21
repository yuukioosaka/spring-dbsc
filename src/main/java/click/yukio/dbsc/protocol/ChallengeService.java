package click.yukio.dbsc.protocol;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;

import java.time.Clock;

/**
 * Challenge issuance and validation (spec 05/06).
 *
 * <p>A challenge JTI MUST be a cryptographically random 32-byte value, encoded
 * base64url without padding — 43 characters. It is single-use, carries an
 * expiry (default 5 minutes), and is consumed atomically.
 */
public class ChallengeService {

    private final StorageAdapter storage;
    private final DbscProperties properties;
    private final Clock clock;

    public ChallengeService(StorageAdapter storage, DbscProperties properties, Clock clock) {
        this.storage = storage;
        this.properties = properties;
        this.clock = clock;
    }

    /** Issues and persists a fresh challenge for the session. */
    public Challenge issue(String sessionId) {
        long now = clock.millis();
        Challenge challenge = new Challenge(
                Base64Url.randomJti(),
                sessionId,
                now,
                now + properties.challengeTtlMs(),
                false);
        storage.setChallenge(challenge);
        return challenge;
    }

    /**
     * Looks up a challenge and applies the shared validation rules: it MUST
     * exist, be unconsumed, be unexpired, and belong to the expected session.
     *
     * @throws DbscException {@code CHALLENGE_NOT_FOUND} / {@code CHALLENGE_CONSUMED}
     *         / {@code CHALLENGE_EXPIRED} / {@code JTI_MISMATCH}
     */
    public Challenge validate(String jti, String expectedSessionId) {
        if (jti == null || jti.isEmpty()) {
            throw DbscException.challengeNotFound();
        }
        Challenge challenge = storage.getChallenge(jti).orElseThrow(DbscException::challengeNotFound);
        if (challenge.consumed()) {
            throw DbscException.challengeConsumed();
        }
        if (challenge.isExpired(clock.millis())) {
            throw DbscException.challengeExpired();
        }
        if (expectedSessionId != null && !challenge.sessionId().equals(expectedSessionId)) {
            throw DbscException.jtiMismatch("challenge does not belong to this session");
        }
        return challenge;
    }

    /**
     * Atomically consumes the challenge.
     *
     * @throws DbscException {@code CHALLENGE_CONSUMED} when this call lost the
     *         race or the challenge does not exist
     */
    public void consume(String jti) {
        if (!storage.consumeChallenge(jti)) {
            throw DbscException.challengeConsumed();
        }
    }

    /**
     * Consumes a challenge, ignoring the outcome. Used on the failure paths,
     * where the challenge must be burned so a captured proof cannot be retried,
     * but where the reported error is the signature failure rather than the race
     * outcome.
     */
    public void consumeQuietly(String jti) {
        if (jti != null && !jti.isEmpty()) {
            storage.consumeChallenge(jti);
        }
    }
}
