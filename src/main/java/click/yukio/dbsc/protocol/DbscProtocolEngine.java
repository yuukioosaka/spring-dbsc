package click.yukio.dbsc.protocol;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.BoundKey;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.DbscErrorCode;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.crypto.DbscJws;
import click.yukio.dbsc.crypto.Jwk;
import click.yukio.dbsc.telemetry.DbscTelemetryEvent;
import click.yukio.dbsc.telemetry.TelemetryPublisher;

import java.time.Clock;
import java.util.Map;

/**
 * The protocol algorithms for native registration and native refresh.
 *
 * <p>Every method here follows the ordered, normative server steps of the
 * toolkit spec. The ordering matters: several steps exist specifically so an
 * attacker cannot distinguish failure modes or win a race.
 */
public class DbscProtocolEngine {

    private final StorageAdapter storage;
    private final DbscProperties properties;
    private final ChallengeService challenges;
    private final Clock clock;
    private final TelemetryPublisher telemetry;

    public DbscProtocolEngine(
            StorageAdapter storage,
            DbscProperties properties,
            ChallengeService challenges,
            Clock clock,
            TelemetryPublisher telemetry) {
        this.storage = storage;
        this.properties = properties;
        this.challenges = challenges;
        this.clock = clock;
        this.telemetry = telemetry;
    }

    // ------------------------------------------------------------------
    // Native registration (spec 02)
    // ------------------------------------------------------------------

    /**
     * Handles the browser's registration POST.
     *
     * <p>Ordered steps: require the response header, self-verify the JWS,
     * validate the challenge, reject a second registration, atomically consume the
     * challenge, store the key, then move the session to {@code tier: dbsc}.
     */
    public BoundKey handleRegistration(String sessionId, String responseHeader, String expectedJti) {
        if (responseHeader == null || responseHeader.isBlank()) {
            throw DbscException.missingResponseHeader("Secure-Session-Response header is required");
        }
        DbscJws.Parsed parsed = DbscJws.verifyRegistration(responseHeader.trim());

        challenges.validate(expectedJti, sessionId);

        if (storage.getBoundKey(sessionId).isPresent()) {
            throw new DbscException(DbscErrorCode.SESSION_ALREADY_REGISTERED,
                    "session already has a native bound key; cannot register again");
        }

        challenges.consume(expectedJti);

        long now = clock.millis();
        BoundKey key = new BoundKey(sessionId, parsed.jwk(),
                parsed.algorithm().wireValue(), now);
        storage.setBoundKey(key);

        storage.getSession(sessionId).ifPresent(session ->
                setSessionTier(session, ProtectionTier.DBSC, now, "native-registration"));

        telemetry.publish(new DbscTelemetryEvent.Registration(
                sessionId, currentTier(sessionId), now, key.algorithm(), null));
        return key;
    }

    // ------------------------------------------------------------------
    // Native refresh (spec 02)
    // ------------------------------------------------------------------

    /**
     * Handles the browser's refresh POST.
     *
     * <p>On a signature failure the challenge is consumed, the session is
     * demoted to {@code tier: none}, and {@code SIGNATURE_INVALID} is raised.
     * Demotion-on-failure is what makes a replayed cookie from another device
     * lose the session — it is the security mechanism, not a side effect.
     *
     * @throws DbscException with {@code SIGNATURE_INVALID}, carrying
     *         whether the bound key still existed (the {@code session_stolen}
     *         signal)
     */
    public RefreshOutcome handleRefresh(String sessionId, String responseHeader, String expectedJti) {
        if (responseHeader == null || responseHeader.isBlank()) {
            throw DbscException.missingResponseHeader(
                    "Secure-Session-Response header is required for refresh");
        }

        BoundKey key = storage.getBoundKey(sessionId)
                .orElseThrow(() -> new DbscException(DbscErrorCode.KEY_NOT_FOUND_NATIVE,
                        "no native bound key for session"));

        Challenge challenge = challenges.validate(expectedJti, sessionId);

        try {
            DbscJws.verifyRefresh(responseHeader.trim(), key.jwk(), challenge.jti());
        } catch (DbscException e) {
            if (e.code() == DbscErrorCode.SIGNATURE_INVALID) {
                // A stolen cookie replayed from a device without the key lands here.
                demoteOnFailure(sessionId, expectedJti, key, e);
            }
            throw e;
        }

        challenges.consume(expectedJti);
        long now = clock.millis();
        storage.getSession(sessionId).ifPresent(session ->
                setSessionTier(session, ProtectionTier.DBSC, now, "native-refresh"));

        telemetry.publish(new DbscTelemetryEvent.Refresh(
                sessionId, ProtectionTier.DBSC, now, null));
        return new RefreshOutcome(sessionId, expectedJti);
    }

    /**
     * The shared failure path for native and bound refresh: burn the challenge so
     * a captured proof cannot be retried, demote the session, and emit the
     * security signal when the key was still present.
     */
    private void demoteOnFailure(
            String sessionId, String jti, BoundKey key, DbscException cause) {
        challenges.consumeQuietly(jti);
        long now = clock.millis();
        storage.getSession(sessionId).ifPresent(session ->
                setSessionTier(session, ProtectionTier.NONE, session.lastRefreshAt(),
                        "signature-invalid"));

        boolean boundKeyStillPresent = key != null
                && storage.getBoundKey(sessionId).isPresent();
        if (boundKeyStillPresent) {
            telemetry.publish(new DbscTelemetryEvent.SessionStolen(
                    sessionId, ProtectionTier.NONE, now, null));
        }
        telemetry.publish(new DbscTelemetryEvent.VerificationFailure(
                sessionId, ProtectionTier.NONE, now, cause.code().name(), null));
    }

    // ------------------------------------------------------------------
    // Session helpers
    // ------------------------------------------------------------------

    /**
     * The tier to report to the application, accounting for the refresh grace
     * window so a poll taken while a refresh is in flight does not read
     * {@code none}.
     *
     * <p>A session that has been explicitly demoted reads {@code none} even
     * though its key is deliberately kept: the key has to survive so that a
     * later failed refresh can still be recognised as {@code session_stolen}. The
     * stored tier is therefore authoritative — the key decides the <em>ceiling</em>
     * a session can reach, not whether it is currently protected.
     */
    public ProtectionTier effectiveTier(Session session) {
        if (session == null) {
            return ProtectionTier.NONE;
        }
        if (session.tier() == ProtectionTier.NONE) {
            return ProtectionTier.NONE;
        }
        if (storage.getBoundKey(session.id()).isPresent()) {
            return ProtectionTier.DBSC;
        }
        long now = clock.millis();
        boolean withinGrace = session.lastRefreshAt() > 0
                && now <= session.lastRefreshAt() + properties.boundCookieTtlMs() + properties.refreshGraceMs();
        if (withinGrace && session.tier() != ProtectionTier.NONE) {
            return session.tier();
        }
        return ProtectionTier.NONE;
    }

    public ProtectionTier currentTier(String sessionId) {
        return storage.getSession(sessionId)
                .map(Session::tier)
                .orElse(ProtectionTier.NONE);
    }

    private void setSessionTier(Session session, ProtectionTier tier, long lastRefreshAt, String reason) {
        if (session.tier() == tier) {
            storage.setSession(session.withLastRefreshAt(lastRefreshAt));
            return;
        }
        storage.setSession(session.withTierAndLastRefreshAt(tier, lastRefreshAt));
        telemetry.publish(new DbscTelemetryEvent.TierChange(
                session.id(), tier, clock.millis(), session.tier(), tier, reason));
    }

    /**
     * The successful outcome of a refresh.
     *
     * @param sessionId the refreshed session
     * @param jti       the challenge that was consumed
     */
    public record RefreshOutcome(String sessionId, String jti) {
    }
}
