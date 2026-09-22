package click.yukio.dbsc.protocol;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.core.DeviceKey;
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
import java.util.Optional;
import java.util.UUID;

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
    public DeviceKey handleRegistration(String sessionId, String responseHeader, String expectedJti) {
        if (responseHeader == null || responseHeader.isBlank()) {
            throw DbscException.missingResponseHeader("Secure-Session-Response header is required");
        }
        DbscJws.Parsed parsed = DbscJws.verifyRegistration(responseHeader.trim());

        challenges.validate(expectedJti, sessionId);

        if (storage.getDeviceKey(sessionId).isPresent()) {
            throw new DbscException(DbscErrorCode.SESSION_ALREADY_REGISTERED,
                    "session already has a device key; cannot register again");
        }

        challenges.consume(expectedJti);

        long now = clock.millis();
        DeviceKey key = new DeviceKey(sessionId, parsed.jwk(),
                parsed.algorithm().wireValue(), now);
        storage.setDeviceKey(key);

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
     *         whether the device key still existed (the {@code session_stolen}
     *         signal)
     */
    public RefreshOutcome handleRefresh(String sessionId, String responseHeader, String expectedJti) {
        if (responseHeader == null || responseHeader.isBlank()) {
            throw DbscException.missingResponseHeader(
                    "Secure-Session-Response header is required for refresh");
        }

        DeviceKey key = storage.getDeviceKey(sessionId)
                .orElseThrow(() -> new DbscException(DbscErrorCode.KEY_NOT_FOUND,
                        "no device key for session"));

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
     * Mints a fresh credential-cookie ticket for a session whose refresh has already
     * verified, and keeps the value the browser was carrying resolvable for the grace.
     *
     * <p>The session id does not move. {@code session_identifier} is the name of the
     * cookie holding it and Chromium keys the session store by that name (spec §7.2),
     * so the value behind that name has to stay put for the life of the binding. What
     * rotates is the value of the credential cookie — the one {@code credentials[]}
     * names and §8.6 asks about — which is what puts a clock on a copy of it.
     *
     * <p>Minting happens on <strong>every</strong> successful refresh and is not a
     * setting. A cookie can be copied, and a copy is worth only as little as the value's
     * remaining life; making this optional would mean the safe behaviour is the one you
     * have to know to ask for.
     *
     * <p>Ordering is the whole security argument, and it is the opposite of the obvious
     * one. The new ticket is minted <strong>after</strong> the signature verified, never
     * before, and the old value is retired only then. Minting first would let anyone who
     * can reach the refresh route retire a stranger's credential by posting a refresh
     * with no proof at all — a denial of service that needs no key and leaves no trace.
     *
     * <p>When there is no session record the id is returned unchanged: {@code
     * handleRefresh} tolerates a session that has gone, and issuing a ticket for one
     * would resurrect a record the storage layer had already discarded.
     *
     * @param sessionId the id the verified refresh arrived with
     * @return the ticket to set in the credential cookie
     */
    public String rotateAfterRefresh(String sessionId) {
        if (storage.getSession(sessionId).isEmpty()) {
            return sessionId;
        }

        String ticket = Base64Url.randomJti();
        // Both writes are unconditional, and together they are the rotation: the new ticket
        // starts resolving, and the old one keeps resolving for exactly as long as it takes
        // the browser to see the new one. Nothing is deleted on the old side -- a tab that
        // arrives late still has to be recognised, or Chromium records a permanent failure.
        storage.setTicket(ticket, sessionId, properties.rotationGraceMs());

        telemetry.publish(new DbscTelemetryEvent.SessionRotated(
                sessionId, storage.getSession(sessionId).map(Session::tier).orElse(ProtectionTier.NONE),
                clock.millis()));
        return ticket;
    }

    /**
     * The shared failure path for a refresh whose signature did not verify: burn the
     * challenge so a captured response cannot be retried, demote the session, and
     * emit the security signal when the key was still present.
     */
    private void demoteOnFailure(
            String sessionId, String jti, DeviceKey key, DbscException cause) {
        challenges.consumeQuietly(jti);
        long now = clock.millis();
        storage.getSession(sessionId).ifPresent(session ->
                setSessionTier(session, ProtectionTier.NONE, session.lastRefreshAt(),
                        "signature-invalid"));

        boolean deviceKeyStillPresent = key != null
                && storage.getDeviceKey(sessionId).isPresent();
        if (deviceKeyStillPresent) {
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
        if (storage.getDeviceKey(session.id()).isPresent()) {
            return ProtectionTier.DBSC;
        }
        long now = clock.millis();
        boolean withinGrace = session.lastRefreshAt() > 0
                && now <= session.lastRefreshAt() + properties.bindingCookieTtlMs() + properties.refreshGraceMs();
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
