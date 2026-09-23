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
    public DeviceKey handleRegistration(String sessionId, String responseHeader) {
        if (responseHeader == null || responseHeader.isBlank()) {
            throw DbscException.missingResponseHeader("Secure-Session-Response header is required");
        }
        DbscJws.Parsed parsed = DbscJws.verifyRegistration(responseHeader.trim());

        // The JTI the browser actually signed is the one that has to be validated and
        // consumed -- not a JTI looked up server-side. Picking the session's newest
        // outstanding challenge would make a replay of an older, already-consumed JTI
        // resolve to that newer challenge and register a second key on it, and two
        // different proofs could race for the same row and both be told they won.
        Challenge challenge = challenges.validate(parsed.jti(), sessionId);

        if (storage.getDeviceKey(sessionId).isPresent()) {
            throw new DbscException(DbscErrorCode.SESSION_ALREADY_REGISTERED,
                    "session already has a device key; cannot register again");
        }

        challenges.consume(parsed.jti());

        long now = clock.millis();
        DeviceKey key = new DeviceKey(sessionId, parsed.jwk(),
                parsed.algorithm().wireValue(), now);
        storage.setDeviceKey(key);

        storage.getSession(sessionId).ifPresent(session ->
                setSessionTier(session, ProtectionTier.DBSC, now, "native-registration"));

        telemetry.publish(new DbscTelemetryEvent.Registration(
                sessionId, currentTier(sessionId), now, key.algorithm(), null));

        // The challenge just spent names the session it will be replaced under: a proof
        // replayed long after it was consumed must still be answered CHALLENGE_CONSUMED
        // rather than being re-armed by this very response.
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
    public RefreshOutcome handleRefresh(String sessionId, String responseHeader) {
        if (responseHeader == null || responseHeader.isBlank()) {
            throw DbscException.missingResponseHeader(
                    "Secure-Session-Response header is required for refresh");
        }

        // The absolute lifetime is checked before anything else is looked up. A session
        // is created with a deadline and a refresh does not move it, so a device that
        // keeps proving possession would otherwise renew its binding forever -- the
        // deadline would be decoration. Refusing here rather than after verification
        // also means an expired session does not consume the challenge it arrived with.
        //
        // The order is deliberate: this runs before the device key lookup so that an
        // expired session and one that never existed are refused with the same
        // SESSION_NOT_FOUND, not one of them with KEY_NOT_FOUND. On an unauthenticated
        // route that difference is an existence oracle, and the whole point of the
        // lifetime rule is that past the deadline the binding is as good as absent.
        requireUnexpired(sessionId);

        DeviceKey key = storage.getDeviceKey(sessionId)
                .orElseThrow(() -> new DbscException(DbscErrorCode.KEY_NOT_FOUND,
                        "no device key for session"));

        // Read the claim without verifying, so the challenge can be resolved from the
        // signed JTI. The signature covers that claim, and the resolved challenge is
        // compared back against it below, so a tampered jti is caught as a signature
        // failure rather than by trusting this read.
        String signedJti = DbscJws.unverifiedJti(responseHeader.trim());
        Challenge challenge = challenges.validate(signedJti, sessionId);

        try {
            DbscJws.verifyRefresh(responseHeader.trim(), key.jwk(), challenge.jti());
        } catch (DbscException e) {
            if (e.code() == DbscErrorCode.SIGNATURE_INVALID) {
                // A stolen cookie replayed from a device without the key lands here.
                demoteOnFailure(sessionId, signedJti, key, e);
            }
            throw e;
        }

        challenges.consume(signedJti);
        long now = clock.millis();
        storage.getSession(sessionId).ifPresent(session ->
                setSessionTier(session, ProtectionTier.DBSC, now, "native-refresh"));

        telemetry.publish(new DbscTelemetryEvent.Refresh(
                sessionId, ProtectionTier.DBSC, now, null));
        return new RefreshOutcome(sessionId, signedJti);
    }

    /**
     * Mints a fresh credential-cookie ticket for a session whose refresh has already
     * verified.
     *
     * <p>The ticket <strong>is</strong> the value of the credential cookie named in
     * {@code credentials[]} — the cookie {@code §8.6} asks about — and replacing it on
     * every refresh is what puts a clock on a copy of it. The session it names does not
     * move, and nothing about this method defines session identity: a refresh is
     * resolved from the {@code Sec-Secure-Session-Id} header, so the ticket the browser
     * was carrying is never consulted here.
     *
     * <p>Minting happens on <strong>every</strong> successful refresh and is not a
     * setting. A cookie can be copied, and a copy is worth only as little as the value's
     * remaining life; making this optional would mean the safe behaviour is the one you
     * have to know to ask for.
     *
     * <p>Ordering is the whole security argument, and it is the opposite of the obvious
     * one. The new ticket is minted <strong>after</strong> the signature verified, never
     * before, and the old value keeps resolving until its own expiry. Minting first would
     * let anyone who can reach the refresh route retire a stranger's credential by
     * posting a refresh with no proof at all — a denial of service that needs no key and
     * leaves no trace.
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
        // The new ticket lives as long as the cookie carrying it is allowed to -- the
        // binding TTL, which is also the refresh cadence -- plus the grace, which covers
        // the overlap while the browser is still holding the previous value. Writing it
        // with rotationGraceMs alone would expire the credential long before Chromium
        // comes back to refresh it, and every refresh after the first would fail.
        storage.setTicket(ticket, sessionId,
                properties.bindingCookieTtlMs() + properties.rotationGraceMs());

        telemetry.publish(new DbscTelemetryEvent.SessionRotated(
                sessionId, storage.getSession(sessionId).map(Session::tier).orElse(ProtectionTier.NONE),
                clock.millis()));
        return ticket;
    }

    /**
     * Refuses a refresh when the session's absolute deadline has passed.
     *
     * <p>Reported as {@link DbscErrorCode#SESSION_NOT_FOUND}, the same code <em>and the
     * same message</em> an unknown session gets, so a caller cannot use the response to
     * tell "this binding was once real" from "this binding never existed" — on an
     * unauthenticated route reachable without a cookie, that difference is worth
     * enumerating for. The shared wording is the reason the two branches below are not
     * written as one: only an expired session emits telemetry, and only it needs to say
     * why in the server's own logs rather than in the caller's response. For the same
     * reason the caller must run this before the device key lookup; otherwise a session
     * past its deadline is refused with a different code from one that is simply absent.
     *
     * <p>The record is deliberately <strong>not</strong> rewritten. Changing it would
     * extend a Redis key past the deadline the storage adapter derived from
     * {@code expiresAt}, and the deadline itself is what the check reads, so the row
     * can be left to expire on its own schedule.
     *
     * @throws DbscException {@code SESSION_NOT_FOUND} when the session is missing or
     *         past {@code expiresAt}
     */
    private void requireUnexpired(String sessionId) {
        Session session = storage.getSession(sessionId).orElse(null);
        boolean expired = session != null && session.isExpired(clock.millis());
        if (expired) {
            telemetry.publish(new DbscTelemetryEvent.VerificationFailure(
                    sessionId, ProtectionTier.NONE, clock.millis(),
                    "SESSION_EXPIRED", null));
        }
        if (session == null || expired) {
            // The same sentence for both, because the difference is exactly what an
            // enumeration would want to know.
            throw new DbscException(DbscErrorCode.SESSION_NOT_FOUND,
                    "no session record for this id");
        }
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
        // An expired binding reports none even though its key is still stored: the
        // refresh route refuses it, so reporting dbsc here would have the guard admit
        // requests that DBSC itself no longer honours.
        if (session.isExpired(clock.millis())) {
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
