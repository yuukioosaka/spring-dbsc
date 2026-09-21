package click.yukio.dbsc.protocol;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.BoundKey;
import click.yukio.dbsc.core.BoundKeyKind;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.DbscErrorCode;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.crypto.DbscJws;
import click.yukio.dbsc.crypto.Jwk;
import click.yukio.dbsc.crypto.SignatureVerifier;
import click.yukio.dbsc.replay.ProofReplayCache;
import click.yukio.dbsc.telemetry.DbscTelemetryEvent;
import click.yukio.dbsc.telemetry.TelemetryPublisher;

import java.time.Clock;
import java.util.Map;

/**
 * The protocol algorithms for native registration, native refresh, the bound
 * protocol's registration and refresh, and per-request proof verification.
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
     * validate the challenge, reject a second key of the same kind, atomically
     * consume the challenge, store the key, then move the session to
     * {@code tier: dbsc}.
     */
    public BoundKey handleRegistration(String sessionId, String responseHeader, String expectedJti) {
        if (responseHeader == null || responseHeader.isBlank()) {
            throw DbscException.missingResponseHeader("Secure-Session-Response header is required");
        }
        DbscJws.Parsed parsed = DbscJws.verifyRegistration(responseHeader.trim());

        challenges.validate(expectedJti, sessionId);

        if (storage.getBoundKey(sessionId, BoundKeyKind.NATIVE).isPresent()) {
            throw new DbscException(DbscErrorCode.SESSION_ALREADY_REGISTERED,
                    "session already has a native bound key; cannot register again");
        }

        challenges.consume(expectedJti);

        long now = clock.millis();
        BoundKey key = new BoundKey(sessionId, BoundKeyKind.NATIVE, parsed.jwk(),
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

        BoundKey key = storage.getBoundKey(sessionId, BoundKeyKind.NATIVE)
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
                && storage.getBoundKey(sessionId, key.kind()).isPresent();
        if (boundKeyStillPresent) {
            telemetry.publish(new DbscTelemetryEvent.SessionStolen(
                    sessionId, ProtectionTier.NONE, now, null));
        }
        telemetry.publish(new DbscTelemetryEvent.VerificationFailure(
                sessionId, ProtectionTier.NONE, now, cause.code().name(), null));
    }

    // ------------------------------------------------------------------
    // Bound registration (spec 03)
    // ------------------------------------------------------------------

    /**
     * Registers the client SDK's polyfill public key. Only ES256 is permitted.
     *
     * <p>The tier becomes {@code bound} only when the session has no native key;
     * a Chromium session that already registered a hardware key keeps
     * {@code tier: dbsc}, because the native path stays authoritative.
     */
    public BoundKey handleBoundRegistration(
            String sessionId, Map<String, Object> publicKey, String signature, String challengeJti) {
        if (publicKey == null || signature == null || signature.isEmpty()
                || challengeJti == null || challengeJti.isEmpty()) {
            throw DbscException.missingResponseHeader(
                    "publicKey, signature and challenge are all required");
        }

        Jwk.validate(publicKey);
        if (Jwk.detectAlgorithm(publicKey) != click.yukio.dbsc.crypto.DbscAlgorithm.ES256) {
            throw DbscException.unknownAlgorithm("bound polyfill requires ES256 (EC P-256)");
        }
        Map<String, Object> publicJwk = SignatureVerifier.publicOnly(publicKey);

        Challenge challenge = challenges.validate(challengeJti, sessionId);

        if (!SignatureVerifier.verifyP256(publicJwk, signature, challenge.jti())) {
            throw DbscException.signatureInvalid("signature does not verify against publicKey");
        }

        if (storage.getBoundKey(sessionId, BoundKeyKind.BOUND).isPresent()) {
            throw new DbscException(DbscErrorCode.SESSION_ALREADY_REGISTERED,
                    "session already has a polyfill bound key; cannot register again");
        }

        challenges.consume(challenge.jti());

        long now = clock.millis();
        BoundKey key = new BoundKey(sessionId, BoundKeyKind.BOUND, publicJwk, "ES256", now);
        storage.setBoundKey(key);

        ProtectionTier tier = storage.getBoundKey(sessionId, BoundKeyKind.NATIVE).isPresent()
                ? null // keep the existing tier
                : ProtectionTier.BOUND;
        storage.getSession(sessionId).ifPresent(session -> {
            if (tier == null) {
                storage.setSession(session.withLastRefreshAt(now));
            } else {
                setSessionTier(session, tier, now, "bound-registration");
            }
        });

        telemetry.publish(new DbscTelemetryEvent.Registration(
                sessionId, currentTier(sessionId), now, "ES256", null));
        return key;
    }

    // ------------------------------------------------------------------
    // Bound refresh (spec 03)
    // ------------------------------------------------------------------

    /**
     * Re-proves possession of the polyfill key over {@code "<jti>.<timestamp>"}.
     *
     * <p>The timestamp MUST be within the window or the request fails
     * {@code SIGNATURE_INVALID}; the client corrects skew using
     * {@code X-Server-Time}. On a signature failure the challenge is consumed and
     * the session is demoted, exactly as on the native path.
     */
    public RefreshOutcome handleBoundRefresh(
            String sessionId, String signature, String challengeJti, Long timestamp) {
        if (signature == null || signature.isEmpty()) {
            throw DbscException.missingResponseHeader("signature is required for bound refresh");
        }
        if (timestamp == null) {
            throw DbscException.missingResponseHeader("timestamp is required for bound refresh");
        }

        long skew = Math.abs(clock.millis() - timestamp);
        if (skew > properties.timestampWindowMs()) {
            throw DbscException.signatureInvalid("timestamp outside acceptable window");
        }

        BoundKey key = storage.getBoundKey(sessionId, BoundKeyKind.BOUND)
                .orElseThrow(() -> new DbscException(DbscErrorCode.KEY_NOT_FOUND_BOUND,
                        "no polyfill bound key for session"));

        challenges.validate(challengeJti, sessionId);

        String message = challengeJti + "." + timestamp;
        if (!SignatureVerifier.verifyP256(key.jwk(), signature, message)) {
            DbscException failure = DbscException.signatureInvalid("signature does not verify");
            demoteOnFailure(sessionId, challengeJti, key, failure);
            throw failure;
        }

        challenges.consume(challengeJti);
        long now = clock.millis();
        storage.getSession(sessionId).ifPresent(session -> {
            ProtectionTier tier = storage.getBoundKey(sessionId, BoundKeyKind.NATIVE).isPresent()
                    ? session.tier()
                    : ProtectionTier.BOUND;
            setSessionTier(session, tier, now, "bound-refresh");
        });

        telemetry.publish(new DbscTelemetryEvent.Refresh(sessionId, currentTier(sessionId), now, null));
        return new RefreshOutcome(sessionId, challengeJti);
    }

    // ------------------------------------------------------------------
    // Per-request proof (spec 04)
    // ------------------------------------------------------------------

    /**
     * Verifies an {@code X-Dbsc-Bound-Proof} header against the session's
     * <em>bound</em> key.
     *
     * <p>The proof is always verified against the polyfill key, even on Chromium
     * sessions that also hold a hardware key: the hardware key cannot sign
     * arbitrary request messages, so a guard works identically everywhere.
     *
     * <p>Ordered per spec: presence, parse, timestamp window, key lookup,
     * body-hash binding, signature, then the replay cache last.
     *
     * @param bodyBytes  raw request body, required when {@code signBody} is true
     * @param signBody   whether body signing is in effect for this route
     * @param replayCache replay cache, or {@code null} to skip the check
     */
    public void verifyBoundProof(
            String sessionId,
            String proofHeader,
            String method,
            String path,
            byte[] bodyBytes,
            boolean signBody,
            ProofReplayCache replayCache) {

        // 1. Presence.
        if (proofHeader == null || proofHeader.isEmpty()) {
            throw new DbscException(DbscErrorCode.MISSING_PROOF, "proof header missing");
        }
        // 2. Parse rules.
        BoundProofHeader.Parsed proof = BoundProofHeader.parse(proofHeader);

        // 3. Timestamp window.
        long windowMs = properties.timestampWindowMs();
        if (Math.abs(clock.millis() - proof.timestamp()) > windowMs) {
            throw DbscException.signatureInvalid("proof timestamp outside window");
        }

        // 4. The polyfill key.
        BoundKey key = storage.getBoundKey(sessionId, BoundKeyKind.BOUND)
                .orElseThrow(() -> new DbscException(DbscErrorCode.KEY_NOT_FOUND_BOUND,
                        "no polyfill bound key for session"));

        // 5/6. Body-hash binding, in both directions.
        String bodyHash = null;
        if (signBody) {
            if (bodyBytes == null) {
                throw DbscException.malformedProof("signBody requires the request body");
            }
            if (proof.bodyHash() == null) {
                throw DbscException.malformedProof("proof header missing bh");
            }
            String actual = click.yukio.dbsc.core.Base64Url.sha256Base64Url(bodyBytes);
            if (!actual.equals(proof.bodyHash())) {
                throw DbscException.signatureInvalid("body hash mismatch");
            }
            bodyHash = proof.bodyHash();
        } else if (proof.bodyHash() != null) {
            throw DbscException.malformedProof("proof header carries bh but signBody is disabled");
        }

        // 7. Signature.
        String message = BoundProofHeader.signedMessage(
                sessionId, method, path, proof.timestamp(), bodyHash);
        if (!SignatureVerifier.verifyP256(key.jwk(), proof.signature(), message)) {
            throw DbscException.signatureInvalid("proof signature did not verify");
        }

        // 8. Replay cache, after the cryptographic gate: recording before
        // verification would let an attacker poison the cache with garbage
        // proofs and lock out the legitimate client.
        if (replayCache != null) {
            String replayKey = proof.replayKey(sessionId);
            if (!replayCache.checkAndRecord(replayKey, 2 * windowMs)) {
                throw new DbscException(DbscErrorCode.PROOF_REPLAY, "proof already used (replay)");
            }
        }
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
     * though its bound key is deliberately kept: the key has to survive so that a
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
        if (storage.getBoundKey(session.id(), BoundKeyKind.NATIVE).isPresent()) {
            return ProtectionTier.DBSC;
        }
        if (storage.getBoundKey(session.id(), BoundKeyKind.BOUND).isPresent()) {
            return ProtectionTier.BOUND;
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
