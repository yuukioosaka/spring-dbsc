package click.yukio.dbsc.telemetry;

import click.yukio.dbsc.core.ProtectionTier;

/**
 * Base for the DBSC telemetry events (spec 08).
 *
 * <p>Every event carries the session it concerns, the session's tier at the time,
 * and the event time. {@code sessionId} may be {@code null} when the session could
 * not be resolved — a verification failure against an unknown session is still worth
 * reporting.
 *
 * <p>Implementations are records, so the accessors below are their components and
 * each record documents its own parameters.
 */
public sealed interface DbscTelemetryEvent
        permits DbscTelemetryEvent.Registration, DbscTelemetryEvent.Refresh,
                DbscTelemetryEvent.VerificationFailure, DbscTelemetryEvent.SessionStolen,
                DbscTelemetryEvent.TierChange, DbscTelemetryEvent.SessionRotated {

    String sessionId();

    ProtectionTier tier();

    long timestamp();

    /** The event's wire name, as used by the reference implementation. */
    String type();

    /**
     * A successful registration.
     *
     * @param algorithm the registered key's algorithm
     * @param ip        the client address
     */
    record Registration(String sessionId, ProtectionTier tier, long timestamp, String algorithm, String ip)
            implements DbscTelemetryEvent {
        @Override
        public String type() {
            return "registration";
        }
    }

    /** A successful refresh. */
    record Refresh(String sessionId, ProtectionTier tier, long timestamp, String ip)
            implements DbscTelemetryEvent {
        @Override
        public String type() {
            return "refresh";
        }
    }

    /**
     * Any signature or JWS verification failure. Individually often benign; a
     * spike on one session is suspicious.
     *
     * @param reason the {@link click.yukio.dbsc.core.DbscErrorCode} name
     */
    record VerificationFailure(String sessionId, ProtectionTier tier, long timestamp, String reason, String ip)
            implements DbscTelemetryEvent {
        @Override
        public String type() {
            return "verification_failure";
        }
    }

    /**
     * A refresh signature failed while a device key still exists for the session.
     * This is the strongest signal that a stolen cookie was replayed from a
     * device without the key. <strong>Alert on it.</strong>
     */
    record SessionStolen(String sessionId, ProtectionTier tier, long timestamp, String ip)
            implements DbscTelemetryEvent {
        @Override
        public String type() {
            return "session_stolen";
        }
    }

    /** The session's tier changed. */
    record TierChange(String sessionId, ProtectionTier tier, long timestamp,
                      ProtectionTier from, ProtectionTier to, String reason)
            implements DbscTelemetryEvent {
        @Override
        public String type() {
            return "tier_change";
        }
    }

    /**
     * A refresh minted a new credential ticket.
     *
     * <p>The session id does not change — {@code session_identifier} names a session
     * and Chromium keys its store by that name (spec §7.2) — so this event exists to
     * mark the credential's turnover, not to follow a session across ids. What it is
     * for operationally is the exposure clock: every one of these is a point at which
     * a previously captured ticket stopped resolving (after the grace), and a burst
     * of them for one session means something is refreshing far more often than a
     * browser should be.
     *
     * <p>The tickets themselves are deliberately <strong>not</strong> in the event:
     * they are bearer credentials, and telemetry ends up in log aggregators with a
     * much wider audience than the storage adapter. Only the session is named.
     *
     * @param sessionId the session whose credential was rotated; unchanged by the
     *         rotation itself
     */
    record SessionRotated(String sessionId, ProtectionTier tier, long timestamp)
            implements DbscTelemetryEvent {
        @Override
        public String type() {
            return "session_rotated";
        }
    }
}
