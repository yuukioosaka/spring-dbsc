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
                DbscTelemetryEvent.TierChange {

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
     * A refresh signature failed while a bound key still exists for the session.
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
}
