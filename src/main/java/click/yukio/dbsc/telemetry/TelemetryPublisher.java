package click.yukio.dbsc.telemetry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;

/**
 * Publishes DBSC telemetry on the Spring {@code ApplicationEventPublisher}, so
 * an application can consume events with a plain {@code @EventListener} without
 * depending on the protocol code.
 *
 * <p>Two events are security signal and are logged at {@code WARN} regardless of
 * listeners: {@code session_stolen} and {@code verification_failure}. The
 * remainder are {@code DEBUG}.
 */
public class TelemetryPublisher {

    private static final Logger log = LoggerFactory.getLogger(TelemetryPublisher.class);

    private final ApplicationEventPublisher publisher;
    private final boolean enabled;

    public TelemetryPublisher(ApplicationEventPublisher publisher, boolean enabled) {
        this.publisher = publisher;
        this.enabled = enabled;
    }

    public void publish(DbscTelemetryEvent event) {
        if (event == null) {
            return;
        }
        //
        // An if/else chain rather than a pattern-matching switch: switch patterns
        // are Java 21, and this library compiles at the Java 17 language level.
        // Order matters — the typed subtypes are tested before the generic
        // fallback, exactly as the switch's default branch did.
        if (event instanceof DbscTelemetryEvent.SessionStolen stolen) {
            log.warn(
                    "DBSC session_stolen: sessionId={} tier={} ip={} — a refresh signature failed "
                            + "while a bound key still exists; a stolen cookie may have been replayed",
                    stolen.sessionId(), stolen.tier().wireValue(), stolen.ip());
        } else if (event instanceof DbscTelemetryEvent.VerificationFailure failure) {
            log.warn(
                    "DBSC verification_failure: sessionId={} tier={} reason={} ip={}",
                    failure.sessionId(), failure.tier().wireValue(), failure.reason(), failure.ip());
        } else if (event instanceof DbscTelemetryEvent.PolyfillMissing missing) {
            log.warn(
                    "DBSC polyfill_missing: sessionId={} tier={} ip={} — native key present but no "
                            + "bound key, so per-request proofs will fail",
                    missing.sessionId(), missing.tier().wireValue(), missing.ip());
        } else {
            log.debug(
                    "DBSC {}: sessionId={} tier={}",
                    event.type(), event.sessionId(), event.tier().wireValue());
        }
        if (enabled) {
            publisher.publishEvent(event);
        }
    }
}
