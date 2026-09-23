package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.DeviceKey;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.protocol.ChallengeService;
import click.yukio.dbsc.protocol.DbscProtocolEngine;
import click.yukio.dbsc.storage.InMemoryStorageAdapter;
import click.yukio.dbsc.telemetry.DbscTelemetryEvent;
import click.yukio.dbsc.telemetry.TelemetryPublisher;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/**
 * A protocol engine over an in-memory store and a clock a test can move.
 *
 * <p>The lifetime check is about the passage of time, so the tests that pin it need a
 * clock they control rather than the real one or a fixed instant: the boundary is
 * "one millisecond either side of the deadline", which no wall clock can express.
 * Everything else here is the same wiring {@code ProtocolBehaviourTest} builds, kept
 * in one place so a test can seed a registered session and sign a proof without
 * restating it.
 */
final class EngineHarness {

    /** The identifier every session this harness seeds is stored under. */
    static final String SESSION_ID = "sess_expiry0000000000000000000000001";

    private EngineHarness() {
    }

    /** A mutable {@link Clock} that only moves when a test moves it. */
    static final class MutableClock extends Clock {

        private long millis;

        MutableClock(long millis) {
            this.millis = millis;
        }

        void advance(long deltaMs) {
            this.millis += deltaMs;
        }

        @Override
        public long millis() {
            return millis;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }

    /** The wiring a lifetime test needs, plus the fixtures it seeds. */
    static final class Support {

        private static final long START_MS = 1_700_000_000_000L;

        private final DbscProperties properties;
        private final StorageAdapter storage;
        private final MutableClock clock;
        private final DbscProtocolEngine engine;
        private final List<DbscTelemetryEvent> events = new ArrayList<>();
        private final HttpFlowTest.TestKey key = HttpFlowTest.TestKey.generate();

        private Support(DbscProperties properties) {
            this.properties = properties;
            this.storage = new InMemoryStorageAdapter();
            this.clock = new MutableClock(START_MS);
            ChallengeService challenges = new ChallengeService(storage, properties, clock);
            TelemetryPublisher telemetry = new TelemetryPublisher(event -> {
                if (event instanceof DbscTelemetryEvent dbscEvent) {
                    events.add(dbscEvent);
                }
            }, true);
            this.engine = new DbscProtocolEngine(storage, properties, challenges, clock, telemetry);
        }

        static Support create(Duration sessionTtl) {
            DbscProperties properties = new DbscProperties();
            properties.setSessionTtl(sessionTtl);
            return new Support(properties);
        }

        static Support create(DbscProperties properties) {
            return new Support(properties);
        }

        DbscProtocolEngine engine() {
            return engine;
        }

        StorageAdapter storage() {
            return storage;
        }

        MutableClock clock() {
            return clock;
        }

        DbscProperties properties() {
            return properties;
        }

        List<DbscTelemetryEvent> events() {
            return events;
        }

        /** Writes the session record {@code bind()} would have written. */
        void bind() {
            storage.setSession(new Session(
                    SESSION_ID, "app_" + SESSION_ID, "user_1",
                    ProtectionTier.NONE, false, clock.millis(),
                    clock.millis() + properties.sessionTtlMs(), 0));
        }

        /** A session that registered and holds the device key {@link #validRefreshJws} signs with. */
        void seedRegisteredSession() {
            bind();
            storage.setDeviceKey(new DeviceKey(
                    SESSION_ID, key.publicJwk(), "ES256", clock.millis()));
            storage.setSession(session().withTierAndLastRefreshAt(ProtectionTier.DBSC, clock.millis()));
        }

        Session session() {
            return storage.getSession(SESSION_ID).orElseThrow();
        }

        /** Persists a fresh challenge for the session and returns it. */
        Challenge seedChallenge() {
            Challenge challenge = new Challenge(
                    Base64Url.randomJti(), SESSION_ID,
                    clock.millis(), clock.millis() + properties.challengeTtlMs(), false);
            storage.setChallenge(challenge);
            return challenge;
        }

        /** A refresh JWS signed by the registered key, naming {@code jti}. */
        String validRefreshJws(String jti) {
            return key.refreshJws(jti);
        }

        /** A refresh JWS signed by a key the session never registered. */
        String foreignRefreshJws(String jti) {
            return HttpFlowTest.TestKey.generate().refreshJws(jti);
        }
    }
}
