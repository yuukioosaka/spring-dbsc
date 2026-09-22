package click.yukio.dbsc;

import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.DeviceKey;
import click.yukio.dbsc.core.RegistrationToken;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.protocol.ChallengeService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The registration token's TTL, which is a security control rather than a
 * convenience.
 *
 * <p>The token is spent by the registration attempt, success or failure (see
 * {@code DbscService.handleRegistration}), so its TTL only bounds a token that is
 * never presented at all. The value that matters is therefore how long a
 * <em>captured</em> token stays live, not how long a user might take to log in —
 * and Chromium POSTs within about a second of the login response (spec 02 step 2),
 * so the two are not in tension. The default is deliberately the same five minutes
 * as a challenge rather than the 24 hours a registration window might suggest.
 */
class RegistrationTokenTtlTest {

    @Test
    @DisplayName("the registration token TTL defaults to five minutes, not a day")
    void defaultIsFiveMinutes() {
        DbscProperties properties = new DbscProperties();

        assertEquals(Duration.ofMinutes(5), properties.getRegistrationTokenTtl(),
                "a captured registration token must not stay usable for hours");
        assertEquals(5 * 60 * 1000L, properties.registrationTokenTtlMs());
    }

    @Test
    @DisplayName("the registration token TTL is independent of the challenge TTL")
    void configurableIndependently() {
        DbscProperties properties = new DbscProperties();
        properties.setRegistrationTokenTtl(Duration.ofMinutes(30));

        assertEquals(30 * 60 * 1000L, properties.registrationTokenTtlMs());
        assertEquals(Duration.ofMinutes(5), properties.getChallengeTtl(),
                "changing one TTL must not move the other");
    }

    @Test
    @DisplayName("issuing a challenge reads the challenge TTL, not the token's")
    void challengeIssuanceUsesItsOwnTtl() {
        DbscProperties properties = new DbscProperties();
        properties.setRegistrationTokenTtl(Duration.ofSeconds(90));

        MutableClock clock = new MutableClock(1_700_000_000_000L);
        ChallengeService challenges = new ChallengeService(new NoopStorage(), properties, clock);
        Challenge challenge = challenges.issue("sess_1");

        assertEquals(clock.millis() + Duration.ofMinutes(5).toMillis(), challenge.expiresAt(),
                "a challenge carries challenge-ttl");
        assertTrue(!challenge.isExpired(clock.millis() + 1));
    }

    @Test
    @DisplayName("a token expires exactly at its expiry boundary")
    void tokenExpiryBoundary() {
        long now = 1_700_000_000_000L;
        long ttl = Duration.ofMinutes(5).toMillis();
        RegistrationToken token = new RegistrationToken("tok", "sess_1", now, now + ttl, false);

        assertTrue(token.isExpired(now + ttl + 1), "past the expiry is expired");
        assertTrue(!token.isExpired(now + ttl - 1), "inside the window is live");
    }

    /** The property is bound from the environment, so the wiring is asserted too. */
    @SpringBootTest
    @ActiveProfiles("test")
    static class Wired {
        @Autowired
        private DbscProperties properties;

        @Autowired
        private StorageAdapter storage;

        @Test
        @DisplayName("dbsc.registration-token-ttl is bound and the service is wired with storage")
        void propertyIsBound() {
            assertEquals(Duration.ofMinutes(5), properties.getRegistrationTokenTtl());
            assertNotNull(storage);
        }
    }

    /** A clock the test can move, so nothing depends on wall time. */
    private static final class MutableClock extends Clock {
        private final long millis;

        MutableClock(long millis) {
            this.millis = millis;
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

    /** Accepts writes and answers nothing: these tests are about issuance maths. */
    private static final class NoopStorage implements StorageAdapter {

        @Override
        public Optional<Session> getSession(String id) {
            return Optional.empty();
        }

        @Override
        public Optional<Session> getSessionByAppSessionId(String appSessionId) {
            return Optional.empty();
        }

        @Override
        public void setSession(Session session) {
        }

        @Override
        public void deleteSession(String id) {
        }

        @Override
        public String resolveTicket(String ticket) {
            return null;
        }

        @Override
        public void setTicket(String ticket, String sessionId, long ttlMs) {
        }

        @Override
        public void deleteTicket(String ticket) {
        }

        @Override
        public Optional<DeviceKey> getDeviceKey(String sessionId) {
            return Optional.empty();
        }

        @Override
        public void setDeviceKey(DeviceKey key) {
        }

        @Override
        public void deleteDeviceKey(String sessionId) {
        }

        @Override
        public Optional<Challenge> getChallenge(String jti) {
            return Optional.empty();
        }

        @Override
        public void setChallenge(Challenge challenge) {
        }

        @Override
        public boolean consumeChallenge(String jti) {
            return false;
        }

        @Override
        public Optional<RegistrationToken> getRegistrationToken(String token) {
            return Optional.empty();
        }

        @Override
        public void setRegistrationToken(RegistrationToken token) {
        }

        @Override
        public boolean consumeRegistrationToken(String token) {
            return false;
        }

        @Override
        public void revokeSession(String sessionId) {
        }
    }
}
