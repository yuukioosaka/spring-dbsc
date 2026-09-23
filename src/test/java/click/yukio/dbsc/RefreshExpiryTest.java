package click.yukio.dbsc;

import click.yukio.dbsc.EngineHarness.Support;
import click.yukio.dbsc.config.DbscProperties;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.DbscErrorCode;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A binding's absolute lifetime, enforced on refresh.
 *
 * <p>The deadline is created by {@code bind()} and a refresh does not move it, so
 * without this check a device that keeps proving possession would renew its binding
 * forever — the lifetime would be decoration, and a single captured device would keep
 * one session alive indefinitely. The check is therefore a security control, not
 * bookkeeping, and it is pinned at the boundary rather than only in the happy path
 * that the rest of the suite exercises.
 */
class RefreshExpiryTest {

    private static final String SESSION_ID = EngineHarness.SESSION_ID;

    @Test
    @DisplayName("a refresh past the deadline is refused, before the challenge is spent")
    void expiredRefreshIsRefused() {
        Support support = Support.create(Duration.ofMinutes(10));
        support.seedRegisteredSession();
        // The session's deadline passes while the device is idle.
        support.clock().advance(Duration.ofMinutes(10).toMillis() + 1);
        Challenge challenge = support.seedChallenge();

        DbscException thrown = assertThrows(DbscException.class,
                () -> support.engine().handleRefresh(SESSION_ID,
                        support.validRefreshJws(challenge.jti())));

        assertEquals(DbscErrorCode.SESSION_NOT_FOUND, thrown.code());
        assertFalse(support.storage().getChallenge(challenge.jti()).orElseThrow().consumed(),
                "an expired session must not burn the challenge it arrived with");
    }

    @Test
    @DisplayName("a refresh just inside the deadline is accepted")
    void refreshInsideTheDeadlineSucceeds() {
        Support support = Support.create(Duration.ofMinutes(10));
        support.seedRegisteredSession();
        support.clock().advance(Duration.ofMinutes(10).toMillis() - 1);
        Challenge challenge = support.seedChallenge();

        support.engine().handleRefresh(SESSION_ID, support.validRefreshJws(challenge.jti()));

        assertEquals(ProtectionTier.DBSC, support.session().tier());
    }

    @Test
    @DisplayName("the deadline is absolute: a successful refresh does not move it")
    void refreshDoesNotExtendTheDeadline() {
        Support support = Support.create(Duration.ofMinutes(10));
        support.seedRegisteredSession();
        long deadline = support.session().expiresAt();

        // Refresh repeatedly, right up to the boundary, and the deadline never moves.
        for (int i = 0; i < 10; i++) {
            support.clock().advance(Duration.ofMinutes(1).toMillis());
            Challenge challenge = support.seedChallenge();
            support.engine().handleRefresh(SESSION_ID, support.validRefreshJws(challenge.jti()));
            assertEquals(deadline, support.session().expiresAt(),
                    "refresh " + i + " moved the deadline");
        }
    }

    @Test
    @DisplayName("effectiveTier reads none once the deadline has passed")
    void expiredSessionReportsNoProtection() {
        Support support = Support.create(Duration.ofMinutes(10));
        support.seedRegisteredSession();
        Session live = support.session();
        assertEquals(ProtectionTier.DBSC, support.engine().effectiveTier(live),
                "the session is protected while inside its life");

        support.clock().advance(Duration.ofMinutes(10).toMillis() + 1);

        assertEquals(ProtectionTier.NONE, support.engine().effectiveTier(support.session()),
                "an expired binding must not be reported as protected");
    }

    @Test
    @DisplayName("the lifetime comes from dbsc.session-ttl, not from the caller")
    void lifetimeComesFromConfiguration() {
        DbscProperties properties = new DbscProperties();
        properties.setSessionTtl(Duration.ofHours(3));

        Support support = Support.create(properties);
        support.bind();

        assertEquals(support.clock().millis() + Duration.ofHours(3).toMillis(),
                support.session().expiresAt(),
                "bind() must apply the configured TTL and nothing else");
    }

    @Test
    @DisplayName("a session with no record at all is refused the same way as an expired one")
    void missingSessionIsIndistinguishableFromExpired() {
        Support support = Support.create(Duration.ofMinutes(10));
        support.seedRegisteredSession();
        Challenge challenge = support.seedChallenge();
        String jws = support.validRefreshJws(challenge.jti());

        support.clock().advance(Duration.ofMinutes(10).toMillis() + 1);
        DbscException expired = assertThrows(DbscException.class,
                () -> support.engine().handleRefresh(SESSION_ID, jws));

        // The record is gone entirely: what a caller sees must not change.
        support.storage().deleteSession(SESSION_ID);
        DbscException missing = assertThrows(DbscException.class,
                () -> support.engine().handleRefresh(SESSION_ID, jws));

        assertEquals(missing.code(), expired.code(),
                "the code must not disclose whether the binding once existed");
        assertEquals(missing.getMessage(), expired.getMessage());
        assertTrue(missing.code() != DbscErrorCode.KEY_NOT_FOUND);
    }
}
