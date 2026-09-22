package click.yukio.dbsc.core;

import java.util.Objects;

/**
 * The answer to "may this request proceed, given what DBSC knows?".
 *
 * <p>The model has to separate three client states that a bare session cookie
 * cannot:
 *
 * <ul>
 *   <li><strong>Unregistered</strong> — nothing was ever bound for this client.
 *       DBSC is additive, so this is normal and must be allowed through; it is
 *       every browser without support for the protocol.</li>
 *   <li><strong>Protected</strong> — the session is registered and currently
 *       proving possession of its device key.</li>
 *   <li><strong>Lapsed</strong> — a binding existed and no longer does. This is
 *       the state that must be refused: a session that registered and then stopped
 *       proving possession is either a stolen cookie replayed elsewhere or a
 *       logged-out session, and neither may fall back to cookie-only access.</li>
 * </ul>
 *
 * <p>The distinction between the first and the third is the whole point. Both look
 * like "no tier", so the difference is carried by evidence the client cannot
 * suppress — see {@link DbscService#guardDecision}.
 */
public record GuardDecision(boolean allowed, Reason reason) {

    /** Why the decision came out the way it did. */
    public enum Reason {
        /** The session is registered and currently protected. */
        PROTECTED,
        /** Nothing was ever bound for this client; DBSC is additive. */
        UNREGISTERED,
        /** A binding existed and the session no longer proves possession. */
        LAPSED,
        /** A binding exists but this request presented no DBSC session cookie. */
        COOKIE_MISSING,
        /** The binding was ended, e.g. by logout. */
        REVOKED
    }

    public GuardDecision {
        Objects.requireNonNull(reason, "reason");
    }

    public static GuardDecision allow(Reason reason) {
        return new GuardDecision(true, reason);
    }

    public static GuardDecision deny(Reason reason) {
        return new GuardDecision(false, reason);
    }

    /** Whether the client must be treated as having a binding, however broken. */
    public boolean hadBinding() {
        return reason != Reason.UNREGISTERED;
    }
}
