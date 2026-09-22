package click.yukio.dbsc.core;

import java.util.Objects;

/**
 * A short-lived value carried by the cookie named in the JSON config's
 * {@code credentials[]}, mapping to the DBSC session it protects.
 *
 * <p>The session id itself does not move. {@code session_identifier} is the
 * <em>name</em> of the cookie that holds the id, and Chromium keys its session store
 * by that string (spec §7.2), so the value behind that name has to stay put for the
 * life of the binding. What rotates is this ticket: a refresh mints a new one, and the
 * retired one keeps resolving for {@code dbsc.rotation-grace}.
 *
 * <p>That is what puts a clock on a captured cookie. The credential cookie travels on
 * every request, and a copy of it is replayable; if the value never changed, the copy
 * would be worth the session's whole lifetime. The cost is a race the protocol creates:
 * the browser only learns the new ticket from the refresh <em>response</em>, so any
 * request already in flight — another tab, a retry, a slow proxy — still carries the
 * old one. Without the retained mapping those requests look like a client with no
 * session, and Chromium records that as a permanent failure it will not retry, which
 * would silently kill DBSC for the whole browser.
 *
 * <p>The mapping is deliberately short-lived and deliberately one hop: it points at
 * exactly one session, and a request that arrives with a retired ticket is answered
 * normally and rotated again, so a long-lived tab chain does not keep a ticket alive.
 *
 * @param ticket    the value the credential cookie carries
 * @param sessionId the DBSC session the ticket names
 * @param expiresAt when this ticket stops resolving (ms)
 */
public record CredentialTicket(
        String ticket,
        String sessionId,
        long expiresAt) {

    public CredentialTicket {
        Objects.requireNonNull(ticket, "ticket");
        Objects.requireNonNull(sessionId, "sessionId");
    }

    public boolean isExpired(long nowMs) {
        return nowMs > expiresAt;
    }
}
