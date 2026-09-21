package click.yukio.dbsc.core;

/**
 * One entry of a parsed {@code Secure-Session-Skipped} header.
 *
 * @param reason    the recognized reason token
 * @param sessionId the optional {@code session_identifier} parameter
 */
public record SkippedEntry(SkippedReason reason, String sessionId) {
}
