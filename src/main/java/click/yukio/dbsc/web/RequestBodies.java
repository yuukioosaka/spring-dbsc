package click.yukio.dbsc.web;

import click.yukio.dbsc.core.DbscException;
import jakarta.servlet.http.HttpServletRequest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Reads a request body with a hard size cap.
 *
 * <p>{@link InputStream#readAllBytes()} on an unbounded stream is a memory
 * exhaustion primitive, and the DBSC protocol routes are unauthenticated: the
 * filter reads the body before any session decision, so a single large POST is
 * enough to hurt the process. The container's own limits are not a substitute,
 * because the filter reads the stream directly rather than going through form or
 * JSON parsing where those limits apply.
 *
 * <p>The cap is checked against {@code Content-Length} first, so an honest client
 * that declares an oversized body is rejected without reading it, and then
 * enforced again while reading, because {@code Content-Length} is absent on
 * chunked requests and is in any case attacker-supplied.
 */
public final class RequestBodies {

    /**
     * The largest body accepted on a DBSC route. Generous for the JSON these
     * routes carry — a JWK and a signature are well under a kilobyte — while
     * keeping the worst case bounded.
     */
    public static final int MAX_BODY_BYTES = 64 * 1024;

    private RequestBodies() {
    }

    /**
     * Reads the body, failing with {@code MALFORMED_JWS} when it exceeds
     * {@link #MAX_BODY_BYTES}.
     *
     * @throws DbscException when the body is too large
     */
    public static byte[] readBounded(HttpServletRequest request) throws IOException {
        long declared = request.getContentLengthLong();
        if (declared > MAX_BODY_BYTES) {
            throw DbscException.malformedJws(
                    "request body of " + declared + " bytes exceeds the "
                            + MAX_BODY_BYTES + " byte limit");
        }

        try (InputStream in = request.getInputStream()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream(
                    declared > 0 ? (int) Math.min(declared, MAX_BODY_BYTES) : 1024);
            byte[] chunk = new byte[8192];
            int total = 0;
            int read;
            while ((read = in.read(chunk)) != -1) {
                total += read;
                if (total > MAX_BODY_BYTES) {
                    throw DbscException.malformedJws(
                            "request body exceeds the " + MAX_BODY_BYTES + " byte limit");
                }
                out.write(chunk, 0, read);
            }
            return out.toByteArray();
        }
    }
}
