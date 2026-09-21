package click.yukio.dbsc.protocol;

import click.yukio.dbsc.core.DbscException;

import java.util.HashMap;
import java.util.Map;

/**
 * The {@code X-Dbsc-Bound-Proof} header codec (spec 04).
 *
 * <p>Header format: {@code ts=<timestamp>;sig=<signature>[;bh=<bodyHash>]}.
 * Segments are {@code key=value} joined by {@code ;}; order is not significant.
 * Every parse rule below is a MUST from the spec.
 */
public final class BoundProofHeader {

    /** Reject a header longer than 8192 bytes. */
    public static final int MAX_HEADER_LENGTH = 8192;

    /** Reject more than 8 segments. */
    public static final int MAX_SEGMENTS = 8;

    /** Enough uniqueness for a replay key: 256 bits in base64url. */
    public static final int SIG_PREFIX_LENGTH = 43;

    private BoundProofHeader() {
    }

    /**
     * A successfully parsed proof header.
     *
     * @param timestamp the {@code ts} value in epoch milliseconds
     * @param signature the raw base64url {@code sig} value
     * @param bodyHash  the {@code bh} value, or {@code null} when absent
     */
    public record Parsed(long timestamp, String signature, String bodyHash) {

        /** {@code "<sessionId>.<ts>.<first 43 chars of sig>"} — the replay cache key. */
        public String replayKey(String sessionId) {
            String prefix = signature.length() > SIG_PREFIX_LENGTH
                    ? signature.substring(0, SIG_PREFIX_LENGTH)
                    : signature;
            return sessionId + "." + timestamp + "." + prefix;
        }
    }

    /**
     * Parses a proof header value, enforcing every documented rule.
     *
     * @throws DbscException {@code MALFORMED_PROOF} on any violation
     */
    public static Parsed parse(String raw) {
        if (raw == null || raw.isEmpty()) {
            throw DbscException.malformedProof("proof header is empty");
        }
        // Length is a byte limit, so measure UTF-8 bytes rather than characters.
        if (raw.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_HEADER_LENGTH) {
            throw DbscException.malformedProof("proof header exceeds " + MAX_HEADER_LENGTH + " bytes");
        }
        String[] segments = raw.split(";", -1);
        if (segments.length > MAX_SEGMENTS) {
            throw DbscException.malformedProof("proof header exceeds " + MAX_SEGMENTS + " segments");
        }

        Map<String, String> parts = new HashMap<>();
        for (String segment : segments) {
            String trimmed = segment.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq <= 0) {
                throw DbscException.malformedProof("proof segment has no key or no '=': " + trimmed);
            }
            String key = trimmed.substring(0, eq);
            String value = trimmed.substring(eq + 1);
            if (value.isEmpty()) {
                throw DbscException.malformedProof("proof segment has an empty value: " + key);
            }
            if (parts.putIfAbsent(key, value) != null) {
                throw DbscException.malformedProof("duplicate proof key: " + key);
            }
        }

        String tsRaw = parts.get("ts");
        long timestamp = parseTimestamp(tsRaw);
        String signature = parts.get("sig");
        if (signature == null || signature.isEmpty()) {
            throw DbscException.malformedProof("proof header is missing sig");
        }
        return new Parsed(timestamp, signature, parts.get("bh"));
    }

    /**
     * Requires a finite numeric {@code ts}. Values such as {@code NaN} or
     * {@code Infinity} are rejected, matching the reference implementation's
     * {@code Number.isFinite} check.
     */
    private static long parseTimestamp(String raw) {
        if (raw == null || raw.isEmpty()) {
            throw DbscException.malformedProof("proof header is missing ts");
        }
        try {
            double parsed = Double.parseDouble(raw);
            if (Double.isNaN(parsed) || Double.isInfinite(parsed) || parsed != Math.floor(parsed)) {
                throw DbscException.malformedProof("proof ts is not a finite integer: " + raw);
            }
            return (long) parsed;
        } catch (NumberFormatException e) {
            throw DbscException.malformedProof("proof ts is not a number: " + raw);
        }
    }

    /**
     * Builds the signed message.
     *
     * <pre>
     * &lt;sessionId&gt;.&lt;METHOD&gt;.&lt;path&gt;.&lt;ts&gt;
     * &lt;sessionId&gt;.&lt;METHOD&gt;.&lt;path&gt;.&lt;ts&gt;.&lt;bh&gt;   (body signing)
     * </pre>
     *
     * <p>The method is uppercased and the fields are joined by single dots.
     */
    public static String signedMessage(
            String sessionId, String method, String path, long timestamp, String bodyHash) {
        String base = sessionId + "." + method.toUpperCase(java.util.Locale.ROOT) + "." + path + "." + timestamp;
        return bodyHash == null ? base : base + "." + bodyHash;
    }
}
