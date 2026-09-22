package click.yukio.dbsc.protocol;

import click.yukio.dbsc.core.SkippedEntry;
import click.yukio.dbsc.core.SkippedReason;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Builders and parsers for the DBSC header values (spec 02).
 *
 * <p>The exact strings here are wire format: a single wrong byte makes Chromium
 * abandon the session silently.
 */
public final class DbscHeaderCodec {

    private DbscHeaderCodec() {
    }

    /**
     * Builds the {@code Secure-Session-Registration} value:
     * {@code (ES256);path="/dbsc/regist/<token>";challenge="<jti>"}.
     *
     * <p>Segments are joined with {@code ;} and <strong>no spaces</strong>, the
     * values are double-quoted, and there is deliberately <strong>no
     * {@code id} parameter</strong>: the W3C draft defines {@code id} only on
     * {@code Secure-Session-Challenge}. The binding cookie name travels in the JSON
     * registration response instead.
     */
    public static String buildRegistrationHeader(String algorithm, String registrationPath, String challenge) {
        return "(" + algorithm + ");path=\"" + registrationPath + "\";challenge=\"" + challenge + "\"";
    }

    /**
     * Builds the {@code Secure-Session-Challenge} value: {@code "<jti>"}, or
     * {@code "<jti>";id="<sessionId>"} when a session identifier is supplied.
     */
    public static String buildChallengeHeader(String jti, String sessionId) {
        String base = "\"" + jti + "\"";
        return sessionId == null ? base : base + ";id=\"" + sessionId + "\"";
    }

    /**
     * Parses the {@code Secure-Session-Skipped} header value into recognized
     * entries. Unrecognized tokens are ignored, optional quotes around
     * {@code session_identifier} are stripped, and a skip is never an error.
     */
    public static List<SkippedEntry> parseSkippedHeader(String raw) {
        List<SkippedEntry> entries = new ArrayList<>();
        if (raw == null || raw.isBlank()) {
            return entries;
        }
        for (String item : raw.split(",")) {
            String trimmed = item.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String[] parts = trimmed.split(";");
            SkippedReason reason = SkippedReason.fromWire(parts[0].trim());
            if (reason == null) {
                continue;
            }
            String sessionId = null;
            for (int i = 1; i < parts.length; i++) {
                String param = parts[i];
                int eq = param.indexOf('=');
                if (eq < 0) {
                    continue;
                }
                String key = param.substring(0, eq).trim();
                String value = param.substring(eq + 1).trim();
                if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }
                if ("session_identifier".equals(key)) {
                    sessionId = value;
                }
            }
            entries.add(new SkippedEntry(reason, sessionId));
        }
        return entries;
    }

    /** Parses a cookie header, normalizing names for case-insensitive lookup. */
    public static Map<String, String> parseCookieHeader(String header) {
        Map<String, String> cookies = new LinkedHashMap<>();
        if (header == null || header.isEmpty()) {
            return cookies;
        }
        for (String part : header.split(";")) {
            int eq = part.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String name = part.substring(0, eq).trim();
            if (name.isEmpty()) {
                continue;
            }
            String value = part.substring(eq + 1).trim();
            if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                value = value.substring(1, value.length() - 1);
            }
            try {
                value = java.net.URLDecoder.decode(value, java.nio.charset.StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                // Keep the raw value when it is not valid percent-encoding.
            }
            cookies.putIfAbsent(name, value);
        }
        return cookies;
    }
}
