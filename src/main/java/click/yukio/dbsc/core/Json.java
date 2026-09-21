package click.yukio.dbsc.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON codec for the DBSC protocol's own payloads.
 *
 * <p>DBSC parses two JSON shapes from untrusted input — a compact JWS's
 * protected header and payload — and emits three response bodies. Rather than
 * pulling in a full object mapper with its own decoding policy, this codec is
 * deliberately narrow: it decodes only the JSON value types DBSC can encounter,
 * rejects anything unexpected, and preserves object key order so emitted bodies
 * are deterministic.
 *
 * <p>It is not a general-purpose JSON library. Duplicate keys keep the last
 * value, matching JSON.parse.
 */
public final class Json {

    private Json() {
    }

    // ---- Decoding ----

    /**
     * @throws IllegalArgumentException if the input is not well-formed JSON
     */
    public static Object parse(String text) {
        if (text == null) {
            throw new IllegalArgumentException("null JSON input");
        }
        Cursor cursor = new Cursor(text);
        cursor.skipWhitespace();
        Object value = cursor.readValue();
        cursor.skipWhitespace();
        if (!cursor.atEnd()) {
            throw new IllegalArgumentException("trailing content at offset " + cursor.offset);
        }
        return value;
    }

    /** Parses and requires the result to be a JSON object. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object value = parse(text);
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("expected a JSON object");
        }
        return (Map<String, Object>) value;
    }

    /** Parses, returning {@code null} on any malformed input. */
    public static Map<String, Object> tryParseObject(String text) {
        try {
            return parseObject(text);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    // ---- Typed accessors ----

    public static String string(Map<String, Object> object, String key) {
        Object value = object.get(key);
        return value instanceof String s ? s : null;
    }

    public static Map<String, Object> object(Map<String, Object> object, String key) {
        Object value = object.get(key);
        if (!(value instanceof Map<?, ?> map)) {
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        map.forEach((k, v) -> out.put(String.valueOf(k), v));
        return out;
    }

    /** Returns a JSON number as a {@code long}, or {@code null} if absent/non-numeric. */
    public static Long longValue(Map<String, Object> object, String key) {
        Object value = object.get(key);
        if (value instanceof Number n) {
            double d = n.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d) || d != Math.floor(d)) {
                return null;
            }
            return n.longValue();
        }
        return null;
    }

    public static List<Object> array(Map<String, Object> object, String key) {
        Object value = object.get(key);
        return value instanceof List<?> list ? new ArrayList<>(list) : null;
    }

    // ---- Encoding ----

    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        writeValue(out, value);
        return out.toString();
    }

    private static void writeValue(StringBuilder out, Object value) {
        switch (value) {
            case null -> out.append("null");
            case String s -> writeString(out, s);
            case Boolean b -> out.append(b);
            case Integer i -> out.append(i.intValue());
            case Long l -> out.append(l.longValue());
            case Double d -> out.append(d);
            case Float f -> out.append(f.floatValue());
            case Map<?, ?> map -> {
                out.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    writeString(out, String.valueOf(entry.getKey()));
                    out.append(':');
                    writeValue(out, entry.getValue());
                }
                out.append('}');
            }
            case Iterable<?> items -> {
                out.append('[');
                boolean first = true;
                for (Object item : items) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    writeValue(out, item);
                }
                out.append(']');
            }
            default -> writeString(out, String.valueOf(value));
        }
    }

    private static void writeString(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    /** Recursive-descent parser over a string. Package-private for tests. */
    private static final class Cursor {
        private final String text;
        private int offset;

        Cursor(String text) {
            this.text = text;
        }

        boolean atEnd() {
            return offset >= text.length();
        }

        void skipWhitespace() {
            while (offset < text.length()) {
                char c = text.charAt(offset);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    offset++;
                } else {
                    break;
                }
            }
        }

        Object readValue() {
            if (atEnd()) {
                throw new IllegalArgumentException("unexpected end of input");
            }
            char c = text.charAt(offset);
            return switch (c) {
                case '{' -> readObject();
                case '[' -> readArray();
                case '"' -> readString();
                case 't' -> readLiteral("true", Boolean.TRUE);
                case 'f' -> readLiteral("false", Boolean.FALSE);
                case 'n' -> readLiteral("null", null);
                default -> readNumber();
            };
        }

        private Map<String, Object> readObject() {
            Map<String, Object> result = new LinkedHashMap<>();
            offset++; // '{'
            skipWhitespace();
            if (!atEnd() && text.charAt(offset) == '}') {
                offset++;
                return result;
            }
            while (true) {
                skipWhitespace();
                if (atEnd() || text.charAt(offset) != '"') {
                    throw new IllegalArgumentException("expected object key at offset " + offset);
                }
                String key = readString();
                skipWhitespace();
                if (atEnd() || text.charAt(offset) != ':') {
                    throw new IllegalArgumentException("expected ':' at offset " + offset);
                }
                offset++;
                skipWhitespace();
                result.put(key, readValue());
                skipWhitespace();
                if (atEnd()) {
                    throw new IllegalArgumentException("unterminated object");
                }
                char c = text.charAt(offset);
                if (c == ',') {
                    offset++;
                } else if (c == '}') {
                    offset++;
                    return result;
                } else {
                    throw new IllegalArgumentException("expected ',' or '}' at offset " + offset);
                }
            }
        }

        private List<Object> readArray() {
            List<Object> result = new ArrayList<>();
            offset++; // '['
            skipWhitespace();
            if (!atEnd() && text.charAt(offset) == ']') {
                offset++;
                return result;
            }
            while (true) {
                skipWhitespace();
                result.add(readValue());
                skipWhitespace();
                if (atEnd()) {
                    throw new IllegalArgumentException("unterminated array");
                }
                char c = text.charAt(offset);
                if (c == ',') {
                    offset++;
                } else if (c == ']') {
                    offset++;
                    return result;
                } else {
                    throw new IllegalArgumentException("expected ',' or ']' at offset " + offset);
                }
            }
        }

        private String readString() {
            offset++; // opening quote
            StringBuilder out = new StringBuilder();
            while (true) {
                if (atEnd()) {
                    throw new IllegalArgumentException("unterminated string");
                }
                char c = text.charAt(offset++);
                if (c == '"') {
                    return out.toString();
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (atEnd()) {
                    throw new IllegalArgumentException("unterminated escape");
                }
                char esc = text.charAt(offset++);
                switch (esc) {
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    case '/' -> out.append('/');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (offset + 4 > text.length()) {
                            throw new IllegalArgumentException("truncated unicode escape");
                        }
                        String hex = text.substring(offset, offset + 4);
                        offset += 4;
                        try {
                            out.append((char) Integer.parseInt(hex, 16));
                        } catch (NumberFormatException e) {
                            throw new IllegalArgumentException("bad unicode escape: \\u" + hex);
                        }
                    }
                    default -> throw new IllegalArgumentException("bad escape: \\" + esc);
                }
            }
        }

        private Object readLiteral(String literal, Object value) {
            if (!text.startsWith(literal, offset)) {
                throw new IllegalArgumentException("bad literal at offset " + offset);
            }
            offset += literal.length();
            return value;
        }

        private Object readNumber() {
            int start = offset;
            if (!atEnd() && (text.charAt(offset) == '-' || text.charAt(offset) == '+')) {
                offset++;
            }
            while (!atEnd()) {
                char c = text.charAt(offset);
                if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    offset++;
                } else {
                    break;
                }
            }
            String raw = text.substring(start, offset);
            if (raw.isEmpty()) {
                throw new IllegalArgumentException("expected a value at offset " + start);
            }
            try {
                if (raw.indexOf('.') < 0 && raw.indexOf('e') < 0 && raw.indexOf('E') < 0) {
                    return Long.parseLong(raw);
                }
                return Double.parseDouble(raw);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("bad number: " + raw);
            }
        }
    }
}
