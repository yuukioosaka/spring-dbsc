package click.yukio.dbsc;

import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.core.Json;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Loads the toolkit's language-neutral test vectors from the classpath.
 *
 * <p>The vectors are the conformance gate (spec 09): reconstructing the signed
 * message byte-for-byte and verifying the supplied signature is what proves an
 * implementation interoperates.
 */
final class TestVectors {

    private TestVectors() {
    }

    static Map<String, Object> load(String name) {
        String path = "/vectors/" + name + ".json";
        try (InputStream in = TestVectors.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException("missing test vector: " + path);
            }
            String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            return Json.parseObject(text);
        } catch (IOException e) {
            throw new IllegalStateException("failed to read test vector " + path, e);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> object(Map<String, Object> parent, String key) {
        Object value = parent.get(key);
        if (!(value instanceof Map)) {
            throw new IllegalStateException("vector has no object field: " + key);
        }
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    static List<Object> array(Map<String, Object> parent, String key) {
        Object value = parent.get(key);
        if (!(value instanceof List)) {
            throw new IllegalStateException("vector has no array field: " + key);
        }
        return (List<Object>) value;
    }

    static String string(Map<String, Object> parent, String key) {
        Object value = parent.get(key);
        if (!(value instanceof String s)) {
            throw new IllegalStateException("vector has no string field: " + key);
        }
        return s;
    }

    static long longValue(Map<String, Object> parent, String key) {
        Object value = parent.get(key);
        if (!(value instanceof Number n)) {
            throw new IllegalStateException("vector has no numeric field: " + key);
        }
        return n.longValue();
    }

    static boolean bool(Map<String, Object> parent, String key) {
        Object value = parent.get(key);
        if (!(value instanceof Boolean b)) {
            throw new IllegalStateException("vector has no boolean field: " + key);
        }
        return b;
    }

    /** Decodes a JWK's {@code d} parameter into the signing key, for fixtures. */
    static byte[] privateKeyBytes(Map<String, Object> privateJwk) {
        return Base64Url.decode(string(privateJwk, "d"));
    }
}
