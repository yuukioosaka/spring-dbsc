package click.yukio.dbsc.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Base64url (unpadded) and SHA-256 helpers. Every binary value DBSC puts on the
 * wire is base64url without padding, so this class is the single place that
 * knowledge lives.
 */
public final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
    private static final SecureRandom RANDOM = new SecureRandom();

    private Base64Url() {
    }

    public static String encode(byte[] bytes) {
        return ENCODER.encodeToString(bytes);
    }

    /**
     * Decodes unpadded base64url. Padding is rejected.
     *
     * <p>Java's URL decoder also accepts well-formed padded input, which would let
     * one signature travel as several distinct wire strings. The spec is explicit
     * that every binary value on the wire is base64url <strong>without</strong>
     * padding, so {@code =} is refused here rather than normalised away.
     *
     * @throws IllegalArgumentException if the input is padded or not valid
     *         base64url
     */
    public static byte[] decode(String value) {
        if (value == null) {
            throw new IllegalArgumentException("null base64url input");
        }
        if (value.indexOf('=') >= 0) {
            throw new IllegalArgumentException("base64url must not be padded: " + value);
        }
        return DECODER.decode(value);
    }

    /** Decodes leniently, returning {@code null} instead of throwing. */
    public static byte[] tryDecode(String value) {
        if (value == null) {
            return null;
        }
        try {
            return decode(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public static String encodeUtf8(String value) {
        return encode(value.getBytes(StandardCharsets.UTF_8));
    }

    /** 32 cryptographically random bytes, base64url encoded (43 characters). */
    public static String randomJti() {
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        return encode(raw);
    }

    public static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", e);
        }
    }

    /** {@code base64url(sha256(input))} — the {@code bh} value of a proof header. */
    public static String sha256Base64Url(byte[] input) {
        return encode(sha256(input));
    }
}
