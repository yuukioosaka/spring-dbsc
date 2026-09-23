package click.yukio.dbsc.crypto;

import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.Json;

import java.util.Map;

/**
 * JWK validation and algorithm detection (spec 05).
 *
 * <p>A server MUST validate any inbound JWK before trusting it. Reject
 * ({@code INVALID_JWK}) any key that fails the rules below.
 */
public final class Jwk {

    private static final int MIN_RSA_BITS = 2048;

    private Jwk() {
    }

    /**
     * Validates an EC or RSA public JWK.
     *
     * <ul>
     *   <li>EC: {@code crv} MUST be {@code P-256}, both {@code x} and {@code y}
     *       present.</li>
     *   <li>RSA: {@code n} present, modulus at least 2048 bits.</li>
     *   <li>Any other {@code kty} is rejected.</li>
     * </ul>
     *
     * @throws DbscException {@code INVALID_JWK}
     */
    public static void validate(Map<String, Object> jwk) {
        if (jwk == null) {
            throw DbscException.invalidJwk("JWK is missing");
        }
        String kty = Json.string(jwk, "kty");
        if (kty == null) {
            throw DbscException.invalidJwk("JWK missing kty");
        }
        switch (kty) {
            case "EC" -> {
                String crv = Json.string(jwk, "crv");
                if (!"P-256".equals(crv)) {
                    throw DbscException.invalidJwk("unsupported curve: " + crv);
                }
                if (isBlank(Json.string(jwk, "x")) || isBlank(Json.string(jwk, "y"))) {
                    throw DbscException.invalidJwk("EC key missing x or y coordinate");
                }
            }
            case "RSA" -> {
                String n = Json.string(jwk, "n");
                if (isBlank(n)) {
                    throw DbscException.invalidJwk("RSA key missing modulus");
                }
                int bits = modulusBits(n);
                if (bits < MIN_RSA_BITS) {
                    throw DbscException.invalidJwk(
                            "RSA key too short: " + bits + " bits, minimum " + MIN_RSA_BITS);
                }
            }
            default -> throw DbscException.invalidJwk("unsupported key type: " + kty);
        }
    }

    /**
     * Determines the algorithm implied by a <em>validated</em> JWK.
     *
     * @throws DbscException {@code UNKNOWN_ALGORITHM}
     */
    public static DbscAlgorithm detectAlgorithm(Map<String, Object> jwk) {
        String kty = jwk == null ? null : Json.string(jwk, "kty");
        if ("EC".equals(kty) && "P-256".equals(Json.string(jwk, "crv"))) {
            return DbscAlgorithm.ES256;
        }
        if ("RSA".equals(kty)) {
            return DbscAlgorithm.RS256;
        }
        throw DbscException.unknownAlgorithm(
                "cannot determine algorithm for kty=" + kty + " crv="
                        + (jwk == null ? null : Json.string(jwk, "crv")));
    }

    /**
     * Bit length of an RSA modulus. JWK {@code n} is unpadded base64url, so the
     * leading byte's high bits determine the true bit length.
     *
     * <p>An undecodable (including padded) modulus has no meaningful bit length and
     * reports {@code 0}, which the size rule then rejects. Estimating a length from
     * the encoded characters instead would let a malformed {@code n} pass the
     * minimum-size check.
     */
    public static int modulusBits(String n) {
        if (n == null) {
            return 0;
        }
        byte[] raw = Base64Url.tryDecode(n);
        if (raw == null) {
            return 0;
        }
        int firstNonZero = 0;
        while (firstNonZero < raw.length && raw[firstNonZero] == 0) {
            firstNonZero++;
        }
        if (firstNonZero == raw.length) {
            return 0;
        }
        int leadingZeroBits = Integer.numberOfLeadingZeros(raw[firstNonZero] & 0xFF) - 24;
        return (raw.length - firstNonZero) * 8 - leadingZeroBits;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isEmpty();
    }
}
