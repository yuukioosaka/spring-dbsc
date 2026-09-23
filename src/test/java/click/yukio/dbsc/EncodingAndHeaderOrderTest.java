package click.yukio.dbsc;

import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.core.DbscErrorCode;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.Json;
import click.yukio.dbsc.crypto.DbscJws;
import click.yukio.dbsc.crypto.Jwk;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression tests for two conformance gaps found by reviewing the verifier
 * against the toolkit spec (05) and the W3C draft.
 *
 * <p>First: every binary value on the wire is base64url <em>without</em> padding,
 * but {@code java.util.Base64.getUrlDecoder()} silently accepts well-formed padded
 * input. One signature therefore had several distinct wire spellings, which is
 * exactly what the spec forbids.
 *
 * <p>Second: {@code verifyRefresh} resolved the header {@code alg} before checking
 * for a smuggled {@code jwk}, so a refresh that carried a key could be reported as
 * {@code UNKNOWN_ALGORITHM} instead of the protocol error it is.
 */
class EncodingAndHeaderOrderTest {

    // ---- base64url padding ----

    @Test
    @DisplayName("padded base64url is rejected by decode and tryDecode")
    void paddedBase64UrlIsRejected() {
        // "AQ==" and "AQI=" are well-formed padded base64url that Java's URL
        // decoder accepts; the spec says padding must never appear on the wire.
        assertThrows(IllegalArgumentException.class, () -> Base64Url.decode("AQ=="));
        assertThrows(IllegalArgumentException.class, () -> Base64Url.decode("AQI="));
        assertNull(Base64Url.tryDecode("AQ=="));
        assertNull(Base64Url.tryDecode("AQI="));

        // The unpadded forms still decode to the same bytes.
        assertEquals(1, Base64Url.decode("AQ").length);
        assertEquals(2, Base64Url.decode("AQI").length);
    }

    @Test
    @DisplayName("a padded signature segment is not a second spelling of a valid proof")
    void paddedSignatureIsRejected() throws Exception {
        KeyPair pair = p256KeyPair();
        Map<String, Object> jwk = publicJwk(pair);
        String jti = Base64Url.randomJti();

        String header = Base64Url.encode(Json.write(Map.of(
                "alg", "ES256", "typ", "dbsc+jwt", "jwk", jwk))
                .getBytes(StandardCharsets.UTF_8));
        String payload = Base64Url.encode(Json.write(Map.of("jti", jti))
                .getBytes(StandardCharsets.UTF_8));
        String signingInput = header + "." + payload;

        byte[] raw = rawSignature(pair, signingInput);
        String unpadded = Base64Url.encode(raw);
        String padded = Base64.getUrlEncoder().encodeToString(raw);

        // The padded form decodes to the same bytes, so it must be refused on the
        // wire rather than normalised: otherwise one proof has two spellings.
        assertFalse(padded.equals(unpadded), "the padded and unpadded forms differ as strings");

        DbscJws.verifyRegistration(signingInput + "." + unpadded);

        // The padded spelling of the same bytes must not be accepted: one proof
        // would otherwise have two distinct wire forms.
        DbscException failure = assertThrows(DbscException.class,
                () -> DbscJws.verifyRegistration(signingInput + "." + padded));
        assertEquals(DbscErrorCode.MALFORMED_JWS, failure.code());
    }

    @Test
    @DisplayName("a padded JWK coordinate is rejected as INVALID_JWK")
    void paddedJwkCoordinateIsRejected() {
        byte[] coordinate = new byte[32];
        String unpadded = Base64Url.encode(coordinate);
        String padded = Base64.getUrlEncoder().encodeToString(coordinate);

        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", padded);
        jwk.put("y", unpadded);

        // Jwk.validate only checks presence, so the rejection comes from the
        // importer -- pin that it happens at all.
        DbscException failure = assertThrows(DbscException.class,
                () -> click.yukio.dbsc.crypto.SignatureVerifier.importEc(jwk));
        assertEquals(DbscErrorCode.INVALID_JWK, failure.code());
    }

    @Test
    @DisplayName("an RSA modulus that will not decode reports zero bits, not an estimate")
    void undecodableModulusHasNoBitLength() {
        // A padded modulus must not be sized from its character count, which would
        // let a malformed key clear the 2048-bit floor.
        assertEquals(0, Jwk.modulusBits("AQ=="));
        assertTrue(Jwk.modulusBits("AQ") < 2048);
    }

    // ---- refresh jwk check ordering ----

    @Test
    @DisplayName("a refresh JWS carrying jwk fails as MALFORMED_JWS even with a bogus alg")
    void refreshWithJwkIsReportedAsMalformedFirst() throws Exception {
        KeyPair pair = p256KeyPair();
        Map<String, Object> jwk = publicJwk(pair);

        // Two faults at once: a smuggled key and an unsupported algorithm. The
        // protocol error is the `jwk`, and the reported code must say so rather
        // than depending on which header value happened to be read first.
        String header = Base64Url.encode(Json.write(Map.of(
                "alg", "HS256", "typ", "dbsc+jwt", "jwk", jwk))
                .getBytes(StandardCharsets.UTF_8));
        String payload = Base64Url.encode(Json.write(Map.of("jti", "x"))
                .getBytes(StandardCharsets.UTF_8));
        String token = header + "." + payload + "." + Base64Url.encode(new byte[64]);

        DbscException failure = assertThrows(DbscException.class,
                () -> DbscJws.verifyRefresh(token, jwk, "x"));
        assertEquals(DbscErrorCode.MALFORMED_JWS, failure.code());
    }

    // ---- fixtures ----

    private static KeyPair p256KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static Map<String, Object> publicJwk(KeyPair pair) {
        ECPublicKey key = (ECPublicKey) pair.getPublic();
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", Base64Url.encode(coordinate(key.getW().getAffineX().toByteArray())));
        jwk.put("y", Base64Url.encode(coordinate(key.getW().getAffineY().toByteArray())));
        return jwk;
    }

    /** Signature as raw {@code r||s}, which is what the JWS form carries. */
    private static byte[] rawSignature(KeyPair pair, String signingInput) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(pair.getPrivate());
        signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return derToRaw(signer.sign());
    }

    private static byte[] coordinate(byte[] value) {
        byte[] out = new byte[32];
        int from = Math.max(0, value.length - 32);
        System.arraycopy(value, from, out, 32 - (value.length - from), value.length - from);
        return out;
    }

    private static byte[] derToRaw(byte[] der) {
        int offset = 2;
        int rLen = der[offset + 1] & 0xFF;
        int rStart = offset + 2;
        while (rLen > 32 && der[rStart] == 0) {
            rStart++;
            rLen--;
        }
        int sOffset = rStart + rLen;
        int sLen = der[sOffset + 1] & 0xFF;
        int sStart = sOffset + 2;
        while (sLen > 32 && der[sStart] == 0) {
            sStart++;
            sLen--;
        }
        byte[] raw = new byte[64];
        System.arraycopy(der, rStart, raw, 32 - rLen, rLen);
        System.arraycopy(der, sStart, raw, 64 - sLen, sLen);
        return raw;
    }
}
