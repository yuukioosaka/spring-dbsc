package click.yukio.dbsc.crypto;

import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.Json;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Map;

/**
 * Signature verification for the two key shapes DBSC accepts. Every entry point
 * converts an inbound JWK to a {@link PublicKey} and verifies raw JWS-style
 * signatures.
 */
public final class SignatureVerifier {

    private static final ECParameterSpec P256 = p256Spec();

    private SignatureVerifier() {
    }

    /**
     * Verifies an ECDSA P-256 signature (raw {@code r||s} bytes, base64url) over
     * the ASCII bytes of {@code message}.
     *
     * @throws DbscException {@code INVALID_JWK} when the JWK will not import as
     *         ES256
     */
    public static boolean verifyP256(Map<String, Object> jwk, String signatureB64Url, String message) {
        PublicKey key = importEc(jwk);
        byte[] signature = decodeSignature(signatureB64Url);
        return verifyRaw(key, "SHA256withECDSA", signature, message, true);
    }

    /**
     * Verifies a JWS signature over {@code signingInput} using the algorithm
     * declared in the JWS protected header.
     *
     * @throws DbscException {@code INVALID_JWK} when the key will not import
     */
    public static boolean verifyJwsSignature(
            Map<String, Object> jwk, DbscAlgorithm algorithm, byte[] signature, String signingInput) {
        PublicKey key = switch (algorithm) {
            case ES256 -> importEc(jwk);
            case RS256 -> importRsa(jwk);
        };
        String jcaAlgorithm = algorithm == DbscAlgorithm.ES256 ? "SHA256withECDSA" : "SHA256withRSA";
        return verifyRaw(key, jcaAlgorithm, signature, signingInput, algorithm == DbscAlgorithm.ES256);
    }

    private static boolean verifyRaw(
            PublicKey key, String jcaAlgorithm, byte[] signature, String message, boolean rawEcdsa) {
        try {
            Signature verifier = Signature.getInstance(jcaAlgorithm);
            verifier.initVerify(key);
            verifier.update(message.getBytes(StandardCharsets.US_ASCII));
            byte[] encoded = rawEcdsa ? rawToDer(signature) : signature;
            return verifier.verify(encoded);
        } catch (java.security.GeneralSecurityException e) {
            // A malformed signature is a failed verification, not a server error.
            return false;
        }
    }

    /**
     * Converts a fixed-width 64-byte {@code r||s} ECDSA signature (the JWS form)
     * into the DER SEQUENCE that {@code Signature} expects.
     */
    public static byte[] rawToDer(byte[] raw) {
        if (raw.length != 64) {
            throw new IllegalArgumentException("expected a 64-byte P-256 signature, got " + raw.length);
        }
        BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(raw, 0, 32));
        BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(raw, 32, 64));
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();
        int contentLength = 2 + rBytes.length + 2 + sBytes.length;
        byte[] der = new byte[2 + contentLength];
        int i = 0;
        der[i++] = 0x30; // SEQUENCE
        der[i++] = (byte) contentLength;
        der[i++] = 0x02; // INTEGER
        der[i++] = (byte) rBytes.length;
        System.arraycopy(rBytes, 0, der, i, rBytes.length);
        i += rBytes.length;
        der[i++] = 0x02;
        der[i++] = (byte) sBytes.length;
        System.arraycopy(sBytes, 0, der, i, sBytes.length);
        return der;
    }

    private static byte[] decodeSignature(String signatureB64Url) {
        byte[] decoded = Base64Url.tryDecode(signatureB64Url);
        if (decoded == null) {
            throw DbscException.signatureInvalid("signature is not valid base64url");
        }
        return decoded;
    }

    public static PublicKey importEc(Map<String, Object> jwk) {
        String x = Json.string(jwk, "x");
        String y = Json.string(jwk, "y");
        byte[] xBytes = x == null ? null : Base64Url.tryDecode(x);
        byte[] yBytes = y == null ? null : Base64Url.tryDecode(y);
        if (xBytes == null || yBytes == null) {
            throw DbscException.invalidJwk("EC key coordinates are not valid base64url");
        }
        try {
            ECPoint point = new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, P256));
        } catch (java.security.GeneralSecurityException e) {
            throw DbscException.invalidJwk("EC key did not import as P-256: " + e.getMessage());
        }
    }

    public static PublicKey importRsa(Map<String, Object> jwk) {
        String n = Json.string(jwk, "n");
        String e = Json.string(jwk, "e");
        byte[] nBytes = n == null ? null : Base64Url.tryDecode(n);
        byte[] eBytes = e == null ? null : Base64Url.tryDecode(e);
        if (nBytes == null || eBytes == null) {
            throw DbscException.invalidJwk("RSA key parameters are not valid base64url");
        }
        try {
            return KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(new BigInteger(1, nBytes), new BigInteger(1, eBytes)));
        } catch (java.security.GeneralSecurityException ex) {
            throw DbscException.invalidJwk("RSA key did not import: " + ex.getMessage());
        }
    }

    /**
     * Reduces a JWK to the public members of its declared key type, so a stored or
     * echoed key can never carry anything an importer could be persuaded to use.
     *
     * <p>This is an <strong>allowlist, deliberately</strong>. Dropping a known set of
     * private fields is not enough: a JWK may carry members belonging to a
     * <em>different</em> key type (an RSA {@code n}/{@code e} alongside
     * {@code kty:"EC"}), and a denylist would let those survive. Since
     * {@link SignatureVerifier#verifyJwsSignature} selects its importer from the
     * algorithm named in an attacker-controlled JWS header, anything that survives
     * here can later be selected as a verification key. Keeping only the members
     * that the declared {@code kty} actually uses removes the discrepancy.
     */
    public static Map<String, Object> publicOnly(Map<String, Object> jwk) {
        Map<String, Object> out = new java.util.LinkedHashMap<>();
        if (jwk == null) {
            return out;
        }
        String kty = Json.string(jwk, "kty");
        out.put("kty", kty);
        if ("EC".equals(kty)) {
            copy(jwk, out, "crv");
            copy(jwk, out, "x");
            copy(jwk, out, "y");
        } else if ("RSA".equals(kty)) {
            copy(jwk, out, "n");
            copy(jwk, out, "e");
        }
        return out;
    }

    private static void copy(Map<String, Object> from, Map<String, Object> to, String key) {
        if (from.containsKey(key)) {
            to.put(key, from.get(key));
        }
    }

    /**
     * The NIST P-256 (secp256r1) curve parameters, resolved once at class load.
     * An uninitialised {@code AlgorithmParameters} would yield a null curve, so
     * the parameters are always initialised from the named curve.
     */
    private static ECParameterSpec p256Spec() {
        try {
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("P-256 is required by the Java platform", e);
        }
    }

    /** @return whether the key derives from the P-256 curve. */
    public static boolean isP256(PublicKey key) {
        return key instanceof ECPublicKey ec && ec.getParams().getCurve().equals(P256.getCurve());
    }
}
