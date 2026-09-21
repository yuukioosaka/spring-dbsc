package click.yukio.dbsc;

import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.Json;
import click.yukio.dbsc.crypto.DbscJws;
import click.yukio.dbsc.crypto.Jwk;
import click.yukio.dbsc.crypto.SignatureVerifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression tests for the algorithm-confusion hole in refresh verification.
 *
 * <p>The attack these pin down: JWS verification selects its key importer from the
 * {@code alg} in the attacker-supplied protected header, so if a stored key can be
 * interpreted as more than one type, the attacker chooses which. Registration
 * always checked that {@code alg} agreed with the key's shape, but refresh did
 * not, and the key stored at registration was whatever the JWK contained —
 * including members of a second key type.
 *
 * <p>Concretely: register a throwaway P-256 key (whose self-signature satisfies
 * registration) and smuggle an attacker-controlled RSA modulus and exponent
 * alongside it in the same JWK. That JWK is stored as the session's native key.
 * At refresh the attacker signs with {@code alg: RS256} using the RSA private key;
 * the server reads {@code n}/{@code e} out of the stored JWK, verifies happily,
 * and refreshes the session. No device key is needed at all, so a stolen cookie
 * survives the refresh that is supposed to kill it — the central DBSC guarantee.
 *
 * <p>Two independent fixes are asserted, because either one alone would close the
 * hole and both should stay closed.
 */
class AlgorithmConfusionTest {

    @Test
    @DisplayName("a JWK cannot smuggle members of a second key type past validation")
    void publicOnlyKeepsOnlyTheDeclaredKeyType() throws Exception {
        Map<String, Object> hybrid = hybridJwk();

        // Both halves are individually well-formed, so validation alone cannot
        // tell that this key is two keys at once.
        Jwk.validate(hybrid);

        Map<String, Object> stored = SignatureVerifier.publicOnly(hybrid);

        assertTrue(stored.containsKey("x") && stored.containsKey("y"),
                "the declared EC coordinates must survive");
        assertFalse(stored.containsKey("n"),
                "an RSA modulus must not survive on a kty=EC JWK: it is what the "
                        + "attacker's RS256 refresh would be verified against");
        assertFalse(stored.containsKey("e"),
                "an RSA exponent must not survive on a kty=EC JWK");
        assertTrue(stored.containsKey("kty") && stored.containsKey("crv"),
                "kty and crv are needed to import the key");
    }

    @Test
    @DisplayName("refresh is pinned to the registered key's algorithm, not the header's")
    void refreshRejectsAnAlgorithmTheStoredKeyDoesNotSupport() throws Exception {
        KeyPair rsa = rsaKeyPair();
        String token = rsaSignedRefresh(rsa);

        // The stored key would be the hybrid above; its kty is EC, so RS256 is not
        // an algorithm this session's key can ever justify.
        Map<String, Object> stored = hybridJwk();

        DbscException failure = assertThrows(DbscException.class,
                () -> DbscJws.verifyRefresh(token, stored, CHALLENGE),
                "an RS256 refresh against a registered EC key must not verify");

        assertTrue(failure.getMessage().contains("does not match the registered key")
                        || failure.code().name().contains("ALGORITHM"),
                "expected a mismatch about the algorithm, got: " + failure.getMessage());
    }

    @Test
    @DisplayName("the same RS256 refresh is accepted once the key really is RSA")
    void theAttackIsSpecificallyAboutTheKeyTypeMismatch() throws Exception {
        // Proves the rejection above comes from the kty/alg mismatch and not from
        // the RSA signature being malformed. Same token, honest RSA key: passes.
        KeyPair rsa = rsaKeyPair();
        String token = rsaSignedRefresh(rsa);

        Map<String, Object> rsaJwk = new LinkedHashMap<>();
        rsaJwk.put("kty", "RSA");
        rsaJwk.put("n", Base64Url.encode(unsigned(((RSAPublicKey) rsa.getPublic()).getModulus())));
        rsaJwk.put("e", Base64Url.encode(unsigned(
                ((RSAPublicKey) rsa.getPublic()).getPublicExponent())));

        DbscJws.Parsed parsed = DbscJws.verifyRefresh(token, rsaJwk, CHALLENGE);
        assertTrue(parsed.algorithm().wireValue().equals("RS256"));
    }

    private static final String CHALLENGE = "challenge-123";

    /** A P-256 key's coordinates plus a different RSA key's modulus and exponent. */
    private static Map<String, Object> hybridJwk() throws Exception {
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(new ECGenParameterSpec("secp256r1"));
        ECPublicKey ec = (ECPublicKey) ecGen.generateKeyPair().getPublic();

        RSAPublicKey rsa = (RSAPublicKey) rsaKeyPair().getPublic();

        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", Base64Url.encode(unsigned(ec.getW().getAffineX())));
        jwk.put("y", Base64Url.encode(unsigned(ec.getW().getAffineY())));
        jwk.put("n", Base64Url.encode(unsigned(rsa.getModulus())));
        jwk.put("e", Base64Url.encode(unsigned(rsa.getPublicExponent())));
        return jwk;
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    /** A well-formed refresh JWS declaring {@code alg: RS256}, signed with {@code rsa}. */
    private static String rsaSignedRefresh(KeyPair rsa) throws Exception {
        String header = Json.write(Map.of("alg", "RS256", "typ", "dbsc+jwt"));
        String payload = Json.write(Map.of("jti", CHALLENGE));
        String signingInput = Base64Url.encode(header.getBytes(StandardCharsets.US_ASCII))
                + "." + Base64Url.encode(payload.getBytes(StandardCharsets.US_ASCII));

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(rsa.getPrivate());
        signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + Base64Url.encode(signer.sign());
    }

    /** JWK members are unpadded base64url of the magnitude, with the sign byte removed. */
    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }
}
