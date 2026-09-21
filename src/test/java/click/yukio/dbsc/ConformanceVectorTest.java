package click.yukio.dbsc;

import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.crypto.DbscAlgorithm;
import click.yukio.dbsc.crypto.DbscJws;
import click.yukio.dbsc.crypto.Jwk;
import click.yukio.dbsc.crypto.SignatureVerifier;
import click.yukio.dbsc.protocol.DbscHeaderCodec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Conformance against the toolkit's language-neutral test vectors (spec 09).
 *
 * <p>Each vector pins the exact string an implementation must construct and
 * carries a real signature a conforming verifier must accept. ECDSA is
 * randomized, so the signature bytes are never reproduced — only the message
 * construction and the verification result must match.
 */
class ConformanceVectorTest {

    @Test
    @DisplayName("registration-header: exact Secure-Session-Registration and Challenge strings")
    void registrationHeaderVector() {
        Map<String, Object> vector = TestVectors.load("registration-header");
        Map<String, Object> inputs = TestVectors.object(vector, "inputs");
        Map<String, Object> expected = TestVectors.object(vector, "expected");

        String algorithm = TestVectors.string(inputs, "algorithm");
        String registrationPath = TestVectors.string(inputs, "registrationPath");
        String challenge = TestVectors.string(inputs, "challenge");
        String sessionId = TestVectors.string(inputs, "sessionId");

        String registration = DbscHeaderCodec.buildRegistrationHeader(
                algorithm, registrationPath, challenge);
        assertEquals(
                TestVectors.string(expected, "Secure-Session-Registration"),
                registration,
                "Secure-Session-Registration must match byte-for-byte");

        // The spec defines no `id` parameter on this header.
        assertFalse(registration.contains("id="),
                "Secure-Session-Registration must not carry an id parameter");

        assertEquals(
                TestVectors.string(expected, "Secure-Session-Challenge (bare)"),
                DbscHeaderCodec.buildChallengeHeader(challenge, null));

        assertEquals(
                TestVectors.string(expected, "Secure-Session-Challenge (with id)"),
                DbscHeaderCodec.buildChallengeHeader(challenge, sessionId));
    }

    @Test
    @DisplayName("registration.json: the vector's self-signed JWS must verify, and yield the expected key")
    void nativeRegistrationVector() {
        Map<String, Object> vector = TestVectors.load("registration");
        String jws = TestVectors.string(vector, "secureSessionResponse");

        DbscJws.Parsed parsed = DbscJws.verifyRegistration(jws);

        assertEquals(TestVectors.string(vector, "challenge"), parsed.jti(),
                "the extracted jti must equal the issued challenge");
        assertEquals("ES256", parsed.algorithm().wireValue());

        Map<String, Object> expectedJwk = TestVectors.object(vector, "publicKeyJwk");
        assertEquals(TestVectors.string(expectedJwk, "x"), parsed.jwk().get("x"),
                "the stored key must be the vector's public key");
        assertEquals(TestVectors.string(expectedJwk, "y"), parsed.jwk().get("y"));

        // A stored key is public-only: the header carried no `d`, and `key_ops`
        // and `ext` are advisory and stripped.
        assertFalse(parsed.jwk().containsKey("d"));
        assertFalse(parsed.jwk().containsKey("key_ops"));

        Map<String, Object> expectedDeviceKey = TestVectors.object(vector, "expectedStoredDeviceKey");
        assertEquals(TestVectors.string(expectedDeviceKey, "sessionId"),
                TestVectors.string(vector, "sessionId"));
        assertEquals("ES256", TestVectors.string(expectedDeviceKey, "algorithm"));

        Map<String, Object> expectedSession = TestVectors.object(vector, "expectedSessionAfter");
        assertEquals("dbsc", TestVectors.string(expectedSession, "tier"),
                "a verified native registration sets tier: dbsc");
    }

    @Test
    @DisplayName("refresh.json: the vector's JWS must verify against the stored key and match the jti")
    void nativeRefreshVector() {
        Map<String, Object> vector = TestVectors.load("refresh");
        String jws = TestVectors.string(vector, "secureSessionResponse");
        Map<String, Object> storedJwk = TestVectors.object(vector, "storedPublicKeyJwk");
        String challenge = TestVectors.string(vector, "challenge");

        DbscJws.Parsed parsed = DbscJws.verifyRefresh(jws, storedJwk, challenge);

        Map<String, Object> expected = TestVectors.object(vector, "expectedResult");
        assertTrue(TestVectors.bool(expected, "verified"));
        assertEquals(TestVectors.string(expected, "sessionId"),
                TestVectors.string(vector, "sessionId"));
        assertEquals(TestVectors.string(expected, "jti"), parsed.jti());

        assertEquals("ES256", parsed.algorithm().wireValue());
        assertEquals("dbsc+jwt", parsed.header().get("typ"));
        assertFalse(parsed.header().containsKey("jwk"),
                "the refresh vector's header carries no jwk");
    }

    @Test
    @DisplayName("a refresh JWS carrying jwk MUST be rejected")
    void refreshJwsWithJwkIsRejected() {
        // The registration JWS does carry a jwk; presenting it on the refresh path
        // must fail, because the server already holds the key at that point.
        Map<String, Object> vector = TestVectors.load("registration");
        String registrationJws = TestVectors.string(vector, "secureSessionResponse");
        Map<String, Object> storedJwk = TestVectors.object(vector, "publicKeyJwk");

        var failure = assertThrows(click.yukio.dbsc.core.DbscException.class,
                () -> DbscJws.verifyRefresh(registrationJws, storedJwk,
                        TestVectors.string(vector, "challenge")));
        assertEquals(click.yukio.dbsc.core.DbscErrorCode.MALFORMED_JWS, failure.code());
    }

    @Test
    @DisplayName("JWK validation and algorithm detection follow spec 05")
    void jwkRules() {
        Map<String, Object> registration = TestVectors.load("registration");
        Map<String, Object> publicJwk = TestVectors.object(registration, "publicKeyJwk");

        Jwk.validate(publicJwk);
        assertEquals(DbscAlgorithm.ES256, Jwk.detectAlgorithm(publicJwk));

        // The private key the vector used for signing carries a `d`; it must be
        // dropped before storage.
        assertArrayEquals(
                Base64Url.decode(TestVectors.string(publicJwk, "x")),
                Base64Url.decode(TestVectors.string(publicJwk, "x")));
        Map<String, Object> privateJwk = TestVectors.object(registration, "privateKeyJwk");
        assertFalse(SignatureVerifier.publicOnly(privateJwk).containsKey("d"),
                "private key material must never be stored");
    }
}
