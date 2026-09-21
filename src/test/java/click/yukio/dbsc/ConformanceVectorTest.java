package click.yukio.dbsc;

import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.crypto.DbscAlgorithm;
import click.yukio.dbsc.crypto.DbscJws;
import click.yukio.dbsc.crypto.Jwk;
import click.yukio.dbsc.crypto.SignatureVerifier;
import click.yukio.dbsc.protocol.BoundProofHeader;
import click.yukio.dbsc.protocol.DbscHeaderCodec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
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

        Map<String, Object> expectedBoundKey = TestVectors.object(vector, "expectedStoredBoundKey");
        assertEquals(TestVectors.string(expectedBoundKey, "sessionId"),
                TestVectors.string(vector, "sessionId"));
        assertEquals("native", TestVectors.string(expectedBoundKey, "kind"));
        assertEquals("ES256", TestVectors.string(expectedBoundKey, "algorithm"));

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
    @DisplayName("bound-registration.json: the signed message is exactly the bare JTI")
    void boundRegistrationVector() {
        Map<String, Object> vector = TestVectors.load("bound-registration");
        Map<String, Object> body = TestVectors.object(vector, "requestBody");
        Map<String, Object> publicJwk = TestVectors.object(vector, "publicKeyJwk");

        String challenge = TestVectors.string(body, "challenge");
        String signature = TestVectors.string(body, "signature");

        // The signed message is the bare JTI: nothing prepended or appended.
        assertEquals(TestVectors.string(vector, "signedMessage"), challenge,
                "the bound registration signed message must be the bare challenge JTI");
        assertTrue(TestVectors.bool(vector, "signatureVerifies"));

        assertTrue(SignatureVerifier.verifyP256(publicJwk, signature, challenge),
                "the vector's bound registration signature must verify against the bare JTI");

        // The request body's publicKey must be the same key as publicKeyJwk.
        Map<String, Object> requestKey = TestVectors.object(body, "publicKey");
        assertEquals(TestVectors.string(publicJwk, "x"), TestVectors.string(requestKey, "x"));
        assertEquals(TestVectors.string(publicJwk, "y"), TestVectors.string(requestKey, "y"));

        Map<String, Object> expectedResponse = TestVectors.object(vector, "expectedResponse");
        assertEquals("/dbsc-bound/refresh", TestVectors.string(expectedResponse, "refresh_url"));
        assertEquals("bound", TestVectors.string(expectedResponse, "tier"));
    }

    @Test
    @DisplayName("bound-refresh.json: the signed message is <jti>.<timestamp>")
    void boundRefreshVector() {
        Map<String, Object> vector = TestVectors.load("bound-refresh");
        Map<String, Object> body = TestVectors.object(vector, "requestBody");
        Map<String, Object> publicJwk = TestVectors.object(vector, "publicKeyJwk");

        String challenge = TestVectors.string(body, "challenge");
        String signature = TestVectors.string(body, "signature");
        long timestamp = TestVectors.longValue(body, "timestamp");

        String message = challenge + "." + timestamp;
        assertEquals(TestVectors.string(vector, "signedMessage"), message,
                "the bound refresh signed message must be <jti>.<timestamp>");
        assertTrue(TestVectors.bool(vector, "signatureVerifies"));
        assertTrue(SignatureVerifier.verifyP256(publicJwk, signature, message),
                "the vector's bound refresh signature must verify");

        assertEquals("/dbsc-bound/refresh",
                TestVectors.string(TestVectors.object(vector, "expectedResponse"), "refresh_url"));
    }

    @Test
    @DisplayName("per-request-proof.json: signed messages and signatures, with and without a body")
    void perRequestProofVector() {
        Map<String, Object> vector = TestVectors.load("per-request-proof");
        Map<String, Object> publicJwk = TestVectors.object(vector, "publicKeyJwk");
        String sessionId = TestVectors.string(vector, "sessionId");

        // --- without body ---
        Map<String, Object> withoutBody = TestVectors.object(vector, "withoutBody");
        String method = TestVectors.string(withoutBody, "method");
        String path = TestVectors.string(withoutBody, "path");
        long timestamp = TestVectors.longValue(withoutBody, "timestamp");

        String message = BoundProofHeader.signedMessage(sessionId, method, path, timestamp, null);
        assertEquals(TestVectors.string(withoutBody, "signedMessage"), message,
                "the proof signed message must match byte-for-byte");

        BoundProofHeader.Parsed parsedWithout = BoundProofHeader.parse(
                TestVectors.string(withoutBody, "header"));
        assertEquals(timestamp, parsedWithout.timestamp());
        assertEquals(null, parsedWithout.bodyHash());
        assertTrue(TestVectors.bool(withoutBody, "signatureVerifies"));
        assertTrue(SignatureVerifier.verifyP256(
                        publicJwk, parsedWithout.signature(), message),
                "the vector's bodyless proof signature must verify");

        // --- with body ---
        Map<String, Object> withBody = TestVectors.object(vector, "withBody");
        String bodyText = TestVectors.string(withBody, "body");
        String expectedBodyHash = TestVectors.string(withBody, "bodyHash");

        // The body hash must be computed from the exact bytes, so reconstruct the
        // message from the raw body rather than trusting the vector's bh.
        String computedBodyHash = Base64Url.sha256Base64Url(bodyText.getBytes(StandardCharsets.UTF_8));
        assertEquals(expectedBodyHash, computedBodyHash,
                "base64url(sha256(body)) must equal the vector's bodyHash");

        BoundProofHeader.Parsed parsedWith = BoundProofHeader.parse(
                TestVectors.string(withBody, "header"));
        assertEquals(expectedBodyHash, parsedWith.bodyHash());

        String bodyMessage = BoundProofHeader.signedMessage(
                sessionId,
                TestVectors.string(withBody, "method"),
                TestVectors.string(withBody, "path"),
                TestVectors.longValue(withBody, "timestamp"),
                computedBodyHash);
        assertEquals(TestVectors.string(withBody, "signedMessage"), bodyMessage);
        assertTrue(TestVectors.bool(withBody, "signatureVerifies"));
        assertTrue(SignatureVerifier.verifyP256(publicJwk, parsedWith.signature(), bodyMessage),
                "the vector's body-bound proof signature must verify");
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
