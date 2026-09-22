package click.yukio.dbsc.crypto;

import click.yukio.dbsc.core.Base64Url;
import click.yukio.dbsc.core.DbscException;
import click.yukio.dbsc.core.Json;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Compact JWS parsing and verification for the native DBSC protocol (spec 05).
 *
 * <p>A native proof is {@code <protected>.<payload>.<signature>}, each segment
 * unpadded base64url. The signature covers the ASCII bytes of
 * {@code <protected>.<payload>} — the first two segments and the joining dot.
 */
public final class DbscJws {

    private static final String DBSC_TYPE = "dbsc+jwt";

    private DbscJws() {
    }

    /**
     * The decoded claims and key of a native JWS.
     *
     * @param jti       the {@code jti} claim
     * @param jwk       the embedded public key, for registration; {@code null} for refresh
     * @param algorithm the algorithm from the protected header
     * @param header    the raw protected header
     * @param payload   the raw payload
     */
    public record Parsed(String jti, Map<String, Object> jwk, DbscAlgorithm algorithm,
                         Map<String, Object> header, Map<String, Object> payload) {
    }

    /**
     * Verifies a <strong>registration</strong> JWS: self-signed, with the public
     * key carried in the protected header.
     *
     * <p>Ordered per spec 05: decode header, check {@code typ}, check
     * {@code alg}, extract {@code jwk}, validate the JWK, confirm the header
     * {@code alg} matches the key shape, then verify the self-signature.
     *
     * @throws DbscException with the code for whichever step failed
     */
    public static Parsed verifyRegistration(String token) {
        Segments segments = Segments.split(token);
        Map<String, Object> header = decodeJson(segments.protectedHeader(), "JWS header");
        Map<String, Object> payload = decodeJson(segments.payload(), "JWS payload");

        if (!DBSC_TYPE.equals(Json.string(header, "typ"))) {
            throw DbscException.malformedJws(
                    "expected typ=" + DBSC_TYPE + ", got " + Json.string(header, "typ"));
        }
        DbscAlgorithm algorithm = parseAlgorithm(header);

        Map<String, Object> jwk = Json.object(header, "jwk");
        if (jwk == null) {
            throw DbscException.malformedJws("registration JWS missing jwk in header");
        }
        Jwk.validate(jwk);

        DbscAlgorithm detected = Jwk.detectAlgorithm(jwk);
        if (detected != algorithm) {
            throw DbscException.unknownAlgorithm(
                    "algorithm " + algorithm.wireValue()
                            + " does not match JWK shape (expected " + detected.wireValue() + ")");
        }

        String jti = requireJti(payload);
        if (!SignatureVerifier.verifyJwsSignature(
                jwk, algorithm, segments.signature(), segments.signingInput())) {
            throw DbscException.signatureInvalid("registration JWS self-signature invalid");
        }
        return new Parsed(jti, SignatureVerifier.publicOnly(jwk), algorithm, header, payload);
    }

    /**
     * Verifies a <strong>refresh</strong> JWS against the stored registration key.
     *
     * <p>A refresh JWS that includes a {@code jwk} is a protocol error and MUST be
     * rejected — the server already holds the key.
     *
     * @param expectedJti the challenge the server issued for this refresh
     * @throws DbscException with the code for whichever step failed
     */
    public static Parsed verifyRefresh(String token, Map<String, Object> storedJwk, String expectedJti) {
        Segments segments = Segments.split(token);
        Map<String, Object> header = decodeJson(segments.protectedHeader(), "JWS header");
        Map<String, Object> payload = decodeJson(segments.payload(), "JWS payload");

        if (!DBSC_TYPE.equals(Json.string(header, "typ"))) {
            throw DbscException.malformedJws(
                    "expected typ=" + DBSC_TYPE + ", got " + Json.string(header, "typ"));
        }
        DbscAlgorithm algorithm = parseAlgorithm(header);

        if (Json.object(header, "jwk") != null) {
            throw DbscException.malformedJws("refresh JWS must not carry a jwk header parameter");
        }

        String jti = requireJti(payload);

        // The algorithm must come from the key the server stored, never from the
        // JWS header. Dispatching on the header alone lets an attacker sign with a
        // key type of their choosing: a stored EC key that also carried RSA n/e
        // members would otherwise be importable as RSA, and a stolen cookie with
        // no device key at all could then be refreshed indefinitely. Registration
        // pins this the same way; the check has to be repeated here because the
        // stored key is read back from storage on every refresh.
        Jwk.validate(storedJwk);
        DbscAlgorithm expected = Jwk.detectAlgorithm(storedJwk);
        if (expected != algorithm) {
            throw DbscException.unknownAlgorithm(
                    "algorithm " + algorithm.wireValue()
                            + " does not match the registered key (expected "
                            + expected.wireValue() + ")");
        }

        if (!SignatureVerifier.verifyJwsSignature(
                storedJwk, algorithm, segments.signature(), segments.signingInput())) {
            throw DbscException.signatureInvalid("JWS signature verification failed");
        }
        if (!jti.equals(expectedJti)) {
            throw DbscException.jtiMismatch("jti does not match issued challenge");
        }
        return new Parsed(jti, null, algorithm, header, payload);
    }

    /** Decodes only the protected header, without verifying anything. */
    public static Map<String, Object> decodeProtectedHeader(String token) {
        return decodeJson(Segments.split(token).protectedHeader(), "JWS header");
    }

    /**
     * Reads the {@code jti} claim without verifying the signature.
     *
     * <p>This is <strong>not</strong> an authorisation check and must never be used as
     * one. It exists because the challenge a proof is checked against has to be found
     * from the value the client signed, and the only place that value appears is the
     * unverified payload. Nothing is trusted by reading it here: the resolved challenge
     * is compared back against the same claim after the signature verifies, so a
     * tampered {@code jti} fails signature verification, and a mismatch fails as
     * {@code JTI_MISMATCH}.
     *
     * @throws DbscException {@code MALFORMED_JWS} when the token is not a JWS or carries
     *         no {@code jti}
     */
    public static String unverifiedJti(String token) {
        return requireJti(decodeJson(Segments.split(token).payload(), "JWS payload"));
    }

    private static DbscAlgorithm parseAlgorithm(Map<String, Object> header) {
        String alg = Json.string(header, "alg");
        DbscAlgorithm algorithm = DbscAlgorithm.fromWire(alg);
        if (algorithm == null) {
            throw DbscException.unknownAlgorithm("unsupported algorithm: " + alg);
        }
        return algorithm;
    }

    private static String requireJti(Map<String, Object> payload) {
        String jti = Json.string(payload, "jti");
        if (jti == null) {
            throw DbscException.malformedJws("missing jti claim");
        }
        return jti;
    }

    private static Map<String, Object> decodeJson(String raw, String what) {
        byte[] decoded = Base64Url.tryDecode(raw);
        if (decoded == null) {
            throw DbscException.malformedJws(what + " is not valid base64url");
        }
        Map<String, Object> parsed = Json.tryParseObject(new String(decoded, StandardCharsets.UTF_8));
        if (parsed == null) {
            throw DbscException.malformedJws(what + " is not a JSON object");
        }
        return parsed;
    }

    /** The three raw segments of a compact JWS plus the signed input. */
    private record Segments(String protectedHeader, String payload, byte[] signature, String signingInput) {

        static Segments split(String token) {
            if (token == null) {
                throw DbscException.malformedJws("JWS token is missing");
            }
            String trimmed = token.trim();
            int firstDot = trimmed.indexOf('.');
            int secondDot = firstDot < 0 ? -1 : trimmed.indexOf('.', firstDot + 1);
            if (firstDot <= 0 || secondDot < 0 || trimmed.indexOf('.', secondDot + 1) >= 0) {
                throw DbscException.malformedJws("JWS is not a three-segment compact serialization");
            }
            String header = trimmed.substring(0, firstDot);
            String payload = trimmed.substring(firstDot + 1, secondDot);
            String signatureRaw = trimmed.substring(secondDot + 1);
            if (signatureRaw.isEmpty()) {
                throw DbscException.malformedJws("JWS signature segment is empty");
            }
            byte[] signature = Base64Url.tryDecode(signatureRaw);
            if (signature == null) {
                throw DbscException.malformedJws("JWS signature is not valid base64url");
            }
            return new Segments(header, payload, signature, header + "." + payload);
        }
    }
}
