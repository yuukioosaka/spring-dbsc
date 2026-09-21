package click.yukio.dbsc;

import click.yukio.dbsc.core.BoundKey;
import click.yukio.dbsc.core.BoundKeyKind;
import click.yukio.dbsc.core.Challenge;
import click.yukio.dbsc.core.Json;
import click.yukio.dbsc.core.ProtectionTier;
import click.yukio.dbsc.core.Session;
import click.yukio.dbsc.core.StorageAdapter;
import click.yukio.dbsc.crypto.SignatureVerifier;
import click.yukio.dbsc.protocol.CookieScope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * End-to-end HTTP tests over the real filter chain, verifying the status codes
 * and response shapes Chromium depends on.
 *
 * <p>These are the rules a wrong answer silently kills a session over: 403 (not
 * 401) on an unproven refresh, and a JSON body on every 200.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class HttpFlowTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private StorageAdapter storage;

    @Autowired
    private CookieScope cookieScope;

    @Autowired
    private Clock dbscClock;

    // ------------------------------------------------------------------
    // Login / bind
    // ------------------------------------------------------------------

    @Test
    @DisplayName("login: bind() sets the registration header (both names) and the two cookies")
    void loginBinds() throws Exception {
        MvcResult result = login();
        var response = result.getResponse();

        String registration = response.getHeader("Secure-Session-Registration");
        assertNotNull(registration, "Chromium only starts a session when this header is present");
        assertTrue(registration.startsWith("(ES256);path=\"/dbsc/registration\";challenge=\""),
                registration);
        assertFalse(registration.contains("id="), "this header carries no id parameter");

        // Some Chromium builds straddle the rename, so the legacy name is emitted too.
        assertEquals(registration, response.getHeader("Sec-Session-Registration"));

        List<String> cookies = response.getHeaders("Set-Cookie");
        assertTrue(cookies.stream().anyMatch(c -> c.startsWith(cookieScope.registrationCookieName() + "=")),
                "the registration cookie must be set: " + cookies);
        assertTrue(cookies.stream().anyMatch(c -> c.startsWith(cookieScope.challengeCookieName() + "=")),
                "the challenge cookie must be set: " + cookies);
    }

    // ------------------------------------------------------------------
    // Native registration
    // ------------------------------------------------------------------

    @Test
    @DisplayName("registration: a valid JWS is 200 + JSON config + fresh binding cookie")
    void registrationSucceeds() throws Exception {
        LoginState login = loginWithState();
        // The browser signs the JTI from the registration header with a new key.
        TestKey key = TestKey.generate();
        String jws = key.registrationJws(login.challenge(), login.sessionId());

        MvcResult result = mvc.perform(post("/dbsc/registration")
                        .header("Secure-Session-Response", jws)
                        .cookie(login.registrationCookie(), login.challengeCookie()))
                .andReturn();

        var response = result.getResponse();
        assertEquals(200, response.getStatus());

        Map<String, Object> config = Json.parseObject(response.getContentAsString());
        assertEquals(login.sessionId(), config.get("session_identifier"));
        assertEquals("/dbsc/refresh", config.get("refresh_url"));

        // The JSON body is mandatory: a 200 without it is read as an opt-out.
        Map<String, Object> scope = Json.object(config, "scope");
        assertNotNull(scope.get("include_site"), "scope.include_site is required");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) config.get("credentials");
        assertEquals(1, credentials.size());
        assertEquals(cookieScope.bindingCookieName(), credentials.get(0).get("name"));
        // This MUST equal the real Set-Cookie attributes byte-for-byte.
        assertEquals(cookieScope.attributesString(), credentials.get(0).get("attributes"));

        List<String> cookies = response.getHeaders("Set-Cookie");
        assertTrue(cookies.stream().anyMatch(c -> c.startsWith(cookieScope.bindingCookieName() + "=sess_")),
                "a fresh binding cookie must be set: " + cookies);
        assertTrue(cookies.stream().anyMatch(c -> c.startsWith(cookieScope.challengeCookieName() + "=;")
                        && c.contains("Max-Age=0")),
                "the challenge cookie must be cleared: " + cookies);

        assertEquals(ProtectionTier.DBSC, storage.getSession(login.sessionId()).orElseThrow().tier());
    }

    @Test
    @DisplayName("registration: no Secure-Session-Response is 403, not 500 or 401")
    void registrationWithoutProof() throws Exception {
        LoginState login = loginWithState();

        MvcResult result = mvc.perform(post("/dbsc/registration")
                        .cookie(login.registrationCookie(), login.challengeCookie()))
                .andReturn();

        assertEquals(403, result.getResponse().getStatus(),
                "a DBSC failure is 403; 401 is ignored by Chromium and the session dies");
    }

    // ------------------------------------------------------------------
    // Native refresh
    // ------------------------------------------------------------------

    @Test
    @DisplayName("refresh: the first leg is 403 + a fresh challenge, never 401")
    void refreshFirstLegIsForbidden() throws Exception {
        LoginState login = loginWithState();
        TestKey key = TestKey.generate();
        register(login, key);

        MvcResult result = mvc.perform(post("/dbsc/refresh")
                        .header("Sec-Secure-Session-Id", login.sessionId()))
                .andReturn();

        var response = result.getResponse();
        assertEquals(403, response.getStatus(),
                "the status MUST be 403; Chromium ignores 401 and the session dies");

        String challengeHeader = response.getHeader("Secure-Session-Challenge");
        assertNotNull(challengeHeader, "the 403 must carry a fresh challenge");
        assertTrue(challengeHeader.matches("\"[A-Za-z0-9_-]{43}\";id=\"[^\"]+\""),
                "the challenge is a 43-char base64url JTI: " + challengeHeader);
        assertEquals(challengeHeader, response.getHeader("Sec-Session-Challenge"));

        assertTrue(response.getHeaders("Set-Cookie").stream()
                        .anyMatch(c -> c.startsWith(cookieScope.challengeCookieName() + "=")),
                "a challenge cookie must be set");
    }

    @Test
    @DisplayName("refresh: the second leg with a valid JWS is 200 + JSON config + fresh cookie")
    void refreshSecondLegSucceeds() throws Exception {
        LoginState login = loginWithState();
        TestKey key = TestKey.generate();
        register(login, key);

        // Leg 1: collect the challenge.
        MvcResult firstLeg = mvc.perform(post("/dbsc/refresh")
                        .header("Sec-Secure-Session-Id", login.sessionId()))
                .andReturn();
        String challengeHeader = firstLeg.getResponse().getHeader("Secure-Session-Challenge");
        String jti = challengeHeader.substring(1, challengeHeader.indexOf('"', 1));
        var challengeCookie = firstLeg.getResponse().getCookie(cookieScope.challengeCookieName());
        assertNotNull(challengeCookie);

        // Leg 2: sign the new JTI with the same key.
        MvcResult secondLeg = mvc.perform(post("/dbsc/refresh")
                        .header("Sec-Secure-Session-Id", login.sessionId())
                        .header("Secure-Session-Response", key.refreshJws(jti))
                        .cookie(challengeCookie))
                .andReturn();

        assertEquals(200, secondLeg.getResponse().getStatus());
        Map<String, Object> config = Json.parseObject(secondLeg.getResponse().getContentAsString());
        assertEquals(login.sessionId(), config.get("session_identifier"));
        assertTrue(secondLeg.getResponse().getHeaders("Set-Cookie").stream()
                        .anyMatch(c -> c.startsWith(cookieScope.bindingCookieName() + "=")),
                "a refresh response MUST set the bound cookie");
        assertEquals(ProtectionTier.DBSC, storage.getSession(login.sessionId()).orElseThrow().tier());
    }

    @Test
    @DisplayName("refresh: a bad signature is 403 and demotes the session to none")
    void refreshWithBadSignatureDemotes() throws Exception {
        LoginState login = loginWithState();
        TestKey key = TestKey.generate();
        register(login, key);

        MvcResult firstLeg = mvc.perform(post("/dbsc/refresh")
                        .header("Sec-Secure-Session-Id", login.sessionId()))
                .andReturn();
        String challengeHeader = firstLeg.getResponse().getHeader("Secure-Session-Challenge");
        String jti = challengeHeader.substring(1, challengeHeader.indexOf('"', 1));
        var challengeCookie = firstLeg.getResponse().getCookie(cookieScope.challengeCookieName());

        // A well-formed refresh JWS from a different key.
        String foreignJws = TestKey.generate().refreshJws(jti);

        MvcResult result = mvc.perform(post("/dbsc/refresh")
                        .header("Sec-Secure-Session-Id", login.sessionId())
                        .header("Secure-Session-Response", foreignJws)
                        .cookie(challengeCookie))
                .andReturn();

        assertEquals(403, result.getResponse().getStatus());
        assertEquals(ProtectionTier.NONE,
                storage.getSession(login.sessionId()).orElseThrow().tier(),
                "a failed refresh signature MUST demote the session to tier: none");
    }

    // ------------------------------------------------------------------
    // Bound protocol
    // ------------------------------------------------------------------

    @Test
    @DisplayName("bound state: no session is 200 with phase unbound")
    void boundStateWithoutSession() throws Exception {
        MvcResult result = mvc.perform(get("/dbsc-bound/state")).andReturn();

        assertEquals(200, result.getResponse().getStatus(), "the state route always answers 200");
        Map<String, Object> body = Json.parseObject(result.getResponse().getContentAsString());
        assertEquals("unbound", body.get("phase"));
        assertTrue(body.containsKey("sessionId"));
        assertEquals(null, body.get("sessionId"));
        assertNotNull(result.getResponse().getHeader("X-Server-Time"),
                "bound endpoints SHOULD emit the server clock for skew correction");
    }

    @Test
    @DisplayName("bound state: a fresh session needs registration and receives a challenge")
    void boundStateNeedsRegistration() throws Exception {
        LoginState login = loginWithState();

        MvcResult result = mvc.perform(get("/dbsc-bound/state")
                        .cookie(login.registrationCookie(), login.challengeCookie()))
                .andReturn();

        assertEquals(200, result.getResponse().getStatus());
        Map<String, Object> body = Json.parseObject(result.getResponse().getContentAsString());
        assertEquals("needs-registration", body.get("phase"));
        assertEquals(login.sessionId(), body.get("sessionId"));
        assertNotNull(body.get("challenge"));
        assertTrue(body.get("challenge").toString().matches("[A-Za-z0-9_-]{43}"),
                "the JTI is 32 random bytes in base64url: " + body.get("challenge"));
    }

    @Test
    @DisplayName("bound state: a session with a native key asks for bound registration, keeping tier dbsc")
    void boundStateNeedsBoundRegistration() throws Exception {
        LoginState login = loginWithState();
        register(login, TestKey.generate());

        MvcResult result = mvc.perform(get("/dbsc-bound/state")
                        .cookie(login.bindingCookie()))
                .andReturn();

        Map<String, Object> body = Json.parseObject(result.getResponse().getContentAsString());
        assertEquals("needs-bound-registration", body.get("phase"));
        assertEquals("dbsc", body.get("tier"),
                "a Chromium session keeps the native tier while co-registering the polyfill key");
        assertNotNull(body.get("challenge"));
        assertEquals(600000L, ((Number) body.get("refreshIntervalMs")).longValue());
    }

    @Test
    @DisplayName("bound challenge: no session is 403 with a machine-readable error")
    void boundChallengeWithoutSession() throws Exception {
        MvcResult result = mvc.perform(get("/dbsc-bound/challenge")).andReturn();

        assertEquals(403, result.getResponse().getStatus());
        Map<String, Object> body = Json.parseObject(result.getResponse().getContentAsString());
        assertEquals("no session", body.get("error"),
                "spec 03 pins this exact body for a sessionless challenge request");
    }

    @Test
    @DisplayName("bound registration and refresh complete the polyfill flow")
    void boundFlow() throws Exception {
        LoginState login = loginWithState();

        // Ask for a challenge.
        MvcResult challengeResult = mvc.perform(get("/dbsc-bound/challenge")
                        .cookie(login.registrationCookie()))
                .andReturn();
        assertEquals(200, challengeResult.getResponse().getStatus());
        String jti = (String) Json.parseObject(
                challengeResult.getResponse().getContentAsString()).get("challenge");
        var challengeCookie = challengeResult.getResponse().getCookie(cookieScope.challengeCookieName());

        // Register over the bare JTI.
        TestKey key = TestKey.generate();
        String registrationBody = Json.write(Map.of(
                "publicKey", key.publicJwk(),
                "signature", key.sign(jti),
                "challenge", jti));

        MvcResult registration = mvc.perform(post("/dbsc-bound/registration")
                        .contentType("application/json")
                        .content(registrationBody)
                        .cookie(login.registrationCookie(), challengeCookie))
                .andReturn();

        assertEquals(200, registration.getResponse().getStatus(),
                registration.getResponse().getContentAsString());
        Map<String, Object> registrationResponse =
                Json.parseObject(registration.getResponse().getContentAsString());
        assertEquals(login.sessionId(), registrationResponse.get("session_identifier"));
        assertEquals("/dbsc-bound/refresh", registrationResponse.get("refresh_url"));
        assertEquals("bound", registrationResponse.get("tier"));
        assertTrue(storage.getBoundKey(login.sessionId(), BoundKeyKind.BOUND).isPresent());

        // Refresh over <jti>.<timestamp>.
        MvcResult nextChallenge = mvc.perform(get("/dbsc-bound/challenge")
                        .cookie(login.registrationCookie()))
                .andReturn();
        String refreshJti = (String) Json.parseObject(
                nextChallenge.getResponse().getContentAsString()).get("challenge");
        var refreshChallengeCookie =
                nextChallenge.getResponse().getCookie(cookieScope.challengeCookieName());
        long timestamp = dbscClock.millis();

        String refreshBody = Json.write(Map.of(
                "challenge", refreshJti,
                "signature", key.sign(refreshJti + "." + timestamp),
                "timestamp", timestamp));

        MvcResult refresh = mvc.perform(post("/dbsc-bound/refresh")
                        .contentType("application/json")
                        .content(refreshBody)
                        .cookie(login.registrationCookie(), refreshChallengeCookie))
                .andReturn();

        assertEquals(200, refresh.getResponse().getStatus(),
                refresh.getResponse().getContentAsString());
        assertEquals("bound", Json.parseObject(
                refresh.getResponse().getContentAsString()).get("tier"));
    }

    @Test
    @DisplayName("bound registration: a body missing fields is 400, not 403")
    void boundRegistrationMissingFields() throws Exception {
        LoginState login = loginWithState();

        MvcResult result = mvc.perform(post("/dbsc-bound/registration")
                        .contentType("application/json")
                        .content("{\"challenge\":\"abc\"}")
                        .cookie(login.registrationCookie()))
                .andReturn();

        assertEquals(400, result.getResponse().getStatus(),
                "a missing body field is a client bug: 400, not a rejected proof");
    }

    @Test
    @DisplayName("bound routes: a forged cookie cannot install a key, and refresh is refused")
    void boundRoutesRequireAnExistingSession() throws Exception {
        // A cookie is attacker-supplied on an unauthenticated route, so a session id
        // it names proves nothing. Registration itself is lazy — whether the browser
        // has registered is unknowable up front — so what has to hold is that a
        // forged cookie cannot get a key installed, and that a proof-bearing route
        // refuses outright.
        var forged = new jakarta.servlet.http.Cookie(cookieScope.bindingCookieName(), "sess_does_not_exist");

        MvcResult challenge = mvc.perform(get("/dbsc-bound/challenge").cookie(forged)).andReturn();
        assertEquals(200, challenge.getResponse().getStatus(),
                "a challenge is issued so a first registration can proceed");

        MvcResult registration = mvc.perform(post("/dbsc-bound/registration")
                        .contentType("application/json")
                        .content(Json.write(Map.of(
                                "publicKey", Map.of("kty", "EC", "crv", "P-256", "x", "AA", "y", "AA"),
                                "signature", "AAAA",
                                "challenge", "AAAA")))
                        .cookie(forged))
                .andReturn();
        assertEquals(403, registration.getResponse().getStatus(),
                "the challenge is not one this server issued, so no key is installed");

        MvcResult refresh = mvc.perform(post("/dbsc-bound/refresh")
                        .contentType("application/json")
                        .content(Json.write(Map.of(
                                "challenge", "AAAA", "signature", "AAAA", "timestamp", 1L)))
                        .cookie(forged))
                .andReturn();
        assertEquals(403, refresh.getResponse().getStatus(),
                "a refresh verifies a signature, so an unknown session is a rejected proof");
    }

    @Test
    @DisplayName("bound registration: a body over the size cap is rejected, not buffered")
    void oversizedBodyIsRejected() throws Exception {
        LoginState login = loginWithState();

        // The DBSC routes are unauthenticated, so the body is read before any
        // session decision. An unbounded read there is a memory exhaustion
        // primitive; the cap turns it into a protocol error.
        String huge = "x".repeat(click.yukio.dbsc.web.RequestBodies.MAX_BODY_BYTES + 1024);
        MvcResult result = mvc.perform(post("/dbsc-bound/registration")
                        .contentType("application/json")
                        .content(Json.write(Map.of(
                                "publicKey", Map.of("kty", "EC"),
                                "signature", huge,
                                "challenge", "AAAA")))
                        .cookie(login.registrationCookie()))
                .andReturn();

        assertEquals(403, result.getResponse().getStatus());
        assertEquals("MALFORMED_JWS", Json.parseObject(
                result.getResponse().getContentAsString()).get("error"));
    }

    // ------------------------------------------------------------------
    // Per-request proof guard
    // ------------------------------------------------------------------

    @Test
    @DisplayName("guard: a guarded route without a proof is 403")
    void guardWithoutProof() throws Exception {
        MvcResult result = mvc.perform(post("/host/payment")
                        .contentType("application/json")
                        .content("{\"amount\":1}"))
                .andReturn();

        assertEquals(403, result.getResponse().getStatus());
        Map<String, Object> body = Json.parseObject(result.getResponse().getContentAsString());
        assertEquals("MISSING_PROOF", body.get("error"));
    }

    @Test
    @DisplayName("guard: a valid body-bound proof passes; a different body is rejected")
    void guardWithProof() throws Exception {
        LoginState login = loginWithState();
        TestKey nativeKey = TestKey.generate();
        register(login, nativeKey);

        // Register the polyfill key that per-request proofs use.
        TestKey boundKey = TestKey.generate();
        String jti = issueBoundChallenge(login);
        mvc.perform(post("/dbsc-bound/registration")
                        .contentType("application/json")
                        .content(Json.write(Map.of(
                                "publicKey", boundKey.publicJwk(),
                                "signature", boundKey.sign(jti),
                                "challenge", jti)))
                        .cookie(login.bindingCookie(),
                                challengeCookieFor(login, jti)))
                .andReturn();

        String body = "{\"amount\":1000,\"currency\":\"usd\"}";
        long ts = dbscClock.millis();
        String bodyHash = click.yukio.dbsc.core.Base64Url.sha256Base64Url(body.getBytes(StandardCharsets.UTF_8));
        String message = login.sessionId() + ".POST./host/payment." + ts + "." + bodyHash;
        String proof = "ts=" + ts + ";sig=" + boundKey.sign(message) + ";bh=" + bodyHash;

        MvcResult allowed = mvc.perform(post("/host/payment")
                        .contentType("application/json")
                        .content(body)
                        .header("X-Dbsc-Bound-Proof", proof)
                        .cookie(login.bindingCookie()))
                .andReturn();

        assertEquals(200, allowed.getResponse().getStatus(),
                allowed.getResponse().getContentAsString());

        // The same proof against a different body must fail: that is the binding.
        MvcResult rejected = mvc.perform(post("/host/payment")
                        .contentType("application/json")
                        .content("{\"amount\":999999,\"currency\":\"usd\"}")
                        .header("X-Dbsc-Bound-Proof", proof)
                        .cookie(login.bindingCookie()))
                .andReturn();

        assertEquals(403, rejected.getResponse().getStatus(),
                "a captured proof must not be reusable on a modified body");
    }

    @Test
    @DisplayName("guard: a stolen cookie with no bound key is 403 on the first guarded request")
    void guardRejectsStolenCookie() throws Exception {
        LoginState login = loginWithState();
        // Native registration happened on the victim's device, but this attacker
        // has only the cookie and no bound key.
        register(login, TestKey.generate());

        MvcResult result = mvc.perform(post("/host/payment")
                        .contentType("application/json")
                        .content("{\"amount\":1}")
                        .header("X-Dbsc-Bound-Proof", "ts=" + dbscClock.millis() + ";sig=AAAA")
                        .cookie(login.bindingCookie()))
                .andReturn();

        assertEquals(403, result.getResponse().getStatus());
        Map<String, Object> body = Json.parseObject(result.getResponse().getContentAsString());
        assertEquals("KEY_NOT_FOUND_BOUND", body.get("error"),
                "without a polyfill key no proof can be produced, so the request is refused");
    }

    // ------------------------------------------------------------------
    // Well-known and logout
    // ------------------------------------------------------------------

    @Test
    @DisplayName("well-known: the device-bound-sessions document is served as JSON")
    void wellKnown() throws Exception {
        MvcResult result = mvc.perform(get("/.well-known/device-bound-sessions")).andReturn();

        assertEquals(200, result.getResponse().getStatus());
        Map<String, Object> body = Json.parseObject(result.getResponse().getContentAsString());
        assertNotNull(body.get("registering_origins"));
        assertNotNull(body.get("relying_origins"));
    }

    @Test
    @DisplayName("logout: terminate() clears the cookies and tells Chromium to stop")
    void logoutTerminates() throws Exception {
        LoginState login = loginWithState();
        register(login, TestKey.generate());

        MvcResult result = mvc.perform(post("/host/logout").cookie(login.bindingCookie())).andReturn();

        assertEquals(200, result.getResponse().getStatus());
        Map<String, Object> config = Json.parseObject(result.getResponse().getContentAsString());
        assertEquals(false, config.get("continue"),
                "continue:false makes Chromium forget the binding immediately");
        assertTrue(result.getResponse().getHeaders("Set-Cookie").stream()
                .anyMatch(c -> c.startsWith(cookieScope.bindingCookieName() + "=;")));
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * The state a logged-in client holds. The binding cookie only exists after
     * native registration completes, so it is a mutable field that
     * {@link #register} fills in on the caller's instance.
     */
    private static final class LoginState {
        private final String sessionId;
        private final String challenge;
        private final jakarta.servlet.http.Cookie registrationCookie;
        private final jakarta.servlet.http.Cookie challengeCookie;
        private jakarta.servlet.http.Cookie bindingCookie;

        LoginState(String sessionId, String challenge,
                   jakarta.servlet.http.Cookie registrationCookie,
                   jakarta.servlet.http.Cookie challengeCookie,
                   jakarta.servlet.http.Cookie bindingCookie) {
            this.sessionId = sessionId;
            this.challenge = challenge;
            this.registrationCookie = registrationCookie;
            this.challengeCookie = challengeCookie;
            this.bindingCookie = bindingCookie;
        }

        String sessionId() {
            return sessionId;
        }

        String challenge() {
            return challenge;
        }

        jakarta.servlet.http.Cookie registrationCookie() {
            return registrationCookie;
        }

        jakarta.servlet.http.Cookie challengeCookie() {
            return challengeCookie;
        }

        jakarta.servlet.http.Cookie bindingCookie() {
            return bindingCookie;
        }
    }

    private MvcResult login() throws Exception {
        return mvc.perform(post("/host/login")
                        .contentType("application/json")
                        .content("{\"userId\":\"user_1\"}"))
                .andReturn();
    }

    private LoginState loginWithState() throws Exception {
        MvcResult result = login();
        var response = result.getResponse();
        Map<String, Object> body = Json.parseObject(response.getContentAsString());
        String sessionId = (String) body.get("sessionId");

        String registration = response.getHeader("Secure-Session-Registration");
        Matcher matcher = Pattern.compile("challenge=\"([^\"]+)\"").matcher(registration);
        assertTrue(matcher.find(), registration);

        var registrationCookie = response.getCookie(cookieScope.registrationCookieName());
        var challengeCookie = response.getCookie(cookieScope.challengeCookieName());
        assertNotNull(registrationCookie);
        assertNotNull(challengeCookie);

        // The binding cookie does not exist until registration completes, so the
        // key material is issued here and the cookie is filled in by register().
        return new LoginState(sessionId, matcher.group(1),
                registrationCookie, challengeCookie, null);
    }

    /**
     * Completes native registration and returns the state a bound client sees,
     * including the binding cookie the registration response issued.
     *
     * <p>The passed-in state is updated in place, so a test that ignores the
     * return value still observes the binding cookie on its own variable.
     */
    private LoginState register(LoginState login, TestKey key) throws Exception {
        MvcResult result = mvc.perform(post("/dbsc/registration")
                        .header("Secure-Session-Response", key.registrationJws(login.challenge(), login.sessionId()))
                        .cookie(login.registrationCookie(), login.challengeCookie()))
                .andReturn();
        assertEquals(200, result.getResponse().getStatus(),
                "registration failed: " + result.getResponse().getContentAsString());

        var bindingCookie = result.getResponse().getCookie(cookieScope.bindingCookieName());
        assertNotNull(bindingCookie, "registration must issue the binding cookie");
        login.bindingCookie = bindingCookie;
        return login;
    }

    private String issueBoundChallenge(LoginState login) throws Exception {
        MvcResult result = mvc.perform(get("/dbsc-bound/challenge")
                        .cookie(login.bindingCookie()))
                .andReturn();
        assertEquals(200, result.getResponse().getStatus());
        return (String) Json.parseObject(result.getResponse().getContentAsString()).get("challenge");
    }

    private jakarta.servlet.http.Cookie challengeCookieFor(LoginState login, String jti) {
        return new jakarta.servlet.http.Cookie(cookieScope.challengeCookieName(), jti);
    }

    /** A generated P-256 key that can produce the JWS shapes DBSC expects. */
    private record TestKey(KeyPair pair) {

        static TestKey generate() {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec("secp256r1"));
                return new TestKey(generator.generateKeyPair());
            } catch (Exception e) {
                throw new IllegalStateException("failed to generate a P-256 key", e);
            }
        }

        ECPublicKey publicKey() {
            return (ECPublicKey) pair.getPublic();
        }

        Map<String, Object> publicJwk() {
            Map<String, Object> jwk = new LinkedHashMap<>();
            jwk.put("kty", "EC");
            jwk.put("crv", "P-256");
            jwk.put("x", base64Url(pad(publicKey().getW().getAffineX().toByteArray())));
            jwk.put("y", base64Url(pad(publicKey().getW().getAffineY().toByteArray())));
            return jwk;
        }

        /** Signs an arbitrary message, returning base64url raw ECDSA. */
        String sign(String message) {
            try {
                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(pair.getPrivate());
                signer.update(message.getBytes(StandardCharsets.UTF_8));
                return base64Url(derToRaw(signer.sign()));
            } catch (Exception e) {
                throw new IllegalStateException("failed to sign", e);
            }
        }

        /** A self-signed registration JWS with the public key in the header. */
        String registrationJws(String jti, String sessionId) {
            try {
                String header = base64Url(Json.write(Map.of(
                        "alg", "ES256", "typ", "dbsc+jwt", "jwk", publicJwk()))
                        .getBytes(StandardCharsets.UTF_8));
                String payload = base64Url(Json.write(Map.of("jti", jti))
                        .getBytes(StandardCharsets.UTF_8));

                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(pair.getPrivate());
                signer.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
                return header + "." + payload + "." + base64Url(derToRaw(signer.sign()));
            } catch (Exception e) {
                throw new IllegalStateException("failed to build a registration JWS", e);
            }
        }

        /** A refresh JWS: same shape, but with no jwk in the header. */
        String refreshJws(String jti) {
            try {
                String header = base64Url(Json.write(Map.of("alg", "ES256", "typ", "dbsc+jwt"))
                        .getBytes(StandardCharsets.UTF_8));
                String payload = base64Url(Json.write(Map.of("jti", jti))
                        .getBytes(StandardCharsets.UTF_8));

                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(pair.getPrivate());
                signer.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
                return header + "." + payload + "." + base64Url(derToRaw(signer.sign()));
            } catch (Exception e) {
                throw new IllegalStateException("failed to build a refresh JWS", e);
            }
        }

        private static byte[] pad(byte[] value) {
            if (value.length == 32) {
                return value;
            }
            byte[] out = new byte[32];
            int copy = Math.min(value.length, 32);
            System.arraycopy(value, value.length - copy, out, 32 - copy, copy);
            return out;
        }

        private static String base64Url(byte[] bytes) {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        }
    }

    private static byte[] derToRaw(byte[] der) {
        int offset = (der[1] & 0xFF) > 0x80 ? 3 : 2;
        int rLength = der[offset + 1] & 0xFF;
        int rStart = offset + 2;
        int sLength = der[rStart + rLength + 1] & 0xFF;
        int sStart = rStart + rLength + 2;

        byte[] raw = new byte[64];
        copyComponent(der, rStart, rLength, raw, 0);
        copyComponent(der, sStart, sLength, raw, 32);
        return raw;
    }

    private static void copyComponent(byte[] der, int start, int length, byte[] out, int outOffset) {
        int effectiveStart = start;
        int effectiveLength = length;
        while (effectiveLength > 32 && der[effectiveStart] == 0) {
            effectiveStart++;
            effectiveLength--;
        }
        System.arraycopy(der, effectiveStart, out, outOffset + 32 - effectiveLength, effectiveLength);
    }
}
