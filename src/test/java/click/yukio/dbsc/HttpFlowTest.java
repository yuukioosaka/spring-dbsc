package click.yukio.dbsc;

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
import org.springframework.mock.web.MockHttpSession;
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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
    @DisplayName("login: bind() sets the registration header and the challenge header (both names)")
    void loginBinds() throws Exception {
        MvcResult result = login();
        var response = result.getResponse();

        String registration = response.getHeader("Secure-Session-Registration");
        assertNotNull(registration, "Chromium only starts a session when this header is present");
        assertTrue(registration.matches(
                        "\\(ES256\\);path=\"/dbsc/regist/[A-Za-z0-9_-]{43}\";challenge=\"[A-Za-z0-9_-]{43}\""),
                "the path must carry a fresh single-use token: " + registration);
        assertFalse(registration.contains("id="), "this header carries no id parameter");

        // Some Chromium builds straddle the rename, so the legacy name is emitted too.
        assertEquals(registration, response.getHeader("Sec-Session-Registration"));

        // The challenge travels as a response header naming the session (spec §8.7, §9.2),
        // not as a cookie: the browser is not asked to hold the server's state, and the
        // registration POST is resolved from the path alone.
        String challengeHeader = response.getHeader("Secure-Session-Challenge");
        assertNotNull(challengeHeader, "bind() must offer the challenge the browser will sign");
        assertTrue(challengeHeader.matches("\"[A-Za-z0-9_-]{43}\";id=\"[^\"]+\""), challengeHeader);
        assertEquals(challengeHeader, response.getHeader("Sec-Session-Challenge"));

        List<String> cookies = response.getHeaders("Set-Cookie");
        assertTrue(cookies.stream().anyMatch(c -> c.startsWith(cookieScope.credentialCookieName() + "=")),
                "the credential cookie is set from the start: " + cookies);
        assertTrue(cookies.stream().noneMatch(c -> c.contains("dbsc-reg")),
                "the pre-registration cookie is gone; the path carries the token now: " + cookies);
        assertTrue(cookies.stream().noneMatch(c -> c.contains("dbsc-challenge")),
                "the challenge cookie is gone; the challenge is held server-side: " + cookies);
        // The session id is echoed in the JSON config as session_identifier, but never as
        // a cookie: it is a value the browser stores and returns in a header, not a
        // credential a cookie jar could leak.
        assertTrue(cookies.stream().noneMatch(
                        c -> c.startsWith("session_identifier" + "=")),
                "no cookie is minted under session_identifier: " + cookies);
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

        MvcResult result = mvc.perform(post(login.registrationPath())
                        .header("Secure-Session-Response", jws))
                .andReturn();

        var response = result.getResponse();
        assertEquals(200, response.getStatus());

        Map<String, Object> config = Json.parseObject(response.getContentAsString());
        // session_identifier IS the session id (spec §9.6: "a string representing a session
        // identifier ... the identifier for the newly created session"). Chromium keys its
        // session store by it and echoes it back as Sec-Secure-Session-Id on every refresh,
        // which is the only way the server can find the session to verify against.
        assertEquals(login.sessionId(), config.get("session_identifier"),
                "session_identifier must be the session id the server knows the session by");
        assertEquals("/dbsc/refresh", config.get("refresh_url"));

        // The JSON body is mandatory: a 200 without it is read as an opt-out.
        Map<String, Object> scope = Json.object(config, "scope");
        assertNotNull(scope.get("include_site"), "scope.include_site is required");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) config.get("credentials");
        assertEquals(1, credentials.size());
        assertEquals(cookieScope.credentialCookieName(), credentials.get(0).get("name"));
        // This MUST match the real Set-Cookie prefix byte-for-byte, but MUST NOT carry
        // Max-Age: Chromium rejects that attribute here outright.
        assertEquals(cookieScope.attributesString(), credentials.get(0).get("attributes"));
        assertFalse(((String) credentials.get(0).get("attributes")).contains("Max-Age"),
                "Max-Age in credentials[].attributes is a registration failure on Chromium");

        List<String> cookies = response.getHeaders("Set-Cookie");
        assertTrue(cookies.stream().anyMatch(c -> c.startsWith(cookieScope.credentialCookieName() + "=")),
                "the credential cookie named in the JSON config must actually be set, or "
                        + "§8.6 finds it missing on the very next request: " + cookies);
        assertTrue(cookies.stream().noneMatch(
                        c -> c.startsWith("session_identifier" + "=")),
                "nothing is set under session_identifier: " + cookies);

        assertEquals(ProtectionTier.DBSC, storage.getSession(login.sessionId()).orElseThrow().tier());
    }

    @Test
    @DisplayName("registration: the token is single-use, so a replayed POST is refused")
    void registrationTokenIsSingleUse() throws Exception {
        LoginState login = loginWithState();
        TestKey key = TestKey.generate();
        register(login, key);

        // A second POST on the same path: the token was consumed by the first, so
        // this is a replay rather than an unknown route.
        MvcResult replay = mvc.perform(post(login.registrationPath())
                        .header("Secure-Session-Response",
                                key.registrationJws(login.challenge(), login.sessionId())))
                .andReturn();

        assertEquals(403, replay.getResponse().getStatus());
        Map<String, Object> body = Json.parseObject(replay.getResponse().getContentAsString());
        assertEquals("REGISTRATION_TOKEN_CONSUMED", body.get("error"));
    }

    @Test
    @DisplayName("registration: an unknown token is SESSION_NOT_FOUND, not a crash")
    void registrationUnknownToken() throws Exception {
        LoginState login = loginWithState();

        MvcResult result = mvc.perform(post("/dbsc/regist/" + "A".repeat(43))
                        .header("Secure-Session-Response", "x.y.z"))
                .andReturn();

        assertEquals(403, result.getResponse().getStatus());
        Map<String, Object> body = Json.parseObject(result.getResponse().getContentAsString());
        assertEquals("SESSION_NOT_FOUND", body.get("error"));
    }

    @Test
    @DisplayName("registration: an expired token is REGISTRATION_TOKEN_EXPIRED")
    void registrationTokenExpired() throws Exception {
        LoginState login = loginWithState();
        // Walk the token past its TTL. The clock is the same one the service reads.
        storage.setRegistrationToken(new click.yukio.dbsc.core.RegistrationToken(
                login.registrationToken(), login.sessionId(),
                dbscClock.millis() - 10_000, dbscClock.millis() - 1, false));

        MvcResult result = mvc.perform(post(login.registrationPath())
                        .header("Secure-Session-Response", "x.y.z"))
                .andReturn();

        assertEquals(403, result.getResponse().getStatus());
        Map<String, Object> body = Json.parseObject(result.getResponse().getContentAsString());
        assertEquals("REGISTRATION_TOKEN_EXPIRED", body.get("error"));
    }

    @Test
    @DisplayName("registration: no Secure-Session-Response is 403, not 500 or 401")
    void registrationWithoutProof() throws Exception {
        LoginState login = loginWithState();

        MvcResult result = mvc.perform(post(login.registrationPath()))
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
                        .noneMatch(c -> c.contains("dbsc-challenge")),
                "no challenge cookie: it is issued again on every leg and held server-side");
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

        // Leg 2: sign the new JTI with the same key. Nothing else is carried: the
        // challenge is looked up server-side by the session the header names.
        MvcResult secondLeg = mvc.perform(post("/dbsc/refresh")
                        .header("Sec-Secure-Session-Id", login.sessionId())
                        .header("Secure-Session-Response", key.refreshJws(jti)))
                .andReturn();

        assertEquals(200, secondLeg.getResponse().getStatus());
        Map<String, Object> config = Json.parseObject(secondLeg.getResponse().getContentAsString());

        // A refresh replaces the credential and nothing else. The session id is echoed as
        // session_identifier -- that is how Chromium knows which session this is -- but no
        // cookie appears under it: the id is a value, not a stored credential.
        assertTrue(secondLeg.getResponse().getHeaders("Set-Cookie").stream()
                        .noneMatch(c -> c.startsWith("session_identifier" + "=")),
                "a refresh must not mint a cookie under session_identifier's name");
        assertEquals(login.sessionId(), config.get("session_identifier"),
                "a refresh must echo the same session id the session was registered under");

        var credential = secondLeg.getResponse().getCookie(cookieScope.credentialCookieName());
        assertNotNull(credential, "a refresh response MUST set the credential cookie");
        assertEquals(login.sessionId(), storage.resolveTicket(credential.getValue()),
                "the new ticket must resolve back to this session");
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

        // A well-formed refresh JWS from a different key.
        String foreignJws = TestKey.generate().refreshJws(jti);

        MvcResult result = mvc.perform(post("/dbsc/refresh")
                        .header("Sec-Secure-Session-Id", login.sessionId())
                        .header("Secure-Session-Response", foreignJws))
                .andReturn();

        assertEquals(403, result.getResponse().getStatus());
        assertEquals(ProtectionTier.NONE,
                storage.getSession(login.sessionId()).orElseThrow().tier(),
                "a failed refresh signature MUST demote the session to tier: none");
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
                .anyMatch(c -> c.startsWith(cookieScope.credentialCookieName() + "=;")));
    }

    // ------------------------------------------------------------------
    // The route guard
    // ------------------------------------------------------------------

    @Test
    @DisplayName("guard: a session the browser has not registered yet is admitted (pre-registration window)")
    void guardedRouteAdmitsUnregisteredSession() throws Exception {
        // bind() has run, so the session record exists — but the browser has not
        // completed registration, which is exactly the state of every client that
        // cannot do DBSC at all. The application must keep serving them, or DBSC
        // would lock out every browser that does not implement it.
        LoginState login = loginWithState();

        MvcResult result = mvc.perform(post("/host/payment")
                        .contentType("application/json")
                        .content("{\"amount\":1000}")
                        .cookie(login.preRegistrationCookie()))
                .andReturn();

        assertEquals(200, result.getResponse().getStatus(),
                "a client that has not registered yet must fall back to the plain session");
    }

    @Test
    @DisplayName("guard: an anonymous request with no session at all is admitted here")
    void guardedRouteAdmitsAnonymousRequest() throws Exception {
        // No session id means no binding can be looked up, so this is the ordinary
        // "not logged in" case. Authenticating the request is the application's
        // job — a DBSC refusal is 403 and would tell a signed-out user nothing.
        MvcResult result = mvc.perform(post("/host/payment")
                        .contentType("application/json")
                        .content("{\"amount\":1000}"))
                .andReturn();

        assertEquals(200, result.getResponse().getStatus());
    }

    @Test
    @DisplayName("guard: dropping the DBSC cookies does not escape a binding")
    void guardedRouteRefusesBindingWithCookiesOmitted() throws Exception {
        // The bypass this rule exists for: register, then send only JSESSIONID.
        // The DBSC cookies are the client's to withhold, so "no cookie" must not
        // be read as "no binding" — otherwise a stolen session id regains
        // unbound access simply by not presenting the cookie it stole.
        LoginState login = loginWithState();
        register(login, TestKey.generate());

        MvcResult result = mvc.perform(post("/host/payment")
                        .contentType("application/json")
                        .content("{\"amount\":1000}")
                        .session(login.appSession()))
                .andReturn();

        assertEquals(403, result.getResponse().getStatus(),
                "a bound session must not escape its binding by omitting the DBSC cookies");
        assertEquals("DBSC_REQUIRED",
                Json.parseObject(result.getResponse().getContentAsString()).get("error"));
    }

    @Test
    @DisplayName("guard: a registered session reaches the guarded handler")
    void guardedRouteAdmitsBoundRequest() throws Exception {
        LoginState login = loginWithState();
        register(login, TestKey.generate());

        MvcResult result = mvc.perform(post("/host/payment")
                        .contentType("application/json")
                        .content("{\"amount\":1000}")
                        .cookie(login.bindingCookie()))
                .andReturn();

        assertEquals(200, result.getResponse().getStatus(),
                result.getResponse().getContentAsString());
        Map<String, Object> body = Json.parseObject(result.getResponse().getContentAsString());
        assertEquals("authorized", body.get("status"));
    }

    @Test
    @DisplayName("guard: an unguarded route is unaffected by the tier")
    void unguardedRouteIgnoresTheTier() throws Exception {
        // /host/whoami is not declared as a guarded route, so DBSC only observes.
        // That the two routes behave differently is the whole point of the guard
        // being opt-in per route rather than a blanket filter.
        LoginState login = loginWithState();

        MvcResult result = mvc.perform(get("/host/whoami").cookie(login.preRegistrationCookie()))
                .andReturn();

        assertEquals(200, result.getResponse().getStatus());
        assertEquals("none", Json.parseObject(result.getResponse().getContentAsString()).get("tier"));
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * The state a logged-in client holds. The binding cookie only exists after
     * native registration completes, so it is a mutable field that
     * {@link #register} fills in on the caller's instance.
     *
     * <p>Package-visible, like the helpers below, so {@link SessionRotationTest} can
     * drive the same flow rather than keeping a second copy of it in step.
     */
    static final class LoginState {
        private final String sessionId;
        private final String challenge;
        private final String registrationToken;
        private final MockHttpSession appSession;
        private final jakarta.servlet.http.Cookie preRegistrationCookie;
        private jakarta.servlet.http.Cookie bindingCookie;

        LoginState(String sessionId, String challenge, String registrationToken,
                   MockHttpSession appSession,
                   jakarta.servlet.http.Cookie bindingCookie,
                   jakarta.servlet.http.Cookie preRegistrationCookie) {
            this.sessionId = sessionId;
            this.challenge = challenge;
            this.registrationToken = registrationToken;
            this.appSession = appSession;
            this.bindingCookie = bindingCookie;
            this.preRegistrationCookie = preRegistrationCookie;
        }

        String sessionId() {
            return sessionId;
        }

        /**
         * The same client state under a different DBSC session id, as a browser that
         * has just read a rotated id would be. The application session is carried
         * over unchanged, which is what a rotation does.
         */
        LoginState withSessionId(String newSessionId) {
            return new LoginState(newSessionId, challenge, registrationToken,
                    appSession, bindingCookie, preRegistrationCookie);
        }

        /**
         * The application's own session id, which {@code bind()} recorded and
         * rotation must leave alone.
         */
        String appSessionId() {
            return appSession.getId();
        }

        String challenge() {
            return challenge;
        }

        /**
         * The single-use token naming this session, as it appears in the
         * registration path. It is not the session id.
         */
        String registrationToken() {
            return registrationToken;
        }

        /** The path Chromium would POST the registration JWS to. */
        String registrationPath() {
            return "/dbsc/regist/" + registrationToken;
        }

        jakarta.servlet.http.Cookie bindingCookie() {
            return bindingCookie;
        }

        /**
         * The credential cookie {@code bind()} set before registration completed.
         * Its ticket resolves to the session, so a request carrying it is recognised
         * as an unregistered browser rather than as one that never bound.
         */
        jakarta.servlet.http.Cookie preRegistrationCookie() {
            return preRegistrationCookie;
        }

        /**
         * The application session the login route bound to, carried so a test can
         * present it without any DBSC cookie — the shape of the bypass above.
         */
        MockHttpSession appSession() {
            return appSession;
        }
    }

    private MvcResult login() throws Exception {
        return mvc.perform(post("/host/login")
                        .contentType("application/json")
                        .content("{\"userId\":\"user_1\"}"))
                .andReturn();
    }

    private LoginState loginWithState() throws Exception {
        return loginWithState(mvc, cookieScope);
    }

    /**
     * Logs in and returns the state a client holds before registration. Shared with
     * {@link SessionRotationTest}.
     */
    static LoginState loginWithState(MockMvc mvc, CookieScope cookieScope) throws Exception {
        MvcResult result = mvc.perform(post("/host/login")
                        .contentType("application/json")
                        .content("{\"userId\":\"user_1\"}"))
                .andReturn();
        var response = result.getResponse();
        Map<String, Object> body = Json.parseObject(response.getContentAsString());
        String sessionId = (String) body.get("sessionId");

        String registration = response.getHeader("Secure-Session-Registration");
        Matcher matcher = Pattern.compile("challenge=\"([^\"]+)\"").matcher(registration);
        assertTrue(matcher.find(), registration);

        // The session is named by the token in the path, not by a cookie.
        Matcher tokenMatcher = Pattern.compile("path=\"/dbsc/regist/([^\"]+)\"").matcher(registration);
        assertTrue(tokenMatcher.find(), "the registration header must carry a token path: " + registration);

        // The binding cookie is already present from bind(), and is re-issued by
        // the registration response with a fresh lifetime.
        MockHttpSession appSession = (MockHttpSession) result.getRequest().getSession(false);
        assertNotNull(appSession, "bind() must have created the application session");
        var preRegistrationCookie = response.getCookie(cookieScope.credentialCookieName());
        assertNotNull(preRegistrationCookie,
                "bind() sets the credential cookie before any registration happens");
        return new LoginState(sessionId, matcher.group(1), tokenMatcher.group(1),
                appSession, null, preRegistrationCookie);
    }

    private LoginState register(LoginState login, TestKey key) throws Exception {
        return register(mvc, cookieScope, login, key);
    }

    /**
     * Completes native registration and returns the state a bound client sees,
     * including the binding cookie the registration response issued.
     *
     * <p>The passed-in state is updated in place, so a test that ignores the
     * return value still observes the binding cookie on its own variable.
     * Shared with {@link SessionRotationTest}.
     */
    static LoginState register(MockMvc mvc, CookieScope cookieScope, LoginState login, TestKey key)
            throws Exception {
        MvcResult result = mvc.perform(post(login.registrationPath())
                        .header("Secure-Session-Response", key.registrationJws(login.challenge(), login.sessionId())))
                .andReturn();
        assertEquals(200, result.getResponse().getStatus(),
                "registration failed: " + result.getResponse().getContentAsString());

        var credentialCookie = result.getResponse().getCookie(cookieScope.credentialCookieName());
        assertNotNull(credentialCookie, "registration must issue the credential cookie");
        login.bindingCookie = credentialCookie;
        return login;
    }

    /** A generated P-256 key that can produce the JWS shapes DBSC expects. */
    static final class TestKey {

        private final KeyPair pair;

        private TestKey(KeyPair pair) {
            this.pair = pair;
        }

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
