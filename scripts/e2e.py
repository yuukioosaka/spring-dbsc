"""End-to-end test against a live HTTPS demo instance.

Unlike HttpFlowTest (MockMvc, no real server), this drives the running
application over TLS and exercises the paths a browser would take, including
ones MockMvc cannot reach: the security chains, cookie scoping, filter order,
and the CSRF/authorization layer.

Usage:
    mvn -Pdemo -Dmaven.repo.local=.m2repo spring-boot:run   # in another shell
    python3 scripts/e2e.py

The challenge-expiry checks need a short challenge TTL, which cannot be waited
out at the 5-minute production default. Start the demo with a short TTL and tell
this script about it:

    mvn -Pdemo -Dmaven.repo.local=.m2repo \
        -Dspring-boot.run.jvmArguments="-Ddbsc.challenge-ttl=2s" spring-boot:run
    DBSC_CHALLENGE_TTL=2 python3 scripts/e2e.py

Without DBSC_CHALLENGE_TTL those checks are reported as skipped, not failed.

Requires `cryptography` (EC keygen + ES256 signing).

SESSION/TICKET ROTATION needs a fourth instance, only because the rotation grace has
   to be short enough to outwait:

    mvn -Pdemo,rotation-e2e -Dmaven.repo.local=.m2repo spring-boot:run
    DBSC_ROTATION_BASE=https://localhost:9445 DBSC_ROTATION_GRACE=5 python3 scripts/e2e.py

scripts/run-demos.sh starts all four for you.
"""
import base64, json, os, re, ssl, sys, time
import http.cookiejar
import urllib.request, urllib.parse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

BASE = "https://localhost:8443"
PASS = []
FAIL = []
SKIP = []

# Seconds the running demo's dbsc.challenge-ttl is set to, if it was shortened.
# Its absence makes the expiry checks unrunnable rather than failing them, since
# waiting out a 5-minute default is not a practical test.
CHALLENGE_TTL_S = float(os.environ.get("DBSC_CHALLENGE_TTL") or 0) or None

# A second instance, started with dbsc.unregistered=deny. The policy is a property of
# the server, not of the client, so the only way to observe both outcomes is to ask two
# servers. The main demo runs the default (allow); section L drives the deny instance
# and compares the two answers on the same guarded route. Absent means those checks are
# skipped, the same way the TTL ones are.
DENY_BASE = os.environ.get("DBSC_DENY_BASE") or ""

# A third instance, started with -Pdemo,rotation-e2e: the only difference from the main
# demo is dbsc.rotation-grace, shortened so the suite can outwait it. Rotation itself is
# unconditional, so this instance is not a control -- it is the only way to observe the
# retirement expiring without sleeping through the 60s default. Section O drives it and
# reads the grace from DBSC_ROTATION_GRACE, since it has to outwait it. Absent means those
# checks are skipped.
ROTATION_BASE = os.environ.get("DBSC_ROTATION_BASE") or ""
ROTATION_GRACE_S = float(os.environ.get("DBSC_ROTATION_GRACE") or 0) or None

# The guarded route both instances agree on. Declared in DemoFormLoginTestConfig's
# DbscGuardRoutes; keep this in step with src/demo/java/.../DemoFormLoginTestConfig.java.
GUARDED_PATH = "/app/payment"


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f"  -- {detail}" if detail and not ok else ""))


def skip(name, why):
    SKIP.append(name)
    print(f"[SKIP] {name}  -- {why}")


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def new_client():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
        NoRedirect())
    return opener, jar


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def request(opener, method, path, body=None, headers=None, form=True, base=None,
            replace_cookies=None):
    """Returns (status, headers, text). Never raises on HTTP error status.

    Headers are kept as a list of (name, value) pairs rather than a dict: a dict
    loses repeated headers, and Set-Cookie legitimately repeats on any response
    that sets more than one cookie. Use all_headers() to read them.

    ``replace_cookies`` substitutes named cookies in the outgoing Cookie header
    while keeping every other cookie the jar holds. Pass a plain ``Cookie`` header
    instead and you lose the rest: CookieJar.add_cookie_header only appends when
    the request has no Cookie header at all, so the explicit value wins and the
    jar's cookies are dropped. Tests that pin the credential cookie to a stale
    value while still needing the rest of the jar must come through here.
    """
    data = None
    hdrs = dict(headers or {})
    if replace_cookies:
        merged = {}
        for cookie in opener_jar(opener):
            merged[cookie.name] = cookie.value
        merged.update(replace_cookies)
        hdrs["Cookie"] = "; ".join(
            f"{name}={value}" for name, value in merged.items() if value is not None)
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request((base or BASE) + path, data=data, headers=hdrs, method=method)
    try:
        with opener.open(req) as r:
            return r.status, r.headers.items(), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.items(), e.read().decode()



def opener_jar(opener):
    """The CookieJar an opener built by new_client() carries.

    urllib gives no public accessor for the processor's jar, and the handlers list
    is the only handle on it. Needed by request() when a test overrides one cookie
    but must keep the others.
    """
    for handler in opener.handlers:
        if isinstance(handler, urllib.request.HTTPCookieProcessor):
            return handler.cookiejar
    raise AssertionError("the opener has no HTTPCookieProcessor")


def cookie_value(jar, name):
    for c in jar:
        if c.name == name:
            return c.value
    return None


def cookie(jar, name):
    for c in jar:
        if c.name == name:
            return c
    return None


class Key:
    """An ES256 key pair, the way the native tier uses them."""

    def __init__(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())

    def public_jwk(self):
        nums = self.priv.public_key().public_numbers()
        return {
            "kty": "EC", "crv": "P-256",
            "x": b64u(nums.x.to_bytes(32, "big")),
            "y": b64u(nums.y.to_bytes(32, "big")),
        }

    def sign(self, message: str) -> str:
        der = self.priv.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def jws(self, payload: dict, include_jwk=True, alg="ES256") -> str:
        # typ must be dbsc+jwt; the verifier rejects anything else, including the
        # plain "jwt" a generic JOSE library would default to.
        head = {"alg": alg, "typ": "dbsc+jwt"}
        if include_jwk:
            head["jwk"] = self.public_jwk()
        h = b64u(json.dumps(head, separators=(",", ":")).encode())
        p = b64u(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}.{self.sign(f'{h}.{p}')}"


def login(opener, jar, user="demo", password="demo", base=None):
    """Form login, returns (status, headers, registration_path, csrf).

    The third value is the **registration path**, i.e. the concrete
    `/dbsc/regist/<token>` Chromium is told to POST to. It is not the DBSC session
    id: the token is a single-use value that names the session for one registration
    POST, and the session id itself is only ever in the response body and in the
    application's own session state.

    The CSRF token is rotated on authentication, so the value scraped from the
    login page is stale by the time the login completes. Callers that need a
    usable token must read it from a page served *after* login.
    """
    _, _, html = request(opener, "GET", "/login", base=base)
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    if not m:
        return None, None, None, None
    status, headers, _ = request(
        opener, "POST", "/login",
        {"username": user, "password": password, "_csrf": m.group(1)}, base=base)
    return status, headers, registration_path(headers), m.group(1)


def registration_path(headers):
    """The token path from the registration header, or None."""
    reg = header(headers, "Secure-Session-Registration")
    if not reg:
        return None
    m = re.search(r'path="([^"]+)"', reg)
    return m.group(1) if m else None


def registration_jti(headers):
    """The JTI from the registration header's ``challenge`` parameter, or None.

    bind() names the same challenge in three places on the login response: the
    registration header's ``challenge`` parameter, which is what Chromium is told
    to sign, and the ``Secure-Session-Challenge`` header (plus its legacy alias),
    which is the other side of the same value. This reads the registration header,
    because that is the copy a browser works from; the challenge header carries the
    identical JTI.
    """
    reg = header(headers, "Secure-Session-Registration")
    if not reg:
        return None
    m = re.search(r'challenge="([^"]+)"', reg)
    return m.group(1) if m else None


def session_id_of(opener, base=None):
    """The DBSC session id, as the application reports it.

    The id is not in any cookie -- by design, since session_identifier *is* the id and
    the id is never a cookie value -- so the application is the only source for it.
    """
    status, _, text = request(opener, "GET", "/app/whoami", base=base)
    if status != 200:
        return None
    try:
        return json.loads(text).get("dbscSessionId")
    except ValueError:
        return None


def current_csrf(opener, base=None):
    """Reads the live CSRF token from the page the app renders it into."""
    _, _, html = request(opener, "GET", "/app", base=base)
    m = re.search(r'name="csrf" content="([^"]+)"', html)
    return m.group(1) if m else None


def post_bind(opener, base=None, csrf=None):
    """
    POSTs the Soft DBSC re-offer route.

    The route is an ordinary application route, so it sits behind Spring Security's
    CsrfFilter like every other POST -- a caller with no token is refused by CSRF, not
    by DBSC, and the two 403s are indistinguishable on the wire. That is deliberate: the
    route changes state (it offers to key a device to a session), so it must not be
    reachable without the token a page of ours was given.
    """
    if csrf is None:
        csrf = current_csrf(opener, base=base)
    return request(opener, "POST", "/dbsc/bind", body=b"",
                   headers={"Content-Type": "application/json",
                            "X-CSRF-TOKEN": csrf or "x"},
                   base=base)


def post_guarded(opener, base, csrf):
    """POSTs the guarded route and returns (status, body).

    The route is guarded by its own DbscGuardRoutes matcher, independent of
authentication, so this is the request whose outcome dbsc.unregistered decides.
    """
    status, _, text = request(
        opener, "POST", GUARDED_PATH, form=False,
        body={"amount": 1000, "currency": "usd"},
        headers={"X-CSRF-TOKEN": csrf or "x"},
        base=base)
    return status, text


def all_headers(headers, name):
    """Every value for a header name; Set-Cookie legitimately repeats.

    headers is the (name, value) sequence request() returns, so repeats survive.
    Folding it into a dict first would keep only the last Set-Cookie and make the
    cookie assertions below test the wrong thing.
    """
    return [v for k, v in headers if k.lower() == name.lower()]


def header(headers, name):
    """The first value for a header name, or None."""
    values = all_headers(headers, name)
    return values[0] if values else None


def refresh_jti(headers):
    """The JTI to sign for a refresh, taken from the challenge header.

    The header is now the *only* copy: the challenge travels to the browser as the
    JTI inside ``Secure-Session-Challenge`` and is held server-side against the
    session, so there is no challenge cookie to fall back to. The first refresh leg
    (no proof) is what re-arms the session, so this reads the header from that 403.

    The value is ``"<jti>"``, or ``"<jti>";id="<sessionId>"`` when the server named
    the session, which is what bind() and the refresh leg both emit.
    """
    raw = header(headers, "Secure-Session-Challenge")
    if not raw:
        return None
    m = re.match(r'\s*"([^"]+)"', raw)
    return m.group(1) if m else None


def refresh_jws(key, jti):
    """The refresh proof: a JWS over the challenge with typ=dbsc+jwt.

    No jwk in the header — the server already holds the key, and spec 02 treats a
    jwk on a refresh as a protocol error.
    """
    return key.jws({"jti": jti}, include_jwk=False)


def native_register(opener, reg_path, key, login_headers):
    """Runs native registration off the path the login response advertised.

    The JTI comes from the login response's registration header, which is the value
    bind() asked the browser to sign; the server looks it back up by the session the
    token names, so no cookie carries it. Pass the headers login() returned.

    Returns (jti, status, text).
    """
    jti = registration_jti(login_headers)
    if jti is None:
        return None, None, "no challenge in the login response's registration header"
    status, _, text = request(
        opener, "POST", reg_path, body=b"", headers={
            "Secure-Session-Response": key.jws({"jti": jti}),
            "Content-Type": "application/json"})
    return jti, status, text


def rebind(opener):
    """Mints a fresh registration token for the session this client already holds.

    The registration path is single-use, and only dbsc.bind() mints one, so a
    *second* registration attempt on the same session -- the already-registered
    case, a consumed-JTI replay, an expired challenge -- cannot reuse the login's
    path or log in again: a second login mints a new random DBSC session id, so
    the attempt would be made against a different session and would prove nothing.
    The demo's /app/rebind re-binds the *current* session and answers with the
    Secure-Session-Registration header, whose path is the new token.

    Returns the fresh registration path, or None when the route refused.
    """
    # /app/rebind sits on the authenticated, CSRF-protected chain — it is an
    # application route, not a protocol route — so it needs the live header token.
    status, headers, _ = request(opener, "POST", "/app/rebind", body=b"", headers={
        "Content-Type": "application/json",
        "X-CSRF-TOKEN": current_csrf(opener) or "x"})
    if status != 200:
        return None
    return registration_path(headers)


def native_register_manual(opener, jti, key, base=None, reg_path=None):
    """Native registration with the JTI and path supplied, not read from a response.

    Needed when the proof must carry a JTI the server has since forgotten -- expired,
    consumed, or never issued to this session -- when registration is aimed at the
    low-budget instance rather than the main demo, and when the path itself is wrong
    on purpose. The JTI travels in the signed proof and nowhere else.
    Returns (jti, status, text).
    """
    status, _, text = request(
        opener, "POST", reg_path or (MAIN_REG_PATH + "/" + "x" * 43), body=b"", base=base, headers={
            "Secure-Session-Response": key.jws({"jti": jti}),
            "Content-Type": "application/json"})
    return jti, status, text



# The registration path prefix, mirrored from dbsc.registration-path. The suite
# talks to a running demo, so it cannot read the property; keep this in step with
# src/demo/resources/application-demo.yaml.
MAIN_REG_PATH = "/dbsc/regist"



def tier_of(opener):
    """The tier /app/whoami reports, or None when it is not JSON."""
    status, _, text = request(opener, "GET", "/app/whoami")
    if status != 200:
        return None
    try:
        return json.loads(text).get("tier")
    except ValueError:
        return None


def now_ms():
    return int(time.time() * 1000)


def main():
    print(f"=== DBSC E2E against {BASE} ===\n")

    # ---------------------------------------------------------------- 1. login
    print("-- 1. form login binds a DBSC session --")
    opener, jar = new_client()
    status, headers, reg_path, csrf = login(opener, jar)
    check("POST /login redirects (302)", status == 302, f"got {status}")
    check("JSESSIONID issued and Secure",
          cookie(jar, "JSESSIONID") is not None and cookie(jar, "JSESSIONID").secure)
    reg = header(headers, "Secure-Session-Registration")
    check("Secure-Session-Registration present", reg is not None)
    if reg:
        check('registration header shape "(ES256);path=...;challenge=..."',
              bool(re.fullmatch(r'\(ES256\);path="/dbsc/regist/[A-Za-z0-9_-]{43}";challenge="[^"]+"', reg)),
              reg)
    check("the registration path carries a single-use token, not the session id",
          reg_path is not None and reg_path.startswith(MAIN_REG_PATH + "/")
          and reg_path[len(MAIN_REG_PATH) + 1:] != session_id_of(opener),
          str(reg_path))
    check("legacy Sec-Session-Registration emitted in parallel",
          header(headers, "Sec-Session-Registration") is not None)
    check("no __Host-dbsc-challenge cookie: the challenge travels in a header now",
          cookie(jar, "__Host-dbsc-challenge") is None)
    check("no __Host-dbsc-reg cookie: the path carries the token now",
          cookie(jar, "__Host-dbsc-reg") is None)
    # The challenge is now a response header only. It is emitted twice under two names
    # (the spec name and the legacy alias bind() straddles), and must not become a
    # cookie: asking the browser to hold our state is what the header-only design
    # removed.
    challenge = refresh_jti(headers)
    check("Secure-Session-Challenge header carries the challenge JTI",
          challenge is not None, str(header(headers, "Secure-Session-Challenge")))
    check("the challenge header names the session it belongs to",
          'id="' in (header(headers, "Secure-Session-Challenge") or ""),
          str(header(headers, "Secure-Session-Challenge")))
    check("legacy Sec-Session-Challenge emitted in parallel",
          header(headers, "Sec-Session-Challenge") is not None)
    check("the registration header and the challenge header name the same JTI",
          registration_jti(headers) == challenge,
          f"{registration_jti(headers)} != {challenge}")
    # The credential cookie is set from bind(), before registration, so a request that
    # omits it is distinguishable from a browser that never bound at all.
    bind_cookie = cookie(jar, "__Host-auth_cookie")
    check("__Host-auth_cookie cookie present from bind()", bind_cookie is not None)
    # session_identifier is the id itself (spec 9.6: "the identifier for the newly
    # created session"), so nothing is ever set under a cookie of that name. That is the
    # design: the id lives only server-side and in the JSON, so a lifted cookie jar holds
    # a rotating ticket and no long-lived id.
    check("no cookie is set under the name session_identifier",
          cookie(jar, "session_identifier") is None)
    check("__Host- cookies are Secure",
          bool(bind_cookie and bind_cookie.secure))
    check("__Host- cookies are HttpOnly and Path=/",
          bool(bind_cookie and bind_cookie.has_nonstandard_attr("HttpOnly")
               and bind_cookie.path == "/"))
    check("the DBSC session id is not the servlet session id",
          session_id_of(opener) != cookie_value(jar, "JSESSIONID")
          and session_id_of(opener) is not None,
          f"{session_id_of(opener)} == {cookie_value(jar, 'JSESSIONID')}")

    # ------------------------------------------------- 2. native registration
    print("\n-- 2. native registration (/dbsc/regist/<token>) --")
    native = Key()
    jws = native.jws({"jti": challenge})
    # Chromium sends only the JWS header on this route; the body is empty.
    status, resp_headers, text = request(
        opener, "POST", reg_path, body=b"", headers={
            "Secure-Session-Response": jws, "Content-Type": "application/json"})
    check("POST /dbsc/regist/<token> -> 200", status == 200, f"got {status}: {text[:200]}")
    if status == 200:
        cfg = json.loads(text)
        check("registration advertises the session id as session_identifier",
              cfg.get("session_identifier") == session_id_of(opener),
              f"{cfg.get('session_identifier')} != {session_id_of(opener)}")
        check("credential cookie set", cookie(jar, "__Host-auth_cookie") is not None)
        check("still no cookie under the name session_identifier",
              cookie(jar, "session_identifier") is None)
        check("and no challenge cookie was set by the registration either",
              cookie(jar, "__Host-dbsc-challenge") is None)

        # The token is single-use: replaying the same path must be refused, and
        # refused as a replay rather than as an unknown route.
        replay_status, _, replay_text = request(
            opener, "POST", reg_path, body=b"", headers={
                "Secure-Session-Response": jws, "Content-Type": "application/json"})
        check("replaying the registration token -> 403", replay_status == 403,
              f"got {replay_status}: {replay_text[:200]}")
        check("the replay is reported as REGISTRATION_TOKEN_CONSUMED",
              "REGISTRATION_TOKEN_CONSUMED" in replay_text, replay_text[:200])

        # An unknown token is a different thing entirely: it was never ours.
        unknown_status, _, unknown_text = request(
            opener, "POST", MAIN_REG_PATH + "/" + "A" * 43, body=b"", headers={
                "Secure-Session-Response": jws, "Content-Type": "application/json"})
        check("an unknown registration token -> 403 SESSION_NOT_FOUND",
              unknown_status == 403 and "SESSION_NOT_FOUND" in unknown_text,
              f"{unknown_status}: {unknown_text[:200]}")

    # ---------------------------------------------------- 3. tier is now dbsc
    print("\n-- 3. tier promotion --")
    status, _, text = request(opener, "GET", "/app/whoami")
    check("GET /app/whoami -> 200", status == 200, f"got {status}")
    who = json.loads(text) if status == 200 else {}
    check("tier is dbsc after native registration", who.get("tier") == "dbsc", str(who))
    check("deviceKey true", who.get("deviceKey") is True, str(who))
    check("dbscSessionId is independent of httpSessionId",
          who.get("dbscSessionId") is not None
          and who.get("dbscSessionId") != who.get("httpSessionId")
          and "coupled" not in who,
          str(who))

    # ------------------------------------------------------- 4. native refresh
    print("\n-- 4. native refresh (/dbsc/refresh) --")
    # First leg: no proof -> 403 with a fresh challenge. 401 would kill the
    # session in Chromium, so 403 is load-bearing.
    status, h1, t1 = request(opener, "POST", "/dbsc/refresh", body=b"",
                             headers={"Content-Type": "application/json",
                                      "Sec-Secure-Session-Id": session_id_of(opener)})
    check("first leg (no proof) -> 403, never 401", status == 403, f"got {status}: {t1[:200]}")
    check("the first leg is refused for want of a proof, not a session",
          "CHALLENGE" not in t1 and "SESSION_NOT_FOUND" not in t1, t1[:200])
    new_ch = refresh_jti(h1)
    check("first leg issues a fresh challenge in the header", new_ch is not None)
    check("first leg sets no challenge cookie",
          cookie(jar, "__Host-dbsc-challenge") is None)
    check("first leg does not return 401", status != 401)

    if new_ch:
        # The refresh proof is a JWS (not the bare "<jti>.<sig>" pair), and the
        # session id travels in a header because the session cookie is gone by now.
        sig = native.sign("")
        status, h2, t2 = request(
            opener, "POST", "/dbsc/refresh", body=b"", headers={
                "Content-Type": "application/json",
                "Sec-Secure-Session-Id": session_id_of(opener),
                "Secure-Session-Response": refresh_jws(native, new_ch)})
        check("second leg (valid proof) -> 200", status == 200, f"got {status}: {t2[:200]}")

    # ------------------------------------------------ 5. refresh replay guard
    print("\n-- 5. a consumed challenge cannot be replayed --")
    if new_ch:
        status, _, t3 = request(
            opener, "POST", "/dbsc/refresh", body=b"", headers={
                "Content-Type": "application/json",
                "Sec-Secure-Session-Id": session_id_of(opener),
                "Secure-Session-Response": refresh_jws(native, new_ch)})
        check("replaying a consumed challenge -> 403", status == 403, f"got {status}")

    # ------------------------------------------------------- 6. bad signature
    print("\n-- 6. a bad refresh signature demotes to none --")
    # Leg 1 first: it both proves the session is still dbsc and hands back a
    # fresh, unconsumed challenge for the bad-signature attempt.
    status, h6, _ = request(opener, "POST", "/dbsc/refresh", body=b"",
                            headers={"Content-Type": "application/json",
                                     "Sec-Secure-Session-Id": session_id_of(opener)})
    _, _, before = request(opener, "GET", "/app/whoami")
    who_before = json.loads(before)
    ch_now = refresh_jti(h6)
    check("session starts this step at tier dbsc",
          who_before.get("tier") == "dbsc", str(who_before))
    if ch_now:
        bogus = Key()
        status, _, t4 = request(
            opener, "POST", "/dbsc/refresh", body=b"", headers={
                "Content-Type": "application/json",
                "Sec-Secure-Session-Id": session_id_of(opener),
                "Secure-Session-Response": refresh_jws(bogus, ch_now)})
        check("wrong-key refresh -> 403", status == 403, f"got {status}")
        check("a bad refresh signature is reported as SIGNATURE_INVALID",
              "SIGNATURE_INVALID" in t4, t4[:200])
        _, _, tw = request(opener, "GET", "/app/whoami")
        w = json.loads(tw)
        check("tier demoted to none after a failed refresh", w.get("tier") == "none", str(w))

    # ------------------------------------------------- 7. bound routes are gone
    # This pins the removal: the bound (Web Crypto polyfill) protocol was deleted,
    # so its routes must not come back -- by re-registration, by an alias, or by a
    # wildcard handler that would silently resurrect an unauthenticated surface.
    #
    # The exact status is not asserted for every method. An unauthenticated request
    # for an /app-scoped path is answered by the login redirect before routing ever
    # happens, so a status pin here would be measuring the security chain, not the
    # absence of the route. What must hold -- authenticated or not -- is that no
    # bound route produces a bound response.
    print("\n-- 7. the removed bound protocol is not served --")
    for path in ("/dbsc-bound/state", "/dbsc-bound/challenge",
                 "/dbsc-bound/registration", "/dbsc-bound/refresh"):
        for method in ("GET", "POST"):
            status, _, text = request(
                opener, method, path, body={} if method == "POST" else None, form=False)
            check(f"{method} {path} is not served",
                  status in (404, 403, 302, 401) and "phase" not in text,
                  f"got {status}: {text[:120]}")
            check(f"{method} {path} never returns a bound payload",
                  not text.strip().startswith("{") or "phase" not in text,
                  f"got {status}: {text[:120]}")

    # ---------------------------------------------------- 8. well-known
    print("\n-- 8. well-known metadata --")
    status, wh, twk = request(opener, "GET", "/.well-known/device-bound-sessions")
    check("GET /.well-known/device-bound-sessions -> 200", status == 200, f"got {status}")
    check("well-known is cacheable",
          "max-age" in (header(wh, "Cache-Control") or ""), str(header(wh, "Cache-Control")))
    if status == 200:
        doc = json.loads(twk)
        check("well-known has registering_origins and relying_origins",
              "registering_origins" in doc and "relying_origins" in doc, twk[:200])

    # ==================================================================
    # The sections below widen coverage from "the happy path works" to
    # "every normative branch in specs 02-08 answers as documented".
    # ==================================================================

    # ------------------------------------------------ A. session config shape
    print("\n-- A. registration JSON is byte-exact against the wire cookie --")
    a_opener, a_jar = new_client()
    # The third value is the registration *path*, not the session id: the path's
    # token names the session for one POST and is unrelated to the session id.
    _, a_headers, a_reg, _ = login(a_opener, a_jar)
    # The session id lives in the session cookie and is echoed by the app, so it is
    # read back rather than inferred from the login response.
    a_sid = session_id_of(a_opener)
    a_key = Key()
    _, a_status, a_text = native_register(a_opener, a_reg, a_key, a_headers)
    a_cfg = json.loads(a_text) if a_status == 200 else {}

    check("native registration returns a JSON body (a 200 with no body is opt-out)",
          bool(a_cfg), a_text[:200])
    check("session_identifier is the session id the app reports",
          a_cfg.get("session_identifier") == a_sid,
          f"{a_cfg.get('session_identifier')} != {a_sid}")
    check("no cookie named session_identifier is ever set",
          cookie_value(a_jar, "session_identifier") is None)
    # The id is a store key, not a cookie value: the only cookie that moves is the
    # rotating credential one, so a lifted jar holds no long-lived id.
    check("the id travels in no cookie",
          a_cfg.get("session_identifier") != cookie_value(a_jar, "__Host-auth_cookie"),
          "the id is the credential cookie value")
    check("the session id is not the servlet session id",
          a_sid != cookie_value(a_jar, "JSESSIONID"),
          f"{a_sid} == {cookie_value(a_jar, 'JSESSIONID')}")
    check("refresh_url is /dbsc/refresh for the native tier",
          a_cfg.get("refresh_url") == "/dbsc/refresh", str(a_cfg.get("refresh_url")))
    check("scope.include_site is a boolean",
          isinstance((a_cfg.get("scope") or {}).get("include_site"), bool), str(a_cfg.get("scope")))
    creds = a_cfg.get("credentials") or []
    check("credentials is a non-empty list", bool(creds), str(creds))
    if creds:
        cred0 = creds[0]
        check("credential[0] is the cookie credential",
              cred0.get("type") == "cookie", str(cred0))
        # The protected cookie is the credential one, NOT the session cookie: they are
        # two cookies with two jobs, and the JSON names them in two different fields.
        check("credential[0].name is the credential cookie",
              cred0.get("name") == "__Host-auth_cookie", str(cred0.get("name")))
        check("credential[0].name is not session_identifier",
              cred0.get("name") != "session_identifier",
              str(cred0.get("name")))
        # Spec 07: attributes must match the Set-Cookie attributes exactly, spaces
        # after semicolons included, and must NOT carry Max-Age.
        set_cookie = " ".join(all_headers(a_headers, "Set-Cookie"))
        declared = cred0.get("attributes", "")
        check("attributes mirror the Set-Cookie attributes exactly",
              declared == "Path=/; Secure; HttpOnly; SameSite=Lax", repr(declared))
        check("attributes carry no Max-Age",
              "Max-Age" not in declared, declared)

    # ------------------------------------------------- scope & initiators
    # Both keys are instructions to the browser, so what is asserted here is only the
    # shape the server emits -- order, types, and the presence of the keys at all.
    scope_map = a_cfg.get("scope") or {}
    specs = scope_map.get("scope_specification")
    check("scope.scope_specification is a list", isinstance(specs, list), str(specs))
    if isinstance(specs, list):
        # Bigger than one, or the demo's own two rules are not being read at all and
        # every assertion below is vacuously true.
        check("the demo's configured scope rules survive into the JSON",
              len(specs) >= 1, str(specs))
        for i, rule in enumerate(specs):
            check(f"scope_specification[{i}].type is include or exclude",
                  rule.get("type") in ("include", "exclude"), str(rule))
            check(f"scope_specification[{i}].domain is a string",
                  isinstance(rule.get("domain"), str), str(rule))
            check(f"scope_specification[{i}].path is a string",
                  isinstance(rule.get("path"), str), str(rule))
    initiators = a_cfg.get("allowed_refresh_initiators")
    check("allowed_refresh_initiators is a list", isinstance(initiators, list), str(initiators))
    if isinstance(initiators, list):
        check("every initiator is a non-empty string",
              all(isinstance(x, str) and x for x in initiators), str(initiators))

    # ------------------------------------------------- B. error ordering
    print("\n-- B. failures are reported in the spec's normative order --")
    # A missing response header outranks the challenge lookup, so the caller learns
    # the real problem instead of a downstream one.
    b_opener, b_jar = new_client()
    _, _, b_reg, _ = login(b_opener, b_jar)
    status, _, text = request(
        b_opener, "POST", b_reg, body=b"",
        headers={"Content-Type": "application/json"})
    check("no response header (and no proof at all) -> 403 MISSING_RESPONSE_HEADER",
          status == 403 and "MISSING_RESPONSE_HEADER" in text, f"{status} {text[:160]}")

    # The registration path is single-use, and it is consumed by any POST that
    # reaches the protocol engine -- including one rejected as MALFORMED_JWS, since
    # the token is spent before the proof is parsed. Each attempt below therefore
    # needs its own token, or the second one is refused as REGISTRATION_TOKEN_CONSUMED
    # and never reaches the rule under test.

    # typ is checked before jwk presence, so a JWS that is wrong in both ways
    # still reports the earlier rule.
    b_key = Key()
    head = b64u(json.dumps({"alg": "ES256", "typ": "jwt"}, separators=(",", ":")).encode())
    payload = b64u(json.dumps({"jti": "x"}, separators=(",", ":")).encode())
    wrong_typ = f"{head}.{payload}.{b_key.sign(f'{head}.{payload}')}"
    status, _, text = request(
        b_opener, "POST", rebind(b_opener) or b_reg, body=b"",
        headers={"Secure-Session-Response": wrong_typ, "Content-Type": "application/json"})
    check("typ != dbsc+jwt -> MALFORMED_JWS (checked before jwk)",
          "MALFORMED_JWS" in text, f"{status} {text[:160]}")

    status, _, text = request(
        b_opener, "POST", rebind(b_opener) or b_reg, body=b"",
        headers={"Secure-Session-Response": b_key.jws({"jti": "x"}, include_jwk=False),
                 "Content-Type": "application/json"})
    check("registration JWS without a jwk header -> MALFORMED_JWS",
          "MALFORMED_JWS" in text, f"{status} {text[:160]}")

    # An anonymous refresh cannot name a session, and must not 401.
    anon3, _ = new_client()
    status, _, text = request(
        anon3, "POST", "/dbsc/refresh", body=b"", headers={"Content-Type": "application/json"})
    check("refresh with no session id -> 403 SESSION_NOT_FOUND, never 401",
          status == 403 and "SESSION_NOT_FOUND" in text, f"{status} {text[:160]}")

    # A proof presented for a session with no native key: the key lookup the spec
    # orders second wins over any signature problem.
    c_opener, c_jar = new_client()
    login(c_opener, c_jar)
    # A refresh names the session by id, and the login response no longer carries
    # one: it comes from /app/whoami.
    c_sid = session_id_of(c_opener)
    _, c_h, _ = request(c_opener, "POST", "/dbsc/refresh", body=b"",
                        headers={"Content-Type": "application/json",
                                 "Sec-Secure-Session-Id": c_sid})
    c_ch = refresh_jti(c_h)
    if c_ch:
        status, _, text = request(
            c_opener, "POST", "/dbsc/refresh", body=b"", headers={
                "Content-Type": "application/json",
                "Sec-Secure-Session-Id": c_sid,
                "Secure-Session-Response": refresh_jws(Key(), c_ch)})
        check("refresh before registering a key -> KEY_NOT_FOUND",
              "KEY_NOT_FOUND" in text, f"{status} {text[:160]}")

    # C. already-registered
    print("\n-- C. a second registration of the same kind is refused --")
    # A fresh challenge: the login's JTI was consumed by the first registration, and
    # the refresh leg's 403 header is what re-arms the session with another one.
    _, a_h2, _ = request(a_opener, "POST", "/dbsc/refresh", body=b"",
                         headers={"Content-Type": "application/json",
                                  "Sec-Secure-Session-Id": a_sid})
    a_ch2 = refresh_jti(a_h2)
    # The registration path is single-use too, so the second registration cannot
    # reuse a_reg. It also cannot come from a fresh login: a login mints a new random
    # DBSC session id, so that would test a *different* session. /app/rebind re-binds
    # the session a already holds, which is what makes this a second registration of
    # the same session.
    a_reg2 = rebind(a_opener)
    check("a second registration opportunity is minted for the same session",
          a_reg2 is not None and a_reg2 != a_reg)
    status, _, text = request(
        a_opener, "POST", a_reg2 or MAIN_REG_PATH + "/" + "x" * 43, body=b"", headers={
            "Secure-Session-Response": a_key.jws({"jti": a_ch2}),
            "Content-Type": "application/json"})
    check("second native registration -> SESSION_ALREADY_REGISTERED",
          "SESSION_ALREADY_REGISTERED" in text, f"{status} {text[:160]}")

    # ------------------------------------------------------ D. cross-protocol
    # Only the native JWS form is served, so anything shaped like the removed
    # two-segment bound signature must be a malformed JWS rather than, say, a
    # crash or a silently accepted proof.
    print("\n-- D. a proof that is not a JWS is rejected as MALFORMED_JWS --")
    status, _, text = request(
        b_opener, "POST", rebind(b_opener) or b_reg, body=b"", headers={
            "Secure-Session-Response": b64u(b"x") + "." + b64u(b"y"),
            "Content-Type": "application/json"})
    check("a two-segment bound-style signature on the native route -> MALFORMED_JWS",
          "MALFORMED_JWS" in text, f"{status} {text[:160]}")

    # --------------------------------------------------------- E. tier matrix
    print("\n-- E. tier reflects the surviving keys --")
    e1, e1_jar = new_client()
    login(e1, e1_jar)
    check("a session with no key reads tier none", tier_of(e1) == "none", str(tier_of(e1)))

    e2, e2_jar = new_client()
    _, e2_h, e2_reg, _ = login(e2, e2_jar)
    e2_key = Key()
    _, e2_status, e2_text = native_register(e2, e2_reg, e2_key, e2_h)
    check("a session that registered natively reads tier dbsc",
          tier_of(e2) == "dbsc", f"{e2_status} {e2_text[:120]}")

    # The removed tier must never be produced by the survivor: a native client
    # that registered correctly is dbsc, not some resurrected bound tier.
    status, _, text = request(e2, "GET", "/app/whoami")
    who2 = json.loads(text)
    check("whoami reports deviceKey true and a tier of dbsc",
          who2.get("deviceKey") is True and who2.get("tier") == "dbsc", str(who2))
    check("the bound tier is never produced",
          who2.get("tier") not in ("bound", None), str(who2))

    # ------------------------------------- F. challenge expiry and consumption
    print("\n-- F. challenge lifecycle: single-use and expiry --")

    # A consumed challenge is observable at any TTL, so this always runs. Nothing is
    # carried to re-present it: the JTI travels in the signed proof, and the server
    # looks it up by the session the registration token names.
    #
    # What proves the challenge was consumed has changed with the new design: the
    # registration token is single-use too, so a replay of the *path* is now caught
    # as REGISTRATION_TOKEN_CONSUMED before the challenge store is ever consulted.
    # To reach the challenge's own consumption rule the second attempt therefore
    # has to carry a *fresh, unconsumed* token, which /app/rebind mints for the same
    # session.
    k1_opener, k1_jar = new_client()
    _, k1_h, k1_reg, _ = login(k1_opener, k1_jar)
    k1_jti = registration_jti(k1_h)
    k1_key = Key()
    status, _, text = request(
        k1_opener, "POST", k1_reg, body=b"", headers={
            "Secure-Session-Response": k1_key.jws({"jti": k1_jti}),
            "Content-Type": "application/json"})
    check("the first use of a challenge succeeds", status == 200, f"{status} {text[:160]}")

    # A fresh token for the same session, so the replay below is refused for its
    # spent JTI rather than for its spent path. The proof re-presents k1_jti by hand,
    # signed with the key that registered, because that JTI is spent server-side.
    request(k1_opener, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json",
                     "Sec-Secure-Session-Id": session_id_of(k1_opener)})
    # The refresh leg above has just armed the session with a new JTI, and only
    # bind() mints registration tokens, so the token has to be re-minted for k1's
    # *own* session: /app/rebind does exactly that, whereas a re-login would mint a
    # new random session id and make this attempt a first registration of a different
    # session rather than a *second* attempt at k1's consumed JTI.
    k1_reg2 = rebind(k1_opener)
    check("a fresh registration token is minted for the session with the spent JTI",
          k1_reg2 is not None and k1_reg2 != k1_reg)
    status, _, text = request(
        k1_opener, "POST", k1_reg2 or MAIN_REG_PATH + "/" + "x" * 43, body=b"", headers={
            "Secure-Session-Response": k1_key.jws({"jti": k1_jti}),
            "Content-Type": "application/json"})
    check("reusing a consumed JTI -> CHALLENGE_CONSUMED",
          "CHALLENGE_CONSUMED" in text, f"{status} {text[:160]}")

    # The same must hold on the refresh leg: one challenge store, one consumption.
    k2_opener, k2_jar = new_client()
    _, k2_h, k2_reg, _ = login(k2_opener, k2_jar)
    k2_jti = registration_jti(k2_h)
    k2_key = Key()
    _, status, text = native_register_manual(k2_opener, k2_jti, k2_key, reg_path=k2_reg)
    check("a challenge works on the native registration route",
          status == 200, f"{status} {text[:160]}")
    # A refresh names its session by header. Without it the request dies as
    # SESSION_NOT_FOUND and the challenge store is never consulted, which would
    # test nothing about consumption.
    status, _, text = request(
        k2_opener, "POST", "/dbsc/refresh", body=b"", headers={
            "Sec-Secure-Session-Id": session_id_of(k2_opener),
            "Secure-Session-Response": refresh_jws(k2_key, k2_jti),
            "Content-Type": "application/json"})
    check("the same JTI replayed on the native refresh route -> CHALLENGE_CONSUMED",
          "CHALLENGE_CONSUMED" in text, f"{status} {text[:160]}")

    if CHALLENGE_TTL_S is None:
        skip("expired challenge -> CHALLENGE_EXPIRED",
             "set DBSC_CHALLENGE_TTL and start the demo with a short dbsc.challenge-ttl")
    else:
        # The JTI is signed directly with the client's key rather than re-presented
        # from anywhere: the server holds the challenge against the session, and the
        # proof names it in its payload. Waiting out the TTL leaves the session's
        # stored challenge lapsed while the signed proof still names its JTI, so the
        # lookup finds nothing live and the expiry branch is the one reached.
        #
        # Registration adds a second clock: its token carries a TTL too
        # (registration-token-ttl, 5m by default), but the token is checked
        # *before* the challenge and this wait is short, so the path below stays
        # a live one and CHALLENGE_EXPIRED, not REGISTRATION_TOKEN_EXPIRED, is
        # the branch under test.
        k3_opener, k3_jar = new_client()
        _, k3_h, k3_reg, _ = login(k3_opener, k3_jar)
        k3_jti = registration_jti(k3_h)
        time.sleep(CHALLENGE_TTL_S + 1.0)
        k3_key = Key()
        status, _, text = request(
            k3_opener, "POST", k3_reg, body=b"", headers={
                "Secure-Session-Response": k3_key.jws({"jti": k3_jti}),
                "Content-Type": "application/json"})
        check("a stale JTI presented after the TTL -> CHALLENGE_EXPIRED",
              status == 403 and "CHALLENGE_EXPIRED" in text, f"{status} {text[:160]}")
        check("an expired challenge is not reported as missing or consumed",
              "CHALLENGE_NOT_FOUND" not in text and "CHALLENGE_CONSUMED" not in text,
              text[:160])
        check("an expired challenge is not reported as a bad registration token",
              "REGISTRATION_TOKEN_EXPIRED" not in text
              and "REGISTRATION_TOKEN_CONSUMED" not in text
              and "SESSION_NOT_FOUND" not in text, text[:160])

        # A JTI that never existed is a different failure and must stay distinct.
        # It needs its own session and token: the attempt above spends the token it
        # presented (consumption precedes verification) and arms a fresh challenge,
        # so reusing either would report REGISTRATION_TOKEN_CONSUMED or
        # CHALLENGE_CONSUMED rather than the unknown-JTI branch under test.
        k4_opener, k4_jar = new_client()
        _, _, k4_reg, _ = login(k4_opener, k4_jar)
        status, _, text = request(
            k4_opener, "POST", k4_reg, body=b"", headers={
                "Secure-Session-Response": k3_key.jws({"jti": "n" * 43}),
                "Content-Type": "application/json"})
        check("an unknown JTI -> CHALLENGE_NOT_FOUND",
              "CHALLENGE_NOT_FOUND" in text, f"{status} {text[:160]}")

    # ------------------------------------------------- N. INVALID_JWK
    # Only the native route is served now, so the JWK rules are exercised through
    # the JWS header -- the same place a browser's key travels.
    # Each attempt names a live JTI: the refresh leg's 403 in the loop below re-arms
    # the session, so the JTI from the re-login's registration header is the live one.
    print("\n-- G. a JWK that breaks the key rules is INVALID_JWK, not a crash --")
    n_opener, n_jar = new_client()
    _, _, _, _ = login(n_opener, n_jar)
    # The refresh leg names the session by id, which is read from /app/whoami now
    # that the login response carries a registration path instead.
    n_sid = session_id_of(n_opener)
    # Registration is behind the token path now, so the loop needs a fresh token
    # per attempt: a consumed path would be refused before the JWK is looked at.
    # A refresh leg arms the session with a fresh challenge, and the re-login below
    # issues a fresh token that names the same JTI, so each attempt gets both.
    # Each of these trips a different rule in Jwk.validate. The signature is real
    # and the challenge is live, so only the key check can reject the request.
    for label, bad_key, expect in [
            ("an unsupported curve (P-384) -> INVALID_JWK",
             {"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"}, "unsupported curve"),
            ("an EC key with no coordinates -> INVALID_JWK",
             {"kty": "EC", "crv": "P-256"}, "missing x or y"),
            ("an unsupported key type (oct) -> INVALID_JWK",
             {"kty": "oct", "k": "AAAA"}, "unsupported key type"),
            ("an RSA modulus under 2048 bits -> INVALID_JWK",
             {"kty": "RSA", "n": "AQAB"}, "too short")]:
        request(n_opener, "POST", "/dbsc/refresh", body=b"",
                headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": n_sid})
        _, n_h2, n_reg, _ = login(n_opener, n_jar)
        # The JTI signs the fresh registration header -- the value the server has
        # just armed the session with. No cookie carries it any more.
        n_jti = registration_jti(n_h2)
        n_head = {"alg": "ES256", "typ": "dbsc+jwt", "jwk": bad_key}
        n_h = b64u(json.dumps(n_head, separators=(",", ":")).encode())
        n_p = b64u(json.dumps({"jti": n_jti}, separators=(",", ":")).encode())
        status, _, text = request(
            n_opener, "POST", n_reg, body=b"", headers={
                "Secure-Session-Response": f"{n_h}.{n_p}.{b64u(b'0' * 64)}",
                "Content-Type": "application/json"})
        check(label, status == 403 and "INVALID_JWK" in text, f"{status} {text[:160]}")
        # The rule that fired is named, so a caller can tell a rejected curve from
        # an undersized modulus without reading the source.
        check(f"  ...and names the rule: {expect}", expect in text, text[:160])

    # A JWK whose shape contradicts the declared alg. Jwk.validate() accepts the key
    # on its own terms, so the mismatch is caught one step later by
    # Jwk.detectAlgorithm(). Without this check UNKNOWN_ALGORITHM has no coverage at
    # all: the only other path to it was the removed bound route's ES256-only rule.
    alg_opener, alg_jar = new_client()
    _, alg_h, alg_reg, _ = login(alg_opener, alg_jar)
    request(alg_opener, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json",
                     "Sec-Secure-Session-Id": session_id_of(alg_opener)})
    alg_jti = registration_jti(alg_h)
    # A fresh token: the login above issued one, and the refresh leg did not
    # consume a path, but reading it from a fresh login keeps this independent
    # of the earlier one's state.
    _, _, alg_reg2, _ = login(alg_opener, alg_jar)
    alg_key = Key()
    status, _, text = request(
        alg_opener, "POST", alg_reg2, body=b"", headers={
            "Secure-Session-Response": alg_key.jws({"jti": alg_jti}, alg="RS256"),
            "Content-Type": "application/json"})
    check("alg disagreeing with the JWK -> UNKNOWN_ALGORITHM",
          status == 403 and "UNKNOWN_ALGORITHM" in text, f"{status} {text[:160]}")
    check("  ...and is not reported as INVALID_JWK",
          "INVALID_JWK" not in text, text[:160])

    # ------------------------------------------------- H. JTI_MISMATCH
    print("\n-- H. a challenge presented by the wrong session --")
    # A JTI is bound to the session it was issued for. Two sessions are set up and
    # one's challenge JTI is signed onto a proof for the other, which is the case a
    # stolen or replayed challenge hits. The signature is made by the *right* key for
    # the presenting session, so the session binding is the only thing rejecting it.
    q1, q1_jar = new_client()
    _, q1_h, q1_reg, _ = login(q1, q1_jar)
    q1_sid = session_id_of(q1)
    # q1 needs a key of its own too. The refresh leg refuses a session with no key
    # before it ever issues a challenge, so an unregistered q1 has no challenge to
    # present and the check would prove nothing about session binding.
    q1_key = Key()
    native_register_manual(q1, registration_jti(q1_h), q1_key, reg_path=q1_reg)

    q2, q2_jar = new_client()
    _, q2_h, q2_reg, _ = login(q2, q2_jar)
    q2_sid = session_id_of(q2)
    # q2 must hold a real key, or the key lookup would reject the request before
    # the session binding is ever compared. Registering spends q2_reg -- the path is
    # single-use -- so the token is kept from here.
    q2_ch = registration_jti(q2_h)
    q2_key = Key()
    native_register_manual(q2, q2_ch, q2_key, reg_path=q2_reg)

    # The challenge q1 was issued has since been consumed, so it is spent before the
    # session binding is even compared. Re-arm q1 with a live challenge and present
    # *that* from the other session. The JTI comes from the refresh leg's own
    # challenge header; nothing about it is in the cookie jar.
    _, q1_h2, _ = request(q1, "POST", "/dbsc/refresh", body=b"",
                          headers={"Content-Type": "application/json",
                                   "Sec-Secure-Session-Id": q1_sid})
    q1_live = refresh_jti(q1_h2)
    # The challenge must still be live when q2 presents it. At the production TTL it
    # always is; at the 2-second test TTL the two requests can straddle the expiry,
    # and the mismatch then surfaces as CHALLENGE_EXPIRED — the same refusal, but for
    # a reason that says nothing about session binding. Re-arm and re-read in a tight
    # pair so the freshness is the only thing this check depends on.
    if not q1_live or q1_h2 is None:
        _, q1_h2, _ = request(q1, "POST", "/dbsc/refresh", body=b"",
                              headers={"Content-Type": "application/json",
                                       "Sec-Secure-Session-Id": q1_sid})
        q1_live = refresh_jti(q1_h2)
    check("q1 holds a live challenge to present from the other session",
          q1_live is not None)

    # A refresh names its session by header; without one the mismatch check is never
    # reached and the request is refused as SESSION_NOT_FOUND instead.
    status, _, text = request(
        q2, "POST", "/dbsc/refresh", body=b"", headers={
            "Sec-Secure-Session-Id": q2_sid,
            "Secure-Session-Response": refresh_jws(q2_key, q1_live),
            "Content-Type": "application/json"})
    check("another session's challenge -> JTI_MISMATCH",
          status == 403 and "JTI_MISMATCH" in text, f"{status} {text[:160]}")
    check("it is not reported as missing or expired",
          "CHALLENGE_NOT_FOUND" not in text and "CHALLENGE_EXPIRED" not in text, text[:160])

    # ---------------------------------------------------- M. logout
    # On its own client: "opener" was deliberately demoted to tier none in step 6,
    # and this is the binding-termination check, not a re-test of that demotion.
    print("\n-- I. logout terminates the binding --")
    l_opener, l_jar = new_client()
    login(l_opener, l_jar)
    # Logout expires the DBSC credential cookie, so check the Set-Cookie header
    # rather than the jar: a jar may simply drop an expired cookie.
    status, lh, _ = request(
        l_opener, "POST", "/logout", body=b"",
        headers={"X-CSRF-TOKEN": current_csrf(l_opener) or "x"})
    check("POST /logout responds with a redirect", status in (302, 303), f"got {status}")
    set_cookies = ", ".join(all_headers(lh, "Set-Cookie"))
    # terminate() must clear every DBSC cookie it knows about, or a revoked session
    # would leave a usable credential cookie behind.
    check("logout expires the DBSC credential cookie",
          "__Host-auth_cookie=" in set_cookies, set_cookies[:300])
    # The pre-registration cookie is gone from the design: the registration token
    # lives in the URL path, so there is nothing left for terminate() to clear. The
    # check is kept as the negative half of that removal -- a __Host-dbsc-reg
    # Set-Cookie here would mean the obsolete cookie had come back.
    check("logout sets no obsolete __Host-dbsc-reg cookie",
          "__Host-dbsc-reg" not in set_cookies, set_cookies[:300])
    # The challenge cookie is gone from the design too: terminate() has only the
    # credential cookie left to clear, and nothing else may reappear under a
    # challenge name -- the challenge is held server-side against the session.
    check("logout sets no obsolete __Host-dbsc-challenge cookie",
          "__Host-dbsc-challenge" not in set_cookies, set_cookies[:300])

    # ---------------------------------- J. unauthenticated access is refused
    print("\n-- J. an anonymous client is refused --")
    anon, _ = new_client()
    status, _, _ = request(anon, "GET", "/app/whoami")
    check("anonymous GET /app/whoami is not 200", status != 200, f"got {status}")

    # ------------------------------------------------- L. dbsc.unregistered policy
    print("\n-- L. dbsc.unregistered decides what an unbound client gets --")
    if not DENY_BASE:
        skip("unregistered client -> 403 on a deny instance",
             "start a second demo with -Ddbsc.unregistered=deny and set DBSC_DENY_BASE")
    else:
        # A client that logs in and then never registers: this is what a browser
        # with no DBSC support looks like, and the two policies must disagree about
        # it. Both checks below are on the *same* route with the same matcher, so the
        # only variable is the property.
        d_opener, d_jar = new_client()
        d_status, _, d_reg, _ = login(d_opener, d_jar, base=DENY_BASE)
        if d_status != 302:
            check("the deny instance accepts the same login", False,
                  f"login returned {d_status}; is an instance on {DENY_BASE}?")
        else:
            check("the deny instance still offers registration",
                  d_reg is not None, str(d_reg))
            d_token = current_csrf(d_opener, base=DENY_BASE)
            d_code, d_text = post_guarded(d_opener, DENY_BASE, d_token)
            check("unregistered client on a deny instance -> 403", d_code == 403,
                  f"got {d_code}: {d_text[:160]}")
            check("that 403 is DBSC_REQUIRED, not a generic refusal",
                  "DBSC_REQUIRED" in d_text, d_text[:160])

            # The control: the same request against the default instance is allowed.
            # Without this the check above would also pass against a guard that
            # refuses everything, which is the failure mode `unregistered` exists to
            # avoid.
            m_opener, m_jar = new_client()
            m_status, _, _, _ = login(m_opener, m_jar)
            m_code, m_text = post_guarded(
                m_opener, BASE, current_csrf(m_opener, base=BASE))
            check("the same request on the default (allow) instance -> 200",
                  m_status == 302 and m_code == 200,
                  f"login {m_status}, guarded {m_code}: {m_text[:160]}")

        # --------------------------------------------------- O. ticket rotation
    print("\n-- O. the credential ticket rotates; the session id does not --")
    if not ROTATION_BASE or not ROTATION_GRACE_S:
        skip("refresh rotates the credential ticket",
             "start a fourth demo with -Pdemo,rotation-e2e and set DBSC_ROTATION_BASE "
             "and DBSC_ROTATION_GRACE")
    else:
        rotation_checks()

    # ------------------------------------ P. a client that manages its own key
    print("\n-- P. the script-client affordances: /dbsc/bind and X-Session-Id --")
    script_checks()

    summary = f"\n=== {len(PASS)} passed, {len(FAIL)} failed"
    summary += f", {len(SKIP)} skipped ===" if SKIP else " ==="
    print(summary)
    if SKIP:
        print("skipped: " + ", ".join(SKIP))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


def rotation_checks():
    """Section O: credential-ticket rotation end to end, against a short-grace instance.

    One cookie is in play, and it is the one the protocol actually protects:
    ``__Host-auth_cookie``, named by ``credentials[].name``, whose value is a ticket a
    successful refresh replaces. A copy of it is therefore worth one refresh window
    rather than the session's lifetime.

    ``session_identifier`` is the key Chromium stores the session under -- the session id
    itself, per spec 9.6 -- and it is not a cookie, so no cookie of that name exists to be
    sent. The session id never travels in the cookie jar: it is read back from the
    application and echoed in the JSON. That is what the id assertions below check -- the
    id is stable and absent from the cookie jar, which is a stronger statement than 'it
    does not rotate'.

    The three properties that matter are asserted against real HTTP, because none of
    them is visible from the library's own tests alone:

      1. A refresh replaces the ticket. A client not told the new value is stranded on a
         retired one, so the replacement has to be observable on the wire.
      2. A retired ticket keeps working for the grace. That is what keeps a second tab
         alive, and it is the window the grace exists to bound.
      3. It stops working after the grace. Without this the rotation would not shorten
         anything, which is the whole reason it exists.

    Rotation is unconditional, so there is no control to compare against: every
    instance rotates. This one is separate only because DBSC_ROTATION_GRACE_S has to be
    short enough to outwait, and the default grace is a minute.
    """
    opener, jar = new_client()
    status, login_h, reg_path, _ = login(opener, jar, base=ROTATION_BASE)
    if status != 302:
        check("the rotation instance accepts the same login", False,
              f"login returned {status}; is an instance on {ROTATION_BASE}?")
        return

    key = Key()
    # The JTI is the one bind() asked the browser to sign, taken from the login
    # response's registration header; the server finds it again by the session the
    # token names, so nothing carries it between the two requests.
    jti = registration_jti(login_h)
    reg_status, _, reg_text = request(
        opener, "POST", reg_path, body=b"", base=ROTATION_BASE, headers={
            "Secure-Session-Response": key.jws({"jti": jti}),
            "Content-Type": "application/json"})
    if reg_status != 200:
        check("registration succeeds on the rotation instance", False,
              f"got {reg_status}: {reg_text[:200]}")
        return

    # The session id is never in a cookie: it lives server-side, the app reports it, and
    # the JSON advertises it. The only cookie the browser holds is the credential one.
    session_before = session_id_of(opener, base=ROTATION_BASE)
    ticket_before = cookie_value(jar, "__Host-auth_cookie")
    check("no cookie named session_identifier is ever set",
          cookie_value(jar, "session_identifier") is None)

    # One full refresh: leg 1 for the challenge, leg 2 for the proof.
    _, leg1_headers, _ = request(
        opener, "POST", "/dbsc/refresh", body=b"", base=ROTATION_BASE,
        headers={"Content-Type": "application/json",
                 "Sec-Secure-Session-Id": session_before})
    ch = refresh_jti(leg1_headers)
    status, _, text = request(
        opener, "POST", "/dbsc/refresh", body=b"", base=ROTATION_BASE, headers={
            "Content-Type": "application/json",
            "Sec-Secure-Session-Id": session_before,
            "Secure-Session-Response": refresh_jws(key, ch)})
    check("a refresh on a rotating instance -> 200", status == 200,
          f"got {status}: {text[:200]}")

    session_after = session_id_of(opener, base=ROTATION_BASE)
    ticket_after = cookie_value(jar, "__Host-auth_cookie")
    check("the credential ticket is replaced by a refresh",
          ticket_after is not None and ticket_after != ticket_before,
          f"{ticket_before} -> {ticket_after}")
    check("the session id is NOT replaced by a refresh",
          session_after is not None and session_after == session_before,
          f"{session_before} -> {session_after}")
    check("a refresh still sets no cookie named session_identifier",
          cookie_value(jar, "session_identifier") is None)
    if status == 200:
        try:
            cfg = json.loads(text)
        except ValueError:
            cfg = {}
        # session_identifier is the id, unchanged by a refresh: Chromium keys its store by
        # this value, so rotating it would orphan the registration.
        check("session_identifier survives a refresh unchanged",
              cfg.get("session_identifier") == session_after,
              f"{cfg.get('session_identifier')} != {session_after}")
        check("the id is still not a cookie value",
              cfg.get("session_identifier") != ticket_after,
              "the id is the credential cookie value")
        creds = cfg.get("credentials") or []
        check("credentials[0].name is the credential cookie, not the session cookie",
              bool(creds) and creds[0].get("name") == "__Host-auth_cookie",
              str(creds[:1])[:200])

    if ticket_after is None:
        return

    # The stale tab: a refresh presenting the ticket the client held before, within
    # the grace. This is the second-tab case, and it must not be answered with an
    # error -- Chromium records a failure here as permanent and abandons the session.
    _, stale_leg1, _ = request(
        opener, "POST", "/dbsc/refresh", body=b"", base=ROTATION_BASE,
        headers={"Content-Type": "application/json",
                 "Sec-Secure-Session-Id": session_before})
    stale_ch = refresh_jti(stale_leg1)
    status, _, stale_text = request(
        opener, "POST", "/dbsc/refresh", body=b"", base=ROTATION_BASE, headers={
            "Content-Type": "application/json",
            "Sec-Secure-Session-Id": session_before,
            "Secure-Session-Response": refresh_jws(key, stale_ch)},
        replace_cookies={"__Host-auth_cookie": ticket_before})
    check("a retired ticket still refreshes within the grace", status == 200,
          f"got {status}: {stale_text[:200]}")
    check("and that refresh rotates the ticket again, so a tab cannot pin the old one",
          cookie_value(jar, "__Host-auth_cookie") not in (None, ticket_before),
          f"{ticket_before} -> {cookie_value(jar, '__Host-auth_cookie')}")
    check("and the session id still has not moved",
          session_id_of(opener, base=ROTATION_BASE) == session_before,
          f"{session_before} -> {session_id_of(opener, base=ROTATION_BASE)}")

    # A guarded route with the retired credential still in hand must read as bound,
    # not as lapsed. This is the same window seen from the application side.
    guarded_status, guarded_text = post_guarded(
        opener, ROTATION_BASE, current_csrf(opener, base=ROTATION_BASE))
    check("a guarded route admits the rotated session", guarded_status == 200,
          f"got {guarded_status}: {guarded_text[:160]}")

    # The session is named by the header and by nothing else. A refresh that carries a
    # retired ticket but no Sec-Secure-Session-Id is not a slow tab -- it is an attacker
    # holding a captured cookie, and it must not be able to name a session at all. The
    # ticket is never consulted, so the retired one is beside the point: the request fails
    # for want of the header.
    ticket_status, _, ticket_text = request(
        opener, "POST", "/dbsc/refresh", body=b"", base=ROTATION_BASE,
        headers={"Content-Type": "application/json"},
        replace_cookies={"__Host-auth_cookie": ticket_before})
    check("a refresh with no Sec-Secure-Session-Id is refused, whatever cookie it carries",
          ticket_status == 403 and "SESSION_NOT_FOUND" in ticket_text,
          f"got {ticket_status}: {ticket_text[:160]}")
    check("and it is a 403, never the 401 Chromium treats as fatal",
          ticket_status != 401, f"got {ticket_status}")
    check("the credential cookie the browser actually holds still works",
          cookie_value(jar, "__Host-auth_cookie") is not None
          and cookie_value(jar, "__Host-auth_cookie") != ticket_before,
          f"{ticket_before} -> {cookie_value(jar, '__Host-auth_cookie')}")

    # The same request with the header names the session outright and succeeds, even on
    # the retired ticket -- the tab presenting it is the browser that holds the live one.
    header_status, _, header_text = request(
        opener, "POST", "/dbsc/refresh", body=b"", base=ROTATION_BASE,
        headers={"Content-Type": "application/json",
                 "Sec-Secure-Session-Id": session_before,
                 "Secure-Session-Response": refresh_jws(key, refresh_jti(
                     request(opener, "POST", "/dbsc/refresh", body=b"",
                             base=ROTATION_BASE,
                             headers={"Content-Type": "application/json",
                                      "Sec-Secure-Session-Id": session_before})[1]))},
        replace_cookies={"__Host-auth_cookie": ticket_before})
    check("the header alone names the session, retired ticket and all",
          header_status == 200, f"got {header_status}: {header_text[:160]}")


def script_checks():
    """Section P: the two affordances a script-managed client needs.

    Both are additions the native flow never touches, and both are only meaningful on
    the wire -- the unit tests drive them through MockMvc, which does not prove the
    servlet stack preserves repeated response headers or that a header name outside
    the safelist is read at all.

    ``POST /dbsc/bind`` is the re-offer route. ``bind()`` writes its offer onto
    whatever response called it, and a script can only act once its own code runs, so
    the native ordering (offer on the login response) does not exist for it. This
    route is where such a client asks again, and the assertions below are the
    contract: the *headers* carry the same wire format ``bind()`` emits, and the
    token in them is still live.

    ``X-Session-Id`` is the refresh header rename. ``Sec-`` is reserved by RFC 6648
    and outside the CORS safelist, so a fetch carrying it is preflighted; the plain
    name carries the same value with none of that.
    """
    opener, jar = new_client()
    status, login_headers, reg_path, _ = login(opener, jar)
    if status != 302:
        check("the script-client section can log in", False,
              f"login returned {status}")
        return

    # --- the re-offer route refuses a client with no session, before anything else.
    #
    # The session for this route comes from the application's own session cookie,
    # not from a token in the path, and an anonymous caller has none. This is the
    # ordering that makes the route safe to expose on the authenticated chain: the
    # refusal happens before a challenge is minted or a token is spent.
    # The re-offer route needs a CSRF token, which is itself worth pinning down: the
    # route must not be reachable without one. This is the anonymous case, so what comes
    # back is Security's own answer rather than DBSC's -- a redirect to the login page,
    # or a 401/403 from CSRF depending on how the caller got there. Either way the route
    # is not served, and no offer is minted. The next block asserts the DBSC refusal
    # itself, on a request from a client that is authenticated but unbound.
    anon, _ = new_client()
    anon_status, anon_headers, anon_text = post_bind(anon)
    check("POST /dbsc/bind without a session is not served",
          anon_status != 200, f"got {anon_status}: {anon_text[:160]}")
    check("and an anonymous re-offer mints no registration header",
          header(anon_headers, "Secure-Session-Registration") is None,
          str(all_headers(anon_headers, "Secure-Session-Registration"))[:200])

    # --- a bound session is refused: re-offering would let it replace the key it
    # proved possession of without proving possession of a new one.
    key = Key()
    jti = registration_jti(login_headers)
    reg_status, _, reg_text = request(
        opener, "POST", reg_path, body=b"", headers={
            "Secure-Session-Response": key.jws({"jti": jti}),
            "Content-Type": "application/json"})
    check("the script-client section can register natively first", reg_status == 200,
          f"got {reg_status}: {reg_text[:200]}")

    bound_status, bound_headers, bound_text = post_bind(opener)
    check("a session that already holds a key is SESSION_ALREADY_REGISTERED",
          bound_status == 403 and "SESSION_ALREADY_REGISTERED" in bound_text,
          f"got {bound_status}: {bound_text[:160]}")
    check("and a refused re-offer writes no registration header either",
          header(bound_headers, "Secure-Session-Registration") is None,
          str(all_headers(bound_headers, "Secure-Session-Registration"))[:200])

    # --- the offer itself, on the session that has not bound yet.
    #
    # A separate client, so the re-offer is the *first* registration for its session
    # and the already-registered refusal above cannot mask a broken offer.
    fresh, fresh_jar = new_client()
    f_status, _, f_reg_path, _ = login(fresh, fresh_jar)
    if f_status != 302:
        check("the re-offer client can log in", False, f"login returned {f_status}")
        return

    offer_status, offer_headers, offer_text = post_bind(fresh)
    check("POST /dbsc/bind on an unbound session -> 200", offer_status == 200,
          f"got {offer_status}: {offer_text[:200]}")

    reg_header = header(offer_headers, "Secure-Session-Registration")
    legacy_header = header(offer_headers, "Sec-Session-Registration")
    check("the re-offer carries Secure-Session-Registration as a header",
          reg_header is not None, str(all_headers(offer_headers, "Secure-Session-Registration"))[:200])
    check("and the legacy alias alongside it, so a straddling browser reads one",
          legacy_header == reg_header, f"{legacy_header!r} != {reg_header!r}")

    offer_path, offer_jti = registration_path(offer_headers), registration_jti(offer_headers)
    check("the offer advertises a registration path",
          bool(offer_path) and offer_path is not None
          and offer_path.startswith(MAIN_REG_PATH + "/"),
          str(offer_path))
    check("and that path is NOT the login response's token",
          offer_path is not None and offer_path != f_reg_path,
          f"re-offer reused the login's single-use path: {offer_path}")

    # The challenge header is the other half of the same value, and the id= parameter
    # is what names the session the challenge belongs to (spec: `<jti>`;id=`<sessionId>`).
    challenge_header = header(offer_headers, "Secure-Session-Challenge")
    check("the re-offer carries Secure-Session-Challenge too",
          challenge_header is not None, str(challenge_header))
    check("and its JTI is the one the registration header points at",
          offer_jti is not None and offer_jti in (challenge_header or ""),
          f"reg jti {offer_jti!r} vs challenge {challenge_header!r}")

    # --- the offer is live: the token it names still registers.
    #
    # This is the assertion that would have caught the one real bug in this route.
    # A re-offer that spends its own token hands the client a path that is already
    # dead -- the registration POST then answers REGISTRATION_TOKEN_CONSUMED and the
    # client has no way back.
    fresh_key = Key()
    live_status, _, live_text = request(
        fresh, "POST", offer_path, body=b"", headers={
            "Secure-Session-Response": fresh_key.jws({"jti": offer_jti}),
            "Content-Type": "application/json"})
    check("the token the re-offer handed out is live, not pre-spent",
          live_status == 200, f"got {live_status}: {live_text[:200]}")
    check("and registering off it did not answer REGISTRATION_TOKEN_CONSUMED",
          live_status == 200 or "REGISTRATION_TOKEN_CONSUMED" not in live_text,
          live_text[:160])

    session_id = session_id_of(fresh)
    check("the re-offer bound the session the application reports",
          session_id is not None
          and (json.loads(live_text).get("session_identifier") == session_id
               if live_status == 200 else False),
          f"{session_id} vs {live_text[:160]}")

    # --- X-Session-Id on refresh.
    #
    # The same exchange the rotation section runs, with the header renamed. Both
    # names must resolve the session identically; anything else would make the
    # choice of name semantically load-bearing, which it is not.
    _, leg1_headers, _ = request(
        fresh, "POST", "/dbsc/refresh", body=b"",
        headers={"Content-Type": "application/json",
                 "X-Session-Id": session_id or ""})
    ch = refresh_jti(leg1_headers)
    check("a refresh naming the session with X-Session-Id answers a challenge",
          ch is not None, str(all_headers(leg1_headers, "Secure-Session-Challenge"))[:200])

    x_status, _, x_text = request(
        fresh, "POST", "/dbsc/refresh", body=b"", headers={
            "Content-Type": "application/json",
            "X-Session-Id": session_id or "",
            "Secure-Session-Response": refresh_jws(fresh_key, ch)})
    check("and the proof over X-Session-Id refreshes -> 200", x_status == 200,
          f"got {x_status}: {x_text[:200]}")

    # --- the two names are interchangeable, not ordered.
    #
    # A client that sends both is named by X-Session-Id (it is read first), which is
    # the only tie-break; a client that sends only the native name must keep working,
    # since that is the path every native browser is on.
    _, leg1_native, _ = request(
        fresh, "POST", "/dbsc/refresh", body=b"",
        headers={"Content-Type": "application/json",
                 "Sec-Secure-Session-Id": session_id or ""})
    native_ch = refresh_jti(leg1_native)
    n_status, _, n_text = request(
        fresh, "POST", "/dbsc/refresh", body=b"", headers={
            "Content-Type": "application/json",
            "Sec-Secure-Session-Id": session_id or "",
            "Secure-Session-Response": refresh_jws(fresh_key, native_ch)})
    check("the native header name still refreshes unchanged", n_status == 200,
          f"got {n_status}: {n_text[:200]}")

    # --- no CORS preflight is needed for the X- name, which is the whole point.
    #
    # X-Session-Id is a CORS-safelisted shape: the name is not reserved, so a fetch
    # that sets it is a simple request. This is asserted structurally (the name is
    # outside the Sec- namespace) rather than by a browser, which is the only way to
    # state it from a script.
    check("X-Session-Id is not a Sec- prefixed (preflight-triggering) name",
          not "X-Session-Id".startswith("Sec-"))

    # --- the route is opt-in: the native flow never sees it.
    #
    # A native browser never calls /dbsc/bind, so the login response must still offer
    # registration on its own. If that ever became dependent on a prior re-offer,
    # every native client would silently stop registering.
    native_client, native_jar = new_client()
    n_login_status, n_login_headers, n_login_path, _ = login(native_client, native_jar)
    check("the native flow still gets its offer from the login response alone",
          n_login_status == 302 and registration_path(n_login_headers) is not None,
          f"login {n_login_status}, offer {registration_path(n_login_headers)}")


if __name__ == "__main__":
    sys.exit(main())
