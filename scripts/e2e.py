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

RATE_LIMITED needs a third thing: the demo raises its rate-limit budgets to 1000 so
this suite's own deliberate failures do not throttle it, which makes the 429 branch
unreachable there. Start a second instance with a small failure budget, and drive it
with repeated rejected *registrations*:

    mvn -Pdemo -Dmaven.repo.local=.m2repo \
        -Dspring-boot.run.arguments="--server.port=9443 \
            --spring.datasource.url=jdbc:h2:file:./data/e2e-ratelimit" \
        -Dspring-boot.run.jvmArguments="-Ddbsc.rate-limit.failure-capacity=5" \
        spring-boot:run
    DBSC_RATE_LIMIT_FAILURES=5 python3 scripts/e2e.py

That instance's window is 90s, and because the limiter keeps its counters for a
whole window against a key derived from the client IP, a previous run -- or an
earlier section -- can leave it already throttled. The suite probes for that, waits
the window out when needed, and only then measures; it never skips for it.

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

# The demo sets capacity/failure-capacity to 1000 so the suite's own negative cases
# (bad signatures, replayed challenges) do not throttle it. That makes RATE_LIMITED
# unreachable against it, so those checks need a second instance started with a
# deliberately tiny budget; this is its registration failure budget. Absent means
# the checks are reported as skipped, the same way the TTL checks are.
RATE_LIMIT_FAILURES = int(os.environ.get("DBSC_RATE_LIMIT_FAILURES") or 0) or None

# The low-budget instance. It shares nothing with the main one: separate port,
# separate database file, so neither can exhaust the other's counters.
RATE_BASE = os.environ.get("DBSC_RATE_BASE") or "https://localhost:9443"

# A third instance, started with dbsc.unregistered=deny. The policy is a property of
# the server, not of the client, so the only way to observe both outcomes is to ask two
# servers. The main demo runs the default (allow); section L drives the deny instance
# and compares the two answers on the same guarded route. Absent means those checks are
# skipped, the same way the TTL and rate-limit ones are.
DENY_BASE = os.environ.get("DBSC_DENY_BASE") or ""

# A fourth instance, started with -Pdemo,rotation-e2e: the only difference from the main
# demo is dbsc.rotation-grace, shortened so the suite can outwait it. Rotation itself is
# unconditional, so this instance is not a control -- it is the only way to observe the
# retirement expiring without sleeping through the 60s default. Section O drives it and
# reads the grace from DBSC_ROTATION_GRACE, since it has to outwait it. Absent means those
# checks are skipped.
ROTATION_BASE = os.environ.get("DBSC_ROTATION_BASE") or ""
ROTATION_GRACE_S = float(os.environ.get("DBSC_ROTATION_GRACE") or 0) or None

# The guarded route both instances agree on. Declared in DemoFormLoginConfig's
# DbscGuardRoutes; keep this in step with src/demo/java/.../DemoFormLoginConfig.java.
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
    jar's cookies are dropped. Tests that pin one cookie to a stale value while
    still needing the challenge cookie must come through here.
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
    session cookie (the cookie `session_identifier` names).

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


def session_id_of(opener, base=None):
    """The DBSC session id, as the application reports it.

    The id is not in any cookie -- by design, since no cookie is minted under the name
    session_identifier advertises -- so the application is the only source for it.
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


def refresh_jti(headers, jar, name="__Host-dbsc-challenge"):
    """The JTI to sign for a refresh, taken from the challenge *header*.

    Not from the challenge cookie, which is the obvious source and the wrong one. The
    cookie's Max-Age is the challenge TTL in seconds, so with the suite's deliberately
    tiny DBSC_CHALLENGE_TTL (2s) it is emitted as ``Max-Age=0`` and a compliant cookie
    jar never stores it at all. The header is the durable copy of the same value and is
    what the spec points a client at, so read it there and fall back to the cookie only
    when a jar happens to hold one.
    """
    raw = header(headers, "Secure-Session-Challenge")
    if raw:
        m = re.match(r'\s*"([^"]+)"', raw)
        if m:
            return m.group(1)
    return cookie_value(jar, name)


def refresh_jws(key, jti):
    """The refresh proof: a JWS over the challenge with typ=dbsc+jwt.

    No jwk in the header — the server already holds the key, and spec 02 treats a
    jwk on a refresh as a protocol error.
    """
    return key.jws({"jti": jti}, include_jwk=False)


def native_register(opener, jar, reg_path, key):
    """Runs native registration off the path the login response advertised.

    Returns (jti, status, text).
    """
    jti = cookie_value(jar, "__Host-dbsc-challenge")
    if jti is None:
        return None, None, "no __Host-dbsc-challenge cookie"
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
    """Native registration with the JTI and path supplied, not read from the jar.

    Needed when the JTI must be re-presented after its cookie was cleared or
    expired, when registration is aimed at the low-budget instance rather than the
    main demo, and when the path itself is wrong on purpose.
    Returns (jti, status, text).
    """
    status, _, text = request(
        opener, "POST", reg_path or (MAIN_REG_PATH + "/" + "x" * 43), body=b"", base=base, headers={
            "Secure-Session-Response": key.jws({"jti": jti}),
            "Content-Type": "application/json"})
    return jti, status, text


def challenge_cookie_header(jar, jti):
    """The cookie values that re-present a JTI the server has since forgotten.

    Returns a {name: value} map for request(replace_cookies=...), not a literal
    header: sending the raw header would suppress every other cookie the jar holds,
    because CookieJar.add_cookie_header appends only when no Cookie header is set.

    The server clears the challenge cookie on use and its Max-Age makes a compliant
    client drop it on expiry, so the only way to exercise the "consumed"/"expired"
    branches is to name the value in the request by hand.
    """
    override = {"__Host-dbsc-challenge": jti}
    if cookie_value(jar, "JSESSIONID"):
        override["JSESSIONID"] = cookie_value(jar, "JSESSIONID")
    return override


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


# The low-budget instance's dbsc.rate-limit.window. A dry run against it is the only
# way to read it from here, and the window only matters for measurement: the checks
# below sleep it out so their attempt counts start from a fresh budget.
_RATE_WINDOW_RAW = os.environ.get("DBSC_RATE_LIMIT_WINDOW") or "90s"


def p_window_seconds():
    """The low-budget instance's rate-limit window, in seconds."""
    m = re.fullmatch(r"(\d+)(ms|s|m|h)?", _RATE_WINDOW_RAW.strip())
    if not m:
        return 90
    value = int(m.group(1))
    return {"ms": value / 1000, "m": value * 60, "h": value * 3600}.get(m.group(2), value)


def p_tripped(opener, jar):
    """Whether the low-budget instance already refuses this client.

    A dry registration that cannot succeed: it presents no challenge cookie, so it
    is rejected whether or not the client is throttled. A 429 here means the
    failure budget is already spent -- by an earlier run, since the limiter holds
    its counters for a whole window -- and that is exactly the state this section
    has to clear before it can measure anything.
    """
    _, status, _ = native_register_manual(opener, "n" * 43, Key(), base=RATE_BASE)
    return status == 429


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
    ch_cookie = cookie(jar, "__Host-dbsc-challenge")
    check("__Host-dbsc-challenge cookie present", ch_cookie is not None)
    check("no __Host-dbsc-reg cookie: the path carries the token now",
          cookie(jar, "__Host-dbsc-reg") is None)
    # The credential cookie is set from bind(), before registration, so a request that
    # omits it is distinguishable from a browser that never bound at all.
    bind_cookie = cookie(jar, "__Host-auth_cookie")
    check("__Host-auth_cookie cookie present from bind()", bind_cookie is not None)
    # session_identifier advertises a cookie name the server never sets. That is the
    # design: the session id lives only server-side, so a lifted cookie jar holds a
    # rotating ticket and no long-lived id.
    check("no cookie is set under the name session_identifier advertises",
          cookie(jar, "__Host-dbsc-session") is None)
    check("__Host- cookies are Secure",
          bool(bind_cookie and bind_cookie.secure and ch_cookie and ch_cookie.secure))
    check("__Host- cookies are HttpOnly and Path=/",
          bool(bind_cookie and bind_cookie.has_nonstandard_attr("HttpOnly")
               and bind_cookie.path == "/"))
    check("the DBSC session id is not the servlet session id",
          session_id_of(opener) != cookie_value(jar, "JSESSIONID")
          and session_id_of(opener) is not None,
          f"{session_id_of(opener)} == {cookie_value(jar, 'JSESSIONID')}")
    challenge = ch_cookie.value if ch_cookie else None

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
        check("registration advertises the session_identifier cookie name",
              cfg.get("session_identifier") == "__Host-dbsc-session",
              str(cfg)[:200])
        check("credential cookie set", cookie(jar, "__Host-auth_cookie") is not None)
        check("still no cookie under session_identifier's name",
              cookie(jar, "__Host-dbsc-session") is None)
        check("challenge cookie cleared after use",
              cookie_value(jar, "__Host-dbsc-challenge") is None)

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
                             headers={"Content-Type": "application/json"})
    check("first leg (no proof) -> 403, never 401", status == 403, f"got {status}: {t1[:200]}")
    new_ch = cookie_value(jar, "__Host-dbsc-challenge")
    check("first leg issues a fresh challenge cookie", new_ch is not None)
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
                "Secure-Session-Response": f"{new_ch}.{native.sign(new_ch)}"})
        check("replaying a consumed challenge -> 403", status == 403, f"got {status}")

    # ------------------------------------------------------- 6. bad signature
    print("\n-- 6. a bad refresh signature demotes to none --")
    # Leg 1 first: it both proves the session is still dbsc and hands back a
    # fresh, unconsumed challenge for the bad-signature attempt.
    request(opener, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json",
                     "Sec-Secure-Session-Id": session_id_of(opener)})
    _, _, before = request(opener, "GET", "/app/whoami")
    who_before = json.loads(before)
    ch_now = cookie_value(jar, "__Host-dbsc-challenge")
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
    _, a_status, a_text = native_register(a_opener, a_jar, a_reg, a_key)
    a_cfg = json.loads(a_text) if a_status == 200 else {}

    check("native registration returns a JSON body (a 200 with no body is opt-out)",
          bool(a_cfg), a_text[:200])
    check("session_identifier names a cookie the server never sets",
          a_cfg.get("session_identifier") == "__Host-dbsc-session",
          f"{a_cfg.get('session_identifier')} != __Host-dbsc-session")
    check("no cookie is set under that name",
          cookie_value(a_jar, "__Host-dbsc-session") is None)
    # It is a NAME, so it must not be the id -- and the id, which the app reports, is what
    # bind() was handed.
    check("session_identifier is a name, not the session id",
          a_cfg.get("session_identifier") != a_sid,
          f"{a_cfg.get('session_identifier')} == {a_sid}")
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
        check("credential[0].name is not the session cookie name",
              cred0.get("name") != a_cfg.get("session_identifier"),
              str(cred0.get("name")))
        # Spec 07: attributes must match the Set-Cookie attributes exactly, spaces
        # after semicolons included, and must NOT carry Max-Age.
        set_cookie = " ".join(all_headers(a_headers, "Set-Cookie"))
        declared = cred0.get("attributes", "")
        check("attributes mirror the Set-Cookie attributes exactly",
              declared == "Path=/; Secure; HttpOnly; SameSite=Lax", repr(declared))
        check("attributes carry no Max-Age",
              "Max-Age" not in declared, declared)

    # ------------------------------------------------- B. error ordering
    print("\n-- B. failures are reported in the spec's normative order --")
    # A missing response header outranks the missing challenge cookie, so the
    # caller learns the real problem instead of a downstream one.
    b_opener, b_jar = new_client()
    _, _, b_reg, _ = login(b_opener, b_jar)
    status, _, text = request(
        b_opener, "POST", b_reg, body=b"",
        headers={"Content-Type": "application/json"})
    check("no response header (and no challenge cookie) -> 403 MISSING_RESPONSE_HEADER",
          status == 403 and "MISSING_RESPONSE_HEADER" in text, f"{status} {text[:160]}")

    # typ is checked before jwk presence, so a JWS that is wrong in both ways
    # still reports the earlier rule.
    b_key = Key()
    head = b64u(json.dumps({"alg": "ES256", "typ": "jwt"}, separators=(",", ":")).encode())
    payload = b64u(json.dumps({"jti": "x"}, separators=(",", ":")).encode())
    wrong_typ = f"{head}.{payload}.{b_key.sign(f'{head}.{payload}')}"
    status, _, text = request(
        b_opener, "POST", b_reg, body=b"",
        headers={"Secure-Session-Response": wrong_typ, "Content-Type": "application/json"})
    check("typ != dbsc+jwt -> MALFORMED_JWS (checked before jwk)",
          "MALFORMED_JWS" in text, f"{status} {text[:160]}")

    status, _, text = request(
        b_opener, "POST", b_reg, body=b"",
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
    request(c_opener, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": c_sid})
    c_ch = cookie_value(c_jar, "__Host-dbsc-challenge")
    if c_ch:
        status, _, text = request(
            c_opener, "POST", "/dbsc/refresh", body=b"", headers={
                "Content-Type": "application/json",
                "Sec-Secure-Session-Id": c_sid,
                "Secure-Session-Response": refresh_jws(Key(), c_ch)})
        check("refresh before registering a key -> KEY_NOT_FOUND",
              "KEY_NOT_FOUND" in text, f"{status} {text[:160]}")

    # ------------------------------------------------- C. already-registered
    print("\n-- C. a second registration of the same kind is refused --")
    # A fresh challenge: the login's cookie was consumed by the first registration,
    # and the refresh leg is what re-arms the session with another JTI.
    request(a_opener, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": a_sid})
    a_ch2 = cookie_value(a_jar, "__Host-dbsc-challenge")
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
        b_opener, "POST", b_reg, body=b"", headers={
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
    _, _, e2_reg, _ = login(e2, e2_jar)
    e2_key = Key()
    _, e2_status, e2_text = native_register(e2, e2_jar, e2_reg, e2_key)
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

    # A consumed challenge is observable at any TTL, so this always runs. The JTI
    # is resent explicitly because the server clears the cookie once it is used.
    #
    # What proves the challenge was consumed has changed with the new design: the
    # registration token is single-use too, so a replay of the *path* is now caught
    # as REGISTRATION_TOKEN_CONSUMED before the challenge store is ever consulted.
    # To reach the challenge's own consumption rule the second attempt therefore
    # has to carry a *fresh, unconsumed* token, which the refresh leg issues along
    # with the new challenge it arms the session with.
    k1_opener, k1_jar = new_client()
    _, _, k1_reg, _ = login(k1_opener, k1_jar)
    k1_jti = cookie_value(k1_jar, "__Host-dbsc-challenge")
    k1_ck = challenge_cookie_header(k1_jar, k1_jti)
    k1_key = Key()
    status, _, text = request(
        k1_opener, "POST", k1_reg, body=b"", headers={
            "Secure-Session-Response": k1_key.jws({"jti": k1_jti}),
            "Content-Type": "application/json"})
    check("the first use of a challenge succeeds", status == 200, f"{status} {text[:160]}")

    # A fresh token for the same session, so the replay below is refused for its
    # spent JTI rather than for its spent path. k1_ck re-presents that JTI by hand:
    # the success above made the server clear the challenge cookie.
    request(k1_opener, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json",
                     "Sec-Secure-Session-Id": session_id_of(k1_opener)})
    # The refresh leg above wrote a fresh challenge cookie, and the server has just
    # armed the session with a new JTI. Only bind() mints registration tokens, so the
    # token has to be re-minted for k1's *own* session: /app/rebind does exactly
    # that, whereas a re-login would mint a new random session id and make this
    # attempt a first registration of a different session rather than a *second*
    # attempt at k1's consumed JTI.
    k1_reg2 = rebind(k1_opener)
    check("a fresh registration token is minted for the session with the spent JTI",
          k1_reg2 is not None and k1_reg2 != k1_reg)
    status, _, text = request(
        k1_opener, "POST", k1_reg2 or MAIN_REG_PATH + "/" + "x" * 43, body=b"", headers={
            "Secure-Session-Response": k1_key.jws({"jti": k1_jti}),
            "Content-Type": "application/json"},
        replace_cookies=k1_ck)
    check("reusing a consumed JTI -> CHALLENGE_CONSUMED",
          "CHALLENGE_CONSUMED" in text, f"{status} {text[:160]}")

    # The same must hold on the refresh leg: one challenge store, one consumption.
    k2_opener, k2_jar = new_client()
    _, _, k2_reg, _ = login(k2_opener, k2_jar)
    k2_jti = cookie_value(k2_jar, "__Host-dbsc-challenge")
    k2_ck = challenge_cookie_header(k2_jar, k2_jti)
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
            "Content-Type": "application/json"},
        replace_cookies=k2_ck)
    check("the same JTI replayed on the native refresh route -> CHALLENGE_CONSUMED",
          "CHALLENGE_CONSUMED" in text, f"{status} {text[:160]}")

    if CHALLENGE_TTL_S is None:
        skip("expired challenge -> CHALLENGE_EXPIRED",
             "set DBSC_CHALLENGE_TTL and start the demo with a short dbsc.challenge-ttl")
    else:
        # The challenge cookie's Max-Age equals the challenge TTL, so a client
        # honouring cookie expiry stops sending the JTI and the server sees a
        # *missing* challenge, not an expired one. To reach the expiry branch the
        # stale JTI has to be replayed outside the cookie jar -- which is exactly
        # what a client with a stale local copy of the challenge does.
        #
        # Registration adds a second clock: its token carries a TTL too
        # (registration-cookie-ttl, 24h by default), and the token is checked
        # *before* the challenge. Waiting out a short challenge TTL does not
        # exhaust it, so the path below stays a live one and CHALLENGE_EXPIRED,
        # not REGISTRATION_TOKEN_EXPIRED, is the branch under test.
        k3_opener, k3_jar = new_client()
        _, _, k3_reg, _ = login(k3_opener, k3_jar)
        k3_jti = cookie_value(k3_jar, "__Host-dbsc-challenge")
        k3_ck = challenge_cookie_header(k3_jar, k3_jti)
        time.sleep(CHALLENGE_TTL_S + 1.0)
        k3_key = Key()
        status, _, text = request(
            k3_opener, "POST", k3_reg, body=b"", headers={
                "Secure-Session-Response": k3_key.jws({"jti": k3_jti}),
                "Content-Type": "application/json"},
            replace_cookies=k3_ck)
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
        # It needs its own session and token: the attempt above does not consume
        # the token (validation precedes consumption) but it does arm a fresh
        # challenge, and reusing the spent one would report CHALLENGE_CONSUMED
        # rather than the unknown-JTI branch under test.
        k4_opener, k4_jar = new_client()
        _, _, k4_reg, _ = login(k4_opener, k4_jar)
        status, _, text = request(
            k4_opener, "POST", k4_reg, body=b"", headers={
                "Secure-Session-Response": k3_key.jws({"jti": "n" * 43}),
                "Content-Type": "application/json"},
            replace_cookies={"__Host-dbsc-challenge": "n" * 43})
        check("an unknown JTI -> CHALLENGE_NOT_FOUND",
              "CHALLENGE_NOT_FOUND" in text, f"{status} {text[:160]}")

    # ------------------------------------------------- N. INVALID_JWK
    # Only the native route is served now, so the JWK rules are exercised through
    # the JWS header -- the same place a browser's key travels.
    print("\n-- G. a JWK that breaks the key rules is INVALID_JWK, not a crash --")
    n_opener, n_jar = new_client()
    login(n_opener, n_jar)
    # The refresh leg names the session by id, which is read from /app/whoami now
    # that the login response carries a registration path instead.
    n_sid = session_id_of(n_opener)
    # Registration is behind the token path now, so the loop needs a fresh token
    # per attempt: a consumed path would be refused before the JWK is looked at.
    # A refresh leg arms the session with a fresh challenge *and* the login below
    # issues a fresh token, so each attempt gets both from one re-login.
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
        n_jti = cookie_value(n_jar, "__Host-dbsc-challenge")
        if n_jti is None:
            check(f"{label}", False, "no challenge cookie to present")
            continue
        _, _, n_reg, _ = login(n_opener, n_jar)
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
    _, _, alg_reg, _ = login(alg_opener, alg_jar)
    request(alg_opener, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json",
                     "Sec-Secure-Session-Id": session_id_of(alg_opener)})
    alg_jti = cookie_value(alg_jar, "__Host-dbsc-challenge")
    if alg_jti is None:
        check("alg disagreeing with the JWK -> UNKNOWN_ALGORITHM", False,
              "no challenge cookie to present")
    else:
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
    # one's challenge is presented on the other, which is the case a stolen or
    # replayed challenge hits. The signature is made by the *right* key for the
    # presenting session, so the session binding is the only thing rejecting it.
    q1, q1_jar = new_client()
    login(q1, q1_jar)
    q1_sid = session_id_of(q1)
    request(q1, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": q1_sid})
    q1_ch = cookie_value(q1_jar, "__Host-dbsc-challenge")

    q2, q2_jar = new_client()
    _, _, q2_reg, _ = login(q2, q2_jar)
    q2_sid = session_id_of(q2)
    request(q2, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": q2_sid})
    # The registration below is what consumes q2's challenge, and it spends q2_reg --
    # the path is single-use. q2's *first* challenge is the one presented later, so
    # the token is read before the registration and the JTI is kept from here.
    q2_reg_first = q2_reg
    q2_ch = cookie_value(q2_jar, "__Host-dbsc-challenge")
    q2_key = Key()
    # q2 must hold a real key, or the key lookup would reject the request before
    # the session binding is ever compared.
    native_register_manual(q2, q2_ch, q2_key, reg_path=q2_reg_first)

    # The challenge q1 was issued has since been consumed by the registration
    # above, so it is spent before the session binding is even compared. Re-arm
    # q1 with a live challenge and present *that* from the other session.
    request(q1, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": q1_sid})
    q1_live = cookie_value(q1_jar, "__Host-dbsc-challenge")
    check("q1 holds a live challenge to present from the other session",
          q1_live is not None)

    # A refresh names its session by header; without one the mismatch check is never
    # reached and the request is refused as SESSION_NOT_FOUND instead.
    status, _, text = request(
        q2, "POST", "/dbsc/refresh", body=b"", headers={
            "Sec-Secure-Session-Id": q2_sid,
            "Secure-Session-Response": refresh_jws(q2_key, q1_live),
            "Content-Type": "application/json"},
        replace_cookies={"__Host-dbsc-challenge": q1_live})
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
    # Logout clears both DBSC cookies by expiring them, so check the Set-Cookie
    # header rather than the jar: a jar may simply drop an expired cookie.
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
    check("logout expires the challenge cookie",
          "__Host-dbsc-challenge" in set_cookies, set_cookies[:300])

    # ---------------------------------- J. unauthenticated access is refused
    print("\n-- J. an anonymous client is refused --")
    anon, _ = new_client()
    status, _, _ = request(anon, "GET", "/app/whoami")
    check("anonymous GET /app/whoami is not 200", status != 200, f"got {status}")

    # ------------------------------------------------- K. RATE_LIMITED
    print("\n-- K. a client that keeps failing is throttled --")
    if RATE_LIMIT_FAILURES is None:
        skip("repeated failures -> 429 RATE_LIMITED",
             "start a second demo on " + RATE_BASE + " with a small "
             "dbsc.rate-limit.failure-capacity and set DBSC_RATE_LIMIT_FAILURES")
    else:
        # A separate instance: the demo's own budgets are 1000 so that this suite's
        # deliberate failures do not throttle it, which leaves RATE_LIMITED
        # unreachable there. The limiter counts failures, not just requests, so a
        # loop of rejected registrations is what trips it.
        p_opener, p_jar = new_client()
        # The third value is the registration path, supplied by the low-budget
        # instance's own login. The loop below deliberately does *not* post to it:
        # the path's token is single-use, so spending it on the first rejected
        # attempt would turn every later attempt into REGISTRATION_TOKEN_CONSUMED,
        # which is refused by the token check before the challenge (and therefore
        # before the failure being counted) is ever reached. Holding the real path
        # here is also what documents that a concrete path exists on this instance.
        p_status, _, p_reg, _ = login(p_opener, p_jar, base=RATE_BASE)
        if p_status != 302:
            check("the low-budget demo accepts the same login", False,
                  f"login returned {p_status}; is a second instance on {RATE_BASE}?")
        else:
            # The probe below is deliberately outside the loop: this section's
            # loop must start at attempt 0 of a *fresh* window, or "it trips at
            # the configured budget" measures a window that was already partly
            # spent. Window lengths here are a minute or so, so starting one only
            # costs seconds -- and waiting is not a skipped check, it is the
            # precondition for the real one.
            if p_tripped(p_opener, p_jar):
                window = p_window_seconds()
                print(f"     the rate-limit window is already spent; waiting {window}s")
                time.sleep(window)
            p_key = Key()

            def p_register():
                # No challenge cookie is ever presented on this leg, so every
                # attempt is rejected and charged to the client's failure budget.
                # An unknown, never-consumed JTI is used rather than a replayed one,
                # because a consumed challenge short-circuits ahead of the failure
                # accounting entirely. The path is deliberately a *wrong* one: it
                # carries an unknown token, so the route reports SESSION_NOT_FOUND
                # without the challenge ever being consulted -- which keeps every
                # attempt a clean, countable failure and never spends p_reg's token.
                _, status, text = native_register_manual(
                    p_opener, "n" * 43, p_key, base=RATE_BASE)
                return status, text

            throttled_at = None
            text = ""
            for i in range(RATE_LIMIT_FAILURES + 10):
                status, text = p_register()
                if status == 429:
                    throttled_at = i
                    break
            check("repeating a rejected registration -> 429 RATE_LIMITED",
                  throttled_at is not None,
                  f"never throttled in {RATE_LIMIT_FAILURES + 10} attempts; last was {status} {text[:120]}")
            if throttled_at is not None:
                check("the 429 body carries RATE_LIMITED, not a generic error",
                      "RATE_LIMITED" in text, text[:160])
                check("it trips at the configured failure budget, not before",
                      throttled_at >= RATE_LIMIT_FAILURES - 1,
                      f"tripped after {throttled_at} attempts, budget {RATE_LIMIT_FAILURES}")
                # A throttled request must not be charged again, or a client that
                # keeps retrying would push its own lockout out forever. Waiting out
                # a whole window is the only way to observe that here, so it is done
                # once and the check is kept cheap.
                status2, _ = p_register()
                check("a refused request stays refused while retried", status2 == 429,
                      f"got {status2}")

    # ------------------------------------------------- L. dbsc.unregistered policy
    print("\n-- L. dbsc.unregistered decides what an unbound client gets --")
    if not DENY_BASE:
        skip("unregistered client -> 403 on a deny instance",
             "start a third demo with -Ddbsc.unregistered=deny and set DBSC_DENY_BASE")
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

    ``session_identifier`` names a cookie this server deliberately never sets. Chromium
    keys its session store by that name and stores only a cookie of it, so the session
    id never travels: it exists only server-side and is read back from the application.
    That is what the id assertions below check -- the id is stable and absent from the
    cookie jar, which is a stronger statement than 'it does not rotate'.

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
    status, _, reg_path, _ = login(opener, jar, base=ROTATION_BASE)
    if status != 302:
        check("the rotation instance accepts the same login", False,
              f"login returned {status}; is an instance on {ROTATION_BASE}?")
        return

    key = Key()
    jti = cookie_value(jar, "__Host-dbsc-challenge")
    reg_status, _, reg_text = request(
        opener, "POST", reg_path, body=b"", base=ROTATION_BASE, headers={
            "Secure-Session-Response": key.jws({"jti": jti}),
            "Content-Type": "application/json"})
    if reg_status != 200:
        check("registration succeeds on the rotation instance", False,
              f"got {reg_status}: {reg_text[:200]}")
        return

    # The session id is never in a cookie: it lives only server-side and the app reports
    # it. The only cookie the browser holds is the credential one.
    session_before = session_id_of(opener, base=ROTATION_BASE)
    ticket_before = cookie_value(jar, "__Host-auth_cookie")
    check("no cookie carries the session id",
          cookie_value(jar, "__Host-dbsc-session") is None)

    # One full refresh: leg 1 for the challenge, leg 2 for the proof.
    _, leg1_headers, _ = request(
        opener, "POST", "/dbsc/refresh", body=b"", base=ROTATION_BASE,
        headers={"Content-Type": "application/json",
                 "Sec-Secure-Session-Id": session_before})
    ch = refresh_jti(leg1_headers, jar)
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
    check("a refresh still sets no cookie under session_identifier's name",
          cookie_value(jar, "__Host-dbsc-session") is None)
    if status == 200:
        try:
            cfg = json.loads(text)
        except ValueError:
            cfg = {}
        # session_identifier names the session cookie, so it never changes -- and it
        # is a name, never the id.
        check("session_identifier still advertises the same cookie name",
              cfg.get("session_identifier") == "__Host-dbsc-session",
              f"{cfg.get('session_identifier')} != __Host-dbsc-session")
        check("session_identifier is a name, not the session id",
              cfg.get("session_identifier") != session_after,
              f"{cfg.get('session_identifier')} == the id")
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
    stale_ch = refresh_jti(stale_leg1, jar)
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

    # Outwait the grace and the retired ticket must stop resolving.
    #
    # Asserted where the ticket is the only clue to the session, i.e. with no
    # Sec-Secure-Session-Id header. That is not a workaround for the header: on a real
    # refresh Chromium sends it, and it names the session outright, so the request is
    # authorised by the session id and the ticket is never consulted -- which is why a
    # refresh carrying a retired ticket still succeeds, and rightly so, since the tab
    # presenting it is the very browser that holds the live one. What the grace bounds
    # is the window in which a *captured* credential cookie is still worth something,
    # and the captured value is exactly what an attacker has: no session id header, a
    # cookie that must resolve on its own.
    deadline = time.time() + ROTATION_GRACE_S + 2
    while time.time() < deadline:
        time.sleep(0.5)
    status, _, expired_text = request(
        opener, "POST", "/dbsc/refresh", body=b"", base=ROTATION_BASE,
        headers={"Content-Type": "application/json",
                 "Secure-Session-Response": refresh_jws(key, refresh_jti(
                     request(opener, "POST", "/dbsc/refresh", body=b"",
                             base=ROTATION_BASE,
                             headers={"Content-Type": "application/json"})[1],
                     jar))},
        replace_cookies={"__Host-auth_cookie": ticket_before})
    check("after the grace, the retired ticket no longer names a session",
          status == 403 and "SESSION_NOT_FOUND" in expired_text,
          f"got {status}: {expired_text[:160]}")
    check("and it is a 403, never the 401 Chromium treats as fatal",
          status != 401, f"got {status}")
    check("the credential cookie the browser actually holds still works",
          cookie_value(jar, "__Host-auth_cookie") is not None
          and cookie_value(jar, "__Host-auth_cookie") != ticket_before,
          f"{ticket_before} -> {cookie_value(jar, '__Host-auth_cookie')}")


if __name__ == "__main__":
    sys.exit(main())
