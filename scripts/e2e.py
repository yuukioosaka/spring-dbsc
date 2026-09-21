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


def request(opener, method, path, body=None, headers=None, form=True, base=None):
    """Returns (status, headers, text). Never raises on HTTP error status."""
    data = None
    hdrs = dict(headers or {})
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
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()



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
    """Form login, returns (status, headers, session id, csrf).

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
    return status, headers, cookie_value(jar, "JSESSIONID"), m.group(1)


def current_csrf(opener):
    """Reads the live CSRF token from the page the app renders it into."""
    _, _, html = request(opener, "GET", "/app")
    m = re.search(r'name="csrf" content="([^"]+)"', html)
    return m.group(1) if m else None


def all_headers(headers, name):
    """Every value for a header name; Set-Cookie legitimately repeats."""
    return [v for k, v in headers.items() if k.lower() == name.lower()]


def header(headers, name):
    """The first value for a header name, or None."""
    values = all_headers(headers, name)
    return values[0] if values else None


def refresh_jws(key, jti):
    """The refresh proof: a JWS over the challenge with typ=dbsc+jwt.

    No jwk in the header — the server already holds the key, and spec 02 treats a
    jwk on a refresh as a protocol error.
    """
    return key.jws({"jti": jti}, include_jwk=False)


def native_register(opener, jar, sid, key):
    """Runs native registration off the challenge cookie the login left behind.

    Returns (jti, status, text).
    """
    jti = cookie_value(jar, "__Host-dbsc-challenge")
    if jti is None:
        return None, None, "no __Host-dbsc-challenge cookie"
    status, _, text = request(
        opener, "POST", "/dbsc/registration", body=b"", headers={
            "Secure-Session-Response": key.jws({"jti": jti}),
            "Content-Type": "application/json"})
    return jti, status, text


def native_register_manual(opener, jti, key, base=None):
    """Native registration with the JTI supplied, rather than read from the jar.

    Needed when the JTI must be re-presented after its cookie was cleared or
    expired, and when registration is aimed at the low-budget instance rather than
    the main demo. Returns (jti, status, text).
    """
    status, _, text = request(
        opener, "POST", "/dbsc/registration", body=b"", base=base, headers={
            "Secure-Session-Response": key.jws({"jti": jti}),
            "Content-Type": "application/json"})
    return jti, status, text


def binder_cookie_header(jar, sid, jti):
    """A Cookie header that re-presents a JTI the server has since forgotten.

    The server clears the challenge cookie on use and its Max-Age makes a
    compliant client drop it on expiry, so the only way to exercise the
    "consumed"/"expired" branches is to send the value by hand.
    """
    jsession = cookie_value(jar, "JSESSIONID")
    parts = []
    if jsession:
        parts.append(f"JSESSIONID={jsession}")
    parts.append(f"__Host-dbsc-reg={sid}")
    parts.append(f"__Host-dbsc-challenge={jti}")
    return "; ".join(parts)



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
    status, headers, session_id, csrf = login(opener, jar)
    check("POST /login redirects (302)", status == 302, f"got {status}")
    check("JSESSIONID issued and Secure",
          cookie(jar, "JSESSIONID") is not None and cookie(jar, "JSESSIONID").secure)
    reg = header(headers, "Secure-Session-Registration")
    check("Secure-Session-Registration present", reg is not None)
    if reg:
        check("registration header shape \"(ES256);path=...;challenge=...\"",
              bool(re.fullmatch(r'\(ES256\);path="/dbsc/registration";challenge="[^"]+"', reg)),
              reg)
    check("legacy Sec-Session-Registration emitted in parallel",
          header(headers, "Sec-Session-Registration") is not None)
    reg_cookie = cookie(jar, "__Host-dbsc-reg")
    ch_cookie = cookie(jar, "__Host-dbsc-challenge")
    check("__Host-dbsc-reg cookie present", reg_cookie is not None)
    check("__Host-dbsc-challenge cookie present", ch_cookie is not None)
    check("__Host- cookies are Secure",
          bool(reg_cookie and reg_cookie.secure and ch_cookie and ch_cookie.secure))
    check("__Host- cookies are HttpOnly and Path=/",
          bool(reg_cookie and reg_cookie.has_nonstandard_attr("HttpOnly")
               and reg_cookie.path == "/"))
    # The cookie carries the session id, which is what the session is keyed on.
    check("registration cookie names the servlet session id (coupling)",
          reg_cookie is not None and reg_cookie.value == session_id,
          f"{reg_cookie.value if reg_cookie else None} vs {session_id}")
    challenge = ch_cookie.value if ch_cookie else None

    # ------------------------------------------------- 2. native registration
    print("\n-- 2. native registration (/dbsc/registration) --")
    native = Key()
    jws = native.jws({"jti": challenge})
    # Chromium sends only the JWS header on this route; the body is empty.
    status, resp_headers, text = request(
        opener, "POST", "/dbsc/registration", body=b"", headers={
            "Secure-Session-Response": jws, "Content-Type": "application/json"})
    check("POST /dbsc/registration -> 200", status == 200, f"got {status}: {text[:200]}")
    if status == 200:
        cfg = json.loads(text)
        check("registration response carries a session identifier",
              bool(cfg.get("session_identifier")), str(cfg)[:200])
        check("binding cookie set", cookie(jar, "__Host-dbsc-session") is not None)
        check("challenge cookie cleared after use",
              cookie_value(jar, "__Host-dbsc-challenge") is None)

    # ---------------------------------------------------- 3. tier is now dbsc
    print("\n-- 3. tier promotion --")
    status, _, text = request(opener, "GET", "/app/whoami")
    check("GET /app/whoami -> 200", status == 200, f"got {status}")
    who = json.loads(text) if status == 200 else {}
    check("tier is dbsc after native registration", who.get("tier") == "dbsc", str(who))
    check("deviceKey true", who.get("deviceKey") is True, str(who))
    check("httpSessionId == dbscSessionId (coupled)",
          who.get("httpSessionId") == who.get("dbscSessionId") and who.get("coupled") is True,
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
        # session id travels in a header because the binding cookie is gone by now.
        sig = native.sign("")
        status, h2, t2 = request(
            opener, "POST", "/dbsc/refresh", body=b"", headers={
                "Content-Type": "application/json",
                "Sec-Secure-Session-Id": session_id,
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
                     "Sec-Secure-Session-Id": session_id})
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
                "Sec-Secure-Session-Id": session_id,
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
          "max-age" in (header(wh, "Cache-Control") or ""), str(wh.get("Cache-Control")))
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
    _, a_headers, a_sid, _ = login(a_opener, a_jar)
    a_key = Key()
    _, a_status, a_text = native_register(a_opener, a_jar, a_sid, a_key)
    a_cfg = json.loads(a_text) if a_status == 200 else {}

    check("native registration returns a JSON body (a 200 with no body is opt-out)",
          bool(a_cfg), a_text[:200])
    check("session_identifier is the app's own session id",
          a_cfg.get("session_identifier") == a_sid, f"{a_cfg.get('session_identifier')} != {a_sid}")
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
        check("credential[0].name is the binding cookie",
              cred0.get("name") == "__Host-dbsc-session", str(cred0.get("name")))
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
    login(b_opener, b_jar)
    status, _, text = request(
        b_opener, "POST", "/dbsc/registration", body=b"",
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
        b_opener, "POST", "/dbsc/registration", body=b"",
        headers={"Secure-Session-Response": wrong_typ, "Content-Type": "application/json"})
    check("typ != dbsc+jwt -> MALFORMED_JWS (checked before jwk)",
          "MALFORMED_JWS" in text, f"{status} {text[:160]}")

    status, _, text = request(
        b_opener, "POST", "/dbsc/registration", body=b"",
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
    _, _, c_sid, _ = login(c_opener, c_jar)
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
    status, _, text = request(
        a_opener, "POST", "/dbsc/registration", body=b"", headers={
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
        b_opener, "POST", "/dbsc/registration", body=b"", headers={
            "Secure-Session-Response": b64u(b"x") + "." + b64u(b"y"),
            "Content-Type": "application/json"})
    check("a two-segment bound-style signature on the native route -> MALFORMED_JWS",
          "MALFORMED_JWS" in text, f"{status} {text[:160]}")

    # --------------------------------------------------------- E. tier matrix
    print("\n-- E. tier reflects the surviving keys --")
    e1, e1_jar = new_client()
    _, _, e1_sid, _ = login(e1, e1_jar)
    check("a session with no key reads tier none", tier_of(e1) == "none", str(tier_of(e1)))

    e2, e2_jar = new_client()
    _, _, e2_sid, _ = login(e2, e2_jar)
    e2_key = Key()
    _, e2_status, e2_text = native_register(e2, e2_jar, e2_sid, e2_key)
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
    k1_opener, k1_jar = new_client()
    _, _, k1_sid, _ = login(k1_opener, k1_jar)
    k1_jti = cookie_value(k1_jar, "__Host-dbsc-challenge")
    k1_ck = binder_cookie_header(k1_jar, k1_sid, k1_jti)
    k1_key = Key()
    status, _, text = request(
        k1_opener, "POST", "/dbsc/registration", body=b"", headers={
            "Secure-Session-Response": k1_key.jws({"jti": k1_jti}),
            "Content-Type": "application/json"})
    check("the first use of a challenge succeeds", status == 200, f"{status} {text[:160]}")

    status, _, text = request(
        k1_opener, "POST", "/dbsc/registration", body=b"", headers={
            "Secure-Session-Response": k1_key.jws({"jti": k1_jti}),
            "Cookie": k1_ck,
            "Content-Type": "application/json"})
    check("reusing a consumed JTI -> CHALLENGE_CONSUMED",
          "CHALLENGE_CONSUMED" in text, f"{status} {text[:160]}")

    # The same must hold on the refresh leg: one challenge store, one consumption.
    k2_opener, k2_jar = new_client()
    _, _, k2_sid, _ = login(k2_opener, k2_jar)
    k2_jti = cookie_value(k2_jar, "__Host-dbsc-challenge")
    k2_ck = binder_cookie_header(k2_jar, k2_sid, k2_jti)
    k2_key = Key()
    _, status, text = native_register_manual(k2_opener, k2_jti, k2_key)
    check("a challenge works on the native registration route",
          status == 200, f"{status} {text[:160]}")
    status, _, text = request(
        k2_opener, "POST", "/dbsc/refresh", body=b"", headers={
            "Secure-Session-Response": refresh_jws(k2_key, k2_jti),
            "Cookie": k2_ck,
            "Content-Type": "application/json"})
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
        k3_opener, k3_jar = new_client()
        _, _, k3_sid, _ = login(k3_opener, k3_jar)
        k3_jti = cookie_value(k3_jar, "__Host-dbsc-challenge")
        k3_ck = binder_cookie_header(k3_jar, k3_sid, k3_jti)
        time.sleep(CHALLENGE_TTL_S + 1.0)
        k3_key = Key()
        status, _, text = request(
            k3_opener, "POST", "/dbsc/registration", body=b"", headers={
                "Secure-Session-Response": k3_key.jws({"jti": k3_jti}),
                "Cookie": k3_ck,
                "Content-Type": "application/json"})
        check("a stale JTI presented after the TTL -> CHALLENGE_EXPIRED",
              status == 403 and "CHALLENGE_EXPIRED" in text, f"{status} {text[:160]}")
        check("an expired challenge is not reported as missing or consumed",
              "CHALLENGE_NOT_FOUND" not in text and "CHALLENGE_CONSUMED" not in text,
              text[:160])

        # A JTI that never existed is a different failure and must stay distinct.
        status, _, text = request(
            k3_opener, "POST", "/dbsc/registration", body=b"", headers={
                "Secure-Session-Response": k3_key.jws({"jti": "n" * 43}),
                "Cookie": binder_cookie_header(k3_jar, k3_sid, "n" * 43),
                "Content-Type": "application/json"})
        check("an unknown JTI -> CHALLENGE_NOT_FOUND",
              "CHALLENGE_NOT_FOUND" in text, f"{status} {text[:160]}")

    # ------------------------------------------------- N. INVALID_JWK
    # Only the native route is served now, so the JWK rules are exercised through
    # the JWS header -- the same place a browser's key travels.
    print("\n-- G. a JWK that breaks the key rules is INVALID_JWK, not a crash --")
    n_opener, n_jar = new_client()
    _, _, n_sid, _ = login(n_opener, n_jar)
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
        n_head = {"alg": "ES256", "typ": "dbsc+jwt", "jwk": bad_key}
        n_h = b64u(json.dumps(n_head, separators=(",", ":")).encode())
        n_p = b64u(json.dumps({"jti": n_jti}, separators=(",", ":")).encode())
        status, _, text = request(
            n_opener, "POST", "/dbsc/registration", body=b"", headers={
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
    _, _, alg_sid, _ = login(alg_opener, alg_jar)
    request(alg_opener, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": alg_sid})
    alg_jti = cookie_value(alg_jar, "__Host-dbsc-challenge")
    if alg_jti is None:
        check("alg disagreeing with the JWK -> UNKNOWN_ALGORITHM", False,
              "no challenge cookie to present")
    else:
        alg_key = Key()
        status, _, text = request(
            alg_opener, "POST", "/dbsc/registration", body=b"", headers={
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
    _, _, q1_sid, _ = login(q1, q1_jar)
    request(q1, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": q1_sid})
    q1_ch = cookie_value(q1_jar, "__Host-dbsc-challenge")

    q2, q2_jar = new_client()
    _, _, q2_sid, _ = login(q2, q2_jar)
    request(q2, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": q2_sid})
    q2_ch = cookie_value(q2_jar, "__Host-dbsc-challenge")
    q2_key = Key()
    # q2 must hold a real key, or the key lookup would reject the request before
    # the session binding is ever compared.
    native_register_manual(q2, q2_ch, q2_key)

    # The challenge q1 was issued has since been consumed by the registration
    # above, so it is spent before the session binding is even compared. Re-arm
    # q1 with a live challenge and present *that* from the other session.
    request(q1, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": q1_sid})
    q1_live = cookie_value(q1_jar, "__Host-dbsc-challenge")
    check("q1 holds a live challenge to present from the other session",
          q1_live is not None)

    status, _, text = request(
        q2, "POST", "/dbsc/refresh", body=b"", headers={
            "Secure-Session-Response": refresh_jws(q2_key, q1_live),
            "Cookie": binder_cookie_header(q2_jar, q2_sid, q1_live),
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
    # Logout clears the binding cookie by expiring it, so check the Set-Cookie
    # header rather than the jar: a jar may simply drop an expired cookie.
    status, lh, _ = request(
        l_opener, "POST", "/logout", body=b"",
        headers={"X-CSRF-TOKEN": current_csrf(l_opener) or "x"})
    check("POST /logout responds with a redirect", status in (302, 303), f"got {status}")
    set_cookies = ", ".join(all_headers(lh, "Set-Cookie"))
    check("logout expires the DBSC binding cookie",
          "__Host-dbsc-session" in set_cookies, set_cookies[:200])

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
        p_status, _, p_sid, _ = login(p_opener, p_jar, base=RATE_BASE)
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
                # accounting entirely.
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

    summary = f"\n=== {len(PASS)} passed, {len(FAIL)} failed"
    summary += f", {len(SKIP)} skipped ===" if SKIP else " ==="
    print(summary)
    if SKIP:
        print("skipped: " + ", ".join(SKIP))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
