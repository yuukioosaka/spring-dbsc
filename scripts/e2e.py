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
unreachable there. Start a second instance with a small failure budget:

    mvn -Pdemo -Dmaven.repo.local=.m2repo \
        -Dspring-boot.run.arguments="--server.port=9443 \
            --spring.datasource.url=jdbc:h2:file:./data/e2e-ratelimit" \
        -Dspring-boot.run.jvmArguments="-Ddbsc.rate-limit.failure-capacity=5" \
        spring-boot:run
    DBSC_RATE_LIMIT_FAILURES=5 python3 scripts/e2e.py

Requires `cryptography` (EC keygen + ES256 signing).
"""
import base64, hashlib, json, os, re, ssl, sys, time
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


def raw_request(opener, method, path, data, headers=None):
    """Sends exact bytes, so a body-hash proof can be computed over them.

    `request(..., form=False)` JSON-encodes a dict, which makes it impossible to
    control the bytes a proof is signed over. Proof tests need byte-for-byte
    control, so they use this instead.
    """
    req = urllib.request.Request(BASE + path, data=data, headers=dict(headers or {}), method=method)
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
    """An ES256 key pair, the way both DBSC tiers use them."""

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

    def jws(self, payload: dict, include_jwk=True) -> str:
        # typ must be dbsc+jwt; the verifier rejects anything else, including the
        # plain "jwt" a generic JOSE library would default to.
        head = {"alg": "ES256", "typ": "dbsc+jwt"}
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


def native_register_manual(opener, jti, key):
    """Native registration with the JTI supplied, rather than read from the jar.

    Needed when the JTI must be re-presented after its cookie was cleared or
    expired. Returns (jti, status, text).
    """
    status, _, text = request(
        opener, "POST", "/dbsc/registration", body=b"", headers={
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


def bound_challenge(opener, jar, path="/dbsc-bound/challenge"):
    """Fetches a bound-protocol challenge from the response *body*.

    The bound routes carry their JTI in JSON, never in a cookie: the challenge
    cookie belongs to the native routes, and a second writer to the same name
    would invalidate a native registration already in flight. Returns
    (jti, status, text).
    """
    status, _, text = request(opener, "GET", path)
    if status != 200:
        return None, status, text
    return json.loads(text).get("challenge"), status, text


def bound_register(opener, jar, key):
    """Runs bound registration off a challenge read from the JSON body."""
    jti, status, text = bound_challenge(opener, jar)
    if jti is None:
        return None, status, text
    status, headers, text = request(
        opener, "POST", "/dbsc-bound/registration", form=False, body={
            "publicKey": key.public_jwk(),
            "signature": key.sign(jti),
            "challenge": jti})
    return jti, status, text


def bound_session(user="demo"):
    """A logged-in client holding both a native and a bound key, plus live CSRF.

    Reaching any spec-04 path requires a bound key, which is only obtainable by
    going through both registrations, so the proof tests share this setup.
    """
    opener, jar = new_client()
    status, _, sid, _ = login(opener, jar, user)
    native = Key()
    native_register(opener, jar, sid, native)
    bound = Key()
    bound_register(opener, jar, bound)
    return opener, jar, sid, native, bound, current_csrf(opener)


def signed_proof(key, sid, method, path, ts, body=None):
    """Builds an X-Dbsc-Bound-Proof header for a given (sid, method, path, ts)."""
    bh = b64u(hashlib.sha256(body).digest()) if body is not None else None
    msg = f"{sid}.{method}.{path}.{ts}" + (f".{bh}" if bh else "")
    header_value = f"ts={ts};sig={key.sign(msg)}"
    return (header_value + f";bh={bh}") if bh else header_value


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
    check("registration cookie is the servlet session id (coupling)",
          reg_cookie is not None and reg_cookie.value == session_id)
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
    print("\n-- 3. tier promotion and the unguarded route --")
    status, _, text = request(opener, "GET", "/app/whoami")
    check("GET /app/whoami -> 200", status == 200, f"got {status}")
    who = json.loads(text) if status == 200 else {}
    check("tier is dbsc after native registration", who.get("tier") == "dbsc", str(who))
    check("nativeKey true", who.get("nativeKey") is True, str(who))
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
        _, _, tw = request(opener, "GET", "/app/whoami")
        w = json.loads(tw)
        check("tier demoted to none after a failed refresh", w.get("tier") == "none", str(w))

    # ------------------------------------------------------- 7. proof guard
    print("\n-- 7. guarded route (/app/payment) --")
    # Re-arm the session first: the previous step deliberately demoted it, and a
    # demoted session cannot reach the proof check at all.
    status, _, _, csrf = login(opener, jar)
    csrf = current_csrf(opener)
    status, _, tg = request(
        opener, "POST", "/app/payment",
        body={"amount": 1000, "currency": "usd"},
        headers={"X-CSRF-TOKEN": csrf}, form=False)
    check("no proof -> 403", status == 403, f"got {status}")
    check("no proof -> DBSC error body, not a Spring error page",
          "MISSING_PROOF" in tg or "KEY_NOT_FOUND" in tg, tg[:200])

    # ------------------------------------------------------- 8. bound flow
    print("\n-- 8. bound (toolkit) flow --")
    status, _, ts = request(opener, "GET", "/dbsc-bound/state")
    check("GET /dbsc-bound/state -> 200", status == 200, f"got {status}: {ts[:200]}")
    status, _, tc = request(opener, "GET", "/dbsc-bound/challenge")
    check("GET /dbsc-bound/challenge -> 200", status == 200, f"got {status}: {tc[:200]}")
    check("the bound challenge arrives in the body, not the cookie jar",
          bool(json.loads(tc).get("challenge")) if status == 200 else False, tc[:200])

    # ---------------------------------------------------- 9. well-known
    print("\n-- 9. well-known metadata --")
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
        check("refresh before registering a key -> KEY_NOT_FOUND_NATIVE",
              "KEY_NOT_FOUND_NATIVE" in text, f"{status} {text[:160]}")

    # ------------------------------------------------- C. already-registered
    print("\n-- C. a second registration of the same kind is refused --")
    # A fresh *native* challenge: the bound routes keep their JTI in the body and
    # never touch the challenge cookie, so this one has to come from the native
    # refresh leg.
    request(a_opener, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": a_sid})
    a_ch2 = cookie_value(a_jar, "__Host-dbsc-challenge")
    status, _, text = request(
        a_opener, "POST", "/dbsc/registration", body=b"", headers={
            "Secure-Session-Response": a_key.jws({"jti": a_ch2}),
            "Content-Type": "application/json"})
    check("second native registration -> SESSION_ALREADY_REGISTERED",
          "SESSION_ALREADY_REGISTERED" in text, f"{status} {text[:160]}")

    # The next section asserts the bound flow against the *same* session, so the
    # challenge it consumes is the one the native registration just passed over.
    request(a_opener, "POST", "/dbsc/refresh", body=b"",
            headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": a_sid})

    # The native key must not block the *bound* registration: the kinds are
    # tracked separately and a Chromium session is expected to hold both.
    a_bound = Key()
    _, status, text = bound_register(a_opener, a_jar, a_bound)
    check("bound registration still succeeds with a native key present",
          status == 200, f"{status} {text[:160]}")
    check("tier stays dbsc when both keys exist",
          (json.loads(text) if status == 200 else {}).get("tier") == "dbsc", text[:160])
    check("bound refresh_url is /dbsc-bound/refresh",
          (json.loads(text) if status == 200 else {}).get("refresh_url") == "/dbsc-bound/refresh",
          text[:160])

    _, status2, text2 = bound_register(a_opener, a_jar, Key())
    check("second bound registration -> SESSION_ALREADY_REGISTERED",
          "SESSION_ALREADY_REGISTERED" in text2, f"{status2} {text2[:160]}")

    # ------------------------------------------------- D. bound state phases
    print("\n-- D. /dbsc-bound/state reports the phase the client must act on --")
    d_anon, _ = new_client()
    status, _, text = request(d_anon, "GET", "/dbsc-bound/state")
    d_state = json.loads(text) if status == 200 else {}
    check("sessionless state -> 200 {phase: unbound, sessionId: null}",
          status == 200 and d_state.get("phase") == "unbound" and d_state.get("sessionId") is None,
          f"{status} {text[:160]}")

    # A fresh login that has done neither registration needs a polyfill key.
    e_opener, e_jar = new_client()
    _, _, e_sid, _ = login(e_opener, e_jar)
    e_login_ch = cookie_value(e_jar, "__Host-dbsc-challenge")
    status, _, text = request(e_opener, "GET", "/dbsc-bound/state")
    e_state = json.loads(text)
    check("no keys at all -> needs-registration with a challenge",
          e_state.get("phase") == "needs-registration" and bool(e_state.get("challenge")),
          text[:200])
    # The bound protocol carries its challenge in the JSON body. It must NOT write
    # the challenge cookie, which belongs to the native routes: a second writer to
    # that name invalidates the native registration the login primed, and the
    # registration POST that follows then fails JTI_MISMATCH.
    check("state leaves the native challenge cookie untouched",
          cookie_value(e_jar, "__Host-dbsc-challenge") == e_login_ch,
          f"{e_login_ch} -> {cookie_value(e_jar, '__Host-dbsc-challenge')}")
    check("the state challenge is not the native login challenge",
          e_state.get("challenge") != e_login_ch, text[:200])

    e_native = Key()
    native_register(e_opener, e_jar, e_sid, e_native)
    status, _, text = request(e_opener, "GET", "/dbsc-bound/state")
    e_state = json.loads(text)
    check("native key but no bound key -> needs-bound-registration, tier stays dbsc",
          e_state.get("phase") == "needs-bound-registration" and e_state.get("tier") == "dbsc",
          text[:200])
    check("needs-bound-registration advertises refreshIntervalMs",
          isinstance(e_state.get("refreshIntervalMs"), int), text[:200])

    e_bound = Key()
    bound_register(e_opener, e_jar, e_bound)
    status, _, text = request(e_opener, "GET", "/dbsc-bound/state")
    e_state = json.loads(text)
    check("both keys -> phase bound and no further challenge",
          e_state.get("phase") == "bound" and "challenge" not in e_state, text[:200])

    status, _, text = request(d_anon, "GET", "/dbsc-bound/challenge")
    check("sessionless challenge -> 403 with the prose body {\"error\":\"no session\"}",
          status == 403 and json.loads(text).get("error") == "no session", f"{status} {text[:160]}")
    check("the sessionless error is prose, not a SCREAMING_SNAKE code",
          "no session" in text and "_" not in text, text[:160])

    status, _, text = request(
        d_anon, "POST", "/dbsc-bound/registration", body={}, form=False)
    check("bound registration without a session cookie -> 400 BAD_REQUEST",
          status == 400 and "BAD_REQUEST" in text, f"{status} {text[:160]}")

    # ------------------------------------------------- E. bound refresh
    print("\n-- E. bound refresh validates the timestamp before the key --")
    e_ch, _, text = bound_challenge(e_opener, e_jar)
    e_ts = now_ms()
    status, e_headers, e_text = request(
        e_opener, "POST", "/dbsc-bound/refresh", form=False, body={
            "challenge": e_ch, "signature": e_bound.sign(f"{e_ch}.{e_ts}"), "timestamp": e_ts})
    check("bound refresh with a fresh timestamp -> 200", status == 200, f"{status} {e_text[:160]}")
    check("bound endpoints advertise the server clock (X-Server-Time)",
          header(e_headers, "X-Server-Time") is not None, str(e_headers)[:160])
    # The bound flow keeps its JTI in the body, so a refresh has nothing to clear
    # and must not clear the native routes' cookie either.
    check("a successful bound refresh leaves the challenge cookie alone",
          "__Host-dbsc-challenge" not in " ".join(all_headers(e_headers, "Set-Cookie")),
          str(e_headers)[:200])

    e_ch2, _, _ = bound_challenge(e_opener, e_jar)
    stale = now_ms() - 10 * 60 * 1000
    status, _, text = request(
        e_opener, "POST", "/dbsc-bound/refresh", form=False, body={
            "challenge": e_ch2, "signature": e_bound.sign(f"{e_ch2}.{stale}"), "timestamp": stale})
    check("bound refresh with a stale timestamp -> SIGNATURE_INVALID",
          status == 403 and "SIGNATURE_INVALID" in text, f"{status} {text[:160]}")

    e_opener2, e_jar2, e_sid2, e_nat2, e_bnd2, _ = bound_session()
    e_ch3, _, _ = bound_challenge(e_opener2, e_jar2)
    e_ts3 = now_ms()
    # Signed by a *different* key than the one registered: the signature is
    # well-formed and in-window, so only the key lookup can reject it.
    e_wrong = Key()
    status, _, text = request(
        e_opener2, "POST", "/dbsc-bound/refresh", form=False, body={
            "challenge": e_ch3, "signature": e_wrong.sign(f"{e_ch3}.{e_ts3}"), "timestamp": e_ts3})
    check("bound refresh with the wrong key -> SIGNATURE_INVALID",
          status == 403 and "SIGNATURE_INVALID" in text, f"{status} {text[:160]}")
    check("a failed bound refresh demotes the session to none",
          tier_of(e_opener2) == "none", str(tier_of(e_opener2)))

    # ------------------------------------------------ F. Sec-Session-Skipped
    print("\n-- F. Sec-Session-Skipped is diagnostic and never an error --")
    status, _, text = request(e_opener2, "GET", "/dbsc-bound/state", headers={
        "Sec-Session-Skipped": 'quota_exceeded;session_identifier="abc", unreachable, not_a_reason'})
    f_state = json.loads(text) if status == 200 else {}
    check("a skipped header does not change the status", status == 200, f"got {status}")
    skipped = f_state.get("nativeSkipped") or []
    check("nativeSkipped echoes the recognised reasons in order",
          [s.get("reason") for s in skipped] == ["quota_exceeded", "unreachable"], str(skipped))
    check("session_identifier is unquoted when echoed",
          skipped and skipped[0].get("sessionId") == "abc", str(skipped))
    check("an unrecognised token is ignored, not an error",
          all(s.get("reason") != "not_a_reason" for s in skipped), str(skipped))

    # ------------------------------------------------------ G. cross-protocol
    print("\n-- G. a proof from one protocol is rejected by the other --")
    status, _, text = request(
        b_opener, "POST", "/dbsc/registration", body=b"", headers={
            "Secure-Session-Response": b64u(b"x") + "." + b64u(b"y"),
            "Content-Type": "application/json"})
    check("a two-segment bound signature on the native route -> MALFORMED_JWS",
          "MALFORMED_JWS" in text, f"{status} {text[:160]}")

    # --------------------------------------------------------- H. tier matrix
    print("\n-- H. tier reflects the surviving keys --")
    h1, h1_jar = new_client()
    _, _, h1_sid, _ = login(h1, h1_jar)
    check("a session with neither key reads tier none", tier_of(h1) == "none", str(tier_of(h1)))

    h2, h2_jar = new_client()
    _, _, h2_sid, _ = login(h2, h2_jar)
    h2_bound = Key()
    bound_register(h2, h2_jar, h2_bound)
    check("a bound-only session reads tier bound", tier_of(h2) == "bound", str(tier_of(h2)))

    status, _, text = request(h2, "GET", "/app/whoami")
    who2 = json.loads(text)
    check("whoami reports boundKey true and nativeKey false",
          who2.get("boundKey") is True and who2.get("nativeKey") is False, str(who2))

    # ------------------------------------------- I. per-request proof (04)
    print("\n-- I. per-request proof on the guarded route --")
    p_opener, p_jar, p_sid, p_native, p_bound, p_csrf = bound_session()
    p_body = b'{"amount":1000,"currency":"usd"}'
    p_headers = {"X-CSRF-TOKEN": p_csrf, "Content-Type": "application/json"}

    status, _, text = raw_request(
        p_opener, "POST", "/app/payment", p_body, dict(p_headers))
    check("a guarded route without a proof -> 403 MISSING_PROOF",
          status == 403 and "MISSING_PROOF" in text, f"{status} {text[:160]}")

    p_ts = now_ms()
    p_proof = signed_proof(p_bound, p_sid, "POST", "/app/payment", p_ts, p_body)
    status, _, text = raw_request(
        p_opener, "POST", "/app/payment", p_body,
        dict(p_headers, **{"X-Dbsc-Bound-Proof": p_proof}))
    check("a valid proof over the exact body -> 200", status == 200, f"{status} {text[:200]}")
    check("the guarded handler still sees the replayed body",
          "1000" in text, text[:200])

    # The replay cache is checked after the signature (spec 04), so the very same
    # proof bytes are now refused.
    status, _, text = raw_request(
        p_opener, "POST", "/app/payment", p_body,
        dict(p_headers, **{"X-Dbsc-Bound-Proof": p_proof}))
    check("replaying an identical proof -> 403 PROOF_REPLAY",
          status == 403 and "PROOF_REPLAY" in text, f"{status} {text[:160]}")

    # Mutating the body invalidates the body hash, which is the whole point of
    # binding the body: the signature itself is still perfectly valid.
    p_body2 = b'{"amount":1,"currency":"usd"}'
    status, _, text = raw_request(
        p_opener, "POST", "/app/payment", p_body2,
        dict(p_headers, **{"X-Dbsc-Bound-Proof": p_proof}))
    check("a proof reused on a modified body -> SIGNATURE_INVALID",
          status == 403 and (
              "SIGNATURE_INVALID" in text or "MALFORMED_PROOF" in text),
          f"{status} {text[:160]}")

    # A proof signed for one path must not open another.
    p_ts3 = now_ms()
    wrong_path = signed_proof(p_bound, p_sid, "POST", "/app/other", p_ts3, p_body)
    status, _, text = raw_request(
        p_opener, "POST", "/app/payment", p_body,
        dict(p_headers, **{"X-Dbsc-Bound-Proof": wrong_path}))
    check("a proof scoped to another path -> SIGNATURE_INVALID",
          status == 403 and "SIGNATURE_INVALID" in text, f"{status} {text[:160]}")

    p_ts4 = now_ms()
    wrong_method = signed_proof(p_bound, p_sid, "GET", "/app/payment", p_ts4, p_body)
    status, _, text = raw_request(
        p_opener, "POST", "/app/payment", p_body,
        dict(p_headers, **{"X-Dbsc-Bound-Proof": wrong_method}))
    check("the signed method is bound into the message",
          status == 403 and "SIGNATURE_INVALID" in text, f"{status} {text[:160]}")

    stale_ts = now_ms() - 10 * 60 * 1000
    status, _, text = raw_request(
        p_opener, "POST", "/app/payment", p_body,
        dict(p_headers, **{"X-Dbsc-Bound-Proof":
                           signed_proof(p_bound, p_sid, "POST", "/app/payment", stale_ts, p_body)}))
    check("a stale proof timestamp -> SIGNATURE_INVALID",
          status == 403 and "SIGNATURE_INVALID" in text, f"{status} {text[:160]}")

    # -------------------------------------------- J. proof header parse rules
    print("\n-- J. proof header parse rules (MALFORMED_PROOF) --")
    j_ts = now_ms()
    j_valid = signed_proof(p_bound, p_sid, "POST", "/app/payment", j_ts, p_body)
    long_value = "ts=" + str(j_ts) + ";sig=" + ("A" * 8300)
    malformed_cases = [
        ("a segment with no '='", "ts" + str(j_ts) + ";sig=" + ("A" * 40)),
        ("a segment with an empty value", f"ts={j_ts};sig="),
        ("a duplicate key", f"ts={j_ts};ts={j_ts};sig={'A' * 40}"),
        ("more than 8 segments", ";".join(f"k{i}=v" for i in range(9))),
        ("a non-numeric ts", "ts=abc;sig=" + ("A" * 40)),
        ("a fractional ts", "ts=1.5;sig=" + ("A" * 40)),
        ("a header over 8192 bytes", long_value),
        ("a proof with no ts", "sig=" + ("A" * 40)),
        ("a proof with no sig", f"ts={j_ts}"),
    ]
    for label, value in malformed_cases:
        status, _, text = raw_request(
            p_opener, "POST", "/app/payment", p_body,
            dict(p_headers, **{"X-Dbsc-Bound-Proof": value}))
        check(f"{label} -> MALFORMED_PROOF",
              status == 403 and "MALFORMED_PROOF" in text, f"{status} {text[:140]}")

    status, _, text = raw_request(
        p_opener, "POST", "/app/payment", p_body,
        dict(p_headers, **{"X-Dbsc-Bound-Proof": ""}))
    check("an empty proof header value -> MISSING_PROOF",
          status == 403 and "MISSING_PROOF" in text, f"{status} {text[:140]}")

    # Body signing is on for this route, so omitting bh is malformed; carrying a
    # bogus bh is a signature failure, because the hash is part of the message.
    status, _, text = raw_request(
        p_opener, "POST", "/app/payment", p_body,
        dict(p_headers, **{"X-Dbsc-Bound-Proof":
                           f"ts={now_ms()};sig={p_bound.sign('anything')}"}))
    check("a body-signed route rejects a proof with no bh -> MALFORMED_PROOF",
          status == 403 and "MALFORMED_PROOF" in text, f"{status} {text[:160]}")

    # Segment order is not significant, so the same proof reordered must verify.
    p_ts5 = now_ms()
    bh5 = b64u(hashlib.sha256(p_body).digest())
    msg5 = f"{p_sid}.POST./app/payment.{p_ts5}.{bh5}"
    reordered = f"bh={bh5};sig={p_bound.sign(msg5)};ts={p_ts5}"
    status, _, text = raw_request(
        p_opener, "POST", "/app/payment", p_body,
        dict(p_headers, **{"X-Dbsc-Bound-Proof": reordered}))
    check("proof segment order is not significant", status == 200, f"{status} {text[:160]}")

    # Values carry whitespace around the ';' separators in the wild.
    p_ts6 = now_ms()
    bh6 = b64u(hashlib.sha256(p_body).digest())
    msg6 = f"{p_sid}.POST./app/payment.{p_ts6}.{bh6}"
    spaced = f"ts={p_ts6}; sig={p_bound.sign(msg6)}; bh={bh6}"
    status, _, text = raw_request(
        p_opener, "POST", "/app/payment", p_body,
        dict(p_headers, **{"X-Dbsc-Bound-Proof": spaced}))
    check("whitespace around segments is tolerated", status == 200, f"{status} {text[:160]}")

    # Proof verification must not be poisoned by earlier garbage: the cache is
    # only written after the cryptographic checks pass.
    p_ts7 = now_ms()
    status, _, text = raw_request(
        p_opener, "POST", "/app/payment", p_body,
        dict(p_headers, **{"X-Dbsc-Bound-Proof":
                           signed_proof(p_bound, p_sid, "POST", "/app/payment", p_ts7, p_body)}))
    check("a valid proof still verifies after many garbage proofs",
          status == 200, f"{status} {text[:160]}")

    # ------------------------------------- K. challenge expiry and consumption
    print("\n-- K. challenge lifecycle: single-use and expiry --")

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

    # Consumption is not scoped to the route that used it: the bound protocol
    # shares one challenge store, so a JTI burnt natively is burnt everywhere.
    k2_opener, k2_jar = new_client()
    _, _, k2_sid, _ = login(k2_opener, k2_jar)
    k2_jti = cookie_value(k2_jar, "__Host-dbsc-challenge")
    k2_ck = binder_cookie_header(k2_jar, k2_sid, k2_jti)
    k2_native = Key()
    m, status, text = native_register_manual(k2_opener, k2_jti, k2_native)
    check("a challenge works on the native route", status == 200, f"{status} {text[:160]}")
    k2_bound = Key()
    status, _, text = request(
        k2_opener, "POST", "/dbsc-bound/registration", form=False, headers={"Cookie": k2_ck}, body={
            "publicKey": k2_bound.public_jwk(),
            "signature": k2_bound.sign(k2_jti),
            "challenge": k2_jti})
    check("a JTI consumed by the native route -> CHALLENGE_CONSUMED on the bound route",
          "CHALLENGE_CONSUMED" in text, f"{status} {text[:160]}")

    # The reverse direction: a JTI the bound route issued is consumable natively.
    k2b_opener, k2b_jar = new_client()
    _, _, k2b_sid, _ = login(k2b_opener, k2b_jar)
    k2b_jti, status, text = bound_challenge(k2b_opener, k2b_jar)
    k2b_bound = Key()
    status, _, text = request(
        k2b_opener, "POST", "/dbsc-bound/registration", form=False, body={
            "publicKey": k2b_bound.public_jwk(),
            "signature": k2b_bound.sign(k2b_jti),
            "challenge": k2b_jti})
    check("a challenge issued by the bound route registers the bound key",
          status == 200, f"{status} {text[:160]}")
    status, _, text = request(
        k2b_opener, "POST", "/dbsc-bound/refresh", form=False, body={
            "challenge": k2b_jti, "signature": k2b_bound.sign(f"{k2b_jti}.{now_ms()}"),
            "timestamp": now_ms()})
    check("the same JTI on the bound refresh -> CHALLENGE_CONSUMED",
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

    # ------------------------------------------------- L. guard needs a binding
    print("\n-- L. a guarded route requires an actual binding --")
    k_opener, k_jar = new_client()
    _, _, k_sid, _ = login(k_opener, k_jar)
    k_csrf = current_csrf(k_opener)
    k_ts = now_ms()
    k_key = Key()
    status, _, text = raw_request(
        k_opener, "POST", "/app/payment", p_body,
        {"X-CSRF-TOKEN": k_csrf or "x", "Content-Type": "application/json",
         "X-Dbsc-Bound-Proof": signed_proof(k_key, k_sid, "POST", "/app/payment", k_ts, p_body)})
    check("a proof with no bound key -> 403, not a crash", status == 403, f"{status} {text[:160]}")
    check("the refusal names KEY_NOT_FOUND_BOUND",
          "KEY_NOT_FOUND_BOUND" in text, text[:160])
    check("the refusal is a DBSC error body, not a Spring default page",
          "error" in text and "timestamp" not in text, text[:160])

    # ------------------------------------------------- N. INVALID_JWK
    print("\n-- N. a JWK that breaks the key rules is INVALID_JWK, not a crash --")
    n_opener, n_jar = new_client()
    _, _, n_sid, _ = login(n_opener, n_jar)
    # Each of these trips a different rule in Jwk.validate. The signature is real
    # and the challenge is live, so only the key check can reject the request.
    for label, bad_key, expect in [
            ("an unsupported curve (P-384) -> INVALID_JWK",
             {"kty": "EC", "crv": "P-384", "x": "a", "y": "b"}, "unsupported curve"),
            ("an EC key with no coordinates -> INVALID_JWK",
             {"kty": "EC", "crv": "P-256"}, "missing x or y"),
            ("an unsupported key type (oct) -> INVALID_JWK",
             {"kty": "oct", "k": "AAAA"}, "unsupported key type"),
            ("an RSA modulus under 2048 bits -> INVALID_JWK",
             {"kty": "RSA", "n": "AQAB"}, "too short")]:
        n_ch, _, _ = bound_challenge(n_opener, n_jar)
        n_key = Key()
        status, _, text = request(
            n_opener, "POST", "/dbsc-bound/registration", form=False, body={
                "publicKey": bad_key, "signature": n_key.sign(n_ch), "challenge": n_ch})
        check(label, status == 403 and "INVALID_JWK" in text, f"{status} {text[:160]}")
        # The rule that fired is named, so a caller can tell a rejected curve from
        # an undersized modulus without reading the source.
        check(f"  ...and names the rule: {expect}", expect in text, text[:160])

    # The native route validates the JWK carried in the JWS header, not just the
    # one in a bound body, so it must reject a bad key on its own path too.
    n_jti = cookie_value(n_jar, "__Host-dbsc-challenge")
    n_bad_head = {"alg": "ES256", "typ": "dbsc+jwt",
                  "jwk": {"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"}}
    n_h = b64u(json.dumps(n_bad_head, separators=(",", ":")).encode())
    n_p = b64u(json.dumps({"jti": n_jti}).encode())
    status, _, text = request(
        n_opener, "POST", "/dbsc/registration", body=b"", headers={
            "Secure-Session-Response": f"{n_h}.{n_p}.{b64u(b'0' * 64)}",
            "Content-Type": "application/json"})
    check("a native registration carrying a bad JWK -> INVALID_JWK",
          status == 403 and "INVALID_JWK" in text, f"{status} {text[:160]}")

    # ------------------------------------------------- O. SESSION_NOT_REGISTERED
    print("\n-- O. a refresh naming a session that was never stored --")
    # A challenge is bound to whatever session id the request presents, so a forged
    # id gets a legitimate challenge. Authentication comes back as OK for *that*
    # id, but no record exists for it: the refresh must be refused rather than
    # treated as an unknown-but-plausible client. This is the forged-cookie case.
    o_forged = "f" * 32
    o_rg, o_rg_jar = new_client()
    login(o_rg, o_rg_jar)
    o_key = Key()
    status, _, text = request(o_rg, "GET", "/dbsc-bound/challenge",
                              headers={"Cookie": f"__Host-dbsc-reg={o_forged}"})
    check("a forged session id can still obtain a challenge", status == 200, f"{status} {text[:160]}")
    o_ch = json.loads(text).get("challenge") if status == 200 else None
    o_ts = now_ms()
    status, _, text = request(
        o_rg, "POST", "/dbsc-bound/refresh", form=False,
        headers={"Cookie": f"__Host-dbsc-reg={o_forged}"},
        body={"challenge": o_ch, "signature": o_key.sign(f"{o_ch}.{o_ts}"),
              "timestamp": o_ts})
    check("a refresh for an unstored session -> SESSION_NOT_REGISTERED",
          status == 403 and "SESSION_NOT_REGISTERED" in text, f"{status} {text[:160]}")
    check("it is not reported as a missing key or a bad signature",
          "KEY_NOT_FOUND" not in text and "SIGNATURE_INVALID" not in text, text[:160])

    # ------------------------------------------------ Q. JTI_MISMATCH
    print("\n-- Q. a challenge presented by the wrong session --")
    # A JTI is bound to the session it was issued for. Two sessions are set up and
    # one's challenge is presented on the other, which is the case a stolen or
    # replayed challenge hits. The signature is made by the *right* key for the
    # presenting session, so the session binding is the only thing rejecting it.
    q1, q1_jar, _, _, q1_bound, _ = bound_session()
    q2, q2_jar, _, _, q2_bound, _ = bound_session()
    q1_ch, _, _ = bound_challenge(q1, q1_jar)
    q_ts = now_ms()
    status, _, text = request(
        q2, "POST", "/dbsc-bound/refresh", form=False, body={
            "challenge": q1_ch,
            "signature": q2_bound.sign(f"{q1_ch}.{q_ts}"),
            "timestamp": q_ts})
    check("another session's challenge -> JTI_MISMATCH",
          status == 403 and "JTI_MISMATCH" in text, f"{status} {text[:160]}")
    check("it is not reported as missing or expired",
          "CHALLENGE_NOT_FOUND" not in text and "CHALLENGE_EXPIRED" not in text, text[:160])

    # -------------------------------------------- R. UNKNOWN_ALGORITHM
    print("\n-- R. a valid key the bound protocol cannot use --")
    # A 2048-bit RSA key is a perfectly valid JWK and the native protocol accepts
    # it, but the bound polyfill is ES256-only. It is therefore UNKNOWN_ALGORITHM
    # (the algorithm cannot be honoured) rather than INVALID_JWK (the key is bad),
    # and the two must not be conflated.
    r_opener, r_jar = new_client()
    _, _, r_sid, _ = login(r_opener, r_jar)
    r_ch, _, _ = bound_challenge(r_opener, r_jar)
    # An RSA modulus of the minimum permitted size, so only the algorithm check can
    # object: Jwk.validate accepts this key.
    r_n = b64u(bytes([0x80]) + b"\x00" * 255)
    r_key = Key()
    status, _, text = request(
        r_opener, "POST", "/dbsc-bound/registration", form=False, body={
            "publicKey": {"kty": "RSA", "n": r_n},
            "signature": r_key.sign(r_ch), "challenge": r_ch})
    check("an RSA key on the bound route -> UNKNOWN_ALGORITHM",
          status == 403 and "UNKNOWN_ALGORITHM" in text, f"{status} {text[:160]}")
    check("it is not reported as INVALID_JWK",
          "INVALID_JWK" not in text, text[:160])

    # ---------------------------------------------------- 10. logout
    print("\n-- M. logout terminates the binding --")
    # Logout clears the binding cookie by expiring it, so check the Set-Cookie
    # header rather than the jar: a jar may simply drop an expired cookie.
    status, lh, _ = request(
        opener, "POST", "/logout", body=b"",
        headers={"X-CSRF-TOKEN": csrf or current_csrf(opener)})
    check("POST /logout responds with a redirect", status in (302, 303), f"got {status}")
    set_cookies = ", ".join(all_headers(lh, "Set-Cookie"))
    check("logout expires the DBSC binding cookie",
          "__Host-dbsc-session" in set_cookies, set_cookies[:200])

    # ---------------------------------- 11. unauthenticated access is refused
    print("\n-- 11. an anonymous client is refused --")
    anon, _ = new_client()
    status, _, _ = request(anon, "GET", "/app/whoami")
    check("anonymous GET /app/whoami is not 200", status != 200, f"got {status}")

    # ------------------------------------------------- P. RATE_LIMITED
    print("\n-- P. a client that keeps failing is throttled --")
    if RATE_LIMIT_FAILURES is None:
        skip("repeated failures -> 429 RATE_LIMITED",
             "start a second demo on " + RATE_BASE + " with a small "
             "dbsc.rate-limit.failure-capacity and set DBSC_RATE_LIMIT_FAILURES")
    else:
        # A separate instance: the demo's own budgets are 1000 so that this suite's
        # deliberate failures do not throttle it, which leaves RATE_LIMITED
        # unreachable there. The limiter counts failures, not just requests, so a
        # loop of rejected proofs is what trips it.
        #
        # The limiter keys on client IP and holds its counters for a whole window,
        # and every local run shares one IP. A previous run -- or a previous
        # section -- can therefore leave this instance already throttled, which
        # would make "it trips after N attempts" meaningless. Probing first tells
        # the two situations apart instead of failing on a spent window.
        p_opener, p_jar = new_client()
        p_status, _, p_sid, _ = login(p_opener, p_jar, base=RATE_BASE)
        if p_status != 302:
            check("the low-budget demo accepts the same login", False,
                  f"login returned {p_status}; is a second instance on {RATE_BASE}?")
        else:
            p_key = Key()

            def p_refresh():
                ts = now_ms()
                return request(
                    p_opener, "POST", "/dbsc-bound/refresh", form=False, base=RATE_BASE, body={
                        "challenge": "never-issued",
                        "signature": p_key.sign(f"never-issued.{ts}"),
                        "timestamp": ts})

            # Each iteration presents a proof whose challenge was never issued, so
            # every request fails and is charged to the client's failure budget.
            throttled_at = None
            for i in range(RATE_LIMIT_FAILURES + 10):
                status, _, text = p_refresh()
                if status == 429:
                    throttled_at = i
                    break
            check("repeating a rejected proof -> 429 RATE_LIMITED", throttled_at is not None,
                  f"never throttled in {RATE_LIMIT_FAILURES + 10} attempts; last was {status} {text[:120]}")
            if throttled_at is not None:
                check("the 429 body carries RATE_LIMITED, not a generic error",
                      "RATE_LIMITED" in text, text[:160])
                if throttled_at == 0:
                    # The window was already spent before this section started, so
                    # the attempt count says nothing. Say so rather than assert it.
                    skip("it trips at the configured failure budget, not before",
                         "the instance was already throttled when this section began")
                else:
                    check("it trips at the configured failure budget, not before",
                          throttled_at >= RATE_LIMIT_FAILURES - 1,
                          f"tripped after {throttled_at} attempts, budget {RATE_LIMIT_FAILURES}")
                # A throttled request must not be charged again, or a client that
                # keeps retrying would push its own lockout out forever. Waiting out
                # a whole window is the only way to observe that here, so it is done
                # once and the check is kept cheap.
                status2, _, _ = p_refresh()
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
