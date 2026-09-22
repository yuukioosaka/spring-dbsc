"""Proves the Redis store survives a restart, at the protocol level.

The reason `dbsc.storage` exists is that an in-memory store loses device keys on
restart: the browser keeps its __Host-dbsc-session cookie, the server has no key to
verify it against, and every refresh is KEY_NOT_FOUND. So the check is not "does a
binding appear after registration" -- every store does that -- but "can the same
binding still complete a refresh once the process that created it is gone".

A refresh is the right probe because it is the operation that needs the stored key:
it verifies a JWS against the JWK the server kept. A store that lost the key answers
KEY_NOT_FOUND, which is the failure this is looking for.

    python3 scripts/redis_binding.py capture > /tmp/binding.txt
    ... restart the demo ...
    python3 scripts/redis_binding.py verify /tmp/binding.txt
"""
import base64, http.cookiejar, json, re, ssl, sys, urllib.error
import urllib.parse, urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

BASE = "https://localhost:8443"
COOKIE = "__Host-dbsc-session"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def new_client():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
        NoRedirect())
    return opener, jar


def request(opener, method, path, form=None, body=None, headers=None, raw=False):
    data = None
    hdrs = dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif body is not None:
        data = body if raw else json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(BASE + path, data=data, headers=hdrs, method=method)
    try:
        with opener.open(req) as r:
            return r.status, r.headers.items(), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.items(), e.read().decode()


def header(headers, name):
    for k, v in headers:
        if k.lower() == name.lower():
            return v
    return None


def cookie_value(jar, name):
    return next((c.value for c in jar if c.name == name), None)


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Key:
    """A device key, in the shape the registration JWS header carries."""

    def __init__(self):
        self.private = ec.generate_private_key(ec.SECP256R1())

    def public_jwk(self):
        numbers = self.private.public_key().public_numbers()
        return {
            "kty": "EC", "crv": "P-256",
            "x": b64u(numbers.x.to_bytes(32, "big")),
            "y": b64u(numbers.y.to_bytes(32, "big")),
        }

    def sign(self, signing_input):
        der = self.private.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def jws(self, payload):
        head = {"alg": "ES256", "typ": "dbsc+jwt", "jwk": self.public_jwk()}
        h = b64u(json.dumps(head, separators=(",", ":")).encode())
        p = b64u(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}.{self.sign(f'{h}.{p}'.encode())}"

    def refresh_jws(self, payload):
        """A proof for an existing binding: no jwk header parameter.

        The server already holds the key, and the protocol forbids re-supplying it
        here -- a JWS that carried one would let a stolen session id pick its own
        verification key.
        """
        head = {"alg": "ES256", "typ": "dbsc+jwt"}
        h = b64u(json.dumps(head, separators=(",", ":")).encode())
        p = b64u(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}.{self.sign(f'{h}.{p}'.encode())}"


def login(opener, jar):
    _, _, html = request(opener, "GET", "/login")
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    return request(opener, "POST", "/login",
                   form={"username": "demo", "password": "demo", "_csrf": m.group(1)})


def whoami(opener):
    status, _, text = request(opener, "GET", "/app/whoami")
    return json.loads(text) if status == 200 else None


def challenge_jti(headers):
    """The JTI to sign, from the Secure-Session-Challenge header.

    The header is `"<jti>";id="<session id>"`; the quoted first value is the JTI.
    There is no challenge cookie any more -- the challenge is held server-side
    against the session, and the header is the only copy the client sees.
    """
    value = header(headers, "Secure-Session-Challenge")
    m = re.match(r'"([^"]+)"', value or "")
    return m.group(1) if m else None


def register(opener, jar, key):
    """Completes the native registration, so the server stores the device key."""
    _, headers, _ = login(opener, jar)
    reg = header(headers, "Secure-Session-Registration")
    path = re.search(r'path="([^"]+)"', reg).group(1)
    jti = challenge_jti(headers)
    status, _, text = request(opener, "POST", path, raw=True, body=b"",
                              headers={"Secure-Session-Response": key.jws({"jti": jti})})
    return status, text


def refresh(opener, jar, key):
    """One refresh round. Returns (status, body, headers) of the second leg.

    The first leg has no proof and is answered with a fresh challenge; the second
    presents the JWS. That second leg is what needs the key the server stored, so it
    is the operation that distinguishes a durable store from a lost one.

    The binding cookie is deliberately not sent on either leg. A real browser's
    refresh arrives without it -- the session id travels in Sec-Secure-Session-Id --
    and this probe is meant to look like that, not like an authenticated page load.
    """
    sid = recorded["session_cookie"]
    status, headers, text = request(
        opener, "POST", "/dbsc/refresh", raw=True, body=b"",
        headers={"Content-Type": "application/json", "Sec-Secure-Session-Id": sid})
    challenge = header(headers, "Secure-Session-Challenge")
    if challenge is None:
        return status, text, headers
    jti = challenge_jti(headers)

    status2, headers2, text2 = request(
        opener, "POST", "/dbsc/refresh", raw=True, body=b"",
        headers={"Content-Type": "application/json",
                 "Secure-Session-Response": key.refresh_jws({"jti": jti}),
                 "Sec-Secure-Session-Id": sid})
    return status2, text2, headers2


mode = sys.argv[1] if len(sys.argv) > 1 else "capture"

if mode == "capture":
    opener, jar = new_client()
    key = Key()
    status, text = register(opener, jar, key)
    who = whoami(opener)
    # The private key has to survive in the caller, not here: the point is to replay
    # a *real* binding, so both the cookie and the key are written out.
    out = {
        "session_cookie": cookie_value(jar, COOKIE),
        "private_key": key.private.private_numbers().private_value.to_bytes(32, "big").hex(),
        "registration_status": status,
    }
    sys.stderr.write(f"capture: registration -> {status}, tier={who and who['tier']}\n")
    print(json.dumps(out))
    sys.exit(0 if status == 200 else 1)

path = sys.argv[2] if len(sys.argv) > 2 else "/tmp/binding.json"
with open(path) as fh:
    recorded = json.load(fh)

# A fresh login first, because the demo's /app routes are authenticated and the
# restart destroyed the servlet session along with everything else. The login mints a
# new application session id and a new DBSC session id; the recorded binding cookie is
# then put back, so the old binding is reachable only through it -- which is exactly
# what the store has to still know about.
opener, jar = new_client()
login(opener, jar)

# The same private key as before the restart, rebuilt from the captured scalar.
key = Key.__new__(Key)
key.private = ec.derive_private_key(int(recorded["private_key"], 16), ec.SECP256R1())

status, text, headers = refresh(opener, jar, key)
print(f"refresh with the pre-restart key -> {status}")
print(text[:200])

if status != 200:
    print("FAIL: the stored device key did not survive; the browser would loop "
          "registration with KEY_NOT_FOUND")
    sys.exit(1)
print("RESULT: the pre-restart binding still refreshes (durable)")
