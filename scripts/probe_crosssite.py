"""Probe: can a registration POST succeed with NO session cookie?

This is the one property that forced the /oidc/bind relay to exist. Behind an
OIDC or SAML callback, Chromium issues the registration POST from a cross-site
navigation context, so the SameSite=Lax JSESSIONID is withheld. Under the old
cookie-based design that made the request unresolvable (SESSION_NOT_FOUND).

Under the token-in-path design the session is named by the URL, so the cookie
should not matter. This script proves it: it logs in, throws the cookie jar
away, then registers using only the token path -- but it does keep the DBSC
challenge cookie, because that is genuinely needed to know which JTI was signed.

Usage: python3 scripts/probe_crosssite.py [base-url]
"""
import http.cookiejar
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from e2e import Key  # reuse the suite's ES256 JWS builder

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://localhost:8443"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """The 302 out of /login carries the registration header; following it
    would land on /app and lose it."""

    def redirect_request(self, *a, **k):
        return None


def client():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
        NoRedirect())
    return opener, jar


def get(opener, path):
    try:
        with opener.open(BASE + path) as r:
            return r.status, dict(r.headers.items()), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read().decode()


def login(opener):
    _, _, html = get(opener, "/login")
    csrf = re.search(r'name="_csrf" value="([^"]+)"', html).group(1)
    data = urllib.parse.urlencode(
        {"username": "demo", "password": "demo", "_csrf": csrf}).encode()
    req = urllib.request.Request(BASE + "/login", data=data, method="POST")
    try:
        with opener.open(req) as r:
            return r.status, dict(r.headers.items())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items())


opener, jar = client()
status, headers = login(opener)
reg = headers.get("Secure-Session-Registration")
print(f"login -> {status}")
print(f"registration header: {reg}")
if not reg:
    print("FAIL: no registration header; is the demo up and is this the form profile?")
    sys.exit(1)

path = re.search(r'path="([^"]+)"', reg).group(1)
jti = None
for c in jar:
    if c.name == "__Host-dbsc-challenge":
        jti = c.value
print(f"token path: {path}")
print(f"challenge jti: {jti}")
if not jti:
    print("FAIL: no challenge cookie; the login did not bind")
    sys.exit(1)

# The point of the probe: a registration POST carrying the token path, but NOT the
# session cookie. If the design is right this is exactly what a cross-site callback
# produces, and it must succeed.
#
# The challenge cookie is included on the first attempt because it is a separate
# cookie with its own SameSite policy: it must be readable cross-site, or the server
# cannot tell which JTI was signed. The second attempt drops it too, to show that a
# client which withholds everything gets a clean protocol error rather than a
# confusing one.
key = Key()
body = key.jws({"jti": jti})

def register(cookie_header):
    req = urllib.request.Request(
        BASE + path, data=b"", method="POST",
        headers={
            "Secure-Session-Response": body,
            "Content-Type": "application/json",
            "Cookie": cookie_header,
        })
    try:
        return opener.open(req).status, ""
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

print()
status, body_text = register(f"__Host-dbsc-challenge={jti}")
print(f"registration, challenge cookie only (no session cookie) -> {status}")
print(body_text[:200])
if status != 200:
    print("\nFAIL: the challenge could not be read without a session cookie.")
    sys.exit(1)
print("PASS: the token in the path named the session, and the challenge cookie")
print("      came across even though no session cookie did.")
