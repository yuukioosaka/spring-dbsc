"""Probe: does dbsc.unregistered=deny refuse a client with no binding?

With the default (allow) a client that never registered reaches the application,
which is what keeps DBSC additive. With deny it must be refused with a bare 403
instead, on the same guarded route. This script asserts both, so
the policy knob is pinned rather than assumed.

Usage: python3 scripts/probe_unregistered.py [base-url]
"""
import http.cookiejar
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://localhost:8443"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def client():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
        NoRedirect())
    return opener, jar


def request(opener, method, path, form=None, raw=None, headers=None):
    data = None
    hdrs = dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif raw is not None:
        data = raw.encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(BASE + path, data=data, headers=hdrs, method=method)
    try:
        with opener.open(req) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


opener, jar = client()
_, html = request(opener, "GET", "/login")
m = re.search(r'name="_csrf" value="([^"]+)"', html)
if not m:
    print("FAIL: no login form; is the form-login demo up on this port?")
    sys.exit(1)

status, _ = request(opener, "POST", "/login",
                    form={"username": "demo", "password": "demo", "_csrf": m.group(1)})
print(f"login -> {status}")

# Authenticated, but the browser never completes registration, so tier is none.
# This is exactly a client without DBSC support.
_, csrf_html = request(opener, "GET", "/app")
csrf = re.search(r'name="csrf" content="([^"]+)"', csrf_html)
token = csrf.group(1) if csrf else "x"

status, text = request(opener, "POST", "/app/payment", raw="{\"amount\":1000,\"currency\":\"usd\"}",
                       headers={"X-CSRF-TOKEN": token})
print(f"POST /app/payment as an unregistered client -> {status}")
print(text[:200])

if status == 403 and "status" in text:
    # Spring Security's AccessDeniedHandler, since an access() rule refuses without a
    # body of its own. What matters is the status, not the shape.
    print("\nRESULT: dbsc.unregistered=deny (refused)")
    sys.exit(0)
if status == 403:
    print("\nRESULT: dbsc.unregistered=deny (refused)")
    sys.exit(0)
if status == 200:
    print("\nRESULT: dbsc.unregistered=allow (allowed through)")
    sys.exit(0)
print("\nFAIL: unexpected outcome; does /app/payment have the isProtected access() rule?")
sys.exit(1)
