"""Dumps every response header from a form-login POST, plus the session state.

Usage: python3 scripts/probe-login.py
"""
import re, ssl, http.cookiejar, urllib.request, urllib.parse

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),
                                 urllib.request.HTTPSHandler(context=ctx))
BASE = "https://localhost:8443"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


noop = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),
                                   urllib.request.HTTPSHandler(context=ctx),
                                   NoRedirect)

html = op.open(BASE + "/login").read().decode()
tok = re.search(r'name="_csrf" value="([^"]+)"', html).group(1)

req = urllib.request.Request(BASE + "/login",
    data=urllib.parse.urlencode({"username": "demo", "password": "demo",
                                 "_csrf": tok}).encode())
try:
    r = noop.open(req)
except urllib.error.HTTPError as e:
    r = e

print(f"POST /login -> {r.status} {r.reason}")
for k, v in r.headers.items():
    print(f"   {k}: {v[:160]}")

print("\ncookies:")
for c in cj:
    print(f"   {c.name} = {c.value[:40]}  secure={c.secure}")
