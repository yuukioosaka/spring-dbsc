"""Checks that /app serves the bound-polyfill wiring (section 3 of the page).

Manual-testing helper, not part of the automated suite. Logs in with the demo
credentials, fetches /app, and reports whether the client bundle is referenced
and whether the two polyfill controls are present.

Usage: python3 scripts/probe-bound-page.py
"""
import http.cookiejar
import re
import ssl
import sys
import urllib.parse
import urllib.request

BASE = "https://localhost:8443"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPSHandler(context=ctx))

login = opener.open(BASE + "/login").read().decode()
token = re.search(r'name="_csrf" value="([^"]+)"', login).group(1)
opener.open(urllib.request.Request(
    BASE + "/login",
    data=urllib.parse.urlencode(
        {"username": "demo", "password": "demo", "_csrf": token}).encode()))

page = opener.open(BASE + "/app").read().decode()

expectations = [
    ("the client bundle is loaded as a module",
     "from '/dbsc-client/index.js'" in page),
    ("initBoundDbsc is re-exported to window",
     "window.initBoundDbsc = initBoundDbsc" in page),
    ("wrapFetch is re-exported to window",
     "window.wrapFetch = wrapFetch" in page),
    ("the polyfill section is present",
     "Bound / polyfill client" in page),
    ("the init control is wired",
     'onclick="runBound()"' in page),
    ("the proof control is wired",
     'onclick="hitGuardedWithProof()"' in page),
]

# The bundle itself must be reachable unauthenticated, or the page's module
# import fails before any of the above can run.
anon = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
status = anon.open(BASE + "/dbsc-client/index.js").status
expectations.append(("the bundle is served unauthenticated", status == 200))

failed = 0
for name, ok in expectations:
    print(("[PASS] " if ok else "[FAIL] ") + name)
    failed += 0 if ok else 1

print(f"\n=== {len(expectations) - failed} passed, {failed} failed ===")
sys.exit(1 if failed else 0)
